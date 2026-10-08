// Package thcseal implements THCSEAL v1, the envelope every tier-2 secret is
// stored in (the platform's decision 0003; SPEC section 14): the secrets a
// server uses on its own, such as the platform's OIDC signing key and HMAC
// keys, Stripe and SMTP credentials, a product's mail provider credentials,
// and the database backups.
//
// The rule it enforces: a tier-2 secret exists at rest only inside an
// envelope whose data key is wrapped by a kms.Wrapper, and the envelope opens
// only for the exact encryption context it was sealed under and only with
// the provider that sealed it.
//
// Layout, big-endian:
//
//	offset  size  field
//	0       7     ASCII "THCSEAL"
//	7       1     version, 0x01
//	8       1     provider (kms.ProviderAWS, kms.ProviderLocal)
//	9       2     L, length of the wrapped data key, 1..6144
//	11      L     wrapped data key (a KMS CiphertextBlob, or a localkek wrap)
//	11+L    12    nonce
//	23+L    ...   AES-256-GCM ciphertext || tag(16)
//
// The additional data is the header, bytes [0, 11+L), followed by service,
// env, purpose and ref, each as a u16 length and its bytes. Every header byte
// is therefore authenticated: changing the version, the provider, the length
// or the wrapped key is a decryption failure, not a change of behaviour. The
// context in the additional data binds the envelope to its row as well as to
// its wrapped key: an envelope moved to another purpose or ref does not open
// even under a provider that ignored the context.
//
// Each envelope gets its own data key. Sealing is rare (key generation,
// secret entry, backups), so there is no nonce accounting to do; the data
// key is zeroed after use, as far as Go allows.
//
// From the platform (github.com/thehappieco/platform), internal/seal at
// d32b663, unchanged in behaviour: only the package's name, the prefix of
// its error messages, its import paths and these comments differ
// (vectors/PROVENANCE.md). The kit's package seal is Wappie's envelope
// (SPEC section 4), hence the name; a consumer that keeps the platform's
// name imports this one as seal "github.com/thehappieco/kit/thcseal".
package thcseal

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/thehappieco/kit/kms"
)

const (
	// Magic opens every envelope.
	Magic = "THCSEAL"
	// Version1 is the only version.
	Version1 byte = 0x01
	// MaxWrappedKeyLen bounds L. It is the largest ciphertext KMS returns.
	MaxWrappedKeyLen = 6144
	// MaxPlaintext bounds what one envelope holds: 256 MiB. A single GCM
	// message must be held in memory whole to be authenticated, so anything
	// bigger needs a chunked format, not a bigger envelope.
	MaxPlaintext = 256 << 20

	headerLen = len(Magic) + 1 + 1 + 2
	nonceLen  = 12
	tagLen    = 16
	// minLen is the smallest well-formed envelope: a one-byte wrapped key and
	// an empty plaintext.
	minLen = headerLen + 1 + nonceLen + tagLen
)

var (
	// ErrMalformed means the bytes are not a THCSEAL v1 envelope: wrong magic
	// or version, a length out of range, or truncated.
	ErrMalformed = errors.New("thcseal: malformed envelope")
	// ErrProviderMismatch means the envelope was sealed by another provider
	// than the wrapper offered to open it, for example a development envelope
	// presented to the production AWS wrapper.
	ErrProviderMismatch = errors.New("thcseal: envelope from another key provider")
	// ErrDecrypt means the envelope did not open: wrong key, wrong context, or
	// altered bytes. Which one is deliberately not reported.
	ErrDecrypt = errors.New("thcseal: decryption failed")
	// ErrTooLarge means the plaintext is over MaxPlaintext.
	ErrTooLarge = errors.New("thcseal: plaintext over 256 MiB")
)

// Envelope is a decoded THCSEAL envelope. Its slices alias the decoded input.
type Envelope struct {
	Version    byte
	Provider   byte
	WrappedKey []byte
	Nonce      []byte
	// Ciphertext is the AES-256-GCM ciphertext followed by its tag.
	Ciphertext []byte

	header []byte
}

// Decode parses an envelope without opening it. It checks only the
// structure; nothing it returns is authenticated until Open succeeds.
func Decode(b []byte) (Envelope, error) {
	if len(b) < minLen {
		return Envelope{}, fmt.Errorf("%w: %d bytes is too short", ErrMalformed, len(b))
	}
	if string(b[:len(Magic)]) != Magic {
		return Envelope{}, fmt.Errorf("%w: not a THCSEAL envelope", ErrMalformed)
	}
	if v := b[len(Magic)]; v != Version1 {
		return Envelope{}, fmt.Errorf("%w: version %d", ErrMalformed, v)
	}
	l := int(binary.BigEndian.Uint16(b[headerLen-2 : headerLen]))
	if l < 1 || l > MaxWrappedKeyLen {
		return Envelope{}, fmt.Errorf("%w: wrapped key length %d", ErrMalformed, l)
	}
	body := headerLen + l + nonceLen
	if len(b)-body < tagLen {
		return Envelope{}, fmt.Errorf("%w: truncated", ErrMalformed)
	}
	if len(b)-body-tagLen > MaxPlaintext {
		return Envelope{}, fmt.Errorf("%w: over the size limit", ErrMalformed)
	}
	return Envelope{
		Version:    b[len(Magic)],
		Provider:   b[len(Magic)+1],
		WrappedKey: b[headerLen : headerLen+l],
		Nonce:      b[headerLen+l : body],
		Ciphertext: b[body:],
		header:     b[:headerLen+l],
	}, nil
}

// Seal encrypts plaintext under a fresh data key from w, bound to ec.
func Seal(ctx context.Context, w kms.Wrapper, ec kms.Context, plaintext []byte) ([]byte, error) {
	if w == nil {
		return nil, errors.New("thcseal: no key wrapper")
	}
	if err := ec.Validate(); err != nil {
		return nil, err
	}
	if len(plaintext) > MaxPlaintext {
		return nil, ErrTooLarge
	}
	dek, wrapped, err := w.GenerateDataKey(ctx, ec)
	defer clear(dek)
	if err != nil {
		return nil, fmt.Errorf("thcseal: generate a data key: %w", err)
	}
	if len(dek) != kms.DataKeyLen {
		return nil, fmt.Errorf("thcseal: the wrapper returned a %d-byte data key", len(dek))
	}
	if len(wrapped) < 1 || len(wrapped) > MaxWrappedKeyLen {
		return nil, fmt.Errorf("thcseal: the wrapper returned a %d-byte wrapped key", len(wrapped))
	}

	n := headerLen + len(wrapped)
	out := make([]byte, n+nonceLen, n+nonceLen+len(plaintext)+tagLen)
	copy(out, Magic)
	out[len(Magic)] = Version1
	out[len(Magic)+1] = w.Provider()
	binary.BigEndian.PutUint16(out[headerLen-2:headerLen], uint16(len(wrapped))) //nolint:gosec // len(wrapped) <= MaxWrappedKeyLen, checked above
	copy(out[headerLen:], wrapped)
	nonce := out[n : n+nonceLen]
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("thcseal: read random: %w", err)
	}

	aead, err := gcm(dek)
	if err != nil {
		return nil, err
	}
	return aead.Seal(out, nonce, plaintext, aad(out[:n], ec)), nil
}

// Open decrypts an envelope sealed under ec by w's provider.
//
// It returns ErrMalformed for bytes that are not an envelope,
// ErrProviderMismatch for an envelope from another provider, and ErrDecrypt
// for every envelope that does not open. A failure to reach the wrapper (KMS
// unavailable, access denied, cancelled context) is returned wrapped as it
// is, because it says nothing about the envelope.
func Open(ctx context.Context, w kms.Wrapper, ec kms.Context, envelope []byte) ([]byte, error) {
	if w == nil {
		return nil, errors.New("thcseal: no key wrapper")
	}
	if err := ec.Validate(); err != nil {
		return nil, err
	}
	e, err := Decode(envelope)
	if err != nil {
		return nil, err
	}
	if e.Provider != w.Provider() {
		return nil, ErrProviderMismatch
	}
	dek, err := w.Decrypt(ctx, e.WrappedKey, ec)
	defer clear(dek)
	if errors.Is(err, kms.ErrUnwrap) {
		return nil, ErrDecrypt
	}
	if err != nil {
		return nil, fmt.Errorf("thcseal: unwrap the data key: %w", err)
	}
	if len(dek) != kms.DataKeyLen {
		return nil, ErrDecrypt
	}
	aead, err := gcm(dek)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, e.Nonce, e.Ciphertext, aad(e.header, ec))
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

func gcm(dek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("thcseal: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("thcseal: %w", err)
	}
	return aead, nil
}

// aad is the header followed by the length-prefixed context fields. Context
// fields are at most kms.MaxFieldLen bytes (Validate), so u16 never wraps.
func aad(header []byte, ec kms.Context) []byte {
	out := make([]byte, 0, len(header)+8+len(ec.Service)+len(ec.Env)+len(ec.Purpose)+len(ec.Ref))
	out = append(out, header...)
	for _, f := range [...]string{ec.Service, ec.Env, ec.Purpose, ec.Ref} {
		out = binary.BigEndian.AppendUint16(out, uint16(len(f))) //nolint:gosec // fields are <= kms.MaxFieldLen
		out = append(out, f...)
	}
	return out
}
