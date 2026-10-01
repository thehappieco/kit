// Package passkey wraps an account key under a WebAuthn PRF output, so a
// passkey can unlock what a password unlocks.
//
// The server hands the authenticator one public evaluation input per relying
// party, SHA-256(EvalPrefix ‖ rpID); the PRF output stays in the client and
// is never sent. The wrap key is HKDF over that output, salted with the RP ID:
//
//	K        = HKDF-SHA256(IKM = PRF first output (32), salt = UTF-8(rpID), info = WrapInfo, L = 32)
//	envelope = Header ‖ nonce (12) ‖ AES-256-GCM(K, nonce, key (32), aad) ‖ tag
//
// The scheme comes from Wappie's browser client
// (packages/client/src/crypto/passkey.ts), which is its reference; the AAD is
// the profile's (Wappie's is the JSON array of the RP ID, the user id and the
// credential id).
package passkey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// Sizes the scheme fixes.
const (
	PRFLen   = 32
	KeyLen   = 32
	NonceLen = 12
	TagLen   = 16
)

// Profile is what a product chooses.
type Profile struct {
	// EvalPrefix precedes the RP ID in the PRF evaluation input.
	EvalPrefix string
	// WrapInfo is the HKDF info of the wrap key.
	WrapInfo string
	// Header prefixes every envelope (Wappie: one version byte, 0x01).
	Header []byte
}

// Error says which check failed: bad_key, bad_prf, bad_envelope or
// open_failed.
type Error struct{ Reason string }

func (e *Error) Error() string { return "passkey: " + e.Reason }

// The failures, as values errors.Is matches by identity.
var (
	ErrBadKey      = &Error{"bad_key"}
	ErrBadPRF      = &Error{"bad_prf"}
	ErrBadEnvelope = &Error{"bad_envelope"}
	ErrOpenFailed  = &Error{"open_failed"}
)

// PRFSalt is the public PRF evaluation input for an RP ID. The server hands it
// out; it is the same for every credential of the RP, which is what lets a
// discoverable login evaluate the PRF without naming the credential first.
func PRFSalt(p Profile, rpID string) [32]byte {
	return sha256.Sum256([]byte(p.EvalPrefix + rpID))
}

// Key derives the wrap key from a PRF output.
func Key(p Profile, prf []byte, rpID string) ([]byte, error) {
	if len(prf) != PRFLen {
		return nil, ErrBadPRF
	}
	return hkdf.Key(sha256.New, prf, []byte(rpID), p.WrapInfo, KeyLen)
}

// Wrap seals a 32-byte key under a PRF output. Only the envelope may leave the
// client.
func Wrap(p Profile, privateKey, prf []byte, rpID string, aad []byte) ([]byte, error) {
	if len(privateKey) != KeyLen {
		return nil, ErrBadKey
	}
	nonce := make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("passkey: entropy: %w", err)
	}
	return wrap(p, privateKey, prf, rpID, aad, nonce)
}

func wrap(p Profile, privateKey, prf []byte, rpID string, aad, nonce []byte) ([]byte, error) {
	if len(privateKey) != KeyLen {
		return nil, ErrBadKey
	}
	gcm, err := newGCM(p, prf, rpID)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(p.Header)+NonceLen+KeyLen+TagLen)
	out = append(out, p.Header...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, privateKey, aad), nil
}

// Unwrap opens an envelope. An envelope of the wrong length or header is
// ErrBadEnvelope; everything after that, a PRF of the wrong length included,
// is ErrOpenFailed, as in the reference client.
func Unwrap(p Profile, envelope, prf []byte, rpID string, aad []byte) ([]byte, error) {
	h := len(p.Header)
	if len(envelope) != h+NonceLen+KeyLen+TagLen || string(envelope[:h]) != string(p.Header) {
		return nil, ErrBadEnvelope
	}
	gcm, err := newGCM(p, prf, rpID)
	if err != nil {
		return nil, ErrOpenFailed
	}
	key, err := gcm.Open(nil, envelope[h:h+NonceLen], envelope[h+NonceLen:], aad)
	if err != nil {
		return nil, ErrOpenFailed
	}
	return key, nil
}

func newGCM(p Profile, prf []byte, rpID string) (cipher.AEAD, error) {
	k, err := Key(p, prf, rpID)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
