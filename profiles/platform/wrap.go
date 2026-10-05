package platform

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/thehappieco/kit/account"
)

// WrapKind is the second byte of a root wrap and names the key that opened
// it (section 11.5).
type WrapKind byte

// The wrap kinds.
const (
	WrapPassword WrapKind = 0x01
	WrapRecovery WrapKind = 0x02
	// WrapPasskey is a wrap under K_pk, the key a passkey's PRF output gives
	// (SPEC section 11.16, PasskeyWrapKey); NewPasskeyWrap and
	// OpenPasskeyWrap seal and open it from the PRF output.
	WrapPasskey WrapKind = 0x03
)

// Root-wrap envelope v1 layout, the wrap envelope of SPEC section 6.5 with
// the two-byte header 0x01 ‖ kind:
//
//	offset  size  field
//	0       1     0x01, the format version
//	1       1     kind
//	2       12    nonce
//	14      48    AES-256-GCM(key, nonce, root, aad): 32 bytes of ciphertext, 16 of tag
const (
	// WrapLen is the length of every root wrap.
	WrapLen = 62
	// WrapVersion is the first byte of every root wrap.
	WrapVersion byte = 0x01

	wrapNonceAt = 2
	wrapBodyAt  = 14
)

// String returns the kind's name as it appears in the AAD.
func (k WrapKind) String() string {
	switch k {
	case WrapPassword:
		return "password"
	case WrapRecovery:
		return "recovery"
	case WrapPasskey:
		return "passkey"
	}
	return fmt.Sprintf("WrapKind(%d)", byte(k))
}

func (k WrapKind) valid() bool { return k == WrapPassword || k == WrapRecovery || k == WrapPasskey }

// Binding is what a root wrap is bound to through its AAD: the immutable sub
// and the key epoch, never the email, so an address change needs no re-wrap
// and a wrap moved to another account or epoch does not open. A passkey wrap
// is also bound to its relying party and credential.
type Binding struct {
	Sub   string // lowercase hyphenated UUID
	Epoch int    // account_key_epoch, from 1
	// RPID and CredentialID (base64url) are set for WrapPasskey only.
	RPID         string
	CredentialID string
}

// WrapAAD returns the restricted JSON array a wrap of this kind is sealed
// under:
//
//	password  ["thehappie-id/root-wrap",1,"password",sub,epoch]
//	recovery  ["thehappie-id/root-wrap",1,"recovery",sub,epoch]
//	passkey   ["thehappie-id/root-wrap",1,"passkey",sub,epoch,rp_id,credential_id_b64url]
//
// It refuses, wrapping ErrWrap, a sub that is not a lowercase UUID, an epoch
// out of range, passkey fields on another kind, and missing or unencodable
// passkey fields.
func WrapAAD(kind WrapKind, b Binding) ([]byte, error) {
	if !kind.valid() {
		return nil, fmt.Errorf("%w: unknown kind", ErrWrap)
	}
	if _, err := parseSub(b.Sub); err != nil {
		return nil, fmt.Errorf("%w: the sub is not a lowercase UUID", ErrWrap)
	}
	if !checkEpoch(b.Epoch) {
		return nil, fmt.Errorf("%w: epoch out of range", ErrWrap)
	}
	var aad []byte
	var err error
	if kind == WrapPasskey {
		if b.RPID == "" || b.CredentialID == "" {
			return nil, fmt.Errorf("%w: a passkey wrap needs its rp id and credential id", ErrWrap)
		}
		if _, err := decodeB64(b.CredentialID); err != nil {
			return nil, fmt.Errorf("%w: the credential id is not strict base64url", ErrWrap)
		}
		aad, err = JCSArray(wrapAADLabel, int(WrapVersion), kind.String(), b.Sub, b.Epoch, b.RPID, b.CredentialID)
	} else {
		if b.RPID != "" || b.CredentialID != "" {
			return nil, fmt.Errorf("%w: passkey fields on a %s wrap", ErrWrap, kind)
		}
		aad, err = JCSArray(wrapAADLabel, int(WrapVersion), kind.String(), b.Sub, b.Epoch)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWrap, err)
	}
	return aad, nil
}

// PasswordWrapAAD is WrapAAD for a password wrap.
func PasswordWrapAAD(sub string, epoch int) ([]byte, error) {
	return WrapAAD(WrapPassword, Binding{Sub: sub, Epoch: epoch})
}

// RecoveryWrapAAD is WrapAAD for a recovery wrap.
func RecoveryWrapAAD(sub string, epoch int) ([]byte, error) {
	return WrapAAD(WrapRecovery, Binding{Sub: sub, Epoch: epoch})
}

// PasskeyWrapAAD is WrapAAD for a passkey wrap.
func PasskeyWrapAAD(sub string, epoch int, rpID, credentialID string) ([]byte, error) {
	return WrapAAD(WrapPasskey, Binding{Sub: sub, Epoch: epoch, RPID: rpID, CredentialID: credentialID})
}

// CheckWrapShape is the server's whole check of a submitted wrap, since it
// cannot open one: the length, the version byte, and that the kind byte is
// the one the field expects. It wraps ErrWrap.
func CheckWrapShape(kind WrapKind, wrap []byte) error {
	switch {
	case !kind.valid():
		return fmt.Errorf("%w: unknown kind", ErrWrap)
	case len(wrap) != WrapLen:
		return fmt.Errorf("%w: %d bytes, not %d", ErrWrap, len(wrap), WrapLen)
	case wrap[0] != WrapVersion:
		return fmt.Errorf("%w: unknown version", ErrWrap)
	case wrap[1] != byte(kind):
		return fmt.Errorf("%w: not a %s wrap", ErrWrap, kind)
	}
	return nil
}

// Wrap seals the 32-byte root under key for kind and b, with a nonce read
// from r (crypto/rand when r is nil; a fixed reader replays a vector). Before
// it returns, it opens the result again with the same key and compares it
// with root: the self-test section 11.5 requires of every new wrap.
//
// It writes the bytes account.Wrap(RootWrapProfile(kind), key, root, aad)
// writes for the same nonce; it seals by itself only so that the nonce can
// come from r.
func Wrap(r io.Reader, kind WrapKind, key, root []byte, b Binding) ([]byte, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("%w: a %d-byte key", ErrWrap, len(key))
	}
	if len(root) != KeyLen {
		return nil, fmt.Errorf("%w: a %d-byte root", ErrWrap, len(root))
	}
	aad, err := WrapAAD(kind, b)
	if err != nil {
		return nil, err
	}
	nonce, err := readRandom(r, wrapBodyAt-wrapNonceAt)
	if err != nil {
		return nil, err
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, wrapBodyAt, WrapLen)
	out[0] = WrapVersion
	out[1] = byte(kind)
	copy(out[wrapNonceAt:], nonce)
	out = aead.Seal(out, nonce, root, aad)

	again, err := Unwrap(kind, key, out, b)
	if err != nil {
		return nil, fmt.Errorf("%w: the new wrap failed its self-test", ErrWrap)
	}
	defer clear(again)
	if subtle.ConstantTimeCompare(again, root) != 1 {
		return nil, fmt.Errorf("%w: the new wrap failed its self-test", ErrWrap)
	}
	return out, nil
}

// Unwrap opens a root wrap of kind under key for b: CheckWrapShape, then
// account.Unwrap with RootWrapProfile(kind) and WrapAAD. Every failure, from
// a wrong length to a wrong key, is ErrWrap and says no more. The caller
// clears the returned root.
func Unwrap(kind WrapKind, key, wrap []byte, b Binding) ([]byte, error) {
	if err := CheckWrapShape(kind, wrap); err != nil {
		return nil, err
	}
	if len(key) != KeyLen {
		return nil, fmt.Errorf("%w: a %d-byte key", ErrWrap, len(key))
	}
	aad, err := WrapAAD(kind, b)
	if err != nil {
		return nil, err
	}
	root, stale, err := account.Unwrap(RootWrapProfile(kind), key, wrap, aad)
	if err != nil || stale || len(root) != KeyLen {
		clear(root)
		return nil, ErrWrap
	}
	return root, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWrap, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWrap, err)
	}
	return aead, nil
}
