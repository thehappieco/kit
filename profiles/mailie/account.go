package mailie

import (
	"encoding/base64"
	"fmt"

	"github.com/thehappieco/kit/account"
	"github.com/thehappieco/kit/profiles/platform"
)

// The account scheme's labels (SPEC section 6 and Appendix D). They name
// keys; they are not credentials.
const (
	// PasswordAuthLabel and PasswordWrapLabel are the HKDF infos of the two
	// branches of the Argon2id master key: the auth key, which is sent, and
	// the wrap key, which never leaves the client.
	PasswordAuthLabel = "mailie/v1/password/auth"
	PasswordWrapLabel = "mailie/v1/password/wrap"
	// RecoveryWrapLabel and RecoveryAuthLabel are the HKDF infos of the two
	// branches of a recovery code: its wrap key and its proof.
	RecoveryWrapLabel = "mailie/v1/recovery/wrap"
	RecoveryAuthLabel = "mailie/v1/recovery/auth"
	// AccountWrapTag opens the additional data of an account wrap.
	AccountWrapTag = "mailie/account-wrap"
	// AccountWrapVersion is the 1 in the additional data: the format's
	// version, the same for both kinds.
	AccountWrapVersion = 1
	// AccountWrapHeader is the first byte of the password and recovery wraps
	// of an account key. The platform wrap starts with 0x03
	// (platformwrap.Header) and a grant with the seal magic 'M', so a blob
	// in the wrong column fails at its first byte.
	AccountWrapHeader = 0x02
	// AccountWrapLen is a wrap's length: the header, a 12-byte nonce, the
	// 32-byte account key and a 16-byte tag.
	AccountWrapLen = 1 + 12 + KeyLen + 16
	// SaltLen is the only salt length the profile derives with.
	SaltLen = platform.SaltLen
	// PasswordPreparation names the preparation of a password: the platform
	// profile's (SPEC section 11.2), for a password being presented (no
	// minimum length; platform.PrepareNewPassword checks a new one's).
	PasswordPreparation = platform.PasswordProfile
)

// WrapKind says which secret an account wrap is under. It is bound into the
// wrap's additional data.
type WrapKind string

const (
	// WrapPassword is the wrap under the password's wrap key.
	WrapPassword WrapKind = "password"
	// WrapRecovery is the wrap under the recovery code's wrap key.
	WrapRecovery WrapKind = "recovery"
)

func (k WrapKind) valid() bool { return k == WrapPassword || k == WrapRecovery }

// DefaultKDF is what Mailie's accounts derive with: Argon2id, 64 MiB, three
// passes, one lane, the floor of the platform's bounds.
var DefaultKDF = account.KDFParams{Alg: platform.KDFAlg, M: platform.KDFMinM, T: platform.KDFMinT, P: platform.KDFMinP}

// Account is Mailie's profile for package account: its labels, the
// platform's preparation of a presented password, the platform's KDF bounds
// (m from 64 to 256 MiB, t from 3 to 10, p from 1 to 4, m×t at most
// 1048576, a salt of exactly 16 bytes), base64url text without padding, the
// platform's canonical form of a recovery code, and the one-byte header 0x02
// with no legacy form. Every call returns a fresh value.
//
//	master = Argon2id(prepared password, salt (16), m, t, p, 32 bytes, version 0x13)
//	auth   = HKDF-SHA256(master, salt = ∅, info = "mailie/v1/password/auth", 32)
//	wrap   = HKDF-SHA256(master, salt = ∅, info = "mailie/v1/password/wrap", 32)
func Account() account.Profile {
	return account.Profile{
		AuthLabel:          PasswordAuthLabel,
		WrapLabel:          PasswordWrapLabel,
		RecoveryKeyLabel:   RecoveryWrapLabel,
		RecoveryProofLabel: RecoveryAuthLabel,
		WrapHeader:         []byte{AccountWrapHeader},
		LegacyV1:           false,
		Prepare:            platform.PreparePassword,
		Bounds:             platform.KDFBounds(),
		Encoding:           base64.RawURLEncoding,
		NormaliseRecovery:  platform.CanonicalRecoveryCode,
	}
}

// AccountWrapAAD is the additional data of an account wrap, a restricted
// JSON AAD (SPEC section 11.1):
//
//	JCS(["mailie/account-wrap", 1, kind, seal_id, base64url(account public key)])
//
// It binds the immutable seal id, never the address, so an address change
// needs no re-wrap; the kind, so a password wrap is never taken for the
// recovery wrap; and the account public key, so a wrap opens only for the
// key the person's grants are sealed to.
func AccountWrapAAD(kind WrapKind, sealID string, accountPublicKey []byte) ([]byte, error) {
	if !kind.valid() {
		return nil, fmt.Errorf("%w: a wrap kind is password or recovery", ErrBinding)
	}
	if !ValidSealID(sealID) {
		return nil, fmt.Errorf("%w: the seal id is not a lowercase UUIDv4", ErrBinding)
	}
	if len(accountPublicKey) != KeyLen {
		return nil, fmt.Errorf("%w: an account public key is %d bytes", ErrBinding, KeyLen)
	}
	aad, err := platform.JCSArray(AccountWrapTag, AccountWrapVersion, string(kind), sealID, platform.EncodeB64(accountPublicKey))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBinding, err)
	}
	return aad, nil
}

// SealAccountWrap wraps a 32-byte account key under a wrap key (the
// password's, or the recovery code's) for the person sealID names, with the
// wrap envelope of SPEC section 6.5:
//
//	0x02 ‖ nonce (12) ‖ AES-256-GCM(wrapKey, nonce, account key, AccountWrapAAD(...))     61 bytes
//
// with a fresh random nonce. It opens what it made and compares before it
// returns it (the self-test). The keys are the caller's to clear.
func SealAccountWrap(kind WrapKind, wrapKey, accountKey []byte, sealID string) ([]byte, error) {
	pub, err := PublicKey(accountKey)
	if err != nil {
		return nil, err
	}
	aad, err := AccountWrapAAD(kind, sealID, pub)
	if err != nil {
		return nil, err
	}
	wrap, err := account.Wrap(Account(), wrapKey, accountKey, aad)
	if err != nil {
		return nil, err
	}
	again, err := OpenAccountWrap(kind, wrapKey, wrap, sealID, pub)
	if err != nil {
		return nil, fmt.Errorf("mailie: the new wrap failed its self-test: %w", err)
	}
	clear(again)
	return wrap, nil
}

// OpenAccountWrap opens an account wrap with its wrap key and returns the
// account key, which the caller clears. In order: the binding (ErrBinding);
// the shape, a wrap shorter than 61 bytes being account.ErrTruncated and one
// longer, or not starting with 0x02, account.ErrWrongKey; the wrap key's
// length (account.ErrBadKey); the tag; and that the key it opened is the
// private half of accountPublicKey, compared in constant time. A wrong key,
// another binding, a changed byte and a key that is not the bound one are
// all account.ErrWrongKey.
func OpenAccountWrap(kind WrapKind, wrapKey, wrap []byte, sealID string, accountPublicKey []byte) ([]byte, error) {
	aad, err := AccountWrapAAD(kind, sealID, accountPublicKey)
	if err != nil {
		return nil, err
	}
	if len(wrap) < AccountWrapLen {
		return nil, account.ErrTruncated
	}
	if len(wrap) != AccountWrapLen || wrap[0] != AccountWrapHeader {
		return nil, account.ErrWrongKey
	}
	key, _, err := account.Unwrap(Account(), wrapKey, wrap, aad)
	if err != nil {
		return nil, err
	}
	if !isPublicHalf(key, accountPublicKey) {
		clear(key)
		return nil, account.ErrWrongKey
	}
	return key, nil
}

// CheckAccountWrapShape is what a server checks of a password or recovery
// wrap it is sent, which it cannot open: 61 bytes starting with 0x02.
func CheckAccountWrapShape(wrap []byte) error {
	if len(wrap) != AccountWrapLen || wrap[0] != AccountWrapHeader {
		return fmt.Errorf("%w: an account wrap is %d bytes starting with 0x%02x", ErrShape, AccountWrapLen, AccountWrapHeader)
	}
	return nil
}
