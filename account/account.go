// Package account is the zero-knowledge account scheme: what a password
// becomes, the envelope that keeps an account's key under it, and the recovery
// code that is the second way back in.
//
// The password never leaves the client. Argon2id stretches it into a master
// key, which HKDF splits into two independent branches: the auth key, sent to
// the server and stored there only as a slow or domain-separated hash, and the
// wrap key, which never leaves and opens the account's key. The scheme comes
// from Wappie's browser client (packages/client/src/crypto/account.ts), which
// remains its reference: this Go implementation is pinned to it by the
// vectors in vectors/wappie/golden/account-ts.json.
//
// Every label, the envelope header, the password preparation, the KDF bounds
// and the text encoding are a Profile's. The AAD of a wrap is an argument,
// built by the profile's own helper, because what a wrap binds to is a
// product's decision: Wappie binds the email, the platform binds the account
// id and epoch.
package account

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// KDFParams is what the server stores beside a salt, so the cost can be raised
// later. M is in KiB.
type KDFParams struct {
	Alg string `json:"alg"`
	M   uint32 `json:"m"`
	T   uint32 `json:"t"`
	P   uint8  `json:"p"`
}

// DefaultKDFParams are the parameters new accounts are created with.
var DefaultKDFParams = KDFParams{Alg: "argon2id", M: 64 * 1024, T: 3, P: 1}

// Bounds are the KDF parameters and salt a client accepts from a server
// before deriving. Without them a server, or anybody who can write its
// database, can hand a client cheap parameters, or a salt it has used before,
// and turn its next login into a cheap offline target.
type Bounds struct {
	Min, Max KDFParams
	// MaxCost bounds M×T; zero means no bound.
	MaxCost uint64
	// MinSaltLen and MaxSaltLen bound the salt's length in bytes; zero means
	// no bound beyond Argon2id's own 8. Equal values fix it (the platform's
	// policy: exactly 16).
	MinSaltLen, MaxSaltLen int
}

// Sizes the scheme fixes.
const (
	KeyLen   = 32
	NonceLen = 12
	TagLen   = 16
	// minSaltLen is what the reference Argon2id implementation
	// (@noble/hashes) accepts.
	minSaltLen = 8
)

// Profile is everything a product chooses about the scheme.
type Profile struct {
	// AuthLabel and WrapLabel are the HKDF infos of the two branches.
	AuthLabel, WrapLabel string
	// RecoveryKeyLabel and RecoveryProofLabel are the HKDF infos of the two
	// branches of a recovery code.
	RecoveryKeyLabel, RecoveryProofLabel string

	// WrapHeader prefixes every wrap envelope: header ‖ nonce ‖ ciphertext ‖ tag.
	WrapHeader []byte
	// LegacyV1 also opens the header-less nonce ‖ ciphertext ‖ tag form with
	// no AAD, reporting it as stale.
	LegacyV1 bool

	// Prepare turns a password into the bytes Argon2id reads. Nil means its
	// UTF-8 bytes, unchanged. Derive clears the slice it returns.
	Prepare func(password string) ([]byte, error)
	// Bounds, when set, are enforced before any derivation.
	Bounds *Bounds
	// Encoding writes the auth key and the recovery proof as text. Nil means
	// standard base64 with padding.
	Encoding *base64.Encoding
	// NormaliseRecovery canonicalises a typed recovery code into the text
	// whose UTF-8 bytes are the HKDF input. Nil means NormaliseRecoveryCode.
	NormaliseRecovery func(code string) (string, error)
}

func (p Profile) encoding() *base64.Encoding {
	if p.Encoding == nil {
		return base64.StdEncoding
	}
	return p.Encoding
}

// Error carries the failure as codes, never as user text: the code is one of
// password, kdf, wrap and recovery, and the reason says which check failed.
// Products translate them.
type Error struct {
	Code, Reason string
	Err          error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("account: %s: %s: %v", e.Code, e.Reason, e.Err)
	}
	return fmt.Sprintf("account: %s: %s", e.Code, e.Reason)
}

func (e *Error) Unwrap() error { return e.Err }

// Is matches on code and reason, so errors.Is(err, ErrWrongKey) works.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code && t.Reason == e.Reason
}

// The failures, as values errors.Is matches.
var (
	ErrUnsupportedAlg = &Error{Code: "kdf", Reason: "unsupported_alg"}
	ErrKDFFailed      = &Error{Code: "kdf", Reason: "kdf_failed"}
	ErrOutOfBounds    = &Error{Code: "kdf", Reason: "out_of_bounds"}
	ErrPassword       = &Error{Code: "password", Reason: "rejected"}
	ErrTruncated      = &Error{Code: "wrap", Reason: "truncated"}
	ErrWrongKey       = &Error{Code: "wrap", Reason: "wrong_key"}
	ErrBadKey         = &Error{Code: "wrap", Reason: "bad_key"}
	ErrRecoveryLength = &Error{Code: "recovery", Reason: "recovery_length"}
)

// CheckSalt reports whether a salt has a length this profile derives with.
func (p Profile) CheckSalt(salt []byte) error {
	b := p.Bounds
	if b == nil {
		return nil
	}
	if (b.MinSaltLen > 0 && len(salt) < b.MinSaltLen) || (b.MaxSaltLen > 0 && len(salt) > b.MaxSaltLen) {
		return ErrOutOfBounds
	}
	return nil
}

// Check reports whether params are ones this profile derives with.
func (p Profile) Check(params KDFParams) error {
	if params.Alg != "argon2id" {
		return ErrUnsupportedAlg
	}
	b := p.Bounds
	if b == nil {
		return nil
	}
	if params.M < b.Min.M || params.M > b.Max.M || params.T < b.Min.T || params.T > b.Max.T ||
		params.P < b.Min.P || params.P > b.Max.P || (b.MaxCost > 0 && uint64(params.M)*uint64(params.T) > b.MaxCost) {
		return ErrOutOfBounds
	}
	return nil
}

// Derived is what a password becomes. Neither half is the password.
type Derived struct {
	// AuthKey is Auth in the profile's text encoding: what is sent.
	//
	// Deprecated: a string cannot be cleared. Use AuthText, the same text as
	// bytes the caller clears. Derive and DerivePrepared still fill AuthKey;
	// DeriveBytes and DerivePreparedBytes leave it empty and make no string.
	AuthKey string
	// Auth is the branch that proves who you are.
	Auth []byte
	// Wrap is the branch that opens the account's key. It never leaves.
	Wrap []byte
	// AuthText is Auth in the profile's text encoding, as bytes: what is
	// sent. Every derivation fills it; the caller clears it with Auth and
	// Wrap (Clear).
	AuthText []byte
}

// Clear zeroes the bytes d holds: AuthText, Auth and Wrap. AuthKey, a
// string, cannot be cleared; DeriveBytes and DerivePreparedBytes leave it
// empty.
func (d *Derived) Clear() {
	if d != nil {
		clear(d.AuthText)
		clear(d.Auth)
		clear(d.Wrap)
	}
}

// Derive runs Argon2id over the prepared password and splits the result:
//
//	master = Argon2id(prepared, salt, m, t, p, dkLen = 32, version 0x13)
//	auth   = HKDF-SHA256(IKM = master, salt = ∅, info = AuthLabel, L = 32)
//	wrap   = HKDF-SHA256(IKM = master, salt = ∅, info = WrapLabel, L = 32)
//
// The parameters and the salt are checked against the profile's bounds
// before anything is derived. The prepared password and the master key are
// cleared before it returns. It fills AuthText and the deprecated AuthKey,
// a string nothing can clear; DeriveBytes makes none.
func Derive(p Profile, password string, salt []byte, params KDFParams) (Derived, error) {
	return p.derivePassword(password, salt, params, true)
}

// DeriveBytes is Derive without the deprecated string: it fills Auth, Wrap
// and AuthText, which the caller clears (Derived.Clear), and leaves AuthKey
// empty, so nothing the derivation makes is beyond the caller's reach.
func DeriveBytes(p Profile, password string, salt []byte, params KDFParams) (Derived, error) {
	return p.derivePassword(password, salt, params, false)
}

// DerivePrepared is Derive for a password the caller has already prepared:
// the bytes Argon2id reads, such as a profile's own preparation produced
// them. The profile's Prepare is not called. The parameters and the salt are
// checked exactly as Derive checks them, before anything is derived, and the
// master key is cleared before it returns; prepared stays the caller's to
// clear. It fills AuthText and the deprecated AuthKey; DerivePreparedBytes
// makes no string.
func DerivePrepared(p Profile, prepared, salt []byte, params KDFParams) (Derived, error) {
	if err := p.checkDerivation(salt, params); err != nil {
		return Derived{}, err
	}
	return p.derive(prepared, salt, params, true)
}

// DerivePreparedBytes is DerivePrepared without the deprecated string: it
// fills Auth, Wrap and AuthText, which the caller clears (Derived.Clear),
// and leaves AuthKey empty. prepared stays the caller's to clear.
func DerivePreparedBytes(p Profile, prepared, salt []byte, params KDFParams) (Derived, error) {
	if err := p.checkDerivation(salt, params); err != nil {
		return Derived{}, err
	}
	return p.derive(prepared, salt, params, false)
}

// derivePassword is Derive and DeriveBytes: the bounds, the profile's
// preparation, and the derivation, with the prepared bytes cleared after.
func (p Profile) derivePassword(password string, salt []byte, params KDFParams, withString bool) (Derived, error) {
	if err := p.checkDerivation(salt, params); err != nil {
		return Derived{}, err
	}
	prepared := []byte(password)
	if p.Prepare != nil {
		var err error
		if prepared, err = p.Prepare(password); err != nil {
			return Derived{}, &Error{Code: "password", Reason: "rejected", Err: err}
		}
	}
	// Clearing is best effort in Go: the runtime may have copied the buffer,
	// and the password string itself cannot be cleared.
	defer clear(prepared)
	return p.derive(prepared, salt, params, withString)
}

// checkDerivation is what Derive and DerivePrepared refuse before deriving:
// the profile's bounds, then Argon2id's own limits.
func (p Profile) checkDerivation(salt []byte, params KDFParams) error {
	if err := p.Check(params); err != nil {
		return err
	}
	if err := p.CheckSalt(salt); err != nil {
		return err
	}
	// The limits the reference implementation enforces. x/crypto/argon2
	// would panic on some of them and round others silently.
	if params.T < 1 || params.P < 1 || params.M < 8*uint32(params.P) || len(salt) < minSaltLen {
		return ErrKDFFailed
	}
	return nil
}

// derive runs Argon2id over prepared bytes and splits the master key. It
// fills AuthText, and with withString the deprecated AuthKey too.
func (p Profile) derive(prepared, salt []byte, params KDFParams, withString bool) (Derived, error) {
	master := argon2.IDKey(prepared, salt, params.T, params.M, params.P, KeyLen)
	defer clear(master)
	auth, err := hkdf.Key(sha256.New, master, nil, p.AuthLabel, KeyLen)
	if err != nil {
		return Derived{}, &Error{Code: "kdf", Reason: "kdf_failed", Err: err}
	}
	wrap, err := hkdf.Key(sha256.New, master, nil, p.WrapLabel, KeyLen)
	if err != nil {
		clear(auth)
		return Derived{}, &Error{Code: "kdf", Reason: "kdf_failed", Err: err}
	}
	enc := p.encoding()
	d := Derived{Auth: auth, Wrap: wrap, AuthText: make([]byte, enc.EncodedLen(len(auth)))}
	enc.Encode(d.AuthText, auth)
	if withString {
		d.AuthKey = string(d.AuthText)
	}
	return d, nil
}

// Wrap seals plaintext (an account key, or a platform root) under a wrap key:
//
//	WrapHeader ‖ nonce (12) ‖ AES-256-GCM(wrapKey, nonce, plaintext, aad) ‖ tag
func Wrap(p Profile, wrapKey, plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("account: entropy: %w", err)
	}
	return wrap(p, wrapKey, nonce, plaintext, aad)
}

func wrap(p Profile, wrapKey, nonce, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(wrapKey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(p.WrapHeader)+NonceLen+len(plaintext)+TagLen)
	out = append(out, p.WrapHeader...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, aad), nil
}

// Unwrap reverses Wrap. A blob that carries the profile's header is opened
// with aad first; a profile with LegacyV1 then tries the header-less form with
// no AAD and reports stale, so the caller re-wraps it. A wrong key and a wrong
// AAD are the same failure: ErrWrongKey.
func Unwrap(p Profile, wrapKey, blob, aad []byte) (plaintext []byte, stale bool, err error) {
	gcm, err := newGCM(wrapKey)
	if err != nil {
		return nil, false, err
	}
	h := len(p.WrapHeader)
	if len(blob) > NonceLen+h && string(blob[:h]) == string(p.WrapHeader) {
		if pt, err := gcm.Open(nil, blob[h:h+NonceLen], blob[h+NonceLen:], aad); err == nil {
			return pt, false, nil
		}
	}
	if !p.LegacyV1 {
		if len(blob) < h+NonceLen+TagLen {
			return nil, false, ErrTruncated
		}
		return nil, false, ErrWrongKey
	}
	if len(blob) <= NonceLen {
		return nil, false, ErrTruncated
	}
	pt, err := gcm.Open(nil, blob[:NonceLen], blob[NonceLen:], nil)
	if err != nil {
		return nil, false, ErrWrongKey
	}
	return pt, true, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeyLen {
		return nil, ErrBadKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, &Error{Code: "wrap", Reason: "bad_key", Err: err}
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, &Error{Code: "wrap", Reason: "bad_key", Err: err}
	}
	return gcm, nil
}
