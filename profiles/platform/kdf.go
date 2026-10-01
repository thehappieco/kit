package platform

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/thehappieco/kit/account"
)

// KDF bounds (section 11.3). They are constants on purpose: the server
// cannot move them, and raising the floor is a new protocol version.
const (
	KDFAlg = "argon2id"

	KDFMinM = 65536 // KiB
	KDFMaxM = 262144
	KDFMinT = 3
	KDFMaxT = 10
	KDFMinP = 1
	KDFMaxP = 4
	// KDFMaxMT caps m × t, so that the slowest accepted parameters still
	// finish on a phone.
	KDFMaxMT = 1048576

	// SaltLen is the only accepted salt length.
	SaltLen = 16
	// KeyLen is the length of every derived key and of the root.
	KeyLen = 32
)

// KDF holds the Argon2id parameters stored with an account and sent in a
// login challenge. M is in KiB. P is 32 bits wide, unlike
// account.KDFParams', so that a server or a bundle saying "p": 300 is
// refused by Check (kdf_policy) rather than by the JSON decoder.
type KDF struct {
	Alg string `json:"alg"`
	M   uint32 `json:"m"`
	T   uint32 `json:"t"`
	P   uint32 `json:"p"`
}

// DefaultKDF is what sign-up uses and what a login challenge for an unknown
// address answers. It is the floor, and account.DefaultKDFParams.
var DefaultKDF = KDF{Alg: KDFAlg, M: KDFMinM, T: KDFMinT, P: KDFMinP}

// Check refuses parameters outside the bounds of section 11.3, wrapping
// ErrKDFPolicy. A client calls it before deriving anything; the server calls
// it before storing anything.
func (k KDF) Check() error {
	switch {
	case k.Alg != KDFAlg:
		return fmt.Errorf("%w: alg is not %s", ErrKDFPolicy, KDFAlg)
	case k.M < KDFMinM || k.M > KDFMaxM:
		return fmt.Errorf("%w: m=%d outside [%d, %d]", ErrKDFPolicy, k.M, KDFMinM, KDFMaxM)
	case k.T < KDFMinT || k.T > KDFMaxT:
		return fmt.Errorf("%w: t=%d outside [%d, %d]", ErrKDFPolicy, k.T, KDFMinT, KDFMaxT)
	case k.P < KDFMinP || k.P > KDFMaxP:
		return fmt.Errorf("%w: p=%d outside [%d, %d]", ErrKDFPolicy, k.P, KDFMinP, KDFMaxP)
	case uint64(k.M)*uint64(k.T) > KDFMaxMT:
		return fmt.Errorf("%w: m*t=%d over %d", ErrKDFPolicy, uint64(k.M)*uint64(k.T), KDFMaxMT)
	}
	return nil
}

// Params returns k as package account's parameters. It is meaningful only
// for parameters Check accepts: P is narrowed to 8 bits.
func (k KDF) Params() account.KDFParams {
	return account.KDFParams{Alg: k.Alg, M: k.M, T: k.T, P: uint8(k.P)}
}

// CheckSalt refuses a salt that is not exactly 16 bytes, wrapping
// ErrKDFPolicy. An account's salt is the server's, fixed per address
// (section 11.3): nothing in this package draws one.
func CheckSalt(salt []byte) error {
	if len(salt) != SaltLen {
		return fmt.Errorf("%w: salt of %d bytes, not %d", ErrKDFPolicy, len(salt), SaltLen)
	}
	return nil
}

// PasswordKeys are the two keys derived from a password. Auth is sent to the
// server (as auth_key); Wrap never leaves the client.
type PasswordKeys struct {
	Auth [KeyLen]byte // K_auth
	Wrap [KeyLen]byte // K_wrap
}

// AuthKey returns auth_key, the base64url of K_auth, as sent on the wire.
func (k *PasswordKeys) AuthKey() string { return EncodeB64(k.Auth[:]) }

// Zero clears both keys.
func (k *PasswordKeys) Zero() {
	if k != nil {
		clear(k.Auth[:])
		clear(k.Wrap[:])
	}
}

// deriveFn is account.DerivePrepared. It is a variable only so that a test
// can prove the bounds are checked before anything is derived.
var deriveFn = account.DerivePrepared

// DerivePassword derives K_auth and K_wrap from a prepared password (section
// 11.3): account.DerivePrepared with Account(). It refuses parameters and
// salts outside the bounds before it runs Argon2id, so a server that answers
// absurd parameters cannot make the client spend memory or time, nor
// downgrade it. The caller clears prepared.
func DerivePassword(prepared, salt []byte, k KDF) (*PasswordKeys, error) {
	if err := k.Check(); err != nil {
		return nil, err
	}
	if err := CheckSalt(salt); err != nil {
		return nil, err
	}
	d, err := deriveFn(Account(), prepared, salt, k.Params())
	if err != nil {
		// Unreachable once Check has passed: account's bounds are the same.
		return nil, fmt.Errorf("%w: %w", ErrKDFPolicy, err)
	}
	defer clear(d.Auth)
	defer clear(d.Wrap)
	keys := &PasswordKeys{}
	copy(keys.Auth[:], d.Auth)
	copy(keys.Wrap[:], d.Wrap)
	return keys, nil
}

// DerivePasswordKeys prepares a presented password and derives its keys
// under the parameters and salt of a login or unlock challenge, or of a key
// bundle.
func DerivePasswordKeys(password string, k KDF, salt []byte) (*PasswordKeys, error) {
	// The bounds come first even here: a refused challenge must not depend on
	// what the user typed.
	if err := k.Check(); err != nil {
		return nil, err
	}
	if err := CheckSalt(salt); err != nil {
		return nil, err
	}
	prepared, err := PreparePassword(password)
	if err != nil {
		return nil, err
	}
	defer clear(prepared)
	return DerivePassword(prepared, salt, k)
}

// NewRoot returns a fresh 32-byte account root read from r, or from
// crypto/rand when r is nil. The caller clears it.
func NewRoot(r io.Reader) ([]byte, error) { return readRandom(r, KeyLen) }

func readRandom(r io.Reader, n int) ([]byte, error) {
	if r == nil {
		r = rand.Reader
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, fmt.Errorf("platform: read random: %w", err)
	}
	return b, nil
}
