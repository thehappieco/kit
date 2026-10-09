package mailie

import (
	"crypto/ecdh"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/thehappieco/kit/profiles/platform"
)

// KeyLen is the length of every key in Mailie's scheme: X25519 private and
// public keys, wrap keys and the product key.
const KeyLen = 32

// The scheme's own refusals (SPEC Appendix D). Each is a sentinel errors.Is
// matches; the kit's errors (account.ErrWrongKey, seal.ErrAuthentication,
// platformwrap.ErrPlatformWrap, ...) pass through as they are. No message
// repeats a refused value.
var (
	// ErrBinding is an input outside its spelling, refused before anything
	// is derived, sealed or opened: a seal id or namespace that is not a
	// lowercase UUIDv4, a wrap kind other than password and recovery, an
	// epoch outside its range, a key that is not 32 bytes, or a platform
	// wrap's seal id equal to the sub.
	ErrBinding = errors.New("mailie: the binding is outside its spelling")
	// ErrShape is what a server refuses of a value it stores and cannot
	// open: an account wrap, or a grant, of the wrong shape.
	ErrShape = errors.New("mailie: not the shape this column holds")
	// ErrPublicKey is a public key a server refuses to store: not 32
	// bytes, not the canonical encoding of an X25519 point, or of low order.
	ErrPublicKey = errors.New("mailie: not an X25519 public key a server accepts")
)

// ValidSealID reports whether id is a seal id in its one spelling: a version
// 4 UUID of the RFC 9562 variant, as 36 characters of lowercase hyphenated
// text. A seal id is the immutable UUID Mailie's server draws for a person
// and every wrap and grant binds the person by: never the address, and
// never id.'s sub. Upper case, braces, a urn: prefix, another version and the
// nil UUID are refused, never normalised.
func ValidSealID(id string) bool { return validUUIDv4(id) }

// ValidNamespace reports whether ns is a mailbox namespace in its one
// spelling, the same as a seal id's. The browser that makes a mailbox's key
// pair draws it; it is both the tenant and the device of the mailbox's
// grants (SPEC section 4.7).
func ValidNamespace(ns string) bool { return validUUIDv4(ns) }

// validUUIDv4 checks the lowercase hyphenated spelling (the platform's rule
// for a sub, SPEC section 11.1), then the version and variant nibbles.
// uuid.Parse alone would accept upper case, braces and a urn: prefix, which
// are other spellings of the same 16 bytes.
func validUUIDv4(s string) bool {
	if !platform.ValidSub(s) {
		return false
	}
	return s[14] == '4' && (s[19] == '8' || s[19] == '9' || s[19] == 'a' || s[19] == 'b')
}

// parseUUIDv4 returns the 16 bytes of a seal id or a namespace.
func parseUUIDv4(s, what string) (uuid.UUID, error) {
	if !validUUIDv4(s) {
		return uuid.UUID{}, fmt.Errorf("%w: the %s is not a lowercase UUIDv4", ErrBinding, what)
	}
	return uuid.MustParse(s), nil
}

// PublicKey returns X25519(key, 9), the public half of a 32-byte private
// key. Any 32 bytes are a private key (SPEC section 6.4); another length is
// ErrBinding.
func PublicKey(key []byte) ([]byte, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("%w: a private key is %d bytes", ErrBinding, KeyLen)
	}
	priv, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBinding, err)
	}
	return priv.PublicKey().Bytes(), nil
}

// isPublicHalf reports, in constant time, whether pub is X25519(key, 9).
func isPublicHalf(key, pub []byte) bool {
	got, err := PublicKey(key)
	return err == nil && subtle.ConstantTimeCompare(got, pub) == 1
}

// CheckPublicKey is a server's check of a public key it is asked to store
// once and hand to others: a person's account public key and a mailbox's.
// It is the platform's check of a product public key (SPEC section 11.4):
// exactly 32 bytes, the canonical encoding of the point, and not of low
// order, so that a key a server hands out has one spelling and a secret can
// be agreed with it. A refusal matches ErrPublicKey.
func CheckPublicKey(pub []byte) error {
	if err := platform.CheckPublicKey(pub); err != nil {
		return fmt.Errorf("%w: %w", ErrPublicKey, err)
	}
	return nil
}
