package wappie

// Wappie's platform wrap (SPEC section 6.8, the platform's decision 0023):
// Wappie's account key (section 6.4, the X25519 key every grant, the AI
// keychain and the personal contacts are sealed to) wrapped under a key
// derived from sk_p, the product key The Happie Co's id. delivers to
// Wappie's page (section 11.12). The account key is kept, not replaced:
// whoever holds sk_p opens the wrap, and below it the hierarchy is the one a
// password account has.
//
//	K_pw = HKDF-SHA256(IKM = sk_p (32 bytes), salt = UTF-8("wappie/platform-wrap/v1"),
//	                   info = JCS(["wappie/platform-wrap", 1, user_id, sub, product_key_id]), L = 32)
//	aad  = JCS(["wappie/platform-wrap", 1, user_id, sub, product_key_id, base64url(account_public_key)])
//	wrap = 0x03 || nonce (12) || AES-256-GCM(K_pw, nonce, account_key (32), aad)       61 bytes
//
// user_id is Wappie's users.id (the sub itself for an account created
// through id., the old id for a linked one), sub is id.'s account id, both
// lowercase hyphenated UUIDs; product_key_id is "wappie:<epoch>"; base64url
// is without padding. Every element is in the restricted alphabet of
// section 11.1, so the JSON is the same from any serialiser.
//
// It is symmetric on purpose. An HPKE seal to pk_p could be made by anyone
// holding pk_p, the server included, which could then plant an account key
// of its choosing; only a holder of sk_p makes this wrap. SealPlatformWrap
// opens what it made and compares (the self-test), and OpenPlatformWrap
// checks that the key it opened is the private half of the binding's
// account public key. Wappie's server never opens a wrap; it checks its
// shape (CheckPlatformWrapShape). The Go side is for the public command-line
// tool's export opener.
//
// From Wappie's console (github.com/thehappieco/wappie-cloud,
// platformwrap/platformwrap.go at 3bfee27), with its names prefixed for this
// package, CheckPlatformWrapShape added, and its first byte 0x03 where the
// console had 0x01, which is Wappie's passkey envelope's (section 7).

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/thehappieco/kit/profiles/platform"
)

const (
	// PlatformWrapHeader is the first byte of a platform wrap. Wappie's other
	// 61-byte envelopes of the account key start with 0x02 (the password and
	// recovery wraps, section 6.5) and 0x01 (the passkey envelope, section
	// 7), so a wrap in the wrong column fails at its header, not at its tag.
	PlatformWrapHeader = 0x03
	// PlatformWrapLen is a platform wrap's length: the header, the nonce,
	// the 32-byte account key and the tag.
	PlatformWrapLen = 1 + platformWrapNonceLen + platformWrapKeyLen + 16
	// PlatformWrapLabel opens the HKDF info and the AAD.
	PlatformWrapLabel = "wappie/platform-wrap"
	// PlatformWrapSalt is the HKDF salt of K_pw.
	PlatformWrapSalt = "wappie/platform-wrap/v1"
	// PlatformWrapProduct is the product of the product key ids a wrap is
	// made for.
	PlatformWrapProduct = "wappie"

	platformWrapNonceLen = 12
	platformWrapKeyLen   = 32
)

// ErrPlatformWrap is every failure to make or open a platform wrap. Which
// check failed is not said beyond the message, and no message repeats a key.
var ErrPlatformWrap = errors.New("wappie: the platform wrap is malformed, does not open, or names another account")

// PlatformWrapBinding is what a platform wrap is bound to.
type PlatformWrapBinding struct {
	// UserID is Wappie's users.id.
	UserID string
	// Sub is id.'s account id.
	Sub string
	// ProductKeyID is "wappie:<epoch>".
	ProductKeyID string
	// AccountPublicKey is the account key's public half, users.public_key.
	AccountPublicKey []byte
}

func (b PlatformWrapBinding) check() error {
	switch {
	case !platform.ValidSub(b.UserID):
		return fmt.Errorf("%w: user_id is not a lowercase UUID", ErrPlatformWrap)
	case !platform.ValidSub(b.Sub):
		return fmt.Errorf("%w: sub is not a lowercase UUID", ErrPlatformWrap)
	case !platform.ValidProductKeyID(b.ProductKeyID) || !strings.HasPrefix(b.ProductKeyID, PlatformWrapProduct+":"):
		return fmt.Errorf("%w: product_key_id is not a Wappie product key id", ErrPlatformWrap)
	case len(b.AccountPublicKey) != platformWrapKeyLen:
		return fmt.Errorf("%w: the account public key is not 32 bytes", ErrPlatformWrap)
	}
	return nil
}

// PlatformWrapInfo is the HKDF info of K_pw:
// JCS(["wappie/platform-wrap", 1, user_id, sub, product_key_id]).
func PlatformWrapInfo(b PlatformWrapBinding) ([]byte, error) {
	if err := b.check(); err != nil {
		return nil, err
	}
	return platform.JCSArray(PlatformWrapLabel, 1, b.UserID, b.Sub, b.ProductKeyID)
}

// PlatformWrapAAD is the AES-GCM additional data of a platform wrap:
// JCS(["wappie/platform-wrap", 1, user_id, sub, product_key_id,
// base64url(account_public_key)]).
func PlatformWrapAAD(b PlatformWrapBinding) ([]byte, error) {
	if err := b.check(); err != nil {
		return nil, err
	}
	return platform.JCSArray(PlatformWrapLabel, 1, b.UserID, b.Sub, b.ProductKeyID, platform.EncodeB64(b.AccountPublicKey))
}

// platformWrapAEAD is AES-256-GCM under K_pw; K_pw is cleared once the
// cipher holds it.
func platformWrapAEAD(productKey []byte, b PlatformWrapBinding) (cipher.AEAD, error) {
	if len(productKey) != platformWrapKeyLen {
		return nil, fmt.Errorf("%w: the product key is not 32 bytes", ErrPlatformWrap)
	}
	info, err := PlatformWrapInfo(b)
	if err != nil {
		return nil, err
	}
	k, err := hkdf.Key(sha256.New, productKey, []byte(PlatformWrapSalt), string(info), platformWrapKeyLen)
	if err != nil {
		return nil, ErrPlatformWrap
	}
	defer clear(k)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, ErrPlatformWrap
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrPlatformWrap
	}
	return aead, nil
}

// platformWrapPublicKey is X25519(key, 9).
func platformWrapPublicKey(key []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil {
		return nil, ErrPlatformWrap
	}
	return priv.PublicKey().Bytes(), nil
}

// SealPlatformWrap wraps the 32-byte account key under the product key sk_p
// for b, with a nonce read from r (crypto/rand when nil; a fixed reader
// replays a vector, as the platform profile's Wrap does). It refuses, before
// anything is encrypted, an account key that is not 32 bytes or whose public
// half is not b.AccountPublicKey (compared in constant time), a product key
// that is not 32 bytes and a binding outside its spelling; and it opens what
// it made and compares before it returns it. productKey and accountKey are
// the caller's.
func SealPlatformWrap(r io.Reader, productKey, accountKey []byte, b PlatformWrapBinding) ([]byte, error) {
	if len(accountKey) != platformWrapKeyLen {
		return nil, fmt.Errorf("%w: the account key is not 32 bytes", ErrPlatformWrap)
	}
	pub, err := platformWrapPublicKey(accountKey)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(pub, b.AccountPublicKey) != 1 {
		return nil, fmt.Errorf("%w: the account key is not the binding's", ErrPlatformWrap)
	}
	aead, err := platformWrapAEAD(productKey, b)
	if err != nil {
		return nil, err
	}
	aad, err := PlatformWrapAAD(b)
	if err != nil {
		return nil, err
	}
	if r == nil {
		r = rand.Reader
	}
	out := make([]byte, 1+platformWrapNonceLen, PlatformWrapLen)
	out[0] = PlatformWrapHeader
	if _, err := io.ReadFull(r, out[1:]); err != nil {
		return nil, fmt.Errorf("%w: no nonce", ErrPlatformWrap)
	}
	out = aead.Seal(out, out[1:1+platformWrapNonceLen], accountKey, aad)
	again, err := OpenPlatformWrap(productKey, out, b)
	if err != nil {
		return nil, fmt.Errorf("%w: the new wrap failed its self-test", ErrPlatformWrap)
	}
	defer clear(again)
	if subtle.ConstantTimeCompare(again, accountKey) != 1 {
		return nil, fmt.Errorf("%w: the new wrap failed its self-test", ErrPlatformWrap)
	}
	return out, nil
}

// OpenPlatformWrap opens a platform wrap with the product key sk_p for b and
// returns the account key, which the caller clears. It checks the shape
// first (CheckPlatformWrapShape), then the product key, the binding and the
// tag, and that the key it opened is the private half of b.AccountPublicKey,
// compared in constant time; a key that is not is cleared and refused. The
// caller also compares b.AccountPublicKey with the one Wappie's server holds
// for the account (users.public_key).
func OpenPlatformWrap(productKey, wrap []byte, b PlatformWrapBinding) ([]byte, error) {
	if err := CheckPlatformWrapShape(wrap); err != nil {
		return nil, err
	}
	aead, err := platformWrapAEAD(productKey, b)
	if err != nil {
		return nil, err
	}
	aad, err := PlatformWrapAAD(b)
	if err != nil {
		return nil, err
	}
	key, err := aead.Open(nil, wrap[1:1+platformWrapNonceLen], wrap[1+platformWrapNonceLen:], aad)
	if err != nil || len(key) != platformWrapKeyLen {
		clear(key)
		return nil, ErrPlatformWrap
	}
	pub, err := platformWrapPublicKey(key)
	if err != nil || subtle.ConstantTimeCompare(pub, b.AccountPublicKey) != 1 {
		clear(key)
		return nil, ErrPlatformWrap
	}
	return key, nil
}

// CheckPlatformWrapShape is what Wappie's server checks of a platform wrap
// it is sent, which it cannot open: PlatformWrapLen (61) bytes starting with
// PlatformWrapHeader (0x03). A store takes both values from here.
func CheckPlatformWrapShape(wrap []byte) error {
	if len(wrap) != PlatformWrapLen || wrap[0] != PlatformWrapHeader {
		return fmt.Errorf("%w: not a wrap of %d bytes starting with 0x%02x", ErrPlatformWrap, PlatformWrapLen, PlatformWrapHeader)
	}
	return nil
}
