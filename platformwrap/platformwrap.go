// Package platformwrap is a product's wrap of its account key under a key
// derived from sk_p, the product key the platform's id. delivers to the
// product's page (SPEC section 6.8, sections 11.4 and 11.12). The account key
// (section 6.4, the X25519 key the product's grants and records are sealed
// to) is kept, not replaced: whoever holds sk_p opens the wrap, and below it
// the hierarchy is the one a password account has. A Profile holds a
// product's labels: Wappie's wrap (the platform's decision 0023) is this
// construction under profiles/wappie.PlatformWrap(), and Mailie's under
// profiles/mailie.PlatformWrap().
//
//	K_pw = HKDF-SHA256(IKM = sk_p (32 bytes), salt = UTF-8(profile salt),
//	                   info = JCS([label, 1, user_id, sub, product_key_id]), L = 32)
//	aad  = JCS([label, 1, user_id, sub, product_key_id, base64url(account_public_key)])
//	wrap = 0x03 || nonce (12) || AES-256-GCM(K_pw, nonce, account_key (32), aad)       61 bytes
//
// user_id is the product's id of the account (the sub itself for an account
// created through id., the product's old id for a linked one), sub is id.'s
// account id, both lowercase hyphenated UUIDs; product_key_id is the
// profile's product, ":" and an epoch; base64url is without padding. Every
// element is in the restricted alphabet of section 11.1, so the JSON is the
// same from any serialiser.
//
// It is symmetric on purpose. An HPKE seal to pk_p could be made by anyone
// holding pk_p, the product's server included, which could then plant an
// account key of its choosing; only a holder of sk_p makes this wrap. Seal
// opens what it made and compares (the self-test), and Open checks that the
// key it opened is the private half of the binding's account public key. A
// product's server never opens a wrap; it checks its shape (CheckShape).
//
// Generalised in v0.6.0 from Wappie's platform wrap (v0.5.0), which came from
// Wappie's console (github.com/thehappieco/wappie-cloud, platformwrap/ at
// 3bfee27) with its first byte 0x03 where the console had 0x01.
package platformwrap

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
	// Header is the first byte of every product's wrap. A product's other
	// 61-byte envelopes of its account key must not start with it (Wappie's
	// start with 0x01, its passkey envelope, and 0x02, its password and
	// recovery wraps), so a wrap in the wrong column fails at its header,
	// not at its tag.
	Header = 0x03
	// Len is a wrap's length: the header, the nonce, the 32-byte account
	// key and the tag.
	Len = 1 + nonceLen + keyLen + 16
	// Version is the format's version, the 1 in the info and the AAD.
	Version = 1

	nonceLen = 12
	keyLen   = 32
)

// ErrPlatformWrap is every failure to make or open a wrap. Which check
// failed is not said beyond the message, and no message repeats a key.
var ErrPlatformWrap = errors.New("platformwrap: the platform wrap is malformed, does not open, or names another account")

// Profile is a product's labels. Its values are wire format: a wrap opens
// only under the profile it was sealed under.
type Profile struct {
	// Product is the product of the product key ids a wrap is made for, a
	// product id of SPEC section 11.4 ("wappie").
	Product string
	// Salt is the HKDF salt of K_pw ("wappie/platform-wrap/v1").
	Salt string
	// Label opens the HKDF info and the AAD ("wappie/platform-wrap").
	Label string
}

// check refuses a profile that names no product id (section 11.4) or whose
// salt or label is not a non-empty string of the restricted JSON AAD's
// alphabet (section 11.1), before anything is derived.
func (p Profile) check() error {
	if !platform.ValidProduct(p.Product) || !restricted(p.Salt) || !restricted(p.Label) {
		return fmt.Errorf("%w: not a platform-wrap profile", ErrPlatformWrap)
	}
	return nil
}

// restricted is a non-empty string of [A-Za-z0-9._:/|@-] (section 11.1).
func restricted(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("._:/|@-", c) >= 0) {
			return false
		}
	}
	return true
}

// Binding is what a wrap is bound to.
type Binding struct {
	// UserID is the product's id of the account (Wappie's users.id).
	UserID string
	// Sub is id.'s account id.
	Sub string
	// ProductKeyID is the profile's product, ":" and an epoch ("wappie:1").
	ProductKeyID string
	// AccountPublicKey is the account key's public half, as the product's
	// server holds it (Wappie's users.public_key).
	AccountPublicKey []byte
}

func (b Binding) check(p Profile) error {
	if err := p.check(); err != nil {
		return err
	}
	switch {
	case !platform.ValidSub(b.UserID):
		return fmt.Errorf("%w: user_id is not a lowercase UUID", ErrPlatformWrap)
	case !platform.ValidSub(b.Sub):
		return fmt.Errorf("%w: sub is not a lowercase UUID", ErrPlatformWrap)
	case !platform.ValidProductKeyID(b.ProductKeyID) || !strings.HasPrefix(b.ProductKeyID, p.Product+":"):
		return fmt.Errorf("%w: product_key_id is not a product key id of %s", ErrPlatformWrap, p.Product)
	case len(b.AccountPublicKey) != keyLen:
		return fmt.Errorf("%w: the account public key is not 32 bytes", ErrPlatformWrap)
	}
	return nil
}

// Info is the HKDF info of K_pw: JCS([label, 1, user_id, sub, product_key_id]).
func Info(p Profile, b Binding) ([]byte, error) {
	if err := b.check(p); err != nil {
		return nil, err
	}
	return platform.JCSArray(p.Label, Version, b.UserID, b.Sub, b.ProductKeyID)
}

// AAD is the AES-GCM additional data of a wrap:
// JCS([label, 1, user_id, sub, product_key_id, base64url(account_public_key)]).
func AAD(p Profile, b Binding) ([]byte, error) {
	if err := b.check(p); err != nil {
		return nil, err
	}
	return platform.JCSArray(p.Label, Version, b.UserID, b.Sub, b.ProductKeyID, platform.EncodeB64(b.AccountPublicKey))
}

// aead is AES-256-GCM under K_pw; K_pw is cleared once the cipher holds it.
func aead(p Profile, productKey []byte, b Binding) (cipher.AEAD, error) {
	if len(productKey) != keyLen {
		return nil, fmt.Errorf("%w: the product key is not 32 bytes", ErrPlatformWrap)
	}
	info, err := Info(p, b)
	if err != nil {
		return nil, err
	}
	k, err := hkdf.Key(sha256.New, productKey, []byte(p.Salt), string(info), keyLen)
	if err != nil {
		return nil, ErrPlatformWrap
	}
	defer clear(k)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, ErrPlatformWrap
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrPlatformWrap
	}
	return gcm, nil
}

// publicKey is X25519(key, 9).
func publicKey(key []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil {
		return nil, ErrPlatformWrap
	}
	return priv.PublicKey().Bytes(), nil
}

// Seal wraps the 32-byte account key under the product key sk_p for b, with
// a nonce read from r (crypto/rand when nil; a fixed reader replays a
// vector). It refuses, before anything is encrypted, an account key that is
// not 32 bytes or whose public half is not b.AccountPublicKey (compared in
// constant time), a product key that is not 32 bytes, and a profile or a
// binding outside its spelling; and it opens what it made and compares
// before it returns it. productKey and accountKey are the caller's.
func Seal(p Profile, r io.Reader, productKey, accountKey []byte, b Binding) ([]byte, error) {
	if len(accountKey) != keyLen {
		return nil, fmt.Errorf("%w: the account key is not 32 bytes", ErrPlatformWrap)
	}
	pub, err := publicKey(accountKey)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(pub, b.AccountPublicKey) != 1 {
		return nil, fmt.Errorf("%w: the account key is not the binding's", ErrPlatformWrap)
	}
	gcm, err := aead(p, productKey, b)
	if err != nil {
		return nil, err
	}
	aad, err := AAD(p, b)
	if err != nil {
		return nil, err
	}
	if r == nil {
		r = rand.Reader
	}
	out := make([]byte, 1+nonceLen, Len)
	out[0] = Header
	if _, err := io.ReadFull(r, out[1:]); err != nil {
		return nil, fmt.Errorf("%w: no nonce", ErrPlatformWrap)
	}
	out = gcm.Seal(out, out[1:1+nonceLen], accountKey, aad)
	again, err := Open(p, productKey, out, b)
	if err != nil {
		return nil, fmt.Errorf("%w: the new wrap failed its self-test", ErrPlatformWrap)
	}
	defer clear(again)
	if subtle.ConstantTimeCompare(again, accountKey) != 1 {
		return nil, fmt.Errorf("%w: the new wrap failed its self-test", ErrPlatformWrap)
	}
	return out, nil
}

// Open opens a wrap with the product key sk_p for b and returns the account
// key, which the caller clears. It checks the shape first (CheckShape), then
// the profile, the binding, the product key and the tag, and that the key it
// opened is the private half of b.AccountPublicKey, compared in constant
// time; a key that is not is cleared and refused. The caller also compares
// b.AccountPublicKey with the one the product's server holds for the account.
func Open(p Profile, productKey, wrap []byte, b Binding) ([]byte, error) {
	if err := CheckShape(wrap); err != nil {
		return nil, err
	}
	gcm, err := aead(p, productKey, b)
	if err != nil {
		return nil, err
	}
	aad, err := AAD(p, b)
	if err != nil {
		return nil, err
	}
	key, err := gcm.Open(nil, wrap[1:1+nonceLen], wrap[1+nonceLen:], aad)
	if err != nil || len(key) != keyLen {
		clear(key)
		return nil, ErrPlatformWrap
	}
	pub, err := publicKey(key)
	if err != nil || subtle.ConstantTimeCompare(pub, b.AccountPublicKey) != 1 {
		clear(key)
		return nil, ErrPlatformWrap
	}
	return key, nil
}

// CheckShape is what a product's server checks of a wrap it is sent, which
// it cannot open: Len (61) bytes starting with Header (0x03). It is the same
// for every product: a wrap of one product is the shape of another's, and a
// product keeps its wraps in a column of its own.
func CheckShape(wrap []byte) error {
	if len(wrap) != Len || wrap[0] != Header {
		return fmt.Errorf("%w: not a wrap of %d bytes starting with 0x%02x", ErrPlatformWrap, Len, Header)
	}
	return nil
}
