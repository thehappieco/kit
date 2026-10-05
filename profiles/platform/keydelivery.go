package platform

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"github.com/thehappieco/kit/hpke"
)

// Key delivery (section 11.12). The id. page seals the product's private
// key sk_p to an X25519 key that only the product's page holds (akd_pub),
// and the blob reaches that page through the token response. The id. server
// stores and forwards it and can never open it.
//
//	info = "thehappie-id/v1/key-delivery"
//	aad  = JCS(["thehappie-id/key-delivery", 1, iss, client_id, redirect_uri, sub,
//	            product_key_id, b64url(pk_p), code_challenge, nonce])
//	(enc, ct)  = HPKE.SealBase(pkR = akd_pub, info, aad, pt = sk_p)   RFC 9180, single shot
//	akd_sealed = enc (32) || ct (32) || tag (16)                       80 bytes
//
// The rule it enforces: a sealed key opens only in the flow it was sealed
// for (that issuer, client, redirect URI, account, product key, PKCE
// challenge and nonce), only with the ephemeral key of the page that asked,
// and only if what it carries is the private half of the product key the
// binding names. The suite is package hpke's, fixed: DHKEM(X25519,
// HKDF-SHA256), HKDF-SHA256, AES-256-GCM, base mode.
//
// What it does not do: HPKE base mode does not authenticate the sender.
// Anyone who knows akd_pub can seal a key of their choosing under a binding
// they also write into an ID token, and it opens and matches. A relying
// party keeps a delivered key only once its own server has named the same
// sub, product_key_id and product_key from its insert-only pin (section
// 11.14 step 9, section 11.15; packages oidcrp and @thehappieco/kit/oidc-rp).

const (
	// SealedProductKeyLen is the length of every akd_sealed: the 32-byte
	// encapsulated key, the 32-byte ciphertext of sk_p and the 16-byte tag.
	SealedProductKeyLen = 80
	// KeyDeliveryInfo is the HPKE info of every key delivery. Discovery
	// publishes it.
	KeyDeliveryInfo = "thehappie-id/v1/key-delivery"
	// KeyDeliverySuite names the HPKE suite as discovery publishes it.
	KeyDeliverySuite = "DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM"

	keyDeliveryAADLabel = "thehappie-id/key-delivery"
	keyDeliveryVersion  = 1
	// The nonce's lengths and alphabet are those of the authorization
	// request.
	minNonceLen = 22
	maxNonceLen = 128
)

// KeyDeliveryBinding is the flow a key delivery is bound to through its AAD.
// The relying party rebuilds it from its own flow record (issuer, client,
// redirect URI, code challenge, nonce) and from the ID token (sub,
// product_key_id, product_key), so a blob moved to any other flow does not
// open.
type KeyDeliveryBinding struct {
	Issuer      string // the issuer, exactly, for example "https://id.thehappie.co"
	ClientID    string
	RedirectURI string
	Sub         string // lowercase hyphenated UUID
	// ProductKeyID is product + ":" + decimal(epoch), for example "wappie:1".
	ProductKeyID string
	// ProductKey is pk_p, the 32-byte public half of the product key; the
	// AAD carries its base64url.
	ProductKey    []byte
	CodeChallenge string // 43 characters of base64url
	Nonce         string // 22 to 128 characters from [A-Za-z0-9_-]
}

// KeyDeliveryAAD returns the JCS array a key delivery is sealed under:
//
//	["thehappie-id/key-delivery",1,iss,client_id,redirect_uri,sub,product_key_id,pk_p_b64url,code_challenge,nonce]
//
// Every field has exactly one spelling, so the page and the relying party
// either build the same bytes or both refuse. It refuses, wrapping
// ErrKeyDelivery:
//
//   - an issuer, client id or redirect URI that is empty or holds a
//     character outside [A-Za-z0-9._:/|@-] (section 11.1);
//   - a sub that is not a lowercase hyphenated UUID;
//   - a product key id that is not a valid product id, ":", and an epoch from
//     1 to 2^31 - 1 in decimal without leading zeros;
//   - a product key that is not 32 bytes;
//   - a code challenge that is not 43 characters of strict base64url;
//   - a nonce that is not 22 to 128 characters from [A-Za-z0-9_-].
func KeyDeliveryAAD(b KeyDeliveryBinding) ([]byte, error) {
	if err := b.check(); err != nil {
		return nil, err
	}
	aad, err := JCSArray(keyDeliveryAADLabel, keyDeliveryVersion, b.Issuer, b.ClientID, b.RedirectURI,
		b.Sub, b.ProductKeyID, EncodeB64(b.ProductKey), b.CodeChallenge, b.Nonce)
	if err != nil {
		// check has already refused every value JCSArray would; the inner
		// error is not wrapped so the result keeps the key_delivery name.
		return nil, fmt.Errorf("%w: the binding has no AAD", ErrKeyDelivery)
	}
	return aad, nil
}

func (b KeyDeliveryBinding) check() error {
	for _, f := range []struct{ name, v string }{
		{"issuer", b.Issuer}, {"client id", b.ClientID}, {"redirect uri", b.RedirectURI},
	} {
		if f.v == "" || !jcsText(f.v) {
			return fmt.Errorf("%w: the %s is empty or outside the AAD alphabet", ErrKeyDelivery, f.name)
		}
	}
	if !ValidSub(b.Sub) {
		return fmt.Errorf("%w: the sub is not a lowercase UUID", ErrKeyDelivery)
	}
	if !ValidProductKeyID(b.ProductKeyID) {
		return fmt.Errorf("%w: the product key id is not product:epoch", ErrKeyDelivery)
	}
	if len(b.ProductKey) != KeyLen {
		return fmt.Errorf("%w: a %d-byte product key", ErrKeyDelivery, len(b.ProductKey))
	}
	if !validCodeChallenge(b.CodeChallenge) {
		return fmt.Errorf("%w: the code challenge is not 43 characters of strict base64url", ErrKeyDelivery)
	}
	if !validNonce(b.Nonce) {
		return fmt.Errorf("%w: the nonce is not %d to %d characters from [A-Za-z0-9_-]", ErrKeyDelivery, minNonceLen, maxNonceLen)
	}
	return nil
}

func validNonce(s string) bool {
	if len(s) < minNonceLen || len(s) > maxNonceLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// errCustomRandom refuses a random source SealProductKey cannot use.
var errCustomRandom = errors.New("platform: SealProductKey takes nil or crypto/rand.Reader; crypto/hpke draws the ephemeral key from the system's secure source")

// SealProductKey is the id. page's seal (section 11.12), for Go tests that
// play the browser and for command-line tools: it derives nothing, and seals
// the given 32-byte sk to akdPub under the binding's AAD. It returns the
// 80-byte akd_sealed.
//
// r must be nil or crypto/rand.Reader. crypto/hpke takes no reader: like the
// rest of the standard library since Go 1.26 it draws the ephemeral key from
// the system's secure source (testing/cryptotest.SetGlobalRandom makes that
// deterministic in a test). Any other reader is refused, so a caller who
// expects a fixed reader to give a fixed blob learns that it does not. No
// function of the kit seals under a chosen ephemeral key.
//
// In this order, it checks the binding (KeyDeliveryAAD) and akdPub with the
// rule of section 11.4 (CheckPublicKey), whatever the server checked,
// wrapping ErrKeyDelivery; then that sk is 32 bytes whose public half is
// b.ProductKey, wrapping ErrProductKey, because a key sealed under another
// key's binding stores and travels fine and is refused only by the product.
func SealProductKey(r io.Reader, akdPub, sk []byte, b KeyDeliveryBinding) ([]byte, error) {
	if r != nil && r != rand.Reader {
		return nil, errCustomRandom
	}
	aad, err := KeyDeliveryAAD(b)
	if err != nil {
		return nil, err
	}
	if err := CheckPublicKey(akdPub); err != nil {
		if errors.Is(err, ErrProductKey) {
			// Not wrapped: akd_pub is the delivery's recipient, not a
			// product key, and the result keeps the key_delivery name.
			return nil, fmt.Errorf("%w: akd_pub is not an acceptable X25519 public key", ErrKeyDelivery)
		}
		return nil, err
	}
	if err := matchesProductKey(sk, b.ProductKey); err != nil {
		return nil, err
	}
	pub, err := hpke.ParsePublicKey(akdPub)
	if err != nil {
		return nil, fmt.Errorf("%w: akd_pub is not an X25519 public key", ErrKeyDelivery)
	}
	enc, ct, err := hpke.Seal(pub, []byte(KeyDeliveryInfo), aad, sk)
	if err != nil {
		// CheckPublicKey has refused every key the encapsulation would.
		return nil, fmt.Errorf("%w: akd_pub gives no shared secret", ErrKeyDelivery)
	}
	out := make([]byte, 0, SealedProductKeyLen)
	out = append(out, enc...)
	out = append(out, ct...)
	if len(out) != SealedProductKeyLen {
		return nil, fmt.Errorf("%w: sealed %d bytes, not %d", ErrKeyDelivery, len(out), SealedProductKeyLen)
	}
	return out, nil
}

// OpenProductKey is the relying party's open (section 11.12, and step 7 of
// section 11.14): it opens akd_sealed with the page's ephemeral private key
// under the AAD it rebuilds from b, requires exactly 32 bytes, derives their
// X25519 public key and compares it, in constant time, with b.ProductKey. It
// returns sk_p, which the caller clears once it has kept it.
//
// A blob that is not 80 bytes, a private key that is not 32 bytes, a binding
// with no AAD, an enc that is not the canonical encoding of an X25519 point,
// another recipient, another flow and altered bytes are all ErrKeyDelivery
// and say no more. A blob that opens but carries a key whose public half is
// not b.ProductKey is ErrProductKey: the page sealed another key than the one
// the ID token names, and nothing it carries is returned.
//
// The canonical enc is stricter than RFC 9180, which lets X25519 read the
// other spellings of a point (bit 255 set, or a value from p upwards) as the
// point itself. A sealer that writes such a spelling into both the blob and
// its KEM context makes a blob that crypto/hpke and WebCrypto engines open
// while an engine that refuses to import the spelling would not; an honest
// sealer never writes one, because X25519(skE, 9) is always canonical.
// Refusing it here and in the TypeScript opener gives every blob one
// spelling and every engine one answer, as section 11.4 does for pk_p.
//
// An opened key that matches is still not to be kept until the product's
// server has named it (section 11.14 step 9): base mode does not
// authenticate the sender.
func OpenProductKey(akdPriv, sealed []byte, b KeyDeliveryBinding) ([]byte, error) {
	if len(sealed) != SealedProductKeyLen {
		return nil, fmt.Errorf("%w: %d bytes, not %d", ErrKeyDelivery, len(sealed), SealedProductKeyLen)
	}
	if len(akdPriv) != KeyLen {
		return nil, fmt.Errorf("%w: a %d-byte private key", ErrKeyDelivery, len(akdPriv))
	}
	aad, err := KeyDeliveryAAD(b)
	if err != nil {
		return nil, err
	}
	enc := sealed[:hpke.EncLen]
	if !canonicalX25519(enc) {
		return nil, fmt.Errorf("%w: enc is not a canonical X25519 encoding", ErrKeyDelivery)
	}
	priv, err := hpke.ParsePrivateKey(akdPriv)
	if err != nil {
		return nil, fmt.Errorf("%w: not an X25519 private key", ErrKeyDelivery)
	}
	// A low-order enc fails here: crypto/ecdh refuses the all-zero shared
	// secret, and package hpke reports it as ErrOpen like a failed tag.
	sk, err := hpke.Open(priv, enc, []byte(KeyDeliveryInfo), aad, sealed[hpke.EncLen:])
	if err != nil {
		return nil, ErrKeyDelivery
	}
	if len(sk) != KeyLen {
		clear(sk)
		return nil, fmt.Errorf("%w: opened %d bytes, not %d", ErrKeyDelivery, len(sk), KeyLen)
	}
	if err := matchesProductKey(sk, b.ProductKey); err != nil {
		clear(sk)
		return nil, err
	}
	return sk, nil
}

// matchesProductKey checks that sk is 32 bytes and that X25519(sk, 9) is pub,
// compared in constant time. It wraps ErrProductKey.
func matchesProductKey(sk, pub []byte) error {
	if len(sk) != KeyLen {
		return fmt.Errorf("%w: a %d-byte product private key", ErrProductKey, len(sk))
	}
	priv, err := ecdh.X25519().NewPrivateKey(sk)
	if err != nil {
		return fmt.Errorf("%w: not an X25519 private key", ErrProductKey)
	}
	if subtle.ConstantTimeCompare(priv.PublicKey().Bytes(), pub) != 1 {
		return fmt.Errorf("%w: the key's public half is not the binding's product key", ErrProductKey)
	}
	return nil
}
