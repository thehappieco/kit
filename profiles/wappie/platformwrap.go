package wappie

// Wappie's platform wrap (SPEC section 6.8, the platform's decision 0023):
// Wappie's account key (section 6.4, the X25519 key every grant, the AI
// keychain and the personal contacts are sealed to) wrapped under a key
// derived from sk_p, the product key The Happie Co's id. delivers to
// Wappie's page (section 11.12). Since v0.6.0 it is the kit's generic
// platform wrap (package platformwrap) under Wappie's labels, PlatformWrap();
// every byte is v0.5.0's:
//
//	K_pw = HKDF-SHA256(IKM = sk_p (32 bytes), salt = UTF-8("wappie/platform-wrap/v1"),
//	                   info = JCS(["wappie/platform-wrap", 1, user_id, sub, product_key_id]), L = 32)
//	aad  = JCS(["wappie/platform-wrap", 1, user_id, sub, product_key_id, base64url(account_public_key)])
//	wrap = 0x03 || nonce (12) || AES-256-GCM(K_pw, nonce, account_key (32), aad)       61 bytes
//
// user_id is Wappie's users.id (the sub itself for an account created
// through id., the old id for a linked one); product_key_id is
// "wappie:<epoch>". Wappie's server never opens a wrap; it checks its shape
// (CheckPlatformWrapShape). The Go side is for the public command-line
// tool's export opener.

import (
	"io"

	"github.com/thehappieco/kit/platformwrap"
)

const (
	// PlatformWrapHeader is the first byte of a platform wrap. Wappie's other
	// 61-byte envelopes of the account key start with 0x02 (the password and
	// recovery wraps, section 6.5) and 0x01 (the passkey envelope, section
	// 7), so a wrap in the wrong column fails at its header, not at its tag.
	PlatformWrapHeader = platformwrap.Header
	// PlatformWrapLen is a platform wrap's length: the header, the nonce,
	// the 32-byte account key and the tag.
	PlatformWrapLen = platformwrap.Len
	// PlatformWrapLabel opens the HKDF info and the AAD.
	PlatformWrapLabel = "wappie/platform-wrap"
	// PlatformWrapSalt is the HKDF salt of K_pw.
	PlatformWrapSalt = "wappie/platform-wrap/v1"
	// PlatformWrapProduct is the product of the product key ids a wrap is
	// made for.
	PlatformWrapProduct = "wappie"
)

// PlatformWrap is Wappie's platform-wrap profile.
func PlatformWrap() platformwrap.Profile {
	return platformwrap.Profile{Product: PlatformWrapProduct, Salt: PlatformWrapSalt, Label: PlatformWrapLabel}
}

// ErrPlatformWrap is every failure to make or open a platform wrap: since
// v0.6.0, platformwrap.ErrPlatformWrap itself.
var ErrPlatformWrap = platformwrap.ErrPlatformWrap

// PlatformWrapBinding is what a platform wrap is bound to: UserID is
// Wappie's users.id, Sub id.'s account id, ProductKeyID "wappie:<epoch>" and
// AccountPublicKey users.public_key.
type PlatformWrapBinding = platformwrap.Binding

// PlatformWrapInfo is platformwrap.Info under PlatformWrap().
func PlatformWrapInfo(b PlatformWrapBinding) ([]byte, error) {
	return platformwrap.Info(PlatformWrap(), b)
}

// PlatformWrapAAD is platformwrap.AAD under PlatformWrap().
func PlatformWrapAAD(b PlatformWrapBinding) ([]byte, error) {
	return platformwrap.AAD(PlatformWrap(), b)
}

// SealPlatformWrap is platformwrap.Seal under PlatformWrap().
func SealPlatformWrap(r io.Reader, productKey, accountKey []byte, b PlatformWrapBinding) ([]byte, error) {
	return platformwrap.Seal(PlatformWrap(), r, productKey, accountKey, b)
}

// OpenPlatformWrap is platformwrap.Open under PlatformWrap(). The caller
// clears the key, and compares b.AccountPublicKey with users.public_key.
func OpenPlatformWrap(productKey, wrap []byte, b PlatformWrapBinding) ([]byte, error) {
	return platformwrap.Open(PlatformWrap(), productKey, wrap, b)
}

// CheckPlatformWrapShape is what Wappie's server checks of a platform wrap
// it is sent, which it cannot open: PlatformWrapLen (61) bytes starting with
// PlatformWrapHeader (0x03). A store takes both values from here.
func CheckPlatformWrapShape(wrap []byte) error {
	return platformwrap.CheckShape(wrap)
}
