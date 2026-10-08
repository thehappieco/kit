// Package mailie is the Mailie profile: the labels Mailie seals and wraps
// under. Its values are wire format. Since v0.6.0 it holds Mailie's
// platform wrap (SPEC section 6.8 and Appendix D): Mailie's account key
// under a key derived from its product key sk_p, the kit's generic
// platformwrap under Mailie's labels. Mailie's other labels join this
// package when its scheme has vectors (SPEC section 3.3).
package mailie

import "github.com/thehappieco/kit/platformwrap"

const (
	// PlatformWrapLabel opens the HKDF info and the AAD of Mailie's
	// platform wrap.
	PlatformWrapLabel = "mailie/platform-wrap"
	// PlatformWrapSalt is the HKDF salt of Mailie's K_pw.
	PlatformWrapSalt = "mailie/platform-wrap/v1"
	// PlatformWrapProduct is the product of the product key ids Mailie's
	// wraps are made for, "mailie:<epoch>".
	PlatformWrapProduct = "mailie"
)

// PlatformWrap is Mailie's platform-wrap profile, for package platformwrap:
//
//	platformwrap.Seal(mailie.PlatformWrap(), nil, productKey, accountKey, b)
//
// None of Mailie's other envelopes of its account key may start with
// platformwrap.Header (0x03), and Mailie keeps its wraps in a column of
// their own: the shape of a wrap is the same for every product.
func PlatformWrap() platformwrap.Profile {
	return platformwrap.Profile{Product: PlatformWrapProduct, Salt: PlatformWrapSalt, Label: PlatformWrapLabel}
}
