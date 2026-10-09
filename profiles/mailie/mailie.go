// Package mailie is the Mailie profile (SPEC Appendix D): the labels,
// headers, magic, kinds and additional data with which Mailie wraps a
// person's account key, grants a mailbox's private key to a person, and keeps
// the account key in a browser. Its values are wire format.
//
// v0.6.0 brought Mailie's platform wrap (SPEC section 6.8): its account key
// under a key derived from its product key sk_p, the kit's generic
// platformwrap under Mailie's labels. v0.7.0 adds the rest of Mailie's key
// scheme as Mailie specified it (its docs/key-scheme.md, version 1, at
// github.com/thehappieco/mailie c9c79cf), pinned by Mailie's own vectors
// under vectors/mailie/key-scheme-v1:
//
//   - the account scheme (account.go): Account, package account's profile
//     with Mailie's labels and the platform's password preparation, KDF
//     bounds and canonical recovery code, and the 61-byte password and
//     recovery wraps, header 0x02, bound to the person's seal id, the kind
//     and the account public key;
//   - the seal domain and the grants (grant.go): magic "ML", label "mlv1",
//     Mailie's kinds, and grants of a mailbox's key at
//     GrantRow(namespace, namespace, seal id, epoch), which open only to
//     the mailbox's public key;
//   - the platform wrap's binding (PlatformWrapBinding below): Mailie's user
//     id is the seal id for every person, never id.'s sub;
//   - the browser vault's additional data (browservault.go).
//
// It holds parameters and the checks around them, never a primitive of its
// own: Argon2id and the auth/wrap split are package account, the wrap
// envelope is account.Wrap, a grant is seal.SealDirect, the platform wrap is
// platformwrap, the password preparation and the recovery code are
// profiles/platform's, and the restricted JSON AAD is platform.JCSArray.
// What stays in Mailie: how its server normalises an address and derives the
// salt it hands out (a server's salts are outside the kit, SPEC section 13),
// drawing seal ids and namespaces, the ceremonies, and every server secret.
package mailie

import (
	"fmt"

	"github.com/thehappieco/kit/platformwrap"
	"github.com/thehappieco/kit/profiles/platform"
)

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

// PlatformWrapBinding is what Mailie binds a platform wrap to: the person's
// seal id as the product's user id, id.'s sub, the product key id
// "mailie:<epoch>" Mailie's server pinned at the person's sign-in, and the
// account public key it holds for the person. The user id is the seal id for
// every person, those created through id. included, and never the sub: a
// departure from the wording of SPEC section 6.8, which makes it the sub for
// an account created through id. (SPEC Appendix D). A seal id that is not a
// lowercase UUIDv4, a seal id equal to the sub whatever the sub's version,
// and an epoch outside 1 to 2^31 - 1 are ErrBinding; platformwrap refuses a
// sub or a public key outside their spelling when the wrap is sealed or
// opened. Whatever opens Mailie's export takes the user id from the export,
// which carries each person's seal id beside their wrap, never from the sub.
func PlatformWrapBinding(sealID, sub string, productKeyEpoch int, accountPublicKey []byte) (platformwrap.Binding, error) {
	if !ValidSealID(sealID) {
		return platformwrap.Binding{}, fmt.Errorf("%w: the seal id is not a lowercase UUIDv4", ErrBinding)
	}
	if sealID == sub {
		return platformwrap.Binding{}, fmt.Errorf("%w: the user id is the seal id, never the sub", ErrBinding)
	}
	if productKeyEpoch < 1 || productKeyEpoch > platform.MaxEpoch {
		return platformwrap.Binding{}, fmt.Errorf("%w: a product key epoch is from 1 to %d", ErrBinding, platform.MaxEpoch)
	}
	return platformwrap.Binding{
		UserID:           sealID,
		Sub:              sub,
		ProductKeyID:     platform.ProductKeyID(PlatformWrapProduct, productKeyEpoch),
		AccountPublicKey: accountPublicKey,
	}, nil
}
