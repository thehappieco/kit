package mailie

import (
	"encoding/base64"
	"fmt"

	"github.com/thehappieco/kit/jcs"
)

// The browser vault (SPEC section 8 under Mailie's tag): the account key
// kept at rest in a browser, bound to the person's seal id.
const (
	BrowserVaultTag     = "mailie/browser-account-key"
	BrowserVaultVersion = 1
)

// BrowserVaultAAD is the additional data under which a browser keeps the
// account key at rest, the JSON AAD of SPEC sections 2 and 8, not the
// restricted one of the other bindings:
//
//	JCS(["mailie/browser-account-key", 1, seal_id, base64(account public key)])
//
// with standard base64, padded, as section 8 writes it; its '+', '/' and '='
// are outside the restricted alphabet, so platform.JCSArray would refuse it.
// The browser computes it (TypeScript browserVaultAAD of profiles/mailie,
// over browserAccount); this is its reference in Go.
func BrowserVaultAAD(sealID string, accountPublicKey []byte) ([]byte, error) {
	if !ValidSealID(sealID) {
		return nil, fmt.Errorf("%w: the seal id is not a lowercase UUIDv4", ErrBinding)
	}
	if len(accountPublicKey) != KeyLen {
		return nil, fmt.Errorf("%w: an account public key is %d bytes", ErrBinding, KeyLen)
	}
	aad, err := jcs.Marshal([]any{BrowserVaultTag, BrowserVaultVersion, sealID, base64.StdEncoding.EncodeToString(accountPublicKey)})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBinding, err)
	}
	return aad, nil
}
