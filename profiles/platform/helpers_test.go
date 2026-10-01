package platform_test

import (
	"bytes"
	"testing"

	"github.com/thehappieco/kit/profiles/platform"
)

const (
	testSub      = "0199e4b2-3c41-7a52-8f3e-9b1d2c4e5f60"
	otherTestSub = "0199e4b2-3c41-7a52-8f3e-9b1d2c4e5f61"
	// The test password of the bundle tests. It is not a secret.
	testPassword = "correct horse battery staple"
)

// testProducts stands in for the platform's registry, which is not the
// kit's.
var testProducts = []string{"mailie", "wappie"}

func testBytes(n int, fill byte) []byte { return bytes.Repeat([]byte{fill}, n) }

// productPublicKeys derives the public key of every product at epoch, in
// order, as the platform's sign-up sends them.
func productPublicKeys(t testing.TB, root []byte, epoch int, products ...string) []platform.ProductPublicKey {
	t.Helper()
	out := make([]platform.ProductPublicKey, 0, len(products))
	for _, p := range products {
		sk, pub, err := platform.ProductKey(root, p, epoch)
		clear(sk)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, platform.ProductPublicKey{Product: p, Epoch: epoch, Pub: platform.EncodeB64(pub)})
	}
	return out
}
