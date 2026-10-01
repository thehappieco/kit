package platform_test

import (
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/thehappieco/kit/internal/forge"
	"github.com/thehappieco/kit/profiles/platform"
)

// knownBadX25519 are the public values libsodium refuses: the low-order
// points of Curve25519 and their encodings with bit 255 set or above p.
var knownBadX25519 = []string{
	"0000000000000000000000000000000000000000000000000000000000000000", // 0
	"0100000000000000000000000000000000000000000000000000000000000000", // 1
	"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", // order 8
	"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", // order 8
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p - 1
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p + 1
	"cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
	"4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
	"d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
}

// The server refuses every low-order key the kit's forgeries use
// (internal/forge, SPEC section 4.4) and every value libsodium refuses.
func TestCheckPublicKeyRefusesLowOrderAndNonCanonical(t *testing.T) {
	for _, lo := range forge.LowOrder {
		if err := platform.CheckPublicKey(lo.Point); !errors.Is(err, platform.ErrProductKey) {
			t.Errorf("%s: %v, want ErrProductKey", lo.Name, err)
		}
	}
	for i, h := range knownBadX25519 {
		pub, _ := hex.DecodeString(h)
		if err := platform.CheckPublicKey(pub); !errors.Is(err, platform.ErrProductKey) {
			t.Errorf("point %d: %v, want ErrProductKey", i, err)
		}
	}
	// The first five are canonical encodings, so it is the all-zero exchange
	// that refuses them, not the encoding rule.
	for i, h := range knownBadX25519[:5] {
		pub, _ := hex.DecodeString(h)
		if err := platform.CheckPublicKey(pub); err == nil || !strings.Contains(err.Error(), "low-order") {
			t.Errorf("point %d was not refused as a low-order point: %v", i, err)
		}
	}
}

func TestANonCanonicalProductKeyIsRefused(t *testing.T) {
	_, pub, err := platform.ProductKey(testBytes(32, 0x11), "wappie", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.CheckPublicKey(pub); err != nil {
		t.Fatalf("a derived key: %v", err)
	}
	// The same point with bit 255 set: X25519 ignores the bit, a byte
	// comparison does not.
	high := slices.Clone(pub)
	high[31] |= 0x80
	if err := platform.CheckPublicKey(high); !errors.Is(err, platform.ErrProductKey) {
		t.Fatalf("bit 255 set: %v", err)
	}
	for _, n := range []int{0, 31, 33} {
		if err := platform.CheckPublicKey(make([]byte, n)); !errors.Is(err, platform.ErrProductKey) {
			t.Fatalf("%d bytes: %v", n, err)
		}
	}
}

func TestEveryDerivedProductKeyPassesTheServerCheck(t *testing.T) {
	for i := range 64 {
		root := testBytes(32, byte(i))
		root[0] = byte(i * 7)
		for _, p := range append(slices.Clone(testProducts), "a-future-product") {
			_, pub, err := platform.ProductKey(root, p, 1+i)
			if err != nil {
				t.Fatal(err)
			}
			if err := platform.CheckPublicKey(pub); err != nil {
				t.Fatalf("root %d, %s: %v", i, p, err)
			}
		}
	}
}

func TestProductKeysAreSeparatedByProductEpochAndRoot(t *testing.T) {
	root := testBytes(32, 0x22)
	seen := map[string]string{}
	for _, c := range []struct {
		root    []byte
		product string
		epoch   int
	}{
		{root, "wappie", 1}, {root, "wappie", 2}, {root, "mailie", 1},
		{testBytes(32, 0x23), "wappie", 1},
		// "wappie|1" cannot be a product id, so ("wappie", 11) and
		// ("wappie|1", 1) can never share an HKDF info.
		{root, "wappie", 11}, {root, "wappie-1", 1},
	} {
		_, pub, err := platform.ProductKey(c.root, c.product, c.epoch)
		if err != nil {
			t.Fatal(err)
		}
		id := platform.ProductKeyID(c.product, c.epoch)
		if prev, dup := seen[string(pub)]; dup {
			t.Fatalf("%s and %s share a key", prev, id)
		}
		seen[string(pub)] = id
	}
}

// There is no registry in the kit: any id of the grammar derives, and
// nothing else does.
func TestAnyValidProductIdDerivesAndNoOtherDoes(t *testing.T) {
	for _, p := range []string{"a", "mailie", "wappie", "a-future-product", "p" + strings.Repeat("0123456789-", 2) + "abcdefghi"} {
		if !platform.ValidProduct(p) {
			t.Errorf("%q is not valid", p)
		}
	}
	for _, p := range []string{"", "Wappie", "1wappie", "-wappie", "wap_pie", "wappie|1", "wap pie", "w\u00e1ppie", strings.Repeat("a", 33)} {
		if platform.ValidProduct(p) {
			t.Errorf("%q is valid", p)
		}
		if _, _, err := platform.ProductKey(testBytes(32, 1), p, 1); !errors.Is(err, platform.ErrProductKey) {
			t.Errorf("%q: %v", p, err)
		}
	}
	if got := platform.ProductKeyID("wappie", 1); got != "wappie:1" {
		t.Fatalf("ProductKeyID = %q", got)
	}
}
