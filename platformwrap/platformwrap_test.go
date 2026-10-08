package platformwrap_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/thehappieco/kit/internal/vectest"
	"github.com/thehappieco/kit/platformwrap"
	"github.com/thehappieco/kit/profiles/wappie"
)

// vaultie is a profile of no product the kit carries, for the tests that
// need a second product's labels.
var vaultie = platformwrap.Profile{Product: "vaultie", Salt: "vaultie/platform-wrap/v1", Label: "vaultie/platform-wrap"}

func public(t testing.TB, key []byte) []byte {
	t.Helper()
	k, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().Bytes()
}

func digest(label string) []byte {
	sum := sha256.Sum256([]byte("platformwrap tests/" + label))
	return sum[:]
}

// refused is every refusal: ErrPlatformWrap, and nothing returned.
func refused(t testing.TB, what string, got []byte, err error) {
	t.Helper()
	if !errors.Is(err, platformwrap.ErrPlatformWrap) || got != nil {
		t.Fatalf("%s: want ErrPlatformWrap and nothing, got %v", what, err)
	}
}

func binding(t testing.TB, p platformwrap.Profile, usk []byte) platformwrap.Binding {
	return platformwrap.Binding{UserID: "019a7c1e-2b3d-7e4f-8a5b-6c7d8e9f0a1b", Sub: "019a7c1e-2b3d-7e4f-8a5b-6c7d8e9f0a1b", ProductKeyID: p.Product + ":1", AccountPublicKey: public(t, usk)}
}

// The construction's fixed values (SPEC section 6.8), and Wappie's labels.
func TestConstants(t *testing.T) {
	if platformwrap.Header != 0x03 || platformwrap.Len != 61 || platformwrap.Version != 1 {
		t.Fatal("a fixed value of SPEC section 6.8 changed")
	}
	if wappie.PlatformWrap() != (platformwrap.Profile{Product: "wappie", Salt: "wappie/platform-wrap/v1", Label: "wappie/platform-wrap"}) {
		t.Fatalf("Wappie's profile is %+v", wappie.PlatformWrap())
	}
	if wappie.PlatformWrapHeader != platformwrap.Header || wappie.PlatformWrapLen != platformwrap.Len || wappie.ErrPlatformWrap != platformwrap.ErrPlatformWrap {
		t.Fatal("Wappie's names are not the generic ones")
	}
}

// A profile outside its spelling is refused by every function, before
// anything is derived: a product that is not a product id of section 11.4,
// a salt or a label that is empty or outside the restricted alphabet of
// section 11.1.
func TestProfileRefusals(t *testing.T) {
	sk, usk := digest("product key"), digest("account key")
	good := binding(t, vaultie, usk)
	wrap, err := platformwrap.Seal(vaultie, nil, sk, usk, good)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []platformwrap.Profile{
		{},
		{Product: "Vaultie", Salt: vaultie.Salt, Label: vaultie.Label},
		{Product: "1vaultie", Salt: vaultie.Salt, Label: vaultie.Label},
		{Product: "-vaultie", Salt: vaultie.Salt, Label: vaultie.Label},
		{Product: "vault|ie", Salt: vaultie.Salt, Label: vaultie.Label},
		{Product: strings.Repeat("v", 33), Salt: vaultie.Salt, Label: vaultie.Label},
		{Product: vaultie.Product, Salt: "", Label: vaultie.Label},
		{Product: vaultie.Product, Salt: vaultie.Salt, Label: ""},
		{Product: vaultie.Product, Salt: "vaultie platform-wrap", Label: vaultie.Label},
		{Product: vaultie.Product, Salt: vaultie.Salt, Label: "vaultie/platform-wrap\""},
		{Product: vaultie.Product, Salt: vaultie.Salt, Label: "vaultie/platform-wrapé"},
		{Product: vaultie.Product, Salt: "vaultie/platform-wrap/v1\n", Label: vaultie.Label},
	} {
		what := strings.ReplaceAll(strings.ReplaceAll(p.Product+" "+p.Salt+" "+p.Label, "\n", `\n`), "\"", `\"`)
		info, err := platformwrap.Info(p, good)
		refused(t, "info under "+what, info, err)
		aad, err := platformwrap.AAD(p, good)
		refused(t, "aad under "+what, aad, err)
		w, err := platformwrap.Seal(p, nil, sk, usk, good)
		refused(t, "seal under "+what, w, err)
		k, err := platformwrap.Open(p, sk, wrap, good)
		refused(t, "open under "+what, k, err)
		if err := platformwrap.CheckShape(wrap); err != nil {
			t.Fatal("the shape depends on a profile")
		}
	}
}

// A seal draws a fresh nonce, leaves the caller's keys alone, refuses a
// reader that runs dry and a binding without its public key, and its wrap
// opens under its profile only; the server's check is the length and the
// header, the same for every product.
func TestUnits(t *testing.T) {
	sk, usk := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 32)
	b := binding(t, vaultie, usk)
	noKey := b
	noKey.AccountPublicKey = nil
	w, err := platformwrap.Seal(vaultie, nil, sk, usk, noKey)
	refused(t, "a binding without its public key", w, err)
	one, err := platformwrap.Seal(vaultie, nil, sk, usk, b)
	if err != nil {
		t.Fatal(err)
	}
	two, err := platformwrap.Seal(vaultie, nil, sk, usk, b)
	if err != nil || bytes.Equal(one[1:13], two[1:13]) || one[0] != platformwrap.Header || len(one) != platformwrap.Len {
		t.Fatalf("two fresh wraps: %v", err)
	}
	if !bytes.Equal(sk, bytes.Repeat([]byte{7}, 32)) || !bytes.Equal(usk, bytes.Repeat([]byte{9}, 32)) {
		t.Fatal("a caller's key changed")
	}
	w, err = platformwrap.Seal(vaultie, bytes.NewReader(make([]byte, 11)), sk, usk, b)
	refused(t, "a nonce of 11 bytes", w, err)
	if k, err := platformwrap.Open(vaultie, sk, one, b); err != nil || !bytes.Equal(k, usk) {
		t.Fatalf("open: %v", err)
	}
	for _, bad := range [][]byte{nil, one[:60], append(bytes.Clone(one), 0), append([]byte{0x01}, one[1:]...), append([]byte{0x02}, one[1:]...), append([]byte{0x00}, one[1:]...)} {
		if err := platformwrap.CheckShape(bad); !errors.Is(err, platformwrap.ErrPlatformWrap) {
			t.Fatalf("a shape of %d bytes accepted", len(bad))
		}
		k, err := platformwrap.Open(vaultie, sk, bad, b)
		refused(t, "a wrap of the wrong shape", k, err)
	}
	// Under Wappie's labels, with the same key bytes and the same binding
	// but for the product of its key id, the wrap does not open; nor does
	// it under the very same binding with the product key id unchanged,
	// which Wappie's labels refuse to bind.
	wb := b
	wb.ProductKeyID = "wappie:1"
	k, err := platformwrap.Open(wappie.PlatformWrap(), sk, one, wb)
	refused(t, "a wrap opened under another product's labels", k, err)
	k, err = platformwrap.Open(wappie.PlatformWrap(), sk, one, b)
	refused(t, "a binding of another product", k, err)
	// A profile that differs in one label only does not open it either.
	for _, p := range []platformwrap.Profile{
		{Product: vaultie.Product, Salt: "vaultie/platform-wrap/v2", Label: vaultie.Label},
		{Product: vaultie.Product, Salt: vaultie.Salt, Label: "vaultie/platform-wrap/x"},
	} {
		k, err := platformwrap.Open(p, sk, one, b)
		refused(t, "a wrap opened under another label", k, err)
	}
	// The same bytes sealed under Wappie's labels are Wappie's wrap.
	nonce := digest("nonce")[:12]
	generic, err := platformwrap.Seal(wappie.PlatformWrap(), bytes.NewReader(nonce), sk, usk, wb)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := wappie.SealPlatformWrap(bytes.NewReader(nonce), sk, usk, wb)
	if err != nil || !bytes.Equal(generic, bound) {
		t.Fatalf("Wappie's SealPlatformWrap is not the generic Seal under its labels: %v", err)
	}
}

// The members of a platform-wrap case (vectors/README.md).
type wrapIn struct {
	UserID           string  `json:"user_id"`
	Sub              string  `json:"sub"`
	ProductKeyID     string  `json:"product_key_id"`
	AccountPublicKey string  `json:"account_public_key_b64"`
	ProductKey       string  `json:"product_key_b64"`
	AccountKey       string  `json:"account_key_b64"`
	Nonce            string  `json:"nonce_b64"`
	Wrap             *string `json:"wrap_b64"`
}

func decode(t testing.TB, raw json.RawMessage, v any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("decoding a case: %v", err)
	}
}

// profileOf is the profile a golden case's op runs under.
func profileOf(op string) (platformwrap.Profile, bool) {
	switch {
	case strings.HasPrefix(op, "wappie.platform_wrap_"):
		return wappie.PlatformWrap(), true
	}
	return platformwrap.Profile{}, false
}

// goldenFiles are the golden files of every product's platform wrap.
var goldenFiles = []string{"wappie/golden/platform-wrap-go.json", "wappie/golden/platform-wrap-ts.json"}

// Every seal of the golden files, replayed through this package under the
// op's profile, is the recorded wrap, and every open refusal is refused: the
// products' functions are this package under their labels.
func TestGoldenThroughTheGenericPackage(t *testing.T) {
	n := 0
	for _, c := range vectest.Cases(t, goldenFiles...) {
		p, ok := profileOf(c.Op)
		if !ok {
			t.Fatalf("%s: op %q", c.ID, c.Op)
		}
		var in wrapIn
		decode(t, c.In, &in)
		b := platformwrap.Binding{UserID: in.UserID, Sub: in.Sub, ProductKeyID: in.ProductKeyID, AccountPublicKey: vectest.B64(t, in.AccountPublicKey)}
		switch {
		case strings.HasSuffix(c.Op, "_seal") && c.Error == "":
			var out struct {
				Wrap string `json:"wrap_b64"`
				KPW  string `json:"k_pw_b64"`
			}
			decode(t, c.Out, &out)
			got, err := platformwrap.Seal(p, bytes.NewReader(vectest.B64(t, in.Nonce)), vectest.B64(t, in.ProductKey), vectest.B64(t, in.AccountKey), b)
			if err != nil || !bytes.Equal(got, vectest.B64(t, out.Wrap)) {
				t.Fatalf("%s: %v", c.ID, err)
			}
			n++
		case strings.HasSuffix(c.Op, "_open") && c.Error != "":
			k, err := platformwrap.Open(p, vectest.B64(t, in.ProductKey), vectest.B64(t, *in.Wrap), b)
			refused(t, c.ID, k, err)
			n++
		}
	}
	if n == 0 {
		t.Fatal("no case ran")
	}
}

// FuzzOpen: under every product's profile, no input panics; every refusal
// is ErrPlatformWrap with nothing returned; and whatever opens is a 32-byte
// key whose public half is the binding's, which a fresh seal under the same
// profile and binding opens to again. Seeded from every golden file.
func FuzzOpen(f *testing.F) {
	profiles := []platformwrap.Profile{wappie.PlatformWrap()}
	index := func(p platformwrap.Profile) uint8 {
		for i, q := range profiles {
			if q == p {
				return uint8(i)
			}
		}
		f.Fatalf("profile %+v", p)
		return 0
	}
	for _, c := range vectest.Cases(f, goldenFiles...) {
		p, _ := profileOf(c.Op)
		var in wrapIn
		decode(f, c.In, &in)
		if in.Wrap != nil {
			f.Add(index(p), vectest.B64(f, in.ProductKey), vectest.B64(f, *in.Wrap), in.UserID, in.Sub, in.ProductKeyID, vectest.B64(f, in.AccountPublicKey))
		}
	}
	f.Fuzz(func(t *testing.T, which uint8, sk, wrap []byte, userID, sub, keyID string, pub []byte) {
		p := profiles[int(which)%len(profiles)]
		b := platformwrap.Binding{UserID: userID, Sub: sub, ProductKeyID: keyID, AccountPublicKey: pub}
		key, err := platformwrap.Open(p, sk, wrap, b)
		if err != nil {
			if !errors.Is(err, platformwrap.ErrPlatformWrap) || key != nil {
				t.Fatalf("an unclassified refusal: %v", err)
			}
			return
		}
		if len(key) != 32 || !bytes.Equal(public(t, key), pub) {
			t.Fatal("opened to a key that is not the binding's")
		}
		again, err := platformwrap.Seal(p, nil, sk, key, b)
		if err != nil {
			t.Fatal(err)
		}
		if k, err := platformwrap.Open(p, sk, again, b); err != nil || !bytes.Equal(k, key) {
			t.Fatal("a fresh seal does not open")
		}
	})
}
