package mailie_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/thehappieco/kit/account"
	"github.com/thehappieco/kit/internal/vectest"
	"github.com/thehappieco/kit/platformwrap"
	"github.com/thehappieco/kit/profiles/mailie"
	"github.com/thehappieco/kit/profiles/wappie"
)

// The members of a platform-wrap case (vectors/README.md); decoding is
// strict, so a member no runner reads fails the case.
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

type wrapOut struct {
	Info       string `json:"info_b64"`
	AAD        string `json:"aad_b64"`
	Wrap       string `json:"wrap_b64"`
	KPW        string `json:"k_pw_b64"`
	AccountKey string `json:"account_key_b64"`
}

func strict(t testing.TB, raw json.RawMessage, v any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("decoding a case: %v", err)
	}
}

func x25519Public(t testing.TB, key []byte) []byte {
	t.Helper()
	k, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().Bytes()
}

// profileOf is the profile a case's op runs under: Mailie's file carries
// Mailie's ops, and Wappie's opener for the cross-product refusals that
// open a Mailie wrap under Wappie's labels.
func profileOf(t *testing.T, op string) (platformwrap.Profile, string) {
	t.Helper()
	for _, p := range []platformwrap.Profile{mailie.PlatformWrap(), wappie.PlatformWrap()} {
		if rest, ok := strings.CutPrefix(op, p.Product+".platform_wrap_"); ok {
			return p, rest
		}
	}
	t.Fatalf("op %q", op)
	return platformwrap.Profile{}, ""
}

const goldenFile = "mailie/golden/platform-wrap-go.json"

// TestMailiePlatformWrapVectors runs vectors/mailie/golden/platform-wrap-go.json,
// which the kit's generator wrote (SPEC section 6.8 under Mailie's labels,
// Appendix D): the info and the AAD byte for byte, every seal replayed from
// its nonce with its K_pw checked, every open back to its account key, and
// every refusal ErrPlatformWrap with nothing returned, the cross-product
// ones included. A wrap is also the wrap envelope of section 6.5 with the
// header 0x03 and no legacy form: account.Unwrap opens it under K_pw.
func TestMailiePlatformWrapVectors(t *testing.T) {
	f := vectest.Load(t, goldenFile)
	if f.Module != "mailie.platform_wrap" || f.Profile != "mailie" || f.GeneratedBy.Lang != "go" {
		t.Fatalf("module %q, profile %q, lang %q", f.Module, f.Profile, f.GeneratedBy.Lang)
	}
	counts := map[string]int{}
	for _, c := range f.Cases {
		if !c.ForGo() {
			continue
		}
		counts[c.Op]++
		if c.Error != "" {
			counts["refused"]++
		}
		if strings.Contains(c.ID, "/cross-product/") {
			counts["cross-product"]++
		}
		t.Run(c.ID, func(t *testing.T) { platformWrapCase(t, c) })
	}
	want := map[string]int{
		"mailie.platform_wrap_info": 6, "mailie.platform_wrap_aad": 6, "mailie.platform_wrap_seal": 17, "mailie.platform_wrap_open": 28,
		"wappie.platform_wrap_open": 3, "refused": 36, "cross-product": 7,
	}
	if len(counts) != len(want) {
		t.Errorf("counts %v, want %v", counts, want)
	}
	for k, n := range want {
		if counts[k] != n {
			t.Errorf("%s: %d cases, want %d", k, counts[k], n)
		}
	}
}

// platformWrapCase runs one case of the platform wrap's ops under the op's
// profile, from the golden file or from the kit's own round trips.
func platformWrapCase(t *testing.T, c vectest.Case) {
	p, op := profileOf(t, c.Op)
	var in wrapIn
	var out wrapOut
	strict(t, c.In, &in)
	if c.Error == "" {
		strict(t, c.Out, &out)
	} else if c.Error != "platform_wrap" {
		t.Fatalf("error %q, want platform_wrap", c.Error)
	}
	b := platformwrap.Binding{UserID: in.UserID, Sub: in.Sub, ProductKeyID: in.ProductKeyID, AccountPublicKey: vectest.B64(t, in.AccountPublicKey)}
	refused := func(got []byte, err error) {
		t.Helper()
		if !errors.Is(err, platformwrap.ErrPlatformWrap) || got != nil {
			t.Fatalf("want ErrPlatformWrap and nothing, got %v", err)
		}
	}
	switch op {
	case "info":
		got, err := platformwrap.Info(p, b)
		if err != nil || !bytes.Equal(got, vectest.B64(t, out.Info)) {
			t.Fatalf("info: %v", err)
		}
	case "aad":
		got, err := platformwrap.AAD(p, b)
		if err != nil || !bytes.Equal(got, vectest.B64(t, out.AAD)) {
			t.Fatalf("aad: %v", err)
		}
	case "seal":
		r := bytes.NewReader(make([]byte, 12))
		if in.Nonce != "" {
			r = bytes.NewReader(vectest.B64(t, in.Nonce))
		}
		got, err := platformwrap.Seal(p, r, vectest.B64(t, in.ProductKey), vectest.B64(t, in.AccountKey), b)
		if c.Error != "" {
			refused(got, err)
			return
		}
		want := vectest.B64(t, out.Wrap)
		if err != nil || !bytes.Equal(got, want) || platformwrap.CheckShape(got) != nil {
			t.Fatalf("seal: %v", err)
		}
		if back, err := platformwrap.Open(p, vectest.B64(t, in.ProductKey), got, b); err != nil || !bytes.Equal(back, vectest.B64(t, in.AccountKey)) {
			t.Fatalf("the seal does not open: %v", err)
		}
		if out.KPW != "" {
			// Section 6.5's envelope, header 0x03, no legacy form.
			aad, _ := platformwrap.AAD(p, b)
			key, stale, err := account.Unwrap(account.Profile{WrapHeader: []byte{platformwrap.Header}}, vectest.B64(t, out.KPW), want, aad)
			if err != nil || stale || !bytes.Equal(key, vectest.B64(t, in.AccountKey)) {
				t.Fatalf("account.Unwrap under k_pw: %v", err)
			}
			block, _ := aes.NewCipher(vectest.B64(t, out.KPW))
			gcm, _ := cipher.NewGCM(block)
			if !bytes.Equal(gcm.Seal(append([]byte{platformwrap.Header}, want[1:13]...), want[1:13], key, aad), want) {
				t.Fatal("k_pw does not seal the wrap")
			}
			info, _ := platformwrap.Info(p, b)
			if !bytes.Equal(kpw(t, p.Salt, vectest.B64(t, in.ProductKey), info), vectest.B64(t, out.KPW)) {
				t.Fatal("k_pw is not section 6.8's HKDF")
			}
		}
	case "open":
		if in.Wrap == nil {
			t.Fatal("an open without wrap_b64")
		}
		got, err := platformwrap.Open(p, vectest.B64(t, in.ProductKey), vectest.B64(t, *in.Wrap), b)
		if c.Error != "" {
			refused(got, err)
			return
		}
		if err != nil || !bytes.Equal(got, vectest.B64(t, out.AccountKey)) {
			t.Fatalf("open: %v", err)
		}
		if !bytes.Equal(x25519Public(t, got), b.AccountPublicKey) {
			t.Fatal("opened to a key that is not the binding's")
		}
	default:
		vectest.Unhandled(t, c)
	}
}

// TestKitMailiePlatformWrapVectors reproduces the kit's own round trips of
// Mailie's platform wrap that the TypeScript side wrote: the fresh file of
// that name in $KIT_CROSS_IN in the cross-language job, every seal replayed
// from the nonce it drew, and every wrap also refused under Wappie's labels.
func TestKitMailiePlatformWrapVectors(t *testing.T) {
	for _, c := range vectest.Fresh(t, "mailie-platform-wrap-ts.json") {
		if !c.ForGo() {
			continue
		}
		t.Run(c.ID, func(t *testing.T) { platformWrapCase(t, c) })
	}
}

// The golden file holds the bindings the kit asked for: an account whose
// user id is not its sub, an account key and a product key whose first byte
// is zero, the largest epoch; and every product key of a binding of Mailie's
// is a Mailie key id's.
func TestMailiePlatformWrapBindings(t *testing.T) {
	notTheSub, zeroAccount, zeroProduct, largest := false, false, false, false
	for _, c := range vectest.Load(t, goldenFile).Cases {
		if c.Op != "mailie.platform_wrap_seal" || c.Error != "" {
			continue
		}
		var in wrapIn
		strict(t, c.In, &in)
		notTheSub = notTheSub || in.UserID != in.Sub
		zeroAccount = zeroAccount || vectest.B64(t, in.AccountKey)[0] == 0
		zeroProduct = zeroProduct || vectest.B64(t, in.ProductKey)[0] == 0
		largest = largest || in.ProductKeyID == "mailie:2147483647"
		if !strings.HasPrefix(in.ProductKeyID, "mailie:") {
			t.Errorf("%s: product key id %q", c.ID, in.ProductKeyID)
		}
	}
	if !notTheSub || !zeroAccount || !zeroProduct || !largest {
		t.Error("a binding the kit asked for is missing")
	}
}

// Mailie's labels (SPEC Appendix D) are its own: no label or salt of
// Wappie's, the same construction and header.
func TestMailieProfile(t *testing.T) {
	p := mailie.PlatformWrap()
	if p != (platformwrap.Profile{Product: "mailie", Salt: "mailie/platform-wrap/v1", Label: "mailie/platform-wrap"}) ||
		mailie.PlatformWrapProduct != p.Product || mailie.PlatformWrapSalt != p.Salt || mailie.PlatformWrapLabel != p.Label {
		t.Fatalf("Mailie's profile is %+v", p)
	}
	w := wappie.PlatformWrap()
	for _, a := range []string{p.Product, p.Salt, p.Label} {
		for _, b := range []string{w.Product, w.Salt, w.Label} {
			if a == b {
				t.Fatalf("Mailie's %q is also Wappie's", a)
			}
		}
	}
}

func kpw(t testing.TB, salt string, productKey, info []byte) []byte {
	t.Helper()
	k, err := hkdf.Key(sha256.New, productKey, []byte(salt), string(info), 32)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
