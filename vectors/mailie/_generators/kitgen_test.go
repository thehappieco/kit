package kitgen

// The kit's generator of vectors/mailie/golden/platform-wrap-go.json (SPEC
// section 6.8 under Mailie's labels, Appendix D). make vectors-mailie-regen
// copies it into a throwaway module against the kit's tree, runs it with
// KIT_GOLDEN_OUT set and compares the file it writes with the committed one,
// byte for byte. Every key, root and nonce is SHA-256 of a fixed label, and
// every product key is section 11.4's sk_p of such a root, so nothing is
// random and the file is a pure function of the kit's code. Every wrap is
// opened again and its K_pw proved against it, every refusal is checked
// against the package before it is written, the counts are checked, and the
// file is opened with O_EXCL. It lives under _generators, which the go tool
// does not build, so that it needs no file to embed.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/thehappieco/kit/platformwrap"
	"github.com/thehappieco/kit/profiles/mailie"
	"github.com/thehappieco/kit/profiles/platform"
	"github.com/thehappieco/kit/profiles/wappie"
)

func kpw(t testing.TB, p platformwrap.Profile, productKey, info []byte) []byte {
	t.Helper()
	k, err := hkdf.Key(sha256.New, productKey, []byte(p.Salt), string(info), 32)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type kitCase struct {
	ID    string         `json:"id"`
	Op    string         `json:"op"`
	In    map[string]any `json:"in"`
	Out   map[string]any `json:"out,omitempty"`
	Error string         `json:"error,omitempty"`
}

func digest(label string) []byte {
	sum := sha256.Sum256([]byte("mailie/platform-wrap kit vectors/" + label))
	return sum[:]
}

var std = base64.StdEncoding.EncodeToString

func public(t testing.TB, key []byte) []byte {
	t.Helper()
	k, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().Bytes()
}

// productKey is sk_p of section 11.4 for a root made from label.
func productKey(t testing.TB, label, product string, epoch int) []byte {
	t.Helper()
	sk, _, err := platform.ProductKey(digest(label+"/root"), product, epoch)
	if err != nil {
		t.Fatal(err)
	}
	return sk
}

func TestWriteMailiePlatformWrapGolden(t *testing.T) {
	out := os.Getenv("KIT_GOLDEN_OUT")
	if out == "" {
		t.Skip("KIT_GOLDEN_OUT is not set")
	}
	m, w := mailie.PlatformWrap(), wappie.PlatformWrap()
	var cases []kitCase
	with := func(m map[string]any, kv ...any) map[string]any {
		c := map[string]any{}
		for k, v := range m {
			c[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			c[kv[i].(string)] = kv[i+1]
		}
		return c
	}
	zeroFirst := func(f func(i int) []byte) []byte {
		for i := 0; ; i++ {
			if k := f(i); k[0] == 0 {
				return k
			}
		}
	}
	type vec struct {
		name, userID, sub string
		epoch             int
		sk, usk, nonce    []byte
	}
	vs := []vec{
		{"user-id-is-the-sub", "019a7c1e-2b3d-7e4f-8a5b-6c7d8e9f0a1b", "019a7c1e-2b3d-7e4f-8a5b-6c7d8e9f0a1b", 1, productKey(t, "new", "mailie", 1), digest("new/account key"), digest("new/nonce")[:12]},
		{"user-id-is-not-the-sub", "6f1d2c3b-4a59-4687-9a6b-5c4d3e2f1a0b", "019a7c1e-5d6e-7f80-9a1b-2c3d4e5f6a7b", 1, productKey(t, "moved", "mailie", 1), digest("moved/account key"), digest("moved/nonce")[:12]},
		{"epoch-2", "6f1d2c3b-4a59-4687-9a6b-5c4d3e2f1a0b", "019a7c1e-5d6e-7f80-9a1b-2c3d4e5f6a7b", 2, productKey(t, "moved", "mailie", 2), digest("moved/account key"), digest("epoch2/nonce")[:12]},
		{"account-key-zero-first-byte", "019a7c1e-2b3d-7e4f-8a5b-6c7d8e9f0a1c", "019a7c1e-2b3d-7e4f-8a5b-6c7d8e9f0a1c", 1, productKey(t, "zero-account", "mailie", 1), zeroFirst(func(i int) []byte {
			return digest("zero-account/account key/" + string(rune('a'+i%26)) + string(rune('a'+i/26)))
		}), digest("zero-account/nonce")[:12]},
		{"product-key-zero-first-byte", "019a7c1e-2b3d-7e4f-8a5b-6c7d8e9f0a1d", "019a7c1e-2b3d-7e4f-8a5b-6c7d8e9f0a1d", 3, zeroFirst(func(i int) []byte {
			return productKey(t, "zero-product/"+string(rune('a'+i%26))+string(rune('a'+i/26)), "mailie", 3)
		}), digest("zero-product/account key"), digest("zero-product/nonce")[:12]},
		{"largest-epoch", "019a7c1e-2b3d-7e4f-8a5b-6c7d8e9f0a1e", "019a7c1e-5d6e-7f80-9a1b-2c3d4e5f6a7c", 2147483647, productKey(t, "max-epoch", "mailie", 2147483647), digest("max-epoch/account key"), digest("max-epoch/nonce")[:12]},
	}
	binding := func(v vec, product string) (platformwrap.Binding, map[string]any) {
		pub := public(t, v.usk)
		id := platform.ProductKeyID(product, v.epoch)
		return platformwrap.Binding{UserID: v.userID, Sub: v.sub, ProductKeyID: id, AccountPublicKey: pub},
			map[string]any{"user_id": v.userID, "sub": v.sub, "product_key_id": id, "account_public_key_b64": std(pub)}
	}
	wraps := map[string][]byte{}
	for _, v := range vs {
		b, bi := binding(v, "mailie")
		info, err := platformwrap.Info(m, b)
		if err != nil {
			t.Fatal(err)
		}
		aad, err := platformwrap.AAD(m, b)
		if err != nil {
			t.Fatal(err)
		}
		wrap, err := platformwrap.Seal(m, bytes.NewReader(v.nonce), v.sk, v.usk, b)
		if err != nil {
			t.Fatal(err)
		}
		k := kpw(t, m, v.sk, info)
		block, _ := aes.NewCipher(k)
		gcm, _ := cipher.NewGCM(block)
		if !bytes.Equal(gcm.Seal(append([]byte{platformwrap.Header}, v.nonce...), v.nonce, v.usk, aad), wrap) {
			t.Fatalf("%s: K_pw does not make the wrap", v.name)
		}
		if back, err := platformwrap.Open(m, v.sk, wrap, b); err != nil || !bytes.Equal(back, v.usk) {
			t.Fatalf("%s: the wrap does not open: %v", v.name, err)
		}
		wraps[v.name] = wrap
		cases = append(cases,
			kitCase{ID: "mailie/platform-wrap/info/" + v.name, Op: "mailie.platform_wrap_info", In: bi, Out: map[string]any{"info_b64": std(info)}},
			kitCase{ID: "mailie/platform-wrap/aad/" + v.name, Op: "mailie.platform_wrap_aad", In: bi, Out: map[string]any{"aad_b64": std(aad)}},
			kitCase{ID: "mailie/platform-wrap/seal/" + v.name, Op: "mailie.platform_wrap_seal", In: with(bi, "product_key_b64", std(v.sk), "account_key_b64", std(v.usk), "nonce_b64", std(v.nonce)), Out: map[string]any{"wrap_b64": std(wrap), "k_pw_b64": std(k)}},
			kitCase{ID: "mailie/platform-wrap/open/" + v.name, Op: "mailie.platform_wrap_open", In: with(bi, "product_key_b64", std(v.sk), "wrap_b64", std(wrap)), Out: map[string]any{"account_key_b64": std(v.usk)}},
		)
	}
	// Open refusals, all of the binding user-id-is-not-the-sub, one thing
	// changed each.
	l := vs[1]
	lbind, lb := binding(l, "mailie")
	lb = with(lb, "product_key_b64", std(l.sk))
	lw := wraps[l.name]
	other := public(t, digest("other/account key"))
	flip := func(i int) []byte { x := bytes.Clone(lw); x[i] ^= 1; return x }
	header := func(h byte) []byte { x := bytes.Clone(lw); x[0] = h; return x }
	foreign := func() []byte {
		// Authenticates under its own AAD around another account's key.
		info, _ := platformwrap.Info(m, lbind)
		aad, _ := platformwrap.AAD(m, lbind)
		block, _ := aes.NewCipher(kpw(t, m, l.sk, info))
		gcm, _ := cipher.NewGCM(block)
		o := append([]byte{platformwrap.Header}, digest("foreign/nonce")[:12]...)
		return gcm.Seal(o, o[1:], digest("other/account key"), aad)
	}()
	type refusal struct {
		id, op string
		in     map[string]any
	}
	refusals := []refusal{
		{"another-user-id", "open", with(lb, "wrap_b64", std(lw), "user_id", "6f1d2c3b-4a59-4687-9a6b-5c4d3e2f1a0c")},
		{"another-sub", "open", with(lb, "wrap_b64", std(lw), "sub", "019a7c1e-5d6e-7f80-9a1b-2c3d4e5f6a7c")},
		{"another-epoch", "open", with(lb, "wrap_b64", std(lw), "product_key_id", "mailie:2")},
		{"another-account-public-key", "open", with(lb, "wrap_b64", std(lw), "account_public_key_b64", std(other))},
		{"another-product-key", "open", with(lb, "wrap_b64", std(lw), "product_key_b64", std(vs[2].sk))},
		{"the-epoch-2-wrap", "open", with(lb, "wrap_b64", std(wraps["epoch-2"]))},
		{"flipped-nonce", "open", with(lb, "wrap_b64", std(flip(1)))},
		{"flipped-ciphertext", "open", with(lb, "wrap_b64", std(flip(20)))},
		{"flipped-tag", "open", with(lb, "wrap_b64", std(flip(60)))},
		{"header-0x01", "open", with(lb, "wrap_b64", std(header(0x01)))},
		{"header-0x02", "open", with(lb, "wrap_b64", std(header(0x02)))},
		{"header-0x00", "open", with(lb, "wrap_b64", std(header(0x00)))},
		{"length-60", "open", with(lb, "wrap_b64", std(lw[:60]))},
		{"length-62", "open", with(lb, "wrap_b64", std(append(bytes.Clone(lw), 0)))},
		{"empty", "open", with(lb, "wrap_b64", "")},
		{"sub-in-upper-case", "open", with(lb, "wrap_b64", std(lw), "sub", "019A7C1E-5D6E-7F80-9A1B-2C3D4E5F6A7B")},
		{"product-key-of-31-bytes", "open", with(lb, "wrap_b64", std(lw), "product_key_b64", std(l.sk[:31]))},
		{"account-public-key-of-31-bytes", "open", with(lb, "wrap_b64", std(lw), "account_public_key_b64", std(public(t, l.usk)[:31]))},
		{"opens-to-another-accounts-key", "open", with(lb, "wrap_b64", std(foreign))},
	}
	// Cross-product: Mailie's and Wappie's wraps never open as each other's.
	// The same person (one root) has a product key per product (section
	// 11.4); a wrap also fails with the very same key bytes, where only the
	// labels and the key id's product differ; and with its own binding,
	// whose key id names the other product.
	same := vec{"same-person", "019a7c1e-2b3d-7e4f-8a5b-6c7d8e9f0a1f", "019a7c1e-2b3d-7e4f-8a5b-6c7d8e9f0a1f", 1, nil, digest("same/account key"), digest("same/nonce")[:12]}
	skM, skW := productKey(t, "same", "mailie", 1), productKey(t, "same", "wappie", 1)
	mb, mbi := binding(same, "mailie")
	wb, wbi := binding(same, "wappie")
	mailieWrap, err := platformwrap.Seal(m, bytes.NewReader(same.nonce), skM, same.usk, mb)
	if err != nil {
		t.Fatal(err)
	}
	wappieWrap, err := platformwrap.Seal(w, bytes.NewReader(same.nonce), skW, same.usk, wb)
	if err != nil {
		t.Fatal(err)
	}
	wappieUnderMailieKey, err := platformwrap.Seal(w, bytes.NewReader(same.nonce), skM, same.usk, wb)
	if err != nil {
		t.Fatal(err)
	}
	mailieUnderWappieKey, err := platformwrap.Seal(m, bytes.NewReader(same.nonce), skW, same.usk, mb)
	if err != nil {
		t.Fatal(err)
	}
	refusals = append(refusals,
		refusal{"cross-product/the-same-persons-wappie-wrap", "open", with(mbi, "product_key_b64", std(skM), "wrap_b64", std(wappieWrap))},
		refusal{"cross-product/a-wappie-wrap-under-the-same-key-bytes", "open", with(mbi, "product_key_b64", std(skM), "wrap_b64", std(wappieUnderMailieKey))},
		refusal{"cross-product/a-wappie-wrap-with-its-own-binding", "open", with(wbi, "product_key_b64", std(skW), "wrap_b64", std(wappieWrap))},
		refusal{"cross-product/the-same-persons-mailie-wrap", "wappie", with(wbi, "product_key_b64", std(skW), "wrap_b64", std(mailieWrap))},
		refusal{"cross-product/a-mailie-wrap-under-the-same-key-bytes", "wappie", with(wbi, "product_key_b64", std(skW), "wrap_b64", std(mailieUnderWappieKey))},
		refusal{"cross-product/a-mailie-wrap-with-its-own-binding", "wappie", with(mbi, "product_key_b64", std(skM), "wrap_b64", std(mailieWrap))},
	)
	bindingOf := func(in map[string]any) platformwrap.Binding {
		pub, _ := base64.StdEncoding.DecodeString(in["account_public_key_b64"].(string))
		return platformwrap.Binding{UserID: in["user_id"].(string), Sub: in["sub"].(string), ProductKeyID: in["product_key_id"].(string), AccountPublicKey: pub}
	}
	b64 := func(v any) []byte { b, _ := base64.StdEncoding.DecodeString(v.(string)); return b }
	for _, r := range refusals {
		p, op, id := m, "mailie.platform_wrap_open", "mailie/platform-wrap/open/refuses/"+r.id
		if r.op == "wappie" {
			p, op, id = w, "wappie.platform_wrap_open", "wappie/platform-wrap/open/refuses/"+r.id
		}
		if k, err := platformwrap.Open(p, b64(r.in["product_key_b64"]), b64(r.in["wrap_b64"]), bindingOf(r.in)); !errors.Is(err, platformwrap.ErrPlatformWrap) || k != nil {
			t.Fatalf("open refusal %s: %v", r.id, err)
		}
		cases = append(cases, kitCase{ID: id, Op: op, In: r.in, Error: "platform_wrap"})
	}
	n := vs[0]
	_, nbi := binding(n, "mailie")
	nb := with(nbi, "product_key_b64", std(n.sk), "account_key_b64", std(n.usk))
	seals := []struct {
		id string
		in map[string]any
	}{
		{"account-key-not-the-public-keys", with(nb, "account_key_b64", std(digest("other/account key")))},
		{"account-key-of-31-bytes", with(nb, "account_key_b64", std(n.usk[:31]))},
		{"product-key-of-31-bytes", with(nb, "product_key_b64", std(n.sk[:31]))},
		{"product-key-of-33-bytes", with(nb, "product_key_b64", std(append(bytes.Clone(n.sk), 0)))},
		{"user-id-not-a-uuid", with(nb, "user_id", "not-a-uuid")},
		{"user-id-in-upper-case", with(nb, "user_id", "019A7C1E-2B3D-7E4F-8A5B-6C7D8E9F0A1B")},
		{"epoch-with-a-leading-zero", with(nb, "product_key_id", "mailie:01")},
		{"epoch-0", with(nb, "product_key_id", "mailie:0")},
		{"epoch-2147483648", with(nb, "product_key_id", "mailie:2147483648")},
		{"no-epoch", with(nb, "product_key_id", "mailie")},
		{"cross-product/a-wappie-product-key-id", with(nb, "product_key_id", "wappie:1")},
	}
	for _, r := range seals {
		if w, err := platformwrap.Seal(m, nil, b64(r.in["product_key_b64"]), b64(r.in["account_key_b64"]), bindingOf(r.in)); !errors.Is(err, platformwrap.ErrPlatformWrap) || w != nil {
			t.Fatalf("seal refusal %s: %v", r.id, err)
		}
		cases = append(cases, kitCase{ID: "mailie/platform-wrap/seal/refuses/" + r.id, Op: "mailie.platform_wrap_seal", In: r.in, Error: "platform_wrap"})
	}
	type source struct {
		Lang       string `json:"lang"`
		Source     string `json:"source"`
		Toolchain  string `json:"toolchain"`
		Randomness string `json:"randomness"`
		Generator  string `json:"generator"`
	}
	file := struct {
		Format      string    `json:"format"`
		Module      string    `json:"module"`
		Profile     string    `json:"profile"`
		GeneratedBy source    `json:"generated_by"`
		Note        string    `json:"note"`
		Cases       []kitCase `json:"cases"`
	}{
		Format:  "thehappieco-kit-vectors/1",
		Module:  "mailie.platform_wrap",
		Profile: "mailie",
		GeneratedBy: source{
			Lang:       "go",
			Source:     "github.com/thehappieco/kit v0.6.0 platformwrap, profiles/mailie",
			Toolchain:  runtime.Version(),
			Randomness: "none: every key, root and nonce is SHA-256 of a fixed label; product keys are section 11.4's from such a root",
			Generator:  "vectors/mailie/_generators/kitgen_test.go",
		},
		Note: "Mailie's platform wrap (SPEC section 6.8 and Appendix D): the kit's generic wrap under Mailie's labels, salt mailie/platform-wrap/v1 and label mailie/platform-wrap. k_pw_b64 is computed with HKDF and recorded only after a wrap sealed under it with the case's nonce was byte for byte the package's Seal. " +
			"The cross-product refusals open a wrap of one product as the other's: with the same person's product key of each product, with the same key bytes (only the labels and the key id's product differ), and with the wrap's own binding; those opened under Wappie's labels carry Wappie's op.",
		Cases: cases,
	}
	bad, cross := 0, 0
	for _, c := range cases {
		if c.Error != "" {
			bad++
		}
		if bytes.Contains([]byte(c.ID), []byte("/cross-product/")) {
			cross++
		}
	}
	if len(cases) != 60 || bad != 36 || cross != 7 {
		t.Fatalf("%d cases, %d must fail, %d across products; want 60, 36 and 7", len(cases), bad, cross)
	}
	raw, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	fh, err := os.OpenFile(filepath.Join(out, "platform-wrap-go.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	if _, err := fh.Write(append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
}
