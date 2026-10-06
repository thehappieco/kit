package platformwrap

// The kit's generator of vectors/wappie/golden/platform-wrap-go.json. The
// kit's vectors/wappie/_generators/run-cloud.sh places it beside this
// package, in a git archive of the console commit PROVENANCE.md records
// (with the header patch recorded there, if any), and runs it. It writes the
// kit's format (thehappieco-kit-vectors/1) from this package's own Seal,
// Open, Info and AAD. Every key and nonce is SHA-256 of a fixed label: the
// package's own three vectors keep the package's labels, so their wraps are
// the console's testdata/vectors.json's; the kit's additions use labels of
// their own. K_pw, which the package keeps inside an AEAD, is computed here
// with HKDF and recorded only once a wrap sealed under it with the case's
// nonce is byte for byte the package's. Every refusal is checked against the
// package before it is written, and the file is opened with O_EXCL.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type kitCase struct {
	ID    string         `json:"id"`
	Op    string         `json:"op"`
	In    map[string]any `json:"in"`
	Out   map[string]any `json:"out,omitempty"`
	Error string         `json:"error,omitempty"`
}

func kitDigest(label string) []byte {
	sum := sha256.Sum256([]byte("wappie/platform-wrap kit vectors/" + label))
	return sum[:]
}

var std = base64.StdEncoding.EncodeToString

func TestKitGenPlatformWrap(t *testing.T) {
	out := os.Getenv("KITGEN_OUT")
	if out == "" {
		t.Skip("KITGEN_OUT is not set")
	}
	if Version != 0x03 {
		t.Fatalf("the package's first byte is %#x; SPEC section 6.8 fixes 0x03", Version)
	}
	var cases []kitCase
	type vec struct {
		name, userID, sub, keyID string
		sk, usk, nonce           []byte
	}
	// The package's own three vectors, from its own labels, and the kit's
	// additions: an account key whose first byte is zero (WebKit for Linux
	// imports such a key only through the kit's X25519 engine), a product
	// key whose first byte is zero, and the largest epoch.
	zeroFirst := func(label string) []byte {
		for i := 0; ; i++ {
			k := kitDigest(label + "/" + string(rune('a'+i%26)) + string(rune('a'+i/26)))
			if k[0] == 0 {
				return k
			}
		}
	}
	vs := []vec{
		{"new", "0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b", "0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b", "wappie:1", digest("new/product key"), digest("new/account key"), digest("new/nonce")[:nonceLen]},
		{"linked", "01a08e0e-5a1c-7b2d-9e3f-4a5b6c7d8e9f", "019a2b3c-4d5e-7f60-8172-93a4b5c6d7e8", "wappie:1", digest("linked/product key"), digest("linked/account key"), digest("linked/nonce")[:nonceLen]},
		{"epoch-2", "01a08e0e-5a1c-7b2d-9e3f-4a5b6c7d8e9f", "019a2b3c-4d5e-7f60-8172-93a4b5c6d7e8", "wappie:2", digest("epoch2/product key"), digest("epoch2/account key"), digest("epoch2/nonce")[:nonceLen]},
		{"account-key-zero-first-byte", "0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c", "0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c", "wappie:1", kitDigest("zero-account/product key"), zeroFirst("zero-account/account key"), kitDigest("zero-account/nonce")[:nonceLen]},
		{"product-key-zero-first-byte", "0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2d", "0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2d", "wappie:3", zeroFirst("zero-product/product key"), kitDigest("zero-product/account key"), kitDigest("zero-product/nonce")[:nonceLen]},
		{"largest-epoch", "0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2e", "019a2b3c-4d5e-7f60-8172-93a4b5c6d7e9", "wappie:2147483647", kitDigest("max-epoch/product key"), kitDigest("max-epoch/account key"), kitDigest("max-epoch/nonce")[:nonceLen]},
	}
	binding := func(v vec, pub []byte) map[string]any {
		return map[string]any{"user_id": v.userID, "sub": v.sub, "product_key_id": v.keyID, "account_public_key_b64": std(pub)}
	}
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
	wraps := map[string][]byte{}
	for _, v := range vs {
		pub, err := publicKey(v.usk)
		if err != nil {
			t.Fatal(err)
		}
		b := Binding{UserID: v.userID, Sub: v.sub, ProductKeyID: v.keyID, AccountPublicKey: pub}
		info, err := Info(b)
		if err != nil {
			t.Fatal(err)
		}
		aad, err := AAD(b)
		if err != nil {
			t.Fatal(err)
		}
		wrap, err := Seal(bytes.NewReader(v.nonce), v.sk, v.usk, b)
		if err != nil {
			t.Fatal(err)
		}
		// K_pw, computed here and proved against the package's wrap.
		kpw, err := hkdf.Key(sha256.New, v.sk, []byte(SaltLabel), string(info), keyLen)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := aes.NewCipher(kpw)
		gcm, _ := cipher.NewGCM(block)
		if !bytes.Equal(gcm.Seal(append([]byte{Version}, v.nonce...), v.nonce, v.usk, aad), wrap) {
			t.Fatalf("%s: K_pw does not make the package's wrap", v.name)
		}
		if opened, err := Open(v.sk, wrap, b); err != nil || !bytes.Equal(opened, v.usk) {
			t.Fatalf("%s: the wrap does not open", v.name)
		}
		wraps[v.name] = wrap
		bi := binding(v, pub)
		cases = append(cases,
			kitCase{ID: "wappie/platform-wrap/info/" + v.name, Op: "wappie.platform_wrap_info", In: bi, Out: map[string]any{"info_b64": std(info)}},
			kitCase{ID: "wappie/platform-wrap/aad/" + v.name, Op: "wappie.platform_wrap_aad", In: bi, Out: map[string]any{"aad_b64": std(aad)}},
			kitCase{ID: "wappie/platform-wrap/seal/" + v.name, Op: "wappie.platform_wrap_seal", In: with(bi, "product_key_b64", std(v.sk), "account_key_b64", std(v.usk), "nonce_b64", std(v.nonce)), Out: map[string]any{"wrap_b64": std(wrap), "k_pw_b64": std(kpw)}},
			kitCase{ID: "wappie/platform-wrap/open/" + v.name, Op: "wappie.platform_wrap_open", In: with(bi, "product_key_b64", std(v.sk), "wrap_b64", std(wrap)), Out: map[string]any{"account_key_b64": std(v.usk)}},
		)
	}
	// Refusals, all of vector "linked", one thing changed each.
	l := vs[1]
	lpub, _ := publicKey(l.usk)
	lw := wraps["linked"]
	lb := with(binding(l, lpub), "product_key_b64", std(l.sk))
	other, _ := publicKey(digest("other/account key"))
	flip := func(i int) []byte { w := bytes.Clone(lw); w[i] ^= 1; return w }
	header := func(h byte) []byte { w := bytes.Clone(lw); w[0] = h; return w }
	foreign := func() []byte {
		b := Binding{UserID: l.userID, Sub: l.sub, ProductKeyID: l.keyID, AccountPublicKey: lpub}
		aead, _ := wrapKey(l.sk, b)
		aad, _ := AAD(b)
		o := append([]byte{Version}, digest("foreign/nonce")[:nonceLen]...)
		return aead.Seal(o, o[1:1+nonceLen], digest("other/account key"), aad)
	}()
	openRefusals := []struct {
		id string
		in map[string]any
	}{
		{"another-user-id", with(lb, "wrap_b64", std(lw), "user_id", "01a08e0e-5a1c-7b2d-9e3f-4a5b6c7d8e90")},
		{"another-sub", with(lb, "wrap_b64", std(lw), "sub", "019a2b3c-4d5e-7f60-8172-93a4b5c6d7e9")},
		{"another-epoch", with(lb, "wrap_b64", std(lw), "product_key_id", "wappie:2")},
		{"another-account-public-key", with(lb, "wrap_b64", std(lw), "account_public_key_b64", std(other))},
		{"another-product-key", with(lb, "wrap_b64", std(lw), "product_key_b64", std(vs[2].sk))},
		{"the-epoch-2-wrap", with(lb, "wrap_b64", std(wraps["epoch-2"]))},
		{"flipped-nonce", with(lb, "wrap_b64", std(flip(1)))},
		{"flipped-ciphertext", with(lb, "wrap_b64", std(flip(20)))},
		{"flipped-tag", with(lb, "wrap_b64", std(flip(60)))},
		{"header-0x01-the-passkey-envelope", with(lb, "wrap_b64", std(header(0x01)))},
		{"header-0x02-the-password-wrap", with(lb, "wrap_b64", std(header(0x02)))},
		{"header-0x00", with(lb, "wrap_b64", std(header(0x00)))},
		{"length-60", with(lb, "wrap_b64", std(lw[:60]))},
		{"length-62", with(lb, "wrap_b64", std(append(bytes.Clone(lw), 0)))},
		{"empty", with(lb, "wrap_b64", "")},
		{"sub-in-upper-case", with(lb, "wrap_b64", std(lw), "sub", "019A2B3C-4D5E-7F60-8172-93A4B5C6D7E8")},
		{"another-products-key-id", with(lb, "wrap_b64", std(lw), "product_key_id", "mailie:1")},
		{"product-key-of-31-bytes", with(lb, "wrap_b64", std(lw), "product_key_b64", std(l.sk[:31]))},
		{"account-public-key-of-31-bytes", with(lb, "wrap_b64", std(lw), "account_public_key_b64", std(lpub[:31]))},
		{"opens-to-another-accounts-key", with(lb, "wrap_b64", std(foreign))},
	}
	for _, r := range openRefusals {
		if _, err := Open(b64(t, r.in["product_key_b64"]), b64(t, r.in["wrap_b64"]), bindingOf(t, r.in)); !errors.Is(err, ErrWrap) {
			t.Fatalf("open refusal %s: %v", r.id, err)
		}
		cases = append(cases, kitCase{ID: "wappie/platform-wrap/open/refuses/" + r.id, Op: "wappie.platform_wrap_open", In: r.in, Error: "platform_wrap"})
	}
	n := vs[0]
	npub, _ := publicKey(n.usk)
	nb := with(binding(n, npub), "product_key_b64", std(n.sk), "account_key_b64", std(n.usk))
	sealRefusals := []struct {
		id string
		in map[string]any
	}{
		{"account-key-not-the-public-keys", with(nb, "account_key_b64", std(digest("other/account key")))},
		{"account-key-of-31-bytes", with(nb, "account_key_b64", std(n.usk[:31]))},
		{"product-key-of-31-bytes", with(nb, "product_key_b64", std(n.sk[:31]))},
		{"product-key-of-33-bytes", with(nb, "product_key_b64", std(append(bytes.Clone(n.sk), 0)))},
		{"user-id-not-a-uuid", with(nb, "user_id", "not-a-uuid")},
		{"user-id-in-upper-case", with(nb, "user_id", "0199A1B2-C3D4-7E5F-8A6B-7C8D9E0F1A2B")},
		{"epoch-with-a-leading-zero", with(nb, "product_key_id", "wappie:01")},
		{"epoch-0", with(nb, "product_key_id", "wappie:0")},
		{"epoch-2147483648", with(nb, "product_key_id", "wappie:2147483648")},
		{"another-products-key-id", with(nb, "product_key_id", "mailie:1")},
		{"no-epoch", with(nb, "product_key_id", "wappie")},
	}
	for _, r := range sealRefusals {
		if _, err := Seal(nil, b64(t, r.in["product_key_b64"]), b64(t, r.in["account_key_b64"]), bindingOf(t, r.in)); !errors.Is(err, ErrWrap) {
			t.Fatalf("seal refusal %s: %v", r.id, err)
		}
		cases = append(cases, kitCase{ID: "wappie/platform-wrap/seal/refuses/" + r.id, Op: "wappie.platform_wrap_seal", In: r.in, Error: "platform_wrap"})
	}
	// In the order of the kit's other files: format, module, profile,
	// generated_by, note, cases.
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
		Module:  "wappie.platform_wrap",
		Profile: "wappie",
		GeneratedBy: source{
			Lang:       "go",
			Source:     "github.com/thehappieco/wappie-cloud@" + os.Getenv("KITGEN_COMMIT") + " platformwrap" + os.Getenv("KITGEN_PATCHED"),
			Toolchain:  runtime.Version(),
			Randomness: "none: every key and nonce is SHA-256 of a fixed label",
			Generator:  "vectors/wappie/_generators/cloud/platformwrap/kitgen_internal_test.go",
		},
		Note: "Wappie's platform wrap (SPEC section 6.8), written by the console's Go package. k_pw_b64 is computed by the generator with HKDF and recorded only after a wrap sealed under it with the case's nonce was byte for byte the package's Seal. " +
			"The bindings new, linked and epoch-2 are the package's own vectors, with its labels; the others are the kit's: an account key whose first byte is zero, a product key whose first byte is zero, and the largest epoch.",
		Cases: cases,
	}
	raw, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(out, "platform-wrap-go.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
}

func b64(t *testing.T, v any) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(v.(string))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func bindingOf(t *testing.T, in map[string]any) Binding {
	return Binding{UserID: in["user_id"].(string), Sub: in["sub"].(string), ProductKeyID: in["product_key_id"].(string), AccountPublicKey: b64(t, in["account_public_key_b64"])}
}
