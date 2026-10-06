package wappie_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/thehappieco/kit/account"
	"github.com/thehappieco/kit/internal/vectest"
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

// TestWappiePlatformWrapVectors runs vectors/wappie/golden/platform-wrap-{go,ts}.json,
// which the console's two modules wrote (SPEC section 6.8): the info and the
// AAD byte for byte, every seal replayed from its nonce, every open back to
// its account key, and every refusal ErrPlatformWrap with nothing returned.
// A wrap is also the wrap envelope of section 6.5 with the header 0x03 and
// no legacy form: account.Unwrap opens it under K_pw, and K_pw seals it.
func TestWappiePlatformWrapVectors(t *testing.T) {
	counts := map[string]int{}
	for _, c := range vectest.Cases(t, "wappie/golden/platform-wrap-go.json", "wappie/golden/platform-wrap-ts.json") {
		if !c.ForGo() {
			continue
		}
		counts[c.Op]++
		if c.Error != "" {
			counts["refused"]++
		}
		t.Run(c.ID, func(t *testing.T) { platformWrapCase(t, c) })
	}
	want := map[string]int{"wappie.platform_wrap_info": 9, "wappie.platform_wrap_aad": 9, "wappie.platform_wrap_seal": 23, "wappie.platform_wrap_open": 36, "refused": 41}
	for op, n := range want {
		if counts[op] != n {
			t.Errorf("%s: %d cases, want %d", op, counts[op], n)
		}
	}
}

// platformWrapCase runs one case of the platform wrap's ops, from a golden
// file or from the kit's own round trips.
func platformWrapCase(t *testing.T, c vectest.Case) {
	var in wrapIn
	var out wrapOut
	strict(t, c.In, &in)
	if c.Error == "" {
		strict(t, c.Out, &out)
	} else if c.Error != "platform_wrap" {
		t.Fatalf("error %q, want platform_wrap", c.Error)
	}
	b := wappie.PlatformWrapBinding{UserID: in.UserID, Sub: in.Sub, ProductKeyID: in.ProductKeyID, AccountPublicKey: vectest.B64(t, in.AccountPublicKey)}
	refused := func(got []byte, err error) {
		t.Helper()
		if !errors.Is(err, wappie.ErrPlatformWrap) || got != nil {
			t.Fatalf("want ErrPlatformWrap and nothing, got %v", err)
		}
	}
	switch c.Op {
	case "wappie.platform_wrap_info":
		got, err := wappie.PlatformWrapInfo(b)
		if err != nil || !bytes.Equal(got, vectest.B64(t, out.Info)) {
			t.Fatalf("info: %v", err)
		}
	case "wappie.platform_wrap_aad":
		got, err := wappie.PlatformWrapAAD(b)
		if err != nil || !bytes.Equal(got, vectest.B64(t, out.AAD)) {
			t.Fatalf("aad: %v", err)
		}
	case "wappie.platform_wrap_seal":
		var r *bytes.Reader
		if in.Nonce != "" {
			r = bytes.NewReader(vectest.B64(t, in.Nonce))
		} else {
			r = bytes.NewReader(make([]byte, 12))
		}
		got, err := wappie.SealPlatformWrap(r, vectest.B64(t, in.ProductKey), vectest.B64(t, in.AccountKey), b)
		if c.Error != "" {
			refused(got, err)
			return
		}
		want := vectest.B64(t, out.Wrap)
		if err != nil || !bytes.Equal(got, want) || wappie.CheckPlatformWrapShape(got) != nil {
			t.Fatalf("seal: %v", err)
		}
		if back, err := wappie.OpenPlatformWrap(vectest.B64(t, in.ProductKey), got, b); err != nil || !bytes.Equal(back, vectest.B64(t, in.AccountKey)) {
			t.Fatalf("the seal does not open: %v", err)
		}
		if out.KPW != "" {
			// Section 6.5's envelope, header 0x03, no legacy form.
			aad, _ := wappie.PlatformWrapAAD(b)
			p := account.Profile{WrapHeader: []byte{wappie.PlatformWrapHeader}}
			key, stale, err := account.Unwrap(p, vectest.B64(t, out.KPW), want, aad)
			if err != nil || stale || !bytes.Equal(key, vectest.B64(t, in.AccountKey)) {
				t.Fatalf("account.Unwrap under k_pw: %v", err)
			}
			block, _ := aes.NewCipher(vectest.B64(t, out.KPW))
			gcm, _ := cipher.NewGCM(block)
			if !bytes.Equal(gcm.Seal(append([]byte{wappie.PlatformWrapHeader}, want[1:13]...), want[1:13], key, aad), want) {
				t.Fatal("k_pw does not seal the wrap")
			}
			info, _ := wappie.PlatformWrapInfo(b)
			if !bytes.Equal(hkdfKey(t, vectest.B64(t, in.ProductKey), info), vectest.B64(t, out.KPW)) {
				t.Fatal("k_pw is not section 6.8's HKDF")
			}
		}
	case "wappie.platform_wrap_open":
		if in.Wrap == nil {
			t.Fatal("an open without wrap_b64")
		}
		got, err := wappie.OpenPlatformWrap(vectest.B64(t, in.ProductKey), vectest.B64(t, *in.Wrap), b)
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

// TestKitWappiePlatformWrapVectors reproduces the kit's own round trips of
// the platform wrap that the TypeScript side wrote: the fresh file of that
// name in $KIT_CROSS_IN in the cross-language job.
func TestKitWappiePlatformWrapVectors(t *testing.T) {
	for _, c := range vectest.Fresh(t, "wappie-platform-wrap-ts.json") {
		if !c.ForGo() {
			continue
		}
		t.Run(c.ID, func(t *testing.T) { platformWrapCase(t, c) })
	}
}

// The two golden files: their headers, the case counts the PROVENANCE table
// records, and the bindings the kit asked for (an account key and a product
// key whose first byte is zero, the largest epoch).
func TestWappiePlatformWrapFiles(t *testing.T) {
	for _, w := range []struct {
		path, lang       string
		cases, mustFail  int
		zeroAccount      bool
		zeroProduct      bool
		largestEpochCase string
	}{
		{"wappie/golden/platform-wrap-go.json", "go", 55, 31, true, true, "wappie/platform-wrap/seal/largest-epoch"},
		{"wappie/golden/platform-wrap-ts.json", "ts", 22, 10, true, false, ""},
	} {
		f := vectest.Load(t, w.path)
		if f.Module != "wappie.platform_wrap" || f.Profile != "wappie" || f.GeneratedBy.Lang != w.lang {
			t.Errorf("%s: module %q, profile %q, lang %q", w.path, f.Module, f.Profile, f.GeneratedBy.Lang)
		}
		bad, zeroAccount, zeroProduct, largest := 0, false, false, w.largestEpochCase == ""
		for _, c := range f.Cases {
			if c.Error != "" {
				bad++
				continue
			}
			var in wrapIn
			strict(t, c.In, &in)
			if c.Op == "wappie.platform_wrap_seal" {
				zeroAccount = zeroAccount || vectest.B64(t, in.AccountKey)[0] == 0
				zeroProduct = zeroProduct || vectest.B64(t, in.ProductKey)[0] == 0
				largest = largest || (c.ID == w.largestEpochCase && in.ProductKeyID == "wappie:2147483647")
			}
		}
		if len(f.Cases) != w.cases || bad != w.mustFail {
			t.Errorf("%s: %d cases, %d must fail; want %d and %d", w.path, len(f.Cases), bad, w.cases, w.mustFail)
		}
		if zeroAccount != w.zeroAccount || zeroProduct != w.zeroProduct || !largest {
			t.Errorf("%s: a binding the kit asked for is missing", w.path)
		}
	}
}

// consoleVector and consoleRefusal are the console's own shapes
// (platformwrap/platformwrap_test.go at 3bfee27), field for field.
type consoleVector struct {
	Name             string `json:"name"`
	ProductKey       string `json:"product_key"`
	AccountKey       string `json:"account_key"`
	AccountPublicKey string `json:"account_public_key"`
	UserID           string `json:"user_id"`
	Sub              string `json:"sub"`
	ProductKeyID     string `json:"product_key_id"`
	Nonce            string `json:"nonce"`
	Info             string `json:"info"`
	AAD              string `json:"aad"`
	Wrap             string `json:"wrap"`
}

type consoleRefusal struct {
	Name             string `json:"name"`
	Vector           int    `json:"vector"`
	ProductKey       string `json:"product_key,omitempty"`
	AccountKey       string `json:"account_key,omitempty"`
	AccountPublicKey string `json:"account_public_key,omitempty"`
	UserID           string `json:"user_id,omitempty"`
	Sub              string `json:"sub,omitempty"`
	ProductKeyID     string `json:"product_key_id,omitempty"`
	Wrap             string `json:"wrap,omitempty"`
}

type consoleFile struct {
	Description  string           `json:"description"`
	Construction []string         `json:"construction"`
	Vectors      []consoleVector  `json:"vectors"`
	OpenRefusals []consoleRefusal `json:"open_refusals"`
	SealRefusals []consoleRefusal `json:"seal_refusals"`
}

func (r consoleRefusal) apply(v consoleVector) consoleVector {
	for _, f := range []struct {
		to   *string
		from string
	}{
		{&v.ProductKey, r.ProductKey}, {&v.AccountKey, r.AccountKey}, {&v.AccountPublicKey, r.AccountPublicKey},
		{&v.UserID, r.UserID}, {&v.Sub, r.Sub}, {&v.ProductKeyID, r.ProductKeyID}, {&v.Wrap, r.Wrap},
	} {
		if f.from != "" {
			*f.to = f.from
		}
	}
	return v
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (v consoleVector) binding(t testing.TB) wappie.PlatformWrapBinding {
	return wappie.PlatformWrapBinding{UserID: v.UserID, Sub: v.Sub, ProductKeyID: v.ProductKeyID, AccountPublicKey: unhex(t, v.AccountPublicKey)}
}

// consoleVectors is the console's generate() with this package's functions:
// the same labels, bindings and refusals, so it writes the console's file.
func consoleVectors(t *testing.T) consoleFile {
	t.Helper()
	digest := func(label string) []byte {
		sum := sha256.Sum256([]byte("wappie/platform-wrap vectors/" + label))
		return sum[:]
	}
	make1 := func(name, label, userID, sub, keyID string) consoleVector {
		sk, usk, nonce := digest(label+"/product key"), digest(label+"/account key"), digest(label + "/nonce")[:12]
		pub := x25519Public(t, usk)
		b := wappie.PlatformWrapBinding{UserID: userID, Sub: sub, ProductKeyID: keyID, AccountPublicKey: pub}
		wrap, err := wappie.SealPlatformWrap(bytes.NewReader(nonce), sk, usk, b)
		if err != nil {
			t.Fatal(err)
		}
		info, _ := wappie.PlatformWrapInfo(b)
		aad, _ := wappie.PlatformWrapAAD(b)
		return consoleVector{Name: name, ProductKey: hex.EncodeToString(sk), AccountKey: hex.EncodeToString(usk), AccountPublicKey: hex.EncodeToString(pub),
			UserID: userID, Sub: sub, ProductKeyID: keyID, Nonce: hex.EncodeToString(nonce), Info: string(info), AAD: string(aad), Wrap: hex.EncodeToString(wrap)}
	}
	vs := []consoleVector{
		make1("an account created through id. (users.id = sub)", "new", "0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b", "0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b", "wappie:1"),
		make1("a linked pilot account (users.id kept)", "linked", "01a08e0e-5a1c-7b2d-9e3f-4a5b6c7d8e9f", "019a2b3c-4d5e-7f60-8172-93a4b5c6d7e8", "wappie:1"),
		make1("the linked account at epoch 2", "epoch2", "01a08e0e-5a1c-7b2d-9e3f-4a5b6c7d8e9f", "019a2b3c-4d5e-7f60-8172-93a4b5c6d7e8", "wappie:2"),
	}
	flip := func(i int) string {
		w := unhex(t, vs[1].Wrap)
		w[i] ^= 0x01
		return hex.EncodeToString(w)
	}
	other := x25519Public(t, digest("other/account key"))
	// A wrap that authenticates under vector 1's K_pw and AAD but holds
	// another account's key, sealed directly since SealPlatformWrap refuses
	// to make it.
	foreign := func() string {
		v := vs[1]
		info, _ := wappie.PlatformWrapInfo(v.binding(t))
		aad, _ := wappie.PlatformWrapAAD(v.binding(t))
		kpw := hkdfKey(t, unhex(t, v.ProductKey), info)
		block, _ := aes.NewCipher(kpw)
		gcm, _ := cipher.NewGCM(block)
		out := append([]byte{wappie.PlatformWrapHeader}, digest("foreign/nonce")[:12]...)
		return hex.EncodeToString(gcm.Seal(out, out[1:13], digest("other/account key"), aad))
	}()
	return consoleFile{
		Description: "Wappie's platform wrap: the Wappie account key under a key derived from id.'s product key sk_p (platform decision 0023). " +
			"Keys, nonces and wraps are hex; info and aad are their UTF-8 text.",
		Construction: []string{
			"K_pw = HKDF-SHA256(IKM = product_key, salt = UTF-8(\"wappie/platform-wrap/v1\"), info = JCS([\"wappie/platform-wrap\", 1, user_id, sub, product_key_id]), L = 32)",
			"aad = JCS([\"wappie/platform-wrap\", 1, user_id, sub, product_key_id, base64url-unpadded(account_public_key)])",
			"wrap = 0x03 || nonce (12) || AES-256-GCM(K_pw, nonce, account_key (32), aad), 61 bytes",
			"Open also requires X25519(account_key, 9) == account_public_key; Seal refuses an account key whose public half is not account_public_key.",
		},
		Vectors: vs,
		OpenRefusals: []consoleRefusal{
			{Name: "another user_id", Vector: 1, UserID: "01a08e0e-5a1c-7b2d-9e3f-4a5b6c7d8e90"},
			{Name: "another sub", Vector: 1, Sub: "019a2b3c-4d5e-7f60-8172-93a4b5c6d7e9"},
			{Name: "another epoch", Vector: 1, ProductKeyID: "wappie:2"},
			{Name: "another account public key", Vector: 1, AccountPublicKey: hex.EncodeToString(other)},
			{Name: "another product key", Vector: 1, ProductKey: vs[2].ProductKey},
			{Name: "the epoch 2 wrap under epoch 1", Vector: 1, Wrap: vs[2].Wrap},
			{Name: "a flipped nonce byte", Vector: 1, Wrap: flip(1)},
			{Name: "a flipped ciphertext byte", Vector: 1, Wrap: flip(20)},
			{Name: "a flipped tag byte", Vector: 1, Wrap: flip(60)},
			{Name: "version 2", Vector: 1, Wrap: "02" + vs[1].Wrap[2:]},
			{Name: "60 bytes", Vector: 1, Wrap: vs[1].Wrap[:120]},
			{Name: "62 bytes", Vector: 1, Wrap: vs[1].Wrap + "00"},
			{Name: "an uppercase sub", Vector: 1, Sub: "019A2B3C-4D5E-7F60-8172-93A4B5C6D7E8"},
			{Name: "another product's key id", Vector: 1, ProductKeyID: "mailie:1"},
			{Name: "a wrap that opens under its AAD to another account's key", Vector: 1, Wrap: foreign},
		},
		SealRefusals: []consoleRefusal{
			{Name: "an account key that is not the public key's", Vector: 0, AccountKey: hex.EncodeToString(digest("other/account key"))},
			{Name: "a 31-byte product key", Vector: 0, ProductKey: vs[0].ProductKey[:62]},
			{Name: "a user_id that is not a lowercase UUID", Vector: 0, UserID: "not-a-uuid"},
			{Name: "an epoch with a leading zero", Vector: 0, ProductKeyID: "wappie:01"},
			{Name: "another product's key id", Vector: 0, ProductKeyID: "mailie:1"},
		},
	}
}

// TestWappiePlatformWrapConsoleVectors runs the console's own file
// (vectors/wappie/legacy/platform-wrap-vectors.json), decoded strictly in
// the console's shape: every vector sealed from its nonce and opened, every
// refusal refused. And it regenerates the file with this package, as the
// console's test does with its own, byte for byte.
func TestWappiePlatformWrapConsoleVectors(t *testing.T) {
	raw := vectest.Raw(t, "wappie/legacy/platform-wrap-vectors.json")
	var file consoleFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) != 3 || len(file.OpenRefusals) != 15 || len(file.SealRefusals) != 5 {
		t.Fatalf("%d vectors, %d and %d refusals; want 3, 15 and 5", len(file.Vectors), len(file.OpenRefusals), len(file.SealRefusals))
	}
	for _, v := range file.Vectors {
		b := v.binding(t)
		if info, err := wappie.PlatformWrapInfo(b); err != nil || string(info) != v.Info {
			t.Errorf("%s: info", v.Name)
		}
		if aad, err := wappie.PlatformWrapAAD(b); err != nil || string(aad) != v.AAD {
			t.Errorf("%s: aad", v.Name)
		}
		if w, err := wappie.SealPlatformWrap(bytes.NewReader(unhex(t, v.Nonce)), unhex(t, v.ProductKey), unhex(t, v.AccountKey), b); err != nil || hex.EncodeToString(w) != v.Wrap {
			t.Errorf("%s: seal: %v", v.Name, err)
		}
		if k, err := wappie.OpenPlatformWrap(unhex(t, v.ProductKey), unhex(t, v.Wrap), b); err != nil || hex.EncodeToString(k) != v.AccountKey {
			t.Errorf("%s: open: %v", v.Name, err)
		}
	}
	for _, r := range file.OpenRefusals {
		v := r.apply(file.Vectors[r.Vector])
		if k, err := wappie.OpenPlatformWrap(unhex(t, v.ProductKey), unhex(t, v.Wrap), v.binding(t)); !errors.Is(err, wappie.ErrPlatformWrap) || k != nil {
			t.Errorf("open refusal %q: %v", r.Name, err)
		}
	}
	for _, r := range file.SealRefusals {
		v := r.apply(file.Vectors[r.Vector])
		if w, err := wappie.SealPlatformWrap(nil, unhex(t, v.ProductKey), unhex(t, v.AccountKey), v.binding(t)); !errors.Is(err, wappie.ErrPlatformWrap) || w != nil {
			t.Errorf("seal refusal %q: %v", r.Name, err)
		}
	}
	again, err := json.MarshalIndent(consoleVectors(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(again, '\n'), raw) {
		t.Fatal("this package does not write the console's file byte for byte")
	}
}

// A seal draws a fresh nonce, leaves the caller's keys alone, and refuses a
// reader that runs dry and a binding without its public key; the server's
// check is the length and the header.
func TestWappiePlatformWrapUnits(t *testing.T) {
	sk, usk := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 32)
	b := wappie.PlatformWrapBinding{UserID: "0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b", Sub: "0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b", ProductKeyID: "wappie:1"}
	if w, err := wappie.SealPlatformWrap(nil, sk, usk, b); !errors.Is(err, wappie.ErrPlatformWrap) || w != nil {
		t.Fatal("sealed without the public key")
	}
	b.AccountPublicKey = x25519Public(t, usk)
	one, err := wappie.SealPlatformWrap(nil, sk, usk, b)
	if err != nil {
		t.Fatal(err)
	}
	two, err := wappie.SealPlatformWrap(nil, sk, usk, b)
	if err != nil || bytes.Equal(one[1:13], two[1:13]) || one[0] != 0x03 || len(one) != wappie.PlatformWrapLen || wappie.PlatformWrapLen != 61 {
		t.Fatalf("two fresh wraps: %v", err)
	}
	if !bytes.Equal(sk, bytes.Repeat([]byte{7}, 32)) || !bytes.Equal(usk, bytes.Repeat([]byte{9}, 32)) {
		t.Fatal("a caller's key changed")
	}
	if w, err := wappie.SealPlatformWrap(bytes.NewReader(make([]byte, 11)), sk, usk, b); !errors.Is(err, wappie.ErrPlatformWrap) || w != nil {
		t.Fatal("sealed with 11 bytes of nonce")
	}
	for _, w := range [][]byte{nil, one[:60], append(bytes.Clone(one), 0), append([]byte{0x01}, one[1:]...), append([]byte{0x02}, one[1:]...), append([]byte{0x00}, one[1:]...)} {
		if err := wappie.CheckPlatformWrapShape(w); !errors.Is(err, wappie.ErrPlatformWrap) {
			t.Fatalf("a shape of %d bytes starting %#x accepted", len(w), w)
		}
		if k, err := wappie.OpenPlatformWrap(sk, w, b); !errors.Is(err, wappie.ErrPlatformWrap) || k != nil {
			t.Fatal("opened a wrap of the wrong shape")
		}
	}
	if err := wappie.CheckPlatformWrapShape(one); err != nil {
		t.Fatal(err)
	}
	// The labels are Wappie's and distinct from every label of the kit's
	// appendices; the binding is in the info and in the AAD.
	if wappie.PlatformWrapLabel != "wappie/platform-wrap" || wappie.PlatformWrapSalt != "wappie/platform-wrap/v1" || wappie.PlatformWrapProduct != "wappie" || wappie.PlatformWrapHeader != 0x03 {
		t.Fatal("a constant of SPEC section 6.8 changed")
	}
	// A wrap of one account does not open as another's (the binding is
	// the HKDF info as well as the AAD).
	for _, other := range []wappie.PlatformWrapBinding{
		{UserID: "0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c", Sub: b.Sub, ProductKeyID: b.ProductKeyID, AccountPublicKey: b.AccountPublicKey},
		{UserID: b.UserID, Sub: b.Sub, ProductKeyID: "wappie:2", AccountPublicKey: b.AccountPublicKey},
	} {
		if k, err := wappie.OpenPlatformWrap(sk, one, other); !errors.Is(err, wappie.ErrPlatformWrap) || k != nil {
			t.Fatal("opened under another binding")
		}
	}
}

// Wappie's three 61-byte envelopes of the account key are told apart by
// their first byte (SPEC section 6.8): a platform wrap is no password wrap
// and no passkey envelope, and neither of those is a platform wrap.
func TestWappiePlatformWrapHeaderIsNoOtherEnvelopes(t *testing.T) {
	if wappie.PlatformWrapHeader == wappie.Account().WrapHeader[0] || wappie.PlatformWrapHeader == wappie.Passkey().Header[0] {
		t.Fatal("the platform wrap shares a header with another envelope of the account key")
	}
	if len(wappie.Account().WrapHeader) != 1 || len(wappie.Passkey().Header) != 1 {
		t.Fatal("another envelope's header is not one byte")
	}
}

// FuzzOpenPlatformWrap: no input panics; every refusal is ErrPlatformWrap
// with nothing returned; and whatever opens is a 32-byte key whose public
// half is the binding's, which a fresh seal under the same binding opens to
// again. Seeded from both golden files.
func FuzzOpenPlatformWrap(f *testing.F) {
	for _, c := range vectest.Cases(f, "wappie/golden/platform-wrap-go.json", "wappie/golden/platform-wrap-ts.json") {
		var in wrapIn
		strict(f, c.In, &in)
		if in.Wrap != nil {
			f.Add(vectest.B64(f, in.ProductKey), vectest.B64(f, *in.Wrap), in.UserID, in.Sub, in.ProductKeyID, vectest.B64(f, in.AccountPublicKey))
		}
	}
	f.Fuzz(func(t *testing.T, sk, wrap []byte, userID, sub, keyID string, pub []byte) {
		b := wappie.PlatformWrapBinding{UserID: userID, Sub: sub, ProductKeyID: keyID, AccountPublicKey: pub}
		key, err := wappie.OpenPlatformWrap(sk, wrap, b)
		if err != nil {
			if !errors.Is(err, wappie.ErrPlatformWrap) || key != nil {
				t.Fatalf("an unclassified refusal: %v", err)
			}
			return
		}
		if len(key) != 32 || !bytes.Equal(x25519Public(t, key), pub) {
			t.Fatal("opened to a key that is not the binding's")
		}
		again, err := wappie.SealPlatformWrap(nil, sk, key, b)
		if err != nil {
			t.Fatal(err)
		}
		if k, err := wappie.OpenPlatformWrap(sk, again, b); err != nil || !bytes.Equal(k, key) {
			t.Fatal("a fresh seal does not open")
		}
	})
}

// hkdfKey is K_pw, computed here from SPEC section 6.8 rather than taken
// from the package.
func hkdfKey(t testing.TB, productKey, info []byte) []byte {
	t.Helper()
	k, err := hkdf.Key(sha256.New, productKey, []byte("wappie/platform-wrap/v1"), string(info), 32)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
