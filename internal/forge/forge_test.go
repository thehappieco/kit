package forge_test

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/thehappieco/kit/hpke"
	"github.com/thehappieco/kit/internal/forge"
)

// rfc9180Vector is the one RFC 9180 test vector for the suite of package
// hpke: mode 0 (base), KEM 0x0020 DHKEM(X25519, HKDF-SHA256), KDF 0x0001
// HKDF-SHA256, AEAD 0x0002 AES-256-GCM, and its first encryption (sequence
// number 0, the only one a single-shot seal makes).
//
// Source: the CFRG test vectors that accompany RFC 9180,
// https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/master/test-vectors.json
// (fetched by the platform on 2026-10-01, sha256
// 61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6), the
// entry with those four ids, as the platform's
// idvectors/hpke_test.go at 4476bf4 records it. The values are copied here;
// nothing is fetched.
var rfc9180Vector = struct {
	info, skRm, pkRm, skEm, enc string
	aad, pt, ct                 string
}{
	info: "4f6465206f6e2061204772656369616e2055726e",
	skRm: "497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d",
	pkRm: "430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c",
	skEm: "179d4b53b6365c45b600c4163b61d95cbc2f4d9e36f1695558dce265ab8bab11",
	enc:  "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256",
	aad:  "436f756e742d30",
	pt:   "4265617574792069732074727574682c20747275746820626561757479",
	ct:   "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a",
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal("a test vector value is not hex")
	}
	return b
}

// SealBase with the vector's ephemeral key is enc || ct of RFC 9180, and
// package hpke (crypto/hpke) opens it with the vector's recipient key.
func TestSealBaseIsTheCFRGVector(t *testing.T) {
	v := rfc9180Vector
	got, err := forge.SealBase(unhex(t, v.pkRm), unhex(t, v.skEm), unhex(t, v.info), unhex(t, v.aad), unhex(t, v.pt))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, append(unhex(t, v.enc), unhex(t, v.ct)...)) {
		t.Fatal("SealBase is not enc || ct of the RFC 9180 vector")
	}
	priv, err := hpke.ParsePrivateKey(unhex(t, v.skRm))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.PublicKey()
	if err != nil || !bytes.Equal(pub.Bytes(), unhex(t, v.pkRm)) {
		t.Fatal("skRm does not give pkRm")
	}
	pt, err := hpke.Open(priv, unhex(t, v.enc), unhex(t, v.info), unhex(t, v.aad), unhex(t, v.ct))
	if err != nil || !bytes.Equal(pt, unhex(t, v.pt)) {
		t.Fatalf("package hpke does not open the RFC 9180 ciphertext: %v", err)
	}
}

// What SealBase seals under fresh keys, package hpke opens.
func TestSealBaseIsHPKE(t *testing.T) {
	for range 64 {
		pub, priv, err := hpke.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		eph, err := ecdh.X25519().GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		info, aad, pt := []byte("info"), []byte("aad"), bytes.Repeat([]byte{0x5a}, 32)
		sealed, err := forge.SealBase(pub.Bytes(), eph.Bytes(), info, aad, pt)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sealed[:hpke.EncLen], eph.PublicKey().Bytes()) {
			t.Fatal("enc is not X25519(skE, 9)")
		}
		got, err := hpke.Open(priv, sealed[:hpke.EncLen], info, aad, sealed[hpke.EncLen:])
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("package hpke does not open SealBase: %v", err)
		}
	}
}

// SealBase refuses a recipient of low order, as RFC 9180 section 7.1.4
// requires: crypto/ecdh refuses the all-zero output.
func TestSealBaseRefusesLowOrderRecipients(t *testing.T) {
	eph := bytes.Repeat([]byte{0x11}, 32)
	for _, lo := range forge.LowOrder {
		if _, err := forge.SealBase(lo.Point, eph, nil, nil, []byte("x")); err == nil {
			t.Errorf("%s: sealed to a low-order key", lo.Name)
		}
	}
}

// Only tests import package forge: a seal under a chosen ephemeral key, or
// under a chosen secret, must never reach a consumer of the kit. Every .go
// file of the module that is not a _test.go file is parsed for its imports.
func TestOnlyTestsImportForge(t *testing.T) {
	const self = "github.com/thehappieco/kit/internal/forge"
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if rel == ".git" || rel == "js" || strings.HasPrefix(d.Name(), "_") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if filepath.Dir(rel) == filepath.Join("internal", "forge") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		checked++
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == self {
				t.Errorf("%s imports internal/forge; only tests may", rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 20 {
		t.Fatalf("only %d files checked", checked)
	}
}
