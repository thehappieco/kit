package hpke_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/thehappieco/kit/hpke"
	"github.com/thehappieco/kit/internal/vectest"
)

func TestRoundTripAndBinding(t *testing.T) {
	pub, priv, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	info, aad, pt := []byte("thehappie-id/v1/key-delivery"), []byte(`["a",1]`), bytes.Repeat([]byte{7}, 32)
	enc, ct, err := hpke.Seal(pub, info, aad, pt)
	if err != nil || len(enc) != hpke.EncLen || len(ct) != len(pt)+hpke.TagLen {
		t.Fatalf("%d %d %v", len(enc), len(ct), err)
	}
	if got, err := hpke.Open(priv, enc, info, aad, ct); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("open: %v", err)
	}
	for name, open := range map[string]func() error{
		"other info": func() error { _, err := hpke.Open(priv, enc, []byte("x"), aad, ct); return err },
		"other aad":  func() error { _, err := hpke.Open(priv, enc, info, nil, ct); return err },
		"short enc":  func() error { _, err := hpke.Open(priv, enc[:31], info, aad, ct); return err },
		"zero enc":   func() error { _, err := hpke.Open(priv, make([]byte, 32), info, aad, ct); return err },
	} {
		if err := open(); !errors.Is(err, hpke.ErrOpen) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestKeys(t *testing.T) {
	pub, priv, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := priv.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	again, err := hpke.ParsePrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if derived, err := again.PublicKey(); err != nil || !bytes.Equal(derived.Bytes(), pub.Bytes()) {
		t.Fatalf("public half: %v", err)
	}
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := hpke.ParsePublicKey(make([]byte, n)); err == nil {
			t.Errorf("a %d byte public key was accepted", n)
		}
		if _, err := hpke.ParsePrivateKey(make([]byte, n)); err == nil {
			t.Errorf("a %d byte private key was accepted", n)
		}
	}
	var zero hpke.PrivateKey
	if zero.Valid() || (hpke.PublicKey{}).Valid() {
		t.Error("a zero key is valid")
	}
	if _, err := zero.Bytes(); err == nil {
		t.Error("a zero key has bytes")
	}
	if _, _, err := hpke.Seal(hpke.PublicKey{}, nil, nil, nil); err == nil {
		t.Error("sealed to no key")
	}
	if _, err := hpke.Open(zero, nil, nil, nil, nil); err == nil {
		t.Error("opened with no key")
	}
}

// TestWappieHPKEVectors opens what Wappie's WebCrypto HPKE sealed
// (golden/hpke-ts.json): the stdlib's crypto/hpke against an independent
// implementation of RFC 9180.
func TestWappieHPKEVectors(t *testing.T) {
	for _, f := range vectest.Files(t, "wappie/golden/hpke-ts.json", "kit/hpke-ts.json") {
		t.Run(f.Path, func(t *testing.T) { runHPKEFile(t, f) })
	}
}

func runHPKEFile(t *testing.T, f *vectest.File) {
	privs := map[string]hpke.PrivateKey{}
	for name, k := range f.Keys {
		priv, err := hpke.ParsePrivateKey(vectest.B64(t, k.PrivateKey))
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := priv.PublicKey()
		if !bytes.Equal(pub.Bytes(), vectest.B64(t, k.PublicKey)) {
			t.Fatalf("key %s: public half differs", name)
		}
		privs[name] = priv
	}
	for _, c := range f.Cases {
		if !c.ForGo() {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			var in struct {
				Key        string `json:"key"`
				Info       string `json:"info_b64"`
				AAD        string `json:"aad_b64"`
				Plaintext  string `json:"plaintext_b64"`
				Enc        string `json:"enc_b64"`
				Ciphertext string `json:"ciphertext_b64"`
				PrivateKey string `json:"private_key_b64"`
			}
			var out struct {
				Enc        string `json:"enc_b64"`
				Ciphertext string `json:"ciphertext_b64"`
				PublicKey  string `json:"public_key_b64"`
			}
			vectest.Decode(t, c.In, &in)
			if c.Error == "" {
				vectest.Decode(t, c.Out, &out)
			}
			b := func(s string) []byte { return vectest.B64(t, s) }
			switch c.Op {
			case "hpke.seal":
				got, err := hpke.Open(privs[in.Key], b(out.Enc), b(in.Info), b(in.AAD), b(out.Ciphertext))
				if err != nil || !bytes.Equal(got, b(in.Plaintext)) {
					t.Errorf("open: %v", err)
				}
			case "hpke.open":
				if _, err := hpke.Open(privs[in.Key], b(in.Enc), b(in.Info), b(in.AAD), b(in.Ciphertext)); !errors.Is(err, hpke.ErrOpen) || c.Error != "open_failed" {
					t.Errorf("error %v, want %s", err, c.Error)
				}
			case "hpke.public_from_private":
				priv, err := hpke.ParsePrivateKey(b(in.PrivateKey))
				if err != nil {
					t.Fatal(err)
				}
				pub, err := priv.PublicKey()
				if err != nil || !bytes.Equal(pub.Bytes(), b(out.PublicKey)) {
					t.Errorf("public %x: %v", pub.Bytes(), err)
				}
			default:
				vectest.Unhandled(t, c)
			}
		})
	}
}
