package hpke_test

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"testing"

	"github.com/thehappieco/kit/hpke"
	"github.com/thehappieco/kit/internal/forge"
)

// TestForgeIsHPKE checks the forger against crypto/hpke: given the real
// X25519 output, what it seals opens. So what it seals under an all-zero
// output is exactly what an implementation without the low-order check
// would open.
func TestForgeIsHPKE(t *testing.T) {
	pub, priv, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := priv.Bytes()
	recipient, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dh, err := ephemeral.ECDH(recipient.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	enc := ephemeral.PublicKey().Bytes()
	info, aad, pt := []byte("info"), []byte("aad"), []byte("forged the honest way")
	ct := forge.Seal(dh, enc, pub.Bytes(), info, aad, pt)
	if got, err := hpke.Open(priv, enc, info, aad, ct); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("crypto/hpke does not open what the forger seals with the real secret: %v", err)
	}
}

// TestLowOrder: RFC 9180 §7.1.4. An encapsulated key of low order gives the
// all-zero secret anybody can compute, so a ciphertext sealed under it is a
// forgery, and must not open; a public key of low order must not be sealed to.
func TestLowOrder(t *testing.T) {
	pub, priv, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	info, aad, pt := []byte("info"), []byte("aad"), bytes.Repeat([]byte{0xaa}, 32)
	for _, lo := range forge.LowOrder {
		t.Run(lo.Name, func(t *testing.T) {
			ct := forge.Seal(make([]byte, 32), lo.Point, pub.Bytes(), info, aad, pt)
			if got, err := hpke.Open(priv, lo.Point, info, aad, ct); !errors.Is(err, hpke.ErrOpen) {
				t.Errorf("opened a forgery: %x %v", got, err)
			}
			bad, err := hpke.ParsePublicKey(lo.Point)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if _, _, err := hpke.Seal(bad, info, aad, pt); !errors.Is(err, hpke.ErrInvalidKey) {
				t.Errorf("sealed to a low-order key: %v", err)
			}
		})
	}
}
