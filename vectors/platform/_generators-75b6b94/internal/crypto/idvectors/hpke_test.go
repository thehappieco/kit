//go:build go1.26

package idvectors

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/hex"
	"testing"

	idcrypto "github.com/thehappieco/kit/profiles/platform"
)

// rfc9180Vector is the one RFC 9180 test vector for the key-delivery suite:
// mode 0 (base), KEM 0x0020 DHKEM(X25519, HKDF-SHA256), KDF 0x0001
// HKDF-SHA256, AEAD 0x0002 AES-256-GCM, and its first encryption (sequence
// number 0, the only one a single-shot seal makes).
//
// Source: the CFRG test vectors that accompany RFC 9180,
// https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/master/test-vectors.json
// (fetched 2026-10-01; the file's SHA-256 was
// 61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6), the
// entry with those four ids. The RFC's own appendix prints only the
// AES-128-GCM and ChaCha20-Poly1305 variants of this KEM; this one is in the
// JSON file. Go's src/crypto/hpke/testdata/rfc9180.json carries the same
// entry in an accumulated form (same ikmE, ikmR, skRm, pkRm and enc).
var rfc9180Vector = struct {
	info, skRm, pkRm, skEm, pkEm, enc string
	sharedSecret, keyScheduleContext  string
	secret, key, baseNonce            string
	aad, pt, ct                       string
}{
	info:               "4f6465206f6e2061204772656369616e2055726e",
	skRm:               "497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d",
	pkRm:               "430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c",
	skEm:               "179d4b53b6365c45b600c4163b61d95cbc2f4d9e36f1695558dce265ab8bab11",
	pkEm:               "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256",
	enc:                "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256",
	sharedSecret:       "3101c54c3a4f87439eaac080699ed9bbcc726ffe44e860c0424ccb7e3e2ead7b",
	keyScheduleContext: "004ce5472ecdd5093ba0aecb8f871ff13f1fbc90ee76f0e18ace1a1b7e565bafa306f6ef962c9ee7cea40407b5d60f0f26990472faae3ac44c78366f1cac1ecde1",
	secret:             "2058ac9b02c1f52c1aaf08bedbec9198219751a94ef67b7d5f0c8b6e2b54ebfb",
	key:                "f50b0609186798729ed0564b36ef2ef8044f1f9d05636874d1f46c819c7a669f",
	baseNonce:          "151d9929e2449747889bc923",
	aad:                "436f756e742d30",
	pt:                 "4265617574792069732074727574682c20747275746820626561757479",
	ct:                 "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a",
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal("a test vector value is not hex")
	}
	return b
}

func TestTheDeterministicSealReproducesTheRFC9180VectorForThisSuite(t *testing.T) {
	v := rfc9180Vector
	pkR := unhex(t, v.pkRm)
	c, err := setupBaseS(pkR, unhex(t, v.skEm), unhex(t, v.info))
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		name      string
		got, want []byte
	}{
		{"enc", c.enc, unhex(t, v.enc)},
		{"enc (pkEm)", c.enc, unhex(t, v.pkEm)},
		{"shared_secret", c.sharedSecret, unhex(t, v.sharedSecret)},
		{"key_schedule_context", c.keyScheduleContext, unhex(t, v.keyScheduleContext)},
		{"secret", c.secret, unhex(t, v.secret)},
		{"key", c.key, unhex(t, v.key)},
		{"base_nonce", c.baseNonce, unhex(t, v.baseNonce)},
	} {
		if !bytes.Equal(step.got, step.want) {
			t.Errorf("%s differs from RFC 9180", step.name)
		}
	}
	ct, err := c.sealFirst(unhex(t, v.aad), unhex(t, v.pt))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ct, unhex(t, v.ct)) {
		t.Error("the first ciphertext differs from RFC 9180")
	}
	sealed, err := sealBase(pkR, unhex(t, v.skEm), unhex(t, v.info), unhex(t, v.aad), unhex(t, v.pt))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sealed, cat(unhex(t, v.enc), unhex(t, v.ct))) {
		t.Error("sealBase is not enc || ct of RFC 9180")
	}

	// And crypto/hpke, which the product side uses, opens the RFC's
	// ciphertext to the RFC's plaintext with the RFC's recipient key.
	skR, err := hpke.DHKEM(ecdh.X25519()).NewPrivateKey(unhex(t, v.skRm))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(skR.PublicKey().Bytes(), pkR) {
		t.Fatal("skRm does not give pkRm")
	}
	r, err := hpke.NewRecipient(unhex(t, v.enc), skR, hpke.HKDFSHA256(), hpke.AES256GCM(), unhex(t, v.info))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := r.Open(unhex(t, v.aad), unhex(t, v.ct))
	if err != nil || !bytes.Equal(pt, unhex(t, v.pt)) {
		t.Fatalf("crypto/hpke does not open the RFC 9180 ciphertext: %v", err)
	}
}

func TestCryptoHPKEOpensEverythingTheDeterministicSealSeals(t *testing.T) {
	kem, kdf, aead := hpke.DHKEM(ecdh.X25519()), hpke.HKDFSHA256(), hpke.AES256GCM()
	for i := range 200 {
		skR, err := kem.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		skE := random(t, 32)
		// Lengths from empty upwards, including the 32 bytes of a product
		// key and the AAD sizes key delivery uses.
		info, aad, pt := random(t, i%70), random(t, (i*7)%300), random(t, (i*3)%97)
		sealed, err := sealBase(skR.PublicKey().Bytes(), skE, info, aad, pt)
		if err != nil {
			t.Fatal(err)
		}
		if len(sealed) != 32+len(pt)+16 {
			t.Fatalf("case %d: %d bytes sealed", i, len(sealed))
		}
		r, err := hpke.NewRecipient(sealed[:32], skR, kdf, aead, info)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		got, err := r.Open(aad, sealed[32:])
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("case %d: crypto/hpke does not open the deterministic seal: %v", i, err)
		}
		// The single-shot API, which binds no AAD, opens it too when the
		// AAD is empty.
		if len(aad) == 0 {
			got, err := hpke.Open(skR, kdf, aead, info, sealed)
			if err != nil || !bytes.Equal(got, pt) {
				t.Fatalf("case %d: hpke.Open does not open the deterministic seal: %v", i, err)
			}
		}
		// The same ephemeral key gives the same bytes: the point of this seal.
		again, err := sealBase(skR.PublicKey().Bytes(), skE, info, aad, pt)
		if err != nil || !bytes.Equal(again, sealed) {
			t.Fatalf("case %d: the seal is not deterministic", i)
		}
	}
}

func TestTheDeterministicSealRefusesALowOrderRecipient(t *testing.T) {
	for _, pkR := range [][]byte{make([]byte, 32), append([]byte{1}, make([]byte, 31)...)} {
		if _, err := sealBase(pkR, random(t, 32), nil, nil, random(t, 32)); err == nil {
			t.Fatal("sealed to a low-order point")
		}
	}
}

// TestAnEncSpelledWithBit255OpensInCryptoHPKEButNotInOpenProductKey proves
// that the must-fail vector for a non-canonical enc tests something: the
// aliased blob is a valid RFC 9180 seal that crypto/hpke opens, and only the
// opener's canonical check refuses it.
func TestAnEncSpelledWithBit255OpensInCryptoHPKEButNotInOpenProductKey(t *testing.T) {
	flow := kdFlow{
		root: random(t, 32), product: "wappie", epoch: 1,
		issuer: prodIssuer, clientID: "wappie-app", redirectURI: wappieRedirect,
		sub:           "0199e4b2-3c41-7a52-8f3e-9b1d2c4e5f60",
		codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		nonce:         "n-0S6_WzA2Mj4Rm7tBQdLwK1vHqXf9cUe3yPbJsZkGo",
		akdPriv:       random(t, 32), ephSK: random(t, 32),
	}
	b, sk, err := flow.binding()
	if err != nil {
		t.Fatal(err)
	}
	akdPub, err := x25519Public(flow.akdPriv)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := idcrypto.KeyDeliveryAAD(b)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := x25519Public(flow.ephSK)
	if err != nil {
		t.Fatal(err)
	}
	alias := bytes.Clone(enc)
	alias[31] |= 0x80
	info := []byte(idcrypto.KeyDeliveryInfo)
	aliased, err := sealBaseAs(akdPub, flow.ephSK, alias, info, aad, sk)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aliased[:32], alias) {
		t.Fatal("the blob does not carry the aliased enc")
	}

	kem := hpke.DHKEM(ecdh.X25519())
	skR, err := kem.NewPrivateKey(flow.akdPriv)
	if err != nil {
		t.Fatal(err)
	}
	r, err := hpke.NewRecipient(aliased[:32], skR, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		t.Fatalf("crypto/hpke refuses the aliased enc: %v", err)
	}
	if got, err := r.Open(aad, aliased[32:]); err != nil || !bytes.Equal(got, sk) {
		t.Fatalf("crypto/hpke does not open the aliased seal: %v", err)
	}
	if got, err := idcrypto.OpenProductKey(flow.akdPriv, aliased, b); idcrypto.ErrorCode(err) != "key_delivery" || got != nil {
		t.Fatalf("OpenProductKey: %v, want key_delivery", err)
	}
	// The canonical spelling of the same seal opens.
	canonical, err := sealBase(akdPub, flow.ephSK, info, aad, sk)
	if err != nil {
		t.Fatal(err)
	}
	got, err := idcrypto.OpenProductKey(flow.akdPriv, canonical, b)
	if err != nil || !bytes.Equal(got, sk) {
		t.Fatalf("the canonical seal does not open: %v", err)
	}
	// sealBaseAs takes only the bit-255 spelling of the ephemeral key.
	for _, wrong := range [][]byte{enc, alias[:31], random(t, 32)} {
		if _, err := sealBaseAs(akdPub, flow.ephSK, wrong, info, aad, sk); err == nil {
			t.Fatal("sealBaseAs took an enc that is not the ephemeral key with bit 255 set")
		}
	}
}

func random(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
