// Package forge seals HPKE ciphertexts under a chosen Diffie-Hellman output,
// for tests that need what an attacker can make, and under a chosen
// ephemeral key, for tests that replay a recorded seal byte for byte.
//
// With an encapsulated key of low order, X25519 gives 32 zero bytes whatever
// the recipient's private key, so anybody who knows the recipient's public key
// can run the rest of DHKEM and the key schedule and seal under the result. A
// conforming recipient refuses such a key (RFC 9180 §7.1.4); one that does
// not opens what Seal makes. The kit's vectors carry these forgeries so that
// an implementation missing the check fails them.
//
// A seal under a known ephemeral key is readable by anyone who knows that
// key, so no shipped function of the kit takes one: SealBase lives here, in
// an internal package, and TestOnlyTestsImportForge fails if any file but a
// test imports it.
//
// Test code only: nothing outside the kit's tests imports it.
package forge

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// The suite of package hpke: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
// AES-256-GCM.
var (
	kemSuite  = []byte{'K', 'E', 'M', 0x00, 0x20}
	hpkeSuite = []byte{'H', 'P', 'K', 'E', 0x00, 0x20, 0x00, 0x01, 0x00, 0x02}
)

// LowOrder names X25519 u-coordinates of low order: the seven 32-byte values
// (canonical or not) that every clamped scalar sends to zero, and two of them
// with bit 255 set, which X25519 masks off.
var LowOrder = []struct {
	Name  string
	Point []byte
}{
	{"zero", mustHex("0000000000000000000000000000000000000000000000000000000000000000")},
	{"one", mustHex("0100000000000000000000000000000000000000000000000000000000000000")},
	{"order-8-a", mustHex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")},
	{"order-8-b", mustHex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157")},
	{"p-minus-1", mustHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")},
	{"p", mustHex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")},
	{"p-plus-1", mustHex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")},
	{"zero-bit-255", mustHex("0000000000000000000000000000000000000000000000000000000000000080")},
	{"order-8-a-bit-255", mustHex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880")},
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func labeledExtract(suite, salt []byte, label string, ikm []byte) []byte {
	in := append(append(append([]byte("HPKE-v1"), suite...), label...), ikm...)
	prk, err := hkdf.Extract(sha256.New, in, salt)
	if err != nil {
		panic(err)
	}
	return prk
}

func labeledExpand(suite, prk []byte, label string, info []byte, length int) []byte {
	in := binary.BigEndian.AppendUint16(nil, uint16(length))
	in = append(append(append(append(in, "HPKE-v1"...), suite...), label...), info...)
	out, err := hkdf.Expand(sha256.New, prk, string(in), length)
	if err != nil {
		panic(err)
	}
	return out
}

// Seal runs single-shot HPKE base mode with dh as the X25519 output, enc as
// the encapsulated key and recipient as the recipient's public key, and
// returns the ciphertext. With the real X25519 output it is ordinary HPKE,
// which the tests use to check this file against crypto/hpke.
func Seal(dh, enc, recipient, info, aad, plaintext []byte) []byte {
	kemContext := append(append([]byte(nil), enc...), recipient...)
	shared := labeledExpand(kemSuite, labeledExtract(kemSuite, nil, "eae_prk", dh), "shared_secret", kemContext, 32)
	context := []byte{0x00} // base mode
	context = append(context, labeledExtract(hpkeSuite, nil, "psk_id_hash", nil)...)
	context = append(context, labeledExtract(hpkeSuite, nil, "info_hash", info)...)
	secret := labeledExtract(hpkeSuite, shared, "secret", nil)
	key := labeledExpand(hpkeSuite, secret, "key", context, 32)
	nonce := labeledExpand(hpkeSuite, secret, "base_nonce", context, 12)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return gcm.Seal(nil, nonce, plaintext, aad)
}

// SealBase is RFC 9180 SealBase, single shot, for the suite of package hpke,
// with the sender's ephemeral private key skE given rather than drawn: it
// returns enc || ciphertext, where enc = X25519(skE, 9) and the
// Diffie-Hellman output is X25519(skE, pkR), which crypto/ecdh refuses when
// it is all zeros (a pkR of low order). It is Seal with the real exchange,
// so it shares Seal's key schedule, which TestForgeIsHPKE ties to
// crypto/hpke and TestSealBaseIsTheCFRGVector to RFC 9180's test vector for
// this suite.
//
// The platform's key-delivery vectors record the ephemeral key of each good
// case, and the tests replay their blobs with it.
func SealBase(pkR, skE, info, aad, plaintext []byte) ([]byte, error) {
	eph, err := ecdh.X25519().NewPrivateKey(skE)
	if err != nil {
		return nil, fmt.Errorf("forge: ephemeral key: %w", err)
	}
	recipient, err := ecdh.X25519().NewPublicKey(pkR)
	if err != nil {
		return nil, fmt.Errorf("forge: recipient key: %w", err)
	}
	dh, err := eph.ECDH(recipient)
	if err != nil {
		return nil, fmt.Errorf("forge: no shared secret: %w", err)
	}
	enc := eph.PublicKey().Bytes()
	ct := Seal(dh, enc, pkR, info, aad, plaintext)
	clear(dh)
	return append(enc, ct...), nil
}
