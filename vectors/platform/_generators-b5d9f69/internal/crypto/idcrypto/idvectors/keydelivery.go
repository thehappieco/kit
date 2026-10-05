//go:build go1.26

package idvectors

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/thehappieco/platform/internal/crypto/idcrypto"
)

// KeyDeliveryCase is one key-delivery vector (spec 7.5 and 7.14).
//
// A good case has every input and every output. The inputs are root,
// product and epoch (which give sk_p, pk_p and product_key_id, spec 2.3),
// the AAD fields, the recipient's private key akd_priv (the product page's
// ephemeral pair) and the sender's ephemeral private key eph_priv, which
// makes the seal deterministic. The outputs are the AAD as text, akd_pub,
// pk_p and the 80-byte akd_sealed, which opens with akd_priv to sk_p.
//
// An error case says which side must refuse it in op:
//
//   - "open": what the product page holds (akd_priv, akd_sealed and the
//     binding it rebuilds: iss, client_id, redirect_uri, sub, product_key_id,
//     pk_p, code_challenge, nonce), with one thing changed. The error is
//     "key_delivery", or "product_key" for a blob that opens but carries
//     another key than pk_p.
//   - "seal": what the id. page holds before sealing (root, product, epoch,
//     the binding, akd_pub), with akd_pub or a binding field unacceptable.
//     The error is "key_delivery".
type KeyDeliveryCase struct {
	Name          string `json:"name"`
	Op            string `json:"op,omitempty"`
	Root          string `json:"root,omitempty"`
	Product       string `json:"product,omitempty"`
	Epoch         int    `json:"epoch,omitempty"`
	Iss           string `json:"iss"`
	ClientID      string `json:"client_id"`
	RedirectURI   string `json:"redirect_uri"`
	Sub           string `json:"sub"`
	ProductKeyID  string `json:"product_key_id"`
	PKP           string `json:"pk_p"`
	CodeChallenge string `json:"code_challenge"`
	Nonce         string `json:"nonce"`
	AKDPriv       string `json:"akd_priv,omitempty"`
	AKDPub        string `json:"akd_pub,omitempty"`
	EphPriv       string `json:"eph_priv,omitempty"`
	AAD           string `json:"aad,omitempty"`
	AKDSealed     string `json:"akd_sealed,omitempty"`
	Error         string `json:"error,omitempty"`
}

// The ops of error cases.
const (
	KeyDeliveryOpSeal = "seal"
	KeyDeliveryOpOpen = "open"
)

// The clients of spec 7.1, as the vectors use them.
const (
	prodIssuer        = "https://id.thehappie.co"
	devIssuer         = "http://id.thehappie.localhost:8290"
	wappieRedirect    = "https://app.wappie.thehappie.co/auth/callback"
	mailieRedirect    = "https://console.mailie.thehappie.co/auth/callback"
	fakeproductOrigin = "http://fakeproduct.thehappie.localhost:8292"
)

// kdFlow is one flow's sealing inputs.
type kdFlow struct {
	root           []byte
	product        string
	epoch          int
	issuer         string
	clientID       string
	redirectURI    string
	sub            string
	codeChallenge  string
	nonce          string
	akdPriv, ephSK []byte
}

// binding returns the flow's binding, with the product key it derives.
func (f kdFlow) binding() (idcrypto.KeyDeliveryBinding, []byte, error) {
	sk, pub, err := idcrypto.ProductKey(f.root, f.product, f.epoch)
	if err != nil {
		return idcrypto.KeyDeliveryBinding{}, nil, err
	}
	return idcrypto.KeyDeliveryBinding{
		Issuer: f.issuer, ClientID: f.clientID, RedirectURI: f.redirectURI, Sub: f.sub,
		ProductKeyID: idcrypto.ProductKeyID(f.product, f.epoch), ProductKey: pub,
		CodeChallenge: f.codeChallenge, Nonce: f.nonce,
	}, sk, nil
}

// x25519Public returns X25519(priv, 9).
func x25519Public(priv []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

// sealWith is the page's seal with a given ephemeral key: the checks
// idcrypto.SealProductKey makes on akd_pub and the binding, then the
// deterministic HPKE seal. It does not check that sk matches the binding's
// product key, so the generator can write the must-fail case where it does
// not; the good cases are opened by idcrypto.OpenProductKey, which does.
func sealWith(ephSK, akdPub, sk []byte, b idcrypto.KeyDeliveryBinding) ([]byte, error) {
	aad, err := idcrypto.KeyDeliveryAAD(b)
	if err != nil {
		return nil, err
	}
	if err := idcrypto.CheckPublicKey(akdPub); err != nil {
		return nil, err
	}
	out, err := sealBase(akdPub, ephSK, []byte(idcrypto.KeyDeliveryInfo), aad, sk)
	if err != nil {
		return nil, err
	}
	if len(out) != idcrypto.SealedProductKeyLen {
		return nil, fmt.Errorf("sealed %d bytes", len(out))
	}
	return out, nil
}

// bindingCase fills a case's binding fields.
func bindingCase(name string, b idcrypto.KeyDeliveryBinding) KeyDeliveryCase {
	return KeyDeliveryCase{
		Name: name, Iss: b.Issuer, ClientID: b.ClientID, RedirectURI: b.RedirectURI, Sub: b.Sub,
		ProductKeyID: b.ProductKeyID, PKP: idcrypto.EncodeB64(b.ProductKey),
		CodeChallenge: b.CodeChallenge, Nonce: b.Nonce,
	}
}

func keyDeliveryCases() ([]KeyDeliveryCase, error) {
	rootA := seeded("key-delivery/root-a", idcrypto.KeyLen)
	rootB := seeded("key-delivery/root-b", idcrypto.KeyLen)
	sub := uuid7("key-delivery")
	akdA := seeded("key-delivery/akd-priv-a", idcrypto.KeyLen)
	akdB := seeded("key-delivery/akd-priv-b", idcrypto.KeyLen)
	challenge, err := idcrypto.PKCEChallenge(idcrypto.EncodeB64(seeded("key-delivery/code-verifier", 32)))
	if err != nil {
		return nil, err
	}
	// As the relying party makes it: 32 random bytes in base64url (spec 7.10).
	nonce := idcrypto.EncodeB64(seeded("key-delivery/nonce", 32))
	base := kdFlow{
		root: rootA, product: "wappie", epoch: 1,
		issuer: prodIssuer, clientID: "wappie-app", redirectURI: wappieRedirect, sub: sub,
		codeChallenge: challenge, nonce: nonce,
		akdPriv: akdA, ephSK: seeded("key-delivery/eph-1", idcrypto.KeyLen),
	}
	with := func(f func(*kdFlow)) kdFlow { c := base; f(&c); return c }

	goods := []struct {
		name string
		f    kdFlow
	}{
		{"wappie-app in production", base},
		{"mailie-console in production", with(func(f *kdFlow) {
			f.product, f.clientID, f.redirectURI = "mailie", "mailie-console", mailieRedirect
			f.ephSK = seeded("key-delivery/eph-2", idcrypto.KeyLen)
		})},
		{"fakeproduct in development", with(func(f *kdFlow) {
			f.issuer, f.clientID, f.redirectURI = devIssuer, "fakeproduct", fakeproductOrigin+"/auth/callback"
			f.ephSK = seeded("key-delivery/eph-3", idcrypto.KeyLen)
		})},
		{"the same flow sealed with another ephemeral key", with(func(f *kdFlow) {
			f.ephSK = seeded("key-delivery/eph-4", idcrypto.KeyLen)
		})},
		{"the same flow sealed to another recipient", with(func(f *kdFlow) {
			f.akdPriv = akdB
		})},
		{"another account", with(func(f *kdFlow) {
			f.root, f.sub = rootB, uuid7("key-delivery/another")
			f.ephSK = seeded("key-delivery/eph-5", idcrypto.KeyLen)
		})},
		{"the largest epoch", with(func(f *kdFlow) {
			f.epoch = idcrypto.MaxEpoch
			f.ephSK = seeded("key-delivery/eph-6", idcrypto.KeyLen)
		})},
		{"the shortest nonce, 22 characters", with(func(f *kdFlow) {
			f.nonce = idcrypto.EncodeB64(seeded("key-delivery/nonce-22", 16))
			f.ephSK = seeded("key-delivery/eph-7", idcrypto.KeyLen)
		})},
		{"the longest nonce, 128 characters", with(func(f *kdFlow) {
			f.nonce = idcrypto.EncodeB64(seeded("key-delivery/nonce-128", 96))
			f.ephSK = seeded("key-delivery/eph-8", idcrypto.KeyLen)
		})},
	}
	var out []KeyDeliveryCase
	for _, g := range goods {
		c, err := goodKeyDelivery(g.name, g.f)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}

	opens, err := keyDeliveryOpenRefusals(base, rootB, akdB)
	if err != nil {
		return nil, err
	}
	seals, err := keyDeliverySealRefusals(base)
	if err != nil {
		return nil, err
	}
	return append(append(out, opens...), seals...), nil
}

// goodKeyDelivery seals one flow and proves the result before writing it:
// idcrypto.OpenProductKey (crypto/hpke) opens it to sk_p, and
// idcrypto.SealProductKey seals the same inputs to a blob that opens alike.
func goodKeyDelivery(name string, f kdFlow) (KeyDeliveryCase, error) {
	b, sk, err := f.binding()
	if err != nil {
		return KeyDeliveryCase{}, fmt.Errorf("case %q: %w", name, err)
	}
	defer clear(sk)
	akdPub, err := x25519Public(f.akdPriv)
	if err != nil {
		return KeyDeliveryCase{}, fmt.Errorf("case %q: %w", name, err)
	}
	aad, err := idcrypto.KeyDeliveryAAD(b)
	if err != nil {
		return KeyDeliveryCase{}, mismatch(name, idcrypto.ErrorCode(err), "")
	}
	sealed, err := sealWith(f.ephSK, akdPub, sk, b)
	if err != nil {
		return KeyDeliveryCase{}, fmt.Errorf("case %q: %w", name, err)
	}
	opened, err := idcrypto.OpenProductKey(f.akdPriv, sealed, b)
	if err != nil {
		return KeyDeliveryCase{}, mismatch(name, idcrypto.ErrorCode(err), "")
	}
	same := bytes.Equal(opened, sk)
	clear(opened)
	if !same {
		return KeyDeliveryCase{}, mismatch(name, "another key", "sk_p")
	}
	random, err := idcrypto.SealProductKey(nil, akdPub, sk, b)
	if err != nil {
		return KeyDeliveryCase{}, mismatch(name, idcrypto.ErrorCode(err), "")
	}
	opened, err = idcrypto.OpenProductKey(f.akdPriv, random, b)
	if err != nil || !bytes.Equal(opened, sk) {
		clear(opened)
		return KeyDeliveryCase{}, mismatch(name, "SealProductKey's blob does not open", "sk_p")
	}
	clear(opened)

	c := bindingCase(name, b)
	c.Root, c.Product, c.Epoch = idcrypto.EncodeB64(f.root), f.product, f.epoch
	c.AKDPriv, c.AKDPub, c.EphPriv = idcrypto.EncodeB64(f.akdPriv), idcrypto.EncodeB64(akdPub), idcrypto.EncodeB64(f.ephSK)
	c.AAD, c.AKDSealed = string(aad), idcrypto.EncodeB64(sealed)
	return c, nil
}

// keyDeliveryOpenRefusals are the blobs a product page must refuse: base's
// delivery with one thing changed at a time.
func keyDeliveryOpenRefusals(base kdFlow, rootB, akdB []byte) ([]KeyDeliveryCase, error) {
	b, sk, err := base.binding()
	if err != nil {
		return nil, err
	}
	defer clear(sk)
	akdPub, err := x25519Public(base.akdPriv)
	if err != nil {
		return nil, err
	}
	sealed, err := sealWith(base.ephSK, akdPub, sk, b)
	if err != nil {
		return nil, err
	}
	_, mailiePub, err := idcrypto.ProductKey(base.root, "mailie", 1)
	if err != nil {
		return nil, err
	}
	_, otherAccountPub, err := idcrypto.ProductKey(rootB, base.product, base.epoch)
	if err != nil {
		return nil, err
	}
	otherChallenge, err := idcrypto.PKCEChallenge(idcrypto.EncodeB64(seeded("key-delivery/another-code-verifier", 32)))
	if err != nil {
		return nil, err
	}
	rebind := func(f func(*idcrypto.KeyDeliveryBinding)) idcrypto.KeyDeliveryBinding {
		c := b
		f(&c)
		return c
	}
	edit := func(f func([]byte) []byte) []byte { return f(bytes.Clone(sealed)) }
	flip := func(i int, bit byte) []byte { return edit(func(s []byte) []byte { s[i] ^= bit; return s }) }
	withEnc := func(enc string) []byte {
		e, _ := hex.DecodeString(enc)
		return edit(func(s []byte) []byte { copy(s, e); return s })
	}
	// The same flow sealed by a sealer that spells enc with bit 255 set in
	// the blob and in the KEM context alike. X25519 reads it as the same
	// point, so a lax opener opens it; the openers refuse every enc but the
	// canonical one.
	aliasEnc := bytes.Clone(sealed[:32])
	aliasEnc[31] |= 0x80
	aad, err := idcrypto.KeyDeliveryAAD(b)
	if err != nil {
		return nil, err
	}
	aliased, err := sealBaseAs(akdPub, base.ephSK, aliasEnc, []byte(idcrypto.KeyDeliveryInfo), aad, sk)
	if err != nil {
		return nil, err
	}

	type refusal struct {
		name    string
		akdPriv []byte
		sealed  []byte
		b       idcrypto.KeyDeliveryBinding
		err     string
	}
	const kd, pk = "key_delivery", "product_key"
	rs := []refusal{
		// Each AAD field changed, one at a time.
		{"opened for another issuer", base.akdPriv, sealed, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.Issuer = devIssuer }), kd},
		{"opened for the issuer with a trailing slash", base.akdPriv, sealed, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.Issuer = prodIssuer + "/" }), kd},
		{"opened for another client of the same product", base.akdPriv, sealed, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.ClientID = "fakeproduct" }), kd},
		{"opened for another redirect_uri", base.akdPriv, sealed, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.RedirectURI = wappieRedirect + "/" }), kd},
		{"opened for another sub", base.akdPriv, sealed, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.Sub = uuid7("key-delivery/another") }), kd},
		{"opened for another epoch's product_key_id", base.akdPriv, sealed, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.ProductKeyID = "wappie:2" }), kd},
		{"opened for another product's product_key_id", base.akdPriv, sealed, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.ProductKeyID = "mailie:1" }), kd},
		{"opened for another product's pk_p", base.akdPriv, sealed, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.ProductKey = mailiePub }), kd},
		{"opened for another account's pk_p", base.akdPriv, sealed, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.ProductKey = otherAccountPub }), kd},
		{"opened for another code_challenge", base.akdPriv, sealed, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.CodeChallenge = otherChallenge }), kd},
		{"opened for another nonce", base.akdPriv, sealed, rebind(func(c *idcrypto.KeyDeliveryBinding) {
			c.Nonce = idcrypto.EncodeB64(seeded("key-delivery/another-nonce", 32))
		}), kd},

		// Another recipient.
		{"opened by another recipient", akdB, sealed, b, kd},
		{"a 31-byte recipient private key", base.akdPriv[:31], sealed, b, kd},

		// Lengths.
		{"truncated to 79 bytes", base.akdPriv, sealed[:79], b, kd},
		{"extended to 81 bytes", base.akdPriv, append(bytes.Clone(sealed), 0x00), b, kd},
		{"extended by a whole block, 96 bytes", base.akdPriv, append(bytes.Clone(sealed), make([]byte, 16)...), b, kd},
		{"only the 32-byte enc", base.akdPriv, sealed[:32], b, kd},
		{"empty", base.akdPriv, []byte{}, b, kd},

		// Altered bytes.
		{"a flipped bit in enc", base.akdPriv, flip(0, 0x01), b, kd},
		{"bit 255 of enc set, which X25519 ignores and the KEM context does not", base.akdPriv, flip(31, 0x80), b, kd},
		{"a flipped bit in ct", base.akdPriv, flip(32, 0x01), b, kd},
		{"a flipped bit in the last ct byte", base.akdPriv, flip(63, 0x80), b, kd},
		{"a flipped bit in the first tag byte", base.akdPriv, flip(64, 0x01), b, kd},
		{"a flipped bit in the last tag byte", base.akdPriv, flip(79, 0x80), b, kd},
		{"enc replaced by the low-order point 0", base.akdPriv, withEnc(strings.Repeat("00", 32)), b, kd},
		{"enc replaced by a low-order point of order 8", base.akdPriv, withEnc("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"), b, kd},
		{"enc spelled with bit 255 set by the sealer, in the blob and in the KEM context alike", base.akdPriv, aliased, b, kd},

		// Bindings that have no AAD: refused before anything is opened (or,
		// by an opener that does not check them, by the AEAD).
		{"a sub in upper case", base.akdPriv, sealed, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.Sub = strings.ToUpper(c.Sub) }), kd},
		{"a product_key_id with a leading zero", base.akdPriv, sealed, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.ProductKeyID = "wappie:01" }), kd},
		{"a product_key_id without an epoch", base.akdPriv, sealed, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.ProductKeyID = "wappie" }), kd},
		{"a 31-byte pk_p", base.akdPriv, sealed, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.ProductKey = c.ProductKey[:31] }), kd},
		{"a code_challenge of 42 characters", base.akdPriv, sealed, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.CodeChallenge = c.CodeChallenge[:42] }), kd},
		{"a nonce of 21 characters", base.akdPriv, sealed, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.Nonce = c.Nonce[:21] }), kd},
		{"a nonce with a dot", base.akdPriv, sealed, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.Nonce = "." + c.Nonce[1:] }), kd},
		{"an issuer outside the AAD alphabet", base.akdPriv, sealed, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.Issuer = prodIssuer + "/?" }), kd},
		{"an empty client_id", base.akdPriv, sealed, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.ClientID = "" }), kd},
	}

	// Blobs that open and carry another key than the one the binding names:
	// a page that sealed the wrong key is caught by the product.
	for _, w := range []struct {
		name    string
		root    []byte
		product string
		epoch   int
	}{
		{"a product key that does not match: another account's key", rootB, base.product, base.epoch},
		{"a product key that does not match: another product's key", base.root, "mailie", base.epoch},
		{"a product key that does not match: another epoch's key", base.root, base.product, 2},
	} {
		wrong, _, err := idcrypto.ProductKey(w.root, w.product, w.epoch)
		if err != nil {
			return nil, err
		}
		blob, err := sealWith(seeded("key-delivery/eph-wrong/"+w.name, idcrypto.KeyLen), akdPub, wrong, b)
		clear(wrong)
		if err != nil {
			return nil, err
		}
		rs = append(rs, refusal{w.name, base.akdPriv, blob, b, pk})
	}

	var out []KeyDeliveryCase
	for _, r := range rs {
		got, err := idcrypto.OpenProductKey(r.akdPriv, r.sealed, r.b)
		clear(got)
		if code := idcrypto.ErrorCode(err); code != r.err {
			return nil, mismatch(r.name, code, r.err)
		}
		c := bindingCase(r.name, r.b)
		c.Op, c.Error = KeyDeliveryOpOpen, r.err
		c.AKDPriv, c.AKDSealed = idcrypto.EncodeB64(r.akdPriv), idcrypto.EncodeB64(r.sealed)
		out = append(out, c)
	}
	return out, nil
}

// lowOrderX25519 are the public values libsodium refuses: the low-order
// points of Curve25519, and encodings that are not canonical (bit 255 set,
// or a value from p upwards).
var lowOrderX25519 = []struct{ name, hex string }{
	{"the low-order point 0", "0000000000000000000000000000000000000000000000000000000000000000"},
	{"the low-order point 1", "0100000000000000000000000000000000000000000000000000000000000000"},
	{"a point of order 8", "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"},
	{"the other point of order 8", "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"},
	{"p - 1, a point of order 2", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
	{"p, a non-canonical 0", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
	{"p + 1, a non-canonical 1", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
	{"a point of order 8 with bit 255 set", "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880"},
	{"the other point of order 8 with bit 255 set", "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7"},
	{"2p - 1 with bit 255 set", "d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
	{"2p with bit 255 set", "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
	{"2p + 1 with bit 255 set", "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
}

// keyDeliverySealRefusals are the inputs the id. page must refuse before it
// seals: an akd_pub that fails the check of spec 2.3, and binding fields the
// AAD cannot carry.
func keyDeliverySealRefusals(base kdFlow) ([]KeyDeliveryCase, error) {
	b, sk, err := base.binding()
	if err != nil {
		return nil, err
	}
	defer clear(sk)
	akdPub, err := x25519Public(base.akdPriv)
	if err != nil {
		return nil, err
	}
	type refusal struct {
		name   string
		akdPub []byte
		b      idcrypto.KeyDeliveryBinding
	}
	var rs []refusal
	for _, p := range lowOrderX25519 {
		raw, err := hex.DecodeString(p.hex)
		if err != nil {
			return nil, err
		}
		rs = append(rs, refusal{"akd_pub is " + p.name, raw, b})
	}
	high := bytes.Clone(akdPub)
	high[31] |= 0x80
	rebind := func(f func(*idcrypto.KeyDeliveryBinding)) idcrypto.KeyDeliveryBinding {
		c := b
		f(&c)
		return c
	}
	rs = append(rs,
		refusal{"akd_pub is a valid key with bit 255 set", high, b},
		refusal{"a 31-byte akd_pub", akdPub[:31], b},
		refusal{"a 33-byte akd_pub", append(bytes.Clone(akdPub), 0x00), b},
		refusal{"an empty akd_pub", []byte{}, b},
		refusal{"a sub in upper case", akdPub, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.Sub = strings.ToUpper(c.Sub) })},
		refusal{"a nonce of 21 characters", akdPub, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.Nonce = c.Nonce[:21] })},
		refusal{"a nonce of 129 characters", akdPub, rebind(func(c *idcrypto.KeyDeliveryBinding) {
			c.Nonce = idcrypto.EncodeB64(seeded("key-delivery/nonce-128", 96)) + "A"
		})},
		refusal{"a nonce with a dot", akdPub, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.Nonce = "." + c.Nonce[1:] })},
		refusal{"a code_challenge of 42 characters", akdPub, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.CodeChallenge = c.CodeChallenge[:42] })},
		refusal{"a code_challenge of 44 characters", akdPub, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.CodeChallenge += "A" })},
		refusal{"a code_challenge with non-zero trailing bits", akdPub, rebind(func(c *idcrypto.KeyDeliveryBinding) {
			c.CodeChallenge = c.CodeChallenge[:42] + nonZeroTrailing(c.CodeChallenge[42])
		})},
		refusal{"an issuer outside the AAD alphabet", akdPub, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.Issuer = prodIssuer + "/?" })},
		refusal{"an empty redirect_uri", akdPub, rebind(func(c *idcrypto.KeyDeliveryBinding) { c.RedirectURI = "" })},
	)

	var out []KeyDeliveryCase
	for _, r := range rs {
		_, err := idcrypto.SealProductKey(nil, r.akdPub, sk, r.b)
		if code := idcrypto.ErrorCode(err); code != "key_delivery" {
			return nil, mismatch(r.name, code, "key_delivery")
		}
		c := bindingCase(r.name, r.b)
		c.Op, c.Error = KeyDeliveryOpSeal, "key_delivery"
		c.Root, c.Product, c.Epoch = idcrypto.EncodeB64(base.root), base.product, base.epoch
		c.AKDPub = idcrypto.EncodeB64(r.akdPub)
		out = append(out, c)
	}
	return out, nil
}

// nonZeroTrailing returns the base64url character that keeps the 6-bit
// value of c except for its two lowest bits, which it sets: the last
// character of a 43-character encoding carries 4 data bits and 2 bits a
// strict decoder requires to be zero.
func nonZeroTrailing(c byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	i := strings.IndexByte(alphabet, c)
	return alphabet[i|0x03 : i|0x03+1]
}

// PKCECase is one PKCE vector (spec 7.3 and 7.6, RFC 7636): a code verifier
// and its S256 challenge, or "error": "pkce" for a verifier outside RFC 7636.
type PKCECase struct {
	Name          string `json:"name"`
	CodeVerifier  string `json:"code_verifier"`
	CodeChallenge string `json:"code_challenge,omitempty"`
	Error         string `json:"error,omitempty"`
}

// The example of RFC 7636 appendix B.
const (
	rfc7636Verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfc7636Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func pkceCases() ([]PKCECase, error) {
	v43 := idcrypto.EncodeB64(seeded("pkce/verifier-43", 32))
	v128 := idcrypto.EncodeB64(seeded("pkce/verifier-128", 96))
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	replace := func(s string, i int, r string) string { return s[:i] + r + s[i+1:] }
	specs := []struct {
		name, verifier, err string
	}{
		{"the example of RFC 7636 appendix B", rfc7636Verifier, ""},
		{"43 characters, from 32 random bytes as the relying party makes them", v43, ""},
		{"128 characters", v128, ""},
		{"every character of the alphabet", alphabet, ""},
		{"only the unreserved punctuation", strings.Repeat("-._~", 11), ""},
		{"43 tildes", strings.Repeat("~", 43), ""},
		{"42 characters", v43[:42], "pkce"},
		{"129 characters", v128 + "A", "pkce"},
		{"empty", "", "pkce"},
		{"a plus sign", replace(v43, 10, "+"), "pkce"},
		{"a slash", replace(v43, 10, "/"), "pkce"},
		{"a padding equals sign", v43 + "=", "pkce"},
		{"a space", replace(v43, 10, " "), "pkce"},
		{"a percent-encoded tilde", v43[:40] + "%7E", "pkce"},
		{"a non-ASCII letter", replace(v43, 10, "é"), "pkce"},
		{"a fullwidth letter", replace(v43, 10, "Ａ"), "pkce"},
		{"a trailing line break", v43 + "\n", "pkce"},
		{"a NUL", replace(v43, 10, "\x00"), "pkce"},
	}
	var out []PKCECase
	for _, s := range specs {
		got, err := idcrypto.PKCEChallenge(s.verifier)
		if code := idcrypto.ErrorCode(err); code != s.err {
			return nil, mismatch(s.name, code, s.err)
		}
		if s.verifier == rfc7636Verifier && got != rfc7636Challenge {
			return nil, mismatch(s.name, "another challenge", "the challenge of RFC 7636 appendix B")
		}
		out = append(out, PKCECase{Name: s.name, CodeVerifier: s.verifier, CodeChallenge: got, Error: s.err})
	}
	return out, nil
}
