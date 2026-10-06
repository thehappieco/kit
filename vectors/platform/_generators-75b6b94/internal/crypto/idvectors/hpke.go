//go:build go1.26

package idvectors

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
)

// A deterministic RFC 9180 SealBase for exactly the key-delivery suite,
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM, with the sender's
// ephemeral private key given rather than generated.
//
// It exists because a vector has to record the ephemeral key it was sealed
// with, and crypto/hpke takes no ephemeral key and no reader. It is used
// only to write vectors and is not exported: a seal under a known ephemeral
// key is readable by anyone who knows that key. Two checks keep it honest:
// every blob the generator writes is opened by idcrypto.OpenProductKey,
// which is crypto/hpke, and hpke_test.go reproduces the RFC 9180 test vector
// for this suite, intermediate values included, and has crypto/hpke open
// what it seals over random inputs.
//
// The steps are RFC 9180 sections 4 to 6, for mode_base and one message:
//
//	dh            = X25519(skE, pkR)                         Encap (4.1)
//	enc           = X25519(skE, 9)
//	shared_secret = LabeledExpand(LabeledExtract("", "eae_prk", dh),
//	                              "shared_secret", enc || pkR, 32)
//	key_schedule_context = 0x00 || LabeledExtract("", "psk_id_hash", "")
//	                            || LabeledExtract("", "info_hash", info)     (5.1)
//	secret        = LabeledExtract(shared_secret, "secret", "")
//	key           = LabeledExpand(secret, "key", key_schedule_context, 32)
//	base_nonce    = LabeledExpand(secret, "base_nonce", key_schedule_context, 12)
//	ct            = AES-256-GCM(key, base_nonce, aad, pt)    seq 0, so nonce = base_nonce (5.2)

const (
	hpkeModeBase = 0x00
	hpkeNsecret  = 32 // shared secret
	hpkeNk       = 32 // AES-256 key
	hpkeNn       = 12 // AES-GCM nonce
)

var (
	// suite_id of the KEM: "KEM" || I2OSP(0x0020, 2).
	hpkeKEMSuiteID = []byte{'K', 'E', 'M', 0x00, 0x20}
	// suite_id of the key schedule: "HPKE" || KEM 0x0020 || KDF 0x0001 || AEAD 0x0002.
	hpkeSuiteID = []byte{'H', 'P', 'K', 'E', 0x00, 0x20, 0x00, 0x01, 0x00, 0x02}
)

// hpkeBase is the sender's context for one message, with the values the RFC
// test vectors record, so the test can compare each step.
type hpkeBase struct {
	enc                []byte
	sharedSecret       []byte
	keyScheduleContext []byte
	secret             []byte
	key                []byte
	baseNonce          []byte
}

// labeledExtract is LabeledExtract(salt, label, ikm) =
// Extract(salt, "HPKE-v1" || suite_id || label || ikm).
func labeledExtract(suiteID, salt []byte, label string, ikm []byte) ([]byte, error) {
	labeled := cat([]byte("HPKE-v1"), suiteID, []byte(label), ikm)
	return hkdf.Extract(sha256.New, labeled, salt)
}

// labeledExpand is LabeledExpand(prk, label, info, L) =
// Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info, L).
func labeledExpand(suiteID, prk []byte, label string, info []byte, l int) ([]byte, error) {
	labeled := cat([]byte{byte(l >> 8), byte(l)}, []byte("HPKE-v1"), suiteID, []byte(label), info) //nolint:gosec // I2OSP(L, 2); L is 12 or 32
	return hkdf.Expand(sha256.New, prk, string(labeled), l)
}

// setupBaseS is SetupBaseS(pkR, info) with the ephemeral key skE given.
func setupBaseS(pkR, skE, info []byte) (*hpkeBase, error) {
	return setupBaseSAs(pkR, skE, nil, info)
}

// setupBaseSAs is setupBaseS with enc written as encAs in both the blob and
// the KEM context, or as X25519(skE, 9) when encAs is nil. encAs must be
// another spelling of that point (bit 255 set), which X25519 reads as the
// point itself: it exists only to write the must-fail vector for an opener
// that accepts a non-canonical enc. An honest sealer never writes one.
func setupBaseSAs(pkR, skE, encAs, info []byte) (*hpkeBase, error) {
	curve := ecdh.X25519()
	eph, err := curve.NewPrivateKey(skE)
	if err != nil {
		return nil, fmt.Errorf("hpke: ephemeral key: %w", err)
	}
	recipient, err := curve.NewPublicKey(pkR)
	if err != nil {
		return nil, fmt.Errorf("hpke: recipient key: %w", err)
	}
	// crypto/ecdh refuses the all-zero output of a low-order point, as
	// RFC 9180 section 7.1.4 requires.
	dh, err := eph.ECDH(recipient)
	if err != nil {
		return nil, fmt.Errorf("hpke: %w", err)
	}
	c := &hpkeBase{enc: eph.PublicKey().Bytes()}
	if encAs != nil {
		if len(encAs) != len(c.enc) {
			return nil, errors.New("hpke: encAs is not an X25519 encoding")
		}
		point := bytes.Clone(encAs)
		point[len(point)-1] &^= 0x80
		if !bytes.Equal(point, c.enc) || bytes.Equal(encAs, c.enc) {
			return nil, errors.New("hpke: encAs is not the ephemeral key with bit 255 set")
		}
		c.enc = bytes.Clone(encAs)
	}
	eaePRK, err := labeledExtract(hpkeKEMSuiteID, nil, "eae_prk", dh)
	if err != nil {
		return nil, err
	}
	if c.sharedSecret, err = labeledExpand(hpkeKEMSuiteID, eaePRK, "shared_secret", cat(c.enc, pkR), hpkeNsecret); err != nil {
		return nil, err
	}

	pskIDHash, err := labeledExtract(hpkeSuiteID, nil, "psk_id_hash", nil)
	if err != nil {
		return nil, err
	}
	infoHash, err := labeledExtract(hpkeSuiteID, nil, "info_hash", info)
	if err != nil {
		return nil, err
	}
	c.keyScheduleContext = cat([]byte{hpkeModeBase}, pskIDHash, infoHash)
	if c.secret, err = labeledExtract(hpkeSuiteID, c.sharedSecret, "secret", nil); err != nil {
		return nil, err
	}
	if c.key, err = labeledExpand(hpkeSuiteID, c.secret, "key", c.keyScheduleContext, hpkeNk); err != nil {
		return nil, err
	}
	if c.baseNonce, err = labeledExpand(hpkeSuiteID, c.secret, "base_nonce", c.keyScheduleContext, hpkeNn); err != nil {
		return nil, err
	}
	return c, nil
}

// sealFirst seals the context's first and only message. Its sequence number
// is 0, so the nonce is base_nonce XOR 0, which is base_nonce.
func (c *hpkeBase) sealFirst(aad, pt []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, c.baseNonce, pt, aad), nil
}

// sealBase is the single-shot SealBase with a given ephemeral key. It
// returns enc || ct, the layout of akd_sealed.
func sealBase(pkR, skE, info, aad, pt []byte) ([]byte, error) {
	return sealBaseAs(pkR, skE, nil, info, aad, pt)
}

// sealBaseAs is sealBase with enc spelled as encAs (setupBaseSAs).
func sealBaseAs(pkR, skE, encAs, info, aad, pt []byte) ([]byte, error) {
	c, err := setupBaseSAs(pkR, skE, encAs, info)
	if err != nil {
		return nil, err
	}
	ct, err := c.sealFirst(aad, pt)
	if err != nil {
		return nil, err
	}
	return cat(c.enc, ct), nil
}

// cat returns the concatenation of parts in a new slice.
func cat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
