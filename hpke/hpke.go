// Package hpke fixes the one HPKE suite the kit uses and wraps the standard
// library's crypto/hpke around it.
//
// The suite is RFC 9180 base mode, single shot, with DHKEM(X25519,
// HKDF-SHA256), HKDF-SHA256 and AES-256-GCM. It is fixed in code rather than
// configured, so there is nothing to misconfigure and nothing to negotiate
// down. A different suite is a new format version in the code that uses this
// package, never a parameter here.
//
// The info and the additional data are the caller's: the sealed envelope
// (package seal) builds them from its profile, and a product-key delivery
// builds its own. Keys are raw 32-byte X25519 values, the format Wappie calls
// a USK and the platform's per-product keys share.
package hpke

import (
	"crypto/ecdh"
	"crypto/hpke"
	"errors"
	"fmt"
)

// The suite's registry values (RFC 9180 §7) and sizes.
const (
	KEM  = 0x0020 // DHKEM(X25519, HKDF-SHA256)
	KDF  = 0x0001 // HKDF-SHA256
	AEAD = 0x0002 // AES-256-GCM

	// KeyLen is the size of an X25519 public or private key.
	KeyLen = 32
	// EncLen is the size of the encapsulated key: an ephemeral public key.
	EncLen = 32
	// TagLen is what AES-256-GCM adds to a plaintext.
	TagLen = 16
)

// ErrOpen is every failure to open a ciphertext: a wrong key, a wrong info or
// AAD, a tampered byte, or an encapsulated key that yields no shared secret.
// They are deliberately one error.
var ErrOpen = errors.New("hpke: open failed")

// ErrInvalidKey is a public key no secret can be agreed with: one of low
// order, whose X25519 output is all zeros. RFC 9180 §7.1.4 requires DHKEM to
// abort there; crypto/ecdh does. Whoever served such a key could open
// whatever was sealed to it.
var ErrInvalidKey = errors.New("hpke: no shared secret with this public key")

func suite() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	return hpke.DHKEM(ecdh.X25519()), hpke.HKDFSHA256(), hpke.AES256GCM()
}

// PublicKey is an X25519 public key.
type PublicKey struct {
	raw []byte
	pk  hpke.PublicKey
}

// ParsePublicKey deserialises a 32-byte X25519 public key.
func ParsePublicKey(b []byte) (PublicKey, error) {
	if len(b) != KeyLen {
		return PublicKey{}, fmt.Errorf("hpke: public key must be %d bytes, got %d", KeyLen, len(b))
	}
	kem, _, _ := suite()
	pk, err := kem.NewPublicKey(b)
	if err != nil {
		return PublicKey{}, fmt.Errorf("hpke: invalid public key: %w", err)
	}
	return PublicKey{raw: append([]byte(nil), b...), pk: pk}, nil
}

// Bytes returns the serialised key.
func (p PublicKey) Bytes() []byte { return append([]byte(nil), p.raw...) }

// Valid reports whether the key was parsed.
func (p PublicKey) Valid() bool { return p.pk != nil }

// PrivateKey is an X25519 private key.
type PrivateKey struct {
	sk hpke.PrivateKey
}

// GenerateKeyPair creates a key pair from crypto/rand.
func GenerateKeyPair() (PublicKey, PrivateKey, error) {
	kem, _, _ := suite()
	sk, err := kem.GenerateKey()
	if err != nil {
		return PublicKey{}, PrivateKey{}, fmt.Errorf("hpke: generate key: %w", err)
	}
	pub, err := ParsePublicKey(sk.PublicKey().Bytes())
	if err != nil {
		return PublicKey{}, PrivateKey{}, err
	}
	return pub, PrivateKey{sk: sk}, nil
}

// ParsePrivateKey deserialises a raw 32-byte private key. Any 32 bytes are a
// valid X25519 scalar: clamping happens inside the scalar multiplication, so a
// key derived with HKDF needs no preparation.
func ParsePrivateKey(b []byte) (PrivateKey, error) {
	if len(b) != KeyLen {
		return PrivateKey{}, fmt.Errorf("hpke: private key must be %d bytes, got %d", KeyLen, len(b))
	}
	kem, _, _ := suite()
	sk, err := kem.NewPrivateKey(b)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("hpke: invalid private key: %w", err)
	}
	return PrivateKey{sk: sk}, nil
}

// Bytes serialises the private key.
func (p PrivateKey) Bytes() ([]byte, error) {
	if p.sk == nil {
		return nil, errors.New("hpke: no private key")
	}
	return p.sk.Bytes()
}

// PublicKey returns the matching public key.
func (p PrivateKey) PublicKey() (PublicKey, error) {
	if p.sk == nil {
		return PublicKey{}, errors.New("hpke: no private key")
	}
	return ParsePublicKey(p.sk.PublicKey().Bytes())
}

// Valid reports whether the key was parsed.
func (p PrivateKey) Valid() bool { return p.sk != nil }

// Seal encrypts plaintext to pub in one shot. The ephemeral key comes from
// crypto/rand; enc is its public half, which the recipient needs. A public key
// of low order is ErrInvalidKey.
func Seal(pub PublicKey, info, aad, plaintext []byte) (enc, ciphertext []byte, err error) {
	if !pub.Valid() {
		return nil, nil, errors.New("hpke: no public key")
	}
	_, kdf, aead := suite()
	enc, sender, err := hpke.NewSender(pub.pk, kdf, aead, info)
	if err != nil {
		// The encapsulation's X25519 refused the key: it is of low order.
		// crypto/rand cannot fail since Go 1.24, so nothing else gets here.
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	ciphertext, err = sender.Seal(aad, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("hpke: seal: %w", err)
	}
	return enc, ciphertext, nil
}

// Open reverses Seal. Every failure is ErrOpen.
func Open(priv PrivateKey, enc, info, aad, ciphertext []byte) ([]byte, error) {
	if !priv.Valid() {
		return nil, errors.New("hpke: no private key")
	}
	_, kdf, aead := suite()
	recipient, err := hpke.NewRecipient(enc, priv.sk, kdf, aead, info)
	if err != nil {
		// An encapsulated key of the wrong length or of low order (an
		// all-zero shared secret). Not distinguished from a failed tag: both
		// are a ciphertext this key cannot open.
		return nil, ErrOpen
	}
	plaintext, err := recipient.Open(aad, ciphertext)
	if err != nil {
		return nil, ErrOpen
	}
	return plaintext, nil
}
