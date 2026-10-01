package platform

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"strconv"

	"github.com/thehappieco/kit/hpke"
)

// maxProductLen bounds a product id: [a-z][a-z0-9-]{0,31}.
const maxProductLen = 32

// ValidProduct reports whether product matches [a-z][a-z0-9-]{0,31}. The
// HKDF info is product + "|" + decimal(epoch); because a product id never
// holds '|' and the epoch has no leading zeros, each (product, epoch) pair
// has exactly one info and no two pairs share one.
//
// The product registry, which ids exist, is the platform's: any valid id
// derives a key here.
func ValidProduct(product string) bool {
	if len(product) < 1 || len(product) > maxProductLen {
		return false
	}
	for i := 0; i < len(product); i++ {
		c := product[i]
		switch {
		case 'a' <= c && c <= 'z':
		case i > 0 && ('0' <= c && c <= '9' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// ProductKeyID returns product + ":" + decimal(epoch), for example
// "wappie:1".
func ProductKeyID(product string, epoch int) string {
	return product + ":" + strconv.Itoa(epoch)
}

// ProductKey derives a product's X25519 key pair from the root (section
// 11.4):
//
//	sk  = HKDF(IKM = root, salt = "thehappie-id/v1/product-key", info = product + "|" + epoch, L = 32)
//	pub = X25519(sk, 9)
//
// Any 32 bytes are a valid X25519 private key, because X25519 clamps inside;
// pub is what package hpke computes for sk. It refuses, wrapping
// ErrProductKey, a root that is not 32 bytes, an invalid product id and an
// epoch out of range. The caller clears sk.
func ProductKey(root []byte, product string, epoch int) (sk, pub []byte, err error) {
	if len(root) != KeyLen {
		return nil, nil, fmt.Errorf("%w: a %d-byte root", ErrProductKey, len(root))
	}
	if !ValidProduct(product) {
		return nil, nil, fmt.Errorf("%w: invalid product id", ErrProductKey)
	}
	if !checkEpoch(epoch) {
		return nil, nil, fmt.Errorf("%w: epoch out of range", ErrProductKey)
	}
	sk, err = hkdf32(root, []byte(labelProductKey), product+"|"+strconv.Itoa(epoch))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrProductKey, err)
	}
	priv, err := hpke.ParsePrivateKey(sk)
	if err != nil {
		clear(sk)
		return nil, nil, fmt.Errorf("%w: %w", ErrProductKey, err)
	}
	public, err := priv.PublicKey()
	if err != nil {
		clear(sk)
		return nil, nil, fmt.Errorf("%w: %w", ErrProductKey, err)
	}
	return sk, public.Bytes(), nil
}

// CheckPublicKey is the server's check of a submitted product public key
// (section 11.4), wrapping ErrProductKey:
//
//   - exactly 32 bytes;
//   - the canonical encoding of a field element: bit 255 clear and the value
//     below 2^255 - 19. X25519 would accept the other spellings as aliases,
//     but a pinned key with two spellings is two keys to a byte comparison,
//     and X25519(sk, 9) never produces one;
//   - an exchange with a fresh random private key does not give the all-zero
//     output, which refuses the low-order points (SPEC section 4.4).
func CheckPublicKey(pub []byte) error {
	if len(pub) != KeyLen {
		return fmt.Errorf("%w: %d bytes, not %d", ErrProductKey, len(pub), KeyLen)
	}
	if !canonicalX25519(pub) {
		return fmt.Errorf("%w: not a canonical X25519 encoding", ErrProductKey)
	}
	pk, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProductKey, err)
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("platform: generate an X25519 key: %w", err)
	}
	// crypto/ecdh returns an error, not zeros, when the shared secret is the
	// all-zero value.
	shared, err := eph.ECDH(pk)
	clear(shared)
	if err != nil {
		return fmt.Errorf("%w: a low-order point", ErrProductKey)
	}
	return nil
}

// canonicalX25519 reports whether u, little-endian, has bit 255 clear and is
// below p = 2^255 - 19, whose encoding is ed ff … ff 7f.
func canonicalX25519(u []byte) bool {
	if u[31]&0x80 != 0 {
		return false
	}
	if u[31] != 0x7f {
		return true
	}
	for i := 30; i >= 1; i-- {
		if u[i] != 0xff {
			return true
		}
	}
	return u[0] < 0xed
}
