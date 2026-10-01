package platform

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/thehappieco/kit/jcs"
)

// MaxEpoch is the largest account key epoch. Epochs start at 1 (section
// 11.1) and fit a signed 32-bit integer, which is what both JSON readers and
// the platform's database hold exactly.
const MaxEpoch = 1<<31 - 1

// maxJCSInt is the largest integer a restricted JSON array may hold.
const maxJCSInt = 1 << 31

// subLen is the length of a sub: a UUID as lowercase hyphenated text.
const subLen = 36

// b64 is base64url without padding that refuses non-zero trailing bits.
// Go's decoder still skips CR and LF, so decodeB64 also re-encodes and
// compares, which leaves exactly one accepted spelling per byte string.
var b64 = base64.RawURLEncoding.Strict()

// EncodeB64 returns b as base64url without padding (RFC 4648 section 5), the
// only spelling of binary values in the protocol's JSON.
func EncodeB64(b []byte) string { return b64.EncodeToString(b) }

// DecodeB64 decodes strict base64url of exactly n bytes. It refuses padding,
// characters outside the alphabet (line breaks included), non-zero trailing
// bits and any other length, wrapping ErrEncoding. The error never repeats
// the input.
func DecodeB64(s string, n int) ([]byte, error) {
	if n < 0 || len(s) != b64.EncodedLen(n) {
		return nil, fmt.Errorf("%w: expected base64url of %d bytes", ErrEncoding, n)
	}
	b, err := decodeB64(s)
	if err != nil {
		return nil, err
	}
	if len(b) != n {
		clear(b)
		return nil, fmt.Errorf("%w: expected base64url of %d bytes", ErrEncoding, n)
	}
	return b, nil
}

// decodeB64 decodes strict base64url of any length.
func decodeB64(s string) ([]byte, error) {
	b, err := b64.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: not strict base64url", ErrEncoding)
	}
	if b64.EncodeToString(b) != s {
		clear(b)
		return nil, fmt.Errorf("%w: not strict base64url", ErrEncoding)
	}
	return b, nil
}

// JCSArray returns the RFC 8785 text (package jcs) of a JSON array whose
// elements are each a string drawn from [A-Za-z0-9._:/|@-] or an int from 0
// to 2^31: a restricted JSON AAD (section 11.1). For such arrays
// JCS, JSON.stringify and encoding/json agree byte for byte: no escapes, no
// spaces, plain decimal integers. Any other element type or value is refused
// with ErrEncoding rather than escaped, because an escape is where two
// serialisers start to differ.
func JCSArray(elems ...any) ([]byte, error) {
	for i, e := range elems {
		switch v := e.(type) {
		case string:
			if !jcsText(v) {
				return nil, fmt.Errorf("%w: array element %d is not a restricted string", ErrEncoding, i)
			}
		case int:
			if v < 0 || int64(v) > maxJCSInt {
				return nil, fmt.Errorf("%w: array element %d is out of range", ErrEncoding, i)
			}
		default:
			return nil, fmt.Errorf("%w: array element %d is neither a string nor an int", ErrEncoding, i)
		}
	}
	if elems == nil {
		elems = []any{}
	}
	out, err := jcs.Marshal(elems)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEncoding, err)
	}
	return out, nil
}

// jcsText reports whether every byte of s is in the AAD alphabet.
func jcsText(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '.', c == '_', c == ':', c == '/', c == '|', c == '@', c == '-':
		default:
			return false
		}
	}
	return true
}

// DummySub is the sub the server uses for an unknown or disabled account, so
// that computing and comparing a verifier costs the same either way (section
// 11.7). It is the nil UUID, whose 16 bytes are zero.
func DummySub() string { return "00000000-0000-0000-0000-000000000000" }

// parseSub returns the 16 bytes of a sub. Only the lowercase hyphenated
// spelling is accepted, so a sub has one AAD and one verifier input. The
// version nibble is not checked: the server issues UUIDv7, and DummySub is
// the nil UUID.
func parseSub(sub string) ([16]byte, error) {
	var out [16]byte
	if len(sub) != subLen {
		return out, fmt.Errorf("%w: sub is not a lowercase hyphenated UUID", ErrEncoding)
	}
	j := 0
	for i := 0; i < subLen; i++ {
		c := sub[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return out, fmt.Errorf("%w: sub is not a lowercase hyphenated UUID", ErrEncoding)
			}
			continue
		}
		v, ok := lowerHex(c)
		if !ok {
			return out, fmt.Errorf("%w: sub is not a lowercase hyphenated UUID", ErrEncoding)
		}
		if j%2 == 0 {
			out[j/2] = v << 4
		} else {
			out[j/2] |= v
		}
		j++
	}
	return out, nil
}

func lowerHex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

func checkEpoch(epoch int) bool { return epoch >= 1 && int64(epoch) <= MaxEpoch }

// hkdf32 is HKDF-SHA256 with a 32-byte output. A nil salt is the empty salt
// of the spec, which RFC 5869 treats as 32 zero bytes; HMAC pads both to the
// same block, so the two readings agree.
func hkdf32(ikm, salt []byte, info string) ([]byte, error) {
	k, err := hkdf.Key(sha256.New, ikm, salt, info, KeyLen)
	if err != nil {
		return nil, fmt.Errorf("platform: hkdf: %w", err)
	}
	return k, nil
}
