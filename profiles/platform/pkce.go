package platform

import (
	"crypto/sha256"
	"fmt"
)

// The code verifier's lengths (RFC 7636 section 4.1, SPEC section 11.13).
const (
	MinCodeVerifierLen = 43
	MaxCodeVerifierLen = 128
	// CodeChallengeLen is the length of every S256 code challenge: the
	// base64url of a SHA-256 digest.
	CodeChallengeLen = 43
)

// PKCEChallenge returns the S256 challenge of a code verifier (RFC 7636
// section 4.2, SPEC section 11.13):
//
//	code_challenge = BASE64URL(SHA-256(ASCII(code_verifier)))
//
// It refuses, wrapping ErrPKCE, a verifier that is not 43 to 128 characters
// from [A-Za-z0-9._~-], rather than hashing it: the token endpoint refuses
// such a verifier, so a relying party that hashed one would hold a flow it
// can never redeem. The challenge is also bound into the key-delivery AAD
// (section 11.12).
//
// A server comparing a presented verifier with a stored challenge compares
// the two challenges in constant time (crypto/subtle).
func PKCEChallenge(verifier string) (string, error) {
	if !validCodeVerifier(verifier) {
		return "", fmt.Errorf("%w: expected %d to %d characters from [A-Za-z0-9._~-]", ErrPKCE, MinCodeVerifierLen, MaxCodeVerifierLen)
	}
	sum := sha256.Sum256([]byte(verifier))
	return EncodeB64(sum[:]), nil
}

// validCodeVerifier reports whether v is 43 to 128 bytes, each one of RFC
// 7636's unreserved characters. Counting bytes is counting characters here,
// because every accepted character is ASCII.
func validCodeVerifier(v string) bool {
	if len(v) < MinCodeVerifierLen || len(v) > MaxCodeVerifierLen {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}

// validCodeChallenge reports whether s is the one spelling of a SHA-256
// digest in base64url: 43 characters whose last two bits are zero.
func validCodeChallenge(s string) bool {
	if len(s) != CodeChallengeLen {
		return false
	}
	b, err := DecodeB64(s, sha256.Size)
	clear(b)
	return err == nil
}
