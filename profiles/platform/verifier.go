package platform

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

// AuthVerifier returns what the platform's server stores for K_auth (section
// 11.7):
//
//	SHA-256("thehappie-id/v1/auth-verifier" || 0x00 || sub16 || K_auth)
//
// A fast hash is enough, because the password wrap in the same row is an
// equally good offline oracle: only the client's Argon2id sets an attacker's
// cost. It wraps ErrEncoding for a sub that is not a lowercase UUID or a key
// that is not 32 bytes.
func AuthVerifier(sub string, kAuth []byte) ([32]byte, error) {
	return verifier(labelAuthVerifier, sub, kAuth)
}

// RecoveryVerifier returns what the server stores for R_proof:
//
//	SHA-256("thehappie-id/v1/recovery-verifier" || 0x00 || sub16 || R_proof)
func RecoveryVerifier(sub string, rProof []byte) ([32]byte, error) {
	return verifier(labelRecoveryVerifier, sub, rProof)
}

func verifier(label, sub string, key []byte) ([32]byte, error) {
	var out [32]byte
	sub16, err := parseSub(sub)
	if err != nil {
		return out, err
	}
	if len(key) != KeyLen {
		return out, fmt.Errorf("%w: a %d-byte key", ErrEncoding, len(key))
	}
	h := sha256.New()
	h.Write([]byte(label))
	h.Write([]byte{0})
	h.Write(sub16[:])
	h.Write(key)
	h.Sum(out[:0])
	return out, nil
}

// VerifierMatches compares a stored verifier with a computed one in constant
// time. A stored value of the wrong length never matches.
func VerifierMatches(stored []byte, computed [32]byte) bool {
	return subtle.ConstantTimeCompare(stored, computed[:]) == 1
}
