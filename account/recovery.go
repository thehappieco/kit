package account

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/thehappieco/kit/internal/ecma"
)

// The recovery code: 30 characters of Crockford's base32 (no I, L, O or U,
// so nothing reads as a digit and back), written as six groups of five. It is
// 150 random bits, written down by hand and typed back by hand.
const (
	recoveryAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	recoveryGroups   = 6
	recoveryGroupLen = 5
	// RecoveryCodeLen is the number of code characters, without dashes.
	RecoveryCodeLen = recoveryGroups * recoveryGroupLen
)

// NewRecoveryCode returns a fresh code: 30 random bytes, each taken modulo 32,
// which is unbiased because 256 is a multiple of 32.
func NewRecoveryCode() (string, error) {
	raw := make([]byte, RecoveryCodeLen)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("account: entropy: %w", err)
	}
	return recoveryCode(raw), nil
}

func recoveryCode(raw []byte) string {
	chars := make([]byte, len(raw))
	for i, b := range raw {
		chars[i] = recoveryAlphabet[int(b)%len(recoveryAlphabet)]
	}
	return group(string(chars))
}

func group(chars string) string {
	groups := make([]string, 0, recoveryGroups)
	for i := 0; i < len(chars); i += recoveryGroupLen {
		groups = append(groups, chars[i:i+recoveryGroupLen])
	}
	return strings.Join(groups, "-")
}

// NormaliseRecoveryCode accepts what somebody actually types back: it
// uppercases with JavaScript's toUpperCase, drops everything outside [0-9A-Z],
// maps O to 0, I and L to 1 and U to V, requires 30 characters and regroups
// them as six groups of five joined by '-'.
func NormaliseRecoveryCode(code string) (string, error) {
	var b strings.Builder
	for _, r := range ecma.ToUpperASCII(code) {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == 'O':
			b.WriteByte('0')
		case r == 'I' || r == 'L':
			b.WriteByte('1')
		case r == 'U':
			b.WriteByte('V')
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		}
	}
	cleaned := b.String()
	if len(cleaned) != RecoveryCodeLen {
		return "", ErrRecoveryLength
	}
	return group(cleaned), nil
}

func (p Profile) normaliseRecovery(code string) (string, error) {
	if p.NormaliseRecovery != nil {
		return p.NormaliseRecovery(code)
	}
	return NormaliseRecoveryCode(code)
}

// RecoveryKey is the wrap key of a recovery code:
// HKDF-SHA256(IKM = UTF-8(normalised code), salt = ∅, info = RecoveryKeyLabel).
// Not stretched: the code is 150 random bits. It never leaves the client.
func RecoveryKey(p Profile, code string) ([]byte, error) {
	normalised, err := p.normaliseRecovery(code)
	if err != nil {
		return nil, err
	}
	return hkdf.Key(sha256.New, []byte(normalised), nil, p.RecoveryKeyLabel, KeyLen)
}

// RecoveryProof is the branch of a recovery code that is sent, so the server
// releases the recovery wrap only to somebody holding the code. It is an
// independent HKDF output, so it says nothing about RecoveryKey.
func RecoveryProof(p Profile, code string) (string, error) {
	normalised, err := p.normaliseRecovery(code)
	if err != nil {
		return "", err
	}
	proof, err := hkdf.Key(sha256.New, []byte(normalised), nil, p.RecoveryProofLabel, KeyLen)
	if err != nil {
		return "", err
	}
	return p.encoding().EncodeToString(proof), nil
}
