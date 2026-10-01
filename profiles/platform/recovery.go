package platform

import (
	"fmt"
	"io"
	"strings"

	"github.com/thehappieco/kit/account"
)

// Recovery code (section 11.6).
const (
	// RecoveryAlphabet is Crockford's base32 alphabet: digits and upper-case
	// letters without I, L, O and U.
	RecoveryAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	// RecoveryCodeLen is the length of the canonical form, and the number of
	// random bytes a code is made from. 30 characters of 5 bits are 150 bits.
	RecoveryCodeLen = 30
	// recoveryGroup is the size of a display group.
	recoveryGroup = 5
)

// NewRecoveryCode reads 30 bytes from r (crypto/rand when r is nil) and
// returns the canonical recovery code they make.
func NewRecoveryCode(r io.Reader) (string, error) {
	b, err := readRandom(r, RecoveryCodeLen)
	if err != nil {
		return "", err
	}
	defer clear(b)
	return RecoveryCodeFromBytes(b)
}

// RecoveryCodeFromBytes maps exactly 30 bytes to a canonical recovery code:
// byte b becomes RecoveryAlphabet[b mod 32]. Since 256 = 8 × 32, every
// character comes from exactly eight byte values, so uniform bytes give a
// uniform code with no rejection sampling.
func RecoveryCodeFromBytes(b []byte) (string, error) {
	if len(b) != RecoveryCodeLen {
		return "", fmt.Errorf("%w: %d bytes, not %d", ErrRecoveryCode, len(b), RecoveryCodeLen)
	}
	out := make([]byte, RecoveryCodeLen)
	defer clear(out)
	for i, x := range b {
		out[i] = RecoveryAlphabet[x%32]
	}
	return string(out), nil
}

// CanonicalRecoveryCode turns typed text into the canonical form C: ASCII
// spaces, tabs, line breaks and '-' are removed, ASCII letters are upper
// cased, O becomes 0 and I and L become 1. Anything else outside the
// alphabet, any non-ASCII byte included, refuses the code, as does a result
// that is not exactly 30 characters. It works on bytes, never on Unicode case
// mappings, so 'ı' or 'ſ' can never pass for 'I' or 'S'.
//
// This is not account.NormaliseRecoveryCode (SPEC section 6.7, Wappie's),
// which maps U to V, upper-cases with Unicode rules and keeps the dashes.
func CanonicalRecoveryCode(s string) (string, error) {
	out := make([]byte, 0, RecoveryCodeLen)
	defer clear(out[:cap(out)])
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ', c == '\t', c == '\n', c == '\r', c == '-':
			continue
		case 'a' <= c && c <= 'z':
			c -= 'a' - 'A'
		}
		switch c {
		case 'O':
			c = '0'
		case 'I', 'L':
			c = '1'
		}
		if strings.IndexByte(RecoveryAlphabet, c) < 0 {
			return "", fmt.Errorf("%w: a character outside the alphabet", ErrRecoveryCode)
		}
		if len(out) == RecoveryCodeLen {
			return "", fmt.Errorf("%w: more than %d characters", ErrRecoveryCode, RecoveryCodeLen)
		}
		out = append(out, c)
	}
	if len(out) != RecoveryCodeLen {
		return "", fmt.Errorf("%w: fewer than %d characters", ErrRecoveryCode, RecoveryCodeLen)
	}
	return string(out), nil
}

// DisplayRecoveryCode returns a code as it is shown: six groups of five
// characters separated by '-'. It accepts any spelling CanonicalRecoveryCode
// accepts.
func DisplayRecoveryCode(code string) (string, error) {
	c, err := CanonicalRecoveryCode(code)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.Grow(RecoveryCodeLen + RecoveryCodeLen/recoveryGroup - 1)
	for i := 0; i < RecoveryCodeLen; i += recoveryGroup {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(c[i : i+recoveryGroup])
	}
	return b.String(), nil
}

// RecoveryKeys are the two keys derived from a recovery code. Proof is sent
// to the server (as recovery_auth); Wrap never leaves the client.
type RecoveryKeys struct {
	Wrap  [KeyLen]byte // K_rwrap
	Proof [KeyLen]byte // R_proof
}

// RecoveryAuth returns recovery_auth, the base64url of R_proof.
func (k *RecoveryKeys) RecoveryAuth() string { return EncodeB64(k.Proof[:]) }

// Zero clears both keys.
func (k *RecoveryKeys) Zero() {
	if k != nil {
		clear(k.Wrap[:])
		clear(k.Proof[:])
	}
}

// DeriveRecovery canonicalises a typed or canonical recovery code and derives
// K_rwrap and R_proof from the ASCII bytes of its canonical form:
// account.RecoveryKey and account.RecoveryProof with Account(). No slow KDF
// is needed: 150 bits cannot be guessed offline.
func DeriveRecovery(code string) (*RecoveryKeys, error) {
	c, err := CanonicalRecoveryCode(code)
	if err != nil {
		return nil, err
	}
	p := Account()
	w, err := account.RecoveryKey(p, c)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRecoveryCode, err)
	}
	defer clear(w)
	proofText, err := account.RecoveryProof(p, c)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRecoveryCode, err)
	}
	proof, err := DecodeB64(proofText, KeyLen)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRecoveryCode, err)
	}
	defer clear(proof)
	keys := &RecoveryKeys{}
	copy(keys.Wrap[:], w)
	copy(keys.Proof[:], proof)
	return keys, nil
}
