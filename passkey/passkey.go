// Package passkey wraps an account key under a WebAuthn PRF output, so a
// passkey can unlock what a password unlocks.
//
// The server hands the authenticator one public evaluation input per relying
// party, SHA-256(EvalPrefix ‖ rpID); the PRF output stays in the client and
// is never sent. The wrap key is HKDF over that output, salted with the RP ID:
//
//	K        = HKDF-SHA256(IKM = PRF first output (32), salt = UTF-8(rpID), info = WrapInfo, L = 32)
//	envelope = Header ‖ nonce (12) ‖ AES-256-GCM(K, nonce, key (32), aad) ‖ tag
//
// The scheme comes from Wappie's browser client
// (packages/client/src/crypto/passkey.ts), which is its reference; the AAD is
// the profile's (Wappie's is the JSON array of the RP ID, the user id and the
// credential id).
//
// The functions of this package do not check the RP ID's spelling: the RP ID
// is the profile's configuration, and the profile or the product checks it
// where it is configured. EndsInANumber is the check every product needs.
package passkey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strings"
)

// Sizes the scheme fixes.
const (
	PRFLen   = 32
	KeyLen   = 32
	NonceLen = 12
	TagLen   = 16
)

// Profile is what a product chooses.
type Profile struct {
	// EvalPrefix precedes the RP ID in the PRF evaluation input.
	EvalPrefix string
	// WrapInfo is the HKDF info of the wrap key.
	WrapInfo string
	// Header prefixes every envelope (Wappie: one version byte, 0x01).
	Header []byte
}

// Error says which check failed: bad_key, bad_aad, bad_prf, bad_envelope or
// open_failed.
type Error struct{ Reason string }

func (e *Error) Error() string { return "passkey: " + e.Reason }

// The failures, as values errors.Is matches by identity.
var (
	ErrBadKey = &Error{"bad_key"}
	// ErrBadAAD is an empty AAD. A wrap binds its passkey (the RP, the user,
	// the credential); one bound to nothing could be moved to any of them.
	ErrBadAAD      = &Error{"bad_aad"}
	ErrBadPRF      = &Error{"bad_prf"}
	ErrBadEnvelope = &Error{"bad_envelope"}
	ErrOpenFailed  = &Error{"open_failed"}
)

// PRFSalt is the public PRF evaluation input for an RP ID. The server hands it
// out; it is the same for every credential of the RP, which is what lets a
// discoverable login evaluate the PRF without naming the credential first.
func PRFSalt(p Profile, rpID string) [32]byte {
	return sha256.Sum256([]byte(p.EvalPrefix + rpID))
}

// Key derives the wrap key from a PRF output.
func Key(p Profile, prf []byte, rpID string) ([]byte, error) {
	if len(prf) != PRFLen {
		return nil, ErrBadPRF
	}
	return hkdf.Key(sha256.New, prf, []byte(rpID), p.WrapInfo, KeyLen)
}

// Wrap seals a 32-byte key under a PRF output, bound to aad, which must not
// be empty. Only the envelope may leave the client.
func Wrap(p Profile, privateKey, prf []byte, rpID string, aad []byte) ([]byte, error) {
	if len(privateKey) != KeyLen {
		return nil, ErrBadKey
	}
	if len(aad) == 0 {
		return nil, ErrBadAAD
	}
	nonce := make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("passkey: entropy: %w", err)
	}
	return wrap(p, privateKey, prf, rpID, aad, nonce)
}

func wrap(p Profile, privateKey, prf []byte, rpID string, aad, nonce []byte) ([]byte, error) {
	if len(privateKey) != KeyLen {
		return nil, ErrBadKey
	}
	if len(aad) == 0 {
		return nil, ErrBadAAD
	}
	gcm, err := newGCM(p, prf, rpID)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(p.Header)+NonceLen+KeyLen+TagLen)
	out = append(out, p.Header...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, privateKey, aad), nil
}

// Unwrap opens an envelope. An empty aad is ErrBadAAD; an envelope of the
// wrong length or header is ErrBadEnvelope; everything after that, a PRF of
// the wrong length included, is ErrOpenFailed, as in the reference client.
func Unwrap(p Profile, envelope, prf []byte, rpID string, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, ErrBadAAD
	}
	h := len(p.Header)
	if len(envelope) != h+NonceLen+KeyLen+TagLen || string(envelope[:h]) != string(p.Header) {
		return nil, ErrBadEnvelope
	}
	gcm, err := newGCM(p, prf, rpID)
	if err != nil {
		return nil, ErrOpenFailed
	}
	key, err := gcm.Open(nil, envelope[h:h+NonceLen], envelope[h+NonceLen:], aad)
	if err != nil {
		return nil, ErrOpenFailed
	}
	return key, nil
}

func newGCM(p Profile, prf []byte, rpID string) (cipher.AEAD, error) {
	k, err := Key(p, prf, rpID)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// EndsInANumber is the "ends in a number checker" of the WHATWG URL Standard
// (https://url.spec.whatwg.org/#ends-in-a-number-checker), step by step, as
// the platform's vector generator runs it (rp-id-ends-in-number.json):
//
//  1. strictly split input on ".";
//  2. if the last part is empty, return false when it is the only part, and
//     otherwise drop it (one trailing empty label only);
//  3. let last be the last part;
//  4. if last is non-empty and all ASCII digits, return true;
//  5. if the standard's IPv4 number parser does not fail on last, return
//     true;
//  6. return false.
//
// A browser's host parser runs it on every domain; when it is true, the host
// is parsed as an IPv4 address ("0x7f000001" is 127.0.0.1, "1.2.3.0x4" is
// 1.2.3.4) or refused ("id.0xff"), and is never a domain, so no passkey is
// ever made for a relying party id that ends in a number. The functions of
// this package do not refuse one: the profile or the product checks the id
// where it is configured (the platform profile's ValidRPID calls this).
func EndsInANumber(input string) bool {
	parts := strings.Split(input, ".")
	if parts[len(parts)-1] == "" {
		if len(parts) == 1 {
			return false
		}
		parts = parts[:len(parts)-1]
	}
	last := parts[len(parts)-1]
	if last != "" && strings.Trim(last, "0123456789") == "" {
		return true
	}
	return isIPv4Number(last)
}

// isIPv4Number reports whether the WHATWG "IPv4 number parser"
// (https://url.spec.whatwg.org/#ipv4-number-parser) does not fail on input;
// only that matters here, not the value. The empty string fails. A "0x" or
// "0X" prefix makes the rest radix 16, and a leading "0" of an input of two
// or more code points makes the rest radix 8; otherwise it is radix 10. The
// parser succeeds when what follows the prefix is empty (the number zero) or
// holds only digits of the radix.
func isIPv4Number(input string) bool {
	if input == "" {
		return false
	}
	digits := "0123456789"
	switch {
	case len(input) >= 2 && (input[:2] == "0x" || input[:2] == "0X"):
		input, digits = input[2:], "0123456789abcdefABCDEF"
	case len(input) >= 2 && input[0] == '0':
		input, digits = input[1:], "01234567"
	}
	return strings.Trim(input, digits) == ""
}
