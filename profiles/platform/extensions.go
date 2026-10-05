package platform

import (
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

// The client extension results a passkey ceremony may carry (SPEC section
// 11.16).
//
// A WebAuthn credential reports its extension outputs in
// clientExtensionResults, and for the PRF extension that output is the
// secret the passkey wrap key is derived from. The page therefore never
// serializes a credential with toJSON(); it copies an allowlist, and the
// server refuses anything outside the same allowlist, so a page bug that
// lets a PRF output through is a refused request rather than a secret in a
// request body, a log line or a database row.
//
// The allowlist, exactly:
//
//	{}                       or any subset, each member at most once, of
//	"credProps": {"rk": true | false}
//	"prf":       {"enabled": true | false}
//
// Everything else is refused: prf.results in any form (an empty object
// included), prf.enabled or credProps.rk of another JSON type (null
// included), an empty credProps or prf, any other member at either level, a
// member name in another case, a repeated member, and a text that is not one
// JSON object. Member names are compared as written after JSON unescaping,
// so "pr\u0066" is "prf" here as it is to every JSON reader, and a repeat
// spelled that way is still a repeat.
//
// Taken from the platform's internal/crypto/idcrypto/extensions.go at
// b5d9f69.

// Member names of the allowlist.
const (
	extCredProps = "credProps"
	extRK        = "rk"
	extPRF       = "prf"
	extEnabled   = "enabled"
)

// CheckClientExtensions refuses, wrapping ErrClientExtensions, a
// clientExtensionResults value (the exact JSON text of that one member of a
// credential) that holds anything outside the allowlist of section 11.16. It
// never reports what it found: a refused value may be a PRF output.
//
// The text is read as strictly as the key bundle (section 11.9): UTF-8, one
// JSON value with JSON's four whitespace characters only, nothing before it
// (a byte order mark is refused) and nothing after it.
//
// The server calls it on every credential it receives, before the WebAuthn
// library reads the credential. Finding the member in the credential is the
// caller's job, and the caller must do it strictly too: encoding/json, which
// WebAuthn libraries use, matches member names case-insensitively and lets a
// repeated member replace the first, so a credential whose
// clientExtensionResults is spelled twice, or in another case, is refused
// there rather than checked here in one spelling and read in another.
func CheckClientExtensions(raw []byte) error {
	// encoding/json reads invalid UTF-8 inside a string as U+FFFD; a text
	// that is not UTF-8 is not JSON (RFC 8259 section 8.1), so it never gets
	// that far.
	if !utf8.Valid(raw) {
		return fmt.Errorf("%w: not UTF-8", ErrClientExtensions)
	}
	members, err := readMembers(raw, extCredProps, extPRF)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrClientExtensions, err)
	}
	if v, ok := members[extCredProps]; ok {
		if err := checkFlagObject(v, extRK); err != nil {
			return fmt.Errorf("%w: credProps: %w", ErrClientExtensions, err)
		}
	}
	if v, ok := members[extPRF]; ok {
		if err := checkFlagObject(v, extEnabled); err != nil {
			return fmt.Errorf("%w: prf: %w", ErrClientExtensions, err)
		}
	}
	return nil
}

// checkFlagObject accepts exactly {name: true | false}.
func checkFlagObject(raw json.RawMessage, name string) error {
	m, err := readObject(raw, name)
	if err != nil {
		return err
	}
	_, err = jsonBool(m[name])
	return err
}
