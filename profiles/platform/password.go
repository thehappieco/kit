package platform

import (
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// The password profile thehappie-password/v1 (section 11.2).
const (
	// MinNewPasswordLen is the fewest code points a new password may have
	// (sign-up, password change, recovery).
	MinNewPasswordLen = 12
	// MaxPasswordLen is the most code points any password may have.
	MaxPasswordLen = 256
	// maxMarkRun is the longest run of combining marks a password may hold
	// in its canonical decomposition. Past 30 non-starters,
	// golang.org/x/text/unicode/norm inserts U+034F to keep the text
	// stream-safe (UAX #15) and its NFC is no longer the NFC of
	// String.prototype.normalize, so the two sides would derive different
	// keys from one password. Such a password is refused instead; marks
	// (category M) are a superset of non-starters that both sides can test.
	maxMarkRun = 30
)

// PreparePassword applies the password profile to a password being presented
// (login, unlock, opening a key bundle): every rule of section 11.2 except
// the minimum length, which applies only to new passwords. It returns P', the
// bytes the KDF consumes; the caller should clear them after use.
func PreparePassword(password string) ([]byte, error) { return preparePassword(password, false) }

// PrepareNewPassword applies the password profile to a password being set
// (sign-up, password change, recovery), minimum length included.
func PrepareNewPassword(password string) ([]byte, error) { return preparePassword(password, true) }

// preparePassword follows section 11.2 in its order, so that a password with
// several defects is refused for the same one in every implementation:
// well-formedness, the run of combining marks (see maxMarkRun), NFC, the
// space mapping, control characters, then length.
//
// The mapped spaces are all starters with no canonical composition partner,
// so mapping after NFC keeps the result in NFC.
func preparePassword(password string, isNew bool) ([]byte, error) {
	if !utf8.ValidString(password) {
		return nil, ErrPasswordInvalid
	}
	if markRunTooLong(password) {
		return nil, ErrPasswordInvalid
	}
	s := norm.NFC.String(password)
	out := make([]byte, 0, len(s))
	n := 0
	for _, r := range s {
		switch {
		case r <= 0x1f, r >= 0x7f && r <= 0x9f:
			clear(out)
			return nil, ErrPasswordInvalid
		case isMappedSpace(r):
			r = ' '
		}
		out = utf8.AppendRune(out, r)
		n++
	}
	if isNew && n < MinNewPasswordLen {
		clear(out)
		return nil, ErrPasswordTooShort
	}
	if n > MaxPasswordLen {
		clear(out)
		return nil, ErrPasswordTooLong
	}
	return out, nil
}

// markRunTooLong reports whether the canonical decomposition of s holds more
// than maxMarkRun consecutive combining marks. Below that, norm inserts
// nothing and its NFD and NFC are Unicode's; at or above it, the U+034F it
// inserts is itself a mark and only lengthens the run, so the answer is the
// one a true NFD gives.
func markRunTooLong(s string) bool {
	run := 0
	for _, r := range norm.NFD.String(s) {
		if !unicode.Is(unicode.M, r) {
			run = 0
			continue
		}
		if run++; run > maxMarkRun {
			return true
		}
	}
	return false
}

// isMappedSpace reports the code points section 11.2 maps to U+0020: the
// space separators of Unicode category Zs other than U+0020 itself.
func isMappedSpace(r rune) bool {
	switch {
	case r == 0x00a0, r == 0x1680, r >= 0x2000 && r <= 0x200a, r == 0x202f, r == 0x205f, r == 0x3000:
		return true
	}
	return false
}
