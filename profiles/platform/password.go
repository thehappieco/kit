package platform

import (
	"strings"
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
	// maxMarkRun is the longest run of counted code points (see counted) a
	// password may hold in its compatibility decomposition. Past 30 of
	// them, golang.org/x/text/unicode/norm inserts U+034F to keep the text
	// stream-safe (UAX #15) and its NFC is no longer the NFC of
	// String.prototype.normalize, so the two sides would derive different
	// keys from one password. Such a password is refused instead.
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
// well-formedness, the run of marks (see maxMarkRun), NFC, the space mapping,
// control characters, then length.
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
	// Defence in depth: with the run rule above, norm inserts no U+034F
	// under the Unicode tables the rule was checked against (15.0 and 17.0,
	// TestNormInsertsNothingTheRunRuleAccepts). Should later tables count a
	// code point the rule does not, the password is refused here rather
	// than prepared to bytes ICU would not produce. NFC itself never adds or
	// removes U+034F, which has no decomposition and composes with nothing.
	if strings.Count(s, graphemeJoiner) != strings.Count(password, graphemeJoiner) {
		return nil, ErrPasswordInvalid
	}
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

// graphemeJoiner is U+034F, which norm inserts into a run that is too long.
const graphemeJoiner = "\u034f"

// markRunTooLong reports whether the compatibility decomposition (NFKD) of s
// holds more than maxMarkRun consecutive counted code points (section 11.2,
// step 2). It decomposes code point by code point: the full decomposition of
// a string differs from the decompositions of its code points put end to end
// only by canonical reordering, which moves only code points with a non-zero
// combining class past each other, and those are all counted. So the runs are
// the same, no Stream-Safe insertion is involved, and the cost is linear.
func markRunTooLong(s string) bool {
	run := 0
	var d []byte
	for _, r := range s {
		if r < utf8.RuneSelf {
			run = 0 // ASCII decomposes to itself and holds no mark
			continue
		}
		d = norm.NFKD.AppendString(d[:0], string(r))
		for _, c := range string(d) {
			if !counted(c) {
				run = 0
				continue
			}
			if run++; run > maxMarkRun {
				return true
			}
		}
	}
	return false
}

// counted reports whether r counts toward a run (section 11.2, step 2): a
// mark (general category M), a Hangul vowel or final jamo (U+1160 to U+11FF
// and U+D7B0 to U+D7FF), or U+16D67 KIRAT RAI VOWEL SIGN E. Together they
// cover what norm counts as a non-starter for the Stream-Safe Text Format:
// every code point with a non-zero combining class, which is a mark, and
// every one that composes with what precedes it, which is a mark, a Hangul
// vowel or final jamo, or (from Unicode 16.0) U+16D67, a letter. Both
// TestNormInsertsNothingTheRunRuleAccepts and TestEveryNonStarterIsCounted
// walk every code point with the running toolchain's tables.
func counted(r rune) bool {
	switch {
	case r < 0x0300:
		return false
	case r >= 0x1160 && r <= 0x11ff, r >= 0xd7b0 && r <= 0xd7ff, r == 0x16d67:
		return true
	}
	return unicode.Is(unicode.M, r)
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
