// Package ecma reproduces the few ECMAScript string operations whose results
// are wire bytes in a kit profile, so Go computes what a browser computes.
//
// Go's strings.TrimSpace, ToLower and ToUpper differ from JavaScript's
// String.prototype.trim, toLowerCase and toUpperCase: Go trims U+0085 and not
// U+FEFF, uses simple case mappings only, and has no final-sigma rule. Wappie's
// account wrap AAD is built from email.trim().toLowerCase() in the browser, and
// its recovery code is normalised with toUpperCase, so the kit's Go side needs
// the JavaScript behaviour. The vectors in vectors/wappie/golden/account-ts.json
// were produced by V8 and pin it.
//
// The remaining difference is the Unicode version: Go's tables and the
// browser's ICU may disagree about characters encoded after Go's version.
package ecma

import (
	"strings"
	"unicode"
)

// isWhiteSpaceOrLineTerminator is ECMAScript's WhiteSpace or LineTerminator.
func isWhiteSpaceOrLineTerminator(r rune) bool {
	switch r {
	case '\t', '\v', '\f', '\ufeff', '\n', '\r', '\u2028', '\u2029':
		return true
	}
	return unicode.Is(unicode.Zs, r)
}

// Trim is String.prototype.trim.
func Trim(s string) string {
	return strings.TrimFunc(s, isWhiteSpaceOrLineTerminator)
}

// ToLowerCase is String.prototype.toLowerCase: the Unicode default lowercase
// mapping, with U+0130's full mapping and the final-sigma rule, which are the
// two places it differs from simple per-rune mapping.
func ToLowerCase(s string) string {
	runes := []rune(s)
	var b strings.Builder
	b.Grow(len(s))
	for i, r := range runes {
		switch {
		case r == '\u0130':
			b.WriteString("i\u0307")
		case r == '\u03a3' && finalSigma(runes, i):
			b.WriteRune('\u03c2')
		default:
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// upperExpansions are the unconditional full uppercase mappings of
// SpecialCasing.txt that produce an ASCII letter. The others expand to Greek
// or Armenian letters, which toUpperCase callers in this kit discard.
var upperExpansions = map[rune]string{
	'\u00df': "SS",
	'\u0149': "\u02bcN",
	'\u01f0': "J\u030c",
	'\u1e96': "H\u0331",
	'\u1e97': "T\u0308",
	'\u1e98': "W\u030a",
	'\u1e99': "Y\u030a",
	'\u1e9a': "A\u02be",
	'\ufb00': "FF",
	'\ufb01': "FI",
	'\ufb02': "FL",
	'\ufb03': "FFI",
	'\ufb04': "FFL",
	'\ufb05': "ST",
	'\ufb06': "ST",
}

// ToUpperASCII is String.prototype.toUpperCase restricted to what survives a
// filter to ASCII letters and digits: every character's uppercase mapping,
// with the full expansions that yield ASCII. Characters that uppercase to
// something outside ASCII come out as some non-ASCII rune; callers that keep
// only [0-9A-Z] get exactly what JavaScript gives them.
func ToUpperASCII(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if x, ok := upperExpansions[r]; ok {
			b.WriteString(x)
			continue
		}
		b.WriteRune(unicode.ToUpper(r))
	}
	return b.String()
}

// finalSigma is the Final_Sigma condition of Unicode section 3.13: the sigma follows
// a cased letter (skipping case-ignorable characters) and is not followed by
// one (skipping them too).
func finalSigma(runes []rune, at int) bool {
	before := false
	for i := at - 1; i >= 0; i-- {
		if caseIgnorable(runes[i]) {
			continue
		}
		before = cased(runes[i])
		break
	}
	if !before {
		return false
	}
	for i := at + 1; i < len(runes); i++ {
		if caseIgnorable(runes[i]) {
			continue
		}
		return !cased(runes[i])
	}
	return true
}

// cased is the Unicode Cased property: Lowercase, Uppercase or Lt.
func cased(r rune) bool {
	return unicode.IsLower(r) || unicode.IsUpper(r) || unicode.IsTitle(r) ||
		unicode.Is(unicode.Other_Lowercase, r) || unicode.Is(unicode.Other_Uppercase, r)
}

// caseIgnorable is the Unicode Case_Ignorable property: Mn, Me, Cf, Lm and Sk,
// plus Word_Break MidLetter, MidNumLet and Single_Quote.
func caseIgnorable(r rune) bool {
	switch r {
	case '\'', '.', ':', '\u00b7', '\u0387', '\u055f', '\u05f4', '\u2018', '\u2019', '\u2024', '\u2027',
		'\ufe13', '\ufe52', '\ufe55', '\uff07', '\uff0e', '\uff1a':
		return true
	}
	return unicode.In(r, unicode.Mn, unicode.Me, unicode.Cf, unicode.Lm, unicode.Sk)
}
