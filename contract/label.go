package contract

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxLabel is the longest label, in code points.
const MaxLabel = 80

// Ellipsis starts a masked run of digits and a hint: U+2026, never dots.
const Ellipsis = "…"

// hidden reports the characters a label or name never carries: C0 and C1
// controls, and every format character (bidirectional controls, zero-width
// characters, the soft hyphen, the word joiner), with the combining
// grapheme joiner, which could hide, split or reorder what a reader sees.
func hidden(r rune) bool {
	switch {
	case r < 0x20, r >= 0x7f && r <= 0x9f:
		return true
	case r == 0x034f, unicode.Is(unicode.Cf, r):
		return true
	}
	return false
}

// separator reports the characters that may sit between the digits of a
// number someone typed: "+55 (11) 91234-5678", "11.91234.5678",
// "11/91234/5678", "55_11_91234_5678", "119·1234·5678", any dash, and the
// minus sign, which reads as one. The platform database's floor (its
// migration 0013) counts no separator this does not, so a cleaned label
// always passes it.
func separator(r rune) bool {
	switch r {
	case ' ', '.', ',', '/', '_', '(', ')', '+', '-', '\u00b7', '\u2022', '*', '#', '\u2212':
		return true
	}
	return unicode.Is(unicode.Pd, r)
}

// atSigns are "@" and the characters that read as one: an address hides
// behind them too.
const atSigns = "@\uff20\ufe6b"

// DigitRun is how many digits make a run that could be a phone number.
const DigitRun = 7

// CleanLabel turns a name a person gave an item into what may cross the
// wire, or "" when nothing is left:
//   - any text with "@", or a character that reads as one, goes, since it
//     may be an address;
//   - hidden characters go (hidden);
//   - whitespace collapses to single spaces, and the ends are trimmed;
//   - each run of DigitRun or more digits (any script's decimal digits),
//     separators allowed between them, becomes "…" and its last four
//     digits;
//   - it is cut at MaxLabel code points, never leaving a lone regional
//     indicator (half a flag).
//
// The app has already set aside placeholders, opaque ids and the number or
// address itself, and applied NFC; the platform applies CleanLabel again on
// intake, as a backstop.
func CleanLabel(raw string) string {
	if !utf8.ValidString(raw) || strings.ContainsAny(raw, atSigns) {
		return ""
	}
	var b strings.Builder
	for _, r := range raw {
		if hidden(r) {
			continue
		}
		b.WriteRune(r)
	}
	// Whitespace first, so that a run of digits a no-break space split is
	// seen whole, and cleaning a clean label changes nothing.
	s := strings.Join(strings.FieldsFunc(b.String(), unicode.IsSpace), " ")
	return cut(maskDigitRuns(s), MaxLabel)
}

// maskDigitRuns replaces every run of DigitRun or more digits, with
// separators between them, by "…" and the run's last four digits. The
// separators inside a run go with it, and so does a "+" or "(" just before
// it; the rest around it stays.
func maskDigitRuns(s string) string {
	rs := []rune(s)
	var out []rune
	for i := 0; i < len(rs); {
		if !isDigit(rs[i]) {
			out = append(out, rs[i])
			i++
			continue
		}
		// The run: digits, with separators between digits.
		last, digits := i, []rune{}
		for j := i; j < len(rs); j++ {
			if isDigit(rs[j]) {
				digits = append(digits, rs[j])
				last = j
				continue
			}
			if !separator(rs[j]) {
				break
			}
		}
		end := last + 1
		if len(digits) >= DigitRun {
			// A "+" or "(" just before the run is the number's too.
			for len(out) > 0 && (out[len(out)-1] == '+' || out[len(out)-1] == '(') {
				out = out[:len(out)-1]
			}
			out = append(out, []rune(Ellipsis)...)
			out = append(out, digits[len(digits)-4:]...)
		} else {
			out = append(out, rs[i:end]...)
		}
		i = end
	}
	return string(out)
}

// isDigit is any script's decimal digit: a fullwidth or an Arabic-Indic
// number is a number too.
func isDigit(r rune) bool { return unicode.IsDigit(r) }

func cut(s string, max int) string {
	rs := []rune(s)
	if len(rs) <= max {
		return s
	}
	rs = rs[:max]
	// A flag is a pair of regional indicators; never leave half of one.
	n := 0
	for i := len(rs) - 1; i >= 0 && rs[i] >= 0x1f1e6 && rs[i] <= 0x1f1ff; i-- {
		n++
	}
	if n%2 == 1 {
		rs = rs[:len(rs)-1]
	}
	return strings.TrimSpace(string(rs))
}

// ValidLabel reports whether s is a label as CleanLabel leaves one: not
// empty, and CleanLabel changes nothing.
func ValidLabel(s string) bool {
	return s != "" && CleanLabel(s) == s
}

// ValidHint reports whether s is a hint: "…" and four digits (the last four
// of a number, never of a WhatsApp LID), or a lowercase letter or digit,
// "…@" and a domain of lowercase labels with at least one dot (an
// address's first character and its domain), whose domain holds fewer
// than DigitRun digits.
func ValidHint(s string) bool {
	if rest, ok := strings.CutPrefix(s, Ellipsis); ok {
		if len(rest) != 4 {
			return false
		}
		for _, r := range rest {
			if r < '0' || r > '9' {
				return false
			}
		}
		return true
	}
	if s == "" || ((s[0] < 'a' || s[0] > 'z') && (s[0] < '0' || s[0] > '9')) {
		return false
	}
	domain, ok := strings.CutPrefix(s[1:], Ellipsis+"@")
	if !ok || domain == "" || len(domain) > 253 {
		return false
	}
	digits := 0
	for _, r := range domain {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '.' {
			return false
		}
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	// A domain with a phone number's worth of digits could carry one.
	if digits >= DigitRun {
		return false
	}
	return strings.Contains(domain, ".") && !strings.HasPrefix(domain, ".") && !strings.HasSuffix(domain, ".") && !strings.Contains(domain, "..")
}
