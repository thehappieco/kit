package ecma_test

import (
	"testing"

	"github.com/thehappieco/kit/internal/ecma"
)

// The cases V8 disagrees with Go's strings package on. The vectors in
// golden/account-ts.json pin the rest.
func TestAgainstJavaScript(t *testing.T) {
	for in, want := range map[string]string{
		"\ufeff a \u0085":     "a \u0085",
		"\u2028\u3000a\u00a0": "a",
		"\u180ea":             "\u180ea",
	} {
		if got := ecma.Trim(in); got != want {
			t.Errorf("Trim(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"\u0130":              "i\u0307",
		"\u0391\u03a3":        "\u03b1\u03c2",
		"\u03a3":              "\u03c3",
		"\u0391\u03a3\u0391":  "\u03b1\u03c3\u03b1",
		"\u0391\u03a3.\u0391": "\u03b1\u03c3.\u03b1",
		"\u0391\u03a3.":       "\u03b1\u03c2.",
		"\u0301\u03a3":        "\u0301\u03c3",
	} {
		if got := ecma.ToLowerCase(in); got != want {
			t.Errorf("ToLowerCase(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"\u00df": "SS", "\ufb01": "FI", "\u0131": "I", "\u017f": "S", "a1": "A1"} {
		if got := ecma.ToUpperASCII(in); got != want {
			t.Errorf("ToUpperASCII(%q) = %q, want %q", in, got, want)
		}
	}
}
