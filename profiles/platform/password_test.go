package platform_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/thehappieco/kit/profiles/platform"
)

func TestTheKDFAcceptsEveryCornerInsideTheBounds(t *testing.T) {
	for _, k := range []platform.KDF{
		platform.DefaultKDF,
		{Alg: "argon2id", M: 262144, T: 4, P: 4},  // m × t exactly at the cap
		{Alg: "argon2id", M: 104857, T: 10, P: 1}, // just under the cap at t's ceiling
		{Alg: "argon2id", M: 65536, T: 10, P: 4},
		{Alg: "argon2id", M: 262144, T: 3, P: 1},
	} {
		if err := k.Check(); err != nil {
			t.Errorf("Check(%+v) = %v", k, err)
		}
	}
	if platform.DefaultKDF != (platform.KDF{Alg: "argon2id", M: 65536, T: 3, P: 1}) {
		t.Fatalf("DefaultKDF moved off the floor: %+v", platform.DefaultKDF)
	}
}

func TestTheAuthKeyAndTheWrapKeyAreDifferentKeys(t *testing.T) {
	keys, err := platform.DerivePasswordKeys("correct horse battery staple", platform.DefaultKDF, make([]byte, platform.SaltLen))
	if err != nil {
		t.Fatal(err)
	}
	if keys.Auth == keys.Wrap {
		t.Fatal("K_auth equals K_wrap")
	}
	if keys.AuthKey() != platform.EncodeB64(keys.Auth[:]) {
		t.Fatal("auth_key is not the base64url of K_auth")
	}
	keys.Zero()
	if keys.Auth != ([32]byte{}) || keys.Wrap != ([32]byte{}) {
		t.Fatal("Zero left key bytes behind")
	}
}

func TestAnIllFormedPasswordIsRefused(t *testing.T) {
	for i, raw := range [][]byte{
		{0xff},
		{0xc0, 0xaf},       // overlong '/'
		{0xed, 0xa0, 0x80}, // a UTF-16 surrogate in UTF-8 clothing
		{0xf4, 0x90, 0x80, 0x80},
		append([]byte(strings.Repeat("a", 20)), 0x80),
	} {
		for _, prepare := range []func(string) ([]byte, error){platform.PreparePassword, platform.PrepareNewPassword} {
			if _, err := prepare(string(raw)); !errors.Is(err, platform.ErrPasswordInvalid) {
				t.Errorf("sequence %d: %v, want ErrPasswordInvalid", i, err)
			}
		}
	}
}

func TestEveryControlCharacterIsRefusedAndNothingElseBelowU00A0(t *testing.T) {
	for r := rune(0); r < 0xa0; r++ {
		pw := "password-" + string(r) + "-1234"
		_, err := platform.PreparePassword(pw)
		control := r <= 0x1f || r >= 0x7f
		if control != errors.Is(err, platform.ErrPasswordInvalid) {
			t.Errorf("U+%04X: %v", r, err)
		}
	}
}

func TestThePreparedPasswordIsNFCWithEverySpaceSeparatorMapped(t *testing.T) {
	got, err := platform.PrepareNewPassword("a\u00a0b\u2000c\u2001d\u3000e\u202ff\u205fg\u1680h")
	if err != nil {
		t.Fatal(err)
	}
	// U+2000 and U+2001 are canonically equivalent to U+2002 and U+2003; NFC
	// rewrites them first, and the mapping catches both spellings.
	if string(got) != "a b c d e f g h" {
		t.Fatal("a space separator survived, or something else changed")
	}
}

func TestPreparingAPreparedPasswordChangesNothing(t *testing.T) {
	for _, pw := range []string{"cafe\u0301 au lait", "a\u00a0b\u3000c d\u0307\u0323", "\u212bngstr\u00f6m units"} {
		once, err := platform.PreparePassword(pw)
		if err != nil {
			t.Fatal(err)
		}
		twice, err := platform.PreparePassword(string(once))
		if err != nil || !bytes.Equal(once, twice) {
			t.Fatalf("not idempotent: %v", err)
		}
	}
}

func TestTheMinimumAppliesOnlyToNewPasswords(t *testing.T) {
	short := "elevenchars"
	if utf8.RuneCountInString(short) != 11 {
		t.Fatal("fixture")
	}
	if _, err := platform.PreparePassword(short); err != nil {
		t.Fatalf("a short password presented at login: %v", err)
	}
	if _, err := platform.PrepareNewPassword(short); !errors.Is(err, platform.ErrPasswordTooShort) {
		t.Fatalf("a short new password: %v", err)
	}
	long := strings.Repeat("\u00e9", 257)
	for _, prepare := range []func(string) ([]byte, error){platform.PreparePassword, platform.PrepareNewPassword} {
		if _, err := prepare(long); !errors.Is(err, platform.ErrPasswordTooLong) {
			t.Fatalf("257 code points: %v", err)
		}
	}
}

func TestNewRootsAreFreshAndOfTheRightLength(t *testing.T) {
	r, err := platform.NewRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := platform.NewRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r) != platform.KeyLen || bytes.Equal(r, r2) {
		t.Fatal("NewRoot")
	}
	if _, err := platform.NewRoot(bytes.NewReader(make([]byte, 31))); err == nil {
		t.Fatal("a short random source did not fail")
	}
}

// The premise of the run rule (SPEC section 11.2, step 2), walked over every
// code point with the running toolchain's tables (Unicode 15.0 below Go 1.27,
// 17.0 from it): every code point with a non-zero canonical combining class is
// counted, so canonical reordering only ever moves counted code points past
// each other and the rule may decompose code point by code point; and every
// counted code point decomposes, canonically and for compatibility, only into
// counted code points, so a run in the text is a run at least as long in its
// NFD and NFKD (which is what keeps the TypeScript side's normalize() linear
// once the rule has passed). U+034F, which norm inserts, is counted.
func TestEveryNonStarterIsCounted(t *testing.T) {
	var buf [utf8.UTFMax]byte
	nonStarters, counted := 0, 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue
		}
		s := string(buf[:utf8.EncodeRune(buf[:], r)])
		if ccc := norm.NFD.PropertiesString(s).CCC(); ccc != 0 {
			nonStarters++
			if !platform.Counted(r) {
				t.Errorf("U+%04X has combining class %d and is not counted", r, ccc)
			}
		}
		if !platform.Counted(r) {
			continue
		}
		counted++
		for _, f := range []norm.Form{norm.NFD, norm.NFKD} {
			for _, d := range f.String(s) {
				if !platform.Counted(d) {
					t.Errorf("U+%04X is counted and its decomposition holds U+%04X, which is not", r, d)
				}
			}
		}
	}
	if nonStarters < 800 || counted < 2000 {
		t.Fatalf("%d non-starters and %d counted code points: the tables are not what this test expects", nonStarters, counted)
	}
	if !platform.Counted(0x034f) {
		t.Fatal("U+034F, which norm inserts, is not counted")
	}
}

// What the run rule is for: norm's NFC inserts U+034F (the Stream-Safe Text
// Format, which ICU's normalize() does not apply) only into a password the
// rule refuses, so every password it accepts has one NFC in Go and in ICU.
// Every code point is walked through templates that put it in a run on its
// own, after a run, before a run and inside one; Hangul syllables, the
// compatibility jamo, U+00B4 and the halfwidth forms are among those whose
// decomposition norm counts and category M alone does not cover. A code point
// that is inert in both NFC and NFKD (no decomposition, combining class 0,
// composing with nothing) adds nothing to norm's count and ends any run, so
// none of the templates can make norm insert around it; those are skipped,
// which keeps the walk short enough for -race.
func TestNormInsertsNothingTheRunRuleAccepts(t *testing.T) {
	acute := "\u0301"
	templates := []func(c string) string{
		func(c string) string { return "a" + strings.Repeat(c, 31) },
		func(c string) string { return "a" + strings.Repeat(c, 11) },
		func(c string) string { return c + strings.Repeat(acute, 30) },
		func(c string) string { return "a" + c + strings.Repeat(acute, 29) },
		func(c string) string { return "a" + strings.Repeat(acute, 29) + c },
		func(c string) string { return "a" + strings.Repeat(acute, 30) + c },
	}
	var buf [utf8.UTFMax]byte
	walked, inserted, missed := 0, 0, 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue
		}
		c := string(buf[:utf8.EncodeRune(buf[:], r)])
		if norm.NFC.PropertiesString(c).BoundaryAfter() && norm.NFKD.PropertiesString(c).BoundaryAfter() {
			continue
		}
		walked++
		for i, tpl := range templates {
			s := tpl(c)
			if strings.Count(norm.NFC.String(s), "\u034f") == strings.Count(s, "\u034f") {
				continue
			}
			inserted++
			if !platform.MarkRunTooLong(s) {
				if missed++; missed <= 20 {
					t.Errorf("template %d with U+%04X: norm inserts U+034F and the rule accepts", i, r)
				}
			}
		}
	}
	if missed > 20 {
		t.Errorf("and %d more", missed-20)
	}
	if walked < 15000 || inserted < 10000 {
		t.Fatalf("%d code points walked, norm inserted U+034F %d times: the tables are not what this test expects", walked, inserted)
	}
}

// Thirty marks prepare; thirty-one are refused before NFC, whatever their
// classes, and the refusal does not depend on Stream-Safe insertion.
func TestTheMarkRunLimitIsThirty(t *testing.T) {
	for _, mark := range []string{"\u0301", "\u0323", "\u093e", "\u05b0"} {
		ok := "a" + strings.Repeat(mark, 30) + "bcdefghijk"
		if _, err := platform.PrepareNewPassword(ok); err != nil {
			t.Errorf("30 x %+q: %v", mark, err)
		}
		if _, err := platform.PreparePassword("a" + strings.Repeat(mark, 31)); !errors.Is(err, platform.ErrPasswordInvalid) {
			t.Errorf("31 x %+q: %v", mark, err)
		}
	}
}

// The runs are counted in the compatibility decomposition, over marks, the
// Hangul vowel and final jamo and U+16D67: one past the limit is refused,
// the limit itself prepares to exactly the input's NFC, with no U+034F.
func TestTheRunCountsWhatNormCounts(t *testing.T) {
	for _, c := range []struct{ name, at, over string }{
		{"a compatibility jamo (U+3160)", strings.Repeat("\u3160", 30), strings.Repeat("\u3160", 31)},
		{"a Hangul syllable, then acutes", "\uac01" + strings.Repeat("\u0301", 28), "\uac01" + strings.Repeat("\u0301", 29)},
		{"U+00B4, then acutes", "\u00b4" + strings.Repeat("\u0301", 29), "\u00b4" + strings.Repeat("\u0301", 30)},
		{"a vowel jamo, then acutes", "\u1161" + strings.Repeat("\u0301", 29), "\u1161" + strings.Repeat("\u0301", 30)},
		{"a halfwidth voiced mark (U+FF9E)", "a" + strings.Repeat("\uff9e", 30), "a" + strings.Repeat("\uff9e", 31)},
		{"a halfwidth jamo (U+FFA3)", "a" + strings.Repeat("\uffa3", 30), "a" + strings.Repeat("\uffa3", 31)},
		{"U+0344, two marks each", "a" + strings.Repeat("\u0344", 15), "a" + strings.Repeat("\u0344", 16)},
	} {
		p, err := platform.PreparePassword(c.at)
		if err != nil {
			t.Errorf("%s, at the limit: %v", c.name, err)
		} else if string(p) != norm.NFC.String(c.at) || strings.Contains(string(p), "\u034f") {
			t.Errorf("%s, at the limit: not the input's NFC", c.name)
		}
		if _, err := platform.PreparePassword(c.over); !errors.Is(err, platform.ErrPasswordInvalid) {
			t.Errorf("%s, one over: %v", c.name, err)
		}
	}
	// U+16D67 is counted whatever the tables: unassigned before Unicode
	// 16.0, a letter that composes with what precedes it from 16.0.
	if _, err := platform.PreparePassword("a" + strings.Repeat("\U00016d67", 31)); !errors.Is(err, platform.ErrPasswordInvalid) {
		t.Errorf("31 x U+16D67: %v", err)
	}
	// A run that norm splits: thirty-one syllables are runs of two, and
	// conjoining jamo compose as they do in ICU.
	if p, err := platform.PreparePassword(strings.Repeat("\u1100\u1161\u11a8", 11)); err != nil || string(p) != strings.Repeat("\uac01", 11) {
		t.Errorf("conjoining jamo: %q, %v", p, err)
	}
	if _, err := platform.PrepareNewPassword(strings.Repeat("\uac01", 31)); err != nil {
		t.Errorf("31 syllables: %v", err)
	}
}

// The guard after NFC: a U+034F already in the password is the person's own
// and prepares like any other mark.
func TestAGraphemeJoinerTypedIsKept(t *testing.T) {
	in := "pass\u034fword-1234"
	p, err := platform.PrepareNewPassword(in)
	if err != nil || string(p) != in {
		t.Fatalf("%q, %v", p, err)
	}
}
