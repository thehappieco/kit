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

// The premise of the 30-mark rule (SPEC section 11.2): every code point with
// a non-zero canonical combining class (a non-starter, which is what
// golang.org/x/text/unicode/norm counts for the Stream-Safe Text Format) is in
// general category M, so a run of at most 30 marks never reaches the limit at
// which norm inserts U+034F, and U+034F is itself a mark. Walked with the
// running toolchain's tables (Unicode 15.0 below Go 1.27, 17.0 from it), so a
// Unicode version that broke the premise fails here.
func TestEveryNonStarterIsAMark(t *testing.T) {
	var buf [utf8.UTFMax]byte
	nonStarters := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue
		}
		n := utf8.EncodeRune(buf[:], r)
		if norm.NFD.PropertiesString(string(buf[:n])).CCC() == 0 {
			continue
		}
		nonStarters++
		if !unicode.Is(unicode.M, r) {
			t.Errorf("U+%04X has combining class %d and is not a mark", r, norm.NFD.PropertiesString(string(buf[:n])).CCC())
		}
	}
	if nonStarters < 800 {
		t.Fatalf("only %d non-starters: the tables are not what this test expects", nonStarters)
	}
	if !unicode.Is(unicode.M, 0x034f) {
		t.Fatal("U+034F, which norm inserts, is not a mark")
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
