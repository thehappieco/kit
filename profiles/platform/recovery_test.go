package platform_test

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/thehappieco/kit/profiles/platform"
)

func TestTheRecoveryCodeIsUniformOverTheAlphabet(t *testing.T) {
	// The structure argument: every byte value maps to one character and
	// every character is hit by exactly 256/32 = 8 byte values, so uniform
	// bytes give uniform characters, with no modulo bias to correct.
	if len(platform.RecoveryAlphabet) != 32 {
		t.Fatalf("an alphabet of %d characters", len(platform.RecoveryAlphabet))
	}
	preimages := map[byte]int{}
	for b := 0; b < 256; b += platform.RecoveryCodeLen {
		in := make([]byte, platform.RecoveryCodeLen)
		for i := range in {
			in[i] = byte(b + i) // wraps past 255 on the last block; counted below
		}
		code, err := platform.RecoveryCodeFromBytes(in)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < platform.RecoveryCodeLen && b+i < 256; i++ {
			preimages[code[i]]++
		}
	}
	if len(preimages) != 32 {
		t.Fatalf("%d characters are reachable", len(preimages))
	}
	for c, n := range preimages {
		if n != 8 {
			t.Fatalf("%q has %d preimages, not 8", c, n)
		}
	}

	// The sanity count: 4000 codes from crypto/rand, 120000 characters. Each
	// count is binomial with mean 3750 and a standard deviation of about 60;
	// six of them bound the test's own failure rate far below one in a
	// million runs.
	const codes = 4000
	counts := map[byte]int{}
	for range codes {
		code, err := platform.NewRecoveryCode(nil)
		if err != nil {
			t.Fatal(err)
		}
		for i := range len(code) {
			counts[code[i]]++
		}
	}
	n := float64(codes * platform.RecoveryCodeLen)
	mean, sd := n/32, math.Sqrt(n*(1.0/32)*(31.0/32))
	for _, c := range []byte(platform.RecoveryAlphabet) {
		if d := math.Abs(float64(counts[c]) - mean); d > 6*sd {
			t.Errorf("%q appeared %d times; expected %.0f +/- %.0f", c, counts[c], mean, 6*sd)
		}
	}
}

func TestTheRecoveryCodeAlphabetIsCrockfordBase32(t *testing.T) {
	for _, c := range "ILOU" {
		if strings.ContainsRune(platform.RecoveryAlphabet, c) {
			t.Fatalf("the alphabet holds %q", c)
		}
	}
	for i := 1; i < len(platform.RecoveryAlphabet); i++ {
		if platform.RecoveryAlphabet[i-1] >= platform.RecoveryAlphabet[i] {
			t.Fatal("the alphabet is not in ascending order")
		}
	}
}

func TestANewRecoveryCodeDisplaysAndCanonicalizesBackToItself(t *testing.T) {
	code, err := platform.NewRecoveryCode(nil)
	if err != nil {
		t.Fatal(err)
	}
	display, err := platform.DisplayRecoveryCode(code)
	if err != nil {
		t.Fatal(err)
	}
	if len(display) != 35 || strings.Count(display, "-") != 5 {
		t.Fatal("the display form is not six groups of five")
	}
	for _, typed := range []string{display, strings.ToLower(display), strings.ReplaceAll(display, "-", " "), " " + code + "\n"} {
		got, err := platform.CanonicalRecoveryCode(typed)
		if err != nil || got != code {
			t.Fatalf("a typed variant did not canonicalize back: %v", err)
		}
	}
}

func TestTheRecoveryWrapKeyAndProofAreIndependent(t *testing.T) {
	keys, err := platform.DeriveRecovery(strings.Repeat("7", 30))
	if err != nil {
		t.Fatal(err)
	}
	if keys.Wrap == keys.Proof {
		t.Fatal("K_rwrap equals R_proof")
	}
	other, err := platform.DeriveRecovery(strings.Repeat("7", 29) + "8")
	if err != nil {
		t.Fatal(err)
	}
	if other.Wrap == keys.Wrap || other.Proof == keys.Proof {
		t.Fatal("two codes gave a shared key")
	}
	keys.Zero()
	if keys.Wrap != ([32]byte{}) || keys.Proof != ([32]byte{}) {
		t.Fatal("Zero left key bytes behind")
	}
}

func TestARecoveryCodeNeverMatchesThroughUnicodeCaseMapping(t *testing.T) {
	base := strings.Repeat("A", 29)
	// Each of these upper- or lower-cases to an ASCII letter of the alphabet
	// under Unicode rules; the canonical form only knows ASCII.
	for _, r := range []string{"\u0131", "\u017f", "\u212a", "\u0130", "\uff21"} {
		if _, err := platform.CanonicalRecoveryCode(base + r); !errors.Is(err, platform.ErrRecoveryCode) {
			t.Errorf("U+%04X: %v", []rune(r)[0], err)
		}
	}
}

func TestNewRecoveryCodeReadsExactlyThirtyBytes(t *testing.T) {
	src := bytes.NewReader(append(make([]byte, 30), 0xff))
	code, err := platform.NewRecoveryCode(src)
	if err != nil || code != strings.Repeat("0", 30) || src.Len() != 1 {
		t.Fatalf("read the wrong bytes: %v", err)
	}
	if _, err := platform.NewRecoveryCode(bytes.NewReader(make([]byte, 29))); err == nil {
		t.Fatal("a short random source did not fail")
	}
}
