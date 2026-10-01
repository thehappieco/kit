package platform_test

import (
	"errors"
	"testing"

	"github.com/thehappieco/kit/profiles/platform"
)

func TestAVerifierIsBoundToItsSub(t *testing.T) {
	key := testBytes(32, 0x5a)
	a, err := platform.AuthVerifier(testSub, key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := platform.AuthVerifier(otherTestSub, key)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("the same key gives the same verifier for two accounts")
	}
}

func TestTheAuthAndRecoveryVerifiersAreDomainSeparated(t *testing.T) {
	key := testBytes(32, 0x5a)
	a, err := platform.AuthVerifier(testSub, key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := platform.RecoveryVerifier(testSub, key)
	if err != nil {
		t.Fatal(err)
	}
	if a == r {
		t.Fatal("an auth verifier equals a recovery verifier over the same bytes")
	}
}

func TestTheDummySubIsTheNilUUIDAndComputesAVerifier(t *testing.T) {
	if platform.DummySub() != "00000000-0000-0000-0000-000000000000" {
		t.Fatal("DummySub moved")
	}
	if _, err := platform.AuthVerifier(platform.DummySub(), testBytes(32, 1)); err != nil {
		t.Fatalf("the dummy sub: %v", err)
	}
	if _, err := platform.RecoveryVerifier(platform.DummySub(), testBytes(32, 1)); err != nil {
		t.Fatalf("the dummy sub: %v", err)
	}
}

func TestVerifierMatchesOnlyTheSameThirtyTwoBytes(t *testing.T) {
	v, err := platform.AuthVerifier(testSub, testBytes(32, 0x5a))
	if err != nil {
		t.Fatal(err)
	}
	if !platform.VerifierMatches(v[:], v) {
		t.Fatal("a verifier does not match itself")
	}
	other := v
	other[31] ^= 1
	for name, stored := range map[string][]byte{"one bit off": other[:], "truncated": v[:31], "empty": nil, "extended": append(v[:], 0)} {
		if platform.VerifierMatches(stored, v) {
			t.Errorf("%s matched", name)
		}
	}
}

func TestAVerifierRefusesAMalformedSubOrKey(t *testing.T) {
	for _, sub := range []string{"", "0199E4B2-3C41-7A52-8F3E-9B1D2C4E5F60", "0199e4b2-3c41-7a52-8f3e-9b1d2c4e5f6", "0199e4b2_3c41-7a52-8f3e-9b1d2c4e5f60", "0199e4b2-3c41-7a52-8f3e-9b1d2c4e5f6g"} {
		if _, err := platform.AuthVerifier(sub, testBytes(32, 1)); !errors.Is(err, platform.ErrEncoding) {
			t.Errorf("sub %q: %v", sub, err)
		}
	}
	for _, n := range []int{0, 31, 33} {
		if _, err := platform.RecoveryVerifier(testSub, make([]byte, n)); !errors.Is(err, platform.ErrEncoding) {
			t.Errorf("a %d-byte proof: %v", n, err)
		}
	}
}
