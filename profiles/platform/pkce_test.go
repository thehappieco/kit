package platform_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/thehappieco/kit/profiles/platform"
)

func TestThePKCEChallengeIsTheOneOfRFC7636AppendixB(t *testing.T) {
	got, err := platform.PKCEChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	if err != nil {
		t.Fatal(err)
	}
	if got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatal("not the challenge of RFC 7636 appendix B")
	}
}

func TestPKCEChallengeAcceptsExactlyTheVerifiersOfRFC7636(t *testing.T) {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	for n := platform.MinCodeVerifierLen; n <= platform.MaxCodeVerifierLen; n++ {
		v := strings.Repeat(unreserved, 2)[:n]
		got, err := platform.PKCEChallenge(v)
		if err != nil {
			t.Fatalf("%d characters: %v", n, err)
		}
		sum := sha256.Sum256([]byte(v))
		if got != base64.RawURLEncoding.EncodeToString(sum[:]) || len(got) != platform.CodeChallengeLen {
			t.Fatalf("%d characters: not BASE64URL(SHA-256(verifier))", n)
		}
	}
	for _, n := range []int{0, 1, platform.MinCodeVerifierLen - 1, platform.MaxCodeVerifierLen + 1, 1000} {
		if _, err := platform.PKCEChallenge(strings.Repeat("a", n)); !errors.Is(err, platform.ErrPKCE) {
			t.Errorf("%d characters: %v", n, err)
		}
	}
	// Every byte outside the unreserved set, in a verifier that is
	// otherwise valid.
	for c := range 256 {
		if strings.IndexByte(unreserved, byte(c)) >= 0 {
			continue
		}
		v := strings.Repeat("a", 42) + string([]byte{byte(c)})
		if _, err := platform.PKCEChallenge(v); !errors.Is(err, platform.ErrPKCE) || platform.ErrorCode(err) != "pkce" {
			t.Errorf("byte 0x%02x: %v", c, err)
		}
	}
}
