package platform_test

import (
	"bytes"
	"testing"

	"github.com/thehappieco/kit/account"
	"github.com/thehappieco/kit/profiles/platform"
)

// DerivePassword takes the derivation as bytes only: account makes no
// string of K_auth for it, and every byte account handed it is zero once it
// returns. The keys it returns are the caller's (PasswordKeys.Zero).
func TestDerivePasswordLeavesNothingUncleared(t *testing.T) {
	seen := platform.ObserveDerivations(t)
	keys, err := platform.DerivePasswordKeys("correct horse battery staple", platform.DefaultKDF, testBytes(platform.SaltLen, 7))
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Zero()
	if len(*seen) != 1 {
		t.Fatalf("%d derivations", len(*seen))
	}
	d := (*seen)[0]
	if d.AuthKey != "" {
		t.Fatal("account made a string of K_auth")
	}
	for name, b := range map[string][]byte{"Auth": d.Auth, "Wrap": d.Wrap, "AuthText": d.AuthText} {
		if len(b) == 0 || !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("%s is not cleared", name)
		}
	}
	if bytes.Equal(keys.Auth[:], make([]byte, platform.KeyLen)) || bytes.Equal(keys.Wrap[:], make([]byte, platform.KeyLen)) {
		t.Fatal("the caller's keys were cleared too")
	}
}

// DeriveRecovery gives what account's recovery branches give, without the
// text round trip: R_proof is RecoveryProofBytes, and RecoveryAuth its
// base64url.
func TestDeriveRecoveryIsAccountsBranches(t *testing.T) {
	code := "01234-56789-ABCDE-FGHJK-MNPQR-STVWX"
	keys, err := platform.DeriveRecovery(code)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Zero()
	c, err := platform.CanonicalRecoveryCode(code)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := account.RecoveryProofBytes(platform.Account(), c)
	if err != nil {
		t.Fatal(err)
	}
	key, err := account.RecoveryKey(platform.Account(), c)
	if err != nil {
		t.Fatal(err)
	}
	text, err := account.RecoveryProof(platform.Account(), c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keys.Proof[:], proof) || !bytes.Equal(keys.Wrap[:], key) || keys.RecoveryAuth() != text {
		t.Fatal("DeriveRecovery differs from account's branches")
	}
}
