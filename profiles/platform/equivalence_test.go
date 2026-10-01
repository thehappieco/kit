package platform_test

import (
	"bytes"
	"testing"

	"github.com/thehappieco/kit/account"
	"github.com/thehappieco/kit/profiles/platform"
)

// The platform profile is the kit's generic schemes with the platform's
// values. These tests pin the places where this package does the work
// itself (sealing a root wrap, to take its nonce from a reader) to what the
// generic package does with the same inputs.

// Wrap writes the bytes account.Wrap writes with RootWrapProfile and the
// same nonce, and each opens the other's.
func TestARootWrapIsTheAccountEnvelopeWithATwoByteHeader(t *testing.T) {
	root := testBytes(32, 0x52)
	key := testBytes(32, 0x4b)
	for _, b := range []struct {
		kind platform.WrapKind
		b    platform.Binding
	}{
		{platform.WrapPassword, platform.Binding{Sub: testSub, Epoch: 1}},
		{platform.WrapRecovery, platform.Binding{Sub: testSub, Epoch: platform.MaxEpoch}},
		{platform.WrapPasskey, platform.Binding{Sub: testSub, Epoch: 2, RPID: "id.thehappie.co", CredentialID: "Y3JlZGVudGlhbC0x"}},
	} {
		aad, err := platform.WrapAAD(b.kind, b.b)
		if err != nil {
			t.Fatal(err)
		}
		generic, err := account.Wrap(platform.RootWrapProfile(b.kind), key, root, aad)
		if err != nil {
			t.Fatal(err)
		}
		if len(generic) != platform.WrapLen || generic[0] != platform.WrapVersion || generic[1] != byte(b.kind) {
			t.Fatalf("%s: account.Wrap wrote %d bytes with header %x", b.kind, len(generic), generic[:2])
		}
		mine, err := platform.Wrap(bytes.NewReader(generic[2:14]), b.kind, key, root, b.b)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(mine, generic) {
			t.Fatalf("%s: Wrap and account.Wrap differ under one nonce", b.kind)
		}
		got, err := platform.Unwrap(b.kind, key, generic, b.b)
		if err != nil || !bytes.Equal(got, root) {
			t.Fatalf("%s: Unwrap of account.Wrap: %v", b.kind, err)
		}
		back, stale, err := account.Unwrap(platform.RootWrapProfile(b.kind), key, mine, aad)
		if err != nil || stale || !bytes.Equal(back, root) {
			t.Fatalf("%s: account.Unwrap of Wrap: %v", b.kind, err)
		}
	}
}

// DerivePasswordKeys is account.Derive with Account(), whose preparation is
// the presented-password profile; DeriveRecovery is account.RecoveryKey and
// RecoveryProof with the platform's canonical form.
func TestTheDerivationsAreTheAccountSchemeWithThePlatformsValues(t *testing.T) {
	salt := testBytes(platform.SaltLen, 0x33)
	password := "pa\u0303o de queijo\u00a0e cafe\u0301"
	keys, err := platform.DerivePasswordKeys(password, platform.DefaultKDF, salt)
	if err != nil {
		t.Fatal(err)
	}
	d, err := account.Derive(platform.Account(), password, salt, platform.DefaultKDF.Params())
	if err != nil {
		t.Fatal(err)
	}
	if d.AuthKey != keys.AuthKey() || !bytes.Equal(d.Wrap, keys.Wrap[:]) {
		t.Fatal("DerivePasswordKeys is not account.Derive with the platform's profile")
	}

	code, err := platform.NewRecoveryCode(nil)
	if err != nil {
		t.Fatal(err)
	}
	display, err := platform.DisplayRecoveryCode(code)
	if err != nil {
		t.Fatal(err)
	}
	rkeys, err := platform.DeriveRecovery(display)
	if err != nil {
		t.Fatal(err)
	}
	k, err := account.RecoveryKey(platform.Account(), display)
	if err != nil || !bytes.Equal(k, rkeys.Wrap[:]) {
		t.Fatalf("DeriveRecovery's wrap key is not account.RecoveryKey: %v", err)
	}
	proof, err := account.RecoveryProof(platform.Account(), display)
	if err != nil || proof != rkeys.RecoveryAuth() {
		t.Fatalf("DeriveRecovery's proof is not account.RecoveryProof: %v", err)
	}
	// Wappie's standard normalisation is another code: it keeps the dashes.
	if w, err := account.RecoveryKey(account.Profile{RecoveryKeyLabel: "thehappie-id/v1/recovery/wrap"}, display); err != nil || bytes.Equal(w, k) {
		t.Fatal("the platform's canonical form is not its own")
	}
}
