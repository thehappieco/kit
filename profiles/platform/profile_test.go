package platform_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/thehappieco/kit/account"
	"github.com/thehappieco/kit/profiles/platform"
)

// The profile constructors hand out fresh values: a caller that edits one
// cannot change what the next caller gets.
func TestProfilesAreFresh(t *testing.T) {
	a := platform.Account()
	a.WrapHeader[1] = 0xff
	a.AuthLabel = "x"
	a.Bounds.Min.M = 8
	if b := platform.Account(); b.WrapHeader[1] != 0x01 || b.AuthLabel != "thehappie-id/v1/password/auth" || b.Bounds.Min.M != platform.KDFMinM {
		t.Error("Account() shares state")
	}
	r := platform.RootWrapProfile(platform.WrapRecovery)
	r.WrapHeader[0] = 9
	if platform.RootWrapProfile(platform.WrapRecovery).WrapHeader[0] != 0x01 {
		t.Error("RootWrapProfile() shares state")
	}
	k := platform.KDFBounds()
	k.MaxCost = 1
	if platform.KDFBounds().MaxCost != platform.KDFMaxMT {
		t.Error("KDFBounds() shares state")
	}
}

// The values of SPEC section 11.1 and 11.3, as package account reads them.
func TestTheAccountProfileIsSection11(t *testing.T) {
	p := platform.Account()
	if p.AuthLabel != "thehappie-id/v1/password/auth" || p.WrapLabel != "thehappie-id/v1/password/wrap" ||
		p.RecoveryKeyLabel != "thehappie-id/v1/recovery/wrap" || p.RecoveryProofLabel != "thehappie-id/v1/recovery/auth" {
		t.Fatalf("labels %+v", p)
	}
	if !bytes.Equal(p.WrapHeader, []byte{0x01, 0x01}) || p.LegacyV1 || p.Encoding != base64.RawURLEncoding {
		t.Fatal("header, legacy form or encoding")
	}
	for kind, b := range map[platform.WrapKind]byte{platform.WrapPassword: 1, platform.WrapRecovery: 2, platform.WrapPasskey: 3} {
		if h := platform.RootWrapProfile(kind).WrapHeader; !bytes.Equal(h, []byte{0x01, b}) {
			t.Fatalf("%s: header %x", kind, h)
		}
	}
	want := account.Bounds{
		Min:     account.KDFParams{Alg: "argon2id", M: 65536, T: 3, P: 1},
		Max:     account.KDFParams{Alg: "argon2id", M: 262144, T: 10, P: 4},
		MaxCost: 1048576, MinSaltLen: 16, MaxSaltLen: 16,
	}
	if *p.Bounds != want {
		t.Fatalf("bounds %+v", *p.Bounds)
	}
	if platform.DefaultKDF.Params() != account.DefaultKDFParams {
		t.Fatal("DefaultKDF is not account.DefaultKDFParams")
	}
	// The preparation is the presented-password profile; the canonical
	// recovery code is the platform's.
	if _, err := p.Prepare("short"); err != nil {
		t.Fatalf("a short presented password: %v", err)
	}
	if _, err := p.Prepare("bad\x00password"); !errors.Is(err, platform.ErrPasswordInvalid) {
		t.Fatalf("a control character: %v", err)
	}
	if c, err := p.NormaliseRecovery("oiolo-11111-22222-33333-44444-55555"); err != nil || c != "010101111122222333334444455555" {
		t.Fatalf("canonical form %q: %v", c, err)
	}
	// The bounds agree with KDF.Check at their corners.
	for _, k := range []platform.KDF{
		platform.DefaultKDF,
		{Alg: "argon2id", M: 262144, T: 4, P: 4},
		{Alg: "argon2id", M: 65536, T: 2, P: 1},
		{Alg: "argon2id", M: 131072, T: 9, P: 1},
		{Alg: "argon2id", M: 65536, T: 3, P: 5},
	} {
		if (k.Check() == nil) != (p.Check(k.Params()) == nil) {
			t.Errorf("%+v: KDF.Check and the account bounds disagree", k)
		}
	}
}

// Every refusal of the KDF bounds, the salt and the bundle comes before
// anything is derived: the derivation counter stays at zero.
func TestTheKDFRefusesBeforeDeriving(t *testing.T) {
	calls := platform.CountDerivations(t)
	salt := make([]byte, platform.SaltLen)
	refused := []platform.KDF{
		{Alg: "argon2id", M: 65535, T: 3, P: 1},
		{Alg: "argon2id", M: 262145, T: 3, P: 1},
		{Alg: "argon2id", M: 65536, T: 2, P: 1},
		{Alg: "argon2id", M: 65536, T: 11, P: 1},
		{Alg: "argon2id", M: 65536, T: 3, P: 0},
		{Alg: "argon2id", M: 65536, T: 3, P: 5},
		{Alg: "argon2id", M: 131072, T: 9, P: 1},
		{Alg: "argon2id", M: 104858, T: 10, P: 1},
		{Alg: "argon2i", M: 65536, T: 3, P: 1},
		{Alg: "ARGON2ID", M: 65536, T: 3, P: 1},
		{},
		// Absurd values: deriving with them would exhaust memory or never
		// finish, and p would wrap if it were narrowed to 8 bits unchecked.
		{Alg: "argon2id", M: 1<<32 - 1, T: 1<<32 - 1, P: 1<<32 - 1},
		{Alg: "argon2id", M: 65536, T: 3, P: 257},
	}
	for _, k := range refused {
		if err := k.Check(); !errors.Is(err, platform.ErrKDFPolicy) {
			t.Errorf("Check(%+v) = %v, want ErrKDFPolicy", k, err)
		}
		if _, err := platform.DerivePassword([]byte("password"), salt, k); !errors.Is(err, platform.ErrKDFPolicy) {
			t.Errorf("DerivePassword(%+v) = %v, want ErrKDFPolicy", k, err)
		}
		if _, err := platform.DerivePasswordKeys("password", k, salt); !errors.Is(err, platform.ErrKDFPolicy) {
			t.Errorf("DerivePasswordKeys(%+v) = %v, want ErrKDFPolicy", k, err)
		}
	}
	for _, n := range []int{0, 1, 15, 17, 32} {
		if _, err := platform.DerivePassword([]byte("password"), make([]byte, n), platform.DefaultKDF); !errors.Is(err, platform.ErrKDFPolicy) {
			t.Errorf("a %d-byte salt: %v, want ErrKDFPolicy", n, err)
		}
	}
	// The bounds come before the password profile: a refused challenge does
	// not depend on what was typed.
	if _, err := platform.DerivePasswordKeys("bad\x00password", platform.KDF{}, salt); !errors.Is(err, platform.ErrKDFPolicy) {
		t.Errorf("a refused challenge with a refused password: %v, want ErrKDFPolicy", err)
	}
	// And a bundle's own parameters are refused before its password is
	// prepared or anything derived.
	a := newTestAccount(t)
	*calls = 0
	b := a.bundle()
	b.KDF.M = 32768
	data := marshalUnchecked(t, b)
	if _, _, err := platform.OpenKeyBundle(data, testPassword); !errors.Is(err, platform.ErrKDFPolicy) {
		t.Errorf("a bundle below the floor: %v", err)
	}
	if _, _, err := platform.OpenKeyBundle(data, "bad\x00password"); !errors.Is(err, platform.ErrKDFPolicy) {
		t.Errorf("a bundle below the floor and a refused password: %v", err)
	}
	good, err := platform.MarshalKeyBundle(a.bundle())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := platform.OpenKeyBundle(good, "bad\x00password"); !errors.Is(err, platform.ErrPasswordInvalid) {
		t.Errorf("a refused password: %v", err)
	}
	if *calls != 0 {
		t.Fatalf("Argon2id ran %d times for refused parameters", *calls)
	}
	if _, _, err := platform.OpenKeyBundle(good, testPassword); err != nil || *calls != 1 {
		t.Fatalf("the good bundle: %v after %d derivations", err, *calls)
	}
}
