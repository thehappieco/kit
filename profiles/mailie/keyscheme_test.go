package mailie_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/thehappieco/kit/account"
	"github.com/thehappieco/kit/hpke"
	"github.com/thehappieco/kit/platformwrap"
	"github.com/thehappieco/kit/profiles/mailie"
	"github.com/thehappieco/kit/profiles/platform"
	"github.com/thehappieco/kit/profiles/wappie"
	"github.com/thehappieco/kit/seal"
)

// Mailie's kinds pass ValidateKinds (SPEC section 3.3) and name the core
// kinds as every profile does; a byte without a name is spelled as section
// 4.3 requires. Only 0x00 and the named bytes are pinned by a vector: a
// reserved byte may be named by a later version.
func TestTheKindsAreAProfileTheKitAccepts(t *testing.T) {
	if err := seal.ValidateKinds[mailie.Kind](); err != nil {
		t.Fatal(err)
	}
	if mailie.KindMailboxGrant != seal.KindGrant || mailie.KindContentKey != seal.KindContentKey || mailie.KindUserWrap != seal.KindUserWrap {
		t.Fatal("a core kind has moved")
	}
	for k, want := range map[mailie.Kind]string{0x00: "kind(0x0)", 0x0b: "kind(0xb)", 0xff: "kind(0xff)", 0x07: "mailbox_grant", 0x0a: "draft"} {
		if got := k.String(); got != want {
			t.Errorf("%d is %q, want %q", byte(k), got, want)
		}
	}
	if d := mailie.KindMailboxGrant.Domain(); d != mailie.SealDomain() || d.Label != "mlv1" || d.Magic != [2]byte{'M', 'L'} {
		t.Fatalf("the domain is %+v", d)
	}
}

// Every label of Mailie's profile is distinct from every label of the
// kit's other profiles (Appendices A and C) and from each other (SPEC
// section 3.3), and the first bytes of Mailie's three envelopes of a
// person's keys differ, so a blob in the wrong column fails at its first
// byte. The platform profile's labels are spelled out as Appendix C lists
// them, since package platform does not export them all.
func TestNoLabelOrHeaderIsAnotherProfiles(t *testing.T) {
	ours := []string{
		mailie.PasswordAuthLabel, mailie.PasswordWrapLabel, mailie.RecoveryWrapLabel, mailie.RecoveryAuthLabel,
		mailie.AccountWrapTag, mailie.SealLabel, mailie.BrowserVaultTag, mailie.PlatformWrapLabel, mailie.PlatformWrapSalt,
		"mailie/v1/kdf-salt", // Mailie's server's salt label, not the kit's
	}
	w := wappie.Account()
	pk := wappie.Passkey()
	theirs := []string{
		w.AuthLabel, w.WrapLabel, w.RecoveryKeyLabel, w.RecoveryProofLabel, "whatserver2/usk",
		wappie.SealDomain().Label, pk.EvalPrefix, pk.WrapInfo, "wappie/passkey-vault", "wappie/browser-account-key",
		wappie.MCPHMAC().Label, wappie.PlatformWrapLabel, wappie.PlatformWrapSalt,
		platform.Account().AuthLabel, platform.Account().WrapLabel, platform.Account().RecoveryKeyLabel, platform.Account().RecoveryProofLabel,
		platform.PasswordProfile, "thehappie-id/v1/product-key", "thehappie-id/root-wrap", "thehappie-id/v1/auth-verifier",
		"thehappie-id/v1/recovery-verifier", "thehappie-id/key-bundle", "thehappie-id/v1/key-delivery", "thehappie-id/key-delivery",
		"thehappie-rp/flow", "thehappie-id/v1/passkey-prf|", "thehappie-id/v1/passkey/wrap",
	}
	seen := map[string]bool{}
	for _, l := range ours {
		if seen[l] {
			t.Errorf("%q is used twice", l)
		}
		seen[l] = true
		for _, o := range theirs {
			if l == o {
				t.Errorf("%q is another profile's label", l)
			}
		}
	}
	if mailie.SealMagic == wappie.SealDomain().Magic {
		t.Error("the seal magic is Wappie's")
	}
	first := map[byte]string{mailie.AccountWrapHeader: "account wrap", platformwrap.Header: "platform wrap", mailie.SealMagic[0]: "grant"}
	if len(first) != 3 {
		t.Errorf("two envelopes of the scheme start with the same byte: %v", first)
	}
}

// The profile derives only within the platform's bounds, has no legacy
// form, prepares a password as the platform does, and reads a recovery
// code in the platform's canonical form.
func TestTheProfileDerivesOnlyWithinThePlatformsBounds(t *testing.T) {
	p := mailie.Account()
	if err := p.Check(mailie.DefaultKDF); err != nil {
		t.Fatal(err)
	}
	cheap := mailie.DefaultKDF
	cheap.M = 8 * 1024
	if _, err := account.DeriveBytes(p, "correct horse battery staple", make([]byte, 16), cheap); !errors.Is(err, account.ErrOutOfBounds) {
		t.Fatalf("a server's cheap parameters: %v", err)
	}
	if _, err := account.DeriveBytes(p, "correct horse battery staple", make([]byte, 8), mailie.DefaultKDF); !errors.Is(err, account.ErrOutOfBounds) {
		t.Fatalf("a short salt: %v", err)
	}
	if p.LegacyV1 || !bytes.Equal(p.WrapHeader, []byte{0x02}) || p.Encoding != base64.RawURLEncoding {
		t.Fatalf("the profile is %+v", p)
	}
	if code, err := p.NormaliseRecovery("o1234 56789 abcde fghjk mnpqr stvwx"); err != nil || code != "0123456789ABCDEFGHJKMNPQRSTVWX" {
		t.Fatalf("the canonical form: %q, %v", code, err)
	}
	if b := mailie.Account().Bounds; b == nil || *b != *platform.KDFBounds() {
		t.Fatal("the bounds are not the platform's")
	}
}

func TestSealIDsAndNamespacesHaveOneSpelling(t *testing.T) {
	id := uuid.NewString()
	if !mailie.ValidSealID(id) || !mailie.ValidNamespace(id) {
		t.Fatalf("a fresh UUIDv4 %q is refused", id)
	}
	for _, bad := range []string{
		strings.ToUpper(id), "{" + id + "}", "urn:uuid:" + id, strings.ReplaceAll(id, "-", ""), id + " ",
		"00000000-0000-0000-0000-000000000000", "019a8b2c-3d4e-7f60-8a71-b2c3d4e5f607",
		id[:14] + "4" + id[15:19] + "c" + id[20:], "",
	} {
		if mailie.ValidSealID(bad) || mailie.ValidNamespace(bad) {
			t.Errorf("%q is accepted", bad)
		}
	}
}

func TestAnAccountWrapOpensOnlyForItsPersonKindAndKey(t *testing.T) {
	key, other := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	wrapKey := bytes.Repeat([]byte{3}, 32)
	person, someone := uuid.NewString(), uuid.NewString()
	wrap, err := mailie.SealAccountWrap(mailie.WrapPassword, wrapKey, key, person)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrap) != mailie.AccountWrapLen || mailie.CheckAccountWrapShape(wrap) != nil {
		t.Fatalf("a wrap of %d bytes", len(wrap))
	}
	again, err := mailie.SealAccountWrap(mailie.WrapPassword, wrapKey, key, person)
	if err != nil || bytes.Equal(again[1:13], wrap[1:13]) {
		t.Fatalf("a second wrap reuses the nonce: %v", err)
	}
	pub, otherPub := public(t, key), public(t, other)
	if got, err := mailie.OpenAccountWrap(mailie.WrapPassword, wrapKey, wrap, person, pub); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("the wrap does not open: %v", err)
	}
	if !bytes.Equal(key, bytes.Repeat([]byte{1}, 32)) || !bytes.Equal(wrapKey, bytes.Repeat([]byte{3}, 32)) {
		t.Fatal("the caller's keys changed")
	}
	for name, open := range map[string]func() ([]byte, error){
		"another person": func() ([]byte, error) {
			return mailie.OpenAccountWrap(mailie.WrapPassword, wrapKey, wrap, someone, pub)
		},
		"the other kind": func() ([]byte, error) {
			return mailie.OpenAccountWrap(mailie.WrapRecovery, wrapKey, wrap, person, pub)
		},
		"another key": func() ([]byte, error) {
			return mailie.OpenAccountWrap(mailie.WrapPassword, wrapKey, wrap, person, otherPub)
		},
		"another wrapper": func() ([]byte, error) {
			return mailie.OpenAccountWrap(mailie.WrapPassword, key, wrap, person, pub)
		},
	} {
		if got, err := open(); !errors.Is(err, account.ErrWrongKey) || got != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := mailie.SealAccountWrap("passkey", wrapKey, key, person); !errors.Is(err, mailie.ErrBinding) {
		t.Errorf("a passkey wrap: %v", err)
	}
}

func TestAGrantOpensOnlyToTheMailboxsKeyForItsPersonMailboxAndEpoch(t *testing.T) {
	alice, bob := bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32)
	mailboxKey := bytes.Repeat([]byte{6}, 32)
	ns, otherNS := uuid.NewString(), uuid.NewString()
	aliceSeal, bobSeal := uuid.NewString(), uuid.NewString()
	g, err := mailie.SealGrant(public(t, alice), ns, aliceSeal, 3, mailboxKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(g) != mailie.GrantLen || mailie.CheckGrantShape(g, 3) != nil {
		t.Fatalf("a grant of %d bytes", len(g))
	}
	if !errors.Is(mailie.CheckGrantShape(g, 4), mailie.ErrShape) {
		t.Error("a server takes a grant at another epoch")
	}
	priv := func(k []byte) hpke.PrivateKey {
		p, err := hpke.ParsePrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	mailboxPub := public(t, mailboxKey)
	if got, err := mailie.OpenGrant(priv(alice), ns, aliceSeal, 3, mailboxPub, g); err != nil || !bytes.Equal(got, mailboxKey) {
		t.Fatalf("the grant does not open: %v", err)
	}
	for name, open := range map[string]func() ([]byte, error){
		"bob's key":         func() ([]byte, error) { return mailie.OpenGrant(priv(bob), ns, aliceSeal, 3, mailboxPub, g) },
		"bob's seal id":     func() ([]byte, error) { return mailie.OpenGrant(priv(alice), ns, bobSeal, 3, mailboxPub, g) },
		"another mailbox":   func() ([]byte, error) { return mailie.OpenGrant(priv(alice), otherNS, aliceSeal, 3, mailboxPub, g) },
		"another epoch":     func() ([]byte, error) { return mailie.OpenGrant(priv(alice), ns, aliceSeal, 4, mailboxPub, g) },
		"another mailbox's": func() ([]byte, error) { return mailie.OpenGrant(priv(alice), ns, aliceSeal, 3, public(t, bob), g) },
	} {
		if got, err := open(); !errors.Is(err, seal.ErrAuthentication) || got != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Anyone who knows Alice's public key can seal her a grant; it opens
	// only if it carries the key whose public half the server holds.
	forged, err := mailie.SealGrant(public(t, alice), ns, aliceSeal, 3, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mailie.OpenGrant(priv(alice), ns, aliceSeal, 3, mailboxPub, forged); !errors.Is(err, seal.ErrAuthentication) {
		t.Errorf("a grant of a key the sealer chose: %v", err)
	}
}

func TestAGrantIsNeverSealedToALowOrderKey(t *testing.T) {
	for _, lo := range lowOrder {
		_, err := mailie.SealGrant(unhex(lo.hex), uuid.NewString(), uuid.NewString(), 1, bytes.Repeat([]byte{6}, 32))
		if !errors.Is(err, seal.ErrInvalidKey) {
			t.Errorf("%s: %v", lo.name, err)
		}
		if !errors.Is(mailie.CheckPublicKey(unhex(lo.hex)), mailie.ErrPublicKey) {
			t.Errorf("%s: a server would store it", lo.name)
		}
	}
	if err := mailie.CheckPublicKey(public(t, bytes.Repeat([]byte{4}, 32))); err != nil {
		t.Errorf("a real key: %v", err)
	}
	high := public(t, bytes.Repeat([]byte{4}, 32))
	high[31] |= 0x80
	if !errors.Is(mailie.CheckPublicKey(high), mailie.ErrPublicKey) {
		t.Error("a server would store a second spelling of a key")
	}
}

// SPEC Appendix D: Mailie's platform wrap binds the seal id as its user id
// for every person, never the sub, and refuses a seal id that is the sub
// even when the sub is a version 4 UUID, which the platform accepts as a
// sub. A wrap bound to the seal id does not open with the sub as its user
// id.
func TestThePlatformWrapsUserIDIsTheSealIDNeverTheSub(t *testing.T) {
	accountKey := bytes.Repeat([]byte{4}, 32)
	pub := public(t, accountKey)
	sealID, subV4, subV7 := uuid.NewString(), uuid.NewString(), "019a8b2c-3d4e-7f60-8a71-b2c3d4e5f607"
	b, err := mailie.PlatformWrapBinding(sealID, subV4, 1, pub)
	if err != nil || b.UserID != sealID || b.Sub != subV4 || b.ProductKeyID != "mailie:1" {
		t.Fatalf("%+v, %v", b, err)
	}
	for _, s := range []string{subV4, subV7} {
		if _, err := mailie.PlatformWrapBinding(s, s, 1, pub); !errors.Is(err, mailie.ErrBinding) {
			t.Errorf("the sub %s as the seal id: %v", s, err)
		}
	}
	for _, e := range []int{0, platform.MaxEpoch + 1} {
		if _, err := mailie.PlatformWrapBinding(sealID, subV7, e, pub); !errors.Is(err, mailie.ErrBinding) {
			t.Errorf("epoch %d: %v", e, err)
		}
	}
	sk, _, err := platform.ProductKey(bytes.Repeat([]byte{7}, 32), mailie.PlatformWrapProduct, 1)
	if err != nil {
		t.Fatal(err)
	}
	b, err = mailie.PlatformWrapBinding(sealID, subV7, 1, pub)
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := platformwrap.Seal(mailie.PlatformWrap(), nil, sk, accountKey, b)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := platformwrap.Open(mailie.PlatformWrap(), sk, wrap, b); err != nil || !bytes.Equal(got, accountKey) {
		t.Fatalf("the wrap does not open: %v", err)
	}
	asSub := b
	asSub.UserID = subV7
	if _, err := platformwrap.Open(mailie.PlatformWrap(), sk, wrap, asSub); !errors.Is(err, platformwrap.ErrPlatformWrap) {
		t.Fatalf("opened with the sub as the user id: %v", err)
	}
}

func TestTheBrowserVaultBindsTheSealIDNotTheAddress(t *testing.T) {
	pub := public(t, bytes.Repeat([]byte{4}, 32))
	id := uuid.NewString()
	aad, err := mailie.BrowserVaultAAD(id, pub)
	if err != nil {
		t.Fatal(err)
	}
	want := `["mailie/browser-account-key",1,"` + id + `","` + base64.StdEncoding.EncodeToString(pub) + `"]`
	if string(aad) != want {
		t.Fatalf("%s, want %s", aad, want)
	}
	if _, err := mailie.BrowserVaultAAD("ana@example.com", pub); !errors.Is(err, mailie.ErrBinding) {
		t.Fatalf("an address as the seal id: %v", err)
	}
}
