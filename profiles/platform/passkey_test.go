package platform_test

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/thehappieco/kit/profiles/platform"
)

// The platform's unit tests of passkeys with PRF (its
// internal/crypto/idcrypto/passkey_test.go at b5d9f69), unchanged but for the
// package and the local type credential.

const (
	prodRP = "id.thehappie.co"
	devRP  = "id.thehappie.localhost"
)

// credential is one passkey as the page sees it after a get: its PRF
// output and its id. (The platform's test calls it passkey, which is a
// package this test package imports.)
type credential struct {
	prf          []byte
	credentialID string
}

var (
	passkeyA = credential{testBytes(32, 0xa1), platform.EncodeB64([]byte("credential-a"))}
	passkeyB = credential{testBytes(32, 0xb2), platform.EncodeB64([]byte("credential-b"))}
)

func (p credential) binding(rpID string) platform.Binding {
	return platform.Binding{Sub: testSub, Epoch: 1, RPID: rpID, CredentialID: p.credentialID}
}

func newPasskeyWrap(t *testing.T, p credential, rpID string, root []byte) []byte {
	t.Helper()
	w, err := platform.NewPasskeyWrap(nil, p.prf, root, p.binding(rpID))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestThePRFSaltIsPublicAndPerRP(t *testing.T) {
	// Public: it is SHA-256 of a label and the RP ID, nothing secret and
	// nothing about an account goes in, so the server can hand it to any
	// browser before anyone signs in.
	for _, rp := range []string{prodRP, devRP} {
		got, err := platform.PRFSalt(rp)
		if err != nil {
			t.Fatalf("%s: %v", rp, err)
		}
		want := sha256.Sum256([]byte("thehappie-id/v1/passkey-prf|" + rp))
		if !bytes.Equal(got, want[:]) || len(got) != platform.PRFSaltLen {
			t.Fatalf("%s: not SHA-256(\"thehappie-id/v1/passkey-prf|\" + rp_id)", rp)
		}
		again, err := platform.PRFSalt(rp)
		if err != nil || !bytes.Equal(again, got) {
			t.Fatalf("%s: a second call gives another salt", rp)
		}
	}
	// Per RP: production and development never share a salt, so a PRF
	// output asked for on one is not the one the other gets.
	prod, _ := platform.PRFSalt(prodRP)
	dev, _ := platform.PRFSalt(devRP)
	if bytes.Equal(prod, dev) {
		t.Fatal("two relying parties share a PRF salt")
	}
	// A caller that changes the returned slice changes nothing for the next.
	prod[0] ^= 0xff
	if again, _ := platform.PRFSalt(prodRP); bytes.Equal(again, prod) {
		t.Fatal("PRFSalt returned shared memory")
	}
}

func TestThePasskeyWrapKeyIsTheHKDFOfTheSpec(t *testing.T) {
	got, err := platform.PasskeyWrapKey(passkeyA.prf, prodRP)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hkdf.Key(sha256.New, passkeyA.prf, []byte(prodRP), "thehappie-id/v1/passkey/wrap", 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("K_pk is not HKDF-SHA256(IKM = prf, salt = rp_id, info = \"thehappie-id/v1/passkey/wrap\")")
	}
	if other, _ := platform.PasskeyWrapKey(passkeyA.prf, devRP); bytes.Equal(other, got) {
		t.Fatal("one PRF output gives the same K_pk on two relying parties")
	}
	if other, _ := platform.PasskeyWrapKey(passkeyB.prf, prodRP); bytes.Equal(other, got) {
		t.Fatal("two PRF outputs give the same K_pk")
	}
	if bytes.Equal(got, passkeyA.prf) {
		t.Fatal("K_pk is the PRF output itself")
	}
}

func TestAPasskeyWrapForOneCredentialDoesNotOpenForAnother(t *testing.T) {
	root := testBytes(32, 0x52)
	wrapA := newPasskeyWrap(t, passkeyA, prodRP, root)
	wrapB := newPasskeyWrap(t, passkeyB, prodRP, root)
	for name, c := range map[string]struct {
		p    credential
		wrap []byte
	}{"A": {passkeyA, wrapA}, "B": {passkeyB, wrapB}} {
		got, err := platform.OpenPasskeyWrap(c.p.prf, c.wrap, c.p.binding(prodRP))
		if err != nil || !bytes.Equal(got, root) {
			t.Fatalf("passkey %s: its own wrap does not open: %v", name, err)
		}
	}
	for name, c := range map[string]struct {
		prf  []byte
		b    platform.Binding
		wrap []byte
	}{
		"B's PRF output on A's wrap":                {passkeyB.prf, passkeyA.binding(prodRP), wrapA},
		"A's PRF output named as B":                 {passkeyA.prf, passkeyB.binding(prodRP), wrapA},
		"B's PRF output and id on A's wrap":         {passkeyB.prf, passkeyB.binding(prodRP), wrapA},
		"A's PRF output and id on B's wrap":         {passkeyA.prf, passkeyA.binding(prodRP), wrapB},
		"A's wrap opened for another account":       {passkeyA.prf, platform.Binding{Sub: otherTestSub, Epoch: 1, RPID: prodRP, CredentialID: passkeyA.credentialID}, wrapA},
		"A's wrap opened at another epoch":          {passkeyA.prf, platform.Binding{Sub: testSub, Epoch: 2, RPID: prodRP, CredentialID: passkeyA.credentialID}, wrapA},
		"A's wrap opened as a password wrap's kind": {passkeyA.prf, passkeyA.binding(prodRP), append([]byte{wrapA[0], byte(platform.WrapPassword)}, wrapA[2:]...)},
	} {
		got, err := platform.OpenPasskeyWrap(c.prf, c.wrap, c.b)
		if !errors.Is(err, platform.ErrWrap) || got != nil {
			t.Errorf("%s: opened (%v)", name, err)
		}
	}
}

func TestAPasskeyWrapForOneRPDoesNotOpenForAnother(t *testing.T) {
	root := testBytes(32, 0x52)
	// The same credential and PRF output on two relying parties: in a
	// browser the PRF outputs would differ too, because the salt does; here
	// they are equal, so what is tested is the RP in K_pk and in the AAD.
	prod := newPasskeyWrap(t, passkeyA, prodRP, root)
	dev := newPasskeyWrap(t, passkeyA, devRP, root)
	if _, err := platform.OpenPasskeyWrap(passkeyA.prf, prod, passkeyA.binding(devRP)); !errors.Is(err, platform.ErrWrap) {
		t.Fatalf("a production wrap opened on development: %v", err)
	}
	if _, err := platform.OpenPasskeyWrap(passkeyA.prf, dev, passkeyA.binding(prodRP)); !errors.Is(err, platform.ErrWrap) {
		t.Fatalf("a development wrap opened on production: %v", err)
	}
	// Each half of the binding counts on its own: the right key with the
	// other RP in the AAD, and the other RP's key with the right AAD.
	prodKey, err := platform.PasskeyWrapKey(passkeyA.prf, prodRP)
	if err != nil {
		t.Fatal(err)
	}
	devKey, err := platform.PasskeyWrapKey(passkeyA.prf, devRP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := platform.Unwrap(platform.WrapPasskey, prodKey, prod, passkeyA.binding(devRP)); !errors.Is(err, platform.ErrWrap) {
		t.Fatalf("the production key opened with the development AAD: %v", err)
	}
	if _, err := platform.Unwrap(platform.WrapPasskey, devKey, prod, passkeyA.binding(prodRP)); !errors.Is(err, platform.ErrWrap) {
		t.Fatalf("the development key opened the production wrap: %v", err)
	}
}

func TestAPasskeyWrapIsTheKindTheServerExpectsAndSelfTested(t *testing.T) {
	root := testBytes(32, 0x52)
	w := newPasskeyWrap(t, passkeyA, prodRP, root)
	if err := platform.CheckWrapShape(platform.WrapPasskey, w); err != nil {
		t.Fatalf("the server refuses a passkey wrap: %v", err)
	}
	for _, kind := range []platform.WrapKind{platform.WrapPassword, platform.WrapRecovery} {
		if err := platform.CheckWrapShape(kind, w); !errors.Is(err, platform.ErrWrap) {
			t.Fatalf("a passkey wrap passes as a %s wrap: %v", kind, err)
		}
	}
	// NewPasskeyWrap is Wrap under K_pk: with the same nonce, the same bytes.
	nonce := testBytes(12, 0x4e)
	w1, err := platform.NewPasskeyWrap(bytes.NewReader(nonce), passkeyA.prf, root, passkeyA.binding(prodRP))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := platform.PasskeyWrapKey(passkeyA.prf, prodRP)
	w2, err := platform.Wrap(bytes.NewReader(nonce), platform.WrapPasskey, key, root, passkeyA.binding(prodRP))
	if err != nil || !bytes.Equal(w1, w2) {
		t.Fatalf("NewPasskeyWrap is not Wrap under K_pk: %v", err)
	}
	// A second wrap of the same root takes a fresh nonce.
	if bytes.Equal(newPasskeyWrap(t, passkeyA, prodRP, root), newPasskeyWrap(t, passkeyA, prodRP, root)) {
		t.Fatal("two passkey wraps of the same root are identical")
	}
}

func TestPasskeyWrapKeyRefusesAPRFOutputThatIsNot32Bytes(t *testing.T) {
	two := append(bytes.Clone(passkeyA.prf), passkeyB.prf...)
	for _, prf := range [][]byte{nil, {}, testBytes(1, 1), testBytes(16, 1), testBytes(31, 1), testBytes(33, 1), two} {
		key, err := platform.PasskeyWrapKey(prf, prodRP)
		if !errors.Is(err, platform.ErrWrap) || key != nil {
			t.Errorf("a %d-byte PRF output: %v", len(prf), err)
		}
		if _, err := platform.NewPasskeyWrap(nil, prf, testBytes(32, 2), passkeyA.binding(prodRP)); !errors.Is(err, platform.ErrWrap) {
			t.Errorf("NewPasskeyWrap with a %d-byte PRF output: %v", len(prf), err)
		}
		if _, err := platform.OpenPasskeyWrap(prf, make([]byte, platform.WrapLen), passkeyA.binding(prodRP)); !errors.Is(err, platform.ErrWrap) {
			t.Errorf("OpenPasskeyWrap with a %d-byte PRF output: %v", len(prf), err)
		}
	}
	// Any 32 bytes are a PRF output, all zeros included.
	if _, err := platform.PasskeyWrapKey(make([]byte, 32), prodRP); err != nil {
		t.Fatalf("an all-zero PRF output: %v", err)
	}
}

func TestTheRelyingPartyIDHasOneSpelling(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	longest := label63 + "." + label63 + "." + label63 + "." + strings.Repeat("d", 61) // 253 bytes
	good := []string{
		prodRP, devRP, "localhost", "a", "x1", "1x", "123.example.com", "xn--bcher-kva.example",
		"a-b.c-d", label63 + ".com", longest,
	}
	bad := []string{
		"", ".", "..", "ID.thehappie.co", "id.Thehappie.co", prodRP + ":443", "https://" + prodRP, prodRP + "/",
		prodRP + ".", "." + prodRP, "id..thehappie.co", "-id.thehappie.co", "id-.thehappie.co", "id.thehappie.co-",
		strings.Repeat("a", 64) + ".com", "e" + longest, "127.0.0.1", "1", "example.123", "[::1]", "::1",
		"id_1.thehappie.co", "id thehappie.co", " " + prodRP, prodRP + "\n", "id.th\u00e9happie.co",
		"id.thehappie.co\x00", "user@id.thehappie.co", "id|thehappie.co", "*.thehappie.co",
	}
	for _, rp := range good {
		if !platform.ValidRPID(rp) {
			t.Errorf("%q is refused", rp)
			continue
		}
		if _, err := platform.PRFSalt(rp); err != nil {
			t.Errorf("%q: PRFSalt: %v", rp, err)
		}
		if _, err := platform.PasskeyWrapKey(passkeyA.prf, rp); err != nil {
			t.Errorf("%q: PasskeyWrapKey: %v", rp, err)
		}
		// Every accepted RP ID is drawn from the AAD alphabet.
		if _, err := platform.WrapAAD(platform.WrapPasskey, passkeyA.binding(rp)); err != nil {
			t.Errorf("%q: no AAD: %v", rp, err)
		}
	}
	for _, rp := range bad {
		if platform.ValidRPID(rp) {
			t.Errorf("%q is accepted", rp)
		}
		if salt, err := platform.PRFSalt(rp); !errors.Is(err, platform.ErrWrap) || salt != nil {
			t.Errorf("%q: PRFSalt: %v", rp, err)
		}
		if key, err := platform.PasskeyWrapKey(passkeyA.prf, rp); !errors.Is(err, platform.ErrWrap) || key != nil {
			t.Errorf("%q: PasskeyWrapKey: %v", rp, err)
		}
		if _, err := platform.NewPasskeyWrap(nil, passkeyA.prf, testBytes(32, 2), passkeyA.binding(rp)); !errors.Is(err, platform.ErrWrap) {
			t.Errorf("%q: NewPasskeyWrap: %v", rp, err)
		}
	}
}

func TestTheLongestCredentialIDWebAuthnAllowsHasAnAAD(t *testing.T) {
	// WebAuthn credential ids are at most 1023 bytes, and the AAD carries
	// their base64url as it is.
	p := credential{passkeyA.prf, platform.EncodeB64(testBytes(1023, 0xfe))}
	root := testBytes(32, 0x52)
	w := newPasskeyWrap(t, p, prodRP, root)
	got, err := platform.OpenPasskeyWrap(p.prf, w, p.binding(prodRP))
	if err != nil || !bytes.Equal(got, root) {
		t.Fatalf("does not open: %v", err)
	}
}
