package platform_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/thehappieco/kit/passkey"
	"github.com/thehappieco/kit/profiles/platform"
)

// The kit's own checks of part 3, beside the platform's ported tests
// (passkey_test.go, extensions_test.go).

// PasskeyProfile is section 7's profile with the values of section 11.16,
// and a fresh value on every call.
func TestThePasskeyProfileIsSection11_16(t *testing.T) {
	p := platform.PasskeyProfile()
	if p.EvalPrefix != "thehappie-id/v1/passkey-prf|" || p.WrapInfo != "thehappie-id/v1/passkey/wrap" || !bytes.Equal(p.Header, []byte{0x01, 0x03}) {
		t.Fatalf("profile %+v", p)
	}
	if !bytes.Equal(p.Header, platform.RootWrapProfile(platform.WrapPasskey).WrapHeader) {
		t.Fatal("the passkey header is not the kind-3 root-wrap header")
	}
	p.Header[1] = 0x01
	p.EvalPrefix = "x"
	if q := platform.PasskeyProfile(); q.Header[1] != 0x03 || q.EvalPrefix != "thehappie-id/v1/passkey-prf|" {
		t.Fatal("PasskeyProfile() shares state")
	}
	if platform.PRFOutputLen != passkey.PRFLen || platform.PRFSaltLen != sha256.Size {
		t.Fatal("the lengths are not section 7's")
	}
}

// A wrap made with section 7's generic package under PasskeyProfile and the
// root-wrap AAD opens with OpenPasskeyWrap, and the reverse: one scheme.
func TestSection7WithThePlatformProfileIsTheKind3RootWrap(t *testing.T) {
	prf, root := testBytes(32, 0x11), testBytes(32, 0x22)
	b := platform.Binding{Sub: testSub, Epoch: 7, RPID: "id.thehappie.co", CredentialID: platform.EncodeB64([]byte("credential"))}
	aad, err := platform.WrapAAD(platform.WrapPasskey, b)
	if err != nil {
		t.Fatal(err)
	}
	generic, err := passkey.Wrap(platform.PasskeyProfile(), root, prf, b.RPID, aad)
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.CheckWrapShape(platform.WrapPasskey, generic); err != nil {
		t.Fatalf("section 7's envelope is not a kind-3 root wrap: %v", err)
	}
	got, err := platform.OpenPasskeyWrap(prf, generic, b)
	if err != nil || !bytes.Equal(got, root) {
		t.Fatalf("OpenPasskeyWrap does not open section 7's envelope: %v", err)
	}
	w, err := platform.NewPasskeyWrap(nil, prf, root, b)
	if err != nil {
		t.Fatal(err)
	}
	got, err = passkey.Unwrap(platform.PasskeyProfile(), w, prf, b.RPID, aad)
	if err != nil || !bytes.Equal(got, root) {
		t.Fatalf("section 7 does not open NewPasskeyWrap's wrap: %v", err)
	}
}

// The root-wrap AAD keeps v0.2.0's rule for the relying party (non-empty,
// the AAD alphabet), so "ID.thehappie.co" still has an AAD; the spelling of
// section 11.16 is enforced where K_pk is made, so no passkey wrap is made
// or opened under it.
func TestTheRelyingPartysSpellingIsEnforcedWhereTheKeyIsMade(t *testing.T) {
	prf, root := testBytes(32, 0x11), testBytes(32, 0x22)
	good := platform.Binding{Sub: testSub, Epoch: 1, RPID: "id.thehappie.co", CredentialID: "AA"}
	w, err := platform.NewPasskeyWrap(nil, prf, root, good)
	if err != nil {
		t.Fatal(err)
	}
	for _, rp := range []string{"ID.thehappie.co", "id.thehappie.co:443", "127.0.0.1", "id_1.thehappie.co"} {
		b := good
		b.RPID = rp
		if _, err := platform.WrapAAD(platform.WrapPasskey, b); err != nil {
			t.Fatalf("%q: WrapAAD changed: %v", rp, err)
		}
		if _, err := platform.NewPasskeyWrap(nil, prf, root, b); platform.ErrorCode(err) != "wrap" {
			t.Errorf("%q: NewPasskeyWrap: %v", rp, err)
		}
		if got, err := platform.OpenPasskeyWrap(prf, w, b); platform.ErrorCode(err) != "wrap" || got != nil {
			t.Errorf("%q: OpenPasskeyWrap: %v", rp, err)
		}
	}
}

// The lower-level path does not tie K_pk's relying party to the binding's
// (SPEC section 11.16): Wrap under a key from PasskeyWrapKey, and
// passkey.Wrap with PasskeyProfile, seal under a binding on another relying
// party, in another spelling or another valid one, and the wrap passes its
// self-test and CheckWrapShape and then never opens with OpenPasskeyWrap,
// under either relying party. NewPasskeyWrap takes the id once for both.
func TestTheLowerLevelSealLeavesTheRelyingPartyToTheCaller(t *testing.T) {
	prf, root := testBytes(32, 0x11), testBytes(32, 0x22)
	key, err := platform.PasskeyWrapKey(prf, "id.thehappie.co")
	if err != nil {
		t.Fatal(err)
	}
	for _, rp := range []string{"ID.thehappie.co", "id.thehappie.localhost"} {
		b := platform.Binding{Sub: testSub, Epoch: 1, RPID: rp, CredentialID: "AA"}
		w, err := platform.Wrap(nil, platform.WrapPasskey, key, root, b)
		if err != nil {
			t.Fatalf("%q: Wrap: %v", rp, err)
		}
		aad, err := platform.WrapAAD(platform.WrapPasskey, b)
		if err != nil {
			t.Fatal(err)
		}
		g, err := passkey.Wrap(platform.PasskeyProfile(), root, prf, "id.thehappie.co", aad)
		if err != nil {
			t.Fatalf("%q: passkey.Wrap: %v", rp, err)
		}
		for _, blob := range [][]byte{w, g} {
			if err := platform.CheckWrapShape(platform.WrapPasskey, blob); err != nil {
				t.Fatalf("%q: the server refuses the wrap: %v", rp, err)
			}
			for _, open := range []string{rp, "id.thehappie.co"} {
				ob := b
				ob.RPID = open
				if got, err := platform.OpenPasskeyWrap(prf, blob, ob); platform.ErrorCode(err) != "wrap" || got != nil {
					t.Errorf("%q: opened on %q: %v", rp, open, err)
				}
			}
		}
	}
}

// ValidRPID refuses only an all-decimal last label (SPEC section 11.16): a
// last label of "0x" and hex digits, which a browser's host parser reads as
// an IPv4 address, passes, as in the platform's idcrypto.ValidRPID.
func TestValidRPIDRefusesOnlyAnAllDecimalLastLabel(t *testing.T) {
	for _, rp := range []string{"127.0.0.1", "1", "id.123", "0"} {
		if platform.ValidRPID(rp) {
			t.Errorf("%q passes", rp)
		}
	}
	for _, rp := range []string{"0x7f000001", "0x", "id.0xff", "id.0x1", "1.0x"} {
		if !platform.ValidRPID(rp) {
			t.Errorf("%q is refused", rp)
		}
	}
}

// The PRF output and the root are the caller's: no function of part 3
// changes them, and every refusal returns nothing.
func TestThePRFOutputAndTheRootAreTheCallers(t *testing.T) {
	prf, root := testBytes(32, 0x11), testBytes(32, 0x22)
	b := platform.Binding{Sub: testSub, Epoch: 1, RPID: "id.thehappie.co", CredentialID: "AA"}
	key, err := platform.PasskeyWrapKey(prf, b.RPID)
	if err != nil {
		t.Fatal(err)
	}
	w, err := platform.NewPasskeyWrap(nil, prf, root, b)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := platform.OpenPasskeyWrap(prf, w, b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(prf, testBytes(32, 0x11)) || !bytes.Equal(root, testBytes(32, 0x22)) {
		t.Fatal("a caller's buffer changed")
	}
	// The returned key and root are the caller's to clear, and are copies.
	clear(key)
	clear(opened)
	if again, err := platform.OpenPasskeyWrap(prf, w, b); err != nil || !bytes.Equal(again, root) {
		t.Fatal("clearing a returned slice changed the next call")
	}
}

// Every refusal of part 3 is one of the protocol's names: package
// passkey's errors never escape.
func TestPasskeyRefusalsAreTheProtocolsNames(t *testing.T) {
	b := platform.Binding{Sub: testSub, Epoch: 1, RPID: "id.thehappie.co", CredentialID: "AA"}
	var errs []error
	_, err := platform.PasskeyWrapKey(nil, b.RPID)
	errs = append(errs, err)
	_, err = platform.NewPasskeyWrap(nil, testBytes(32, 1), testBytes(31, 2), b)
	errs = append(errs, err)
	_, err = platform.OpenPasskeyWrap(testBytes(32, 1), testBytes(62, 0), b)
	errs = append(errs, err)
	_, err = platform.OpenPasskeyWrap(testBytes(32, 1), nil, platform.Binding{RPID: b.RPID})
	errs = append(errs, err)
	for i, err := range errs {
		var pe *passkey.Error
		if platform.ErrorCode(err) != "wrap" || errors.As(err, &pe) {
			t.Errorf("refusal %d: %v", i, err)
		}
	}
	if err := platform.CheckClientExtensions(nil); platform.ErrorCode(err) != "client_extensions" {
		t.Errorf("an empty text: %v", err)
	}
}
