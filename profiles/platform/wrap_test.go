package platform_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/thehappieco/kit/profiles/platform"
)

func wrapFor(t *testing.T, kind platform.WrapKind, b platform.Binding) (key, root, wrap []byte) {
	t.Helper()
	key, root = testBytes(32, 0x4b), testBytes(32, 0x52)
	wrap, err := platform.Wrap(nil, kind, key, root, b)
	if err != nil {
		t.Fatal(err)
	}
	return key, root, wrap
}

func TestAWrapMovedToAnotherAccountDoesNotOpen(t *testing.T) {
	for _, kind := range []platform.WrapKind{platform.WrapPassword, platform.WrapRecovery} {
		key, root, wrap := wrapFor(t, kind, platform.Binding{Sub: testSub, Epoch: 1})
		got, err := platform.Unwrap(kind, key, wrap, platform.Binding{Sub: testSub, Epoch: 1})
		if err != nil || !bytes.Equal(got, root) {
			t.Fatalf("%s: the wrap does not open for its own account: %v", kind, err)
		}
		if _, err := platform.Unwrap(kind, key, wrap, platform.Binding{Sub: otherTestSub, Epoch: 1}); !errors.Is(err, platform.ErrWrap) {
			t.Fatalf("%s: opened for another account: %v", kind, err)
		}
	}
}

func TestAWrapForOneEpochDoesNotOpenInAnother(t *testing.T) {
	key, _, wrap := wrapFor(t, platform.WrapPassword, platform.Binding{Sub: testSub, Epoch: 1})
	for _, epoch := range []int{2, platform.MaxEpoch} {
		if _, err := platform.Unwrap(platform.WrapPassword, key, wrap, platform.Binding{Sub: testSub, Epoch: epoch}); !errors.Is(err, platform.ErrWrap) {
			t.Fatalf("opened at epoch %d: %v", epoch, err)
		}
	}
}

func TestAWrapOfOneKindDoesNotOpenAsAnotherEvenRelabelled(t *testing.T) {
	b := platform.Binding{Sub: testSub, Epoch: 1}
	key, _, wrap := wrapFor(t, platform.WrapPassword, b)
	if _, err := platform.Unwrap(platform.WrapRecovery, key, wrap, b); !errors.Is(err, platform.ErrWrap) {
		t.Fatalf("opened as a recovery wrap: %v", err)
	}
	// Rewriting the kind byte gets past the header check but not the AAD,
	// which repeats the kind.
	relabelled := bytes.Clone(wrap)
	relabelled[1] = byte(platform.WrapRecovery)
	if err := platform.CheckWrapShape(platform.WrapRecovery, relabelled); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if _, err := platform.Unwrap(platform.WrapRecovery, key, relabelled, b); !errors.Is(err, platform.ErrWrap) {
		t.Fatalf("a relabelled wrap opened: %v", err)
	}
}

func TestEveryBitOfAWrapIsAuthenticated(t *testing.T) {
	b := platform.Binding{Sub: testSub, Epoch: 1}
	key, _, wrap := wrapFor(t, platform.WrapPassword, b)
	for i := range wrap {
		for bit := 0; bit < 8; bit++ {
			w := bytes.Clone(wrap)
			w[i] ^= 1 << bit
			if root, err := platform.Unwrap(platform.WrapPassword, key, w, b); !errors.Is(err, platform.ErrWrap) || root != nil {
				t.Fatalf("byte %d bit %d flipped and the wrap still opened", i, bit)
			}
		}
	}
}

func TestAPasskeyWrapIsBoundToItsRelyingPartyAndCredential(t *testing.T) {
	b := platform.Binding{Sub: testSub, Epoch: 1, RPID: "id.thehappie.co", CredentialID: "Y3JlZGVudGlhbC0x"}
	key, root, wrap := wrapFor(t, platform.WrapPasskey, b)
	if got, err := platform.Unwrap(platform.WrapPasskey, key, wrap, b); err != nil || !bytes.Equal(got, root) {
		t.Fatalf("does not open for its own credential: %v", err)
	}
	for _, other := range []platform.Binding{
		{Sub: testSub, Epoch: 1, RPID: "id.thehappie.localhost", CredentialID: b.CredentialID},
		{Sub: testSub, Epoch: 1, RPID: b.RPID, CredentialID: "Y3JlZGVudGlhbC0y"},
		{Sub: otherTestSub, Epoch: 1, RPID: b.RPID, CredentialID: b.CredentialID},
	} {
		if _, err := platform.Unwrap(platform.WrapPasskey, key, wrap, other); !errors.Is(err, platform.ErrWrap) {
			t.Fatalf("opened for %+v: %v", other, err)
		}
	}
}

func TestTheWrapAADIsTheSpecArray(t *testing.T) {
	got, err := platform.PasswordWrapAAD(testSub, 1)
	if err != nil {
		t.Fatal(err)
	}
	if want := `["thehappie-id/root-wrap",1,"password","` + testSub + `",1]`; string(got) != want {
		t.Fatalf("got %s", got)
	}
	got, err = platform.RecoveryWrapAAD(testSub, 7)
	if err != nil {
		t.Fatal(err)
	}
	if want := `["thehappie-id/root-wrap",1,"recovery","` + testSub + `",7]`; string(got) != want {
		t.Fatalf("got %s", got)
	}
	got, err = platform.PasskeyWrapAAD(testSub, 1, "id.thehappie.co", "AbC-_w")
	if err != nil {
		t.Fatal(err)
	}
	if want := `["thehappie-id/root-wrap",1,"passkey","` + testSub + `",1,"id.thehappie.co","AbC-_w"]`; string(got) != want {
		t.Fatalf("got %s", got)
	}
}

func TestTheWrapAADRefusesAnAmbiguousBinding(t *testing.T) {
	for name, c := range map[string]struct {
		kind platform.WrapKind
		b    platform.Binding
	}{
		"an upper-case sub":               {platform.WrapPassword, platform.Binding{Sub: "0199E4B2-3C41-7A52-8F3E-9B1D2C4E5F60", Epoch: 1}},
		"a sub without hyphens":           {platform.WrapPassword, platform.Binding{Sub: "0199e4b23c417a528f3e9b1d2c4e5f60", Epoch: 1}},
		"epoch 0":                         {platform.WrapPassword, platform.Binding{Sub: testSub, Epoch: 0}},
		"a negative epoch":                {platform.WrapRecovery, platform.Binding{Sub: testSub, Epoch: -1}},
		"passkey fields on a password":    {platform.WrapPassword, platform.Binding{Sub: testSub, Epoch: 1, RPID: "id.thehappie.co"}},
		"a passkey without a credential":  {platform.WrapPasskey, platform.Binding{Sub: testSub, Epoch: 1, RPID: "id.thehappie.co"}},
		"a padded credential id":          {platform.WrapPasskey, platform.Binding{Sub: testSub, Epoch: 1, RPID: "id.thehappie.co", CredentialID: "AA=="}},
		"an rp id that needs escaping":    {platform.WrapPasskey, platform.Binding{Sub: testSub, Epoch: 1, RPID: `id"x`, CredentialID: "AA"}},
		"an unknown kind":                 {platform.WrapKind(4), platform.Binding{Sub: testSub, Epoch: 1}},
		"the zero kind":                   {platform.WrapKind(0), platform.Binding{Sub: testSub, Epoch: 1}},
		"a non-ASCII rp id":               {platform.WrapPasskey, platform.Binding{Sub: testSub, Epoch: 1, RPID: "id.th\u00e9happie.co", CredentialID: "AA"}},
		"a credential id with a newline":  {platform.WrapPasskey, platform.Binding{Sub: testSub, Epoch: 1, RPID: "id.thehappie.co", CredentialID: "AA\n"}},
		"a credential id with a space":    {platform.WrapPasskey, platform.Binding{Sub: testSub, Epoch: 1, RPID: "id.thehappie.co", CredentialID: "A A"}},
		"a credential id outside base64":  {platform.WrapPasskey, platform.Binding{Sub: testSub, Epoch: 1, RPID: "id.thehappie.co", CredentialID: "A+/A"}},
		"a credential id with bad length": {platform.WrapPasskey, platform.Binding{Sub: testSub, Epoch: 1, RPID: "id.thehappie.co", CredentialID: "AAAAA"}},
	} {
		if _, err := platform.WrapAAD(c.kind, c.b); !errors.Is(err, platform.ErrWrap) {
			t.Errorf("%s: %v, want ErrWrap", name, err)
		}
		if _, err := platform.Wrap(nil, c.kind, testBytes(32, 1), testBytes(32, 2), c.b); !errors.Is(err, platform.ErrWrap) {
			t.Errorf("%s: Wrap: %v, want ErrWrap", name, err)
		}
	}
}

func TestTheServerShapeCheckOfAWrap(t *testing.T) {
	_, _, wrap := wrapFor(t, platform.WrapRecovery, platform.Binding{Sub: testSub, Epoch: 1})
	if err := platform.CheckWrapShape(platform.WrapRecovery, wrap); err != nil {
		t.Fatalf("a good recovery wrap: %v", err)
	}
	bad := map[string]struct {
		kind platform.WrapKind
		wrap []byte
	}{
		"the password field":   {platform.WrapPassword, wrap},
		"61 bytes":             {platform.WrapRecovery, wrap[:61]},
		"63 bytes":             {platform.WrapRecovery, append(bytes.Clone(wrap), 0)},
		"empty":                {platform.WrapRecovery, nil},
		"version 2":            {platform.WrapRecovery, append([]byte{2}, wrap[1:]...)},
		"an unknown kind byte": {platform.WrapKind(9), append([]byte{1, 9}, wrap[2:]...)},
	}
	for name, c := range bad {
		if err := platform.CheckWrapShape(c.kind, c.wrap); !errors.Is(err, platform.ErrWrap) {
			t.Errorf("%s: %v, want ErrWrap", name, err)
		}
	}
}

func TestWrapRefusesKeysAndRootsOfTheWrongLengthAndAShortRandomSource(t *testing.T) {
	b := platform.Binding{Sub: testSub, Epoch: 1}
	if _, err := platform.Wrap(nil, platform.WrapPassword, testBytes(31, 1), testBytes(32, 2), b); !errors.Is(err, platform.ErrWrap) {
		t.Errorf("a 31-byte key: %v", err)
	}
	if _, err := platform.Wrap(nil, platform.WrapPassword, testBytes(32, 1), testBytes(16, 2), b); !errors.Is(err, platform.ErrWrap) {
		t.Errorf("a 16-byte root: %v", err)
	}
	if _, err := platform.Wrap(bytes.NewReader(make([]byte, 11)), platform.WrapPassword, testBytes(32, 1), testBytes(32, 2), b); err == nil {
		t.Error("an 11-byte random source did not fail")
	}
	if _, err := platform.Unwrap(platform.WrapPassword, testBytes(16, 1), make([]byte, platform.WrapLen), b); !errors.Is(err, platform.ErrWrap) {
		t.Errorf("a 16-byte key: %v", err)
	}
}

func TestTwoWrapsOfTheSameRootUseFreshNonces(t *testing.T) {
	b := platform.Binding{Sub: testSub, Epoch: 1}
	_, _, a := wrapFor(t, platform.WrapPassword, b)
	_, _, c := wrapFor(t, platform.WrapPassword, b)
	if bytes.Equal(a, c) {
		t.Fatal("two wraps of the same root under the same key are identical")
	}
}
