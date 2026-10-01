package seal_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/thehappieco/kit/hpke"
	"github.com/thehappieco/kit/profiles/wappie"
	"github.com/thehappieco/kit/seal"
)

// These are Wappie's own binding tests (internal/crypto/seal/seal_test.go),
// run against the kit with the Wappie profile, plus the tests of what the kit
// added: the domain as a parameter.

var (
	tenant     = uuid.MustParse("01a034b7-d09c-7121-b7f8-41f210a9244a")
	testDevice = uuid.MustParse("01a036b0-ddcc-78ae-a207-82f3cb3e9502")
	rowA       = uuid.MustParse("11111111-1111-7111-8111-111111111111")
	rowB       = uuid.MustParse("22222222-2222-7222-8222-222222222222")
)

func keys(t testing.TB) (hpke.PublicKey, hpke.PrivateKey) {
	t.Helper()
	pub, priv, err := hpke.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return pub, priv
}

func contentKey(t testing.TB, pub hpke.PublicKey, id uint32) *seal.ContentKey[wappie.Kind] {
	t.Helper()
	ck, err := seal.NewContentKey[wappie.Kind](pub, tenant, testDevice, 1, id)
	if err != nil {
		t.Fatalf("NewContentKey: %v", err)
	}
	return ck
}

func opened(t testing.TB, priv hpke.PrivateKey, ck *seal.ContentKey[wappie.Kind]) *seal.ContentKey[wappie.Kind] {
	t.Helper()
	o, err := seal.OpenContentKey[wappie.Kind](priv, tenant, testDevice, ck.ID, ck.Sealed)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// Everything the sealing side holds recovers no plaintext; the private key does.
func TestSealingSideCannotOpen(t *testing.T) {
	pub, priv := keys(t)
	secret := []byte("a message the server must never be able to read")
	ck := contentKey(t, pub, 1)
	sealed, err := ck.Seal(wappie.KindBody, tenant, rowA, secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, blob := range [][]byte{pub.Bytes(), sealed, ck.Sealed, tenant[:], rowA[:]} {
		if bytes.Contains(blob, secret) {
			t.Fatal("plaintext is recoverable from what the sealing side holds")
		}
	}
	_, other := keys(t)
	if _, err := seal.OpenContentKey[wappie.Kind](other, tenant, testDevice, 1, ck.Sealed); err == nil {
		t.Fatal("an unrelated private key unwrapped the content key")
	}
	got, err := opened(t, priv, ck).Open(wappie.KindBody, tenant, rowA, sealed)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("round trip: %v", err)
	}
}

func TestRelocationKindAndTenantAreBound(t *testing.T) {
	pub, priv := keys(t)
	ck := contentKey(t, pub, 1)
	sealed, err := ck.Seal(wappie.KindThumbnail, tenant, rowA, []byte("meet me at eight"))
	if err != nil {
		t.Fatal(err)
	}
	o := opened(t, priv, ck)
	for name, open := range map[string]func() error{
		"another row":    func() error { _, err := o.Open(wappie.KindThumbnail, tenant, rowB, sealed); return err },
		"another kind":   func() error { _, err := o.Open(wappie.KindBody, tenant, rowA, sealed); return err },
		"another tenant": func() error { _, err := o.Open(wappie.KindThumbnail, rowB, rowA, sealed); return err },
	} {
		if err := open(); !errors.Is(err, seal.ErrAuthentication) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := o.Open(wappie.KindThumbnail, tenant, rowA, sealed); err != nil {
		t.Fatalf("no longer opens in its own row: %v", err)
	}
}

// Every single-bit flip is caught, header included.
func TestTamperingIsDetected(t *testing.T) {
	pub, priv := keys(t)
	ck := contentKey(t, pub, 1)
	sealed, err := ck.Seal(wappie.KindBody, tenant, rowA, []byte("integrity matters"))
	if err != nil {
		t.Fatal(err)
	}
	o := opened(t, priv, ck)
	for i := range sealed {
		for _, bit := range []byte{0x01, 0x80} {
			tampered := bytes.Clone(sealed)
			tampered[i] ^= bit
			if _, err := o.Open(wappie.KindBody, tenant, rowA, tampered); err == nil {
				t.Fatalf("byte %d bit %#x: tampering not detected", i, bit)
			}
		}
	}
}

func TestDirectRoundTrip(t *testing.T) {
	pub, priv := keys(t)
	for name, payload := range map[string][]byte{"empty": {}, "key sized": make([]byte, seal.KeyLen), "text": []byte("a grant")} {
		sealed, err := seal.SealDirect(pub, wappie.KindDeviceGrant, tenant, rowA, 1, payload)
		if err != nil {
			t.Fatal(err)
		}
		got, err := seal.OpenDirect(priv, wappie.KindDeviceGrant, tenant, rowA, sealed)
		if err != nil || !bytes.Equal(got, payload) {
			t.Errorf("%s: %q %v", name, got, err)
		}
	}
}

func TestOverheads(t *testing.T) {
	pub, priv := keys(t)
	ck := contentKey(t, pub, 7)
	o := opened(t, priv, ck)
	for _, n := range []int{0, 1, 32, 280, 4096, 1 << 16} {
		payload := bytes.Repeat([]byte("x"), n)
		sealed, err := ck.Seal(wappie.KindBody, tenant, rowA, payload)
		if err != nil {
			t.Fatal(err)
		}
		if len(sealed) != seal.BatchOverhead+n {
			t.Errorf("size %d: envelope is %d bytes", n, len(sealed))
		}
		if got, err := o.Open(wappie.KindBody, tenant, rowA, sealed); err != nil || !bytes.Equal(got, payload) {
			t.Errorf("size %d: %v", n, err)
		}
	}
	direct, err := seal.SealDirect(pub, wappie.KindContentKey, tenant, rowA, 1, nil)
	if err != nil || len(direct) != seal.DirectOverhead || seal.DirectOverhead != 56 || seal.BatchOverhead != 40 {
		t.Errorf("direct overhead %d: %v", len(direct), err)
	}
}

func TestWrongContentKeyNamesTheMismatch(t *testing.T) {
	pub, priv := keys(t)
	a, b := contentKey(t, pub, 1), contentKey(t, pub, 2)
	sealed, err := a.Seal(wappie.KindBody, tenant, rowA, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = opened(t, priv, b).Open(wappie.KindBody, tenant, rowA, sealed)
	if !errors.Is(err, seal.ErrKeyMismatch) || !strings.Contains(err.Error(), "envelope needs content key 1, have 2") {
		t.Fatalf("error %v", err)
	}
}

func TestContentKeyID(t *testing.T) {
	pub, _ := keys(t)
	sealed, err := contentKey(t, pub, 4242).Seal(wappie.KindBody, tenant, rowA, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if id, epoch, err := seal.ContentKeyID[wappie.Kind](sealed); err != nil || id != 4242 || epoch != 1 {
		t.Fatalf("%d %d %v", id, epoch, err)
	}
}

func TestMissingKeysRefuse(t *testing.T) {
	if _, err := seal.SealDirect(hpke.PublicKey{}, wappie.KindBody, tenant, rowA, 1, []byte("x")); !errors.Is(err, seal.ErrInvalidKey) {
		t.Fatalf("sealing with no public key: %v", err)
	}
	if _, err := seal.OpenDirect(hpke.PrivateKey{}, wappie.KindBody, tenant, rowA, nil); !errors.Is(err, seal.ErrInvalidKey) {
		t.Fatalf("opening with no private key: %v", err)
	}
}

// A test-only profile: another product with its own magic and label.
type otherKind uint8

func (k otherKind) String() string {
	switch k {
	case seal.KindContentKey:
		return "content_key"
	case seal.KindGrant:
		return "grant"
	case seal.KindUserWrap:
		return "user_wrap"
	case 0x01:
		return "body"
	}
	return fmt.Sprintf("kind(%#x)", byte(k))
}

func (otherKind) Domain() seal.Domain {
	return seal.Domain{Magic: [2]byte{'T', 'H'}, Label: "thehappie-test/v1/seal"}
}

// Two products never open each other's envelopes, even with the same key,
// the same kind byte and the same row: the magic, the AAD and the info differ.
func TestDomainsAreSeparate(t *testing.T) {
	pub, priv := keys(t)
	if err := seal.ValidateKinds[otherKind](); err != nil {
		t.Fatal(err)
	}
	w, err := seal.SealDirect(pub, wappie.KindDeviceGrant, tenant, rowA, 1, []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	o, err := seal.SealDirect(pub, otherKind(seal.KindGrant), tenant, rowA, 1, []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(o[:2], []byte("TH")) {
		t.Fatalf("magic %q", o[:2])
	}
	if _, err := seal.OpenDirect(priv, otherKind(seal.KindGrant), tenant, rowA, w); !errors.Is(err, seal.ErrMagic) {
		t.Errorf("a Wappie envelope under another domain: %v", err)
	}
	if _, err := seal.OpenDirect(priv, wappie.KindDeviceGrant, tenant, rowA, o); !errors.Is(err, seal.ErrMagic) {
		t.Errorf("another domain's envelope under Wappie's: %v", err)
	}
	// With the magic forced equal, the label still separates them.
	forged := bytes.Clone(o)
	forged[0], forged[1] = 'W', 'S'
	if _, err := seal.OpenDirect(priv, wappie.KindDeviceGrant, tenant, rowA, forged); !errors.Is(err, seal.ErrAuthentication) {
		t.Errorf("a relabelled envelope: %v", err)
	}
	if got, err := seal.OpenDirect(priv, otherKind(seal.KindGrant), tenant, rowA, o); err != nil || string(got) != "k" {
		t.Errorf("its own domain: %v", err)
	}
	if aad := seal.AAD(otherKind(1), tenant, rowA, o[:8]); !bytes.HasPrefix(aad, []byte("thehappie-test/v1/seal\x01")) || len(aad) != len("thehappie-test/v1/seal")+41 {
		t.Errorf("aad %x", aad)
	}
	if info := string(seal.Info(otherKind(seal.KindGrant), tenant, 3)); info != "thehappie-test/v1/seal/grant/"+tenant.String()+"/3" {
		t.Errorf("info %q", info)
	}
}

type badName uint8

func (k badName) String() string {
	if k == seal.KindContentKey || k == seal.KindGrant || k == seal.KindUserWrap {
		return []string{"content_key", "grant", "user_wrap"}[k-seal.KindContentKey]
	}
	if k == 1 {
		return "Body"
	}
	return fmt.Sprintf("kind(%#x)", byte(k))
}
func (badName) Domain() seal.Domain { return seal.Domain{Magic: [2]byte{1, 2}, Label: "x"} }

type unnamedCore uint8

func (k unnamedCore) String() string { return fmt.Sprintf("kind(%#x)", byte(k)) }
func (unnamedCore) Domain() seal.Domain {
	return seal.Domain{Magic: [2]byte{1, 2}, Label: "x"}
}

type badLabel uint8

func (k badLabel) String() string    { return wappie.Kind(k).String() }
func (badLabel) Domain() seal.Domain { return seal.Domain{Magic: [2]byte{1, 2}, Label: "with space"} }

func TestValidateKinds(t *testing.T) {
	if err := seal.ValidateKinds[wappie.Kind](); err != nil {
		t.Errorf("wappie: %v", err)
	}
	if err := seal.ValidateKinds[badName](); err == nil {
		t.Error("an upper-case name passed")
	}
	if err := seal.ValidateKinds[unnamedCore](); err == nil {
		t.Error("unnamed core kinds passed")
	}
	if err := seal.ValidateKinds[badLabel](); err == nil {
		t.Error("a label with a space passed")
	}
	pub, _ := keys(t)
	if _, err := seal.SealDirect(pub, badLabel(1), tenant, rowA, 1, nil); err == nil {
		t.Error("sealed under a label with a space")
	}
}

// Arbitrary input must never panic: envelopes come from a database an
// attacker may have written to.
func FuzzOpen(f *testing.F) {
	pub, priv, err := hpke.GenerateKeyPair()
	if err != nil {
		f.Fatal(err)
	}
	ck := contentKey(f, pub, 1)
	o := opened(f, priv, ck)
	good, _ := ck.Seal(wappie.KindBody, tenant, rowA, []byte("seed"))
	direct, _ := seal.SealDirect(pub, wappie.KindDeviceGrant, tenant, rowA, 1, []byte("seed"))
	f.Add(good)
	f.Add(direct)
	f.Add([]byte{})
	f.Add(make([]byte, 40))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = o.Open(wappie.KindBody, tenant, rowA, data)
		_, _ = seal.OpenDirect(priv, wappie.KindBody, tenant, rowA, data)
		_, _, _ = seal.ContentKeyID[wappie.Kind](data)
		_, _ = seal.OpenContentKey[wappie.Kind](priv, tenant, testDevice, 1, data)
	})
}
