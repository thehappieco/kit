package platform_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/thehappieco/kit/hpke"
	"github.com/thehappieco/kit/internal/forge"
	"github.com/thehappieco/kit/profiles/platform"
)

// A key delivery as the tests use it: the product page's ephemeral pair,
// and one flow's product key and binding.
type delivery struct {
	akdPriv, akdPub []byte
	sk              []byte
	b               platform.KeyDeliveryBinding
}

const (
	testChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" // RFC 7636 appendix B
	testNonce     = "n-0S6_WzA2Mj4Rm7tBQdLwK1vHqXf9cUe3yPbJsZkGo"
)

func newDelivery(t testing.TB, product string) delivery {
	t.Helper()
	akd, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sk, pub, err := platform.ProductKey(testBytes(32, 0x52), product, 1)
	if err != nil {
		t.Fatal(err)
	}
	clientID, redirect := "wappie-app", "https://app.wappie.thehappie.co/auth/callback"
	if product == "mailie" {
		clientID, redirect = "mailie-console", "https://console.mailie.thehappie.co/auth/callback"
	}
	return delivery{
		akdPriv: akd.Bytes(), akdPub: akd.PublicKey().Bytes(), sk: sk,
		b: platform.KeyDeliveryBinding{
			Issuer: "https://id.thehappie.co", ClientID: clientID, RedirectURI: redirect,
			Sub: testSub, ProductKeyID: platform.ProductKeyID(product, 1), ProductKey: pub,
			CodeChallenge: testChallenge, Nonce: testNonce,
		},
	}
}

func (d delivery) seal(t testing.TB) []byte {
	t.Helper()
	sealed, err := platform.SealProductKey(nil, d.akdPub, d.sk, d.b)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return sealed
}

func TestASealedProductKeyOpensForTheFlowItWasSealedFor(t *testing.T) {
	for _, product := range testProducts {
		d := newDelivery(t, product)
		sealed := d.seal(t)
		if len(sealed) != platform.SealedProductKeyLen {
			t.Fatalf("%s: %d bytes sealed, not %d", product, len(sealed), platform.SealedProductKeyLen)
		}
		got, err := platform.OpenProductKey(d.akdPriv, sealed, d.b)
		if err != nil {
			t.Fatalf("%s: %v", product, err)
		}
		if !bytes.Equal(got, d.sk) {
			t.Fatalf("%s: opened another key", product)
		}
	}
}

func TestEverySealUsesAFreshEphemeralKey(t *testing.T) {
	d := newDelivery(t, "wappie")
	a, b := d.seal(t), d.seal(t)
	if bytes.Equal(a[:32], b[:32]) || bytes.Equal(a, b) {
		t.Fatal("two seals of the same key share their encapsulated key")
	}
	// rand.Reader is accepted too, and means the same.
	if _, err := platform.SealProductKey(rand.Reader, d.akdPub, d.sk, d.b); err != nil {
		t.Fatal(err)
	}
}

func TestSealProductKeyRefusesARandomSourceItCannotUse(t *testing.T) {
	d := newDelivery(t, "wappie")
	_, err := platform.SealProductKey(bytes.NewReader(make([]byte, 1024)), d.akdPub, d.sk, d.b)
	if err == nil {
		t.Fatal("a fixed reader was accepted, and silently ignored")
	}
	if platform.ErrorCode(err) != "" {
		t.Fatalf("a usage error carries a protocol name: %v", err)
	}
}

func TestASealedKeyForOneFlowDoesNotOpenInAnother(t *testing.T) {
	d := newDelivery(t, "wappie")
	sealed := d.seal(t)
	_, otherAccountKey, err := platform.ProductKey(testBytes(32, 0x53), "wappie", 1)
	if err != nil {
		t.Fatal(err)
	}
	others := []struct {
		field string
		edit  func(*platform.KeyDeliveryBinding)
	}{
		{"issuer", func(b *platform.KeyDeliveryBinding) { b.Issuer = "http://id.thehappie.localhost:8290" }},
		{"client_id", func(b *platform.KeyDeliveryBinding) { b.ClientID = "fakeproduct" }},
		{"redirect_uri", func(b *platform.KeyDeliveryBinding) { b.RedirectURI += "/" }},
		{"sub", func(b *platform.KeyDeliveryBinding) { b.Sub = otherTestSub }},
		{"product_key_id", func(b *platform.KeyDeliveryBinding) { b.ProductKeyID = "wappie:2" }},
		{"product_key", func(b *platform.KeyDeliveryBinding) { b.ProductKey = otherAccountKey }},
		{"code_challenge", func(b *platform.KeyDeliveryBinding) { b.CodeChallenge = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU" }},
		{"nonce", func(b *platform.KeyDeliveryBinding) { b.Nonce = strings.Replace(b.Nonce, "n", "m", 1) }},
	}
	for _, o := range others {
		b := d.b
		o.edit(&b)
		if _, err := platform.KeyDeliveryAAD(b); err != nil {
			t.Fatalf("%s: the other flow is not a valid binding: %v", o.field, err)
		}
		got, err := platform.OpenProductKey(d.akdPriv, sealed, b)
		if !errors.Is(err, platform.ErrKeyDelivery) || got != nil {
			t.Errorf("another %s: %v, want ErrKeyDelivery and no key", o.field, err)
		}
	}
	// Another flow is also another page, with its own ephemeral key.
	other := newDelivery(t, "wappie")
	if _, err := platform.OpenProductKey(other.akdPriv, sealed, d.b); !errors.Is(err, platform.ErrKeyDelivery) {
		t.Errorf("another recipient: %v, want ErrKeyDelivery", err)
	}
}

func TestAKeyDeliveredForOneProductDoesNotPassAsAnother(t *testing.T) {
	wappie, mailie := newDelivery(t, "wappie"), newDelivery(t, "mailie")
	mailie.akdPriv, mailie.akdPub = wappie.akdPriv, wappie.akdPub

	// Mailie's delivery, presented to a page that expects Wappie's key: the
	// page rebuilds the AAD with Wappie's client, key id and key.
	if _, err := platform.OpenProductKey(wappie.akdPriv, mailie.seal(t), wappie.b); !errors.Is(err, platform.ErrKeyDelivery) {
		t.Fatalf("mailie's delivery opened as wappie's: %v", err)
	}

	// A binding with Wappie's client and Mailie's key id and key, sealed
	// honestly, opens nowhere but in itself: Wappie's page takes the key id
	// and the key from its own ID token.
	mixed := wappie.b
	mixed.ProductKeyID, mixed.ProductKey = mailie.b.ProductKeyID, mailie.b.ProductKey
	mixedSealed, err := platform.SealProductKey(nil, wappie.akdPub, mailie.sk, mixed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := platform.OpenProductKey(wappie.akdPriv, mixedSealed, wappie.b); !errors.Is(err, platform.ErrKeyDelivery) {
		t.Fatalf("a delivery naming mailie's key opened as wappie's: %v", err)
	}

	// Mailie's private key under Wappie's whole binding: the seal refuses
	// it, and a page that sealed it anyway is caught by the product, which
	// compares the opened key's public half with the one it was told.
	if _, err := platform.SealProductKey(nil, wappie.akdPub, mailie.sk, wappie.b); !errors.Is(err, platform.ErrProductKey) {
		t.Fatalf("sealed mailie's key under wappie's binding: %v", err)
	}
	got, err := platform.OpenProductKey(wappie.akdPriv, sealUnchecked(t, wappie.akdPub, mailie.sk, wappie.b), wappie.b)
	if !errors.Is(err, platform.ErrProductKey) || got != nil {
		t.Fatalf("mailie's key passed as wappie's: %v", err)
	}
}

func TestOpenProductKeyRefusesAKeyWhosePublicHalfIsNotTheRegisteredOne(t *testing.T) {
	d := newDelivery(t, "wappie")
	wrong, _, err := platform.ProductKey(testBytes(32, 0x53), "wappie", 1)
	if err != nil {
		t.Fatal(err)
	}
	// SealProductKey will not make such a blob.
	if _, err := platform.SealProductKey(nil, d.akdPub, wrong, d.b); !errors.Is(err, platform.ErrProductKey) {
		t.Fatalf("sealed a key whose public half is not the binding's: %v", err)
	}
	// A page that made it anyway: the right recipient, the right AAD,
	// another account's key inside. It opens, and the product refuses it
	// after comparing public halves.
	got, err := platform.OpenProductKey(d.akdPriv, sealUnchecked(t, d.akdPub, wrong, d.b), d.b)
	if !errors.Is(err, platform.ErrProductKey) || platform.ErrorCode(err) != "product_key" || got != nil {
		t.Fatalf("%v, want product_key and no key", err)
	}
}

// sealUnchecked seals sk under b's AAD straight with package hpke, without
// SealProductKey's check that sk is b's product key: what a faulty or
// hostile page could send.
func sealUnchecked(t *testing.T, akdPub, sk []byte, b platform.KeyDeliveryBinding) []byte {
	t.Helper()
	aad, err := platform.KeyDeliveryAAD(b)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := hpke.ParsePublicKey(akdPub)
	if err != nil {
		t.Fatal(err)
	}
	enc, ct, err := hpke.Seal(pub, []byte(platform.KeyDeliveryInfo), aad, sk)
	if err != nil {
		t.Fatal(err)
	}
	return append(enc, ct...)
}

func TestSealProductKeyRefusesALowOrderOrNonCanonicalAkdPub(t *testing.T) {
	d := newDelivery(t, "wappie")
	high := slices.Clone(d.akdPub)
	high[31] |= 0x80
	bad := [][]byte{high, d.akdPub[:31], append(slices.Clone(d.akdPub), 0), nil}
	for _, h := range knownBadX25519 {
		bad = append(bad, mustHex(t, h))
	}
	for _, lo := range forge.LowOrder {
		bad = append(bad, lo.Point)
	}
	for i, pub := range bad {
		got, err := platform.SealProductKey(nil, pub, d.sk, d.b)
		if !errors.Is(err, platform.ErrKeyDelivery) || platform.ErrorCode(err) != "key_delivery" || got != nil {
			t.Errorf("akd_pub %d: %v, want key_delivery", i, err)
		}
	}
}

func TestOpenProductKeyRefusesEveryLengthButEighty(t *testing.T) {
	d := newDelivery(t, "wappie")
	sealed := d.seal(t)
	for _, n := range []int{0, 1, 32, 48, 64, 79, 81, 96, 160} {
		blob := make([]byte, n)
		copy(blob, sealed)
		if _, err := platform.OpenProductKey(d.akdPriv, blob, d.b); !errors.Is(err, platform.ErrKeyDelivery) {
			t.Errorf("%d bytes: %v", n, err)
		}
	}
	for _, n := range []int{0, 31, 33} {
		if _, err := platform.OpenProductKey(make([]byte, n), sealed, d.b); !errors.Is(err, platform.ErrKeyDelivery) {
			t.Errorf("a %d-byte private key: %v", n, err)
		}
	}
}

func TestEveryAlteredBitOfASealedKeyIsRefused(t *testing.T) {
	d := newDelivery(t, "wappie")
	sealed := d.seal(t)
	for i := range len(sealed) * 8 {
		blob := slices.Clone(sealed)
		blob[i/8] ^= 1 << (i % 8)
		if got, err := platform.OpenProductKey(d.akdPriv, blob, d.b); !errors.Is(err, platform.ErrKeyDelivery) || got != nil {
			t.Fatalf("bit %d flipped: %v", i, err)
		}
	}
}

// Rule (a) of section 11.12: an enc that is not the canonical encoding of an
// X25519 point is refused before any exchange, even when the sealer wrote
// the same spelling into the KEM context, so that the blob opens under
// RFC 9180. Every non-canonical spelling of the honest enc is tried: bit 255
// set, and for an enc below 19 its alias from p upwards.
func TestOpenProductKeyRefusesEveryNonCanonicalEnc(t *testing.T) {
	d := newDelivery(t, "wappie")
	aad, err := platform.KeyDeliveryAAD(d.b)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := hpke.ParsePrivateKey(d.akdPriv)
	if err != nil {
		t.Fatal(err)
	}
	for range 16 {
		eph, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		akd, err := ecdh.X25519().NewPublicKey(d.akdPub)
		if err != nil {
			t.Fatal(err)
		}
		dh, err := eph.ECDH(akd)
		if err != nil {
			t.Fatal(err)
		}
		alias := eph.PublicKey().Bytes()
		alias[31] |= 0x80
		ct := forge.Seal(dh, alias, d.akdPub, []byte(platform.KeyDeliveryInfo), aad, d.sk)
		// RFC 9180 opens it: package hpke reads the alias as the point.
		if got, err := hpke.Open(priv, alias, []byte(platform.KeyDeliveryInfo), aad, ct); err != nil || !bytes.Equal(got, d.sk) {
			t.Fatalf("the aliased blob does not open under RFC 9180, so it tests nothing: %v", err)
		}
		got, err := platform.OpenProductKey(d.akdPriv, append(slices.Clone(alias), ct...), d.b)
		if !errors.Is(err, platform.ErrKeyDelivery) || got != nil {
			t.Fatalf("an aliased enc was opened: %v", err)
		}
	}
}

func TestTheKeyDeliveryAADIsTheJCSArrayOfTheSpec(t *testing.T) {
	d := newDelivery(t, "wappie")
	aad, err := platform.KeyDeliveryAAD(d.b)
	if err != nil {
		t.Fatal(err)
	}
	want := `["thehappie-id/key-delivery",1,"https://id.thehappie.co","wappie-app",` +
		`"https://app.wappie.thehappie.co/auth/callback","` + testSub + `","wappie:1","` +
		platform.EncodeB64(d.b.ProductKey) + `","` + testChallenge + `","` + testNonce + `"]`
	if string(aad) != want {
		t.Fatal("the AAD is not the array of section 11.12")
	}
}

func TestTheKeyDeliveryAADRefusesBindingsWithoutOneSpelling(t *testing.T) {
	d := newDelivery(t, "wappie")
	edits := map[string]func(*platform.KeyDeliveryBinding){
		"an empty issuer":                  func(b *platform.KeyDeliveryBinding) { b.Issuer = "" },
		"an issuer with a query":           func(b *platform.KeyDeliveryBinding) { b.Issuer += "/?x" },
		"an issuer with a space":           func(b *platform.KeyDeliveryBinding) { b.Issuer += " " },
		"an empty client id":               func(b *platform.KeyDeliveryBinding) { b.ClientID = "" },
		"a client id with a quote":         func(b *platform.KeyDeliveryBinding) { b.ClientID = `wappie"app` },
		"an empty redirect uri":            func(b *platform.KeyDeliveryBinding) { b.RedirectURI = "" },
		"a redirect uri with a fragment":   func(b *platform.KeyDeliveryBinding) { b.RedirectURI += "#x" },
		"a sub in upper case":              func(b *platform.KeyDeliveryBinding) { b.Sub = strings.ToUpper(b.Sub) },
		"a sub without hyphens":            func(b *platform.KeyDeliveryBinding) { b.Sub = strings.ReplaceAll(b.Sub, "-", "") },
		"an empty product key id":          func(b *platform.KeyDeliveryBinding) { b.ProductKeyID = "" },
		"a product key id without epoch":   func(b *platform.KeyDeliveryBinding) { b.ProductKeyID = "wappie:" },
		"a product key id with epoch 0":    func(b *platform.KeyDeliveryBinding) { b.ProductKeyID = "wappie:0" },
		"a product key id with epoch 01":   func(b *platform.KeyDeliveryBinding) { b.ProductKeyID = "wappie:01" },
		"a product key id with epoch +1":   func(b *platform.KeyDeliveryBinding) { b.ProductKeyID = "wappie:+1" },
		"a product key id with epoch 2^31": func(b *platform.KeyDeliveryBinding) { b.ProductKeyID = "wappie:2147483648" },
		"a product key id in upper case":   func(b *platform.KeyDeliveryBinding) { b.ProductKeyID = "Wappie:1" },
		"a product key id with two colons": func(b *platform.KeyDeliveryBinding) { b.ProductKeyID = "wappie:1:1" },
		"a 31-byte product key":            func(b *platform.KeyDeliveryBinding) { b.ProductKey = b.ProductKey[:31] },
		"no product key":                   func(b *platform.KeyDeliveryBinding) { b.ProductKey = nil },
		"a 42-character code challenge":    func(b *platform.KeyDeliveryBinding) { b.CodeChallenge = b.CodeChallenge[:42] },
		"a padded code challenge":          func(b *platform.KeyDeliveryBinding) { b.CodeChallenge += "=" },
		"a code challenge with trailing bits": func(b *platform.KeyDeliveryBinding) {
			b.CodeChallenge = b.CodeChallenge[:42] + "N" // 'M' is 12; 'N' sets a trailing bit
		},
		"a 21-character nonce":     func(b *platform.KeyDeliveryBinding) { b.Nonce = b.Nonce[:21] },
		"a 129-character nonce":    func(b *platform.KeyDeliveryBinding) { b.Nonce = strings.Repeat("a", 129) },
		"a nonce with a dot":       func(b *platform.KeyDeliveryBinding) { b.Nonce = "." + b.Nonce[1:] },
		"a nonce with a tilde":     func(b *platform.KeyDeliveryBinding) { b.Nonce = "~" + b.Nonce[1:] },
		"a nonce with a non-ASCII": func(b *platform.KeyDeliveryBinding) { b.Nonce = "é" + b.Nonce[2:] },
	}
	for name, edit := range edits {
		b := d.b
		b.ProductKey = slices.Clone(b.ProductKey)
		edit(&b)
		if _, err := platform.KeyDeliveryAAD(b); !errors.Is(err, platform.ErrKeyDelivery) || platform.ErrorCode(err) != "key_delivery" {
			t.Errorf("%s: %v, want key_delivery", name, err)
		}
		if _, err := platform.SealProductKey(nil, d.akdPub, d.sk, b); platform.ErrorCode(err) != "key_delivery" {
			t.Errorf("%s: sealed anyway (%v)", name, err)
		}
	}
	// The bounds themselves are accepted.
	for _, nonce := range []string{strings.Repeat("a", 22), strings.Repeat("_", 128)} {
		b := d.b
		b.Nonce = nonce
		if _, err := platform.KeyDeliveryAAD(b); err != nil {
			t.Errorf("a %d-character nonce: %v", len(nonce), err)
		}
	}
	b := d.b
	b.ProductKeyID = platform.ProductKeyID("wappie", platform.MaxEpoch)
	if _, err := platform.KeyDeliveryAAD(b); err != nil {
		t.Errorf("the largest epoch: %v", err)
	}
}

func TestValidProductKeyIDAndValidSub(t *testing.T) {
	for _, id := range []string{"wappie:1", "mailie:2147483647", "a:1", "a-b-0:10"} {
		if !platform.ValidProductKeyID(id) {
			t.Errorf("%q refused", id)
		}
	}
	for _, id := range []string{"", ":", "wappie", "wappie:", ":1", "wappie:0", "wappie:01", "wappie:+1", "wappie:-1",
		"wappie:2147483648", "Wappie:1", "wappie:1:1", "wappie|1", "wappie:1 ", "1wappie:1", "wappie:१"} {
		if platform.ValidProductKeyID(id) {
			t.Errorf("%q accepted", id)
		}
	}
	if !platform.ValidSub(testSub) || !platform.ValidSub(platform.DummySub()) {
		t.Error("a valid sub refused")
	}
	for _, sub := range []string{"", strings.ToUpper(testSub), strings.ReplaceAll(testSub, "-", ""), testSub + "0", "{" + testSub + "}"} {
		if platform.ValidSub(sub) {
			t.Errorf("%q accepted", sub)
		}
	}
}

func TestTheServerSideCheckRefusesWhatTheSealRefuses(t *testing.T) {
	// The authorize endpoint checks akd_pub with CheckPublicKey and the page
	// checks it again before sealing: the two refuse the same values, so
	// nothing the server accepts is refused only later.
	d := newDelivery(t, "wappie")
	for _, h := range knownBadX25519 {
		pub := mustHex(t, h)
		_, sealErr := platform.SealProductKey(nil, pub, d.sk, d.b)
		if (platform.CheckPublicKey(pub) == nil) != (sealErr == nil) {
			t.Fatal("the server and the seal disagree on an akd_pub")
		}
	}
	if err := platform.CheckPublicKey(d.akdPub); err != nil {
		t.Fatal(err)
	}
}

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal("not hex")
	}
	return b
}
