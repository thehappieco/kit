package cross_test

import (
	"bytes"
	"crypto/ecdh"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/thehappieco/kit/internal/forge"
	"github.com/thehappieco/kit/profiles/platform"
)

// The alphabets of section 11.12's binding and of section 11.13's verifier.
const (
	aadAlphabet      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/|@-"
	nonceAlphabet    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	verifierAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	productAlphabet  = "abcdefghijklmnopqrstuvwxyz0123456789-"
)

// The deployments and clients the platform has, and some it might have.
var (
	deliveryIssuers   = []string{"https://id.thehappie.co", "http://id.thehappie.localhost:8290"}
	deliveryClients   = []string{"wappie-app", "mailie-app", "mailie-console", "fakeproduct"}
	deliveryRedirects = []string{"https://app.wappie.thehappie.co/auth/callback", "http://fakeproduct.thehappie.localhost:8292/auth/callback"}
)

func randomFrom(t *testing.T, alphabet string, n int) string {
	t.Helper()
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[randomInt(t, int64(len(alphabet)))]
	}
	return string(b)
}

func pick(t *testing.T, from []string) string {
	t.Helper()
	return from[randomInt(t, int64(len(from)))]
}

// randomText is a non-empty string of the AAD alphabet, or one of the given
// values.
func randomText(t *testing.T, known []string) string {
	t.Helper()
	if randomInt(t, 2) == 0 {
		return pick(t, known)
	}
	return randomFrom(t, aadAlphabet, 1+int(randomInt(t, 60)))
}

func randomProduct(t *testing.T) string {
	t.Helper()
	switch randomInt(t, 3) {
	case 0:
		return "wappie"
	case 1:
		return "mailie"
	}
	return randomFrom(t, "abcdefghijklmnopqrstuvwxyz", 1) + randomFrom(t, productAlphabet, int(randomInt(t, 32)))
}

func randomEpoch(t *testing.T) int {
	t.Helper()
	if randomInt(t, 2) == 0 {
		return 1 + int(randomInt(t, 3))
	}
	return 1 + int(randomInt(t, platform.MaxEpoch))
}

func randomVerifier(t *testing.T) string {
	t.Helper()
	return randomFrom(t, verifierAlphabet, platform.MinCodeVerifierLen+int(randomInt(t, platform.MaxCodeVerifierLen-platform.MinCodeVerifierLen+1)))
}

// randomRequest is a valid binding without its product key.
func randomRequest(t *testing.T) platform.KeyDeliveryBinding {
	t.Helper()
	challenge, err := platform.PKCEChallenge(randomVerifier(t))
	if err != nil {
		t.Fatal(err)
	}
	return platform.KeyDeliveryBinding{
		Issuer:        randomText(t, deliveryIssuers),
		ClientID:      randomText(t, deliveryClients),
		RedirectURI:   randomText(t, deliveryRedirects),
		Sub:           uuid.Must(uuid.NewV7()).String(),
		CodeChallenge: challenge,
		Nonce:         randomFrom(t, nonceAlphabet, 22+int(randomInt(t, 107))),
	}
}

// bindingIn is a binding as a case's inputs.
func bindingIn(b platform.KeyDeliveryBinding) map[string]any {
	return map[string]any{
		"iss": b.Issuer, "client_id": b.ClientID, "redirect_uri": b.RedirectURI, "sub": b.Sub,
		"product_key_id": b.ProductKeyID, "pk_p_b64": b64(b.ProductKey), "code_challenge": b.CodeChallenge, "nonce": b.Nonce,
	}
}

func withIn(in map[string]any, more map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	for k, v := range more {
		out[k] = v
	}
	return out
}

// breakBinding changes one field of b to a spelling section 11.12 refuses.
func breakBinding(t *testing.T, b platform.KeyDeliveryBinding) (platform.KeyDeliveryBinding, string) {
	t.Helper()
	outside := []string{" ", "?", "#", `"`, "\\", "%", "+", ",", "~", "é", " ", "\t"}
	insert := func(s string) string {
		at := int(randomInt(t, int64(len(s)+1)))
		return s[:at] + pick(t, outside) + s[at:]
	}
	b.ProductKey = bytes.Clone(b.ProductKey)
	switch field := randomInt(t, 8); field {
	case 0:
		if randomInt(t, 2) == 0 {
			b.Issuer = ""
		} else {
			b.Issuer = insert(b.Issuer)
		}
		return b, "iss"
	case 1:
		if randomInt(t, 2) == 0 {
			b.ClientID = ""
		} else {
			b.ClientID = insert(b.ClientID)
		}
		return b, "client_id"
	case 2:
		if randomInt(t, 2) == 0 {
			b.RedirectURI = ""
		} else {
			b.RedirectURI = insert(b.RedirectURI)
		}
		return b, "redirect_uri"
	case 3:
		switch randomInt(t, 3) {
		case 0:
			b.Sub = strings.ToUpper(b.Sub[:9]) + "A" + b.Sub[10:]
		case 1:
			b.Sub = strings.ReplaceAll(b.Sub, "-", "")
		default:
			b.Sub = "{" + b.Sub + "}"
		}
		return b, "sub"
	case 4:
		product, epoch, _ := strings.Cut(b.ProductKeyID, ":")
		b.ProductKeyID = pick(t, []string{
			product + ":0" + epoch, product + ":0", product, product + ":", product + ":+" + epoch,
			product + ":2147483648", strings.ToUpper(product[:1]) + product[1:] + ":" + epoch, product + ":" + epoch + ":" + epoch,
			product + "|" + epoch, product + ":" + epoch + " ",
		})
		return b, "product_key_id"
	case 5:
		if randomInt(t, 2) == 0 {
			b.ProductKey = b.ProductKey[:31]
		} else {
			b.ProductKey = append(b.ProductKey, 0)
		}
		return b, "pk_p"
	case 6:
		c := b.CodeChallenge
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		i := strings.IndexByte(alphabet, c[42])
		b.CodeChallenge = pick(t, []string{c[:42], c + "A", c + "=", c[:42] + alphabet[i|0x03:i|0x03+1], c[:20] + "+" + c[21:]})
		if b.CodeChallenge == c {
			b.CodeChallenge = c[:42]
		}
		return b, "code_challenge"
	default:
		switch randomInt(t, 3) {
		case 0:
			b.Nonce = randomFrom(t, nonceAlphabet, 21)
		case 1:
			b.Nonce = randomFrom(t, nonceAlphabet, 129)
		default:
			b.Nonce = insert(b.Nonce[1:])
		}
		return b, "nonce"
	}
}

// otherBinding changes one field of b to another valid value: a different
// flow, which section 11.12's AAD tells apart.
func otherBinding(t *testing.T, b platform.KeyDeliveryBinding) (platform.KeyDeliveryBinding, string) {
	t.Helper()
	o := randomRequest(t)
	switch field := randomInt(t, 8); field {
	case 0:
		b.Issuer = b.Issuer + "/"
		return b, "iss"
	case 1:
		b.ClientID = b.ClientID + "-2"
		return b, "client_id"
	case 2:
		b.RedirectURI = b.RedirectURI + "/"
		return b, "redirect_uri"
	case 3:
		b.Sub = o.Sub
		return b, "sub"
	case 4:
		product, epoch, _ := strings.Cut(b.ProductKeyID, ":")
		if epoch == "1" {
			epoch = "2"
		} else {
			epoch = "1"
		}
		b.ProductKeyID = product + ":" + epoch
		return b, "product_key_id"
	case 5:
		b.ProductKey = randomBytes(t, 32)
		return b, "pk_p"
	case 6:
		b.CodeChallenge = o.CodeChallenge
		return b, "code_challenge"
	default:
		b.Nonce = o.Nonce
		return b, "nonce"
	}
}

// writePlatformDelivery writes platform-delivery-go.json: fresh key
// deliveries and PKCE cases of the platform profile (SPEC sections 11.12 and
// 11.13), for the TypeScript tests. Fresh seals draw their ephemeral key from
// the system and cannot be replayed in the other language, so every
// delivery is checked by opening it. Each case's outcome is first checked
// here.
func writePlatformDelivery(t *testing.T, dir string) {
	var cases []vcase
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	expect := func(id string, err error, want string) {
		t.Helper()
		if got := platform.ErrorCode(err); got != want || (err != nil && got == "") {
			t.Fatalf("%s: %q (%v), want %q", id, got, err, want)
		}
	}

	// The AAD, of valid bindings and of bindings with one field broken.
	for i := range 200 {
		b := randomRequest(t)
		b.ProductKeyID = platform.ProductKeyID(randomProduct(t), randomEpoch(t))
		b.ProductKey = randomBytes(t, 32)
		id := fmt.Sprintf("platform/key-delivery-aad/%d", i)
		c := vcase{ID: id, Op: "platform.key_delivery_aad"}
		if i%2 == 1 {
			var field string
			b, field = breakBinding(t, b)
			c.ID += "/refuses/" + field
		}
		c.In = bindingIn(b)
		aad, err := platform.KeyDeliveryAAD(b)
		if i%2 == 1 {
			expect(c.ID, err, "key_delivery")
			c.Error = "key_delivery"
		} else {
			must(err)
			c.Out = map[string]any{"aad": string(aad)}
		}
		cases = append(cases, c)
	}

	// Fresh deliveries, each also opened in another flow, by another
	// recipient and with a flipped bit.
	for i := range 24 {
		akd, err := ecdh.X25519().GenerateKey(nil)
		must(err)
		root, product, epoch := randomBytes(t, 32), randomProduct(t), randomEpoch(t)
		sk, pub, err := platform.ProductKey(root, product, epoch)
		must(err)
		b := randomRequest(t)
		b.ProductKeyID, b.ProductKey = platform.ProductKeyID(product, epoch), pub
		sealed, err := platform.SealProductKey(nil, akd.PublicKey().Bytes(), sk, b)
		must(err)
		id := fmt.Sprintf("platform/open-product-key/%d", i)
		got, err := platform.OpenProductKey(akd.Bytes(), sealed, b)
		if err != nil || !bytes.Equal(got, sk) {
			t.Fatalf("%s: %v", id, err)
		}
		in := withIn(bindingIn(b), map[string]any{"akd_priv_b64": b64(akd.Bytes()), "akd_sealed_b64": b64(sealed)})
		cases = append(cases, vcase{ID: id, Op: "platform.open_product_key", In: in, Out: map[string]any{"sk_b64": b64(sk)}})

		other, field := otherBinding(t, b)
		_, err = platform.OpenProductKey(akd.Bytes(), sealed, other)
		expect(id+"/other-"+field, err, "key_delivery")
		cases = append(cases, vcase{ID: id + "/refuses/other-" + field, Op: "platform.open_product_key",
			In: withIn(bindingIn(other), map[string]any{"akd_priv_b64": b64(akd.Bytes()), "akd_sealed_b64": b64(sealed)}), Error: "key_delivery"})

		stranger := randomBytes(t, 32)
		_, err = platform.OpenProductKey(stranger, sealed, b)
		expect(id+"/other-recipient", err, "key_delivery")
		cases = append(cases, vcase{ID: id + "/refuses/other-recipient", Op: "platform.open_product_key",
			In: withIn(in, map[string]any{"akd_priv_b64": b64(stranger)}), Error: "key_delivery"})

		flipped := bytes.Clone(sealed)
		bit := randomInt(t, int64(len(flipped)*8))
		flipped[bit/8] ^= 1 << (bit % 8)
		_, err = platform.OpenProductKey(akd.Bytes(), flipped, b)
		expect(id+"/flipped-bit", err, "key_delivery")
		cases = append(cases, vcase{ID: fmt.Sprintf("%s/refuses/flipped-bit-%d", id, bit), Op: "platform.open_product_key",
			In: withIn(in, map[string]any{"akd_sealed_b64": b64(flipped)}), Error: "key_delivery"})

		if i >= 4 {
			continue
		}
		// What a sealer that does not follow section 11.12 can make: enc
		// spelled with bit 255 set in the blob and the KEM context alike,
		// which RFC 9180 opens, and another key sealed under the binding,
		// which opens and is not pk_p. Both through the forger with the real
		// exchange.
		eph, err := ecdh.X25519().GenerateKey(nil)
		must(err)
		dh, err := eph.ECDH(akd.PublicKey())
		must(err)
		aad, err := platform.KeyDeliveryAAD(b)
		must(err)
		alias := eph.PublicKey().Bytes()
		alias[31] |= 0x80
		aliased := append(alias, forge.Seal(dh, alias, akd.PublicKey().Bytes(), []byte(platform.KeyDeliveryInfo), aad, sk)...)
		_, err = platform.OpenProductKey(akd.Bytes(), aliased, b)
		expect(id+"/aliased-enc", err, "key_delivery")
		cases = append(cases, vcase{ID: id + "/refuses/aliased-enc", Op: "platform.open_product_key",
			In: withIn(in, map[string]any{"akd_sealed_b64": b64(aliased)}), Error: "key_delivery"})

		wrong, _, err := platform.ProductKey(randomBytes(t, 32), product, epoch)
		must(err)
		enc := eph.PublicKey().Bytes()
		wrongSealed := append(enc, forge.Seal(dh, enc, akd.PublicKey().Bytes(), []byte(platform.KeyDeliveryInfo), aad, wrong)...)
		_, err = platform.OpenProductKey(akd.Bytes(), wrongSealed, b)
		expect(id+"/another-key", err, "product_key")
		cases = append(cases, vcase{ID: id + "/refuses/another-key", Op: "platform.open_product_key",
			In: withIn(in, map[string]any{"akd_sealed_b64": b64(wrongSealed)}), Error: "product_key"})
	}

	// The seal's refusals of akd_pub: every low-order encoding of the
	// forger, and a valid key spelled with bit 255 set.
	akd, err := ecdh.X25519().GenerateKey(nil)
	must(err)
	high := akd.PublicKey().Bytes()
	high[31] |= 0x80
	bad := []struct {
		name string
		pub  []byte
	}{{"bit-255", high}}
	for _, lo := range forge.LowOrder {
		bad = append(bad, struct {
			name string
			pub  []byte
		}{lo.Name, lo.Point})
	}
	for _, p := range bad {
		root, product, epoch := randomBytes(t, 32), randomProduct(t), randomEpoch(t)
		sk, pub, err := platform.ProductKey(root, product, epoch)
		must(err)
		b := randomRequest(t)
		b.ProductKeyID, b.ProductKey = platform.ProductKeyID(product, epoch), pub
		id := "platform/seal-product-key/refuses/" + p.name
		_, err = platform.SealProductKey(nil, p.pub, sk, b)
		expect(id, err, "key_delivery")
		cases = append(cases, vcase{ID: id, Op: "platform.seal_product_key", In: map[string]any{
			"root_b64": b64(root), "product": product, "epoch": epoch, "akd_pub_b64": b64(p.pub),
			"iss": b.Issuer, "client_id": b.ClientID, "redirect_uri": b.RedirectURI, "sub": b.Sub, "code_challenge": b.CodeChallenge, "nonce": b.Nonce,
		}, Error: "key_delivery"})
	}

	// PKCE: verifiers of every length the RFC allows, and malformed ones.
	for i := range 64 {
		v := randomVerifier(t)
		ch, err := platform.PKCEChallenge(v)
		must(err)
		cases = append(cases, vcase{ID: fmt.Sprintf("platform/pkce-challenge/%d", i), Op: "platform.pkce_challenge", In: map[string]any{"code_verifier": v}, Out: map[string]any{"code_challenge": ch}})
	}
	for i := range 32 {
		v := randomVerifier(t)
		switch randomInt(t, 3) {
		case 0:
			v = randomFrom(t, verifierAlphabet, int(randomInt(t, platform.MinCodeVerifierLen)))
		case 1:
			v = randomFrom(t, verifierAlphabet, platform.MaxCodeVerifierLen+1+int(randomInt(t, 64)))
		default:
			at := int(randomInt(t, int64(len(v))))
			v = v[:at] + pick(t, []string{"+", "/", "=", " ", "%7E", "é", "Ａ", "\n", "\x00", "!", "*"}) + v[at+1:]
		}
		_, err := platform.PKCEChallenge(v)
		expect(fmt.Sprintf("pkce %d", i), err, "pkce")
		cases = append(cases, vcase{ID: fmt.Sprintf("platform/pkce-challenge/refuses/%d", i), Op: "platform.pkce_challenge", In: map[string]any{"code_verifier": v}, Error: "pkce"})
	}

	writeProfile(t, dir, "platform-delivery-go.json", "platform", "platform", "Fresh cases of the platform profile's part 2 (SPEC sections 11.12 and 11.13) by the kit's Go, for the TypeScript tests: key-delivery AADs of random bindings, half with one field broken; fresh deliveries sealed by SealProductKey, each also opened in another flow, by another recipient and with a flipped bit, and a few blobs a sealer outside the rules can make (enc spelled with bit 255 set, which RFC 9180 opens; another key under the binding, which opens and is product_key), made with the real exchange; the seal's refusals of low-order and non-canonical akd_pub; and PKCE verifiers of every length, and malformed ones. A fresh seal's ephemeral key comes from the system, so deliveries are checked by opening.", nil, cases)
}
