package cross_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/thehappieco/kit/profiles/wappie"
)

// writeWappiePlatformWrap writes kit/wappie-platform-wrap-go.json: fresh
// platform wraps of Wappie's profile (SPEC section 6.8) by the kit's Go, for
// the TypeScript tests. Each has a random binding (an account created
// through id., whose user id is its sub, or a linked one with an older id;
// a random epoch), a random product key and account key (some with a first
// byte of zero), the nonce it drew, its info, AAD and K_pw; and each is
// also opened with one thing changed. Then seals refused for a binding or a
// key outside the rules.
func writeWappiePlatformWrap(t *testing.T, dir string) {
	var cases []vcase
	refused := func(id string, got []byte, err error) {
		t.Helper()
		if !errors.Is(err, wappie.ErrPlatformWrap) || got != nil {
			t.Fatalf("%s: want ErrPlatformWrap, got %v", id, err)
		}
	}
	public := func(key []byte) []byte {
		k, err := ecdh.X25519().NewPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return k.PublicKey().Bytes()
	}
	bindingIn := func(b wappie.PlatformWrapBinding) map[string]any {
		return map[string]any{"user_id": b.UserID, "sub": b.Sub, "product_key_id": b.ProductKeyID, "account_public_key_b64": b64(b.AccountPublicKey)}
	}
	newBinding := func(usk []byte) wappie.PlatformWrapBinding {
		sub := uuid.Must(uuid.NewV7()).String()
		userID := sub
		if randomInt(t, 2) == 0 {
			userID = uuid.New().String()
		}
		return wappie.PlatformWrapBinding{UserID: userID, Sub: sub, ProductKeyID: "wappie:" + strconv.Itoa(randomEpoch(t)), AccountPublicKey: public(usk)}
	}

	for i := range 32 {
		sk, usk := randomBytes(t, 32), randomBytes(t, 32)
		switch i % 8 {
		case 0:
			sk[0] = 0
		case 1:
			usk[0] = 0
		}
		b := newBinding(usk)
		id := fmt.Sprintf("wappie/platform-wrap/%d", i)
		var drawn bytes.Buffer
		w, err := wappie.SealPlatformWrap(io.TeeReader(rand.Reader, &drawn), sk, usk, b)
		if err != nil || drawn.Len() != 12 {
			t.Fatalf("%s: %v", id, err)
		}
		info := must[[]byte](t)(wappie.PlatformWrapInfo(b))
		aad := must[[]byte](t)(wappie.PlatformWrapAAD(b))
		// K_pw, computed here from section 6.8 and proved against the wrap.
		kpw := must[[]byte](t)(hkdf.Key(sha256.New, sk, []byte(wappie.PlatformWrapSalt), string(info), 32))
		block := must[cipher.Block](t)(aes.NewCipher(kpw))
		gcm := must[cipher.AEAD](t)(cipher.NewGCM(block))
		if !bytes.Equal(gcm.Seal([]byte{wappie.PlatformWrapHeader}, drawn.Bytes(), usk, aad), append([]byte{w[0]}, w[13:]...)) || !bytes.Equal(w[1:13], drawn.Bytes()) {
			t.Fatalf("%s: K_pw does not make the wrap", id)
		}
		if got, err := wappie.OpenPlatformWrap(sk, w, b); err != nil || !bytes.Equal(got, usk) {
			t.Fatalf("%s: does not open: %v", id, err)
		}
		in := bindingIn(b)
		cases = append(cases,
			vcase{ID: id + "/info", Op: "wappie.platform_wrap_info", In: in, Out: map[string]any{"info_b64": b64(info)}},
			vcase{ID: id + "/aad", Op: "wappie.platform_wrap_aad", In: in, Out: map[string]any{"aad_b64": b64(aad)}},
			vcase{ID: id + "/seal", Op: "wappie.platform_wrap_seal", In: withIn(in, map[string]any{"product_key_b64": b64(sk), "account_key_b64": b64(usk), "nonce_b64": b64(drawn.Bytes())}),
				Out: map[string]any{"wrap_b64": b64(w), "k_pw_b64": b64(kpw)}},
			vcase{ID: id + "/open", Op: "wappie.platform_wrap_open", In: withIn(in, map[string]any{"product_key_b64": b64(sk), "wrap_b64": b64(w)}), Out: map[string]any{"account_key_b64": b64(usk)}},
		)

		open := func(what string, sk, wrap []byte, b wappie.PlatformWrapBinding) {
			t.Helper()
			got, err := wappie.OpenPlatformWrap(sk, wrap, b)
			refused(id+"/"+what, got, err)
			cases = append(cases, vcase{ID: id + "/open/refuses/" + what, Op: "wappie.platform_wrap_open",
				In: withIn(bindingIn(b), map[string]any{"product_key_b64": b64(sk), "wrap_b64": b64(wrap)}), Error: "platform_wrap"})
		}
		flipped := bytes.Clone(w)
		bit := randomInt(t, int64(len(flipped)*8-8)) + 8
		flipped[bit/8] ^= 1 << (bit % 8)
		open(fmt.Sprintf("flipped-bit-%d", bit), sk, flipped, b)
		header := bytes.Clone(w)
		header[0] = []byte{0x00, 0x01, 0x02, 0x04, 0xff}[randomInt(t, 5)]
		open(fmt.Sprintf("header-0x%02x", header[0]), sk, header, b)
		if randomInt(t, 2) == 0 {
			open("length", sk, w[:wappie.PlatformWrapLen-1-int(randomInt(t, 3))], b)
		} else {
			open("length", sk, append(bytes.Clone(w), randomBytes(t, 1+int(randomInt(t, 3)))...), b)
		}
		open("other-product-key", randomBytes(t, 32), w, b)
		other := b
		other.UserID = uuid.New().String()
		open("other-user-id", sk, w, other)
		other = b
		other.Sub = uuid.Must(uuid.NewV7()).String()
		open("other-sub", sk, w, other)
		other = b
		for other.ProductKeyID == b.ProductKeyID {
			other.ProductKeyID = "wappie:" + strconv.Itoa(randomEpoch(t))
		}
		open("other-epoch", sk, w, other)
		other = b
		other.AccountPublicKey = public(randomBytes(t, 32))
		open("other-account-public-key", sk, w, other)
	}

	// Seals refused before anything is encrypted.
	for i := range 16 {
		sk, usk := randomBytes(t, 32), randomBytes(t, 32)
		b := newBinding(usk)
		var how string
		switch i % 8 {
		case 0:
			usk, how = randomBytes(t, 32), "account-key-not-the-public-keys"
		case 1:
			usk, how = usk[:31], "account-key-of-31-bytes"
		case 2:
			sk, how = append(sk, randomBytes(t, 1)...), "product-key-of-33-bytes"
		case 3:
			b.UserID, how = strings.ToUpper(b.UserID), "user-id-in-upper-case"
		case 4:
			b.Sub, how = "{"+b.Sub+"}", "sub-in-braces"
		case 5:
			b.ProductKeyID, how = []string{"mailie:1", "vaultie:2", "platform:1"}[randomInt(t, 3)], "another-products-key-id"
		case 6:
			b.ProductKeyID, how = []string{"wappie:0", "wappie:01", "wappie:2147483648", "wappie", "wappie:-1"}[randomInt(t, 5)], "epoch-out-of-range"
		case 7:
			b.AccountPublicKey, how = b.AccountPublicKey[:31], "account-public-key-of-31-bytes"
		}
		id := fmt.Sprintf("wappie/platform-wrap/seal/refuses/%d/%s", i, how)
		got, err := wappie.SealPlatformWrap(nil, sk, usk, b)
		refused(id, got, err)
		cases = append(cases, vcase{ID: id, Op: "wappie.platform_wrap_seal",
			In: withIn(bindingIn(b), map[string]any{"product_key_b64": b64(sk), "account_key_b64": b64(usk)}), Error: "platform_wrap"})
	}
	writeProfile(t, dir, "wappie-platform-wrap-go.json", "wappie.platform_wrap", "wappie", "Fresh platform wraps of the Wappie profile (SPEC section 6.8) by the kit's Go, for the TypeScript tests: 32 random bindings (an account created through id., whose user id is its sub, or a linked one; a random epoch), random product and account keys, some with a first byte of zero, each wrap with the nonce it drew, its info, AAD and K_pw (computed from the section and proved against the wrap), each also opened with one thing changed (a bit, the header, the length, the product key, the user id, the sub, the epoch, the account public key); and 16 seals refused for a key or a binding outside the rules.", nil, cases)
}
