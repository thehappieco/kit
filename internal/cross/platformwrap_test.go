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

	"github.com/thehappieco/kit/platformwrap"
	"github.com/thehappieco/kit/profiles/mailie"
	"github.com/thehappieco/kit/profiles/wappie"
)

// writeWappiePlatformWrap writes kit/wappie-platform-wrap-go.json: fresh
// platform wraps of Wappie's profile (SPEC section 6.8) by the kit's Go, for
// the TypeScript tests.
func writeWappiePlatformWrap(t *testing.T, dir string) {
	writePlatformWrap(t, dir, wappie.PlatformWrap(), "Wappie", []string{"mailie:1", "vaultie:2", "platform:1"}, nil)
}

// writeMailiePlatformWrap writes kit/mailie-platform-wrap-go.json: the same
// for Mailie's profile (SPEC Appendix D), and each wrap also refused under
// Wappie's labels.
func writeMailiePlatformWrap(t *testing.T, dir string) {
	w := wappie.PlatformWrap()
	writePlatformWrap(t, dir, mailie.PlatformWrap(), "Mailie", []string{"wappie:1", "vaultie:2", "platform:1"}, &w)
}

// writePlatformWrap writes kit/<product>-platform-wrap-go.json: fresh
// platform wraps under the profile p by the kit's Go. Each has a random
// binding (an account created through id., whose user id is its sub, or a
// linked one with an older id; a random epoch), a random product key and
// account key (some with a first byte of zero), the nonce it drew, its
// info, AAD and K_pw; and each is also opened with one thing changed, and,
// when other is set, under other's labels with the same key bytes and the
// binding's key id naming other's product (the op of other's product).
// Then seals refused for a binding or a key outside the rules; otherKeyIDs
// are product key ids of other products.
func writePlatformWrap(t *testing.T, dir string, p platformwrap.Profile, name string, otherKeyIDs []string, other *platformwrap.Profile) {
	var cases []vcase
	op := func(p platformwrap.Profile, what string) string { return p.Product + ".platform_wrap_" + what }
	refused := func(id string, got []byte, err error) {
		t.Helper()
		if !errors.Is(err, platformwrap.ErrPlatformWrap) || got != nil {
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
	bindingIn := func(b platformwrap.Binding) map[string]any {
		return map[string]any{"user_id": b.UserID, "sub": b.Sub, "product_key_id": b.ProductKeyID, "account_public_key_b64": b64(b.AccountPublicKey)}
	}
	newBinding := func(usk []byte) platformwrap.Binding {
		sub := uuid.Must(uuid.NewV7()).String()
		userID := sub
		if randomInt(t, 2) == 0 {
			userID = uuid.New().String()
		}
		return platformwrap.Binding{UserID: userID, Sub: sub, ProductKeyID: p.Product + ":" + strconv.Itoa(randomEpoch(t)), AccountPublicKey: public(usk)}
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
		id := fmt.Sprintf("%s/platform-wrap/%d", p.Product, i)
		var drawn bytes.Buffer
		w, err := platformwrap.Seal(p, io.TeeReader(rand.Reader, &drawn), sk, usk, b)
		if err != nil || drawn.Len() != 12 {
			t.Fatalf("%s: %v", id, err)
		}
		info := must[[]byte](t)(platformwrap.Info(p, b))
		aad := must[[]byte](t)(platformwrap.AAD(p, b))
		// K_pw, computed here from section 6.8 and proved against the wrap.
		kpw := must[[]byte](t)(hkdf.Key(sha256.New, sk, []byte(p.Salt), string(info), 32))
		block := must[cipher.Block](t)(aes.NewCipher(kpw))
		gcm := must[cipher.AEAD](t)(cipher.NewGCM(block))
		if !bytes.Equal(gcm.Seal([]byte{platformwrap.Header}, drawn.Bytes(), usk, aad), append([]byte{w[0]}, w[13:]...)) || !bytes.Equal(w[1:13], drawn.Bytes()) {
			t.Fatalf("%s: K_pw does not make the wrap", id)
		}
		if got, err := platformwrap.Open(p, sk, w, b); err != nil || !bytes.Equal(got, usk) {
			t.Fatalf("%s: does not open: %v", id, err)
		}
		in := bindingIn(b)
		cases = append(cases,
			vcase{ID: id + "/info", Op: op(p, "info"), In: in, Out: map[string]any{"info_b64": b64(info)}},
			vcase{ID: id + "/aad", Op: op(p, "aad"), In: in, Out: map[string]any{"aad_b64": b64(aad)}},
			vcase{ID: id + "/seal", Op: op(p, "seal"), In: withIn(in, map[string]any{"product_key_b64": b64(sk), "account_key_b64": b64(usk), "nonce_b64": b64(drawn.Bytes())}),
				Out: map[string]any{"wrap_b64": b64(w), "k_pw_b64": b64(kpw)}},
			vcase{ID: id + "/open", Op: op(p, "open"), In: withIn(in, map[string]any{"product_key_b64": b64(sk), "wrap_b64": b64(w)}), Out: map[string]any{"account_key_b64": b64(usk)}},
		)

		openUnder := func(q platformwrap.Profile, what string, sk, wrap []byte, b platformwrap.Binding) {
			t.Helper()
			got, err := platformwrap.Open(q, sk, wrap, b)
			refused(id+"/"+what, got, err)
			cases = append(cases, vcase{ID: id + "/open/refuses/" + what, Op: op(q, "open"),
				In: withIn(bindingIn(b), map[string]any{"product_key_b64": b64(sk), "wrap_b64": b64(wrap)}), Error: "platform_wrap"})
		}
		open := func(what string, sk, wrap []byte, b platformwrap.Binding) {
			t.Helper()
			openUnder(p, what, sk, wrap, b)
		}
		flipped := bytes.Clone(w)
		bit := randomInt(t, int64(len(flipped)*8-8)) + 8
		flipped[bit/8] ^= 1 << (bit % 8)
		open(fmt.Sprintf("flipped-bit-%d", bit), sk, flipped, b)
		header := bytes.Clone(w)
		header[0] = []byte{0x00, 0x01, 0x02, 0x04, 0xff}[randomInt(t, 5)]
		open(fmt.Sprintf("header-0x%02x", header[0]), sk, header, b)
		if randomInt(t, 2) == 0 {
			open("length", sk, w[:platformwrap.Len-1-int(randomInt(t, 3))], b)
		} else {
			open("length", sk, append(bytes.Clone(w), randomBytes(t, 1+int(randomInt(t, 3)))...), b)
		}
		open("other-product-key", randomBytes(t, 32), w, b)
		changed := b
		changed.UserID = uuid.New().String()
		open("other-user-id", sk, w, changed)
		changed = b
		changed.Sub = uuid.Must(uuid.NewV7()).String()
		open("other-sub", sk, w, changed)
		changed = b
		for changed.ProductKeyID == b.ProductKeyID {
			changed.ProductKeyID = p.Product + ":" + strconv.Itoa(randomEpoch(t))
		}
		open("other-epoch", sk, w, changed)
		changed = b
		changed.AccountPublicKey = public(randomBytes(t, 32))
		open("other-account-public-key", sk, w, changed)
		if other != nil {
			changed = b
			_, epoch, _ := strings.Cut(b.ProductKeyID, ":")
			changed.ProductKeyID = other.Product + ":" + epoch
			openUnder(*other, "under-"+other.Product+"s-labels", sk, w, changed)
		}
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
			b.ProductKeyID, how = otherKeyIDs[randomInt(t, int64(len(otherKeyIDs)))], "another-products-key-id"
		case 6:
			b.ProductKeyID, how = []string{p.Product + ":0", p.Product + ":01", p.Product + ":2147483648", p.Product, p.Product + ":-1"}[randomInt(t, 5)], "epoch-out-of-range"
		case 7:
			b.AccountPublicKey, how = b.AccountPublicKey[:31], "account-public-key-of-31-bytes"
		}
		id := fmt.Sprintf("%s/platform-wrap/seal/refuses/%d/%s", p.Product, i, how)
		got, err := platformwrap.Seal(p, nil, sk, usk, b)
		refused(id, got, err)
		cases = append(cases, vcase{ID: id, Op: op(p, "seal"),
			In: withIn(bindingIn(b), map[string]any{"product_key_b64": b64(sk), "account_key_b64": b64(usk)}), Error: "platform_wrap"})
	}
	crossNote := ""
	if other != nil {
		crossNote = fmt.Sprintf(", and under %s's labels with the same key bytes and the key id of %s's product (op %s)", other.Product, other.Product, op(*other, "open"))
	}
	writeProfile(t, dir, p.Product+"-platform-wrap-go.json", p.Product+".platform_wrap", p.Product, "Fresh platform wraps of the "+name+" profile (SPEC section 6.8) by the kit's Go, for the TypeScript tests: 32 random bindings (an account created through id., whose user id is its sub, or a linked one; a random epoch), random product and account keys, some with a first byte of zero, each wrap with the nonce it drew, its info, AAD and K_pw (computed from the section and proved against the wrap), each also opened with one thing changed (a bit, the header, the length, the product key, the user id, the sub, the epoch, the account public key)"+crossNote+"; and 16 seals refused for a key or a binding outside the rules.", nil, cases)
}
