package cross_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/thehappieco/kit/internal/forge"
	"github.com/thehappieco/kit/profiles/platform"
)

// randomBytes is n bytes from crypto/rand.
func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func randomInt(t *testing.T, n int64) int64 {
	t.Helper()
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		t.Fatal(err)
	}
	return v.Int64()
}

// passwordBlocks are ranges of code points assigned long before Unicode
// 15.0, whose normalisation is the same in Go's tables (15.0 below Go 1.27,
// 17.0 from it) and in ICU's: letters with and without precomposed forms,
// combining marks, Hangul jamo and syllables, spacing marks, CJK, emoji, and
// the spaces the profile maps.
var passwordBlocks = [][2]rune{
	{'a', 'z'}, {'A', 'Z'}, {'0', '9'}, {' ', '~'},
	{0x00c0, 0x00ff}, {0x0100, 0x017f}, {0x0300, 0x034e}, {0x0391, 0x03c9},
	{0x0410, 0x044f}, {0x0905, 0x0939}, {0x093e, 0x094c}, {0x1100, 0x1112},
	{0x1161, 0x1175}, {0x11a8, 0x11c2}, {0xac00, 0xd7a3}, {0x4e00, 0x9fa5},
	{0x2000, 0x200a}, {0x00a0, 0x00a0}, {0x3000, 0x3000}, {0x1f600, 0x1f64f},
}

func randomPassword(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for n := 12 + randomInt(t, 30); n > 0; n-- {
		r := passwordBlocks[randomInt(t, int64(len(passwordBlocks)))]
		b.WriteRune(r[0] + rune(randomInt(t, int64(r[1]-r[0]+1))))
	}
	return b.String()
}

// writePlatform writes platform-go.json: fresh cases of the platform profile
// (SPEC section 11) in the kit's format, for the TypeScript tests to
// reproduce.
func writePlatform(t *testing.T, dir string) {
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	var cases []vcase
	code := func(err error) string {
		t.Helper()
		c := platform.ErrorCode(err)
		if c == "" {
			t.Fatalf("an error outside the protocol's names: %v", err)
		}
		return c
	}

	// The password profile, on random text and on a few fixed refusals.
	inputs := []struct {
		pw    string
		isNew bool
	}{
		{"a\u0301" + strings.Repeat("\u0323", 29) + "bcdefghijk", true},
		{"a" + strings.Repeat("\u0301", 31), false},
		{"\u1100\u1161\u11a8 \u212bngstr\u00f6m\u00a0\u3000", false},
		{"short", true},
		{"pass\u0085word-1234", false},
	}
	for range 12 {
		inputs = append(inputs, struct {
			pw    string
			isNew bool
		}{randomPassword(t), randomInt(t, 2) == 1})
	}
	for i, in := range inputs {
		prepare := platform.PreparePassword
		if in.isNew {
			prepare = platform.PrepareNewPassword
		}
		c := vcase{ID: fmt.Sprintf("platform/prepare-password/%d", i), Op: "platform.prepare_password", In: map[string]any{"password": in.pw, "new": in.isNew}}
		if p, err := prepare(in.pw); err != nil {
			c.Error = code(err)
		} else {
			c.Out = map[string]any{"prepared_b64": b64(p)}
		}
		cases = append(cases, c)
	}

	// The KDF at the floor and with four lanes, and a refusal.
	for i, k := range []platform.KDF{platform.DefaultKDF, {Alg: "argon2id", M: 65536, T: 3, P: 4}} {
		prepared, err := platform.PrepareNewPassword(randomPassword(t))
		must(err)
		salt := randomBytes(t, platform.SaltLen)
		keys, err := platform.DerivePassword(prepared, salt, k)
		must(err)
		cases = append(cases, vcase{ID: fmt.Sprintf("platform/derive-password/%d", i), Op: "platform.derive_password",
			In:  map[string]any{"prepared_b64": b64(prepared), "salt_b64": b64(salt), "kdf": k},
			Out: map[string]any{"auth_key": keys.AuthKey(), "wrap_b64": b64(keys.Wrap[:])}})
	}
	cases = append(cases, vcase{ID: "platform/derive-password/refuses/m-32768", Op: "platform.derive_password",
		In:    map[string]any{"prepared_b64": b64([]byte("x")), "salt_b64": b64(randomBytes(t, 16)), "kdf": platform.KDF{Alg: "argon2id", M: 32768, T: 3, P: 1}},
		Error: "kdf_policy"})

	// Root wraps of each kind, with the nonce they drew.
	for _, kind := range []platform.WrapKind{platform.WrapPassword, platform.WrapRecovery, platform.WrapPasskey} {
		sub := uuid.Must(uuid.NewV7()).String()
		b := platform.Binding{Sub: sub, Epoch: 1 + int(randomInt(t, platform.MaxEpoch))}
		if kind == platform.WrapPasskey {
			b.RPID, b.CredentialID = "id.thehappie.co", platform.EncodeB64(randomBytes(t, 16))
		}
		key, root, nonce := randomBytes(t, 32), randomBytes(t, 32), randomBytes(t, 12)
		aad, err := platform.WrapAAD(kind, b)
		must(err)
		wrap, err := platform.Wrap(bytes.NewReader(nonce), kind, key, root, b)
		must(err)
		in := map[string]any{"kind": kind.String(), "key_b64": b64(key), "root_b64": b64(root), "sub": b.Sub, "epoch": b.Epoch, "nonce_b64": b64(nonce)}
		if kind == platform.WrapPasskey {
			in["rp_id"], in["credential_id"] = b.RPID, b.CredentialID
		}
		cases = append(cases, vcase{ID: "platform/root-wrap/" + kind.String(), Op: "platform.root_wrap", In: in, Out: map[string]any{"aad": string(aad), "wrap_b64": b64(wrap)}})
		other := map[string]any{"kind": kind.String(), "key_b64": b64(key), "sub": uuid.Must(uuid.NewV7()).String(), "epoch": b.Epoch, "wrap_b64": b64(wrap)}
		if kind == platform.WrapPasskey {
			other["rp_id"], other["credential_id"] = b.RPID, b.CredentialID
		}
		cases = append(cases, vcase{ID: "platform/root-wrap/" + kind.String() + "/other-sub", Op: "platform.open_root_wrap", In: other, Error: "wrap"})
	}

	// Recovery codes from their bytes, read back as a person types them.
	for i := range 2 {
		raw := randomBytes(t, platform.RecoveryCodeLen)
		c, err := platform.RecoveryCodeFromBytes(raw)
		must(err)
		display, err := platform.DisplayRecoveryCode(c)
		must(err)
		keys, err := platform.DeriveRecovery(c)
		must(err)
		cases = append(cases, vcase{ID: fmt.Sprintf("platform/recovery-code/%d", i), Op: "platform.recovery_code",
			In:  map[string]any{"random_b64": b64(raw), "typed": strings.ToLower(strings.ReplaceAll(display, "-", " "))},
			Out: map[string]any{"canonical": c, "display": display, "wrap_b64": b64(keys.Wrap[:]), "recovery_auth": keys.RecoveryAuth()}})
	}
	cases = append(cases, vcase{ID: "platform/recovery-code/refuses/u", Op: "platform.recovery_code",
		In: map[string]any{"typed": "U" + strings.Repeat("0", 29)}, Error: "recovery_code"})

	// Product keys, and the server's refusal of low-order keys.
	for i, product := range []string{"wappie", "a-future-product"} {
		root, epoch := randomBytes(t, 32), 1+int(randomInt(t, platform.MaxEpoch))
		sk, pub, err := platform.ProductKey(root, product, epoch)
		must(err)
		must(platform.CheckPublicKey(pub))
		cases = append(cases, vcase{ID: fmt.Sprintf("platform/product-key/%d", i), Op: "platform.product_key",
			In:  map[string]any{"root_b64": b64(root), "product": product, "epoch": epoch},
			Out: map[string]any{"sk_b64": b64(sk), "pub_b64": b64(pub), "product_key_id": platform.ProductKeyID(product, epoch)}})
		cases = append(cases, vcase{ID: fmt.Sprintf("platform/check-public-key/%d", i), Op: "platform.check_public_key", Langs: []string{"go"},
			In: map[string]any{"pub_b64": b64(pub)}, Out: map[string]any{"valid": true}})
	}
	for _, lo := range forge.LowOrder {
		if err := platform.CheckPublicKey(lo.Point); !errors.Is(err, platform.ErrProductKey) {
			t.Fatalf("%s: %v", lo.Name, err)
		}
		cases = append(cases, vcase{ID: "platform/check-public-key/refuses/" + lo.Name, Op: "platform.check_public_key", Langs: []string{"go"},
			In: map[string]any{"pub_b64": b64(lo.Point)}, Error: "product_key"})
	}

	// Verifiers.
	for i, recovery := range []bool{false, true} {
		sub, key := uuid.Must(uuid.NewV7()).String(), randomBytes(t, 32)
		c := vcase{ID: fmt.Sprintf("platform/verifier/%d", i), Op: "platform.verifier"}
		if recovery {
			v, err := platform.RecoveryVerifier(sub, key)
			must(err)
			c.In, c.Out = map[string]any{"sub": sub, "r_proof_b64": b64(key)}, map[string]any{"recovery_verifier_b64": b64(v[:])}
		} else {
			v, err := platform.AuthVerifier(sub, key)
			must(err)
			c.In, c.Out = map[string]any{"sub": sub, "k_auth_b64": b64(key)}, map[string]any{"auth_verifier_b64": b64(v[:])}
		}
		cases = append(cases, c)
	}

	// Email normalisation.
	for i, in := range []string{" Ana.Silva+Kit@Example.COM\r\n", "x@" + strings.Repeat("d", 63) + ".io", "ana@192.168.0.1", "\u212aate@example.com"} {
		c := vcase{ID: fmt.Sprintf("platform/normalize-email/%d", i), Op: "platform.normalize_email", In: map[string]any{"input": in}}
		if e, err := platform.NormalizeEmail(in); err != nil {
			c.Error = code(err)
		} else {
			c.Out = map[string]any{"email_norm": e}
		}
		cases = append(cases, c)
	}

	// A key bundle, opened with the password and with the recovery code.
	root, salt, sub := randomBytes(t, 32), randomBytes(t, 16), uuid.Must(uuid.NewV7()).String()
	password := randomPassword(t)
	prepared, err := platform.PrepareNewPassword(password)
	must(err)
	keys, err := platform.DerivePassword(prepared, salt, platform.DefaultKDF)
	must(err)
	b := platform.Binding{Sub: sub, Epoch: 1}
	pw, err := platform.Wrap(nil, platform.WrapPassword, keys.Wrap[:], root, b)
	must(err)
	recoveryCode, err := platform.NewRecoveryCode(nil)
	must(err)
	rkeys, err := platform.DeriveRecovery(recoveryCode)
	must(err)
	rw, err := platform.Wrap(nil, platform.WrapRecovery, rkeys.Wrap[:], root, b)
	must(err)
	var productKeys []platform.ProductPublicKey
	for _, p := range []string{"mailie", "wappie"} {
		_, pub, err := platform.ProductKey(root, p, 1)
		must(err)
		productKeys = append(productKeys, platform.ProductPublicKey{Product: p, Epoch: 1, Pub: platform.EncodeB64(pub)})
	}
	bundle, err := platform.MarshalKeyBundle(platform.KeyBundle{
		Format: platform.KeyBundleFormat, Version: platform.KeyBundleVersion, Issuer: "https://id.thehappie.co", Sub: sub,
		Email: "ana@example.com", AccountKeyEpoch: 1, KDF: platform.DefaultKDF, KDFSalt: platform.EncodeB64(salt),
		PasswordWrap: platform.EncodeB64(pw), RecoveryWrap: platform.EncodeB64(rw), ProductKeys: productKeys,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	must(err)
	cases = append(cases,
		vcase{ID: "platform/key-bundle/password", Op: "platform.key_bundle", In: map[string]any{"bundle_text": string(bundle), "password": password}, Out: map[string]any{"root_b64": b64(root)}},
		vcase{ID: "platform/key-bundle/recovery-code", Op: "platform.key_bundle", In: map[string]any{"bundle_text": string(bundle), "recovery_code": recoveryCode}, Out: map[string]any{"root_b64": b64(root)}},
		vcase{ID: "platform/key-bundle/other-code", Op: "platform.key_bundle", In: map[string]any{"bundle_text": string(bundle), "recovery_code": strings.Repeat("7", 30)}, Error: "wrap"},
	)
	writeProfile(t, dir, "platform-go.json", "platform", "platform", "Fresh cases of the platform profile (SPEC section 11) by the kit's Go, for the TypeScript tests: random passwords from blocks whose normalisation is stable since Unicode 15.0, derivations, root wraps with the nonce they drew, recovery codes with the bytes they came from, product keys, verifiers, addresses and a key bundle. The check_public_key cases are the server's, for Go only.", nil, cases)
}
