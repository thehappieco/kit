package platform_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thehappieco/kit/profiles/platform"
)

// testAccount is an account built the way the page builds one at sign-up,
// with testPassword. Neither is a secret.
type testAccount struct {
	root         []byte
	salt         []byte
	passwordWrap []byte
	recoveryWrap []byte
	recoveryCode string
	productKeys  []platform.ProductPublicKey
}

func newTestAccount(t testing.TB) testAccount {
	t.Helper()
	root, err := platform.NewRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	salt := testBytes(platform.SaltLen, 0x5a)
	prepared, err := platform.PrepareNewPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := platform.DerivePassword(prepared, salt, platform.DefaultKDF)
	if err != nil {
		t.Fatal(err)
	}
	b := platform.Binding{Sub: testSub, Epoch: 1}
	pw, err := platform.Wrap(nil, platform.WrapPassword, keys.Wrap[:], root, b)
	if err != nil {
		t.Fatal(err)
	}
	code, err := platform.NewRecoveryCode(nil)
	if err != nil {
		t.Fatal(err)
	}
	rkeys, err := platform.DeriveRecovery(code)
	if err != nil {
		t.Fatal(err)
	}
	rw, err := platform.Wrap(nil, platform.WrapRecovery, rkeys.Wrap[:], root, b)
	if err != nil {
		t.Fatal(err)
	}
	display, err := platform.DisplayRecoveryCode(code)
	if err != nil {
		t.Fatal(err)
	}
	return testAccount{root: root, salt: salt, passwordWrap: pw, recoveryWrap: rw, recoveryCode: display,
		productKeys: productPublicKeys(t, root, 1, testProducts...)}
}

func (a testAccount) bundle() platform.KeyBundle {
	return platform.KeyBundle{
		Format:          platform.KeyBundleFormat,
		Version:         platform.KeyBundleVersion,
		Issuer:          "http://id.localhost:8290",
		Sub:             testSub,
		Email:           "ana@example.com",
		AccountKeyEpoch: 1,
		KDF:             platform.DefaultKDF,
		KDFSalt:         platform.EncodeB64(a.salt),
		PasswordWrap:    platform.EncodeB64(a.passwordWrap),
		RecoveryWrap:    platform.EncodeB64(a.recoveryWrap),
		ProductKeys:     a.productKeys,
		CreatedAt:       time.Date(2026, 10, 1, 9, 30, 15, 123, time.FixedZone("BRT", -3*3600)).Format(time.RFC3339Nano),
	}
}

// marshalUnchecked writes a bundle as MarshalKeyBundle would, without
// refusing what Validate refuses.
func marshalUnchecked(t testing.TB, b platform.KeyBundle) []byte {
	t.Helper()
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

func TestAKeyBundleOpensWithThePasswordAndWithTheRecoveryCode(t *testing.T) {
	a := newTestAccount(t)
	data, err := platform.MarshalKeyBundle(a.bundle())
	if err != nil {
		t.Fatal(err)
	}
	root, b, err := platform.OpenKeyBundle(data, testPassword)
	if err != nil {
		t.Fatalf("with the password: %v", err)
	}
	if !bytes.Equal(root, a.root) || b.Sub != testSub {
		t.Fatal("the password opened another root")
	}
	root, _, err = platform.OpenKeyBundleWithRecoveryCode(data, a.recoveryCode)
	if err != nil {
		t.Fatalf("with the recovery code: %v", err)
	}
	if !bytes.Equal(root, a.root) {
		t.Fatal("the recovery code opened another root")
	}
	if _, _, err := platform.OpenKeyBundle(data, testPassword+" "); !errors.Is(err, platform.ErrWrap) {
		t.Fatalf("a wrong password: %v, want ErrWrap", err)
	}
}

func TestMarshalKeyBundleWritesSortedKeysAndUTCSecondsAndParsesBack(t *testing.T) {
	a := newTestAccount(t)
	in := a.bundle()
	in.ProductKeys = []platform.ProductPublicKey{a.productKeys[1], a.productKeys[0]}
	data, err := platform.MarshalKeyBundle(in)
	if err != nil {
		t.Fatal(err)
	}
	if in.ProductKeys[0].Product != "wappie" {
		t.Fatal("MarshalKeyBundle reordered the caller's slice")
	}
	if !bytes.HasSuffix(data, []byte("}\n")) || !bytes.Contains(data, []byte("\n  \"format\"")) {
		t.Fatal("not 2-space indented JSON with a trailing newline")
	}
	b, err := platform.ParseKeyBundle(data)
	if err != nil {
		t.Fatal(err)
	}
	if b.CreatedAt != "2026-10-01T12:30:15Z" {
		t.Fatalf("created_at %q", b.CreatedAt)
	}
	if b.ProductKeys[0].Product != "mailie" || b.ProductKeys[1].Product != "wappie" {
		t.Fatal("product keys not sorted")
	}
	again, err := platform.MarshalKeyBundle(*b)
	if err != nil || !bytes.Equal(again, data) {
		t.Fatalf("marshal, parse, marshal is not stable: %v", err)
	}
}

func TestAKeyBundleWithAProductKeyThatDoesNotMatchTheRootDoesNotOpen(t *testing.T) {
	a := newTestAccount(t)
	b := a.bundle()
	other := productPublicKeys(t, testBytes(32, 0x77), 1, testProducts...)
	b.ProductKeys = []platform.ProductPublicKey{a.productKeys[0], other[1]}
	data, err := platform.MarshalKeyBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	if root, _, err := platform.OpenKeyBundleWithRecoveryCode(data, a.recoveryCode); !errors.Is(err, platform.ErrProductKey) || root != nil {
		t.Fatalf("got %v, want ErrProductKey and no root", err)
	}
}

func TestABundleDownloadedBeforeARecoveryCodeChangeStillOpensWithTheOldCode(t *testing.T) {
	// The honest limit of section 11.9: the root does not change, so an old
	// bundle keeps opening with the credential it was downloaded under.
	a := newTestAccount(t)
	old, err := platform.MarshalKeyBundle(a.bundle())
	if err != nil {
		t.Fatal(err)
	}
	newCode, err := platform.NewRecoveryCode(nil)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := platform.DeriveRecovery(newCode)
	if err != nil {
		t.Fatal(err)
	}
	rw, err := platform.Wrap(nil, platform.WrapRecovery, keys.Wrap[:], a.root, platform.Binding{Sub: testSub, Epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	b := a.bundle()
	b.RecoveryWrap = platform.EncodeB64(rw)
	current, err := platform.MarshalKeyBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := platform.OpenKeyBundleWithRecoveryCode(old, a.recoveryCode); err != nil {
		t.Fatalf("the old bundle with the old code: %v", err)
	}
	if _, _, err := platform.OpenKeyBundleWithRecoveryCode(current, a.recoveryCode); !errors.Is(err, platform.ErrWrap) {
		t.Fatalf("the current bundle with the old code: %v", err)
	}
	if _, _, err := platform.OpenKeyBundleWithRecoveryCode(current, newCode); err != nil {
		t.Fatalf("the current bundle with the new code: %v", err)
	}
}

func TestParseKeyBundleIsStrict(t *testing.T) {
	a := newTestAccount(t)
	good, err := platform.MarshalKeyBundle(a.bundle())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := platform.ParseKeyBundle(good); err != nil {
		t.Fatal(err)
	}
	text := string(good)
	edits := map[string]string{
		"a duplicate member":         strings.Replace(text, `"version": 1,`, `"version": 1, "version": 1,`, 1),
		"a member in another case":   strings.Replace(text, `"issuer"`, `"Issuer"`, 1),
		"a fractional version":       strings.Replace(text, `"version": 1,`, `"version": 1.0,`, 1),
		"an exponent epoch":          strings.Replace(text, `"account_key_epoch": 1,`, `"account_key_epoch": 1e0,`, 1),
		"a string epoch":             strings.Replace(text, `"account_key_epoch": 1,`, `"account_key_epoch": "1",`, 1),
		"an extra kdf member":        strings.Replace(text, `"alg": "argon2id",`, `"alg": "argon2id", "v": 19,`, 1),
		"an m beyond uint32":         strings.Replace(text, `"m": 65536,`, `"m": 4294967296,`, 1),
		"a negative t":               strings.Replace(text, `"t": 3,`, `"t": -3,`, 1),
		"a trailing value":           text + "{}",
		"a byte order mark":          "\ufeff" + text,
		"a created_at that is not":   strings.Replace(text, `"created_at": "`, `"created_at": "yesterday`, 1),
		"an empty issuer":            strings.Replace(text, `"issuer": "http://id.localhost:8290"`, `"issuer": ""`, 1),
		"an extra product key field": strings.Replace(text, `"product": "mailie",`, `"product": "mailie", "kid": "x",`, 1),
		"a product key epoch 0":      strings.Replace(text, `"epoch": 1,`, `"epoch": 0,`, 1),
		"an invalid product id":      strings.Replace(text, `"product": "mailie"`, `"product": "Mailie"`, 1),
		"a huge file":                strings.Replace(text, `"issuer": "`, `"issuer": "`+strings.Repeat("a", 70000), 1),
	}
	for name, f := range map[string]func(map[string]json.RawMessage){
		"a null kdf":            func(m map[string]json.RawMessage) { m["kdf"] = json.RawMessage(`null`) },
		"a null product_keys":   func(m map[string]json.RawMessage) { m["product_keys"] = json.RawMessage(`null`) },
		"a kdf array":           func(m map[string]json.RawMessage) { m["kdf"] = json.RawMessage(`[]`) },
		"product keys as a map": func(m map[string]json.RawMessage) { m["product_keys"] = json.RawMessage(`{}`) },
		"a null sub":            func(m map[string]json.RawMessage) { m["sub"] = json.RawMessage(`null`) },
		"a numeric email":       func(m map[string]json.RawMessage) { m["email"] = json.RawMessage(`1`) },
	} {
		m := map[string]json.RawMessage{}
		if err := json.Unmarshal(good, &m); err != nil {
			t.Fatal(err)
		}
		f(m)
		edited, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		edits[name] = string(edited)
	}
	for name, edited := range edits {
		if edited == text {
			t.Fatalf("%s: the edit did not apply", name)
		}
		if _, err := platform.ParseKeyBundle([]byte(edited)); !errors.Is(err, platform.ErrBundle) && !errors.Is(err, platform.ErrKDFPolicy) {
			t.Errorf("%s: %v, want a refusal", name, err)
		}
	}
	// encoding/json would have read every one of these without complaint
	// into the struct; the strict reader is what refuses them.
	var lax platform.KeyBundle
	if err := json.Unmarshal([]byte(edits["a member in another case"]), &lax); err != nil || lax.Issuer == "" {
		t.Fatal("fixture: encoding/json no longer matches member names case-insensitively")
	}
}

func TestMarshalKeyBundleRefusesAnInvalidBundle(t *testing.T) {
	a := newTestAccount(t)
	for name, f := range map[string]func(*platform.KeyBundle){
		"no product keys":  func(b *platform.KeyBundle) { b.ProductKeys = nil },
		"a bad created_at": func(b *platform.KeyBundle) { b.CreatedAt = "2026-10-01" },
		"a repeated key":   func(b *platform.KeyBundle) { b.ProductKeys = append(b.ProductKeys, b.ProductKeys[0]) },
		"swapped wraps":    func(b *platform.KeyBundle) { b.PasswordWrap, b.RecoveryWrap = b.RecoveryWrap, b.PasswordWrap },
		"another format":   func(b *platform.KeyBundle) { b.Format = "x" },
	} {
		b := a.bundle()
		f(&b)
		if _, err := platform.MarshalKeyBundle(b); !errors.Is(err, platform.ErrBundle) {
			t.Errorf("%s: %v, want ErrBundle", name, err)
		}
	}
	b := a.bundle()
	b.KDF.T = 2
	if _, err := platform.MarshalKeyBundle(b); !errors.Is(err, platform.ErrKDFPolicy) {
		t.Errorf("kdf below the floor: %v, want ErrKDFPolicy", err)
	}
}
