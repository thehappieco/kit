//go:build go1.26

package idvectors

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/thehappieco/platform/internal/crypto/idcrypto"
)

// KeyBundleCase is one key-bundle vector (spec 2.9). It gives a bundle and
// exactly one credential: Password or RecoveryCode. The bundle is either
// Bundle, a JSON value, or BundleText, the exact text of the file, for what a
// parsed value cannot carry: a repeated member, the spelling of a number, a
// byte order mark. A reader that is handed Bundle may also be tested on its
// text. A good case opens to Root, after every listed product key was
// checked against it.
type KeyBundleCase struct {
	Name         string          `json:"name"`
	Password     *string         `json:"password,omitempty"`
	RecoveryCode *string         `json:"recovery_code,omitempty"`
	Bundle       json.RawMessage `json:"bundle,omitempty"`
	BundleText   *string         `json:"bundle_text,omitempty"`
	Root         string          `json:"root,omitempty"`
	Error        string          `json:"error,omitempty"`
}

// The test password of the key-bundle vectors. It is not a secret.
const bundlePassword = "correct horse battery staple"

func keyBundleCases() ([]KeyBundleCase, error) {
	root := seeded("key-bundle/root", idcrypto.KeyLen)
	sub := uuid7("key-bundle")
	b := idcrypto.Binding{Sub: sub, Epoch: 1}
	salt := seeded("key-bundle/salt", idcrypto.SaltLen)

	prepared, err := idcrypto.PrepareNewPassword(bundlePassword)
	if err != nil {
		return nil, err
	}
	keys, err := idcrypto.DerivePassword(prepared, salt, idcrypto.DefaultKDF)
	if err != nil {
		return nil, err
	}
	passwordWrap, err := idcrypto.Wrap(bytes.NewReader(seeded("key-bundle/password-nonce", 12)), idcrypto.WrapPassword, keys.Wrap[:], root, b)
	keys.Zero()
	if err != nil {
		return nil, err
	}
	code, err := idcrypto.RecoveryCodeFromBytes(seeded("key-bundle/recovery-code", 30))
	if err != nil {
		return nil, err
	}
	display, err := idcrypto.DisplayRecoveryCode(code)
	if err != nil {
		return nil, err
	}
	rkeys, err := idcrypto.DeriveRecovery(code)
	if err != nil {
		return nil, err
	}
	recoveryWrap, err := idcrypto.Wrap(bytes.NewReader(seeded("key-bundle/recovery-nonce", 12)), idcrypto.WrapRecovery, rkeys.Wrap[:], root, b)
	rkeys.Zero()
	if err != nil {
		return nil, err
	}
	productKeys, err := idcrypto.ProductPublicKeys(root, 1)
	if err != nil {
		return nil, err
	}
	good := idcrypto.KeyBundle{
		Format:          idcrypto.KeyBundleFormat,
		Version:         idcrypto.KeyBundleVersion,
		Issuer:          "https://id.thehappie.co",
		Sub:             sub,
		Email:           "ana@example.com",
		AccountKeyEpoch: 1,
		KDF:             idcrypto.DefaultKDF,
		KDFSalt:         idcrypto.EncodeB64(salt),
		PasswordWrap:    idcrypto.EncodeB64(passwordWrap),
		RecoveryWrap:    idcrypto.EncodeB64(recoveryWrap),
		ProductKeys:     productKeys,
		CreatedAt:       vectorTime.Format(time.RFC3339),
	}
	goodJSON, err := idcrypto.MarshalKeyBundle(good)
	if err != nil {
		return nil, err
	}

	otherCode, err := idcrypto.RecoveryCodeFromBytes(seeded("key-bundle/another-recovery-code", 30))
	if err != nil {
		return nil, err
	}
	otherKeys, err := idcrypto.ProductPublicKeys(seeded("key-bundle/another-root", idcrypto.KeyLen), 1)
	if err != nil {
		return nil, err
	}

	// variant marshals a changed copy of the good bundle without validating
	// it; members keeps the JSON level for what a struct cannot express.
	variant := func(f func(*idcrypto.KeyBundle)) json.RawMessage {
		v := good
		v.ProductKeys = slices.Clone(good.ProductKeys)
		f(&v)
		out, err := json.Marshal(v)
		if err != nil {
			panic(err) // a struct of strings and ints always marshals
		}
		return out
	}
	members := func(f func(map[string]json.RawMessage)) json.RawMessage {
		m := map[string]json.RawMessage{}
		if err := json.Unmarshal(goodJSON, &m); err != nil {
			panic(err) // goodJSON came from MarshalKeyBundle
		}
		f(m)
		out, err := json.Marshal(m)
		if err != nil {
			panic(err)
		}
		return out
	}

	// text edits the exact text of the good bundle, for the cases a JSON
	// value cannot express. Each edit must apply exactly once.
	goodText := string(goodJSON)
	text := func(old, replacement string) json.RawMessage {
		if strings.Count(goodText, old) != 1 {
			panic(fmt.Sprintf("idvectors: %q is not in the good bundle exactly once", old))
		}
		out, err := json.Marshal(strings.Replace(goodText, old, replacement, 1))
		if err != nil {
			panic(err) // a string always marshals
		}
		return out
	}
	createdAt := func(s string) json.RawMessage {
		return variant(func(v *idcrypto.KeyBundle) { v.CreatedAt = s })
	}

	type spec struct {
		name     string
		password *string
		code     *string
		bundle   json.RawMessage // a JSON object, or a JSON string holding the bundle's text
		err      string
	}
	pw := ptr(bundlePassword)
	rc := ptr(display)
	specs := []spec{
		{"opens with the password", pw, nil, goodJSON, ""},
		{"opens with the recovery code", nil, rc, goodJSON, ""},
		{"opens with the recovery code typed in lower case with spaces", nil, ptr(strings.ToLower(strings.ReplaceAll(display, "-", " "))), goodJSON, ""},
		{"a wrong password", ptr(bundlePassword + "!"), nil, goodJSON, "wrap"},
		{"a wrong recovery code", nil, ptr(otherCode), goodJSON, "wrap"},
		{"a malformed recovery code", nil, ptr("not a recovery code"), goodJSON, "recovery_code"},
		{"a password that breaks the profile", ptr("correct horse\x00battery staple"), nil, goodJSON, "password_invalid"},
		{"a product key that does not match the root", nil, rc, variant(func(v *idcrypto.KeyBundle) { v.ProductKeys[1].Pub = otherKeys[1].Pub }), "product_key"},
		{"another sub", nil, rc, variant(func(v *idcrypto.KeyBundle) { v.Sub = uuid7("key-bundle/another") }), "wrap"},
		{"another epoch", nil, rc, variant(func(v *idcrypto.KeyBundle) { v.AccountKeyEpoch = 2 }), "wrap"},
		{"an unknown format", nil, rc, variant(func(v *idcrypto.KeyBundle) { v.Format = "thehappie-id/key-bundle-v2" }), "bundle"},
		{"version 2", nil, rc, variant(func(v *idcrypto.KeyBundle) { v.Version = 2 }), "bundle"},
		{"version as a string", nil, rc, members(func(m map[string]json.RawMessage) { m["version"] = json.RawMessage(`"1"`) }), "bundle"},
		{"kdf parameters below the floor", pw, nil, variant(func(v *idcrypto.KeyBundle) { v.KDF.M = 32768 }), "kdf_policy"},
		{"a padded kdf_salt", nil, rc, variant(func(v *idcrypto.KeyBundle) { v.KDFSalt += "==" }), "bundle"},
		{"the wraps swapped", nil, rc, variant(func(v *idcrypto.KeyBundle) { v.PasswordWrap, v.RecoveryWrap = v.RecoveryWrap, v.PasswordWrap }), "bundle"},
		{"a truncated password wrap", nil, rc, variant(func(v *idcrypto.KeyBundle) { v.PasswordWrap = idcrypto.EncodeB64(passwordWrap[:61]) }), "bundle"},
		{"a product key that is not 32 bytes", nil, rc, variant(func(v *idcrypto.KeyBundle) {
			v.ProductKeys[0].Pub = idcrypto.EncodeB64(seeded("key-bundle/short-pub", 31))
		}), "bundle"},
		{"product keys out of order", nil, rc, variant(func(v *idcrypto.KeyBundle) { slices.Reverse(v.ProductKeys) }), "bundle"},
		{"a repeated product key", nil, rc, variant(func(v *idcrypto.KeyBundle) { v.ProductKeys = append(v.ProductKeys, v.ProductKeys[1]) }), "bundle"},
		{"no product keys", nil, rc, variant(func(v *idcrypto.KeyBundle) { v.ProductKeys = []idcrypto.ProductPublicKey{} }), "bundle"},
		{"a sub in upper case", nil, rc, variant(func(v *idcrypto.KeyBundle) { v.Sub = strings.ToUpper(v.Sub) }), "bundle"},
		{"account_key_epoch 0", nil, rc, variant(func(v *idcrypto.KeyBundle) { v.AccountKeyEpoch = 0 }), "bundle"},
		{"an email that is not normalized", nil, rc, variant(func(v *idcrypto.KeyBundle) { v.Email = "Ana@Example.com" }), "bundle"},
		{"an unknown member", nil, rc, members(func(m map[string]json.RawMessage) { m["note"] = json.RawMessage(`"hello"`) }), "bundle"},
		{"a missing member", nil, rc, members(func(m map[string]json.RawMessage) { delete(m, "recovery_wrap") }), "bundle"},
		{"a member name in another case", nil, rc, members(func(m map[string]json.RawMessage) { m["SUB"] = m["sub"]; delete(m, "sub") }), "bundle"},
		{"a null member", nil, rc, members(func(m map[string]json.RawMessage) { m["recovery_wrap"] = json.RawMessage(`null`) }), "bundle"},
		{"not a JSON object", nil, rc, json.RawMessage(`[]`), "bundle"},

		// created_at: RFC 3339 in UTC, in the one shape both readers take.
		{"created_at with nine fraction digits", nil, rc, createdAt("2026-10-01T12:00:00.123456789Z"), ""},
		{"created_at in the year 0050", nil, rc, createdAt("0050-01-01T00:00:00Z"), ""},
		{"created_at with the offset +00:00", nil, rc, createdAt("2026-10-01T12:00:00+00:00"), "bundle"},
		{"created_at with the offset -03:00", nil, rc, createdAt("2026-10-01T09:00:00-03:00"), "bundle"},
		{"created_at with a lower-case z", nil, rc, createdAt("2026-10-01T12:00:00z"), "bundle"},
		{"created_at with a lower-case t", nil, rc, createdAt("2026-10-01t12:00:00Z"), "bundle"},
		{"created_at with a comma before the fraction", nil, rc, createdAt("2026-10-01T12:00:00,5Z"), "bundle"},
		{"created_at with ten fraction digits", nil, rc, createdAt("2026-10-01T12:00:00.1234567891Z"), "bundle"},
		{"created_at with a dot and no fraction", nil, rc, createdAt("2026-10-01T12:00:00.Z"), "bundle"},
		{"created_at on February 29 of a common year", nil, rc, createdAt("2026-02-29T12:00:00Z"), "bundle"},
		{"created_at on February 29 of 1900, not a leap year", nil, rc, createdAt("1900-02-29T12:00:00Z"), "bundle"},
		{"created_at on February 29 of 2000, a leap year", nil, rc, createdAt("2000-02-29T12:00:00Z"), ""},
		{"created_at on February 29 of the year 0, a leap year", nil, rc, createdAt("0000-02-29T00:00:00Z"), ""},
		{"created_at at hour 24", nil, rc, createdAt("2026-10-01T24:00:00Z"), "bundle"},
		{"created_at at second 60", nil, rc, createdAt("2026-10-01T12:00:60Z"), "bundle"},
		{"created_at without seconds", nil, rc, createdAt("2026-10-01T12:00Z"), "bundle"},

		// The exact text: what JSON.parse and encoding/json would let through.
		{"the bundle as text", nil, rc, text(`"format"`, `"format"`), ""},
		{"a repeated member whose last value is good", nil, rc, text(`"issuer": "https://id.thehappie.co",`, `"issuer": "https://other.example",
  "issuer": "https://id.thehappie.co",`), "bundle"},
		{"a repeated member inside kdf", nil, rc, text(`"m": 65536,`, `"m": 65536,
    "m": 65536,`), "bundle"},
		{"a repeated member inside a product key", nil, rc, text(`"product": "mailie",`, `"product": "mailie",
      "product": "mailie",`), "bundle"},
		{"version written as 1.0", nil, rc, text(`"version": 1,`, `"version": 1.0,`), "bundle"},
		{"account_key_epoch written as 1e0", nil, rc, text(`"account_key_epoch": 1,`, `"account_key_epoch": 1e0,`), "bundle"},
		{"kdf t written as 3E0", nil, rc, text(`"t": 3,`, `"t": 3E0,`), "bundle"},
		{"a product key epoch written as 1.0", nil, rc, text(`"product": "wappie",
      "epoch": 1,`, `"product": "wappie",
      "epoch": 1.0,`), "bundle"},
		{"kdf m of 2^63, past a 64-bit integer", nil, rc, text(`"m": 65536,`, `"m": 9223372036854775808,`), "bundle"},
		{"kdf m of 2^63 - 1, a 64-bit integer out of bounds", nil, rc, text(`"m": 65536,`, `"m": 9223372036854775807,`), "kdf_policy"},
		{"kdf m of -0", nil, rc, text(`"m": 65536,`, `"m": -0,`), "kdf_policy"},
		{"a byte order mark", nil, rc, text(`{
  "format"`, "\ufeff{\n  \"format\""), "bundle"},
		{"a value after the bundle", nil, rc, text(`"created_at": "2026-10-01T12:00:00Z"
}`, `"created_at": "2026-10-01T12:00:00Z"
} {}`), "bundle"},
		{"a member name with an escape", nil, rc, text(`"sub":`, `"\u0073ub":`), ""},
	}

	var out []KeyBundleCase
	for _, s := range specs {
		c := KeyBundleCase{Name: s.name, Password: s.password, RecoveryCode: s.code, Error: s.err}
		data := []byte(s.bundle)
		if len(s.bundle) > 0 && s.bundle[0] == '"' {
			var t string
			if err := json.Unmarshal(s.bundle, &t); err != nil {
				return nil, fmt.Errorf("case %q: %w", s.name, err)
			}
			c.BundleText, data = &t, []byte(t)
		} else {
			c.Bundle = s.bundle
		}
		var got []byte
		var err error
		if s.password != nil {
			got, _, err = idcrypto.OpenKeyBundle(data, *s.password)
		} else {
			got, _, err = idcrypto.OpenKeyBundleWithRecoveryCode(data, *s.code)
		}
		if code := idcrypto.ErrorCode(err); code != s.err {
			clear(got)
			return nil, mismatch(s.name, code, s.err)
		}
		if err == nil {
			if !bytes.Equal(got, root) {
				clear(got)
				return nil, fmt.Errorf("case %q: opened to another root", s.name)
			}
			c.Root = idcrypto.EncodeB64(got)
			clear(got)
		}
		out = append(out, c)
	}
	return out, nil
}
