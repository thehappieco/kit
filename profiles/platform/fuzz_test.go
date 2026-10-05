package platform_test

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/thehappieco/kit/internal/vectest"
	"github.com/thehappieco/kit/profiles/platform"
)

// FuzzCanonicalRecoveryCode: no input panics; whatever is accepted is 30
// characters of the alphabet, canonical already, and comes back unchanged
// through its display form.
func FuzzCanonicalRecoveryCode(f *testing.F) {
	for _, s := range []string{
		"7K2QD-8M4TV-ZP3XA-0N9RH-6W1GB-5CY8E", "oiol0-11111-22222-33333-44444-55555",
		"", "-", "U", strings.Repeat("A", 31), "\u0131", "\xff", strings.Repeat("a ", 30),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c, err := platform.CanonicalRecoveryCode(s)
		if err != nil {
			if !errors.Is(err, platform.ErrRecoveryCode) {
				t.Fatalf("unclassified error: %v", err)
			}
			return
		}
		if len(c) != platform.RecoveryCodeLen {
			t.Fatalf("accepted a code of %d characters", len(c))
		}
		for i := range len(c) {
			if !strings.Contains(platform.RecoveryAlphabet, c[i:i+1]) {
				t.Fatal("a character outside the alphabet")
			}
		}
		again, err := platform.CanonicalRecoveryCode(c)
		if err != nil || again != c {
			t.Fatal("the canonical form is not canonical")
		}
		d, err := platform.DisplayRecoveryCode(c)
		if err != nil {
			t.Fatal(err)
		}
		back, err := platform.CanonicalRecoveryCode(d)
		if err != nil || back != c {
			t.Fatal("the display form does not come back")
		}
	})
}

// FuzzNormalizeEmail: no input panics, and normalizing a normalized address
// returns it unchanged. Anything accepted is short, lower-case printable
// ASCII with exactly one '@'.
func FuzzNormalizeEmail(f *testing.F) {
	for _, s := range []string{
		"ana@example.com", " Ana@Example.COM\n", "a@b.c0", "a..b@c.d", "@", "a@b", "a@b.1",
		"\u212aate@example.com", "a@" + strings.Repeat("b", 63) + ".com", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		e, err := platform.NormalizeEmail(s)
		if err != nil {
			if !errors.Is(err, platform.ErrEmailInvalid) {
				t.Fatalf("unclassified error: %v", err)
			}
			return
		}
		again, err := platform.NormalizeEmail(e)
		if err != nil || again != e {
			t.Fatal("normalizing a normalized address changed it")
		}
		if len(e) > platform.MaxEmailLen || strings.Count(e, "@") != 1 {
			t.Fatal("accepted an address outside the limits")
		}
		for i := range len(e) {
			if c := e[i]; c < 0x21 || c > 0x7e || ('A' <= c && c <= 'Z') {
				t.Fatal("accepted a byte that is not lower-case printable ASCII")
			}
		}
	})
}

// FuzzPreparePassword: no input panics; whatever is accepted is valid UTF-8,
// in NFC with no U+034F that the password did not hold, free of control
// characters and mapped spaces, at most 256 code points, and preparing it
// again changes nothing.
func FuzzPreparePassword(f *testing.F) {
	for _, s := range []string{
		"correct horse battery staple", "cafe\u0301", "\u00a0\u3000", "\xed\xa0\x80", "\x00",
		"d\u0307\u0323", "\u1100\u1161\u11a8", strings.Repeat("\U0001f600", 300), "",
		strings.Repeat("\u3160", 31), "\uac01" + strings.Repeat("\u0301", 29), "\u00b4" + strings.Repeat("\u0301", 30),
		"a" + strings.Repeat("\uff9e", 30), "pass\u034fword",
	} {
		f.Add(s, false)
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, s string, isNew bool) {
		prepare := platform.PreparePassword
		if isNew {
			prepare = platform.PrepareNewPassword
		}
		p, err := prepare(s)
		if err != nil {
			if platform.ErrorCode(err) == "" || !strings.HasPrefix(platform.ErrorCode(err), "password_") {
				t.Fatalf("unclassified error: %v", err)
			}
			return
		}
		if !utf8.Valid(p) {
			t.Fatal("prepared to invalid UTF-8")
		}
		if !norm.NFC.IsNormal(p) {
			t.Fatal("prepared to a string that is not NFC")
		}
		if strings.Count(string(p), "\u034f") != strings.Count(s, "\u034f") {
			t.Fatal("prepared with a U+034F the password did not hold")
		}
		n := 0
		for _, r := range string(p) {
			n++
			if r <= 0x1f || (r >= 0x7f && r <= 0x9f) || r == 0xa0 || r == 0x3000 || (r >= 0x2000 && r <= 0x200a) {
				t.Fatal("a control character or an unmapped space survived")
			}
		}
		if n > platform.MaxPasswordLen || (isNew && n < platform.MinNewPasswordLen) {
			t.Fatalf("accepted %d code points", n)
		}
		again, err := platform.PreparePassword(string(p))
		if err != nil || string(again) != string(p) {
			t.Fatal("preparing a prepared password changed it")
		}
	})
}

// FuzzDecodeB64: whatever DecodeB64 accepts is the one spelling of its
// bytes.
func FuzzDecodeB64(f *testing.F) {
	for _, s := range []string{"", "AA", "AB", "AA==", "AAAA", "A\nAA", "_-_-", "////"} {
		f.Add(s, 1)
		f.Add(s, 3)
	}
	f.Fuzz(func(t *testing.T, s string, n int) {
		b, err := platform.DecodeB64(s, n)
		if err != nil {
			if !errors.Is(err, platform.ErrEncoding) {
				t.Fatalf("unclassified error: %v", err)
			}
			return
		}
		if len(b) != n || base64.RawURLEncoding.EncodeToString(b) != s {
			t.Fatal("accepted a second spelling")
		}
	})
}

// FuzzParseKeyBundle: no input panics, every refusal is classified, and an
// accepted bundle survives a marshal and a second parse unchanged.
func FuzzParseKeyBundle(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"format":"thehappie-id/key-bundle","version":1}`))
	a := keyBundleSeed(f)
	f.Add(a)
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := platform.ParseKeyBundle(data)
		if err != nil {
			if !errors.Is(err, platform.ErrBundle) && !errors.Is(err, platform.ErrKDFPolicy) {
				t.Fatalf("unclassified error: %v", err)
			}
			return
		}
		out, err := platform.MarshalKeyBundle(*b)
		if err != nil {
			t.Fatalf("an accepted bundle does not marshal: %v", err)
		}
		if _, err := platform.ParseKeyBundle(out); err != nil {
			t.Fatalf("a marshalled bundle does not parse: %v", err)
		}
	})
}

// keyBundleSeed builds a valid bundle without running Argon2id: the fuzz
// target never opens it, so the wraps only need the right shape.
func keyBundleSeed(f *testing.F) []byte {
	f.Helper()
	root := testBytes(32, 3)
	b := platform.Binding{Sub: testSub, Epoch: 1}
	pw, err := platform.Wrap(nil, platform.WrapPassword, testBytes(32, 1), root, b)
	if err != nil {
		f.Fatal(err)
	}
	rw, err := platform.Wrap(nil, platform.WrapRecovery, testBytes(32, 2), root, b)
	if err != nil {
		f.Fatal(err)
	}
	keys := productPublicKeys(f, root, 1, testProducts...)
	data, err := platform.MarshalKeyBundle(platform.KeyBundle{
		Format: platform.KeyBundleFormat, Version: platform.KeyBundleVersion,
		Issuer: "https://id.thehappie.co", Sub: testSub, Email: "ana@example.com", AccountKeyEpoch: 1,
		KDF: platform.DefaultKDF, KDFSalt: platform.EncodeB64(testBytes(16, 4)),
		PasswordWrap: platform.EncodeB64(pw), RecoveryWrap: platform.EncodeB64(rw),
		ProductKeys: keys, CreatedAt: "2026-10-01T12:00:00Z",
	})
	if err != nil {
		f.Fatal(err)
	}
	return data
}

// FuzzOpenProductKey: no input panics; a refusal is key_delivery or
// product_key and returns nothing; whatever opens is 32 bytes whose public
// half is the binding's product key.
func FuzzOpenProductKey(f *testing.F) {
	d := newDelivery(f, "wappie")
	sealed := d.seal(f)
	b := d.b
	f.Add(d.akdPriv, sealed, b.Issuer, b.ClientID, b.RedirectURI, b.Sub, b.ProductKeyID, b.ProductKey, b.CodeChallenge, b.Nonce)
	f.Add(d.akdPriv, sealed[:79], b.Issuer, b.ClientID, b.RedirectURI, b.Sub, b.ProductKeyID, b.ProductKey, b.CodeChallenge, b.Nonce)
	f.Add(d.akdPriv, make([]byte, 80), b.Issuer, b.ClientID, b.RedirectURI, b.Sub, "wappie:01", b.ProductKey, b.CodeChallenge, b.Nonce)
	f.Add([]byte{}, []byte{}, "", "", "", "", "", []byte{}, "", "")
	f.Fuzz(func(t *testing.T, akdPriv, sealed []byte, iss, clientID, redirectURI, sub, productKeyID string, productKey []byte, codeChallenge, nonce string) {
		b := platform.KeyDeliveryBinding{
			Issuer: iss, ClientID: clientID, RedirectURI: redirectURI, Sub: sub,
			ProductKeyID: productKeyID, ProductKey: productKey, CodeChallenge: codeChallenge, Nonce: nonce,
		}
		got, err := platform.OpenProductKey(akdPriv, sealed, b)
		if err != nil {
			if code := platform.ErrorCode(err); code != "key_delivery" && code != "product_key" {
				t.Fatalf("unclassified error: %v", err)
			}
			if got != nil {
				t.Fatal("a refusal returned key material")
			}
			return
		}
		if len(got) != platform.KeyLen {
			t.Fatalf("opened %d bytes", len(got))
		}
		priv, err := ecdh.X25519().NewPrivateKey(got)
		if err != nil || !bytes.Equal(priv.PublicKey().Bytes(), productKey) {
			t.Fatal("opened a key whose public half is not the binding's")
		}
	})
}

// FuzzPKCEChallenge: no input panics; a verifier is accepted exactly when
// it is 43 to 128 characters of [A-Za-z0-9._~-], and its challenge is 43
// characters of strict base64url.
func FuzzPKCEChallenge(f *testing.F) {
	for _, s := range []string{
		"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", strings.Repeat("~", 42), strings.Repeat("a", 129),
		strings.Repeat("a", 42) + "+", strings.Repeat("a", 42) + "é", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		got, err := platform.PKCEChallenge(v)
		valid := len(v) >= platform.MinCodeVerifierLen && len(v) <= platform.MaxCodeVerifierLen &&
			strings.Trim(v, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~") == ""
		if (err == nil) != valid {
			t.Fatalf("accepted %v, valid %v", err == nil, valid)
		}
		if err != nil {
			if !errors.Is(err, platform.ErrPKCE) {
				t.Fatalf("unclassified error: %v", err)
			}
			return
		}
		if _, err := platform.DecodeB64(got, 32); err != nil || len(got) != platform.CodeChallengeLen {
			t.Fatal("a challenge that is not 43 characters of strict base64url")
		}
	})
}

// FuzzCheckClientExtensions: no input panics and every refusal is
// client_extensions. Whatever is accepted, encoding/json (what WebAuthn
// libraries decode with, matching names case-insensitively) reads as the
// allowlist and nothing else, with no PRF results anywhere; and whatever
// encoding/json reads as the allowlist is accepted once written in one
// spelling, so the allowlist refuses spellings, never values it allows.
// Ported from the platform's idcrypto fuzz_test.go at b5d9f69, seeded from
// client-extensions.json through vectest.
func FuzzCheckClientExtensions(f *testing.F) {
	for _, c := range vectest.Platform[vectest.ClientExtensionsCase](f, "client-extensions") {
		f.Add([]byte(*c.ClientExtensionResults))
	}
	f.Add([]byte(`{"credProps":{"RK":true}}`))
	f.Add([]byte(`{"prf":{"enabled":true,"RESULTS":{}}}`))
	f.Add([]byte("{\"prf\":{\"enabled\":true}}\xff"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		err := platform.CheckClientExtensions(raw)
		if err != nil && (!errors.Is(err, platform.ErrClientExtensions) || platform.ErrorCode(err) != "client_extensions") {
			t.Fatalf("unclassified error: %v", err)
		}
		var parsed any
		allowed := json.Unmarshal(raw, &parsed) == nil && allowlisted(parsed)
		if err != nil {
			if allowed {
				canon, mErr := json.Marshal(parsed)
				if mErr != nil {
					t.Fatal(mErr)
				}
				if err := platform.CheckClientExtensions(canon); err != nil {
					t.Fatal("the one spelling of an allowed value is refused")
				}
			}
			return
		}
		if !allowed {
			t.Fatal("accepted a text encoding/json reads as something outside the allowlist")
		}
		var asLibrary struct {
			CredProps *struct {
				RK *bool `json:"rk"`
			} `json:"credProps"`
			PRF *struct {
				Enabled *bool           `json:"enabled"`
				Results json.RawMessage `json:"results"`
			} `json:"prf"`
		}
		if json.Unmarshal(raw, &asLibrary) != nil {
			t.Fatal("encoding/json cannot read an accepted text")
		}
		if asLibrary.PRF != nil && (asLibrary.PRF.Results != nil || asLibrary.PRF.Enabled == nil) {
			t.Fatal("encoding/json reads PRF results, or no flag, in an accepted text")
		}
		if asLibrary.CredProps != nil && asLibrary.CredProps.RK == nil {
			t.Fatal("encoding/json reads credProps without rk in an accepted text")
		}
	})
}

// allowlisted reports whether a value encoding/json decoded is an object
// holding only credProps {rk: bool} and prf {enabled: bool}.
func allowlisted(v any) bool {
	top, ok := v.(map[string]any)
	if !ok {
		return false
	}
	for name, inner := range top {
		var flag string
		switch name {
		case "credProps":
			flag = "rk"
		case "prf":
			flag = "enabled"
		default:
			return false
		}
		m, ok := inner.(map[string]any)
		if !ok || len(m) != 1 {
			return false
		}
		if _, ok := m[flag].(bool); !ok {
			return false
		}
	}
	return true
}

// rpIDLabel is one label of a relying party id as the TypeScript side's
// isRPID matches it; rpIDDigits is a label of digits only.
var (
	rpIDLabel  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	rpIDDigits = regexp.MustCompile(`^[0-9]+$`)
)

// FuzzValidRPID: no input panics; ValidRPID's byte loop agrees with the
// regular expressions TypeScript's isRPID uses (labels split on '.', 1 to
// 253 bytes in all, the last label not all digits); every id it accepts
// passes WrapAAD's alphabet and gives a salt and a key, and every id it
// refuses gives neither.
func FuzzValidRPID(f *testing.F) {
	for _, c := range vectest.Platform[vectest.PasskeyCase](f, "passkey") {
		f.Add(c.RPID)
	}
	for _, s := range []string{
		"a", "1", "a.1", "1.a", "a-", "-a", "a..b", ".", "", "xn--bcher-kva.example", "A.b", "a_b", "a\x00",
		strings.Repeat("a", 63), strings.Repeat("a", 64), strings.Repeat("a.", 126) + "a", strings.Repeat("a.", 126) + "ab",
		"\xff", "\u0430.com", "id.thehappie.co\n",
	} {
		f.Add(s)
	}
	prf := testBytes(platform.PRFOutputLen, 0x5a)
	f.Fuzz(func(t *testing.T, rpID string) {
		got := platform.ValidRPID(rpID)
		labels := strings.Split(rpID, ".")
		want := len(rpID) >= 1 && len(rpID) <= 253 && !rpIDDigits.MatchString(labels[len(labels)-1])
		for _, l := range labels {
			want = want && rpIDLabel.MatchString(l)
		}
		if got != want {
			t.Fatalf("ValidRPID says %v, the regular expressions %v", got, want)
		}
		salt, sErr := platform.PRFSalt(rpID)
		key, kErr := platform.PasskeyWrapKey(prf, rpID)
		if !got {
			if platform.ErrorCode(sErr) != "wrap" || platform.ErrorCode(kErr) != "wrap" || salt != nil || key != nil {
				t.Fatal("a refused relying party id gave a salt or a key")
			}
			return
		}
		if sErr != nil || kErr != nil || len(salt) != platform.PRFSaltLen || len(key) != platform.KeyLen {
			t.Fatal("an accepted relying party id gives no salt or no key")
		}
		if _, err := platform.WrapAAD(platform.WrapPasskey, platform.Binding{Sub: testSub, Epoch: 1, RPID: rpID, CredentialID: "AA"}); err != nil {
			t.Fatalf("an accepted relying party id has no AAD: %v", err)
		}
	})
}
