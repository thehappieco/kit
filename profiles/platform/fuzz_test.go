package platform_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

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
// in NFC, free of control characters and mapped spaces, at most 256 code
// points, and preparing it again changes nothing.
func FuzzPreparePassword(f *testing.F) {
	for _, s := range []string{
		"correct horse battery staple", "cafe\u0301", "\u00a0\u3000", "\xed\xa0\x80", "\x00",
		"d\u0307\u0323", "\u1100\u1161\u11a8", strings.Repeat("\U0001f600", 300), "",
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
