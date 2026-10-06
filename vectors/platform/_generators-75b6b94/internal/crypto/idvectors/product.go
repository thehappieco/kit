//go:build go1.26

package idvectors

import (
	"strings"

	idcrypto "github.com/thehappieco/kit/profiles/platform"
)

// ProductKeyCase is one product-key vector (spec 2.3): the X25519 key pair a
// product receives, derived from the root, and its key id.
type ProductKeyCase struct {
	Name         string `json:"name"`
	Root         string `json:"root"`
	Product      string `json:"product"`
	Epoch        int    `json:"epoch"`
	SK           string `json:"sk,omitempty"`
	Pub          string `json:"pub,omitempty"`
	ProductKeyID string `json:"product_key_id,omitempty"`
	Error        string `json:"error,omitempty"`
}

func productKeyCases() ([]ProductKeyCase, error) {
	rootA := seeded("product-key/root-a", idcrypto.KeyLen)
	rootB := seeded("product-key/root-b", idcrypto.KeyLen)
	specs := []struct {
		name    string
		root    []byte
		product string
		epoch   int
		err     string
	}{
		{"mailie at epoch 1", rootA, "mailie", 1, ""},
		{"wappie at epoch 1", rootA, "wappie", 1, ""},
		{"wappie at epoch 2", rootA, "wappie", 2, ""},
		{"wappie at epoch 1 from another root", rootB, "wappie", 1, ""},
		{"a valid product id outside the registry", rootA, "a-future-product", 1, ""},
		{"the longest product id", rootA, "p" + strings.Repeat("0123456789-", 2) + "abcdefghi", 1, ""},
		{"the largest epoch", rootA, "wappie", idcrypto.MaxEpoch, ""},
		{"an all-zero root", make([]byte, idcrypto.KeyLen), "wappie", 1, ""},
		{"a product id in upper case", rootA, "Wappie", 1, "product_key"},
		{"an empty product id", rootA, "", 1, "product_key"},
		{"a product id starting with a digit", rootA, "1wappie", 1, "product_key"},
		{"a product id starting with a dash", rootA, "-wappie", 1, "product_key"},
		{"a product id with an underscore", rootA, "wap_pie", 1, "product_key"},
		{"a product id with a pipe", rootA, "wappie|1", 1, "product_key"},
		{"a product id of 33 characters", rootA, "p" + strings.Repeat("0123456789-", 2) + "abcdefghij", 1, "product_key"},
		{"epoch 0", rootA, "wappie", 0, "product_key"},
		{"a negative epoch", rootA, "wappie", -1, "product_key"},
		{"an epoch of 2^31", rootA, "wappie", epochPast(), "product_key"},
		{"a 31-byte root", rootA[:31], "wappie", 1, "product_key"},
		{"a 33-byte root", append(rootA[:32:32], 0x00), "wappie", 1, "product_key"},
	}
	var out []ProductKeyCase
	for _, s := range specs {
		c := ProductKeyCase{Name: s.name, Root: idcrypto.EncodeB64(s.root), Product: s.product, Epoch: s.epoch}
		sk, pub, err := idcrypto.ProductKey(s.root, s.product, s.epoch)
		if got := idcrypto.ErrorCode(err); got != s.err {
			return nil, mismatch(s.name, got, s.err)
		}
		if err != nil {
			c.Error = s.err
		} else {
			if err := idcrypto.CheckPublicKey(pub); err != nil {
				return nil, mismatch(s.name, idcrypto.ErrorCode(err), "a public key the server accepts")
			}
			c.SK, c.Pub, c.ProductKeyID = idcrypto.EncodeB64(sk), idcrypto.EncodeB64(pub), idcrypto.ProductKeyID(s.product, s.epoch)
			clear(sk)
		}
		out = append(out, c)
	}
	return out, nil
}

// epochPast returns 2^31, one past MaxEpoch, computed at run time so the
// package still compiles where int is 32 bits (where it wraps negative and
// stays refused).
func epochPast() int {
	n := int64(idcrypto.MaxEpoch)
	n++
	return int(n) //nolint:gosec // deliberately out of range; refused either way
}

// VerifierCase is one verifier vector (spec 2.6): what the server stores for
// K_auth or R_proof under a sub. The error cases are inputs the server must
// refuse as malformed.
type VerifierCase struct {
	Name             string `json:"name"`
	Sub              string `json:"sub"`
	KAuth            string `json:"k_auth,omitempty"`
	RProof           string `json:"r_proof,omitempty"`
	AuthVerifier     string `json:"auth_verifier,omitempty"`
	RecoveryVerifier string `json:"recovery_verifier,omitempty"`
	Error            string `json:"error,omitempty"`
}

func verifierCases() ([]VerifierCase, error) {
	sub := uuid7("verifier")
	key := seeded("verifier/key", idcrypto.KeyLen)
	specs := []struct {
		name     string
		sub      string
		key      []byte
		recovery bool
		err      string
	}{
		{"an auth verifier", sub, key, false, ""},
		{"a recovery verifier over the same sub and bytes", sub, key, true, ""},
		{"an auth verifier for another sub", uuid7("verifier/another"), key, false, ""},
		{"an auth verifier for the dummy sub", idcrypto.DummySub(), key, false, ""},
		{"a recovery verifier for the dummy sub", idcrypto.DummySub(), key, true, ""},
		{"a sub in upper case", strings.ToUpper(sub), key, false, "encoding"},
		{"a sub without hyphens", strings.ReplaceAll(sub, "-", ""), key, false, "encoding"},
		{"a sub in braces", "{" + sub + "}", key, false, "encoding"},
		{"a 31-byte k_auth", sub, key[:31], false, "encoding"},
		{"a 33-byte r_proof", sub, append(key[:32:32], 0x00), true, "encoding"},
	}
	var out []VerifierCase
	for _, s := range specs {
		c := VerifierCase{Name: s.name, Sub: s.sub}
		var v [32]byte
		var err error
		if s.recovery {
			c.RProof = idcrypto.EncodeB64(s.key)
			v, err = idcrypto.RecoveryVerifier(s.sub, s.key)
		} else {
			c.KAuth = idcrypto.EncodeB64(s.key)
			v, err = idcrypto.AuthVerifier(s.sub, s.key)
		}
		if got := idcrypto.ErrorCode(err); got != s.err {
			return nil, mismatch(s.name, got, s.err)
		}
		switch {
		case err != nil:
			c.Error = s.err
		case s.recovery:
			c.RecoveryVerifier = idcrypto.EncodeB64(v[:])
		default:
			c.AuthVerifier = idcrypto.EncodeB64(v[:])
		}
		out = append(out, c)
	}
	return out, nil
}

// EmailCase is one email vector (spec 2.8).
type EmailCase struct {
	Name      string `json:"name"`
	Input     string `json:"input"`
	EmailNorm string `json:"email_norm,omitempty"`
	Error     string `json:"error,omitempty"`
}

func emailCases() ([]EmailCase, error) {
	local64 := strings.Repeat("l", 64)
	label63 := strings.Repeat("d", 63)
	// 64 + 1 + 189 = 254 bytes: labels of 63, 63, 57 and 3.
	domain189 := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 57) + ".com"
	domain190 := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 58) + ".com"
	specs := []struct {
		name, input, want, err string
	}{
		{"a plain address", "ana@example.com", "ana@example.com", ""},
		{"upper case is folded", "Ana.Silva@Example.COM", "ana.silva@example.com", ""},
		{"surrounding spaces, tabs and line breaks are trimmed", " \t\r\nana@example.com\r\n\t ", "ana@example.com", ""},
		{"dots and plus tags are kept", "a.n.a+news@gmail.com", "a.n.a+news@gmail.com", ""},
		{"every symbol allowed in the local part", "a!#$%&'*+/=?^_`{|}~-z@example.com", "a!#$%&'*+/=?^_`{|}~-z@example.com", ""},
		{"digits and dashes in the domain", "ana@mail-1.example-2.com", "ana@mail-1.example-2.com", ""},
		{"an all-digit label that is not the last", "ana@123.example.com", "ana@123.example.com", ""},
		{"a last label with a digit", "ana@example.c0m", "ana@example.c0m", ""},
		{"a punycode domain", "ana@xn--bcher-kva.example", "ana@xn--bcher-kva.example", ""},
		{"a one-character local part", "a@example.com", "a@example.com", ""},
		{"a local part of 64 bytes", local64 + "@example.com", local64 + "@example.com", ""},
		{"a domain label of 63 bytes", "ana@" + label63 + ".com", "ana@" + label63 + ".com", ""},
		{"an address of 254 bytes", local64 + "@" + domain189, local64 + "@" + domain189, ""},
		{"an address of 255 bytes", local64 + "@" + domain190, "", "email"},
		{"a local part of 65 bytes", local64 + "l@example.com", "", "email"},
		{"a domain label of 64 bytes", "ana@" + label63 + "d.com", "", "email"},
		{"empty", "", "", "email"},
		{"only spaces", "   ", "", "email"},
		{"no @", "ana.example.com", "", "email"},
		{"two @", "ana@foo@example.com", "", "email"},
		{"an empty local part", "@example.com", "", "email"},
		{"an empty domain", "ana@", "", "email"},
		{"a leading dot", ".ana@example.com", "", "email"},
		{"a trailing dot in the local part", "ana.@example.com", "", "email"},
		{"two dots in a row", "a..na@example.com", "", "email"},
		{"a domain without a dot", "ana@localhost", "", "email"},
		{"a numeric top-level label", "ana@example.123", "", "email"},
		{"an IPv4 address", "ana@192.168.0.1", "", "email"},
		{"an address literal", "ana@[192.168.0.1]", "", "email"},
		{"a domain label starting with a dash", "ana@-example.com", "", "email"},
		{"a domain label ending with a dash", "ana@example-.com", "", "email"},
		{"an empty domain label", "ana@example..com", "", "email"},
		{"a trailing dot in the domain", "ana@example.com.", "", "email"},
		{"a leading dot in the domain", "ana@.example.com", "", "email"},
		{"an underscore in the domain", "ana@ex_ample.com", "", "email"},
		{"an inner space", "ana silva@example.com", "", "email"},
		{"a quoted local part", "\"ana\"@example.com", "", "email"},
		{"a comment", "ana(work)@example.com", "", "email"},
		{"a comma", "ana,bia@example.com", "", "email"},
		{"a non-ASCII local part", "\u00e1na@example.com", "", "email"},
		{"a non-ASCII domain", "ana@ex\u00e4mple.com", "", "email"},
		{"a Kelvin sign (U+212A) is not a k", "\u212aate@example.com", "", "email"},
		{"a dotted capital I (U+0130) is not an i", "\u0130van@example.com", "", "email"},
		{"a non-breaking space is not trimmed", "\u00a0ana@example.com", "", "email"},
		{"a vertical tab is not trimmed", "\vana@example.com", "", "email"},
		{"a trailing NUL", "ana@example.com\x00", "", "email"},
	}
	var out []EmailCase
	for _, s := range specs {
		got, err := idcrypto.NormalizeEmail(s.input)
		if code := idcrypto.ErrorCode(err); code != s.err {
			return nil, mismatch(s.name, code, s.err)
		}
		if s.err == "" && got != s.want {
			return nil, mismatch(s.name, "another address", "the stated address")
		}
		out = append(out, EmailCase{Name: s.name, Input: s.input, EmailNorm: got, Error: s.err})
	}
	return out, nil
}
