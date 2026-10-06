//go:build go1.26

package idvectors

import (
	"strings"

	idcrypto "github.com/thehappieco/kit/profiles/platform"
)

// RecoveryCodeCase is one recovery-code vector (spec 2.5). The input is
// either Bytes, the 30 random bytes a code is generated from, or Input, text
// as a person might type it. A good case gives the display and canonical
// forms and the two keys: K_rwrap and recovery_auth (R_proof).
type RecoveryCodeCase struct {
	Name         string  `json:"name"`
	Bytes        string  `json:"bytes,omitempty"`
	Input        *string `json:"input,omitempty"`
	Display      string  `json:"display,omitempty"`
	Canonical    string  `json:"canonical,omitempty"`
	KRWrap       string  `json:"k_rwrap,omitempty"`
	RecoveryAuth string  `json:"recovery_auth,omitempty"`
	Error        string  `json:"error,omitempty"`
}

func recoveryCodeCases() ([]RecoveryCodeCase, error) {
	var out []RecoveryCodeCase
	add := func(c RecoveryCodeCase, canonical, wantErr string) error {
		if wantErr != "" {
			c.Error = wantErr
			out = append(out, c)
			return nil
		}
		display, err := idcrypto.DisplayRecoveryCode(canonical)
		if err != nil {
			return mismatch(c.Name, idcrypto.ErrorCode(err), "")
		}
		keys, err := idcrypto.DeriveRecovery(canonical)
		if err != nil {
			return mismatch(c.Name, idcrypto.ErrorCode(err), "")
		}
		c.Display, c.Canonical = display, canonical
		c.KRWrap, c.RecoveryAuth = idcrypto.EncodeB64(keys.Wrap[:]), keys.RecoveryAuth()
		keys.Zero()
		out = append(out, c)
		return nil
	}

	fromBytes := []struct {
		name string
		b    []byte
		want string // the canonical code, when it is worth stating
		err  string
	}{
		{"thirty zero bytes", make([]byte, 30), strings.Repeat("0", 30), ""},
		{"bytes 0 to 29", seq(0, 30), idcrypto.RecoveryAlphabet[:30], ""},
		{"bytes 226 to 255 map by their value mod 32", seq(226, 30), idcrypto.RecoveryAlphabet[2:], ""},
		{"random bytes", seeded("recovery-code/random-1", 30), "", ""},
		{"other random bytes", seeded("recovery-code/random-2", 30), "", ""},
		{"29 bytes", seeded("recovery-code/random-1", 29), "", "recovery_code"},
		{"31 bytes", seeded("recovery-code/random-1", 31), "", "recovery_code"},
	}
	for _, s := range fromBytes {
		code, err := idcrypto.RecoveryCodeFromBytes(s.b)
		if got := idcrypto.ErrorCode(err); got != s.err {
			return nil, mismatch(s.name, got, s.err)
		}
		if s.want != "" && code != s.want {
			return nil, mismatch(s.name, "another code", "the stated code")
		}
		if err := add(RecoveryCodeCase{Name: s.name, Bytes: idcrypto.EncodeB64(s.b)}, code, s.err); err != nil {
			return nil, err
		}
	}

	code, err := idcrypto.RecoveryCodeFromBytes(seeded("recovery-code/random-1", 30))
	if err != nil {
		return nil, err
	}
	display, err := idcrypto.DisplayRecoveryCode(code)
	if err != nil {
		return nil, err
	}
	groups := strings.Split(display, "-")
	lookalikes := "0101010101" + "ABCDEFGHJKMNPQRSTVWX"
	fromInput := []struct {
		name, input, want, err string
	}{
		{"the display form", display, code, ""},
		{"the canonical form", code, code, ""},
		{"lower case", strings.ToLower(display), code, ""},
		{"spaces instead of dashes", strings.Join(groups, " "), code, ""},
		{"tabs and line breaks between groups", groups[0] + "\t" + groups[1] + "\r\n" + groups[2] + "\n" + groups[3] + "\r" + groups[4] + " \t " + groups[5], code, ""},
		{"surrounding spaces and extra dashes", "  --" + strings.Join(groups, "--") + "-  ", code, ""},
		{"O for 0, and I and L for 1, in either case", "OIOLoiolOI-ABCDE-FGHJK-MNPQR-STVWX", lookalikes, ""},
		{"a U", "U" + code[1:], "", "recovery_code"},
		{"a lower-case u", "u" + code[1:], "", "recovery_code"},
		{"29 characters", code[:29], "", "recovery_code"},
		{"31 characters", code + "0", "", "recovery_code"},
		{"a non-ASCII letter", code[:29] + "\u00d6", "", "recovery_code"},
		{"a dotless i (U+0131) is not an I", code[:29] + "\u0131", "", "recovery_code"},
		{"a long s (U+017F) is not an S", code[:29] + "\u017f", "", "recovery_code"},
		{"a full-width digit", code[:29] + "\uff10", "", "recovery_code"},
		{"an underscore", code[:29] + "_", "", "recovery_code"},
		{"a vertical tab is not a line break", strings.Join(groups, "\v"), "", "recovery_code"},
		{"a non-breaking space is not a space", strings.Join(groups, "\u00a0"), "", "recovery_code"},
		{"an empty string", "", "", "recovery_code"},
		{"only dashes and spaces", "- - - -", "", "recovery_code"},
	}
	for _, s := range fromInput {
		got, err := idcrypto.CanonicalRecoveryCode(s.input)
		if code := idcrypto.ErrorCode(err); code != s.err {
			return nil, mismatch(s.name, code, s.err)
		}
		if s.err == "" && got != s.want {
			return nil, mismatch(s.name, "another canonical form", "the stated one")
		}
		if err := add(RecoveryCodeCase{Name: s.name, Input: ptr(s.input)}, got, s.err); err != nil {
			return nil, err
		}
	}
	return out, nil
}
