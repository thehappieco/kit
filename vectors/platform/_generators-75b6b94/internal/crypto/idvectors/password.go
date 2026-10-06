//go:build go1.26

package idvectors

import (
	"strings"
	"unicode/utf16"

	idcrypto "github.com/thehappieco/kit/profiles/platform"
)

// PasswordProfileCase is one password-profile vector (spec 2.1). A
// well-formed password is in Password. JSON cannot carry ill-formed Unicode
// in a way both languages read alike, so an ill-formed one is given twice
// instead: PasswordUTF16, the UTF-16 code units TypeScript builds its string
// from, and PasswordUTF8, the raw bytes Go builds its string from. Each
// language tests its own form. New says whether the 12-code-point minimum
// applies.
type PasswordProfileCase struct {
	Name          string   `json:"name"`
	Password      *string  `json:"password,omitempty"`
	PasswordUTF16 []uint16 `json:"password_utf16,omitempty"`
	PasswordUTF8  string   `json:"password_utf8_b64url,omitempty"`
	New           bool     `json:"new"`
	Prepared      *string  `json:"prepared_b64url,omitempty"`
	Error         string   `json:"error,omitempty"`
}

const allMappedSpaces = "\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000"

// profileSpec is one well-formed password-profile case as the generator
// declares it: the password, whether it is new, and either the prepared
// text (when it is worth stating; same for the input itself) or the error.
type profileSpec struct {
	name     string
	password string
	isNew    bool
	want     string
	err      string
}

// same, as a profileSpec's want, is the input itself.
const same = "\x00same"

// profileCases runs the declared cases through the kit and refuses any that
// does not come out as declared.
func profileCases(specs []profileSpec) ([]PasswordProfileCase, error) {
	var out []PasswordProfileCase
	for _, s := range specs {
		c := PasswordProfileCase{Name: s.name, Password: ptr(s.password), New: s.isNew}
		prepared, err := prepare(s.password, s.isNew)
		if got := idcrypto.ErrorCode(err); got != s.err || (err != nil && got == "") {
			return nil, mismatch(s.name, got, s.err)
		}
		if err != nil {
			c.Error = s.err
		} else {
			want := s.want
			if want == same {
				want = s.password
			}
			if want != "" && string(prepared) != want {
				return nil, mismatch(s.name, "other prepared bytes", "the stated ones")
			}
			c.Prepared = ptr(idcrypto.EncodeB64(prepared))
		}
		out = append(out, c)
	}
	return out, nil
}

func passwordProfileCases() ([]PasswordProfileCase, error) {
	type spec = profileSpec
	specs := []spec{
		{"twelve ASCII characters, new", "abcdefghijkl", true, same, ""},
		{"eleven code points, new", "abcdefghijk", true, "", "password_too_short"},
		{"eleven code points, presented at login", "abcdefghijk", false, same, ""},
		{"empty, presented at login", "", false, same, ""},
		{"empty, new", "", true, "", "password_too_short"},
		{"e and a combining acute compose under NFC", "cafe\u0301 au lait", true, "caf\u00e9 au lait", ""},
		{"code points are counted after NFC", "cafe\u0301 au lai", true, "", "password_too_short"},
		{"a singleton decomposition (U+212B) becomes U+00C5", "\u212bngstr\u00f6m units", false, "\u00c5ngstr\u00f6m units", ""},
		{"combining marks are reordered and composed", "d\u0307\u0323otted letter", false, "\u1e0d\u0307otted letter", ""},
		{"Hangul jamo compose to a syllable", "\u1100\u1161\u11a8 password", false, "\uac01 password", ""},
		{"NFC is not NFKC: a ligature stays", "\ufb01le password", false, same, ""},
		{"NFC is not NFKC: full-width letters stay", "\uff41\uff42\uff43 password", false, same, ""},
		{"every space separator becomes U+0020", "a" + allMappedSpaces + "b", true, "a" + strings.Repeat(" ", 16) + "b", ""},
		{"a zero width space is not a space and stays", "zero\u200bwidth space", false, same, ""},
		{"a no-break space before a combining accent becomes a space and keeps the accent", "pass\u00a0\u0301word-1234", false, "pass \u0301word-1234", ""},
		{"spaces are not trimmed", "  padded password  ", true, same, ""},
		{"twelve spaces are a valid new password", strings.Repeat(" ", 12), true, same, ""},
		{"NUL is refused", "password\x00-1234", false, "", "password_invalid"},
		{"a tab is refused", "pass\tword-1234", false, "", "password_invalid"},
		{"a line feed is refused", "password-1234\n", false, "", "password_invalid"},
		{"a carriage return is refused", "password-1234\r", false, "", "password_invalid"},
		{"DEL is refused", "pass\x7fword-1234", false, "", "password_invalid"},
		{"a C1 control (U+0085) is refused", "pass\u0085word-1234", false, "", "password_invalid"},
		{"the last C1 control (U+009F) is refused", "pass\u009fword-1234", false, "", "password_invalid"},
		{"a control character is refused before the length is counted", "\a", true, "", "password_invalid"},
		{"256 code points, new", strings.Repeat("a", 256), true, same, ""},
		{"257 code points", strings.Repeat("a", 257), false, "", "password_too_long"},
		{"twelve emoji are twelve code points", strings.Repeat("\U0001f600", 12), true, same, ""},
		{"eleven emoji are eleven code points, not twenty-two UTF-16 units", strings.Repeat("\U0001f600", 11), true, "", "password_too_short"},
		{"129 emoji are 129 code points, not 258 UTF-16 units", strings.Repeat("\U0001f600", 129), false, same, ""},
		{"256 emoji are 256 code points", strings.Repeat("\U0001f600", 256), false, same, ""},
		{"257 emoji are too many", strings.Repeat("\U0001f600", 257), false, "", "password_too_long"},
		{"six flags are twelve code points", strings.Repeat("\U0001f1e7\U0001f1f7", 6), true, same, ""},

		// Runs of combining marks (spec 2.1, step 2); the runs that only the
		// compatibility decomposition or the Hangul jamo make are in
		// passwordStreamSafeCases.
		{"thirty combining accents on one letter are prepared", "a" + strings.Repeat("\u0301", 30) + "bcdefghijk", true, "\u00e1" + strings.Repeat("\u0301", 29) + "bcdefghijk", ""},
		{"thirty-one combining accents on one letter are refused", "a" + strings.Repeat("\u0301", 31), false, "", "password_invalid"},
		{"sixteen U+0344 decompose to thirty-two marks and are refused", "a" + strings.Repeat("\u0344", 16), false, "", "password_invalid"},
		{"U+01D8 brings two marks of its own to a run", "\u01d8" + strings.Repeat("\u0301", 29), false, "", "password_invalid"},
		{"thirty-one spacing marks are refused too", "\u0915" + strings.Repeat("\u093e", 31), false, "", "password_invalid"},
		{"a letter between two runs of marks starts a new run", "a" + strings.Repeat("\u0301", 20) + "b" + strings.Repeat("\u0301", 20), true, "\u00e1" + strings.Repeat("\u0301", 19) + "b" + strings.Repeat("\u0301", 20), ""},
		{"thirty marks of two classes are reordered and composed", "e" + strings.Repeat("\u0301", 15) + strings.Repeat("\u0323", 15), false, "", ""},
		{"the run is checked before the length", strings.Repeat("\u0301", 31), true, "", "password_invalid"},
	}
	out, err := profileCases(specs)
	if err != nil {
		return nil, err
	}

	// Ill-formed UTF-16 and its WTF-8 spelling: lone and reversed surrogates.
	illFormed := []struct {
		name  string
		units []uint16
	}{
		{"a lone high surrogate", append(append(utf16.Encode([]rune("password")), 0xd800), utf16.Encode([]rune("1234"))...)},
		{"a lone low surrogate", append(append(utf16.Encode([]rune("password")), 0xdc00), utf16.Encode([]rune("1234"))...)},
		{"a reversed surrogate pair", append(append(utf16.Encode([]rune("password")), 0xdc00, 0xd800), utf16.Encode([]rune("1234"))...)},
		{"a lone high surrogate at the end", append(utf16.Encode([]rune("password1234")), 0xd83d)},
	}
	for _, s := range illFormed {
		raw := wtf8(s.units)
		_, err := prepare(string(raw), false)
		if got := idcrypto.ErrorCode(err); got != "password_invalid" {
			return nil, mismatch(s.name, got, "password_invalid")
		}
		out = append(out, PasswordProfileCase{
			Name:          s.name,
			PasswordUTF16: s.units,
			PasswordUTF8:  idcrypto.EncodeB64(raw),
			Error:         "password_invalid",
		})
	}
	return out, nil
}

// passwordStreamSafeCases are password-profile cases at and one past the run
// limit of spec 2.1, step 2, as adopted from kit SPEC section 11.2 on
// 2026-10-01: runs that only the compatibility decomposition, the Hangul
// vowel and final jamo or U+16D67 make, which the earlier rule (category M in
// the canonical decomposition) did not count. One past the limit, Go's
// normalizer would insert U+034F and the browser's would not, so both refuse;
// at the limit both prepare the password's NFC. They live in a file of their
// own so that password-profile.json stays byte for byte what Phase 1b handed
// to the kit, whose every case keeps its outcome. Every character is assigned
// by Unicode 15.0, apart from the refusal of thirty-one U+16D67, which every
// version counts.
func passwordStreamSafeCases() ([]PasswordProfileCase, error) {
	type spec = profileSpec
	acutes := func(n int) string { return strings.Repeat("\u0301", n) }
	return profileCases([]spec{
		{"thirty-one compatibility vowel jamo (U+3160) are refused", strings.Repeat("\u3160", 31), false, "", "password_invalid"},
		{"thirty compatibility vowel jamo (U+3160) are prepared", strings.Repeat("\u3160", 30), true, same, ""},
		{"a Hangul syllable then twenty-nine acute accents is refused", "\uac01" + acutes(29), false, "", "password_invalid"},
		{"a Hangul syllable then twenty-eight acute accents is prepared", "\uac01" + acutes(28), true, same, ""},
		{"U+00B4 then thirty acute accents is refused", "\u00b4" + acutes(30), false, "", "password_invalid"},
		{"U+00B4 then twenty-nine acute accents is prepared", "\u00b4" + acutes(29), true, same, ""},
		{"a vowel jamo (U+1161) then thirty acute accents is refused", "\u1161" + acutes(30), false, "", "password_invalid"},
		{"a vowel jamo (U+1161) then twenty-nine acute accents is prepared", "\u1161" + acutes(29), true, same, ""},
		{"thirty-one halfwidth voiced sound marks (U+FF9E) are refused", "a" + strings.Repeat("\uff9e", 31), false, "", "password_invalid"},
		{"thirty halfwidth voiced sound marks (U+FF9E) are prepared", "a" + strings.Repeat("\uff9e", 30), true, same, ""},
		{"thirty-one halfwidth jamo (U+FFA3) are refused", "a" + strings.Repeat("\uffa3", 31), false, "", "password_invalid"},
		{"thirty halfwidth jamo (U+FFA3) are prepared", "a" + strings.Repeat("\uffa3", 30), true, same, ""},
		{"thirty-one U+16D67 are refused", "a" + strings.Repeat("\U00016d67", 31), false, "", "password_invalid"},
		{"thirty-one syllables are runs of two and are prepared", strings.Repeat("\uac01", 31), true, same, ""},
		{"conjoining jamo compose to syllables", strings.Repeat("\u1100\u1161\u11a8", 11), false, strings.Repeat("\uac01", 11), ""},
		{"thirty-one combining accents on one letter are still refused", "a" + acutes(31), false, "", "password_invalid"},
		{"U+01D8 and twenty-nine acute accents are still refused", "\u01d8" + acutes(29), false, "", "password_invalid"},
		{"thirty-one spacing marks are still refused", "\u0915" + strings.Repeat("\u093e", 31), false, "", "password_invalid"},
		{"sixteen U+0344 are still refused", "a" + strings.Repeat("\u0344", 16), false, "", "password_invalid"},
	})
}

func prepare(password string, isNew bool) ([]byte, error) {
	if isNew {
		return idcrypto.PrepareNewPassword(password)
	}
	return idcrypto.PreparePassword(password)
}

// wtf8 encodes UTF-16 code units the way a lax encoder would: pairs as one
// code point, lone surrogates as their own three bytes. Those bytes are not
// UTF-8, which is the point.
func wtf8(units []uint16) []byte {
	var out []byte
	for i := 0; i < len(units); i++ {
		u := rune(units[i])
		if utf16.IsSurrogate(u) && i+1 < len(units) {
			if r := utf16.DecodeRune(u, rune(units[i+1])); r != 0xfffd {
				out = appendCodePoint(out, r)
				i++
				continue
			}
		}
		out = appendCodePoint(out, u)
	}
	return out
}

// appendCodePoint writes r in the UTF-8 bit layout even when r is a
// surrogate, which utf8.AppendRune would replace with U+FFFD.
func appendCodePoint(b []byte, r rune) []byte {
	u := uint32(r) //nolint:gosec // callers pass code points, never negative runes
	six := func(shift uint) byte { return 0x80 | byte(u>>shift&0x3f) }
	switch {
	case u < 0x80:
		return append(b, byte(u))
	case u < 0x800:
		return append(b, 0xc0|byte(u>>6), six(0))
	case u < 0x10000:
		return append(b, 0xe0|byte(u>>12), six(6), six(0))
	default:
		return append(b, 0xf0|byte(u>>18&0x07), six(12), six(6), six(0))
	}
}

// KDFCase is one kdf vector (spec 2.2): Argon2id over the prepared password
// and salt, then HKDF into K_auth and K_wrap. AuthKey is K_auth as sent on
// the wire, which is the same text as KAuth. Error cases must be refused
// before anything is derived.
type KDFCase struct {
	Name     string       `json:"name"`
	Prepared string       `json:"prepared_b64url"`
	Salt     string       `json:"salt"`
	KDF      idcrypto.KDF `json:"kdf"`
	KAuth    string       `json:"k_auth,omitempty"`
	KWrap    string       `json:"k_wrap,omitempty"`
	AuthKey  string       `json:"auth_key,omitempty"`
	Error    string       `json:"error,omitempty"`
}

func kdfCases() ([]KDFCase, error) {
	ascii, err := idcrypto.PrepareNewPassword("correct horse battery staple")
	if err != nil {
		return nil, err
	}
	accented, err := idcrypto.PrepareNewPassword("pa\u0303o de queijo e cafe\u0301 \u2615")
	if err != nil {
		return nil, err
	}
	salt := seeded("kdf/salt", idcrypto.SaltLen)
	floor := idcrypto.DefaultKDF
	with := func(f func(*idcrypto.KDF)) idcrypto.KDF { k := floor; f(&k); return k }

	type spec struct {
		name     string
		prepared []byte
		salt     []byte
		kdf      idcrypto.KDF
		err      string
	}
	specs := []spec{
		{"the floor parameters", ascii, salt, floor, ""},
		{"a non-ASCII password at the floor", accented, seeded("kdf/salt-2", idcrypto.SaltLen), floor, ""},
		// Lanes are where two Argon2id implementations part ways if they do;
		// m and t stay at the floor, so this costs what a floor case costs.
		{"four lanes at the floor memory and time", ascii, salt, with(func(k *idcrypto.KDF) { k.P = 4 }), ""},
		{"m below the floor", ascii, salt, with(func(k *idcrypto.KDF) { k.M = 65535 }), "kdf_policy"},
		{"m above the ceiling", ascii, salt, with(func(k *idcrypto.KDF) { k.M = 262145 }), "kdf_policy"},
		{"m of zero", ascii, salt, with(func(k *idcrypto.KDF) { k.M = 0 }), "kdf_policy"},
		{"t below the floor", ascii, salt, with(func(k *idcrypto.KDF) { k.T = 2 }), "kdf_policy"},
		{"t above the ceiling", ascii, salt, with(func(k *idcrypto.KDF) { k.T = 11 }), "kdf_policy"},
		{"p below the floor", ascii, salt, with(func(k *idcrypto.KDF) { k.P = 0 }), "kdf_policy"},
		{"p above the ceiling", ascii, salt, with(func(k *idcrypto.KDF) { k.P = 5 }), "kdf_policy"},
		{"m times t just over the cap", ascii, salt, with(func(k *idcrypto.KDF) { k.M = 104858; k.T = 10 }), "kdf_policy"},
		{"m times t over the cap with each inside its bounds", ascii, salt, with(func(k *idcrypto.KDF) { k.M = 131072; k.T = 9 }), "kdf_policy"},
		{"the ceilings of m and t together", ascii, salt, with(func(k *idcrypto.KDF) { k.M = 262144; k.T = 10 }), "kdf_policy"},
		{"alg argon2i", ascii, salt, with(func(k *idcrypto.KDF) { k.Alg = "argon2i" }), "kdf_policy"},
		{"alg in another case", ascii, salt, with(func(k *idcrypto.KDF) { k.Alg = "Argon2id" }), "kdf_policy"},
		{"alg empty", ascii, salt, with(func(k *idcrypto.KDF) { k.Alg = "" }), "kdf_policy"},
		{"a salt of 15 bytes", ascii, salt[:15], floor, "kdf_policy"},
		{"a salt of 17 bytes", ascii, append(salt[:16:16], 0x00), floor, "kdf_policy"},
		{"an empty salt", ascii, []byte{}, floor, "kdf_policy"},
	}
	var out []KDFCase
	for _, s := range specs {
		c := KDFCase{Name: s.name, Prepared: idcrypto.EncodeB64(s.prepared), Salt: idcrypto.EncodeB64(s.salt), KDF: s.kdf}
		keys, err := idcrypto.DerivePassword(s.prepared, s.salt, s.kdf)
		if got := idcrypto.ErrorCode(err); got != s.err || (err != nil && got == "") {
			return nil, mismatch(s.name, got, s.err)
		}
		if err != nil {
			c.Error = s.err
		} else {
			c.KAuth = idcrypto.EncodeB64(keys.Auth[:])
			c.KWrap = idcrypto.EncodeB64(keys.Wrap[:])
			c.AuthKey = keys.AuthKey()
			keys.Zero()
		}
		out = append(out, c)
	}
	return out, nil
}
