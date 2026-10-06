//go:build go1.26

package idvectors

import (
	"fmt"
	"strings"

	idcrypto "github.com/thehappieco/kit/profiles/platform"
)

// RPIDEndsInNumberCase is one case of rp-id-ends-in-number.json (spec 8.1):
// a relying party id that a browser's host parser (the WHATWG URL Standard)
// reads as an IPv4 address, or refuses, because its last label "ends in a
// number", although idcrypto.ValidRPID of kit v0.4.0 accepts it. The file is
// new since the switch to the kit (decision 0017: new cases come as new
// files), and the kit is asked to adopt the rule with it
// (docs/handoff/2026-10-05-wappie-kit-rpid.md).
//
// Every case has rp_id and ends_in_a_number, the outcome of the WHATWG "ends
// in a number checker" on rp_id. A relying party id is accepted when
// ValidRPID accepts it and it does not end in a number; an accepted case
// carries prf_salt, PRF_SALT of rp_id (spec 8.2), and a refused one "error":
// "wrap", the refusal PRFSalt gives a relying party id it does not accept.
//
// Until the kit adopts the rule, the platform applies it on its own
// (internal/rpid, which internal/config applies to the id. origin and
// internal/id to the service's relying party), and reads this file there.
type RPIDEndsInNumberCase struct {
	Name          string `json:"name"`
	RPID          string `json:"rp_id"`
	EndsInANumber bool   `json:"ends_in_a_number"`
	PRFSalt       string `json:"prf_salt,omitempty"`
	Error         string `json:"error,omitempty"`
}

func rpIDEndsInNumberCases() ([]RPIDEndsInNumberCase, error) {
	const refused = "wrap"
	specs := []struct {
		name, rpID    string
		endsInANumber bool
		err           string
	}{
		// Accepted: a domain name in its one spelling whose last label a
		// URL parser keeps as a label.
		{"the production relying party", prodRPID, false, ""},
		{"the development relying party", devRPID, false, ""},
		{"a hexadecimal number as the first label, which does not count", "0x7f000001.thehappie.co", false, ""},
		{"a last label of 0x and a letter that is no hex digit", "id.0x1g", false, ""},
		{"a single label of 0x, a hex digit and a letter that is no hex digit", "0x1g", false, ""},
		{"a last label of 0x twice, whose second x is no hex digit", "id.0x0x", false, ""},
		{"a last label of 0x, hex digits and a dash", "id.0xabc-def", false, ""},
		{"a last label of 00x1: a leading zero makes it octal, and x is no octal digit", "id.00x1", false, ""},
		{"a last label of a decimal with an exponent", "id.1e3", false, ""},
		{"a last label of 0b and a binary digit", "id.0b1", false, ""},
		{"a last label of x and hex digits", "id.x7f", false, ""},
		{"a last label of digits and a letter", "1.2.3.4a", false, ""},

		// Refused: the last label is a number to a URL parser.
		{"a hexadecimal IPv4 address in one label", "0x7f000001", true, refused},
		{"a hexadecimal last label", "id.0xff", true, refused},
		{"a dotted address whose last part is hexadecimal", "1.2.3.0x4", true, refused},
		{"0x alone, which is the number zero", "0x", true, refused},
		{"a last label of 0x alone", "id.0x", true, refused},
		{"0x as both labels", "0x.0x", true, refused},
		{"a hexadecimal last label past 32 bits", "id.thehappie.0x100000000", true, refused},
		{"a hexadecimal last label with many leading zeros", "a.0x00000000000000000000001", true, refused},
		{"a hexadecimal IPv4 address in one label, in upper case", "0X7F000001", true, refused},
		{"a hexadecimal last label with 0X in upper case", "x.0XFF", true, refused},
		{"a hexadecimal last label before a trailing dot", "id.0x1.", true, refused},
		// Refused by ValidRPID already: an all-decimal last label.
		{"a dotted-decimal IPv4 address", "127.0.0.1", true, refused},
		{"a decimal last label", "id.thehappie.123", true, refused},
		{"a decimal last label with a leading zero and a digit that is not octal", "id.09", true, refused},
		{"a dotted-decimal IPv4 address with a trailing dot", "1.2.3.4.", true, refused},
		// Refused by ValidRPID for empty labels, although only one trailing
		// empty label is dropped before the check, so neither ends in a
		// number.
		{"a lone dot", ".", false, refused},
		{"a hexadecimal label before two trailing dots", "id.0x1..", false, refused},
	}
	var out []RPIDEndsInNumberCase
	for _, s := range specs {
		ends := endsInANumber(s.rpID)
		if ends != s.endsInANumber {
			return nil, fmt.Errorf("case %q: ends in a number: got %t, declared %t", s.name, ends, s.endsInANumber)
		}
		c := RPIDEndsInNumberCase{Name: s.name, RPID: s.rpID, EndsInANumber: ends}
		got := ""
		if idcrypto.ValidRPID(s.rpID) && !ends {
			salt, err := idcrypto.PRFSalt(s.rpID)
			if err != nil {
				return nil, fmt.Errorf("case %q: PRFSalt: %w", s.name, err)
			}
			c.PRFSalt = idcrypto.EncodeB64(salt)
		} else {
			got = refused
			c.Error = refused
		}
		if got != s.err {
			return nil, mismatch(s.name, got, s.err)
		}
		// Where the kit refuses the id already, it refuses it as the file
		// says.
		if !idcrypto.ValidRPID(s.rpID) {
			if _, err := idcrypto.PRFSalt(s.rpID); idcrypto.ErrorCode(err) != refused {
				return nil, mismatch(s.name, idcrypto.ErrorCode(err), refused)
			}
		}
		out = append(out, c)
	}
	return out, nil
}

// endsInANumber is the "ends in a number checker" of the WHATWG URL
// Standard (https://url.spec.whatwg.org/#ends-in-a-number-checker), step by
// step. A browser's host parser runs it on every domain; when it is true,
// the host is parsed as an IPv4 address, or is refused, and is never a
// domain.
func endsInANumber(input string) bool {
	// 1. Let parts be the result of strictly splitting input on ".".
	parts := strings.Split(input, ".")
	// 2. If the last item in parts is the empty string: if parts's size is
	// 1, return false; remove the last item from parts.
	if parts[len(parts)-1] == "" {
		if len(parts) == 1 {
			return false
		}
		parts = parts[:len(parts)-1]
	}
	// 3. Let last be the last item in parts.
	last := parts[len(parts)-1]
	// 4. If last is non-empty and contains only ASCII digits, return true.
	if last != "" && strings.IndexFunc(last, func(r rune) bool { return r < '0' || r > '9' }) < 0 {
		return true
	}
	// 5. If parsing last as an IPv4 number does not return failure, return
	// true.
	// 6. Return false.
	return isIPv4Number(last)
}

// isIPv4Number reports whether the WHATWG "IPv4 number parser"
// (https://url.spec.whatwg.org/#ipv4-number-parser) does not return failure
// for input. Only whether it fails matters here, not the value.
func isIPv4Number(input string) bool {
	// 1. If input is the empty string, return failure.
	if input == "" {
		return false
	}
	// 2. Let R be 10.
	radix := 10
	switch {
	// 3. If input contains at least two code points and the first two are
	// "0X" or "0x": remove them, and set R to 16.
	case len(input) >= 2 && (input[:2] == "0x" || input[:2] == "0X"):
		input, radix = input[2:], 16
	// 4. Otherwise, if input contains at least two code points and the
	// first is "0": remove it, and set R to 8.
	case len(input) >= 2 && input[0] == '0':
		input, radix = input[1:], 8
	}
	// 5. If input is the empty string, return (0, true).
	if input == "" {
		return true
	}
	// 6. If input contains a code point that is not a radix-R digit, return
	// failure.
	for _, r := range input {
		if !isRadixDigit(r, radix) {
			return false
		}
	}
	return true
}

func isRadixDigit(r rune, radix int) bool {
	switch radix {
	case 8:
		return '0' <= r && r <= '7'
	case 16:
		return ('0' <= r && r <= '9') || ('a' <= r && r <= 'f') || ('A' <= r && r <= 'F')
	}
	return '0' <= r && r <= '9'
}
