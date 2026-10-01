package platform

import (
	"bytes"
	"fmt"
	"strings"
)

// Email normalisation, version 1 (section 11.8): ASCII addresses only.
const (
	// MaxEmailLen bounds the whole normalised address, in bytes.
	MaxEmailLen = 254
	// MaxEmailLocalLen bounds the local part.
	MaxEmailLocalLen = 64
	// MaxEmailDomainLen bounds the domain.
	MaxEmailDomainLen = 253
	// MaxEmailLabelLen bounds one domain label.
	MaxEmailLabelLen = 63
)

// emailLocalSymbols are the non-alphanumeric characters a local part may
// hold: RFC 5322 atext, plus '.' between atoms.
const emailLocalSymbols = ".!#$%&'*+/=?^_`{|}~-"

// NormalizeEmail returns email_norm, the account's address (section 11.8):
//
//  1. trim ASCII spaces, tabs and line breaks at both ends;
//  2. every remaining byte is printable ASCII, 0x21 to 0x7E;
//  3. lower-case ASCII letters;
//  4. exactly one '@'; a local part of 1 to 64 bytes from
//     [a-z0-9.!#$%&'*+/=?^_`{|}~-], not starting or ending with '.', without
//     "..";
//  5. a domain of 1 to 253 bytes with at least two labels, each 1 to 63
//     bytes of [a-z0-9-], not starting or ending with '-', the last one not
//     all digits;
//  6. at most 254 bytes in all.
//
// There is no folding of dots or '+' tags. Refusals wrap ErrEmailInvalid and
// never repeat the address. Non-ASCII input is refused before any case
// mapping, so a Kelvin sign or a dotted capital I can never become a 'k' or
// an 'i'.
func NormalizeEmail(s string) (string, error) {
	s = strings.Trim(s, " \t\r\n")
	if len(s) == 0 {
		return "", fmt.Errorf("%w: empty", ErrEmailInvalid)
	}
	if len(s) > MaxEmailLen {
		return "", fmt.Errorf("%w: longer than %d bytes", ErrEmailInvalid, MaxEmailLen)
	}
	b := []byte(s)
	for i, c := range b {
		if c < 0x21 || c > 0x7e {
			return "", fmt.Errorf("%w: a byte that is not printable ASCII", ErrEmailInvalid)
		}
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	at := bytes.IndexByte(b, '@')
	if at < 0 || bytes.IndexByte(b[at+1:], '@') >= 0 {
		return "", fmt.Errorf("%w: not exactly one '@'", ErrEmailInvalid)
	}
	if err := checkEmailLocal(b[:at]); err != nil {
		return "", err
	}
	if err := checkEmailDomain(b[at+1:]); err != nil {
		return "", err
	}
	return string(b), nil
}

func checkEmailLocal(local []byte) error {
	if len(local) < 1 || len(local) > MaxEmailLocalLen {
		return fmt.Errorf("%w: local part of %d bytes", ErrEmailInvalid, len(local))
	}
	for _, c := range local {
		if !lowerAlnum(c) && strings.IndexByte(emailLocalSymbols, c) < 0 {
			return fmt.Errorf("%w: a character not allowed in the local part", ErrEmailInvalid)
		}
	}
	if local[0] == '.' || local[len(local)-1] == '.' || bytes.Contains(local, []byte("..")) {
		return fmt.Errorf("%w: misplaced '.' in the local part", ErrEmailInvalid)
	}
	return nil
}

func checkEmailDomain(domain []byte) error {
	if len(domain) < 1 || len(domain) > MaxEmailDomainLen {
		return fmt.Errorf("%w: domain of %d bytes", ErrEmailInvalid, len(domain))
	}
	labels := bytes.Split(domain, []byte("."))
	if len(labels) < 2 {
		return fmt.Errorf("%w: a domain with one label", ErrEmailInvalid)
	}
	for _, l := range labels {
		if len(l) < 1 || len(l) > MaxEmailLabelLen {
			return fmt.Errorf("%w: a domain label of %d bytes", ErrEmailInvalid, len(l))
		}
		for _, c := range l {
			if !lowerAlnum(c) && c != '-' {
				return fmt.Errorf("%w: a character not allowed in the domain", ErrEmailInvalid)
			}
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("%w: a domain label starting or ending with '-'", ErrEmailInvalid)
		}
	}
	allDigits := true
	for _, c := range labels[len(labels)-1] {
		if c < '0' || c > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return fmt.Errorf("%w: an all-digit top-level label", ErrEmailInvalid)
	}
	return nil
}

func lowerAlnum(c byte) bool { return 'a' <= c && c <= 'z' || '0' <= c && c <= '9' }
