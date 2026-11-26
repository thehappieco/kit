package contract

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Trial codes (SPEC section 11.20): an app computes a keyed code for each
// identity of an item, so that no identifier crosses the contract. A code
// is personal data: with the app's key, the code of any phone number or
// LID is found by trying every identifier. So the key (TrialKey) is never
// printed or logged, and no error of this package carries an identifier or
// a code.
//
//	code = base64url-nopad( HMAC-SHA256( key = K_app (32 raw bytes),
//	         msg = "thehappie-trial/v1" || 0x00 || app || 0x00 || kind || 0x00 || identifier ) )

// The values of a trial code.
const (
	// TrialCodeLabel opens every code's message.
	TrialCodeLabel = "thehappie-trial/v1"
	// TrialKeyLen is K_app's length, in bytes.
	TrialKeyLen = 32
	// TrialCodeLen is a code's length: 43 characters of unpadded base64url,
	// the one canonical spelling of 32 bytes.
	TrialCodeLen = 43
	// MaxTrialCodes is the most codes a link check or an event carries.
	MaxTrialCodes = 4

	// The kinds of identity. Wappie's (and the reference app's): a number's
	// own phone number and its LID. Mailie's: a Google account's sub, a
	// Microsoft account's tid and sub, a mailbox's address, and an IMAP
	// login on a host that is not a provider's own.
	TrialKindE164      = "e164"
	TrialKindWALID     = "wa_lid"
	TrialKindGoogleSub = "google_sub"
	TrialKindMSTidSub  = "ms_tid_sub"
	TrialKindAddress   = "address"
	TrialKindIMAPLogin = "imap_login"
)

var (
	numberKinds  = []string{TrialKindE164, TrialKindWALID}
	mailboxKinds = []string{TrialKindGoogleSub, TrialKindMSTidSub, TrialKindAddress, TrialKindIMAPLogin}
	// providerIMAPHosts are the IMAP hosts a provider owns, where a login
	// with @ proves an address: Google's two and iCloud's. A host added is
	// a change of the spec, with a new vectors file.
	providerIMAPHosts = []string{"imap.gmail.com", "imap.googlemail.com", "imap.mail.me.com"}
)

// TrialCodeKinds are the kinds of identity app makes codes of: Wappie's and
// the reference app's e164 and wa_lid, Mailie's google_sub, ms_tid_sub,
// address and imap_login; none for an app the part does not know. It
// returns a copy.
func TrialCodeKinds(app string) []string {
	switch kind, _ := AppItemKind(app); kind {
	case ItemNumber:
		return slices.Clone(numberKinds)
	case ItemMailbox:
		return slices.Clone(mailboxKinds)
	}
	return nil
}

// ProviderIMAPHosts are the IMAP hosts a provider owns, lowercased, where a
// login with @ makes an address code: imap.gmail.com, imap.googlemail.com
// and imap.mail.me.com. It returns a copy.
func ProviderIMAPHosts() []string { return slices.Clone(providerIMAPHosts) }

// ErrNoCode means an identifier makes no code: it is empty or holds a zero
// byte or invalid UTF-8, or it is not of its kind's form (an e164 that is
// not a + and 2 to 15 digits, the first not 0; an address with no @, or
// with an empty local part or domain once normalized). An item with no
// identifier that makes a code holds no clock and sends no event of
// codes. It is never ErrInvalid, which is a caller's fault.
var ErrNoCode = errors.New("contract: the identifier makes no trial code")

// TrialKey is an app's K_app: 32 random bytes, a tier-2 key of the app's
// own, which serves this HMAC alone. It is never printed, logged or
// serialised: it holds only a function that makes the HMAC, its bytes
// inside it, so that reflection reaches no byte of it (fmt shows only an
// address for a TrialKey held in an unexported field, in every verb, and
// encoding/json leaves such a field out); String, GoString, Format and
// LogValue hide it, and MarshalJSON and MarshalText refuse. The zero
// TrialKey is no key.
type TrialKey struct{ mac func() hash.Hash }

// NewTrialKey is the key of b, exactly TrialKeyLen bytes and not all zero.
// It copies b.
func NewTrialKey(b []byte) (TrialKey, error) {
	if len(b) != TrialKeyLen {
		return TrialKey{}, invalid("a trial key is %d bytes", TrialKeyLen)
	}
	var k [TrialKeyLen]byte
	copy(k[:], b)
	if k == ([TrialKeyLen]byte{}) {
		return TrialKey{}, invalid("a trial key is not all zero")
	}
	return TrialKey{func() hash.Hash { return hmac.New(sha256.New, k[:]) }}, nil
}

// String hides the key.
func (TrialKey) String() string { return "contract.TrialKey{" + Ellipsis + "}" }

// GoString is String, for %#v.
func (k TrialKey) GoString() string { return k.String() }

// Format hides the key in every verb, %x and %d included.
func (k TrialKey) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.String()) }

// LogValue hides the key from a structured log.
func (TrialKey) LogValue() slog.Value { return slog.StringValue(Ellipsis) }

// MarshalJSON refuses: a key is never serialised, so a struct that holds
// one in an exported field never writes it.
func (TrialKey) MarshalJSON() ([]byte, error) { return nil, invalid("a trial key is never serialised") }

// MarshalText refuses, as MarshalJSON does.
func (TrialKey) MarshalText() ([]byte, error) { return nil, invalid("a trial key is never serialised") }

// TrialCode is the trial code of identifier, of kind, for app, under key.
// It normalizes identifier by its kind first (NormalizeTrialIdentifier), so
// that no caller can skip it, and returns ErrNoCode when the identifier
// makes none. A key that is zero, an app the part does not know, or a kind
// that is not one of app's is ErrInvalid.
func TrialCode(key TrialKey, app, kind, identifier string) (string, error) {
	switch {
	case key.mac == nil:
		return "", invalid("no trial key")
	case !slices.Contains(TrialCodeKinds(app), kind):
		return "", invalid("the kind is not one of the app's")
	}
	id, ok := NormalizeTrialIdentifier(kind, identifier)
	if !ok {
		return "", ErrNoCode
	}
	mac := key.mac()
	for i, part := range []string{TrialCodeLabel, app, kind, id} {
		if i > 0 {
			mac.Write([]byte{0})
		}
		mac.Write([]byte(part))
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// ValidTrialCode reports whether s is a trial code's spelling: 43
// characters of unpadded base64url, the last one's low two bits zero, so
// that it is the one canonical spelling of 32 bytes.
func ValidTrialCode(s string) bool { return validSecret(s) }

var (
	e164RE  = regexp.MustCompile(`^\+[1-9][0-9]{1,14}$`)
	waLIDRE = regexp.MustCompile(`^[0-9]+$`)
)

// NormalizeTrialIdentifier is identifier normalized as kind's code takes
// it, or false when it makes no code. Every kind refuses an empty
// identifier, one holding a zero byte, and invalid UTF-8.
//
//   - e164: + and 2 to 15 ASCII digits, the first not 0, taken as given and
//     never reformatted (no digit added or removed): the number's own
//     phone-number JID's user part, never one a person typed.
//   - wa_lid: the LID's user part, ASCII digits, as given.
//   - google_sub: the ID token's sub, as given.
//   - ms_tid_sub: tid, "/", sub, as given (MSTidSub): one "/", neither half
//     empty.
//   - address: ASCII letters lowercased, nothing else changed or trimmed;
//     the domain is what follows the last @, the local part what precedes
//     it; for gmail.com and googlemail.com only, the domain becomes
//     gmail.com, the local part is cut at its first + and every . left in
//     it is removed. No @, or an empty local part or domain once
//     normalized, makes no code.
//   - imap_login: host "/" login, the host as IMAPIdentity normalizes it
//     and the login with its ASCII letters lowercased, nothing else
//     changed; a login with @ on a provider's own host is an address, so
//     it makes no imap_login code.
func NormalizeTrialIdentifier(kind, identifier string) (string, bool) {
	if identifier == "" || strings.IndexByte(identifier, 0) >= 0 || !utf8.ValidString(identifier) {
		return "", false
	}
	switch kind {
	case TrialKindE164:
		return identifier, e164RE.MatchString(identifier)
	case TrialKindWALID:
		return identifier, waLIDRE.MatchString(identifier)
	case TrialKindGoogleSub:
		return identifier, true
	case TrialKindMSTidSub:
		tid, sub, _ := strings.Cut(identifier, "/")
		return MSTidSub(tid, sub)
	case TrialKindAddress:
		return normalizeAddress(identifier)
	case TrialKindIMAPLogin:
		host, login, ok := strings.Cut(identifier, "/")
		if !ok {
			return "", false
		}
		k, id, ok := IMAPIdentity(host, login)
		if !ok || k != TrialKindIMAPLogin {
			return "", false
		}
		return id, true
	}
	return "", false
}

// MSTidSub is a Microsoft account's ms_tid_sub identifier: tid, "/", sub,
// as the ID token gives them, from the cloud's single web client; false
// when either is empty, holds a "/" or a zero byte, or is invalid UTF-8.
func MSTidSub(tid, sub string) (string, bool) {
	for _, s := range []string{tid, sub} {
		if s == "" || strings.ContainsAny(s, "/\x00") || !utf8.ValidString(s) {
			return "", false
		}
	}
	return tid + "/" + sub, true
}

// lowerASCII lowercases the ASCII letters of s and changes nothing else: a
// non-ASCII character is taken as given.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// normalizeAddress is an address as its code takes it, or false when it
// makes none.
func normalizeAddress(s string) (string, bool) {
	s = lowerASCII(s)
	at := strings.LastIndexByte(s, '@')
	if at < 0 {
		return "", false
	}
	local, domain := s[:at], s[at+1:]
	if domain == "gmail.com" || domain == "googlemail.com" {
		domain = "gmail.com"
		local, _, _ = strings.Cut(local, "+")
		local = strings.ReplaceAll(local, ".", "")
	}
	if local == "" || domain == "" {
		return "", false
	}
	return local + "@" + domain, true
}

// IMAPIdentity is the kind and identifier of an IMAP login on host, the
// host the app dialled: on a provider's own host (ProviderIMAPHosts), a
// login with @ is an address (normalized as one, so a Gmail mailbox linked
// by Google's sign-in and by imap.gmail.com meets); on any other host, and
// for a login without @ on a provider's own host, it is an imap_login,
// host "/" login, which never meets an address.
//
// The host is taken in ASCII, as A-labels: the caller converts a U-label
// first, and a non-ASCII host is false. Its ASCII letters are lowercased,
// a port (":" and 1 to 65535, with no leading zero) dropped, and one
// trailing dot dropped. A host dialled by address is an IP literal, an
// IPv6 one with or without its brackets: it is written as netip writes it
// (dotted IPv4, an IPv4-mapped IPv6 address as its IPv4, IPv6 in RFC 5952
// form without brackets), so that 2001:DB8::1 and [2001:db8::1]:993 meet;
// one with a zone is false. Any other host is a host name (ValidHost), or
// false. The login's ASCII letters are lowercased and nothing else changes
// (no Gmail folding). An empty login, or one holding a zero byte or
// invalid UTF-8, is false.
//
// That the TLS certificate was verified for the name dialled is the app's
// to check, as is that the login succeeded: a code is made only once
// ownership is proven.
func IMAPIdentity(host, login string) (kind, identifier string, ok bool) {
	host, ok = imapHost(host)
	if !ok || login == "" || strings.IndexByte(login, 0) >= 0 || !utf8.ValidString(login) {
		return "", "", false
	}
	if slices.Contains(providerIMAPHosts, host) && strings.Contains(login, "@") {
		id, ok := normalizeAddress(login)
		if !ok {
			return "", "", false
		}
		return TrialKindAddress, id, true
	}
	return TrialKindIMAPLogin, host + "/" + lowerASCII(login), true
}

// imapHost is host as an imap_login code takes it (IMAPIdentity), or false.
func imapHost(host string) (string, bool) {
	host = lowerASCII(host)
	bracketed := strings.HasPrefix(host, "[")
	switch {
	case bracketed:
		end := strings.IndexByte(host, ']')
		if end < 0 {
			return "", false
		}
		rest := host[end+1:]
		host = host[1:end]
		if rest != "" {
			port, ok := strings.CutPrefix(rest, ":")
			if !ok || !validPort(port) {
				return "", false
			}
		}
	case strings.Count(host, ":") == 1:
		name, port, _ := strings.Cut(host, ":")
		if !validPort(port) {
			return "", false
		}
		host = name
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Zone() != "" || (bracketed && !a.Is6()) {
			return "", false
		}
		return a.Unmap().String(), true
	}
	if bracketed {
		return "", false
	}
	host = strings.TrimSuffix(host, ".")
	if a, err := netip.ParseAddr(host); err == nil && a.Is4() {
		return a.String(), true
	}
	if !ValidHost(host) {
		return "", false
	}
	return host, true
}

// validPort reports whether s is a port: 1 to 65535, with no leading zero.
func validPort(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == s
}

// TrialCodes are the codes an event carries: on item.linked and
// item.identity_updated, required, 1 to MaxTrialCodes, each once; absent
// (nil) on every other type. Present, the list is never null. A link
// check's codes are TrialCodes too, [] for none.
//
// A code is personal data: String, GoString, Format (every verb) and
// LogValue print only how many codes the list holds, never a code. Its
// JSON is the list itself, so a value that holds codes and has no
// LogValue of its own (a []Event, an app's own struct) is never logged
// through a handler that encodes JSON.
type TrialCodes []string

// String is how many codes the list holds, never a code.
func (c TrialCodes) String() string {
	return "contract.TrialCodes{" + strconv.Itoa(len(c)) + " codes}"
}

// GoString is String, for %#v.
func (c TrialCodes) GoString() string { return c.String() }

// Format prints String for every verb, %q quoted, so that no verb reaches
// a code.
func (c TrialCodes) Format(f fmt.State, verb rune) { formatAs(f, verb, c.String()) }

// formatAs writes s, a value's String, for every verb of fmt, quoted for
// %q: a type whose fields hold a code, a figure, a step or a MAC gives
// its Format to it, so that no verb (%d, %o, %x, %t and the rest included)
// walks its fields.
func formatAs(f fmt.State, verb rune, s string) {
	if verb == 'q' {
		_, _ = io.WriteString(f, strconv.Quote(s))
		return
	}
	_, _ = io.WriteString(f, s)
}

// LogValue is how many codes the list holds, never a code.
func (c TrialCodes) LogValue() slog.Value { return slog.IntValue(len(c)) }

// UnmarshalJSON reads the list, refusing null, which would read as absent,
// and anything but strings; Validate checks its codes.
func (c *TrialCodes) UnmarshalJSON(b []byte) error {
	var v []string
	if string(bytes.TrimSpace(b)) == "null" || json.Unmarshal(b, &v) != nil {
		return invalid("codes is absent, never null, and lists strings")
	}
	for _, e := range v {
		if e == "" {
			// A null element reads as "": refuse it here, as no code.
			return invalid("codes: each a trial code")
		}
	}
	if v == nil {
		v = []string{}
	}
	*c = v
	return nil
}

// validTrialCodes checks a list of codes: at most max, each a valid code
// and once.
func validTrialCodes(codes []string, maxCodes int) error {
	if len(codes) > maxCodes {
		return invalid("codes: at most %d", maxCodes)
	}
	seen := make(map[string]bool, len(codes))
	for _, c := range codes {
		if !ValidTrialCode(c) || seen[c] {
			return invalid("codes: each a trial code, once")
		}
		seen[c] = true
	}
	return nil
}
