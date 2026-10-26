package contract

import (
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// The token's layout (SPEC section 11.18; the platform's decision 0053):
// "thc_", a selector of 8 random bytes in lowercase hex, a dot, and a
// secret of 32 random bytes in unpadded base64url, 64 ASCII characters in
// all.
const (
	TokenLen         = 64
	TokenPrefix      = "thc_"
	SelectorLen      = 16
	TokenSecretLen   = 43
	TokenSecretBytes = 32
)

// The labels of the token part's two hashes, each followed by one zero
// byte before what it hashes.
const (
	TokenHashLabel  = "thehappie-token/v1/secret"
	ReadingKeyLabel = "thehappie-token/v1/reading-key"
)

// ErrToken is the root of every refusal of a token: ParseToken's,
// BearerToken's and VerifyToken's. An app answers each with its one
// invalid_token (HTTP 401), whatever the cause. No error names a byte of
// the token.
var ErrToken = errors.New("contract: not a valid token")

// TokenError is a refusal of ParseToken or BearerToken: the step of the
// check that refused the text (SPEC section 11.18), and the rule of that
// step. Step 0 is the Authorization header around the token (BearerToken);
// steps 1 to 6 are the token's own:
//  1. exactly 64 bytes, every one ASCII;
//  2. it starts with "thc_";
//  3. bytes 4 to 19 are [0-9a-f];
//  4. byte 20 is ".";
//  5. bytes 21 to 63 are [A-Za-z0-9_-];
//  6. the last character is canonical: its two low bits are zero, so the 43
//     characters are the one spelling of 32 bytes.
//
// It matches ErrToken.
type TokenError struct {
	Step int
	Rule string
}

func (e *TokenError) Error() string {
	return fmt.Sprintf("contract: not a valid token (step %d: %s)", e.Step, e.Rule)
}

// Unwrap is ErrToken.
func (e *TokenError) Unwrap() error { return ErrToken }

func tokenStep(step int, rule string) error { return &TokenError{Step: step, Rule: rule} }

// ParsedToken is a token that passed ParseToken: its selector, which is not
// secret and which a log may name, and its secret's 32 bytes, which never
// leave it but through Hash. String, GoString and LogValue name the
// selector alone.
type ParsedToken struct {
	Selector string
	secret   [TokenSecretBytes]byte
}

// Hash is the token's hash (TokenHash of its secret).
func (t ParsedToken) Hash() string { return TokenHash(t.secret) }

// String names the token by its selector alone.
func (t ParsedToken) String() string { return TokenPrefix + t.Selector + "." + Ellipsis }

// GoString is String, for %#v.
func (t ParsedToken) GoString() string { return t.String() }

// LogValue is the selector alone.
func (t ParsedToken) LogValue() slog.Value { return slog.StringValue(t.Selector) }

// ParseToken checks the text of a token, with no trimming, case folding or
// percent-decoding, and returns its selector and secret. A refusal is a
// *TokenError, which names the step that refused it and never a byte of
// the text.
func ParseToken(s string) (ParsedToken, error) {
	if len(s) != TokenLen {
		return ParsedToken{}, tokenStep(1, "64 ASCII characters")
	}
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return ParsedToken{}, tokenStep(1, "64 ASCII characters")
		}
	}
	if s[:len(TokenPrefix)] != TokenPrefix {
		return ParsedToken{}, tokenStep(2, "the prefix thc_")
	}
	selector := s[len(TokenPrefix) : len(TokenPrefix)+SelectorLen]
	if !ValidSelector(selector) {
		return ParsedToken{}, tokenStep(3, "a selector of 16 lowercase hex digits")
	}
	if s[20] != '.' {
		return ParsedToken{}, tokenStep(4, "a dot after the selector")
	}
	secret := s[21:]
	for i := 0; i < len(secret); i++ {
		if b64urlValue(secret[i]) < 0 {
			return ParsedToken{}, tokenStep(5, "a secret of 43 base64url characters")
		}
	}
	if b64urlValue(secret[TokenSecretLen-1])&3 != 0 {
		return ParsedToken{}, tokenStep(6, "the secret's canonical last character")
	}
	raw, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(raw) != TokenSecretBytes {
		return ParsedToken{}, tokenStep(5, "a secret of 43 base64url characters")
	}
	t := ParsedToken{Selector: selector}
	copy(t.secret[:], raw)
	return t, nil
}

// ValidSelector reports whether s is a token's selector: 16 lowercase hex
// digits, as a token and a record carry it and as the selector GET's path
// names it.
func ValidSelector(s string) bool {
	if len(s) != SelectorLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// b64urlValue is c's value in the unpadded base64url alphabet, or -1.
func b64urlValue(c byte) int {
	switch {
	case c >= 'A' && c <= 'Z':
		return int(c - 'A')
	case c >= 'a' && c <= 'z':
		return int(c-'a') + 26
	case c >= '0' && c <= '9':
		return int(c-'0') + 52
	case c == '-':
		return 62
	case c == '_':
		return 63
	default:
		return -1
	}
}

// TokenHash is a token's hash, the one a record carries: the lowercase hex
// SHA-256 of TokenHashLabel, one zero byte and the secret's 32 bytes, never
// its 43 characters. The secret has 256 bits, so no slow hash is needed
// (the platform's decision 0053).
func TokenHash(secret [TokenSecretBytes]byte) string {
	sum := tokenSum(secret)
	return hex.EncodeToString(sum[:])
}

func tokenSum(secret [TokenSecretBytes]byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(TokenHashLabel))
	h.Write([]byte{0})
	h.Write(secret[:])
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}

// The dummy a refused token is compared with, so that a token the app
// holds no record of, or one that does not parse, costs what a wrong one
// costs. No hash equals it in practice, and the comparison's result is
// thrown away.
var (
	dummyHash     = [sha256.Size]byte{0: 0xff, 31: 0xff}
	dummySelector = strings.Repeat("0", SelectorLen)
)

// BearerToken reads the token of an HTTP request from its Authorization
// header's values, as the server hands them (http.Header's Values): exactly
// one value, "Bearer" in any case, one space and the token, with nothing
// before or after. A second header, a tab or a space more is a refusal
// (*TokenError, step 0), and so is a token that ParseToken refuses (its
// step). Note that Go's net/http, as RFC 9110 has it, drops the spaces and
// tabs that start or end a field's value before an app reads it, so a
// trailing space the client sent may never reach this check; one that
// reaches it is refused. Another transport of the app's own carries the
// token's 64 bytes with nothing around them, for ParseToken.
func BearerToken(values []string) (string, error) {
	if len(values) != 1 {
		return "", tokenStep(0, "exactly one Authorization header")
	}
	scheme, rest, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", tokenStep(0, "Bearer, one space and the token")
	}
	if _, err := ParseToken(rest); err != nil {
		return "", err
	}
	return rest, nil
}

// VerifyToken checks a token against rec, the record the app found by the
// token's selector (an index lookup), or nil when it holds none
// (SPEC section 11.18):
//  1. the token is parsed (ParseToken); one that does not parse is compared
//     with a fixed dummy hash all the same;
//  2. with no record, the token is compared with the dummy;
//  3. the record's selector is compared with the token's again, in
//     constant time;
//  4. the token's hash is compared with the record's, in constant time,
//     over the 32 bytes of each.
//
// It returns nil only when both match. Otherwise it returns an error that
// matches ErrToken (a *TokenError when the token did not parse), and every
// refusal gets the app's one invalid_token. Every record the app holds costs
// the same.
//
// VerifyToken checks the secret alone. Only once it holds does the app
// check the record's revocation, its expiry by the app's own clock, and
// its own stops (SPEC section 11.18), each of them invalid_token too.
func VerifyToken(rec *TokenRecord, token string) error {
	t, perr := ParseToken(token)
	sum := tokenSum(t.secret)
	want, selector := dummyHash, dummySelector
	ok := perr == nil && rec != nil
	if rec != nil {
		selector = rec.Selector
		if h, good := decodeHash(rec.Hash); good {
			want = h
		} else {
			ok = false
		}
	}
	tokenSelector := t.Selector
	if perr != nil {
		tokenSelector = dummySelector
	}
	selectorOK := subtle.ConstantTimeCompare([]byte(tokenSelector), []byte(selector))
	hashOK := subtle.ConstantTimeCompare(sum[:], want[:])
	if perr != nil {
		return perr
	}
	if !ok || selectorOK&hashOK != 1 {
		return ErrToken
	}
	return nil
}

// decodeHash reads a record's hash: 64 lowercase hex digits.
func decodeHash(s string) ([sha256.Size]byte, bool) {
	var out [sha256.Size]byte
	if !validHex(s, 2*sha256.Size) {
		return out, false
	}
	if _, err := hex.Decode(out[:], []byte(s)); err != nil {
		return out, false
	}
	return out, true
}

// validHex reports whether s is n lowercase hex digits.
func validHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ReadingKeySuite is the one suite of a reading key in v1.
const ReadingKeySuite = "x25519"

// FingerprintLen is a reading key's fingerprint's length: 16 bytes in
// lowercase hex.
const FingerprintLen = 32

// The refusals of a reading key. Each matches ErrReadingKey, and none
// echoes the key.
var (
	ErrReadingKey = errors.New("contract: not a reading key")
	// ErrReadingKeyEncoding: not 43 base64url characters, the one spelling
	// of 32 bytes (padded, 31 or 33 bytes, another alphabet).
	ErrReadingKeyEncoding = fmt.Errorf("%w: not the unpadded base64url of 32 bytes", ErrReadingKey)
	// ErrReadingKeyNotCanonical: the top bit of the last byte is set, or the
	// value, read little-endian, is not below p = 2^255 - 19. Grants sealed
	// to such a key would never open.
	ErrReadingKeyNotCanonical = fmt.Errorf("%w: not a canonical X25519 key", ErrReadingKey)
	// ErrReadingKeyLowOrder: a point of low order, whose X25519 with the
	// kit's check scalar is all zeros.
	ErrReadingKeyLowOrder = fmt.Errorf("%w: a low-order point", ErrReadingKey)
	// ErrReadingKeyFingerprint: the fingerprint is not the key's
	// (CheckReadingKey): a record that carries one is a bad record, refused
	// as reading_key_changed.
	ErrReadingKeyFingerprint = fmt.Errorf("%w: the fingerprint is not its key's", ErrReadingKey)
)

// lowOrderCheckScalar is the kit's fixed check scalar for low-order points:
// the SHA-256 of "thehappie-token/v1/low-order-check". X25519 clamps every
// scalar to a multiple of 8, so any scalar finds them; this one is fixed so
// that every implementation checks alike.
var lowOrderCheckScalar = sha256.Sum256([]byte("thehappie-token/v1/low-order-check"))

// decodeKey reads a reading key's text: 43 base64url characters whose last
// one is canonical, the one spelling of 32 bytes.
func decodeKey(key string) ([32]byte, error) {
	var out [32]byte
	if len(key) != TokenSecretLen {
		return out, ErrReadingKeyEncoding
	}
	for i := 0; i < len(key); i++ {
		if b64urlValue(key[i]) < 0 {
			return out, ErrReadingKeyEncoding
		}
	}
	if b64urlValue(key[len(key)-1])&3 != 0 {
		return out, ErrReadingKeyEncoding
	}
	raw, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return out, ErrReadingKeyEncoding
	}
	copy(out[:], raw)
	return out, nil
}

// ValidReadingKey checks a reading key's text as the platform does when a
// person registers it (SPEC section 11.18): the unpadded base64url of
// exactly 32 bytes (ErrReadingKeyEncoding); a canonical X25519 public key,
// its last byte's top bit clear and its value below p
// (ErrReadingKeyNotCanonical); and not a point of low order
// (ErrReadingKeyLowOrder).
func ValidReadingKey(key string) error {
	b, err := decodeKey(key)
	if err != nil {
		return err
	}
	if b[31]&0x80 != 0 || atLeastP(b) {
		return ErrReadingKeyNotCanonical
	}
	priv, err := ecdh.X25519().NewPrivateKey(lowOrderCheckScalar[:])
	if err != nil {
		return ErrReadingKeyLowOrder
	}
	pub, err := ecdh.X25519().NewPublicKey(b[:])
	if err != nil {
		return ErrReadingKeyLowOrder
	}
	// crypto/ecdh refuses an all-zero result, as RFC 7748 section 6.1 asks.
	if _, err := priv.ECDH(pub); err != nil {
		return ErrReadingKeyLowOrder
	}
	return nil
}

// atLeastP reports whether b, little-endian with its top bit clear, is at
// least p = 2^255 - 19: 0x7f, thirty 0xff and then at least 0xed, from the
// most significant byte down.
func atLeastP(b [32]byte) bool {
	if b[31] != 0x7f {
		return false
	}
	for i := 30; i >= 1; i-- {
		if b[i] != 0xff {
			return false
		}
	}
	return b[0] >= 0xed
}

// ReadingKeyFingerprint is a reading key's fingerprint: the lowercase hex
// of the first 16 bytes of the SHA-256 of ReadingKeyLabel, one zero byte
// and the key's 32 bytes. It reads the key's text strictly
// (ErrReadingKeyEncoding) and checks nothing else of it: ValidReadingKey
// does. The console and the apps' grant pages show it as eight groups of
// four characters, each computing it from the key itself.
func ReadingKeyFingerprint(key string) (string, error) {
	b, err := decodeKey(key)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(ReadingKeyLabel))
	h.Write([]byte{0})
	h.Write(b[:])
	return hex.EncodeToString(h.Sum(nil)[:FingerprintLen/2]), nil
}

// CheckReadingKey checks a reading key and the fingerprint beside it, as an
// app checks a record's: ValidReadingKey, then that fingerprint is the
// key's own (ErrReadingKeyFingerprint). A record whose fingerprint is not
// its key's is a bad record: an app applies only what it narrows, and
// refuses its grants as reading_key_changed (SPEC section 11.18).
func CheckReadingKey(key, fingerprint string) error {
	if err := ValidReadingKey(key); err != nil {
		return err
	}
	fp, err := ReadingKeyFingerprint(key)
	if err != nil {
		return err
	}
	if fp != fingerprint {
		return ErrReadingKeyFingerprint
	}
	return nil
}
