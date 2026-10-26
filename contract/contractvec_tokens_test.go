package contract_test

// The generator of the vector files kit v0.9.0 adds to
// vectors/platform/contract-v1 (SPEC sections 11.17 and 11.18): the token
// part of the platform's design of 2026-10-26 (platform commit 509cc65,
// docs/design/2026-10-26/contract-tokens-and-settings.md, sections 3, 5 and
// 7), written here first, as test code over this package, so that the
// platform's own generator writes the same bytes once it takes this kit.
// TestTheKitWritesTheContractVectorsAgain compares what it writes with the
// frozen files byte for byte in every test run.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/thehappieco/kit/contract"
)

// The fixed material of the token part's vectors: made-up ids.
const (
	vecGeneration  = "0199b1e0-0000-7000-8000-000000000001"
	vecGeneration2 = "0199b1e0-0000-7000-8000-000000000002"
	vecSub         = "0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20"
	vecOther       = "0199c3d4-0000-7000-8000-000000000002"
	vecTeam        = "01a034b7-d09c-7121-b7f8-41f210a9244a"
	vecToken       = "0199f2a1-0000-7000-8000-000000000011"
	vecToken2      = "0199f2a1-0000-7000-8000-000000000012"
	vecNumber      = "0199e000-0000-7000-8000-000000000004"
	vecMailbox     = "acc_7f3a"
	vecSelector    = "9f3c0a7be41d2c58"
)

// vecSecret is the made-up secret of the vectors' first token: the bytes 0
// to 31.
func vecSecret() [contract.TokenSecretBytes]byte {
	var s [contract.TokenSecretBytes]byte
	for i := range s {
		s[i] = byte(i)
	}
	return s
}

// formatToken writes a token from its selector and secret.
func formatToken(selector string, secret [contract.TokenSecretBytes]byte) string {
	return contract.TokenPrefix + selector + "." + base64.RawURLEncoding.EncodeToString(secret[:])
}

// vecKey is the made-up reading key n: the X25519 public key of the scalar
// SHA-256("thehappie-token/v1/vector-reading-key-<n>").
func vecKey(n int) string {
	scalar := sha256.Sum256([]byte(fmt.Sprintf("thehappie-token/v1/vector-reading-key-%d", n)))
	priv, err := ecdh.X25519().NewPrivateKey(scalar[:])
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
}

func fingerprint(key string) string {
	fp, err := contract.ReadingKeyFingerprint(key)
	if err != nil {
		panic(err)
	}
	return fp
}

// encode writes v as the vector files hold a value.
func encode(v any) (json.RawMessage, error) { return json.Marshal(v) }

// TokenCase is one valid token, its parts and its hash.
type TokenCase struct {
	Name      string `json:"name"`
	Token     string `json:"token"`
	Selector  string `json:"selector"`
	SecretHex string `json:"secret_hex"`
	Hash      string `json:"hash"`
}

// RefusedToken is a text ParseToken refuses, and the step that refuses it.
type RefusedToken struct {
	Name  string `json:"name"`
	Token string `json:"token"`
	Step  int    `json:"step"`
}

// HeaderCase is the Authorization header's values and whether BearerToken
// takes a token from them.
type HeaderCase struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
	Valid  bool     `json:"valid"`
}

// Tokens is tokens.json.
type Tokens struct {
	Format      string         `json:"format"`
	Version     int            `json:"version"`
	Kind        string         `json:"kind"`
	Description string         `json:"description"`
	Label       string         `json:"label"`
	Tokens      []TokenCase    `json:"tokens"`
	Refused     []RefusedToken `json:"refused"`
	Headers     []HeaderCase   `json:"authorization"`
}

func tokensFile() (any, error) {
	out := Tokens{
		Format: Format, Version: 1, Kind: "tokens", Label: contract.TokenHashLabel,
		Description: "The token part's tokens (SPEC section 11.18): thc_, a selector of 16 lowercase hex, a dot and a secret of 43 unpadded base64url characters, 64 ASCII bytes. tokens: valid tokens, their selector and secret bytes, and their hash, the lowercase hex SHA-256 of the label, one zero byte and the secret's 32 bytes (contract.ParseToken, contract.TokenHash); two tokens with the same secret share a hash, since it covers the secret alone. refused: texts contract.ParseToken refuses, each with the step that refuses it (1: 64 ASCII bytes; 2: the prefix thc_; 3: the selector; 4: the dot; 5: the secret's alphabet; 6: the secret's canonical last character). authorization: an Authorization header's values as the server hands them, and whether contract.BearerToken takes a valid token from them: one value, Bearer in any case, one space and the token, nothing else.",
	}
	add := func(name, selector string, secret [contract.TokenSecretBytes]byte) string {
		tok := formatToken(selector, secret)
		out.Tokens = append(out.Tokens, TokenCase{Name: name, Token: tok, Selector: selector, SecretHex: hex.EncodeToString(secret[:]), Hash: contract.TokenHash(secret)})
		return tok
	}
	good := add("a token", vecSelector, vecSecret())
	add("the same secret under another selector shares its hash", "0123456789abcdef", vecSecret())
	add("a secret of zero bytes", "0000000000000000", [contract.TokenSecretBytes]byte{})
	var ones [contract.TokenSecretBytes]byte
	for i := range ones {
		ones[i] = 0xff
	}
	add("a secret of 0xff bytes, all underscores and a last 8", "ffffffffffffffff", ones)
	drawn := "5e1fa0c3d2b4e6f7"
	add("a secret drawn from a hash", drawn, sha256.Sum256([]byte("thehappie-token/v1/vector-secret")))

	sel, secret := good[4:20], good[21:]
	lastBits := strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", secret[42])
	notCanonical := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[lastBits|1]
	for _, c := range []struct {
		name, token string
	}{
		{"empty", ""},
		{"63 characters", good[:63]},
		{"65 characters", good + "A"},
		{"a leading space", " " + good},
		{"a trailing space", good + " "},
		{"a leading newline", "\n" + good},
		{"a trailing newline", good + "\n"},
		{"a zero-width space inside", good[:30] + "​" + good[30:]},
		{"a zero-width space in place of three characters, 64 bytes", good[:30] + "​" + good[33:]},
		{"a non-ASCII character in place of two, 64 bytes", good[:5] + "é" + good[7:]},
		{"a selector of 15 characters", "thc_" + sel[:15] + "." + secret},
		{"a selector of 17 characters", "thc_" + sel + "a." + secret},
		{"no dot", "thc_" + sel + secret},
		{"the token twice", good + good},
		{"THC_ in capitals", "THC_" + good[4:]},
		{"thc- with a dash", "thc-" + good[4:]},
		{"tch_, the prefix's letters swapped", "tch_" + good[4:]},
		{"an uppercase selector", "thc_" + strings.ToUpper(sel) + good[20:]},
		{"a selector with a g", "thc_g" + sel[1:] + good[20:]},
		{"a selector of 15 characters and a secret of 44, 64 bytes", "thc_" + sel[:15] + "." + secret + "A"},
		{"a selector of 17 characters and a secret of 42, 64 bytes", "thc_" + sel + "a." + secret[:42]},
		{"a colon for the dot", "thc_" + sel + ":" + secret},
		{"no dot, a base64url character in its place", "thc_" + sel + "A" + secret},
		{"= padding", "thc_" + sel + "." + secret[:42] + "="},
		{"a + in the secret, the standard alphabet", "thc_" + sel + ".+" + secret[1:]},
		{"a / in the secret, the standard alphabet", "thc_" + sel + "./" + secret[1:]},
		{"a space inside the secret", "thc_" + sel + ". " + secret[1:]},
		{"a non-canonical last character", "thc_" + sel + "." + secret[:42] + string(notCanonical)},
	} {
		_, err := contract.ParseToken(c.token)
		var te *contract.TokenError
		if !errors.As(err, &te) {
			return nil, fmt.Errorf("contractvec: ParseToken takes %q", c.name)
		}
		out.Refused = append(out.Refused, RefusedToken{Name: c.name, Token: c.token, Step: te.Step})
	}
	for _, c := range []struct {
		name   string
		values []string
	}{
		{"Bearer, one space and the token", []string{"Bearer " + good}},
		{"bearer in lower case", []string{"bearer " + good}},
		{"BEARER in upper case", []string{"BEARER " + good}},
		{"bEaReR in mixed case", []string{"bEaReR " + good}},
		{"a tab for the space", []string{"Bearer\t" + good}},
		{"two spaces", []string{"Bearer  " + good}},
		{"a trailing space", []string{"Bearer " + good + " "}},
		{"a leading space", []string{" Bearer " + good}},
		{"a trailing tab", []string{"Bearer " + good + "\t"}},
		{"a second header", []string{"Bearer " + good, "Bearer " + good}},
		{"no header", []string{}},
		{"Basic for Bearer", []string{"Basic " + good}},
		{"the token with no scheme", []string{good}},
		{"Bearer alone", []string{"Bearer"}},
		{"two tokens in one value, joined by a comma", []string{"Bearer " + good + ", Bearer " + good}},
		{"a token ParseToken refuses", []string{"Bearer THC_" + good[4:]}},
	} {
		_, err := contract.BearerToken(c.values)
		out.Headers = append(out.Headers, HeaderCase{Name: c.name, Values: c.values, Valid: err == nil})
	}
	return out, nil
}

// ReadingKeyCase is a reading key, the fingerprint beside it, and what
// contract.CheckReadingKey makes of them.
type ReadingKeyCase struct {
	Name        string `json:"name"`
	Key         string `json:"key"`
	Fingerprint string `json:"fingerprint"`
	Result      string `json:"result"`
}

// ReadingKeys is reading-keys.json.
type ReadingKeys struct {
	Format      string           `json:"format"`
	Version     int              `json:"version"`
	Kind        string           `json:"kind"`
	Description string           `json:"description"`
	Label       string           `json:"label"`
	CheckLabel  string           `json:"check_label"`
	Keys        []ReadingKeyCase `json:"reading_keys"`
}

// keyResult names what CheckReadingKey returned.
func keyResult(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, contract.ErrReadingKeyEncoding):
		return "encoding"
	case errors.Is(err, contract.ErrReadingKeyNotCanonical):
		return "not_canonical"
	case errors.Is(err, contract.ErrReadingKeyLowOrder):
		return "low_order"
	case errors.Is(err, contract.ErrReadingKeyFingerprint):
		return "fingerprint"
	default:
		return "error"
	}
}

// le is the 32 little-endian bytes of hex written most significant first.
func le(bigEndianHex string) []byte {
	b, err := hex.DecodeString(bigEndianHex)
	if err != nil || len(b) != 32 {
		panic("le: not 32 bytes")
	}
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

func readingKeysFile() (any, error) {
	out := ReadingKeys{
		Format: Format, Version: 1, Kind: "reading-keys", Label: contract.ReadingKeyLabel, CheckLabel: "thehappie-token/v1/low-order-check",
		Description: "A token's reading key (SPEC section 11.18): an X25519 public key, 43 unpadded base64url characters of 32 bytes, and its fingerprint, the lowercase hex of the first 16 bytes of the SHA-256 of the label, one zero byte and the key's 32 bytes (contract.ReadingKeyFingerprint). result is what contract.CheckReadingKey makes of the pair: ok; encoding (not the one spelling of 32 bytes); not_canonical (the last byte's top bit set, or a value at or above p = 2^255 - 19); low_order (its X25519 with the check scalar, the SHA-256 of check_label, is all zeros); fingerprint (not the key's). A fingerprint is the key's own wherever the key decodes, but in the fingerprint cases; it is empty where the key does not decode.",
	}
	add := func(name, key, fp string) {
		out.Keys = append(out.Keys, ReadingKeyCase{Name: name, Key: key, Fingerprint: fp, Result: keyResult(contract.CheckReadingKey(key, fp))})
	}
	own := func(name string, raw []byte) {
		key := base64.RawURLEncoding.EncodeToString(raw)
		add(name, key, fingerprint(key))
	}
	k1, k2, k3 := vecKey(1), vecKey(2), vecKey(3)
	add("a key", k1, fingerprint(k1))
	add("another key", k2, fingerprint(k2))
	add("a third key", k3, fingerprint(k3))
	// The value p - 2 is canonical and of no low order.
	own("p - 2, the highest canonical value of no low order", le("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb"))
	own("9, the base point", le("0000000000000000000000000000000000000000000000000000000000000009"))
	// The canonical points of low order, from the list of libsodium's
	// has_small_order: 0 (order 2), 1 (order 4), the two of order 8, and
	// p - 1 (order 4, on the twist).
	own("0, of low order", make([]byte, 32))
	own("1, of low order", le("0000000000000000000000000000000000000000000000000000000000000001"))
	own("a point of order 8", le("00b8495f16056286fdb1329ceb8d09da6ac49ff1fae35616aeb8413b7c7aebe0"))
	own("the other point of order 8", le("57119fd0dd4e22d8868e1c58c45c44045bef839c55b1d0b1248c50a3bc959c5f"))
	own("p - 1, of order 4, on the twist", le("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec"))
	// Not canonical: at or above p, or the top bit set.
	own("p, which reads as 0", le("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"))
	own("p + 1, which reads as 1", le("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffee"))
	own("2^255 - 1, the highest value with the top bit clear", le("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))
	raw1, _ := base64.RawURLEncoding.DecodeString(k1)
	top := append([]byte(nil), raw1...)
	top[31] |= 0x80
	own("a key with its last byte's top bit set", top)
	ones := bytes.Repeat([]byte{0xff}, 32)
	own("2^256 - 1, every bit set", ones)
	// Not the one spelling of 32 bytes.
	add("31 bytes", base64.RawURLEncoding.EncodeToString(raw1[:31]), "")
	add("33 bytes", base64.RawURLEncoding.EncodeToString(append(append([]byte(nil), raw1...), 0)), "")
	add("padded base64url", base64.URLEncoding.EncodeToString(raw1), "")
	add("the standard alphabet", strings.NewReplacer("-", "+", "_", "/").Replace(base64.RawURLEncoding.EncodeToString(append([]byte{0xfb, 0xff}, raw1[2:]...))), "")
	add("a non-canonical last character", k1[:42]+string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", k1[42])|1]), "")
	add("empty", "", "")
	add("a trailing space", k1+" ", "")
	// A fingerprint that is not the key's.
	add("another key's fingerprint", k1, fingerprint(k2))
	add("the fingerprint in capitals", k1, strings.ToUpper(fingerprint(k1)))
	add("the fingerprint grouped as the console shows it", k1, groups(fingerprint(k1)))
	add("the whole SHA-256 for the fingerprint", k1, fullSHA(k1))
	add("no fingerprint", k1, "")
	return out, nil
}

// groups is a fingerprint as the console shows it: eight groups of four.
func groups(fp string) string {
	var parts []string
	for i := 0; i < len(fp); i += 4 {
		parts = append(parts, fp[i:i+4])
	}
	return strings.Join(parts, " ")
}

func fullSHA(key string) string {
	raw, _ := base64.RawURLEncoding.DecodeString(key)
	sum := sha256.Sum256(append(append([]byte(contract.ReadingKeyLabel), 0), raw...))
	return hex.EncodeToString(sum[:])
}

// ActionCase is a record an app receives, and what it does with it.
type ActionCase struct {
	Name       string          `json:"name"`
	App        string          `json:"app"`
	Generation string          `json:"generation"`
	Value      json.RawMessage `json:"value"`
	Action     string          `json:"action"`
	Code       *string         `json:"code"`
}

// BodyCase is a body as the app sends it, and whether it is within the
// call's limit, decodes and validates.
type BodyCase struct {
	Name  string `json:"name"`
	Body  string `json:"body"`
	Valid bool   `json:"valid"`
}

// WireTokens is wire-tokens.json.
type WireTokens struct {
	Format      string       `json:"format"`
	Version     int          `json:"version"`
	Kind        string       `json:"kind"`
	Description string       `json:"description"`
	Records     []WireCase   `json:"records"`
	Feeds       []WireCase   `json:"feeds"`
	Applied     []WireCase   `json:"applied"`
	Usage       []BodyCase   `json:"usage"`
	Actions     []ActionCase `json:"actions"`
}

// vecRecord is the vectors' base record: Wappie's, live, with a reading
// key and one number given read and send by two owners.
func vecRecord(mut func(*contract.TokenRecord)) contract.TokenRecord {
	key := vecKey(1)
	r := contract.TokenRecord{
		V: contract.TokenRecordV, Type: contract.TokenRecordType, App: "wappie", Generation: vecGeneration,
		ID: vecToken, Version: 4, Selector: vecSelector, Hash: contract.TokenHash(vecSecret()), WorkspaceID: vecTeam,
		Name: "Nightly export", CreatedBy: vecSub, CreatedAt: contract.T(Now), ExpiresAt: contract.T(Now.Add(contract.MaxTokenLifetime)),
		ReadingKey: &contract.ReadingKey{Suite: contract.ReadingKeySuite, Key: key, Fingerprint: fingerprint(key), RegisteredAt: contract.T(Now.Add(3 * time.Minute))},
		Items: []contract.TokenItem{{ID: vecNumber, Kind: contract.ItemNumber, Perms: []contract.TokenPerm{
			{Perm: contract.CanRead, GrantedBy: vecSub, GrantedAt: contract.T(Now)},
			{Perm: contract.CanSend, GrantedBy: vecOther, GrantedAt: contract.T(Now.Add(24 * time.Hour))},
		}}},
	}
	if mut != nil {
		mut(&r)
	}
	return r
}

// vecMailieRecord is Mailie's: a personal mailbox given read and act under
// its key terms.
func vecMailieRecord(mut func(*contract.TokenRecord)) contract.TokenRecord {
	return vecRecord(func(r *contract.TokenRecord) {
		r.App, r.ReadingKey = "mailie", nil
		r.Terms = &contract.TokenTerms{Version: "2026-10-api-keys-2", AgreedAt: contract.T(Now)}
		r.Items = []contract.TokenItem{{ID: vecMailbox, Kind: contract.ItemMailbox, Perms: []contract.TokenPerm{
			{Perm: contract.CanRead, GrantedBy: vecSub, GrantedAt: contract.T(Now)},
			{Perm: contract.CanAct, GrantedBy: vecSub, GrantedAt: contract.T(Now)},
		}}}
		if mut != nil {
			mut(r)
		}
	})
}

func revoke(reason string) func(*contract.TokenRecord) {
	return func(r *contract.TokenRecord) {
		at := contract.T(Now.Add(48 * time.Hour))
		r.RevokedAt, r.RevokedReason, r.Items = &at, &reason, []contract.TokenItem{}
	}
}

// replaceOnce replaces old with new in raw, once, and fails when old is not
// there.
func replaceOnce(raw json.RawMessage, old, new string) (json.RawMessage, error) {
	if !bytes.Contains(raw, []byte(old)) {
		return nil, fmt.Errorf("contractvec: no %s to replace", old)
	}
	return json.RawMessage(bytes.Replace(raw, []byte(old), []byte(new), 1)), nil
}

func wireTokens() (any, error) {
	out := WireTokens{
		Format: Format, Version: 1, Kind: "wire-tokens",
		Description: "The token part's wire (SPEC section 11.18), each value with whether it is valid. records: contract.TokenRecord, decoded as an app decodes what the platform sends (a member it does not know is ignored), then its Validate. feeds: contract.TokenFeed, decoded the same way, then its Validate, which checks the page and not its records, each of which stays as it came until the app decodes it on its own: a bad record, one that does not decode included, never stalls the feed. applied: contract.TokenApplied, decoded as the platform decodes what an app sends (strictly: no member it does not know, every name exactly as written and once), then its Validate. usage: bodies of POST /contract/v1/tokens/usage as the app sends them: valid when the body is within the call's 256 KiB, decodes strictly as contract.TokenUsage and validates. actions: a record an app holding the generation receives, decoded on its own (contract.TokenFeedItem.Record), and what it does: refuse (another app's record: it logs it, applies nothing of it and advances, so one app's revocation never reaches another); reset (another generation: it resets its token state and follows the feed from 0, never widening); narrow (a record that does not decode or fails Validate, code invalid_record, or whose fingerprint is not its key's, code reading_key_changed: the app applies only what it narrows, a revocation, an earlier expires_at, an item or permission no longer listed, refuses its grants with that code, and advances through); revoke (code: the reason; app_removed and app_held revoke that app's record only); apply. The app decides in that order.",
	}
	str := func(s string) *string { return &s }
	add := func(list *[]WireCase, name string, v any, valid func() bool) error {
		raw, err := encode(v)
		if err != nil {
			return err
		}
		*list = append(*list, WireCase{Name: name, Value: raw, Valid: valid()})
		return nil
	}
	record := func(name string, r contract.TokenRecord) error {
		return add(&out.Records, name, r, func() bool { return r.Validate() == nil })
	}
	// Records.
	manyItems := make([]contract.TokenItem, contract.MaxTokenItems+1)
	for i := range manyItems {
		manyItems[i] = contract.TokenItem{ID: fmt.Sprintf("n%04d", i+1), Kind: contract.ItemNumber, Perms: []contract.TokenPerm{{Perm: contract.CanRead, GrantedBy: vecSub, GrantedAt: contract.T(Now)}}}
	}
	for _, c := range []struct {
		name string
		r    contract.TokenRecord
	}{
		{"a live record with a reading key", vecRecord(nil)},
		{"a live record with no reading key yet", vecRecord(func(r *contract.TokenRecord) { r.ReadingKey = nil })},
		{"a live record whose items were all un-ticked: the app stays on the token", vecRecord(func(r *contract.TokenRecord) { r.Items = []contract.TokenItem{} })},
		{"a record revoked in the console", vecRecord(revoke(contract.RevokedInConsole))},
		{"a record revoked by its creator's recovery", vecRecord(revoke(contract.RevokedCreatorRecovered))},
		{"Mailie's record: read and act under its key terms", vecMailieRecord(nil)},
		{"Mailie's read alone", vecMailieRecord(func(r *contract.TokenRecord) { r.Items[0].Perms = r.Items[0].Perms[:1] })},
		{"Wappie's three permissions, each given on its own", vecRecord(func(r *contract.TokenRecord) {
			r.Items[0].Perms = []contract.TokenPerm{{Perm: contract.CanManage, GrantedBy: vecOther, GrantedAt: contract.T(Now)}}
		})},
		{"an expiry a day after its creation", vecRecord(func(r *contract.TokenRecord) { r.ExpiresAt = contract.T(Now.Add(24 * time.Hour)) })},
		{"version 2 of the format", vecRecord(func(r *contract.TokenRecord) { r.V = 2 })},
		{"version 0", vecRecord(func(r *contract.TokenRecord) { r.Version = 0 })},
		{"an expiry at its creation", vecRecord(func(r *contract.TokenRecord) { r.ExpiresAt = r.CreatedAt })},
		{"an expiry before its creation", vecRecord(func(r *contract.TokenRecord) { r.ExpiresAt = contract.T(Now.Add(-time.Second)) })},
		{"an expiry a second over 365 days", vecRecord(func(r *contract.TokenRecord) {
			r.ExpiresAt = contract.T(Now.Add(contract.MaxTokenLifetime + time.Second))
		})},
		{"a reason without revoked_at", vecRecord(func(r *contract.TokenRecord) {
			revoke(contract.RevokedInConsole)(r)
			r.RevokedAt = nil
		})},
		{"revoked_at without a reason", vecRecord(func(r *contract.TokenRecord) {
			revoke(contract.RevokedInConsole)(r)
			r.RevokedReason = nil
		})},
		{"a revoked record with items", vecRecord(func(r *contract.TokenRecord) {
			items := r.Items
			revoke(contract.RevokedInConsole)(r)
			r.Items = items
		})},
		{"an unknown reason", vecRecord(revoke("expired"))},
		{"a permission outside the app's list", vecRecord(func(r *contract.TokenRecord) { r.Items[0].Perms[1].Perm = "delete" })},
		{"a permission twice", vecRecord(func(r *contract.TokenRecord) { r.Items[0].Perms[1].Perm = contract.CanRead })},
		{"a granted_by that is not a UUID", vecRecord(func(r *contract.TokenRecord) { r.Items[0].Perms[0].GrantedBy = "owner" })},
		{"Wappie's act", vecRecord(func(r *contract.TokenRecord) { r.Items[0].Perms[1].Perm = contract.CanAct })},
		{"Mailie's manage", vecMailieRecord(func(r *contract.TokenRecord) { r.Items[0].Perms[1].Perm = contract.CanManage })},
		{"Mailie's act without read", vecMailieRecord(func(r *contract.TokenRecord) { r.Items[0].Perms = r.Items[0].Perms[1:] })},
		{"a mailbox on Wappie's record", vecRecord(func(r *contract.TokenRecord) { r.Items[0].Kind = contract.ItemMailbox })},
		{"an item with no permission", vecRecord(func(r *contract.TokenRecord) { r.Items[0].Perms = []contract.TokenPerm{} })},
		{"an item twice", vecRecord(func(r *contract.TokenRecord) { r.Items = append(r.Items, r.Items[0]) })},
		{"a name with an @", vecRecord(func(r *contract.TokenRecord) { r.Name = "export@loja" })},
		{"a name with a run of 7 digits", vecRecord(func(r *contract.TokenRecord) { r.Name = "Export 1234567" })},
		{"an empty name", vecRecord(func(r *contract.TokenRecord) { r.Name = "" })},
		{"a selector in capitals", vecRecord(func(r *contract.TokenRecord) { r.Selector = strings.ToUpper(vecSelector) })},
		{"a hash of 63 characters", vecRecord(func(r *contract.TokenRecord) { r.Hash = r.Hash[:63] })},
		{"a reading key of low order", vecRecord(func(r *contract.TokenRecord) {
			zero := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
			r.ReadingKey.Key, r.ReadingKey.Fingerprint = zero, fingerprint(zero)
		})},
		{"a reading key of another suite", vecRecord(func(r *contract.TokenRecord) { r.ReadingKey.Suite = "p256" })},
		{"key terms with no revision", vecMailieRecord(func(r *contract.TokenRecord) { r.Terms.Version = "" })},
		{"an uppercase creator", vecRecord(func(r *contract.TokenRecord) { r.CreatedBy = strings.ToUpper(vecSub) })},
		{"1001 items", vecRecord(func(r *contract.TokenRecord) { r.Items = manyItems })},
	} {
		if err := record(c.name, c.r); err != nil {
			return nil, err
		}
	}
	// Times and members as an app reads them.
	base, err := encode(vecRecord(nil))
	if err != nil {
		return nil, err
	}
	at, _ := json.Marshal(contract.T(Now))
	whole := strings.TrimSuffix(string(at), `Z"`)
	for _, c := range []struct{ name, old, new string }{
		{"times of 120 milliseconds, written .120Z", `"created_at":` + string(at), `"created_at":` + whole + `.120Z"`},
		{"a member the app does not know, which it ignores", `"v":1,`, `"v":1,"tier":"gold",`},
		{"a created_at with a comma before its fraction", `"created_at":` + string(at), `"created_at":` + whole + `,5Z"`},
	} {
		raw, err := replaceOnce(base, c.old, c.new)
		if err != nil {
			return nil, err
		}
		var r contract.TokenRecord
		valid := json.Unmarshal(raw, &r) == nil && r.Validate() == nil
		out.Records = append(out.Records, WireCase{Name: c.name, Value: raw, Valid: valid})
	}

	// Feeds.
	item := func(seq int64, r contract.TokenRecord) contract.TokenFeedItem {
		it, err := contract.NewTokenFeedItem(seq, r)
		if err != nil {
			panic(err)
		}
		return it
	}
	// A record whose revoked_at is the zero time, as a zero Time marshals,
	// does not decode: Time takes no year before 1970.
	undecodable := vecRecord(func(r *contract.TokenRecord) {
		r.Version = 90
		revoke(contract.RevokedInConsole)(r)
		r.RevokedAt = &contract.Time{}
	})
	feed := func(mut func(*contract.TokenFeed)) contract.TokenFeed {
		f := contract.TokenFeed{
			Generation: vecGeneration, GenerationConfirmed: true, Head: 90, PublishedThrough: contract.T(Now.Add(4 * time.Second)),
			Items: []contract.TokenFeedItem{
				item(89, vecRecord(func(r *contract.TokenRecord) { r.ID, r.Version, r.Selector = vecToken2, 89, "0123456789abcdef" })),
				item(90, vecRecord(func(r *contract.TokenRecord) { r.Version = 90 })),
			},
			NextAfter: 90,
		}
		if mut != nil {
			mut(&f)
		}
		return f
	}
	for _, c := range []struct {
		name string
		f    contract.TokenFeed
	}{
		{"a page of two records, oldest first", feed(nil)},
		{"an empty page at the head", feed(func(f *contract.TokenFeed) { f.Items = []contract.TokenFeedItem{} })},
		{"a page with more to come", feed(func(f *contract.TokenFeed) { f.Head, f.More, f.NextAfter = 120, true, 90 })},
		{"a page of a generation not yet confirmed", feed(func(f *contract.TokenFeed) { f.GenerationConfirmed = false })},
		{"a page that holds a bad record still stands", feed(func(f *contract.TokenFeed) {
			f.Items[1] = item(90, vecRecord(func(r *contract.TokenRecord) {
				r.Version, r.ExpiresAt = 90, contract.T(Now.Add(contract.MaxTokenLifetime+time.Hour))
			}))
		})},
		{"a page that holds a record that does not decode still stands", feed(func(f *contract.TokenFeed) { f.Items[1] = item(90, undecodable) })},
		{"records out of order", feed(func(f *contract.TokenFeed) { f.Items[0], f.Items[1] = f.Items[1], f.Items[0] })},
		{"a seq above the head", feed(func(f *contract.TokenFeed) { f.Items[1].Seq = 91 })},
		{"next_after above the head", feed(func(f *contract.TokenFeed) { f.NextAfter = 91 })},
		{"a generation that is not a UUID", feed(func(f *contract.TokenFeed) { f.Generation = "1" })},
		{"items null", feed(func(f *contract.TokenFeed) { f.Items = nil })},
	} {
		if err := add(&out.Feeds, c.name, c.f, func() bool { return c.f.Validate() == nil }); err != nil {
			return nil, err
		}
	}

	// Acknowledgements.
	ack := func(mut func(*contract.TokenApplied)) contract.TokenApplied {
		a := contract.TokenApplied{
			Generation: vecGeneration, Through: 90, AppliedAt: contract.T(Now.Add(5 * time.Second)),
			Refused:   []contract.TokenRefusal{{Token: vecToken, Version: 4, Item: vecNumber, Perm: contract.CanRead, Code: contract.RefusedGiverNotReader}},
			Waiting:   contract.WaitingPerms{},
			Suspended: contract.Suspensions{{Token: vecToken, Cause: contract.SuspendedOperator}},
			Held:      []contract.TokenHeld{},
		}
		if mut != nil {
			mut(&a)
		}
		return a
	}
	waiting := contract.WaitingPerm{Token: vecToken, Item: vecNumber, Perm: contract.CanSend, GrantedBy: vecOther, GrantedAt: contract.T(Now)}
	fp := fingerprint(vecKey(1))
	expires := contract.T(Now.Add(30 * 24 * time.Hour))
	many := func(n int) contract.Suspensions {
		s := make(contract.Suspensions, n)
		for i := range s {
			s[i] = contract.Suspension{Token: fmt.Sprintf("0199f2a1-0000-7000-8000-%012d", i+1), Cause: contract.SuspendedOperator}
		}
		return s
	}
	manyWaiting := make(contract.WaitingPerms, contract.MaxAppliedEntries+1)
	for i := range manyWaiting {
		manyWaiting[i] = waiting
		manyWaiting[i].Item = fmt.Sprintf("n%04d", i+1)
	}
	for _, c := range []struct {
		name string
		a    contract.TokenApplied
	}{
		{"a refusal, no waiting permission and the app's own stop", ack(nil)},
		{"waiting and suspended absent: both unchanged", ack(func(a *contract.TokenApplied) { a.Waiting, a.Suspended = nil, nil })},
		{"waiting and suspended empty: none", ack(func(a *contract.TokenApplied) { a.Suspended = contract.Suspensions{} })},
		{"a permission held back unjudged until the giver's document", ack(func(a *contract.TokenApplied) { a.Waiting = contract.WaitingPerms{waiting} })},
		{"more waiting than the list holds", ack(func(a *contract.TokenApplied) { a.Waiting, a.WaitingMore = contract.WaitingPerms{waiting}, true })},
		{"a stop because the app's own operator disabled the creator", ack(func(a *contract.TokenApplied) {
			a.Suspended = contract.Suspensions{{Token: vecToken, Cause: contract.SuspendedCreatorDisabledHere}}
		})},
		{"a stop by the app's own roles before it enforces", ack(func(a *contract.TokenApplied) {
			a.Suspended = contract.Suspensions{{Token: vecToken, Cause: contract.SuspendedLocalRule}}
		})},
		{"after a reset: a token held revoked", ack(func(a *contract.TokenApplied) {
			a.Held = []contract.TokenHeld{{Token: vecToken, Revoked: true, Removed: []contract.HeldPerm{}}}
		})},
		{"after a reset: an earlier expiry, a permission kept off and the pin of a key the record lost", ack(func(a *contract.TokenApplied) {
			a.Held = []contract.TokenHeld{{Token: vecToken, ExpiresAt: &expires, Removed: []contract.HeldPerm{{Item: vecNumber, Perm: contract.CanSend}}, ReadingKey: &fp}}
		})},
		{"each refusal code", ack(func(a *contract.TokenApplied) {
			a.Refused = nil
			for _, code := range contract.RefusalCodes() {
				a.Refused = append(a.Refused, contract.TokenRefusal{Token: vecToken, Version: 4, Item: vecNumber, Perm: contract.CanRead, Code: code})
			}
		})},
		{"through 0, before any record", ack(func(a *contract.TokenApplied) { a.Through, a.Refused, a.Suspended = 0, []contract.TokenRefusal{}, nil })},
		{"through below zero", ack(func(a *contract.TokenApplied) { a.Through = -1 })},
		{"an unknown refusal code", ack(func(a *contract.TokenApplied) { a.Refused[0].Code = "giver_left" })},
		{"a refusal of version 0", ack(func(a *contract.TokenApplied) { a.Refused[0].Version = 0 })},
		{"an unknown stop cause", ack(func(a *contract.TokenApplied) { a.Suspended[0].Cause = "leaked" })},
		{"a stop twice", ack(func(a *contract.TokenApplied) { a.Suspended = append(a.Suspended, a.Suspended[0]) })},
		{"an empty granted_by on a waiting permission", ack(func(a *contract.TokenApplied) {
			w := waiting
			w.GrantedBy = ""
			a.Waiting = contract.WaitingPerms{w}
		})},
		{"a granted_at before 1970 on a waiting permission", ack(func(a *contract.TokenApplied) {
			w := waiting
			w.GrantedAt = contract.Time{}
			a.Waiting = contract.WaitingPerms{w}
		})},
		{"waiting_more without waiting", ack(func(a *contract.TokenApplied) { a.Waiting, a.WaitingMore = nil, true })},
		{"suspended_more without suspended", ack(func(a *contract.TokenApplied) { a.Suspended, a.SuspendedMore = nil, true })},
		{"a held entry with removed null", ack(func(a *contract.TokenApplied) { a.Held = []contract.TokenHeld{{Token: vecToken}} })},
		{"a held reading key that is not a fingerprint", ack(func(a *contract.TokenApplied) {
			bad := "key"
			a.Held = []contract.TokenHeld{{Token: vecToken, Removed: []contract.HeldPerm{}, ReadingKey: &bad}}
		})},
		{"refused null", ack(func(a *contract.TokenApplied) { a.Refused = nil })},
		{"held null", ack(func(a *contract.TokenApplied) { a.Held = nil })},
		{"a waiting permission twice", ack(func(a *contract.TokenApplied) { a.Waiting = contract.WaitingPerms{waiting, waiting} })},
		{"a waiting permission twice, given apart", ack(func(a *contract.TokenApplied) {
			again := waiting
			again.GrantedBy = vecSub
			a.Waiting = contract.WaitingPerms{waiting, again}
		})},
		{"a token held twice", ack(func(a *contract.TokenApplied) {
			a.Held = []contract.TokenHeld{{Token: vecToken, Revoked: true, Removed: []contract.HeldPerm{}}, {Token: vecToken, Removed: []contract.HeldPerm{}}}
		})},
		{"a permission kept off twice", ack(func(a *contract.TokenApplied) {
			off := contract.HeldPerm{Item: vecNumber, Perm: contract.CanSend}
			a.Held = []contract.TokenHeld{{Token: vecToken, Removed: []contract.HeldPerm{off, off}}}
		})},
		{"1001 waiting", ack(func(a *contract.TokenApplied) {
			a.Refused, a.Suspended, a.Waiting = []contract.TokenRefusal{}, nil, manyWaiting
		})},
		{"1001 suspended", ack(func(a *contract.TokenApplied) {
			a.Refused, a.Suspended = []contract.TokenRefusal{}, many(contract.MaxAppliedEntries+1)
		})},
		{"1000 suspended and one refusal: 1001 together", ack(func(a *contract.TokenApplied) { a.Suspended = many(contract.MaxAppliedEntries) })},
	} {
		if err := add(&out.Applied, c.name, c.a, func() bool { return c.a.Validate() == nil }); err != nil {
			return nil, err
		}
	}
	// What only the raw text can say: null, and a member the platform does
	// not know.
	abase, err := encode(ack(func(a *contract.TokenApplied) { a.Suspended = contract.Suspensions{} }))
	if err != nil {
		return nil, err
	}
	wbase, err := encode(ack(func(a *contract.TokenApplied) {
		a.Waiting, a.WaitingMore, a.Suspended, a.SuspendedMore = contract.WaitingPerms{waiting}, true, contract.Suspensions{}, true
	}))
	if err != nil {
		return nil, err
	}
	wentry := `{"token":"` + vecToken + `","item":"` + vecNumber + `","perm":"send",`
	for _, c := range []struct {
		name     string
		base     json.RawMessage
		old, new string
	}{
		{"waiting null", abase, `"waiting":[]`, `"waiting":null`},
		{"suspended null", abase, `"suspended":[]`, `"suspended":null`},
		{"a member the platform does not know", abase, `"through":90,`, `"through":90,"note":"x",`},
		{"waiting_more and suspended_more true", wbase, ``, ``},
		{"waiting_more false", wbase, `"waiting_more":true`, `"waiting_more":false`},
		{"waiting_more null", wbase, `"waiting_more":true`, `"waiting_more":null`},
		{"suspended_more false", wbase, `"suspended_more":true`, `"suspended_more":false`},
		{"a waiting permission without granted_by", wbase, `"granted_by":"` + vecOther + `",`, ``},
		{"a waiting permission without granted_at", wbase, `,"granted_at":"2026-10-13T12:00:00Z"`, ``},
		{"a waiting permission's token written Token", wbase, wentry, `{"Token":"` + vecToken + `","item":"` + vecNumber + `","perm":"send",`},
		{"a waiting permission's token twice, once written Token", wbase, wentry, wentry + `"Token":"` + vecToken2 + `",`},
	} {
		raw := c.base
		if c.old != "" {
			if raw, err = replaceOnce(c.base, c.old, c.new); err != nil {
				return nil, err
			}
		}
		var a contract.TokenApplied
		valid := strictDecode(raw, &a) == nil && a.Validate() == nil
		out.Applied = append(out.Applied, WireCase{Name: c.name, Value: raw, Valid: valid})
	}

	// Usage bodies.
	usage := func(mut func(*contract.TokenUsage)) contract.TokenUsage {
		u := contract.TokenUsage{
			Used:     []contract.TokenUsed{{Token: vecToken, Day: "2026-10-13"}},
			Refusals: []contract.UsageRefusal{{Token: vecToken, Day: "2026-10-13", Item: str(vecNumber), Perm: str(contract.CanSend), Code: contract.UseNoPermission, Count: 3}},
		}
		if mut != nil {
			mut(&u)
		}
		return u
	}
	big := usage(func(u *contract.TokenUsage) {
		u.Used, u.Refusals = nil, nil
		for i := 0; i < contract.MaxUsageEntries; i++ {
			tok := fmt.Sprintf("0199f2a1-0000-7000-8000-%012d", i+1)
			u.Used = append(u.Used, contract.TokenUsed{Token: tok, Day: "2026-10-13"})
			u.Refusals = append(u.Refusals, contract.UsageRefusal{
				Token: tok, Day: "2026-10-13", Item: str(fmt.Sprintf("%064d", i+1)), Perm: str(contract.CanManage),
				Code: contract.UseWorkspaceClosed, Count: 1 << 52,
			})
		}
	})
	if err := big.Validate(); err != nil {
		return nil, fmt.Errorf("contractvec: the large usage body's entries are not valid: %w", err)
	}
	for _, c := range []struct {
		name string
		u    contract.TokenUsage
	}{
		{"a day of use and three refused sends", usage(nil)},
		{"a refusal of a revoked token names no item or perm", usage(func(u *contract.TokenUsage) {
			u.Refusals[0].Item, u.Refusals[0].Perm, u.Refusals[0].Code = nil, nil, contract.UseRevoked
		})},
		{"each refusal code", usage(func(u *contract.TokenUsage) {
			u.Refusals = nil
			for _, code := range contract.UsageRefusalCodes() {
				r := contract.UsageRefusal{Token: vecToken, Day: "2026-10-13", Item: str(vecNumber), Perm: str(contract.CanRead), Code: code, Count: 1}
				if code == contract.UseRevoked || code == contract.UseExpired || code == contract.UseSuspendedHere {
					r.Item, r.Perm = nil, nil
				}
				u.Refusals = append(u.Refusals, r)
			}
		})},
		{"nothing to report", usage(func(u *contract.TokenUsage) { u.Used, u.Refusals = []contract.TokenUsed{}, []contract.UsageRefusal{} })},
		{"1000 days of use and 1000 refusals, under the body limit only once split", big},
		{"an unknown refusal code", usage(func(u *contract.TokenUsage) { u.Refusals[0].Code = "denied" })},
		{"a refusal of an expired token that names an item", usage(func(u *contract.TokenUsage) { u.Refusals[0].Code = contract.UseExpired })},
		{"a refused send that names no item", usage(func(u *contract.TokenUsage) { u.Refusals[0].Item = nil })},
		{"a count of 0", usage(func(u *contract.TokenUsage) { u.Refusals[0].Count = 0 })},
		{"a day that is no date", usage(func(u *contract.TokenUsage) { u.Used[0].Day = "2026-02-30" })},
		{"a day with a time", usage(func(u *contract.TokenUsage) { u.Used[0].Day = "2026-10-13T00:00:00Z" })},
		{"a day of a token twice", usage(func(u *contract.TokenUsage) { u.Used = append(u.Used, u.Used[0]) })},
		{"a refusal twice", usage(func(u *contract.TokenUsage) { u.Refusals = append(u.Refusals, u.Refusals[0]) })},
		{"used null", usage(func(u *contract.TokenUsage) { u.Used = nil })},
	} {
		body, err := json.Marshal(c.u)
		if err != nil {
			return nil, err
		}
		out.Usage = append(out.Usage, BodyCase{Name: c.name, Body: string(body), Valid: usageValid(body)})
	}
	if out.Usage[4].Valid || len(out.Usage[4].Body) <= contract.UsageBodyLimit {
		return nil, errors.New("contractvec: the large usage body is within the limit")
	}

	// What an app does with a record.
	for _, c := range []struct {
		name string
		r    contract.TokenRecord
	}{
		{"a record to apply", vecRecord(nil)},
		{"a record with no reading key yet, to apply", vecRecord(func(r *contract.TokenRecord) { r.ReadingKey = nil })},
		{"a record of another generation: a reset", vecRecord(func(r *contract.TokenRecord) { r.Generation = vecGeneration2 })},
		{"revoked in the console", vecRecord(revoke(contract.RevokedInConsole))},
		{"its creator left the workspace", vecRecord(revoke(contract.RevokedCreatorLeft))},
		{"the app was taken off the token: this app's record only", vecRecord(revoke(contract.RevokedAppRemoved))},
		{"the app held it revoked after a reset: this app's record only", vecRecord(revoke(contract.RevokedAppHeld))},
		{"a fingerprint that is not its key's", vecRecord(func(r *contract.TokenRecord) { r.ReadingKey.Fingerprint = fingerprint(vecKey(2)) })},
		{"a record that fails Validate: an expiry over 365 days", vecRecord(func(r *contract.TokenRecord) {
			r.ExpiresAt = contract.T(Now.Add(contract.MaxTokenLifetime + time.Hour))
		})},
		{"a record that fails Validate and revokes: the revocation applies", vecRecord(func(r *contract.TokenRecord) {
			revoke(contract.RevokedInConsole)(r)
			r.Name = "Export 1234567"
		})},
		{"a record that fails Validate and narrows: Mailie's act without read", vecMailieRecord(func(r *contract.TokenRecord) { r.Items[0].Perms = r.Items[0].Perms[1:] })},
		{"a record that does not decode: its revocation still applies", undecodable},
	} {
		raw, err := encode(c.r)
		if err != nil {
			return nil, err
		}
		action, code := recordAction(c.r.App, vecGeneration, raw)
		out.Actions = append(out.Actions, ActionCase{Name: c.name, App: c.r.App, Generation: vecGeneration, Value: raw, Action: action, Code: code})
	}
	// Another app's record, as Wappie receives it: refused whole, so that
	// Mailie's app_removed never revokes the token in Wappie.
	other, err := encode(vecMailieRecord(revoke(contract.RevokedAppRemoved)))
	if err != nil {
		return nil, err
	}
	action, code := recordAction("wappie", vecGeneration, other)
	out.Actions = append(out.Actions, ActionCase{Name: "another app's record, revoked there: refused, nothing applied", App: "wappie", Generation: vecGeneration, Value: other, Action: action, Code: code})
	return out, nil
}

// recordAction is what an app holding generation does with a record it
// receives (wire-tokens.json's actions), in TokenFeed.Validate's order:
// another app's record is refused; another generation is a reset; a record
// that does not decode or fails Validate, or whose fingerprint is not its
// key's, is narrowed; then the revocation; else the record applies.
func recordAction(app, generation string, raw json.RawMessage) (string, *string) {
	code := func(s string) *string { return &s }
	r, err := contract.TokenFeedItem{Token: raw}.Record()
	if r.App != app {
		return "refuse", nil
	}
	if contract.ValidUUID(r.Generation) && r.Generation != generation {
		return "reset", nil
	}
	if err != nil || r.Validate() != nil {
		return "narrow", code(contract.RefusedInvalidRecord)
	}
	if r.ReadingKey != nil && r.ReadingKey.Check() != nil {
		return "narrow", code(contract.RefusedReadingKeyChanged)
	}
	if r.RevokedReason != nil {
		return "revoke", code(*r.RevokedReason)
	}
	return "apply", nil
}

// usageValid is what the platform makes of a usage body: within the call's
// limit, decoded strictly, and valid.
func usageValid(body []byte) bool {
	var u contract.TokenUsage
	return len(body) <= contract.UsageBodyLimit && strictDecode(body, &u) == nil && u.Validate() == nil
}

// strictDecode decodes one object with no member dst does not have.
func strictDecode(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("more than one value")
	}
	return nil
}

// wireSnapshotTokens is wire-snapshot-tokens.json: snapshots with the
// optional members ordinal and tokens.
func wireSnapshotTokens() (any, error) {
	out := Wire{
		Format: Format, Version: 1, Kind: "wire",
		Description: "Access snapshots with the optional members items[].ordinal and items[].tokens (SPEC sections 11.17 and 11.18), each with whether it decodes and contract.Snapshot's Validate accepts it. An ordinal is 1 to 9999, unique among the snapshot's items; tokens list each token by its id once, with the permissions the app applied by the item's kind, and waiting is a number's only. An optional member is absent, never null, and a token's members are named exactly as written, once. Added after wire.json was frozen.",
		Documents:   []WireCase{}, Events: []WireCase{},
	}
	str := func(s string) *string { return &s }
	person := contract.Person{Sub: vecSub, Can: []string{contract.CanRead}, Reads: true, Enrolled: true, HoldsKey: true}
	number := func(mut func(*contract.Item)) contract.Item {
		it := contract.Item{
			ID: vecNumber, Kind: contract.ItemNumber, Label: str("Vendas"), Hint: str("…5678"), State: contract.StateActive,
			People: []contract.Person{person}, Protected: []string{vecSub}, Ordinal: 1,
			Tokens: contract.ItemTokens{{ID: vecToken, Can: []string{contract.CanRead, contract.CanSend}, Reads: true}},
		}
		if mut != nil {
			mut(&it)
		}
		return it
	}
	mailbox := func(mut func(*contract.Item)) contract.Item {
		it := contract.Item{
			ID: vecMailbox, Kind: contract.ItemMailbox, Label: nil, Hint: str("j…@gmail.com"), State: contract.StateActive,
			People: []contract.Person{person}, Protected: []string{vecSub}, Ordinal: 2,
			Tokens: contract.ItemTokens{{ID: vecToken, Can: []string{contract.CanRead, contract.CanAct}, Reads: true}},
		}
		if mut != nil {
			mut(&it)
		}
		return it
	}
	snap := func(items ...contract.Item) contract.Snapshot {
		return contract.Snapshot{V: contract.SnapshotV, SnapshotSeq: Now.UnixMilli(), Items: items}
	}
	for _, c := range []struct {
		name string
		s    contract.Snapshot
	}{
		{"a number with its ordinal and a token that reads and sends", snap(number(nil))},
		{"a token with Read waiting for its grant (Wappie)", snap(number(func(it *contract.Item) {
			it.Tokens = contract.ItemTokens{{ID: vecToken, Can: []string{contract.CanRead}, Waiting: true}}
		}))},
		{"a mailbox with a token that reads and acts", snap(mailbox(nil))},
		{"an unlabelled item named by its ordinal", snap(number(func(it *contract.Item) { it.Label, it.Hint, it.Ordinal = nil, nil, 3 }))},
		{"tokens empty: no token holds the item", snap(number(func(it *contract.Item) { it.Tokens = contract.ItemTokens{} }))},
		{"neither member: the app reports no ordinal and no token", snap(number(func(it *contract.Item) { it.Ordinal, it.Tokens = 0, nil }))},
		{"the highest ordinal", snap(number(func(it *contract.Item) { it.Ordinal = contract.MaxOrdinal }))},
		{"two items, each with its own ordinal", snap(number(nil), mailbox(nil))},
		{"a token id twice", snap(number(func(it *contract.Item) { it.Tokens = append(it.Tokens, it.Tokens[0]) }))},
		{"waiting with Mailie's read", snap(mailbox(func(it *contract.Item) {
			it.Tokens = contract.ItemTokens{{ID: vecToken, Can: []string{contract.CanRead}, Waiting: true}}
		}))},
		{"an ordinal of 10000", snap(number(func(it *contract.Item) { it.Ordinal = contract.MaxOrdinal + 1 }))},
		{"an ordinal shared by two items", snap(number(nil), mailbox(func(it *contract.Item) { it.Ordinal = 1 }))},
		{"a token with manage on a mailbox", snap(mailbox(func(it *contract.Item) {
			it.Tokens = contract.ItemTokens{{ID: vecToken, Can: []string{contract.CanRead, contract.CanManage}, Reads: true}}
		}))},
		{"a token with act on a number", snap(number(func(it *contract.Item) {
			it.Tokens = contract.ItemTokens{{ID: vecToken, Can: []string{contract.CanAct}}}
		}))},
		{"a token named by its selector", snap(number(func(it *contract.Item) { it.Tokens[0].ID = vecSelector }))},
	} {
		raw, err := encode(c.s)
		if err != nil {
			return nil, err
		}
		var s contract.Snapshot
		valid := json.Unmarshal(raw, &s) == nil && s.Validate() == nil
		out.Snapshots = append(out.Snapshots, WireCase{Name: c.name, Value: raw, Valid: valid})
	}
	base, err := encode(snap(number(func(it *contract.Item) { it.Tokens = contract.ItemTokens{} })))
	if err != nil {
		return nil, err
	}
	withToken, err := encode(snap(number(nil)))
	if err != nil {
		return nil, err
	}
	for _, c := range []struct {
		name     string
		base     json.RawMessage
		old, new string
	}{
		{"an ordinal of 0", base, `"ordinal":1,`, `"ordinal":0,`},
		{"an ordinal null", base, `"ordinal":1,`, `"ordinal":null,`},
		{"an ordinal of 1.5", base, `"ordinal":1,`, `"ordinal":1.5,`},
		{"tokens null", base, `"tokens":[]`, `"tokens":null`},
		{"a token's id written ID", withToken, `"tokens":[{"id":`, `"tokens":[{"ID":`},
		{"a token's id twice, once written ID", withToken, `"tokens":[{"id":"` + vecToken + `",`, `"tokens":[{"id":"` + vecToken + `","ID":"` + vecToken2 + `",`},
	} {
		raw, err := replaceOnce(c.base, c.old, c.new)
		if err != nil {
			return nil, err
		}
		var s contract.Snapshot
		valid := json.Unmarshal(raw, &s) == nil && s.Validate() == nil
		out.Snapshots = append(out.Snapshots, WireCase{Name: c.name, Value: raw, Valid: valid})
	}
	return out, nil
}

// wireEventsStop is wire-events-stop.json: item.sync_paused with and
// without stop.
func wireEventsStop() (any, error) {
	out := Wire{
		Format: Format, Version: 1, Kind: "wire",
		Description: "Events with the optional member stop (SPEC section 11.17), each with whether it decodes and contract.Event's Validate accepts it. stop is pause or turn_off, only on item.sync_paused, and turn_off only for a mailbox; absent, the platform reads pause for a number and turn_off for a mailbox, what each app sent before the member existed. An optional member is absent, never null: \"stop\": null is refused. Added after wire.json was frozen.",
		Documents:   []WireCase{}, Snapshots: []WireCase{},
	}
	str := func(s string) *string { return &s }
	ev := func(typ, kind string, stop contract.Stop, mut func(*contract.Event)) contract.Event {
		readers := []string{vecSub, vecOther}
		e := contract.Event{
			EventID: "0199d000-0000-7000-8000-000000000003", WorkspaceID: vecTeam, Type: typ, OccurredAt: contract.T(Now),
			Item:  contract.EventItem{ID: vecNumber, Kind: contract.ItemNumber, Label: str("Vendas"), Hint: str("…5678")},
			Actor: str(vecSub), ActorKind: kind, Readers: &readers, Stop: stop,
		}
		if mut != nil {
			mut(&e)
		}
		return e
	}
	asMailbox := func(e *contract.Event) {
		e.Item = contract.EventItem{ID: vecMailbox, Kind: contract.ItemMailbox, Label: str("Suporte"), Hint: str("j…@gmail.com")}
	}
	purge := contract.T(Now.Add(30 * 24 * time.Hour))
	for _, c := range []struct {
		name string
		e    contract.Event
	}{
		{"a number's capture paused", ev(contract.EventSyncPaused, contract.ActorPerson, contract.StopPause, nil)},
		{"a mailbox's sync paused", ev(contract.EventSyncPaused, contract.ActorPerson, contract.StopPause, asMailbox)},
		{"a team mailbox's sync turned off", ev(contract.EventSyncPaused, contract.ActorPerson, contract.StopTurnOff, asMailbox)},
		{"a token with manage paused a number; the actor is its creator", ev(contract.EventSyncPaused, contract.ActorKey, contract.StopPause, nil)},
		{"no stop on a number: read as a pause", ev(contract.EventSyncPaused, contract.ActorPerson, "", nil)},
		{"no stop on a mailbox: read as a turn-off", ev(contract.EventSyncPaused, contract.ActorPerson, "", asMailbox)},
		{"turn_off on a number", ev(contract.EventSyncPaused, contract.ActorPerson, contract.StopTurnOff, nil)},
		{"stop on item.deleted", ev(contract.EventDeleted, contract.ActorPerson, contract.StopPause, func(e *contract.Event) { e.PurgeAt = &purge })},
		{"stop on item.recovered", ev(contract.EventRecovered, contract.ActorPerson, contract.StopPause, nil)},
		{"an unknown stop", ev(contract.EventSyncPaused, contract.ActorPerson, "resume", nil)},
		{"stop in capitals", ev(contract.EventSyncPaused, contract.ActorPerson, "PAUSE", nil)},
	} {
		raw, err := encode(c.e)
		if err != nil {
			return nil, err
		}
		var e contract.Event
		valid := json.Unmarshal(raw, &e) == nil && e.Validate() == nil
		out.Events = append(out.Events, WireCase{Name: c.name, Value: raw, Valid: valid})
	}
	base, err := encode(ev(contract.EventSyncPaused, contract.ActorPerson, contract.StopPause, nil))
	if err != nil {
		return nil, err
	}
	for _, c := range []struct{ name, old, new string }{
		{`"stop": null`, `"stop":"pause"`, `"stop":null`},
		{`"stop": ""`, `"stop":"pause"`, `"stop":""`},
		{"stop as a number", `"stop":"pause"`, `"stop":1`},
	} {
		raw, err := replaceOnce(base, c.old, c.new)
		if err != nil {
			return nil, err
		}
		var e contract.Event
		valid := json.Unmarshal(raw, &e) == nil && e.Validate() == nil
		out.Events = append(out.Events, WireCase{Name: c.name, Value: raw, Valid: valid})
	}
	return out, nil
}
