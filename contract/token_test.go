package contract_test

// The token part's own tests (SPEC section 11.18), beside its vectors: the
// token's layout and hash, the one answer VerifyToken gives, the reading
// key's checks, the optional members that are absent and never null, and
// the closed lists.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/thehappieco/kit/contract"
)

func TestATokenIsItsSixtyFourCharactersAndNothingElse(t *testing.T) {
	good := formatToken(vecSelector, vecSecret())
	p, err := contract.ParseToken(good)
	if err != nil || len(good) != contract.TokenLen {
		t.Fatalf("%v, %d characters", err, len(good))
	}
	if p.Selector != vecSelector || p.Hash() != contract.TokenHash(vecSecret()) {
		t.Fatalf("selector %s, hash %s", p.Selector, p.Hash())
	}
	// Nothing around it is trimmed, folded or decoded.
	for _, s := range []string{" " + good, good + " ", good + "\r\n", strings.ToUpper(good), strings.Replace(good, ".", "%2E", 1)} {
		if _, err := contract.ParseToken(s); !errors.Is(err, contract.ErrToken) {
			t.Errorf("%q: %v", s, err)
		}
	}
}

func TestATokensHashCoversItsSecretsThirtyTwoBytesAlone(t *testing.T) {
	secret := vecSecret()
	sum := sha256.Sum256(append(append([]byte("thehappie-token/v1/secret"), 0), secret[:]...))
	if got := contract.TokenHash(secret); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("hash %s", got)
	}
	a, _ := contract.ParseToken(formatToken("0123456789abcdef", secret))
	b, _ := contract.ParseToken(formatToken("fedcba9876543210", secret))
	if a.Hash() != b.Hash() {
		t.Fatal("two selectors of one secret hash apart: the hash covers more than the secret")
	}
	// The 43 characters are not what is hashed.
	text := sha256.Sum256(append(append([]byte("thehappie-token/v1/secret"), 0), base64.RawURLEncoding.EncodeToString(secret[:])...))
	if a.Hash() == hex.EncodeToString(text[:]) {
		t.Fatal("the hash covers the secret's text")
	}
}

func TestVerifyTokenAnswersOnlyTheRecordsOwnToken(t *testing.T) {
	secret := vecSecret()
	good := formatToken(vecSelector, secret)
	rec := &contract.TokenRecord{Selector: vecSelector, Hash: contract.TokenHash(secret)}
	if err := contract.VerifyToken(rec, good); err != nil {
		t.Fatalf("its own token: %v", err)
	}
	other := secret
	other[0] ^= 1
	for name, c := range map[string]struct {
		rec   *contract.TokenRecord
		token string
	}{
		"no record":                   {nil, good},
		"another secret":              {rec, formatToken(vecSelector, other)},
		"another selector":            {&contract.TokenRecord{Selector: "0123456789abcdef", Hash: rec.Hash}, good},
		"a hash in capitals":          {&contract.TokenRecord{Selector: vecSelector, Hash: strings.ToUpper(rec.Hash)}, good},
		"a hash of 63 digits":         {&contract.TokenRecord{Selector: vecSelector, Hash: rec.Hash[:63]}, good},
		"no hash":                     {&contract.TokenRecord{Selector: vecSelector}, good},
		"a token that does not parse": {rec, "THC_" + good[4:]},
		"no token":                    {rec, ""},
	} {
		err := contract.VerifyToken(c.rec, c.token)
		if !errors.Is(err, contract.ErrToken) {
			t.Errorf("%s: %v, want ErrToken", name, err)
		}
	}
}

func TestNoTokenRefusalNamesAByteOfTheToken(t *testing.T) {
	secret := vecSecret()
	good := formatToken(vecSelector, secret)
	secretText := good[21:]
	for _, s := range []string{good + "x", "THC_" + good[4:], good[:63] + "B", strings.Replace(good, ".", ":", 1)} {
		_, err := contract.ParseToken(s)
		if err == nil || strings.Contains(err.Error(), secretText[:8]) || strings.Contains(err.Error(), vecSelector) {
			t.Errorf("%v names the token", err)
		}
		if _, err := contract.BearerToken([]string{"Bearer " + s}); err == nil || strings.Contains(err.Error(), secretText[:8]) {
			t.Errorf("%v names the token", err)
		}
	}
	p, _ := contract.ParseToken(good)
	// Held in an unexported field, fmt prints the struct's fields as they
	// are, and slog's text handler too: the parsed token keeps no byte of
	// the secret to print.
	type session struct {
		user  string
		token contract.ParsedToken
	}
	held := session{user: "ana", token: p}
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	log.Info("token", "token", p)
	log.Info("session", "session", held)
	secretDec := strings.Trim(fmt.Sprint(secret[:8]), "[]")
	secretHex := hex.EncodeToString(secret[:8])
	printed := []string{fmt.Sprint(p), buf.String()}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x"} {
		// Every verb, those vet would refuse for the type included: a
		// program may still print a struct that holds one with them.
		printed = append(printed, fmt.Sprintf(verb, p), fmt.Sprintf(verb, held))
	}
	for _, printed := range printed {
		if strings.Contains(printed, secretText[:8]) || strings.Contains(printed, secretDec) || strings.Contains(printed, secretHex) {
			t.Errorf("a parsed token prints its secret: %q", printed)
		}
	}
	if !strings.Contains(fmt.Sprint(p), vecSelector) {
		t.Error("a parsed token does not print its selector")
	}
}

// The points of low order of libsodium's has_small_order list: 0 (order 2),
// 1 (order 4), the two of order 8, p - 1 (order 4, on the twist), and p and
// p + 1, which are 0 and 1 spelled again; each also with the top bit set,
// which X25519 ignores.
var lowOrder = []string{
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0100000000000000000000000000000000000000000000000000000000000000",
	"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
	"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
}

func TestEveryPointOfLowOrderIsRefused(t *testing.T) {
	for i, h := range lowOrder {
		b, _ := hex.DecodeString(h)
		key := base64.RawURLEncoding.EncodeToString(b)
		err := contract.ValidReadingKey(key)
		want := contract.ErrReadingKeyLowOrder
		if i >= 5 { // p and p + 1 are no canonical spelling
			want = contract.ErrReadingKeyNotCanonical
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", h, err, want)
		}
		b[31] |= 0x80
		if err := contract.ValidReadingKey(base64.RawURLEncoding.EncodeToString(b)); !errors.Is(err, contract.ErrReadingKeyNotCanonical) {
			t.Errorf("%s with the top bit: %v", h, err)
		}
	}
	for n := 1; n <= 64; n++ {
		if err := contract.ValidReadingKey(vecKey(n)); err != nil {
			t.Errorf("a key made by X25519: %v", err)
		}
	}
}

func TestAReadingKeysFingerprintIsTheFirstSixteenBytesOfItsHash(t *testing.T) {
	key := vecKey(1)
	raw, _ := base64.RawURLEncoding.DecodeString(key)
	sum := sha256.Sum256(append(append([]byte("thehappie-token/v1/reading-key"), 0), raw...))
	fp, err := contract.ReadingKeyFingerprint(key)
	if err != nil || fp != hex.EncodeToString(sum[:16]) || len(fp) != contract.FingerprintLen {
		t.Fatalf("%s %v", fp, err)
	}
	if err := contract.CheckReadingKey(key, fp); err != nil {
		t.Fatal(err)
	}
	rk := contract.ReadingKey{Suite: contract.ReadingKeySuite, Key: key, Fingerprint: fingerprint(vecKey(2)), RegisteredAt: contract.T(Now)}
	if rk.Validate() != nil || !errors.Is(rk.Check(), contract.ErrReadingKeyFingerprint) {
		t.Fatal("another key's fingerprint is the record's shape and not its key's")
	}
}

// An optional member is absent, never null: Go's zero value writes nothing,
// and a receiver refuses null, and for ordinal 0 and stop "", which would
// read as absent.
func TestAnOptionalMemberIsAbsentNeverNull(t *testing.T) {
	item := contract.Item{ID: "n1", Kind: contract.ItemNumber, State: contract.StateActive, People: []contract.Person{}, Protected: []string{}}
	raw, _ := json.Marshal(item)
	if bytes.Contains(raw, []byte("ordinal")) || bytes.Contains(raw, []byte("tokens")) {
		t.Fatalf("absent members written: %s", raw)
	}
	item.Tokens = contract.ItemTokens{}
	raw, _ = json.Marshal(item)
	if !bytes.Contains(raw, []byte(`"tokens":[]`)) {
		t.Fatalf("an empty list of tokens is not written: %s", raw)
	}
	var back contract.Item
	if err := json.Unmarshal(raw, &back); err != nil || back.Tokens == nil || len(back.Tokens) != 0 {
		t.Fatalf("an empty list of tokens read back as %v, %v", back.Tokens, err)
	}
	ev, _ := json.Marshal(contract.Event{})
	ack, _ := json.Marshal(contract.TokenApplied{})
	if bytes.Contains(ev, []byte("stop")) || bytes.Contains(ack, []byte("waiting")) || bytes.Contains(ack, []byte("suspended")) {
		t.Fatalf("absent members written: %s %s", ev, ack)
	}
	for _, c := range []struct {
		into any
		raw  string
	}{
		{&contract.Item{}, `{"ordinal":null}`},
		{&contract.Item{}, `{"ordinal":0}`},
		{&contract.Item{}, `{"ordinal":"1"}`},
		{&contract.Item{}, `{"tokens":null}`},
		{&contract.Item{}, `{"tokens":[{"id":"x","can":[],"reads":false,"waiting":false,"selector":"9f3c0a7be41d2c58"}]}`},
		{&contract.Event{}, `{"stop":null}`},
		{&contract.Event{}, `{"stop":""}`},
		{&contract.TokenApplied{}, `{"waiting":null}`},
		{&contract.TokenApplied{}, `{"suspended":null}`},
		{&contract.TokenApplied{}, `{"suspended":[{"token":"x","cause":"operator","note":1}]}`},
	} {
		if err := json.Unmarshal([]byte(c.raw), c.into); err == nil {
			t.Errorf("%s decodes", c.raw)
		}
	}
}

// The closed lists Validate checks are the package's: a caller changing
// what a function returned changes nothing.
func TestTheTokenPartsClosedListsCannotBeWidened(t *testing.T) {
	for _, c := range []struct {
		get  func() []string
		want []string
	}{
		{contract.RevokedReasons, []string{"revoked", "creator_left", "creator_disabled", "creator_closed", "creator_recovered", "operator", "app_removed", "app_held"}},
		{contract.RefusalCodes, []string{"giver_not_reader", "local_role", "not_offered", "item_unknown", "terms_not_current", "team_withheld", "reading_key_changed", "invalid_record"}},
		{contract.SuspendCauses, []string{"operator", "creator_disabled_here", "local_rule"}},
		{contract.UsageRefusalCodes, []string{"no_permission", "no_grant", "switch_off", "api_paused", "creator_consent", "not_offered", "stale_feed", "workspace_closed", "revoked", "expired", "suspended_here"}},
		{func() []string { return contract.TokenPerms(contract.ItemNumber) }, []string{"read", "send", "manage"}},
		{func() []string { return contract.TokenPerms(contract.ItemMailbox) }, []string{"read", "act", "send"}},
	} {
		got := c.get()
		if !slices.Equal(got, c.want) {
			t.Fatalf("%v, want %v", got, c.want)
		}
		got[0] = "teapot"
		if c.get()[0] != c.want[0] {
			t.Fatal("a caller changed a closed list")
		}
	}
	rec := vecRecord(revoke(contract.RevokedReasons()[0]))
	if err := rec.Validate(); err != nil {
		t.Fatal(err)
	}
	teapot := "teapot"
	rec.RevokedReason = &teapot
	if rec.Validate() == nil {
		t.Fatal("a reason outside the list validated")
	}
}

// An app other than Wappie and Mailie, the platform's reference app in
// development, may list either kind, each under its kind's rule.
func TestAnotherAppsItemsFollowTheirKindsRule(t *testing.T) {
	rec := vecRecord(func(r *contract.TokenRecord) { r.App = "fakeproduct" })
	if err := rec.Validate(); err != nil {
		t.Fatal(err)
	}
	rec.Items = append(rec.Items, contract.TokenItem{ID: vecMailbox, Kind: contract.ItemMailbox, Perms: []contract.TokenPerm{{Perm: contract.CanAct, GrantedBy: vecSub, GrantedAt: contract.T(Now)}}})
	if rec.Validate() == nil {
		t.Fatal("a mailbox's act without read validated")
	}
}

// What ParseToken takes is exactly the layout: thc_, 16 lowercase hex, a
// dot, and the one spelling of 32 bytes; and BearerToken takes a header
// only around such a token.
func FuzzParseTokenTakesOnlyTheLayout(f *testing.F) {
	good := formatToken(vecSelector, vecSecret())
	for _, s := range []string{good, "", good[:63] + "B", "THC_" + good[4:], good + " ", strings.Replace(good, ".", ":", 1), good[:21] + strings.Repeat("_", 42) + "8"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := contract.ParseToken(s)
		_, berr := contract.BearerToken([]string{"Bearer " + s})
		if (err == nil) != (berr == nil) {
			t.Fatalf("%q: ParseToken %v, BearerToken %v", s, err, berr)
		}
		if err != nil {
			var te *contract.TokenError
			if !errors.As(err, &te) || te.Step < 1 || te.Step > 6 || !errors.Is(err, contract.ErrToken) {
				t.Fatalf("%q: %v", s, err)
			}
			return
		}
		raw, derr := base64.RawURLEncoding.Strict().DecodeString(s[21:])
		if len(s) != 64 || s[:4] != "thc_" || s[20] != '.' || p.Selector != s[4:20] || derr != nil || len(raw) != 32 ||
			base64.RawURLEncoding.EncodeToString(raw) != s[21:] || p.Selector != strings.ToLower(p.Selector) {
			t.Fatalf("%q is not the layout", s)
		}
		var secret [32]byte
		copy(secret[:], raw)
		if p.Hash() != contract.TokenHash(secret) || contract.VerifyToken(&contract.TokenRecord{Selector: p.Selector, Hash: p.Hash()}, s) != nil {
			t.Fatalf("%q does not verify against its own record", s)
		}
	})
}

// A reading key ValidReadingKey takes is the one spelling of 32 bytes, its
// top bit clear, below p, and of full order: its X25519 with any scalar is
// not all zeros.
func FuzzAValidReadingKeyIsCanonicalAndOfFullOrder(f *testing.F) {
	for _, h := range lowOrder {
		b, _ := hex.DecodeString(h)
		f.Add(base64.RawURLEncoding.EncodeToString(b))
	}
	f.Add(vecKey(1))
	f.Add(vecKey(1) + "=")
	f.Fuzz(func(t *testing.T, key string) {
		if contract.ValidReadingKey(key) != nil {
			return
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(key)
		if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != key || raw[31]&0x80 != 0 {
			t.Fatalf("%q is not a canonical key's spelling", key)
		}
		le := slices.Clone(raw)
		slices.Reverse(le)
		if hex.EncodeToString(le) >= "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed" {
			t.Fatalf("%q is at or above p", key)
		}
		scalar := sha256.Sum256([]byte("another scalar"))
		priv, _ := ecdh.X25519().NewPrivateKey(scalar[:])
		pub, _ := ecdh.X25519().NewPublicKey(raw)
		if _, err := priv.ECDH(pub); err != nil {
			t.Fatalf("%q is of low order", key)
		}
		if _, err := contract.ReadingKeyFingerprint(key); err != nil {
			t.Fatalf("%q has no fingerprint", key)
		}
	})
}

// A record that does not decode comes with what of it could be read, and
// a revoked_at that is set, whatever its value, revokes.
func TestARecordThatDoesNotDecodeStillNarrows(t *testing.T) {
	bad := vecRecord(func(r *contract.TokenRecord) {
		revoke(contract.RevokedInConsole)(r)
		r.RevokedAt = &contract.Time{}
	})
	raw, err := json.Marshal(bad)
	if err != nil {
		t.Fatal(err)
	}
	r, err := contract.TokenFeedItem{Token: raw}.Record()
	if !errors.Is(err, contract.ErrInvalid) || r.ID != vecToken || r.App != "wappie" || r.RevokedAt == nil || !r.RevokedAt.IsZero() {
		t.Fatalf("%+v %v", r, err)
	}
	// An expires_at that does not decode is the earliest.
	raw = []byte(strings.Replace(string(mustJSON(t, vecRecord(nil))), `"expires_at":"`, `"expires_at":"x`, 1))
	if r, err = (contract.TokenFeedItem{Token: raw}).Record(); err == nil || !r.ExpiresAt.IsZero() || r.RevokedAt != nil || len(r.Items) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	// A revoked_reason revokes too: a revoked_at written in another case is
	// one the record does not have, and the revocation still sticks.
	raw = []byte(strings.Replace(string(mustJSON(t, vecRecord(revoke(contract.RevokedInConsole)))), `"revoked_at":"`, `"Revoked_at":"`, 1))
	if r, err = (contract.TokenFeedItem{Token: raw}).Record(); err != nil || r.RevokedAt == nil || !r.RevokedAt.IsZero() || r.Validate() == nil {
		t.Fatalf("a miscased revoked_at: %+v %v", r, err)
	}
	for _, junk := range []string{`null`, `5`, `[]`, `"x"`} {
		if r, err := (contract.TokenFeedItem{Token: json.RawMessage(junk)}).Record(); err == nil || r.App != "" {
			t.Errorf("%s: %+v %v", junk, r, err)
		}
	}
	// One that decodes comes whole, ready for Validate.
	if r, err := (contract.TokenFeedItem{Token: mustJSON(t, vecRecord(nil))}).Record(); err != nil || r.Validate() != nil {
		t.Fatalf("%v %v", err, r.Validate())
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A flag present only as true: false and null are refused, and false is
// written as nothing.
func TestAFlagIsAbsentOrTrue(t *testing.T) {
	var a contract.TokenApplied
	for _, raw := range []string{`{"waiting_more":false}`, `{"waiting_more":null}`, `{"suspended_more":1}`, `{"suspended_more":"true"}`} {
		if json.Unmarshal([]byte(raw), &a) == nil {
			t.Errorf("%s decodes", raw)
		}
	}
	if err := json.Unmarshal([]byte(`{"waiting_more":true,"suspended_more":true}`), &a); err != nil || !a.WaitingMore || !a.SuspendedMore {
		t.Fatalf("%+v %v", a, err)
	}
	if b := mustJSON(t, contract.TokenApplied{WaitingMore: false}); bytes.Contains(b, []byte("_more")) {
		t.Fatalf("false is written: %s", b)
	}
}

// Each limit holds at its count and refuses one more (the vectors carry the
// ones over; these are the ones at).
func TestEveryCountLimitHoldsAtItsCount(t *testing.T) {
	ids := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("0199f2a1-0000-7000-8000-%012d", i+1)
		}
		return out
	}
	check := func(name string, at, over error) {
		t.Helper()
		if at != nil || over == nil {
			t.Errorf("%s: at the limit %v, over it %v", name, at, over)
		}
	}
	// A token feed page: 200 records.
	page := func(n int) contract.TokenFeed {
		f := contract.TokenFeed{Generation: vecGeneration, Head: int64(n), NextAfter: int64(n), PublishedThrough: contract.T(Now), Items: []contract.TokenFeedItem{}}
		for i := 1; i <= n; i++ {
			f.Items = append(f.Items, contract.TokenFeedItem{Seq: int64(i), Token: json.RawMessage(`{}`)})
		}
		return f
	}
	check("feed items", page(contract.MaxTokenFeedItems).Validate(), page(contract.MaxTokenFeedItems+1).Validate())
	// A record: 1000 items.
	items := func(n int) contract.TokenRecord {
		return vecRecord(func(r *contract.TokenRecord) {
			r.Items = nil
			for i := 0; i < n; i++ {
				r.Items = append(r.Items, contract.TokenItem{ID: fmt.Sprintf("n%04d", i), Kind: contract.ItemNumber, Perms: []contract.TokenPerm{{Perm: contract.CanRead, GrantedBy: vecSub, GrantedAt: contract.T(Now)}}})
			}
		})
	}
	check("record items", items(contract.MaxTokenItems).Validate(), items(contract.MaxTokenItems+1).Validate())
	// An acknowledgement: 1000 waiting, 1000 suspended, 1000 together, 1000 removed.
	base := contract.TokenApplied{Generation: vecGeneration, AppliedAt: contract.T(Now), Refused: []contract.TokenRefusal{}, Held: []contract.TokenHeld{}}
	waiting := func(n int) contract.TokenApplied {
		a := base
		for i, id := range ids(n) {
			a.Waiting = append(a.Waiting, contract.WaitingPerm{Token: id, Item: fmt.Sprintf("n%d", i), Perm: contract.CanRead, GrantedBy: vecSub, GrantedAt: contract.T(Now)})
		}
		return a
	}
	check("waiting", waiting(contract.MaxAppliedEntries).Validate(), waiting(contract.MaxAppliedEntries+1).Validate())
	suspended := func(n int) contract.TokenApplied {
		a := base
		for _, id := range ids(n) {
			a.Suspended = append(a.Suspended, contract.Suspension{Token: id, Cause: contract.SuspendedOperator})
		}
		return a
	}
	check("suspended", suspended(contract.MaxAppliedEntries).Validate(), suspended(contract.MaxAppliedEntries+1).Validate())
	together := func(n int) contract.TokenApplied {
		a := suspended(contract.MaxAppliedEntries - 1)
		for _, id := range ids(n) {
			a.Held = append(a.Held, contract.TokenHeld{Token: id, Removed: []contract.HeldPerm{}})
		}
		return a
	}
	check("the four lists together", together(1).Validate(), together(2).Validate())
	removed := func(n int) contract.TokenApplied {
		a := base
		h := contract.TokenHeld{Token: vecToken, Removed: []contract.HeldPerm{}}
		for i := 0; i < n; i++ {
			h.Removed = append(h.Removed, contract.HeldPerm{Item: fmt.Sprintf("n%d", i), Perm: contract.CanRead})
		}
		a.Held = []contract.TokenHeld{h}
		return a
	}
	check("held removed", removed(contract.MaxHeldRemoved).Validate(), removed(contract.MaxHeldRemoved+1).Validate())
	// Usage: 1000 used, 1000 refusals; the body limit is the transport's,
	// at most UsageBodyLimit bytes.
	used := func(n int) contract.TokenUsage {
		u := contract.TokenUsage{Refusals: []contract.UsageRefusal{}}
		for _, id := range ids(n) {
			u.Used = append(u.Used, contract.TokenUsed{Token: id, Day: "2026-10-13"})
		}
		return u
	}
	check("used", used(contract.MaxUsageEntries).Validate(), used(contract.MaxUsageEntries+1).Validate())
	refusals := func(n int) contract.TokenUsage {
		u := contract.TokenUsage{Used: []contract.TokenUsed{}}
		for _, id := range ids(n) {
			u.Refusals = append(u.Refusals, contract.UsageRefusal{Token: id, Day: "2026-10-13", Code: contract.UseRevoked, Count: 1})
		}
		return u
	}
	check("refusals", refusals(contract.MaxUsageEntries).Validate(), refusals(contract.MaxUsageEntries+1).Validate())
	// A snapshot item: 1000 tokens; the ordinal 9999.
	tokens := func(n int) contract.Snapshot {
		it := contract.Item{ID: "n1", Kind: contract.ItemNumber, State: contract.StateActive, People: []contract.Person{}, Protected: []string{}, Ordinal: contract.MaxOrdinal, Tokens: contract.ItemTokens{}}
		for _, id := range ids(n) {
			it.Tokens = append(it.Tokens, contract.ItemToken{ID: id, Can: []string{contract.CanRead}, Reads: true})
		}
		return contract.Snapshot{V: 1, SnapshotSeq: 1, Items: []contract.Item{it}}
	}
	check("item tokens", tokens(contract.MaxItemTokens).Validate(), tokens(contract.MaxItemTokens+1).Validate())
	if contract.UsageBodyLimit != 256<<10 {
		t.Fatal("the usage body limit")
	}
	if !usageValid(append(bytes.Repeat([]byte(" "), contract.UsageBodyLimit-len(`{"used":[],"refusals":[]}`)), `{"used":[],"refusals":[]}`...)) ||
		usageValid(append(bytes.Repeat([]byte(" "), contract.UsageBodyLimit+1-len(`{"used":[],"refusals":[]}`)), `{"used":[],"refusals":[]}`...)) {
		t.Fatal("a usage body of exactly 256 KiB is within the limit, and one byte more is not")
	}
}
