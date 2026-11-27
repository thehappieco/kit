package contract

// The kit's own tests of the contract, beside the platform's: fuzz targets
// for the parsers both sides run on what the other sends, and the rules the
// kit adds to the platform's code (SPEC section 11.17).

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/thehappieco/kit/reqhmac"
)

// What a Time accepts is RFC 3339's date-time in UTC: the grammar, a year
// from 1970, a moment time.Parse reads the same, in UTC, which it writes
// back as itself.
func FuzzReadingATimeTakesOnlyRFC3339InUTC(f *testing.F) {
	for _, s := range []string{
		`"2026-10-13T12:00:00Z"`, `"2026-10-13T12:00:00.123456789Z"`, `"2026-10-13T12:00:00.1234567890Z"`,
		`"2026-10-13T12:00:00,5Z"`, `"1969-12-31T23:59:59Z"`, `"1970-01-01T00:00:00Z"`, `"2026-10-13T12:00:00+00:00"`,
		`"2026-02-30T00:00:00Z"`, `"2026-10-13T24:00:00Z"`, `"2026-10-13T23:59:60Z"`, `"9999-12-31T23:59:59.999999999Z"`,
		`"2026-10-13T12:00:00.Z"`, `"2026-10-13t12:00:00z"`, `null`, `""`, `"`, `0`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var tm Time
		if tm.UnmarshalJSON(b) != nil {
			return
		}
		text := string(b[1 : len(b)-1])
		if !timeGrammar.MatchString(text) {
			t.Fatalf("%q is not RFC 3339's date-time in UTC", b)
		}
		parsed, err := time.Parse(time.RFC3339Nano, text)
		if err != nil || !parsed.Equal(tm.Time) {
			t.Fatalf("%q: time.Parse reads %v, %v; the wire %v", b, parsed, err, tm.Time)
		}
		if tm.Year() < 1970 || tm.Location() != time.UTC {
			t.Fatalf("%q: %v", b, tm.Time)
		}
		out, err := tm.MarshalJSON()
		var again Time
		if err != nil || again.UnmarshalJSON(out) != nil || !again.Equal(tm.Time) {
			t.Fatalf("%q written as %q, read again as %v", b, out, again.Time)
		}
	})
}

// A hint ValidHint accepts is "…" and four digits, or an address's first
// character, "…@" and a domain: ASCII but the ellipsis, one ellipsis, no
// "@" but the one after it, and no run of DigitRun digits in the domain.
func FuzzAValidHintHoldsNoNumberOrAddress(f *testing.F) {
	for _, s := range []string{
		"…5678", "…567", "…56789", "j…@example.com", "J…@example.com", "j…@exa@mple.com", "j…@1234567.com",
		"j…@123456.com", "j…＠example.com", "j…@example", "j…@.example.com", "jo…@example.com", "", "…", "…١٢٣٤",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !ValidHint(s) {
			return
		}
		if strings.Count(s, Ellipsis) != 1 || strings.ContainsAny(s, "＠﹫") {
			t.Fatalf("%q", s)
		}
		rest := strings.Replace(s, Ellipsis, "", 1)
		for i := 0; i < len(rest); i++ {
			if rest[i] >= utf8.RuneSelf {
				t.Fatalf("%q is not ASCII but its ellipsis", s)
			}
		}
		if digits, ok := strings.CutPrefix(s, Ellipsis); ok {
			if len(digits) != 4 || strings.Trim(digits, "0123456789") != "" {
				t.Fatalf("%q", s)
			}
			return
		}
		first, domain, ok := strings.Cut(s, Ellipsis+"@")
		if !ok || len(first) != 1 || strings.Contains(domain, "@") || !strings.Contains(domain, ".") {
			t.Fatalf("%q", s)
		}
		digits := 0
		for _, r := range domain {
			if r >= '0' && r <= '9' {
				digits++
			}
		}
		if digits >= DigitRun {
			t.Fatalf("%q keeps %d digits in its domain", s, digits)
		}
	})
}

// An answer verifies only under the secret that signed it, for the request
// that sent its nonce, and never under a key that is not a secret.
func FuzzAnAnswerVerifiesOnlyUnderTheSecret(f *testing.F) {
	const target = "/contract/v1/feed?after=0&wait=0"
	f.Add("1760356800", nonce, Scheme().Signature(secretA, ToApp, "wappie", "GET", target, "1760356800", nonce, []byte(`{}`)), []byte(`{}`))
	f.Add("1760356800", nonce, "v1="+strings.Repeat("0", 64), []byte(`{}`))
	f.Add("1760356861", nonce, "v1=", []byte(nil))
	f.Fuzz(func(t *testing.T, timestamp, n, signature string, body []byte) {
		h := http.Header{}
		h.Set(HeaderTimestamp, timestamp)
		h.Set(HeaderNonce, n)
		h.Set(HeaderSignature, signature)
		err := VerifyAnswer(h, []string{secretA}, "wappie", "GET", target, n, body, now)
		if err == nil && signature != Scheme().Signature(secretA, ToApp, "wappie", "GET", target, timestamp, n, body) {
			t.Fatalf("an answer verified that the secret did not sign: %q %q %q", timestamp, n, signature)
		}
		if err == nil && VerifyAnswer(h, []string{secretA}, "wappie", "GET", target, otherNonceOf(n), body, now) == nil {
			t.Fatal("an answer verified for another request")
		}
		for _, key := range []string{"", secretA[:42], "x"} {
			forged := http.Header{}
			forged.Set(HeaderTimestamp, timestamp)
			forged.Set(HeaderNonce, n)
			forged.Set(HeaderSignature, Scheme().Signature(key, ToApp, "wappie", "GET", target, timestamp, n, body))
			if VerifyAnswer(forged, []string{key}, "wappie", "GET", target, n, body, now) == nil {
				t.Fatalf("an answer verified under the key %q, which is no secret", key)
			}
		}
	})
}

func otherNonceOf(n string) string {
	if strings.HasPrefix(n, "A") {
		return "B" + n[1:]
	}
	return "A" + n
}

// An empty or malformed key would verify what anyone signs with it: an
// answer signed with one never verifies, alone or beside a good secret,
// and the refusal is hmac_bad, at the signature's step.
func TestAnAnswerNeverVerifiesUnderAKeyThatIsNoSecret(t *testing.T) {
	body := []byte(`{"accepted":true}`)
	target := "/contract/v1/workspaces/x/access"
	for _, key := range []string{"", secretA[:42], secretA + "A", secretA[:42] + "B"} {
		h := http.Header{}
		SignAnswer(h, key, "wappie", "PUT", target, nonce, body, now)
		for _, secrets := range [][]string{{key}, {secretA, key}, {key, secretA}} {
			if err := VerifyAnswer(h, secrets, "wappie", "PUT", target, nonce, body, now); err != reqhmac.ErrBad {
				t.Errorf("signed with %q, verified with %q: %v, want ErrBad", key, secrets, err)
			}
		}
	}
	// The checks before the signature's still come first.
	if err := VerifyAnswer(http.Header{}, []string{""}, "wappie", "PUT", target, nonce, body, now); err != reqhmac.ErrMissing {
		t.Errorf("unsigned, under an empty key: %v, want ErrMissing", err)
	}
}

// The closed sets Validate checks are the package's: a caller changing what
// PauseReasons or StrandedCauses returned changes nothing.
func TestTheClosedSetsCannotBeWidened(t *testing.T) {
	reasons, causes := PauseReasons(), StrandedCauses()
	if !slices.Equal(reasons, []string{"by_person", "team_closed", "no_reader", "needs_reauth", "quota", "error"}) ||
		!slices.Equal(causes, []string{"disabled", "revoked", "removed", "left", "closed"}) {
		t.Fatalf("%v %v", reasons, causes)
	}
	reasons[0], causes[0] = "teapot", "teapot"
	if PauseReasons()[0] != "by_person" || StrandedCauses()[0] != "disabled" {
		t.Fatal("a caller changed a closed set")
	}
	paused := Item{ID: "n1", Kind: ItemNumber, State: StateSyncPaused, Reason: &reasons[0], People: []Person{}, Protected: []string{}}
	if (Snapshot{V: 1, SnapshotSeq: 1, Items: []Item{paused}}).Validate() == nil {
		t.Fatal("a reason outside the set validated")
	}
	paused.Reason = &PauseReasons()[0]
	if err := (Snapshot{V: 1, SnapshotSeq: 1, Items: []Item{paused}}).Validate(); err != nil {
		t.Fatalf("a reason of the set: %v", err)
	}
}

// A command verifies only under the MAC SignCommand writes for it: whatever
// the bytes, a command that SignCommand signs verifies, its mac is the
// signature of its canonical text under that app and secret alone, and the
// bytes as given verify only when their mac is that one.
func FuzzACommandVerifiesOnlyUnderItsMAC(f *testing.F) {
	const secret, other = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"
	for _, s := range []string{
		`{"v":1,"app":"wappie","kind":"item.rename","params":{"before":{"label":"Vendas"},"after":{"label":"Vendas SP"}},"issued_at":"2026-10-13T12:00:00.120Z"}`,
		`{"app":"wappie","mac":"v1=00","a":[1,2,{"b":null}]}`, `{"app":"mailie","a":1}`, `{"app":"wappie","a":"\u2028\u00e9"}`,
		`{"app":"wappie","a":1,"a":2}`, `{"app":"wappie","a":"\ud800"}`, `{"app":"wappie"}`, `{}`, `[]`, `null`, `{"app":"wappie","a":1.5}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		signed, err := SignCommand(raw, "wappie", secret)
		if err != nil {
			if _, err := VerifyCommand(raw, "wappie", []string{secret}); err == nil {
				t.Fatal("a command SignCommand refuses verifies")
			}
			return
		}
		if _, err := VerifyCommand(signed, "wappie", []string{secret}); errors.Is(err, ErrCommandMAC) {
			t.Fatal("a signed command does not verify")
		}
		if _, err := VerifyCommand(signed, "wappie", []string{other}); !errors.Is(err, ErrCommandMAC) {
			t.Fatal("a signed command verifies under another secret")
		}
		if _, err := VerifyCommand(signed, "mailie", []string{secret}); !errors.Is(err, ErrInvalid) {
			t.Fatal("a signed command verifies for another app")
		}
		_, err = VerifyCommand(raw, "wappie", []string{secret})
		canonical, mac, _, cerr := canonicalCommand(signed)
		_, carried, _, _ := canonicalCommand(raw)
		if cerr != nil || commandMAC(canonical, "wappie", secret) != mac {
			t.Fatal("the mac SignCommand writes is not its canonical text's")
		}
		if (err == nil || !errors.Is(err, ErrCommandMAC)) != (carried == mac) {
			t.Fatalf("the given bytes verify %v with their own mac %v", err, carried == mac)
		}
	})
}

// A document the strict reading takes and Validate accepts reads again
// the same: encoded again, its data decodes into the same value and
// validates, so no member is lost or bent between the platform and the
// console.
func FuzzASettingsDocumentThatValidatesReadsAgainTheSame(f *testing.F) {
	for _, s := range []string{
		`{"v":1,"type":"person_settings","app":"wappie","producer":"wappie","sub":"0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20","state_seq":1,"measured_at":"2026-10-13T12:00:00Z","truncated":false,"accepts":[],"data":{"notices":[],"signed_out_everywhere_at":null}}`,
		`{"v":1,"type":"settings","app":"mailie","section":"permissions","producer":"mailie","workspace_id":"01a034b7-d09c-7121-b7f8-41f210a9244a","state_seq":1,"snapshot_seq":1,"measured_at":"2026-10-13T12:00:00Z","truncated":false,"accepts":["item.flags_drop"],"data":{"members":[{"sub":"0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20","status":"active","enrolled":true}]}}`,
		`{"v":1,"type":"settings","app":"wappie","section":"installations","producer":"wappie-cloud","workspace_id":"01a034b7-d09c-7121-b7f8-41f210a9244a","state_seq":1,"snapshot_seq":null,"measured_at":"2026-10-13T12:00:00Z","truncated":false,"accepts":[],"data":{"licences":{"used":0,"capacity":null},"hosted_numbers":0,"installations":[{"id":"i","name":null,"origin":"https://8.8.8.8:1","created_at":"2026-10-13T12:00:00Z"}],"bindings":[]}}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		var section SettingsDoc
		if decodeExact(raw, &section, "doc") == nil && section.Validate() == nil {
			data, err := section.DecodeData()
			if err != nil {
				t.Fatal(err)
			}
			again := section
			again.Data, _ = json.Marshal(data)
			data2, err := again.DecodeData()
			if err != nil || !reflect.DeepEqual(data, data2) {
				t.Fatalf("a valid section reads again otherwise: %v", err)
			}
		}
		var person PersonSettingsDoc
		if decodeExact(raw, &person, "doc") == nil && person.Validate() == nil {
			data, err := person.DecodeData()
			if err != nil {
				t.Fatal(err)
			}
			again := person
			again.Data, _ = json.Marshal(data)
			data2, err := again.DecodeData()
			if err != nil || !reflect.DeepEqual(data, data2) {
				t.Fatalf("a valid person reads again otherwise: %v", err)
			}
		}
	})
}

// A document of the entitlements feed is either applied, valid and the
// app's own of the page's generation at its seq, or refused alone with one
// of the three codes; never both, and nothing panics.
func FuzzAnEntitlementsDocumentIsAppliedOrRefusedAlone(f *testing.F) {
	const gen = "0199b1e0-0000-7000-8000-000000000001"
	for _, s := range []string{
		`{"v":1,"type":"entitlements","app":"wappie","generation":"` + gen + `"}`,
		`{"app":"mailie","workspace_id":"01a034b7-d09c-7121-b7f8-41f210a9244a"}`,
		`{"generation":"0199b1e0-0000-7000-8000-000000000002"}`,
		`{"timeline":[{"at":"2026-12-04T09:12:00Z","sync":"off"}],"trim":{"app":"wappie"}}`,
		`null`, `[]`, `{`, `{"v":1,"v":2}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		d, r := EntitlementsFeedItem{Seq: 7, Doc: b}.Document("wappie", gen)
		if r != nil {
			if !oneOf(r.Code, entitlementsRefusals) || r.Seq != 7 || !subOrNull(r.WorkspaceID) {
				t.Fatalf("refused %+v", r)
			}
			return
		}
		if d.Validate() != nil || d.App != "wappie" || d.Generation != gen || d.Version != 7 {
			t.Fatalf("applied %+v", d)
		}
		raw, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		var again EntitlementsDoc
		if json.Unmarshal(raw, &again) != nil || again.Validate() != nil {
			t.Fatalf("an applied document does not decode again: %s", raw)
		}
	})
}

// A trial identifier normalizes to itself again, and makes a valid code
// exactly when it normalizes: never a code for what makes none, never
// ErrInvalid for an identifier, and an IMAP login on a provider's own host
// is an address only with @.
func FuzzATrialIdentifierNormalizesOnceAndMakesACodeExactlyThen(f *testing.F) {
	for _, s := range []string{
		"+5511988887777", "+0511988887777", "A.N.A+x@GoogleMail.com", "+x@gmail.com", ".@gmail.com", "ana",
		"imap.gmail.com/ana@gmail.com", "Imap.Example.COM./Ana", "imap.gmail.com:993/a@gmail.com", "[2001:DB8::1]:993/Ana", "192.0.2.10./ana", "tid/sub", "tid/sub/x", "\x00", "ÉVA@exämple.com", "a@b@c",
	} {
		f.Add(s)
	}
	key, err := NewTrialKey([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, kind := range append(TrialCodeKinds("wappie"), TrialCodeKinds("mailie")...) {
			app := "mailie"
			if kind == TrialKindE164 || kind == TrialKindWALID {
				app = "wappie"
			}
			id, ok := NormalizeTrialIdentifier(kind, s)
			code, err := TrialCode(key, app, kind, s)
			switch {
			case ok != (err == nil):
				t.Fatalf("%s %q: normalized %v, code error %v", kind, s, ok, err)
			case !ok && (!errors.Is(err, ErrNoCode) || code != ""):
				t.Fatalf("%s %q: %q %v", kind, s, code, err)
			case !ok:
				continue
			case !ValidTrialCode(code) || id == "" || strings.IndexByte(id, 0) >= 0 || !utf8.ValidString(id):
				t.Fatalf("%s %q: %q %q", kind, s, id, code)
			}
			again, ok := NormalizeTrialIdentifier(kind, id)
			if !ok || again != id {
				t.Fatalf("%s %q: %q normalizes to %q %v", kind, s, id, again, ok)
			}
			if same, _ := TrialCode(key, app, kind, id); same != code {
				t.Fatalf("%s %q: the normalized identifier makes another code", kind, s)
			}
		}
		host, login, _ := strings.Cut(s, "/")
		if kind, id, ok := IMAPIdentity(host, login); ok {
			name := strings.ToLower(host)
			if strings.Count(name, ":") == 1 {
				name, _, _ = strings.Cut(name, ":")
			}
			provider := slices.Contains(ProviderIMAPHosts(), strings.TrimSuffix(name, "."))
			if (kind == TrialKindAddress) != (provider && strings.Contains(login, "@")) {
				t.Fatalf("%q %q: %s", host, login, kind)
			}
			if again, ok := NormalizeTrialIdentifier(kind, id); !ok || again != id {
				t.Fatalf("%q %q: %s %q does not normalize to itself", host, login, kind, id)
			}
		}
	})
}

// Whatever a usage report's bytes, the platform reads it strictly and
// Validate holds the exact sum: nothing panics, and a report that passes
// decodes again to itself.
func FuzzAUsageReportThatValidatesHoldsItsSum(f *testing.F) {
	for _, s := range []string{
		`{"v":1,"type":"usage","app":"wappie","workspace_id":"01a034b7-d09c-7121-b7f8-41f210a9244a","usage_seq":1,"rule_version":"wappie-storage/1","measured_at":"2026-12-03T09:40:00Z","total_bytes":3,"shared_bytes":1,"items":[{"id":"d","state":"active","purge_at":null,"bytes":2,"recent_bytes":1,"undated_bytes":0,"fixed_bytes":1}]}`,
		`{"v":1,"type":"usage","app":"mailie","workspace_id":"01a034b7-d09c-7121-b7f8-41f210a9244a","usage_seq":1,"rule_version":"mailie-usage/1","measured_at":"2026-12-03T09:40:00Z","total_bytes":0,"shared_bytes":0,"items":[]}`,
		`{"total_bytes":9007199254740993}`, `null`, `{`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var u Usage
		if DecodeStrict(b, &u) != nil || u.Validate() != nil {
			return
		}
		sum := u.SharedBytes
		for _, it := range u.Items {
			sum += it.Bytes
			if it.RecentBytes+it.UndatedBytes+it.FixedBytes > it.Bytes {
				t.Fatalf("parts over bytes: %s", b)
			}
		}
		if sum != u.TotalBytes || sum > MaxSafeInteger {
			t.Fatalf("the sum: %s", b)
		}
		raw, err := json.Marshal(u)
		if err != nil {
			t.Fatal(err)
		}
		var again Usage
		if DecodeStrict(raw, &again) != nil || !reflect.DeepEqual(again, u) {
			t.Fatalf("does not decode again: %s", raw)
		}
	})
}

// A trim order verifies only under the MAC SignTrimOrder writes for it,
// with the trim's own label: whatever the bytes, an order SignTrimOrder
// signs passes the MAC check under that secret alone, its mac is the trim
// signature of its canonical text, never a command's, and the bytes as
// given pass the MAC check only when their mac is that one.
func FuzzATrimOrderVerifiesOnlyUnderItsMAC(f *testing.F) {
	const secret, other = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"
	for _, s := range []string{
		`{"order_id":"0199c3a0-0000-7000-8000-000000000001","app":"wappie","round":1,"steps":[{"item":"dev_9","action":"purge"}],"issued_at":"2026-12-31T09:20:00.120Z"}`,
		`{"app":"wappie","mac":"v1=00","secret":1,"a":[1,2,{"b":null}]}`, `{"app":"mailie","a":1}`, `{"app":"wappie","a":" é"}`,
		`{"app":"wappie","a":1,"a":2}`, `{"app":"wappie","a":"\ud800"}`, `{"app":"wappie"}`, `{}`, `[]`, `null`, `{"app":"wappie","a":1.5}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		verify := func(b []byte, s string) error {
			_, err := VerifyTrimOrder(EntitlementsDoc{App: "wappie", Trim: b}, "wappie", []string{s})
			return err
		}
		signed, err := SignTrimOrder(raw, "wappie", secret, 2)
		if err != nil {
			if verify(raw, secret) == nil {
				t.Fatal("an order SignTrimOrder refuses verifies")
			}
			return
		}
		if err := verify(signed, secret); err == nil || errors.Is(err, ErrTrimMAC) {
			// The empty document fails after the MAC, never at it.
			t.Fatalf("a signed order fails its MAC check: %v", err)
		}
		if !errors.Is(verify(signed, other), ErrTrimMAC) {
			t.Fatal("a signed order passes the MAC check under another secret")
		}
		canonical, mac, _, cerr := canonicalSigned(signed, "trim")
		if cerr != nil || trimMAC(canonical, "wappie", secret) != mac || commandMAC(canonical, "wappie", secret) == mac {
			t.Fatal("the mac SignTrimOrder writes is not its canonical text's trim MAC")
		}
		given, carried, _, _ := canonicalSigned(raw, "trim")
		if !errors.Is(verify(raw, secret), ErrTrimMAC) != (carried == trimMAC(given, "wappie", secret)) {
			t.Fatal("the given bytes pass the MAC check other than by their own mac")
		}
	})
}
