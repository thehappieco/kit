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
		if _, err := VerifyCommand(signed, "mailie", []string{secret}); !errors.Is(err, ErrCommandMAC) {
			t.Fatal("a signed command verifies for another app")
		}
		_, err = VerifyCommand(raw, "wappie", []string{secret})
		canonical, mac, cerr := canonicalCommand(signed)
		_, carried, _ := canonicalCommand(raw)
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
