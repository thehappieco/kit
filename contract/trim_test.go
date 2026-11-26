package contract_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/jcs"
)

const (
	trimOrderID = "0199c3a0-0000-7000-8000-000000000001"
	trimEpisode = "0199a2f0-0000-7000-8000-000000000001"
)

// trimIssued is when the test orders were issued: the spec's example.
var trimIssued = time.Date(2026, 12, 31, 9, 20, 0, 0, time.UTC)

func trimAt(d time.Duration) contract.Time { return contract.T(trimIssued.Add(d)) }

// trimOrder is the spec's example order, valid, for app in the test team
// and generation, its mac left for SignTrimOrder.
func trimOrder(app string, mut func(*contract.TrimOrder)) contract.TrimOrder {
	o := contract.TrimOrder{
		OrderID: trimOrderID, App: app, WorkspaceID: vecTeam, Generation: vecGeneration, Episode: trimEpisode,
		Round: 1, IssuedAt: trimAt(0), NotBefore: trimAt(0), ValidUntil: trimAt(6 * time.Hour),
		Floor: ptr("2026-10-02"),
		Basis: contract.TrimBasis{UsageSeq: 1798708320000, MeasuredAt: trimAt(-8 * time.Minute)},
		Steps: []contract.TrimStep{
			{Item: "dev_9", Action: contract.TrimActionPurge},
			{Item: "dev_7", Action: contract.TrimActionKeep, KeepBytes: ptr[int64](14000000000)},
		},
		BasisPurge: map[string]contract.Time{"dev_9": contract.T(time.Date(2026, 12, 20, 0, 0, 0, 0, time.UTC))},
		Secret:     2,
		MAC:        "v1=" + strings.Repeat("0", 64),
	}
	if mut != nil {
		mut(&o)
	}
	return o
}

// trimSigned is o signed for its own app under secret, generation 2.
func trimSigned(t testing.TB, o contract.TrimOrder, secret string) []byte {
	t.Helper()
	raw, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := contract.SignTrimOrder(raw, o.App, secret, 2)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// trimDoc is a valid expired document of app carrying the order raw.
func trimDoc(app string, raw []byte, mut func(*contract.EntitlementsDoc)) contract.EntitlementsDoc {
	return entDoc(app, func(d *contract.EntitlementsDoc) {
		d.State = contract.EntitlementsState{Name: contract.WorkspaceExpired, Reason: ptr(contract.ReasonNoPlan),
			Since: *entAt(-40 * 24 * time.Hour), ExpiredSince: entAt(-10 * 24 * time.Hour)}
		d.Trim = raw
		if mut != nil {
			mut(d)
		}
	})
}

// trimNoPlan makes a document's workspace one without a plan.
func trimNoPlan(d *contract.EntitlementsDoc) {
	d.Plan = contract.EntitlementsPlan{Source: contract.SourceNone}
	d.Places = contract.EntitlementsPlaces{Kind: contract.ItemNumber, Used: ptr[int64](2), UsedConnected: ptr[int64](1),
		Free: ptr[int64](0), CountedAt: entAt(-2 * time.Minute)}
	d.Storage = contract.EntitlementsStorage{UsedBytes: ptr[int64](27300000000), OthersBytes: 1200000000,
		MeasuredThrough: entAt(-20 * time.Minute)}
}

// trimNoFloor makes an order one without a plan: no floor, every keep step
// keeping nothing.
func trimNoFloor(o *contract.TrimOrder) {
	o.Floor = nil
	o.Steps[1].KeepBytes = ptr[int64](0)
}

// The spec's own example, its ids and mac written whole, decodes as an app
// reads it and validates; signed again under its secret it comes back
// with the same text.
func TestTheSpecsTrimOrderDecodesAndValidates(t *testing.T) {
	example := `{"order_id": "` + trimOrderID + `", "app": "wappie", "workspace_id": "` + vecTeam + `", "generation": "` + vecGeneration + `",
 "episode": "` + trimEpisode + `", "round": 1, "issued_at": "2026-12-31T09:20:00Z",
 "not_before": "2026-12-31T09:20:00Z", "valid_until": "2026-12-31T15:20:00Z",
 "floor": "2026-10-02", "basis": {"usage_seq": 1798708320000, "measured_at": "2026-12-31T09:12:00Z"},
 "steps": [{"item": "dev_9", "action": "purge"},
           {"item": "dev_7", "action": "keep", "keep_bytes": 14000000000}],
 "basis_purge": {"dev_9": "2026-12-20T00:00:00Z"},
 "secret": 2, "mac": "v1=` + strings.Repeat("ab", 32) + `"}`
	var o contract.TrimOrder
	if err := json.Unmarshal([]byte(example), &o); err != nil {
		t.Fatal(err)
	}
	if err := o.Validate(); err != nil {
		t.Fatal(err)
	}
	want := trimOrder("wappie", func(o *contract.TrimOrder) { o.MAC = "v1=" + strings.Repeat("ab", 32) })
	if !reflect.DeepEqual(o, want) {
		t.Fatalf("\n%+v\n%+v", o, want)
	}
	if !reflect.DeepEqual(o.Items(), []string{"dev_9", "dev_7"}) {
		t.Errorf("items %v", o.Items())
	}
	signed, err := contract.SignTrimOrder([]byte(example), "wappie", SecretA, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signed, trimSigned(t, want, SecretA)) {
		t.Errorf("the example signed\n%s\nthe order signed\n%s", signed, trimSigned(t, want, SecretA))
	}
}

func TestATrimOrderValidatesEachRow(t *testing.T) {
	steps := func(n int) []contract.TrimStep {
		s := make([]contract.TrimStep, n)
		for i := range s {
			s[i] = contract.TrimStep{Item: fmt.Sprintf("dev_%d", i), Action: contract.TrimActionKeep, KeepBytes: ptr[int64](0)}
		}
		return s
	}
	for _, c := range []struct {
		name string
		mut  func(*contract.TrimOrder)
		ok   bool
	}{
		{"the spec's", nil, true},
		{"without a plan", trimNoFloor, true},
		{"a later round, a later not_before", func(o *contract.TrimOrder) { o.Round = 3; o.NotBefore = trimAt(5 * time.Hour) }, true},
		{"order_id not a UUIDv7", func(o *contract.TrimOrder) { o.OrderID = "0199c3a0-0000-4000-8000-000000000001" }, false},
		{"order_id of another variant", func(o *contract.TrimOrder) { o.OrderID = "0199c3a0-0000-7000-c000-000000000001" }, false},
		{"order_id upper-case", func(o *contract.TrimOrder) { o.OrderID = strings.ToUpper(trimOrderID) }, false},
		{"another app's id", func(o *contract.TrimOrder) { o.App = "Wappie" }, false},
		{"workspace_id", func(o *contract.TrimOrder) { o.WorkspaceID = "" }, false},
		{"generation", func(o *contract.TrimOrder) { o.Generation = "x" }, false},
		{"episode", func(o *contract.TrimOrder) { o.Episode = "00000000-0000-0000-0000-000000000000" }, false},
		{"round 0", func(o *contract.TrimOrder) { o.Round = 0 }, false},
		{"round 4", func(o *contract.TrimOrder) { o.Round = 4 }, false},
		{"valid_until 6 hours after issued_at", func(o *contract.TrimOrder) { o.ValidUntil = trimAt(6 * time.Hour) }, true},
		{"valid_until over 6 hours after issued_at", func(o *contract.TrimOrder) { o.ValidUntil = trimAt(6*time.Hour + time.Millisecond) }, false},
		{"not_before before issued_at", func(o *contract.TrimOrder) { o.NotBefore = trimAt(-time.Second) }, false},
		{"not_before at valid_until", func(o *contract.TrimOrder) { o.NotBefore = o.ValidUntil }, false},
		{"no issued_at", func(o *contract.TrimOrder) { o.IssuedAt = contract.Time{} }, false},
		{"a floor a day off", func(o *contract.TrimOrder) { o.Floor = ptr("2026-10-03") }, false},
		{"a floor not a date", func(o *contract.TrimOrder) { o.Floor = ptr("2026-10-02T00:00:00Z") }, false},
		{"a floor of another day of issue", func(o *contract.TrimOrder) {
			o.IssuedAt, o.NotBefore, o.Basis.MeasuredAt = trimAt(15*time.Hour), trimAt(15*time.Hour), trimAt(14*time.Hour+30*time.Minute)
			o.ValidUntil = trimAt(18 * time.Hour)
		}, false},
		{"no floor with a keep_bytes above 0", func(o *contract.TrimOrder) { o.Floor = nil }, false},
		{"basis.usage_seq 0", func(o *contract.TrimOrder) { o.Basis.UsageSeq = 0 }, false},
		{"basis.usage_seq past 2^53 - 1", func(o *contract.TrimOrder) { o.Basis.UsageSeq = contract.MaxSafeInteger + 1 }, false},
		{"no basis.measured_at", func(o *contract.TrimOrder) { o.Basis.MeasuredAt = contract.Time{} }, false},
		{"a basis just under an hour old", func(o *contract.TrimOrder) { o.Basis.MeasuredAt = trimAt(-time.Hour + time.Millisecond) }, true},
		{"a basis an hour old", func(o *contract.TrimOrder) { o.Basis.MeasuredAt = trimAt(-time.Hour) }, false},
		{"a basis measured 60 s after issued_at", func(o *contract.TrimOrder) { o.Basis.MeasuredAt = trimAt(time.Minute) }, true},
		{"a basis measured over 60 s after issued_at", func(o *contract.TrimOrder) { o.Basis.MeasuredAt = trimAt(time.Minute + time.Millisecond) }, false},
		{"no steps", func(o *contract.TrimOrder) {
			o.Steps = []contract.TrimStep{}
			o.BasisPurge = map[string]contract.Time{}
		}, false},
		{"2000 steps", func(o *contract.TrimOrder) { o.Steps = steps(2000); o.BasisPurge = map[string]contract.Time{} }, true},
		{"2001 steps", func(o *contract.TrimOrder) { o.Steps = steps(2001); o.BasisPurge = map[string]contract.Time{} }, false},
		{"a step item twice", func(o *contract.TrimOrder) { o.Steps[1].Item = "dev_9" }, false},
		{"a step item not an id", func(o *contract.TrimOrder) { o.Steps[1].Item = "dev 7" }, false},
		{"another action", func(o *contract.TrimOrder) { o.Steps[1].Action = "trim" }, false},
		{"keep_bytes on a purge", func(o *contract.TrimOrder) { o.Steps[0].KeepBytes = ptr[int64](0) }, false},
		{"no keep_bytes on a keep", func(o *contract.TrimOrder) { o.Steps[1].KeepBytes = nil }, false},
		{"a negative keep_bytes", func(o *contract.TrimOrder) { o.Steps[1].KeepBytes = ptr[int64](-1) }, false},
		{"keep_bytes past 2^53 - 1", func(o *contract.TrimOrder) { o.Steps[1].KeepBytes = ptr[int64](contract.MaxSafeInteger + 1) }, false},
		{"basis_purge missing a purge step", func(o *contract.TrimOrder) { o.BasisPurge = map[string]contract.Time{} }, false},
		{"basis_purge null", func(o *contract.TrimOrder) { o.BasisPurge = nil }, false},
		{"basis_purge naming a keep step", func(o *contract.TrimOrder) { o.BasisPurge["dev_7"] = trimAt(0) }, false},
		{"basis_purge naming no step", func(o *contract.TrimOrder) { o.BasisPurge["dev_1"] = trimAt(0) }, false},
		{"basis_purge without its time", func(o *contract.TrimOrder) { o.BasisPurge["dev_9"] = contract.Time{} }, false},
		{"secret 0", func(o *contract.TrimOrder) { o.Secret = 0 }, false},
		{"secret 1", func(o *contract.TrimOrder) { o.Secret = 1 }, true},
		{"no mac", func(o *contract.TrimOrder) { o.MAC = "" }, false},
		{"an upper-case mac", func(o *contract.TrimOrder) { o.MAC = "v1=" + strings.Repeat("AB", 32) }, false},
		{"a mac of another version", func(o *contract.TrimOrder) { o.MAC = "v2=" + strings.Repeat("ab", 32) }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := trimOrder("wappie", c.mut)
			if err := o.Validate(); (err == nil) != c.ok {
				t.Fatalf("Validate = %v, want ok %v", err, c.ok)
			} else if err != nil && !errors.Is(err, contract.ErrInvalid) {
				t.Fatalf("%v is not ErrInvalid", err)
			}
		})
	}
}

// An order is read as an app reads what the platform sends: members it does
// not know ignored at every depth, a member counted only as exactly named,
// every member present, null only for floor, and keep_bytes never null.
func TestAnAppReadsATrimOrderAsThePlatformSendsIt(t *testing.T) {
	base, err := json.Marshal(trimOrder("wappie", nil))
	if err != nil {
		t.Fatal(err)
	}
	edit := func(old, new string) []byte {
		if !bytes.Contains(base, []byte(old)) {
			t.Fatalf("%s not in %s", old, base)
		}
		return bytes.Replace(base, []byte(old), []byte(new), 1)
	}
	for _, c := range []struct {
		name string
		raw  []byte
		ok   bool
	}{
		{"as written", base, true},
		{"a member it does not know", edit(`"round":1`, `"round":1,"note":"<&>"`), true},
		{"a member it does not know in a step", edit(`"action":"purge"`, `"action":"purge","why":"deleted"`), true},
		{"a member it does not know in basis", edit(`"usage_seq"`, `"x":[],"usage_seq"`), true},
		{"floor null", bytes.Replace(edit(`"floor":"2026-10-02"`, `"floor":null`), []byte(`"keep_bytes":14000000000`), []byte(`"keep_bytes":0`), 1), true},
		{"floor missing", edit(`"floor":"2026-10-02",`, ``), false},
		{"round null", edit(`"round":1`, `"round":null`), false},
		{"steps null", edit(`"steps":[`, `"steps":null,"x":[`), false},
		{"basis_purge null", edit(`"basis_purge":{`, `"basis_purge":null,"x":{`), false},
		{"a basis_purge time null", edit(`"dev_9":"2026-12-20T00:00:00Z"`, `"dev_9":null`), false},
		{"order_id named in another case", edit(`"order_id"`, `"Order_id"`), false},
		{"a step's item named in another case", edit(`"item":"dev_9"`, `"Item":"dev_9"`), false},
		{"a step's item null", edit(`"item":"dev_9"`, `"item":null`), false},
		{"a step's action missing", edit(`,"action":"purge"`, ``), false},
		{"keep_bytes null", edit(`"keep_bytes":14000000000`, `"keep_bytes":null`), false},
		{"keep_bytes a fraction", edit(`"keep_bytes":14000000000`, `"keep_bytes":1.5`), false},
		{"keep_bytes a string", edit(`"keep_bytes":14000000000`, `"keep_bytes":"14000000000"`), false},
		{"keep_bytes named in another case", edit(`"keep_bytes"`, `"Keep_bytes"`), false},
		{"a member twice", edit(`"round":1`, `"round":1,"round":2`), false},
		{"a member twice in a step", edit(`"action":"purge"`, `"action":"purge","action":"keep"`), false},
		{"not an object", []byte(`[]`), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var o contract.TrimOrder
			err := json.Unmarshal(c.raw, &o)
			if err == nil {
				err = o.Validate()
			}
			if (err == nil) != c.ok {
				t.Fatalf("got %v, want ok %v", err, c.ok)
			}
		})
	}
}

// The MAC is computed as the spec writes it, independently of the kit's
// own code: HMAC-SHA256 under the secret's text of the label, the app and
// the JCS text of the order without mac, secret included.
func TestATrimOrdersMACIsTheSpecs(t *testing.T) {
	signed := trimSigned(t, trimOrder("wappie", nil), SecretA)
	var v map[string]any
	dec := json.NewDecoder(bytes.NewReader(signed))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	mac, _ := v["mac"].(string)
	delete(v, "mac")
	if v["secret"] != json.Number("2") {
		t.Fatalf("secret %v", v["secret"])
	}
	canonical, err := jcs.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	h := hmac.New(sha256.New, []byte(SecretA))
	h.Write([]byte("thehappie-platform-trim/v1\nwappie\n"))
	h.Write(canonical)
	if want := "v1=" + hex.EncodeToString(h.Sum(nil)); mac != want {
		t.Fatalf("mac %s, want %s", mac, want)
	}
	if contract.TrimMACLabel != "thehappie-platform-trim/v1" {
		t.Error("label")
	}
	// The whole text is JCS: signing it again changes nothing.
	again, err := contract.SignTrimOrder(signed, "wappie", SecretA, 2)
	if err != nil || !bytes.Equal(again, signed) {
		t.Fatalf("signed again %s, %v", again, err)
	}
}

// The platform stores an order without secret and mac and sets both at
// each serve: SignTrimOrder adds or replaces them, with the generation of
// the secret that signs the answer.
func TestSignTrimOrderSetsTheSecretAndTheMAC(t *testing.T) {
	stored := []byte(`{"order_id":"` + trimOrderID + `","app":"wappie","steps":[]}`)
	signed, err := contract.SignTrimOrder(stored, "wappie", SecretB, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(signed, []byte(`"secret":3`)) || !bytes.Contains(signed, []byte(`"mac":"v1=`)) {
		t.Fatalf("signed %s", signed)
	}
	promoted, err := contract.SignTrimOrder(signed, "wappie", SecretA, 4)
	if err != nil || !bytes.Contains(promoted, []byte(`"secret":4`)) || bytes.Equal(promoted, signed) {
		t.Fatalf("promoted %s, %v", promoted, err)
	}
	for _, c := range []struct {
		name   string
		raw    []byte
		app    string
		secret string
		gen    int64
	}{
		{"a secret that is no secret", stored, "wappie", "short", 3},
		{"no app id", stored, "", SecretA, 3},
		{"another app's body", stored, "mailie", SecretA, 3},
		{"secret generation 0", stored, "wappie", SecretA, 0},
		{"secret generation past 2^53 - 1", stored, "wappie", SecretA, contract.MaxSafeInteger + 1},
		{"not an object", []byte(`[1]`), "wappie", SecretA, 3},
		{"a member twice", []byte(`{"app":"wappie","app":"wappie"}`), "wappie", SecretA, 3},
		{"a fraction", []byte(`{"app":"wappie","x":1.5}`), "wappie", SecretA, 3},
		{"a mac that is no string", []byte(`{"app":"wappie","mac":1}`), "wappie", SecretA, 3},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := contract.SignTrimOrder(c.raw, c.app, c.secret, c.gen); err == nil {
				t.Fatal("signed")
			}
		})
	}
}

// replaceMember is the JSON object raw with member name set to value,
// written as JSON text.
func replaceMember(t *testing.T, raw []byte, name, value string) []byte {
	t.Helper()
	var v map[string]json.RawMessage
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if value == "" {
		delete(v, name)
	} else {
		v[name] = json.RawMessage(value)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// upperMAC is raw with its mac's hex in upper case.
func upperMAC(t *testing.T, raw []byte) []byte {
	t.Helper()
	var v map[string]json.RawMessage
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	mac := string(v["mac"])
	return replaceMember(t, raw, "mac", `"v1=`+strings.ToUpper(mac[4:len(mac)-1])+`"`)
}

// macWith is raw re-signed by hand: its mac replaced by one under label,
// app and secret over its canonical text without mac.
func macWith(t *testing.T, raw []byte, label, app, secret string) []byte {
	t.Helper()
	var v map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	delete(v, "mac")
	canonical, err := jcs.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(label + "\n" + app + "\n"))
	h.Write(canonical)
	v["mac"] = "v1=" + hex.EncodeToString(h.Sum(nil))
	out, err := jcs.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// VerifyTrimOrder holds check 1 whole: the MAC under one of the app's
// secrets, for its own id only, over the order as received; the order's
// app, workspace and generation those of the app and of the document
// carrying it; and no order without a floor beside a plan that grants.
func TestVerifyTrimOrderHoldsCheckOne(t *testing.T) {
	good := trimSigned(t, trimOrder("wappie", nil), SecretA)
	noFloor := trimSigned(t, trimOrder("wappie", trimNoFloor), SecretA)
	held := []string{SecretB, SecretA}
	for _, c := range []struct {
		name    string
		doc     contract.EntitlementsDoc
		app     string
		secrets []string
		want    error // nil: verifies
	}{
		{"signed under the current secret", trimDoc("wappie", good, nil), "wappie", held, nil},
		{"signed under the next secret", trimDoc("wappie", good, nil), "wappie", []string{SecretA}, nil},
		{"another secret", trimDoc("wappie", good, nil), "wappie", []string{SecretB}, contract.ErrTrimMAC},
		{"no secret", trimDoc("wappie", good, nil), "wappie", nil, contract.ErrTrimMAC},
		{"an empty secret among them", trimDoc("wappie", good, nil), "wappie", []string{SecretA, ""}, contract.ErrTrimMAC},
		{"an app that is no id", trimDoc("wappie", good, nil), "", held, contract.ErrTrimMAC},
		{"a command's label", trimDoc("wappie", macWith(t, good, contract.CommandMACLabel, "wappie", SecretA), nil), "wappie", held, contract.ErrTrimMAC},
		{"another app's mac over the body", trimDoc("wappie", macWith(t, good, contract.TrimMACLabel, "mailie", SecretA), nil), "wappie", held, contract.ErrTrimMAC},
		{"mac missing", trimDoc("wappie", replaceMember(t, good, "mac", ""), nil), "wappie", held, contract.ErrTrimMAC},
		{"mac in upper-case hex", trimDoc("wappie", upperMAC(t, good), nil), "wappie", held, contract.ErrTrimMAC},
		{"a member changed after signing", trimDoc("wappie", replaceMember(t, good, "round", "2"), nil), "wappie", held, contract.ErrTrimMAC},
		{"secret changed after signing", trimDoc("wappie", replaceMember(t, good, "secret", "1"), nil), "wappie", held, contract.ErrTrimMAC},
		{"a member it does not know, signed", trimDoc("wappie", macWith(t, replaceMember(t, good, "note", `"x"`), contract.TrimMACLabel, "wappie", SecretA), nil), "wappie", held, nil},
		{"a member it does not know, added after", trimDoc("wappie", replaceMember(t, good, "note", `"x"`), nil), "wappie", held, contract.ErrTrimMAC},
		{"a member twice", trimDoc("wappie", bytes.Replace(good, []byte(`"round":1`), []byte(`"round":1,"round":1`), 1), nil), "wappie", held, contract.ErrInvalid},
		{"a member twice in a step", trimDoc("wappie", bytes.Replace(good, []byte(`"action":"purge"`), []byte(`"action":"purge","action":"purge"`), 1), nil), "wappie", held, contract.ErrInvalid},
		{"a fraction", trimDoc("wappie", replaceMember(t, good, "x", "1.5"), nil), "wappie", held, contract.ErrInvalid},
		{"an integer past 2^53 - 1", trimDoc("wappie", replaceMember(t, good, "x", "9007199254740992"), nil), "wappie", held, contract.ErrInvalid},
		{"not an object", trimDoc("wappie", nil, func(d *contract.EntitlementsDoc) { d.Trim = json.RawMessage(`[1]`) }), "wappie", held, contract.ErrInvalid},
		{"no order", trimDoc("wappie", nil, nil), "wappie", held, contract.ErrInvalid},
		{"an order of another app", trimDoc("wappie", trimSigned(t, trimOrder("mailie", nil), SecretA), nil), "wappie", held, contract.ErrInvalid},
		{"a document of another app", trimDoc("mailie", good, nil), "wappie", held, contract.ErrInvalid},
		{"another workspace than the document's", trimDoc("wappie", good, func(d *contract.EntitlementsDoc) { d.WorkspaceID = vecSub }), "wappie", held, contract.ErrInvalid},
		{"another generation than the document's", trimDoc("wappie", good, func(d *contract.EntitlementsDoc) { d.Generation = vecGeneration2 }), "wappie", held, contract.ErrInvalid},
		{"a signed order that fails Validate", trimDoc("wappie", nil, func(d *contract.EntitlementsDoc) {
			d.Trim = trimSigned(t, trimOrder("wappie", func(o *contract.TrimOrder) { o.Round = 4 }), SecretA)
		}), "wappie", held, contract.ErrInvalid},
		{"no floor without a plan", trimDoc("wappie", noFloor, trimNoPlan), "wappie", held, nil},
		{"no floor in the trial", trimDoc("wappie", noFloor, func(d *contract.EntitlementsDoc) {
			trimNoPlan(d)
			d.Plan = contract.EntitlementsPlan{Source: contract.SourceTrial, Numbers: 1, Mailboxes: 1}
			d.Places.Total = 1
			d.Places.Free = ptr[int64](0)
			d.Storage.QuotaBytes, d.Storage.AllowanceBytes = 15000000000, 13800000000
		}), "wappie", held, nil},
		{"no floor beside a plan", trimDoc("wappie", noFloor, nil), "wappie", held, contract.ErrTrimFloor},
		{"no floor beside a test plan in its 30 days", trimDoc("wappie", noFloor, func(d *contract.EntitlementsDoc) {
			d.Plan.Source, d.Plan.Test = contract.SourceLiveMove, true
		}), "wappie", held, contract.ErrTrimFloor},
	} {
		t.Run(c.name, func(t *testing.T) {
			o, err := contract.VerifyTrimOrder(c.doc, c.app, c.secrets)
			switch {
			case c.want == nil && err != nil:
				t.Fatalf("refused: %v", err)
			case c.want != nil && !errors.Is(err, c.want):
				t.Fatalf("got %v, want %v", err, c.want)
			case c.want != nil && !reflect.DeepEqual(o, contract.TrimOrder{}):
				t.Fatalf("a refused order came back: %+v", o)
			}
			if errors.Is(c.want, contract.ErrTrimFloor) && !errors.Is(err, contract.ErrInvalid) {
				t.Fatalf("%v is not ErrInvalid", err)
			}
			if errors.Is(err, contract.ErrTrimMAC) && errors.Is(err, contract.ErrInvalid) {
				t.Fatalf("%v is both", err)
			}
		})
	}
}

// The order VerifyTrimOrder returns is decoded from the bytes it verified,
// a time written .120Z and the secret's generation included, and a member
// it does not know, verified with the rest, is ignored.
func TestVerifyTrimOrderReturnsTheOrderItVerified(t *testing.T) {
	o := trimOrder("wappie", func(o *contract.TrimOrder) {
		o.Basis.MeasuredAt = contract.T(trimIssued.Add(-8*time.Minute + 120*time.Millisecond))
	})
	raw := trimSigned(t, o, SecretA)
	raw = macWith(t, replaceMember(t, raw, "note", `{"a":[1,2]}`), contract.TrimMACLabel, "wappie", SecretA)
	if !bytes.Contains(raw, []byte(`"measured_at":"2026-12-31T09:12:00.12Z"`)) {
		// json.Marshal writes the fewest digits; the spec's .120Z is
		// written by hand below.
		t.Fatalf("raw %s", raw)
	}
	raw = macWith(t, bytes.Replace(raw, []byte(`09:12:00.12Z`), []byte(`09:12:00.120Z`), 1), contract.TrimMACLabel, "wappie", SecretA)
	got, err := contract.VerifyTrimOrder(trimDoc("wappie", raw, nil), "wappie", []string{SecretA})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Steps, o.Steps) || got.Basis != o.Basis || got.Secret != 2 || got.OrderID != o.OrderID {
		t.Fatalf("%+v", got)
	}
	// The same text as written differently (.12Z) is another order: its MAC
	// does not hold.
	other := bytes.Replace(raw, []byte(`09:12:00.120Z`), []byte(`09:12:00.12Z`), 1)
	if _, err := contract.VerifyTrimOrder(trimDoc("wappie", other, nil), "wappie", []string{SecretA}); !errors.Is(err, contract.ErrTrimMAC) {
		t.Fatalf("got %v", err)
	}
}

// A document carries only an order that validates, of its app, workspace
// and generation; an order without a floor beside a plan is no fault of
// the document, whose switches still apply, and VerifyTrimOrder alone
// refuses it.
func TestADocumentsTrimOrderValidates(t *testing.T) {
	for _, c := range []struct {
		name string
		doc  contract.EntitlementsDoc
		ok   bool
	}{
		{"a valid order", trimDoc("wappie", trimSigned(t, trimOrder("wappie", nil), SecretA), nil), true},
		{"an order without a floor beside a plan", trimDoc("wappie", trimSigned(t, trimOrder("wappie", trimNoFloor), SecretA), nil), true},
		{"an order whose mac does not hold", trimDoc("wappie", replaceMember(t, trimSigned(t, trimOrder("wappie", nil), SecretA), "mac", `"v1=`+strings.Repeat("0", 64)+`"`), nil), true},
		{"an order of round 4", trimDoc("wappie", trimSigned(t, trimOrder("wappie", func(o *contract.TrimOrder) { o.Round = 4 }), SecretA), nil), false},
		{"an order with keep_bytes on a purge", trimDoc("wappie", trimSigned(t, trimOrder("wappie", func(o *contract.TrimOrder) {
			o.Steps[0].KeepBytes = ptr[int64](0)
		}), SecretA), nil), false},
		{"an order missing its floor", trimDoc("wappie", replaceMember(t, trimSigned(t, trimOrder("wappie", nil), SecretA), "floor", ""), nil), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := c.doc.Validate(); (err == nil) != c.ok {
				t.Fatalf("Validate = %v, want ok %v", err, c.ok)
			}
		})
	}
}

func trimResult(mut func(*contract.TrimResult)) contract.TrimResult {
	r := contract.TrimResult{
		OrderID: trimOrderID, Outcome: contract.TrimOutcomePartial,
		Steps: []contract.TrimStepResult{
			{Item: "dev_9", Outcome: contract.TrimOutcomeDone, BytesAfter: ptr[int64](0)},
			{Item: "dev_7", Outcome: contract.TrimOutcomePartial, BytesAfter: ptr[int64](15200000000)},
		},
		UsageSeq: ptr[int64](1798709100000),
	}
	if mut != nil {
		mut(&r)
	}
	return r
}

func trimRefused(code string) func(*contract.TrimResult) {
	return func(r *contract.TrimResult) {
		r.Outcome, r.Code, r.Steps, r.UsageSeq = contract.TrimOutcomeRefused, ptr(code), []contract.TrimStepResult{}, nil
	}
}

func TestATrimResultValidatesEachRow(t *testing.T) {
	stopped := func(code string, outcomes ...string) func(*contract.TrimResult) {
		return func(r *contract.TrimResult) {
			r.Code = ptr(code)
			for i, o := range outcomes {
				r.Steps[i].Outcome = o
				if o == contract.TrimOutcomeNotRun {
					r.Steps[i].BytesAfter = nil
				}
			}
		}
	}
	allDone := func(r *contract.TrimResult) {
		r.Outcome = contract.TrimOutcomeDone
		r.Steps[1].Outcome, r.Steps[1].BytesAfter = contract.TrimOutcomeDone, ptr[int64](14000000000)
	}
	for _, c := range []struct {
		name string
		mut  func(*contract.TrimResult)
		ok   bool
	}{
		{"the spec's: partial at the floor", nil, true},
		{"done", allDone, true},
		{"done with a code", func(r *contract.TrimResult) { allDone(r); r.Code = ptr(contract.TrimCodeExpired) }, false},
		{"done with a partial step", func(r *contract.TrimResult) { r.Outcome = contract.TrimOutcomeDone }, false},
		{"done with a refused step", func(r *contract.TrimResult) {
			allDone(r)
			r.Steps[1] = contract.TrimStepResult{Item: "dev_7", Outcome: contract.TrimOutcomeRefused, Code: ptr(contract.TrimCodeItemChanged)}
		}, false},
		{"partial with a step refused item_changed", func(r *contract.TrimResult) {
			r.Steps[1] = contract.TrimStepResult{Item: "dev_7", Outcome: contract.TrimOutcomeRefused, Code: ptr(contract.TrimCodeItemChanged)}
		}, true},
		{"partial whose every step is done", func(r *contract.TrimResult) { allDone(r); r.Outcome = contract.TrimOutcomePartial }, false},
		{"another outcome", func(r *contract.TrimResult) { r.Outcome = "ran" }, false},
		{"order_id", func(r *contract.TrimResult) { r.OrderID = "x" }, false},
		{"usage_seq null on partial", func(r *contract.TrimResult) { r.UsageSeq = nil }, false},
		{"usage_seq 0", func(r *contract.TrimResult) { r.UsageSeq = ptr[int64](0) }, false},
		{"steps null", func(r *contract.TrimResult) { r.Steps = nil }, false},
		{"no steps on partial", func(r *contract.TrimResult) { r.Steps = []contract.TrimStepResult{} }, false},
		{"a step twice", func(r *contract.TrimResult) { r.Steps[1].Item = "dev_9" }, false},
		{"a step's item not an id", func(r *contract.TrimResult) { r.Steps[1].Item = "" }, false},
		{"a step's other outcome", func(r *contract.TrimResult) { r.Steps[1].Outcome = "skipped" }, false},
		{"a refused step without its code", func(r *contract.TrimResult) {
			r.Steps[1] = contract.TrimStepResult{Item: "dev_7", Outcome: contract.TrimOutcomeRefused}
		}, false},
		{"a refused step with another code", func(r *contract.TrimResult) {
			r.Steps[1] = contract.TrimStepResult{Item: "dev_7", Outcome: contract.TrimOutcomeRefused, Code: ptr(contract.TrimCodeItemUnknown)}
		}, false},
		{"a refused step with bytes_after", func(r *contract.TrimResult) {
			r.Steps[1] = contract.TrimStepResult{Item: "dev_7", Outcome: contract.TrimOutcomeRefused, Code: ptr(contract.TrimCodeItemChanged), BytesAfter: ptr[int64](1)}
		}, false},
		{"a done step with a code", func(r *contract.TrimResult) { r.Steps[0].Code = ptr(contract.TrimCodeItemChanged) }, false},
		{"a done step without bytes_after", func(r *contract.TrimResult) { r.Steps[0].BytesAfter = nil }, false},
		{"a negative bytes_after", func(r *contract.TrimResult) { r.Steps[1].BytesAfter = ptr[int64](-1) }, false},
		{"bytes_after past 2^53 - 1", func(r *contract.TrimResult) { r.Steps[1].BytesAfter = ptr[int64](contract.MaxSafeInteger + 1) }, false},
		{"stopped held, the rest not_run", stopped(contract.TrimCodeHeld, contract.TrimOutcomeDone, contract.TrimOutcomeNotRun), true},
		{"stopped expired during a step", stopped(contract.TrimCodeExpired, contract.TrimOutcomeDone, contract.TrimOutcomePartial), true},
		{"stopped not_current", stopped(contract.TrimCodeNotCurrent, contract.TrimOutcomeDone, contract.TrimOutcomeNotRun), true},
		{"interrupted", stopped(contract.TrimCodeInterrupted, contract.TrimOutcomePartial, contract.TrimOutcomeNotRun), true},
		{"interrupted before any step", stopped(contract.TrimCodeInterrupted, contract.TrimOutcomeNotRun, contract.TrimOutcomeNotRun), true},
		{"stopped with a refusal's code", stopped(contract.TrimCodeUsageMoved, contract.TrimOutcomeDone, contract.TrimOutcomeNotRun), false},
		{"stopped with invalid_order", stopped(contract.TrimCodeInvalidOrder, contract.TrimOutcomeDone, contract.TrimOutcomeNotRun), false},
		{"a not_run step with bytes_after", func(r *contract.TrimResult) {
			stopped(contract.TrimCodeHeld, contract.TrimOutcomeDone, contract.TrimOutcomeNotRun)(r)
			r.Steps[1].BytesAfter = ptr[int64](1)
		}, false},
		{"a step under way, then not_run", stopped(contract.TrimCodeHeld, contract.TrimOutcomePartial, contract.TrimOutcomeNotRun), true},
		{"not_run in an order that did not stop", func(r *contract.TrimResult) {
			r.Steps[1].Outcome, r.Steps[1].BytesAfter = contract.TrimOutcomeNotRun, nil
		}, false},
		{"a step run after a not_run one", stopped(contract.TrimCodeHeld, contract.TrimOutcomeNotRun, contract.TrimOutcomeDone), false},
		{"done with a not_run step", func(r *contract.TrimResult) {
			allDone(r)
			r.Steps[1].Outcome, r.Steps[1].BytesAfter = contract.TrimOutcomeNotRun, nil
		}, false},
		{"refused not_current", trimRefused(contract.TrimCodeNotCurrent), true},
		{"refused expired", trimRefused(contract.TrimCodeExpired), true},
		{"refused usage_moved", trimRefused(contract.TrimCodeUsageMoved), true},
		{"refused item_unknown", trimRefused(contract.TrimCodeItemUnknown), true},
		{"refused invalid_order", trimRefused(contract.TrimCodeInvalidOrder), true},
		{"refused held", trimRefused(contract.TrimCodeHeld), true},
		{"refused interrupted", trimRefused(contract.TrimCodeInterrupted), false},
		{"refused item_changed", trimRefused(contract.TrimCodeItemChanged), false},
		{"refused without a code", func(r *contract.TrimResult) { trimRefused("")(r); r.Code = nil }, false},
		{"refused with steps", func(r *contract.TrimResult) {
			steps := r.Steps
			trimRefused(contract.TrimCodeHeld)(r)
			r.Steps = steps
		}, false},
		{"refused with steps null", func(r *contract.TrimResult) { trimRefused(contract.TrimCodeHeld)(r); r.Steps = nil }, false},
		{"refused with a usage_seq", func(r *contract.TrimResult) {
			trimRefused(contract.TrimCodeHeld)(r)
			r.UsageSeq = ptr[int64](1)
		}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := trimResult(c.mut)
			if err := r.Validate(); (err == nil) != c.ok {
				t.Fatalf("Validate = %v, want ok %v", err, c.ok)
			} else if err != nil && !errors.Is(err, contract.ErrInvalid) {
				t.Fatalf("%v is not ErrInvalid", err)
			}
		})
	}
}

func TestATrimResultIsValidatedForItsOrder(t *testing.T) {
	o := trimOrder("wappie", nil)
	for _, c := range []struct {
		name string
		mut  func(*contract.TrimResult)
		ok   bool
	}{
		{"the order's steps", nil, true},
		{"refused", trimRefused(contract.TrimCodeUsageMoved), true},
		{"another order", func(r *contract.TrimResult) { r.OrderID = "0199c3a0-0000-7000-8000-000000000002" }, false},
		{"refused, another order", func(r *contract.TrimResult) {
			trimRefused(contract.TrimCodeHeld)(r)
			r.OrderID = "0199c3a0-0000-7000-8000-000000000002"
		}, false},
		{"the steps in another order", func(r *contract.TrimResult) { r.Steps[0], r.Steps[1] = r.Steps[1], r.Steps[0] }, false},
		{"a step left out", func(r *contract.TrimResult) { r.Steps = r.Steps[1:] }, false},
		{"a step added", func(r *contract.TrimResult) {
			r.Steps = append(r.Steps, contract.TrimStepResult{Item: "dev_1", Outcome: contract.TrimOutcomeDone, BytesAfter: ptr[int64](0)})
		}, false},
		{"a purge done above 0 bytes", func(r *contract.TrimResult) { r.Steps[0].BytesAfter = ptr[int64](1) }, false},
		{"a purge under way when the order stopped", func(r *contract.TrimResult) {
			r.Code = ptr(contract.TrimCodeExpired)
			r.Steps[0] = contract.TrimStepResult{Item: "dev_9", Outcome: contract.TrimOutcomePartial, BytesAfter: ptr[int64](7)}
			r.Steps[1] = contract.TrimStepResult{Item: "dev_7", Outcome: contract.TrimOutcomeNotRun}
		}, true},
		{"one that does not validate", func(r *contract.TrimResult) { r.UsageSeq = nil }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := trimResult(c.mut).ValidateFor(o); (err == nil) != c.ok {
				t.Fatalf("ValidateFor = %v, want ok %v", err, c.ok)
			}
		})
	}
}

// The platform reads a result strictly, as it reads what an app sends.
func TestThePlatformReadsATrimResultStrictly(t *testing.T) {
	base, err := json.Marshal(trimResult(nil))
	if err != nil {
		t.Fatal(err)
	}
	refused, err := json.Marshal(trimResult(trimRefused(contract.TrimCodeHeld)))
	if err != nil {
		t.Fatal(err)
	}
	if string(refused) != `{"order_id":"`+trimOrderID+`","outcome":"refused","code":"held","steps":[],"usage_seq":null}` {
		t.Fatalf("refused %s", refused)
	}
	for _, c := range []struct {
		name string
		raw  string
		ok   bool
	}{
		{"as written", string(base), true},
		{"refused as written", string(refused), true},
		{"a member it does not know", strings.Replace(string(base), `"outcome"`, `"x":1,"outcome"`, 1), false},
		{"code missing", strings.Replace(string(base), `"code":null,`, ``, 1), false},
		{"usage_seq missing on refused", strings.Replace(string(refused), `,"usage_seq":null`, ``, 1), false},
		{"steps null on refused", strings.Replace(string(refused), `"steps":[]`, `"steps":null`, 1), false},
		{"bytes_after missing", strings.Replace(string(base), `,"bytes_after":0`, ``, 1), false},
		{"a member named in another case", strings.Replace(string(base), `"order_id"`, `"Order_id"`, 1), false},
		{"a member twice", strings.Replace(string(base), `"outcome":"partial"`, `"outcome":"partial","outcome":"done"`, 1), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var r contract.TrimResult
			err := contract.DecodeStrict([]byte(c.raw), &r)
			if err == nil {
				err = r.Validate()
			}
			if (err == nil) != c.ok {
				t.Fatalf("got %v, want ok %v", err, c.ok)
			}
		})
	}
}

func TestATrimResultAnswerIsOneOfThree(t *testing.T) {
	for _, c := range []struct {
		name string
		raw  string
		ok   bool
	}{
		{"accepted", `{"order_id":"` + trimOrderID + `","outcome":"accepted","code":null}`, true},
		{"duplicate", `{"order_id":"` + trimOrderID + `","outcome":"duplicate","code":null}`, true},
		{"rejected invalid_request", `{"order_id":"` + trimOrderID + `","outcome":"rejected","code":"invalid_request"}`, true},
		{"rejected not_found", `{"order_id":"` + trimOrderID + `","outcome":"rejected","code":"not_found"}`, true},
		{"rejected conflict", `{"order_id":"` + trimOrderID + `","outcome":"rejected","code":"conflict"}`, true},
		{"rejected invalid_request, no UUID to echo", `{"order_id":"","outcome":"rejected","code":"invalid_request"}`, true},
		{"a member it does not know", `{"order_id":"` + trimOrderID + `","outcome":"accepted","code":null,"x":{}}`, true},
		{"rejected not_found without an id", `{"order_id":"","outcome":"rejected","code":"not_found"}`, false},
		{"accepted without an id", `{"order_id":"","outcome":"accepted","code":null}`, false},
		{"accepted with a code", `{"order_id":"` + trimOrderID + `","outcome":"accepted","code":"conflict"}`, false},
		{"rejected without a code", `{"order_id":"` + trimOrderID + `","outcome":"rejected","code":null}`, false},
		{"rejected gone", `{"order_id":"` + trimOrderID + `","outcome":"rejected","code":"gone"}`, false},
		{"another outcome", `{"order_id":"` + trimOrderID + `","outcome":"ran","code":null}`, false},
		{"an order_id that is no UUID", `{"order_id":"x","outcome":"rejected","code":"invalid_request"}`, false},
		{"code missing", `{"order_id":"` + trimOrderID + `","outcome":"accepted"}`, false},
		{"order_id null", `{"order_id":null,"outcome":"rejected","code":"invalid_request"}`, false},
		{"a member twice", `{"order_id":"` + trimOrderID + `","outcome":"accepted","outcome":"accepted","code":null}`, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var a contract.TrimResultAnswer
			err := json.Unmarshal([]byte(c.raw), &a)
			if err == nil {
				err = a.Validate()
			}
			if (err == nil) != c.ok {
				t.Fatalf("got %v, want ok %v", err, c.ok)
			}
		})
	}
}

// The closed lists come back as copies, in their order.
func TestTheTrimListsAreClosed(t *testing.T) {
	for _, c := range []struct {
		get  func() []string
		want []string
	}{
		{contract.TrimActions, []string{"purge", "keep"}},
		{contract.TrimOutcomes, []string{"done", "partial", "refused"}},
		{contract.TrimStepOutcomes, []string{"done", "partial", "refused", "not_run"}},
		{contract.TrimRefusedCodes, []string{"not_current", "expired", "usage_moved", "item_unknown", "invalid_order", "held"}},
		{contract.TrimStoppedCodes, []string{"held", "expired", "not_current", "interrupted"}},
	} {
		got := c.get()
		if !slices.Equal(got, c.want) {
			t.Errorf("%v, want %v", got, c.want)
		}
		got[0] = "x"
		if c.get()[0] == "x" {
			t.Error("not a copy")
		}
	}
}
