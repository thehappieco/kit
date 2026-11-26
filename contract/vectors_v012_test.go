package contract_test

// The runners of kit v0.12.0's nine files (SPEC section 11.20): each case
// of each file, read from the embedded file, is judged again by the kit's
// code, or by the generator's model of the spec where the behaviour is an
// app's, and must come out as the file records it.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/thehappieco/kit/contract"
)

// header checks a file's format, version and kind.
func header(t *testing.T, name, format string, version int, kind, want string) {
	t.Helper()
	if format != Format || version != 1 || kind != want {
		t.Fatalf("%s: header %q %d %q", name, format, version, kind)
	}
}

// bothWays fails unless some case of a list is valid and some is not.
func bothWays(t *testing.T, what string, valid []bool) {
	t.Helper()
	if !slices.Contains(valid, true) || !slices.Contains(valid, false) {
		t.Errorf("%s: want valid and invalid cases", what)
	}
}

func TestEveryWireV012VectorHolds(t *testing.T) {
	var f WireV012
	read(t, "wire-v012.json", &f)
	header(t, "wire-v012.json", f.Format, f.Version, f.Kind, "wire-v012")
	var valid []bool
	for _, c := range f.Snapshots {
		if snapshotValid(caseValue(c)) != c.Valid {
			t.Errorf("snapshot %q: valid should be %v", c.Name, c.Valid)
		}
		valid = append(valid, c.Valid)
	}
	bothWays(t, "snapshots", valid)
	valid = nil
	for _, c := range f.Sections {
		if sectionValid(caseValue(c)) != c.Valid {
			t.Errorf("section %q: valid should be %v", c.Name, c.Valid)
		}
		valid = append(valid, c.Valid)
	}
	bothWays(t, "sections", valid)
	refused := map[string]bool{}
	for _, c := range f.Results {
		if resultValid(c.App, c.Kind, c.Value) != c.Valid {
			t.Errorf("result %q: valid should be %v", c.Name, c.Valid)
		}
		if c.Valid && c.App == "mailie" {
			var r contract.CommandResult
			if err := contract.DecodeStrict(c.Value, &r); err != nil {
				t.Fatal(err)
			}
			refused[c.Kind+" "+*r.Code] = true
		}
	}
	for _, want := range []string{
		contract.OpItemSyncNow + " " + contract.CodeCapacityReached, contract.OpItemSyncResume + " " + contract.CodeCapacityReached,
		contract.OpItemSyncNow + " " + contract.CodeStoragePaused,
	} {
		if !refused[want] {
			t.Errorf("no valid Mailie result refuses %s", want)
		}
	}
	// A valid section with the three members reads back to them, and
	// writes back as it came.
	for _, c := range f.Sections {
		if !c.Valid {
			continue
		}
		var d contract.SettingsDoc
		if err := contract.DecodeStrict(caseValue(c), &d); err != nil {
			t.Fatal(err)
		}
		var s contract.EmailAccountsSettings
		if err := contract.DecodeStrict(d.Data, &s); err != nil {
			t.Fatal(err)
		}
		has := bytes.Contains(caseValue(c), []byte(`"places_free"`))
		if (s.Linking != nil) != has {
			t.Errorf("section %q: Linking %v, the members present %v", c.Name, s.Linking, has)
		}
		again, err := json.Marshal(s)
		var compact bytes.Buffer
		if err != nil || json.Compact(&compact, caseValue(c)) != nil || !bytes.Contains(compact.Bytes(), again) {
			t.Errorf("section %q: its data writes back as %s", c.Name, again)
		}
	}
}

func TestEveryEventCodesVectorHolds(t *testing.T) {
	var f WireEventsCodes
	read(t, "wire-events-codes.json", &f)
	header(t, "wire-events-codes.json", f.Format, f.Version, f.Kind, "wire-events-codes")
	types := map[string]bool{}
	var valid []bool
	for _, c := range f.Events {
		if eventValid(caseValue(c)) != c.Valid {
			t.Errorf("event %q: valid should be %v", c.Name, c.Valid)
		}
		valid = append(valid, c.Valid)
		if !c.Valid {
			continue
		}
		var e contract.Event
		if err := contract.DecodeStrict(caseValue(c), &e); err != nil {
			t.Fatal(err)
		}
		types[e.Type] = true
		// The codes never leave in a log line or a printed event.
		for _, code := range e.Codes {
			if bytes.Contains([]byte(e.String()+fmt.Sprintf("%#v", e)), []byte(code)) {
				t.Errorf("event %q prints a code", c.Name)
			}
		}
	}
	bothWays(t, "events", valid)
	if !types[contract.EventLinked] || !types[contract.EventIdentityUpdated] {
		t.Errorf("valid events of %v; want both types", types)
	}
}

func TestEveryLinkCheckVectorHolds(t *testing.T) {
	var f WireLinkCheck
	read(t, "wire-link-check.json", &f)
	header(t, "wire-link-check.json", f.Format, f.Version, f.Kind, "wire-link-check")
	var valid []bool
	for _, c := range f.Requests {
		if linkCheckValid(c.App, c.Value) != c.Valid {
			t.Errorf("request %q: valid should be %v", c.Name, c.Valid)
		}
		valid = append(valid, c.Valid)
	}
	bothWays(t, "requests", valid)
	valid = nil
	trials := map[string]bool{}
	for _, c := range f.Answers {
		if linkAnswerValid(caseValue(c)) != c.Valid {
			t.Errorf("answer %q: valid should be %v", c.Name, c.Valid)
		}
		valid = append(valid, c.Valid)
		var a contract.LinkCheckAnswer
		if c.Valid && json.Unmarshal(caseValue(c), &a) == nil {
			trials[a.Trial] = true
		}
	}
	bothWays(t, "answers", valid)
	for _, trial := range contract.LinkCheckTrials() {
		if !trials[trial] {
			t.Errorf("no valid answer says %s", trial)
		}
	}
}

// specCode is the spec's formula itself, not TrialCode:
// base64url-nopad(HMAC-SHA256(key, label || 0x00 || app || 0x00 || kind ||
// 0x00 || identifier)).
func specCode(key []byte, app, kind, identifier string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(contract.TrialCodeLabel + "\x00" + app + "\x00" + kind + "\x00" + identifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func TestEveryTrialCodeVectorHolds(t *testing.T) {
	var f TrialCodesFile
	read(t, "trial-codes.json", &f)
	header(t, "trial-codes.json", f.Format, f.Version, f.Kind, "trial-codes")
	if f.Label != contract.TrialCodeLabel || f.KeyHex != vecTrialKeyHex {
		t.Fatalf("label %q, key %q", f.Label, f.KeyHex)
	}
	key, err := hex.DecodeString(f.KeyHex)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, c := range f.Codes {
		kind, id, code, err := trialOf(c.TrialRef)
		if err != nil || kind != c.Kind || id != c.Identifier || code != c.Code {
			t.Errorf("code %q: %s %q %s (%v), want %s %q %s", c.Name, kind, id, code, err, c.Kind, c.Identifier, c.Code)
		}
		// Both directions: the code is the spec's formula over the file's
		// identifier, and it is a canonical code.
		if specCode(key, c.App, c.Kind, c.Identifier) != c.Code || !contract.ValidTrialCode(c.Code) {
			t.Errorf("code %q is not the spec's HMAC of its identifier", c.Name)
		}
		kinds[c.Kind] = true
	}
	for _, app := range []string{"wappie", "mailie"} {
		for _, k := range contract.TrialCodeKinds(app) {
			if !kinds[k] {
				t.Errorf("no code of kind %s", k)
			}
		}
	}
	codeOf := func(r TrialRef) string {
		_, _, code, err := trialOf(r)
		if err != nil {
			t.Fatalf("%+v: %v", r, err)
		}
		return code
	}
	for _, p := range f.Meet {
		if codeOf(p.A) != codeOf(p.B) {
			t.Errorf("meet %q: the codes differ", p.Name)
		}
	}
	for _, p := range f.Differ {
		if codeOf(p.A) == codeOf(p.B) {
			t.Errorf("differ %q: the codes meet", p.Name)
		}
	}
	for _, c := range f.NoCode {
		if _, _, _, err := trialOf(c.TrialRef); !errors.Is(err, contract.ErrNoCode) {
			t.Errorf("no_code %q: %v", c.Name, err)
		}
	}
	if len(f.Meet) == 0 || len(f.Differ) == 0 || len(f.NoCode) == 0 {
		t.Error("a list is empty")
	}
}

func TestEveryUsageVectorHolds(t *testing.T) {
	var f WireUsage
	read(t, "wire-usage.json", &f)
	header(t, "wire-usage.json", f.Format, f.Version, f.Kind, "wire-usage")
	var valid []bool
	for _, c := range f.Reports {
		if usageReportValid(c.Value, c.Now) != c.Valid {
			t.Errorf("report %q: valid should be %v", c.Name, c.Valid)
		}
		valid = append(valid, c.Valid)
		// A valid report's figures never leave in a printed or logged report.
		var u contract.Usage
		if c.Valid && contract.DecodeStrict(c.Value, &u) == nil {
			printed := u.String() + fmt.Sprintf("%#v %v", u, u.LogValue())
			if bytes.Contains([]byte(printed), []byte(strconv.FormatInt(u.TotalBytes, 10))) && u.TotalBytes > 9 {
				t.Errorf("report %q prints its total", c.Name)
			}
		}
	}
	bothWays(t, "reports", valid)
	kept := map[bool]bool{}
	for _, c := range f.Intake {
		if !usageReportValid(c.Value, f.Reports[0].Now) {
			t.Errorf("intake %q: its report is not valid", c.Name)
		}
		if got := usageKept(c); got != c.Kept {
			t.Errorf("intake %q: kept %v, want %v", c.Name, got, c.Kept)
		}
		kept[c.Kept] = true
	}
	if !kept[true] || !kept[false] {
		t.Error("intake: want kept true and false")
	}
	valid = nil
	for _, c := range f.Answers {
		if usageAnswerValid(caseValue(c)) != c.Valid {
			t.Errorf("answer %q: valid should be %v", c.Name, c.Valid)
		}
		valid = append(valid, c.Valid)
	}
	bothWays(t, "answers", valid)
}

func TestEveryUsageDateVectorHolds(t *testing.T) {
	var f UsageDates
	read(t, "usage-dates.json", &f)
	header(t, "usage-dates.json", f.Format, f.Version, f.Kind, "usage-dates")
	for _, c := range f.Cases {
		measured, err := time.Parse(time.RFC3339, c.MeasuredAt)
		if err != nil {
			t.Fatal(err)
		}
		if got := contract.RecentFrom(measured).Format(time.RFC3339); got != c.RecentFrom {
			t.Errorf("dates %q: recent from %s, want %s", c.Name, got, c.RecentFrom)
		}
		items, shared, err := dateFigures(c.App, c.Rows, measured)
		if err != nil {
			t.Fatal(err)
		}
		if shared != c.SharedBytes || len(items) != len(c.Items) {
			t.Errorf("dates %q: shared %d, %d items", c.Name, shared, len(items))
		}
		for id, want := range c.Items {
			if items[id] != want {
				t.Errorf("dates %q: %s is %+v, want %+v", c.Name, id, items[id], want)
			}
		}
	}
	for _, c := range f.Floors {
		measured, err := time.Parse(time.RFC3339, c.MeasuredAt)
		if err != nil {
			t.Fatal(err)
		}
		issued, err := time.Parse(time.RFC3339, c.IssuedAt)
		if err != nil {
			t.Fatal(err)
		}
		if contract.RecentFrom(measured).Format(time.RFC3339) != c.RecentFrom || contract.TrimFloor(issued) != c.Floor {
			t.Errorf("floor %q", c.Name)
		}
		floor, _ := time.Parse(time.DateOnly, c.Floor)
		if days := int(floor.Sub(contract.RecentFrom(measured)) / (24 * time.Hour)); days != c.DaysLess || days > 1 {
			t.Errorf("floor %q keeps %d days less", c.Name, days)
		}
	}
}

func TestEveryEntitlementsVectorHolds(t *testing.T) {
	var f WireEntitlements
	read(t, "wire-entitlements.json", &f)
	header(t, "wire-entitlements.json", f.Format, f.Version, f.Kind, "wire-entitlements")
	for list, cases := range map[string][]WireCase{"documents": f.Documents, "feeds": f.Feeds, "applied": f.Applied} {
		judge := map[string]func([]byte) bool{"documents": entDocValid, "feeds": entFeedValid, "applied": entAppliedValid}[list]
		var valid []bool
		for _, c := range cases {
			if judge(caseValue(c)) != c.Valid {
				t.Errorf("%s %q: valid should be %v", list, c.Name, c.Valid)
			}
			valid = append(valid, c.Valid)
		}
		bothWays(t, list, valid)
	}
	// The cap the spec names: a quota of 15000000000 with no other report
	// kept gives Wappie a cap of 15750000000.
	found := false
	for _, c := range f.Documents {
		var d contract.EntitlementsDoc
		if c.Valid && json.Unmarshal(caseValue(c), &d) == nil && d.App == "wappie" && d.Storage.QuotaBytes == 15000000000 &&
			d.Storage.OthersBytes == 0 && d.Storage.AllowanceBytes == 15000000000 && d.Storage.CapBytes == 15750000000 {
			found = true
		}
	}
	if !found {
		t.Error("no valid document carries the quota 15000000000 and the cap 15750000000")
	}
	for _, c := range f.Actions {
		action, ref, through := entPageAction(c)
		if action != c.Action || !equalRefused(ref, c.Refused) || !equalPtr(through, c.Through) {
			t.Errorf("page %q: %s %+v %v, want %s %+v %v", c.Name, action, ref, through, c.Action, c.Refused, c.Through)
		}
	}
	for _, c := range f.Gets {
		action, fresh := entGetAction(c)
		if action != c.Action || fresh != c.Fresh {
			t.Errorf("GET %q: %s %v, want %s %v", c.Name, action, fresh, c.Action, c.Fresh)
		}
	}
	for _, s := range f.Sequences {
		steps, err := entSequence(s)
		if err != nil {
			t.Fatal(err)
		}
		for i, st := range steps {
			if st.Action != s.Steps[i].Action || !slices.Equal(st.HeldBack, s.Steps[i].HeldBack) {
				t.Errorf("sequence %q step %d: %s %v, want %s %v", s.Name, i+1, st.Action, st.HeldBack, s.Steps[i].Action, s.Steps[i].HeldBack)
			}
		}
	}
	for _, c := range f.Versions {
		if sameVersion(c.Feed, c.Get) != c.Same {
			t.Errorf("versions %q: same should be %v", c.Name, c.Same)
		}
	}
	for _, c := range f.Links {
		asks, action, logged := linkDecision(c)
		if asks != c.Asks || action != c.Action || logged != c.Logged {
			t.Errorf("link %q: %v %s %v", c.Name, asks, action, logged)
		}
	}
	for _, c := range f.Resets {
		after := entReset(c.Before, c.Generation)
		a, _ := json.Marshal(after)
		b, _ := json.Marshal(c.After)
		if !bytes.Equal(a, b) {
			t.Errorf("reset %q: %s, want %s", c.Name, a, b)
		}
	}
	for _, c := range f.Freeze {
		stops, action, err := freezeAction(c)
		if err != nil || action != c.Action || !equalPtr(stops, c.StopsAt) {
			t.Errorf("freeze %q: %v %s %v", c.Name, stops, action, err)
		}
	}
	for _, c := range f.Caps {
		if capBytes(c) != c.CapBytes {
			t.Errorf("cap %q: %d", c.Name, capBytes(c))
		}
	}
	for _, c := range f.CodesAfter {
		if codesAfterAction(c) != c.Action {
			t.Errorf("codes_after %q: %s", c.Name, codesAfterAction(c))
		}
	}
	for _, c := range f.Places {
		before, after := placesStopped(c.Before), placesStopped(c.After)
		if !slices.Equal(before, c.StoppedBefore) || !slices.Equal(after, c.StoppedAfter) || placesAction(before, after) != c.Action {
			t.Errorf("places %q: %v %v %s", c.Name, before, after, placesAction(before, after))
		}
		// The app's own count is never frozen: the same action either way.
		flipped := c
		flipped.Frozen = !c.Frozen
		if a, b := placesAction(placesStopped(flipped.Before), placesStopped(flipped.After)), c.Action; a != b {
			t.Errorf("places %q frozen %v: %s", c.Name, flipped.Frozen, a)
		}
	}
	for _, c := range f.TrialStops {
		if trialStopAction(c) != c.Action {
			t.Errorf("trial stop %q: %s", c.Name, trialStopAction(c))
		}
		ended, err := time.Parse(time.RFC3339, c.TrialEndedAt)
		if err != nil || trialStoppedAt(c.App, ended).Format(time.RFC3339) != c.StoppedAt {
			t.Errorf("trial stop %q: stopped at %s for an end at %s", c.Name, c.StoppedAt, c.TrialEndedAt)
		}
	}
	for _, c := range f.CapStops {
		flipped := c
		flipped.Frozen = !c.Frozen
		if capStopAction(c) != c.Action || capStopAction(flipped) != c.Action {
			t.Errorf("cap stop %q: %s, frozen %v %s", c.Name, capStopAction(c), flipped.Frozen, capStopAction(flipped))
		}
	}
	for _, c := range f.PlacedAt {
		after, action, err := placedAt(c)
		if err != nil || action != c.Action || !equalPtr(after, c.After) {
			t.Errorf("placed_at %q: %v %s %v", c.Name, after, action, err)
		}
	}
	for _, c := range f.LinkOutcomes {
		action, code, linked, logged := linkOutcome(c)
		if action != c.Action || !equalPtr(code, c.Code) || linked != c.Linked || logged != c.Logged {
			t.Errorf("link outcome %q: %s %v %v %v", c.Name, action, code, linked, logged)
		}
	}
	// A places lift and a cap resume each hold frozen and not.
	for _, frozen := range []bool{false, true} {
		places, caps := false, false
		for _, c := range f.Places {
			places = places || (c.Frozen == frozen && c.Action == "lift")
		}
		for _, c := range f.CapStops {
			caps = caps || (c.Frozen == frozen && c.Action == "lift")
		}
		if !places || !caps {
			t.Errorf("frozen %v: a places lift %v, a cap resume %v", frozen, places, caps)
		}
	}
}

func equalPtr[T comparable](a, b *T) bool {
	return (a == nil) == (b == nil) && (a == nil || *a == *b)
}

func equalRefused(a, b *contract.EntitlementsRefused) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return a == nil || (a.Seq == b.Seq && a.Code == b.Code && equalPtr(a.WorkspaceID, b.WorkspaceID))
}

func TestEveryTrimVectorHolds(t *testing.T) {
	var f WireTrim
	read(t, "wire-trim.json", &f)
	header(t, "wire-trim.json", f.Format, f.Version, f.Kind, "wire-trim")
	var valid []bool
	for _, c := range f.Orders {
		if orderValid(caseValue(c)) != c.Valid {
			t.Errorf("order %q: valid should be %v", c.Name, c.Valid)
		}
		valid = append(valid, c.Valid)
	}
	bothWays(t, "orders", valid)
	for _, c := range f.Decisions {
		action, code, steps, err := trimDecide(c)
		if err != nil || action != c.Action || !equalPtr(code, c.Code) || !slices.Equal(steps, c.Steps) {
			t.Errorf("decision %q: %s %v %v (%v), want %s %v %v", c.Name, action, code, steps, err, c.Action, c.Code, c.Steps)
		}
	}
	for _, c := range f.Runs {
		res, err := trimRun(c)
		if err != nil {
			t.Fatal(err)
		}
		var want contract.TrimResult
		if err := contract.DecodeStrict(c.Reported, &want); err != nil {
			t.Fatal(err)
		}
		var o contract.TrimOrder
		if err := json.Unmarshal(c.Order, &o); err != nil || want.ValidateFor(o) != nil {
			t.Errorf("run %q: its result is not valid for its order", c.Name)
		}
		if got := mustRaw(res); !bytes.Equal(got, mustRaw(want)) {
			t.Errorf("run %q reports %s, want %s", c.Name, got, c.Reported)
		}
	}
	valid = nil
	for _, c := range f.Results {
		if trimResultValid(c.Value, f.Order, c.ForOrder) != c.Valid {
			t.Errorf("result %q: valid should be %v", c.Name, c.Valid)
		}
		valid = append(valid, c.Valid)
	}
	bothWays(t, "results", valid)
	valid = nil
	for _, c := range f.Answers {
		if trimAnswerValid(caseValue(c)) != c.Valid {
			t.Errorf("answer %q: valid should be %v", c.Name, c.Valid)
		}
		valid = append(valid, c.Valid)
	}
	bothWays(t, "answers", valid)
}

func TestEveryTrimMACVectorHolds(t *testing.T) {
	var f TrimMACs
	read(t, "trim-macs.json", &f)
	header(t, "trim-macs.json", f.Format, f.Version, f.Kind, "trim-macs")
	if f.Label != contract.TrimMACLabel {
		t.Fatalf("label %q", f.Label)
	}
	pass, fail := 0, 0
	for _, c := range f.MACs {
		if c.JCS != "" {
			if got, err := canonicalOf([]byte(c.Order)); err != nil || got != c.JCS {
				t.Errorf("%q: the canonical text is not the file's", c.Name)
			}
			if trimMACOver([]byte(c.Secrets[0]), contract.TrimMACLabel, c.App, []byte(c.JCS)) != c.MAC {
				t.Errorf("%q: the MAC is not the file's", c.Name)
			}
		} else if c.MAC != "" || c.Valid {
			t.Errorf("%q: an order with no canonical text has no MAC, and never verifies", c.Name)
		}
		err := verifyCarried(c.App, c.PlanSource, c.Order, c.Secrets)
		if (err == nil) != c.Valid {
			t.Errorf("%q: verifies %v, want %v (%v)", c.Name, err == nil, c.Valid, err)
		}
		if errors.Is(err, contract.ErrTrimMAC) != c.MACFails {
			t.Errorf("%q: a MAC failure %v, want %v (%v)", c.Name, errors.Is(err, contract.ErrTrimMAC), c.MACFails, err)
		}
		if !c.Valid {
			fail++
			continue
		}
		pass++
		// An order that verifies was signed under one of the secrets, and
		// SignTrimOrder under that secret, with the order's own secret
		// number, writes the same mac.
		carried := must(macOf([]byte(c.Order)))
		signedBy := ""
		for _, s := range c.Secrets {
			if trimMACOver([]byte(s), contract.TrimMACLabel, c.App, []byte(c.JCS)) == carried {
				signedBy = s
			}
		}
		var o contract.TrimOrder
		if err := json.Unmarshal([]byte(c.Order), &o); err != nil {
			t.Fatal(err)
		}
		again, err := contract.SignTrimOrder([]byte(c.Order), c.App, signedBy, o.Secret)
		if err != nil || must(macOf(again)) != carried {
			t.Errorf("%q: SignTrimOrder does not write the mac it carries", c.Name)
		}
	}
	if pass == 0 || fail == 0 {
		t.Errorf("%d orders verify and %d do not; want both", pass, fail)
	}
}
