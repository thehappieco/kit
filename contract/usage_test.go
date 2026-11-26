package contract_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/thehappieco/kit/contract"
)

// usageMeasured is when the test reports were measured: the spec's
// example, whose usage_seq is its milliseconds.
var usageMeasured = time.Date(2026, 12, 3, 9, 40, 0, 0, time.UTC)

// usage is a valid report of app: the spec's two items, a live one and a
// deleted one with every part above 0.
func usage(app string, mut func(*contract.Usage)) contract.Usage {
	purge := contract.T(time.Date(2026, 12, 20, 0, 0, 0, 0, time.UTC))
	u := contract.Usage{
		V: contract.UsageV, Type: contract.UsageType, App: app, WorkspaceID: vecTeam, UsageSeq: usageMeasured.UnixMilli(),
		RuleVersion: app + "-storage/1", MeasuredAt: contract.T(usageMeasured), TotalBytes: 26100000000, SharedBytes: 300000000,
		Items: []contract.UsageItem{
			{ID: "dev_7", State: contract.StateActive, Bytes: 21000000000, RecentBytes: 2100000000, UndatedBytes: 1200000, FixedBytes: 3400000},
			{ID: "dev_9", State: contract.StateDeleted, PurgeAt: &purge, Bytes: 4800000000, RecentBytes: 310000000, FixedBytes: 900000},
		},
	}
	if app == "mailie" {
		u.RuleVersion, u.SharedBytes, u.TotalBytes = "mailie-usage/1", 0, 25800000000
		u.Items[0].UndatedBytes = 0
	}
	if mut != nil {
		mut(&u)
	}
	return u
}

// The spec's example report decodes strictly, validates, and comes back
// as it went.
func TestTheSpecsUsageReportDecodesAndValidates(t *testing.T) {
	example := `{"v": 1, "type": "usage", "app": "wappie", "workspace_id": "01a034b7-d09c-7121-b7f8-41f210a9244a", "usage_seq": 1796290800000,
 "rule_version": "wappie-storage/1", "measured_at": "2026-12-03T09:40:00Z",
 "total_bytes": 26100000000, "shared_bytes": 300000000,
 "items": [
   {"id": "dev_7", "state": "active", "purge_at": null, "bytes": 21000000000,
    "recent_bytes": 2100000000, "undated_bytes": 1200000, "fixed_bytes": 3400000},
   {"id": "dev_9", "state": "deleted", "purge_at": "2026-12-20T00:00:00Z", "bytes": 4800000000,
    "recent_bytes": 310000000, "undated_bytes": 0, "fixed_bytes": 900000}]}`
	var u contract.Usage
	if err := contract.DecodeStrict([]byte(example), &u); err != nil {
		t.Fatal(err)
	}
	if err := u.ValidateAt(usageMeasured); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(u, usage("wappie", nil)) {
		t.Fatalf("%#v", u.Items)
	}
	raw, _ := json.Marshal(u)
	var again contract.Usage
	if err := contract.DecodeStrict(raw, &again); err != nil || !reflect.DeepEqual(again, u) {
		t.Fatalf("round trip: %v", err)
	}
}

// The platform reads a report strictly: every member present, none
// unknown, none twice, purge_at present even when null, and nothing null
// but purge_at.
func TestAUsageReportIsReadStrictly(t *testing.T) {
	raw, _ := json.Marshal(usage("wappie", nil))
	for name, edit := range map[string]func(m map[string]any){
		"a member missing":     func(m map[string]any) { delete(m, "shared_bytes") },
		"an unknown member":    func(m map[string]any) { m["history"] = []int{} },
		"items null":           func(m map[string]any) { m["items"] = nil },
		"a figure null":        func(m map[string]any) { m["total_bytes"] = nil },
		"purge_at missing":     func(m map[string]any) { delete(m["items"].([]any)[0].(map[string]any), "purge_at") },
		"an item's bytes null": func(m map[string]any) { m["items"].([]any)[0].(map[string]any)["bytes"] = nil },
		"a fraction":           func(m map[string]any) { m["shared_bytes"] = 1.5 },
		"an item member in caps": func(m map[string]any) {
			it := m["items"].([]any)[0].(map[string]any)
			it["Bytes"] = it["bytes"]
			delete(it, "bytes")
		},
	} {
		b := entEdit(t, raw, edit)
		var u contract.Usage
		if err := contract.DecodeStrict(b, &u); !errors.Is(err, contract.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	twice := bytes.Replace(raw, []byte(`"v":1,`), []byte(`"v":1,"v":1,`), 1)
	var u contract.Usage
	if contract.DecodeStrict(twice, &u) == nil {
		t.Error("a member twice")
	}
}

// Validate checks every rule of a report, and ValidateAt the platform's two
// checks on its clock.
func TestUsageValidateChecksEveryRule(t *testing.T) {
	many := func(n int) []contract.UsageItem {
		items := make([]contract.UsageItem, n)
		for i := range items {
			items[i] = contract.UsageItem{ID: "dev_" + strconv.Itoa(i), State: contract.StateActive, Bytes: 1}
		}
		return items
	}
	valid := map[string]contract.Usage{
		"the example":       usage("wappie", nil),
		"mailie":            usage("mailie", nil),
		"the reference app": usage("fakeproduct", func(u *contract.Usage) { u.RuleVersion = "fakeproduct-usage/1" }),
		"an empty report": usage("mailie", func(u *contract.Usage) {
			u.Items, u.TotalBytes = []contract.UsageItem{}, 0
		}),
		"a paused item": usage("wappie", func(u *contract.Usage) { u.Items[0].State = contract.StateSyncPaused }),
		"parts that fill bytes": usage("wappie", func(u *contract.Usage) {
			u.Items[0].RecentBytes, u.Items[0].UndatedBytes, u.Items[0].FixedBytes = 20000000000, 990000000, 10000000
		}),
		"2000 items": usage("wappie", func(u *contract.Usage) { u.Items, u.SharedBytes, u.TotalBytes = many(2000), 0, 2000 }),
		"the largest total": usage("wappie", func(u *contract.Usage) {
			u.Items = []contract.UsageItem{{ID: "dev_1", State: contract.StateActive, Bytes: contract.MaxSafeInteger - 1}}
			u.SharedBytes, u.TotalBytes = 1, contract.MaxSafeInteger
		}),
		"a rule of six digits": usage("wappie", func(u *contract.Usage) { u.RuleVersion = "a/999999" }),
		"a rule of 32 letters": usage("wappie", func(u *contract.Usage) { u.RuleVersion = "a" + strings.Repeat("b-", 15) + "c/1" }),
	}
	for name, u := range valid {
		if err := u.ValidateAt(usageMeasured); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	purge := contract.T(usageMeasured.Add(24 * time.Hour))
	invalid := map[string]contract.Usage{
		"v 2":                           func() contract.Usage { u := usage("wappie", nil); u.V = 2; return u }(),
		"another type":                  usage("wappie", func(u *contract.Usage) { u.Type = "usage_report" }),
		"an app the part does not know": usage("wappie", func(u *contract.Usage) { u.App = "vaultie" }),
		"a workspace not a UUID":        usage("wappie", func(u *contract.Usage) { u.WorkspaceID = "TBFG" }),
		"usage_seq 0":                   usage("wappie", func(u *contract.Usage) { u.UsageSeq = 0 }),
		"usage_seq past 2^53 - 1":       usage("wappie", func(u *contract.Usage) { u.UsageSeq = contract.MaxSafeInteger + 1 }),
		"a rule with no version":        usage("wappie", func(u *contract.Usage) { u.RuleVersion = "wappie-storage" }),
		"a rule version 0":              usage("wappie", func(u *contract.Usage) { u.RuleVersion = "wappie-storage/0" }),
		"a rule version of 7 digits":    usage("wappie", func(u *contract.Usage) { u.RuleVersion = "wappie-storage/1000000" }),
		"a rule in capitals":            usage("wappie", func(u *contract.Usage) { u.RuleVersion = "Wappie-storage/1" }),
		"a rule of 33 letters":          usage("wappie", func(u *contract.Usage) { u.RuleVersion = strings.Repeat("a", 33) + "/1" }),
		"no measured_at":                usage("wappie", func(u *contract.Usage) { u.MeasuredAt = contract.Time{} }),
		"items nil":                     usage("wappie", func(u *contract.Usage) { u.Items, u.TotalBytes = nil, 300000000 }),
		"2001 items":                    usage("wappie", func(u *contract.Usage) { u.Items, u.SharedBytes, u.TotalBytes = many(2001), 0, 2001 }),
		"the sum one over":              usage("wappie", func(u *contract.Usage) { u.TotalBytes++ }),
		"the sum one under":             usage("wappie", func(u *contract.Usage) { u.TotalBytes-- }),
		"a total that overflows": usage("wappie", func(u *contract.Usage) {
			u.Items = []contract.UsageItem{{ID: "dev_1", State: contract.StateActive, Bytes: contract.MaxSafeInteger}}
			u.SharedBytes, u.TotalBytes = 1, contract.MaxSafeInteger+1
		}),
		"a sum past 2^53 - 1 in a valid total": usage("wappie", func(u *contract.Usage) {
			// Each figure is safe, but the items' sum is not: no wrap
			// brings it back to the total.
			u.Items = []contract.UsageItem{
				{ID: "dev_1", State: contract.StateActive, Bytes: contract.MaxSafeInteger},
				{ID: "dev_2", State: contract.StateActive, Bytes: contract.MaxSafeInteger},
			}
			u.SharedBytes, u.TotalBytes = 0, contract.MaxSafeInteger
		}),
		"a negative figure":            usage("wappie", func(u *contract.Usage) { u.Items[0].FixedBytes = -1; u.Items[0].RecentBytes += 1 }),
		"a negative shared":            usage("wappie", func(u *contract.Usage) { u.SharedBytes, u.TotalBytes = -1, 25799999999 }),
		"parts over bytes":             usage("wappie", func(u *contract.Usage) { u.Items[0].RecentBytes = 20996600001 }),
		"an id twice":                  usage("wappie", func(u *contract.Usage) { u.Items[1].ID = "dev_7" }),
		"an id not an item's":          usage("wappie", func(u *contract.Usage) { u.Items[0].ID = "dev 7" }),
		"a state of another list":      usage("wappie", func(u *contract.Usage) { u.Items[0].State = "pending" }),
		"purge_at on a live item":      usage("wappie", func(u *contract.Usage) { u.Items[0].PurgeAt = &purge }),
		"a deleted item with no purge": usage("wappie", func(u *contract.Usage) { u.Items[1].PurgeAt = nil }),
		"Mailie's shared_bytes":        usage("mailie", func(u *contract.Usage) { u.SharedBytes, u.TotalBytes = 1, u.TotalBytes+1 }),
		"Mailie's undated_bytes":       usage("mailie", func(u *contract.Usage) { u.Items[0].UndatedBytes = 1 }),
	}
	for name, u := range invalid {
		if err := u.Validate(); !errors.Is(err, contract.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		} else if strings.Contains(err.Error(), "2100000000") || strings.Contains(err.Error(), "21000000000") {
			t.Errorf("%s: the error carries a figure: %v", name, err)
		}
	}
	// The platform's clock: measured_at at most 60 s after it, usage_seq at
	// most a day ahead of it, in milliseconds.
	now := usageMeasured
	clock := map[string]struct {
		u  contract.Usage
		ok bool
	}{
		"measured_at 60 s ahead":  {usage("wappie", func(u *contract.Usage) { u.MeasuredAt = contract.T(now.Add(60 * time.Second)) }), true},
		"measured_at 61 s ahead":  {usage("wappie", func(u *contract.Usage) { u.MeasuredAt = contract.T(now.Add(61 * time.Second)) }), false},
		"measured_at a month ago": {usage("wappie", func(u *contract.Usage) { u.MeasuredAt = contract.T(now.Add(-30 * 24 * time.Hour)) }), true},
		"usage_seq a day ahead":   {usage("wappie", func(u *contract.Usage) { u.UsageSeq = now.Add(24 * time.Hour).UnixMilli() }), true},
		"usage_seq a day and 1 ms ahead": {usage("wappie", func(u *contract.Usage) {
			u.UsageSeq = now.Add(24*time.Hour).UnixMilli() + 1
		}), false},
		"usage_seq behind its measured_at": {usage("wappie", func(u *contract.Usage) { u.UsageSeq = 1 }), true},
	}
	for name, c := range clock {
		if err := c.u.Validate(); err != nil {
			t.Errorf("%s: Validate %v", name, err)
		}
		if err := c.u.ValidateAt(now); (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A report never prints a figure, in any verb or in a structured log.
func TestAUsageReportNeverPrintsAFigure(t *testing.T) {
	u := usage("wappie", nil)
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("usage", "report", u)
	for _, s := range []string{fmt.Sprint(u), fmt.Sprintf("%v %+v %#v %s", u, u, u, u), logged.String()} {
		for _, figure := range []string{"26100000000", "300000000", "21000000000", "2100000000", "1200000", "dev_7"} {
			if strings.Contains(s, figure) {
				t.Errorf("printed %s in %s", figure, s)
			}
		}
		if !strings.Contains(s, "wappie-storage/1") || !strings.Contains(s, vecTeam) {
			t.Errorf("printed %s", s)
		}
	}
	if !strings.Contains(logged.String(), `"usage_seq":1796290800000`) {
		t.Error(logged.String())
	}
}

// The answer is {"accepted": true, "kept": bool}, read as an app reads
// what the platform sends: both members by their exact names, neither null,
// and a member the app does not know ignored.
func TestAUsageAnswerIsReadAsTheAppReadsWhatThePlatformSends(t *testing.T) {
	for raw, want := range map[string]contract.UsageAnswer{
		`{"accepted": true, "kept": true}`:                  {Accepted: true, Kept: true},
		`{"kept": false, "accepted": true}`:                 {Accepted: true},
		`{"accepted": true, "kept": true, "why": "closed"}`: {Accepted: true, Kept: true},
		`{"accepted": true, "kept": false, "Kept": true}`:   {Accepted: true},
	} {
		var a contract.UsageAnswer
		if err := json.Unmarshal([]byte(raw), &a); err != nil || a != want || a.Validate() != nil {
			t.Errorf("%s: %+v %v", raw, a, err)
		}
	}
	for _, raw := range []string{
		`{"accepted": true}`, `{"accepted": true, "kept": null}`,
		`{"Accepted": true, "kept": true}`, `{"accepted": true, "Kept": true}`, `{"accepted": true, "kept": "true"}`, `{"accepted": true, "kept": true, "kept": false}`,
		`null`, `[]`,
	} {
		var a contract.UsageAnswer
		if err := json.Unmarshal([]byte(raw), &a); err == nil {
			t.Errorf("%s: read", raw)
		}
	}
	var a contract.UsageAnswer
	if err := json.Unmarshal([]byte(`{"accepted": false, "kept": true}`), &a); err != nil || a.Validate() == nil {
		t.Errorf("accepted false: %v", err)
	}
}

// Recent is a date on or after 00:00 UTC of measured_at's UTC date less 90
// days; a date after measured_at counts as measured_at; the trim's floor is
// the same day of issued_at.
func TestTheDateRuleCountsWholeUTCDays(t *testing.T) {
	measured := time.Date(2026, 12, 3, 23, 59, 59, 0, time.FixedZone("BRT", -3*3600))
	edge := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	if got := contract.RecentFrom(measured); !got.Equal(edge) || got.Location() != time.UTC {
		t.Fatalf("RecentFrom %v", got)
	}
	for _, c := range []struct {
		date time.Time
		want bool
	}{
		{edge, true},
		{edge.Add(-time.Millisecond), false},
		{time.Date(2026, 9, 4, 23, 59, 59, 999000000, time.UTC), false},
		{measured, true},
		{measured.Add(365 * 24 * time.Hour), true},
		{time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC), false},
	} {
		if got := contract.IsRecent(c.date, measured); got != c.want {
			t.Errorf("%v: %v", c.date, got)
		}
	}
	for issued, floor := range map[time.Time]string{
		time.Date(2026, 12, 31, 9, 12, 0, 0, time.UTC):                  "2026-10-02",
		time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC):                   "2026-10-02",
		time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC):                "2026-10-02",
		time.Date(2027, 1, 1, 0, 30, 0, 0, time.FixedZone("CET", 3600)): "2026-10-02",
		time.Date(2028, 5, 30, 12, 0, 0, 0, time.UTC):                   "2028-03-01",
	} {
		if got := contract.TrimFloor(issued); got != floor {
			t.Errorf("%v: %s, want %s", issued, got, floor)
		}
	}
	// An order whose day is later than its report's keeps at most one day
	// less than recent_bytes counted.
	report := time.Date(2026, 12, 30, 23, 30, 0, 0, time.UTC)
	order := report.Add(time.Hour)
	if got, err := time.Parse(time.DateOnly, contract.TrimFloor(order)); err != nil || got.Sub(contract.RecentFrom(report)) != 24*time.Hour {
		t.Errorf("the floor of a later day: %v %v", got, err)
	}
}

// The usage report's list of states is a copy.
func TestUsageStatesAreACopy(t *testing.T) {
	s := contract.UsageStates()
	if !reflect.DeepEqual(s, []string{"active", "sync_paused", "deleted"}) {
		t.Fatal(s)
	}
	s[0] = "pending"
	if contract.UsageStates()[0] != "active" {
		t.Error("not a copy")
	}
}
