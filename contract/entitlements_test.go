package contract_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/thehappieco/kit/contract"
)

// entComputed is when the test documents were computed.
var entComputed = time.Date(2026, 12, 3, 10, 0, 0, 0, time.UTC)

func entAt(d time.Duration) *contract.Time { t := contract.T(entComputed.Add(d)); return &t }

// entDoc is a valid document of app: over its quota, with a plan, a counted
// snapshot, and one step to come.
func entDoc(app string, mut func(*contract.EntitlementsDoc)) contract.EntitlementsDoc {
	kind, _ := contract.AppItemKind(app)
	d := contract.EntitlementsDoc{
		V: contract.EntitlementsV, Type: contract.EntitlementsType, App: app, Generation: vecGeneration,
		WorkspaceID: vecTeam, Version: 57, ComputedAt: contract.T(entComputed), Mode: contract.ModeEnforce, TestMode: true,
		State: contract.EntitlementsState{
			Name: contract.WorkspaceOverQuota, Reason: ptr(contract.ReasonOverQuota), Since: *entAt(-49 * time.Hour),
			Deadline: entAt(28 * 24 * time.Hour),
		},
		Plan: contract.EntitlementsPlan{Source: contract.SourcePlan, Test: true, Numbers: 2, Mailboxes: 1, PeriodEnd: entAt(29 * 24 * time.Hour)},
		Places: contract.EntitlementsPlaces{Kind: kind, Total: 2, Used: ptr[int64](2), UsedConnected: ptr[int64](1),
			Free: ptr[int64](0), CountedAt: entAt(-2 * time.Minute)},
		Storage: contract.EntitlementsStorage{QuotaBytes: 25000000000, UsedBytes: ptr[int64](27300000000), OthersBytes: 1200000000,
			AllowanceBytes: 23800000000, CapBytes: 25050000000, MeasuredThrough: entAt(-20 * time.Minute)},
		Switches: contract.Switches{API: contract.SwitchOff, NewLinks: contract.SwitchOff, Sync: contract.SwitchOn, Send: contract.SwitchOff},
		Timeline: []contract.TimelineStep{{At: *entAt(23 * time.Hour), Off: []string{contract.SwitchSync}}},
		Items:    []contract.ItemTrial{},
		Links: contract.EntitlementsLinks{
			Plan:    "https://console.thehappie.co/workspaces/" + vecTeam + "/plan",
			Storage: "https://console.thehappie.co/workspaces/" + vecTeam + "/storage",
		},
	}
	if app == "mailie" {
		d.Places.Total = 1
		d.Places.Used, d.Places.UsedConnected = ptr[int64](1), ptr[int64](0)
		d.Storage.CapBytes = d.Storage.AllowanceBytes
	}
	if mut != nil {
		mut(&d)
	}
	return d
}

// entTrial is a valid document of a workspace on trial, with item trials.
func entTrial(mut func(*contract.EntitlementsDoc)) contract.EntitlementsDoc {
	return entDoc("wappie", func(d *contract.EntitlementsDoc) {
		d.Mode = contract.ModeObserve
		d.State = contract.EntitlementsState{Name: contract.WorkspaceTrial, Since: *entAt(-48 * time.Hour), TrialEndsAt: entAt(13 * 24 * time.Hour)}
		d.Plan = contract.EntitlementsPlan{Source: contract.SourceTrial, Numbers: 1, Mailboxes: 1}
		d.Places = contract.EntitlementsPlaces{Kind: contract.ItemNumber, Total: 1}
		d.Storage = contract.EntitlementsStorage{QuotaBytes: 15000000000, AllowanceBytes: 15000000000, CapBytes: 15750000000}
		d.Switches = contract.Switches{API: "on", NewLinks: "on", Sync: "on", Send: "on"}
		d.Timeline = []contract.TimelineStep{
			{At: *entAt(13 * 24 * time.Hour), Off: []string{contract.SwitchAPI, contract.SwitchNewLinks, contract.SwitchSend}},
			{At: *entAt(13*24*time.Hour + 72*time.Hour), Off: []string{contract.SwitchSync}},
		}
		d.Items = []contract.ItemTrial{
			{ID: "dev_1", Trial: contract.TrialRunning, TrialEndsAt: *entAt(time.Nanosecond)},
			{ID: "dev_2", Trial: contract.TrialUsedUp, TrialEndsAt: contract.T(entComputed)},
		}
		d.Requests = contract.EntitlementsRequests{UsageAfter: entAt(-time.Hour), CodesAfter: entAt(0)}
		if mut != nil {
			mut(d)
		}
	})
}

func entRaw(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// entEdit is raw with its object at path changed by edit.
func entEdit(t *testing.T, raw []byte, edit func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	return entRaw(t, m)
}

func entDecode(raw []byte) (contract.EntitlementsDoc, error) {
	var d contract.EntitlementsDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return d, err
	}
	return d, d.Validate()
}

// The spec's own example, with its ids written whole, decodes and
// validates, and the document comes back as it went.
func TestTheSpecsEntitlementsDocumentDecodesAndValidates(t *testing.T) {
	example := `{"v": 1, "type": "entitlements", "app": "wappie", "generation": "0199b1e0-0000-7000-8000-000000000001",
 "workspace_id": "01a034b7-d09c-7121-b7f8-41f210a9244a", "version": 57, "computed_at": "2026-12-03T10:00:00Z",
 "mode": "enforce", "test_mode": true,
 "state": {"name": "over_quota", "reason": "over_quota", "since": "2026-12-01T09:12:00Z",
           "deadline": "2026-12-31T09:12:00Z", "expired_since": null, "trial_ends_at": null, "buy_by": null},
 "plan": {"source": "plan", "test": true, "numbers": 2, "mailboxes": 1, "packs": 0,
          "period_end": "2027-01-01T00:00:00Z", "ends_at": null},
 "places": {"kind": "number", "total": 2, "used": 2, "used_connected": 1, "free": 0, "counted_at": "2026-12-03T09:58:00Z"},
 "storage": {"quota_bytes": 25000000000, "used_bytes": 27300000000, "others_bytes": 1200000000,
             "allowance_bytes": 23800000000, "cap_bytes": 25050000000, "measured_through": "2026-12-03T09:40:00Z"},
 "switches": {"api": "off", "new_links": "off", "sync": "on", "send": "off"},
 "timeline": [{"at": "2026-12-04T09:12:00Z", "sync": "off"}],
 "items": [],
 "requests": {"usage_after": null, "codes_after": null},
 "trim": null,
 "links": {"plan": "https://console.thehappie.co/workspaces/01a034b7-d09c-7121-b7f8-41f210a9244a/plan",
           "storage": "https://console.thehappie.co/workspaces/01a034b7-d09c-7121-b7f8-41f210a9244a/storage"}}`
	d, err := entDecode([]byte(example))
	if err != nil {
		t.Fatal(err)
	}
	if d.Trim != nil || len(d.Timeline) != 1 || !reflect.DeepEqual(d.Timeline[0].Off, []string{"sync"}) || *d.Places.Free != 0 {
		t.Fatalf("decoded %+v", d)
	}
	again, err := entDecode(entRaw(t, d))
	if err != nil || !reflect.DeepEqual(again, d) {
		t.Fatalf("round trip: %v\n%+v\n%+v", err, again, d)
	}
	if err := d.ValidateFor("wappie", vecTeam); err != nil {
		t.Error(err)
	}
	if d.ValidateFor("mailie", vecTeam) == nil || d.ValidateFor("wappie", vecSub) == nil {
		t.Error("a GET's answer for another app or workspace passes")
	}
}

// Every valid document of the three apps decodes back to itself, its
// timeline steps written with their switches in the wire's order.
func TestEntitlementsDocumentsRoundTrip(t *testing.T) {
	for name, d := range map[string]contract.EntitlementsDoc{
		"wappie": entDoc("wappie", nil), "mailie": entDoc("mailie", nil), "fakeproduct": entDoc("fakeproduct", nil),
		"trial": entTrial(nil),
		"closed": entDoc("wappie", func(d *contract.EntitlementsDoc) {
			d.State = contract.EntitlementsState{Name: contract.WorkspaceClosed, Since: *entAt(-time.Hour)}
			d.Switches = contract.Switches{API: "off", NewLinks: "off", Sync: "off", Send: "off"}
			d.Timeline = []contract.TimelineStep{}
		}),
		"expired with a trim": entDoc("wappie", func(d *contract.EntitlementsDoc) {
			d.State = contract.EntitlementsState{Name: contract.WorkspaceExpired, Reason: ptr(contract.ReasonNoPlan),
				Since: *entAt(-40 * 24 * time.Hour), ExpiredSince: entAt(-10 * 24 * time.Hour)}
			d.Trim = bytes.Replace(entTrimRefs("wappie", vecTeam, vecGeneration), []byte(`"app":"wappie"`), []byte(`"app":"wappie","note":"<&>"`), 1)
		}),
	} {
		t.Run(name, func(t *testing.T) {
			if err := d.Validate(); err != nil {
				t.Fatal(err)
			}
			raw := entRaw(t, d)
			got, err := entDecode(raw)
			if err != nil {
				t.Fatal(err)
			}
			if d.Trim != nil {
				// The order comes back whole; its text as it was
				// written (here re-escaped by json.Marshal) is what the
				// app verifies.
				if !json.Valid(got.Trim) || !bytes.Contains(got.Trim, []byte(`"order_id"`)) {
					t.Fatalf("trim %s", got.Trim)
				}
				got.Trim, d.Trim = nil, nil
			}
			if !reflect.DeepEqual(got, d) {
				t.Fatalf("\n%+v\n%+v", got, d)
			}
		})
	}
	step, _ := json.Marshal(contract.TimelineStep{At: contract.T(entComputed), Off: []string{"send", "api", "sync"}})
	if string(step) != `{"at":"2026-12-03T10:00:00Z","api":"off","sync":"off","send":"off"}` {
		t.Errorf("step %s", step)
	}
}

// The trim order's bytes are kept as they came, for its MAC.
func TestADocumentKeepsItsTrimOrderAsItCame(t *testing.T) {
	order := strings.Replace(string(entTrimRefs("wappie", vecTeam, vecGeneration)), `"app":"wappie",`, `"app" : "wappie", "x": "<&>" ,`, 1)
	raw := entEdit(t, entRaw(t, entDoc("wappie", func(d *contract.EntitlementsDoc) {
		d.State = contract.EntitlementsState{Name: contract.WorkspaceExpired, Reason: ptr(contract.ReasonNoPlan),
			Since: *entAt(-40 * 24 * time.Hour), ExpiredSince: entAt(-10 * 24 * time.Hour)}
	})), func(m map[string]any) { m["trim"] = "PLACEHOLDER" })
	raw = bytes.Replace(raw, []byte(`"PLACEHOLDER"`), []byte(order), 1)
	d, err := entDecode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(d.Trim) != order {
		t.Errorf("trim %s, want %s", d.Trim, order)
	}
}

// What an app reads of a document: members it does not know are ignored,
// a member counts only as exactly named, and one missing, or null where
// it may not be, refuses the document rather than reading as null.
func TestAnAppReadsADocumentAsThePlatformSendsIt(t *testing.T) {
	base := entRaw(t, entTrial(nil))
	nested := func(member, field string, v any) func(m map[string]any) {
		return func(m map[string]any) {
			if field == "" {
				m[member] = v
				return
			}
			o := m[member].(map[string]any)
			if v == "DELETE" {
				delete(o, field)
				return
			}
			o[field] = v
		}
	}
	for _, c := range []struct {
		name string
		edit func(m map[string]any)
		ok   bool
	}{
		{"as sent", func(map[string]any) {}, true},
		{"a member the app does not know", nested("future", "", map[string]any{"a": 1}), true},
		{"a nested member the app does not know", nested("state", "future", true), true},
		{"trim missing", func(m map[string]any) { delete(m, "trim") }, false},
		{"requests.codes_after missing", nested("requests", "codes_after", "DELETE"), false},
		{"storage.others_bytes null", nested("storage", "others_bytes", nil), false},
		{"storage.used_bytes null", nested("storage", "used_bytes", nil), true},
		{"computed_at null", nested("computed_at", "", nil), false},
		{"test_mode null", nested("test_mode", "", nil), false},
		{"timeline null", nested("timeline", "", nil), false},
		{"items null", nested("items", "", nil), false},
		{"a timeline step null", nested("timeline", "", []any{nil}), false},
		{"App in place of app", func(m map[string]any) { m["App"] = m["app"]; delete(m, "app") }, false},
		{"an item's trial_ends_at null", func(m map[string]any) {
			m["items"].([]any)[0].(map[string]any)["trial_ends_at"] = nil
		}, false},
		{"a step naming an unknown switch", nested("timeline", "", []any{map[string]any{"at": "2026-12-04T00:00:00Z", "mcp": "off"}}), false},
		{"a step turning a switch on", nested("timeline", "", []any{map[string]any{"at": "2026-12-04T00:00:00Z", "sync": "on"}}), false},
		{"a step naming no switch", nested("timeline", "", []any{map[string]any{"at": "2026-12-04T00:00:00Z"}}), false},
		{"a step with no at", nested("timeline", "", []any{map[string]any{"sync": "off"}}), false},
		{"a step's at a number", nested("timeline", "", []any{map[string]any{"at": 1, "sync": "off"}}), false},
		{"a switch null in a step", nested("timeline", "", []any{map[string]any{"at": "2026-12-04T00:00:00Z", "sync": nil}}), false},
		{"a step naming every switch", nested("timeline", "", []any{map[string]any{"at": "2026-12-04T00:00:00Z",
			"api": "off", "new_links": "off", "sync": "off", "send": "off"}}), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := entDecode(entEdit(t, base, c.edit))
			if (err == nil) != c.ok {
				t.Errorf("err %v, want ok %v", err, c.ok)
			}
			if err != nil && !errors.Is(err, contract.ErrInvalid) {
				t.Errorf("%v is not ErrInvalid", err)
			}
		})
	}
	twice := bytes.Replace(base, []byte(`"v":1,`), []byte(`"v":1,"v":1,`), 1)
	if _, err := entDecode(twice); err == nil {
		t.Error("a member twice passes")
	}
	for _, s := range []string{`null`, `[]`, `"doc"`, `{"v":1}`} {
		if _, err := entDecode([]byte(s)); err == nil {
			t.Errorf("%s passes", s)
		}
	}
}

// Validate checks every rule of a document, each against computed_at.
func TestEntitlementsValidateChecksEveryRule(t *testing.T) {
	wappie := func(mut func(*contract.EntitlementsDoc)) contract.EntitlementsDoc { return entDoc("wappie", mut) }
	trial := entTrial
	for _, c := range []struct {
		name string
		d    contract.EntitlementsDoc
		ok   bool
	}{
		{"v 2", wappie(func(d *contract.EntitlementsDoc) { d.V = 2 }), false},
		{"another type", wappie(func(d *contract.EntitlementsDoc) { d.Type = "account" }), false},
		{"an app the part does not know", wappie(func(d *contract.EntitlementsDoc) { d.App = "vaultie" }), false},
		{"an uppercase generation", wappie(func(d *contract.EntitlementsDoc) { d.Generation = strings.ToUpper(vecGeneration) }), false},
		{"a workspace that is no UUID", wappie(func(d *contract.EntitlementsDoc) { d.WorkspaceID = "tbfg" }), false},
		{"version 0", wappie(func(d *contract.EntitlementsDoc) { d.Version = 0 }), false},
		{"version 2^53 - 1", wappie(func(d *contract.EntitlementsDoc) { d.Version = contract.MaxSafeInteger }), true},
		{"version 2^53", wappie(func(d *contract.EntitlementsDoc) { d.Version = contract.MaxSafeInteger + 1 }), false},
		{"computed_at zero", wappie(func(d *contract.EntitlementsDoc) { d.ComputedAt = contract.Time{} }), false},
		{"mode observe", wappie(func(d *contract.EntitlementsDoc) { d.Mode = contract.ModeObserve }), true},
		{"another mode", wappie(func(d *contract.EntitlementsDoc) { d.Mode = "validate" }), false},

		// state
		{"an unknown state", wappie(func(d *contract.EntitlementsDoc) { d.State.Name = "paused" }), false},
		{"over_quota without a reason", wappie(func(d *contract.EntitlementsDoc) { d.State.Reason = nil }), false},
		{"over_quota for no plan", wappie(func(d *contract.EntitlementsDoc) { d.State.Reason = ptr(contract.ReasonNoPlan) }), true},
		{"an unknown reason", wappie(func(d *contract.EntitlementsDoc) { d.State.Reason = ptr("quota") }), false},
		{"over_quota with no deadline yet", wappie(func(d *contract.EntitlementsDoc) { d.State.Deadline = nil }), true},
		{"over_quota with a trial end", wappie(func(d *contract.EntitlementsDoc) { d.State.TrialEndsAt = entAt(time.Hour) }), true},
		{"over_quota with expired_since", wappie(func(d *contract.EntitlementsDoc) { d.State.ExpiredSince = entAt(-time.Hour) }), false},
		{"since zero", wappie(func(d *contract.EntitlementsDoc) { d.State.Since = contract.Time{} }), false},
		{"active with a reason", wappie(func(d *contract.EntitlementsDoc) {
			d.State = contract.EntitlementsState{Name: contract.WorkspaceActive, Reason: ptr(contract.ReasonOverQuota), Since: *entAt(-time.Hour)}
		}), false},
		{"active", wappie(func(d *contract.EntitlementsDoc) {
			d.State = contract.EntitlementsState{Name: contract.WorkspaceActive, Since: *entAt(-time.Hour)}
		}), true},
		{"active with buy_by", wappie(func(d *contract.EntitlementsDoc) {
			d.State = contract.EntitlementsState{Name: contract.WorkspaceActive, Since: *entAt(-time.Hour), BuyBy: entAt(30 * 24 * time.Hour)}
		}), true},
		{"active with a deadline", wappie(func(d *contract.EntitlementsDoc) {
			d.State = contract.EntitlementsState{Name: contract.WorkspaceActive, Since: *entAt(-time.Hour), Deadline: entAt(time.Hour)}
		}), false},
		{"active with a trial end", wappie(func(d *contract.EntitlementsDoc) {
			d.State = contract.EntitlementsState{Name: contract.WorkspaceActive, Since: *entAt(-time.Hour), TrialEndsAt: entAt(time.Hour)}
		}), false},
		{"expired", wappie(func(d *contract.EntitlementsDoc) {
			d.State = contract.EntitlementsState{Name: contract.WorkspaceExpired, Reason: ptr(contract.ReasonOverQuota),
				Since: *entAt(-40 * 24 * time.Hour), ExpiredSince: entAt(-time.Hour)}
		}), true},
		{"expired without expired_since", wappie(func(d *contract.EntitlementsDoc) {
			d.State = contract.EntitlementsState{Name: contract.WorkspaceExpired, Reason: ptr(contract.ReasonOverQuota), Since: *entAt(-time.Hour)}
		}), false},
		{"expired with a deadline", wappie(func(d *contract.EntitlementsDoc) {
			d.State = contract.EntitlementsState{Name: contract.WorkspaceExpired, Reason: ptr(contract.ReasonOverQuota),
				Since: *entAt(-40 * 24 * time.Hour), ExpiredSince: entAt(-time.Hour), Deadline: entAt(-time.Hour)}
		}), false},
		{"expired with a trial end", wappie(func(d *contract.EntitlementsDoc) {
			d.State = contract.EntitlementsState{Name: contract.WorkspaceExpired, Reason: ptr(contract.ReasonNoPlan),
				Since: *entAt(-40 * 24 * time.Hour), ExpiredSince: entAt(-time.Hour), TrialEndsAt: entAt(time.Hour)}
		}), false},
		{"trial without its end", trial(func(d *contract.EntitlementsDoc) {
			d.State.TrialEndsAt = nil
			d.Items = []contract.ItemTrial{}
			d.Requests.CodesAfter = nil
		}), false},
		{"trial with a reason", trial(func(d *contract.EntitlementsDoc) { d.State.Reason = ptr(contract.ReasonNoPlan) }), false},

		// plan
		{"an unknown source", wappie(func(d *contract.EntitlementsDoc) { d.Plan.Source = "paid" }), false},
		{"51 numbers", wappie(func(d *contract.EntitlementsDoc) { d.Plan.Numbers = 51 }), false},
		{"50 packs", wappie(func(d *contract.EntitlementsDoc) { d.Plan.Packs = 50 }), true},
		{"-1 packs", wappie(func(d *contract.EntitlementsDoc) { d.Plan.Packs = -1 }), false},
		{"a trial of 2 numbers", trial(func(d *contract.EntitlementsDoc) { d.Plan.Numbers = 2; d.Places.Total = 2 }), false},
		{"a trial with a pack", trial(func(d *contract.EntitlementsDoc) { d.Plan.Packs = 1 }), false},
		{"a test trial", trial(func(d *contract.EntitlementsDoc) { d.Plan.Test = true }), false},
		{"a trial with a period", trial(func(d *contract.EntitlementsDoc) { d.Plan.PeriodEnd = entAt(time.Hour) }), false},
		{"a trial with an end", trial(func(d *contract.EntitlementsDoc) { d.Plan.EndsAt = entAt(time.Hour) }), false},
		{"none", wappie(func(d *contract.EntitlementsDoc) {
			d.Plan = contract.EntitlementsPlan{Source: contract.SourceNone}
			d.Places = contract.EntitlementsPlaces{Kind: contract.ItemNumber, Total: 0, Used: ptr[int64](2), UsedConnected: ptr[int64](0),
				Free: ptr[int64](0), CountedAt: entAt(-time.Minute)}
		}), true},
		{"none with a number", wappie(func(d *contract.EntitlementsDoc) {
			d.Plan = contract.EntitlementsPlan{Source: contract.SourceNone, Numbers: 1}
			d.Places.Total = 1
		}), false},
		{"none with a test plan", wappie(func(d *contract.EntitlementsDoc) {
			d.Plan = contract.EntitlementsPlan{Source: contract.SourceNone, Test: true}
			d.Places.Total = 0
		}), false},
		{"live_move", wappie(func(d *contract.EntitlementsDoc) { d.Plan.Source = contract.SourceLiveMove }), true},
		{"live_move that is no test plan", wappie(func(d *contract.EntitlementsDoc) { d.Plan.Source = contract.SourceLiveMove; d.Plan.Test = false }), false},
		{"a paid plan bought live", wappie(func(d *contract.EntitlementsDoc) { d.Plan.Test = false }), true},

		// places
		{"places of Mailie's kind in Wappie", wappie(func(d *contract.EntitlementsDoc) { d.Places.Kind = contract.ItemMailbox }), false},
		{"places.total not the plan's numbers", wappie(func(d *contract.EntitlementsDoc) { d.Places.Total = 3; d.Places.Free = ptr[int64](1) }), false},
		{"Mailie's total its mailboxes", entDoc("mailie", nil), true},
		{"Mailie's total its numbers", entDoc("mailie", func(d *contract.EntitlementsDoc) { d.Places.Total = 2; d.Places.Free = ptr[int64](1) }), false},
		{"places counted as null together", wappie(func(d *contract.EntitlementsDoc) {
			d.Places.Used, d.Places.UsedConnected, d.Places.Free, d.Places.CountedAt = nil, nil, nil, nil
		}), true},
		{"used null alone", wappie(func(d *contract.EntitlementsDoc) { d.Places.Used = nil }), false},
		{"counted_at null alone", wappie(func(d *contract.EntitlementsDoc) { d.Places.CountedAt = nil }), false},
		{"free not total - used", wappie(func(d *contract.EntitlementsDoc) { d.Places.Used = ptr[int64](1) }), false},
		{"free 0 over the places", wappie(func(d *contract.EntitlementsDoc) { d.Places.Used = ptr[int64](5) }), true},
		{"free 1 with a place left", wappie(func(d *contract.EntitlementsDoc) {
			d.Places.Used, d.Places.UsedConnected, d.Places.Free = ptr[int64](1), ptr[int64](1), ptr[int64](1)
		}), true},
		{"used_connected over used", wappie(func(d *contract.EntitlementsDoc) { d.Places.UsedConnected = ptr[int64](3) }), false},
		{"used below 0", wappie(func(d *contract.EntitlementsDoc) { d.Places.Used = ptr[int64](-1) }), false},

		// storage
		{"allowance not quota - others", wappie(func(d *contract.EntitlementsDoc) { d.Storage.AllowanceBytes++ }), false},
		{"allowance 0 when others pass the quota", wappie(func(d *contract.EntitlementsDoc) {
			d.Storage.OthersBytes, d.Storage.AllowanceBytes, d.Storage.CapBytes = 30000000000, 0, 0
		}), true},
		{"others 0 and Wappie's cap from it", trial(nil), true},
		{"used_bytes null with measured_through", wappie(func(d *contract.EntitlementsDoc) { d.Storage.UsedBytes = nil }), false},
		{"measured_through null with used_bytes", wappie(func(d *contract.EntitlementsDoc) { d.Storage.MeasuredThrough = nil }), false},
		{"quota below 0", wappie(func(d *contract.EntitlementsDoc) { d.Storage.QuotaBytes = -1 }), false},
		{"a cap of 2^53", wappie(func(d *contract.EntitlementsDoc) { d.Storage.CapBytes = contract.MaxSafeInteger + 1 }), false},
		{"Wappie's cap is not checked", wappie(func(d *contract.EntitlementsDoc) { d.Storage.CapBytes = 1 }), true},
		{"Mailie's cap not its allowance", entDoc("mailie", func(d *contract.EntitlementsDoc) { d.Storage.CapBytes = 25050000000 }), false},

		// switches and timeline
		{"a switch neither on nor off", wappie(func(d *contract.EntitlementsDoc) { d.Switches.Send = "paused" }), false},
		{"a switch empty", wappie(func(d *contract.EntitlementsDoc) { d.Switches.API = "" }), false},
		{"closed with a switch on", wappie(func(d *contract.EntitlementsDoc) {
			d.State = contract.EntitlementsState{Name: contract.WorkspaceClosed, Since: *entAt(-time.Hour)}
			d.Switches = contract.Switches{API: "off", NewLinks: "off", Sync: "on", Send: "off"}
			d.Timeline = []contract.TimelineStep{}
		}), false},
		{"closed with a step", wappie(func(d *contract.EntitlementsDoc) {
			d.State = contract.EntitlementsState{Name: contract.WorkspaceClosed, Since: *entAt(-time.Hour)}
			d.Switches = contract.Switches{API: "off", NewLinks: "off", Sync: "off", Send: "off"}
		}), false},
		{"a timeline null", wappie(func(d *contract.EntitlementsDoc) { d.Timeline = nil }), false},
		{"16 steps", wappie(func(d *contract.EntitlementsDoc) { d.Timeline = entSteps(16) }), true},
		{"17 steps", wappie(func(d *contract.EntitlementsDoc) { d.Timeline = entSteps(17) }), false},
		{"a step at computed_at", wappie(func(d *contract.EntitlementsDoc) { d.Timeline[0].At = contract.T(entComputed) }), false},
		{"a step a nanosecond after computed_at", wappie(func(d *contract.EntitlementsDoc) { d.Timeline[0].At = *entAt(time.Nanosecond) }), true},
		{"steps out of order", trial(func(d *contract.EntitlementsDoc) { d.Timeline[0], d.Timeline[1] = d.Timeline[1], d.Timeline[0] }), false},
		{"two steps at one time", trial(func(d *contract.EntitlementsDoc) { d.Timeline[1].At = d.Timeline[0].At }), false},
		{"a step naming a switch twice", wappie(func(d *contract.EntitlementsDoc) { d.Timeline[0].Off = []string{"sync", "sync"} }), false},
		{"a step naming nothing", wappie(func(d *contract.EntitlementsDoc) { d.Timeline[0].Off = nil }), false},
		{"a step naming an unknown switch", wappie(func(d *contract.EntitlementsDoc) { d.Timeline[0].Off = []string{"ai"} }), false},

		// items
		{"items while no trial runs", wappie(func(d *contract.EntitlementsDoc) {
			d.Items = []contract.ItemTrial{{ID: "dev_1", Trial: contract.TrialUsedUp, TrialEndsAt: *entAt(-time.Hour)}}
		}), false},
		{"items on over_quota with a trial end", wappie(func(d *contract.EntitlementsDoc) {
			d.State.TrialEndsAt = entAt(time.Hour)
			d.Items = []contract.ItemTrial{{ID: "dev_1", Trial: contract.TrialUsedUp, TrialEndsAt: *entAt(-time.Hour)}}
		}), true},
		{"items null", trial(func(d *contract.EntitlementsDoc) { d.Items = nil }), false},
		{"an item twice", trial(func(d *contract.EntitlementsDoc) { d.Items[1].ID = d.Items[0].ID }), false},
		{"an item's id not an id", trial(func(d *contract.EntitlementsDoc) { d.Items[0].ID = "dev 1" }), false},
		{"not_needed in an entry", trial(func(d *contract.EntitlementsDoc) { d.Items[0].Trial = contract.TrialNotNeeded }), false},
		{"running at computed_at", trial(func(d *contract.EntitlementsDoc) { d.Items[0].TrialEndsAt = contract.T(entComputed) }), false},
		{"running just before computed_at", trial(func(d *contract.EntitlementsDoc) { d.Items[0].TrialEndsAt = *entAt(-time.Nanosecond) }), false},
		{"used_up just after computed_at", trial(func(d *contract.EntitlementsDoc) { d.Items[1].TrialEndsAt = *entAt(time.Nanosecond) }), false},
		{"used_up just before computed_at", trial(func(d *contract.EntitlementsDoc) { d.Items[1].TrialEndsAt = *entAt(-time.Nanosecond) }), true},
		{"1000 items", trial(func(d *contract.EntitlementsDoc) { d.Items = entItems(1000) }), true},
		{"1001 items", trial(func(d *contract.EntitlementsDoc) { d.Items = entItems(1001) }), false},

		// requests
		{"usage_after after computed_at", trial(func(d *contract.EntitlementsDoc) { d.Requests.UsageAfter = entAt(time.Nanosecond) }), false},
		{"codes_after after computed_at", trial(func(d *contract.EntitlementsDoc) { d.Requests.CodesAfter = entAt(time.Second) }), false},
		{"codes_after without a trial end", wappie(func(d *contract.EntitlementsDoc) { d.Requests.CodesAfter = entAt(-time.Hour) }), false},
		{"usage_after without a trial", wappie(func(d *contract.EntitlementsDoc) { d.Requests.UsageAfter = entAt(-time.Hour) }), true},

		// trim
		{"a trim in an observe document", entExpired(func(d *contract.EntitlementsDoc) { d.Mode = contract.ModeObserve }), false},
		{"a trim outside expired", wappie(func(d *contract.EntitlementsDoc) { d.Trim = entTrimRefs("wappie", vecTeam, vecGeneration) }), false},
		{"a trim naming another workspace", entExpired(func(d *contract.EntitlementsDoc) { d.Trim = entTrimRefs("wappie", vecSub, vecGeneration) }), false},
		{"a trim naming another generation", entExpired(func(d *contract.EntitlementsDoc) { d.Trim = entTrimRefs("wappie", vecTeam, vecGeneration2) }), false},
		{"a trim naming another app", entExpired(func(d *contract.EntitlementsDoc) { d.Trim = entTrimRefs("mailie", vecTeam, vecGeneration) }), false},
		{"a trim that is no object", entExpired(func(d *contract.EntitlementsDoc) { d.Trim = json.RawMessage(`[]`) }), false},
		{"a trim in an expired enforce document", entExpired(nil), true},
		{"no trim in an expired enforce document", entExpired(func(d *contract.EntitlementsDoc) { d.Trim = nil }), true},

		// links
		{"a link in development", wappie(func(d *contract.EntitlementsDoc) {
			d.Links.Plan = "http://console.thehappie.localhost:8290/workspaces/" + vecTeam + "/plan"
		}), true},
		{"an http link off localhost", wappie(func(d *contract.EntitlementsDoc) { d.Links.Plan = "http://console.thehappie.co/plan" }), false},
		{"a relative link", wappie(func(d *contract.EntitlementsDoc) { d.Links.Storage = "/workspaces/x/storage" }), false},
		{"a link with user information", wappie(func(d *contract.EntitlementsDoc) { d.Links.Storage = "https://me@console.thehappie.co/" }), false},
		{"a link with a fragment", wappie(func(d *contract.EntitlementsDoc) { d.Links.Storage = "https://console.thehappie.co/#x" }), false},
		{"a link on an address", wappie(func(d *contract.EntitlementsDoc) { d.Links.Storage = "https://10.0.0.1/" }), false},
		{"a javascript link", wappie(func(d *contract.EntitlementsDoc) { d.Links.Plan = "javascript:alert(1)" }), false},
		{"an empty link", wappie(func(d *contract.EntitlementsDoc) { d.Links.Plan = "" }), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.d.Validate()
			if (err == nil) != c.ok {
				t.Errorf("err %v, want ok %v", err, c.ok)
			}
			if err != nil && !errors.Is(err, contract.ErrInvalid) {
				t.Errorf("%v is not ErrInvalid", err)
			}
		})
	}
}

func entSteps(n int) []contract.TimelineStep {
	steps := make([]contract.TimelineStep, n)
	for i := range steps {
		steps[i] = contract.TimelineStep{At: *entAt(time.Duration(i+1) * time.Hour), Off: []string{contract.SwitchSync}}
	}
	return steps
}

func entItems(n int) []contract.ItemTrial {
	items := make([]contract.ItemTrial, n)
	for i := range items {
		items[i] = contract.ItemTrial{ID: fmt.Sprintf("dev_%d", i), Trial: contract.TrialRunning, TrialEndsAt: *entAt(time.Hour)}
	}
	return items
}

// entTrimRefs is a valid trim order, signed, naming app, ws and generation.
func entTrimRefs(app, ws, generation string) json.RawMessage {
	o := trimOrder(app, func(o *contract.TrimOrder) { o.WorkspaceID, o.Generation = ws, generation })
	raw, err := json.Marshal(o)
	if err != nil {
		panic(err)
	}
	if raw, err = contract.SignTrimOrder(raw, app, SecretA, 2); err != nil {
		panic(err)
	}
	return raw
}

func entExpired(mut func(*contract.EntitlementsDoc)) contract.EntitlementsDoc {
	return entDoc("wappie", func(d *contract.EntitlementsDoc) {
		d.State = contract.EntitlementsState{Name: contract.WorkspaceExpired, Reason: ptr(contract.ReasonNoPlan),
			Since: *entAt(-40 * 24 * time.Hour), ExpiredSince: entAt(-10 * 24 * time.Hour)}
		d.Trim = entTrimRefs("wappie", vecTeam, vecGeneration)
		if mut != nil {
			mut(d)
		}
	})
}

func entItem(t *testing.T, seq int64, raw []byte) contract.EntitlementsFeedItem {
	t.Helper()
	return contract.EntitlementsFeedItem{Seq: seq, Doc: raw}
}

// A page is checked alone; each document is judged alone, a bad one
// refused with its code and, when it reads, its workspace.
func TestTheEntitlementsFeedJudgesEachDocumentAlone(t *testing.T) {
	good := entDoc("wappie", nil)
	item, err := contract.NewEntitlementsFeedItem(57, good)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := contract.NewEntitlementsFeedItem(58, good); err == nil {
		t.Error("an item whose seq is not its version is made")
	}
	page := contract.EntitlementsFeed{Generation: vecGeneration, GenerationConfirmed: true, Head: 60,
		PublishedThrough: contract.T(entComputed), Items: []contract.EntitlementsFeedItem{item}, NextAfter: 60}
	if err := page.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		mut  func(*contract.EntitlementsFeed)
		ok   bool
	}{
		{"no items", func(f *contract.EntitlementsFeed) { f.Items = []contract.EntitlementsFeedItem{} }, true},
		{"items null", func(f *contract.EntitlementsFeed) { f.Items = nil }, false},
		{"a generation that is no UUID", func(f *contract.EntitlementsFeed) { f.Generation = "g" }, false},
		{"next_after past head", func(f *contract.EntitlementsFeed) { f.NextAfter = 61 }, false},
		{"head below 0", func(f *contract.EntitlementsFeed) { f.Head = -1; f.NextAfter = -1 }, false},
		{"no published_through", func(f *contract.EntitlementsFeed) { f.PublishedThrough = contract.Time{} }, false},
		{"a seq past head", func(f *contract.EntitlementsFeed) { f.Items[0].Seq = 61 }, false},
		{"a seq 0", func(f *contract.EntitlementsFeed) { f.Items[0].Seq = 0 }, false},
		{"two items of one seq", func(f *contract.EntitlementsFeed) { f.Items = append(f.Items, f.Items[0]) }, false},
		{"a bad document does not refuse its page", func(f *contract.EntitlementsFeed) { f.Items[0].Doc = json.RawMessage(`{"v":9}`) }, true},
		{"201 items", func(f *contract.EntitlementsFeed) {
			f.Head, f.NextAfter, f.Items = 300, 300, nil
			for i := range 201 {
				f.Items = append(f.Items, contract.EntitlementsFeedItem{Seq: int64(i + 1), Doc: item.Doc})
			}
		}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := page
			p.Items = append([]contract.EntitlementsFeedItem(nil), page.Items...)
			c.mut(&p)
			if err := p.Validate(); (err == nil) != c.ok {
				t.Errorf("err %v, want ok %v", err, c.ok)
			}
		})
	}

	raw := item.Doc
	edit := func(e func(m map[string]any)) []byte { return entEdit(t, raw, e) }
	ws := vecTeam
	for _, c := range []struct {
		name string
		raw  []byte
		seq  int64
		code string
		ws   *string
	}{
		{"the app's own", raw, 57, "", nil},
		{"another app's", entRaw(t, entDoc("mailie", func(d *contract.EntitlementsDoc) { d.Version = 57 })), 57, contract.RefusedAnotherApp, &ws},
		{"another app's that fails Validate", edit(func(m map[string]any) { m["app"] = "mailie"; m["v"] = 9 }), 57, contract.RefusedAnotherApp, &ws},
		{"another generation's", edit(func(m map[string]any) { m["generation"] = vecGeneration2 }), 57, contract.RefusedAnotherGeneration, &ws},
		{"a generation that is no UUID", edit(func(m map[string]any) { m["generation"] = "g" }), 57, contract.RefusedInvalidDocument, &ws},
		{"an app that is no app id", edit(func(m map[string]any) { m["app"] = "Wappie" }), 57, contract.RefusedInvalidDocument, &ws},
		{"one that fails Validate", edit(func(m map[string]any) { m["mode"] = "validate" }), 57, contract.RefusedInvalidDocument, &ws},
		{"one missing trim", edit(func(m map[string]any) { delete(m, "trim") }), 57, contract.RefusedInvalidDocument, &ws},
		{"a version not its seq", raw, 58, contract.RefusedInvalidDocument, &ws},
		{"one whose workspace does not read", edit(func(m map[string]any) { m["workspace_id"] = 7 }), 57, contract.RefusedInvalidDocument, nil},
		{"one with no workspace", edit(func(m map[string]any) { delete(m, "workspace_id") }), 57, contract.RefusedInvalidDocument, nil},
		{"not an object", []byte(`[1]`), 57, contract.RefusedInvalidDocument, nil},
		{"not JSON", []byte(`{`), 57, contract.RefusedInvalidDocument, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			d, r := entItem(t, c.seq, c.raw).Document("wappie", vecGeneration)
			if c.code == "" {
				if r != nil || !reflect.DeepEqual(d, good) {
					t.Fatalf("refused %+v, or decoded %+v", r, d)
				}
				return
			}
			if r == nil || r.Code != c.code || r.Seq != c.seq || !reflect.DeepEqual(r.WorkspaceID, c.ws) {
				t.Fatalf("refused %+v, want %s seq %d ws %v", r, c.code, c.seq, c.ws)
			}
			if !reflect.DeepEqual(d, contract.EntitlementsDoc{}) {
				t.Error("a bad document comes back with content")
			}
		})
	}
}

// An acknowledgement is read strictly, refused lists at most 20 entries at
// or below through, and absent when there is none.
func TestAnEntitlementsAcknowledgementIsReadStrictly(t *testing.T) {
	entries := func(n int) contract.EntitlementsRefusals {
		r := contract.EntitlementsRefusals{}
		for i := range n {
			r = append(r, contract.EntitlementsRefused{Seq: int64(i + 1), WorkspaceID: ptr(vecTeam), Code: contract.RefusedInvalidDocument})
		}
		return r
	}
	for _, c := range []struct {
		name string
		body string
		ok   bool
	}{
		{"through 0", `{"generation":"` + vecGeneration + `","through":0}`, true},
		{"through 57", `{"generation":"` + vecGeneration + `","through":57}`, true},
		{"through below 0", `{"generation":"` + vecGeneration + `","through":-1}`, false},
		{"through 2^53", `{"generation":"` + vecGeneration + `","through":9007199254740992}`, false},
		{"no generation", `{"through":57}`, false},
		{"Through in place of through", `{"generation":"` + vecGeneration + `","Through":57}`, false},
		{"an unknown member", `{"generation":"` + vecGeneration + `","through":57,"applied_at":"2026-12-03T10:00:00Z"}`, false},
		{"refused null", `{"generation":"` + vecGeneration + `","through":57,"refused":null}`, false},
		{"refused empty", `{"generation":"` + vecGeneration + `","through":57,"refused":[]}`, false},
		{"one refused", `{"generation":"` + vecGeneration + `","through":57,"refused":[{"seq":57,"workspace_id":"` + vecTeam + `","code":"another_app"}]}`, true},
		{"a refused workspace null", `{"generation":"` + vecGeneration + `","through":57,"refused":[{"seq":3,"workspace_id":null,"code":"invalid_document"}]}`, true},
		{"a refused workspace missing", `{"generation":"` + vecGeneration + `","through":57,"refused":[{"seq":3,"code":"invalid_document"}]}`, false},
		{"a refused seq past through", `{"generation":"` + vecGeneration + `","through":57,"refused":[{"seq":58,"workspace_id":null,"code":"invalid_document"}]}`, false},
		{"a refused seq 0", `{"generation":"` + vecGeneration + `","through":57,"refused":[{"seq":0,"workspace_id":null,"code":"invalid_document"}]}`, false},
		{"a refused seq twice", `{"generation":"` + vecGeneration + `","through":57,"refused":[{"seq":3,"workspace_id":null,"code":"invalid_document"},{"seq":3,"workspace_id":null,"code":"another_app"}]}`, false},
		{"an unknown code", `{"generation":"` + vecGeneration + `","through":57,"refused":[{"seq":3,"workspace_id":null,"code":"invalid_record"}]}`, false},
		{"a refused workspace not a UUID", `{"generation":"` + vecGeneration + `","through":57,"refused":[{"seq":3,"workspace_id":"x","code":"invalid_document"}]}`, false},
		{"20 refused", string(entRaw(t, contract.EntitlementsApplied{Generation: vecGeneration, Through: 57, Refused: entries(20)})), true},
		{"21 refused", string(entRaw(t, contract.EntitlementsApplied{Generation: vecGeneration, Through: 57, Refused: entries(21)})), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var a contract.EntitlementsApplied
			err := contract.DecodeStrict([]byte(c.body), &a)
			if err == nil {
				err = a.Validate()
			}
			if (err == nil) != c.ok {
				t.Errorf("err %v, want ok %v", err, c.ok)
			}
			if len(c.body) > contract.EntitlementsAppliedLimit {
				t.Errorf("a body of %d bytes", len(c.body))
			}
		})
	}
	if b := entRaw(t, contract.EntitlementsApplied{Generation: vecGeneration, Through: 57}); string(b) != `{"generation":"`+vecGeneration+`","through":57}` {
		t.Errorf("an acknowledgement with none refused is written %s", b)
	}
}

// The part's closed lists are copies.
func TestTheEntitlementsPartsListsAreCopies(t *testing.T) {
	for _, list := range []func() []string{
		contract.EntitlementSwitches, contract.EntitlementsRefusalCodes, contract.WorkspaceStates, contract.PlanSources,
	} {
		a := list()
		a[0] = "changed"
		if list()[0] == "changed" {
			t.Errorf("a list shares its backing array: %v", list())
		}
	}
	for app, want := range map[string]string{"wappie": contract.ItemNumber, "fakeproduct": contract.ItemNumber, "mailie": contract.ItemMailbox, "vaultie": ""} {
		if got, ok := contract.AppItemKind(app); got != want || ok != (want != "") {
			t.Errorf("%s: %q %v", app, got, ok)
		}
	}
}

// A snapshot's items take server and pending, each present only as true:
// a connected item protects nobody, and only a mailbox is pending, never
// beside server.
func TestSnapshotItemsTakeServerAndPending(t *testing.T) {
	item := func(kind, extra string, protected bool) string {
		p := `[]`
		if protected {
			p = `["` + vecSub + `"]`
		}
		return `{"v":1,"snapshot_seq":1760296812345,"items":[{"id":"it_1","kind":"` + kind + `","label":null,"hint":null,` +
			`"state":"active","reason":null,"purge_at":null,"other_backups":1,` +
			`"people":[{"sub":"` + vecSub + `","can":["read"],"reads":true,"waiting":false,"enrolled":true,"holds_key":true}],` +
			`"protected":` + p + extra + `}]}`
	}
	for _, c := range []struct {
		name string
		body string
		ok   bool
	}{
		{"neither", item("number", ``, true), true},
		{"server on a number", item("number", `,"server":true`, false), true},
		{"server on a mailbox", item("mailbox", `,"server":true`, false), true},
		{"server protecting someone", item("number", `,"server":true`, true), false},
		{"server false", item("number", `,"server":false`, false), false},
		{"server null", item("number", `,"server":null`, false), false},
		{"pending on a mailbox", item("mailbox", `,"pending":true`, true), true},
		{"pending on a number", item("number", `,"pending":true`, false), false},
		{"pending false", item("mailbox", `,"pending":false`, false), false},
		{"pending null", item("mailbox", `,"pending":null`, false), false},
		{"pending beside server", item("mailbox", `,"server":true,"pending":true`, false), false},
		{"Server in place of server", item("number", `,"Server":true`, false), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var s contract.Snapshot
			err := contract.DecodeStrict([]byte(c.body), &s)
			if err == nil {
				err = s.Validate()
			}
			if (err == nil) != c.ok {
				t.Errorf("err %v, want ok %v", err, c.ok)
			}
			if err == nil {
				if again := entRaw(t, s); !bytes.Equal(again, mustCompact(t, c.body)) {
					t.Errorf("written again as %s", again)
				}
			}
		})
	}
}

func mustCompact(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := json.Compact(&b, []byte(s)); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// Mailie's email-accounts takes storage_paused, can_link and places_free,
// all three or none; a section without them is written as before.
func TestMailiesEmailAccountsTakeTheirThreeEntitlementMembers(t *testing.T) {
	without := vecEmailAccounts(nil)
	if b := string(entRaw(t, without)); strings.Contains(b, "storage_paused") || strings.Contains(b, "can_link") || strings.Contains(b, "places_free") {
		t.Fatalf("a section without them writes %s", b)
	}
	base := entRaw(t, without)
	with := func(members string) []byte {
		return bytes.Replace(base, []byte(`"items":`), []byte(members+`"items":`), 1)
	}
	for _, c := range []struct {
		name string
		data []byte
		want *contract.MailboxLinking
		ok   bool
	}{
		{"none", base, nil, true},
		{"all three, a count", with(`"storage_paused":false,"can_link":true,"places_free":2,`), &contract.MailboxLinking{CanLink: true, PlacesFree: ptr[int64](2)}, true},
		{"all three, places_free 0", with(`"storage_paused":true,"can_link":false,"places_free":0,`), &contract.MailboxLinking{StoragePaused: true, PlacesFree: ptr[int64](0)}, true},
		{"all three, places_free null", with(`"storage_paused":false,"can_link":false,"places_free":null,`), &contract.MailboxLinking{}, true},
		{"places_free below 0", with(`"storage_paused":false,"can_link":false,"places_free":-1,`), nil, false},
		{"places_free a fraction", with(`"storage_paused":false,"can_link":false,"places_free":1.5,`), nil, false},
		{"places_free a string", with(`"storage_paused":false,"can_link":false,"places_free":"1",`), nil, false},
		{"storage_paused alone", with(`"storage_paused":false,`), nil, false},
		{"two of them", with(`"storage_paused":false,"can_link":true,`), nil, false},
		{"places_free alone", with(`"places_free":null,`), nil, false},
		{"storage_paused null", with(`"storage_paused":null,"can_link":true,"places_free":1,`), nil, false},
		{"can_link null", with(`"storage_paused":false,"can_link":null,"places_free":1,`), nil, false},
		{"CanLink in place of can_link", with(`"storage_paused":false,"CanLink":true,"places_free":1,`), nil, false},
		{"storage_paused twice", with(`"storage_paused":false,"storage_paused":true,"can_link":true,"places_free":1,`), nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			doc := sectionDoc("mailie", contract.SectionEmailAccounts, without, func(d *contract.SettingsDoc) { d.Data = c.data })
			raw := entRaw(t, doc)
			var got contract.SettingsDoc
			err := contract.DecodeStrict(raw, &got)
			if err == nil {
				err = got.Validate()
			}
			if (err == nil) != c.ok {
				t.Fatalf("err %v, want ok %v", err, c.ok)
			}
			if !c.ok {
				return
			}
			data, err := got.DecodeData()
			if err != nil {
				t.Fatal(err)
			}
			s := data.(*contract.EmailAccountsSettings)
			if !reflect.DeepEqual(s.Linking, c.want) {
				t.Errorf("linking %+v, want %+v", s.Linking, c.want)
			}
			if again := entRaw(t, s); !bytes.Equal(again, mustCompact(t, string(c.data))) {
				t.Errorf("written again as\n%s\nnot\n%s", again, c.data)
			}
		})
	}
}

// Mailie's sync now and resume answer capacity_reached, and sync now
// storage_paused, in 14.7's order; its other kinds do not.
func TestMailiesSyncRefusalsTakeTheEntitlementCodes(t *testing.T) {
	for kind, want := range map[string][]string{
		contract.OpItemSyncNow: {contract.CodePaused, contract.CodeConsentNeeded, contract.CodeNeedsReauth,
			contract.CodeStoragePaused, contract.CodeCapacityReached, contract.CodeItemBusy},
		contract.OpItemSyncResume: {contract.CodeCapacityReached, contract.CodeStateChanged, contract.CodeNotCurrentText, contract.CodeNoReader},
	} {
		k, ok := contract.CommandKindOf("mailie", kind)
		if !ok || !reflect.DeepEqual(k.Refusals, want) {
			t.Errorf("%s: %v", kind, k.Refusals)
		}
	}
	result := func(code string) contract.CommandResult {
		return contract.CommandResult{ID: vecGeneration, Outcome: contract.OutcomeRefused, Code: ptr(code), StateSeq: ptr[int64](1),
			At: contract.T(entComputed)}
	}
	for _, c := range []struct {
		kind, code string
		ok         bool
	}{
		{contract.OpItemSyncNow, contract.CodeCapacityReached, true},
		{contract.OpItemSyncNow, contract.CodeStoragePaused, true},
		{contract.OpItemSyncResume, contract.CodeCapacityReached, true},
		{contract.OpItemSyncResume, contract.CodeStoragePaused, false},
		{contract.OpItemSyncStop, contract.CodeCapacityReached, false},
		{contract.OpItemLiftHold, contract.CodeStoragePaused, false},
	} {
		if err := result(c.code).ValidateFor("mailie", c.kind); (err == nil) != c.ok {
			t.Errorf("Mailie's %s refused %s: %v, want ok %v", c.kind, c.code, err, c.ok)
		}
	}
}
