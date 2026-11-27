package contract_test

// The kit's generators of wire-usage.json and usage-dates.json (kit
// v0.12.0, SPEC section 11.20): usage reports valid and invalid, the
// platform's intake answers, and the date rule both apps follow. Every
// case states the outcome the spec asks of it, and the generator fails
// rather than write a case whose outcome the code does not give.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/jcs"
)

// UsageCase is one usage report body, the platform's clock, and whether
// the platform takes it.
type UsageCase struct {
	Name  string          `json:"name"`
	Now   int64           `json:"now"`
	Value json.RawMessage `json:"value"`
	Valid bool            `json:"valid"`
}

// HeldReport is the report the platform holds for a workspace.
type HeldReport struct {
	UsageSeq int64           `json:"usage_seq"`
	Body     json.RawMessage `json:"body"`
}

// IntakeCase is one valid report the platform receives, what it holds,
// and whether its answer is kept.
type IntakeCase struct {
	Name string `json:"name"`
	// Held is the report the platform holds for the workspace, or null.
	Held *HeldReport `json:"held"`
	// Mode is the platform's: "keep" once the privacy text's "Storage
	// usage" is live, "validate" before (all of E0).
	Mode string `json:"mode"`
	// Workspace is "open", "closed_personal" or "closed_team_past" (a
	// closed team past its 30 days).
	Workspace string          `json:"workspace"`
	Value     json.RawMessage `json:"value"`
	Kept      bool            `json:"kept"`
}

// WireUsage is wire-usage.json.
type WireUsage struct {
	Format      string       `json:"format"`
	Version     int          `json:"version"`
	Kind        string       `json:"kind"`
	Description string       `json:"description"`
	Reports     []UsageCase  `json:"reports"`
	Intake      []IntakeCase `json:"intake"`
	Answers     []WireCase   `json:"answers"`
}

// usageReportValid is what the platform makes of a report at its clock
// now (Unix seconds): within 1 MiB, decoded strictly, and ValidateAt(now).
func usageReportValid(raw []byte, now int64) bool {
	var u contract.Usage
	return len(raw) <= contract.UsageReportBodyLimit && contract.DecodeStrict(raw, &u) == nil && u.ValidateAt(time.Unix(now, 0)) == nil
}

// sameJSON reports whether a and b are the same JSON value: the same JCS
// text.
func sameJSON(a, b []byte) bool {
	ca, errA := canonicalJSON(a)
	cb, errB := canonicalJSON(b)
	return errA == nil && errB == nil && bytes.Equal(ca, cb)
}

func canonicalJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return jcs.Marshal(v)
}

// usageKept is the platform's kept for a valid report (SPEC section
// 11.20): true when, after it, the platform holds a report of this
// usage_seq with this body, a retry of the held report answered as its
// first send; false while it only validates, for a closed personal
// workspace or a closed team past its 30 days, a lower usage_seq, or an
// equal one with another body.
func usageKept(c IntakeCase) bool {
	var u contract.Usage
	if contract.DecodeStrict(c.Value, &u) != nil || c.Mode != "keep" || c.Workspace != "open" {
		return false
	}
	switch {
	case c.Held == nil || u.UsageSeq > c.Held.UsageSeq:
		return true
	case u.UsageSeq == c.Held.UsageSeq:
		return sameJSON(c.Value, c.Held.Body)
	}
	return false
}

// usageAnswerValid is what an app makes of the answer: its two members by
// their exact names, each a boolean, accepted true, and members it does not
// know ignored.
func usageAnswerValid(raw []byte) bool {
	var a contract.UsageAnswer
	return json.Unmarshal(raw, &a) == nil && a.Validate() == nil
}

// vecUsage is a valid report of app, measured 20 minutes before Now: the
// spec's two items, a live one and a deleted one with every part above 0.
func vecUsage(app string, mut func(*contract.Usage)) contract.Usage {
	measured := Now.Add(-20 * time.Minute)
	purge := at(17 * 24 * time.Hour)
	u := contract.Usage{
		V: contract.UsageV, Type: contract.UsageType, App: app, WorkspaceID: vecTeam, UsageSeq: measured.UnixMilli(),
		RuleVersion: "wappie-storage/1", MeasuredAt: contract.T(measured), TotalBytes: 26100000000, SharedBytes: 300000000,
		Items: []contract.UsageItem{
			{ID: "dev_7", State: contract.StateActive, Bytes: 21000000000, RecentBytes: 2100000000, UndatedBytes: 1200000, FixedBytes: 3400000},
			{ID: "dev_9", State: contract.StateDeleted, PurgeAt: &purge, Bytes: 4800000000, RecentBytes: 310000000, UndatedBytes: 2000, FixedBytes: 900000},
		},
	}
	switch app {
	case "mailie":
		u.RuleVersion, u.SharedBytes, u.TotalBytes = "mailie-usage/1", 0, 25800000000
		u.Items[0].ID, u.Items[1].ID = "acc_7f3a", "acc_9b21"
		u.Items[0].UndatedBytes, u.Items[1].UndatedBytes = 0, 0
	case contract.ReferenceApp:
		u.RuleVersion = "fakeproduct-usage/1"
	}
	if mut != nil {
		mut(&u)
	}
	return u
}

func wireUsage() (any, error) {
	out := WireUsage{
		Format: Format, Version: 1, Kind: "wire-usage",
		Description: "The usage report (SPEC section 11.20), PUT /contract/v1/workspaces/{id}/usage. reports: a body and the platform's clock now (Unix seconds); valid: within 1 MiB, decoded strictly (every member present, none null but purge_at, none twice or unknown, names exactly as written), then ValidateAt(now): v 1, type usage, an app the part knows, a UUID workspace_id, usage_seq 1 to 2^53 - 1 and at most a day (in milliseconds) ahead of now, rule_version ^[a-z][a-z0-9-]{0,31}/[1-9][0-9]{0,5}$, measured_at at most 60 s after now, every integer 0 to 2^53 - 1, total_bytes exactly the sum of items[].bytes and shared_bytes, at most 2000 items each id once, state active, sync_paused or deleted, purge_at set exactly on deleted, recent_bytes + undated_bytes + fixed_bytes at most bytes, and in Mailie shared_bytes and every undated_bytes 0. An empty report, items [] and totals 0, is valid. intake: a valid report and what the platform holds; kept: the answer's kept, true when, after the request, the platform holds a report of this usage_seq with this body (the same JSON value; a retry of the held report is answered as its first send), false while the platform only validates (mode validate), for a closed personal workspace or a closed team past its 30 days, a lower usage_seq, or an equal one with another body. answers: the platform's 200, {\"accepted\": true, \"kept\": a boolean}, read as an app reads what the platform sends: both members present by their exact names, each a boolean, neither null, none twice, and a member the app does not know ignored.",
	}
	now := Now.Unix()
	base := mustRaw(vecUsage("wappie", nil))
	empty := mustRaw(vecUsage("wappie", func(u *contract.Usage) { u.Items, u.TotalBytes, u.SharedBytes = []contract.UsageItem{}, 0, 0 }))
	manyItems := func(n int) json.RawMessage {
		return mustRaw(vecUsage("wappie", func(u *contract.Usage) {
			u.Items = many(n, func(i int) contract.UsageItem {
				return contract.UsageItem{ID: fmt.Sprintf("dev_%d", i+1), State: contract.StateActive, Bytes: 1000, RecentBytes: 100, FixedBytes: 10}
			})
			u.SharedBytes, u.TotalBytes = 0, int64(n)*1000
		}))
	}
	item0 := func(mut func(*contract.UsageItem)) json.RawMessage {
		return mustRaw(vecUsage("wappie", func(u *contract.Usage) {
			mut(&u.Items[0])
			u.TotalBytes = u.SharedBytes + u.Items[0].Bytes + u.Items[1].Bytes
		}))
	}
	measuredAhead := func(d time.Duration) json.RawMessage {
		return mustRaw(vecUsage("wappie", func(u *contract.Usage) {
			u.MeasuredAt, u.UsageSeq = at(d), Now.Add(d).UnixMilli()
		}))
	}
	purge := at(17 * 24 * time.Hour)
	maxInt := int64(contract.MaxSafeInteger)
	for _, c := range []struct {
		name  string
		raw   json.RawMessage
		valid bool
	}{
		{"the spec's report: a live item and a deleted one with every part above 0", base, true},
		{"an empty report: items [] and totals 0", empty, true},
		{"Mailie's report", mustRaw(vecUsage("mailie", nil)), true},
		{"the reference app's report", mustRaw(vecUsage(contract.ReferenceApp, nil)), true},
		{"an item paused", item0(func(it *contract.UsageItem) { it.State = contract.StateSyncPaused }), true},
		{"an item's three parts exactly its bytes", item0(func(it *contract.UsageItem) {
			it.Bytes = it.RecentBytes + it.UndatedBytes + it.FixedBytes
		}), true},
		{"an item of 0 bytes", item0(func(it *contract.UsageItem) { it.Bytes, it.RecentBytes, it.UndatedBytes, it.FixedBytes = 0, 0, 0, 0 }), true},
		{"bytes only shared", mustRaw(vecUsage("wappie", func(u *contract.Usage) { u.Items, u.TotalBytes = []contract.UsageItem{}, u.SharedBytes })), true},
		{"a total of 2^53 - 1", mustRaw(vecUsage("wappie", func(u *contract.Usage) {
			u.Items = []contract.UsageItem{{ID: "dev_7", State: contract.StateActive, Bytes: maxInt - 1}}
			u.SharedBytes, u.TotalBytes = 1, maxInt
		})), true},
		{"2000 items, the most", manyItems(contract.MaxUsageItems), true},
		{"measured_at 60 s after the platform's clock", measuredAhead(time.Minute), true},
		{"usage_seq a day ahead of the platform's clock", mustRaw(vecUsage("wappie", func(u *contract.Usage) {
			u.UsageSeq = Now.Add(24 * time.Hour).UnixMilli()
		})), true},
		{"the sum one byte over", mustRaw(vecUsage("wappie", func(u *contract.Usage) { u.TotalBytes++ })), false},
		{"the sum one byte under", mustRaw(vecUsage("wappie", func(u *contract.Usage) { u.TotalBytes-- })), false},
		{"an overflow: two items of 2^53 - 1", mustRaw(vecUsage("wappie", func(u *contract.Usage) {
			u.Items = []contract.UsageItem{{ID: "dev_7", State: contract.StateActive, Bytes: maxInt}, {ID: "dev_8", State: contract.StateActive, Bytes: maxInt}}
			u.SharedBytes, u.TotalBytes = 0, maxInt
		})), false},
		{"a total of 2^53", mustRaw(vecUsage("wappie", func(u *contract.Usage) {
			u.Items = []contract.UsageItem{{ID: "dev_7", State: contract.StateActive, Bytes: maxInt}}
			u.SharedBytes, u.TotalBytes = 1, maxInt+1
		})), false},
		{"recent_bytes one over the item's bytes less its other parts", item0(func(it *contract.UsageItem) {
			it.RecentBytes = it.Bytes - it.UndatedBytes - it.FixedBytes + 1
		}), false},
		{"undated_bytes one over", item0(func(it *contract.UsageItem) { it.UndatedBytes = it.Bytes - it.RecentBytes - it.FixedBytes + 1 }), false},
		{"fixed_bytes one over", item0(func(it *contract.UsageItem) { it.FixedBytes = it.Bytes - it.RecentBytes - it.UndatedBytes + 1 }), false},
		{"purge_at on an active item", item0(func(it *contract.UsageItem) { it.PurgeAt = &purge }), false},
		{"purge_at on a paused item", item0(func(it *contract.UsageItem) { it.State, it.PurgeAt = contract.StateSyncPaused, &purge }), false},
		{"a deleted item with no purge_at", mustRaw(vecUsage("wappie", func(u *contract.Usage) { u.Items[1].PurgeAt = nil })), false},
		{"2001 items", manyItems(contract.MaxUsageItems + 1), false},
		{"an item id twice", mustRaw(vecUsage("wappie", func(u *contract.Usage) { u.Items[1].ID = u.Items[0].ID })), false},
		{"a state the part does not know", item0(func(it *contract.UsageItem) { it.State = "paused" }), false},
		{"measured_at 61 s after the platform's clock", measuredAhead(61 * time.Second), false},
		{"usage_seq a day and a millisecond ahead", mustRaw(vecUsage("wappie", func(u *contract.Usage) {
			u.UsageSeq = Now.Add(24*time.Hour).UnixMilli() + 1
		})), false},
		{"usage_seq 0", mustRaw(vecUsage("wappie", func(u *contract.Usage) { u.UsageSeq = 0 })), false},
		{"a rule_version in capitals", mustRaw(vecUsage("wappie", func(u *contract.Usage) { u.RuleVersion = "Wappie-storage/1" })), false},
		{"a rule_version of version 0", mustRaw(vecUsage("wappie", func(u *contract.Usage) { u.RuleVersion = "wappie-storage/0" })), false},
		{"a rule_version with no version", mustRaw(vecUsage("wappie", func(u *contract.Usage) { u.RuleVersion = "wappie-storage" })), false},
		{"Mailie's shared_bytes above 0", mustRaw(vecUsage("mailie", func(u *contract.Usage) { u.SharedBytes, u.TotalBytes = 5, u.TotalBytes+5 })), false},
		{"Mailie's undated_bytes above 0", mustRaw(vecUsage("mailie", func(u *contract.Usage) { u.Items[0].UndatedBytes = 5 })), false},
		{"an app the part does not know", mustRaw(vecUsage("vaultie", nil)), false},
		{"a workspace_id that is no UUID", mustRaw(vecUsage("wappie", func(u *contract.Usage) { u.WorkspaceID = "team-1" })), false},
		{"v 2", mustRaw(vecUsage("wappie", func(u *contract.Usage) { u.V = 2 })), false},
		{"type entitlements", mustRaw(vecUsage("wappie", func(u *contract.Usage) { u.Type = contract.EntitlementsType })), false},
		{"items null", edit(empty, `"items":[]`, `"items":null`), false},
		{"bytes below 0", edit(base, `"bytes":21000000000`, `"bytes":-21000000000`), false},
		{"bytes as a fraction", edit(base, `"bytes":21000000000`, `"bytes":21000000000.5`), false},
		{"a member the part does not know", edit(base, `"shared_bytes":`, `"index_bytes":7,"shared_bytes":`), false},
		{"a member twice", edit(base, `"shared_bytes":300000000`, `"shared_bytes":300000000,"shared_bytes":0`), false},
		{"purge_at missing on an active item", edit(base, `"state":"active","purge_at":null,`, `"state":"active",`), false},
		{"over 1 MiB", json.RawMessage(padTo(string(empty), contract.UsageReportBodyLimit+1)), false},
	} {
		if got := usageReportValid(c.raw, now); got != c.valid {
			return nil, fmt.Errorf("contractvec: usage report %q is valid %v, the spec asks %v", c.name, got, c.valid)
		}
		out.Reports = append(out.Reports, UsageCase{Name: c.name, Now: now, Value: bigValue(c.raw), Valid: c.valid})
	}

	seq := vecUsage("wappie", nil).UsageSeq
	held := &HeldReport{UsageSeq: seq, Body: base}
	var reindented bytes.Buffer
	if err := json.Indent(&reindented, base, "", "  "); err != nil {
		return nil, err
	}
	later := mustRaw(vecUsage("wappie", func(u *contract.Usage) { u.UsageSeq += 60000; u.MeasuredAt = at(-19 * time.Minute) }))
	other := mustRaw(vecUsage("wappie", func(u *contract.Usage) {
		u.Items[0].Bytes += 1000
		u.TotalBytes += 1000
	}))
	earlier := mustRaw(vecUsage("wappie", func(u *contract.Usage) { u.UsageSeq -= 60000; u.MeasuredAt = at(-21 * time.Minute) }))
	for _, c := range []IntakeCase{
		{Name: "a first report, kept", Mode: "keep", Workspace: "open", Value: base, Kept: true},
		{Name: "a higher usage_seq, kept", Held: held, Mode: "keep", Workspace: "open", Value: later, Kept: true},
		{Name: "a retry of the held report: answered as its first send", Held: held, Mode: "keep", Workspace: "open", Value: base, Kept: true},
		{Name: "a retry of the held report written otherwise: the same JSON value", Held: held, Mode: "keep", Workspace: "open",
			Value: json.RawMessage(reindented.Bytes()), Kept: true},
		{Name: "an equal usage_seq with another body", Held: held, Mode: "keep", Workspace: "open", Value: other, Kept: false},
		{Name: "a lower usage_seq", Held: held, Mode: "keep", Workspace: "open", Value: earlier, Kept: false},
		{Name: "while the platform only validates (E0)", Mode: "validate", Workspace: "open", Value: base, Kept: false},
		{Name: "a retry while the platform only validates", Held: held, Mode: "validate", Workspace: "open", Value: base, Kept: false},
		{Name: "a closed personal workspace", Mode: "keep", Workspace: "closed_personal", Value: base, Kept: false},
		{Name: "a closed team past its 30 days", Mode: "keep", Workspace: "closed_team_past", Value: later, Kept: false},
		{Name: "an empty report, kept", Mode: "keep", Workspace: "open", Value: empty, Kept: true},
	} {
		if !usageReportValid(c.Value, now) {
			return nil, fmt.Errorf("contractvec: intake %q: its report is not valid", c.Name)
		}
		if got := usageKept(c); got != c.Kept {
			return nil, fmt.Errorf("contractvec: intake %q is kept %v, the spec asks %v", c.Name, got, c.Kept)
		}
		out.Intake = append(out.Intake, c)
	}

	for _, c := range []struct {
		name, raw string
		valid     bool
	}{
		{"kept", `{"accepted":true,"kept":true}`, true},
		{"not kept: the app treats it as delivered too", `{"accepted":true,"kept":false}`, true},
		{"its members in another order", `{"kept":false,"accepted":true}`, true},
		{"accepted false", `{"accepted":false,"kept":false}`, false},
		{"no kept", `{"accepted":true}`, false},
		{"kept null", `{"accepted":true,"kept":null}`, false},
		{"kept as text", `{"accepted":true,"kept":"true"}`, false},
		{"a member the part does not know, ignored", `{"accepted":true,"kept":true,"usage_seq":1}`, true},
		{"kept twice", `{"accepted":true,"kept":true,"kept":false}`, false},
		{"kept written Kept", `{"accepted":true,"Kept":true}`, false},
		{"not an object", `[true,true]`, false},
	} {
		raw := json.RawMessage(c.raw)
		if got := usageAnswerValid(raw); got != c.valid {
			return nil, fmt.Errorf("contractvec: usage answer %q is valid %v, the spec asks %v", c.name, got, c.valid)
		}
		out.Answers = append(out.Answers, wireCase(c.name, raw, c.valid))
	}
	return out, nil
}

// DateRow is one stored row of an app, in the abstract shape the date rule
// reads. Wappie's kinds: message (its ts, null when it has none),
// receipt and group_change (their own ts, never null), transcript (an AI
// transcript of the message named by of, which takes that message's date,
// undated with it), object (an attachment counted once per key: refs are
// the messages that reference it, [] for an object no message references,
// which goes to shared_bytes). Mailie's: row (its internal_date, in UTC
// whatever zone it is written in; never the Date header). Both apps':
// fixed (what keeps the item running and is no message, named by what:
// Wappie's chat, contact and group_member, Mailie's folders_row and
// open_draft), which takes no date and counts in bytes and fixed_bytes
// only.
type DateRow struct {
	ID    string   `json:"id"`
	Kind  string   `json:"kind"`
	What  string   `json:"what,omitempty"`
	Item  string   `json:"item,omitempty"`
	TS    *string  `json:"ts"`
	Of    string   `json:"of,omitempty"`
	Refs  []string `json:"refs,omitzero"`
	Bytes int64    `json:"bytes"`
}

// fixedRows are the fixed rows each app stores (SPEC section 11.20).
var fixedRows = map[string][]string{
	"wappie": {"chat", "contact", "group_member"},
	"mailie": {"folders_row", "open_draft"},
}

// DateFigures are an item's bytes and what the date rule makes of them.
type DateFigures struct {
	Bytes        int64 `json:"bytes"`
	RecentBytes  int64 `json:"recent_bytes"`
	UndatedBytes int64 `json:"undated_bytes"`
	FixedBytes   int64 `json:"fixed_bytes"`
}

// DateCase is a report's rows measured at measured_at, and the figures
// they make: per item, and the bytes no single item owns.
type DateCase struct {
	Name        string                 `json:"name"`
	App         string                 `json:"app"`
	MeasuredAt  string                 `json:"measured_at"`
	RecentFrom  string                 `json:"recent_from"`
	Rows        []DateRow              `json:"rows"`
	Items       map[string]DateFigures `json:"items"`
	SharedBytes int64                  `json:"shared_bytes"`
}

// FloorCase is an order's floor against the report it was computed from.
type FloorCase struct {
	Name       string `json:"name"`
	MeasuredAt string `json:"measured_at"`
	IssuedAt   string `json:"issued_at"`
	RecentFrom string `json:"recent_from"`
	Floor      string `json:"floor"`
	// DaysLess are how many whole days the floor keeps fewer than the
	// report's recent_bytes counted: 0 or 1.
	DaysLess int `json:"days_less"`
}

// UsageDates is usage-dates.json.
type UsageDates struct {
	Format      string      `json:"format"`
	Version     int         `json:"version"`
	Kind        string      `json:"kind"`
	Description string      `json:"description"`
	Cases       []DateCase  `json:"dates"`
	Floors      []FloorCase `json:"floors"`
}

// dateFigures applies the date rule to app's rows measured at measuredAt.
func dateFigures(app string, rows []DateRow, measuredAt time.Time) (map[string]DateFigures, int64, error) {
	type dated struct {
		item string
		date *time.Time
	}
	parse := func(s *string) (*time.Time, error) {
		if s == nil {
			return nil, nil
		}
		t, err := time.Parse(time.RFC3339Nano, *s)
		if err != nil {
			return nil, err
		}
		t = t.UTC()
		return &t, nil
	}
	messages := map[string]dated{}
	for _, r := range rows {
		if r.Kind == "message" {
			d, err := parse(r.TS)
			if err != nil {
				return nil, 0, err
			}
			messages[r.ID] = dated{r.Item, d}
		}
	}
	figures := map[string]DateFigures{}
	var shared int64
	add := func(item string, date *time.Time, n int64) {
		f := figures[item]
		f.Bytes += n
		switch {
		case date == nil:
			f.UndatedBytes += n
		case contract.IsRecent(*date, measuredAt):
			f.RecentBytes += n
		}
		figures[item] = f
	}
	for _, r := range rows {
		switch r.Kind {
		case "message":
			add(r.Item, messages[r.ID].date, r.Bytes)
		case "fixed":
			if !slices.Contains(fixedRows[app], r.What) || r.TS != nil {
				return nil, 0, fmt.Errorf("contractvec: fixed row %s is %q of %s, or dated", r.ID, r.What, app)
			}
			f := figures[r.Item]
			f.Bytes += r.Bytes
			f.FixedBytes += r.Bytes
			figures[r.Item] = f
		case "receipt", "group_change", "row":
			d, err := parse(r.TS)
			if err != nil || d == nil {
				return nil, 0, fmt.Errorf("contractvec: row %s has no date of its own", r.ID)
			}
			add(r.Item, d, r.Bytes)
		case "transcript":
			m, ok := messages[r.Of]
			if !ok {
				return nil, 0, fmt.Errorf("contractvec: transcript %s of no message", r.ID)
			}
			add(m.item, m.date, r.Bytes)
		case "object":
			items := map[string]bool{}
			var newest *time.Time
			for _, ref := range r.Refs {
				m, ok := messages[ref]
				if !ok {
					return nil, 0, fmt.Errorf("contractvec: object %s referenced by no message", r.ID)
				}
				items[m.item] = true
				if m.date != nil && (newest == nil || m.date.After(*newest)) {
					newest = m.date
				}
			}
			if len(items) != 1 {
				shared += r.Bytes
				continue
			}
			for item := range items {
				add(item, newest, r.Bytes)
			}
		default:
			return nil, 0, fmt.Errorf("contractvec: a row kind %q", r.Kind)
		}
	}
	return figures, shared, nil
}

func usageDates() (any, error) {
	out := UsageDates{
		Format: Format, Version: 1, Kind: "usage-dates",
		Description: "The date rule (SPEC section 11.20), which both apps follow for recent_bytes and for a trim's floor. dates: a report's rows, in an abstract shape, measured at measured_at, and the figures they make. Each row is {id, kind, item, ts, of, refs, bytes}: Wappie's message (its ts; null when it has none, then undated), receipt and group_change (their own ts, a receipt of an undated message included), transcript (an AI transcript of the message of names: that message's date, undated with it), object (an attachment counted once per key: the date of the newest dated message among refs, the messages that reference it, undated when they all are; referenced from several numbers, or from none (refs [], an unassigned object), it goes to shared_bytes and to no item, never undated); Mailie's row (its internal_date, in UTC whatever zone it is written in, never the Date header; Mailie has no undated bytes); and both apps' fixed (what keeps the item running and is no message, named by what: Wappie's chat, contact and group_member, Mailie's folders_row and open_draft; ts null), which takes no date and counts in the item's bytes and fixed_bytes only, never in recent_bytes or undated_bytes. A date after measured_at counts as measured_at. Recent is a date on or after recent_from, 00:00 UTC of the UTC date of measured_at less 90 days: whole UTC days. items: per item, its bytes, recent_bytes, undated_bytes and fixed_bytes. floors: an order's floor (issued_at's UTC date less 90 days) against recent_from of the report it was computed from, which is under an hour older: on another UTC day, the floor keeps one day less than recent_bytes counted, so the platform deletes less, never more.",
	}
	ts := func(s string) *string { return &s }
	msg := func(id, item string, t *string, n int64) DateRow {
		return DateRow{ID: id, Kind: "message", Item: item, TS: t, Bytes: n}
	}
	for _, c := range []DateCase{
		{Name: "Wappie's messages, receipts and group changes, recent and older", App: "wappie", MeasuredAt: "2026-10-13T12:00:00Z", Rows: []DateRow{
			msg("m1", "dev_7", ts("2026-10-01T08:00:00Z"), 1000),
			msg("m2", "dev_7", ts("2026-06-01T08:00:00Z"), 2000),
			{ID: "r1", Kind: "receipt", Item: "dev_7", TS: ts("2026-10-01T08:00:05Z"), Bytes: 40},
			{ID: "r2", Kind: "receipt", Item: "dev_7", TS: ts("2026-06-01T08:00:05Z"), Bytes: 40},
			{ID: "g1", Kind: "group_change", Item: "dev_7", TS: ts("2026-08-01T00:00:00Z"), Bytes: 300},
		}},
		{Name: "an AI transcript of a dated message and of an undated one", App: "wappie", MeasuredAt: "2026-10-13T12:00:00Z", Rows: []DateRow{
			msg("m1", "dev_7", ts("2026-05-20T10:00:00Z"), 500),
			msg("m2", "dev_7", nil, 700),
			{ID: "t1", Kind: "transcript", Of: "m1", TS: nil, Bytes: 120},
			{ID: "t2", Kind: "transcript", Of: "m2", TS: nil, Bytes: 80},
		}},
		{Name: "a receipt of an undated message: its own ts", App: "wappie", MeasuredAt: "2026-10-13T12:00:00Z", Rows: []DateRow{
			msg("m1", "dev_7", nil, 900),
			{ID: "r1", Kind: "receipt", Item: "dev_7", Of: "m1", TS: ts("2026-10-12T09:00:00Z"), Bytes: 40},
		}},
		{Name: "an object referenced on one number: its newest message's date", App: "wappie", MeasuredAt: "2026-10-13T12:00:00Z", Rows: []DateRow{
			msg("m1", "dev_7", ts("2026-04-01T00:00:00Z"), 100),
			msg("m2", "dev_7", ts("2026-09-30T00:00:00Z"), 100),
			msg("m3", "dev_7", nil, 100),
			{ID: "o1", Kind: "object", Refs: []string{"m1", "m2", "m3"}, Bytes: 50000},
		}},
		{Name: "an object only undated messages reference: undated", App: "wappie", MeasuredAt: "2026-10-13T12:00:00Z", Rows: []DateRow{
			msg("m1", "dev_7", nil, 100),
			{ID: "o1", Kind: "object", Refs: []string{"m1"}, Bytes: 30000},
		}},
		{Name: "an object several numbers reference: shared_bytes", App: "wappie", MeasuredAt: "2026-10-13T12:00:00Z", Rows: []DateRow{
			msg("m1", "dev_7", ts("2026-10-01T00:00:00Z"), 100),
			msg("m2", "dev_9", ts("2026-03-01T00:00:00Z"), 100),
			{ID: "o1", Kind: "object", Refs: []string{"m1", "m2"}, Bytes: 80000},
		}},
		{Name: "an object no message references (refs []): shared_bytes, never undated", App: "wappie", MeasuredAt: "2026-10-13T12:00:00Z", Rows: []DateRow{
			msg("m1", "dev_7", ts("2026-10-01T00:00:00Z"), 100),
			{ID: "o1", Kind: "object", Refs: []string{}, Bytes: 25000},
		}},
		{Name: "Wappie's fixed rows beside a dated and an undated message: in bytes and fixed_bytes only", App: "wappie", MeasuredAt: "2026-10-13T12:00:00Z", Rows: []DateRow{
			msg("m1", "dev_7", ts("2026-10-01T08:00:00Z"), 1000),
			msg("m2", "dev_7", nil, 500),
			{ID: "c1", Kind: "fixed", What: "chat", Item: "dev_7", Bytes: 200},
			{ID: "k1", Kind: "fixed", What: "contact", Item: "dev_7", Bytes: 50},
			{ID: "p1", Kind: "fixed", What: "group_member", Item: "dev_7", Bytes: 30},
		}},
		{Name: "Mailie's fixed rows beside rows by internal_date: in bytes and fixed_bytes only", App: "mailie", MeasuredAt: "2026-10-13T12:00:00Z", Rows: []DateRow{
			{ID: "u1", Kind: "row", Item: "acc_7f3a", TS: ts("2026-06-01T10:00:00Z"), Bytes: 3000},
			{ID: "u2", Kind: "row", Item: "acc_7f3a", TS: ts("2026-10-10T10:00:00Z"), Bytes: 5000},
			{ID: "f1", Kind: "fixed", What: "folders_row", Item: "acc_7f3a", Bytes: 400},
			{ID: "d1", Kind: "fixed", What: "open_draft", Item: "acc_7f3a", Bytes: 1200},
		}},
		{Name: "Mailie's rows by internal_date in UTC", App: "mailie", MeasuredAt: "2026-10-13T12:00:00Z", Rows: []DateRow{
			{ID: "u1", Kind: "row", Item: "acc_7f3a", TS: ts("2026-07-14T23:30:00-03:00"), Bytes: 3000},
			{ID: "u2", Kind: "row", Item: "acc_7f3a", TS: ts("2026-07-15T01:30:00+03:00"), Bytes: 4000},
			{ID: "u3", Kind: "row", Item: "acc_7f3a", TS: ts("2026-10-10T10:00:00Z"), Bytes: 5000},
		}},
		{Name: "a date after measured_at counts as measured_at", App: "wappie", MeasuredAt: "2026-10-13T12:00:00Z", Rows: []DateRow{
			msg("m1", "dev_7", ts("2027-01-01T00:00:00Z"), 600),
		}},
		{Name: "the 90-day edge: 00:00:00 of the edge day is recent, the instant before is not", App: "wappie", MeasuredAt: "2026-10-13T12:00:00Z", Rows: []DateRow{
			msg("m1", "dev_7", ts("2026-07-15T00:00:00Z"), 10),
			msg("m2", "dev_7", ts("2026-07-14T23:59:59.999Z"), 20),
		}},
		{Name: "the edge with measured_at late in its UTC day: whole days", App: "wappie", MeasuredAt: "2026-10-13T23:59:59Z", Rows: []DateRow{
			msg("m1", "dev_7", ts("2026-07-15T00:00:00Z"), 10),
			msg("m2", "dev_7", ts("2026-07-14T23:59:59.999Z"), 20),
		}},
		{Name: "the edge a UTC day later: the edge day is no longer recent", App: "wappie", MeasuredAt: "2026-10-14T00:00:00Z", Rows: []DateRow{
			msg("m1", "dev_7", ts("2026-07-15T00:00:00Z"), 10),
			msg("m2", "dev_7", ts("2026-07-16T00:00:00Z"), 20),
		}},
	} {
		measured, err := time.Parse(time.RFC3339, c.MeasuredAt)
		if err != nil {
			return nil, err
		}
		items, shared, err := dateFigures(c.App, c.Rows, measured)
		if err != nil {
			return nil, fmt.Errorf("contractvec: dates %q: %w", c.Name, err)
		}
		c.RecentFrom = contract.RecentFrom(measured).Format(time.RFC3339)
		c.Items, c.SharedBytes = items, shared
		out.Cases = append(out.Cases, c)
	}
	// The figures the spec names, so that a rule that moved is caught here
	// rather than written.
	want := map[string]string{
		"Wappie's messages, receipts and group changes, recent and older":                          "dev_7 3380 1340 0 0",
		"an AI transcript of a dated message and of an undated one":                                "dev_7 1400 0 780 0",
		"a receipt of an undated message: its own ts":                                              "dev_7 940 40 900 0",
		"an object referenced on one number: its newest message's date":                            "dev_7 50300 50100 100 0",
		"an object only undated messages reference: undated":                                       "dev_7 30100 0 30100 0",
		"an object several numbers reference: shared_bytes":                                        "dev_7 100 100 0 0;dev_9 100 0 0 0;shared 80000",
		"an object no message references (refs []): shared_bytes, never undated":                   "dev_7 100 100 0 0;shared 25000",
		"Wappie's fixed rows beside a dated and an undated message: in bytes and fixed_bytes only": "dev_7 1780 1000 500 280",
		"Mailie's fixed rows beside rows by internal_date: in bytes and fixed_bytes only":          "acc_7f3a 9600 5000 0 1600",
		"Mailie's rows by internal_date in UTC":                                                    "acc_7f3a 12000 8000 0 0",
		"a date after measured_at counts as measured_at":                                           "dev_7 600 600 0 0",
		"the 90-day edge: 00:00:00 of the edge day is recent, the instant before is not":           "dev_7 30 10 0 0",
		"the edge with measured_at late in its UTC day: whole days":                                "dev_7 30 10 0 0",
		"the edge a UTC day later: the edge day is no longer recent":                               "dev_7 30 20 0 0",
	}
	for _, c := range out.Cases {
		var parts []string
		for id, f := range c.Items {
			parts = append(parts, fmt.Sprintf("%s %d %d %d %d", id, f.Bytes, f.RecentBytes, f.UndatedBytes, f.FixedBytes))
		}
		sort.Strings(parts)
		if c.SharedBytes != 0 {
			parts = append(parts, fmt.Sprintf("shared %d", c.SharedBytes))
		}
		if got := strings.Join(parts, ";"); got != want[c.Name] {
			return nil, fmt.Errorf("contractvec: dates %q make %q, the spec asks %q", c.Name, got, want[c.Name])
		}
	}

	for _, c := range []struct {
		name, measured, issued string
		days                   int
	}{
		{"an order issued the same UTC day as its report: the floor is recent_from", "2026-10-13T11:20:00Z", "2026-10-13T12:00:00Z", 0},
		{"an order issued the UTC day after its report: one day less kept", "2026-10-13T23:50:00Z", "2026-10-14T00:10:00Z", 1},
	} {
		measured, err := time.Parse(time.RFC3339, c.measured)
		if err != nil {
			return nil, err
		}
		issued, err := time.Parse(time.RFC3339, c.issued)
		if err != nil {
			return nil, err
		}
		from := contract.RecentFrom(measured)
		floor := contract.TrimFloor(issued)
		f, err := time.Parse(time.DateOnly, floor)
		if err != nil {
			return nil, err
		}
		if days := int(f.Sub(from) / (24 * time.Hour)); days != c.days {
			return nil, fmt.Errorf("contractvec: floor %q keeps %d days less, the spec asks %d", c.name, days, c.days)
		}
		out.Floors = append(out.Floors, FloorCase{Name: c.name, MeasuredAt: c.measured, IssuedAt: c.issued,
			RecentFrom: from.Format(time.RFC3339), Floor: floor, DaysLess: c.days})
	}
	return out, nil
}
