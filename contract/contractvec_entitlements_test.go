package contract_test

// The kit's generator of wire-entitlements.json (kit v0.12.0, SPEC section
// 11.20): entitlements documents valid and invalid, feed pages,
// acknowledgements, and what an app does with each document and answer:
// the feed's actions, the GET's, freshness held back and given back, the
// same version from the feed and the GET, link decisions, a reset, the
// freeze, Wappie's cap at a boundary, requests.codes_after, and the lifts
// of 15.4's Resuming. The behaviours are written here as small models of
// the spec, which the runners replay; every case states the outcome the
// spec asks of it, and the generator fails rather than write a case whose
// outcome the code or the model does not give.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sort"
	"time"

	"github.com/thehappieco/kit/contract"
)

// The fixed material of the entitlements part's vectors: made-up ids.
const (
	vecWS2 = "0199d000-0000-7000-8000-000000000041"
	vecWS3 = "0199d000-0000-7000-8000-000000000042"
)

// vecEnt is a valid document of app in the team, computed at Now: the
// spec's example, over its quota, with a plan, a counted snapshot and one
// step to come.
func vecEnt(app string, mut func(*contract.EntitlementsDoc)) contract.EntitlementsDoc {
	kind, _ := contract.AppItemKind(app)
	d := contract.EntitlementsDoc{
		V: contract.EntitlementsV, Type: contract.EntitlementsType, App: app, Generation: vecGeneration,
		WorkspaceID: vecTeam, Version: 57, ComputedAt: at(0), Mode: contract.ModeEnforce, TestMode: true,
		State: contract.EntitlementsState{Name: contract.WorkspaceOverQuota, Reason: ptr(contract.ReasonOverQuota),
			Since: at(-49 * time.Hour), Deadline: ptr(at(28 * 24 * time.Hour))},
		Plan: contract.EntitlementsPlan{Source: contract.SourcePlan, Test: true, Numbers: 2, Mailboxes: 1, PeriodEnd: ptr(at(29 * 24 * time.Hour))},
		Places: contract.EntitlementsPlaces{Kind: kind, Total: 2, Used: ptr[int64](2), UsedConnected: ptr[int64](1),
			Free: ptr[int64](0), CountedAt: ptr(at(-2 * time.Minute))},
		Storage: contract.EntitlementsStorage{QuotaBytes: 25000000000, UsedBytes: ptr[int64](27300000000), OthersBytes: 1200000000,
			AllowanceBytes: 23800000000, CapBytes: 25050000000, MeasuredThrough: ptr(at(-20 * time.Minute))},
		Switches: contract.Switches{API: contract.SwitchOff, NewLinks: contract.SwitchOff, Sync: contract.SwitchOn, Send: contract.SwitchOff},
		Timeline: []contract.TimelineStep{{At: at(23 * time.Hour), Off: []string{contract.SwitchSync}}},
		Items:    []contract.ItemTrial{},
		Links: contract.EntitlementsLinks{
			Plan:    "https://console.thehappie.co/workspaces/" + vecTeam + "/plan",
			Storage: "https://console.thehappie.co/workspaces/" + vecTeam + "/storage",
		},
	}
	if app == "mailie" {
		d.Places.Total, d.Places.Used, d.Places.UsedConnected = 1, ptr[int64](1), ptr[int64](0)
		d.Storage.CapBytes = d.Storage.AllowanceBytes
		d.Timeline = []contract.TimelineStep{}
		d.Switches.Sync = contract.SwitchOff
	}
	if mut != nil {
		mut(&d)
	}
	return d
}

// onTrial makes a document's workspace one on trial, in observe, with no
// other app's report kept: others_bytes 0, the allowance the trial's 15
// GB, and Wappie's cap 105 % of it.
func onTrial(d *contract.EntitlementsDoc) {
	d.Mode = contract.ModeObserve
	d.State = contract.EntitlementsState{Name: contract.WorkspaceTrial, Since: at(-48 * time.Hour), TrialEndsAt: ptr(at(13 * 24 * time.Hour))}
	d.Plan = contract.EntitlementsPlan{Source: contract.SourceTrial, Numbers: 1, Mailboxes: 1}
	d.Places.Total, d.Places.Used, d.Places.UsedConnected, d.Places.Free = 1, ptr[int64](1), ptr[int64](0), ptr[int64](0)
	d.Storage = contract.EntitlementsStorage{QuotaBytes: 15000000000, AllowanceBytes: 15000000000, CapBytes: 15750000000}
	if d.App == "mailie" {
		d.Storage.CapBytes = d.Storage.AllowanceBytes
	}
	d.Switches = contract.Switches{API: contract.SwitchOn, NewLinks: contract.SwitchOn, Sync: contract.SwitchOn, Send: contract.SwitchOn}
	d.Timeline = []contract.TimelineStep{
		{At: at(13 * 24 * time.Hour), Off: []string{contract.SwitchAPI, contract.SwitchNewLinks, contract.SwitchSend}},
		{At: at(16 * 24 * time.Hour), Off: []string{contract.SwitchSync}},
	}
}

// active makes a document's workspace active, within its quota.
func active(d *contract.EntitlementsDoc) {
	d.State = contract.EntitlementsState{Name: contract.WorkspaceActive, Since: at(-10 * 24 * time.Hour)}
	d.Storage.UsedBytes, d.Storage.MeasuredThrough = ptr[int64](12000000000), ptr(at(-20*time.Minute))
	d.Switches = contract.Switches{API: contract.SwitchOn, NewLinks: contract.SwitchOn, Sync: contract.SwitchOn, Send: contract.SwitchOn}
	d.Timeline = []contract.TimelineStep{}
}

// expired makes a document's workspace expired, a no-plan episode past its
// deadline, everything stopped.
func expired(d *contract.EntitlementsDoc) {
	d.State = contract.EntitlementsState{Name: contract.WorkspaceExpired, Reason: ptr(contract.ReasonNoPlan),
		Since: at(-40 * 24 * time.Hour), ExpiredSince: ptr(at(-10 * 24 * time.Hour))}
	d.Plan = contract.EntitlementsPlan{Source: contract.SourceNone}
	d.Places.Total, d.Places.Free = 0, ptr[int64](0)
	d.Storage.QuotaBytes, d.Storage.AllowanceBytes, d.Storage.CapBytes = 0, 0, 0
	d.Switches = contract.Switches{API: contract.SwitchOff, NewLinks: contract.SwitchOff, Sync: contract.SwitchOff, Send: contract.SwitchOff}
	d.Timeline = []contract.TimelineStep{}
}

// entDocValid is what an app makes of a document: read as it reads what
// the platform sends, then Validate.
func entDocValid(raw []byte) bool {
	var d contract.EntitlementsDoc
	return json.Unmarshal(raw, &d) == nil && d.Validate() == nil
}

// entFeedValid is what an app makes of a page: read as it reads what the
// platform sends, then the page's own Validate; its documents are judged
// one by one apart.
func entFeedValid(raw []byte) bool {
	var f contract.EntitlementsFeed
	return json.Unmarshal(raw, &f) == nil && f.Validate() == nil
}

// entAppliedValid is what the platform makes of an acknowledgement:
// within its 4 KiB, decoded strictly, and valid.
func entAppliedValid(raw []byte) bool {
	var a contract.EntitlementsApplied
	return len(raw) <= contract.EntitlementsAppliedLimit && contract.DecodeStrict(raw, &a) == nil && a.Validate() == nil
}

// entPage is a page of generation holding the documents raw, at seqs from
// head - len(docs) + 1 to head.
func entPage(generation string, head int64, docs ...json.RawMessage) json.RawMessage {
	f := contract.EntitlementsFeed{Generation: generation, GenerationConfirmed: true, Head: head, PublishedThrough: at(4 * time.Second),
		Items: []contract.EntitlementsFeedItem{}, NextAfter: head}
	for i, d := range docs {
		f.Items = append(f.Items, contract.EntitlementsFeedItem{Seq: head - int64(len(docs)) + 1 + int64(i), Doc: d})
	}
	return mustRaw(f)
}

// docAt is d's JSON at version v.
func docAt(d contract.EntitlementsDoc, v int64) json.RawMessage {
	d.Version = v
	return mustRaw(d)
}

// EntPageCase is a page of one document, the app that reads it, its
// generation, the workspaces it holds (known: named by an account
// document) and the version it applied in each; what it does with the
// document, the acknowledgement's refused entry, and where its cursor
// goes.
type EntPageCase struct {
	Name       string                        `json:"name"`
	App        string                        `json:"app"`
	Generation string                        `json:"generation"`
	Known      []string                      `json:"known"`
	Held       map[string]int64              `json:"held"`
	Value      json.RawMessage               `json:"value"`
	Action     string                        `json:"action"`
	Refused    *contract.EntitlementsRefused `json:"refused"`
	Through    *int64                        `json:"through"`
}

// entPageAction is what an app does with a page of one document (SPEC
// section 11.20): a page that does not decode or validate, "invalid"; a
// page of another generation, "reset", whatever its document says; in a
// page of its own generation, a bad document "refuse" with its refused
// entry (another_app, another_generation, invalid_document); a document of
// a workspace it does not hold yet "keep" (kept and counted as applied,
// applied once an account document names the workspace); a version at or
// below the one it applied "ignore"; else "apply". Through is the page's
// next_after, but for an invalid page and a reset.
func entPageAction(c EntPageCase) (string, *contract.EntitlementsRefused, *int64) {
	var f contract.EntitlementsFeed
	if json.Unmarshal(c.Value, &f) != nil || f.Validate() != nil || len(f.Items) != 1 {
		return "invalid", nil, nil
	}
	if f.Generation != c.Generation {
		return "reset", nil, nil
	}
	through := ptr(f.NextAfter)
	d, ref := f.Items[0].Document(c.App, c.Generation)
	switch {
	case ref != nil:
		return "refuse", ref, through
	case !slices.Contains(c.Known, d.WorkspaceID):
		return "keep", nil, through
	case d.Version <= c.Held[d.WorkspaceID]:
		return "ignore", nil, through
	}
	return "apply", nil, through
}

// EntGetCase is a signed answer of GET /contract/v1/workspaces/{id}/
// entitlements for the workspace of the path, the version the app applied
// there, and what it does: status is 200 with the document, or the code
// of a signed refusal.
type EntGetCase struct {
	Name       string          `json:"name"`
	App        string          `json:"app"`
	Generation string          `json:"generation"`
	Workspace  string          `json:"workspace"`
	Held       int64           `json:"held"`
	Status     string          `json:"status"`
	Value      json.RawMessage `json:"value"`
	Action     string          `json:"action"`
	Fresh      bool            `json:"fresh"`
}

// entGetAction is what an app does with a GET's signed answer (SPEC
// section 11.20): a signed not_found, "not_found" (the platform keeps no
// document: the last applied one holds, frozen, and the app stops asking
// until a document of the workspace reaches its feed); any other signed
// refusal, "none"; a document that does not decode, fails Validate, or
// names another app or another workspace than the path's, "refuse" (the
// kit's client refuses it and logs it); of another generation, "reset";
// of a lower version than the one applied, "ignore"; of the same,
// "fresh"; else "apply". Only "fresh" and "apply" give freshness.
func entGetAction(c EntGetCase) (string, bool) {
	switch c.Status {
	case "200":
	case contract.CodeNotFound:
		return "not_found", false
	default:
		return "none", false
	}
	var d contract.EntitlementsDoc
	if json.Unmarshal(c.Value, &d) != nil || d.ValidateFor(c.App, c.Workspace) != nil {
		return "refuse", false
	}
	switch {
	case d.Generation != c.Generation:
		return "reset", false
	case d.Version < c.Held:
		return "ignore", false
	case d.Version == c.Held:
		return "fresh", true
	}
	return "apply", true
}

// EntStep is one page or GET answer of a sequence, and the workspaces
// whose freshness from pages is held back after it.
type EntStep struct {
	Source    string          `json:"source"`
	Workspace string          `json:"workspace,omitempty"`
	Status    string          `json:"status,omitempty"`
	Value     json.RawMessage `json:"value"`
	Action    string          `json:"action"`
	HeldBack  []string        `json:"held_back"`
}

// EntSequence is a sequence of pages and GET answers an app takes in turn,
// from what it holds.
type EntSequence struct {
	Name       string           `json:"name"`
	App        string           `json:"app"`
	Generation string           `json:"generation"`
	Known      []string         `json:"known"`
	Held       map[string]int64 `json:"held"`
	Steps      []EntStep        `json:"steps"`
}

// entSequence plays a sequence (SPEC section 11.20): each step as
// entPageAction or entGetAction takes it; a refused document holds back
// its workspace's freshness from pages, or every workspace the app keeps a
// document of when its workspace_id cannot be read; a workspace is given
// back by a valid document of it of a higher version that applies, or by
// a GET answer that gives freshness.
func entSequence(s EntSequence) ([]EntStep, error) {
	held := maps.Clone(s.Held)
	back := map[string]bool{}
	var out []EntStep
	for _, st := range s.Steps {
		switch st.Source {
		case "page":
			action, ref, _ := entPageAction(EntPageCase{App: s.App, Generation: s.Generation, Known: s.Known, Held: held, Value: st.Value})
			st.Action = action
			switch action {
			case "refuse":
				if ref.WorkspaceID != nil {
					back[*ref.WorkspaceID] = true
				} else {
					for ws := range held {
						back[ws] = true
					}
				}
			case "apply":
				var f contract.EntitlementsFeed
				_ = json.Unmarshal(st.Value, &f)
				d, _ := f.Items[0].Document(s.App, s.Generation)
				held[d.WorkspaceID] = d.Version
				delete(back, d.WorkspaceID)
			}
		case "get":
			action, fresh := entGetAction(EntGetCase{App: s.App, Generation: s.Generation, Workspace: st.Workspace,
				Held: held[st.Workspace], Status: st.Status, Value: st.Value})
			st.Action = action
			if fresh {
				var d contract.EntitlementsDoc
				_ = json.Unmarshal(st.Value, &d)
				held[st.Workspace] = d.Version
				delete(back, st.Workspace)
			}
		default:
			return nil, fmt.Errorf("contractvec: a step from %q", st.Source)
		}
		st.HeldBack = slices.Sorted(maps.Keys(back))
		if st.HeldBack == nil {
			st.HeldBack = []string{}
		}
		out = append(out, st)
	}
	return out, nil
}

// VersionCase is a feed item's document and a GET's answer of the same
// version, and whether they are the same document.
type VersionCase struct {
	Name string          `json:"name"`
	Feed json.RawMessage `json:"feed"`
	Get  json.RawMessage `json:"get"`
	Same bool            `json:"same"`
}

// sameVersion reports whether a feed's and a GET's document of the same
// version are the same document: byte for byte, except a trim's secret and
// mac, which are set when served.
func sameVersion(feed, get []byte) bool {
	if bytes.Equal(feed, get) {
		return true
	}
	strip := func(raw []byte) ([]byte, bool) {
		var v map[string]any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if dec.Decode(&v) != nil {
			return nil, false
		}
		trim, ok := v["trim"].(map[string]any)
		if !ok {
			return nil, false
		}
		delete(trim, "secret")
		delete(trim, "mac")
		b, err := json.Marshal(v)
		return b, err == nil
	}
	a, okA := strip(feed)
	b, okB := strip(get)
	return okA && okB && bytes.Equal(a, b)
}

// LinkDoc is what a link decision reads of a document: its mode and its
// new_links switch.
type LinkDoc struct {
	Mode     string `json:"mode"`
	NewLinks string `json:"new_links"`
}

// LinkCase is a link (or a connection) an app is asked to make in a
// workspace: the mode its release runs (enforce: it enforces this part),
// the document it applied there (null for none) and how many minutes old
// that document's freshness is, the GET's answer when it asks (doc, a
// signed not_found, or none: no signed answer), and what it decides.
type LinkCase struct {
	Name         string   `json:"name"`
	Release      string   `json:"release"`
	Held         *LinkDoc `json:"held"`
	FreshMinutes *int     `json:"fresh_minutes"`
	Get          string   `json:"get"`
	GetDoc       *LinkDoc `json:"get_doc"`
	Asks         bool     `json:"asks"`
	Action       string   `json:"action"`
	Logged       bool     `json:"logged"`
}

// linkDecision is an app's link decision (SPEC section 11.20): with no
// applied document, or one whose freshness is over an hour old, it first
// asks the GET and judges by the document it then holds. The workspace
// enforces when that document says enforce, or, with none, when the
// release enforces. Without a signed answer carrying a document it
// refuses the link, as a retry, in a workspace that enforces, and in one
// that does not, logs the refusal with ids only and links. With a
// document, new_links off refuses the link where it enforces, and is
// logged and linked where it does not.
func linkDecision(c LinkCase) (asks bool, action string, logged bool) {
	doc := c.Held
	asks = c.Held == nil || c.FreshMinutes == nil || *c.FreshMinutes > 60
	unanswered := false
	if asks {
		if c.Get == "doc" {
			doc = c.GetDoc
		} else {
			unanswered = true
		}
	}
	enforces := (doc != nil && doc.Mode == contract.ModeEnforce) || (doc == nil && c.Release == contract.ModeEnforce)
	refuse := unanswered || doc.NewLinks == contract.SwitchOff
	switch {
	case refuse && enforces:
		return asks, "refuse_link", false
	case refuse:
		return asks, "link", true
	}
	return asks, "link", false
}

// ItemStop is an app's own stop record of an item: why and from when.
type ItemStop struct {
	Item  string `json:"item"`
	Cause string `json:"cause"`
	At    string `json:"at"`
}

// AppState is what an app holds of the entitlements feed: its generation
// and cursor, the version it applied per workspace, the last document it
// applied per workspace, its own per-item stop records, and the last
// requests.codes_after it answered per workspace.
type AppState struct {
	Generation string                     `json:"generation"`
	Cursor     int64                      `json:"cursor"`
	Versions   map[string]int64           `json:"versions"`
	Applied    map[string]json.RawMessage `json:"applied"`
	Stops      []ItemStop                 `json:"stops"`
	CodesAfter map[string]string          `json:"codes_after"`
}

// ResetCase is what an app holds before a page of another generation, and
// after it.
type ResetCase struct {
	Name       string   `json:"name"`
	Before     AppState `json:"before"`
	Generation string   `json:"generation"`
	After      AppState `json:"after"`
	Action     string   `json:"action"`
}

// entReset is a reset (SPEC section 11.17's 7.4, 11.20): it forgets the
// cursor, the stored versions and each workspace's last answered
// codes_after, and keeps every last applied document and the app's own
// per-item stop records until a new one is applied: it never loosens.
func entReset(s AppState, generation string) AppState {
	return AppState{Generation: generation, Cursor: 0, Versions: map[string]int64{}, Applied: maps.Clone(s.Applied),
		Stops: slices.Clone(s.Stops), CodesAfter: map[string]string{}}
}

// FreezeCase is a step to come (cause timeline: a step's at; item_trial:
// an item's own trial stop; places: Wappie's 72 hours over its places),
// the app's clock now, when its freshness was last given, and what it
// does: fire, hold (frozen: freshness 24 hours old or more at the step's
// time), wait (not yet) or none (no stop: an item's trial stop holds only
// while the plan grants nothing).
type FreezeCase struct {
	Name       string  `json:"name"`
	App        string  `json:"app"`
	Cause      string  `json:"cause"`
	At         string  `json:"at"`
	PlanSource *string `json:"plan_source,omitempty"`
	Trial      *string `json:"trial,omitempty"`
	Now        string  `json:"now"`
	FreshAt    string  `json:"fresh_at"`
	StopsAt    *string `json:"stops_at"`
	Action     string  `json:"action"`
}

// freezeAction is what an app does with a step under the freeze (SPEC
// section 11.20). A timeline step stops at its at. An item's own trial
// stop, running or used_up alike, holds only while the plan source is
// trial or none, and stops at the item's trial end in Mailie, 72 hours
// later in Wappie. Wappie's place stop comes 72 hours after its own count
// first found the item over its places. A stop fires at its time while the
// app's freshness is under 24 hours old at that time; past that the app is
// frozen and holds it.
func freezeAction(c FreezeCase) (*string, string, error) {
	at, err := time.Parse(time.RFC3339, c.At)
	if err != nil {
		return nil, "", err
	}
	now, err := time.Parse(time.RFC3339, c.Now)
	if err != nil {
		return nil, "", err
	}
	fresh, err := time.Parse(time.RFC3339, c.FreshAt)
	if err != nil {
		return nil, "", err
	}
	stops := at
	switch c.Cause {
	case "timeline":
	case "item_trial":
		if c.PlanSource == nil || (*c.PlanSource != contract.SourceTrial && *c.PlanSource != contract.SourceNone) {
			return nil, "none", nil
		}
		if c.App != "mailie" {
			stops = at.Add(72 * time.Hour)
		}
	case "places":
		stops = at.Add(72 * time.Hour)
	default:
		return nil, "", fmt.Errorf("contractvec: a cause %q", c.Cause)
	}
	s := stops.Format(time.RFC3339)
	switch {
	case now.Before(stops):
		return &s, "wait", nil
	case stops.Sub(fresh) >= 24*time.Hour:
		return &s, "hold", nil
	}
	return &s, "fire", nil
}

// CapCase is Wappie's cap_bytes (SPEC section 11.20): floor(1.05 ×
// cap_quota) - others_bytes, at least 0, where cap_quota is quota_bytes,
// except at a boundary (a trial's end, a set ends_at, the 14 days' end,
// buy_by) before Wappie's sync step, where it is the quota that last
// granted; Mailie's is its allowance.
type CapCase struct {
	Name           string `json:"name"`
	App            string `json:"app"`
	Boundary       string `json:"boundary"`
	QuotaBytes     int64  `json:"quota_bytes"`
	LastGranted    int64  `json:"last_granted"`
	OthersBytes    int64  `json:"others_bytes"`
	BeforeSyncStep bool   `json:"before_sync_step"`
	CapBytes       int64  `json:"cap_bytes"`
}

func capBytes(c CapCase) int64 {
	if c.App == "mailie" {
		return max(0, c.QuotaBytes-c.OthersBytes)
	}
	q := c.QuotaBytes
	if c.Boundary != "" && c.BeforeSyncStep {
		q = c.LastGranted
	}
	return max(0, q*105/100-c.OthersBytes)
}

// CodesAfterCase is a document's requests.codes_after against the last
// value the app answered for the workspace (null: none, or forgotten by a
// reset), and whether the app sends item.identity_updated for the items
// the document's items do not list.
type CodesAfterCase struct {
	Name         string  `json:"name"`
	LastAnswered *string `json:"last_answered"`
	CodesAfter   *string `json:"codes_after"`
	Action       string  `json:"action"`
}

func codesAfterAction(c CodesAfterCase) string {
	if c.CodesAfter == nil {
		return "none"
	}
	if c.LastAnswered != nil && *c.CodesAfter <= *c.LastAnswered {
		return "none"
	}
	return "send"
}

// Placed is an item the app counts for its places, by when it was placed.
type Placed struct {
	ID       string `json:"id"`
	PlacedAt string `json:"placed_at"`
}

// PlacesCount is what the app's own count reads: the plan's places, the
// licence bindings it counts (Wappie, until its licences become
// connections), and its linked, not-deleted, not-pending items.
type PlacesCount struct {
	Total    int64    `json:"total"`
	Bindings int64    `json:"bindings"`
	Items    []Placed `json:"items"`
}

// PlacesCase is the app's count before and after a change, the items it
// stops after each, and what the change does: lift (an item stopped
// resumes), stop (an item is stopped) or keep.
type PlacesCase struct {
	Name          string      `json:"name"`
	App           string      `json:"app"`
	Before        PlacesCount `json:"before"`
	After         PlacesCount `json:"after"`
	StoppedBefore []string    `json:"stopped_before"`
	StoppedAfter  []string    `json:"stopped_after"`
	Action        string      `json:"action"`
}

// placesStopped are the items an app stops for want of a place (SPEC
// section 11.20): the licence bindings take the first places and are
// never stopped; the items beyond the first total less the bindings (at
// least 0), by placed_at (then id), stop.
func placesStopped(c PlacesCount) []string {
	items := slices.Clone(c.Items)
	sort.Slice(items, func(i, j int) bool {
		if items[i].PlacedAt != items[j].PlacedAt {
			return items[i].PlacedAt < items[j].PlacedAt
		}
		return items[i].ID < items[j].ID
	})
	first := max(0, c.Total-c.Bindings)
	out := []string{}
	for i, it := range items {
		if int64(i) >= first {
			out = append(out, it.ID)
		}
	}
	sort.Strings(out)
	return out
}

func placesAction(before, after []string) string {
	for _, id := range after {
		if !slices.Contains(before, id) {
			return "stop"
		}
	}
	for _, id := range before {
		if !slices.Contains(after, id) {
			return "lift"
		}
	}
	return "keep"
}

// TrialStopCase is an item stopped at its own trial's end, the next
// document the app applies (its plan source, and the item's entry there:
// null when it does not list it), and whether that lifts the stop.
type TrialStopCase struct {
	Name       string              `json:"name"`
	StoppedAt  string              `json:"stopped_at"`
	PlanSource string              `json:"plan_source"`
	Entry      *contract.ItemTrial `json:"entry"`
	Action     string              `json:"action"`
}

// trialStopAction lifts an item's own trial stop on a document whose plan
// source is plan or live_move, or that lists it running with a later end;
// a document that only stops listing it lifts nothing.
func trialStopAction(c TrialStopCase) string {
	stopped, _ := time.Parse(time.RFC3339, c.StoppedAt)
	switch {
	case c.PlanSource == contract.SourcePlan || c.PlanSource == contract.SourceLiveMove:
		return "lift"
	case c.Entry != nil && c.Entry.Trial == contract.TrialRunning && c.Entry.TrialEndsAt.After(stopped):
		return "lift"
	}
	return "keep"
}

// CapStopCase is the app's total against the cap_bytes of the last
// applied document, and whether capture stopped by the cap stores again.
type CapStopCase struct {
	Name     string `json:"name"`
	Total    int64  `json:"total_bytes"`
	CapBytes int64  `json:"cap_bytes"`
	Action   string `json:"action"`
}

func capStopAction(c CapStopCase) string {
	if c.Total <= c.CapBytes {
		return "lift"
	}
	return "stop"
}

// WireEntitlements is wire-entitlements.json.
type WireEntitlements struct {
	Format      string           `json:"format"`
	Version     int              `json:"version"`
	Kind        string           `json:"kind"`
	Description string           `json:"description"`
	Documents   []WireCase       `json:"documents"`
	Feeds       []WireCase       `json:"feeds"`
	Applied     []WireCase       `json:"applied"`
	Actions     []EntPageCase    `json:"actions"`
	Gets        []EntGetCase     `json:"gets"`
	Sequences   []EntSequence    `json:"sequences"`
	Versions    []VersionCase    `json:"versions"`
	Links       []LinkCase       `json:"links"`
	Resets      []ResetCase      `json:"resets"`
	Freeze      []FreezeCase     `json:"freeze"`
	Caps        []CapCase        `json:"caps"`
	CodesAfter  []CodesAfterCase `json:"codes_after"`
	Places      []PlacesCase     `json:"places"`
	TrialStops  []TrialStopCase  `json:"trial_stops"`
	CapStops    []CapStopCase    `json:"cap_stops"`
}

func wireEntitlements() (any, error) {
	out := WireEntitlements{
		Format: Format, Version: 1, Kind: "wire-entitlements",
		Description: entitlementsDescription,
	}
	if err := entDocuments(&out); err != nil {
		return nil, err
	}
	if err := entFeeds(&out); err != nil {
		return nil, err
	}
	if err := entBehaviour(&out); err != nil {
		return nil, err
	}
	return out, nil
}

const entitlementsDescription = "The entitlements document, its feed and acknowledgement, and what an app does with them (SPEC section 11.20). " +
	"documents: a document as the platform sends it, read as an app reads what the platform sends (members it does not know ignored, a member counted only as exactly named, every member present and null only where its rule allows), then Validate, which judges every time against computed_at, never the reader's clock: every type, enum and bound (timeline at most 16 steps, items at most 1000, plan counts 0 to 50); reason set exactly on over_quota and expired; deadline only on over_quota, where it may be null; expired_since set exactly on expired; trial_ends_at set on trial, allowed on over_quota, null on active, expired and closed; plan.source trial with counts 1, 1 and 0, test false and no period, none with 0, 0 and 0, test false and no period, live_move with test true; places.kind the app's and places.total the plan's count of it; places.used, used_connected, free and counted_at null together or set together, then free = max(0, total - used) and used_connected at most used; allowance_bytes = max(0, quota_bytes - others_bytes), others_bytes never null; Mailie's cap_bytes its allowance (Wappie's, floor(1.05 x cap_quota) - others_bytes, is not checked: its quota may be the one that last granted); measured_through null exactly with used_bytes; every switch off and timeline [] on closed; the timeline after computed_at in strictly rising at, each step {at, <switch>: off} naming one to four switches, each only as off; items only while state.trial_ends_at is set, each id once, running after computed_at and used_up at or before it, never not_needed; requests at or before computed_at, codes_after only while state.trial_ends_at is set; trim only with mode enforce and state expired, naming the document's app, workspace and generation, and valid as an order; links https, or http on a *.localhost host. The others_bytes 0 cases show the allowance and Wappie's cap from it: a quota_bytes of 15000000000 gives a cap_bytes of 15750000000. " +
	"feeds: a page, read as an app reads what the platform sends, then the page's own Validate (generation, head, published_through, items at most 200 in rising seq at or below head, next_after at most head); its documents are judged one by one, so one never refuses the page. " +
	"applied: an acknowledgement, within 4 KiB, decoded strictly, then Validate: refused absent when none, else 1 to 20 entries, each {seq, workspace_id, code}, seq 1 to through and once, workspace_id a UUID or null, code invalid_document, another_app or another_generation. " +
	"actions: a page of one document, the app reading it, its generation, the workspaces it holds (known) and the version it applied in each (held); action: invalid (the page does not decode or validate), reset (a page of another generation, whatever its document says), refuse (a bad document in a page of its own generation: another_app when its app reads as another app id, another_generation when its generation reads as another UUID, else invalid_document when it does not decode, fails Validate or its version is not its seq; refused is the acknowledgement's entry, its workspace_id null when that cannot be read), keep (a workspace no account document names yet: kept, counted as applied, applied once one does), ignore (a version at or below the one applied), apply; through is where the cursor goes: the page's next_after, past a refused document too. " +
	"gets: a signed answer of the GET computed now for the workspace of the path, and the version the app applied there; status 200 or a signed refusal's code; action: not_found (the platform keeps no document: the last applied holds, frozen, and the app stops asking until a document of the workspace reaches its feed), none (any other signed refusal), refuse (a document that does not decode, fails Validate, or names another app or another workspace than the path's), reset (another generation), ignore (a lower version: a race with the feed), fresh (the same version: nothing changed), apply; fresh: whether it gives the workspace freshness (fresh and apply only). " +
	"sequences: pages and GET answers in turn; held_back: after each step, the workspaces whose freshness from pages is held back: a refused document's, or every workspace the app keeps a document of when its workspace_id cannot be read; each until a valid document of it of a higher version applies from a page, or a GET answer gives it freshness. " +
	"versions: a feed item's document and a GET's answer of the same version; same: byte for byte, except a trim's secret and mac, which differ when a promote falls between the two. " +
	"links: a link the app is asked to make: release (observe, or enforce for a release that enforces this part), held (the document applied there: its mode and new_links, null for none), fresh_minutes (its freshness, null for none), get (the GET's answer when the app asks: doc with get_doc, not_found, or none: no signed answer); asks: whether it asks the GET (no document, or freshness over 60 minutes); the workspace enforces when the document it then holds says enforce, or with none when the release enforces; action refuse_link (a retry) where it enforces and the link would be refused (no answer, or new_links off), else link; logged: a refusal it logs with ids only where it does not enforce. " +
	"resets: what an app holds before a page of another generation and after: the cursor, the stored versions and each workspace's last answered codes_after forgotten; every last applied document (its mode, switches, timeline, places, cap and items) and the app's own per-item stop records kept. " +
	"freeze: a stop to come and what the app does at now with its freshness last given at fresh_at: a timeline step stops at its at; an item's own trial stop (running or used_up alike) only while plan_source is trial or none, at its trial end in Mailie and 72 hours later in Wappie (none otherwise); Wappie's place stop 72 hours after its count first found the item over its places; stops_at is when; action wait (before it), fire (freshness under 24 hours old at stops_at), hold (frozen: 24 hours or more). " +
	"caps: Wappie's cap_bytes, floor(1.05 x cap_quota) - others_bytes, at least 0, cap_quota the quota_bytes but at a boundary (trial_end, ends_at, late_payment_end, buy_by) before the sync step, where it is the quota that last granted (last_granted); Mailie's, its allowance. " +
	"codes_after: send (item.identity_updated for every linked hosted item the document's items do not list) when codes_after is set and later than the last value the app answered for the workspace, else none. " +
	"places: the app's own count before and after a change (total, the licence bindings it counts, its items by placed_at); the bindings take the first places and are never stopped, the items beyond the first total less the bindings stop; action lift, stop or keep. " +
	"trial_stops: an item stopped at its own trial end, the next document applied (plan_source, the item's entry or null); action lift (plan_source plan or live_move, or listed running with a later end), else keep. " +
	"cap_stops: the app's total against the cap_bytes of the last applied document: lift (at or below it, frozen or not) or stop."

func entDocuments(out *WireEntitlements) error {
	base := mustRaw(vecEnt("wappie", nil))
	trialDoc := mustRaw(vecEnt("wappie", onTrial))
	steps := func(n int) []contract.TimelineStep {
		return many(n, func(i int) contract.TimelineStep {
			return contract.TimelineStep{At: at(time.Duration(i+1) * time.Hour), Off: []string{contract.SwitchSync}}
		})
	}
	items := func(n int) []contract.ItemTrial {
		return many(n, func(i int) contract.ItemTrial {
			return contract.ItemTrial{ID: fmt.Sprintf("dev_%d", i+1), Trial: contract.TrialRunning, TrialEndsAt: at(24 * time.Hour)}
		})
	}
	item := func(trial string, d time.Duration) func(*contract.EntitlementsDoc) {
		return func(e *contract.EntitlementsDoc) {
			onTrial(e)
			e.Items = []contract.ItemTrial{{ID: "dev_7", Trial: trial, TrialEndsAt: at(d)}}
		}
	}
	both := func(fs ...func(*contract.EntitlementsDoc)) func(*contract.EntitlementsDoc) {
		return func(d *contract.EntitlementsDoc) {
			for _, f := range fs {
				f(d)
			}
		}
	}
	orderFor := func(mut func(*contract.TrimOrder)) json.RawMessage {
		return signedOrder(vecOrder("wappie", mut), SecretA, 2)
	}
	withTrim := func(raw json.RawMessage) func(*contract.EntitlementsDoc) {
		return func(d *contract.EntitlementsDoc) { expired(d); d.Trim = raw }
	}
	closed := func(d *contract.EntitlementsDoc) {
		d.State = contract.EntitlementsState{Name: contract.WorkspaceClosed, Since: at(-5 * 24 * time.Hour)}
		d.Switches = contract.Switches{API: "off", NewLinks: "off", Sync: "off", Send: "off"}
		d.Timeline = []contract.TimelineStep{}
	}
	timeStr := func(d time.Duration) string { return at(d).Format(time.RFC3339) }
	for _, c := range []struct {
		name  string
		raw   json.RawMessage
		valid bool
	}{
		{"the spec's document: Wappie over its quota, a plan, one step to come", base, true},
		{"Mailie's: its cap its allowance, sync off at once", mustRaw(vecEnt("mailie", nil)), true},
		{"the reference app's", mustRaw(vecEnt(contract.ReferenceApp, nil)), true},
		{"a workspace on trial with no other report kept: others_bytes 0, the allowance 15000000000, Wappie's cap 15750000000", trialDoc, true},
		{"Mailie on trial with no other report kept: its cap 15000000000", mustRaw(vecEnt("mailie", onTrial)), true},
		{"active, observe", mustRaw(vecEnt("wappie", both(active, func(d *contract.EntitlementsDoc) { d.Mode = contract.ModeObserve }))), true},
		{"over_quota no_plan before its first notice: deadline null", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) {
			d.State.Reason, d.State.Deadline = ptr(contract.ReasonNoPlan), nil
			d.Plan = contract.EntitlementsPlan{Source: contract.SourceNone}
			d.Places.Total = 0
			d.Storage.QuotaBytes, d.Storage.AllowanceBytes, d.Storage.CapBytes = 0, 0, 15750000000-1200000000
		})), true},
		{"over_quota on trial: a trial over its 15 GB", mustRaw(vecEnt("wappie", both(onTrial, func(d *contract.EntitlementsDoc) {
			d.State = contract.EntitlementsState{Name: contract.WorkspaceOverQuota, Reason: ptr(contract.ReasonOverQuota), Since: at(-time.Hour),
				TrialEndsAt: ptr(at(13 * 24 * time.Hour))}
		}))), true},
		{"expired", mustRaw(vecEnt("wappie", expired)), true},
		{"closed: every switch off and no step", mustRaw(vecEnt("wappie", closed)), true},
		{"live_move: a test plan in its 30 days to buy", mustRaw(vecEnt("wappie", both(active, func(d *contract.EntitlementsDoc) {
			d.Plan.Source, d.State.BuyBy = contract.SourceLiveMove, ptr(at(20*24*time.Hour))
		}))), true},
		{"a plan bought in live mode: test false", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Plan.Test, d.TestMode = false, false })), true},
		{"a plan with a set end", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Plan.EndsAt = ptr(at(10 * 24 * time.Hour)) })), true},
		{"places counted unknown: the snapshot stale, all four null", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) {
			d.Places.Used, d.Places.UsedConnected, d.Places.Free, d.Places.CountedAt = nil, nil, nil, nil
		})), true},
		{"places over the total: free 0", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) {
			d.Places.Used, d.Places.UsedConnected = ptr[int64](3), ptr[int64](0)
		})), true},
		{"no report kept: used_bytes and measured_through null", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) {
			d.Storage.UsedBytes, d.Storage.MeasuredThrough = nil, nil
		})), true},
		{"others over the quota: the allowance 0", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) {
			d.Storage.OthersBytes, d.Storage.AllowanceBytes, d.Storage.CapBytes = 30000000000, 0, 0
		})), true},
		{"16 steps, the most", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Timeline = steps(contract.MaxTimelineSteps) })), true},
		{"a step turning four switches off", mustRaw(vecEnt("wappie", both(active, func(d *contract.EntitlementsDoc) {
			d.Timeline = []contract.TimelineStep{{At: at(time.Hour), Off: contract.EntitlementSwitches()}}
		}))), true},
		{"1000 items, the most", mustRaw(vecEnt("wappie", both(onTrial, func(d *contract.EntitlementsDoc) { d.Items = items(contract.MaxEntitlementItems) }))), true},
		{"an item running, its clock ending a second after computed_at", mustRaw(vecEnt("wappie", item(contract.TrialRunning, time.Second))), true},
		{"an item used_up at computed_at", mustRaw(vecEnt("wappie", item(contract.TrialUsedUp, 0))), true},
		{"an item used_up a second before computed_at", mustRaw(vecEnt("wappie", item(contract.TrialUsedUp, -time.Second))), true},
		{"an item listed on over_quota with the trial's end set", mustRaw(vecEnt("wappie", both(item(contract.TrialRunning, time.Hour), func(d *contract.EntitlementsDoc) {
			d.State = contract.EntitlementsState{Name: contract.WorkspaceOverQuota, Reason: ptr(contract.ReasonOverQuota), Since: at(-time.Hour),
				TrialEndsAt: ptr(at(13 * 24 * time.Hour))}
		}))), true},
		{"requests at computed_at", mustRaw(vecEnt("wappie", both(onTrial, func(d *contract.EntitlementsDoc) {
			d.Requests = contract.EntitlementsRequests{UsageAfter: ptr(at(0)), CodesAfter: ptr(at(0))}
		}))), true},
		{"codes_after before computed_at", mustRaw(vecEnt("wappie", both(onTrial, func(d *contract.EntitlementsDoc) {
			d.Requests.CodesAfter = ptr(at(-time.Hour))
		}))), true},
		{"a trim order in an expired document that enforces", mustRaw(vecEnt("wappie", withTrim(orderFor(nil)))), true},
		{"a trim order with no floor beside a plan: the document holds, only the order is refused", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) {
			withTrim(orderFor(func(o *contract.TrimOrder) { o.Floor = nil; o.Steps[1].KeepBytes = ptr[int64](0) }))(d)
			d.Plan = contract.EntitlementsPlan{Source: contract.SourcePlan, Test: true, Numbers: 1}
			d.Places.Total, d.Places.Free = 1, ptr[int64](0)
		})), true},
		{"links on the development console", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) {
			d.Links.Plan = "http://console.thehappie.localhost:8290/workspaces/" + vecTeam + "/plan"
		})), true},
		{"a member the app does not know, ignored", edit(base, `"test_mode":true`, `"test_mode":true,"advice":"buy"`), true},
		{"v 2", edit(base, `"v":1`, `"v":2`), false},
		{"type usage", edit(base, `"type":"entitlements"`, `"type":"usage"`), false},
		{"an app the part does not know", mustRaw(vecEnt("vaultie", nil)), false},
		{"a generation that is no UUID", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Generation = "gen-1" })), false},
		{"a workspace_id that is no UUID", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.WorkspaceID = "team-1" })), false},
		{"version 0", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Version = 0 })), false},
		{"version 2^53", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Version = contract.MaxSafeInteger + 1 })), false},
		{"a mode the part does not know", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Mode = "brake" })), false},
		{"a state the part does not know", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.State.Name = "paused" })), false},
		{"over_quota without a reason", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.State.Reason = nil })), false},
		{"a reason the part does not know", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.State.Reason = ptr("late_payment") })), false},
		{"a reason on active", mustRaw(vecEnt("wappie", both(active, func(d *contract.EntitlementsDoc) { d.State.Reason = ptr(contract.ReasonNoPlan) }))), false},
		{"a deadline on expired", mustRaw(vecEnt("wappie", both(expired, func(d *contract.EntitlementsDoc) { d.State.Deadline = ptr(at(-10 * 24 * time.Hour)) }))), false},
		{"a deadline on trial", mustRaw(vecEnt("wappie", both(onTrial, func(d *contract.EntitlementsDoc) { d.State.Deadline = ptr(at(40 * 24 * time.Hour)) }))), false},
		{"expired without expired_since", mustRaw(vecEnt("wappie", both(expired, func(d *contract.EntitlementsDoc) { d.State.ExpiredSince = nil }))), false},
		{"expired_since on over_quota", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.State.ExpiredSince = ptr(at(-time.Hour)) })), false},
		{"trial without trial_ends_at", mustRaw(vecEnt("wappie", both(onTrial, func(d *contract.EntitlementsDoc) { d.State.TrialEndsAt = nil }))), false},
		{"trial_ends_at on active", mustRaw(vecEnt("wappie", both(active, func(d *contract.EntitlementsDoc) { d.State.TrialEndsAt = ptr(at(time.Hour)) }))), false},
		{"trial_ends_at on expired", mustRaw(vecEnt("wappie", both(expired, func(d *contract.EntitlementsDoc) { d.State.TrialEndsAt = ptr(at(time.Hour)) }))), false},
		{"trial_ends_at on closed", mustRaw(vecEnt("wappie", both(closed, func(d *contract.EntitlementsDoc) { d.State.TrialEndsAt = ptr(at(time.Hour)) }))), false},
		{"a plan source the part does not know", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Plan.Source = "gift" })), false},
		{"the trial with two numbers", mustRaw(vecEnt("wappie", both(onTrial, func(d *contract.EntitlementsDoc) { d.Plan.Numbers, d.Places.Total = 2, 2 }))), false},
		{"the trial as a test plan", mustRaw(vecEnt("wappie", both(onTrial, func(d *contract.EntitlementsDoc) { d.Plan.Test = true }))), false},
		{"the trial with a period", mustRaw(vecEnt("wappie", both(onTrial, func(d *contract.EntitlementsDoc) { d.Plan.PeriodEnd = ptr(at(time.Hour)) }))), false},
		{"none with a number", mustRaw(vecEnt("wappie", both(expired, func(d *contract.EntitlementsDoc) { d.Plan.Numbers, d.Places.Total = 1, 1 }))), false},
		{"none with a period", mustRaw(vecEnt("wappie", both(expired, func(d *contract.EntitlementsDoc) { d.Plan.EndsAt = ptr(at(time.Hour)) }))), false},
		{"live_move not a test plan", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Plan.Source, d.Plan.Test = contract.SourceLiveMove, false })), false},
		{"51 numbers", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Plan.Numbers, d.Places.Total = 51, 51 })), false},
		{"packs below 0", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Plan.Packs = -1 })), false},
		{"places of Mailie's kind in Wappie", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Places.Kind = contract.ItemMailbox })), false},
		{"places.total not the plan's numbers", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Places.Total = 3 })), false},
		{"Mailie's places.total its numbers", mustRaw(vecEnt("mailie", func(d *contract.EntitlementsDoc) { d.Places.Total, d.Places.Free = 2, ptr[int64](1) })), false},
		{"used set, free null", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Places.Free = nil })), false},
		{"counted_at null alone", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Places.CountedAt = nil })), false},
		{"used null, the others set", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Places.Used = nil })), false},
		{"free not max(0, total - used)", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Places.Free = ptr[int64](1) })), false},
		{"used_connected over used", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Places.UsedConnected = ptr[int64](3) })), false},
		{"allowance not quota less others", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Storage.AllowanceBytes++ })), false},
		{"allowance below 0 when others pass the quota", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) {
			d.Storage.OthersBytes, d.Storage.AllowanceBytes = 30000000000, -5000000000
		})), false},
		{"others_bytes null", edit(base, `"others_bytes":1200000000`, `"others_bytes":null`), false},
		{"measured_through null beside used_bytes", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Storage.MeasuredThrough = nil })), false},
		{"used_bytes null beside measured_through", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Storage.UsedBytes = nil })), false},
		{"Mailie's cap 105 % of its allowance", mustRaw(vecEnt("mailie", func(d *contract.EntitlementsDoc) { d.Storage.CapBytes = 25050000000 })), false},
		{"a switch the part does not know a value of", edit(base, `"sync":"on","send":"off"}`, `"sync":"paused","send":"off"}`), false},
		{"a switch missing", edit(base, `,"send":"off"}`, `}`), false},
		{"closed with a switch on", mustRaw(vecEnt("wappie", both(closed, func(d *contract.EntitlementsDoc) { d.Switches.API = contract.SwitchOn }))), false},
		{"closed with a step to come", mustRaw(vecEnt("wappie", both(closed, func(d *contract.EntitlementsDoc) {
			d.Timeline = []contract.TimelineStep{{At: at(time.Hour), Off: []string{contract.SwitchSync}}}
		}))), false},
		{"17 steps", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Timeline = steps(contract.MaxTimelineSteps + 1) })), false},
		{"a step at computed_at", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Timeline[0].At = at(0) })), false},
		{"a step before computed_at: it is carried in switches", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Timeline[0].At = at(-time.Hour) })), false},
		{"steps out of order", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) {
			d.Timeline = []contract.TimelineStep{{At: at(2 * time.Hour), Off: []string{contract.SwitchSync}}, {At: at(time.Hour), Off: []string{contract.SwitchSend}}}
		})), false},
		{"two steps at one time", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) {
			d.Timeline = []contract.TimelineStep{{At: at(time.Hour), Off: []string{contract.SwitchSync}}, {At: at(time.Hour), Off: []string{contract.SwitchSend}}}
		})), false},
		{"a step turning a switch on", edit(base, `"timeline":[{"at":"`+timeStr(23*time.Hour)+`","sync":"off"}]`,
			`"timeline":[{"at":"`+timeStr(23*time.Hour)+`","sync":"on"}]`), false},
		{"a step naming no switch", edit(base, `,"sync":"off"}]`, `}]`), false},
		{"a step naming a switch the part does not know", edit(base, `"sync":"off"}]`, `"mcp":"off"}]`), false},
		{"a step naming a switch twice", edit(base, `"sync":"off"}]`, `"sync":"off","sync":"off"}]`), false},
		{"timeline null", edit(base, `"timeline":[{"at":"`+timeStr(23*time.Hour)+`","sync":"off"}]`, `"timeline":null`), false},
		{"1001 items", mustRaw(vecEnt("wappie", both(onTrial, func(d *contract.EntitlementsDoc) { d.Items = items(contract.MaxEntitlementItems + 1) }))), false},
		{"an item twice", mustRaw(vecEnt("wappie", both(item(contract.TrialRunning, time.Hour), func(d *contract.EntitlementsDoc) {
			d.Items = append(d.Items, d.Items[0])
		}))), false},
		{"an item not_needed", mustRaw(vecEnt("wappie", item(contract.TrialNotNeeded, time.Hour))), false},
		{"an item running at computed_at", mustRaw(vecEnt("wappie", item(contract.TrialRunning, 0))), false},
		{"an item running a second before computed_at", mustRaw(vecEnt("wappie", item(contract.TrialRunning, -time.Second))), false},
		{"an item used_up a second after computed_at", mustRaw(vecEnt("wappie", item(contract.TrialUsedUp, time.Second))), false},
		{"an item listed while state.trial_ends_at is null", mustRaw(vecEnt("wappie", both(item(contract.TrialRunning, time.Hour), active))), false},
		{"items null", edit(base, `"items":[]`, `"items":null`), false},
		{"usage_after after computed_at", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Requests.UsageAfter = ptr(at(time.Second)) })), false},
		{"codes_after after computed_at", mustRaw(vecEnt("wappie", both(onTrial, func(d *contract.EntitlementsDoc) { d.Requests.CodesAfter = ptr(at(time.Second)) }))), false},
		{"codes_after while state.trial_ends_at is null", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Requests.CodesAfter = ptr(at(-time.Hour)) })), false},
		{"a trim order in an observe document", mustRaw(vecEnt("wappie", both(withTrim(orderFor(nil)), func(d *contract.EntitlementsDoc) { d.Mode = contract.ModeObserve }))), false},
		{"a trim order outside expired", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Trim = orderFor(nil) })), false},
		{"a trim order naming another workspace", mustRaw(vecEnt("wappie", withTrim(orderFor(func(o *contract.TrimOrder) { o.WorkspaceID = vecWS2 })))), false},
		{"a trim order naming another generation", mustRaw(vecEnt("wappie", withTrim(orderFor(func(o *contract.TrimOrder) { o.Generation = vecGeneration2 })))), false},
		{"a trim order of another app", mustRaw(vecEnt("wappie", withTrim(signedOrder(vecOrder("mailie", nil), SecretA, 2)))), false},
		{"a trim order that is not valid: round 4", mustRaw(vecEnt("wappie", withTrim(orderFor(func(o *contract.TrimOrder) { o.Round = 4 })))), false},
		{"a trim that is no object", mustRaw(vecEnt("wappie", withTrim(json.RawMessage(`"purge everything"`)))), false},
		{"a link over http to another host", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Links.Plan = "http://console.thehappie.co/plan" })), false},
		{"a link with a fragment", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Links.Storage += "#top" })), false},
		{"a link that is relative", mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.Links.Plan = "/workspaces/" + vecTeam + "/plan" })), false},
		{"plan null", edit(base, `"plan":{"source":"plan"`, `"plan":null,"x":{"source":"plan"`), false},
		{"no requests member", edit(base, `"requests":{"usage_after":null,"codes_after":null},`, ``), false},
		{"computed_at written with a zone", edit(base, `"computed_at":"`+timeStr(0)+`"`, `"computed_at":"2026-10-13T09:00:00-03:00"`), false},
		{"a member twice", edit(base, `"mode":"enforce"`, `"mode":"enforce","mode":"observe"`), false},
		{"not an object", json.RawMessage(`[1]`), false},
	} {
		if got := entDocValid(c.raw); got != c.valid {
			return fmt.Errorf("contractvec: document %q is valid %v, the spec asks %v", c.name, got, c.valid)
		}
		out.Documents = append(out.Documents, wireCase(c.name, c.raw, c.valid))
	}
	return nil
}

func entFeeds(out *WireEntitlements) error {
	doc := docAt(vecEnt("wappie", nil), 57)
	page := entPage(vecGeneration, 57, doc)
	empty := entPage(vecGeneration, 57)
	small := json.RawMessage(`{"v":1}`)
	bad := entPage(vecGeneration, 57, small)
	for _, c := range []struct {
		name  string
		raw   json.RawMessage
		valid bool
	}{
		{"a page of one document", page, true},
		{"an empty page at the head", empty, true},
		{"a page of another generation", entPage(vecGeneration2, 57, doc), true},
		{"a page whose document is bad: judged alone, never refusing the page", bad, true},
		{"two documents in rising seq", entPage(vecGeneration, 58, doc, docAt(vecEnt("wappie", func(d *contract.EntitlementsDoc) { d.WorkspaceID = vecWS2 }), 58)), true},
		{"200 documents, the most", entPage(vecGeneration, 200, many(200, func(int) json.RawMessage { return small })...), true},
		{"more pages to come", edit(page, `"more":false`, `"more":true`), true},
		{"201 documents", entPage(vecGeneration, 201, many(201, func(int) json.RawMessage { return small })...), false},
		{"a seq above head", edit(page, `"head":57`, `"head":56`), false},
		{"seq out of order", edit(entPage(vecGeneration, 58, doc, doc), `"seq":57`, `"seq":59`), false},
		{"a seq of 0", edit(entPage(vecGeneration, 0), `"items":[]`, `"items":[{"seq":0,"doc":`+string(doc)+`}]`), false},
		{"next_after above head", edit(page, `"next_after":57`, `"next_after":58`), false},
		{"a generation that is no UUID", edit(page, `"generation":"`+vecGeneration+`","generation_confirmed"`, `"generation":"g","generation_confirmed"`), false},
		{"items null", edit(empty, `"items":[]`, `"items":null`), false},
		{"published_through missing", edit(page, `"published_through":"`+at(4*time.Second).Format(time.RFC3339)+`",`, ``), false},
	} {
		if got := entFeedValid(c.raw); got != c.valid {
			return fmt.Errorf("contractvec: page %q is valid %v, the spec asks %v", c.name, got, c.valid)
		}
		out.Feeds = append(out.Feeds, wireCase(c.name, c.raw, c.valid))
	}

	refusal := func(seq int64, ws, code string) string {
		w := "null"
		if ws != "" {
			w = `"` + ws + `"`
		}
		return fmt.Sprintf(`{"seq":%d,"workspace_id":%s,"code":"%s"}`, seq, w, code)
	}
	refusals := func(n int) string {
		var parts []string
		for i := range n {
			parts = append(parts, refusal(int64(i+1), vecTeam, contract.RefusedInvalidDocument))
		}
		return "[" + joinComma(parts) + "]"
	}
	ack := func(through int64, refused string) json.RawMessage {
		s := fmt.Sprintf(`{"generation":"%s","through":%d`, vecGeneration, through)
		if refused != "" {
			s += `,"refused":` + refused
		}
		return json.RawMessage(s + "}")
	}
	for _, c := range []struct {
		name  string
		raw   json.RawMessage
		valid bool
	}{
		{"every document up to 57", ack(57, ""), true},
		{"through 0: nothing yet", ack(0, ""), true},
		{"a bad document refused", ack(57, "["+refusal(55, vecTeam, contract.RefusedInvalidDocument)+"]"), true},
		{"a bad document whose workspace_id cannot be read", ack(57, "["+refusal(56, "", contract.RefusedInvalidDocument)+"]"), true},
		{"another app's document", ack(57, "["+refusal(57, vecTeam, contract.RefusedAnotherApp)+"]"), true},
		{"another generation's document", ack(57, "["+refusal(57, vecWS2, contract.RefusedAnotherGeneration)+"]"), true},
		{"20 refused, the most", ack(57, refusals(20)), true},
		{"21 refused", ack(57, refusals(21)), false},
		{"refused []", ack(57, "[]"), false},
		{"refused null", ack(57, "null"), false},
		{"a refused seq above through", ack(57, "["+refusal(58, vecTeam, contract.RefusedInvalidDocument)+"]"), false},
		{"a refused seq of 0", ack(57, "["+refusal(0, vecTeam, contract.RefusedInvalidDocument)+"]"), false},
		{"a refused seq twice", ack(57, "["+refusal(5, vecTeam, contract.RefusedInvalidDocument)+","+refusal(5, vecWS2, contract.RefusedAnotherApp)+"]"), false},
		{"a refused code the part does not know", ack(57, "["+refusal(5, vecTeam, "invalid_record")+"]"), false},
		{"a refused workspace_id that is no UUID", ack(57, "["+refusal(5, "team-1", contract.RefusedInvalidDocument)+"]"), false},
		{"a refused entry without workspace_id", ack(57, `[{"seq":5,"code":"invalid_document"}]`), false},
		{"through below 0", ack(-1, ""), false},
		{"a generation that is no UUID", json.RawMessage(`{"generation":"g","through":57}`), false},
		{"through null", json.RawMessage(`{"generation":"` + vecGeneration + `","through":null}`), false},
		{"a member the part does not know", json.RawMessage(`{"generation":"` + vecGeneration + `","through":57,"waiting":[]}`), false},
		{"through twice", json.RawMessage(`{"generation":"` + vecGeneration + `","through":57,"through":58}`), false},
	} {
		if got := entAppliedValid(c.raw); got != c.valid {
			return fmt.Errorf("contractvec: acknowledgement %q is valid %v, the spec asks %v", c.name, got, c.valid)
		}
		out.Applied = append(out.Applied, wireCase(c.name, c.raw, c.valid))
	}
	return nil
}

func joinComma(parts []string) string {
	var b bytes.Buffer
	for i, p := range parts {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(p)
	}
	return b.String()
}

func entBehaviour(out *WireEntitlements) error {
	known := []string{vecTeam, vecWS2}
	held := map[string]int64{vecTeam: 50, vecWS2: 40}
	doc := func(v int64, mut func(*contract.EntitlementsDoc)) json.RawMessage {
		return docAt(vecEnt("wappie", mut), v)
	}
	inWS := func(ws string) func(*contract.EntitlementsDoc) {
		return func(d *contract.EntitlementsDoc) { d.WorkspaceID = ws }
	}
	page := func(gen string, seq int64, raw json.RawMessage) json.RawMessage { return entPage(gen, seq, raw) }
	unreadable := edit(doc(57, nil), `"workspace_id":"`+vecTeam+`"`, `"workspace_id":7`)
	for _, c := range []struct {
		name   string
		value  json.RawMessage
		known  []string
		action string
	}{
		{"a document of a higher version: applied", page(vecGeneration, 57, doc(57, nil)), known, "apply"},
		{"a document of the version applied: ignored", page(vecGeneration, 50, doc(50, nil)), known, "ignore"},
		{"a document of a lower version: ignored", page(vecGeneration, 45, doc(45, nil)), known, "ignore"},
		{"a document an app observes only: applied all the same", page(vecGeneration, 57, doc(57, func(d *contract.EntitlementsDoc) { d.Mode = contract.ModeObserve })), known, "apply"},
		{"a document of a workspace no account document names yet: kept and acknowledged", page(vecGeneration, 57, doc(57, inWS(vecWS3))), known, "keep"},
		{"a document that does not decode: refused invalid_document", page(vecGeneration, 57, edit(doc(57, nil), `"links":{`, `"links":null,"x":{`)), known, "refuse"},
		{"a document that fails Validate: refused invalid_document", page(vecGeneration, 57, doc(57, func(d *contract.EntitlementsDoc) { d.Storage.AllowanceBytes++ })), known, "refuse"},
		{"a document whose version is not its seq: refused invalid_document", edit(page(vecGeneration, 57, doc(57, nil)), `"seq":57`, `"seq":56`), known, "refuse"},
		{"a trim order in an observe document: refused, nothing of it run", page(vecGeneration, 57, doc(57, func(d *contract.EntitlementsDoc) {
			expired(d)
			d.Trim = signedOrder(vecOrder("wappie", nil), SecretA, 2)
			d.Mode = contract.ModeObserve
		})), known, "refuse"},
		{"another app's document: refused another_app", page(vecGeneration, 57, docAt(vecEnt("mailie", nil), 57)), known, "refuse"},
		{"a document of another generation in a page of the app's: refused another_generation, never a reset", page(vecGeneration, 57,
			doc(57, func(d *contract.EntitlementsDoc) { d.Generation = vecGeneration2 })), known, "refuse"},
		{"a bad document whose workspace_id cannot be read: refused with workspace_id null", page(vecGeneration, 57, unreadable), known, "refuse"},
		{"a page of another generation: a reset, whatever its document", page(vecGeneration2, 3, doc(3, func(d *contract.EntitlementsDoc) { d.Generation = vecGeneration2 })), known, "reset"},
		{"a page of another generation whose document names the app's generation: a reset", page(vecGeneration2, 57, doc(57, nil)), known, "reset"},
		{"a page of another generation whose document is bad: a reset", page(vecGeneration2, 57, json.RawMessage(`{"v":1}`)), known, "reset"},
		{"a page that does not validate", edit(page(vecGeneration, 57, doc(57, nil)), `"head":57`, `"head":56`), known, "invalid"},
	} {
		pc := EntPageCase{Name: c.name, App: "wappie", Generation: vecGeneration, Known: c.known, Held: held, Value: c.value}
		action, ref, through := entPageAction(pc)
		if action != c.action {
			return fmt.Errorf("contractvec: page %q is %s, the spec asks %s", c.name, action, c.action)
		}
		pc.Action, pc.Refused, pc.Through = action, ref, through
		out.Actions = append(out.Actions, pc)
	}
	// The codes of the refused entries, each once at least.
	codes := map[string]bool{}
	for _, a := range out.Actions {
		if a.Refused != nil {
			codes[a.Refused.Code] = true
		}
	}
	for _, code := range contract.EntitlementsRefusalCodes() {
		if !codes[code] {
			return fmt.Errorf("contractvec: no page refuses a document %s", code)
		}
	}

	for _, c := range []struct {
		name, ws, status string
		value            json.RawMessage
		action           string
	}{
		{"a higher version: applied, fresh", vecTeam, "200", doc(57, nil), "apply"},
		{"the version applied: nothing changed, fresh", vecTeam, "200", doc(50, nil), "fresh"},
		{"a lower version, a race with the feed: no freshness", vecTeam, "200", doc(49, nil), "ignore"},
		{"another app's document under a signature that holds: refused, no freshness", vecTeam, "200", docAt(vecEnt("mailie", nil), 57), "refuse"},
		{"another workspace's document: refused, no freshness", vecTeam, "200", doc(57, inWS(vecWS2)), "refuse"},
		{"a document that fails Validate: refused, no freshness", vecTeam, "200", doc(57, func(d *contract.EntitlementsDoc) { d.Places.Free = nil }), "refuse"},
		{"another generation's document: a reset", vecTeam, "200", doc(3, func(d *contract.EntitlementsDoc) { d.Generation = vecGeneration2 }), "reset"},
		{"a signed rate_limited: no freshness", vecTeam, contract.CodeRateLimited, json.RawMessage(`{"error":{"code":"rate_limited","message":"too many requests"}}`), "none"},
		{"a signed unavailable: no freshness", vecTeam, "unavailable", json.RawMessage(`{"error":{"code":"unavailable","message":"try again"}}`), "none"},
		{"a signed not_found: the last document holds, frozen", vecTeam, contract.CodeNotFound, json.RawMessage(`{"error":{"code":"not_found","message":"not found"}}`), "not_found"},
	} {
		gc := EntGetCase{Name: c.name, App: "wappie", Generation: vecGeneration, Workspace: c.ws, Held: held[c.ws], Status: c.status, Value: c.value}
		action, fresh := entGetAction(gc)
		if action != c.action {
			return fmt.Errorf("contractvec: GET %q is %s, the spec asks %s", c.name, action, c.action)
		}
		gc.Action, gc.Fresh = action, fresh
		out.Gets = append(out.Gets, gc)
	}

	for _, c := range []struct {
		name  string
		steps []EntStep
		want  [][]string
	}{
		{"a bad document whose workspace_id cannot be read holds back every workspace until its own GET or document", []EntStep{
			{Source: "page", Value: page(vecGeneration, 57, unreadable)},
			{Source: "get", Workspace: vecTeam, Status: "200", Value: doc(50, nil)},
			{Source: "page", Value: page(vecGeneration, 58, doc(58, inWS(vecWS2)))},
		}, [][]string{{vecWS2, vecTeam}, {vecWS2}, {}}},
		{"a document refused another_generation, then its GET answering a new version", []EntStep{
			{Source: "page", Value: page(vecGeneration, 57, doc(57, func(d *contract.EntitlementsDoc) { d.Generation = vecGeneration2 }))},
			{Source: "get", Workspace: vecTeam, Status: "200", Value: doc(58, nil)},
		}, [][]string{{vecTeam}, {}}},
		{"after a bad document, the version applied again from a page gives nothing back; a GET of it does", []EntStep{
			{Source: "page", Value: page(vecGeneration, 57, doc(57, func(d *contract.EntitlementsDoc) { d.Places.Free = nil }))},
			{Source: "page", Value: page(vecGeneration, 50, doc(50, nil))},
			{Source: "get", Workspace: vecTeam, Status: contract.CodeRateLimited, Value: json.RawMessage(`{"error":{"code":"rate_limited","message":"too many requests"}}`)},
			{Source: "get", Workspace: vecTeam, Status: "200", Value: doc(50, nil)},
		}, [][]string{{vecTeam}, {vecTeam}, {vecTeam}, {}}},
	} {
		seq := EntSequence{Name: c.name, App: "wappie", Generation: vecGeneration, Known: known, Held: held, Steps: c.steps}
		steps, err := entSequence(seq)
		if err != nil {
			return err
		}
		for i, st := range steps {
			if !slices.Equal(st.HeldBack, c.want[i]) {
				return fmt.Errorf("contractvec: sequence %q step %d holds back %v, the spec asks %v", c.name, i+1, st.HeldBack, c.want[i])
			}
		}
		seq.Steps = steps
		out.Sequences = append(out.Sequences, seq)
	}
	// The first step of the second sequence holds the page back without
	// a reset: the case the spec names.
	if out.Sequences[1].Steps[0].Action != "refuse" || out.Sequences[1].Steps[1].Action != "apply" {
		return fmt.Errorf("contractvec: another_generation's sequence is not refuse then apply")
	}

	trimDoc := func(secret string, gen int64, mut func(*contract.EntitlementsDoc)) json.RawMessage {
		return docAt(vecEnt("wappie", func(d *contract.EntitlementsDoc) {
			expired(d)
			d.Trim = signedOrder(vecOrder("wappie", nil), secret, gen)
			if mut != nil {
				mut(d)
			}
		}), 57)
	}
	for _, c := range []VersionCase{
		{Name: "the same version from the feed and the GET: byte for byte", Feed: doc(57, nil), Get: doc(57, nil), Same: true},
		{Name: "across a promote: only the trim's secret and mac differ", Feed: trimDoc(SecretA, 2, nil), Get: trimDoc(SecretB, 3, nil), Same: true},
		{Name: "a switch differs: not the same document, a platform fault", Feed: doc(57, nil), Get: doc(57, active), Same: false},
		{Name: "the trim's steps differ: not the same order", Feed: trimDoc(SecretA, 2, nil), Get: docAt(vecEnt("wappie", func(d *contract.EntitlementsDoc) {
			expired(d)
			d.Trim = signedOrder(vecOrder("wappie", func(o *contract.TrimOrder) { o.Steps = o.Steps[:1] }), SecretA, 2)
		}), 57), Same: false},
	} {
		if got := sameVersion(c.Feed, c.Get); got != c.Same {
			return fmt.Errorf("contractvec: versions %q are the same %v, the spec asks %v", c.Name, got, c.Same)
		}
		out.Versions = append(out.Versions, c)
	}

	minutes := func(n int) *int { return &n }
	enf := &LinkDoc{Mode: contract.ModeEnforce, NewLinks: contract.SwitchOn}
	obs := &LinkDoc{Mode: contract.ModeObserve, NewLinks: contract.SwitchOn}
	enfOff := &LinkDoc{Mode: contract.ModeEnforce, NewLinks: contract.SwitchOff}
	obsOff := &LinkDoc{Mode: contract.ModeObserve, NewLinks: contract.SwitchOff}
	for _, c := range []LinkCase{
		{Name: "a fresh enforce document, new links on", Release: "enforce", Held: enf, FreshMinutes: minutes(5), Action: "link"},
		{Name: "a fresh enforce document, new links off", Release: "enforce", Held: enfOff, FreshMinutes: minutes(5), Action: "refuse_link"},
		{Name: "a fresh observe document, new links off: logged, linked", Release: "enforce", Held: obsOff, FreshMinutes: minutes(5), Action: "link", Logged: true},
		{Name: "freshness of exactly an hour: no GET", Release: "enforce", Held: enf, FreshMinutes: minutes(60), Action: "link"},
		{Name: "freshness over an hour, the GET answering enforce", Release: "enforce", Held: enf, FreshMinutes: minutes(61), Get: "doc", GetDoc: enf, Asks: true, Action: "link"},
		{Name: "freshness over an hour, the GET answering enforce with new links off", Release: "observe", Held: obs, FreshMinutes: minutes(61), Get: "doc", GetDoc: enfOff, Asks: true, Action: "refuse_link"},
		{Name: "freshness over an hour, the GET answering observe", Release: "enforce", Held: enf, FreshMinutes: minutes(90), Get: "doc", GetDoc: obsOff, Asks: true, Action: "link", Logged: true},
		{Name: "freshness over an hour, no answer, the workspace enforcing", Release: "observe", Held: enf, FreshMinutes: minutes(120), Get: "none", Asks: true, Action: "refuse_link"},
		{Name: "freshness over an hour, no answer, the workspace observing", Release: "enforce", Held: obs, FreshMinutes: minutes(120), Get: "none", Asks: true, Action: "link", Logged: true},
		{Name: "freshness over an hour, a signed not_found, the workspace enforcing", Release: "enforce", Held: enf, FreshMinutes: minutes(120), Get: "not_found", Asks: true, Action: "refuse_link"},
		{Name: "freshness over an hour, a signed not_found, the workspace observing", Release: "enforce", Held: obs, FreshMinutes: minutes(120), Get: "not_found", Asks: true, Action: "link", Logged: true},
		{Name: "no document held, the GET answering enforce", Release: "observe", Get: "doc", GetDoc: enf, Asks: true, Action: "link"},
		{Name: "no document held, the GET answering observe", Release: "enforce", Get: "doc", GetDoc: obs, Asks: true, Action: "link"},
		{Name: "no document held, no answer, at a release that enforces", Release: "enforce", Get: "none", Asks: true, Action: "refuse_link"},
		{Name: "no document held, no answer, at a release that observes", Release: "observe", Get: "none", Asks: true, Action: "link", Logged: true},
		{Name: "no document held, a signed not_found, at a release that enforces", Release: "enforce", Get: "not_found", Asks: true, Action: "refuse_link"},
		{Name: "no document held, a signed not_found, at a release that observes", Release: "observe", Get: "not_found", Asks: true, Action: "link", Logged: true},
	} {
		asks, action, logged := linkDecision(c)
		if asks != c.Asks || action != c.Action || logged != c.Logged {
			return fmt.Errorf("contractvec: link %q: asks %v, %s, logged %v; the spec asks %v, %s, %v", c.Name, asks, action, logged, c.Asks, c.Action, c.Logged)
		}
		out.Links = append(out.Links, c)
	}

	pending := doc(57, nil)
	before := AppState{Generation: vecGeneration, Cursor: 57, Versions: map[string]int64{vecTeam: 57, vecWS2: 40},
		Applied: map[string]json.RawMessage{vecTeam: pending}, Stops: []ItemStop{},
		CodesAfter: map[string]string{vecTeam: at(-time.Hour).Format(time.RFC3339)}}
	stopped := before
	stopped.Stops = []ItemStop{{Item: "dev_7", Cause: "item_trial", At: at(2 * time.Hour).Format(time.RFC3339)},
		{Item: "dev_8", Cause: "places", At: at(-time.Hour).Format(time.RFC3339)}}
	for _, c := range []struct {
		name   string
		before AppState
	}{
		{"a reset keeps a pending step: Wappie's sync at since + 72 h", before},
		{"a reset keeps an item's own stop records and forgets codes_after", stopped},
	} {
		after := entReset(c.before, vecGeneration2)
		if after.Cursor != 0 || len(after.Versions) != 0 || len(after.CodesAfter) != 0 || !maps.EqualFunc(after.Applied, c.before.Applied, func(a, b json.RawMessage) bool {
			return bytes.Equal(a, b)
		}) || !slices.Equal(after.Stops, c.before.Stops) {
			return fmt.Errorf("contractvec: reset %q", c.name)
		}
		out.Resets = append(out.Resets, ResetCase{Name: c.name, Before: c.before, Generation: vecGeneration2, After: after, Action: "reset"})
	}

	t := func(d time.Duration) string { return at(d).Format(time.RFC3339) }
	src := func(s string) *string { return &s }
	for _, c := range []FreezeCase{
		{Name: "a step whose time has come, freshness an hour old: it fires", App: "wappie", Cause: "timeline", At: t(0), Now: t(0), FreshAt: t(-time.Hour), Action: "fire"},
		{Name: "a step to come: wait", App: "wappie", Cause: "timeline", At: t(time.Hour), Now: t(0), FreshAt: t(-time.Hour), Action: "wait"},
		{Name: "freshness 23 h 59 min old at the step: it fires", App: "mailie", Cause: "timeline", At: t(0), Now: t(time.Minute), FreshAt: t(-(23*time.Hour + 59*time.Minute)), Action: "fire"},
		{Name: "freshness 24 h old at the step: frozen, it holds", App: "mailie", Cause: "timeline", At: t(0), Now: t(time.Minute), FreshAt: t(-24 * time.Hour), Action: "hold"},
		{Name: "a long outage: a step two days on holds", App: "wappie", Cause: "timeline", At: t(48 * time.Hour), Now: t(49 * time.Hour), FreshAt: t(0), Action: "hold"},
		{Name: "a step announced fires through a short outage", App: "wappie", Cause: "timeline", At: t(20 * time.Hour), Now: t(21 * time.Hour), FreshAt: t(0), Action: "fire"},
		{Name: "Mailie's item running stops at its trial's end", App: "mailie", Cause: "item_trial", At: t(0), PlanSource: src(contract.SourceTrial), Trial: src(contract.TrialRunning), Now: t(0), FreshAt: t(-time.Hour), Action: "fire"},
		{Name: "Mailie's item used_up stops at its trial's end too", App: "mailie", Cause: "item_trial", At: t(-time.Hour), PlanSource: src(contract.SourceTrial), Trial: src(contract.TrialUsedUp), Now: t(0), FreshAt: t(-2 * time.Hour), Action: "fire"},
		{Name: "Wappie's item at its trial's end: 72 hours to come", App: "wappie", Cause: "item_trial", At: t(0), PlanSource: src(contract.SourceTrial), Trial: src(contract.TrialRunning), Now: t(0), FreshAt: t(-time.Hour), Action: "wait"},
		{Name: "Wappie's item 72 hours after its trial's end", App: "wappie", Cause: "item_trial", At: t(-72 * time.Hour), PlanSource: src(contract.SourceNone), Trial: src(contract.TrialUsedUp), Now: t(0), FreshAt: t(-time.Hour), Action: "fire"},
		{Name: "an item's trial stop under the freeze holds", App: "mailie", Cause: "item_trial", At: t(0), PlanSource: src(contract.SourceTrial), Trial: src(contract.TrialRunning), Now: t(time.Hour), FreshAt: t(-30 * time.Hour), Action: "hold"},
		{Name: "an item's trial stop with a plan that grants: no stop", App: "mailie", Cause: "item_trial", At: t(0), PlanSource: src(contract.SourcePlan), Trial: src(contract.TrialUsedUp), Now: t(0), FreshAt: t(-time.Hour), Action: "none"},
		{Name: "an item's trial stop in a live move: no stop", App: "wappie", Cause: "item_trial", At: t(-80 * time.Hour), PlanSource: src(contract.SourceLiveMove), Trial: src(contract.TrialUsedUp), Now: t(0), FreshAt: t(-time.Hour), Action: "none"},
		{Name: "Wappie's place stop 72 hours after its count found the item over", App: "wappie", Cause: "places", At: t(-72 * time.Hour), Now: t(0), FreshAt: t(-time.Hour), Action: "fire"},
		{Name: "Wappie's place stop under the freeze holds", App: "wappie", Cause: "places", At: t(-72 * time.Hour), Now: t(0), FreshAt: t(-25 * time.Hour), Action: "hold"},
	} {
		stops, action, err := freezeAction(c)
		if err != nil {
			return err
		}
		if action != c.Action {
			return fmt.Errorf("contractvec: freeze %q is %s, the spec asks %s", c.Name, action, c.Action)
		}
		c.StopsAt = stops
		out.Freeze = append(out.Freeze, c)
	}

	for _, c := range []CapCase{
		{Name: "on trial, no other report kept", App: "wappie", QuotaBytes: 15000000000, CapBytes: 15750000000},
		{Name: "a trial's end, before the sync step: the trial's 15 GB", App: "wappie", Boundary: "trial_end", LastGranted: 15000000000, BeforeSyncStep: true, CapBytes: 15750000000},
		{Name: "a trial's end, after the sync step: 0", App: "wappie", Boundary: "trial_end", LastGranted: 15000000000, CapBytes: 0},
		{Name: "a set ends_at, before the sync step: the ended plan's quota", App: "wappie", Boundary: "ends_at", LastGranted: 25000000000, OthersBytes: 1200000000, BeforeSyncStep: true, CapBytes: 25050000000},
		{Name: "a set ends_at, after the sync step", App: "wappie", Boundary: "ends_at", LastGranted: 25000000000, OthersBytes: 1200000000, CapBytes: 0},
		{Name: "the 14 days' end, before the sync step", App: "wappie", Boundary: "late_payment_end", LastGranted: 10000000000, BeforeSyncStep: true, CapBytes: 10500000000},
		{Name: "buy_by, before the sync step", App: "wappie", Boundary: "buy_by", LastGranted: 60000000000, OthersBytes: 500000000, BeforeSyncStep: true, CapBytes: 62500000000},
		{Name: "buy_by, after the sync step", App: "wappie", Boundary: "buy_by", LastGranted: 60000000000, OthersBytes: 500000000, CapBytes: 0},
		{Name: "a quota episode: the quota itself", App: "wappie", QuotaBytes: 25000000000, OthersBytes: 1200000000, CapBytes: 25050000000},
		{Name: "105 % rounded down", App: "wappie", QuotaBytes: 25000000001, CapBytes: 26250000001},
		{Name: "others past 105 %: 0", App: "wappie", QuotaBytes: 10000000000, OthersBytes: 11000000000, CapBytes: 0},
		{Name: "Mailie's: its allowance, at a boundary too", App: "mailie", Boundary: "trial_end", LastGranted: 15000000000, OthersBytes: 1000000000, BeforeSyncStep: true, CapBytes: 0},
		{Name: "Mailie's with a plan", App: "mailie", QuotaBytes: 25000000000, OthersBytes: 1200000000, CapBytes: 23800000000},
	} {
		if got := capBytes(c); got != c.CapBytes {
			return fmt.Errorf("contractvec: cap %q is %d, the spec asks %d", c.Name, got, c.CapBytes)
		}
		out.Caps = append(out.Caps, c)
	}

	for _, c := range []CodesAfterCase{
		{Name: "set, none answered yet", CodesAfter: src(t(-time.Hour)), Action: "send"},
		{Name: "later than the last answered", LastAnswered: src(t(-2 * time.Hour)), CodesAfter: src(t(-time.Hour)), Action: "send"},
		{Name: "equal to the last answered", LastAnswered: src(t(-time.Hour)), CodesAfter: src(t(-time.Hour)), Action: "none"},
		{Name: "earlier than the last answered", LastAnswered: src(t(-time.Hour)), CodesAfter: src(t(-2 * time.Hour)), Action: "none"},
		{Name: "null", LastAnswered: src(t(-time.Hour)), Action: "none"},
		{Name: "after a reset forgot the last answered", CodesAfter: src(t(-2 * time.Hour)), Action: "send"},
	} {
		if got := codesAfterAction(c); got != c.Action {
			return fmt.Errorf("contractvec: codes_after %q is %s, the spec asks %s", c.Name, got, c.Action)
		}
		out.CodesAfter = append(out.CodesAfter, c)
	}

	p := func(id string, d time.Duration) Placed { return Placed{ID: id, PlacedAt: t(d)} }
	three := []Placed{p("dev_1", -72*time.Hour), p("dev_2", -48*time.Hour), p("dev_3", -24*time.Hour)}
	for _, c := range []PlacesCase{
		{Name: "a deletion frees a place: the stopped item resumes", App: "wappie",
			Before: PlacesCount{Total: 2, Items: three}, After: PlacesCount{Total: 2, Items: []Placed{three[1], three[2]}}, Action: "lift"},
		{Name: "a purge frees a place", App: "mailie",
			Before: PlacesCount{Total: 1, Items: []Placed{p("acc_1", -48*time.Hour), p("acc_2", -24*time.Hour)}},
			After:  PlacesCount{Total: 1, Items: []Placed{p("acc_2", -24*time.Hour)}}, Action: "lift"},
		{Name: "a move out frees a place", App: "wappie",
			Before: PlacesCount{Total: 2, Items: three}, After: PlacesCount{Total: 2, Items: []Placed{three[0], three[2]}}, Action: "lift"},
		{Name: "a higher total frees a place", App: "wappie",
			Before: PlacesCount{Total: 2, Items: three}, After: PlacesCount{Total: 3, Items: three}, Action: "lift"},
		{Name: "one place freed: the earliest placed_at resumes first", App: "wappie",
			Before: PlacesCount{Total: 1, Items: three}, After: PlacesCount{Total: 2, Items: three}, Action: "lift"},
		{Name: "a licence binding released frees a place", App: "wappie",
			Before: PlacesCount{Total: 2, Bindings: 1, Items: three[:2]}, After: PlacesCount{Total: 2, Items: three[:2]}, Action: "lift"},
		{Name: "a reserved binding expired frees a place", App: "wappie",
			Before: PlacesCount{Total: 3, Bindings: 2, Items: three}, After: PlacesCount{Total: 3, Bindings: 1, Items: three}, Action: "lift"},
		{Name: "a licence binding counted: the hosted items placed last stop", App: "wappie",
			Before: PlacesCount{Total: 3, Items: three}, After: PlacesCount{Total: 3, Bindings: 1, Items: three}, Action: "stop"},
		{Name: "bindings over the total stop every hosted item", App: "wappie",
			Before: PlacesCount{Total: 2, Items: three[:2]}, After: PlacesCount{Total: 2, Bindings: 3, Items: three[:2]}, Action: "stop"},
		{Name: "a link within the places stops nothing", App: "mailie",
			Before: PlacesCount{Total: 2, Items: []Placed{p("acc_1", -48*time.Hour)}},
			After:  PlacesCount{Total: 2, Items: []Placed{p("acc_1", -48*time.Hour), p("acc_2", 0)}}, Action: "keep"},
		{Name: "a recovery over the places comes back stopped", App: "mailie",
			Before: PlacesCount{Total: 1, Items: []Placed{p("acc_1", -48*time.Hour)}},
			After:  PlacesCount{Total: 1, Items: []Placed{p("acc_1", -48*time.Hour), p("acc_2", 0)}}, Action: "stop"},
	} {
		c.StoppedBefore, c.StoppedAfter = placesStopped(c.Before), placesStopped(c.After)
		if got := placesAction(c.StoppedBefore, c.StoppedAfter); got != c.Action {
			return fmt.Errorf("contractvec: places %q is %s, the spec asks %s", c.Name, got, c.Action)
		}
		out.Places = append(out.Places, c)
	}
	// The earliest placed_at resumes first.
	if !slices.Equal(out.Places[4].StoppedAfter, []string{"dev_3"}) {
		return fmt.Errorf("contractvec: the earliest placed_at does not resume first")
	}

	entry := func(trial string, d time.Duration) *contract.ItemTrial {
		return &contract.ItemTrial{ID: "dev_7", Trial: trial, TrialEndsAt: at(d)}
	}
	for _, c := range []TrialStopCase{
		{Name: "a plan that grants lifts it", StoppedAt: t(-time.Hour), PlanSource: contract.SourcePlan, Action: "lift"},
		{Name: "a live move lifts it", StoppedAt: t(-time.Hour), PlanSource: contract.SourceLiveMove, Action: "lift"},
		{Name: "listed running with a later end lifts it", StoppedAt: t(-time.Hour), PlanSource: contract.SourceTrial, Entry: entry(contract.TrialRunning, 24*time.Hour), Action: "lift"},
		{Name: "a document that only stops listing the item lifts nothing", StoppedAt: t(-time.Hour), PlanSource: contract.SourceNone, Action: "keep"},
		{Name: "listed used_up lifts nothing", StoppedAt: t(-time.Hour), PlanSource: contract.SourceTrial, Entry: entry(contract.TrialUsedUp, -time.Hour), Action: "keep"},
		{Name: "listed running with the same end lifts nothing", StoppedAt: t(time.Hour), PlanSource: contract.SourceTrial, Entry: entry(contract.TrialRunning, time.Hour), Action: "keep"},
	} {
		if got := trialStopAction(c); got != c.Action {
			return fmt.Errorf("contractvec: trial stop %q is %s, the spec asks %s", c.Name, got, c.Action)
		}
		out.TrialStops = append(out.TrialStops, c)
	}

	for _, c := range []CapStopCase{
		{Name: "back at the cap: stores again", Total: 15750000000, CapBytes: 15750000000, Action: "lift"},
		{Name: "below the cap: stores again, frozen or not", Total: 15000000000, CapBytes: 15750000000, Action: "lift"},
		{Name: "a byte over the cap: stores nothing new", Total: 15750000001, CapBytes: 15750000000, Action: "stop"},
	} {
		if got := capStopAction(c); got != c.Action {
			return fmt.Errorf("contractvec: cap stop %q is %s, the spec asks %s", c.Name, got, c.Action)
		}
		out.CapStops = append(out.CapStops, c)
	}
	return nil
}
