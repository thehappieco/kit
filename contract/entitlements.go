package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

// The entitlements part (SPEC section 11.20): the platform tells each app
// what a workspace may do in it, one document per (app, workspace named to
// it), on a fourth feed with its own acknowledgement, and computed now by a
// GET. The platform computes; the app enforces locally and keeps working
// on its last valid document.

// The values of an entitlements document.
const (
	EntitlementsV    = 1
	EntitlementsType = "entitlements"

	// ModeObserve: the app compares and logs only. ModeEnforce: it
	// enforces the document.
	ModeObserve = "observe"
	ModeEnforce = "enforce"

	// The workspace's states (state.name): 0016's four, and closed for a
	// closed team.
	WorkspaceActive    = "active"
	WorkspaceTrial     = "trial"
	WorkspaceOverQuota = "over_quota"
	WorkspaceExpired   = "expired"
	WorkspaceClosed    = "closed"

	// Why a workspace is over_quota or expired (state.reason).
	ReasonOverQuota = "over_quota"
	ReasonNoPlan    = "no_plan"

	// Where the plan in force comes from (plan.source): a plan that counts
	// as paid, the trial, a test plan in its 30 days after test plans stop
	// granting, or nothing.
	SourcePlan     = "plan"
	SourceTrial    = "trial"
	SourceLiveMove = "live_move"
	SourceNone     = "none"

	// The four switches, what a pause stops, and their two values.
	SwitchAPI      = "api"
	SwitchNewLinks = "new_links"
	SwitchSync     = "sync"
	SwitchSend     = "send"
	SwitchOn       = "on"
	SwitchOff      = "off"

	// An item's own trial (items[].trial). An item the document does not
	// list reads as TrialNotNeeded, which an entry never carries, so that
	// meaning has one spelling; the link check's answer spells it.
	TrialRunning   = "running"
	TrialUsedUp    = "used_up"
	TrialNotNeeded = "not_needed"
)

// The bounds of the entitlements part.
const (
	// MaxTimelineSteps is the most steps a document's timeline holds.
	MaxTimelineSteps = 16
	// MaxEntitlementItems is the most item trials a document lists.
	MaxEntitlementItems = 1000
	// MaxPlanCount is the most numbers, mailboxes or packs a plan holds.
	MaxPlanCount = 50
	// MaxEntitlementsFeedItems is the most documents one page of the
	// entitlements feed carries; a page also ends before 4 MiB.
	MaxEntitlementsFeedItems = 200
	// MaxEntitlementsWaiting is the most entitlements feed requests of one
	// app that wait at once, apart from the other three feeds; a fifth is
	// a signed rate_limited.
	MaxEntitlementsWaiting = 4
	// MaxAppliedRefused is the most bad documents one acknowledgement
	// lists; more go in the acknowledgements that follow.
	MaxAppliedRefused = 20
	// EntitlementsAppliedLimit is the body limit of
	// POST /contract/v1/entitlements/applied.
	EntitlementsAppliedLimit = 4 << 10
	// MaxSafeInteger is the largest integer the part carries: 2^53 - 1,
	// what every JSON reader holds exactly.
	MaxSafeInteger = 1<<53 - 1
)

// switchNames are the four switches, in the wire's order.
var switchNames = []string{SwitchAPI, SwitchNewLinks, SwitchSync, SwitchSend}

// EntitlementSwitches are the four switches, in the wire's order: api,
// new_links, sync, send. It returns a copy: the set Validate checks is
// closed.
func EntitlementSwitches() []string { return slices.Clone(switchNames) }

var (
	workspaceStates = []string{WorkspaceActive, WorkspaceTrial, WorkspaceOverQuota, WorkspaceExpired, WorkspaceClosed}
	planSources     = []string{SourcePlan, SourceTrial, SourceLiveMove, SourceNone}
)

// WorkspaceStates are a document's state.name values. It returns a copy.
func WorkspaceStates() []string { return slices.Clone(workspaceStates) }

// PlanSources are a document's plan.source values. It returns a copy.
func PlanSources() []string { return slices.Clone(planSources) }

// AppItemKind is the kind of item app holds, which its places count:
// Wappie's and the reference app's number, Mailie's mailbox. An app the
// part does not know has none.
func AppItemKind(app string) (string, bool) {
	switch app {
	case "wappie", ReferenceApp:
		return ItemNumber, true
	case "mailie":
		return ItemMailbox, true
	}
	return "", false
}

// EntitlementsDoc is what one workspace may do in one app: its state and
// dates, its plan and places, its storage figures, the four switches now
// and the steps to come, each item's trial, and, last, a trim order. Every
// member is always present; one that has nothing to say is null where its
// rule allows it. It never holds an email address, a phone number, a
// person's name, a sub, a key or a token.
//
// An app reads it as it reads what the platform sends (UnmarshalJSON): a
// member it does not know is ignored, a member counts only as exactly
// named, and a member missing, or null where it may not be, makes the
// document one that does not decode, never one read as null.
//
// It prints and logs its ids alone (String, GoString, Format, LogValue).
// slog calls LogValue only on the value logged itself: a slice of
// documents, or an app's own struct holding one, goes through a JSON
// handler as JSON, every figure and the trim order included, so an app
// logs a document itself, or its ids, never a slice of them or a struct
// holding one.
type EntitlementsDoc struct {
	V          int    `json:"v"`
	Type       string `json:"type"`
	App        string `json:"app"`
	Generation string `json:"generation"`
	// WorkspaceID is a workspace named to the app.
	WorkspaceID string `json:"workspace_id"`
	// Version is the document's seq in the app's entitlements feed: it only
	// rises. An app applies a document only of its generation and of a
	// higher version than it applied for the workspace.
	Version    int64 `json:"version"`
	ComputedAt Time  `json:"computed_at"`
	// Mode is ModeObserve or ModeEnforce, per document.
	Mode string `json:"mode"`
	// TestMode: billing runs in Stripe's test mode; it changes no rule.
	TestMode bool                 `json:"test_mode"`
	State    EntitlementsState    `json:"state"`
	Plan     EntitlementsPlan     `json:"plan"`
	Places   EntitlementsPlaces   `json:"places"`
	Storage  EntitlementsStorage  `json:"storage"`
	Switches Switches             `json:"switches"`
	Timeline []TimelineStep       `json:"timeline"`
	Items    []ItemTrial          `json:"items"`
	Requests EntitlementsRequests `json:"requests"`
	// Trim is the trim order as received, or nil for null. It is kept raw
	// so that the order is verified (its MAC) on the bytes it came in, and
	// decoded from them alone.
	Trim  json.RawMessage   `json:"trim"`
	Links EntitlementsLinks `json:"links"`
}

// String names the document by its app, workspace, generation, version,
// mode and state, and prints no storage figure, place, date or order: no
// figure of a report is ever logged (SPEC section 11.20).
func (d EntitlementsDoc) String() string {
	return fmt.Sprintf("contract.EntitlementsDoc{App: %q, WorkspaceID: %q, Generation: %q, Version: %d, Mode: %q, State: %q, %s}",
		d.App, d.WorkspaceID, d.Generation, d.Version, d.Mode, d.State.Name, Ellipsis)
}

// GoString is String, for %#v.
func (d EntitlementsDoc) GoString() string { return d.String() }

// Format prints String for every verb, %q quoted, so that no verb walks
// the document's figures or its trim order.
func (d EntitlementsDoc) Format(f fmt.State, verb rune) { formatAs(f, verb, d.String()) }

// LogValue is what an app may log of a document, ids only: its app,
// workspace, generation, version, mode and state.
func (d EntitlementsDoc) LogValue() slog.Value {
	return slog.GroupValue(slog.String("app", d.App), slog.String("workspace_id", d.WorkspaceID),
		slog.String("generation", d.Generation), slog.Int64("version", d.Version),
		slog.String("mode", d.Mode), slog.String("state", d.State.Name))
}

// EntitlementsState is a workspace's state and its dates.
type EntitlementsState struct {
	Name string `json:"name"`
	// Reason is set exactly on over_quota and expired.
	Reason *string `json:"reason"`
	// Since is when the state began; for over_quota and expired, the
	// episode's start.
	Since Time `json:"since"`
	// Deadline is over_quota's day-30 deadline, or null.
	Deadline *Time `json:"deadline"`
	// ExpiredSince is set exactly on expired.
	ExpiredSince *Time `json:"expired_since"`
	// TrialEndsAt is the workspace's trial end while its trial runs.
	TrialEndsAt *Time `json:"trial_ends_at"`
	// BuyBy is the end of the 30 days to buy once test plans stop
	// granting, or null.
	BuyBy *Time `json:"buy_by"`
}

// EntitlementsPlan is the plan in force.
type EntitlementsPlan struct {
	Source string `json:"source"`
	// Test: bought in test mode.
	Test      bool  `json:"test"`
	Numbers   int   `json:"numbers"`
	Mailboxes int   `json:"mailboxes"`
	Packs     int   `json:"packs"`
	PeriodEnd *Time `json:"period_end"`
	EndsAt    *Time `json:"ends_at"`
}

// EntitlementsPlaces are the app's places: bought, and counted from its
// latest access snapshot. The four counted members are null together, while
// the snapshot is stale or missing.
type EntitlementsPlaces struct {
	// Kind is the app's kind (AppItemKind).
	Kind  string `json:"kind"`
	Total int64  `json:"total"`
	// Used are the items of the kind not deleted and not pending, hosted
	// and connected; UsedConnected those of them with server.
	Used          *int64 `json:"used"`
	UsedConnected *int64 `json:"used_connected"`
	// Free is max(0, Total - Used).
	Free *int64 `json:"free"`
	// CountedAt is when the platform received the snapshot it counted.
	CountedAt *Time `json:"counted_at"`
}

// EntitlementsStorage are the workspace's storage figures, in bytes
// (1 GB = 10^9 bytes).
type EntitlementsStorage struct {
	QuotaBytes int64 `json:"quota_bytes"`
	// UsedBytes is every app's usage, from the latest kept reports, or null
	// while none is kept.
	UsedBytes *int64 `json:"used_bytes"`
	// OthersBytes are the other apps' bytes: 0 while none is kept, never
	// null.
	OthersBytes int64 `json:"others_bytes"`
	// AllowanceBytes is max(0, QuotaBytes - OthersBytes).
	AllowanceBytes int64 `json:"allowance_bytes"`
	// CapBytes are the bytes past which the app stores nothing new. Mailie's
	// is its allowance; Wappie's is floor(1.05 × cap_quota) - OthersBytes,
	// at least 0, which a document alone cannot check.
	CapBytes int64 `json:"cap_bytes"`
	// MeasuredThrough is the oldest measured_at of the reports used, null
	// exactly with UsedBytes.
	MeasuredThrough *Time `json:"measured_through"`
}

// String prints no figure: where one app alone reports, used_bytes is
// that app's report total.
func (EntitlementsStorage) String() string { return "contract.EntitlementsStorage{" + Ellipsis + "}" }

// GoString is String, for %#v.
func (st EntitlementsStorage) GoString() string { return st.String() }

// Format prints String for every verb, %q quoted: no figure.
func (st EntitlementsStorage) Format(f fmt.State, verb rune) { formatAs(f, verb, st.String()) }

// LogValue prints no figure.
func (EntitlementsStorage) LogValue() slog.Value { return slog.StringValue(Ellipsis) }

// Switches are the four switches now, each SwitchOn or SwitchOff.
type Switches struct {
	API      string `json:"api"`
	NewLinks string `json:"new_links"`
	Sync     string `json:"sync"`
	Send     string `json:"send"`
}

// Get is the value of the switch named name, or "" for no such switch.
func (s Switches) Get(name string) string {
	switch name {
	case SwitchAPI:
		return s.API
	case SwitchNewLinks:
		return s.NewLinks
	case SwitchSync:
		return s.Sync
	case SwitchSend:
		return s.Send
	}
	return ""
}

// TimelineStep is a step to come: at its time, by the app's own clock, the
// switches it names turn off. On the wire it is {"at", <switch>: "off",
// …}, naming one to four switches, each only as "off": no step turns a
// switch on.
type TimelineStep struct {
	At Time
	// Off are the switches the step turns off, in the wire's order.
	Off []string
}

// MarshalJSON writes the step as {"at", <switch>: "off", …}, its switches
// in the wire's order.
func (s TimelineStep) MarshalJSON() ([]byte, error) {
	at, err := s.At.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(`{"at":`)
	b.Write(at)
	for _, name := range switchNames {
		if slices.Contains(s.Off, name) {
			b.WriteString(`,"` + name + `":"off"`)
		}
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// UnmarshalJSON reads a step: "at", and one to four switches, each named
// exactly and once, each "off". Any other member is refused: a step's
// members are switch names, a closed list.
func (s *TimelineStep) UnmarshalJSON(b []byte) error {
	if !wellFormed(b) {
		return invalid("timeline[]")
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(b, &members) != nil || members == nil {
		return invalid("timeline[]")
	}
	var step TimelineStep
	raw, ok := members["at"]
	if !ok || json.Unmarshal(raw, &step.At) != nil {
		return invalid("timeline[].at")
	}
	for name, v := range members {
		if name == "at" {
			continue
		}
		var value string
		if !oneOf(name, switchNames) || json.Unmarshal(v, &value) != nil || value != SwitchOff {
			return invalid("timeline[] names switches, each only as off")
		}
	}
	for _, name := range switchNames {
		if _, ok := members[name]; ok {
			step.Off = append(step.Off, name)
		}
	}
	if len(step.Off) == 0 {
		return invalid("timeline[] names a switch")
	}
	*s = step
	return nil
}

// ItemTrial is one linked item's own trial.
type ItemTrial struct {
	ID string `json:"id"`
	// Trial is TrialRunning or TrialUsedUp, never TrialNotNeeded.
	Trial string `json:"trial"`
	// TrialEndsAt is the item's clock end: after computed_at on running, at
	// or before it on used_up.
	TrialEndsAt Time `json:"trial_ends_at"`
}

// EntitlementsRequests are what the platform asks of the app.
type EntitlementsRequests struct {
	// UsageAfter asks for a usage report measured after it.
	UsageAfter *Time `json:"usage_after"`
	// CodesAfter, when later than the last value the app answered for the
	// workspace, asks for the codes of every linked hosted item the
	// document's items do not list.
	CodesAfter *Time `json:"codes_after"`
}

// EntitlementsLinks are the console's plan and storage pages for the
// workspace.
type EntitlementsLinks struct {
	Plan    string `json:"plan"`
	Storage string `json:"storage"`
}

// UnmarshalJSON reads a document as an app reads what the platform sends:
// one well-formed JSON object; members it does not know ignored, at every
// depth; a member counted only as exactly named; every member present, and
// null only where its rule allows. Trim keeps the order's bytes as they
// came, or nil for null. Validate is the reader's next step.
func (d *EntitlementsDoc) UnmarshalJSON(b []byte) error {
	type doc EntitlementsDoc
	var v doc
	if err := decodeSent(b, &v, "doc"); err != nil {
		return err
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(b, &members) != nil {
		return invalid("doc")
	}
	v.Trim = nil
	if raw := bytes.TrimSpace(members["trim"]); string(raw) != "null" {
		v.Trim = slices.Clone(json.RawMessage(raw))
	}
	*d = EntitlementsDoc(v)
	return nil
}

// decodeSent decodes raw, one JSON value the platform sends an app, into
// dst, a pointer, as the app reads it: valid UTF-8 with no escape of half a
// surrogate pair and no member twice; a member dst's type does not name
// exactly ignored, at every depth; then every member present but those it
// marks omitempty or omitzero, and null only where it holds a pointer, a raw
// value or a type that reads itself.
func decodeSent(raw []byte, dst any, what string) error {
	if !wellFormed(raw) {
		return invalid("%s: not one well-formed JSON value, or a member twice", what)
	}
	t := reflect.TypeOf(dst).Elem()
	kept := exactOnly(raw, t)
	if !exactShape(kept, t) {
		return invalid("%s: a member missing, or null where it may not be", what)
	}
	if err := json.Unmarshal(kept, dst); err != nil {
		return invalid("%s", what)
	}
	return nil
}

// safeCount reports whether n is an integer the part carries: 0 to
// MaxSafeInteger.
func safeCount(n int64) bool { return n >= 0 && n <= MaxSafeInteger }

// countOrNull reports whether p is null or a safe count.
func countOrNull(p *int64) bool { return p == nil || safeCount(*p) }

// Validate checks every member of a document, and the rules between them
// (SPEC section 11.20). It judges every time against computed_at, never
// the reader's clock. It does not check Wappie's cap_bytes, whose quota
// (the one that last granted, in a no_plan episode) the document does not
// carry.
func (d EntitlementsDoc) Validate() error {
	kind, known := AppItemKind(d.App)
	switch {
	case d.V != EntitlementsV:
		return invalid("v")
	case d.Type != EntitlementsType:
		return invalid("type")
	case !ValidApp(d.App) || !known:
		return invalid("app")
	case !ValidUUID(d.Generation):
		return invalid("generation")
	case !ValidUUID(d.WorkspaceID):
		return invalid("workspace_id")
	case d.Version < 1 || d.Version > MaxSafeInteger:
		return invalid("version")
	case d.ComputedAt.IsZero():
		return invalid("computed_at")
	case d.Mode != ModeObserve && d.Mode != ModeEnforce:
		return invalid("mode")
	}
	for _, check := range []func() error{
		d.validState, d.validPlan, func() error { return d.validPlaces(kind) }, d.validStorage,
		d.validSwitches, d.validItems, d.validRequests, d.validTrim, d.validLinks,
	} {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

func (d EntitlementsDoc) validState() error {
	s := d.State
	switch {
	case !oneOf(s.Name, workspaceStates):
		return invalid("state.name")
	case s.Since.IsZero():
		return invalid("state.since")
	case !timeOrNull(s.Deadline), !timeOrNull(s.ExpiredSince), !timeOrNull(s.TrialEndsAt), !timeOrNull(s.BuyBy):
		return invalid("state: a time")
	case !codeOrNull(s.Reason, []string{ReasonOverQuota, ReasonNoPlan}):
		return invalid("state.reason")
	}
	paused := s.Name == WorkspaceOverQuota || s.Name == WorkspaceExpired
	switch {
	case (s.Reason != nil) != paused:
		return invalid("state.reason is set exactly on over_quota and expired")
	case s.Deadline != nil && s.Name != WorkspaceOverQuota:
		return invalid("state.deadline is over_quota's")
	case (s.ExpiredSince != nil) != (s.Name == WorkspaceExpired):
		return invalid("state.expired_since is set exactly on expired")
	case s.Name == WorkspaceTrial && s.TrialEndsAt == nil:
		return invalid("state.trial_ends_at is set on trial")
	case s.TrialEndsAt != nil && s.Name != WorkspaceTrial && s.Name != WorkspaceOverQuota:
		return invalid("state.trial_ends_at is null on active, expired and closed")
	}
	return nil
}

func (d EntitlementsDoc) validPlan() error {
	p := d.Plan
	count := func(n int) bool { return n >= 0 && n <= MaxPlanCount }
	switch {
	case !oneOf(p.Source, planSources):
		return invalid("plan.source")
	case !count(p.Numbers) || !count(p.Mailboxes) || !count(p.Packs):
		return invalid("plan: numbers, mailboxes and packs are 0 to 50")
	case !timeOrNull(p.PeriodEnd) || !timeOrNull(p.EndsAt):
		return invalid("plan: a time")
	}
	switch p.Source {
	case SourceTrial:
		if p.Numbers != 1 || p.Mailboxes != 1 || p.Packs != 0 || p.Test || p.PeriodEnd != nil || p.EndsAt != nil {
			return invalid("plan: the trial holds 1, 1 and 0, is no test plan and has no period")
		}
	case SourceNone:
		if p.Numbers != 0 || p.Mailboxes != 0 || p.Packs != 0 || p.Test || p.PeriodEnd != nil || p.EndsAt != nil {
			return invalid("plan: none holds 0, 0 and 0, is no test plan and has no period")
		}
	case SourceLiveMove:
		if !p.Test {
			return invalid("plan: live_move is a test plan")
		}
	}
	return nil
}

func (d EntitlementsDoc) validPlaces(kind string) error {
	p := d.Places
	total := int64(d.Plan.Numbers)
	if kind == ItemMailbox {
		total = int64(d.Plan.Mailboxes)
	}
	switch {
	case p.Kind != kind:
		return invalid("places.kind is the app's")
	case p.Total != total:
		return invalid("places.total is the plan's count of the app's kind")
	case !countOrNull(p.Used) || !countOrNull(p.UsedConnected) || !countOrNull(p.Free) || !timeOrNull(p.CountedAt):
		return invalid("places: a count or a time")
	}
	set := p.Used != nil
	if (p.UsedConnected != nil) != set || (p.Free != nil) != set || (p.CountedAt != nil) != set {
		return invalid("places: used, used_connected, free and counted_at are all null or all set")
	}
	if set && (*p.Free != max(0, p.Total-*p.Used) || *p.UsedConnected > *p.Used) {
		return invalid("places: free is max(0, total - used), and used_connected at most used")
	}
	return nil
}

func (d EntitlementsDoc) validStorage() error {
	s := d.Storage
	switch {
	case !safeCount(s.QuotaBytes) || !countOrNull(s.UsedBytes) || !safeCount(s.OthersBytes) ||
		!safeCount(s.AllowanceBytes) || !safeCount(s.CapBytes) || !timeOrNull(s.MeasuredThrough):
		return invalid("storage: a count or a time")
	case s.AllowanceBytes != max(0, s.QuotaBytes-s.OthersBytes):
		return invalid("storage.allowance_bytes is max(0, quota_bytes - others_bytes)")
	case (s.MeasuredThrough == nil) != (s.UsedBytes == nil):
		return invalid("storage.measured_through is null exactly with used_bytes")
	case d.App == "mailie" && s.CapBytes != s.AllowanceBytes:
		return invalid("storage.cap_bytes is Mailie's allowance")
	}
	return nil
}

func (d EntitlementsDoc) validSwitches() error {
	for _, name := range switchNames {
		v := d.Switches.Get(name)
		if v != SwitchOn && v != SwitchOff {
			return invalid("switches.%s", name)
		}
		if d.State.Name == WorkspaceClosed && v != SwitchOff {
			return invalid("on closed, every switch is off")
		}
	}
	switch {
	case d.Timeline == nil || len(d.Timeline) > MaxTimelineSteps:
		return invalid("timeline")
	case d.State.Name == WorkspaceClosed && len(d.Timeline) != 0:
		return invalid("on closed, the timeline is []")
	}
	last := d.ComputedAt.Time
	for _, step := range d.Timeline {
		if step.At.IsZero() || !step.At.After(last) {
			return invalid("timeline: steps after computed_at, by strictly rising at")
		}
		last = step.At.Time
		if len(step.Off) == 0 || len(step.Off) > len(switchNames) {
			return invalid("timeline[] names one to four switches")
		}
		seen := map[string]bool{}
		for _, name := range step.Off {
			if !oneOf(name, switchNames) || seen[name] {
				return invalid("timeline[] names each switch once")
			}
			seen[name] = true
		}
	}
	return nil
}

func (d EntitlementsDoc) validItems() error {
	switch {
	case d.Items == nil || len(d.Items) > MaxEntitlementItems:
		return invalid("items")
	case len(d.Items) != 0 && d.State.TrialEndsAt == nil:
		return invalid("items are listed only while state.trial_ends_at is set")
	}
	seen := map[string]bool{}
	for _, it := range d.Items {
		switch {
		case !ValidItemID(it.ID) || seen[it.ID]:
			return invalid("items[].id")
		case it.TrialEndsAt.IsZero():
			return invalid("items[].trial_ends_at")
		case it.Trial == TrialRunning:
			if !it.TrialEndsAt.After(d.ComputedAt.Time) {
				return invalid("items[].trial_ends_at is after computed_at on running")
			}
		case it.Trial == TrialUsedUp:
			if it.TrialEndsAt.After(d.ComputedAt.Time) {
				return invalid("items[].trial_ends_at is at or before computed_at on used_up")
			}
		default:
			return invalid("items[].trial is running or used_up")
		}
		seen[it.ID] = true
	}
	return nil
}

func (d EntitlementsDoc) validRequests() error {
	r := d.Requests
	notAfter := func(p *Time) bool { return p == nil || (!p.IsZero() && !p.After(d.ComputedAt.Time)) }
	switch {
	case !notAfter(r.UsageAfter) || !notAfter(r.CodesAfter):
		return invalid("requests: at or before computed_at")
	case r.CodesAfter != nil && d.State.TrialEndsAt == nil:
		return invalid("requests.codes_after only while state.trial_ends_at is set")
	}
	return nil
}

// validTrim holds a trim order to mode enforce and state expired, to the
// document's app, workspace and generation, and to TrimOrder's Validate.
// It never checks the order's mac (VerifyTrimOrder does), nor its floor
// against the plan: a document whose order fails only that is applied,
// its switches included, and the order alone is refused invalid_order.
func (d EntitlementsDoc) validTrim() error {
	raw := bytes.TrimSpace(d.Trim)
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if d.Mode != ModeEnforce || d.State.Name != WorkspaceExpired {
		return invalid("trim only with mode enforce and state expired")
	}
	if raw[0] != '{' {
		return invalid("trim")
	}
	var o TrimOrder
	if err := json.Unmarshal(raw, &o); err != nil {
		return invalid("trim: it does not decode")
	}
	if o.App != d.App || o.WorkspaceID != d.WorkspaceID || o.Generation != d.Generation {
		return invalid("trim names the document's app, workspace and generation")
	}
	if err := o.Validate(); err != nil {
		return fmt.Errorf("trim: %w", err)
	}
	return nil
}

func (d EntitlementsDoc) validLinks() error {
	if !validConsoleLink(d.Links.Plan) || !validConsoleLink(d.Links.Storage) {
		return invalid("links")
	}
	return nil
}

// validConsoleLink reports whether s is an absolute https:// URL on a host
// (ValidHost), or, in development, an http:// one on a *.localhost host;
// an optional port, a path and a query, but no user information or
// fragment.
func validConsoleLink(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Opaque != "" || u.User != nil || u.Fragment != "" || strings.Contains(s, "#") || u.Host == "" {
		return false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return false
		}
	}
	host := u.Hostname()
	switch u.Scheme {
	case "https":
		return ValidHost(host)
	case "http":
		return ValidHost(host) && strings.HasSuffix(host, ".localhost")
	}
	return false
}

// ValidateFor checks a document an app received for workspaceID, a GET's
// answer: Validate, and that it names app and that workspace. Its
// generation is the app's to judge: another one is a reset (SPEC section
// 11.17's 7.4).
func (d EntitlementsDoc) ValidateFor(app, workspaceID string) error {
	if err := d.Validate(); err != nil {
		return err
	}
	if d.App != app || d.WorkspaceID != workspaceID {
		return invalid("the document names another app or workspace")
	}
	return nil
}

// EntitlementsFeed is one answer of the entitlements feed: the documents
// that changed after a cursor, each workspace's latest version, oldest
// first. It has the account feed's grammar and members, with each doc kept
// as it came.
//
// Its JSON is the wire, each document whole; String, GoString, Format and
// LogValue print only its generation, head, next_after, more and how many
// items it holds. slog calls LogValue only on the value logged itself, so
// a page inside a slice or an app's own struct is never logged through a
// JSON handler, which would write every document.
type EntitlementsFeed struct {
	Generation          string                 `json:"generation"`
	GenerationConfirmed bool                   `json:"generation_confirmed"`
	Head                int64                  `json:"head"`
	PublishedThrough    Time                   `json:"published_through"`
	Items               []EntitlementsFeedItem `json:"items"`
	NextAfter           int64                  `json:"next_after"`
	More                bool                   `json:"more"`
}

// EntitlementsFeedItem is one document and its place in the feed. The
// document is kept as it came, and judged on its own (Document), so that
// one document never refuses its page.
//
// Its Doc is the document's raw JSON, figures, places and trim order
// included: String, GoString, Format and LogValue print only its seq, and
// the document's app and workspace_id where they read as an app id and a
// UUID. slog calls LogValue only on the value logged itself, so an item
// inside a slice or an app's own struct is never logged through a JSON
// handler.
type EntitlementsFeedItem struct {
	Seq int64           `json:"seq"`
	Doc json.RawMessage `json:"doc"`
}

// String names the page by its generation, head, next_after and more, and
// counts its items: no document.
func (f EntitlementsFeed) String() string {
	return fmt.Sprintf("contract.EntitlementsFeed{Generation: %q, Head: %d, NextAfter: %d, More: %t, Items: %d}",
		f.Generation, f.Head, f.NextAfter, f.More, len(f.Items))
}

// GoString is String, for %#v.
func (f EntitlementsFeed) GoString() string { return f.String() }

// Format prints String for every verb, %q quoted: no document.
func (f EntitlementsFeed) Format(s fmt.State, verb rune) { formatAs(s, verb, f.String()) }

// LogValue is the page's generation, head, next_after, more and item
// count, never a document.
func (f EntitlementsFeed) LogValue() slog.Value {
	return slog.GroupValue(slog.String("generation", f.Generation), slog.Int64("head", f.Head),
		slog.Int64("next_after", f.NextAfter), slog.Bool("more", f.More), slog.Int("items", len(f.Items)))
}

// ids are the document's app and workspace_id where each reads as an app
// id and a UUID, else "".
func (it EntitlementsFeedItem) ids() (app, workspaceID string) {
	if a, ok := readMember(it.Doc, "app"); ok && ValidApp(a) {
		app = a
	}
	if ws, ok := readMember(it.Doc, "workspace_id"); ok && ValidUUID(ws) {
		workspaceID = ws
	}
	return app, workspaceID
}

// String names the item by its seq, and its document's app and workspace
// where they read as ids: no figure, place or order.
func (it EntitlementsFeedItem) String() string {
	app, ws := it.ids()
	return fmt.Sprintf("contract.EntitlementsFeedItem{Seq: %d, App: %q, WorkspaceID: %q, %s}", it.Seq, app, ws, Ellipsis)
}

// GoString is String, for %#v.
func (it EntitlementsFeedItem) GoString() string { return it.String() }

// Format prints String for every verb, %q quoted: no document.
func (it EntitlementsFeedItem) Format(f fmt.State, verb rune) { formatAs(f, verb, it.String()) }

// LogValue is the item's seq, and its document's app and workspace_id
// where they read as ids, never the document.
func (it EntitlementsFeedItem) LogValue() slog.Value {
	attrs := []slog.Attr{slog.Int64("seq", it.Seq)}
	app, ws := it.ids()
	if app != "" {
		attrs = append(attrs, slog.String("app", app))
	}
	if ws != "" {
		attrs = append(attrs, slog.String("workspace_id", ws))
	}
	return slog.GroupValue(attrs...)
}

// UnmarshalJSON reads a page as an app reads what the platform sends, the
// account feed's fixed shape: one object, no member twice, whose seven
// members generation, generation_confirmed, head, published_through, items,
// next_after and more are each present by its exact name and none null;
// a member it does not know is ignored, and one named in another case
// counts as one it does not know. So a page that never said more is false
// gives no freshness, and one with no next_after never sends the cursor
// back to the start. Each item is read the same way (EntitlementsFeedItem),
// its doc kept as its bytes came and judged alone.
func (f *EntitlementsFeed) UnmarshalJSON(b []byte) error {
	m, ok := objectMembers(b)
	if !ok {
		return invalid("entitlements feed: one object, no member twice")
	}
	var v EntitlementsFeed
	for _, field := range []struct {
		name string
		dst  any
	}{
		{"generation", &v.Generation}, {"generation_confirmed", &v.GenerationConfirmed}, {"head", &v.Head},
		{"published_through", &v.PublishedThrough}, {"items", &v.Items}, {"next_after", &v.NextAfter}, {"more", &v.More},
	} {
		raw, ok := m[field.name]
		if !ok || string(raw) == "null" {
			return invalid("entitlements feed: %s is present, never null", field.name)
		}
		if err := json.Unmarshal(raw, field.dst); err != nil {
			return invalid("entitlements feed: %s", field.name)
		}
	}
	*f = v
	return nil
}

// UnmarshalJSON reads an item as an app reads what the platform sends: one
// object, no member twice, its seq present by its exact name and never
// null, a member it does not know ignored; and its doc, by its exact name,
// kept as its bytes came, byte for byte. A doc that does not decode, null
// or missing included (Doc nil), is a bad document refused alone
// (Document: invalid_document, with no workspace_id), never the page.
func (it *EntitlementsFeedItem) UnmarshalJSON(b []byte) error {
	m, ok := objectMembers(b)
	if !ok {
		return invalid("entitlements feed: an item is one object, no member twice")
	}
	raw, ok := m["seq"]
	var v EntitlementsFeedItem
	if !ok || string(raw) == "null" || json.Unmarshal(raw, &v.Seq) != nil {
		return invalid("entitlements feed: items[].seq is present, never null")
	}
	if doc, ok := m["doc"]; ok {
		v.Doc = slices.Clone(doc)
	}
	*it = v
	return nil
}

// objectMembers reads raw, one JSON object, into its members by their exact
// names, each value's bytes as they came; false when raw is not one object
// or names a member twice. It judges no value but as JSON.
func objectMembers(raw []byte) (map[string]json.RawMessage, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false
	}
	m := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		name, ok := tok.(string)
		if err != nil || !ok {
			return nil, false
		}
		if _, seen := m[name]; seen {
			return nil, false
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, false
		}
		m[name] = v
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return m, true
}

// NewEntitlementsFeedItem is the item of d at seq, as the platform writes
// it: with no HTML escaping, so the feed's document is byte for byte the
// GET's, which the platform writes so too (SPEC section 11.20), and a link
// with an & in it is written as it is. d's version is its seq.
func NewEntitlementsFeedItem(seq int64, d EntitlementsDoc) (EntitlementsFeedItem, error) {
	if d.Version != seq {
		return EntitlementsFeedItem{}, invalid("a document's version is its seq")
	}
	raw, err := marshalPlain(d)
	if err != nil {
		return EntitlementsFeedItem{}, err
	}
	return EntitlementsFeedItem{Seq: seq, Doc: json.RawMessage(raw)}, nil
}

// Validate checks a page of the entitlements feed itself: its generation,
// its head and cursor, and its documents' order. It does not decode or
// validate the documents: one document never refuses a page. A page whose
// generation is not the one the app holds is a reset, whatever its
// documents say; in a page of its own generation, an app judges each
// document alone (EntitlementsFeedItem.Document).
func (f EntitlementsFeed) Validate() error {
	switch {
	case !ValidUUID(f.Generation):
		return invalid("generation")
	case f.Head < 0 || f.Head > MaxSafeInteger || f.NextAfter < 0 || f.NextAfter > f.Head:
		return invalid("head")
	case f.PublishedThrough.IsZero():
		return invalid("published_through")
	case f.Items == nil || len(f.Items) > MaxEntitlementsFeedItems:
		return invalid("items")
	}
	last := int64(0)
	for _, it := range f.Items {
		if it.Seq <= last || it.Seq > f.Head {
			return invalid("items[].seq")
		}
		last = it.Seq
	}
	return nil
}

// The codes of an acknowledgement's refused entries: why an app refused a
// document of a page of its own generation.
const (
	// RefusedInvalidDocument: the document does not decode, fails Validate,
	// or its version is not its seq.
	RefusedInvalidDocument = "invalid_document"
	// RefusedAnotherApp: the document names another app.
	RefusedAnotherApp = "another_app"
	// RefusedAnotherGeneration: the document's generation is not its
	// page's.
	RefusedAnotherGeneration = "another_generation"
)

var entitlementsRefusals = []string{RefusedInvalidDocument, RefusedAnotherApp, RefusedAnotherGeneration}

// EntitlementsRefusalCodes are the codes of an entitlements
// acknowledgement's refused entries. It returns a copy: the set Validate
// checks is closed.
func EntitlementsRefusalCodes() []string { return slices.Clone(entitlementsRefusals) }

// Document judges the item's document for app in a page of generation,
// the app's own: it is the document to apply, or a bad one, refused alone,
// never a reset. A bad document comes back as the acknowledgement's refused
// entry, its seq, its workspace_id when that reads as a UUID (else null) and
// its code, in this order: a document whose app reads as another valid app
// id is another_app; one whose generation reads as another valid UUID is
// another_generation; one that does not decode, fails Validate, or whose
// version is not its seq is invalid_document. The app applies nothing of a
// bad document (never its trim), lists it in its next acknowledgement,
// sends that workspace's GET once, and moves its cursor past it.
func (it EntitlementsFeedItem) Document(app, generation string) (EntitlementsDoc, *EntitlementsRefused) {
	refuse := func(code string) (EntitlementsDoc, *EntitlementsRefused) {
		r := &EntitlementsRefused{Seq: it.Seq, Code: code}
		if ws, ok := readMember(it.Doc, "workspace_id"); ok && ValidUUID(ws) {
			r.WorkspaceID = &ws
		}
		return EntitlementsDoc{}, r
	}
	if got, ok := readMember(it.Doc, "app"); ok && ValidApp(got) && got != app {
		return refuse(RefusedAnotherApp)
	}
	if got, ok := readMember(it.Doc, "generation"); ok && ValidUUID(got) && got != generation {
		return refuse(RefusedAnotherGeneration)
	}
	var d EntitlementsDoc
	if json.Unmarshal(it.Doc, &d) != nil || d.Validate() != nil || d.App != app || d.Generation != generation || d.Version != it.Seq {
		return refuse(RefusedInvalidDocument)
	}
	return d, nil
}

// readMember is the string member name of the JSON object raw, by its exact
// name, when it reads as a string.
func readMember(raw json.RawMessage, name string) (string, bool) {
	var members map[string]json.RawMessage
	if json.Unmarshal(raw, &members) != nil {
		return "", false
	}
	var s string
	v, ok := members[name]
	if !ok || json.Unmarshal(v, &s) != nil {
		return "", false
	}
	return s, true
}

// EntitlementsApplied is an app's acknowledgement of the entitlements feed:
// POST /contract/v1/entitlements/applied. It goes at once after a page that
// changed a switch, a timeline or a trim, or that refused a document;
// otherwise at most once a second and at least once a minute while the
// feed runs.
type EntitlementsApplied struct {
	// Generation is the app's; another one is answered gone.
	Generation string `json:"generation"`
	// Through: the app applied every document of this generation's feed up
	// to this seq, a document only observed, one kept for a workspace it
	// does not hold yet, and a bad one refused included.
	Through int64 `json:"through"`
	// Refused, when present, are the bad documents up to Through not listed
	// in an earlier acknowledgement, at most MaxAppliedRefused; absent (nil)
	// when there are none, never [] or null.
	Refused EntitlementsRefusals `json:"refused,omitzero"`
}

// EntitlementsRefusals are an acknowledgement's refused entries. Present,
// the list is never null.
type EntitlementsRefusals []EntitlementsRefused

// UnmarshalJSON reads the list, refusing null, and each entry strictly,
// every member present. Validate refuses an empty list: refused is absent
// when none.
func (r *EntitlementsRefusals) UnmarshalJSON(b []byte) error {
	var v []EntitlementsRefused
	if err := decodeExact(b, &v, "refused"); err != nil {
		return err
	}
	*r = v
	return nil
}

// EntitlementsRefused is one bad document an app refused.
type EntitlementsRefused struct {
	Seq int64 `json:"seq"`
	// WorkspaceID is the document's, or null when it cannot be read.
	WorkspaceID *string `json:"workspace_id"`
	Code        string  `json:"code"`
}

// Validate checks an acknowledgement: its generation and cursor, and each
// refused entry, at or below Through, each seq once.
func (a EntitlementsApplied) Validate() error {
	switch {
	case !ValidUUID(a.Generation):
		return invalid("generation")
	case !safeCount(a.Through):
		return invalid("through")
	case a.Refused != nil && (len(a.Refused) == 0 || len(a.Refused) > MaxAppliedRefused):
		return invalid("refused is absent when none, and lists at most 20")
	}
	seen := map[int64]bool{}
	for _, r := range a.Refused {
		switch {
		case r.Seq < 1 || r.Seq > a.Through || seen[r.Seq]:
			return invalid("refused[].seq is at most through, each once")
		case !subOrNull(r.WorkspaceID):
			return invalid("refused[].workspace_id")
		case !oneOf(r.Code, entitlementsRefusals):
			return invalid("refused[].code")
		}
		seen[r.Seq] = true
	}
	return nil
}
