package contract_test

// The kit's generators of wire-trim.json and trim-macs.json (kit v0.12.0,
// SPEC section 11.20): trim orders valid and invalid, the app's decision on
// an order at a given clock and state, its run through the events that may
// stop it, the results and the platform's answers, and the orders' MACs.
// The decision and the run are written here as small models of the spec,
// over the kit's own VerifyTrimOrder, which the runners replay; every case
// states the outcome the spec asks of it, and the generator fails rather
// than write a case whose outcome the code or the model does not give.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/thehappieco/kit/contract"
)

// The fixed material of the trim orders' vectors: made-up ids.
const (
	vecOrderID  = "0199c3a0-0000-7000-8000-000000000101"
	vecOrderID2 = "0199c3a0-0000-7000-8000-000000000102"
	vecEpisode  = "0199a2f0-0000-7000-8000-000000000101"
	// SecretC is a third made-up secret that protects nothing.
	SecretC = "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8" //nolint:gosec // G101: a made-up vector secret that protects nothing
)

// vecPurgeAt is when the order's deleted item was due to be purged.
var vecPurgeAt = at(7 * 24 * time.Hour)

// vecOrder is a valid order of app issued at Now, as the platform stores
// it, its mac left for signedOrder: the spec's example, a deleted item
// purged then a live one kept down to the floor.
func vecOrder(app string, mut func(*contract.TrimOrder)) contract.TrimOrder {
	deleted, live := "dev_9", "dev_7"
	if app == "mailie" {
		deleted, live = "acc_9b21", "acc_7f3a"
	}
	o := contract.TrimOrder{
		OrderID: vecOrderID, App: app, WorkspaceID: vecTeam, Generation: vecGeneration, Episode: vecEpisode,
		Round: 1, IssuedAt: at(0), NotBefore: at(0), ValidUntil: at(6 * time.Hour),
		Floor: ptr(contract.TrimFloor(Now)),
		Basis: contract.TrimBasis{UsageSeq: Now.Add(-8 * time.Minute).UnixMilli(), MeasuredAt: at(-8 * time.Minute)},
		Steps: []contract.TrimStep{
			{Item: deleted, Action: contract.TrimActionPurge},
			{Item: live, Action: contract.TrimActionKeep, KeepBytes: ptr[int64](14000000000)},
		},
		BasisPurge: map[string]contract.Time{deleted: vecPurgeAt},
		Secret:     2,
		MAC:        "v1=" + strings.Repeat("0", 64),
	}
	if mut != nil {
		mut(&o)
	}
	return o
}

// noFloor makes an order one without a plan: no floor, every keep step
// keeping nothing.
func noFloor(o *contract.TrimOrder) {
	o.Floor = nil
	for i := range o.Steps {
		if o.Steps[i].Action == contract.TrimActionKeep {
			o.Steps[i].KeepBytes = ptr[int64](0)
		}
	}
}

// signedOrder is o as the platform serves it: signed for its app under
// secret, whose generation number is gen.
func signedOrder(o contract.TrimOrder, secret string, gen int64) json.RawMessage {
	raw, err := contract.SignTrimOrder(mustRaw(o), o.App, secret, gen)
	if err != nil {
		panic(err)
	}
	return raw
}

// carrier is a valid expired document of app at Now carrying the order
// raw, of a workspace with no plan or, with planSource plan, a plan of one
// place.
func carrier(app string, raw json.RawMessage, planSource string) json.RawMessage {
	return mustRaw(vecEnt(app, func(d *contract.EntitlementsDoc) {
		expired(d)
		d.Trim = raw
		if planSource == contract.SourcePlan {
			d.Plan = contract.EntitlementsPlan{Source: contract.SourcePlan, Test: true, Numbers: 1, Mailboxes: 1}
			d.Places.Total = 1
			d.Storage.QuotaBytes = 15000000000
			d.Storage.AllowanceBytes = max(0, d.Storage.QuotaBytes-d.Storage.OthersBytes)
			d.Storage.CapBytes = d.Storage.AllowanceBytes
			if app != "mailie" {
				d.Storage.CapBytes = d.Storage.QuotaBytes*105/100 - d.Storage.OthersBytes
			}
		}
	}))
}

// orderValid is what an app makes of an order: read as it reads what the
// platform sends, then Validate.
func orderValid(raw []byte) bool {
	var o contract.TrimOrder
	return json.Unmarshal(raw, &o) == nil && o.Validate() == nil
}

// UsageFigures are the bytes of a report or of the app's usage now: its
// total, and per item.
type UsageFigures struct {
	Total int64            `json:"total_bytes"`
	Items map[string]int64 `json:"items"`
}

// ItemNow is one of a step's items as the app holds it now: live,
// deleted (with its purge_at), purged (by the app since the basis's
// measured_at; it sent item.purged), or absent (not its own in the
// workspace).
type ItemNow struct {
	State   string  `json:"state"`
	PurgeAt *string `json:"purge_at,omitempty"`
}

// StepPlan is what the app does with one step of an order it takes: run
// it, refuse it alone item_changed, or count it done with bytes_after 0
// (a purge step whose item it purged already).
type StepPlan struct {
	Item   string `json:"item"`
	Action string `json:"action"`
}

// TrimDecision is an order the app's feed carries in the document feed,
// what the app holds and sees, and its decision.
type TrimDecision struct {
	Name string `json:"name"`
	App  string `json:"app"`
	// Now is the app's clock.
	Now string `json:"now"`
	// Secrets are the contract secrets the app holds.
	Secrets []string `json:"secrets"`
	// GenerationConfirmed is what the latest trusted answer of the
	// entitlements feed in the order's generation said.
	GenerationConfirmed bool `json:"generation_confirmed"`
	// AllowOpen is the app's local trim allow for the workspace;
	// HeldAtObserve, a local brake holding the workspace at observe.
	AllowOpen     bool `json:"allow_open"`
	HeldAtObserve bool `json:"held_at_observe"`
	// Recorded is the result the app recorded for the order's order_id
	// before, or null.
	Recorded *contract.TrimResult `json:"recorded"`
	// Feed is the document carrying the order as the feed gave it.
	Feed json.RawMessage `json:"feed"`
	// Get is check 4's GET: doc (a signed answer with GetDoc), none (no
	// signed answer), rate_limited, unavailable or not_found (signed).
	Get    string          `json:"get"`
	GetDoc json.RawMessage `json:"get_doc"`
	// Basis is the report the order's basis names as the app kept it, or
	// null when it no longer holds it.
	Basis *UsageFigures `json:"basis"`
	// Usage is the app's usage now.
	Usage UsageFigures `json:"usage"`
	// Items are the steps' items as the app holds them now.
	Items map[string]ItemNow `json:"items"`
	// Action is wait, run, refused or resend; Code a refusal's; Steps what
	// a run does with each step; Result the recorded result resent.
	Action string     `json:"action"`
	Code   *string    `json:"code"`
	Steps  []StepPlan `json:"steps"`
}

// trimDecide is an app's decision on an order (SPEC section 11.20), in
// order: check 1 on the feed's copy (VerifyTrimOrder), and when that copy
// verifies under none of the secrets it holds (ErrTrimMAC: its mac holds
// under none, or it is not one well-formed object, names a member twice,
// carries a mac that is no string or is another app's body), check 4's GET
// first: no signed answer, rate_limited or unavailable, wait; a signed
// not_found or a document with no trim, not_current; else check 1 on that
// answer's copy, whose failure is invalid_order. Any other failure of
// check 1 on the feed's copy is invalid_order. An order whose order_id has a recorded result
// sends that result again. Before valid_until, it waits while its clock is
// before not_before or the generation is not confirmed. Then check 2 (the
// allow open and no local brake, else held), check 3 (before valid_until,
// else expired), check 4 (a signed answer carrying the same order_id, else
// not_current, or wait with no signed answer, rate_limited or
// unavailable; then check 1 again on that copy, which is used from here),
// check 5 (with a floor: the basis held, and usage now within max(1 % of
// quota_bytes, 100 MB) of it in total and for each step's item, a purge
// step whose item was purged already left out with its bytes, else
// usage_moved), check 6 (every step's item its own, or a purge step's
// purged since, else item_unknown; then per step: a purge step's item
// deleted with its basis_purge, a keep step's live, else that step alone
// item_changed; a purge step purged already done).
func trimDecide(c TrimDecision) (action string, code *string, steps []StepPlan, err error) {
	refuse := func(code string) (string, *string, []StepPlan, error) { return "refused", &code, nil, nil }
	now, err := time.Parse(time.RFC3339, c.Now)
	if err != nil {
		return "", nil, nil, err
	}
	var feed contract.EntitlementsDoc
	if err := json.Unmarshal(c.Feed, &feed); err != nil {
		return "", nil, nil, err
	}
	var get contract.EntitlementsDoc
	if c.Get == "doc" {
		if err := json.Unmarshal(c.GetDoc, &get); err != nil {
			return "", nil, nil, err
		}
	}
	gotGet := false
	o, verr := contract.VerifyTrimOrder(feed, c.App, c.Secrets)
	if errors.Is(verr, contract.ErrTrimMAC) {
		switch {
		case c.Get == contract.CodeNotFound:
			return refuse(contract.TrimCodeNotCurrent)
		case c.Get != "doc":
			return "wait", nil, nil, nil
		case !carriesTrim(get):
			return refuse(contract.TrimCodeNotCurrent)
		}
		gotGet = true
		o, verr = contract.VerifyTrimOrder(get, c.App, c.Secrets)
	}
	if verr != nil {
		return refuse(contract.TrimCodeInvalidOrder)
	}
	if c.Recorded != nil && c.Recorded.OrderID == o.OrderID {
		return "resend", nil, nil, nil
	}
	if now.Before(o.ValidUntil.Time) && (now.Before(o.NotBefore.Time) || !c.GenerationConfirmed) {
		return "wait", nil, nil, nil
	}
	if !c.AllowOpen || c.HeldAtObserve {
		return refuse(contract.TrimCodeHeld)
	}
	if !now.Before(o.ValidUntil.Time) {
		return refuse(contract.TrimCodeExpired)
	}
	switch c.Get {
	case "none", contract.CodeRateLimited, "unavailable":
		return "wait", nil, nil, nil
	case contract.CodeNotFound:
		return refuse(contract.TrimCodeNotCurrent)
	case "doc":
	default:
		return "", nil, nil, fmt.Errorf("contractvec: a GET %q", c.Get)
	}
	var other contract.TrimOrder
	if !carriesTrim(get) || json.Unmarshal(get.Trim, &other) != nil || other.OrderID != o.OrderID {
		return refuse(contract.TrimCodeNotCurrent)
	}
	if !gotGet {
		if o, verr = contract.VerifyTrimOrder(get, c.App, c.Secrets); verr != nil {
			return refuse(contract.TrimCodeInvalidOrder)
		}
	}
	purgedAlready := func(s contract.TrimStep) bool {
		return s.Action == contract.TrimActionPurge && c.Items[s.Item].State == "purged"
	}
	if o.Floor != nil {
		if c.Basis == nil {
			return refuse(contract.TrimCodeUsageMoved)
		}
		tol := max(get.Storage.QuotaBytes/100, 100000000)
		within := func(a, b int64) bool { return a-b <= tol && b-a <= tol }
		basisTotal := c.Basis.Total
		for _, s := range o.Steps {
			if purgedAlready(s) {
				basisTotal -= c.Basis.Items[s.Item]
				continue
			}
			if !within(c.Usage.Items[s.Item], c.Basis.Items[s.Item]) {
				return refuse(contract.TrimCodeUsageMoved)
			}
		}
		if !within(c.Usage.Total, basisTotal) {
			return refuse(contract.TrimCodeUsageMoved)
		}
	}
	for _, s := range o.Steps {
		st := c.Items[s.Item].State
		if st == "" || st == "absent" || (st == "purged" && s.Action != contract.TrimActionPurge) {
			return refuse(contract.TrimCodeItemUnknown)
		}
	}
	for _, s := range o.Steps {
		it := c.Items[s.Item]
		plan := StepPlan{Item: s.Item, Action: "run"}
		switch {
		case purgedAlready(s):
			plan.Action = "done"
		case s.Action == contract.TrimActionPurge:
			if it.State != "deleted" || it.PurgeAt == nil || *it.PurgeAt != o.BasisPurge[s.Item].Format(time.RFC3339) {
				plan.Action = "item_changed"
			}
		case it.State != "live":
			plan.Action = "item_changed"
		}
		steps = append(steps, plan)
	}
	return "run", nil, steps, nil
}

// carriesTrim reports whether d carries an order: a trim neither absent
// nor null.
func carriesTrim(d contract.EntitlementsDoc) bool {
	t := bytes.TrimSpace(d.Trim)
	return len(t) > 0 && string(t) != "null"
}

// RunStep is one step of a run and what happens around it: Before, the
// events from the end of the previous step to this one's start (none for
// the first, which the decision started); Item, this step's item at its
// check 6 (as_ordered, changed, purged_since); Between, the events between
// its batches; and where it ends.
type RunStep struct {
	Before     []string `json:"before"`
	Item       string   `json:"item"`
	Between    []string `json:"between"`
	BytesAfter int64    `json:"bytes_after"`
	AtFloor    bool     `json:"at_floor"`
}

// TrimRun is an order the app took, the run's events, and the result it
// reports (reported).
type TrimRun struct {
	Name     string          `json:"name"`
	App      string          `json:"app"`
	Order    json.RawMessage `json:"order"`
	Steps    []RunStep       `json:"steps"`
	UsageSeq int64           `json:"usage_seq"`
	Reported json.RawMessage `json:"reported"`
}

// runEvents are the events a run meets, by what each does: go on (no
// effect on the order), wait (no further step or batch, until an answer),
// or stop the order with a code.
var runEvents = map[string]string{
	"same": "", "batch": "", "report": "", "purged_event": "", "snapshot": "", "feed_same": "",
	"none": "wait", "rate_limited": "wait", "unavailable": "wait",
	"expired": contract.TrimCodeExpired, "held": contract.TrimCodeHeld,
	"other": contract.TrimCodeNotCurrent, "not_found": contract.TrimCodeNotCurrent, "no_trim": contract.TrimCodeNotCurrent,
	"feed_null": contract.TrimCodeNotCurrent, "feed_other": contract.TrimCodeNotCurrent,
	"interrupted": contract.TrimCodeInterrupted,
}

// trimRun plays a run (SPEC section 11.20): the steps in order; before a
// step and between its batches, an event that stops the order ends the
// run (the step under way partial with its bytes, a step not started
// not_run, the rest not_run, the result partial with the code); a wait
// runs nothing until the next event; check 6 again for each step after the
// first, a step whose item changed refused item_changed and the run going
// on, a purge step whose item the app purged since done with 0; a keep
// step stopped at the floor partial; the result done when every step is.
func trimRun(r TrimRun) (contract.TrimResult, error) {
	var o contract.TrimOrder
	if err := json.Unmarshal(r.Order, &o); err != nil {
		return contract.TrimResult{}, err
	}
	if len(r.Steps) != len(o.Steps) {
		return contract.TrimResult{}, fmt.Errorf("contractvec: run %q: %d steps for an order of %d", r.Name, len(r.Steps), len(o.Steps))
	}
	res := contract.TrimResult{OrderID: o.OrderID, Steps: []contract.TrimStepResult{}, UsageSeq: ptr(r.UsageSeq)}
	var stop *string
	stopped := func(events []string) (*string, error) {
		for _, e := range events {
			what, ok := runEvents[e]
			if !ok {
				return nil, fmt.Errorf("contractvec: an event %q", e)
			}
			if what != "" && what != "wait" {
				return &what, nil
			}
		}
		return nil, nil
	}
	for i, s := range r.Steps {
		item := o.Steps[i].Item
		if stop != nil {
			res.Steps = append(res.Steps, contract.TrimStepResult{Item: item, Outcome: contract.TrimOutcomeNotRun})
			continue
		}
		var err error
		if stop, err = stopped(s.Before); err != nil {
			return contract.TrimResult{}, err
		}
		if stop != nil {
			res.Steps = append(res.Steps, contract.TrimStepResult{Item: item, Outcome: contract.TrimOutcomeNotRun})
			continue
		}
		switch {
		case i > 0 && s.Item == "changed":
			res.Steps = append(res.Steps, contract.TrimStepResult{Item: item, Outcome: contract.TrimOutcomeRefused, Code: ptr(contract.TrimCodeItemChanged)})
			continue
		case s.Item == "purged_since":
			res.Steps = append(res.Steps, contract.TrimStepResult{Item: item, Outcome: contract.TrimOutcomeDone, BytesAfter: ptr[int64](0)})
			continue
		}
		if stop, err = stopped(s.Between); err != nil {
			return contract.TrimResult{}, err
		}
		outcome := contract.TrimOutcomeDone
		if stop != nil || s.AtFloor {
			outcome = contract.TrimOutcomePartial
		}
		res.Steps = append(res.Steps, contract.TrimStepResult{Item: item, Outcome: outcome, BytesAfter: ptr(s.BytesAfter)})
	}
	res.Outcome, res.Code = contract.TrimOutcomeDone, stop
	for _, s := range res.Steps {
		if s.Outcome != contract.TrimOutcomeDone {
			res.Outcome = contract.TrimOutcomePartial
		}
	}
	return res, nil
}

// TrimResultCase is a result body, whether the platform takes it alone
// (Validate) and against the file's order (ValidateFor) when for_order.
type TrimResultCase struct {
	Name     string          `json:"name"`
	ForOrder bool            `json:"for_order"`
	Value    json.RawMessage `json:"value"`
	Valid    bool            `json:"valid"`
}

// WireTrim is wire-trim.json.
type WireTrim struct {
	Format      string           `json:"format"`
	Version     int              `json:"version"`
	Kind        string           `json:"kind"`
	Description string           `json:"description"`
	Order       json.RawMessage  `json:"order"`
	Orders      []WireCase       `json:"orders"`
	Decisions   []TrimDecision   `json:"decisions"`
	Runs        []TrimRun        `json:"runs"`
	Results     []TrimResultCase `json:"results"`
	Answers     []WireCase       `json:"answers"`
}

// trimResultValid is what the platform makes of a result: decoded
// strictly, Validate, and ValidateFor the order when forOrder.
func trimResultValid(raw []byte, order json.RawMessage, forOrder bool) bool {
	var r contract.TrimResult
	if contract.DecodeStrict(raw, &r) != nil || r.Validate() != nil {
		return false
	}
	if !forOrder {
		return true
	}
	var o contract.TrimOrder
	return json.Unmarshal(order, &o) == nil && r.ValidateFor(o) == nil
}

// trimAnswerValid is what an app makes of the platform's answer.
func trimAnswerValid(raw []byte) bool {
	var a contract.TrimResultAnswer
	return json.Unmarshal(raw, &a) == nil && a.Validate() == nil
}

func wireTrim() (any, error) {
	out := WireTrim{
		Format: Format, Version: 1, Kind: "wire-trim",
		Description: trimDescription,
		Order:       signedOrder(vecOrder("wappie", nil), SecretA, 2),
	}
	if err := trimOrders(&out); err != nil {
		return nil, err
	}
	if err := trimDecisions(&out); err != nil {
		return nil, err
	}
	if err := trimRuns(&out); err != nil {
		return nil, err
	}
	if err := trimResults(&out); err != nil {
		return nil, err
	}
	return out, nil
}

const trimDescription = "Trim orders (SPEC section 11.20), every one signed with SecretA of signatures.json for its app, generation 2, but where a case says otherwise. " +
	"order: the file's order, Wappie's, issued at 2026-10-13T12:00:00Z: a deleted item purged, then a live one kept down to its floor; results' for_order cases are judged against it. " +
	"orders: an order read as an app reads what the platform sends (members it does not know ignored, every member present, null only for floor), then Validate: order_id a UUIDv7; round 1 to 3; issued_at <= not_before < valid_until <= issued_at + 6 h; floor issued_at's UTC date less 90 days, or null, and then every keep step's keep_bytes 0; basis.measured_at under an hour before issued_at; 1 to 2000 steps, each item once, keep_bytes (0 to 2^53 - 1) exactly on keep; basis_purge naming exactly the purge steps' items; secret 1 or more; mac v1= and 64 lowercase hex. " +
	"decisions: the order as the feed's document carries it (feed), what the app holds and sees, and its decision, in this order: check 1 on the feed's copy (contract.VerifyTrimOrder: the MAC under one of secrets, its app, workspace and generation the document's, and with floor null a plan source neither plan nor live_move), and when that copy verifies under none of the secrets (contract.ErrTrimMAC: its mac holds under none, or it has none or one that is no string, or it is not one well-formed object, names a member twice or is another app's body), check 4's GET first: no signed answer, rate_limited or unavailable, wait; a signed not_found or a document with no trim, refused not_current; else check 1 on that answer's copy, only whose failure is invalid_order; any other failure of check 1 on the feed's copy (its MAC holding) is refused invalid_order; invalid_order is recorded nowhere. An order whose order_id has a recorded result: resend, that result unchanged. Before valid_until (exclusive), wait while now is before not_before (inclusive) or generation_confirmed is false: no result, no record, no round. Then refused held (the allow shut, or a local brake holding the workspace at observe), refused expired (now at or after valid_until), check 4 (get: doc with get_doc, none, rate_limited, unavailable or not_found; no signed answer, rate_limited and unavailable wait; not_found, a document with no trim or another order_id, refused not_current; the same order_id: check 1 again on that copy, used from here), with a floor check 5 (basis, the report its basis names as the app kept it, null when it no longer does: usage_moved; else usage now within max(1 % of the GET's quota_bytes, 100 MB) of it, in total and for each step's item, a purge step whose item was purged already left out with its basis bytes; else usage_moved), check 6 (a step's item absent, or purged on a keep step: item_unknown; then per step: a purge step's item deleted with its basis_purge and a keep step's live run, else that step alone item_changed; a purge step whose item the app purged since: done with 0). steps: what a run does with each step. " +
	"runs: an order the app took (order), and per step the events before it starts (before; none for the first) and between its batches (between): same (check 4's GET answered the same order_id), feed_same (the feed applied a newer document carrying the same order_id, as after a step's own item.purged or a report), batch, report, purged_event and snapshot go on; none, rate_limited and unavailable wait, running nothing; expired, held, other, not_found, no_trim, feed_null and feed_other (the feed applied a document whose trim is null or another order) and interrupted stop the order with expired, held, not_current or interrupted; item: the step's item at its check 6 (as_ordered; changed: refused item_changed and the run goes on; purged_since: done with 0); bytes_after and at_floor (a keep step stopped at the floor above keep_bytes: partial). reported: the result the app reports, with usage_seq. " +
	"results: a result decoded strictly, then Validate, and with for_order ValidateFor the file's order: outcome done (every step done), partial or refused; code one of not_current, expired, usage_moved, item_unknown, invalid_order, held on refused, null or one of held, expired, not_current, interrupted on partial, null on done; steps [] on refused, else each step once, outcome done, partial, refused (code item_changed) or not_run (only once the order stopped, and every step after it), bytes_after null on refused and not_run; usage_seq null exactly on refused; against the order: its order_id, its steps in its order, a purge step done at 0 bytes. " +
	"answers: the platform's answer, read as an app reads what the platform sends, then Validate: accepted or duplicate with code null; rejected with invalid_request, not_found or conflict; order_id a UUID, or \"\" on a rejected invalid_request alone."

func trimOrders(out *WireTrim) error {
	base := signedOrder(vecOrder("wappie", nil), SecretA, 2)
	steps := func(n int) func(*contract.TrimOrder) {
		return func(o *contract.TrimOrder) {
			o.Steps = many(n, func(i int) contract.TrimStep {
				return contract.TrimStep{Item: fmt.Sprintf("dev_%d", i+1), Action: contract.TrimActionKeep, KeepBytes: ptr[int64](0)}
			})
			o.BasisPurge = map[string]contract.Time{}
		}
	}
	signed := func(mut func(*contract.TrimOrder)) json.RawMessage {
		return signedOrder(vecOrder("wappie", mut), SecretA, 2)
	}
	for _, c := range []struct {
		name  string
		raw   json.RawMessage
		valid bool
	}{
		{"the file's order", base, true},
		{"Mailie's order", signedOrder(vecOrder("mailie", nil), SecretA, 2), true},
		{"without a plan: floor null, keep_bytes 0", signed(noFloor), true},
		{"valid_until 6 hours after issued_at, the most", signed(nil), true},
		{"not_before 30 s after issued_at", signed(func(o *contract.TrimOrder) { o.NotBefore = at(30 * time.Second) }), true},
		{"not_before a second before valid_until", signed(func(o *contract.TrimOrder) { o.NotBefore = at(6*time.Hour - time.Second) }), true},
		{"round 3, the last", signed(func(o *contract.TrimOrder) { o.Round = 3 }), true},
		{"keep steps only: basis_purge {}", signed(func(o *contract.TrimOrder) {
			o.Steps, o.BasisPurge = o.Steps[1:], map[string]contract.Time{}
		}), true},
		{"a keep step keeping 0 with a floor", signed(func(o *contract.TrimOrder) { o.Steps[1].KeepBytes = ptr[int64](0) }), true},
		{"2000 steps, the most", signed(steps(contract.MaxTrimSteps)), true},
		{"secret 1", signedOrder(vecOrder("wappie", nil), SecretA, 1), true},
		{"a basis 59 minutes before issued_at", signed(func(o *contract.TrimOrder) { o.Basis.MeasuredAt = at(-59 * time.Minute) }), true},
		{"a member the app does not know, ignored", edit(base, `"round":1`, `"round":1,"reason":"day 30"`), true},
		{"valid_until 6 hours and a second after issued_at", signed(func(o *contract.TrimOrder) { o.ValidUntil = at(6*time.Hour + time.Second) }), false},
		{"not_before before issued_at", signed(func(o *contract.TrimOrder) { o.NotBefore = at(-time.Second) }), false},
		{"not_before at valid_until", signed(func(o *contract.TrimOrder) { o.NotBefore = o.ValidUntil }), false},
		{"a floor a day later than issued_at's date less 90 days", signed(func(o *contract.TrimOrder) {
			o.Floor = ptr(contract.RecentFrom(Now).AddDate(0, 0, 1).Format(time.DateOnly))
		}), false},
		{"a floor a day earlier", signed(func(o *contract.TrimOrder) {
			o.Floor = ptr(contract.RecentFrom(Now).AddDate(0, 0, -1).Format(time.DateOnly))
		}), false},
		{"a null floor with a keep_bytes above 0", signed(func(o *contract.TrimOrder) { o.Floor = nil }), false},
		{"basis_purge missing a purge step's item", signed(func(o *contract.TrimOrder) { o.BasisPurge = map[string]contract.Time{} }), false},
		{"basis_purge naming a keep step's item too", signed(func(o *contract.TrimOrder) { o.BasisPurge["dev_7"] = vecPurgeAt }), false},
		{"basis_purge naming an item not in the order", signed(func(o *contract.TrimOrder) { o.BasisPurge["dev_8"] = vecPurgeAt }), false},
		{"keep_bytes on a purge step", signed(func(o *contract.TrimOrder) { o.Steps[0].KeepBytes = ptr[int64](0) }), false},
		{"a keep step without keep_bytes", signed(func(o *contract.TrimOrder) { o.Steps[1].KeepBytes = nil }), false},
		{"keep_bytes null", edit(base, `"keep_bytes":14000000000`, `"keep_bytes":null`), false},
		{"keep_bytes below 0", signed(func(o *contract.TrimOrder) { o.Steps[1].KeepBytes = ptr[int64](-1) }), false},
		{"an action the part does not know", signed(func(o *contract.TrimOrder) { o.Steps[0].Action = "delete" }), false},
		{"secret 0", edit(base, `"secret":2`, `"secret":0`), false},
		{"round 0", signed(func(o *contract.TrimOrder) { o.Round = 0 }), false},
		{"round 4", signed(func(o *contract.TrimOrder) { o.Round = 4 }), false},
		{"2001 steps", signed(steps(contract.MaxTrimSteps + 1)), false},
		{"no step", signed(func(o *contract.TrimOrder) { o.Steps, o.BasisPurge = []contract.TrimStep{}, map[string]contract.Time{} }), false},
		{"a step's item twice", signed(func(o *contract.TrimOrder) { o.Steps[1].Item = o.Steps[0].Item }), false},
		{"an order_id that is a UUIDv4", signed(func(o *contract.TrimOrder) { o.OrderID = "0199c3a0-0000-4000-8000-000000000101" }), false},
		{"an episode that is no UUID", signed(func(o *contract.TrimOrder) { o.Episode = "episode-1" }), false},
		{"a basis an hour before issued_at", signed(func(o *contract.TrimOrder) { o.Basis.MeasuredAt = at(-time.Hour) }), false},
		{"a basis measured after issued_at by more than 60 s", signed(func(o *contract.TrimOrder) { o.Basis.MeasuredAt = at(2 * time.Minute) }), false},
		{"a mac in capitals", edit(base, `"mac":"v1=`, `"mac":"V1=`), false},
		{"no mac", edit(base, `,"mac":"`+must(macOf(base))+`"`, ``), false},
		{"floor missing", edit(base, `"floor":"`+contract.TrimFloor(Now)+`",`, ``), false},
	} {
		if got := orderValid(c.raw); got != c.valid {
			return fmt.Errorf("contractvec: order %q is valid %v, the spec asks %v", c.name, got, c.valid)
		}
		out.Orders = append(out.Orders, wireCase(c.name, c.raw, c.valid))
	}
	return nil
}

func trimDecisions(out *WireTrim) error {
	t := func(d time.Duration) string { return at(d).Format(time.RFC3339) }
	purgeAt := vecPurgeAt.Format(time.RFC3339)
	signed := func(mut func(*contract.TrimOrder)) json.RawMessage {
		return signedOrder(vecOrder("wappie", mut), SecretA, 2)
	}
	planFeed := func(raw json.RawMessage) json.RawMessage { return carrier("wappie", raw, contract.SourcePlan) }
	withFloor := planFeed(signed(nil))
	noPlan := carrier("wappie", signed(noFloor), contract.SourceNone)
	items := map[string]ItemNow{"dev_9": {State: "deleted", PurgeAt: &purgeAt}, "dev_7": {State: "live"}}
	basis := &UsageFigures{Total: 26100000000, Items: map[string]int64{"dev_9": 4800000000, "dev_7": 21000000000}}
	usage := UsageFigures{Total: 26100000000, Items: map[string]int64{"dev_9": 4800000000, "dev_7": 21000000000}}
	one := []string{SecretA}
	base := func(name string, mut func(*TrimDecision)) TrimDecision {
		d := TrimDecision{Name: name, App: "wappie", Now: t(time.Minute), Secrets: one, GenerationConfirmed: true, AllowOpen: true,
			Feed: withFloor, Get: "doc", GetDoc: withFloor, Basis: basis, Usage: usage, Items: items}
		if mut != nil {
			mut(&d)
		}
		return d
	}
	with := func(m map[string]ItemNow, id string, it ItemNow) map[string]ItemNow {
		c := map[string]ItemNow{}
		for k, v := range m {
			c[k] = v
		}
		c[id] = it
		return c
	}
	recorded := func(code string) *contract.TrimResult {
		return &contract.TrimResult{OrderID: vecOrderID, Outcome: contract.TrimOutcomeRefused, Code: &code, Steps: []contract.TrimStepResult{}}
	}
	taken := &contract.TrimResult{OrderID: vecOrderID, Outcome: contract.TrimOutcomeDone, Steps: []contract.TrimStepResult{
		{Item: "dev_9", Outcome: contract.TrimOutcomeDone, BytesAfter: ptr[int64](0)},
		{Item: "dev_7", Outcome: contract.TrimOutcomeDone, BytesAfter: ptr[int64](14000000000)}}, UsageSeq: ptr(Now.Add(time.Hour).UnixMilli())}
	other := planFeed(signed(func(o *contract.TrimOrder) { o.OrderID = vecOrderID2 }))
	noTrim := mustRaw(vecEnt("wappie", func(d *contract.EntitlementsDoc) {
		active(d)
		d.Plan = contract.EntitlementsPlan{Source: contract.SourcePlan, Test: true, Numbers: 2, Mailboxes: 1}
	}))
	movedBy := func(n int64) UsageFigures {
		return UsageFigures{Total: usage.Total + n, Items: map[string]int64{"dev_9": 4800000000, "dev_7": 21000000000 + n}}
	}
	for _, c := range []struct {
		d      TrimDecision
		action string
		code   string
	}{
		{base("everything holds: the steps run", nil), "run", ""},
		{base("an order with no plan: no check 5, however usage moved", func(d *TrimDecision) {
			d.Feed, d.GetDoc, d.Usage = noPlan, noPlan, movedBy(5000000000)
		}), "run", ""},
		{base("Mailie's order", func(d *TrimDecision) {
			d.App = "mailie"
			mf := carrier("mailie", signedOrder(vecOrder("mailie", nil), SecretA, 2), contract.SourcePlan)
			d.Feed, d.GetDoc = mf, mf
			pa := purgeAt
			d.Items = map[string]ItemNow{"acc_9b21": {State: "deleted", PurgeAt: &pa}, "acc_7f3a": {State: "live"}}
			d.Basis = &UsageFigures{Total: 25800000000, Items: map[string]int64{"acc_9b21": 4800000000, "acc_7f3a": 21000000000}}
			d.Usage = UsageFigures{Total: 25800000000, Items: map[string]int64{"acc_9b21": 4800000000, "acc_7f3a": 21000000000}}
		}), "run", ""},
		{base("check 1: another app's body verifies under nothing, nor does the GET's copy: invalid_order", func(d *TrimDecision) { d.App = "mailie" }), "refused", contract.TrimCodeInvalidOrder},
		{base("check 1: a null floor beside a document whose plan.source is plan", func(d *TrimDecision) {
			bad := planFeed(signed(noFloor))
			d.Feed, d.GetDoc = bad, bad
		}), "refused", contract.TrimCodeInvalidOrder},
		{base("check 1: a feed copy no held secret verifies, the GET's copy verifying: judged on the GET's copy", func(d *TrimDecision) {
			d.Secrets = []string{SecretB}
			d.GetDoc = planFeed(signedOrder(vecOrder("wappie", nil), SecretB, 3))
		}), "run", ""},
		{base("check 1: a waiting order whose feed copy's secret the app dropped before not_before, judged on the GET's copy", func(d *TrimDecision) {
			late := func(o *contract.TrimOrder) { o.NotBefore = at(30 * time.Second) }
			d.Secrets = []string{SecretB}
			d.Feed = planFeed(signedOrder(vecOrder("wappie", late), SecretA, 2))
			d.GetDoc = planFeed(signedOrder(vecOrder("wappie", late), SecretB, 3))
		}), "run", ""},
		{base("check 1: a feed copy no held secret verifies, the GET unanswered: wait", func(d *TrimDecision) {
			d.Secrets, d.Get, d.GetDoc = []string{SecretB}, "none", nil
		}), "wait", ""},
		{base("check 1: a feed copy no held secret verifies, the GET a signed not_found: not_current", func(d *TrimDecision) {
			d.Secrets, d.Get, d.GetDoc = []string{SecretB}, contract.CodeNotFound, nil
		}), "refused", contract.TrimCodeNotCurrent},
		{base("check 1: a feed copy no held secret verifies, the GET's document carrying no trim: not_current", func(d *TrimDecision) {
			d.Secrets, d.GetDoc = []string{SecretB}, noTrim
		}), "refused", contract.TrimCodeNotCurrent},
		{base("check 1: a feed copy no held secret verifies, nor the GET's copy", func(d *TrimDecision) {
			d.Secrets = []string{SecretB}
			d.GetDoc = planFeed(signedOrder(vecOrder("wappie", nil), SecretC, 3))
		}), "refused", contract.TrimCodeInvalidOrder},
		{base("check 1 again on the GET's copy: its mac does not hold", func(d *TrimDecision) {
			d.GetDoc = planFeed(signedOrder(vecOrder("wappie", nil), SecretC, 3))
		}), "refused", contract.TrimCodeInvalidOrder},
		{base("invalid_order before held", func(d *TrimDecision) {
			d.App, d.AllowOpen = "mailie", false
		}), "refused", contract.TrimCodeInvalidOrder},
		{base("check 2: the allow shut", func(d *TrimDecision) { d.AllowOpen = false }), "refused", contract.TrimCodeHeld},
		{base("check 2: a local brake holds the workspace at observe", func(d *TrimDecision) { d.HeldAtObserve = true }), "refused", contract.TrimCodeHeld},
		{base("held before an expired window", func(d *TrimDecision) { d.AllowOpen, d.Now = false, t(7*time.Hour) }), "refused", contract.TrimCodeHeld},
		{base("check 3: at valid_until", func(d *TrimDecision) { d.Now = t(6 * time.Hour) }), "refused", contract.TrimCodeExpired},
		{base("check 4: no signed answer: wait", func(d *TrimDecision) { d.Get, d.GetDoc = "none", nil }), "wait", ""},
		{base("check 4: a signed rate_limited: wait", func(d *TrimDecision) { d.Get, d.GetDoc = contract.CodeRateLimited, nil }), "wait", ""},
		{base("check 4: a signed unavailable: wait", func(d *TrimDecision) { d.Get, d.GetDoc = "unavailable", nil }), "wait", ""},
		{base("check 4: no signed answer past valid_until: expired", func(d *TrimDecision) {
			d.Get, d.GetDoc, d.Now = "none", nil, t(6*time.Hour+time.Second)
		}), "refused", contract.TrimCodeExpired},
		{base("check 4: a signed not_found", func(d *TrimDecision) { d.Get, d.GetDoc = contract.CodeNotFound, nil }), "refused", contract.TrimCodeNotCurrent},
		{base("check 4: the GET's document carries another order_id", func(d *TrimDecision) { d.GetDoc = other }), "refused", contract.TrimCodeNotCurrent},
		{base("check 4: the GET's document carries no trim", func(d *TrimDecision) { d.GetDoc = noTrim }), "refused", contract.TrimCodeNotCurrent},
		{base("check 5: usage within the tolerance, 1 % of the quota", func(d *TrimDecision) { d.Usage = movedBy(150000000) }), "run", ""},
		{base("check 5: usage moved a byte past the tolerance", func(d *TrimDecision) { d.Usage = movedBy(150000001) }), "refused", contract.TrimCodeUsageMoved},
		{base("check 5: usage moved down past the tolerance", func(d *TrimDecision) { d.Usage = movedBy(-150000001) }), "refused", contract.TrimCodeUsageMoved},
		{base("check 5: one item moved past the tolerance, the total within", func(d *TrimDecision) {
			d.Usage = UsageFigures{Total: usage.Total, Items: map[string]int64{"dev_9": 4800000000 - 200000000, "dev_7": 21000000000 + 200000000}}
		}), "refused", contract.TrimCodeUsageMoved},
		{base("check 5: the basis report no longer held", func(d *TrimDecision) { d.Basis = nil }), "refused", contract.TrimCodeUsageMoved},
		{base("check 6: a step's item not the app's", func(d *TrimDecision) { d.Items = with(items, "dev_7", ItemNow{State: "absent"}) }), "refused", contract.TrimCodeItemUnknown},
		{base("check 6: a purge step whose item the app purged since: done with 0, its bytes left out of check 5", func(d *TrimDecision) {
			d.Items = with(items, "dev_9", ItemNow{State: "purged"})
			d.Usage = UsageFigures{Total: usage.Total - 4800000000, Items: map[string]int64{"dev_7": 21000000000}}
		}), "run", ""},
		{base("check 6: a purge step's item recovered: that step alone item_changed", func(d *TrimDecision) {
			d.Items = with(items, "dev_9", ItemNow{State: "live"})
		}), "run", ""},
		{base("check 6: a purge step's item deleted again since, with another purge_at", func(d *TrimDecision) {
			later := t(30 * 24 * time.Hour)
			d.Items = with(items, "dev_9", ItemNow{State: "deleted", PurgeAt: &later})
		}), "run", ""},
		{base("check 6: a keep step's item deleted since", func(d *TrimDecision) {
			d.Items = with(items, "dev_7", ItemNow{State: "deleted", PurgeAt: &purgeAt})
		}), "run", ""},
		{base("wait 30 s before not_before", func(d *TrimDecision) {
			late := planFeed(signed(func(o *contract.TrimOrder) { o.NotBefore = at(time.Minute) }))
			d.Feed, d.GetDoc, d.Now = late, late, t(30*time.Second)
		}), "wait", ""},
		{base("run at not_before", func(d *TrimDecision) {
			late := planFeed(signed(func(o *contract.TrimOrder) { o.NotBefore = at(time.Minute) }))
			d.Feed, d.GetDoc, d.Now = late, late, t(time.Minute)
		}), "run", ""},
		{base("wait while generation_confirmed is false", func(d *TrimDecision) { d.GenerationConfirmed = false }), "wait", ""},
		{base("a recorded held, sent again though the allow is open now", func(d *TrimDecision) { d.Recorded = recorded(contract.TrimCodeHeld) }), "resend", ""},
		{base("a recorded usage_moved, sent again though usage is back within tolerance", func(d *TrimDecision) {
			d.Recorded = recorded(contract.TrimCodeUsageMoved)
		}), "resend", ""},
		{base("an order taken and reported, reaching the app again: its result sent again", func(d *TrimDecision) { d.Recorded = taken }), "resend", ""},
		{base("a recorded result of another order: this one judged", func(d *TrimDecision) {
			r := recorded(contract.TrimCodeHeld)
			r.OrderID = vecOrderID2
			d.Recorded = r
		}), "run", ""},
		{base("a forged feed copy under no held secret, the GET unanswered: wait, nothing recorded", func(d *TrimDecision) {
			d.Feed = planFeed(json.RawMessage(withMAC(signed(nil), "v1="+strings.Repeat("ab", 32))))
			d.Secrets, d.Get, d.GetDoc = one, "none", nil
		}), "wait", ""},
	} {
		action, code, steps, err := trimDecide(c.d)
		if err != nil {
			return fmt.Errorf("contractvec: decision %q: %w", c.d.Name, err)
		}
		got := ""
		if code != nil {
			got = *code
		}
		if action != c.action || got != c.code {
			return fmt.Errorf("contractvec: decision %q is %s %s, the spec asks %s %s", c.d.Name, action, got, c.action, c.code)
		}
		c.d.Action, c.d.Code, c.d.Steps = action, code, steps
		out.Decisions = append(out.Decisions, c.d)
	}
	// The step plans the spec names.
	want := map[string]string{
		"everything holds: the steps run": "run run",
		"check 6: a purge step whose item the app purged since: done with 0, its bytes left out of check 5": "done run",
		"check 6: a purge step's item recovered: that step alone item_changed":                              "item_changed run",
		"check 6: a purge step's item deleted again since, with another purge_at":                           "item_changed run",
		"check 6: a keep step's item deleted since":                                                         "run item_changed",
	}
	for _, d := range out.Decisions {
		w, ok := want[d.Name]
		if !ok {
			continue
		}
		var got []string
		for _, s := range d.Steps {
			got = append(got, s.Action)
		}
		if strings.Join(got, " ") != w {
			return fmt.Errorf("contractvec: decision %q runs %v, the spec asks %s", d.Name, got, w)
		}
	}
	for _, code := range contract.TrimRefusedCodes() {
		found := false
		for _, d := range out.Decisions {
			found = found || (d.Code != nil && *d.Code == code)
		}
		if !found {
			return fmt.Errorf("contractvec: no decision refuses %s", code)
		}
	}
	return nil
}

func trimRuns(out *WireTrim) error {
	order := signedOrder(vecOrder("wappie", nil), SecretA, 2)
	three := signedOrder(vecOrder("wappie", func(o *contract.TrimOrder) {
		o.Steps = []contract.TrimStep{{Item: "dev_9", Action: contract.TrimActionPurge}, {Item: "dev_8", Action: contract.TrimActionPurge},
			{Item: "dev_7", Action: contract.TrimActionKeep, KeepBytes: ptr[int64](14000000000)}}
		o.BasisPurge["dev_8"] = vecPurgeAt
	}), SecretA, 2)
	seq := Now.Add(time.Hour).UnixMilli()
	done := func(n int64) RunStep { return RunStep{Item: "as_ordered", BytesAfter: n} }
	type want struct {
		outcome string
		code    string
		steps   string
	}
	for _, c := range []struct {
		run  TrimRun
		want want
	}{
		{TrimRun{Name: "a purge, its item.purged, a report still over the quota and a snapshot without the item, the GET before step 2 the same order_id: done", App: "wappie",
			Order: order, Steps: []RunStep{done(0), {Before: []string{"purged_event", "report", "snapshot", "same"}, Item: "as_ordered", BytesAfter: 14000000000}}},
			want{"done", "", "done done"}},
		{TrimRun{Name: "a keep step whose 1 % report falls between its batches: done", App: "wappie",
			Order: order, Steps: []RunStep{done(0), {Before: []string{"same"}, Item: "as_ordered", Between: []string{"batch", "report", "batch", "same", "batch"}, BytesAfter: 14000000000}}},
			want{"done", "", "done done"}},
		{TrimRun{Name: "a keep step stopped at the floor above keep_bytes: partial, code null", App: "wappie",
			Order: order, Steps: []RunStep{done(0), {Before: []string{"same"}, Item: "as_ordered", BytesAfter: 15200000000, AtFloor: true}}},
			want{"partial", "", "done partial"}},
		{TrimRun{Name: "a next step's item recovered by a person since the basis: refused item_changed, the run goes on", App: "wappie",
			Order: three, Steps: []RunStep{done(0), {Before: []string{"same"}, Item: "changed"}, {Before: []string{"same"}, Item: "as_ordered", BytesAfter: 14000000000}}},
			want{"partial", "", "done refused done"}},
		{TrimRun{Name: "a next purge step whose item the app purged since: done with 0", App: "wappie",
			Order: three, Steps: []RunStep{done(0), {Before: []string{"same"}, Item: "purged_since"}, {Before: []string{"same"}, Item: "as_ordered", BytesAfter: 14000000000}}},
			want{"done", "", "done done done"}},
		{TrimRun{Name: "check 4's GET before step 2 with no answer, then a signed unavailable, then valid_until passes: partial expired", App: "wappie",
			Order: order, Steps: []RunStep{done(0), {Before: []string{"none", "unavailable", "expired"}, Item: "as_ordered"}}},
			want{"partial", contract.TrimCodeExpired, "done not_run"}},
		{TrimRun{Name: "check 4's GET between batches with no answer, then the same order_id: done", App: "wappie",
			Order: order, Steps: []RunStep{done(0), {Before: []string{"same"}, Item: "as_ordered", Between: []string{"batch", "none", "rate_limited", "same", "batch"}, BytesAfter: 14000000000}}},
			want{"done", "", "done done"}},
		{TrimRun{Name: "check 4's GET between batches unanswered until valid_until passes: the step partial, expired", App: "wappie",
			Order: order, Steps: []RunStep{done(0), {Before: []string{"same"}, Item: "as_ordered", Between: []string{"batch", "none", "expired"}, BytesAfter: 18000000000}}},
			want{"partial", contract.TrimCodeExpired, "done partial"}},
		{TrimRun{Name: "a run stopped after its first step, a plan bought meanwhile, by a GET answering another order_id: not_current", App: "wappie",
			Order: three, Steps: []RunStep{done(0), {Before: []string{"other"}, Item: "as_ordered"}, {Item: "as_ordered"}}},
			want{"partial", contract.TrimCodeNotCurrent, "done not_run not_run"}},
		{TrimRun{Name: "the feed applies a document whose trim is null between batches: not_current", App: "wappie",
			Order: order, Steps: []RunStep{done(0), {Before: []string{"same"}, Item: "as_ordered", Between: []string{"batch", "feed_null"}, BytesAfter: 19000000000}}},
			want{"partial", contract.TrimCodeNotCurrent, "done partial"}},
		{TrimRun{Name: "a purge step's own item.purged, then the feed applies a newer document carrying the same order_id: the run goes on, done", App: "wappie",
			Order: order, Steps: []RunStep{done(0), {Before: []string{"purged_event", "feed_same", "same"}, Item: "as_ordered", BytesAfter: 14000000000}}},
			want{"done", "", "done done"}},
		{TrimRun{Name: "a keep step's report between batches, then a newer feed document carrying the same order_id: the run goes on, done", App: "wappie",
			Order: order, Steps: []RunStep{done(0), {Before: []string{"same"}, Item: "as_ordered", Between: []string{"batch", "report", "feed_same", "batch"}, BytesAfter: 14000000000}}},
			want{"done", "", "done done"}},
		{TrimRun{Name: "the feed applies a document carrying another order after a step's item.purged: partial, not_current", App: "wappie",
			Order: three, Steps: []RunStep{done(0), {Before: []string{"purged_event", "feed_other"}, Item: "as_ordered"}, {Item: "as_ordered"}}},
			want{"partial", contract.TrimCodeNotCurrent, "done not_run not_run"}},
		{TrimRun{Name: "the allow shut before step 2: held", App: "wappie",
			Order: order, Steps: []RunStep{done(0), {Before: []string{"held"}, Item: "as_ordered"}}},
			want{"partial", contract.TrimCodeHeld, "done not_run"}},
		{TrimRun{Name: "an interrupted order: partial interrupted, running nothing more", App: "wappie",
			Order: three, Steps: []RunStep{done(0), {Before: []string{"same"}, Item: "as_ordered", Between: []string{"interrupted"}, BytesAfter: 0}, {Item: "as_ordered"}}},
			want{"partial", contract.TrimCodeInterrupted, "done partial not_run"}},
		{TrimRun{Name: "an order interrupted in its first step", App: "mailie",
			Order: signedOrder(vecOrder("mailie", nil), SecretA, 2), Steps: []RunStep{{Item: "as_ordered", Between: []string{"batch", "interrupted"}, BytesAfter: 2000000000}, {Item: "as_ordered"}}},
			want{"partial", contract.TrimCodeInterrupted, "partial not_run"}},
	} {
		c.run.UsageSeq = seq
		res, err := trimRun(c.run)
		if err != nil {
			return err
		}
		var o contract.TrimOrder
		if err := json.Unmarshal(c.run.Order, &o); err != nil {
			return err
		}
		if err := res.ValidateFor(o); err != nil {
			return fmt.Errorf("contractvec: run %q reports a result that is not valid: %w", c.run.Name, err)
		}
		code := ""
		if res.Code != nil {
			code = *res.Code
		}
		var steps []string
		for _, s := range res.Steps {
			steps = append(steps, s.Outcome)
		}
		if res.Outcome != c.want.outcome || code != c.want.code || strings.Join(steps, " ") != c.want.steps {
			return fmt.Errorf("contractvec: run %q reports %s %s %v, the spec asks %+v", c.run.Name, res.Outcome, code, steps, c.want)
		}
		c.run.Reported = mustRaw(res)
		out.Runs = append(out.Runs, c.run)
	}
	return nil
}

func trimResults(out *WireTrim) error {
	seq := Now.Add(time.Hour).UnixMilli()
	step := func(item, outcome string, bytes *int64) contract.TrimStepResult {
		s := contract.TrimStepResult{Item: item, Outcome: outcome, BytesAfter: bytes}
		if outcome == contract.TrimOutcomeRefused {
			s.Code = ptr(contract.TrimCodeItemChanged)
		}
		return s
	}
	res := func(outcome string, code *string, steps ...contract.TrimStepResult) json.RawMessage {
		r := contract.TrimResult{OrderID: vecOrderID, Outcome: outcome, Code: code, Steps: append([]contract.TrimStepResult{}, steps...), UsageSeq: ptr(seq)}
		if outcome == contract.TrimOutcomeRefused {
			r.UsageSeq = nil
		}
		return mustRaw(r)
	}
	n := func(v int64) *int64 { return &v }
	code := func(c string) *string { return &c }
	doneBoth := res(contract.TrimOutcomeDone, nil, step("dev_9", "done", n(0)), step("dev_7", "done", n(14000000000)))
	type rc struct {
		name     string
		forOrder bool
		raw      json.RawMessage
		valid    bool
	}
	cases := []rc{
		{"done: every step reached its target", true, doneBoth, true},
		{"partial: the keep step stopped at the floor", true, res("partial", nil, step("dev_9", "done", n(0)), step("dev_7", "partial", n(15200000000))), true},
		{"partial: a step refused item_changed", true, res("partial", nil, step("dev_9", "refused", nil), step("dev_7", "done", n(14000000000))), true},
		{"partial interrupted, a step not_run", true, res("partial", code(contract.TrimCodeInterrupted), step("dev_9", "partial", n(100)), step("dev_7", "not_run", nil)), true},
		{"a code on a stopped partial: held", true, res("partial", code(contract.TrimCodeHeld), step("dev_9", "done", n(0)), step("dev_7", "not_run", nil)), true},
		{"a code on a stopped partial: expired, the step under way partial", true, res("partial", code(contract.TrimCodeExpired), step("dev_9", "done", n(0)), step("dev_7", "partial", n(18000000000))), true},
		{"a code on a stopped partial: not_current, nothing not_run", true, res("partial", code(contract.TrimCodeNotCurrent), step("dev_9", "done", n(0)), step("dev_7", "partial", n(19000000000))), true},
	}
	for _, c := range contract.TrimRefusedCodes() {
		cases = append(cases, rc{"refused " + c, true, res("refused", code(c)), true})
	}
	cases = append(cases, []rc{
		{"refused for another order: valid alone", false, edit(res("refused", code(contract.TrimCodeHeld)), vecOrderID, vecOrderID2), true},
		{"done with a step not_run", false, res("done", nil, step("dev_9", "done", n(0)), step("dev_7", "not_run", nil)), false},
		{"done with a code", false, res("done", code(contract.TrimCodeExpired), step("dev_9", "done", n(0)), step("dev_7", "done", n(1))), false},
		{"done with a step partial", false, res("done", nil, step("dev_9", "done", n(0)), step("dev_7", "partial", n(1))), false},
		{"refused with steps", false, edit(res("refused", code(contract.TrimCodeHeld)), `"steps":[]`, `"steps":[{"item":"dev_9","outcome":"not_run","code":null,"bytes_after":null}]`), false},
		{"refused with a usage_seq", false, edit(res("refused", code(contract.TrimCodeHeld)), `"usage_seq":null`, fmt.Sprintf(`"usage_seq":%d`, seq)), false},
		{"refused with no code", false, edit(res("refused", code(contract.TrimCodeHeld)), `"code":"held"`, `"code":null`), false},
		{"refused interrupted", false, res("refused", code(contract.TrimCodeInterrupted)), false},
		{"refused item_changed", false, res("refused", code(contract.TrimCodeItemChanged)), false},
		{"a partial stopped usage_moved", false, res("partial", code(contract.TrimCodeUsageMoved), step("dev_9", "done", n(0)), step("dev_7", "not_run", nil)), false},
		{"not_run in an order that did not stop", false, res("partial", nil, step("dev_9", "done", n(0)), step("dev_7", "not_run", nil)), false},
		{"a step after a not_run one that ran", false, res("partial", code(contract.TrimCodeHeld), step("dev_9", "not_run", nil), step("dev_7", "done", n(1))), false},
		{"a partial that did not stop with every step done", false, res("partial", nil, step("dev_9", "done", n(0)), step("dev_7", "done", n(14000000000))), false},
		{"bytes_after on a refused step", false, edit(res("partial", nil, step("dev_9", "refused", nil), step("dev_7", "done", n(14000000000))), `"code":"item_changed","bytes_after":null`, `"code":"item_changed","bytes_after":5`), false},
		{"bytes_after null on a done step", false, edit(doneBoth, `"bytes_after":0`, `"bytes_after":null`), false},
		{"a refused step with another code", false, edit(res("partial", nil, step("dev_9", "refused", nil), step("dev_7", "done", n(14000000000))), `"code":"item_changed"`, `"code":"item_unknown"`), false},
		{"a step outcome the part does not know", false, edit(doneBoth, `"outcome":"done","code":null,"bytes_after":0`, `"outcome":"skipped","code":null,"bytes_after":0`), false},
		{"usage_seq null on done", false, edit(doneBoth, fmt.Sprintf(`"usage_seq":%d`, seq), `"usage_seq":null`), false},
		{"an order_id that is no UUID", false, edit(doneBoth, vecOrderID, "order-1"), false},
		{"a member the part does not know", false, edit(doneBoth, `"outcome":"done","code":null,"steps"`, `"outcome":"done","code":null,"note":"ok","steps"`), false},
		{"against the order: its steps in another order", true, res("done", nil, step("dev_7", "done", n(14000000000)), step("dev_9", "done", n(0))), false},
		{"against the order: a step missing", true, res("partial", nil, step("dev_9", "done", n(0))), false},
		{"against the order: a step it does not hold", true, res("done", nil, step("dev_9", "done", n(0)), step("dev_7", "done", n(1)), step("dev_8", "done", n(1))), false},
		{"against the order: a purge step done above 0 bytes", true, res("done", nil, step("dev_9", "done", n(5)), step("dev_7", "done", n(14000000000))), false},
		{"against the order: another order_id", true, edit(doneBoth, vecOrderID, vecOrderID2), false},
	}...)
	for _, c := range cases {
		if got := trimResultValid(c.raw, out.Order, c.forOrder); got != c.valid {
			return fmt.Errorf("contractvec: result %q is valid %v, the spec asks %v", c.name, got, c.valid)
		}
		out.Results = append(out.Results, TrimResultCase{Name: c.name, ForOrder: c.forOrder, Value: c.raw, Valid: c.valid})
	}

	answer := func(id, outcome, code string) json.RawMessage {
		c := "null"
		if code != "" {
			c = `"` + code + `"`
		}
		return json.RawMessage(fmt.Sprintf(`{"order_id":"%s","outcome":"%s","code":%s}`, id, outcome, c))
	}
	for _, c := range []struct {
		name  string
		raw   json.RawMessage
		valid bool
	}{
		{"accepted", answer(vecOrderID, contract.OutcomeAccepted, ""), true},
		{"duplicate: the result is kept already", answer(vecOrderID, contract.OutcomeDuplicate, ""), true},
		{"rejected invalid_request", answer(vecOrderID, contract.OutcomeRejected, contract.CodeInvalid), true},
		{"rejected not_found: no order of the app with that id", answer(vecOrderID, contract.OutcomeRejected, contract.CodeNotFound), true},
		{"rejected conflict: another result is kept", answer(vecOrderID, contract.OutcomeRejected, contract.CodeConflict), true},
		{`rejected invalid_request echoing order_id ""`, answer("", contract.OutcomeRejected, contract.CodeInvalid), true},
		{"a member the app does not know, ignored", edit(answer(vecOrderID, contract.OutcomeAccepted, ""), `"code":null`, `"code":null,"kept_at":"x"`), true},
		{`order_id "" on accepted`, answer("", contract.OutcomeAccepted, ""), false},
		{`order_id "" on rejected not_found`, answer("", contract.OutcomeRejected, contract.CodeNotFound), false},
		{"a code on accepted", answer(vecOrderID, contract.OutcomeAccepted, contract.CodeConflict), false},
		{"rejected with no code", answer(vecOrderID, contract.OutcomeRejected, ""), false},
		{"rejected gone", answer(vecOrderID, contract.OutcomeRejected, "gone"), false},
		{"an outcome the part does not know", answer(vecOrderID, "kept", ""), false},
		{"an order_id that is no UUID", answer("order-1", contract.OutcomeAccepted, ""), false},
		{"no code member", json.RawMessage(`{"order_id":"` + vecOrderID + `","outcome":"accepted"}`), false},
	} {
		if got := trimAnswerValid(c.raw); got != c.valid {
			return fmt.Errorf("contractvec: answer %q is valid %v, the spec asks %v", c.name, got, c.valid)
		}
		out.Answers = append(out.Answers, wireCase(c.name, c.raw, c.valid))
	}
	return nil
}

// TrimMACCase is one order as an app receives it in a document whose plan
// source is plan_source, the secrets it holds, the order's canonical text
// without its mac, the MAC a signer computes over that text under the
// first secret, whether VerifyTrimOrder takes it, and whether it refuses
// it as verifying under nothing (ErrTrimMAC), which sends a feed's copy to
// check 4's GET first.
type TrimMACCase struct {
	Name       string   `json:"name"`
	App        string   `json:"app"`
	PlanSource string   `json:"plan_source"`
	Secrets    []string `json:"secrets"`
	Order      string   `json:"order"`
	JCS        string   `json:"jcs"`
	MAC        string   `json:"mac"`
	Valid      bool     `json:"valid"`
	MACFails   bool     `json:"mac_fails"`
}

// TrimMACs is trim-macs.json.
type TrimMACs struct {
	Format      string        `json:"format"`
	Version     int           `json:"version"`
	Kind        string        `json:"kind"`
	Description string        `json:"description"`
	Label       string        `json:"label"`
	MACs        []TrimMACCase `json:"macs"`
}

// trimMACOver is the MAC of msg, a canonical order, for app under key and
// label.
func trimMACOver(key []byte, label, app string, msg []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(label + "\n" + app + "\n"))
	h.Write(msg)
	return "v1=" + hex.EncodeToString(h.Sum(nil))
}

// verifyCarried is VerifyTrimOrder on order as the expired document of app
// whose plan source is planSource carries it: its trim the order's bytes
// as they came, even those a document's own decoding would refuse, so that
// VerifyTrimOrder judges them.
func verifyCarried(app, planSource, order string, secrets []string) error {
	var d contract.EntitlementsDoc
	if err := json.Unmarshal(carrier(app, json.RawMessage(`null`), planSource), &d); err != nil {
		return err
	}
	d.Trim = json.RawMessage(order)
	_, err := contract.VerifyTrimOrder(d, app, secrets)
	return err
}

func trimMACs() (any, error) {
	out := TrimMACs{
		Format: Format, Version: 1, Kind: "trim-macs", Label: contract.TrimMACLabel,
		Description: "The trim order's MAC (SPEC section 11.20): mac = \"v1=\" + lowercase hex(HMAC-SHA256(key = the secret's 43-character text, msg = label || \"\\n\" || app || \"\\n\" || JCS(the order as received, without mac))). order: the exact text of a document's trim as an app receives it; jcs: its canonical text without mac (RFC 8785), \"\" when it has none; mac: what a signer computes over jcs for app under the first of secrets, \"\" when jcs is; valid: whether contract.VerifyTrimOrder takes the order for app under secrets, each of which it tries, carried by an expired document of app at 2026-10-13T12:00:00Z whose plan.source is plan_source (none, or plan with one place of each kind): its MAC holds, it decodes and validates, it names the document's app, workspace and generation, and a floor null is refused beside plan or live_move. An order that is not one well-formed object, or names a member twice anywhere, or holds what JCS does not write (a fraction, an integer past 2^53 - 1), or is another app's body, verifies under nothing. mac_fails: whether VerifyTrimOrder refuses it as verifying under none of secrets (contract.ErrTrimMAC: its mac holds under none, or it has none or one that is no string, or it verifies under nothing as above), which sends a feed's copy to check 4's GET first (wire-trim.json's decisions); every other refusal, the floor's here, is invalid_order at once.",
	}
	plain := string(signedOrder(vecOrder("wappie", nil), SecretA, 2))
	add := func(name, app, planSource string, secrets []string, order string, valid bool) error {
		canonical, err := canonicalOf([]byte(order))
		mac := ""
		if err != nil || !strictJSON([]byte(order)) {
			canonical = ""
		} else {
			mac = trimMACOver([]byte(secrets[0]), contract.TrimMACLabel, app, []byte(canonical))
		}
		verr := verifyCarried(app, planSource, order, secrets)
		if (verr == nil) != valid {
			return fmt.Errorf("contractvec: trim mac %q verifies %v, the spec asks %v (%v)", name, verr == nil, valid, verr)
		}
		macFails := errors.Is(verr, contract.ErrTrimMAC)
		if !valid && macFails == errors.Is(verr, contract.ErrTrimFloor) {
			return fmt.Errorf("contractvec: trim mac %q fails %v: only the floor's case is no MAC failure", name, verr)
		}
		out.MACs = append(out.MACs, TrimMACCase{Name: name, App: app, PlanSource: planSource, Secrets: secrets, Order: order, JCS: canonical, MAC: mac, Valid: valid, MACFails: macFails})
		return nil
	}
	one := []string{SecretA}
	var indented bytes.Buffer
	if err := json.Indent(&indented, []byte(plain), "", "  "); err != nil {
		return nil, err
	}
	reordered, err := reorder([]byte(plain))
	if err != nil {
		return nil, err
	}
	resign := func(raw json.RawMessage) string {
		s, err := contract.SignTrimOrder(raw, "wappie", SecretA, 2)
		if err != nil {
			panic(err)
		}
		return string(s)
	}
	unknown := resign(edit(edit(json.RawMessage(plain), `"round":`, `"reason":"day 30","round":`), `"action":"purge"`, `"action":"purge","note":"deleted"`))
	fraction := resign(edit(edit(json.RawMessage(plain), `"issued_at":"`+at(0).Format(time.RFC3339)+`"`, `"issued_at":"2026-10-13T12:00:00.120Z"`),
		`"not_before":"`+at(0).Format(time.RFC3339)+`"`, `"not_before":"2026-10-13T12:00:00.120Z"`))
	mailie := string(signedOrder(vecOrder("mailie", nil), SecretB, 3))
	macHex := strings.TrimPrefix(must(macOf([]byte(plain))), "v1=")
	commandLabel := withMAC([]byte(plain), trimMACOver([]byte(SecretA), contract.CommandMACLabel, "wappie", []byte(must(canonicalOf([]byte(plain))))))
	forMailie := withMAC([]byte(plain), trimMACOver([]byte(SecretA), contract.TrimMACLabel, "mailie", []byte(must(canonicalOf([]byte(plain))))))
	noFloorOrder := string(signedOrder(vecOrder("wappie", noFloor), SecretA, 2))
	for _, c := range []struct {
		name, app, plan string
		secrets         []string
		order           string
		valid           bool
	}{
		{"an order as served: compact JCS", "wappie", contract.SourceNone, one, plain, true},
		{"the same indented", "wappie", contract.SourceNone, one, indented.String(), true},
		{"the same with its members in another order", "wappie", contract.SourceNone, one, reordered, true},
		{"an unknown member at the top and in a step", "wappie", contract.SourceNone, one, unknown, true},
		{"a time of 120 milliseconds, written .120Z", "wappie", contract.SourceNone, one, fraction, true},
		{"secret 2: the generation of the secret that made it", "wappie", contract.SourcePlan, one, plain, true},
		{"Mailie's, during a rotation: the next secret, generation 3", "mailie", contract.SourceNone, []string{SecretA, SecretB}, mailie, true},
		{"a floor null in a document with no plan", "wappie", contract.SourceNone, one, noFloorOrder, true},
		{"another secret", "wappie", contract.SourceNone, []string{SecretB}, plain, false},
		{"another app", "mailie", contract.SourceNone, one, plain, false},
		{"a body naming another app, under a MAC for this one", "mailie", contract.SourceNone, one, forMailie, false},
		{"a MAC under the command's label", "wappie", contract.SourceNone, one, commandLabel, false},
		{"a member changed after signing", "wappie", contract.SourceNone, one, string(edit(json.RawMessage(plain), `"keep_bytes":14000000000`, `"keep_bytes":1`)), false},
		{"no mac", "wappie", contract.SourceNone, one, strings.Replace(plain, `,"mac":"v1=`+macHex+`"`, "", 1), false},
		{"a mac in capitals", "wappie", contract.SourceNone, one, withMAC([]byte(plain), "v1="+strings.ToUpper(macHex)), false},
		{"a mac that is no string", "wappie", contract.SourceNone, one, strings.Replace(plain, `"mac":"v1=`+macHex+`"`, `"mac":7`, 1), false},
		{"a member twice at the top", "wappie", contract.SourceNone, one, strings.Replace(plain, `"round":1`, `"round":1,"round":1`, 1), false},
		{"a member twice inside steps", "wappie", contract.SourceNone, one, strings.Replace(plain, `"action":"purge"`, `"action":"purge","action":"purge"`, 1), false},
		{"not an object", "wappie", contract.SourceNone, one, `[` + plain + `]`, false},
		{"a fraction", "wappie", contract.SourceNone, one, strings.Replace(plain, `"keep_bytes":14000000000`, `"keep_bytes":14000000000.5`, 1), false},
		{"an integer past 2^53 - 1", "wappie", contract.SourceNone, one, strings.Replace(plain, `"keep_bytes":14000000000`, `"keep_bytes":9007199254740993`, 1), false},
		{"a floor null beside a granting document: refused, written to the security log", "wappie", contract.SourcePlan, one, noFloorOrder, false},
	} {
		if err := add(c.name, c.app, c.plan, c.secrets, c.order, c.valid); err != nil {
			return nil, err
		}
	}
	// The floor case fails as ErrTrimFloor, so that the app logs it.
	if err := verifyCarried("wappie", contract.SourcePlan, noFloorOrder, one); !errors.Is(err, contract.ErrTrimFloor) {
		return nil, fmt.Errorf("contractvec: a floor null beside a plan is %v, not ErrTrimFloor", err)
	}
	if !slices.ContainsFunc(out.MACs, func(c TrimMACCase) bool { return c.Valid }) {
		return nil, errors.New("contractvec: no trim MAC verifies")
	}
	return out, nil
}
