package contract

import (
	"bytes"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/thehappieco/kit/jcs"
)

// Trim orders (SPEC section 11.20): the platform's signed instruction to
// delete, for one (app, workspace), riding in the app's entitlements
// document (its trim member), only with mode enforce and state expired. An
// app runs only an order it verified (VerifyTrimOrder), decoded from the
// bytes it verified, and posts what became of it to
// POST /contract/v1/trim/results (TrimResult), whose answer is a
// TrimResultAnswer. Checks 2 to 6 of the spec's order, the waits, judging
// an order once, running it and the restore records are the app's, pinned
// by the vectors.

// The values and bounds of a trim order and its result.
const (
	// TrimMACLabel opens the message a trim order's MAC covers.
	TrimMACLabel = "thehappie-platform-trim/v1"

	// TrimResultBodyLimit is the body limit of
	// POST /contract/v1/trim/results: 512 KiB, which holds the largest
	// valid result, MaxTrimSteps steps of 64-character item ids.
	TrimResultBodyLimit = 512 << 10

	// MaxTrimSteps is the most steps one order holds.
	MaxTrimSteps = 2000
	// MaxTrimRound is the last round of an episode: rounds are 1 to 3.
	MaxTrimRound = 3
	// MaxTrimValidity is the longest an order is valid: valid_until is at
	// most issued_at plus 6 hours.
	MaxTrimValidity = 6 * time.Hour
	// MaxTrimBasisAge is how old the report an order was computed from may
	// be at issued_at: under an hour. Its measured_at, the app's clock, may
	// also lie up to MaxUsageMeasuredAhead after issued_at, as the
	// platform's intake accepts it.
	MaxTrimBasisAge = time.Hour

	// A step's action: purge the item for good, or keep at most
	// keep_bytes of it.
	TrimActionPurge = "purge"
	TrimActionKeep  = "keep"

	// A result's outcome: every step reached its target; a step stopped
	// at the floor or was refused, or the order stopped before its end; or
	// nothing ran.
	TrimOutcomeDone    = "done"
	TrimOutcomePartial = "partial"
	TrimOutcomeRefused = "refused"
	// A step's outcome also: the order stopped before it.
	TrimOutcomeNotRun = "not_run"

	// Why an order was refused, or stopped before its end.
	TrimCodeNotCurrent   = "not_current"
	TrimCodeExpired      = "expired"
	TrimCodeUsageMoved   = "usage_moved"
	TrimCodeItemUnknown  = "item_unknown"
	TrimCodeInvalidOrder = "invalid_order"
	TrimCodeHeld         = "held"
	TrimCodeInterrupted  = "interrupted"
	// Why one step was refused: its item is no longer its own in the
	// workspace, or no longer meets its action's state.
	TrimCodeItemChanged = "item_changed"
)

var (
	trimActions = []string{TrimActionPurge, TrimActionKeep}
	// trimRefusedCodes are a refused result's codes, in the spec's order
	// (15.13's code row).
	trimRefusedCodes = []string{TrimCodeNotCurrent, TrimCodeExpired, TrimCodeUsageMoved, TrimCodeItemUnknown,
		TrimCodeInvalidOrder, TrimCodeHeld}
	// trimStoppedCodes are a partial result's codes when the order stopped
	// before its end.
	trimStoppedCodes   = []string{TrimCodeHeld, TrimCodeExpired, TrimCodeNotCurrent, TrimCodeInterrupted}
	trimOutcomes       = []string{TrimOutcomeDone, TrimOutcomePartial, TrimOutcomeRefused}
	trimStepOutcomes   = []string{TrimOutcomeDone, TrimOutcomePartial, TrimOutcomeRefused, TrimOutcomeNotRun}
	trimAnswerOutcomes = []string{OutcomeAccepted, OutcomeDuplicate, OutcomeRejected}
	trimAnswerCodes    = []string{CodeInvalid, CodeNotFound, CodeConflict}
)

// TrimActions are a step's actions: purge, keep. It returns a copy.
func TrimActions() []string { return slices.Clone(trimActions) }

// TrimRefusedCodes are a refused result's codes: not_current, expired,
// usage_moved, item_unknown, invalid_order, held. It returns a copy.
func TrimRefusedCodes() []string { return slices.Clone(trimRefusedCodes) }

// TrimStoppedCodes are the codes of a partial result whose order stopped
// before its end: held, expired, not_current, interrupted. It returns a
// copy.
func TrimStoppedCodes() []string { return slices.Clone(trimStoppedCodes) }

// TrimOutcomes are a result's outcomes: done, partial, refused. It returns
// a copy.
func TrimOutcomes() []string { return slices.Clone(trimOutcomes) }

// TrimStepOutcomes are a step's outcomes: done, partial, refused, not_run.
// It returns a copy.
func TrimStepOutcomes() []string { return slices.Clone(trimStepOutcomes) }

// ErrTrimMAC is a trim order that verifies under none of the secrets an
// app holds: its mac holds under none of them, or it has none, or one that
// is not a string; it is not one well-formed JSON object (a member twice
// anywhere, or what JCS does not write: a fraction, an integer past
// 2^53−1); or it is another app's body. A feed's copy that fails so sends
// the app to the workspace's GET first, whose copy it judges from check 1
// again (a waiting order served before a promote whose old secret the app
// has since dropped, or a copy that verifies under nothing); only a GET's
// copy that fails check 1 is refused invalid_order.
var ErrTrimMAC = errors.New("contract: the trim order's mac does not hold")

// ErrTrimFloor is a trim order with floor null carried by a document whose
// plan.source is plan or live_move: an order without a plan's floor beside
// a plan that grants. It is also ErrInvalid. The app refuses it
// invalid_order and writes it to its security log.
var ErrTrimFloor = errors.New("contract: a trim order without a floor beside a plan")

// TrimOrder is the platform's instruction to delete, for one (app,
// workspace): 0015's instruction, with 0045's and 0065's order (deleted
// items whole, then the items in use down to the floor). An app takes it
// only from VerifyTrimOrder, which decodes it from the bytes it verified;
// its UnmarshalJSON reads it as an app reads what the platform sends.
type TrimOrder struct {
	// OrderID is the order's UUIDv7, 0015's instruction_id: the
	// idempotency key of its result.
	OrderID     string `json:"order_id"`
	App         string `json:"app"`
	WorkspaceID string `json:"workspace_id"`
	Generation  string `json:"generation"`
	// Episode is the pause the order ends.
	Episode string `json:"episode"`
	// Round is the order's round in its episode, 1 to MaxTrimRound.
	Round      int  `json:"round"`
	IssuedAt   Time `json:"issued_at"`
	NotBefore  Time `json:"not_before"`
	ValidUntil Time `json:"valid_until"`
	// Floor is the UTC date YYYY-MM-DD before which a keep step may delete
	// (TrimFloor of IssuedAt) with a plan; nil (null) without one, and then
	// every keep step keeps 0 bytes.
	Floor *string `json:"floor"`
	// Basis is the app's report the order was computed from.
	Basis TrimBasis `json:"basis"`
	// Steps are the steps in the order to run, each item once.
	Steps []TrimStep `json:"steps"`
	// BasisPurge names exactly the purge steps' items, each with the
	// purge_at it was computed from.
	BasisPurge map[string]Time `json:"basis_purge"`
	// Secret is the generation number of the contract secret that made
	// MAC, for the platform's log.
	Secret int64  `json:"secret"`
	MAC    string `json:"mac"`
}

// String names the order by its id, app, workspace and generation, and
// prints no step, figure, floor or MAC.
func (o TrimOrder) String() string {
	return fmt.Sprintf("contract.TrimOrder{OrderID: %q, App: %q, WorkspaceID: %q, Generation: %q, %s}",
		o.OrderID, o.App, o.WorkspaceID, o.Generation, Ellipsis)
}

// GoString is String, for %#v.
func (o TrimOrder) GoString() string { return o.String() }

// LogValue is the order's id, app, workspace and generation, never a
// figure or its MAC.
func (o TrimOrder) LogValue() slog.Value {
	return slog.GroupValue(slog.String("order_id", o.OrderID), slog.String("app", o.App),
		slog.String("workspace_id", o.WorkspaceID), slog.String("generation", o.Generation))
}

// TrimBasis names the usage report an order was computed from.
type TrimBasis struct {
	UsageSeq   int64 `json:"usage_seq"`
	MeasuredAt Time  `json:"measured_at"`
}

// TrimStep is one step of an order: {"item", "action": "purge"} or
// {"item", "action": "keep", "keep_bytes"}. KeepBytes is set exactly on a
// keep step.
type TrimStep struct {
	Item      string `json:"item"`
	Action    string `json:"action"`
	KeepBytes *int64 `json:"keep_bytes,omitempty"`
}

// UnmarshalJSON reads a step as an app reads what the platform sends: a
// member it does not know ignored, a member counted only as exactly named;
// item and action present, each a string; keep_bytes, when present, an
// integer, never null. Validate holds keep_bytes to keep steps.
func (s *TrimStep) UnmarshalJSON(b []byte) error {
	if !wellFormed(b) {
		return invalid("steps[]")
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(b, &members) != nil || members == nil {
		return invalid("steps[]")
	}
	var step TrimStep
	for name, dst := range map[string]*string{"item": &step.Item, "action": &step.Action} {
		raw, ok := members[name]
		if !ok || string(bytes.TrimSpace(raw)) == "null" || json.Unmarshal(raw, dst) != nil {
			return invalid("steps[].%s", name)
		}
	}
	if raw, ok := members["keep_bytes"]; ok {
		var n int64
		if string(bytes.TrimSpace(raw)) == "null" || json.Unmarshal(raw, &n) != nil {
			return invalid("steps[].keep_bytes")
		}
		step.KeepBytes = &n
	}
	*s = step
	return nil
}

// UnmarshalJSON reads an order as an app reads what the platform sends:
// one well-formed JSON object; a member it does not know ignored, at every
// depth; a member counted only as exactly named; every member present, and
// null only for floor. Validate is the next step; VerifyTrimOrder does
// both.
func (o *TrimOrder) UnmarshalJSON(b []byte) error {
	type order TrimOrder
	var v order
	if err := decodeSent(b, &v, "trim"); err != nil {
		return err
	}
	*o = TrimOrder(v)
	return nil
}

// validUUIDv7 reports whether s is a canonical lowercase UUID of version 7
// and RFC 9562's variant.
func validUUIDv7(s string) bool {
	return ValidUUID(s) && s[14] == '7' && bytes.IndexByte([]byte("89ab"), s[19]) >= 0
}

// Validate checks every member of an order and the rules between them: the
// three times in order within MaxTrimValidity, the floor's date against
// issued_at, the basis under MaxTrimBasisAge old at issued_at, the steps
// each item once with keep_bytes exactly on keep, and basis_purge naming
// exactly the purge steps. It does not check the mac: VerifyTrimOrder
// does, over the order as received.
func (o TrimOrder) Validate() error {
	switch {
	case !validUUIDv7(o.OrderID):
		return invalid("order_id is a UUIDv7")
	case !ValidApp(o.App):
		return invalid("app")
	case !ValidUUID(o.WorkspaceID):
		return invalid("workspace_id")
	case !ValidUUID(o.Generation):
		return invalid("generation")
	case !ValidUUID(o.Episode):
		return invalid("episode")
	case o.Round < 1 || o.Round > MaxTrimRound:
		return invalid("round is 1 to 3")
	case o.IssuedAt.IsZero() || o.NotBefore.IsZero() || o.ValidUntil.IsZero():
		return invalid("issued_at, not_before and valid_until")
	case o.NotBefore.Before(o.IssuedAt.Time) || !o.NotBefore.Before(o.ValidUntil.Time):
		return invalid("issued_at <= not_before < valid_until")
	case o.ValidUntil.Sub(o.IssuedAt.Time) > MaxTrimValidity:
		return invalid("valid_until is at most 6 hours after issued_at")
	case o.Floor != nil && *o.Floor != TrimFloor(o.IssuedAt.Time):
		return invalid("floor is issued_at's UTC date less 90 days, or null")
	case o.Basis.UsageSeq < 1 || o.Basis.UsageSeq > MaxSafeInteger:
		return invalid("basis.usage_seq")
	case o.Basis.MeasuredAt.IsZero():
		return invalid("basis.measured_at")
	case o.Basis.MeasuredAt.After(o.IssuedAt.Add(MaxUsageMeasuredAhead)) || o.IssuedAt.Sub(o.Basis.MeasuredAt.Time) >= MaxTrimBasisAge:
		return invalid("basis.measured_at is under an hour before issued_at")
	case len(o.Steps) < 1 || len(o.Steps) > MaxTrimSteps:
		return invalid("steps are 1 to 2000")
	case o.Secret < 1 || o.Secret > MaxSafeInteger:
		return invalid("secret")
	case !validMAC(o.MAC):
		return invalid("mac")
	}
	seen := make(map[string]bool, len(o.Steps))
	purges := 0
	for _, s := range o.Steps {
		switch {
		case !ValidItemID(s.Item) || seen[s.Item]:
			return invalid("steps[].item, each once")
		case s.Action == TrimActionPurge && s.KeepBytes != nil:
			return invalid("steps[].keep_bytes only on keep")
		case s.Action == TrimActionKeep && (s.KeepBytes == nil || !safeCount(*s.KeepBytes)):
			return invalid("steps[].keep_bytes on keep, 0 to 2^53 - 1")
		case s.Action == TrimActionKeep && o.Floor == nil && *s.KeepBytes != 0:
			return invalid("steps[].keep_bytes is 0 without a floor")
		case !oneOf(s.Action, trimActions):
			return invalid("steps[].action")
		}
		seen[s.Item] = true
		if s.Action == TrimActionPurge {
			purges++
			at, ok := o.BasisPurge[s.Item]
			if !ok || at.IsZero() {
				return invalid("basis_purge names every purge step's item")
			}
		}
	}
	if o.BasisPurge == nil || len(o.BasisPurge) != purges {
		return invalid("basis_purge names exactly the purge steps' items")
	}
	return nil
}

// Items are the order's step items, in its order.
func (o TrimOrder) Items() []string {
	items := make([]string, len(o.Steps))
	for i, s := range o.Steps {
		items[i] = s.Item
	}
	return items
}

// trimMAC is the MAC of a canonical order for app under secret.
func trimMAC(canonical []byte, app, secret string) string {
	return signedMAC(TrimMACLabel, canonical, app, secret)
}

// SignTrimOrder returns the order raw, a JSON object, with its secret
// member set to secretGen and its mac member to the MAC of the rest under
// app and secret, as the JCS text of the whole: the platform's, each time
// it serves the document that carries the order, with the secret that
// signs that answer, since it stores the order without secret and mac.
// Both members raw holds already are replaced. secret must be a secret
// (CheckSecrets), secretGen its generation number (1 or more), app an
// app's id, and the body's app that one.
//
//	mac = "v1=" + lowercase hex(HMAC-SHA256(key = the secret's 43-character text,
//	      msg = "thehappie-platform-trim/v1" || "\n" || app || "\n" ||
//	            JCS(the order as received, without "mac")))
func SignTrimOrder(raw []byte, app, secret string, secretGen int64) ([]byte, error) {
	if !validSecret(secret) {
		return nil, ErrSecret
	}
	if !ValidApp(app) {
		return nil, invalid("app")
	}
	if secretGen < 1 || secretGen > MaxSafeInteger {
		return nil, invalid("secret")
	}
	canonical, _, bodyApp, err := canonicalSigned(raw, "trim")
	if err != nil {
		return nil, err
	}
	if bodyApp != app {
		return nil, invalid("trim: the body names another app")
	}
	v, err := genericObject(canonical)
	if err != nil {
		return nil, err
	}
	v["secret"] = json.Number(fmt.Sprint(secretGen))
	if canonical, err = jcs.Marshal(v); err != nil {
		return nil, invalid("trim: no canonical text")
	}
	v["mac"] = trimMAC(canonical, app, secret)
	return jcs.Marshal(v)
}

// genericObject decodes canonical, a JSON object, into generic values,
// numbers kept as written.
func genericObject(canonical []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(canonical))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil || v == nil {
		return nil, invalid("trim: not a JSON object")
	}
	return v, nil
}

// VerifyTrimOrder makes the app's check 1 on the order doc carries, the
// document app applied for the workspace, as received (doc.Trim, the
// order's bytes as they came), with each contract secret the app holds
// (its current and next during a rotation), and returns the order decoded
// from those bytes: the app runs and keeps that order only. Every error is
// the result code invalid_order, but for a feed's copy that fails with
// ErrTrimMAC (see ErrTrimMAC), which the app judges on the GET's copy
// instead. In order:
//   - a list of secrets that is empty, or holds a key that is not a
//     secret, or an app that is no app id, is ErrTrimMAC;
//   - a document with no order is ErrInvalid;
//   - an order that is not one well-formed JSON object, names a member
//     twice anywhere, holds what JCS does not write (a fraction, an
//     integer past 2^53−1) or a mac that is not a string, verifies under
//     nothing: ErrTrimMAC;
//   - an order whose body names another app than app verifies under
//     nothing too, before its MAC is checked: ErrTrimMAC;
//   - an order whose mac holds under none of the secrets, or that has
//     none, is ErrTrimMAC;
//   - an order that does not decode or fails Validate, a document that
//     fails Validate or is not app's, or an order whose workspace_id or
//     generation is not the document's, is ErrInvalid;
//   - an order with floor null in a document whose plan.source is plan
//     or live_move is ErrTrimFloor, also ErrInvalid, which the app writes
//     to its security log.
func VerifyTrimOrder(doc EntitlementsDoc, app string, secrets []string) (TrimOrder, error) {
	if len(secrets) == 0 || !ValidApp(app) {
		return TrimOrder{}, ErrTrimMAC
	}
	for _, s := range secrets {
		if !validSecret(s) {
			return TrimOrder{}, ErrTrimMAC
		}
	}
	raw := bytes.TrimSpace(doc.Trim)
	if len(raw) == 0 || string(raw) == "null" {
		return TrimOrder{}, invalid("trim: the document carries no order")
	}
	canonical, mac, bodyApp, err := canonicalSigned(raw, "trim")
	if err != nil || bodyApp != app || !validMAC(mac) {
		return TrimOrder{}, ErrTrimMAC
	}
	ok := false
	for _, s := range secrets {
		if hmac.Equal([]byte(trimMAC(canonical, app, s)), []byte(mac)) {
			ok = true
		}
	}
	if !ok {
		return TrimOrder{}, ErrTrimMAC
	}
	var o TrimOrder
	if err := json.Unmarshal(raw, &o); err != nil {
		return TrimOrder{}, invalid("trim: it does not decode")
	}
	if err := o.Validate(); err != nil {
		return TrimOrder{}, err
	}
	switch {
	case doc.App != app || doc.Validate() != nil:
		return TrimOrder{}, invalid("trim: the document is not one of the app's that validates")
	case o.WorkspaceID != doc.WorkspaceID || o.Generation != doc.Generation:
		return TrimOrder{}, invalid("trim: the order names another workspace or generation than its document")
	case o.Floor == nil && (doc.Plan.Source == SourcePlan || doc.Plan.Source == SourceLiveMove):
		return TrimOrder{}, fmt.Errorf("%w: %w", ErrInvalid, ErrTrimFloor)
	}
	return o, nil
}

// TrimResult is what became of an order, posted to
// POST /contract/v1/trim/results (TrimResultBodyLimit), by its order_id:
// refused (nothing ran), partial or done. The platform reads it strictly
// (DecodeStrict), then Validate, then ValidateFor its kept order.
type TrimResult struct {
	OrderID string `json:"order_id"`
	Outcome string `json:"outcome"`
	// Code is a refused result's check, or a partial result's when its
	// order stopped before its end; else nil (null).
	Code *string `json:"code"`
	// Steps are [] on refused, and each step of the order once otherwise.
	Steps []TrimStepResult `json:"steps"`
	// UsageSeq is a report the app measured after the last step it ran;
	// nil (null) exactly on refused.
	UsageSeq *int64 `json:"usage_seq"`
}

// String names the result by its order and outcome, and prints no step,
// figure or usage_seq.
func (r TrimResult) String() string {
	return fmt.Sprintf("contract.TrimResult{OrderID: %q, Outcome: %q, %s}", r.OrderID, r.Outcome, Ellipsis)
}

// GoString is String, for %#v.
func (r TrimResult) GoString() string { return r.String() }

// LogValue is the result's order and outcome, never a figure.
func (r TrimResult) LogValue() slog.Value {
	return slog.GroupValue(slog.String("order_id", r.OrderID), slog.String("outcome", r.Outcome))
}

// TrimStepResult is what became of one step.
type TrimStepResult struct {
	Item    string `json:"item"`
	Outcome string `json:"outcome"`
	// Code is item_changed exactly on a refused step; else nil (null).
	Code *string `json:"code"`
	// BytesAfter is the item's bytes after the step: nil (null) on refused
	// and not_run.
	BytesAfter *int64 `json:"bytes_after"`
}

// Validate checks a result alone:
//   - outcome done, partial or refused;
//   - code one of TrimRefusedCodes on refused, null or one of
//     TrimStoppedCodes on partial, null on done;
//   - steps [] on refused, else 1 to MaxTrimSteps, each item once; a
//     step's outcome one of TrimStepOutcomes, its code item_changed
//     exactly on refused, its bytes_after 0 to 2^53 − 1 but null on
//     refused and not_run;
//   - usage_seq null exactly on refused, else 1 to 2^53 − 1;
//   - done only with every step done; not_run only in a result whose order
//     stopped (a code), and then every step after it not_run too; and a
//     partial whose order did not stop holds a partial or a refused step.
func (r TrimResult) Validate() error {
	switch {
	case !ValidUUID(r.OrderID):
		return invalid("order_id")
	case !oneOf(r.Outcome, trimOutcomes):
		return invalid("outcome")
	case r.Steps == nil:
		return invalid("steps is a list, [] on refused")
	}
	switch r.Outcome {
	case TrimOutcomeRefused:
		switch {
		case r.Code == nil || !oneOf(*r.Code, trimRefusedCodes):
			return invalid("code is a refusal's")
		case len(r.Steps) != 0:
			return invalid("steps is [] on refused")
		case r.UsageSeq != nil:
			return invalid("usage_seq is null on refused")
		}
		return nil
	case TrimOutcomePartial:
		if r.Code != nil && !oneOf(*r.Code, trimStoppedCodes) {
			return invalid("code is null, or why the order stopped")
		}
	case TrimOutcomeDone:
		if r.Code != nil {
			return invalid("code is null on done")
		}
	}
	switch {
	case len(r.Steps) < 1 || len(r.Steps) > MaxTrimSteps:
		return invalid("steps are each step of the order once")
	case r.UsageSeq == nil || *r.UsageSeq < 1 || *r.UsageSeq > MaxSafeInteger:
		return invalid("usage_seq")
	}
	seen := make(map[string]bool, len(r.Steps))
	stopped, unfinished := false, false
	for _, s := range r.Steps {
		switch {
		case !ValidItemID(s.Item) || seen[s.Item]:
			return invalid("steps[].item, each once")
		case !oneOf(s.Outcome, trimStepOutcomes):
			return invalid("steps[].outcome")
		case (s.Outcome == TrimOutcomeRefused) != (s.Code != nil):
			return invalid("steps[].code only on refused")
		case s.Code != nil && *s.Code != TrimCodeItemChanged:
			return invalid("steps[].code is item_changed")
		case s.Outcome == TrimOutcomeRefused || s.Outcome == TrimOutcomeNotRun:
			if s.BytesAfter != nil {
				return invalid("steps[].bytes_after is null on refused and not_run")
			}
		case s.BytesAfter == nil || !safeCount(*s.BytesAfter):
			return invalid("steps[].bytes_after is 0 to 2^53 - 1")
		}
		seen[s.Item] = true
		switch {
		case s.Outcome == TrimOutcomeNotRun:
			stopped = true
		case stopped:
			return invalid("steps after a not_run step are not_run")
		}
		if s.Outcome == TrimOutcomePartial || s.Outcome == TrimOutcomeRefused {
			unfinished = true
		}
	}
	switch {
	case r.Outcome == TrimOutcomeDone && (stopped || unfinished):
		return invalid("done only with every step done")
	case stopped && r.Code == nil:
		return invalid("not_run only when the order stopped")
	case r.Outcome == TrimOutcomePartial && r.Code == nil && !unfinished:
		return invalid("a partial order that did not stop holds a partial or refused step")
	}
	return nil
}

// ValidateFor checks a result against the order it reports, the one the
// platform keeps: Validate, the same order_id, and, unless refused, the
// order's steps exactly, in the order's order, with a purge step done only
// at 0 bytes.
func (r TrimResult) ValidateFor(o TrimOrder) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if r.OrderID != o.OrderID {
		return invalid("order_id is the order's")
	}
	if r.Outcome == TrimOutcomeRefused {
		return nil
	}
	if len(r.Steps) != len(o.Steps) {
		return invalid("steps are the order's, each once, in its order")
	}
	for i, s := range r.Steps {
		switch {
		case s.Item != o.Steps[i].Item:
			return invalid("steps are the order's, each once, in its order")
		case o.Steps[i].Action == TrimActionPurge && s.Outcome == TrimOutcomeDone && *s.BytesAfter != 0:
			return invalid("a purge step done leaves 0 bytes")
		}
	}
	return nil
}

// TrimResultAnswer is the platform's signed 200 to a result that is one
// JSON object: accepted (kept); duplicate (this result is kept already);
// or rejected with invalid_request (it does not validate), not_found (no
// order of this app with that id: lost in a restore of the platform's, or
// past its retention) or conflict (another result is kept for the order).
// OrderID echoes the body's when it is a UUID, else "", which only a
// rejected invalid_request carries. An app marks a result delivered on
// accepted and duplicate; a rejected one ends its delivery too. Its
// UnmarshalJSON reads it as an app reads what the platform sends.
type TrimResultAnswer struct {
	OrderID string  `json:"order_id"`
	Outcome string  `json:"outcome"`
	Code    *string `json:"code"`
}

// UnmarshalJSON reads an answer as an app reads what the platform sends:
// members it does not know ignored, a member counted only as exactly named,
// every member present, and null only for code.
func (a *TrimResultAnswer) UnmarshalJSON(b []byte) error {
	type answer TrimResultAnswer
	var v answer
	if err := decodeSent(b, &v, "trim result answer"); err != nil {
		return err
	}
	*a = TrimResultAnswer(v)
	return nil
}

// Validate checks an answer: an outcome of accepted, duplicate or
// rejected; code null on the first two, and invalid_request, not_found or
// conflict on rejected; order_id a UUID, or "" on a rejected
// invalid_request alone.
func (a TrimResultAnswer) Validate() error {
	switch {
	case !oneOf(a.Outcome, trimAnswerOutcomes):
		return invalid("outcome")
	case a.Outcome == OutcomeRejected && (a.Code == nil || !oneOf(*a.Code, trimAnswerCodes)):
		return invalid("code is invalid_request, not_found or conflict on rejected")
	case a.Outcome != OutcomeRejected && a.Code != nil:
		return invalid("code is null on accepted and duplicate")
	case a.OrderID == "" && (a.Outcome != OutcomeRejected || *a.Code != CodeInvalid):
		return invalid(`order_id is "" only on a rejected invalid_request`)
	case a.OrderID != "" && !ValidUUID(a.OrderID):
		return invalid("order_id")
	}
	return nil
}
