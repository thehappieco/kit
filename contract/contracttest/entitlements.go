package contracttest

// The entitlements part (SPEC section 11.20): the documents a test sets,
// each app's entitlements feed and the GET computed now, the
// acknowledgement, the usage reports, the link check, and trim orders with
// their results. A document reaches an app only for a workspace named to
// it, as on the platform. Times are the fake's clock (Options.Now).
//
// Where the platform does more, the fake is simpler:
//   - it computes no document: a test sets each one (SetEntitlements), and
//     the fake fills its generation, its version (the feed's seq) and, when
//     the test leaves it zero, its computed_at, validates it, and publishes
//     it unless it is the same document as the latest published (equal
//     without version, generation, computed_at and places.counted_at). Its
//     storage figures count, where the platform's threshold may leave them
//     unpublished: a test that sets new figures means them published;
//   - a workspace named to an app with no document the test set gets a
//     default one at once (Options.DefaultEntitlements, else
//     DefaultEntitlementsDoc), as the platform always has a document for a
//     named workspace; a document the test sets for a workspace that
//     exists but is not named yet is kept and published at naming;
//   - the GET answers the latest document the test set, published again
//     only when the latest published is not it (a bad one of
//     PublishRawEntitlements, or one of another generation); it answers
//     unavailable only through Refuse, or when the hook's document does
//     not validate;
//   - the link check's place and new_links come from the document the test
//     set, and its trial from the clocks it sets (SetTrialClock), judged on
//     whenever the document says the workspace is on trial
//     (state.trial_ends_at set): the platform's gate for what it says of a
//     trial is not played;
//   - a trim order is issued by the test (IssueTrimOrder), with none of the
//     platform's conditions (the owner's OK, the notices, the reports'
//     age): the fake checks only that the order validates in its document;
//   - a team's 30 days after its closing are counted on the fake's clock
//     from CloseTeam, and nothing else it keeps expires.

import (
	"bytes"
	"cmp"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/thehappieco/kit/contract"
)

// The entitlements part's calls, as Refuse and Corrupt name them (kit
// v0.12.0).
const (
	CallEntitlements        = "entitlements"         // GET /contract/v1/entitlements?after=&wait=
	CallEntitlementsDoc     = "entitlements-doc"     // GET /contract/v1/workspaces/{id}/entitlements
	CallEntitlementsApplied = "entitlements-applied" // POST /contract/v1/entitlements/applied
	CallUsage               = "usage"                // PUT /contract/v1/workspaces/{id}/usage
	CallLinkCheck           = "link-check"           // POST /contract/v1/workspaces/{id}/link-check
	CallTrimResults         = "trim-results"         // POST /contract/v1/trim/results
)

// The body limits of the entitlements part's calls.
const (
	EntitlementsAppliedLimit = contract.EntitlementsAppliedLimit
	UsageReportBodyLimit     = contract.UsageReportBodyLimit
	LinkCheckBodyLimit       = contract.LinkCheckBodyLimit
	TrimResultBodyLimit      = contract.TrimResultBodyLimit
)

// ClosedTeamRetention is how long after a team's closing the platform still
// keeps its documents and reports: past it, the GET and the link check are
// not_found and a usage report is not kept.
const ClosedTeamRetention = 30 * 24 * time.Hour

// trialLength is a clock a link would start: 360 hours.
const trialLength = 360 * time.Hour

// entitlementsApp is an app's entitlements feed, the documents the test
// set, and what the app sent back.
type entitlementsApp struct {
	entHead   int64
	entInputs map[string]*entInput    // what the test set, by workspace
	entPub    map[string]entPublished // the latest published, by workspace
	entWake   chan struct{}
	entPolls  chan struct{}
	entAcks   []contract.EntitlementsApplied
	entUsage  map[string]keptUsage      // by workspace
	entSent   map[string]contract.Usage // the last answered, kept or not, by workspace
	linkRate  map[string]*bucket        // link checks with codes, by workspace
	orders    map[string]*trimRecord    // by order_id
}

// entInput is a workspace's document as the test set it, with no version
// or generation, and the order issued into it, kept without secret and mac.
type entInput struct {
	doc   contract.EntitlementsDoc
	order *contract.TrimOrder
}

// entPublished is a published document: its seq (its version), its
// generation, and its content, fixed by its version; or a raw one a test
// published (PublishRawEntitlements), served as it is.
type entPublished struct {
	doc   contract.EntitlementsDoc // Trim nil
	order *contract.TrimOrder      // without secret and mac
	raw   json.RawMessage
	seq   int64
}

// trimRecord is an order the fake issued, and the result kept for it.
type trimRecord struct {
	order  contract.TrimOrder
	result *contract.TrimResult
}

// keptUsage is a report kept, and its text as the fake compares a retry.
type keptUsage struct {
	u    contract.Usage
	text []byte
}

// bucket is a token bucket of capacity n, refilled n every minute.
type bucket struct {
	tokens  float64
	metered time.Time
}

func newEntitlementsApp(longPolls int) entitlementsApp {
	return entitlementsApp{
		entInputs: map[string]*entInput{}, entPub: map[string]entPublished{},
		entWake: make(chan struct{}), entPolls: make(chan struct{}, longPolls),
		entUsage: map[string]keptUsage{}, entSent: map[string]contract.Usage{}, linkRate: map[string]*bucket{},
		orders: map[string]*trimRecord{},
	}
}

// resetEntitlements is Restore's: the feed starts again from 0 with no
// document in it, and the acknowledgements, reports, link check counts,
// orders and results go, as a backup from before them holds none. The
// documents the test set stay, as the directory does, without their orders,
// and are published again once their workspaces are named to the app
// again.
func (a *entitlementsApp) resetEntitlements() {
	a.entHead = 0
	a.entPub = map[string]entPublished{}
	a.entAcks = nil
	a.entUsage, a.linkRate, a.orders = map[string]keptUsage{}, map[string]*bucket{}, map[string]*trimRecord{}
	for _, in := range a.entInputs {
		in.order = nil
	}
}

func (a *entitlementsApp) wakeEntitlements() {
	close(a.entWake)
	a.entWake = make(chan struct{})
}

// matchEntitlements finds the entitlements part's calls for a method and
// the raw path after /contract/v1/.
func matchEntitlements(method, rest string) (route, string, bool) {
	switch {
	case rest == "entitlements":
		if method == http.MethodGet {
			return route{CallEntitlements, SmallBodyLimit, (*Platform).entitlementsFeed}, "", true
		}
	case rest == "entitlements/applied":
		if method == http.MethodPost {
			return route{CallEntitlementsApplied, EntitlementsAppliedLimit, (*Platform).entitlementsApplied}, "", true
		}
	case rest == "trim/results":
		if method == http.MethodPost {
			return route{CallTrimResults, TrimResultBodyLimit, (*Platform).postTrimResult}, "", true
		}
	case strings.HasPrefix(rest, "workspaces/"):
		ws, tail, _ := strings.Cut(strings.TrimPrefix(rest, "workspaces/"), "/")
		if !contract.ValidUUID(ws) {
			return route{}, "", false
		}
		switch {
		case tail == "entitlements" && method == http.MethodGet:
			return route{CallEntitlementsDoc, SmallBodyLimit, (*Platform).entitlementsDoc}, ws, true
		case tail == "usage" && method == http.MethodPut:
			return route{CallUsage, UsageReportBodyLimit, (*Platform).putUsage}, ws, true
		case tail == "link-check" && method == http.MethodPost:
			return route{CallLinkCheck, LinkCheckBodyLimit, (*Platform).linkCheck}, ws, true
		}
	}
	return route{}, "", false
}

// ---------------------------------------------------------------------------
// The documents a test sets
// ---------------------------------------------------------------------------

// SetEntitlements sets the document of the workspace ws for app, as the
// platform would compute it, and publishes it to app's entitlements feed
// unless it is the same document as the latest published. It returns the
// document's version, its seq in the feed. The workspace must exist
// (ErrUnknown otherwise); one not named to app yet keeps the document,
// validated, which is published the moment it is named (the version
// returned is then 0). The fake fills V, Type, App and
// WorkspaceID when they are empty (ErrInvalid for another app or
// workspace), places.kind when empty, the console's two links when empty,
// a nil timeline or items as [], and computed_at, when zero, by its clock;
// it sets generation and version itself. Trim must be empty: an order is
// issued with IssueTrimOrder. The order issued into the workspace's
// document stays while the new document is still enforce and expired with
// the same plan, and goes otherwise, as the platform drops an order at a
// change of its plan or the episode's end. A document that does not
// validate is ErrInvalid, and changes nothing.
func (p *Platform) SetEntitlements(app, ws string, doc contract.EntitlementsDoc) (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil || p.workspaces[ws] == nil {
		return 0, ErrUnknown
	}
	if len(bytes.TrimSpace(doc.Trim)) != 0 || (doc.App != "" && doc.App != app) || (doc.WorkspaceID != "" && doc.WorkspaceID != ws) {
		return 0, ErrInvalid
	}
	doc = fillEntitlements(app, ws, doc)
	in := &entInput{doc: doc}
	if old := st.entInputs[ws]; old != nil && old.order != nil && doc.Mode == contract.ModeEnforce &&
		doc.State.Name == contract.WorkspaceExpired && samePlan(doc.Plan, old.doc.Plan) {
		in.order = old.order
	}
	if !st.named[ws] {
		if _, err := p.entCandidateLocked(st, in); err != nil {
			return 0, ErrInvalid
		}
		st.entInputs[ws] = in
		return 0, nil
	}
	prev := st.entInputs[ws]
	st.entInputs[ws] = in
	pub, err := p.publishEntitlementsLocked(st, ws)
	if err != nil {
		if prev == nil {
			delete(st.entInputs, ws)
		} else {
			st.entInputs[ws] = prev
		}
		return 0, ErrInvalid
	}
	return pub.seq, nil
}

// fillEntitlements fills what SetEntitlements fills of a document the test
// set for app's workspace ws.
func fillEntitlements(app, ws string, doc contract.EntitlementsDoc) contract.EntitlementsDoc {
	doc.App, doc.WorkspaceID, doc.Trim = app, ws, nil
	if doc.V == 0 {
		doc.V = contract.EntitlementsV
	}
	if doc.Type == "" {
		doc.Type = contract.EntitlementsType
	}
	if doc.Places.Kind == "" {
		doc.Places.Kind, _ = contract.AppItemKind(app)
	}
	if doc.Timeline == nil {
		doc.Timeline = []contract.TimelineStep{}
	}
	if doc.Items == nil {
		doc.Items = []contract.ItemTrial{}
	}
	if doc.Links.Plan == "" {
		doc.Links.Plan = "https://console.thehappie.co/workspaces/" + ws + "/plan"
	}
	if doc.Links.Storage == "" {
		doc.Links.Storage = "https://console.thehappie.co/workspaces/" + ws + "/storage"
	}
	return doc
}

// DefaultEntitlementsDoc is the document the fake publishes for a
// workspace named to app when the test set none and Options has no
// DefaultEntitlements: observe, active since the moment it is named (the
// fake fills state.since by its clock), no plan (source none), no places
// counted, no storage, every switch on, no step to come and no item. The
// fake fills the rest as SetEntitlements does.
func DefaultEntitlementsDoc(app string) contract.EntitlementsDoc {
	kind, _ := contract.AppItemKind(app)
	return contract.EntitlementsDoc{
		Mode:     contract.ModeObserve,
		State:    contract.EntitlementsState{Name: contract.WorkspaceActive},
		Plan:     contract.EntitlementsPlan{Source: contract.SourceNone},
		Places:   contract.EntitlementsPlaces{Kind: kind},
		Switches: contract.Switches{API: contract.SwitchOn, NewLinks: contract.SwitchOn, Sync: contract.SwitchOn, Send: contract.SwitchOn},
		Timeline: []contract.TimelineStep{},
		Items:    []contract.ItemTrial{},
	}
}

// defaultEntInputLocked gives the workspace ws, named to st's app with no
// document the test set, its default one: the hook's, else
// DefaultEntitlementsDoc, filled as SetEntitlements fills a document and
// its state.since, when zero, by the fake's clock. It is kept only when it
// validates; nil otherwise.
func (p *Platform) defaultEntInputLocked(st *appState, ws string) *entInput {
	doc := DefaultEntitlementsDoc(st.id)
	if p.defaultEnt != nil {
		doc = p.defaultEnt(st.id, ws)
	}
	if len(bytes.TrimSpace(doc.Trim)) != 0 || (doc.App != "" && doc.App != st.id) || (doc.WorkspaceID != "" && doc.WorkspaceID != ws) {
		return nil
	}
	doc = fillEntitlements(st.id, ws, doc)
	if doc.State.Since.IsZero() {
		doc.State.Since = contract.T(atMicroseconds(p.now()))
	}
	in := &entInput{doc: doc}
	if _, err := p.entCandidateLocked(st, in); err != nil {
		return nil
	}
	st.entInputs[ws] = in
	return in
}

// PublishRawEntitlements publishes raw, one JSON value, as the next
// document of app's entitlements feed under the key ws, as it is: a bad
// document (another app or generation, one that does not decode or
// validate), which the platform never sends, for an app's test of its
// refusals. It is not validated, and replaces the workspace's latest
// document in the feed; the GET of a named ws answers the document the
// test set, published again. It returns its seq.
func (p *Platform) PublishRawEntitlements(app, ws string, raw json.RawMessage) (int64, error) {
	if !json.Valid(raw) {
		return 0, ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil {
		return 0, ErrUnknown
	}
	st.entHead++
	st.entPub[ws] = entPublished{raw: slices.Clone(raw), seq: st.entHead}
	st.wakeEntitlements()
	return st.entHead, nil
}

// Entitlements is the latest document published for the workspace ws to
// app, its order signed with the app's current secret; false when there is
// none, or the latest is a raw one.
func (p *Platform) Entitlements(app, ws string) (contract.EntitlementsDoc, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil {
		return contract.EntitlementsDoc{}, false
	}
	pub, ok := st.entPub[ws]
	if !ok || pub.raw != nil {
		return contract.EntitlementsDoc{}, false
	}
	d, err := p.servedDocLocked(st, pub, st.current, st.secretNo)
	return d, err == nil
}

// publishEntitlementsLocked publishes the workspace's document as the test
// set it, or its default one when the test set none, unless the workspace
// is not named to the app, or it is the same document as the latest
// published in this generation. A document that does not validate is not
// published, and is an error; a default one that does not validate
// publishes nothing.
func (p *Platform) publishEntitlementsLocked(st *appState, ws string) (entPublished, error) {
	if !st.named[ws] {
		return entPublished{}, nil
	}
	in := st.entInputs[ws]
	if in == nil {
		if in = p.defaultEntInputLocked(st, ws); in == nil {
			return entPublished{}, nil
		}
	}
	cand, err := p.entCandidateLocked(st, in)
	if err != nil {
		return entPublished{}, err
	}
	if old, ok := st.entPub[ws]; ok && old.raw == nil && old.doc.Generation == p.generation && sameEntitlements(old, cand) {
		return old, nil
	}
	st.entHead = cand.seq
	st.entPub[ws] = cand
	st.wakeEntitlements()
	return cand, nil
}

// entCandidateLocked is the document in as the feed's next seq would
// publish it now, validated as served.
func (p *Platform) entCandidateLocked(st *appState, in *entInput) (entPublished, error) {
	cand := entPublished{doc: in.doc, order: in.order}
	if cand.doc.ComputedAt.IsZero() {
		cand.doc.ComputedAt = contract.T(atMicroseconds(p.now()))
	}
	cand.doc.Generation = p.generation
	cand.seq = st.entHead + 1
	cand.doc.Version = cand.seq
	served, err := p.servedDocLocked(st, cand, st.current, st.secretNo)
	if err != nil {
		return entPublished{}, err
	}
	if err := served.Validate(); err != nil {
		return entPublished{}, err
	}
	return cand, nil
}

// samePlan reports whether a and b are the same plan, their times
// compared as the wire writes them.
func samePlan(a, b contract.EntitlementsPlan) bool {
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}

// sameEntitlements reports whether a and b are the same document: equal
// without version, generation, computed_at and places.counted_at, their
// orders included.
func sameEntitlements(a, b entPublished) bool {
	norm := func(e entPublished) []byte {
		d := e.doc
		d.Version, d.Generation, d.ComputedAt, d.Places.CountedAt, d.Trim = 0, "", contract.Time{}, nil, nil
		dj, err := json.Marshal(d)
		if err != nil {
			return nil
		}
		oj, err := json.Marshal(e.order)
		if err != nil {
			return nil
		}
		return append(append(dj, '\n'), oj...)
	}
	na, nb := norm(a), norm(b)
	return na != nil && bytes.Equal(na, nb)
}

// servedDocLocked is the published document as the fake serves it: its
// order, if any, signed with the secret that signs the answer.
func (p *Platform) servedDocLocked(st *appState, pub entPublished, secret string, secretNo int64) (contract.EntitlementsDoc, error) {
	d := pub.doc
	d.Trim = nil
	if pub.order != nil {
		o := *pub.order
		o.Secret, o.MAC = 0, ""
		raw, err := json.Marshal(o)
		if err != nil {
			return contract.EntitlementsDoc{}, err
		}
		if d.Trim, err = contract.SignTrimOrder(raw, st.id, secret, secretNo); err != nil {
			return contract.EntitlementsDoc{}, err
		}
	}
	return d, nil
}

// publishNamedEntitlementsLocked publishes, for app, the document of every
// workspace named to it the test set: what a new generation, or a
// workspace named again after a restore, does.
func (p *Platform) publishNamedEntitlementsLocked(st *appState) {
	ws := make([]string, 0, len(st.entInputs))
	for id := range st.entInputs {
		ws = append(ws, id)
	}
	slices.Sort(ws)
	for _, id := range ws {
		_, _ = p.publishEntitlementsLocked(st, id)
	}
}

// newGenerationEntitlementsLocked is NewGeneration's: the orders the
// documents carry are dropped (their records stay, so a result for one is
// still judged), the acknowledgements kept go, and every document is
// published again under the new generation.
func (p *Platform) newGenerationEntitlementsLocked(st *appState) {
	for _, in := range st.entInputs {
		in.order = nil
	}
	st.entAcks = nil
	p.publishNamedEntitlementsLocked(st)
}

// closedPast reports whether the platform keeps nothing more for w: a
// closed personal workspace, or a team closed over 30 days ago.
func (p *Platform) closedPast(w *workspace) bool {
	return w.closed && (w.kind == contract.KindPersonal || p.now().Sub(w.closedAt) > ClosedTeamRetention)
}

// ---------------------------------------------------------------------------
// The feed and the GET
// ---------------------------------------------------------------------------

// entitlementsFeed answers GET /contract/v1/entitlements?after=&wait=, the
// query read as the other feeds' are, with its own long-polls.
func (p *Platform) entitlementsFeed(rq *request) answer {
	if ans, ok := noBody(rq); !ok {
		return ans
	}
	after, wait, ok := feedQuery(rq.query)
	if !ok {
		return refusal(contract.CodeInvalid, "the entitlements feed takes after and an optional wait from 0 to 25")
	}
	f, woken, ans, ok := p.readEntitlementsFeed(rq, after)
	if !ok {
		return ans
	}
	if len(f.Items) > 0 || wait == 0 {
		return answer{status: http.StatusOK, body: f}
	}
	select {
	case rq.app.entPolls <- struct{}{}:
		defer func() { <-rq.app.entPolls }()
	default:
		return refusal(contract.CodeRateLimited, "too many entitlements feed requests wait at once")
	}
	timer := time.NewTimer(time.Duration(wait) * time.Second)
	defer timer.Stop()
	select {
	case <-rq.ctx.Done():
		return answer{status: http.StatusOK, body: f}
	case <-p.drain:
	case <-woken:
	case <-timer.C:
	}
	f, _, ans, ok = p.readEntitlementsFeed(rq, after)
	if !ok {
		return ans
	}
	return answer{status: http.StatusOK, body: f}
}

// readEntitlementsFeed is the app's entitlements feed after the cursor:
// each workspace's latest document, oldest first, at most 200 and, after
// the first, no more bytes than a page holds; and the channel its next
// publish closes.
func (p *Platform) readEntitlementsFeed(rq *request, after int64) (contract.EntitlementsFeed, <-chan struct{}, answer, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	app := rq.app
	woken := app.entWake
	if after > app.entHead {
		return contract.EntitlementsFeed{}, woken, refusal(contract.CodeGone, "the cursor is past the entitlements feed's head: take every document again"), false
	}
	f := contract.EntitlementsFeed{
		Generation: p.generation, GenerationConfirmed: p.confirmed, Head: app.entHead,
		PublishedThrough: contract.T(p.now()), Items: []contract.EntitlementsFeedItem{},
	}
	var pubs []entPublished
	for _, pub := range app.entPub {
		if pub.seq > after {
			pubs = append(pubs, pub)
		}
	}
	slices.SortFunc(pubs, func(a, b entPublished) int { return cmp.Compare(a.seq, b.seq) })
	size := 0
	for _, pub := range pubs {
		if len(f.Items) == contract.MaxEntitlementsFeedItems {
			f.More = true
			break
		}
		item := contract.EntitlementsFeedItem{Seq: pub.seq, Doc: pub.raw}
		if pub.raw == nil {
			d, err := p.servedDocLocked(app, pub, rq.secret, rq.secretNo)
			if err != nil {
				return contract.EntitlementsFeed{}, woken, refusal(contract.CodeUnavailable, "try again"), false
			}
			if item, err = contract.NewEntitlementsFeedItem(pub.seq, d); err != nil {
				return contract.EntitlementsFeed{}, woken, refusal(contract.CodeUnavailable, "try again"), false
			}
		}
		if len(f.Items) > 0 && size+len(item.Doc) > maxFeedPageBytes {
			f.More = true
			break
		}
		size += len(item.Doc)
		f.Items = append(f.Items, item)
	}
	f.NextAfter = max(after, f.Head)
	if f.More {
		f.NextAfter = f.Items[len(f.Items)-1].Seq
	}
	return f, woken, answer{}, true
}

// entitlementsDoc answers GET /contract/v1/workspaces/{id}/entitlements: the
// document the test set, published again first when the latest published is
// not it, or its default one when the test set none; not_found for a
// workspace not named to the app, a closed personal workspace and a team
// closed past its 30 days; unavailable only when a default document does
// not validate (or through Refuse).
func (p *Platform) entitlementsDoc(rq *request) answer {
	if ans, ok := noBody(rq); !ok {
		return ans
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	w := p.workspaces[rq.arg]
	if w == nil || !rq.app.named[rq.arg] || p.closedPast(w) {
		return refusal(contract.CodeNotFound, "not found")
	}
	pub, err := p.publishEntitlementsLocked(rq.app, rq.arg)
	if err != nil || rq.app.entInputs[rq.arg] == nil {
		return refusal(contract.CodeUnavailable, "try again")
	}
	d, err := p.servedDocLocked(rq.app, pub, rq.secret, rq.secretNo)
	if err != nil {
		return refusal(contract.CodeUnavailable, "try again")
	}
	return answer{status: http.StatusOK, body: d}
}

// entitlementsApplied takes an acknowledgement: decoded strictly and valid
// (else invalid_request), of the platform's generation and within the
// feed's head (else gone). Each is kept, its refused entries with it.
func (p *Platform) entitlementsApplied(rq *request) answer {
	var a contract.EntitlementsApplied
	if err := decodeContract(rq.body, &a); err != nil || a.Validate() != nil {
		return refusal(contract.CodeInvalid, "the acknowledgement is not valid")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if a.Generation != p.generation || a.Through > rq.app.entHead {
		return refusal(contract.CodeGone, "another generation, or past the entitlements feed's head")
	}
	rq.app.entAcks = append(rq.app.entAcks, a)
	return answer{status: http.StatusOK, body: contract.AccessResult{Accepted: true}}
}

// EntitlementsApplied are app's acknowledgements of its entitlements feed
// the fake accepted, in the order it accepted them, each with its refused
// entries. A new generation and a restore forget them.
func (p *Platform) EntitlementsApplied(app string) []contract.EntitlementsApplied {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil {
		return nil
	}
	return slices.Clone(st.entAcks)
}

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------

// putUsage takes a usage report: decoded strictly, valid on the fake's
// clock (ValidateAt), the app's and the path's workspace's, else
// invalid_request; for a workspace named to the app, else not_found. It is
// kept when its usage_seq is above the one held; a retry of the held report
// is answered kept as its first send; a lower usage_seq, an equal one with
// another body, a closed personal workspace, a team closed past its 30
// days, and every report under Options.UsageValidateOnly are answered
// kept false.
func (p *Platform) putUsage(rq *request) answer {
	var u contract.Usage
	if err := decodeContract(rq.body, &u); err != nil || u.ValidateAt(p.now()) != nil ||
		u.App != rq.app.id || u.WorkspaceID != rq.arg {
		return refusal(contract.CodeInvalid, "the report is not valid")
	}
	text, err := json.Marshal(u)
	if err != nil {
		return refusal(contract.CodeInvalid, "the report is not valid")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	w := p.workspaces[rq.arg]
	if w == nil || !rq.app.named[rq.arg] {
		return refusal(contract.CodeNotFound, "not found")
	}
	rq.app.entSent[rq.arg] = u
	kept := false
	held, ok := rq.app.entUsage[rq.arg]
	switch {
	case p.usageOnly || p.closedPast(w):
	case !ok || held.u.UsageSeq < u.UsageSeq:
		rq.app.entUsage[rq.arg] = keptUsage{u: u, text: text}
		kept = true
	case held.u.UsageSeq == u.UsageSeq:
		kept = bytes.Equal(held.text, text)
	}
	return answer{status: http.StatusOK, body: contract.UsageAnswer{Accepted: true, Kept: kept}}
}

// UsageSent is the last usage report of the workspace ws that app sent and
// the fake answered 200, whatever kept answered: under
// Options.UsageValidateOnly, for a lower usage_seq, and for a closed
// workspace too, so that a test sees what the app sent where Usage holds
// nothing. It is what the app sent, not what the platform keeps, so a
// Restore leaves it. False when there is none.
func (p *Platform) UsageSent(app, ws string) (contract.Usage, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil {
		return contract.Usage{}, false
	}
	u, ok := st.entSent[ws]
	return u, ok
}

// Usage is the latest usage report of the workspace ws that app sent and
// the fake kept; false when there is none.
func (p *Platform) Usage(app, ws string) (contract.Usage, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil {
		return contract.Usage{}, false
	}
	k, ok := st.entUsage[ws]
	return k.u, ok
}

// ---------------------------------------------------------------------------
// The link check
// ---------------------------------------------------------------------------

// SetTrialClock sets the trial clock a trial code matches, ending at
// endsAt: the link check answers running before it and used_up from it. A
// code that is not one is ErrInvalid.
func (p *Platform) SetTrialClock(code string, endsAt time.Time) error {
	if !contract.ValidTrialCode(code) || endsAt.IsZero() {
		return ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.trialClocks[code] = atMicroseconds(endsAt)
	return nil
}

// linkCheck answers POST /contract/v1/workspaces/{id}/link-check: decoded
// strictly, else invalid_request; with codes, at most LinkChecksPerMinute
// a minute per workspace, else rate_limited; valid for the app's kind, else
// invalid_request; for a workspace named to the app the platform still
// keeps, else not_found; from the document the test set, or its default
// one, else unavailable.
func (p *Platform) linkCheck(rq *request) answer {
	var lc contract.LinkCheck
	if err := decodeContract(rq.body, &lc); err != nil {
		return refusal(contract.CodeInvalid, "the check is not valid")
	}
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(lc.Codes) > 0 && !rq.app.allowLinkCheck(rq.arg, now) {
		return refusal(contract.CodeRateLimited, "too many link checks with codes in this workspace")
	}
	if lc.ValidateFor(rq.app.id) != nil {
		return refusal(contract.CodeInvalid, "the check is not valid")
	}
	w := p.workspaces[rq.arg]
	if w == nil || !rq.app.named[rq.arg] || p.closedPast(w) {
		return refusal(contract.CodeNotFound, "not found")
	}
	in := rq.app.entInputs[rq.arg]
	if in == nil {
		in = p.defaultEntInputLocked(rq.app, rq.arg)
	}
	if in == nil {
		return refusal(contract.CodeUnavailable, "try again")
	}
	d := in.doc
	computed := contract.T(atMicroseconds(now))
	a := contract.LinkCheckAnswer{Trial: contract.TrialNotNeeded, ComputedAt: computed,
		Switches: contract.LinkCheckSwitches{NewLinks: d.Switches.NewLinks}}
	if d.Places.Free != nil {
		place := contract.PlaceNone
		if *d.Places.Free > 0 {
			place = contract.PlaceFree
		}
		a.Place = &place
	}
	if len(lc.Codes) > 0 && !lc.Connected && d.State.TrialEndsAt != nil {
		// Identities merge, so the oldest clock a code matches wins.
		var end *time.Time
		for _, c := range lc.Codes {
			if at, ok := p.trialClocks[c]; ok && (end == nil || at.Before(*end)) {
				end = &at
			}
		}
		switch {
		case end == nil:
			ends := contract.T(computed.Add(trialLength))
			a.Trial, a.TrialEndsAt = contract.TrialRunning, &ends
		case end.After(computed.Time):
			ends := contract.T(*end)
			a.Trial, a.TrialEndsAt = contract.TrialRunning, &ends
		default:
			a.Trial = contract.TrialUsedUp
		}
	}
	return answer{status: http.StatusOK, body: a}
}

// allowLinkCheck spends one of the workspace's link checks with codes.
func (a *entitlementsApp) allowLinkCheck(ws string, now time.Time) bool {
	b := a.linkRate[ws]
	if b == nil {
		b = &bucket{tokens: contract.LinkChecksPerMinute, metered: now}
		a.linkRate[ws] = b
	}
	if elapsed := now.Sub(b.metered).Minutes(); elapsed > 0 {
		b.tokens = min(contract.LinkChecksPerMinute, b.tokens+elapsed*contract.LinkChecksPerMinute)
	}
	b.metered = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// ---------------------------------------------------------------------------
// Trim orders and their results
// ---------------------------------------------------------------------------

// IssueTrimOrder issues the order o into the document of the workspace ws
// that the test set for app, and publishes that document with it. The
// fake fills the order's app, workspace and generation, a fresh UUIDv7
// order_id when it is empty, and issued_at (its clock), not_before
// (issued_at) and valid_until (issued_at plus 6 hours) when they are zero;
// it keeps the order without secret and mac, and signs it each time it
// serves the document, with the secret that signs that answer. It refuses,
// as ErrInvalid, an order that does not validate, one with floor null
// beside a plan source plan or live_move, an order_id issued before, and a
// document that is not enforce and expired; ErrUnknown for a workspace
// not named to the app, or with no document. It returns the order_id. The order is the
// workspace's until a result for it is kept, the test sets a document that
// drops it, or a new generation or a restore drops it.
func (p *Platform) IssueTrimOrder(app, ws string, o contract.TrimOrder) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil || st.entInputs[ws] == nil || !st.named[ws] {
		return "", ErrUnknown
	}
	in := st.entInputs[ws]
	now := atMicroseconds(p.now())
	o.App, o.WorkspaceID, o.Generation = app, ws, p.generation
	if o.OrderID == "" {
		o.OrderID = st.newCommandID(now)
	}
	if o.IssuedAt.IsZero() {
		o.IssuedAt = contract.T(now)
	}
	if o.NotBefore.IsZero() {
		o.NotBefore = o.IssuedAt
	}
	if o.ValidUntil.IsZero() {
		o.ValidUntil = contract.T(o.IssuedAt.Add(contract.MaxTrimValidity))
	}
	if o.BasisPurge == nil {
		o.BasisPurge = map[string]contract.Time{}
	}
	o.Secret, o.MAC = 0, ""
	probe := o
	probe.Secret, probe.MAC = 1, "v1="+strings.Repeat("0", 64)
	switch {
	case probe.Validate() != nil, st.orders[o.OrderID] != nil:
		return "", ErrInvalid
	case o.Floor == nil && (in.doc.Plan.Source == contract.SourcePlan || in.doc.Plan.Source == contract.SourceLiveMove):
		return "", ErrInvalid
	}
	prev := in.order
	in.order = &o
	if _, err := p.publishEntitlementsLocked(st, ws); err != nil {
		in.order = prev
		return "", ErrInvalid
	}
	st.orders[o.OrderID] = &trimRecord{order: o}
	return o.OrderID, nil
}

// TrimResult is the result app sent for the order orderID that the fake
// kept; false when there is none.
func (p *Platform) TrimResult(app, orderID string) (contract.TrimResult, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil || st.orders[orderID] == nil || st.orders[orderID].result == nil {
		return contract.TrimResult{}, false
	}
	return *st.orders[orderID].result, true
}

// postTrimResult answers POST /contract/v1/trim/results: a body that is
// not one JSON object is invalid_request; any other gets a signed 200 for
// the result: rejected invalid_request when it does not decode strictly or
// validate, alone or against its order (order_id echoed when a UUID, else
// ""); rejected not_found for no order of the app with that id; duplicate
// for the same result kept; rejected conflict for another kept; else
// accepted, and kept, which ends the order: the workspace's document is
// published again without it.
func (p *Platform) postTrimResult(rq *request) answer {
	if !json.Valid(rq.body) || !bytes.HasPrefix(bytes.TrimSpace(rq.body), []byte("{")) {
		return refusal(contract.CodeInvalid, "the result is not one JSON object")
	}
	var r contract.TrimResult
	if decodeContract(rq.body, &r) != nil || r.Validate() != nil {
		return answer{status: http.StatusOK, body: trimAnswer(orderIDOf(rq.body), contract.OutcomeRejected, contract.CodeInvalid)}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	rec := rq.app.orders[r.OrderID]
	switch {
	case rec == nil:
		return answer{status: http.StatusOK, body: trimAnswer(r.OrderID, contract.OutcomeRejected, contract.CodeNotFound)}
	case r.ValidateFor(rec.order) != nil:
		return answer{status: http.StatusOK, body: trimAnswer(r.OrderID, contract.OutcomeRejected, contract.CodeInvalid)}
	case rec.result != nil && sameTrimResult(*rec.result, r):
		return answer{status: http.StatusOK, body: trimAnswer(r.OrderID, contract.OutcomeDuplicate, "")}
	case rec.result != nil:
		return answer{status: http.StatusOK, body: trimAnswer(r.OrderID, contract.OutcomeRejected, contract.CodeConflict)}
	}
	rec.result = &r
	if in := rq.app.entInputs[rec.order.WorkspaceID]; in != nil && in.order != nil && in.order.OrderID == r.OrderID {
		in.order = nil
		_, _ = p.publishEntitlementsLocked(rq.app, rec.order.WorkspaceID)
	}
	return answer{status: http.StatusOK, body: trimAnswer(r.OrderID, contract.OutcomeAccepted, "")}
}

func trimAnswer(id, outcome, code string) contract.TrimResultAnswer {
	a := contract.TrimResultAnswer{OrderID: id, Outcome: outcome}
	if code != "" {
		a.Code = &code
	}
	return a
}

func sameTrimResult(a, b contract.TrimResult) bool {
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}

// orderIDOf is the order_id of a result that did not decode, when it holds
// a UUID; "" otherwise.
func orderIDOf(raw []byte) string {
	var members map[string]json.RawMessage
	var id string
	if json.Unmarshal(raw, &members) != nil || json.Unmarshal(members["order_id"], &id) != nil || !contract.ValidUUID(id) {
		return ""
	}
	return id
}
