package contracttest

// The settings part (SPEC section 11.19; the platform's decision 0054): the
// documents an app sends of its settings, per workspace section and per
// person; the commands a test issues as the console does (IssueCommand),
// which reach the app's command feed signed when served; and the results the
// app sends back, after which the fake issues an intent again for a retry
// code, as the platform does. Times are the fake's clock (Options.Now): a
// command's expiry, a retry's backoff, an intent's five minutes and the 90
// days of a command delivered again all follow it, so a test moves the clock
// it gives the fake. What falls due by the clock alone (a retry's backoff,
// an expiry no answer carried, an intent's end) is settled whenever the fake
// next looks at the app's commands: at a command feed request, a batch of
// results, a document, a change to the directory, IssueCommand and the
// accessors. So a long-poll that waits is woken by a command issued, or
// issued again on an event (ReopenTeam, a newer document whose accepts
// lists the kind again), never by the clock alone: it sees a retry the
// clock made due when its wait ends.
//
// The rules the fake holds an app to, as the platform does:
//   - a document and each result are read strictly (contract.DecodeStrict):
//     every member present but those the type marks omitempty, null only
//     where the type holds a pointer, so a document missing truncated, or
//     Wappie Cloud's missing its null snapshot_seq, is invalid_request, and
//     a result missing at is rejected invalid_request;
//   - an intent refused kind_not_accepted, a retry for a tightening kind
//     only, is issued again once the fake keeps a document of its section
//     (for a person's kind, the actor's own document) whose state_seq is
//     higher than that of the document kept when the result came (any, when
//     none was), and whose accepts lists the kind; the document kept when
//     the result came never issues it again, whatever its accepts;
//   - a final result for a command with one kept already is duplicate when
//     it is the same result (its time compared at microseconds), else
//     rejected conflict; for a command delivered again (again: true), which
//     an app runs again after its own restore, it is duplicate when its
//     outcome and code are the kept one's, whatever its at, state_seq and
//     detail.
//
// Where the platform does more, the fake is simpler:
//   - it cleans no label of a document again, where the platform cleans each
//     one and drops a hint that is not one: Validate refuses a label that is
//     not one (contract.ValidLabel), and the fake keeps what the app sent;
//   - it keeps every command, result and intent for good, where the platform
//     keeps a command 30 days and a tightening that ran 90;
//   - it checks no role or row-bound right before issuing a command, nor
//     that params.before is the value the state shows, nor a withheld team:
//     a test issues what it means the app to judge;
//   - a command issued again names the state_seq its first command was drawn
//     from, the actor's role now (or, once the actor is no longer a member,
//     the role the last command named) and the account documents published
//     now, a document the app no longer follows keeping the version the last
//     command named.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/thehappieco/kit/contract"
)

// ErrNotOffered is a command the console would not offer, so IssueCommand
// issues none: no state of its section, or of its actor's own settings, is
// kept; that state's accepts does not list its kind; its workspace is
// closed; or the app does not follow its actor or the target's person (the
// console offers the app's sign-in hop instead). It never echoes a value.
var ErrNotOffered = errors.New("contracttest: the console offers no such command")

// againWindow is how long a tightening that ran is delivered again to an app
// that asks from below the cursor it acknowledged.
const againWindow = 90 * 24 * time.Hour

// The backoff of an intent issued again after a retry code that waits on
// time and names no retry_after: 5 s × 2ⁿ, at most 5 minutes.
const (
	retryBackoff    = 5 * time.Second
	retryBackoffMax = 5 * time.Minute
)

// maxCommandPageBytes bounds a command feed answer: a page ends, with more,
// before it would reach 1 MiB, though a first command over it still comes
// alone.
const maxCommandPageBytes = 1 << 20

// placeholderMAC stands for a command's mac while the fake validates a
// command it keeps without one: it signs each command when it serves it.
var placeholderMAC = "v1=" + strings.Repeat("0", 64)

// sectionSegment is a section's path segment the route matches; a section
// that is not one of the app's is the call's invalid_request.
var sectionSegment = regexp.MustCompile(`^[a-z][a-z-]{0,63}$`)

// CommandSpec is what the console chooses of a command; IssueCommand fills
// the rest.
type CommandSpec struct {
	// Kind is one of the app's kinds (contract.CommandKinds).
	Kind string
	// Workspace is the workspace's id, or "" for a person's kind.
	Workspace string
	// Actor is the sub of the person who acted.
	Actor  string
	Target contract.CommandTarget
	// Params are the kind's params; nil for {}.
	Params    json.RawMessage
	Confirm   *string
	Agreement *contract.Agreement
}

// Intent is where an intent stands: a command a test issued, and every
// command the fake issued again for it after a retry code.
type Intent struct {
	// Commands are the ids of its commands, the first first.
	Commands []string
	// Waiting: it waits to be issued again, once Due passes by the fake's
	// clock or, when Due is zero, for the event its last code names
	// (team_closed: the team's reopening; kind_not_accepted: a document of
	// its section newer than the one kept when the result came, whose
	// accepts lists the kind); and either way for an open workspace whose
	// kept document accepts its kind.
	Waiting bool
	Due     time.Time
	// Expired: the fake ended it expired, as the console shows it: a kind
	// with an expiry whose first command's five minutes ended while it
	// waited, or whose command no answer carried by its expires_at; or an
	// intent that waited 30 days from its last issue.
	Expired bool
}

// settingsKey names a workspace's section.
type settingsKey struct{ workspace, section string }

// settingsApp is an app's settings part: the documents it sent, the
// commands issued to it, its command feed, and the results it sent.
type settingsApp struct {
	sections map[settingsKey]contract.SettingsDoc
	people   map[string]contract.PersonSettingsDoc

	// secretNo is the generation number of the app's current secret: 1,
	// rising each time SetSecrets changes it.
	secretNo int64

	cmdHead  int64
	wseqs    map[string]int64 // by workspace
	cmds     []*command       // by cseq
	cmdByID  map[string]*command
	intents  []*intent // in the order they began
	acked    int64     // the highest cursor the app asked after in this generation
	cmdWake  chan struct{}
	cmdPolls chan struct{}
}

func newSettingsApp(longPolls int) settingsApp {
	return settingsApp{
		sections: map[settingsKey]contract.SettingsDoc{}, people: map[string]contract.PersonSettingsDoc{},
		secretNo: 1, wseqs: map[string]int64{}, cmdByID: map[string]*command{},
		cmdWake: make(chan struct{}), cmdPolls: make(chan struct{}, longPolls),
	}
}

// command is one command issued to an app.
type command struct {
	c          contract.Command // as kept: no mac
	intent     *intent
	tightening bool
	// carried: an answer carried it by its expires_at, so its result is the
	// app's, whenever it comes.
	carried bool
	// final is its final result, the app's or the fake's own expired;
	// progress its in_progress, while no final one is kept.
	final, progress *contract.CommandResult
	// ranAt is when the fake kept a final ran, for a command delivered
	// again.
	ranAt time.Time
	// again: the fake delivered it again (again: true), so a result an app
	// sends after running it again matches the kept one by its outcome and
	// code.
	again bool
}

// intent is what a person chose in the console, issued once and again after
// each retry code until it runs, gets a final code, or ends expired.
type intent struct {
	spec       CommandSpec
	section    string
	tightening bool
	basedOn    int64 // the state_seq its first command was drawn from
	firstID    string
	firstAt    time.Time
	deadline   *time.Time // the first command's expires_at; nil for a tightening kind
	ids        []string
	role       *string          // the last command's actor_role
	docs       map[string]int64 // the last command's based_on.docs
	lastIssue  time.Time
	waiting    bool
	due        time.Time
	expired    bool
	// newerThan: after kind_not_accepted, it is issued again only from a
	// document whose state_seq is above this one, the state_seq of the
	// document kept when the result came (0 for none).
	newerThan     int64
	needsNewerDoc bool
}

// restoreCommands is Restore's: the documents go, as the snapshots do; the
// commands with a final result go too, so a result for one is not_found;
// the commands without one stay, numbered again from 1 in their order, so
// the command feed from 0 holds them; their intents, and the intents
// waiting to be issued again, stay.
func (a *settingsApp) restoreCommands() {
	a.sections, a.people = map[settingsKey]contract.SettingsDoc{}, map[string]contract.PersonSettingsDoc{}
	var kept []*command
	live := map[*intent]bool{}
	for _, c := range a.cmds {
		if c.final != nil {
			delete(a.cmdByID, c.c.ID)
			continue
		}
		c.c.CSeq = int64(len(kept) + 1)
		kept = append(kept, c)
		live[c.intent] = true
	}
	a.cmds, a.cmdHead, a.acked = kept, int64(len(kept)), 0
	a.intents = slices.DeleteFunc(a.intents, func(in *intent) bool { return !in.waiting && !live[in] })
}

// newCommandGeneration is NewGeneration's: the app follows the command feed
// from 0 again, which holds every command without a final result, and no
// cursor is acknowledged in the new generation yet.
func (a *settingsApp) newCommandGeneration() { a.acked = 0 }

// wakeCommands wakes the app's command feed long-polls.
func (a *settingsApp) wakeCommands() {
	close(a.cmdWake)
	a.cmdWake = make(chan struct{})
}

// newCommandID is a fresh UUIDv7 for a command issued at at, lowercase and
// canonical, never the nil UUID nor one the app holds.
func (a *settingsApp) newCommandID(at time.Time) string {
	for {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		ms := max(at.UnixMilli(), 0)
		for i := 5; i >= 0; i-- {
			b[i] = byte(ms)
			ms >>= 8
		}
		b[6] = 0x70 | b[6]&0x0f
		b[8] = 0x80 | b[8]&0x3f
		h := hex.EncodeToString(b[:])
		id := h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
		if a.cmdByID[id] == nil {
			return id
		}
	}
}

// matchSettings finds the settings part's calls for a method and the raw
// path after /contract/v1/: a section's argument is its workspace and
// section, joined by a slash.
func matchSettings(method, rest string) (route, string, bool) {
	switch {
	case rest == "commands":
		if method == http.MethodGet {
			return route{CallCommands, SmallBodyLimit, (*Platform).commandFeed}, "", true
		}
	case rest == "commands/results":
		if method == http.MethodPost {
			return route{CallResults, ResultsBodyLimit, (*Platform).postResults}, "", true
		}
	case strings.HasPrefix(rest, "accounts/") && strings.HasSuffix(rest, "/settings"):
		sub := strings.TrimSuffix(strings.TrimPrefix(rest, "accounts/"), "/settings")
		if contract.ValidUUID(sub) && method == http.MethodPut {
			return route{CallPersonSettings, PersonSettingsBodyLimit, (*Platform).putPersonSettings}, sub, true
		}
	case strings.HasPrefix(rest, "workspaces/"):
		ws, tail, _ := strings.Cut(strings.TrimPrefix(rest, "workspaces/"), "/")
		section, ok := strings.CutPrefix(tail, "settings/")
		if ok && contract.ValidUUID(ws) && sectionSegment.MatchString(section) && method == http.MethodPut {
			return route{CallSettings, SettingsBodyLimit, (*Platform).putSettings}, ws + "/" + section, true
		}
	}
	return route{}, "", false
}

// ---------------------------------------------------------------------------
// Documents
// ---------------------------------------------------------------------------

// decodeContract reads what an app sends as the platform reads it: the
// fake's own checks of its text first (valid UTF-8, no escape of half a
// surrogate pair, no member twice, member names), then the contract's
// strict reading (contract.DecodeStrict): every member present but those
// the type marks omitempty, and null only where it holds a pointer.
func decodeContract(raw []byte, dst any) error {
	if err := checkJSON(raw, 1<<30); err != nil {
		return err
	}
	return contract.DecodeStrict(raw, dst)
}

// putSettings takes a section: decoded strictly and valid, for the
// workspace and section its path names, of the app that sends it, its
// state_seq at most a day ahead of the fake's clock, else invalid_request;
// for a workspace named to the app, else not_found. One at or below the
// state_seq kept is ignored, and answered accepted all the same.
func (p *Platform) putSettings(rq *request) answer {
	ws, section, _ := strings.Cut(rq.arg, "/")
	var doc contract.SettingsDoc
	if err := decodeContract(rq.body, &doc); err != nil || doc.Validate() != nil {
		return refusal(contract.CodeInvalid, "the section is not valid")
	}
	switch {
	case doc.WorkspaceID != ws || doc.Section != section:
		return refusal(contract.CodeInvalid, "the path names another workspace or section")
	case doc.App != rq.app.id:
		return refusal(contract.CodeInvalid, "the section is another app's")
	case doc.StateSeq > p.now().Add(MaxSnapshotAhead).UnixMilli():
		return refusal(contract.CodeInvalid, "the state_seq is more than a day ahead")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.workspaces[ws] == nil || !rq.app.named[ws] {
		return refusal(contract.CodeNotFound, "not found")
	}
	key := settingsKey{ws, section}
	if old, ok := rq.app.sections[key]; !ok || old.StateSeq < doc.StateSeq {
		rq.app.sections[key] = doc
	}
	p.settleCommandsLocked(rq.app, p.now())
	return answer{status: http.StatusOK, body: contract.AccessResult{Accepted: true}}
}

// putPersonSettings takes a person's document, as putSettings takes a
// section: for the sub its path names, of a person the app follows, else
// not_found.
func (p *Platform) putPersonSettings(rq *request) answer {
	var doc contract.PersonSettingsDoc
	if err := decodeContract(rq.body, &doc); err != nil || doc.Validate() != nil {
		return refusal(contract.CodeInvalid, "the person's settings are not valid")
	}
	switch {
	case doc.Sub != rq.arg:
		return refusal(contract.CodeInvalid, "the path names another person")
	case doc.App != rq.app.id:
		return refusal(contract.CodeInvalid, "the person's settings are another app's")
	case doc.StateSeq > p.now().Add(MaxSnapshotAhead).UnixMilli():
		return refusal(contract.CodeInvalid, "the state_seq is more than a day ahead")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !rq.app.follows[doc.Sub] {
		return refusal(contract.CodeNotFound, "not found")
	}
	if old, ok := rq.app.people[doc.Sub]; !ok || old.StateSeq < doc.StateSeq {
		rq.app.people[doc.Sub] = doc
	}
	p.settleCommandsLocked(rq.app, p.now())
	return answer{status: http.StatusOK, body: contract.AccessResult{Accepted: true}}
}

// Settings is the latest section of the workspace ws that app sent and the
// fake kept, as the app sent it; false when there is none.
func (p *Platform) Settings(app, ws, section string) (contract.SettingsDoc, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil {
		return contract.SettingsDoc{}, false
	}
	d, ok := st.sections[settingsKey{ws, section}]
	return d, ok
}

// PersonSettings is the latest document of the person sub that app sent
// and the fake kept, as the app sent it; false when there is none.
func (p *Platform) PersonSettings(app, sub string) (contract.PersonSettingsDoc, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil {
		return contract.PersonSettingsDoc{}, false
	}
	d, ok := st.people[sub]
	return d, ok
}

// ---------------------------------------------------------------------------
// Issuing commands
// ---------------------------------------------------------------------------

// IssueCommand issues a command to app, as the console does once a person
// chose it, and returns its id. The fake fills what the console fills: the
// current generation, a fresh UUIDv7, the next cseq of the app's command
// feed and, for a workspace's kind, the next wseq of the workspace for the
// app; the kind's section; the actor's role in the workspace, from the
// directory (null for a person's kind); issued_at and first_issued_at at the
// fake's clock, kept at microseconds, and expires_at five minutes later
// (null for a tightening kind); based_on's state_seq, the kept section's or,
// for a person's kind, the actor's own document's, and the versions of the
// actor's and the target person's account documents, which it publishes
// first, as the console does inline; and secret, the generation number of
// the app's current secret. It keeps the command without a mac: the fake
// signs it each time it serves it.
//
// It refuses, issuing nothing: an app it does not serve, a workspace that
// does not exist, or an actor who is not an account and, for a workspace's
// kind, a member of it (ErrUnknown); a kind that is not one of the app's
// (only wappie, mailie and contract.ReferenceApp have any), a person's kind
// with a workspace, or a command that fails contract.Command.ValidateIn with
// the workspace's kind (ErrInvalid); and what the console would not offer
// (ErrNotOffered).
func (p *Platform) IssueCommand(app string, spec CommandSpec) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil {
		return "", ErrUnknown
	}
	now := p.now()
	p.settleCommandsLocked(st, now)
	k, ok := contract.CommandKindOf(app, spec.Kind)
	if !ok {
		return "", ErrInvalid
	}
	person := k.Section == contract.SectionPerson
	if person && spec.Workspace != "" {
		return "", ErrInvalid
	}
	if p.accounts[spec.Actor] == nil {
		return "", ErrUnknown
	}
	if !person {
		w := p.workspaces[spec.Workspace]
		if w == nil {
			return "", ErrUnknown
		}
		if _, member := w.members[spec.Actor]; !member {
			return "", ErrUnknown
		}
	}
	spec.Params = bytes.Clone(spec.Params)
	if len(spec.Params) == 0 {
		spec.Params = json.RawMessage(`{}`)
	}
	in := &intent{spec: spec, section: k.Section, tightening: k.Tightening}
	if err := p.offeredLocked(st, in); err != nil {
		return "", err
	}
	in.basedOn = p.stateLocked(st, in).seq
	c, err := p.issueLocked(st, in, now)
	if err != nil {
		return "", err
	}
	st.intents = append(st.intents, in)
	return c.c.ID, nil
}

// keptState is the state a command is drawn from: its section's, or its
// actor's own document's.
type keptState struct {
	seq     int64
	accepts []string
	ok      bool
}

func (p *Platform) stateLocked(app *appState, in *intent) keptState {
	if in.section == contract.SectionPerson {
		d, ok := app.people[in.spec.Actor]
		return keptState{d.StateSeq, d.Accepts, ok}
	}
	d, ok := app.sections[settingsKey{in.spec.Workspace, in.section}]
	return keptState{d.StateSeq, d.Accepts, ok}
}

// offeredLocked is nil when the console would offer the intent's command
// now: in an open workspace, from a kept state whose accepts lists its kind.
func (p *Platform) offeredLocked(app *appState, in *intent) error {
	if ws := in.spec.Workspace; ws != "" {
		if w := p.workspaces[ws]; w == nil || w.closed {
			return fmt.Errorf("%w: the workspace is closed", ErrNotOffered)
		}
	}
	state := p.stateLocked(app, in)
	switch {
	case !state.ok:
		return fmt.Errorf("%w: no state is kept to draw it from", ErrNotOffered)
	case !slices.Contains(state.accepts, in.spec.Kind):
		return fmt.Errorf("%w: the state does not accept its kind", ErrNotOffered)
	}
	return nil
}

// docVersionsLocked publishes, inline as the console does, the account
// documents of the actor and the target's person for app, and returns their
// versions. A sub the app does not follow keeps the version held, and,
// without one, the command is not offered.
func (p *Platform) docVersionsLocked(app *appState, spec CommandSpec, held map[string]int64) (map[string]int64, error) {
	docs := map[string]int64{}
	for _, sub := range []string{spec.Actor, spec.Target.Person} {
		switch v, ok := held[sub]; {
		case sub == "":
		case app.follows[sub]:
			docs[sub] = p.publishLocked(app, sub).Version
		case ok:
			docs[sub] = v
		default:
			return nil, fmt.Errorf("%w: the app does not follow the actor or the target's person", ErrNotOffered)
		}
	}
	return docs, nil
}

// issueLocked issues the intent's next command at now: its first, or one
// issued again, which names the first (retry_of), carries its
// first_issued_at and, for a kind with an expiry, the first's expires_at.
// It keeps the command only once it validates, and wakes the app's command
// feed.
func (p *Platform) issueLocked(app *appState, in *intent, now time.Time) (*command, error) {
	spec := in.spec
	at := atMicroseconds(now)
	c := contract.Command{
		V: contract.CommandV, Type: contract.CommandType, App: app.id, Generation: p.generation,
		ID: app.newCommandID(at), CSeq: app.cmdHead + 1, Kind: spec.Kind, Section: in.section, Actor: spec.Actor,
		Target: spec.Target, Params: spec.Params, IssuedAt: contract.T(at), FirstIssuedAt: contract.T(at),
		Confirm: spec.Confirm, Agreement: spec.Agreement, Secret: app.secretNo,
	}
	switch {
	case len(in.ids) > 0:
		first := in.firstID
		c.RetryOf, c.FirstIssuedAt = &first, contract.T(in.firstAt)
		if in.deadline != nil {
			deadline := contract.T(*in.deadline)
			c.ExpiresAt = &deadline
		}
	case !in.tightening:
		expires := contract.T(at.Add(contract.CommandLifetime))
		c.ExpiresAt = &expires
	}
	wsKind := ""
	if ws := spec.Workspace; ws != "" {
		w := p.workspaces[ws]
		wseq := app.wseqs[ws] + 1
		c.WorkspaceID, c.WSeq, wsKind = &ws, &wseq, w.kind
		c.ActorRole = in.role
		if role, member := w.members[spec.Actor]; member {
			c.ActorRole = &role
		}
	}
	docs, err := p.docVersionsLocked(app, spec, in.docs)
	if err != nil {
		return nil, err
	}
	c.BasedOn = contract.BasedOn{StateSeq: in.basedOn, Docs: docs}
	probe := c
	probe.MAC = placeholderMAC
	if err := probe.ValidateIn(wsKind); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	app.cmdHead = c.CSeq
	if c.WSeq != nil {
		app.wseqs[spec.Workspace] = *c.WSeq
	}
	if len(in.ids) == 0 {
		in.firstID, in.firstAt = c.ID, at
		if c.ExpiresAt != nil {
			deadline := c.ExpiresAt.Time
			in.deadline = &deadline
		}
	}
	in.ids = append(in.ids, c.ID)
	in.role, in.docs, in.lastIssue, in.waiting, in.due, in.needsNewerDoc = c.ActorRole, docs, at, false, time.Time{}, false
	cmd := &command{c: c, intent: in, tightening: in.tightening}
	app.cmds = append(app.cmds, cmd)
	app.cmdByID[c.ID] = cmd
	app.wakeCommands()
	return cmd, nil
}

// settleCommandsLocked settles what fell due by the clock for app: an
// intent that waits past its first command's five minutes, or 30 days from
// its last issue, ends expired; one whose retry is due, and which the
// console would offer now (after kind_not_accepted, from a document newer
// than the one kept when the result came), is issued again; and a command
// with an expiry that no answer carried by its expires_at is recorded
// expired.
func (p *Platform) settleCommandsLocked(app *appState, now time.Time) {
	var due []*intent
	for _, in := range app.intents {
		if !in.waiting {
			continue
		}
		switch {
		case in.deadline != nil && !now.Before(*in.deadline), !now.Before(in.lastIssue.Add(contract.CommandRetention)):
			in.waiting, in.expired = false, true
		case (in.due.IsZero() || !now.Before(in.due)) && p.offeredLocked(app, in) == nil &&
			(!in.needsNewerDoc || p.stateLocked(app, in).seq > in.newerThan):
			due = append(due, in)
		}
	}
	slices.SortStableFunc(due, func(a, b *intent) int { return a.due.Compare(b.due) })
	for _, in := range due {
		if _, err := p.issueLocked(app, in, now); err != nil {
			// What no longer validates, or names someone the app never
			// followed, is never issued: the intent ends there.
			in.waiting = false
		}
	}
	for _, c := range app.cmds {
		if c.final == nil && !c.carried && c.c.ExpiresAt != nil && now.After(c.c.ExpiresAt.Time) {
			code := contract.CodeExpired
			c.final = &contract.CommandResult{ID: c.c.ID, Outcome: contract.OutcomeRefused, Code: &code, At: *c.c.ExpiresAt}
			if in := c.intent; in.ids[len(in.ids)-1] == c.c.ID {
				in.expired = true
			}
		}
	}
}

// Command is the command id issued to app as the fake keeps it, in the
// platform's generation now: with no mac, and the secret number it was
// issued under; false when there is none.
func (p *Platform) Command(app, id string) (contract.Command, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil {
		return contract.Command{}, false
	}
	p.settleCommandsLocked(st, p.now())
	c := st.cmdByID[id]
	if c == nil {
		return contract.Command{}, false
	}
	out := c.c
	out.Generation = p.generation
	return out, true
}

// CommandResult is the result of the command id of app the fake keeps: its
// final one, the app's or, for a command no answer carried by its
// expires_at, the fake's own refused expired (at its expires_at, with no
// state_seq); else its in_progress; false when there is neither.
func (p *Platform) CommandResult(app, id string) (contract.CommandResult, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil {
		return contract.CommandResult{}, false
	}
	p.settleCommandsLocked(st, p.now())
	c := st.cmdByID[id]
	switch {
	case c == nil:
		return contract.CommandResult{}, false
	case c.final != nil:
		return *c.final, true
	case c.progress != nil:
		return *c.progress, true
	}
	return contract.CommandResult{}, false
}

// Intent is where the intent of the command id of app stands, id being any
// of its commands; false when there is none.
func (p *Platform) Intent(app, id string) (Intent, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil {
		return Intent{}, false
	}
	p.settleCommandsLocked(st, p.now())
	for _, in := range st.intents {
		if slices.Contains(in.ids, id) {
			return Intent{Commands: slices.Clone(in.ids), Waiting: in.waiting, Due: in.due, Expired: in.expired}, true
		}
	}
	return Intent{}, false
}

// ---------------------------------------------------------------------------
// The command feed
// ---------------------------------------------------------------------------

// commandFeed answers GET /contract/v1/commands?after=&wait=, the query read
// as the other feeds' are.
func (p *Platform) commandFeed(rq *request) answer {
	if ans, ok := noBody(rq); !ok {
		return ans
	}
	after, wait, ok := feedQuery(rq.query)
	if !ok {
		return refusal(contract.CodeInvalid, "the command feed takes after and an optional wait from 0 to 25")
	}
	// The channel is taken before the read, so a command issued between the
	// two still wakes this request.
	f, woken, ans, ok := p.readCommandFeed(rq, after)
	if !ok {
		return ans
	}
	if len(f.Items) > 0 || wait == 0 {
		return answer{status: http.StatusOK, body: f}
	}
	select {
	case rq.app.cmdPolls <- struct{}{}:
		defer func() { <-rq.app.cmdPolls }()
	default:
		return refusal(contract.CodeRateLimited, "too many command feed requests wait at once")
	}
	timer := time.NewTimer(time.Duration(wait) * time.Second)
	defer timer.Stop()
	select {
	case <-p.drain:
		return answer{status: http.StatusOK, body: f}
	case <-rq.ctx.Done():
		return answer{status: http.StatusOK, body: f}
	case <-woken:
	case <-timer.C:
	}
	f, _, ans, ok = p.readCommandFeed(rq, after)
	if !ok {
		return ans
	}
	return answer{status: http.StatusOK, body: f}
}

// readCommandFeed is the app's command feed after the cursor, and the
// channel its next issue closes. The request acknowledges every command up
// to the cursor. A page holds, oldest first, every command after the cursor
// with no final result, which it marks carried; and, when the cursor is
// below the highest the app acknowledged in this generation, every
// tightening command after it whose final result is a ran kept in the last
// 90 days, marked again. Each command is signed as served, with the secret
// that signs the answer.
func (p *Platform) readCommandFeed(rq *request, after int64) (contract.CommandFeed, <-chan struct{}, answer, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	app := rq.app
	now := p.now()
	p.settleCommandsLocked(app, now)
	woken := app.cmdWake
	if after > app.cmdHead {
		return contract.CommandFeed{}, woken, refusal(contract.CodeGone, "the cursor is past the command feed's head: take every command again"), false
	}
	again := after < app.acked
	app.acked = max(app.acked, after)
	f := contract.CommandFeed{Generation: p.generation, Head: app.cmdHead, Items: []contract.CommandFeedItem{}, NextAfter: app.cmdHead}
	// The envelope at its longest: next_after at the head, more false.
	size := len(marshal(f))
	for _, c := range app.cmds {
		redo := again && c.tightening && c.final != nil && c.final.Outcome == contract.OutcomeRan && !now.After(c.ranAt.Add(againWindow))
		if c.c.CSeq <= after || (c.final != nil && !redo) {
			continue
		}
		if len(f.Items) == contract.MaxCommandFeedItems {
			f.More = true
			break
		}
		raw, err := p.servedLocked(app, c, rq.secret, rq.secretNo)
		if err != nil {
			return contract.CommandFeed{}, woken, refusal(contract.CodeUnavailable, "try again"), false
		}
		item := contract.CommandFeedItem{CSeq: c.c.CSeq, Command: raw, Again: redo}
		n := len(marshal(item)) + 1
		if len(f.Items) > 0 && size+n >= maxCommandPageBytes {
			f.More = true
			break
		}
		size += n
		f.Items = append(f.Items, item)
		if c.final == nil {
			c.carried = true
		}
		if redo {
			c.again = true
		}
	}
	f.NextAfter = max(after, f.Head)
	if f.More {
		f.NextAfter = f.Items[len(f.Items)-1].CSeq
	}
	return f, woken, answer{}, true
}

// servedLocked is the command as the fake serves it now: in the platform's
// generation, naming the generation number of the secret that signs the
// answer, and its mac made with that secret.
func (p *Platform) servedLocked(app *appState, c *command, secret string, secretNo int64) (json.RawMessage, error) {
	out := c.c
	out.Generation, out.Secret, out.MAC = p.generation, secretNo, ""
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return contract.SignCommand(raw, app.id, secret)
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

// postResults takes a batch of 1 to 100 results, whose text must be valid
// (else the whole batch is invalid_request), and answers each result alone,
// in order.
func (p *Platform) postResults(rq *request) answer {
	var batch struct {
		Results []json.RawMessage `json:"results"`
	}
	if checkJSON(rq.body, 1) != nil {
		return refusal(contract.CodeInvalid, "a batch holds 1 to 100 results")
	}
	dec := json.NewDecoder(bytes.NewReader(rq.body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&batch); err != nil || len(batch.Results) == 0 || len(batch.Results) > contract.MaxCommandResults {
		return refusal(contract.CodeInvalid, "a batch holds 1 to 100 results")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	p.settleCommandsLocked(rq.app, now)
	out := make([]contract.CommandResultAnswer, len(batch.Results))
	for i, raw := range batch.Results {
		out[i] = p.postResultLocked(rq.app, raw, now)
	}
	p.settleCommandsLocked(rq.app, now)
	return answer{status: http.StatusOK, body: contract.CommandResultsAnswer{Results: out}}
}

// postResultLocked answers one result: rejected invalid_request when it does
// not decode strictly or is not valid for its command's kind; rejected
// not_found for no such command of the app; for a final result, duplicate
// when the same final result is kept (its time compared at microseconds, as
// the platform keeps it), or, for a command delivered again, one of the
// same outcome and code, and rejected conflict when another is; for an
// in_progress, duplicate after a final one or the same in_progress; else
// accepted, and kept.
func (p *Platform) postResultLocked(app *appState, raw json.RawMessage, now time.Time) contract.CommandResultAnswer {
	var r contract.CommandResult
	if decodeContract(raw, &r) != nil || r.Validate() != nil {
		return resultAnswer(resultID(raw), contract.OutcomeRejected, contract.CodeInvalid)
	}
	c := app.cmdByID[r.ID]
	switch {
	case c == nil:
		return resultAnswer(r.ID, contract.OutcomeRejected, contract.CodeNotFound)
	case r.ValidateFor(app.id, c.c.Kind) != nil:
		return resultAnswer(r.ID, contract.OutcomeRejected, contract.CodeInvalid)
	case r.Outcome == contract.OutcomeInProgress:
		if c.final != nil || (c.progress != nil && sameResult(*c.progress, r)) {
			return resultAnswer(r.ID, contract.OutcomeDuplicate, "")
		}
		c.progress = &r
		return resultAnswer(r.ID, contract.OutcomeAccepted, "")
	case c.final != nil && (sameResult(*c.final, r) || c.again && sameOutcome(*c.final, r)):
		return resultAnswer(r.ID, contract.OutcomeDuplicate, "")
	case c.final != nil:
		return resultAnswer(r.ID, contract.OutcomeRejected, contract.CodeConflict)
	}
	c.final, c.progress = &r, nil
	if r.Outcome == contract.OutcomeRan {
		c.ranAt = now
	}
	p.awaitRetryLocked(app, c, r, now)
	return resultAnswer(r.ID, contract.OutcomeAccepted, "")
}

// awaitRetryLocked makes an intent whose last command got a retry code wait
// to be issued again: for team_closed, for the team's reopening; for
// kind_not_accepted, for a document of its section with a state_seq above
// the one kept now, which lists the kind; for any other, after retry_after
// or a backoff of 5 s × 2ⁿ, at most 5 minutes, n counting the commands
// issued again so far. Any other final result ends the intent.
func (p *Platform) awaitRetryLocked(app *appState, c *command, r contract.CommandResult, now time.Time) {
	in := c.intent
	if in.ids[len(in.ids)-1] != c.c.ID || r.Outcome != contract.OutcomeRefused ||
		contract.CommandRefusalClass(*r.Code, c.tightening) != contract.ClassRetry {
		return
	}
	in.waiting, in.due = true, time.Time{}
	switch *r.Code {
	case contract.CodeTeamClosed:
	case contract.CodeKindNotAccepted:
		in.needsNewerDoc, in.newerThan = true, p.stateLocked(app, in).seq
	default:
		delay := retryBackoffMax
		if n := len(in.ids) - 1; n < 6 {
			delay = min(retryBackoff<<n, retryBackoffMax)
		}
		if r.RetryAfter != nil {
			delay = time.Duration(*r.RetryAfter) * time.Second
		}
		in.due = now.Add(delay)
	}
}

// sameResult reports whether a and b are the same result, their times
// compared at microseconds.
func sameResult(a, b contract.CommandResult) bool {
	a.At, b.At = contract.T(atMicroseconds(a.At.Time)), contract.T(atMicroseconds(b.At.Time))
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}

// sameOutcome reports whether a and b have the same outcome and code: how
// a result an app sends for a command delivered again, after running it
// again, matches the kept one, whatever its at, state_seq and detail.
func sameOutcome(a, b contract.CommandResult) bool {
	return a.Outcome == b.Outcome && (a.Code == nil) == (b.Code == nil) && (a.Code == nil || *a.Code == *b.Code)
}

func resultAnswer(id, outcome, code string) contract.CommandResultAnswer {
	a := contract.CommandResultAnswer{ID: id, Outcome: outcome}
	if code != "" {
		a.Code = &code
	}
	return a
}

// resultID is the id of a result that did not decode, when it holds a UUID;
// "" otherwise.
func resultID(raw json.RawMessage) string {
	var members map[string]json.RawMessage
	var id string
	if json.Unmarshal(raw, &members) != nil || json.Unmarshal(members["id"], &id) != nil || !contract.ValidUUID(id) {
		return ""
	}
	return id
}
