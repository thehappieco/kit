package contracttest_test

// The fake's settings part (SPEC section 11.19), through an app's
// contract.Client: the documents an app sends, the commands a test issues
// as the console does, signed when served, their expiry and their delivery
// again by the fake's clock, the results the app sends back, and the
// intents the fake issues again after a retry code.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"
)

const (
	carlaSub = "0199a0c2-0000-7000-8000-000000000003"
	danSub   = "0199a0c2-0000-7000-8000-000000000004"
)

// settingsFixture is a team of ana (owner) and bob (admin), both of whom
// wappie follows, with wappie's numbers section of the team and ana's own
// document kept, every kind of theirs accepted.
type settingsFixture struct {
	h              *harness
	c              *contract.Client
	team, personal string
	// seq is the state_seq of the documents the fixture sent.
	seq int64
}

func settingsSetup(t *testing.T, opts contracttest.Options) settingsFixture {
	t.Helper()
	if opts.Apps == nil {
		opts.Apps = []contracttest.App{wappie()}
	}
	h := newHarness(t, opts)
	personal, err := h.p.AddAccount(anaSub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.p.AddAccount(bobSub); err != nil {
		t.Fatal(err)
	}
	team, err := h.p.AddTeam("TBFG", anaSub)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.p.SetRole(team, bobSub, contract.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	c := h.p.Client("wappie")
	for _, sub := range []string{anaSub, bobSub} {
		if _, err := c.Subscribe(t.Context(), sub); err != nil {
			t.Fatal(err)
		}
	}
	fx := settingsFixture{h: h, c: c, team: team, personal: personal, seq: h.clock.Now().UnixMilli()}
	if err := c.PutSettings(t.Context(), numbersDoc(team, fx.seq, kindsOf(contract.SectionNumbers))); err != nil {
		t.Fatal(err)
	}
	if err := c.PutPersonSettings(t.Context(), personDoc(anaSub, fx.seq, kindsOf(contract.SectionPerson))); err != nil {
		t.Fatal(err)
	}
	return fx
}

// kindsOf are wappie's kinds of a section, in the SPEC's order.
func kindsOf(section string) []string {
	var out []string
	for _, k := range contract.CommandKinds("wappie") {
		if k.Section == section {
			out = append(out, k.Kind)
		}
	}
	return out
}

func without(kinds []string, drop ...string) []string {
	return slices.DeleteFunc(slices.Clone(kinds), func(k string) bool { return slices.Contains(drop, k) })
}

const numbersData = `{"can_link":true,"places_free":null,"storage_paused":false,"pending":[],"items":[]}`

func numbersDoc(ws string, seq int64, accepts []string) contract.SettingsDoc {
	snap := seq
	return contract.SettingsDoc{
		V: contract.SettingsV, Type: contract.SettingsType, App: "wappie", Section: contract.SectionNumbers,
		Producer: contract.ProducerWappie, WorkspaceID: ws, StateSeq: seq, SnapshotSeq: &snap,
		MeasuredAt: contract.T(time.UnixMilli(seq)), Accepts: accepts, Data: json.RawMessage(numbersData),
	}
}

func personDoc(sub string, seq int64, accepts []string) contract.PersonSettingsDoc {
	return contract.PersonSettingsDoc{
		V: contract.SettingsV, Type: contract.PersonSettingsType, App: "wappie", Producer: contract.ProducerWappie,
		Sub: sub, StateSeq: seq, MeasuredAt: contract.T(time.UnixMilli(seq)), Accepts: accepts,
		Data: json.RawMessage(`{"notices":[],"signed_out_everywhere_at":null}`),
	}
}

// dropSend is ana taking bob's send away on a number: a tightening.
func dropSend(team string) contracttest.CommandSpec {
	return contracttest.CommandSpec{
		Kind: contract.OpItemFlagsDrop, Workspace: team, Actor: anaSub,
		Target: contract.CommandTarget{Item: number, Person: bobSub},
		Params: json.RawMessage(`{"before":{"can":["read","send"]},"after":{"can":["read"]}}`),
	}
}

// removeAccess is ana taking every flag of bob's away: a tightening.
func removeAccess(team string) contracttest.CommandSpec {
	return contracttest.CommandSpec{
		Kind: contract.OpItemAccessRemove, Workspace: team, Actor: anaSub,
		Target: contract.CommandTarget{Item: number, Person: bobSub},
		Params: json.RawMessage(`{"before":{"can":["read","send"]},"after":{"can":[]}}`),
	}
}

// rename is ana naming a number: a kind with an expiry.
func rename(team string) contracttest.CommandSpec {
	return contracttest.CommandSpec{
		Kind: contract.OpItemRename, Workspace: team, Actor: anaSub, Target: contract.CommandTarget{Item: number},
		Params: json.RawMessage(`{"before":{"label":null},"after":{"label":"Vendas"}}`),
	}
}

// moveOut is ana moving a number to her personal workspace: a kind whose
// first result may be in_progress.
func moveOut(team, personal string) contracttest.CommandSpec {
	item := number
	return contracttest.CommandSpec{
		Kind: contract.OpItemMoveOut, Workspace: team, Actor: anaSub, Target: contract.CommandTarget{Item: number}, Confirm: &item,
		Params: json.RawMessage(`{"before":{"workspace":"` + team + `"},"after":{"workspace":"` + personal + `"}}`),
	}
}

func issue(t *testing.T, fx settingsFixture, spec contracttest.CommandSpec) string {
	t.Helper()
	id, err := fx.h.p.IssueCommand("wappie", spec)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// take reads the command feed after the cursor, at once, and verifies and
// decodes each command as an app does, under secrets (secretA when none).
func take(t *testing.T, c *contract.Client, after int64, secrets ...string) (contract.CommandFeed, []contract.Command, time.Time) {
	t.Helper()
	if len(secrets) == 0 {
		secrets = []string{secretA}
	}
	f, signedAt, err := c.Commands(t.Context(), after, 0)
	if err != nil {
		t.Fatal(err)
	}
	cmds := make([]contract.Command, len(f.Items))
	for i, it := range f.Items {
		cmd, err := contract.VerifyCommand(it.Command, c.App, secrets)
		if err != nil {
			t.Fatalf("command %d: %v", it.CSeq, err)
		}
		if cmd.CSeq != it.CSeq || cmd.Generation != f.Generation {
			t.Fatalf("command %d is not its item's: %+v", it.CSeq, cmd)
		}
		cmds[i] = cmd
	}
	return f, cmds, signedAt
}

func ids(cmds []contract.Command) []string {
	out := make([]string, len(cmds))
	for i, c := range cmds {
		out[i] = c.ID
	}
	return out
}

func ran(fx settingsFixture, id string) contract.CommandResult {
	seq := fx.seq + 1
	return contract.CommandResult{ID: id, Outcome: contract.OutcomeRan, StateSeq: &seq, At: contract.T(fx.h.clock.Now())}
}

func refused(fx settingsFixture, id, code string, retryAfter int64) contract.CommandResult {
	r := contract.CommandResult{ID: id, Outcome: contract.OutcomeRefused, Code: &code, StateSeq: &fx.seq, At: contract.T(fx.h.clock.Now())}
	if retryAfter > 0 {
		r.RetryAfter = &retryAfter
	}
	return r
}

func inProgress(fx settingsFixture, id string) contract.CommandResult {
	return contract.CommandResult{ID: id, Outcome: contract.OutcomeInProgress, At: contract.T(fx.h.clock.Now())}
}

// post sends results and wants the answers named, each an outcome or
// "rejected:" and its code.
func post(t *testing.T, fx settingsFixture, results []contract.CommandResult, want ...string) {
	t.Helper()
	answers, err := fx.c.PostResults(t.Context(), results)
	if err != nil {
		t.Fatal(err)
	}
	for i, a := range answers {
		got := a.Outcome
		if a.Code != nil {
			got += ":" + *a.Code
		}
		if got != want[i] {
			t.Errorf("result %d: got %s, want %s", i, got, want[i])
		}
	}
}

func results(r ...contract.CommandResult) []contract.CommandResult { return r }

func TestASectionAndAPersonsDocumentAreKeptAsTheAppSentThem(t *testing.T) {
	fx := settingsSetup(t, contracttest.Options{})
	ctx, c, p := t.Context(), fx.c, fx.h.p
	all := kindsOf(contract.SectionNumbers)
	kept, ok := p.Settings("wappie", fx.team, contract.SectionNumbers)
	if !ok || kept.StateSeq != fx.seq || !slices.Equal(kept.Accepts, all) || string(kept.Data) != numbersData {
		t.Fatalf("the section kept: %+v %v", kept, ok)
	}
	// One at or below the state_seq kept is answered accepted, and ignored.
	for _, seq := range []int64{fx.seq - 1, fx.seq} {
		if err := c.PutSettings(ctx, numbersDoc(fx.team, seq, []string{})); err != nil {
			t.Fatalf("state_seq %d: %v", seq, err)
		}
	}
	if kept, _ := p.Settings("wappie", fx.team, contract.SectionNumbers); kept.StateSeq != fx.seq || len(kept.Accepts) != len(all) {
		t.Fatalf("an older section replaced the kept one: %+v", kept)
	}
	if err := c.PutSettings(ctx, numbersDoc(fx.team, fx.seq+1, []string{contract.OpItemRename})); err != nil {
		t.Fatal(err)
	}
	if kept, _ := p.Settings("wappie", fx.team, contract.SectionNumbers); kept.StateSeq != fx.seq+1 || len(kept.Accepts) != 1 {
		t.Fatalf("a newer section was not kept: %+v", kept)
	}
	person, ok := p.PersonSettings("wappie", anaSub)
	if !ok || person.StateSeq != fx.seq || person.Sub != anaSub {
		t.Fatalf("the person kept: %+v %v", person, ok)
	}
	// A workspace never named to the app, and a person it does not follow,
	// are not_found.
	if _, err := p.AddAccount(carlaSub); err != nil {
		t.Fatal(err)
	}
	elsewhere, err := p.AddTeam("Elsewhere", carlaSub)
	if err != nil {
		t.Fatal(err)
	}
	mustRefusal(t, c.PutSettings(ctx, numbersDoc(elsewhere, fx.seq+2, []string{})), contract.CodeNotFound)
	mustRefusal(t, c.PutSettings(ctx, numbersDoc(teamID, fx.seq+2, []string{})), contract.CodeNotFound)
	mustRefusal(t, c.PutPersonSettings(ctx, personDoc(carlaSub, fx.seq+2, []string{})), contract.CodeNotFound)
	// Another app's document, though valid for that app, is refused.
	other := numbersDoc(fx.team, fx.seq+2, []string{})
	other.App, other.Producer = "fakeproduct", "fakeproduct"
	if other.Validate() != nil {
		t.Fatal("the other app's section is not valid")
	}
	mustRefusal(t, c.PutSettings(ctx, other), contract.CodeInvalid)
	// The path names the document's workspace and section, or sub.
	body, _ := json.Marshal(numbersDoc(fx.team, fx.seq+2, []string{}))
	for _, target := range []string{
		"/contract/v1/workspaces/" + fx.team + "/settings/mcp",
		"/contract/v1/workspaces/" + fx.personal + "/settings/numbers",
	} {
		cl := call{method: http.MethodPut, target: target, app: "wappie", body: string(body)}
		fx.h.wantSigned(t, fx.h.send(t, cl), cl, http.StatusBadRequest, contract.CodeInvalid)
	}
	pbody, _ := json.Marshal(personDoc(anaSub, fx.seq+2, []string{}))
	cl := call{method: http.MethodPut, target: "/contract/v1/accounts/" + bobSub + "/settings", app: "wappie", body: string(pbody)}
	fx.h.wantSigned(t, fx.h.send(t, cl), cl, http.StatusBadRequest, contract.CodeInvalid)
	// The body is decoded strictly, its data too.
	target := "/contract/v1/workspaces/" + fx.team + "/settings/numbers"
	for _, bad := range []string{
		strings.Replace(string(body), `{"v":1`, `{"x":1,"v":1`, 1),
		strings.Replace(string(body), `"can_link":true`, `"can_link":true,"x":1`, 1),
		strings.Replace(string(body), `"truncated":false`, `"truncated":false,"truncated":false`, 1),
		strings.Replace(string(body), `"section"`, `"Section"`, 1),
	} {
		if bad == string(body) {
			t.Fatal("the bad body is the good one")
		}
		cl := call{method: http.MethodPut, target: target, app: "wappie", body: bad}
		fx.h.wantSigned(t, fx.h.send(t, cl), cl, http.StatusBadRequest, contract.CodeInvalid)
	}
	// A state_seq a day ahead of the clock is taken, one millisecond more is
	// not.
	ahead := fx.h.clock.Now().Add(contracttest.MaxSnapshotAhead).UnixMilli()
	mustRefusal(t, c.PutSettings(ctx, numbersDoc(fx.team, ahead+1, []string{})), contract.CodeInvalid)
	mustRefusal(t, c.PutPersonSettings(ctx, personDoc(anaSub, ahead+1, []string{})), contract.CodeInvalid)
	if err := c.PutSettings(ctx, numbersDoc(fx.team, ahead, []string{})); err != nil {
		t.Fatalf("a day ahead: %v", err)
	}
}

func TestACommandIsIssuedAsTheConsoleIssuesItAndSignedWhenServed(t *testing.T) {
	fx := settingsSetup(t, contracttest.Options{})
	ctx := t.Context()
	first := issue(t, fx, dropSend(fx.team))
	second := issue(t, fx, rename(fx.team))
	f, cmds, signedAt := take(t, fx.c, 0)
	now := fx.h.clock.Now()
	if !signedAt.Equal(now.Truncate(time.Second)) {
		t.Fatalf("the answer's signed time %v, the clock %v", signedAt, now)
	}
	gen, _ := fx.h.p.Generation()
	if f.Generation != gen || f.Head != 2 || f.NextAfter != 2 || f.More || !slices.Equal(ids(cmds), []string{first, second}) {
		t.Fatalf("the feed: %+v", f)
	}
	ana, err := fx.c.Account(ctx, anaSub)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := fx.c.Account(ctx, bobSub)
	if err != nil {
		t.Fatal(err)
	}
	for i, cmd := range cmds {
		if err := cmd.ValidateIn(contract.KindTeam); err != nil {
			t.Fatalf("command %d: %v", i, err)
		}
		if cmd.CSeq != int64(i+1) || *cmd.WSeq != int64(i+1) || *cmd.WorkspaceID != fx.team || cmd.RetryOf != nil ||
			*cmd.ActorRole != contract.RoleOwner || cmd.Secret != 1 || cmd.BasedOn.StateSeq != fx.seq ||
			cmd.BasedOn.Docs[anaSub] != ana.Version || !cmd.IssuedAt.Equal(now) || !cmd.FirstIssuedAt.Equal(now) {
			t.Fatalf("command %d: %+v", i, cmd)
		}
		// A UUIDv7 of the clock's millisecond.
		if hex := strings.ReplaceAll(cmd.ID, "-", ""); cmd.ID[14] != '7' || hex[:12] != fmt.Sprintf("%012x", now.UnixMilli()) {
			t.Fatalf("command %d's id is no UUIDv7 of its time: %s", i, cmd.ID)
		}
	}
	if cmds[0].ExpiresAt != nil || cmds[0].BasedOn.Docs[bobSub] != bob.Version || len(cmds[0].BasedOn.Docs) != 2 {
		t.Fatalf("the tightening: %+v", cmds[0])
	}
	if cmds[1].ExpiresAt == nil || !cmds[1].ExpiresAt.Equal(now.Add(contract.CommandLifetime)) || len(cmds[1].BasedOn.Docs) != 1 {
		t.Fatalf("the kind with an expiry: %+v", cmds[1])
	}
	// Under another app the body is refused before its mac, and under
	// another secret no mac holds.
	if _, err := contract.VerifyCommand(f.Items[0].Command, "mailie", []string{secretA}); !errors.Is(err, contract.ErrInvalid) {
		t.Fatalf("under another app: %v", err)
	}
	if _, err := contract.VerifyCommand(f.Items[0].Command, "wappie", []string{secretB}); !errors.Is(err, contract.ErrCommandMAC) {
		t.Fatalf("under another secret: %v", err)
	}
	// The fake keeps it with no mac.
	if kept, ok := fx.h.p.Command("wappie", first); !ok || kept.MAC != "" || kept.ID != first || kept.Secret != 1 || kept.Generation != gen {
		t.Fatalf("kept: %+v %v", kept, ok)
	}
	// A person's kind names no workspace, wseq or role, and is drawn from
	// the actor's own document.
	signOut := issue(t, fx, contracttest.CommandSpec{Kind: contract.OpPersonSignOutEverywhere, Actor: anaSub})
	_, cmds, _ = take(t, fx.c, 2)
	if len(cmds) != 1 || cmds[0].ID != signOut || cmds[0].ValidateIn("") != nil || cmds[0].WorkspaceID != nil ||
		cmds[0].WSeq != nil || cmds[0].ActorRole != nil || cmds[0].Section != contract.SectionPerson ||
		cmds[0].CSeq != 3 || cmds[0].BasedOn.StateSeq != fx.seq || cmds[0].ExpiresAt != nil {
		t.Fatalf("the person's command: %+v", cmds)
	}
	// The workspace's wseq goes on where it was; the app's cseq rises by one.
	issue(t, fx, rename(fx.team))
	if _, cmds, _ = take(t, fx.c, 3); len(cmds) != 1 || cmds[0].CSeq != 4 || *cmds[0].WSeq != 3 {
		t.Fatalf("the next command: %+v", cmds)
	}
}

func TestACommandNoAnswerCarriedBeforeItsExpiryIsRecordedExpiredAndNeverDelivered(t *testing.T) {
	fx := settingsSetup(t, contracttest.Options{})
	late := issue(t, fx, rename(fx.team))
	tightening := issue(t, fx, dropSend(fx.team))
	issuedAt := fx.h.clock.Now()
	fx.h.clock.Add(contract.CommandLifetime + time.Second)
	if _, cmds, _ := take(t, fx.c, 0); !slices.Equal(ids(cmds), []string{tightening}) {
		t.Fatalf("after the five minutes: %v", ids(cmds))
	}
	r, ok := fx.h.p.CommandResult("wappie", late)
	if !ok || r.Outcome != contract.OutcomeRefused || *r.Code != contract.CodeExpired || r.StateSeq != nil ||
		!r.At.Equal(issuedAt.Add(contract.CommandLifetime)) {
		t.Fatalf("the expired command's result: %+v %v", r, ok)
	}
	if in, ok := fx.h.p.Intent("wappie", late); !ok || !in.Expired || in.Waiting || len(in.Commands) != 1 {
		t.Fatalf("its intent: %+v %v", in, ok)
	}
	// An answer that carries one at its expires_at makes it the app's, to
	// answer whenever it does.
	onTime := issue(t, fx, rename(fx.team))
	fx.h.clock.Add(contract.CommandLifetime)
	if _, cmds, _ := take(t, fx.c, 0); !slices.Contains(ids(cmds), onTime) {
		t.Fatalf("at its expires_at: %v", ids(cmds))
	}
	fx.h.clock.Add(time.Hour)
	if _, cmds, _ := take(t, fx.c, 0); !slices.Equal(ids(cmds), []string{tightening, onTime}) {
		t.Fatalf("an hour after it was carried: %v", ids(cmds))
	}
	if r, ok := fx.h.p.CommandResult("wappie", onTime); ok {
		t.Fatalf("the fake answered a carried command: %+v", r)
	}
}

func TestACommandWithAFinalResultIsNeverDeliveredAgain(t *testing.T) {
	fx := settingsSetup(t, contracttest.Options{})
	id := issue(t, fx, rename(fx.team))
	if _, cmds, _ := take(t, fx.c, 0); len(cmds) != 1 {
		t.Fatalf("the command: %+v", cmds)
	}
	// Carried, it stays in the feed until its result, however long.
	fx.h.clock.Add(time.Hour)
	if _, cmds, _ := take(t, fx.c, 0); len(cmds) != 1 || cmds[0].ID != id {
		t.Fatalf("an hour on: %+v", cmds)
	}
	post(t, fx, results(ran(fx, id)), contract.OutcomeAccepted)
	if _, cmds, _ := take(t, fx.c, 0); len(cmds) != 0 {
		t.Fatalf("after its result: %+v", cmds)
	}
	// Acknowledged, then asked for from below: a kind that does not tighten
	// is never delivered again.
	if _, cmds, _ := take(t, fx.c, 1); len(cmds) != 0 {
		t.Fatalf("after the cursor: %+v", cmds)
	}
	if f, cmds, _ := take(t, fx.c, 0); len(cmds) != 0 || f.NextAfter != 1 {
		t.Fatalf("from below the cursor: %+v", f)
	}
	if r, ok := fx.h.p.CommandResult("wappie", id); !ok || r.Outcome != contract.OutcomeRan {
		t.Fatalf("kept: %+v %v", r, ok)
	}
}

func TestEachResultIsAnsweredAloneAndInOrder(t *testing.T) {
	fx := settingsSetup(t, contracttest.Options{})
	drop := issue(t, fx, dropSend(fx.team))
	name := issue(t, fx, rename(fx.team))
	move := issue(t, fx, moveOut(fx.team, fx.personal))
	take(t, fx.c, 0)
	unknown := "0199f3c4-0000-7000-8000-00000000dead"
	noSeq := ran(fx, drop)
	noSeq.StateSeq = nil // a ran names its state_seq, whatever its kind
	one := int64(1)
	sessions := ran(fx, name)
	sessions.Detail = &contract.ResultDetail{SessionsEnded: &one} // a person.sign_out_everywhere's, not a rename's
	nanos := ran(fx, drop)
	nanos.At = contract.T(fx.h.clock.Now().Add(100 * time.Nanosecond)) // the same at microseconds
	post(t, fx, results(
		ran(fx, drop), ran(fx, drop), nanos, refused(fx, drop, contract.CodeLastReader, 0), ran(fx, unknown), noSeq, sessions,
		inProgress(fx, move), inProgress(fx, move), ran(fx, move), inProgress(fx, move),
	),
		contract.OutcomeAccepted, contract.OutcomeDuplicate, contract.OutcomeDuplicate, "rejected:conflict", "rejected:not_found",
		"rejected:invalid_request", "rejected:invalid_request",
		contract.OutcomeAccepted, contract.OutcomeDuplicate, contract.OutcomeAccepted, contract.OutcomeDuplicate,
	)
	if r, ok := fx.h.p.CommandResult("wappie", move); !ok || r.Outcome != contract.OutcomeRan {
		t.Fatalf("the move's result: %+v %v", r, ok)
	}
	if _, ok := fx.h.p.CommandResult("wappie", name); ok {
		t.Fatal("a result refused as invalid was kept")
	}
	// A result that does not decode is rejected alone, by its id, and the
	// batch goes on.
	good, _ := json.Marshal(ran(fx, name))
	bad := strings.Replace(string(good), `"state_seq":`+fmt.Sprint(fx.seq+1), `"state_seq":1.5`, 1)
	bad = strings.Replace(bad, name, drop, 1)
	if bad == string(good) {
		t.Fatal("the bad result is the good one")
	}
	target := "/contract/v1/commands/results"
	cl := call{method: http.MethodPost, target: target, app: "wappie", body: `{"results":[` + bad + `,` + string(good) + `]}`}
	a := fx.h.send(t, cl)
	fx.h.verified(t, a, []string{secretA}, "wappie", http.MethodPost, target)
	var got contract.CommandResultsAnswer
	if err := json.Unmarshal(a.body, &got); err != nil || len(got.Results) != 2 ||
		got.Results[0].ID != drop || got.Results[0].Outcome != contract.OutcomeRejected || *got.Results[0].Code != contract.CodeInvalid ||
		got.Results[1].ID != name || got.Results[1].Outcome != contract.OutcomeAccepted {
		t.Fatalf("the answers: %d %s", a.status, a.body)
	}
	// A batch of none, of more than 100, or whose text is not valid is
	// refused whole.
	for _, body := range []string{`{"results":[]}`, `{"results":[` + string(good) + `],"results":[]}`, `{"results":[` + string(good) + `],"x":1}`} {
		cl := call{method: http.MethodPost, target: target, app: "wappie", body: body}
		fx.h.wantSigned(t, fx.h.send(t, cl), cl, http.StatusBadRequest, contract.CodeInvalid)
	}
	many := make([]contract.CommandResult, contract.MaxCommandResults+1)
	for i := range many {
		many[i] = ran(fx, name)
	}
	_, err := fx.c.PostResults(t.Context(), many)
	mustRefusal(t, err, contract.CodeInvalid)
}

func TestAskingFromBelowTheAcknowledgedCursorDeliversAgainOnlyTheTighteningsThatRan(t *testing.T) {
	fx := settingsSetup(t, contracttest.Options{})
	ranTightening := issue(t, fx, dropSend(fx.team))
	ranRename := issue(t, fx, rename(fx.team))
	refusedTightening := issue(t, fx, removeAccess(fx.team))
	open := issue(t, fx, dropSend(fx.team))
	if _, cmds, _ := take(t, fx.c, 0); len(cmds) != 4 {
		t.Fatalf("the four: %+v", cmds)
	}
	post(t, fx, results(ran(fx, ranTightening), ran(fx, ranRename), refused(fx, refusedTightening, contract.CodeLastReader, 0)),
		contract.OutcomeAccepted, contract.OutcomeAccepted, contract.OutcomeAccepted)
	if _, cmds, _ := take(t, fx.c, 4); len(cmds) != 0 {
		t.Fatalf("after the cursor: %+v", cmds)
	}
	// The app restored a backup and asks from 0, below the 4 it
	// acknowledged.
	f, cmds, _ := take(t, fx.c, 0)
	if !slices.Equal(ids(cmds), []string{ranTightening, open}) || !f.Items[0].Again || f.Items[1].Again {
		t.Fatalf("from below the cursor: %+v", f)
	}
	// Asked for from 2, the one that ran is behind the cursor.
	if f, cmds, _ := take(t, fx.c, 2); !slices.Equal(ids(cmds), []string{open}) || f.Items[0].Again {
		t.Fatalf("from 2: %+v", f)
	}
	// Run again an hour later, judged on another state_seq, it meets the
	// kept result by its outcome and code; another outcome or code is a
	// conflict. A command never delivered again keeps the strict rule: the
	// same ran an hour later is a conflict.
	fx.h.clock.Add(time.Hour)
	rerunSeq := fx.seq + 9
	rerun := ran(fx, ranTightening)
	rerun.StateSeq = &rerunSeq
	stale := refused(fx, ranTightening, contract.CodeStateChanged, 0)
	later := ran(fx, ranRename)
	later.StateSeq = &rerunSeq
	post(t, fx, results(rerun, stale, later), contract.OutcomeDuplicate, "rejected:conflict", "rejected:conflict")
	if r, _ := fx.h.p.CommandResult("wappie", ranTightening); r.StateSeq == nil || *r.StateSeq != fx.seq+1 {
		t.Fatalf("the rerun replaced the kept result: %+v", r)
	}
	// Ninety days on, a tightening that ran comes again no more.
	fx.h.clock.Add(90*24*time.Hour - time.Hour)
	if _, cmds, _ := take(t, fx.c, 0); !slices.Equal(ids(cmds), []string{ranTightening, open}) {
		t.Fatalf("at 90 days: %v", ids(cmds))
	}
	fx.h.clock.Add(time.Second)
	if _, cmds, _ := take(t, fx.c, 0); !slices.Equal(ids(cmds), []string{open}) {
		t.Fatalf("past 90 days: %v", ids(cmds))
	}
}

func TestARetryCodeIssuesTheIntentAgainNamingItsFirstCommand(t *testing.T) {
	fx := settingsSetup(t, contracttest.Options{})
	first := issue(t, fx, dropSend(fx.team))
	_, cmds, _ := take(t, fx.c, 0)
	firstAt := cmds[0].IssuedAt
	post(t, fx, results(refused(fx, first, contract.CodeWorkspaceBusy, 0)), contract.OutcomeAccepted)
	// No retry_after: a backoff of 5 s.
	if in, _ := fx.h.p.Intent("wappie", first); !in.Waiting || !in.Due.Equal(fx.h.clock.Now().Add(5*time.Second)) {
		t.Fatalf("the intent: %+v", in)
	}
	fx.h.clock.Add(4 * time.Second)
	if _, cmds, _ := take(t, fx.c, 1); len(cmds) != 0 {
		t.Fatalf("before its backoff: %+v", cmds)
	}
	fx.h.clock.Add(time.Second)
	_, cmds, _ = take(t, fx.c, 1)
	if len(cmds) != 1 || cmds[0].ID == first || cmds[0].RetryOf == nil || *cmds[0].RetryOf != first ||
		!cmds[0].FirstIssuedAt.Equal(firstAt.Time) || !cmds[0].IssuedAt.Equal(fx.h.clock.Now()) ||
		cmds[0].CSeq != 2 || *cmds[0].WSeq != 2 || cmds[0].ExpiresAt != nil || cmds[0].ValidateIn(contract.KindTeam) != nil {
		t.Fatalf("issued again: %+v", cmds)
	}
	second := cmds[0].ID
	// retry_after is the wait, when the app names one.
	post(t, fx, results(refused(fx, second, contract.CodeRateLimited, 30)), contract.OutcomeAccepted)
	fx.h.clock.Add(29 * time.Second)
	if _, cmds, _ := take(t, fx.c, 2); len(cmds) != 0 {
		t.Fatalf("before its retry_after: %+v", cmds)
	}
	fx.h.clock.Add(time.Second)
	_, cmds, _ = take(t, fx.c, 2)
	if len(cmds) != 1 || *cmds[0].RetryOf != first || cmds[0].CSeq != 3 {
		t.Fatalf("issued a third time: %+v", cmds)
	}
	third := cmds[0].ID
	// The backoff doubles with each command issued again: 5 s × 2².
	post(t, fx, results(refused(fx, third, contract.CodeMembershipsBehind, 0)), contract.OutcomeAccepted)
	if in, _ := fx.h.p.Intent("wappie", first); !in.Due.Equal(fx.h.clock.Now().Add(20 * time.Second)) {
		t.Fatalf("the third backoff: %+v", in)
	}
	fx.h.clock.Add(20 * time.Second)
	_, cmds, _ = take(t, fx.c, 3)
	if len(cmds) != 1 || *cmds[0].RetryOf != first {
		t.Fatalf("issued a fourth time: %+v", cmds)
	}
	fourth := cmds[0].ID
	// A final code ends it.
	post(t, fx, results(refused(fx, fourth, contract.CodeNotAuthorized, 0)), contract.OutcomeAccepted)
	fx.h.clock.Add(time.Hour)
	if _, cmds, _ := take(t, fx.c, 4); len(cmds) != 0 {
		t.Fatalf("after a final code: %+v", cmds)
	}
	in, ok := fx.h.p.Intent("wappie", third)
	if !ok || in.Waiting || in.Expired || !slices.Equal(in.Commands, []string{first, second, third, fourth}) {
		t.Fatalf("the intent: %+v %v", in, ok)
	}
}

func TestAKindWithAnExpiryIsIssuedAgainOnlyWithinItsFirstCommandsFiveMinutes(t *testing.T) {
	fx := settingsSetup(t, contracttest.Options{})
	first := issue(t, fx, rename(fx.team))
	_, cmds, _ := take(t, fx.c, 0)
	deadline := cmds[0].ExpiresAt
	post(t, fx, results(refused(fx, first, contract.CodeWorkspaceBusy, 60)), contract.OutcomeAccepted)
	fx.h.clock.Add(time.Minute)
	_, cmds, _ = take(t, fx.c, 1)
	// Issued again, it ends when its first command does.
	if len(cmds) != 1 || *cmds[0].RetryOf != first || cmds[0].ExpiresAt == nil || !cmds[0].ExpiresAt.Equal(deadline.Time) ||
		cmds[0].ValidateIn(contract.KindTeam) != nil {
		t.Fatalf("issued again: %+v", cmds)
	}
	post(t, fx, results(refused(fx, cmds[0].ID, contract.CodeWorkspaceBusy, 3600)), contract.OutcomeAccepted)
	fx.h.clock.Add(3 * time.Minute)
	if in, _ := fx.h.p.Intent("wappie", first); !in.Waiting || in.Expired {
		t.Fatalf("within its five minutes: %+v", in)
	}
	fx.h.clock.Add(time.Minute)
	if in, _ := fx.h.p.Intent("wappie", first); in.Waiting || !in.Expired || len(in.Commands) != 2 {
		t.Fatalf("at its five minutes: %+v", in)
	}
	fx.h.clock.Add(time.Hour)
	if _, cmds, _ := take(t, fx.c, 2); len(cmds) != 0 {
		t.Fatalf("an expired intent was issued again: %+v", cmds)
	}
}

func TestATeamClosedRefusalWaitsForTheTeamToReopen(t *testing.T) {
	fx := settingsSetup(t, contracttest.Options{})
	first := issue(t, fx, dropSend(fx.team))
	_, cmds, _ := take(t, fx.c, 0)
	if err := fx.h.p.CloseTeam(fx.team); err != nil {
		t.Fatal(err)
	}
	post(t, fx, results(refused(fx, first, contract.CodeTeamClosed, 0)), contract.OutcomeAccepted)
	fx.h.clock.Add(time.Hour)
	if _, again, _ := take(t, fx.c, 1); len(again) != 0 {
		t.Fatalf("issued again in a closed team: %+v", again)
	}
	if in, _ := fx.h.p.Intent("wappie", first); !in.Waiting || !in.Due.IsZero() {
		t.Fatalf("the intent waits for an event: %+v", in)
	}
	if err := fx.h.p.ReopenTeam(fx.team); err != nil {
		t.Fatal(err)
	}
	_, again, _ := take(t, fx.c, 1)
	if len(again) != 1 || *again[0].RetryOf != first || !again[0].FirstIssuedAt.Equal(cmds[0].IssuedAt.Time) ||
		again[0].BasedOn.Docs[anaSub] <= cmds[0].BasedOn.Docs[anaSub] || again[0].BasedOn.StateSeq != fx.seq {
		t.Fatalf("issued again at the reopening, with the documents published since: %+v", again)
	}
	// An intent that waits for an event ends 30 days from its last issue.
	if err := fx.h.p.CloseTeam(fx.team); err != nil {
		t.Fatal(err)
	}
	post(t, fx, results(refused(fx, again[0].ID, contract.CodeTeamClosed, 0)), contract.OutcomeAccepted)
	fx.h.clock.Add(contract.CommandRetention)
	if err := fx.h.p.ReopenTeam(fx.team); err != nil {
		t.Fatal(err)
	}
	if in, _ := fx.h.p.Intent("wappie", first); in.Waiting || !in.Expired {
		t.Fatalf("after 30 days: %+v", in)
	}
	if _, cmds, _ := take(t, fx.c, 2); len(cmds) != 0 {
		t.Fatalf("issued after 30 days: %+v", cmds)
	}
}

func TestKindNotAcceptedWaitsForItsKindInAcceptsOnlyForATightening(t *testing.T) {
	fx := settingsSetup(t, contracttest.Options{})
	drop := issue(t, fx, dropSend(fx.team))
	name := issue(t, fx, rename(fx.team))
	take(t, fx.c, 0)
	// Wappie rolled back: its section accepts neither kind now.
	all := kindsOf(contract.SectionNumbers)
	if err := fx.c.PutSettings(t.Context(), numbersDoc(fx.team, fx.seq+1, without(all, contract.OpItemFlagsDrop, contract.OpItemRename))); err != nil {
		t.Fatal(err)
	}
	post(t, fx, results(refused(fx, drop, contract.CodeKindNotAccepted, 0), refused(fx, name, contract.CodeKindNotAccepted, 0)),
		contract.OutcomeAccepted, contract.OutcomeAccepted)
	fx.h.clock.Add(time.Hour)
	if _, cmds, _ := take(t, fx.c, 2); len(cmds) != 0 {
		t.Fatalf("issued again while not accepted: %+v", cmds)
	}
	if in, _ := fx.h.p.Intent("wappie", drop); !in.Waiting || !in.Due.IsZero() {
		t.Fatalf("the tightening's intent: %+v", in)
	}
	if in, _ := fx.h.p.Intent("wappie", name); in.Waiting || in.Expired {
		t.Fatalf("for a kind that does not tighten, kind_not_accepted is final: %+v", in)
	}
	if err := fx.c.PutSettings(t.Context(), numbersDoc(fx.team, fx.seq+2, all)); err != nil {
		t.Fatal(err)
	}
	_, cmds, _ := take(t, fx.c, 2)
	if len(cmds) != 1 || *cmds[0].RetryOf != drop || cmds[0].BasedOn.StateSeq != fx.seq {
		t.Fatalf("issued again once accepted: %+v", cmds)
	}
}

func TestKindNotAcceptedIsIssuedAgainOnlyFromANewerDocumentThatListsTheKind(t *testing.T) {
	fx := settingsSetup(t, contracttest.Options{})
	all := kindsOf(contract.SectionNumbers)
	drop := issue(t, fx, dropSend(fx.team))
	take(t, fx.c, 0)
	// The answer comes before the narrower document: the document kept
	// then still lists the kind, and issues nothing again, however often
	// the app asks.
	post(t, fx, results(refused(fx, drop, contract.CodeKindNotAccepted, 0)), contract.OutcomeAccepted)
	for i := range 5 {
		if _, cmds, _ := take(t, fx.c, 1); len(cmds) != 0 {
			t.Fatalf("round %d issued it again from the document kept when the answer came: %+v", i, cmds)
		}
	}
	fx.h.clock.Add(time.Hour)
	if _, cmds, _ := take(t, fx.c, 1); len(cmds) != 0 {
		t.Fatalf("an hour on: %+v", cmds)
	}
	if in, _ := fx.h.p.Intent("wappie", drop); !in.Waiting || !in.Due.IsZero() || len(in.Commands) != 1 {
		t.Fatalf("the intent: %+v", in)
	}
	// The narrower document, newer, does not list it.
	if err := fx.c.PutSettings(t.Context(), numbersDoc(fx.team, fx.seq+1, without(all, contract.OpItemFlagsDrop))); err != nil {
		t.Fatal(err)
	}
	if _, cmds, _ := take(t, fx.c, 1); len(cmds) != 0 {
		t.Fatalf("from the narrower document: %+v", cmds)
	}
	// A newer one that lists it again issues it again.
	if err := fx.c.PutSettings(t.Context(), numbersDoc(fx.team, fx.seq+2, all)); err != nil {
		t.Fatal(err)
	}
	_, cmds, _ := take(t, fx.c, 1)
	if len(cmds) != 1 || *cmds[0].RetryOf != drop {
		t.Fatalf("from a newer document that lists it: %+v", cmds)
	}
	// Refused so again, it waits for a document newer than that one.
	post(t, fx, results(refused(fx, cmds[0].ID, contract.CodeKindNotAccepted, 0)), contract.OutcomeAccepted)
	if _, cmds, _ := take(t, fx.c, 2); len(cmds) != 0 {
		t.Fatalf("issued again from the same document: %+v", cmds)
	}
	if err := fx.c.PutSettings(t.Context(), numbersDoc(fx.team, fx.seq+3, all)); err != nil {
		t.Fatal(err)
	}
	if _, cmds, _ := take(t, fx.c, 2); len(cmds) != 1 || *cmds[0].RetryOf != drop || cmds[0].CSeq != 3 {
		t.Fatalf("from the next document: %+v", cmds)
	}
}

func TestADocumentOrAResultMissingAMemberOrNullWhereItMayNotBeIsInvalid(t *testing.T) {
	fx := settingsSetup(t, contracttest.Options{})
	send := func(what, target, body string) {
		t.Helper()
		cl := call{method: http.MethodPut, target: target, app: "wappie", body: body}
		a := fx.h.send(t, cl)
		if a.status != http.StatusBadRequest {
			t.Errorf("%s: %d %s", what, a.status, a.body)
			return
		}
		fx.h.wantSigned(t, a, cl, http.StatusBadRequest, contract.CodeInvalid)
	}
	cut := func(body, member string) string {
		t.Helper()
		out := strings.Replace(body, member, "", 1)
		if out == body {
			t.Fatalf("no %s in %s", member, body)
		}
		return out
	}
	section := "/contract/v1/workspaces/" + fx.team + "/settings/"
	numbers, _ := json.Marshal(numbersDoc(fx.team, fx.seq+1, []string{}))
	send("a section missing truncated", section+"numbers", cut(string(numbers), `"truncated":false,`))
	send("a section's truncated null", section+"numbers", strings.Replace(string(numbers), `"truncated":false`, `"truncated":null`, 1))
	send("a section's state_seq null", section+"numbers", strings.Replace(string(numbers), `"state_seq":`+fmt.Sprint(fx.seq+1), `"state_seq":null`, 1))
	send("a section's data with can_link null", section+"numbers", strings.Replace(string(numbers), `"can_link":true`, `"can_link":null`, 1))
	person, _ := json.Marshal(personDoc(anaSub, fx.seq+1, []string{}))
	send("a person's document missing truncated", "/contract/v1/accounts/"+anaSub+"/settings", cut(string(person), `"truncated":false,`))
	// Wappie Cloud's section names its snapshot_seq, null: missing, it is
	// not valid.
	cloud := contract.SettingsDoc{
		V: contract.SettingsV, Type: contract.SettingsType, App: "wappie", Section: contract.SectionInstallations,
		Producer: contract.ProducerWappieCloud, WorkspaceID: fx.team, StateSeq: fx.seq, MeasuredAt: contract.T(fx.h.clock.Now()),
		Accepts: []string{},
		Data:    json.RawMessage(`{"licences":{"used":0,"capacity":null},"hosted_numbers":0,"installations":[],"bindings":[]}`),
	}
	if err := fx.c.PutSettings(t.Context(), cloud); err != nil {
		t.Fatalf("Wappie Cloud's section: %v", err)
	}
	cloud.StateSeq++
	installations, _ := json.Marshal(cloud)
	send("Wappie Cloud's section missing snapshot_seq", section+"installations", cut(string(installations), `"snapshot_seq":null,`))
	if kept, _ := fx.h.p.Settings("wappie", fx.team, contract.SectionInstallations); kept.StateSeq != fx.seq {
		t.Fatalf("a refused section was kept: %+v", kept)
	}
	// A result missing at, or retry_after, is rejected alone, by its id.
	name := issue(t, fx, rename(fx.team))
	drop := issue(t, fx, dropSend(fx.team))
	take(t, fx.c, 0)
	noAt, _ := json.Marshal(ran(fx, name))
	noRetryAfter, _ := json.Marshal(ran(fx, drop))
	good, _ := json.Marshal(ran(fx, drop))
	target := "/contract/v1/commands/results"
	cl := call{method: http.MethodPost, target: target, app: "wappie", body: `{"results":[` +
		cut(string(noAt), `,"at":"`+fx.h.clock.Now().UTC().Format(time.RFC3339Nano)+`"`) + `,` +
		cut(string(noRetryAfter), `"retry_after":null,`) + `,` + string(good) + `]}`}
	a := fx.h.send(t, cl)
	fx.h.verified(t, a, []string{secretA}, "wappie", http.MethodPost, target)
	var got contract.CommandResultsAnswer
	if err := json.Unmarshal(a.body, &got); err != nil || len(got.Results) != 3 {
		t.Fatalf("the answers: %d %s", a.status, a.body)
	}
	for i, want := range []struct{ id, outcome string }{{name, contract.OutcomeRejected}, {drop, contract.OutcomeRejected}, {drop, contract.OutcomeAccepted}} {
		r := got.Results[i]
		if r.ID != want.id || r.Outcome != want.outcome || (want.outcome == contract.OutcomeRejected && *r.Code != contract.CodeInvalid) {
			t.Errorf("result %d: %+v", i, r)
		}
	}
}

func TestTheFakeIssuesNoCommandTheConsoleWouldNotOffer(t *testing.T) {
	fx := settingsSetup(t, contracttest.Options{})
	p := fx.h.p
	refuse := func(what string, spec contracttest.CommandSpec, want error) {
		t.Helper()
		if _, err := p.IssueCommand("wappie", spec); !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", what, err, want)
		}
	}
	// No state of the section kept.
	refuse("no state", contracttest.CommandSpec{Kind: contract.OpMCPConnectionRevoke, Workspace: fx.team, Actor: anaSub,
		Target: contract.CommandTarget{Row: "conn_1"}}, contracttest.ErrNotOffered)
	// A kind the state does not accept.
	if err := fx.c.PutSettings(t.Context(), numbersDoc(fx.team, fx.seq+1, without(kindsOf(contract.SectionNumbers), contract.OpItemRename))); err != nil {
		t.Fatal(err)
	}
	refuse("not accepted", rename(fx.team), contracttest.ErrNotOffered)
	// A target the app does not follow.
	if _, err := p.AddAccount(carlaSub); err != nil {
		t.Fatal(err)
	}
	if err := p.SetRole(fx.team, carlaSub, contract.RoleMember); err != nil {
		t.Fatal(err)
	}
	toCarla := dropSend(fx.team)
	toCarla.Target.Person = carlaSub
	refuse("a target not followed", toCarla, contracttest.ErrNotOffered)
	// An actor who is not a member, or no account.
	if _, err := p.AddAccount(danSub); err != nil {
		t.Fatal(err)
	}
	byDan := dropSend(fx.team)
	byDan.Actor = danSub
	refuse("an actor not a member", byDan, contracttest.ErrUnknown)
	byNobody := dropSend(fx.team)
	byNobody.Actor = eventA
	refuse("an actor with no account", byNobody, contracttest.ErrUnknown)
	refuse("a workspace that does not exist", dropSend(teamID), contracttest.ErrUnknown)
	// A kind not the app's, a person's kind with a workspace, and a command
	// that does not validate.
	refuse("a kind of mailie's", contracttest.CommandSpec{Kind: contract.OpConsentWithdraw, Actor: anaSub}, contracttest.ErrInvalid)
	refuse("a person's kind in a workspace", contracttest.CommandSpec{Kind: contract.OpPersonSignOutEverywhere, Workspace: fx.team, Actor: anaSub}, contracttest.ErrInvalid)
	twoSettings := dropSend(fx.team)
	twoSettings.Params = json.RawMessage(`{"before":{"can":["read","send"],"label":null},"after":{"can":["read"],"label":"x"}}`)
	refuse("two settings", twoSettings, contracttest.ErrInvalid)
	noConfirm := moveOut(fx.team, fx.personal)
	noConfirm.Confirm = nil
	refuse("no confirm", noConfirm, contracttest.ErrInvalid)
	// A closed team.
	if err := p.CloseTeam(fx.team); err != nil {
		t.Fatal(err)
	}
	refuse("a closed team", dropSend(fx.team), contracttest.ErrNotOffered)
	if f, cmds, _ := take(t, fx.c, 0); len(cmds) != 0 || f.Head != 0 {
		t.Fatalf("a command was issued: %+v", f)
	}
}

func TestACommandIsSignedWithTheSecretItsAnswerIsSignedWith(t *testing.T) {
	fx := settingsSetup(t, contracttest.Options{})
	id := issue(t, fx, dropSend(fx.team))
	// The rotation's second step: the next secret signs the answers.
	if err := fx.h.p.SetSecrets("wappie", secretB, secretA); err != nil {
		t.Fatal(err)
	}
	c := fx.h.p.Client("wappie")
	f, cmds, _ := take(t, c, 0, secretB)
	if len(cmds) != 1 || cmds[0].ID != id || cmds[0].Secret != 2 {
		t.Fatalf("served after the rotation: %+v", cmds)
	}
	if _, err := contract.VerifyCommand(f.Items[0].Command, "wappie", []string{secretA}); !errors.Is(err, contract.ErrCommandMAC) {
		t.Fatalf("under the former secret: %v", err)
	}
	if _, err := contract.VerifyCommand(f.Items[0].Command, "wappie", []string{secretA, secretB}); err != nil {
		t.Fatalf("under both secrets an app holds during a rotation: %v", err)
	}
	if kept, _ := fx.h.p.Command("wappie", id); kept.Secret != 1 {
		t.Fatalf("the command kept names the secret it was issued under: %+v", kept)
	}
	// A change of the other secret alone is no new generation.
	if err := fx.h.p.SetSecrets("wappie", secretB, secretC); err != nil {
		t.Fatal(err)
	}
	if _, cmds, _ := take(t, c, 0, secretB); cmds[0].Secret != 2 {
		t.Fatalf("after the other secret changed: %+v", cmds)
	}
}

// commandPoll sends a command feed request that waits, in the background.
func commandPoll(t *testing.T, h *harness, wait int) <-chan answer {
	t.Helper()
	out := make(chan answer, 1)
	go func() {
		out <- h.send(t, call{method: http.MethodGet, target: fmt.Sprintf("/contract/v1/commands?after=0&wait=%d", wait), app: "wappie", at: time.Now()})
	}()
	return out
}

func TestOnlyFourCommandFeedRequestsWaitAtOnceAndAnIssueWakesThem(t *testing.T) {
	fx := settingsSetup(t, contracttest.Options{Now: time.Now})
	fx.h.clock = &clock{t: time.Now()}
	var waiting []<-chan answer
	for range contracttest.DefaultLongPolls {
		waiting = append(waiting, commandPoll(t, fx.h, 25))
	}
	time.Sleep(200 * time.Millisecond) // the four take their places
	c := call{method: http.MethodGet, target: "/contract/v1/commands?after=0&wait=25", app: "wappie", at: time.Now()}
	fx.h.wantSigned(t, fx.h.send(t, c), c, http.StatusTooManyRequests, contract.CodeRateLimited)
	id := issue(t, fx, dropSend(fx.team))
	for i, w := range waiting {
		select {
		case a := <-w:
			var f contract.CommandFeed
			if err := json.Unmarshal(a.body, &f); err != nil || len(f.Items) != 1 {
				t.Fatalf("poll %d woken with %d %s", i, a.status, a.body)
			}
			if cmd, err := contract.VerifyCommand(f.Items[0].Command, "wappie", []string{secretA}); err != nil || cmd.ID != id {
				t.Fatalf("poll %d: %+v %v", i, cmd, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("poll %d was not woken", i)
		}
	}
	// Each one's place is free again.
	waiting = waiting[:0]
	for range contracttest.DefaultLongPolls {
		waiting = append(waiting, commandPoll(t, fx.h, 25))
	}
	time.Sleep(200 * time.Millisecond)
	fx.h.p.Close()
	for _, w := range waiting {
		if a := <-w; a.status != http.StatusOK {
			t.Fatalf("a poll after the first four: %d %s", a.status, a.body)
		}
	}
}

func TestARestoreDeliversTheCommandsWithoutAFinalResultFromZeroUnderItsNewGeneration(t *testing.T) {
	fx := settingsSetup(t, contracttest.Options{})
	ctx := t.Context()
	done := issue(t, fx, dropSend(fx.team))
	open := issue(t, fx, dropSend(fx.team))
	taken := issue(t, fx, rename(fx.team))
	_, before, _ := take(t, fx.c, 0)
	post(t, fx, results(ran(fx, done)), contract.OutcomeAccepted)
	gen := fx.h.p.Restore()
	_, _, err := fx.c.Commands(ctx, 3, 0)
	mustRefusal(t, err, contract.CodeGone)
	f, cmds, _ := take(t, fx.c, 0)
	if f.Generation != gen || f.Head != 2 || !slices.Equal(ids(cmds), []string{open, taken}) ||
		cmds[0].CSeq != 1 || cmds[1].CSeq != 2 || *cmds[0].WSeq != *before[1].WSeq || *cmds[1].WSeq != *before[2].WSeq {
		t.Fatalf("after the restore: %+v", f)
	}
	// The command whose result the restore lost is not_found, and the
	// documents went with it.
	post(t, fx, results(ran(fx, done)), "rejected:not_found")
	if _, ok := fx.h.p.Settings("wappie", fx.team, contract.SectionNumbers); ok {
		t.Fatal("a section outlived the restore")
	}
	mustRefusal(t, fx.c.PutSettings(ctx, numbersDoc(fx.team, fx.seq+1, kindsOf(contract.SectionNumbers))), contract.CodeNotFound)
	// Named again, the app sends its section, and the next command follows
	// the kept ones.
	for _, sub := range []string{anaSub, bobSub} {
		if _, err := fx.c.Subscribe(ctx, sub); err != nil {
			t.Fatal(err)
		}
	}
	if err := fx.c.PutSettings(ctx, numbersDoc(fx.team, fx.seq+1, kindsOf(contract.SectionNumbers))); err != nil {
		t.Fatal(err)
	}
	issue(t, fx, dropSend(fx.team))
	if _, cmds, _ := take(t, fx.c, 2); len(cmds) != 1 || cmds[0].CSeq != 3 || *cmds[0].WSeq != 4 || cmds[0].Generation != gen {
		t.Fatalf("the next command: %+v", cmds)
	}
}

func TestANewGenerationDeliversEveryCommandWithoutAFinalResultFromZero(t *testing.T) {
	fx := settingsSetup(t, contracttest.Options{})
	done := issue(t, fx, dropSend(fx.team))
	open := issue(t, fx, dropSend(fx.team))
	take(t, fx.c, 0)
	post(t, fx, results(ran(fx, done)), contract.OutcomeAccepted)
	take(t, fx.c, 2)
	gen := fx.h.p.NewGeneration()
	// From 0 in the new generation: no cursor is acknowledged in it yet, so
	// the tightening that ran is not delivered again.
	f, cmds, _ := take(t, fx.c, 0)
	if f.Generation != gen || !slices.Equal(ids(cmds), []string{open}) || f.Items[0].Again || cmds[0].CSeq != 2 {
		t.Fatalf("in the new generation: %+v", f)
	}
}

func TestTheOldGenerationsCursorAcknowledgesNothingInTheNewOne(t *testing.T) {
	fx := settingsSetup(t, contracttest.Options{})
	name := issue(t, fx, rename(fx.team))
	cut := issue(t, fx, dropSend(fx.team))
	take(t, fx.c, 0)
	post(t, fx, results(ran(fx, name), ran(fx, cut)), contract.OutcomeAccepted, contract.OutcomeAccepted)
	take(t, fx.c, 2)
	fx.h.clock.Add(60 * 24 * time.Hour)
	gen := fx.h.p.NewGeneration()
	// The app's first request after the platform's restore still carries
	// its cursor of the old generation, and learns of the new one.
	if f, cmds, _ := take(t, fx.c, 2); f.Generation != gen || len(cmds) != 0 {
		t.Fatalf("the old cursor in the new generation: %+v", f)
	}
	// Its reset to 0 is no restore of its own: nothing comes again.
	if f, cmds, _ := take(t, fx.c, 0); f.Generation != gen || len(cmds) != 0 {
		t.Fatalf("the reset after the platform's restore: %v, %+v", ids(cmds), f.Items)
	}
	// Once answered in the new generation, its own restore still is one:
	// the tightening that ran comes again, the rename does not.
	take(t, fx.c, 2)
	if f, cmds, _ := take(t, fx.c, 0); !slices.Equal(ids(cmds), []string{cut}) || !f.Items[0].Again || cmds[0].Generation != gen {
		t.Fatalf("a restore in the new generation: %v, %+v", ids(cmds), f.Items)
	}
}

func TestTheSettingsCallsReadTheirBodiesUpToTheContractsLimits(t *testing.T) {
	// The bodies below are built from the constants, so the constants
	// themselves are pinned: moving one fails here.
	for _, l := range []struct {
		name                 string
		fake, contract, want int
	}{
		{"SettingsBodyLimit", contracttest.SettingsBodyLimit, contract.SettingsBodyLimit, 1 << 20},
		{"PersonSettingsBodyLimit", contracttest.PersonSettingsBodyLimit, contract.PersonSettingsBodyLimit, 256 << 10},
		{"ResultsBodyLimit", contracttest.ResultsBodyLimit, contract.ResultsBodyLimit, 256 << 10},
	} {
		if l.fake != l.want || l.contract != l.want {
			t.Fatalf("%s is %d here and %d in the contract, not %d", l.name, l.fake, l.contract, l.want)
		}
	}
	fx := settingsSetup(t, contracttest.Options{PerSecond: 1000})
	for _, c := range []struct {
		method, target string
		limit          int
	}{
		{http.MethodPut, "/contract/v1/workspaces/" + fx.team + "/settings/numbers", contracttest.SettingsBodyLimit},
		{http.MethodPut, "/contract/v1/accounts/" + anaSub + "/settings", contracttest.PersonSettingsBodyLimit},
		{http.MethodPost, "/contract/v1/commands/results", contracttest.ResultsBodyLimit},
	} {
		at := strings.Repeat(" ", c.limit-2) + "{}"
		cl := call{method: c.method, target: c.target, app: "wappie", body: at}
		// Read whole, and refused signed as the object it is not.
		fx.h.wantSigned(t, fx.h.send(t, cl), cl, http.StatusBadRequest, contract.CodeInvalid)
		cl.body = " " + at
		fx.h.send(t, cl).wantUnsigned(t, http.StatusRequestEntityTooLarge, contract.CodeTooLarge)
	}
	// Only the command feed takes a query, read as the other feeds'.
	for _, target := range []string{
		"/contract/v1/commands?after=01", "/contract/v1/commands?wait=1", "/contract/v1/commands?after=0&wait=26",
		"/contract/v1/commands/results?x=1",
	} {
		cl := call{method: http.MethodGet, target: target, app: "wappie"}
		if strings.Contains(target, "results") {
			cl.method, cl.body = http.MethodPost, `{"results":[]}`
		}
		fx.h.wantSigned(t, fx.h.send(t, cl), cl, http.StatusBadRequest, contract.CodeInvalid)
	}
	// Other methods and shapes of the paths are no call.
	for _, cl := range []call{
		{method: http.MethodGet, target: "/contract/v1/workspaces/" + fx.team + "/settings/numbers", app: "wappie"},
		{method: http.MethodPut, target: "/contract/v1/workspaces/" + fx.team + "/settings/Numbers", app: "wappie", body: "{}"},
		{method: http.MethodPut, target: "/contract/v1/workspaces/" + fx.team + "/settings", app: "wappie", body: "{}"},
		{method: http.MethodGet, target: "/contract/v1/accounts/" + anaSub + "/settings", app: "wappie"},
		{method: http.MethodPost, target: "/contract/v1/commands", app: "wappie", body: "{}"},
		{method: http.MethodGet, target: "/contract/v1/commands/results", app: "wappie"},
	} {
		fx.h.send(t, cl).wantUnsigned(t, http.StatusNotFound, contract.CodeNotFound)
	}
}

func TestRefuseAndCorruptReachTheSettingsPartsCalls(t *testing.T) {
	fx := settingsSetup(t, contracttest.Options{})
	ctx, p := t.Context(), fx.h.p
	id := issue(t, fx, dropSend(fx.team))
	if err := p.Refuse("wappie", contracttest.CallCommands, contract.CodeGone); err != nil {
		t.Fatal(err)
	}
	_, _, err := fx.c.Commands(ctx, 0, 0)
	mustRefusal(t, err, contract.CodeGone)
	// A refused request carried nothing: the command is still the fake's to
	// expire, and the next request takes it.
	if _, cmds, _ := take(t, fx.c, 0); len(cmds) != 1 || cmds[0].ID != id {
		t.Fatalf("after the refusal: %+v", cmds)
	}
	if err := p.Refuse("wappie", contracttest.CallSettings, contract.CodeUnavailable); err != nil {
		t.Fatal(err)
	}
	mustRefusal(t, fx.c.PutSettings(ctx, numbersDoc(fx.team, fx.seq+1, []string{})), contract.CodeUnavailable)
	if err := p.Refuse("wappie", contracttest.CallPersonSettings, contract.CodeTooLarge); err != nil {
		t.Fatal(err)
	}
	if err := fx.c.PutPersonSettings(ctx, personDoc(anaSub, fx.seq+1, []string{})); !errors.Is(err, contract.ErrUnverified) {
		t.Fatalf("an unsigned refusal: %v", err)
	}
	if err := p.Corrupt("wappie", contracttest.CallResults, contracttest.AnotherBody); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.c.PostResults(ctx, results(ran(fx, id))); !errors.Is(err, contract.ErrUnverified) {
		t.Fatalf("a corrupted answer: %v", err)
	}
	// The fake kept the result all the same; the app sends it again.
	post(t, fx, results(ran(fx, id)), contract.OutcomeDuplicate)
}
