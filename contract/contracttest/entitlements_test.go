package contracttest_test

// The fake's entitlements part (SPEC section 11.20), through an app's
// contract.Client: the documents a test sets reach the app's entitlements
// feed and the GET, a trim order rides its document signed at each serve,
// and what the app sends back (acknowledgements, usage, link checks, trim
// results) is judged as the platform judges it.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"
	"github.com/thehappieco/kit/vectors"
)

const episodeID = "0199a2f0-0000-7000-8000-000000000001"

// entSetup is ana's personal workspace and her team, which wappie was told
// of through her document.
func entSetup(t *testing.T, opts contracttest.Options) (*harness, *contract.Client, string, string) {
	t.Helper()
	if opts.Apps == nil {
		opts.Apps = []contracttest.App{wappie()}
	}
	h := newHarness(t, opts)
	personal, err := h.p.AddAccount(anaSub)
	if err != nil {
		t.Fatal(err)
	}
	team, err := h.p.AddTeam("TBFG", anaSub)
	if err != nil {
		t.Fatal(err)
	}
	c := h.p.Client("wappie")
	if _, err := c.Subscribe(t.Context(), anaSub); err != nil {
		t.Fatal(err)
	}
	return h, c, personal, team
}

func tAt(now time.Time, d time.Duration) *contract.Time {
	t := contract.T(now.Add(d))
	return &t
}

// activeDoc is a workspace with a plan of two numbers, one used: what the
// test sets, the fake filling the rest.
func activeDoc(now time.Time) contract.EntitlementsDoc {
	return contract.EntitlementsDoc{
		Mode:     contract.ModeObserve,
		State:    contract.EntitlementsState{Name: contract.WorkspaceActive, Since: *tAt(now, -48*time.Hour)},
		Plan:     contract.EntitlementsPlan{Source: contract.SourcePlan, Test: true, Numbers: 2, Mailboxes: 1, PeriodEnd: tAt(now, 20*24*time.Hour)},
		Places:   contract.EntitlementsPlaces{Total: 2, Used: i64(1), UsedConnected: i64(0), Free: i64(1), CountedAt: tAt(now, -time.Minute)},
		Storage:  contract.EntitlementsStorage{QuotaBytes: 25000000000, AllowanceBytes: 25000000000, CapBytes: 26250000000},
		Switches: contract.Switches{API: contract.SwitchOn, NewLinks: contract.SwitchOn, Sync: contract.SwitchOn, Send: contract.SwitchOn},
	}
}

// trialDoc is a workspace on trial, no place counted yet.
func trialDoc(now time.Time) contract.EntitlementsDoc {
	d := activeDoc(now)
	d.State = contract.EntitlementsState{Name: contract.WorkspaceTrial, Since: *tAt(now, -time.Hour), TrialEndsAt: tAt(now, 300*time.Hour)}
	d.Plan = contract.EntitlementsPlan{Source: contract.SourceTrial, Numbers: 1, Mailboxes: 1}
	d.Places = contract.EntitlementsPlaces{Total: 1, Used: i64(1), UsedConnected: i64(0), Free: i64(0), CountedAt: tAt(now, -time.Minute)}
	d.Storage = contract.EntitlementsStorage{QuotaBytes: 15000000000, AllowanceBytes: 15000000000, CapBytes: 15750000000}
	return d
}

// expiredDoc is an expired workspace with no plan, enforced: where a trim
// order may ride.
func expiredDoc(now time.Time) contract.EntitlementsDoc {
	d := activeDoc(now)
	d.Mode = contract.ModeEnforce
	d.State = contract.EntitlementsState{Name: contract.WorkspaceExpired, Reason: ptr(contract.ReasonNoPlan),
		Since: *tAt(now, -40*24*time.Hour), ExpiredSince: tAt(now, -10*24*time.Hour)}
	d.Plan = contract.EntitlementsPlan{Source: contract.SourceNone}
	d.Places = contract.EntitlementsPlaces{Total: 0, Used: i64(1), UsedConnected: i64(0), Free: i64(0), CountedAt: tAt(now, -time.Minute)}
	d.Storage = contract.EntitlementsStorage{}
	d.Switches = contract.Switches{API: contract.SwitchOff, NewLinks: contract.SwitchOff, Sync: contract.SwitchOff, Send: contract.SwitchOff}
	return d
}

// noPlanOrder is an order without a plan: everything of dev_1 goes.
func noPlanOrder(now time.Time) contract.TrimOrder {
	return contract.TrimOrder{
		Episode: episodeID, Round: 1,
		Basis: contract.TrimBasis{UsageSeq: now.UnixMilli(), MeasuredAt: contract.T(now.Add(-5 * time.Minute))},
		Steps: []contract.TrimStep{{Item: "dev_1", Action: contract.TrimActionKeep, KeepBytes: i64(0)}},
	}
}

func entFeed(t *testing.T, c *contract.Client, after int64) contract.EntitlementsFeed {
	t.Helper()
	f, err := c.Entitlements(t.Context(), after, 0)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// document is a feed item's document, judged as an app judges it.
func document(t *testing.T, f contract.EntitlementsFeed, i int) contract.EntitlementsDoc {
	t.Helper()
	d, refused := f.Items[i].Document("wappie", f.Generation)
	if refused != nil {
		t.Fatalf("item %d refused %s", f.Items[i].Seq, refused.Code)
	}
	return d
}

func TestAnAppFollowsItsWorkspacesEntitlementsThroughTheirFeed(t *testing.T) {
	h, c, personal, team := entSetup(t, contracttest.Options{})
	ctx := t.Context()
	now := h.clock.Now()
	// Each workspace named to the app has its default document already, as
	// the platform has one for every named workspace: seq 1 and 2.
	if f := entFeed(t, c, 0); len(f.Items) != 2 || f.Head != 2 {
		t.Fatalf("the default documents: %+v", f)
	}
	if v, err := h.p.SetEntitlements("wappie", personal, trialDoc(now)); err != nil || v != 3 {
		t.Fatalf("the personal workspace's: %d %v", v, err)
	}
	if v, err := h.p.SetEntitlements("wappie", team, activeDoc(now)); err != nil || v != 4 {
		t.Fatalf("the team's: %d %v", v, err)
	}
	f := entFeed(t, c, 0)
	gen, _ := h.p.Generation()
	if len(f.Items) != 2 || f.Head != 4 || f.NextAfter != 4 || f.More || f.Generation != gen || !f.GenerationConfirmed {
		t.Fatalf("the feed: %+v", f)
	}
	d := document(t, f, 1)
	if d.WorkspaceID != team || d.Version != 4 || d.Places.Kind != contract.ItemNumber || !d.ComputedAt.Equal(now) || d.Trim != nil {
		t.Fatalf("the team's document: %+v", d)
	}
	// The GET answers the latest, as published, with the time it signed.
	got, signedAt, err := c.EntitlementsDoc(ctx, team)
	if err != nil || got.Version != 4 || !signedAt.Equal(now.Truncate(time.Second)) {
		t.Fatalf("GET: %+v %v %v", got.Version, signedAt, err)
	}
	// The same document again publishes nothing, a later computed_at or
	// count time included; another switch does.
	h.clock.Add(time.Minute)
	same := activeDoc(now)
	same.Places.CountedAt = tAt(now, time.Second)
	if v, err := h.p.SetEntitlements("wappie", team, same); err != nil || v != 4 {
		t.Fatalf("the same document: %d %v", v, err)
	}
	changed := activeDoc(now)
	changed.Switches.Send = contract.SwitchOff
	if v, err := h.p.SetEntitlements("wappie", team, changed); err != nil || v != 5 {
		t.Fatalf("a switch off: %d %v", v, err)
	}
	f = entFeed(t, c, 4)
	if len(f.Items) != 1 || document(t, f, 0).Switches.Send != contract.SwitchOff || f.NextAfter != 5 {
		t.Fatalf("the feed after 4: %+v", f)
	}
	// Each workspace's latest only.
	if f := entFeed(t, c, 0); len(f.Items) != 2 || f.Items[0].Seq != 3 || f.Items[1].Seq != 5 {
		t.Fatalf("the feed from 0: %+v", f)
	}
	if _, err := c.Entitlements(ctx, 6, 0); err == nil {
		t.Fatal("a cursor past the head is not gone")
	} else {
		mustRefusal(t, err, contract.CodeGone)
	}
	// A workspace that does not exist, another app's document and one that
	// does not validate are refused, and change nothing.
	if _, err := h.p.SetEntitlements("wappie", teamID, activeDoc(now)); !errors.Is(err, contracttest.ErrUnknown) {
		t.Errorf("a workspace that does not exist: %v", err)
	}
	other := activeDoc(now)
	other.App = "mailie"
	if _, err := h.p.SetEntitlements("wappie", team, other); !errors.Is(err, contracttest.ErrInvalid) {
		t.Errorf("another app's: %v", err)
	}
	bad := activeDoc(now)
	bad.Places.Free = i64(2)
	if _, err := h.p.SetEntitlements("wappie", team, bad); !errors.Is(err, contracttest.ErrInvalid) {
		t.Errorf("one that does not validate: %v", err)
	}
	if got, _, err := c.EntitlementsDoc(ctx, team); err != nil || got.Version != 5 {
		t.Fatalf("after the refusals: %+v %v", got.Version, err)
	}
	// A workspace not named to the app is not_found.
	if _, _, err := c.EntitlementsDoc(ctx, teamID); err == nil {
		t.Fatal("a workspace not named")
	} else {
		mustRefusal(t, err, contract.CodeNotFound)
	}
}

// A team named to the app while it follows its owner has a document at
// once: the GET right after the team is added is a valid signed document,
// the default one (observe, active, no plan, no places, no storage, every
// switch on, nothing to come), never unavailable.
func TestAWorkspaceNamedWhileTheAppFollowsHasADocumentAtOnce(t *testing.T) {
	h, c, _, _ := entSetup(t, contracttest.Options{})
	ctx := t.Context()
	vendas, err := h.p.AddTeam("Vendas", anaSub)
	if err != nil {
		t.Fatal(err)
	}
	d, _, err := c.EntitlementsDoc(ctx, vendas)
	if err != nil {
		t.Fatalf("the GET right after the team was named: %v", err)
	}
	on := contract.Switches{API: contract.SwitchOn, NewLinks: contract.SwitchOn, Sync: contract.SwitchOn, Send: contract.SwitchOn}
	if d.Version != 3 || d.Mode != contract.ModeObserve || d.State.Name != contract.WorkspaceActive || d.Plan.Source != contract.SourceNone ||
		d.Places.Total != 0 || d.Places.Used != nil || d.Places.Free != nil || d.Storage.QuotaBytes != 0 || d.Storage.UsedBytes != nil ||
		d.Switches != on || len(d.Timeline) != 0 || len(d.Items) != 0 || d.Trim != nil || d.ValidateFor("wappie", vendas) != nil {
		t.Fatalf("the default document: %+v", d)
	}
	// It came through the feed too, the same version.
	if f := entFeed(t, c, 2); len(f.Items) != 1 || document(t, f, 0).WorkspaceID != vendas || f.Items[0].Seq != 3 {
		t.Fatalf("the feed: %+v", f)
	}
	// So does the link check, from that document.
	if a, err := c.LinkCheck(ctx, vendas, contract.LinkCheck{Kind: contract.ItemNumber}); err != nil ||
		a.Trial != contract.TrialNotNeeded || a.Place != nil || a.Switches.NewLinks != contract.SwitchOn {
		t.Fatalf("the link check: %+v %v", a, err)
	}
}

// A document the test sets for a workspace that exists but is not named
// to the app yet is kept, and published the moment the workspace is named;
// before it, the GET is not_found.
func TestADocumentSetBeforeTheWorkspaceIsNamedIsPublishedAtNaming(t *testing.T) {
	h, c, _, _ := entSetup(t, contracttest.Options{})
	ctx := t.Context()
	now := h.clock.Now()
	if err := h.p.HoldPublishing("wappie"); err != nil {
		t.Fatal(err)
	}
	vendas, err := h.p.AddTeam("Vendas", anaSub)
	if err != nil {
		t.Fatal(err)
	}
	if h.p.Named("wappie", vendas) {
		t.Fatal("named while held")
	}
	if v, err := h.p.SetEntitlements("wappie", vendas, activeDoc(now)); err != nil || v != 0 {
		t.Fatalf("set before naming: %d %v", v, err)
	}
	bad := activeDoc(now)
	bad.Places.Free = i64(2)
	if _, err := h.p.SetEntitlements("wappie", vendas, bad); !errors.Is(err, contracttest.ErrInvalid) {
		t.Errorf("one that does not validate, before naming: %v", err)
	}
	if _, _, err := c.EntitlementsDoc(ctx, vendas); err == nil {
		t.Fatal("a workspace not named yet")
	} else {
		mustRefusal(t, err, contract.CodeNotFound)
	}
	if f := entFeed(t, c, 0); f.Head != 2 {
		t.Fatalf("published before naming: %+v", f)
	}
	if err := h.p.Release("wappie"); err != nil {
		t.Fatal(err)
	}
	d, _, err := c.EntitlementsDoc(ctx, vendas)
	if err != nil || d.Version != 3 || d.Plan.Source != contract.SourcePlan || d.Places.Free == nil || *d.Places.Free != 1 {
		t.Fatalf("the document set before naming: %+v %v", d, err)
	}
}

// Options.DefaultEntitlements gives the document a named workspace gets
// when the test set none; one that does not validate publishes nothing,
// the GET is then unavailable, and EntitlementsError says why.
func TestTheDefaultDocumentComesFromTheHook(t *testing.T) {
	var spoil atomic.Bool
	h, c, personal, _ := entSetup(t, contracttest.Options{DefaultEntitlements: func(app, ws string) contract.EntitlementsDoc {
		d := activeDoc(time.Date(2026, 12, 1, 12, 0, 0, 0, time.UTC))
		if spoil.Load() {
			d.Places.Free = i64(2) // does not validate
		}
		return d
	}})
	ctx := t.Context()
	if d, _, err := c.EntitlementsDoc(ctx, personal); err != nil || d.Plan.Source != contract.SourcePlan || d.Plan.Numbers != 2 {
		t.Fatalf("the hook's document: %+v %v", d, err)
	}
	spoil.Store(true)
	vendas, err := h.p.AddTeam("Vendas", anaSub)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.p.EntitlementsError("wappie", vendas); err == nil {
		t.Fatal("the naming's failed publish of the hook's document is not kept")
	}
	if _, _, err := c.EntitlementsDoc(ctx, vendas); err == nil {
		t.Fatal("the hook's document does not validate")
	} else {
		mustRefusal(t, err, contract.CodeUnavailable)
	}
	if err := h.p.EntitlementsError("wappie", vendas); err == nil {
		t.Fatal("the GET answered unavailable with no error kept")
	}
	if _, err := h.p.SetEntitlements("wappie", vendas, activeDoc(h.clock.Now())); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.EntitlementsDoc(ctx, vendas); err != nil {
		t.Fatalf("once the test set one: %v", err)
	}
	if err := h.p.EntitlementsError("wappie", vendas); err != nil {
		t.Fatalf("an error kept after the test set a document that publishes: %v", err)
	}
}

func TestAnEntitlementsLongPollAnswersWhenADocumentIsPublished(t *testing.T) {
	h, c, personal, _ := entSetup(t, contracttest.Options{LongPolls: 1})
	got := make(chan contract.EntitlementsFeed, 1)
	go func() {
		// After the two default documents of the setup's workspaces.
		f, err := c.Entitlements(t.Context(), 2, 10)
		if err != nil {
			t.Error(err)
		}
		got <- f
	}()
	time.Sleep(200 * time.Millisecond) // the first takes its place
	// Once one waits, a second is refused: one waits at a time here.
	if _, err := c.Entitlements(t.Context(), 2, 10); err == nil {
		t.Fatal("a second long-poll waits too")
	} else {
		mustRefusal(t, err, contract.CodeRateLimited)
	}
	if _, err := h.p.SetEntitlements("wappie", personal, trialDoc(h.clock.Now())); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-got:
		if len(f.Items) != 1 || f.Items[0].Seq != 3 {
			t.Fatalf("woken with %+v", f)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the long-poll still waits")
	}
}

// A bad document, which the platform never sends, comes alone in its page;
// the app lists it in its acknowledgement, and the GET publishes the
// workspace's document again.
func TestABadDocumentIsAcknowledgedAsRefusedAndTheGETPublishesAgain(t *testing.T) {
	h, c, personal, team := entSetup(t, contracttest.Options{})
	ctx := t.Context()
	now := h.clock.Now()
	if _, err := h.p.SetEntitlements("wappie", team, activeDoc(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.p.PublishRawEntitlements("wappie", personal, []byte(`{"app":"mailie","workspace_id":"`+personal+`"}`)); err != nil {
		t.Fatal(err)
	}
	f := entFeed(t, c, 0)
	if len(f.Items) != 2 {
		t.Fatalf("the feed: %+v", f)
	}
	_, refused := f.Items[1].Document("wappie", f.Generation)
	if refused == nil || refused.Code != contract.RefusedAnotherApp || *refused.WorkspaceID != personal || refused.Seq != 4 {
		t.Fatalf("the bad document: %+v", refused)
	}
	ack := contract.EntitlementsApplied{Generation: f.Generation, Through: f.NextAfter, Refused: contract.EntitlementsRefusals{*refused}}
	if err := c.EntitlementsApplied(ctx, ack); err != nil {
		t.Fatal(err)
	}
	acks := h.p.EntitlementsApplied("wappie")
	if len(acks) != 1 || acks[0].Through != 4 || len(acks[0].Refused) != 1 || acks[0].Refused[0].Code != contract.RefusedAnotherApp {
		t.Fatalf("the acknowledgements: %+v", acks)
	}
	for name, a := range map[string]contract.EntitlementsApplied{
		"past the head":      {Generation: f.Generation, Through: 5},
		"another generation": {Generation: "0199b1e0-0000-7000-8000-0000000000ff", Through: 1},
	} {
		mustRefusal(t, c.EntitlementsApplied(ctx, a), contract.CodeGone)
		_ = name
	}
	// The personal workspace has no document of the test's: the GET
	// publishes its default one again over the bad one.
	if d, _, err := c.EntitlementsDoc(ctx, personal); err != nil || d.Version != 5 || d.Plan.Source != contract.SourceNone {
		t.Fatalf("the default document again: %+v %v", d.Version, err)
	}
	if _, err := h.p.SetEntitlements("wappie", personal, trialDoc(now)); err != nil {
		t.Fatal(err)
	}
	if d, _, err := c.EntitlementsDoc(ctx, personal); err != nil || d.Version != 6 {
		t.Fatalf("the GET after the bad one: %+v %v", d.Version, err)
	}
	if _, err := h.p.PublishRawEntitlements("wappie", personal, []byte(`{`)); !errors.Is(err, contracttest.ErrInvalid) {
		t.Errorf("text that is not JSON: %v", err)
	}
	if _, err := h.p.PublishRawEntitlements("wappie", personal, []byte(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	// The latest in the feed is the bad one; the GET publishes the test's
	// document again over it.
	if d, _, err := c.EntitlementsDoc(ctx, personal); err != nil || d.Version != 8 {
		t.Fatalf("the GET after a second bad one: %+v %v", d.Version, err)
	}
}

func TestAUsageReportIsKeptByItsSeq(t *testing.T) {
	h, c, personal, team := entSetup(t, contracttest.Options{})
	ctx := t.Context()
	now := h.clock.Now()
	report := func(seq int64, bytes int64) contract.Usage {
		return contract.Usage{V: contract.UsageV, Type: contract.UsageType, App: "wappie", WorkspaceID: team, UsageSeq: seq,
			RuleVersion: "wappie-storage/1", MeasuredAt: contract.T(now), TotalBytes: bytes,
			Items: []contract.UsageItem{{ID: "dev_1", State: contract.StateActive, Bytes: bytes, RecentBytes: bytes}}}
	}
	seq := now.UnixMilli()
	for _, tc := range []struct {
		name string
		u    contract.Usage
		kept bool
	}{
		{"the first", report(seq, 100), true},
		{"a retry of the held report", report(seq, 100), true},
		{"the same seq with another body", report(seq, 200), false},
		{"a lower seq", report(seq-1, 300), false},
		{"a higher seq", report(seq+1, 400), true},
	} {
		kept, err := c.PutUsage(ctx, team, tc.u)
		if err != nil || kept != tc.kept {
			t.Errorf("%s: %t %v", tc.name, kept, err)
		}
	}
	if u, ok := h.p.Usage("wappie", team); !ok || u.UsageSeq != seq+1 || u.TotalBytes != 400 {
		t.Fatalf("kept %+v", u)
	}
	// A workspace not named to the app is not_found.
	ws := report(seq, 1)
	ws.WorkspaceID = teamID
	if _, err := c.PutUsage(ctx, teamID, ws); err == nil {
		t.Fatal("a workspace not named")
	} else {
		mustRefusal(t, err, contract.CodeNotFound)
	}
	// A report the client would refuse is invalid_request on the fake.
	body := `{"v":1,"type":"usage","app":"wappie","workspace_id":"` + personal + `","usage_seq":1,"rule_version":"wappie-storage/1",` +
		`"measured_at":"2025-10-12T20:13:20Z","total_bytes":1,"shared_bytes":0,"items":[]}`
	a := h.send(t, call{method: http.MethodPut, target: "/contract/v1/workspaces/" + personal + "/usage", body: body, app: "wappie"})
	h.wantSigned(t, a, call{method: http.MethodPut, target: "/contract/v1/workspaces/" + personal + "/usage", app: "wappie"}, http.StatusBadRequest, contract.CodeInvalid)
	// A team closed past its 30 days keeps no report, and its GET is
	// not_found.
	if err := h.p.CloseTeam(team); err != nil {
		t.Fatal(err)
	}
	if _, err := h.p.SetEntitlements("wappie", team, activeDoc(now)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.EntitlementsDoc(ctx, team); err != nil {
		t.Fatalf("a team closed a moment ago: %v", err)
	}
	h.clock.Add(contracttest.ClosedTeamRetention + time.Second)
	later := report(h.clock.Now().UnixMilli(), 500)
	later.MeasuredAt = contract.T(h.clock.Now())
	if kept, err := c.PutUsage(ctx, team, later); err != nil || kept {
		t.Fatalf("a team closed past its 30 days: %t %v", kept, err)
	}
	if _, _, err := c.EntitlementsDoc(ctx, team); err == nil {
		t.Fatal("a team closed past its 30 days")
	} else {
		mustRefusal(t, err, contract.CodeNotFound)
	}
}

func TestUsageValidateOnlyKeepsNoReport(t *testing.T) {
	h, c, personal, team := entSetup(t, contracttest.Options{UsageValidateOnly: true})
	now := h.clock.Now()
	u := contract.Usage{V: contract.UsageV, Type: contract.UsageType, App: "wappie", WorkspaceID: team, UsageSeq: now.UnixMilli(),
		RuleVersion: "wappie-storage/1", MeasuredAt: contract.T(now), Items: []contract.UsageItem{}}
	if kept, err := c.PutUsage(t.Context(), team, u); err != nil || kept {
		t.Fatalf("%t %v", kept, err)
	}
	if _, ok := h.p.Usage("wappie", team); ok {
		t.Fatal("a report kept")
	}
	// UsageSent shows what the app sent, kept or not: its usage_seq rises
	// across answers of kept false.
	if sent, ok := h.p.UsageSent("wappie", team); !ok || sent.UsageSeq != u.UsageSeq || sent.RuleVersion != "wappie-storage/1" {
		t.Fatalf("the report sent: %v %t", sent, ok)
	}
	u.UsageSeq++
	if kept, err := c.PutUsage(t.Context(), team, u); err != nil || kept {
		t.Fatalf("%t %v", kept, err)
	}
	if sent, ok := h.p.UsageSent("wappie", team); !ok || sent.UsageSeq != u.UsageSeq {
		t.Fatalf("the second report sent: %v %t", sent, ok)
	}
	// One that does not validate, refused invalid_request, is not a report
	// the fake answered.
	bad := u
	bad.UsageSeq++
	bad.TotalBytes = 1
	raw, err := json.Marshal(bad)
	if err != nil {
		t.Fatal(err)
	}
	target := "/contract/v1/workspaces/" + team + "/usage"
	h.wantSigned(t, h.send(t, call{method: http.MethodPut, target: target, body: string(raw), app: "wappie"}),
		call{method: http.MethodPut, target: target, app: "wappie"}, http.StatusBadRequest, contract.CodeInvalid)
	if sent, _ := h.p.UsageSent("wappie", team); sent.UsageSeq != u.UsageSeq {
		t.Fatalf("after a bad one: %v", sent)
	}
	if _, ok := h.p.UsageSent("wappie", personal); ok {
		t.Fatal("a workspace with no report sent")
	}
}

func TestALinkCheckAnswersFromTheDocumentAndTheTrialClocks(t *testing.T) {
	h, c, personal, team := entSetup(t, contracttest.Options{})
	ctx := t.Context()
	now := h.clock.Now()
	key, _ := contract.NewTrialKey([]byte("0123456789abcdef0123456789abcdef"))
	code := func(n string) string {
		s, err := contract.TrialCode(key, "wappie", contract.TrialKindE164, n)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	used, running, fresh := code("+5511988887777"), code("+5511977776666"), code("+5511966665555")
	if err := h.p.SetTrialClock(used, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	ends := now.Add(48 * time.Hour)
	if err := h.p.SetTrialClock(running, ends); err != nil {
		t.Fatal(err)
	}
	if err := h.p.SetTrialClock("not-a-code", ends); !errors.Is(err, contracttest.ErrInvalid) {
		t.Errorf("a code that is not one: %v", err)
	}
	if _, err := h.p.SetEntitlements("wappie", personal, trialDoc(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.p.SetEntitlements("wappie", team, activeDoc(now)); err != nil {
		t.Fatal(err)
	}
	check := func(ws string, codes ...string) contract.LinkCheckAnswer {
		t.Helper()
		a, err := c.LinkCheck(ctx, ws, contract.LinkCheck{Kind: contract.ItemNumber, Codes: codes})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	// On trial: a code that matches no clock starts one; the oldest clock
	// a code matches wins.
	if a := check(personal); a.Trial != contract.TrialNotNeeded || *a.Place != contract.PlaceNone || a.Switches.NewLinks != contract.SwitchOn {
		t.Errorf("no codes: %+v", a)
	}
	if a := check(personal, fresh); a.Trial != contract.TrialRunning || !a.TrialEndsAt.Equal(now.Add(360*time.Hour)) {
		t.Errorf("a new identity: %+v", a)
	}
	if a := check(personal, fresh, running); a.Trial != contract.TrialRunning || !a.TrialEndsAt.Equal(ends) {
		t.Errorf("a running clock: %+v", a)
	}
	if a := check(personal, running, used); a.Trial != contract.TrialUsedUp || a.TrialEndsAt != nil {
		t.Errorf("a clock that ended: %+v", a)
	}
	// Not on trial: not_needed whatever the codes match.
	if a := check(team, used); a.Trial != contract.TrialNotNeeded || *a.Place != contract.PlaceFree {
		t.Errorf("a workspace with a plan: %+v", a)
	}
	// A connected item carries no codes and needs no trial.
	if a, err := c.LinkCheck(ctx, personal, contract.LinkCheck{Kind: contract.ItemNumber, Connected: true}); err != nil || a.Trial != contract.TrialNotNeeded {
		t.Errorf("a connected item: %+v %v", a, err)
	}
	// 30 checks with codes a minute per workspace, the three above among
	// them in the personal workspace; without codes, no such limit.
	for range contract.LinkChecksPerMinute - 3 {
		check(personal, fresh)
	}
	if _, err := c.LinkCheck(ctx, personal, contract.LinkCheck{Kind: contract.ItemNumber, Codes: []string{fresh}}); err == nil {
		t.Fatal("a 31st check with codes")
	} else {
		mustRefusal(t, err, contract.CodeRateLimited)
	}
	check(personal)
	check(team, fresh)
	h.clock.Add(time.Minute)
	check(personal, fresh)
	// The kind is the app's; a workspace not named is not_found.
	body := `{"kind":"mailbox","codes":[],"connected":false}`
	target := "/contract/v1/workspaces/" + team + "/link-check"
	h.wantSigned(t, h.send(t, call{method: http.MethodPost, target: target, body: body, app: "wappie"}),
		call{method: http.MethodPost, target: target, app: "wappie"}, http.StatusBadRequest, contract.CodeInvalid)
	if _, err := c.LinkCheck(ctx, teamID, contract.LinkCheck{Kind: contract.ItemNumber}); err == nil {
		t.Fatal("a workspace not named")
	} else {
		mustRefusal(t, err, contract.CodeNotFound)
	}
}

// An order rides its document, signed each time the fake serves it with
// the secret that signs that answer; its result is judged against it, and
// a kept result ends it.
func TestATrimOrderRidesItsDocumentAndItsResultEndsIt(t *testing.T) {
	h, c, _, team := entSetup(t, contracttest.Options{})
	ctx := t.Context()
	now := h.clock.Now()
	if _, err := h.p.IssueTrimOrder("wappie", teamID, noPlanOrder(now)); !errors.Is(err, contracttest.ErrUnknown) {
		t.Errorf("an order in a workspace not named: %v", err)
	}
	if _, err := h.p.IssueTrimOrder("wappie", team, noPlanOrder(now)); !errors.Is(err, contracttest.ErrInvalid) {
		t.Errorf("an order in the default document: %v", err)
	}
	if _, err := h.p.SetEntitlements("wappie", team, activeDoc(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.p.IssueTrimOrder("wappie", team, noPlanOrder(now)); !errors.Is(err, contracttest.ErrInvalid) {
		t.Errorf("an order in an active document: %v", err)
	}
	if _, err := h.p.SetEntitlements("wappie", team, expiredDoc(now)); err != nil {
		t.Fatal(err)
	}
	id, err := h.p.IssueTrimOrder("wappie", team, noPlanOrder(now))
	if err != nil {
		t.Fatal(err)
	}
	d, _, err := c.EntitlementsDoc(ctx, team)
	if err != nil {
		t.Fatal(err)
	}
	o, err := contract.VerifyTrimOrder(d, "wappie", []string{secretA})
	if err != nil || o.OrderID != id || o.Secret != 1 || !o.ValidUntil.Equal(now.Add(contract.MaxTrimValidity)) {
		t.Fatalf("the GET's order: %+v %v", o, err)
	}
	f := entFeed(t, c, 0)
	if fo, err := contract.VerifyTrimOrder(document(t, f, len(f.Items)-1), "wappie", []string{secretA}); err != nil || fo.OrderID != id {
		t.Fatalf("the feed's order: %v", err)
	}
	if _, err := h.p.IssueTrimOrder("wappie", team, func() contract.TrimOrder { o := noPlanOrder(now); o.OrderID = id; return o }()); !errors.Is(err, contracttest.ErrInvalid) {
		t.Errorf("an order_id issued before: %v", err)
	}
	// A rotation: the answer's secret signs the order, under its number.
	if err := h.p.SetSecrets("wappie", secretB, secretA); err != nil {
		t.Fatal(err)
	}
	c.Accept = []string{secretB, secretA}
	d, _, err = c.EntitlementsDoc(ctx, team)
	if err != nil {
		t.Fatal(err)
	}
	if o, err := contract.VerifyTrimOrder(d, "wappie", []string{secretB}); err != nil || o.Secret != 2 {
		t.Fatalf("after a rotation: %+v %v", o.Secret, err)
	}
	if _, err := contract.VerifyTrimOrder(d, "wappie", []string{secretA}); !errors.Is(err, contract.ErrTrimMAC) {
		t.Fatalf("the old secret: %v", err)
	}
	if err := h.p.SetSecrets("wappie", secretA, ""); err != nil {
		t.Fatal(err)
	}
	c.Accept = nil
	// Results.
	other := "0199c3a0-0000-7000-8000-0000000000ff"
	refused := func(orderID, code string) contract.TrimResult {
		return contract.TrimResult{OrderID: orderID, Outcome: contract.TrimOutcomeRefused, Code: &code, Steps: []contract.TrimStepResult{}}
	}
	notItsSteps := contract.TrimResult{OrderID: id, Outcome: contract.TrimOutcomeDone, UsageSeq: i64(now.UnixMilli()),
		Steps: []contract.TrimStepResult{{Item: "dev_2", Outcome: contract.TrimOutcomeDone, BytesAfter: i64(0)}}}
	for _, tc := range []struct {
		name    string
		r       contract.TrimResult
		outcome string
		code    string
	}{
		{"an order the fake never issued", refused(other, contract.TrimCodeHeld), contract.OutcomeRejected, contract.CodeNotFound},
		{"a result that is not its order's", notItsSteps, contract.OutcomeRejected, contract.CodeInvalid},
		{"the result", refused(id, contract.TrimCodeHeld), contract.OutcomeAccepted, ""},
		{"the same again", refused(id, contract.TrimCodeHeld), contract.OutcomeDuplicate, ""},
		{"another", refused(id, contract.TrimCodeExpired), contract.OutcomeRejected, contract.CodeConflict},
	} {
		a, err := c.PostTrimResult(ctx, tc.r)
		if err != nil || a.Outcome != tc.outcome || (a.Code == nil) != (tc.code == "") || (a.Code != nil && *a.Code != tc.code) {
			t.Errorf("%s: %+v %v", tc.name, a, err)
		}
	}
	if r, ok := h.p.TrimResult("wappie", id); !ok || *r.Code != contract.TrimCodeHeld {
		t.Fatalf("kept %+v", r)
	}
	// The kept result ended the order: the next document carries none.
	if d, _, err := c.EntitlementsDoc(ctx, team); err != nil || d.Trim != nil {
		t.Fatalf("after its result: %s %v", d.Trim, err)
	}
	// A body that is not one JSON object is refused whole; one that does
	// not decode is rejected with its order_id when it reads.
	target := "/contract/v1/trim/results"
	h.wantSigned(t, h.send(t, call{method: http.MethodPost, target: target, body: `[]`, app: "wappie"}),
		call{method: http.MethodPost, target: target, app: "wappie"}, http.StatusBadRequest, contract.CodeInvalid)
	a := h.send(t, call{method: http.MethodPost, target: target, body: `{"order_id":"` + id + `","outcome":"done"}`, app: "wappie"})
	if a.status != http.StatusOK || !strings.Contains(string(a.body), `"order_id":"`+id+`","outcome":"rejected","code":"invalid_request"`) {
		t.Fatalf("a result that does not decode: %d %s", a.status, a.body)
	}
	a = h.send(t, call{method: http.MethodPost, target: target, body: `{"order_id":"x"}`, app: "wappie"})
	if a.status != http.StatusOK || string(a.body) != `{"order_id":"","outcome":"rejected","code":"invalid_request"}` {
		t.Fatalf("a result with no order_id: %d %s", a.status, a.body)
	}
}

// A new generation publishes every document again, not confirmed, and
// drops the orders they carried; their results are still judged. A
// restore forgets the feed, the reports and the orders.
func TestANewGenerationAndARestoreReachTheEntitlementsPart(t *testing.T) {
	h, c, personal, team := entSetup(t, contracttest.Options{})
	ctx := t.Context()
	now := h.clock.Now()
	if _, err := h.p.SetEntitlements("wappie", personal, trialDoc(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.p.SetEntitlements("wappie", team, expiredDoc(now)); err != nil {
		t.Fatal(err)
	}
	id, err := h.p.IssueTrimOrder("wappie", team, noPlanOrder(now))
	if err != nil {
		t.Fatal(err)
	}
	f := entFeed(t, c, 0)
	if err := c.EntitlementsApplied(ctx, contract.EntitlementsApplied{Generation: f.Generation, Through: f.NextAfter}); err != nil {
		t.Fatal(err)
	}
	u := contract.Usage{V: contract.UsageV, Type: contract.UsageType, App: "wappie", WorkspaceID: team, UsageSeq: now.UnixMilli(),
		RuleVersion: "wappie-storage/1", MeasuredAt: contract.T(now), Items: []contract.UsageItem{}}
	if kept, err := c.PutUsage(ctx, team, u); err != nil || !kept {
		t.Fatal(kept, err)
	}
	gen := h.p.NewGeneration()
	g := entFeed(t, c, f.NextAfter)
	if g.Generation != gen || g.GenerationConfirmed || len(g.Items) != 2 || g.Head != f.Head+2 {
		t.Fatalf("after a new generation: %+v", g)
	}
	for i := range g.Items {
		if d := document(t, g, i); d.Generation != gen || d.Trim != nil {
			t.Fatalf("a document after a new generation: %+v", d)
		}
	}
	if len(h.p.EntitlementsApplied("wappie")) != 0 {
		t.Fatal("an acknowledgement kept across the generation")
	}
	mustRefusal(t, c.EntitlementsApplied(ctx, contract.EntitlementsApplied{Generation: f.Generation, Through: 1}), contract.CodeGone)
	if _, ok := h.p.Usage("wappie", team); !ok {
		t.Fatal("a new generation forgot a report")
	}
	done := contract.TrimResult{OrderID: id, Outcome: contract.TrimOutcomePartial, Code: ptr(contract.TrimCodeNotCurrent), UsageSeq: i64(now.UnixMilli()),
		Steps: []contract.TrimStepResult{{Item: "dev_1", Outcome: contract.TrimOutcomeNotRun}}}
	if a, err := c.PostTrimResult(ctx, done); err != nil || a.Outcome != contract.OutcomeAccepted {
		t.Fatalf("a dropped order's result: %+v %v", a, err)
	}
	// A restore.
	h.p.Restore()
	if _, err := c.Entitlements(ctx, 1, 0); err == nil {
		t.Fatal("a cursor above 0 after a restore")
	} else {
		mustRefusal(t, err, contract.CodeGone)
	}
	if f := entFeed(t, c, 0); len(f.Items) != 0 || f.Head != 0 {
		t.Fatalf("the feed after a restore: %+v", f)
	}
	if _, ok := h.p.Usage("wappie", team); ok {
		t.Fatal("a restore kept a report")
	}
	if a, err := c.PostTrimResult(ctx, done); err != nil || a.Outcome != contract.OutcomeRejected || *a.Code != contract.CodeNotFound {
		t.Fatalf("an order the restore lost: %+v %v", a, err)
	}
	// Named again, the workspaces' documents come again.
	if _, err := c.Subscribe(ctx, anaSub); err != nil {
		t.Fatal(err)
	}
	if f := entFeed(t, c, 0); len(f.Items) != 2 || f.Head != 2 {
		t.Fatalf("the feed once named again: %+v", f)
	}
}

// Refuse and Corrupt take the entitlements part's calls, and only the feed
// takes a query.
func TestTheEntitlementsCallsCanBeRefusedAndCorrupted(t *testing.T) {
	h, c, personal, _ := entSetup(t, contracttest.Options{})
	ctx := t.Context()
	if _, err := h.p.SetEntitlements("wappie", personal, trialDoc(h.clock.Now())); err != nil {
		t.Fatal(err)
	}
	for _, call := range []string{contracttest.CallEntitlements, contracttest.CallEntitlementsDoc, contracttest.CallEntitlementsApplied,
		contracttest.CallUsage, contracttest.CallLinkCheck, contracttest.CallTrimResults} {
		if err := h.p.Refuse("wappie", call, contract.CodeUnavailable); err != nil {
			t.Errorf("%s: %v", call, err)
		}
		if err := h.p.Corrupt("wappie", call, contracttest.AnotherNonce); err != nil {
			t.Errorf("%s: %v", call, err)
		}
	}
	// The refusal comes first, its answer corrupted.
	if _, _, err := c.EntitlementsDoc(ctx, personal); !errors.Is(err, contract.ErrUnverified) {
		t.Fatalf("a corrupted refusal: %v", err)
	}
	if d, _, err := c.EntitlementsDoc(ctx, personal); err != nil || d.Version != 3 {
		t.Fatalf("the next GET: %v %v", d.Version, err)
	}
	target := "/contract/v1/workspaces/" + personal + "/entitlements?after=0"
	h.wantSigned(t, h.send(t, call{method: http.MethodGet, target: target, app: "wappie"}),
		call{method: http.MethodGet, target: target, app: "wappie"}, http.StatusBadRequest, contract.CodeInvalid)
}

func i64(n int64) *int64 { return &n }

// Each body limit of the entitlements part has the value of the contract's
// constant of the same name; the usage report's is UsageReportBodyLimit,
// 1 MiB, never the token part's usage call's 256 KiB (UsageBodyLimit).
func TestTheEntitlementsLimitsAreTheContractsOfTheSameName(t *testing.T) {
	for _, l := range []struct {
		name                 string
		fake, contract, want int
	}{
		{"EntitlementsAppliedLimit", contracttest.EntitlementsAppliedLimit, contract.EntitlementsAppliedLimit, 4 << 10},
		{"UsageReportBodyLimit", contracttest.UsageReportBodyLimit, contract.UsageReportBodyLimit, 1 << 20},
		{"LinkCheckBodyLimit", contracttest.LinkCheckBodyLimit, contract.LinkCheckBodyLimit, 4 << 10},
		{"TrimResultBodyLimit", contracttest.TrimResultBodyLimit, contract.TrimResultBodyLimit, 512 << 10},
	} {
		if l.fake != l.want || l.contract != l.want {
			t.Errorf("%s is %d here and %d in the contract, not %d", l.name, l.fake, l.contract, l.want)
		}
	}
	if contracttest.UsageReportBodyLimit == contract.UsageBodyLimit {
		t.Error("the usage report's limit is the token part's")
	}
}

// The feed's document and the GET's are the same bytes, a console link
// with an & included: neither is HTML-escaped (SPEC section 11.20).
func TestTheFeedsDocumentIsTheGETsByteForByte(t *testing.T) {
	h, c, _, team := entSetup(t, contracttest.Options{})
	d := activeDoc(h.clock.Now())
	d.Links.Plan = "https://console.thehappie.co/workspaces/" + team + "/plan?from=wappie&tab=places"
	v, err := h.p.SetEntitlements("wappie", team, d)
	if err != nil {
		t.Fatal(err)
	}
	f := entFeed(t, c, v-1)
	if len(f.Items) != 1 || f.Items[0].Seq != v {
		t.Fatalf("the feed: %+v", f)
	}
	status, body, err := c.Do(t.Context(), http.MethodGet, "/contract/v1/workspaces/"+team+"/entitlements", nil)
	if err != nil || status != http.StatusOK {
		t.Fatalf("GET: %d %v", status, err)
	}
	if !bytes.Equal(f.Items[0].Doc, body) {
		t.Fatalf("the feed's document\n%s\nis not the GET's\n%s", f.Items[0].Doc, body)
	}
	if !bytes.Contains(body, []byte("from=wappie&tab=places")) {
		t.Fatalf("the link is escaped: %s", body)
	}
}

// HoldPublishing holds the entitlements publisher as it holds the others:
// a document set while held is not in the feed, whose published_through
// stays at the first change held; the GET publishes it and clears its
// mark; Release publishes the others; a new generation forgets the marks,
// and its documents, held again, leave no document of the old generation
// in the feed.
func TestHoldPublishingHoldsTheEntitlementsFeed(t *testing.T) {
	h, c, personal, team := entSetup(t, contracttest.Options{})
	ctx := t.Context()
	start := h.clock.Now()
	head := entFeed(t, c, 0).Head
	if err := h.p.HoldPublishing("wappie"); err != nil {
		t.Fatal(err)
	}
	h.clock.Add(time.Minute)
	held := h.clock.Now()
	if v, err := h.p.SetEntitlements("wappie", team, activeDoc(start)); err != nil || v != 0 {
		t.Fatalf("set while held: %d %v", v, err)
	}
	if v, err := h.p.SetEntitlements("wappie", personal, trialDoc(start)); err != nil || v != 0 {
		t.Fatalf("set while held: %d %v", v, err)
	}
	// One that does not validate is still refused while held.
	bad := activeDoc(start)
	bad.Places.Free = i64(2)
	if _, err := h.p.SetEntitlements("wappie", team, bad); !errors.Is(err, contracttest.ErrInvalid) {
		t.Fatalf("a bad document while held: %v", err)
	}
	h.clock.Add(time.Minute)
	f := entFeed(t, c, head)
	if len(f.Items) != 0 || f.Head != head || !f.PublishedThrough.Equal(held) {
		t.Fatalf("the feed while held: %+v", f)
	}
	// The GET publishes the team's at once, and its mark goes; the personal
	// workspace's still holds published_through.
	got, _, err := c.EntitlementsDoc(ctx, team)
	if err != nil || got.Plan.Source != contract.SourcePlan || got.Version != head+1 {
		t.Fatalf("GET while held: %+v %v", got.Version, err)
	}
	if f := entFeed(t, c, head); len(f.Items) != 1 || f.Items[0].Seq != head+1 || !f.PublishedThrough.Equal(held) {
		t.Fatalf("the feed after the GET: %+v", f)
	}
	// Release publishes the personal workspace's, and published_through is
	// now again.
	if err := h.p.Release("wappie"); err != nil {
		t.Fatal(err)
	}
	f = entFeed(t, c, head+1)
	if len(f.Items) != 1 || document(t, f, 0).WorkspaceID != personal || !f.PublishedThrough.Equal(h.clock.Now()) {
		t.Fatalf("the feed after Release: %+v", f)
	}
	// Held again, a new generation: its documents are held from its own
	// time, and the old generation's leave the feed.
	if err := h.p.HoldPublishing("wappie"); err != nil {
		t.Fatal(err)
	}
	h.clock.Add(time.Minute)
	if _, err := h.p.SetEntitlements("wappie", team, expiredDoc(start)); err != nil {
		t.Fatal(err)
	}
	h.clock.Add(time.Minute)
	gen := h.p.NewGeneration()
	f = entFeed(t, c, 0)
	if f.Generation != gen || len(f.Items) != 0 || !f.PublishedThrough.Equal(h.clock.Now()) {
		t.Fatalf("a new generation while held: %+v", f)
	}
	if err := h.p.Release("wappie"); err != nil {
		t.Fatal(err)
	}
	f = entFeed(t, c, 0)
	if len(f.Items) != 2 {
		t.Fatalf("after Release: %+v", f)
	}
	for i := range f.Items {
		if d := document(t, f, i); d.Generation != gen {
			t.Fatalf("a document of another generation: %+v", d)
		}
	}
	// Restore forgets the marks too.
	if err := h.p.HoldPublishing("wappie"); err != nil {
		t.Fatal(err)
	}
	h.clock.Add(time.Minute)
	if _, err := h.p.SetEntitlements("wappie", team, activeDoc(start)); err != nil {
		t.Fatal(err)
	}
	h.p.Restore()
	h.clock.Add(time.Minute)
	if f := entFeed(t, c, 0); len(f.Items) != 0 || !f.PublishedThrough.Equal(h.clock.Now()) {
		t.Fatalf("after a restore: %+v", f)
	}
}

// A document keeps the computed_at it was set with: published again by a
// new generation, or at a naming after a restore, once the clock passed a
// step of its timeline, it is still valid, and no publish failed.
func TestADocumentPublishedAgainKeepsItsComputedAt(t *testing.T) {
	h, c, personal, team := entSetup(t, contracttest.Options{})
	ctx := t.Context()
	set := h.clock.Now()
	d := activeDoc(set)
	d.Timeline = []contract.TimelineStep{{At: *tAt(set, time.Hour), Off: []string{contract.SwitchSend}}}
	if _, err := h.p.SetEntitlements("wappie", team, d); err != nil {
		t.Fatal(err)
	}
	check := func(when string, f contract.EntitlementsFeed) {
		t.Helper()
		var found bool
		for i := range f.Items {
			doc := document(t, f, i)
			if doc.WorkspaceID != team {
				continue
			}
			found = true
			if !doc.ComputedAt.Equal(set) || len(doc.Timeline) != 1 {
				t.Fatalf("%s: %+v", when, doc)
			}
		}
		if !found {
			t.Fatalf("%s: no document of the team: %+v", when, f)
		}
		for _, ws := range []string{personal, team} {
			if err := h.p.EntitlementsError("wappie", ws); err != nil {
				t.Fatalf("%s: a publish failed: %v", when, err)
			}
		}
		if got, _, err := c.EntitlementsDoc(ctx, team); err != nil || !got.ComputedAt.Equal(set) {
			t.Fatalf("%s: GET %+v %v", when, got, err)
		}
	}
	h.clock.Add(2 * time.Hour)
	gen := h.p.NewGeneration()
	f := entFeed(t, c, 0)
	if f.Generation != gen {
		t.Fatalf("the generation: %+v", f)
	}
	check("after a new generation", f)
	h.clock.Add(2 * time.Hour)
	h.p.Restore()
	if _, err := c.Subscribe(ctx, anaSub); err != nil {
		t.Fatal(err)
	}
	check("named again after a restore", entFeed(t, c, 0))
}

// wireUsage is the intake of wire-usage.json (SPEC section 11.20).
type wireUsage struct {
	Reports []struct {
		Now int64 `json:"now"`
	} `json:"reports"`
	Intake []struct {
		Name string `json:"name"`
		Held *struct {
			Body json.RawMessage `json:"body"`
		} `json:"held"`
		Mode      string          `json:"mode"`
		Workspace string          `json:"workspace"`
		Value     json.RawMessage `json:"value"`
		Kept      bool            `json:"kept"`
	} `json:"intake"`
}

// The fake keeps a usage report as wire-usage.json's intake says, a retry
// judged by the JCS text of the body sent: each case replayed through it,
// its workspace the fake's, at the vectors' clock.
func TestTheFakeKeepsUsageAsTheIntakeVectorsSay(t *testing.T) {
	raw, err := vectors.FS.ReadFile("platform/contract-v1/wire-usage.json")
	if err != nil {
		t.Fatal(err)
	}
	var w wireUsage
	if err := json.Unmarshal(raw, &w); err != nil || len(w.Intake) == 0 || len(w.Reports) == 0 {
		t.Fatalf("wire-usage.json: %v", err)
	}
	now := time.Unix(w.Reports[0].Now, 0).UTC()
	for _, c := range w.Intake {
		t.Run(c.Name, func(t *testing.T) {
			h, client, personal, team := entSetup(t, contracttest.Options{UsageValidateOnly: c.Mode == "validate"})
			ctx := t.Context()
			ws := team
			switch c.Workspace {
			case "open":
				h.clock.Add(now.Sub(h.clock.Now()))
			case "closed_personal":
				h.clock.Add(now.Sub(h.clock.Now()))
				if _, err := h.p.AddAccount(bobSub); err != nil {
					t.Fatal(err)
				}
				var err error
				if ws, err = bobPersonal(t, h); err != nil {
					t.Fatal(err)
				}
				if err := h.p.CloseAccount(bobSub); err != nil {
					t.Fatal(err)
				}
			case "closed_team_past":
				h.clock.Add(now.Add(-contracttest.ClosedTeamRetention - time.Hour).Sub(h.clock.Now()))
				if err := h.p.CloseTeam(team); err != nil {
					t.Fatal(err)
				}
				h.clock.Add(now.Sub(h.clock.Now()))
			default:
				t.Fatalf("workspace %q", c.Workspace)
			}
			_ = personal
			put := func(body json.RawMessage) bool {
				t.Helper()
				if !bytes.Contains(body, []byte(teamID)) {
					t.Fatalf("a body without the vectors' workspace written plainly: %s", body)
				}
				status, answer, err := client.Do(ctx, http.MethodPut, "/contract/v1/workspaces/"+ws+"/usage",
					bytes.ReplaceAll(body, []byte(teamID), []byte(ws)))
				if err != nil || status != http.StatusOK {
					t.Fatalf("PUT: %d %s %v", status, answer, err)
				}
				var a contract.UsageAnswer
				if err := json.Unmarshal(answer, &a); err != nil || a.Validate() != nil {
					t.Fatalf("the answer %s: %v", answer, err)
				}
				return a.Kept
			}
			if c.Held != nil {
				if kept := put(c.Held.Body); kept != (c.Mode == "keep") {
					t.Fatalf("the held report kept %t", kept)
				}
			}
			if kept := put(c.Value); kept != c.Kept {
				t.Fatalf("kept %t, want %t", kept, c.Kept)
			}
		})
	}
}

// bobPersonal names bob's personal workspace to wappie, by his sign-in,
// and returns its id.
func bobPersonal(t *testing.T, h *harness) (string, error) {
	t.Helper()
	doc, err := h.p.Client("wappie").Subscribe(t.Context(), bobSub)
	if err != nil {
		return "", err
	}
	for _, w := range doc.Workspaces {
		if w.Kind == contract.KindPersonal {
			return w.ID, nil
		}
	}
	return "", errors.New("bob has no personal workspace")
}
