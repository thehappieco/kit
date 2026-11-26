package contracttest_test

// The fake's entitlements part (SPEC section 11.20), through an app's
// contract.Client: the documents a test sets reach the app's entitlements
// feed and the GET, a trim order rides its document signed at each serve,
// and what the app sends back (acknowledgements, usage, link checks, trim
// results) is judged as the platform judges it.

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"
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
	if v, err := h.p.SetEntitlements("wappie", personal, trialDoc(now)); err != nil || v != 1 {
		t.Fatalf("the personal workspace's: %d %v", v, err)
	}
	if v, err := h.p.SetEntitlements("wappie", team, activeDoc(now)); err != nil || v != 2 {
		t.Fatalf("the team's: %d %v", v, err)
	}
	f := entFeed(t, c, 0)
	gen, _ := h.p.Generation()
	if len(f.Items) != 2 || f.Head != 2 || f.NextAfter != 2 || f.More || f.Generation != gen || !f.GenerationConfirmed {
		t.Fatalf("the feed: %+v", f)
	}
	d := document(t, f, 1)
	if d.WorkspaceID != team || d.Version != 2 || d.Places.Kind != contract.ItemNumber || !d.ComputedAt.Equal(now) || d.Trim != nil {
		t.Fatalf("the team's document: %+v", d)
	}
	// The GET answers the latest, as published, with the time it signed.
	got, signedAt, err := c.EntitlementsDoc(ctx, team)
	if err != nil || got.Version != 2 || !signedAt.Equal(now.Truncate(time.Second)) {
		t.Fatalf("GET: %+v %v %v", got.Version, signedAt, err)
	}
	// The same document again publishes nothing, a later computed_at or
	// count time included; another switch does.
	h.clock.Add(time.Minute)
	same := activeDoc(now)
	same.Places.CountedAt = tAt(now, time.Second)
	if v, err := h.p.SetEntitlements("wappie", team, same); err != nil || v != 2 {
		t.Fatalf("the same document: %d %v", v, err)
	}
	changed := activeDoc(now)
	changed.Switches.Send = contract.SwitchOff
	if v, err := h.p.SetEntitlements("wappie", team, changed); err != nil || v != 3 {
		t.Fatalf("a switch off: %d %v", v, err)
	}
	f = entFeed(t, c, 2)
	if len(f.Items) != 1 || document(t, f, 0).Switches.Send != contract.SwitchOff || f.NextAfter != 3 {
		t.Fatalf("the feed after 2: %+v", f)
	}
	// Each workspace's latest only.
	if f := entFeed(t, c, 0); len(f.Items) != 2 || f.Items[0].Seq != 1 || f.Items[1].Seq != 3 {
		t.Fatalf("the feed from 0: %+v", f)
	}
	if _, err := c.Entitlements(ctx, 4, 0); err == nil {
		t.Fatal("a cursor past the head is not gone")
	} else {
		mustRefusal(t, err, contract.CodeGone)
	}
	// A workspace not named to the app, another app's document and one that
	// does not validate are refused, and change nothing.
	if _, err := h.p.SetEntitlements("wappie", teamID, activeDoc(now)); !errors.Is(err, contracttest.ErrUnknown) {
		t.Errorf("a workspace not named: %v", err)
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
	if got, _, err := c.EntitlementsDoc(ctx, team); err != nil || got.Version != 3 {
		t.Fatalf("after the refusals: %+v %v", got.Version, err)
	}
	// A workspace not named to the app is not_found; one named whose
	// document the test never set, unavailable.
	if _, _, err := c.EntitlementsDoc(ctx, teamID); err == nil {
		t.Fatal("a workspace not named")
	} else {
		mustRefusal(t, err, contract.CodeNotFound)
	}
	other2, err := h.p.AddTeam("Vendas", anaSub)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.EntitlementsDoc(ctx, other2); err == nil {
		t.Fatal("no document set")
	} else {
		mustRefusal(t, err, contract.CodeUnavailable)
	}
}

func TestAnEntitlementsLongPollAnswersWhenADocumentIsPublished(t *testing.T) {
	h, c, personal, _ := entSetup(t, contracttest.Options{LongPolls: 1})
	got := make(chan contract.EntitlementsFeed, 1)
	go func() {
		f, err := c.Entitlements(t.Context(), 0, 10)
		if err != nil {
			t.Error(err)
		}
		got <- f
	}()
	time.Sleep(200 * time.Millisecond) // the first takes its place
	// Once one waits, a second is refused: one waits at a time here.
	if _, err := c.Entitlements(t.Context(), 0, 10); err == nil {
		t.Fatal("a second long-poll waits too")
	} else {
		mustRefusal(t, err, contract.CodeRateLimited)
	}
	if _, err := h.p.SetEntitlements("wappie", personal, trialDoc(h.clock.Now())); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-got:
		if len(f.Items) != 1 || f.Items[0].Seq != 1 {
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
	if refused == nil || refused.Code != contract.RefusedAnotherApp || *refused.WorkspaceID != personal || refused.Seq != 2 {
		t.Fatalf("the bad document: %+v", refused)
	}
	ack := contract.EntitlementsApplied{Generation: f.Generation, Through: f.NextAfter, Refused: contract.EntitlementsRefusals{*refused}}
	if err := c.EntitlementsApplied(ctx, ack); err != nil {
		t.Fatal(err)
	}
	acks := h.p.EntitlementsApplied("wappie")
	if len(acks) != 1 || acks[0].Through != 2 || len(acks[0].Refused) != 1 || acks[0].Refused[0].Code != contract.RefusedAnotherApp {
		t.Fatalf("the acknowledgements: %+v", acks)
	}
	for name, a := range map[string]contract.EntitlementsApplied{
		"past the head":      {Generation: f.Generation, Through: 3},
		"another generation": {Generation: "0199b1e0-0000-7000-8000-0000000000ff", Through: 1},
	} {
		mustRefusal(t, c.EntitlementsApplied(ctx, a), contract.CodeGone)
		_ = name
	}
	// The personal workspace has no document of the test's: unavailable.
	if _, _, err := c.EntitlementsDoc(ctx, personal); err == nil {
		t.Fatal("no document set")
	} else {
		mustRefusal(t, err, contract.CodeUnavailable)
	}
	if _, err := h.p.SetEntitlements("wappie", personal, trialDoc(now)); err != nil {
		t.Fatal(err)
	}
	if d, _, err := c.EntitlementsDoc(ctx, personal); err != nil || d.Version != 3 {
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
	if d, _, err := c.EntitlementsDoc(ctx, personal); err != nil || d.Version != 5 {
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
	h, c, _, team := entSetup(t, contracttest.Options{UsageValidateOnly: true})
	now := h.clock.Now()
	u := contract.Usage{V: contract.UsageV, Type: contract.UsageType, App: "wappie", WorkspaceID: team, UsageSeq: now.UnixMilli(),
		RuleVersion: "wappie-storage/1", MeasuredAt: contract.T(now), Items: []contract.UsageItem{}}
	if kept, err := c.PutUsage(t.Context(), team, u); err != nil || kept {
		t.Fatalf("%t %v", kept, err)
	}
	if _, ok := h.p.Usage("wappie", team); ok {
		t.Fatal("a report kept")
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
	if _, err := h.p.IssueTrimOrder("wappie", team, noPlanOrder(now)); !errors.Is(err, contracttest.ErrUnknown) {
		t.Errorf("an order with no document: %v", err)
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
	if d, _, err := c.EntitlementsDoc(ctx, personal); err != nil || d.Version != 1 {
		t.Fatalf("the next GET: %v", err)
	}
	target := "/contract/v1/workspaces/" + personal + "/entitlements?after=0"
	h.wantSigned(t, h.send(t, call{method: http.MethodGet, target: target, app: "wappie"}),
		call{method: http.MethodGet, target: target, app: "wappie"}, http.StatusBadRequest, contract.CodeInvalid)
}

func i64(n int64) *int64 { return &n }
