package contracttest_test

import (
	"errors"
	"testing"
	"time"

	"github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"
	"github.com/thehappieco/kit/reqhmac"
)

// The fake's platform, through an app's contract.Client: the directory a
// test sets, the documents it publishes, the feed, snapshots, events, the
// generation, and the answers a test spoils.

func start(t *testing.T, opts contracttest.Options) (*contracttest.Platform, *contract.Client) {
	t.Helper()
	if opts.Apps == nil {
		opts.Apps = []contracttest.App{wappie()}
	}
	p := contracttest.Start(t, opts)
	return p, p.Client("wappie")
}

func mustRefusal(t *testing.T, err error, code string) *contract.Refusal {
	t.Helper()
	var r *contract.Refusal
	if !errors.As(err, &r) || r.Code != code {
		t.Fatalf("got %v, want the signed refusal %s", err, code)
	}
	return r
}

func TestAnAppFollowsItsPeoplesWorkspacesThroughTheFeed(t *testing.T) {
	p, c := start(t, contracttest.Options{})
	ctx := t.Context()
	personal, err := p.AddAccount(anaSub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.AddAccount(bobSub); err != nil {
		t.Fatal(err)
	}
	doc, err := c.Subscribe(ctx, anaSub)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Version != 1 || len(doc.Workspaces) != 1 || doc.Workspaces[0].ID != personal || doc.Workspaces[0].Kind != contract.KindPersonal {
		t.Fatalf("the first document: %+v", doc)
	}
	gen, confirmed := p.Generation()
	if doc.Generation != gen || !confirmed || !p.Named("wappie", personal) {
		t.Fatal("the generation, or the personal workspace not named")
	}
	team, err := p.AddTeam("TBFG", anaSub)
	if err != nil {
		t.Fatal(err)
	}
	// A member the app does not follow joins: ana's document says nothing
	// new until the team's owner count changes.
	if err := p.SetRole(team, bobSub, contract.RoleMember); err != nil {
		t.Fatal(err)
	}
	f, err := c.Feed(ctx, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Items) != 1 || f.Items[0].Seq != 2 || f.NextAfter != 2 || f.More || f.Head != 2 {
		t.Fatalf("the feed after the team: %+v", f)
	}
	ws := f.Items[0].Doc.Workspaces
	if len(ws) != 2 || ws[0].ID != personal || ws[1].ID != team || *ws[1].Name != "TBFG" || *ws[1].Owners != 1 || ws[1].Role != contract.RoleOwner {
		t.Fatalf("ana's workspaces: %+v", ws)
	}
	if err := p.SetRole(team, bobSub, contract.RoleOwner); err != nil {
		t.Fatal(err)
	}
	if err := p.RenameTeam(team, "TBFG Vendas"); err != nil {
		t.Fatal(err)
	}
	if err := p.CloseTeam(team); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	if err := p.RevokeSessions(anaSub, at, true); err != nil {
		t.Fatal(err)
	}
	if err := p.Disable(anaSub, at); err != nil {
		t.Fatal(err)
	}
	f, err = c.Feed(ctx, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Five changes, one document: the feed carries each account's latest.
	if len(f.Items) != 1 || f.Items[0].Seq != 7 || f.Head != 7 {
		t.Fatalf("the feed after five changes: %+v", f)
	}
	d := f.Items[0].Doc
	w := d.Workspaces[1]
	if d.Status != contract.AccountDisabled || !d.DisabledAt.Equal(at) || !d.SessionsRevokedAt.Equal(at) || !d.CredentialsRevokedAt.Equal(at) ||
		*w.Owners != 2 || *w.Name != "TBFG Vendas" || w.Status != contract.StatusClose || w.WVersion != 3 {
		t.Fatalf("ana's latest document: %+v %+v", d, w)
	}
	if got, err := c.Account(ctx, anaSub); err != nil || got.Version != 7 {
		t.Fatalf("GET: %+v %v", got, err)
	}
	// Nothing new: the feed is empty, and its cursor stays.
	if f, err := c.Feed(ctx, 7, 0); err != nil || len(f.Items) != 0 || f.NextAfter != 7 {
		t.Fatalf("an empty feed: %+v %v", f, err)
	}
}

func TestTheDirectoryRefusesWhatThePlatformWouldNot(t *testing.T) {
	p, _ := start(t, contracttest.Options{})
	if _, err := p.AddAccount("not-a-uuid"); !errors.Is(err, contracttest.ErrInvalid) {
		t.Errorf("a sub that is no UUID: %v", err)
	}
	if _, err := p.AddAccount(anaSub); err != nil {
		t.Fatal(err)
	}
	if _, err := p.AddAccount(anaSub); !errors.Is(err, contracttest.ErrExists) {
		t.Errorf("twice: %v", err)
	}
	team, err := p.AddTeam("TBFG", anaSub)
	if err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"a name with a bidirectional control": func() error { _, err := p.AddTeam("TB\u202eFG", anaSub); return err }(),
		"an empty name":                       p.RenameTeam(team, ""),
		"an unknown role":                     p.SetRole(team, anaSub, "service"),
	} {
		if !errors.Is(err, contracttest.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, err := range map[string]error{
		"the last owner removed":          p.RemoveMember(team, anaSub),
		"the last owner made a member":    p.SetRole(team, anaSub, contract.RoleAdmin),
		"the last owner's account closed": p.CloseAccount(anaSub),
	} {
		if !errors.Is(err, contracttest.ErrLastOwner) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := p.SetRole(team, bobSub, contract.RoleMember); !errors.Is(err, contracttest.ErrUnknown) {
		t.Errorf("an account nobody made: %v", err)
	}
}

func TestAClosedAccountsDocumentSaysClosed(t *testing.T) {
	p, c := start(t, contracttest.Options{})
	ctx := t.Context()
	if _, err := c.Subscribe(ctx, anaSub); err == nil {
		t.Fatal("an account the platform does not have")
	} else {
		mustRefusal(t, err, contract.CodeNotFound)
	}
	personal, err := p.AddAccount(anaSub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Account(ctx, anaSub); err == nil {
		t.Fatal("GET of an account the app does not follow")
	} else {
		mustRefusal(t, err, contract.CodeNotFound)
	}
	if _, err := c.Subscribe(ctx, anaSub); err != nil {
		t.Fatal(err)
	}
	if err := p.CloseAccount(anaSub); err != nil {
		t.Fatal(err)
	}
	d, err := c.Account(ctx, anaSub)
	if err != nil || d.Status != contract.AccountClosed || len(d.Workspaces) != 0 {
		t.Fatalf("closed: %+v %v", d, err)
	}
	// A snapshot of the closed personal workspace is accepted, not kept.
	if err := c.PutAccess(ctx, personal, contract.Snapshot{V: contract.SnapshotV, SnapshotSeq: 1, Items: []contract.Item{}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Snapshot("wappie", personal); ok {
		t.Fatal("a closed personal workspace's snapshot was kept")
	}
	if err := c.Unsubscribe(ctx, anaSub); err != nil || p.Following("wappie", anaSub) {
		t.Fatalf("unsubscribe: %v", err)
	}
}

func TestARestoredPlatformIsGoneAndItsNewGenerationIsTold(t *testing.T) {
	p, c := start(t, contracttest.Options{})
	ctx := t.Context()
	if _, err := p.AddAccount(anaSub); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Subscribe(ctx, anaSub); err != nil {
		t.Fatal(err)
	}
	old, _ := p.Generation()
	gen := p.Restore()
	if gen == old {
		t.Fatal("no new generation")
	}
	_, err := c.Feed(ctx, 1, 0)
	mustRefusal(t, err, contract.CodeGone)
	f, err := c.Feed(ctx, 0, 0)
	if err != nil || f.Generation != gen || f.GenerationConfirmed || len(f.Items) != 0 {
		t.Fatalf("the feed from 0: %+v %v", f, err)
	}
	d, err := c.Subscribe(ctx, anaSub)
	if err != nil || d.Generation != gen || d.Version != 1 {
		t.Fatalf("subscribed again: %+v %v", d, err)
	}
	p.ConfirmGeneration()
	if f, err := c.Feed(ctx, 0, 0); err != nil || !f.GenerationConfirmed || len(f.Items) != 1 {
		t.Fatalf("confirmed: %+v %v", f, err)
	}
	// A new generation alone keeps the cursor and tells it.
	next := p.NewGeneration()
	if f, err := c.Feed(ctx, 1, 0); err != nil || f.Generation != next || f.GenerationConfirmed {
		t.Fatalf("a new generation: %+v %v", f, err)
	}
}

func TestTheFeedPagesTwoHundredDocumentsAtATime(t *testing.T) {
	p, c := start(t, contracttest.Options{PerSecond: 10_000})
	ctx := t.Context()
	subs := make([]string, contract.MaxFeedItems+1)
	for i := range subs {
		subs[i] = "0199a0c2-0000-7000-8000-" + time.Unix(int64(i), 0).UTC().Format("150405") + "000000"
		if _, err := p.AddAccount(subs[i]); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Subscribe(ctx, subs[i]); err != nil {
			t.Fatal(err)
		}
	}
	f, err := c.Feed(ctx, 0, 0)
	if err != nil || len(f.Items) != contract.MaxFeedItems || !f.More || f.NextAfter != contract.MaxFeedItems || f.Head != int64(len(subs)) {
		t.Fatalf("the first page: %d items, more %v, next %d, head %d, %v", len(f.Items), f.More, f.NextAfter, f.Head, err)
	}
	f, err = c.Feed(ctx, f.NextAfter, 0)
	if err != nil || len(f.Items) != 1 || f.More || f.NextAfter != f.Head {
		t.Fatalf("the second page: %+v %v", f, err)
	}
}

func TestSnapshotsAndEventsReachTheFakeAsTheAppSentThem(t *testing.T) {
	p, c := start(t, contracttest.Options{})
	ctx := t.Context()
	if _, err := p.AddAccount(anaSub); err != nil {
		t.Fatal(err)
	}
	team, err := p.AddTeam("TBFG", anaSub)
	if err != nil {
		t.Fatal(err)
	}
	snap := contract.Snapshot{V: contract.SnapshotV, SnapshotSeq: 1_760_356_800_000, Items: []contract.Item{{
		ID: "dev_1", Kind: contract.ItemNumber, Label: ptr("+55 11 91234-5678"), Hint: ptr("5678"), State: contract.StateActive,
		People:    []contract.Person{{Sub: anaSub, Can: []string{contract.CanRead}, Reads: true, Enrolled: true, HoldsKey: true}},
		Protected: []string{anaSub},
	}}}
	// Not named yet: the app has not followed anyone in it.
	mustRefusal(t, c.PutAccess(ctx, team, snap), contract.CodeNotFound)
	if _, err := c.Subscribe(ctx, anaSub); err != nil {
		t.Fatal(err)
	}
	// The platform masks the label and drops the hint, as a backstop; the
	// fake keeps the snapshot as the app sent it.
	if err := c.PutAccess(ctx, team, snap); err != nil {
		t.Fatal(err)
	}
	if got, ok := p.Snapshot("wappie", team); !ok || *got.Items[0].Label != "+55 11 91234-5678" {
		t.Fatalf("kept %+v", got)
	}
	readers := []string{anaSub}
	purge := contract.T(time.Now().Add(30 * 24 * time.Hour))
	ev := contract.Event{
		EventID: eventA, WorkspaceID: team, Type: contract.EventDeleted, OccurredAt: contract.T(time.Now()),
		Item: contract.EventItem{ID: "dev_1", Kind: contract.ItemNumber, Label: ptr("Vendas")}, Actor: ptr(anaSub),
		ActorKind: contract.ActorPerson, Readers: &readers, PurgeAt: &purge,
	}
	results, err := c.PostEvents(ctx, []contract.Event{ev, ev})
	if err != nil || results[0].Outcome != contract.OutcomeAccepted || results[1].Outcome != contract.OutcomeDuplicate {
		t.Fatalf("results %+v %v", results, err)
	}
	if got := p.Events("wappie"); len(got) != 1 || got[0].EventID != eventA {
		t.Fatalf("kept %+v", got)
	}
}

func TestStrictLabelsRefusesWhatThePlatformWouldMend(t *testing.T) {
	p, c := start(t, contracttest.Options{StrictLabels: true})
	ctx := t.Context()
	personal, err := p.AddAccount(anaSub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Subscribe(ctx, anaSub); err != nil {
		t.Fatal(err)
	}
	item := func(label, hint *string) contract.Snapshot {
		return contract.Snapshot{V: contract.SnapshotV, SnapshotSeq: 1, Items: []contract.Item{{
			ID: "dev_1", Kind: contract.ItemNumber, Label: label, Hint: hint, State: contract.StateActive,
			People: []contract.Person{}, Protected: []string{},
		}}}
	}
	mustRefusal(t, c.PutAccess(ctx, personal, item(ptr("+55 11 91234-5678"), nil)), contract.CodeInvalid)
	mustRefusal(t, c.PutAccess(ctx, personal, item(ptr("Vendas"), ptr("5678"))), contract.CodeInvalid)
	if err := c.PutAccess(ctx, personal, item(ptr(contract.CleanLabel("+55 11 91234-5678")), ptr("…5678"))); err != nil {
		t.Fatal(err)
	}
}

func TestRefuseAndCorruptMakeTheClientSeeARefusalOrIgnoreTheAnswer(t *testing.T) {
	p, c := start(t, contracttest.Options{})
	ctx := t.Context()
	if err := p.Refuse("wappie", contracttest.CallFeed, contract.CodeUnavailable); err != nil {
		t.Fatal(err)
	}
	_, err := c.Feed(ctx, 0, 0)
	if r := mustRefusal(t, err, contract.CodeUnavailable); r.Status != 503 {
		t.Fatalf("status %d", r.Status)
	}
	if _, err := c.Feed(ctx, 0, 0); err != nil {
		t.Fatalf("only the next request is refused: %v", err)
	}
	for how, want := range map[contracttest.Corruption]error{
		contracttest.Unsigned:      reqhmac.ErrMissing,
		contracttest.AnotherNonce:  contract.ErrAnswerNonce,
		contracttest.AnotherBody:   reqhmac.ErrBad,
		contracttest.AnotherSecret: reqhmac.ErrBad,
		contracttest.Stale:         reqhmac.ErrStale,
	} {
		if err := p.Corrupt("wappie", contracttest.CallFeed, how); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Feed(ctx, 0, 0); !errors.Is(err, contract.ErrUnverified) || !errors.Is(err, want) {
			t.Errorf("corruption %d: %v, want %v", how, err, want)
		}
	}
	for name, err := range map[string]error{
		"an unknown code":       p.Refuse("wappie", contracttest.CallFeed, "teapot"),
		"an unknown call":       p.Refuse("wappie", "renew", contract.CodeGone),
		"an unknown corruption": p.Corrupt("wappie", contracttest.CallFeed, 0),
	} {
		if !errors.Is(err, contracttest.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := p.Refuse("mailie", contracttest.CallFeed, contract.CodeGone); !errors.Is(err, contracttest.ErrUnknown) {
		t.Errorf("an app the fake does not serve: %v", err)
	}
}

func ptr(s string) *string { return &s }
