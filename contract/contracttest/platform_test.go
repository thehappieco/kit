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
	personal, err := p.AddAccount(anaSub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Subscribe(ctx, anaSub); err != nil {
		t.Fatal(err)
	}
	empty := contract.Snapshot{V: contract.SnapshotV, SnapshotSeq: 1, Items: []contract.Item{}}
	if err := c.PutAccess(ctx, personal, empty); err != nil {
		t.Fatal(err)
	}
	old, _ := p.Generation()
	gen := p.Restore()
	if gen == old {
		t.Fatal("no new generation")
	}
	// The backup was taken before any document was published: it holds no
	// subscription, names no workspace and keeps no snapshot.
	if p.Following("wappie", anaSub) || p.Named("wappie", personal) {
		t.Fatal("the restore kept a subscription or a named workspace")
	}
	if _, ok := p.Snapshot("wappie", personal); ok {
		t.Fatal("the restore kept a snapshot")
	}
	_, err = c.Feed(ctx, 1, 0)
	mustRefusal(t, err, contract.CodeGone)
	f, err := c.Feed(ctx, 0, 0)
	if err != nil || f.Generation != gen || f.GenerationConfirmed || len(f.Items) != 0 {
		t.Fatalf("the feed from 0: %+v %v", f, err)
	}
	// A workspace not named again takes no snapshot.
	mustRefusal(t, c.PutAccess(ctx, personal, empty), contract.CodeNotFound)
	d, err := c.Subscribe(ctx, anaSub)
	if err != nil || d.Generation != gen || d.Version != 1 {
		t.Fatalf("subscribed again: %+v %v", d, err)
	}
	if err := c.PutAccess(ctx, personal, empty); err != nil || !p.Named("wappie", personal) {
		t.Fatalf("a snapshot once named again: %v", err)
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

// An app that does not subscribe again after gone follows nobody: a later
// disable of one of its people never reaches its feed.
func TestAfterARestoreOnlyAnAppThatSubscribesAgainHearsOfADisable(t *testing.T) {
	p, c := start(t, contracttest.Options{})
	ctx := t.Context()
	for _, sub := range []string{anaSub, bobSub} {
		if _, err := p.AddAccount(sub); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Subscribe(ctx, sub); err != nil {
			t.Fatal(err)
		}
	}
	p.Restore()
	mustRefusal(t, func() error { _, err := c.Feed(ctx, 2, 0); return err }(), contract.CodeGone)
	// The app subscribes again for bob only.
	if _, err := c.Subscribe(ctx, bobSub); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	for _, sub := range []string{anaSub, bobSub} {
		if err := p.Disable(sub, at); err != nil {
			t.Fatal(err)
		}
	}
	f, err := c.Feed(ctx, 0, 0)
	if err != nil || len(f.Items) != 1 || f.Items[0].Doc.Sub != bobSub || f.Items[0].Doc.Status != contract.AccountDisabled {
		t.Fatalf("the feed after the disables: %+v %v", f, err)
	}
	if _, err := c.Account(ctx, anaSub); err == nil {
		t.Fatal("GET of an account the app follows no more")
	} else {
		mustRefusal(t, err, contract.CodeNotFound)
	}
}

// The operator's disable ends every session too, once: disabled_at and
// sessions_revoked_at rise together, and disabling a disabled account
// changes nothing.
func TestADisableRevokesTheSessionsOnce(t *testing.T) {
	p, c := start(t, contracttest.Options{})
	ctx := t.Context()
	if _, err := p.AddAccount(anaSub); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Subscribe(ctx, anaSub); err != nil {
		t.Fatal(err)
	}
	t1 := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	if err := p.Disable(anaSub, t1); err != nil {
		t.Fatal(err)
	}
	d, err := c.Account(ctx, anaSub)
	if err != nil || d.Status != contract.AccountDisabled || !d.DisabledAt.Equal(t1) || d.SessionsRevokedAt == nil || !d.SessionsRevokedAt.Equal(t1) || d.CredentialsRevokedAt != nil {
		t.Fatalf("disabled: %+v %v", d, err)
	}
	if err := p.Disable(anaSub, t1.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if again, err := c.Account(ctx, anaSub); err != nil || again.Version != d.Version || !again.DisabledAt.Equal(t1) || !again.SessionsRevokedAt.Equal(t1) {
		t.Fatalf("a second disable changed the document: %+v %v", again, err)
	}
	// A revocation after the disable stays the latest, whatever a later
	// disable's time; a disable after an enable rises both again.
	t2 := t1.Add(2 * time.Hour)
	if err := p.RevokeSessions(anaSub, t2, false); err != nil {
		t.Fatal(err)
	}
	if err := p.Enable(anaSub); err != nil {
		t.Fatal(err)
	}
	if err := p.Disable(anaSub, t1.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	d, err = c.Account(ctx, anaSub)
	if err != nil || d.Status != contract.AccountDisabled || !d.DisabledAt.Equal(t1.Add(time.Hour)) || !d.SessionsRevokedAt.Equal(t2) {
		t.Fatalf("disabled again: %+v %v", d, err)
	}
	t3 := t2.Add(time.Hour)
	if err := p.Enable(anaSub); err != nil {
		t.Fatal(err)
	}
	if err := p.Disable(anaSub, t3); err != nil {
		t.Fatal(err)
	}
	if d, err := c.Account(ctx, anaSub); err != nil || !d.DisabledAt.Equal(t3) || !d.SessionsRevokedAt.Equal(t3) {
		t.Fatalf("disabled a third time: %+v %v", d, err)
	}
}

// The platform keeps its times at microseconds, and so does the fake: a
// disable at a time with nanoseconds, an enable, and a disable again in the
// same microsecond never show an app that stores microseconds a
// disabled_at or a sessions_revoked_at that rose, which would suspend the
// person again and end their sessions for nothing.
func TestTheFakeKeepsItsTimesAtMicroseconds(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 13, 12, 0, 0, 987654321, time.UTC)}
	p, c := start(t, contracttest.Options{Now: clk.Now})
	ctx := t.Context()
	if _, err := p.AddAccount(anaSub); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Subscribe(ctx, anaSub); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 13, 9, 0, 0, 123456789, time.UTC)
	want := time.Date(2026, 10, 13, 9, 0, 0, 123456000, time.UTC)
	if err := p.Disable(anaSub, at); err != nil {
		t.Fatal(err)
	}
	d, err := c.Account(ctx, anaSub)
	if err != nil || d.Status != contract.AccountDisabled || !d.DisabledAt.Equal(want) || !d.SessionsRevokedAt.Equal(want) {
		t.Fatalf("disabled at nanoseconds: %+v %v", d, err)
	}
	// What an app that stores microseconds keeps of them.
	disabled, revoked := d.DisabledAt.Truncate(time.Microsecond), d.SessionsRevokedAt.Truncate(time.Microsecond)
	for _, again := range []time.Time{at, at.Add(210 * time.Nanosecond)} {
		if err := p.Enable(anaSub); err != nil {
			t.Fatal(err)
		}
		if err := p.Disable(anaSub, again); err != nil {
			t.Fatal(err)
		}
		d, err := c.Account(ctx, anaSub)
		if err != nil || d.Status != contract.AccountDisabled {
			t.Fatalf("disabled again: %+v %v", d, err)
		}
		if d.DisabledAt.After(disabled) || d.SessionsRevokedAt.After(revoked) {
			t.Fatalf("disabled again at %s: disabled_at %s and sessions_revoked_at %s rose past %s", again.Format(time.RFC3339Nano),
				d.DisabledAt.Format(time.RFC3339Nano), d.SessionsRevokedAt.Format(time.RFC3339Nano), disabled.Format(time.RFC3339Nano))
		}
	}
	if err := p.RevokeSessions(anaSub, at.Add(100*time.Nanosecond), true); err != nil {
		t.Fatal(err)
	}
	if d, err := c.Account(ctx, anaSub); err != nil || !d.SessionsRevokedAt.Equal(want) || !d.CredentialsRevokedAt.Equal(want) {
		t.Fatalf("a recovery at nanoseconds: %+v %v", d, err)
	}
	// A change a held publisher has not published: published_through is
	// its time at microseconds.
	if err := p.HoldPublishing("wappie"); err != nil {
		t.Fatal(err)
	}
	changed := clk.Now()
	if _, err := p.AddTeam("TBFG", anaSub); err != nil {
		t.Fatal(err)
	}
	clk.Add(time.Minute)
	if f, err := c.Feed(ctx, 0, 0); err != nil || !f.PublishedThrough.Equal(changed.Truncate(time.Microsecond)) {
		t.Fatalf("held: %+v %v", f, err)
	}
}

// A rotation of the app's secret, the platform's steps played with
// SetSecrets and the app's half with its client's Secret and Accept (SPEC
// section 11.17): no request fails at any step, an app that drops the old
// secret before the platform's promote cannot verify the answers, and a
// rotation abandoned before its promote leaves the app signing with the
// old secret again once it drops the next one.
func TestARotationFailsNoRequestAtAnyStep(t *testing.T) {
	p, c := start(t, contracttest.Options{})
	ctx := t.Context()
	if _, err := p.AddAccount(anaSub); err != nil {
		t.Fatal(err)
	}
	ok := func(step string) {
		t.Helper()
		if _, err := c.Subscribe(ctx, anaSub); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
	}
	fails := func(step string) {
		t.Helper()
		if _, err := c.Subscribe(ctx, anaSub); !errors.Is(err, contract.ErrUnverified) {
			t.Fatalf("%s: %v, want ErrUnverified", step, err)
		}
	}
	old, next := secretA, secretB
	ok("before the rotation")
	if err := p.SetSecrets("wappie", old, next); err != nil {
		t.Fatal(err)
	}
	ok("1, secret-next")
	if err := contract.CheckSecrets(old, next); err != nil {
		t.Fatal(err)
	}
	c.Accept = contract.Secrets(old, next)
	ok("2, the next secret installed as accepted")
	c.Secret = next
	ok("3, the app signs with the next secret")
	c.Accept = []string{next}
	fails("the old secret dropped before the platform's promote")
	c.Accept = contract.Secrets(old, next)
	if err := p.SetSecrets("wappie", next, old); err != nil {
		t.Fatal(err)
	}
	ok("4, secret-promote")
	c.Accept = []string{next}
	ok("5, the app drops the old secret")
	if err := p.SetSecrets("wappie", next, ""); err != nil {
		t.Fatal(err)
	}
	ok("6, secret-drop")

	// Abandoned before its promote: the platform accepts the next secret
	// no more, so the app drops it and signs with the old one again.
	old, next = secretB, secretC
	if err := p.SetSecrets("wappie", old, next); err != nil {
		t.Fatal(err)
	}
	c.Secret, c.Accept = next, contract.Secrets(old, next)
	ok("signing with the next secret")
	if err := p.SetSecrets("wappie", old, ""); err != nil {
		t.Fatal(err)
	}
	fails("secret-cancel, the app still signing with the next secret")
	c.Secret, c.Accept = old, []string{old}
	ok("secret-cancel, the next secret dropped")
}

// A stuck publisher: the feed answers, but published_through stays at the
// oldest change not yet published, so an app's freshness grows old, until
// the publisher runs again. A sign-in's PUT still computes the document
// now.
func TestAHeldPublisherLeavesTheFeedAnsweringButStale(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	p, c := start(t, contracttest.Options{Now: clk.Now})
	ctx := t.Context()
	for _, sub := range []string{anaSub, bobSub} {
		if _, err := p.AddAccount(sub); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Subscribe(ctx, sub); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.HoldPublishing("wappie"); err != nil {
		t.Fatal(err)
	}
	if f, err := c.Feed(ctx, 2, 0); err != nil || !f.PublishedThrough.Equal(clk.Now()) {
		t.Fatalf("held, nothing to publish: %+v %v", f, err)
	}
	changed := clk.Now()
	team, err := p.AddTeam("TBFG", anaSub)
	if err != nil {
		t.Fatal(err)
	}
	clk.Add(30 * time.Minute)
	if err := p.SetRole(team, bobSub, contract.RoleMember); err != nil {
		t.Fatal(err)
	}
	clk.Add(31 * time.Minute)
	f, err := c.Feed(ctx, 2, 0)
	if err != nil || len(f.Items) != 0 || f.More || f.Head != 2 || !f.PublishedThrough.Equal(changed) {
		t.Fatalf("held: %+v %v", f, err)
	}
	if clk.Now().Sub(f.PublishedThrough.Time) <= time.Hour {
		t.Fatal("published_through is not over an hour old")
	}
	// The team is named to the app only once a document names it.
	if p.Named("wappie", team) {
		t.Fatal("a held document named its workspace")
	}
	// bob signs in: his document is computed and published now; ana's
	// change stays held.
	d, err := c.Subscribe(ctx, bobSub)
	if err != nil || d.Version != 3 || len(d.Workspaces) != 2 || !p.Named("wappie", team) {
		t.Fatalf("bob's sign-in: %+v %v", d, err)
	}
	if f, err := c.Feed(ctx, 2, 0); err != nil || len(f.Items) != 1 || f.Items[0].Doc.Sub != bobSub || !f.PublishedThrough.Equal(changed) {
		t.Fatalf("after bob's sign-in: %+v %v", f, err)
	}
	if err := p.Release("wappie"); err != nil {
		t.Fatal(err)
	}
	f, err = c.Feed(ctx, 3, 0)
	if err != nil || len(f.Items) != 1 || f.Items[0].Doc.Sub != anaSub || len(f.Items[0].Doc.Workspaces) != 2 || !f.PublishedThrough.Equal(clk.Now()) {
		t.Fatalf("released: %+v %v", f, err)
	}
	if err := p.HoldPublishing("mailie"); !errors.Is(err, contracttest.ErrUnknown) {
		t.Errorf("an app the fake does not serve: %v", err)
	}
	if err := p.Release("mailie"); !errors.Is(err, contracttest.ErrUnknown) {
		t.Errorf("an app the fake does not serve: %v", err)
	}
}

// A long-poll answers early only for a new document: a sign-in's PUT that
// leaves the document as it was wakes none.
func TestTheSameDocumentAgainWakesNoLongPoll(t *testing.T) {
	p, c := start(t, contracttest.Options{})
	ctx := t.Context()
	if _, err := p.AddAccount(anaSub); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Subscribe(ctx, anaSub); err != nil {
		t.Fatal(err)
	}
	type polled struct {
		f   contract.Feed
		err error
		in  time.Duration
	}
	got := make(chan polled, 1)
	began := time.Now()
	go func() {
		f, err := c.Feed(ctx, 1, 1)
		got <- polled{f, err, time.Since(began)}
	}()
	time.Sleep(100 * time.Millisecond) // most likely waiting by now; either way it must wait out its second
	if _, err := c.Subscribe(ctx, anaSub); err != nil {
		t.Fatal(err)
	}
	r := <-got
	if r.err != nil || len(r.f.Items) != 0 || r.in < 900*time.Millisecond {
		t.Fatalf("the long-poll: %+v %v after %v", r.f, r.err, r.in)
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

// A page also ends, with more, before its documents reach the page's bytes,
// though a first document over them still comes alone.
func TestAFeedPageEndsBeforeItsDocumentsReachItsBytes(t *testing.T) {
	p, c := start(t, contracttest.Options{})
	ctx := t.Context()
	subs := []string{anaSub, bobSub, "0199a0c2-0000-7000-8000-000000000003"}
	for _, sub := range subs {
		if _, err := p.AddAccount(sub); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Subscribe(ctx, sub); err != nil {
			t.Fatal(err)
		}
	}
	// The three documents are of one size, counted as the platform counts
	// them stored, with no generation: two fit in two and a half, not
	// three.
	f, err := c.Feed(ctx, 0, 0)
	if err != nil || len(f.Items) != 3 {
		t.Fatalf("the whole feed: %+v %v", f, err)
	}
	stored := f.Items[0].Doc
	stored.Generation = ""
	one := contracttest.StoredLen(stored)
	restore := contracttest.ShortenFeedPages(one * 5 / 2)
	defer restore()
	f, err = c.Feed(ctx, 0, 0)
	if err != nil || len(f.Items) != 2 || !f.More || f.NextAfter != 2 {
		t.Fatalf("the first page: %+v %v", f, err)
	}
	if f, err = c.Feed(ctx, f.NextAfter, 0); err != nil || len(f.Items) != 1 || f.More || f.NextAfter != 3 {
		t.Fatalf("the second page: %+v %v", f, err)
	}
	contracttest.ShortenFeedPages(1)
	for after := int64(0); after < 3; after++ {
		if f, err := c.Feed(ctx, after, 0); err != nil || len(f.Items) != 1 || f.More != (after < 2) {
			t.Fatalf("a page over its bytes after %d: %+v %v", after, f, err)
		}
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
	// The codes the platform never signs go unsigned: the client cannot
	// trust them, as with the platform.
	for _, code := range []string{contract.CodeUnauthenticated, contract.CodeStale, contract.CodeTooLarge} {
		if err := p.Refuse("wappie", contracttest.CallFeed, code); err != nil {
			t.Fatal(err)
		}
		_, err := c.Feed(ctx, 0, 0)
		var r *contract.Refusal
		if !errors.Is(err, contract.ErrUnverified) || !errors.Is(err, reqhmac.ErrMissing) || errors.As(err, &r) {
			t.Errorf("Refuse %s: %v, want an unsigned answer", code, err)
		}
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
