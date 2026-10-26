package contracttest_test

// The fake's token part (SPEC section 11.18), through an app's
// contract.Client: the records a test makes reach the app's token feed and
// the signed GETs, the creator's revocations come before the document that
// causes them, and what the app sends back narrows the records as the
// platform does.

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"
)

const (
	number  = "dev_1"
	number2 = "dev_2"
)

// tokenSetup is a team of ana (owner) and bob (admin), which wappie was
// told of through ana's document, and a token ana made there.
func tokenSetup(t *testing.T, opts contracttest.Options) (*harness, *contract.Client, string, string, string) {
	t.Helper()
	if opts.Apps == nil {
		opts.Apps = []contracttest.App{wappie()}
	}
	h := newHarness(t, opts)
	if _, err := h.p.AddAccount(anaSub); err != nil {
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
	if _, err := c.Subscribe(t.Context(), anaSub); err != nil {
		t.Fatal(err)
	}
	id, text, err := h.p.AddToken(team, bobSub, "Nightly export", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	return h, c, team, id, text
}

func readingKey(t *testing.T) string {
	t.Helper()
	scalar := sha256.Sum256([]byte("a client's reading key"))
	priv, err := ecdh.X25519().NewPrivateKey(scalar[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
}

// record is a feed item's record, decoded on its own as an app does.
func record(t *testing.T, it contract.TokenFeedItem) contract.TokenRecord {
	t.Helper()
	r, err := it.Record()
	if err != nil {
		t.Fatalf("item %d: %v", it.Seq, err)
	}
	return r
}

func tokenFeed(t *testing.T, c *contract.Client, after int64) contract.TokenFeed {
	t.Helper()
	f, err := c.Tokens(t.Context(), after, 0)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestATokensRecordReachesAnAppOnceItNamesTheAppAndItsWorkspaceIsNamed(t *testing.T) {
	h, c, team, id, text := tokenSetup(t, contracttest.Options{})
	if f := tokenFeed(t, c, 0); len(f.Items) != 0 || f.Head != 0 {
		t.Fatalf("a token that names no app reached the feed: %+v", f)
	}
	if err := h.p.GrantToken(id, "wappie", number, contract.ItemNumber, contract.CanRead, anaSub); err != nil {
		t.Fatal(err)
	}
	if err := h.p.SetReadingKey(id, readingKey(t)); err != nil {
		t.Fatal(err)
	}
	f := tokenFeed(t, c, 0)
	if len(f.Items) != 1 || f.Head != 2 || f.Items[0].Seq != 2 || f.NextAfter != 2 {
		t.Fatalf("the feed: %+v", f)
	}
	rec := record(t, f.Items[0])
	gen, _ := h.p.Generation()
	if err := rec.Validate(); err != nil || rec.Generation != gen || rec.App != "wappie" || rec.WorkspaceID != team || rec.CreatedBy != bobSub {
		t.Fatalf("the record: %+v, %v", rec, err)
	}
	if rec.ReadingKey == nil || rec.ReadingKey.Check() != nil || len(rec.Items) != 1 || rec.Items[0].Perms[0].GrantedBy != anaSub {
		t.Fatalf("the record's key and items: %+v", rec)
	}
	// The app checks the token it is shown against the record it holds.
	if err := contract.VerifyToken(&rec, text); err != nil {
		t.Fatalf("the token does not verify against its record: %v", err)
	}
	// A workspace never named to an app keeps its tokens from it.
	other, err := h.p.AddTeam("Elsewhere", bobSub)
	if err != nil {
		t.Fatal(err)
	}
	hidden, _, err := h.p.AddToken(other, bobSub, "Hidden", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.p.GrantToken(hidden, "wappie", number, contract.ItemNumber, contract.CanSend, bobSub); err != nil {
		t.Fatal(err)
	}
	if f := tokenFeed(t, c, 2); len(f.Items) != 0 {
		t.Fatalf("a token of a workspace not named to the app: %+v", f)
	}
	mustRefusal(t, func() error { _, err := c.Token(t.Context(), hidden); return err }(), contract.CodeNotFound)
	// Bob's document names it, and the record follows.
	if _, err := c.Subscribe(t.Context(), bobSub); err != nil {
		t.Fatal(err)
	}
	if f := tokenFeed(t, c, 2); len(f.Items) != 1 || record(t, f.Items[0]).ID != hidden {
		t.Fatalf("once named: %+v", f)
	}
}

func TestTheSignedGETsAnswerTheRecordComputedNow(t *testing.T) {
	h, c, _, id, text := tokenSetup(t, contracttest.Options{})
	if err := h.p.GrantToken(id, "wappie", number, contract.ItemNumber, contract.CanRead, anaSub); err != nil {
		t.Fatal(err)
	}
	byID, err := c.Token(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	p, err := contract.ParseToken(text)
	if err != nil {
		t.Fatal(err)
	}
	bySelector, err := c.TokenBySelector(t.Context(), p.Selector)
	if err != nil {
		t.Fatal(err)
	}
	if byID.Version != bySelector.Version || byID.Hash != p.Hash() || bySelector.ID != id {
		t.Fatalf("by id %+v, by selector %+v", byID, bySelector)
	}
	mustRefusal(t, func() error { _, err := c.Token(t.Context(), eventA); return err }(), contract.CodeNotFound)
	mustRefusal(t, func() error { _, err := c.TokenBySelector(t.Context(), "0123456789abcdef"); return err }(), contract.CodeNotFound)
	// A token that never named the app is not_found too.
	quiet, _, err := h.p.AddToken(teamOf(t, h), anaSub, "Quiet", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	mustRefusal(t, func() error { _, err := c.Token(t.Context(), quiet); return err }(), contract.CodeNotFound)
}

// teamOf is the team tokenSetup made.
func teamOf(t *testing.T, h *harness) string {
	t.Helper()
	for _, ws := range func() []string {
		doc, _ := h.p.Client("wappie").Account(t.Context(), anaSub)
		var ids []string
		for _, w := range doc.Workspaces {
			if w.Kind == contract.KindTeam {
				ids = append(ids, w.ID)
			}
		}
		return ids
	}() {
		return ws
	}
	t.Fatal("no team")
	return ""
}

func TestTheSelectorGETSpendsABucketOfItsOwn(t *testing.T) {
	h, c, _, _, text := tokenSetup(t, contracttest.Options{PerSecond: 50, SelectorPerSecond: 2})
	p, _ := contract.ParseToken(text)
	for i := 0; i < 2; i++ {
		mustRefusal(t, func() error { _, err := c.TokenBySelector(t.Context(), p.Selector); return err }(), contract.CodeNotFound)
	}
	// The third within the second is refused, signed once its signature
	// holds, as the design's 3.4 says: the app sees a *Refusal.
	c3 := call{method: http.MethodGet, target: "/contract/v1/token-selectors/" + p.Selector, app: "wappie"}
	h.wantSigned(t, h.send(t, c3), c3, http.StatusTooManyRequests, contract.CodeRateLimited)
	mustRefusal(t, func() error { _, err := c.TokenBySelector(t.Context(), p.Selector); return err }(), contract.CodeRateLimited)
	// One that does not sign spends nothing of either bucket.
	h.send(t, call{method: http.MethodGet, target: "/contract/v1/token-selectors/" + p.Selector, app: "wappie", secret: secretC}).
		wantUnsigned(t, http.StatusUnauthorized, contract.CodeUnauthenticated)
	// The app's own bucket is untouched.
	if _, err := c.Tokens(t.Context(), 0, 0); err != nil {
		t.Fatal(err)
	}
	h.clock.Add(time.Second)
	mustRefusal(t, func() error { _, err := c.TokenBySelector(t.Context(), p.Selector); return err }(), contract.CodeNotFound)
}

func TestACreatorsRevocationReachesTheTokenFeedBeforeTheDocument(t *testing.T) {
	h, c, team, id, _ := tokenSetup(t, contracttest.Options{})
	if err := h.p.GrantToken(id, "wappie", number, contract.ItemNumber, contract.CanRead, anaSub); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Subscribe(t.Context(), bobSub); err != nil {
		t.Fatal(err)
	}
	feed, err := c.Feed(t.Context(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	before := tokenFeed(t, c, 0).Head
	if err := h.p.RemoveMember(team, bobSub); err != nil {
		t.Fatal(err)
	}
	// By the time the document that removes bob is in the feed, his token's
	// revocation is in the token feed.
	docs, err := c.Feed(t.Context(), feed.Head, 0)
	if err != nil || len(docs.Items) == 0 {
		t.Fatalf("the document: %+v %v", docs, err)
	}
	f := tokenFeed(t, c, before)
	if len(f.Items) != 1 || record(t, f.Items[0]).RevokedReason == nil || *record(t, f.Items[0]).RevokedReason != contract.RevokedCreatorLeft || len(record(t, f.Items[0]).Items) != 0 {
		t.Fatalf("the revocation: %+v", f)
	}
	// It is never cleared.
	if err := h.p.GrantToken(id, "wappie", number2, contract.ItemNumber, contract.CanRead, anaSub); !errors.Is(err, contracttest.ErrRevoked) {
		t.Fatalf("a grant to a revoked token: %v", err)
	}
}

func TestARecoveryStopsOnlyTheTokensMadeBeforeIt(t *testing.T) {
	h, c, team, old, _ := tokenSetup(t, contracttest.Options{})
	h.clock.Add(time.Hour)
	recovery := h.clock.Now()
	h.clock.Add(time.Hour)
	fresh, _, err := h.p.AddToken(team, bobSub, "Made after", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{old, fresh} {
		if err := h.p.GrantToken(id, "wappie", number, contract.ItemNumber, contract.CanSend, bobSub); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.p.RevokeSessions(bobSub, recovery, true); err != nil {
		t.Fatal(err)
	}
	oldRec, _ := c.Token(t.Context(), old)
	freshRec, _ := c.Token(t.Context(), fresh)
	if oldRec.RevokedReason == nil || *oldRec.RevokedReason != contract.RevokedCreatorRecovered || freshRec.RevokedAt != nil {
		t.Fatalf("old %+v, fresh %+v", oldRec, freshRec)
	}
}

func TestTakingAnAppOffATokenRevokesItThereOnly(t *testing.T) {
	h, c, _, id, _ := tokenSetup(t, contracttest.Options{Apps: []contracttest.App{wappie(), {ID: "mailie", Current: secretB}}})
	m := h.p.Client("mailie")
	if _, err := m.Subscribe(t.Context(), anaSub); err != nil {
		t.Fatal(err)
	}
	if err := h.p.GrantToken(id, "wappie", number, contract.ItemNumber, contract.CanRead, anaSub); err != nil {
		t.Fatal(err)
	}
	if err := h.p.GrantToken(id, "mailie", "acc_1", contract.ItemMailbox, contract.CanRead, anaSub); err != nil {
		t.Fatal(err)
	}
	if err := h.p.TakeTokenOffApp(id, "mailie"); err != nil {
		t.Fatal(err)
	}
	gone, err := m.Token(t.Context(), id)
	if err != nil || gone.RevokedReason == nil || *gone.RevokedReason != contract.RevokedAppRemoved || len(gone.Items) != 0 {
		t.Fatalf("mailie's record: %+v %v", gone, err)
	}
	kept, err := c.Token(t.Context(), id)
	if err != nil || kept.RevokedAt != nil || len(kept.Items) != 1 {
		t.Fatalf("wappie's record: %+v %v", kept, err)
	}
	if err := h.p.GrantToken(id, "mailie", "acc_1", contract.ItemMailbox, contract.CanRead, anaSub); !errors.Is(err, contracttest.ErrRevoked) {
		t.Fatalf("the app given back: %v", err)
	}
	// Mailie's act goes with its read, and its act alone is refused.
	if err := h.p.GrantToken(id, "wappie", number, contract.ItemNumber, contract.CanAct, anaSub); !errors.Is(err, contracttest.ErrInvalid) {
		t.Fatalf("wappie's act: %v", err)
	}
}

func TestAnAcknowledgementNarrowsTheAppsRecordAsThePlatformDoes(t *testing.T) {
	h, c, _, id, _ := tokenSetup(t, contracttest.Options{Apps: []contracttest.App{wappie(), {ID: "mailie", Current: secretB}}})
	m := h.p.Client("mailie")
	if _, err := m.Subscribe(t.Context(), anaSub); err != nil {
		t.Fatal(err)
	}
	for _, perm := range []string{contract.CanRead, contract.CanSend} {
		if err := h.p.GrantToken(id, "wappie", number, contract.ItemNumber, perm, anaSub); err != nil {
			t.Fatal(err)
		}
	}
	for _, perm := range []string{contract.CanRead, contract.CanAct} {
		if err := h.p.GrantToken(id, "mailie", "acc_1", contract.ItemMailbox, perm, anaSub); err != nil {
			t.Fatal(err)
		}
	}
	gen, _ := h.p.Generation()
	rec, _ := c.Token(t.Context(), id)
	// A refusal of an older grant is ignored: read is given again since.
	if err := h.p.UngrantToken(id, "wappie", number, contract.CanRead); err != nil {
		t.Fatal(err)
	}
	h.clock.Add(time.Second)
	if err := h.p.GrantToken(id, "wappie", number, contract.ItemNumber, contract.CanRead, bobSub); err != nil {
		t.Fatal(err)
	}
	head := tokenFeed(t, c, 0).Head
	ack := contract.TokenApplied{
		Generation: gen, Through: head, AppliedAt: contract.T(h.clock.Now()), Held: []contract.TokenHeld{},
		Refused: []contract.TokenRefusal{
			{Token: id, Version: rec.Version, Item: number, Perm: contract.CanRead, Code: contract.RefusedGiverNotReader},
			{Token: id, Version: rec.Version, Item: number, Perm: contract.CanSend, Code: contract.RefusedNotOffered},
		},
	}
	if err := c.TokensApplied(t.Context(), ack); err != nil {
		t.Fatal(err)
	}
	now, _ := c.Token(t.Context(), id)
	if len(now.Items) != 1 || len(now.Items[0].Perms) != 1 || now.Items[0].Perms[0].Perm != contract.CanRead || now.Items[0].Perms[0].GrantedBy != bobSub {
		t.Fatalf("after the refusals: %+v", now.Items)
	}
	if got := h.p.TokensApplied("wappie"); len(got) != 1 || got[0].Through != head {
		t.Fatalf("the acknowledgements kept: %+v", got)
	}
	// Mailie's refused read takes its act with it.
	mrec, _ := m.Token(t.Context(), id)
	mack := contract.TokenApplied{
		Generation: gen, Through: tokenFeed(t, m, 0).Head, AppliedAt: contract.T(h.clock.Now()), Held: []contract.TokenHeld{},
		Refused: []contract.TokenRefusal{{Token: id, Version: mrec.Version, Item: "acc_1", Perm: contract.CanRead, Code: contract.RefusedGiverNotReader}},
	}
	if err := m.TokensApplied(t.Context(), mack); err != nil {
		t.Fatal(err)
	}
	if mrec, _ = m.Token(t.Context(), id); len(mrec.Items) != 0 || mrec.RevokedAt != nil {
		t.Fatalf("mailie's record after its read was refused: %+v", mrec)
	}
	// Held revoked after a reset revokes that app's record only.
	held := contract.TokenApplied{
		Generation: gen, Through: 0, AppliedAt: contract.T(h.clock.Now()), Refused: []contract.TokenRefusal{},
		Held: []contract.TokenHeld{{Token: id, Revoked: true, Removed: []contract.HeldPerm{}}},
	}
	if err := m.TokensApplied(t.Context(), held); err != nil {
		t.Fatal(err)
	}
	if mrec, _ = m.Token(t.Context(), id); mrec.RevokedReason == nil || *mrec.RevokedReason != contract.RevokedAppHeld {
		t.Fatalf("mailie's held record: %+v", mrec)
	}
	if rec, _ = c.Token(t.Context(), id); rec.RevokedAt != nil {
		t.Fatalf("wappie's record was revoked by mailie's held: %+v", rec)
	}
	// Another generation, or a through past the head, is gone.
	ack.Generation, ack.Refused = "0199b1e0-0000-7000-8000-00000000000f", []contract.TokenRefusal{}
	mustRefusal(t, c.TokensApplied(t.Context(), ack), contract.CodeGone)
	ack.Generation, ack.Through = gen, head+100
	mustRefusal(t, c.TokensApplied(t.Context(), ack), contract.CodeGone)
}

func TestUsageIsKeptAsTheAppSentIt(t *testing.T) {
	h, c, _, id, _ := tokenSetup(t, contracttest.Options{})
	item, perm := number, contract.CanSend
	u := contract.TokenUsage{
		Used:     []contract.TokenUsed{{Token: id, Day: "2026-10-13"}},
		Refusals: []contract.UsageRefusal{{Token: id, Day: "2026-10-13", Item: &item, Perm: &perm, Code: contract.UseNoPermission, Count: 3}},
	}
	if err := c.TokenUsage(t.Context(), u); err != nil {
		t.Fatal(err)
	}
	if got := h.p.TokenUsage("wappie"); len(got) != 1 || got[0].Refusals[0].Count != 3 {
		t.Fatalf("the usage kept: %+v", got)
	}
	u.Refusals[0].Count = 0
	mustRefusal(t, c.TokenUsage(t.Context(), u), contract.CodeInvalid)
}

func TestAHeldPublisherLeavesTheTokenFeedStale(t *testing.T) {
	h, c, _, id, _ := tokenSetup(t, contracttest.Options{})
	if err := h.p.GrantToken(id, "wappie", number, contract.ItemNumber, contract.CanRead, anaSub); err != nil {
		t.Fatal(err)
	}
	head := tokenFeed(t, c, 0).Head
	if err := h.p.HoldPublishing("wappie"); err != nil {
		t.Fatal(err)
	}
	held := h.clock.Now()
	if err := h.p.RevokeToken(id, contract.RevokedInConsole); err != nil {
		t.Fatal(err)
	}
	h.clock.Add(2 * time.Hour)
	f := tokenFeed(t, c, head)
	if len(f.Items) != 0 || !f.PublishedThrough.Equal(held) {
		t.Fatalf("a held change reached the feed, or published_through moved: %+v", f)
	}
	// The GET computes and publishes now.
	rec, err := c.Token(t.Context(), id)
	if err != nil || rec.RevokedAt == nil {
		t.Fatalf("the GET: %+v %v", rec, err)
	}
	if err := h.p.Release("wappie"); err != nil {
		t.Fatal(err)
	}
	if f := tokenFeed(t, c, head); len(f.Items) != 1 || !f.PublishedThrough.Equal(h.clock.Now()) {
		t.Fatalf("after the release: %+v", f)
	}
}

func TestATokenFeedLongPollAnswersWhenARecordIsPublished(t *testing.T) {
	h, c, _, id, _ := tokenSetup(t, contracttest.Options{})
	done := make(chan contract.TokenFeed, 1)
	go func() {
		f, _ := c.Tokens(t.Context(), 0, 10)
		done <- f
	}()
	time.Sleep(100 * time.Millisecond)
	if err := h.p.GrantToken(id, "wappie", number, contract.ItemNumber, contract.CanRead, anaSub); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-done:
		if len(f.Items) != 1 {
			t.Fatalf("woken with %+v", f)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the long-poll was not woken")
	}
}

func TestARestoreStartsTheTokenFeedAgainFromZero(t *testing.T) {
	h, c, _, id, _ := tokenSetup(t, contracttest.Options{})
	if err := h.p.GrantToken(id, "wappie", number, contract.ItemNumber, contract.CanRead, anaSub); err != nil {
		t.Fatal(err)
	}
	gen := h.p.Restore()
	mustRefusal(t, func() error { _, err := c.Tokens(t.Context(), 1, 0); return err }(), contract.CodeGone)
	if _, err := c.Subscribe(t.Context(), anaSub); err != nil {
		t.Fatal(err)
	}
	f := tokenFeed(t, c, 0)
	if len(f.Items) != 1 || f.Generation != gen || record(t, f.Items[0]).Generation != gen || f.GenerationConfirmed {
		t.Fatalf("after the restore: %+v", f)
	}
}

// A selector GET spends none of the app's rate: with the app's 50 a second
// and the selector's 3, fifty selector GETs in a second get three answers
// and 47 signed rate_limited, and then the app's own 50 calls all get
// through.
func TestASelectorGETSpendsNoneOfTheAppsRate(t *testing.T) {
	h, c, _, _, text := tokenSetup(t, contracttest.Options{PerSecond: 50, SelectorPerSecond: 3})
	p, _ := contract.ParseToken(text)
	h.clock.Add(time.Second) // tokenSetup spent some of the 50
	for i := 0; i < 50; i++ {
		mustRefusal(t, func() error { _, err := c.TokenBySelector(t.Context(), p.Selector); return err }(), func() string {
			if i < 3 {
				return contract.CodeNotFound
			}
			return contract.CodeRateLimited
		}())
	}
	// Fifty selector GETs in a second, three answered and 47 refused
	// signed: the app's 50 are untouched.
	for i := 0; i < 50; i++ {
		if _, err := c.Tokens(t.Context(), 0, 0); err != nil {
			t.Fatalf("call %d of the app's 50: %v", i+1, err)
		}
	}
}

// The token part's two bodies are read up to 256 KiB, that much included:
// one byte more is too_large, unsigned, before the signature.
func TestATokenBodyOfTwoHundredFiftySixKiBIsReadAndOneByteMoreIsNot(t *testing.T) {
	// The bodies below are built from the constant, so the constant itself
	// is pinned: moving it fails here.
	if contracttest.TokensBodyLimit != 256<<10 {
		t.Fatalf("TokensBodyLimit is %d, not 256 KiB", contracttest.TokensBodyLimit)
	}
	h, _, _, _, _ := tokenSetup(t, contracttest.Options{})
	const body = `{"used":[],"refusals":[]}`
	for _, target := range []string{"/contract/v1/tokens/usage", "/contract/v1/tokens/applied"} {
		at := strings.Repeat(" ", contracttest.TokensBodyLimit-len(body)) + body
		c := call{method: http.MethodPost, target: target, app: "wappie", body: at}
		a := h.send(t, c)
		if a.status == http.StatusRequestEntityTooLarge {
			t.Fatalf("%s: a body of exactly 256 KiB is too_large", target)
		}
		h.verified(t, a, []string{secretA}, "wappie", http.MethodPost, target)
		over := " " + at
		h.send(t, call{method: http.MethodPost, target: target, app: "wappie", body: over}).
			wantUnsigned(t, http.StatusRequestEntityTooLarge, contract.CodeTooLarge)
	}
}

// The client sends an acknowledgement's and a usage report's nil lists as
// [], since they are always present.
func TestTheClientSendsNilListsAsEmpty(t *testing.T) {
	h, c, _, _, _ := tokenSetup(t, contracttest.Options{})
	gen, _ := h.p.Generation()
	if err := c.TokensApplied(t.Context(), contract.TokenApplied{Generation: gen, AppliedAt: contract.T(h.clock.Now())}); err != nil {
		t.Fatalf("an acknowledgement with nil lists: %v", err)
	}
	if got := h.p.TokensApplied("wappie"); len(got) != 1 || got[0].Refused == nil || got[0].Held == nil {
		t.Fatalf("kept: %+v", got)
	}
	if err := c.TokenUsage(t.Context(), contract.TokenUsage{}); err != nil {
		t.Fatalf("a usage report with nil lists: %v", err)
	}
	if got := h.p.TokenUsage("wappie"); len(got) != 1 || got[0].Used == nil || got[0].Refusals == nil {
		t.Fatalf("kept: %+v", got)
	}
}
