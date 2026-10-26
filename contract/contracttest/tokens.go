package contracttest

// The token part (SPEC section 11.18): tokens a test makes, each app's
// records of them in its token feed, the signed GETs, and what the app
// sends back. A token's record reaches an app only once the token names the
// app and its workspace is named to the app, as on the platform. Times are
// the fake's clock (Options.Now), so a test sets a token's expiry against
// the clock it gives the app.
//
// Where the platform does more, the fake is simpler:
//   - it keeps every record in the app's feed for good, where the platform
//     keeps one until its token's created_at plus 365 days, and the GET
//     answers an app taken off a token for good;
//   - it checks no giver's reading before a grant, nor key terms, nor the
//     registry's offer: a test gives what it means the app to judge;
//   - it keeps every version of a record it published, to judge a refusal
//     by the version it names.

import (
	"bytes"
	"cmp"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/thehappieco/kit/contract"
)

// token is one token, as the platform keeps it.
type token struct {
	id, selector, hash, workspace, name, creator string
	createdAt, expiresAt                         time.Time
	revokedAt                                    *time.Time
	reason                                       string
	readingKey                                   *contract.ReadingKey
	apps                                         map[string]*tokenOnApp
	order                                        []string // the apps, in the order they were added
}

// tokenOnApp is one app's part of a token.
type tokenOnApp struct {
	items     []contract.TokenItem
	terms     *contract.TokenTerms
	revokedAt *time.Time // app_removed, app_held
	reason    string
	expiresAt *time.Time // an earlier expiry an app held after a reset
}

// tokenApp is an app's token feed, and what it sent back.
type tokenApp struct {
	tokenHead    int64
	tokenRecs    map[string]contract.TokenRecord           // the latest, by token id; Version is its seq
	tokenHistory map[string]map[int64]contract.TokenRecord // every version, by token id
	tokenWake    chan struct{}
	tokenPolls   chan struct{}
	tokenMarks   map[string]time.Time // held changes, by token id

	selectorTokens  float64
	selectorMetered time.Time

	acks  []contract.TokenApplied
	usage []contract.TokenUsage
}

func newTokenApp(longPolls int, selectorRate float64, now time.Time) tokenApp {
	return tokenApp{
		tokenRecs: map[string]contract.TokenRecord{}, tokenHistory: map[string]map[int64]contract.TokenRecord{},
		tokenWake: make(chan struct{}), tokenPolls: make(chan struct{}, longPolls), tokenMarks: map[string]time.Time{},
		selectorTokens: selectorRate, selectorMetered: now,
	}
}

// resetTokens is Restore's: the app's token feed starts again from 0, with
// no record in it; the tokens stay, and their records come again once their
// workspaces are named to the app again.
func (a *tokenApp) resetTokens() {
	a.tokenHead = 0
	a.tokenRecs, a.tokenHistory, a.tokenMarks = map[string]contract.TokenRecord{}, map[string]map[int64]contract.TokenRecord{}, map[string]time.Time{}
	a.acks, a.usage = nil, nil
}

// isSelectorGET reports whether r is a selector GET, which spends none of
// the app's rate and a bucket of its own once its signature holds: told by
// its method and raw path alone, a selector of 16 lowercase hex digits, so
// that any other path spends the app's rate as every call does.
func isSelectorGET(r *http.Request) bool {
	path, _, _ := strings.Cut(r.RequestURI, "?")
	sel, ok := strings.CutPrefix(path, "/contract/v1/token-selectors/")
	return r.Method == http.MethodGet && ok && contract.ValidSelector(sel)
}

// ---------------------------------------------------------------------------
// The directory of tokens
// ---------------------------------------------------------------------------

// AddToken makes a token of the workspace ws, created by creator and named
// name, as the console does: a fresh selector and secret, its hash kept, no
// app named yet (GrantToken names one). It lives until expiresAt, or, for
// the zero time, 365 days from now by the fake's clock. It returns the
// token's id and its text, which the platform shows once and never keeps.
func (p *Platform) AddToken(ws, creator, name string, expiresAt time.Time) (id, text string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	w := p.workspaces[ws]
	if w == nil || p.accounts[creator] == nil {
		return "", "", ErrUnknown
	}
	if _, member := w.members[creator]; !member {
		return "", "", ErrUnknown
	}
	now := atMicroseconds(p.now())
	if expiresAt.IsZero() {
		expiresAt = now.Add(contract.MaxTokenLifetime)
	}
	expiresAt = atMicroseconds(expiresAt)
	if !contract.ValidLabel(name) || !expiresAt.After(now) || expiresAt.Sub(now) > contract.MaxTokenLifetime {
		return "", "", ErrInvalid
	}
	var sel [8]byte
	var secret [contract.TokenSecretBytes]byte
	for {
		if _, err := rand.Read(sel[:]); err != nil {
			return "", "", err
		}
		if p.selectors[hex.EncodeToString(sel[:])] == "" {
			break
		}
	}
	if _, err := rand.Read(secret[:]); err != nil {
		return "", "", err
	}
	t := &token{
		id: newUUID(), selector: hex.EncodeToString(sel[:]), hash: contract.TokenHash(secret), workspace: ws, name: name,
		creator: creator, createdAt: now, expiresAt: expiresAt, apps: map[string]*tokenOnApp{},
	}
	p.tokens[t.id], p.selectors[t.selector] = t, t.id
	return t.id, contract.TokenPrefix + t.selector + "." + base64.RawURLEncoding.EncodeToString(secret[:]), nil
}

// GrantToken gives the token id the permission perm on the app's item of
// kind (contract.ItemNumber, contract.ItemMailbox), given by giver at the
// fake's clock, and publishes the app's record. The first grant for an app
// names it on the token. A permission held already is held as it was; one
// given again after UngrantToken has a new granted_at. It refuses what
// would make the record invalid (Mailie's act without read, Wappie's act).
func (p *Platform) GrantToken(id, app, item, kind, perm, giver string) error {
	return p.updateToken(id, app, true, func(t *token, ta *tokenOnApp) error {
		if !contract.ValidUUID(giver) || !contract.ValidItemID(item) {
			return ErrInvalid
		}
		i := slices.IndexFunc(ta.items, func(it contract.TokenItem) bool { return it.ID == item })
		if i < 0 {
			ta.items = append(ta.items, contract.TokenItem{ID: item, Kind: kind, Perms: []contract.TokenPerm{}})
			i = len(ta.items) - 1
		}
		if ta.items[i].Kind != kind {
			return ErrInvalid
		}
		if slices.ContainsFunc(ta.items[i].Perms, func(tp contract.TokenPerm) bool { return tp.Perm == perm }) {
			return nil
		}
		ta.items[i].Perms = append(ta.items[i].Perms, contract.TokenPerm{Perm: perm, GrantedBy: giver, GrantedAt: contract.T(atMicroseconds(p.now()))})
		return nil
	})
}

// UngrantToken takes the permission perm on the app's item away from the
// token id; taking a mailbox's read takes its act with it. An item left
// with no permission leaves the record, and a record left with no item
// stays live, so items may be given again.
func (p *Platform) UngrantToken(id, app, item, perm string) error {
	return p.updateToken(id, app, false, func(t *token, ta *tokenOnApp) error {
		removePerm(ta, item, perm)
		return nil
	})
}

// removePerm takes perm on item away, and a mailbox's act with its read.
func removePerm(ta *tokenOnApp, item, perm string) {
	for i := range ta.items {
		if ta.items[i].ID != item {
			continue
		}
		mailbox := ta.items[i].Kind == contract.ItemMailbox
		ta.items[i].Perms = slices.DeleteFunc(ta.items[i].Perms, func(tp contract.TokenPerm) bool {
			return tp.Perm == perm || (mailbox && perm == contract.CanRead && tp.Perm == contract.CanAct)
		})
	}
	ta.items = slices.DeleteFunc(ta.items, func(it contract.TokenItem) bool { return len(it.Perms) == 0 })
}

// SetTokenTerms records the key terms of revision version that the token's
// creator agreed to for app, at the fake's clock, and publishes the app's
// record. The app must be named on the token.
func (p *Platform) SetTokenTerms(id, app, version string) error {
	return p.updateToken(id, app, false, func(t *token, ta *tokenOnApp) error {
		ta.terms = &contract.TokenTerms{Version: version, AgreedAt: contract.T(atMicroseconds(p.now()))}
		return nil
	})
}

// SetReadingKey registers the token's reading key, once, as an owner or
// admin does in the console (contract.ValidReadingKey), and publishes every
// app's record. A second key is refused: to change keys, make a new token.
func (p *Platform) SetReadingKey(id, key string) error {
	fp, err := contract.ReadingKeyFingerprint(key)
	if err != nil || contract.ValidReadingKey(key) != nil {
		return ErrInvalid
	}
	return p.updateWholeToken(id, func(t *token) error {
		if t.readingKey != nil {
			return ErrExists
		}
		t.readingKey = &contract.ReadingKey{Suite: contract.ReadingKeySuite, Key: key, Fingerprint: fp, RegisteredAt: contract.T(atMicroseconds(p.now()))}
		return nil
	})
}

// ShortenToken moves the token's expiry earlier, to at: never later, and
// never to or before its creation.
func (p *Platform) ShortenToken(id string, at time.Time) error {
	at = atMicroseconds(at)
	return p.updateWholeToken(id, func(t *token) error {
		if !at.Before(t.expiresAt) || !at.After(t.createdAt) {
			return ErrInvalid
		}
		t.expiresAt = at
		return nil
	})
}

// RevokeToken revokes the token for every app it names, with reason:
// contract.RevokedInConsole or contract.RevokedOperator. The creator's
// reasons come from the directory (RemoveMember, Disable, CloseAccount,
// RevokeSessions with a recovery), and an app's own from TakeTokenOffApp
// and an acknowledgement's held. A revocation is never cleared.
func (p *Platform) RevokeToken(id, reason string) error {
	if reason != contract.RevokedInConsole && reason != contract.RevokedOperator {
		return ErrInvalid
	}
	return p.updateWholeToken(id, func(t *token) error {
		p.revokeLocked(t, reason)
		return nil
	})
}

// TakeTokenOffApp takes app off the token: that app's record is revoked
// with app_removed, so the token never works there again; the token's
// other apps keep theirs. To give the app back, make a new token.
func (p *Platform) TakeTokenOffApp(id, app string) error {
	return p.updateToken(id, app, false, func(t *token, ta *tokenOnApp) error {
		if ta.revokedAt == nil {
			at := atMicroseconds(p.now())
			ta.revokedAt, ta.reason, ta.items = &at, contract.RevokedAppRemoved, []contract.TokenItem{}
		}
		return nil
	})
}

// TokenRecord is the latest record of the token id the fake published to
// app, as it published it, with the generation; false when there is none.
func (p *Platform) TokenRecord(app, id string) (contract.TokenRecord, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil {
		return contract.TokenRecord{}, false
	}
	r, ok := st.tokenRecs[id]
	r.Generation = p.generation
	return r, ok
}

// TokensApplied are the acknowledgements of app the fake accepted, in the
// order it accepted them, as the app sent them.
func (p *Platform) TokensApplied(app string) []contract.TokenApplied {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil {
		return nil
	}
	return slices.Clone(st.acks)
}

// TokenUsage are the usage reports of app the fake accepted, in the order
// it accepted them, as the app sent them.
func (p *Platform) TokenUsage(app string) []contract.TokenUsage {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil {
		return nil
	}
	return slices.Clone(st.usage)
}

// updateToken changes app's part of the token id and publishes app's
// record. name says whether the change may name the app on the token.
func (p *Platform) updateToken(id, app string, name bool, f func(*token, *tokenOnApp) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	t, st := p.tokens[id], p.apps[app]
	if t == nil || st == nil {
		return ErrUnknown
	}
	ta := t.apps[app]
	if ta == nil {
		if !name {
			return ErrUnknown
		}
		ta = &tokenOnApp{items: []contract.TokenItem{}}
	}
	if t.revokedAt != nil || ta.revokedAt != nil {
		return ErrRevoked
	}
	// Change a copy, and keep it only if the record it makes is valid.
	next := &tokenOnApp{items: cloneItems(ta.items), terms: ta.terms, revokedAt: ta.revokedAt, reason: ta.reason, expiresAt: ta.expiresAt}
	if err := f(t, next); err != nil {
		return err
	}
	probe := *t
	probe.apps = map[string]*tokenOnApp{app: next}
	rec := p.recordOf(&probe, app)
	rec.Generation, rec.Version = p.generation, 1
	if rec.Validate() != nil {
		return ErrInvalid
	}
	if t.apps[app] == nil {
		t.order = append(t.order, app)
	}
	t.apps[app] = next
	p.publishTokenLocked(st, t)
	return nil
}

// updateWholeToken changes the token itself and publishes every app's
// record.
func (p *Platform) updateWholeToken(id string, f func(*token) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	t := p.tokens[id]
	if t == nil {
		return ErrUnknown
	}
	if t.revokedAt != nil {
		return ErrRevoked
	}
	if err := f(t); err != nil {
		return err
	}
	p.publishEverywhereLocked(t)
	return nil
}

func cloneItems(items []contract.TokenItem) []contract.TokenItem {
	out := make([]contract.TokenItem, len(items))
	for i, it := range items {
		out[i] = contract.TokenItem{ID: it.ID, Kind: it.Kind, Perms: slices.Clone(it.Perms)}
	}
	return out
}

// revokeLocked revokes the whole token, with reason, at the fake's clock.
func (p *Platform) revokeLocked(t *token, reason string) {
	if t.revokedAt != nil {
		return
	}
	at := atMicroseconds(p.now())
	t.revokedAt, t.reason = &at, reason
}

// revokeCreatorsTokensLocked revokes, with reason, the live tokens creator
// made: in the workspace ws only when it is not "", and only those created
// before *before when it is not nil. It publishes them at once, so the
// records reach the apps before the documents the same change publishes.
func (p *Platform) revokeCreatorsTokensLocked(creator, ws string, before *time.Time, reason string) {
	for _, t := range p.sortedTokens() {
		if t.creator != creator || t.revokedAt != nil || (ws != "" && t.workspace != ws) || (before != nil && !t.createdAt.Before(*before)) {
			continue
		}
		p.revokeLocked(t, reason)
		p.publishEverywhereLocked(t)
	}
}

// sortedTokens are the tokens in the order they were made, so publishing
// several follows it.
func (p *Platform) sortedTokens() []*token {
	out := make([]*token, 0, len(p.tokens))
	for _, t := range p.tokens {
		out = append(out, t)
	}
	slices.SortFunc(out, func(a, b *token) int {
		return cmp.Or(a.createdAt.Compare(b.createdAt), cmp.Compare(a.id, b.id))
	})
	return out
}

// ---------------------------------------------------------------------------
// Records and the token feed
// ---------------------------------------------------------------------------

// recordOf is the record of t for app, with no version or generation.
func (p *Platform) recordOf(t *token, app string) contract.TokenRecord {
	ta := t.apps[app]
	expires := t.expiresAt
	if ta.expiresAt != nil && ta.expiresAt.Before(expires) {
		expires = *ta.expiresAt
	}
	r := contract.TokenRecord{
		V: contract.TokenRecordV, Type: contract.TokenRecordType, App: app, ID: t.id, Selector: t.selector, Hash: t.hash,
		WorkspaceID: t.workspace, Name: t.name, CreatedBy: t.creator, CreatedAt: contract.T(t.createdAt), ExpiresAt: contract.T(expires),
		Terms: ta.terms, ReadingKey: t.readingKey, Items: cloneItems(ta.items),
	}
	switch {
	case t.revokedAt != nil:
		r.RevokedAt, r.RevokedReason = wireTime(t.revokedAt), &t.reason
	case ta.revokedAt != nil:
		r.RevokedAt, r.RevokedReason = wireTime(ta.revokedAt), &ta.reason
	}
	if r.RevokedAt != nil {
		r.Items = []contract.TokenItem{}
	}
	return r
}

// publishTokenLocked publishes app's record of t, when the token names app
// and its workspace is named to app, with the next seq of app's token feed
// when its content changed, which wakes app's long-polls; or, while app's
// publishing is held, marks it. It returns the record with its version
// and the generation, and false when there is none.
func (p *Platform) publishTokenLocked(app *appState, t *token) (contract.TokenRecord, bool) {
	if t.apps[app.id] == nil || !app.named[t.workspace] {
		return contract.TokenRecord{}, false
	}
	if app.held {
		if _, marked := app.tokenMarks[t.id]; !marked {
			if stored, ok := app.tokenRecs[t.id]; !ok || !sameRecord(stored, p.recordOf(t, app.id)) {
				app.tokenMarks[t.id] = atMicroseconds(p.now())
			}
		}
		stored, ok := app.tokenRecs[t.id]
		stored.Generation = p.generation
		return stored, ok
	}
	return p.publishTokenNowLocked(app, t), true
}

// publishTokenNowLocked publishes app's record of t whether or not app's
// publishing is held, as the GETs do.
func (p *Platform) publishTokenNowLocked(app *appState, t *token) contract.TokenRecord {
	delete(app.tokenMarks, t.id)
	rec := p.recordOf(t, app.id)
	stored, ok := app.tokenRecs[t.id]
	if !ok || !sameRecord(stored, rec) {
		app.tokenHead++
		rec.Version = app.tokenHead
		app.tokenRecs[t.id] = rec
		if app.tokenHistory[t.id] == nil {
			app.tokenHistory[t.id] = map[int64]contract.TokenRecord{}
		}
		app.tokenHistory[t.id][rec.Version] = rec
		close(app.tokenWake)
		app.tokenWake = make(chan struct{})
	} else {
		rec = stored
	}
	rec.Generation = p.generation
	return rec
}

func (p *Platform) publishEverywhereLocked(t *token) {
	for _, app := range t.order {
		if st := p.apps[app]; st != nil {
			p.publishTokenLocked(st, t)
		}
	}
}

// publishWorkspaceTokensLocked publishes app's records of the tokens of a
// workspace just named to it.
func (p *Platform) publishWorkspaceTokensLocked(app *appState, ws string) {
	for _, t := range p.sortedTokens() {
		if t.workspace == ws {
			p.publishTokenLocked(app, t)
		}
	}
}

// releaseTokensLocked publishes every token change held for app.
func (p *Platform) releaseTokensLocked(app *appState) {
	for _, t := range p.sortedTokens() {
		if _, marked := app.tokenMarks[t.id]; marked {
			p.publishTokenNowLocked(app, t)
		}
	}
}

func sameRecord(a, b contract.TokenRecord) bool {
	a.Version, a.Generation, b.Version, b.Generation = 0, "", 0, ""
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}

func (p *Platform) tokenFeed(rq *request) answer {
	if ans, ok := noBody(rq); !ok {
		return ans
	}
	after, wait, ok := feedQuery(rq.query)
	if !ok {
		return refusal(contract.CodeInvalid, "the token feed takes after and an optional wait from 0 to 25")
	}
	f, woken, ans, ok := p.readTokenFeed(rq.app, after)
	if !ok {
		return ans
	}
	if len(f.Items) > 0 || wait == 0 {
		return answer{status: http.StatusOK, body: f}
	}
	select {
	case rq.app.tokenPolls <- struct{}{}:
		defer func() { <-rq.app.tokenPolls }()
	default:
		return refusal(contract.CodeRateLimited, "too many token feed requests wait at once")
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
	f, _, ans, ok = p.readTokenFeed(rq.app, after)
	if !ok {
		return ans
	}
	return answer{status: http.StatusOK, body: f}
}

// readTokenFeed is the app's token feed after the cursor, and the channel
// its next publish closes.
func (p *Platform) readTokenFeed(app *appState, after int64) (contract.TokenFeed, <-chan struct{}, answer, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	woken := app.tokenWake
	if after > app.tokenHead {
		return contract.TokenFeed{}, woken, refusal(contract.CodeGone, "the cursor is past the token feed's head: take every record again"), false
	}
	through := p.now()
	for _, at := range app.tokenMarks {
		if at.Before(through) {
			through = at
		}
	}
	f := contract.TokenFeed{
		Generation: p.generation, GenerationConfirmed: p.confirmed, Head: app.tokenHead,
		PublishedThrough: contract.T(through), Items: []contract.TokenFeedItem{},
	}
	var recs []contract.TokenRecord
	for _, r := range app.tokenRecs {
		if r.Version > after {
			recs = append(recs, r)
		}
	}
	slices.SortFunc(recs, func(a, b contract.TokenRecord) int { return cmp.Compare(a.Version, b.Version) })
	kept, size := 0, 0
	for kept < len(recs) && kept < contract.MaxTokenFeedItems {
		b, _ := json.Marshal(recs[kept])
		if kept > 0 && size+len(b) > maxFeedPageBytes {
			break
		}
		size += len(b)
		kept++
	}
	f.More = kept < len(recs)
	recs = recs[:kept]
	for _, r := range recs {
		r.Generation = p.generation
		it, err := contract.NewTokenFeedItem(r.Version, r)
		if err != nil {
			return contract.TokenFeed{}, woken, refusal(contract.CodeUnavailable, "try again"), false
		}
		f.Items = append(f.Items, it)
	}
	f.NextAfter = max(after, f.Head)
	if f.More {
		f.NextAfter = recs[len(recs)-1].Version
	}
	return f, woken, answer{}, true
}

// tokenByID answers GET /contract/v1/tokens/{id}: the record, computed and
// published now; not_found for a token that never named the app, one
// unknown, or one of a workspace not named to the app.
func (p *Platform) tokenByID(rq *request) answer {
	if ans, ok := noBody(rq); !ok {
		return ans
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.answerToken(rq.app, p.tokens[rq.arg])
}

// tokenBySelector answers GET /contract/v1/token-selectors/{selector}.
func (p *Platform) tokenBySelector(rq *request) answer {
	if ans, ok := noBody(rq); !ok {
		return ans
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.answerToken(rq.app, p.tokens[p.selectors[rq.arg]])
}

func (p *Platform) answerToken(app *appState, t *token) answer {
	if t == nil || t.apps[app.id] == nil || !app.named[t.workspace] {
		return refusal(contract.CodeNotFound, "not found")
	}
	return answer{status: http.StatusOK, body: p.publishTokenNowLocked(app, t)}
}

// tokensApplied takes an acknowledgement: decoded strictly and valid, of
// the platform's generation and within the feed's head (else gone). Its
// refusals of a permission's grant as the named version carried it take
// that permission off the app's record, with a mailbox's act beside a
// refused read; its held entries revoke that app's record (app_held), move
// its expiry earlier and take what the app keeps off.
func (p *Platform) tokensApplied(rq *request) answer {
	var a contract.TokenApplied
	if err := decodeStrict(rq.body, &a); err != nil || a.Validate() != nil {
		return refusal(contract.CodeInvalid, "the acknowledgement is not valid")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	app := rq.app
	if a.Generation != p.generation || a.Through > app.tokenHead {
		return refusal(contract.CodeGone, "another generation, or past the token feed's head")
	}
	app.acks = append(app.acks, a)
	changed := map[string]bool{}
	for _, r := range a.Refused {
		t := p.tokens[r.Token]
		if t == nil || t.apps[app.id] == nil {
			continue
		}
		was, ok := app.tokenHistory[r.Token][r.Version]
		if !ok {
			continue
		}
		carried := grantOf(was.Items, r.Item, r.Perm)
		now := grantOf(t.apps[app.id].items, r.Item, r.Perm)
		if carried == nil || now == nil || carried.GrantedBy != now.GrantedBy || !carried.GrantedAt.Equal(now.GrantedAt.Time) {
			continue // an older grant's refusal is ignored
		}
		removePerm(t.apps[app.id], r.Item, r.Perm)
		changed[t.id] = true
	}
	for _, h := range a.Held {
		t := p.tokens[h.Token]
		if t == nil || t.apps[app.id] == nil {
			continue
		}
		ta := t.apps[app.id]
		switch {
		case h.Revoked:
			if t.revokedAt == nil && ta.revokedAt == nil {
				at := atMicroseconds(p.now())
				ta.revokedAt, ta.reason, ta.items = &at, contract.RevokedAppHeld, []contract.TokenItem{}
			}
		default:
			if h.ExpiresAt != nil && h.ExpiresAt.Before(t.expiresAt) && h.ExpiresAt.After(t.createdAt) && (ta.expiresAt == nil || h.ExpiresAt.Before(*ta.expiresAt)) {
				at := atMicroseconds(h.ExpiresAt.Time)
				ta.expiresAt = &at
			}
			for _, off := range h.Removed {
				removePerm(ta, off.Item, off.Perm)
			}
		}
		changed[t.id] = true
	}
	for _, t := range p.sortedTokens() {
		if changed[t.id] {
			p.publishTokenLocked(app, t)
		}
	}
	return answer{status: http.StatusOK, body: contract.AccessResult{Accepted: true}}
}

// grantOf is the permission perm on item, or nil.
func grantOf(items []contract.TokenItem, item, perm string) *contract.TokenPerm {
	for _, it := range items {
		if it.ID != item {
			continue
		}
		for _, tp := range it.Perms {
			if tp.Perm == perm {
				return &tp
			}
		}
	}
	return nil
}

// tokenUsage takes a usage report: decoded strictly and valid.
func (p *Platform) tokenUsage(rq *request) answer {
	var u contract.TokenUsage
	if err := decodeStrict(rq.body, &u); err != nil || u.Validate() != nil {
		return refusal(contract.CodeInvalid, "the usage is not valid")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	rq.app.usage = append(rq.app.usage, u)
	return answer{status: http.StatusOK, body: contract.AccessResult{Accepted: true}}
}
