// Package contracttest is a fake platform for the apps' tests: the six calls
// of the contract's membership part (SPEC section 11.17) over loopback
// HTTP, each request checked in the order the platform's transport checks
// it, and every answer to a request whose signature held signed with
// contract.SignAnswer, refusals included. An app's own client, or a
// contract.Client from Client, talks to it as it talks to the platform.
//
// The order a request meets the checks, as the platform's
// internal/contractapi (its reference) runs them, each refusing before the
// next one runs:
//  1. X-Happie-App exactly once, naming a configured app, else 404
//     not_found, unsigned. The fake is the platform's development transport,
//     loopback TCP, where no peer uid is read and the signature alone
//     authenticates: a test that needs the production socket's uid check
//     runs against the platform itself;
//  2. the app's rate, PerSecond requests a second, else 429 rate_limited,
//     unsigned;
//  3. the timestamp, nonce and signature headers once each, well formed,
//     and the timestamp within 60 s (reqhmac's Read), else 401
//     unauthenticated or stale_timestamp, unsigned;
//  4. the call, by method and raw path, else 404 not_found, unsigned; then
//     the body, up to the call's limit, else 413 too_large, unsigned;
//  5. the signature, by the app's current or other secret, direction
//     to-platform, over the raw request-target, else 401 unauthenticated,
//     unsigned;
//  6. the nonce, admitted once in the app's replay cache, else 401 replay,
//     signed (503 unavailable when the cache is full);
//  7. no query but on the feed, else 400 invalid_request, signed; then the
//     call itself, whose every answer is signed.
//
// Bodies are decoded as strictly as the platform decodes them: one JSON
// object of valid UTF-8, with no escape of half a UTF-16 surrogate pair
// (the platform's encoding/json/v2 refuses one, where encoding/json would
// read U+FFFD), no unknown member, no member twice, names compared exactly;
// an event in a batch that does not decode is rejected alone, and a batch
// whose text is not valid is refused whole.
//
// Behind the transport is a small, in-memory platform: accounts and their
// personal workspaces, teams and their members (AddAccount, AddTeam,
// SetRole, ...), each app's subscriptions, its feed and the workspaces
// named to it, the snapshots and events it sent (Snapshot, Events), and
// the generation (NewGeneration, Restore). A change to the directory
// publishes the documents it changes at once, so published_through is now,
// unless HoldPublishing stops the publisher for an app, as a stuck one,
// until Release. The times it keeps are at microseconds, as the platform's
// database keeps them: disabled_at, sessions_revoked_at and
// credentials_revoked_at, the oldest change a held publisher has not
// published, and an event's time for the duplicate rule (Snapshot and
// Events return what an app sent as it sent it). A feed page ends, with
// more, after 200 documents or before its documents reach half of
// contract.MaxAnswer, counted as the platform's are, by the text Postgres
// returns for them, and a long-poll answers early only for a new document.
// Refuse and Corrupt make the next answer to a call a refusal, signed as
// the platform signs it, or one an app must ignore.
//
// What it does not do: read a peer's uid, apply NFC to a label before
// cleaning it (the platform does; an app applies NFC itself, SPEC section
// 11.17), mail anyone, or keep anything beyond the test. And where the
// platform's directory does more, the fake's is simpler:
//   - CloseAccount refuses to close the last owner of an open team
//     (ErrLastOwner), where the platform hands the team, open or closed, on
//     to its longest-standing admin, else its longest-standing member, as
//     owner, published with the closing, and closes a team left with
//     nobody; a test that needs the hand-over plays it with SetRole first;
//   - a closed team may be left with no owner, by RemoveMember, SetRole or
//     CloseAccount, and ReopenTeam then refuses it;
//   - a closed account's subscription never expires: its closed document
//     stays in the app's feed until the app unsubscribes, where the
//     platform drops it after 30 days.
package contracttest

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/reqhmac"
)

// The calls, as Refuse and Corrupt name them.
const (
	CallSubscribe   = "subscribe"   // PUT /contract/v1/accounts/{sub}
	CallAccount     = "account"     // GET /contract/v1/accounts/{sub}
	CallUnsubscribe = "unsubscribe" // DELETE /contract/v1/accounts/{sub}
	CallFeed        = "feed"        // GET /contract/v1/feed?after=&wait=
	CallAccess      = "access"      // PUT /contract/v1/workspaces/{id}/access
	CallEvents      = "events"      // POST /contract/v1/events
)

// The body limits of the calls.
const (
	SmallBodyLimit    = 4 << 10
	EventsBodyLimit   = 256 << 10
	SnapshotBodyLimit = 1 << 20
)

// The defaults of Options.
const (
	DefaultPerSecond = 50
	DefaultLongPolls = 4
)

// MaxSnapshotAhead is how far ahead of the platform's clock a snapshot_seq
// may be.
const MaxSnapshotAhead = 24 * time.Hour

// App is one app the fake serves.
type App struct {
	// ID is the app's id, its X-Happie-App.
	ID string
	// Current signs the answers and is accepted on requests; Other, when
	// not empty, is accepted too, during a rotation.
	Current string `json:"-"`
	Other   string `json:"-"`
}

// String hides the secrets.
func (a App) String() string { return fmt.Sprintf("contracttest.App{ID: %q}", a.ID) }

// GoString is String, for %#v.
func (a App) GoString() string { return a.String() }

// LogValue hides the secrets from a structured log.
func (a App) LogValue() slog.Value { return slog.GroupValue(slog.String("id", a.ID)) }

// Options configure a Platform.
type Options struct {
	// Apps are the apps the fake serves. None: every request is 404.
	Apps []App
	// Now is the platform's clock (time.Now when nil): it checks request
	// timestamps, stamps answers and meters the rate.
	Now func() time.Time
	// PerSecond is each app's rate (DefaultPerSecond when 0), LongPolls the
	// most feed requests one app may have waiting at once
	// (DefaultLongPolls when 0).
	PerSecond, LongPolls int
	// StrictLabels refuses, as invalid_request, a snapshot or an event
	// whose label CleanLabel would change or whose hint is not one; the
	// platform cleans the label and drops the hint instead. For an app's
	// tests that it cleans its labels itself.
	StrictLabels bool
}

// Corruption is how Corrupt spoils an answer.
type Corruption int

// The corruptions, and the error contract.VerifyAnswer returns for each.
const (
	// Unsigned leaves out the timestamp, nonce and signature headers
	// (reqhmac.ErrMissing).
	Unsigned Corruption = iota + 1
	// AnotherNonce echoes, and signs, a nonce the request did not carry
	// (contract.ErrAnswerNonce).
	AnotherNonce
	// AnotherBody changes the body after it was signed (reqhmac.ErrBad).
	AnotherBody
	// AnotherSecret signs with a secret that is not the app's
	// (reqhmac.ErrBad).
	AnotherSecret
	// Stale stamps the answer 61 s in the past (reqhmac.ErrStale).
	Stale
)

// The refusals of the directory's methods. They never echo a value.
var (
	ErrOptions   = errors.New("contracttest: the options are not valid")
	ErrInvalid   = errors.New("contracttest: not a valid value")
	ErrUnknown   = errors.New("contracttest: no such account, workspace, member or app")
	ErrExists    = errors.New("contracttest: the account or member exists already")
	ErrLastOwner = errors.New("contracttest: an open team keeps one owner")
)

// Platform is the fake platform. Its methods are safe for concurrent use.
type Platform struct {
	now          func() time.Time
	perSecond    float64
	strictLabels bool
	server       *httptest.Server
	drain        chan struct{}
	drainOnce    sync.Once

	mu         sync.Mutex
	apps       map[string]*appState
	accounts   map[string]*account
	closed     map[string]bool // closing records, by sub
	workspaces map[string]*workspace
	created    int // workspaces made, for their order
	generation string
	confirmed  bool
}

type appState struct {
	id      string
	current string
	secrets []string
	replay  *reqhmac.ReplayCache
	polls   chan struct{}
	tokens  float64
	metered time.Time

	follows   map[string]bool
	docs      map[string]contract.AccountDoc // stored, by sub; Version is its seq
	head      int64
	named     map[string]bool
	snapshots map[string]contract.Snapshot
	events    []contract.Event
	kept      map[string]keptEvent
	wake      chan struct{}
	refuse    map[string]string
	corrupt   map[string]Corruption

	// held is HoldPublishing's: the changes not yet published, by sub, at
	// the time of the oldest.
	held  bool
	marks map[string]time.Time
}

type keptEvent struct {
	workspace, typ, item string
	at                   time.Time
}

type account struct {
	disabled                       bool
	disabledAt, revokedAt, credsAt *time.Time
	personal                       string
}

type workspace struct {
	kind     string
	name     string
	closed   bool
	wversion int64
	order    int
	members  map[string]string // by sub, its role
}

// New builds a fake platform for opts.Apps, as the platform's transport
// does: it refuses an app id that is not one, an app twice and secrets
// that are not valid (contract.CheckSecrets). Serve it with ServeHTTP, or
// use Start, which also listens.
func New(opts Options) (*Platform, error) {
	if opts.PerSecond == 0 {
		opts.PerSecond = DefaultPerSecond
	}
	if opts.LongPolls == 0 {
		opts.LongPolls = DefaultLongPolls
	}
	if opts.PerSecond < 1 || opts.LongPolls < 1 {
		return nil, fmt.Errorf("%w: the limits must be positive", ErrOptions)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	p := &Platform{
		now: opts.Now, perSecond: float64(opts.PerSecond), strictLabels: opts.StrictLabels, drain: make(chan struct{}),
		apps: map[string]*appState{}, accounts: map[string]*account{}, closed: map[string]bool{}, workspaces: map[string]*workspace{},
		generation: newUUID(), confirmed: true,
	}
	for _, a := range opts.Apps {
		switch {
		case !contract.ValidApp(a.ID):
			return nil, fmt.Errorf("%w: an app id is not one", ErrOptions)
		case p.apps[a.ID] != nil:
			return nil, fmt.Errorf("%w: %s appears twice", ErrOptions, a.ID)
		case contract.CheckSecrets(a.Current, a.Other) != nil:
			return nil, fmt.Errorf("%w: %s's secrets are not valid", ErrOptions, a.ID)
		}
		p.apps[a.ID] = &appState{
			id: a.ID, current: a.Current, secrets: contract.Secrets(a.Current, a.Other),
			replay: contract.NewReplayCache(), polls: make(chan struct{}, opts.LongPolls),
			tokens: p.perSecond, metered: p.now(),
			follows: map[string]bool{}, docs: map[string]contract.AccountDoc{}, named: map[string]bool{},
			snapshots: map[string]contract.Snapshot{}, kept: map[string]keptEvent{}, wake: make(chan struct{}),
			refuse: map[string]string{}, corrupt: map[string]Corruption{}, marks: map[string]time.Time{},
		}
	}
	return p, nil
}

// Start builds a fake platform and serves it on loopback until the test
// ends; it fails the test if opts are not valid.
func Start(tb testing.TB, opts Options) *Platform {
	tb.Helper()
	p, err := New(opts)
	if err != nil {
		tb.Fatal(err)
	}
	p.server = httptest.NewServer(p)
	tb.Cleanup(p.Close)
	return p
}

// URL is the fake's base address, http://127.0.0.1:port, for Start's
// Platform; "" for one served elsewhere.
func (p *Platform) URL() string {
	if p.server == nil {
		return ""
	}
	return p.server.URL
}

// Client is a contract.Client for app, signing with its current secret,
// against Start's Platform, on the platform's clock.
func (p *Platform) Client(app string) *contract.Client {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := &contract.Client{App: app, Base: p.URL(), Now: p.now}
	if st := p.apps[app]; st != nil {
		c.Secret = st.current
	}
	if p.server != nil {
		c.HTTP = p.server.Client()
	}
	return c
}

// Close ends every waiting long-poll and, for Start's Platform, stops
// listening.
func (p *Platform) Close() {
	p.drainOnce.Do(func() { close(p.drain) })
	if p.server != nil {
		p.server.Close()
	}
}

// SetSecrets replaces an app's secrets: current signs the answers, and
// requests signed with current or other are accepted (a rotation's steps).
func (p *Platform) SetSecrets(app, current, other string) error {
	if contract.CheckSecrets(current, other) != nil {
		return fmt.Errorf("%w: the secrets are not valid", ErrInvalid)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil {
		return ErrUnknown
	}
	st.current, st.secrets = current, contract.Secrets(current, other)
	return nil
}

// Refuse makes the next request of app to call (CallFeed, ...) that passes
// the transport's checks get the refusal code (contract.CodeGone, ...),
// with the status the contract sends it with, instead of its answer:
// signed, except the codes the platform only ever sends before a signature
// holds (contract.CodeUnauthenticated, CodeStale and CodeTooLarge), which
// go unsigned, as the platform sends them, so the client sees
// contract.ErrUnverified, never a *contract.Refusal.
func (p *Platform) Refuse(app, call, code string) error {
	if _, ok := statusOf[code]; !ok || !calls[call] {
		return ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil {
		return ErrUnknown
	}
	st.refuse[call] = code
	return nil
}

// Corrupt spoils the next signed answer to app's call, as how says.
func (p *Platform) Corrupt(app, call string, how Corruption) error {
	if how < Unsigned || how > Stale || !calls[call] {
		return ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil {
		return ErrUnknown
	}
	st.corrupt[call] = how
	return nil
}

var calls = map[string]bool{CallSubscribe: true, CallAccount: true, CallUnsubscribe: true, CallFeed: true, CallAccess: true, CallEvents: true}

// unsignedOnly are the codes the platform sends only before a request's
// signature holds, so never signed.
var unsignedOnly = map[string]bool{contract.CodeUnauthenticated: true, contract.CodeStale: true, contract.CodeTooLarge: true}

// statusOf is the HTTP status the platform sends with a code.
var statusOf = map[string]int{
	contract.CodeUnauthenticated: http.StatusUnauthorized,
	contract.CodeStale:           http.StatusUnauthorized,
	contract.CodeReplay:          http.StatusUnauthorized,
	contract.CodeInvalid:         http.StatusBadRequest,
	contract.CodeNotFound:        http.StatusNotFound,
	contract.CodeGone:            http.StatusGone,
	contract.CodeConflict:        http.StatusConflict,
	contract.CodeTooLarge:        http.StatusRequestEntityTooLarge,
	contract.CodeRateLimited:     http.StatusTooManyRequests,
	contract.CodeUnavailable:     http.StatusServiceUnavailable,
}

// ---------------------------------------------------------------------------
// The transport
// ---------------------------------------------------------------------------

type route struct {
	name  string
	limit int64
	serve func(p *Platform, rq *request) answer
}

type request struct {
	ctx   context.Context
	app   *appState
	query string
	arg   string
	body  []byte
}

type answer struct {
	status int
	body   any
}

func refusal(code, message string) answer {
	return answer{status: statusOf[code], body: contract.Error{Code: code, Message: message}}
}

// match finds the call for a method and a raw path, and its UUID argument.
func match(method, path string) (route, string, bool) {
	rest, ok := strings.CutPrefix(path, "/contract/v1/")
	if !ok {
		return route{}, "", false
	}
	switch {
	case rest == "feed":
		if method == http.MethodGet {
			return route{CallFeed, SmallBodyLimit, (*Platform).feed}, "", true
		}
	case rest == "events":
		if method == http.MethodPost {
			return route{CallEvents, EventsBodyLimit, (*Platform).postEvents}, "", true
		}
	case strings.HasPrefix(rest, "accounts/"):
		sub := strings.TrimPrefix(rest, "accounts/")
		if !contract.ValidUUID(sub) {
			return route{}, "", false
		}
		switch method {
		case http.MethodPut:
			return route{CallSubscribe, SmallBodyLimit, (*Platform).subscribe}, sub, true
		case http.MethodGet:
			return route{CallAccount, SmallBodyLimit, (*Platform).account}, sub, true
		case http.MethodDelete:
			return route{CallUnsubscribe, SmallBodyLimit, (*Platform).unsubscribe}, sub, true
		}
	case strings.HasPrefix(rest, "workspaces/"):
		ws, tail, ok := strings.Cut(strings.TrimPrefix(rest, "workspaces/"), "/")
		if ok && tail == "access" && contract.ValidUUID(ws) && method == http.MethodPut {
			return route{CallAccess, SnapshotBodyLimit, (*Platform).access}, ws, true
		}
	}
	return route{}, "", false
}

// ServeHTTP takes a request through the steps of the package's comment,
// then its call.
func (p *Platform) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	now := p.now()
	// 1: the app.
	app := p.appOf(r)
	if app == nil {
		unsigned(w, contract.CodeNotFound, "not found")
		return
	}
	// 2: the app's rate.
	if !p.allow(app, now) {
		unsigned(w, contract.CodeRateLimited, "too many requests")
		return
	}
	// 3: the signature's headers and the time.
	scheme := contract.Scheme()
	got, err := scheme.Read(r.Header, now)
	if err != nil {
		if errors.Is(err, contract.ErrStale) {
			unsigned(w, contract.CodeStale, "the timestamp is not within a minute")
			return
		}
		unsigned(w, contract.CodeUnauthenticated, "the request is not signed")
		return
	}
	// 4: the call, by the raw request-target, then the body.
	target := r.RequestURI
	path, query, _ := strings.Cut(target, "?")
	rt, arg, found := match(r.Method, path)
	if !strings.HasPrefix(target, "/") || !found {
		unsigned(w, contract.CodeNotFound, "no such call")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, rt.limit+1))
	if err != nil {
		unsigned(w, contract.CodeInvalid, "the body could not be read")
		return
	}
	if int64(len(body)) > rt.limit {
		unsigned(w, contract.CodeTooLarge, "the body is too large")
		return
	}
	// 5: the signature.
	p.mu.Lock()
	secrets, current := app.secrets, app.current
	p.mu.Unlock()
	if !scheme.SignedBy(secrets, got, contract.ToPlatform, app.id, r.Method, target, body) {
		unsigned(w, contract.CodeUnauthenticated, "the signature does not hold")
		return
	}
	sign := func(ans answer) {
		p.signed(w, app, rt.name, current, r.Method, target, got.Nonce, ans)
	}
	// 6: the nonce, once.
	if err := app.replay.Admit(contract.ToPlatform, app.id, got.Nonce, got.Unix, now); err != nil {
		if errors.Is(err, contract.ErrReplayFull) {
			sign(refusal(contract.CodeUnavailable, "try again"))
			return
		}
		sign(refusal(contract.CodeReplay, "the nonce was used"))
		return
	}
	// 7: no query but the feed's, then the call.
	if rt.name != CallFeed && strings.Contains(target, "?") {
		sign(refusal(contract.CodeInvalid, "this call takes no query"))
		return
	}
	p.mu.Lock()
	code, refused := app.refuse[rt.name]
	delete(app.refuse, rt.name)
	p.mu.Unlock()
	if refused {
		if unsignedOnly[code] {
			unsigned(w, code, "refused by the test")
			return
		}
		sign(refusal(code, "refused by the test"))
		return
	}
	ans := rt.serve(p, &request{ctx: r.Context(), app: app, query: query, arg: arg, body: body})
	if r.Context().Err() != nil {
		return // the app went away; nothing reaches it
	}
	sign(ans)
}

// appOf is step 1: the configured app X-Happie-App names, exactly once.
func (p *Platform) appOf(r *http.Request) *appState {
	values := r.Header.Values(contract.HeaderApp)
	if len(values) != 1 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.apps[values[0]]
}

// allow spends one of app's tokens: a burst of PerSecond, refilled at
// PerSecond a second.
func (p *Platform) allow(app *appState, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if elapsed := now.Sub(app.metered).Seconds(); elapsed > 0 {
		app.tokens = min(p.perSecond, app.tokens+elapsed*p.perSecond)
	}
	app.metered = now
	if app.tokens < 1 {
		return false
	}
	app.tokens--
	return true
}

// unsigned answers a request whose signature did not hold, or was never
// read: an app trusts nothing in it.
func unsigned(w http.ResponseWriter, code, message string) {
	body := marshal(contract.Error{Code: code, Message: message})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(statusOf[code])
	_, _ = w.Write(body)
}

// signed answers a request whose signature held, signed with the app's
// current secret over the request's method, target and nonce, unless the
// test asked to corrupt it.
func (p *Platform) signed(w http.ResponseWriter, app *appState, call, secret, method, target, nonce string, ans answer) {
	body := marshal(ans.body)
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	p.mu.Lock()
	how := app.corrupt[call]
	delete(app.corrupt, call)
	p.mu.Unlock()
	now := p.now()
	switch how {
	case Unsigned:
	case AnotherNonce:
		contract.SignAnswer(h, secret, app.id, method, target, otherNonce(nonce), body, now)
	case AnotherSecret:
		contract.SignAnswer(h, otherSecret(secret), app.id, method, target, nonce, body, now)
	case Stale:
		contract.SignAnswer(h, secret, app.id, method, target, nonce, body, now.Add(-contract.Skew-time.Second))
	case AnotherBody:
		contract.SignAnswer(h, secret, app.id, method, target, nonce, body, now)
		body = append(bytes.TrimSuffix(body, []byte("}")), []byte(`,"x":1}`)...)
	default:
		contract.SignAnswer(h, secret, app.id, method, target, nonce, body, now)
	}
	w.WriteHeader(ans.status)
	_, _ = w.Write(body)
}

// marshal writes v as the platform does: compact, with no HTML escaping.
func marshal(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return []byte(`{"code":"unavailable","message":"try again"}`)
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

func otherNonce(n string) string {
	if strings.HasPrefix(n, "A") {
		return "B" + n[1:]
	}
	return "A" + n[1:]
}

func otherSecret(s string) string {
	if strings.HasPrefix(s, "A") {
		return "B" + s[1:]
	}
	return "A" + s[1:]
}

// noBody refuses a call that takes no body and got one.
func noBody(rq *request) (answer, bool) {
	if len(rq.body) != 0 {
		return refusal(contract.CodeInvalid, "this call takes no body"), false
	}
	return answer{}, true
}

// ---------------------------------------------------------------------------
// Strict decoding
// ---------------------------------------------------------------------------

var errNotStrict = errors.New("contracttest: not one JSON object of the contract")

// memberName is every member name of the contract: lowercase letters and
// underscores. A name outside it is no member, so the case-insensitive
// matching of encoding/json never sees one that differs from a member's
// in case alone.
var memberName = regexp.MustCompile(`^[a-z_]+$`)

// checkJSON reads raw as one JSON object of valid UTF-8, with no escape of
// half a surrogate pair, no member twice in any object, and nothing after
// it; the names of the objects nested at most namesDepth deep must be
// member names.
func checkJSON(raw []byte, namesDepth int) error {
	if !utf8.Valid(raw) || loneSurrogate(raw) {
		return errNotStrict
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return errNotStrict
	}
	if err := walkObject(dec, 1, namesDepth); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errNotStrict
	}
	return nil
}

// loneSurrogate reports whether a string of the JSON text raw escapes half
// a UTF-16 surrogate pair: a \uD800 to \uDBFF not followed at once by a
// \uDC00 to \uDFFF, or a \uDC00 to \uDFFF on its own. The platform's
// encoding/json/v2 refuses such text; encoding/json reads U+FFFD. Only the
// strings are read, and in them a backslash always starts an escape, so an
// escaped backslash before a "u" is never taken for one. Text that is not
// JSON is the decoder's to refuse.
func loneSurrogate(raw []byte) bool {
	inString := false
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case !inString:
			inString = c == '"'
		case c == '"':
			inString = false
		case c == '\\':
			r, ok := escapedUnit(raw[i:])
			if !ok {
				i++ // a two-character escape, or one the decoder refuses
				continue
			}
			i += 5
			switch {
			case r >= 0xdc00 && r <= 0xdfff:
				return true
			case r >= 0xd800 && r <= 0xdbff:
				low, ok := escapedUnit(raw[i+1:])
				if !ok || low < 0xdc00 || low > 0xdfff {
					return true
				}
				i += 6
			}
		}
	}
	return false
}

// escapedUnit reads the \uXXXX escape b starts with.
func escapedUnit(b []byte) (rune, bool) {
	if len(b) < 6 || b[0] != '\\' || b[1] != 'u' {
		return 0, false
	}
	var r rune
	for _, c := range b[2:6] {
		switch {
		case c >= '0' && c <= '9':
			r = r<<4 | rune(c-'0')
		case c >= 'a' && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			r = r<<4 | rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return r, true
}

// walkObject reads the members of an object whose '{' was read.
func walkObject(dec *json.Decoder, depth, namesDepth int) error {
	seen := map[string]bool{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return errNotStrict
		}
		if tok == json.Delim('}') {
			return nil
		}
		name, ok := tok.(string)
		if !ok || seen[name] || (depth <= namesDepth && !memberName.MatchString(name)) {
			return errNotStrict
		}
		seen[name] = true
		if err := walkValue(dec, depth, namesDepth); err != nil {
			return err
		}
	}
}

// walkValue reads one value inside an object nested depth deep.
func walkValue(dec *json.Decoder, depth, namesDepth int) error {
	tok, err := dec.Token()
	if err != nil {
		return errNotStrict
	}
	switch tok {
	case json.Delim('{'):
		return walkObject(dec, depth+1, namesDepth)
	case json.Delim('['):
		for dec.More() {
			if err := walkValue(dec, depth, namesDepth); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return errNotStrict
		}
	}
	return nil
}

// decodeStrict decodes one object of the contract into dst.
func decodeStrict(raw []byte, dst any) error {
	if err := checkJSON(raw, 1<<30); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

// ---------------------------------------------------------------------------
// The calls
// ---------------------------------------------------------------------------

func (p *Platform) subscribe(rq *request) answer {
	if ans, ok := noBody(rq); !ok {
		return ans
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.accounts[rq.arg] == nil && !p.closed[rq.arg] {
		return refusal(contract.CodeNotFound, "not found")
	}
	rq.app.follows[rq.arg] = true
	return answer{status: http.StatusOK, body: p.publishLocked(rq.app, rq.arg)}
}

func (p *Platform) account(rq *request) answer {
	if ans, ok := noBody(rq); !ok {
		return ans
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !rq.app.follows[rq.arg] || (p.accounts[rq.arg] == nil && !p.closed[rq.arg]) {
		return refusal(contract.CodeNotFound, "not found")
	}
	return answer{status: http.StatusOK, body: p.publishLocked(rq.app, rq.arg)}
}

func (p *Platform) unsubscribe(rq *request) answer {
	if ans, ok := noBody(rq); !ok {
		return ans
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(rq.app.follows, rq.arg)
	delete(rq.app.docs, rq.arg)
	delete(rq.app.marks, rq.arg)
	return answer{status: http.StatusOK, body: struct {
		Subscribed bool `json:"subscribed"`
	}{false}}
}

// feedQuery reads ?after={seq}&wait={0..25}, as the platform does: after
// required, wait optional, each once, as decimals with no sign or leading
// zero, never percent-decoded.
func feedQuery(raw string) (after int64, wait int, ok bool) {
	parts := strings.Split(raw, "&")
	if len(parts) > 2 {
		return 0, 0, false
	}
	seen := map[string]string{}
	for _, part := range parts {
		k, v, found := strings.Cut(part, "=")
		if !found || (k != "after" && k != "wait") || seen[k] != "" || v == "" {
			return 0, 0, false
		}
		seen[k] = v
	}
	if seen["after"] == "" {
		return 0, 0, false
	}
	after, ok = decimal(seen["after"], 1<<62)
	if !ok {
		return 0, 0, false
	}
	if w := seen["wait"]; w != "" {
		n, ok := decimal(w, contract.MaxWait)
		if !ok {
			return 0, 0, false
		}
		wait = int(n)
	}
	return after, wait, true
}

// decimal reads a non-negative decimal of at most max, with no sign, space
// or leading zero.
func decimal(s string, max int64) (int64, bool) {
	if s == "" || len(s) > 19 || (len(s) > 1 && s[0] == '0') ||
		strings.ContainsFunc(s, func(c rune) bool { return c < '0' || c > '9' }) {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil && n <= max
}

func (p *Platform) feed(rq *request) answer {
	if ans, ok := noBody(rq); !ok {
		return ans
	}
	after, wait, ok := feedQuery(rq.query)
	if !ok {
		return refusal(contract.CodeInvalid, "the feed takes after and an optional wait from 0 to 25")
	}
	// The channel is taken before the read, so a document published
	// between the two still wakes this request.
	f, woken, ans, ok := p.readFeed(rq.app, after)
	if !ok {
		return ans
	}
	if len(f.Items) > 0 || wait == 0 {
		return answer{status: http.StatusOK, body: f}
	}
	select {
	case rq.app.polls <- struct{}{}:
		defer func() { <-rq.app.polls }()
	default:
		return refusal(contract.CodeRateLimited, "too many feed requests wait at once")
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
	f, _, ans, ok = p.readFeed(rq.app, after)
	if !ok {
		return ans
	}
	return answer{status: http.StatusOK, body: f}
}

// readFeed is the app's feed after the cursor, and the channel its next
// publish closes.
func (p *Platform) readFeed(app *appState, after int64) (contract.Feed, <-chan struct{}, answer, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	woken := app.wake
	if after > app.head {
		return contract.Feed{}, woken, refusal(contract.CodeGone, "the cursor is past the feed's head: take every document again"), false
	}
	// published_through is the oldest change not yet published, or now.
	through := p.now()
	for _, at := range app.marks {
		if at.Before(through) {
			through = at
		}
	}
	f := contract.Feed{
		Generation: p.generation, GenerationConfirmed: p.confirmed, Head: app.head,
		PublishedThrough: contract.T(through), Items: []contract.FeedItem{},
	}
	var docs []contract.AccountDoc
	for _, d := range app.docs {
		if d.Version > after {
			docs = append(docs, d)
		}
	}
	slices.SortFunc(docs, func(a, b contract.AccountDoc) int { return cmp.Compare(a.Version, b.Version) })
	// At most MaxFeedItems documents, and no more bytes than
	// maxFeedPageBytes once there is one, each measured as the platform
	// measures what it stores (storedLen, with no generation).
	kept, size := 0, 0
	for kept < len(docs) && kept < contract.MaxFeedItems {
		stored := storedLen(docs[kept])
		if kept > 0 && size+stored > maxFeedPageBytes {
			break
		}
		size += stored
		kept++
	}
	f.More = kept < len(docs)
	docs = docs[:kept]
	for _, d := range docs {
		d.Generation = p.generation
		f.Items = append(f.Items, contract.FeedItem{Seq: d.Version, Doc: d})
	}
	f.NextAfter = max(after, f.Head)
	if f.More {
		f.NextAfter = docs[len(docs)-1].Version
	}
	return f, woken, answer{}, true
}

// cleanLabel applies the platform's backstop to the labels and hints of a
// snapshot or an event, or, with StrictLabels, refuses what it would mend.
func (p *Platform) cleanLabel(label, hint **string) bool {
	if *label != nil {
		c := contract.CleanLabel(**label)
		switch {
		case p.strictLabels && c != **label:
			return false
		case c == "":
			*label = nil
		default:
			*label = &c
		}
	}
	if *hint != nil && !contract.ValidHint(**hint) {
		if p.strictLabels {
			return false
		}
		*hint = nil
	}
	return true
}

func (p *Platform) access(rq *request) answer {
	var snap contract.Snapshot
	if err := decodeStrict(rq.body, &snap); err != nil {
		return refusal(contract.CodeInvalid, "the snapshot is not valid")
	}
	// Validated as the platform cleans it; kept as the app sent it.
	cleaned := snap
	cleaned.Items = slices.Clone(snap.Items)
	for i := range cleaned.Items {
		if !p.cleanLabel(&cleaned.Items[i].Label, &cleaned.Items[i].Hint) {
			return refusal(contract.CodeInvalid, "the request is not valid")
		}
	}
	if cleaned.Validate() != nil || cleaned.SnapshotSeq > p.now().Add(MaxSnapshotAhead).UnixMilli() {
		return refusal(contract.CodeInvalid, "the request is not valid")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ws := p.workspaces[rq.arg]
	if ws == nil || !rq.app.named[rq.arg] {
		return refusal(contract.CodeNotFound, "not found")
	}
	if ws.kind == contract.KindPersonal && ws.closed {
		// A closed personal workspace's account is closed: accepted, and
		// not kept.
		delete(rq.app.snapshots, rq.arg)
		return answer{status: http.StatusOK, body: contract.AccessResult{Accepted: true}}
	}
	if old, ok := rq.app.snapshots[rq.arg]; !ok || old.SnapshotSeq < snap.SnapshotSeq {
		rq.app.snapshots[rq.arg] = snap
	}
	return answer{status: http.StatusOK, body: contract.AccessResult{Accepted: true}}
}

func (p *Platform) postEvents(rq *request) answer {
	var batch struct {
		Events []json.RawMessage `json:"events"`
	}
	if checkJSON(rq.body, 1) != nil {
		return refusal(contract.CodeInvalid, "a batch holds 1 to 100 events")
	}
	dec := json.NewDecoder(bytes.NewReader(rq.body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&batch); err != nil || len(batch.Events) == 0 || len(batch.Events) > contract.MaxEvents {
		return refusal(contract.CodeInvalid, "a batch holds 1 to 100 events")
	}
	results := make([]contract.EventResult, len(batch.Events))
	for i, raw := range batch.Events {
		var ev contract.Event
		if err := decodeStrict(raw, &ev); err != nil {
			results[i] = rejected(eventID(raw), contract.CodeInvalid)
			continue
		}
		results[i] = p.postEvent(rq.app, ev)
	}
	return answer{status: http.StatusOK, body: contract.EventResults{Results: results}}
}

func rejected(id, code string) contract.EventResult {
	return contract.EventResult{EventID: id, Outcome: contract.OutcomeRejected, Code: &code}
}

// eventID is the event_id of an event that did not decode, when it holds a
// UUID; "" otherwise.
func eventID(raw json.RawMessage) string {
	var members map[string]json.RawMessage
	var id string
	if json.Unmarshal(raw, &members) != nil || json.Unmarshal(members["event_id"], &id) != nil || !contract.ValidUUID(id) {
		return ""
	}
	return id
}

func (p *Platform) postEvent(app *appState, ev contract.Event) contract.EventResult {
	sent := ev
	if !p.cleanLabel(&ev.Item.Label, &ev.Item.Hint) || ev.Validate() != nil {
		return rejected(ev.EventID, contract.CodeInvalid)
	}
	// The platform keeps microseconds: a retry of the same event, with the
	// wire's nanoseconds, is the duplicate it is.
	at := atMicroseconds(ev.OccurredAt.Time)
	p.mu.Lock()
	defer p.mu.Unlock()
	if !app.named[ev.WorkspaceID] {
		return rejected(ev.EventID, contract.CodeNotFound)
	}
	if k, ok := app.kept[ev.EventID]; ok {
		if k.workspace == ev.WorkspaceID && k.typ == ev.Type && k.item == ev.Item.ID && k.at.Equal(at) {
			return contract.EventResult{EventID: ev.EventID, Outcome: contract.OutcomeDuplicate}
		}
		return rejected(ev.EventID, contract.CodeConflict)
	}
	app.kept[ev.EventID] = keptEvent{workspace: ev.WorkspaceID, typ: ev.Type, item: ev.Item.ID, at: at}
	app.events = append(app.events, sent)
	return contract.EventResult{EventID: ev.EventID, Outcome: contract.OutcomeAccepted}
}

// ---------------------------------------------------------------------------
// Documents and the feed
// ---------------------------------------------------------------------------

// documentLocked computes the document of sub for app. Generation and
// Version are the caller's, and so is naming its workspaces to app.
func (p *Platform) documentLocked(app *appState, sub string) (contract.AccountDoc, bool) {
	doc := contract.AccountDoc{V: contract.DocV, Type: contract.DocType, App: app.id, Sub: sub, Workspaces: []contract.Workspace{}}
	a := p.accounts[sub]
	if a == nil {
		if !p.closed[sub] {
			return doc, false
		}
		doc.Status = contract.AccountClosed
		return doc, true
	}
	doc.Status = contract.AccountActive
	if a.disabled {
		doc.Status = contract.AccountDisabled
	}
	doc.DisabledAt, doc.SessionsRevokedAt, doc.CredentialsRevokedAt = wireTime(a.disabledAt), wireTime(a.revokedAt), wireTime(a.credsAt)
	var ids []string
	for id, w := range p.workspaces {
		if _, member := w.members[sub]; member {
			ids = append(ids, id)
		}
	}
	// The personal workspace first, then in the order they were made.
	slices.SortFunc(ids, func(a, b string) int {
		wa, wb := p.workspaces[a], p.workspaces[b]
		if (wa.kind == contract.KindPersonal) != (wb.kind == contract.KindPersonal) {
			if wa.kind == contract.KindPersonal {
				return -1
			}
			return 1
		}
		return cmp.Compare(wa.order, wb.order)
	})
	for _, id := range ids {
		w := p.workspaces[id]
		out := contract.Workspace{ID: id, Kind: w.kind, Role: w.members[sub], Status: contract.StatusOpen, WVersion: w.wversion}
		if w.closed {
			out.Status = contract.StatusClose
		}
		if w.kind == contract.KindTeam {
			name, owners := w.name, 0
			for _, role := range w.members {
				if role == contract.RoleOwner {
					owners++
				}
			}
			out.Name, out.Owners = &name, &owners
		}
		doc.Workspaces = append(doc.Workspaces, out)
	}
	return doc, true
}

func wireTime(t *time.Time) *contract.Time {
	if t == nil {
		return nil
	}
	w := contract.T(*t)
	return &w
}

// publishLocked computes the document of sub for app, which follows it,
// names its workspaces to app, and stores it with the next seq of app's
// feed when its content changed, which wakes app's long-polls; the same
// document again wakes none. It returns the document with its version and
// the generation. The changes held for sub are published with it.
func (p *Platform) publishLocked(app *appState, sub string) contract.AccountDoc {
	doc, _ := p.documentLocked(app, sub)
	for _, w := range doc.Workspaces {
		app.named[w.ID] = true
	}
	delete(app.marks, sub)
	stored, ok := app.docs[sub]
	if !ok || !sameContent(stored, doc) {
		app.head++
		doc.Version = app.head
		app.docs[sub] = doc
		close(app.wake)
		app.wake = make(chan struct{})
	} else {
		doc.Version = stored.Version
	}
	doc.Generation = p.generation
	return doc
}

func sameContent(a, b contract.AccountDoc) bool {
	a.Version, a.Generation, b.Version, b.Generation = 0, "", 0, ""
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}

// republishLocked publishes, for every app, the document of every account
// it follows: what a change to the directory marks. For an app whose
// publishing is held, it marks the accounts whose document changed instead,
// each at the time of its oldest change not yet published.
func (p *Platform) republishLocked() {
	for _, app := range p.apps {
		for sub := range app.follows {
			if !app.held {
				p.publishLocked(app, sub)
				continue
			}
			if _, marked := app.marks[sub]; marked {
				continue
			}
			doc, _ := p.documentLocked(app, sub)
			if stored, ok := app.docs[sub]; !ok || !sameContent(stored, doc) {
				app.marks[sub] = atMicroseconds(p.now())
			}
		}
	}
}

// maxFeedPageBytes bounds the documents of a feed page, as the platform's
// does: half of what a client reads at most (contract.MaxAnswer), counted
// by storedLen. A first document over it still comes alone. The package's
// tests shorten it.
var maxFeedPageBytes = contract.MaxAnswer / 2

// storedLen is what the platform counts of d against a page's bound: the
// length of the text Postgres returns for the jsonb column that holds it,
// not of the json.Marshal the platform stored. That text has a space after
// every ':' and ',' between values, about a tenth more than compact JSON,
// and writes as itself each character json.Marshal escapes and jsonb does
// not: '<', '>' and '&', U+2028 and U+2029, and the U+FFFD json.Marshal
// writes for a byte that is not UTF-8. Both escape '"', '\' and the
// control characters alike, and the keys jsonb sorts change no length.
func storedLen(d contract.AccountDoc) int {
	b, err := json.Marshal(d)
	if err != nil {
		return 0
	}
	n, inString := 0, false
	for i := 0; i < len(b); i++ {
		switch c := b[i]; {
		case !inString:
			n++
			if c == ':' || c == ',' {
				n++
			}
			inString = c == '"'
		case c == '"':
			n++
			inString = false
		case c == '\\' && b[i+1] == 'u':
			r, _ := strconv.ParseUint(string(b[i+2:i+6]), 16, 32)
			if r < 0x20 {
				n += 6
			} else {
				n += utf8.RuneLen(rune(r))
			}
			i += 5
		case c == '\\':
			n += 2
			i++
		default:
			n++
		}
	}
	return n
}

// HoldPublishing stops the publisher for app, as a stuck one on the
// platform: a change to the directory reaches app's feed no more, and the
// feed's published_through stays at the time of the oldest change not yet
// published, so an app's freshness grows old while the feed still answers
// (SPEC section 11.17). PUT and GET still compute an account's document now
// and publish it, the account's held changes with it, as the platform's
// do. Release starts the publisher again.
func (p *Platform) HoldPublishing(app string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil {
		return ErrUnknown
	}
	st.held = true
	return nil
}

// Release starts app's publisher again: every change held is published at
// once, and published_through is now again.
func (p *Platform) Release(app string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil {
		return ErrUnknown
	}
	st.held = false
	for sub := range st.marks {
		p.publishLocked(st, sub)
	}
	return nil
}

// ---------------------------------------------------------------------------
// The directory
// ---------------------------------------------------------------------------

// AddAccount makes an active account, with its personal workspace, whose
// id it returns.
func (p *Platform) AddAccount(sub string) (personal string, err error) {
	if !contract.ValidUUID(sub) {
		return "", ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.accounts[sub] != nil || p.closed[sub] {
		return "", ErrExists
	}
	personal = p.newWorkspaceLocked(contract.KindPersonal, "", sub)
	p.accounts[sub] = &account{personal: personal}
	p.republishLocked()
	return personal, nil
}

func (p *Platform) newWorkspaceLocked(kind, name, owner string) string {
	id := newUUID()
	p.created++
	p.workspaces[id] = &workspace{kind: kind, name: name, wversion: 1, order: p.created, members: map[string]string{owner: contract.RoleOwner}}
	return id
}

// Disable suspends an account, as the operator does, at at, and so ends
// every session of it: disabled_at and sessions_revoked_at each rise to
// at, kept at microseconds as the platform keeps it, unless it holds that
// time or a later one already. Disabling an account that is
// disabled already changes nothing, as on the platform; Enable lifts it.
func (p *Platform) Disable(sub string, at time.Time) error {
	return p.updateAccount(sub, func(a *account) {
		if a.disabled {
			return
		}
		a.disabled, a.disabledAt, a.revokedAt = true, later(a.disabledAt, at), later(a.revokedAt, at)
	})
}

// Enable lifts an account's disable.
func (p *Platform) Enable(sub string) error {
	return p.updateAccount(sub, func(a *account) { a.disabled = false })
}

// RevokeSessions ends every session of an account at at, kept at
// microseconds as the platform keeps it; a recovery also stops the
// integrations the person created (credentials_revoked_at).
func (p *Platform) RevokeSessions(sub string, at time.Time, recovery bool) error {
	return p.updateAccount(sub, func(a *account) {
		a.revokedAt = later(a.revokedAt, at)
		if recovery {
			a.credsAt = later(a.credsAt, at)
		}
	})
}

// later is the later of held and at, kept at microseconds.
func later(held *time.Time, at time.Time) *time.Time {
	at = atMicroseconds(at)
	if held != nil && held.After(at) {
		return held
	}
	return &at
}

// atMicroseconds is t as the platform keeps a time, in a timestamptz: in
// UTC, at microseconds. An app that stores microseconds of a time the fake
// sends then sees it rise only when it rose.
func atMicroseconds(t time.Time) time.Time {
	return t.UTC().Truncate(time.Microsecond)
}

func (p *Platform) updateAccount(sub string, f func(*account)) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	a := p.accounts[sub]
	if a == nil {
		return ErrUnknown
	}
	f(a)
	p.republishLocked()
	return nil
}

// CloseAccount closes an account: its memberships end, its personal
// workspace closes, and its document says closed from then on. It refuses
// to leave an open team with no owner.
func (p *Platform) CloseAccount(sub string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	a := p.accounts[sub]
	if a == nil {
		return ErrUnknown
	}
	for id, w := range p.workspaces {
		if id != a.personal && w.members[sub] == contract.RoleOwner && p.lastOwnerLocked(w, sub) {
			return ErrLastOwner
		}
	}
	for id, w := range p.workspaces {
		delete(w.members, sub)
		if id == a.personal {
			w.closed = true
		}
	}
	delete(p.accounts, sub)
	p.closed[sub] = true
	p.republishLocked()
	return nil
}

func (p *Platform) lastOwnerLocked(w *workspace, sub string) bool {
	if w.closed || w.members[sub] != contract.RoleOwner {
		return false
	}
	for other, role := range w.members {
		if other != sub && role == contract.RoleOwner {
			return false
		}
	}
	return true
}

// AddTeam makes an open team named name with owner as its owner, and
// returns its id.
func (p *Platform) AddTeam(name, owner string) (string, error) {
	if !validName(name) {
		return "", ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.accounts[owner] == nil {
		return "", ErrUnknown
	}
	id := p.newWorkspaceLocked(contract.KindTeam, name, owner)
	p.republishLocked()
	return id, nil
}

// SetRole makes sub a member of the team ws with role, or changes its
// role. It refuses to leave an open team with no owner.
func (p *Platform) SetRole(ws, sub, role string) error {
	if role != contract.RoleOwner && role != contract.RoleAdmin && role != contract.RoleMember {
		return ErrInvalid
	}
	return p.updateTeam(ws, func(w *workspace) error {
		if p.accounts[sub] == nil {
			return ErrUnknown
		}
		if role != contract.RoleOwner && p.lastOwnerLocked(w, sub) {
			return ErrLastOwner
		}
		w.members[sub] = role
		return nil
	})
}

// RemoveMember ends sub's membership of the team ws. It refuses to leave an
// open team with no owner.
func (p *Platform) RemoveMember(ws, sub string) error {
	return p.updateTeam(ws, func(w *workspace) error {
		if _, ok := w.members[sub]; !ok {
			return ErrUnknown
		}
		if p.lastOwnerLocked(w, sub) {
			return ErrLastOwner
		}
		delete(w.members, sub)
		return nil
	})
}

// RenameTeam names the team ws name: its wversion rises.
func (p *Platform) RenameTeam(ws, name string) error {
	if !validName(name) {
		return ErrInvalid
	}
	return p.updateTeam(ws, func(w *workspace) error {
		if w.name != name {
			w.name = name
			w.wversion++
		}
		return nil
	})
}

// CloseTeam closes the team ws, keeping its members; ReopenTeam opens it
// again, as only the operator does. Its wversion rises. A team reopens
// only with an owner.
func (p *Platform) CloseTeam(ws string) error { return p.setClosed(ws, true) }

// ReopenTeam opens the team ws again.
func (p *Platform) ReopenTeam(ws string) error { return p.setClosed(ws, false) }

func (p *Platform) setClosed(ws string, closed bool) error {
	return p.updateTeam(ws, func(w *workspace) error {
		if w.closed == closed {
			return nil
		}
		if !closed {
			owners := 0
			for _, role := range w.members {
				if role == contract.RoleOwner {
					owners++
				}
			}
			if owners == 0 {
				return ErrLastOwner
			}
		}
		w.closed = closed
		w.wversion++
		return nil
	})
}

func (p *Platform) updateTeam(ws string, f func(*workspace) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	w := p.workspaces[ws]
	if w == nil || w.kind != contract.KindTeam {
		return ErrUnknown
	}
	if err := f(w); err != nil {
		return err
	}
	p.republishLocked()
	return nil
}

// validName is a team's name as the wire carries it, checked by the
// contract's own rule on a document that names it.
func validName(name string) bool {
	one := 1
	probe := contract.AccountDoc{
		V: contract.DocV, Type: contract.DocType, App: "probe", Generation: "00000000-0000-4000-8000-000000000001",
		Sub: "00000000-0000-4000-8000-000000000002", Version: 1, Status: contract.AccountActive,
		Workspaces: []contract.Workspace{{ID: "00000000-0000-4000-8000-000000000003", Kind: contract.KindTeam, Name: &name,
			Role: contract.RoleOwner, Status: contract.StatusOpen, WVersion: 1, Owners: &one}},
	}
	return probe.Validate() == nil
}

// ---------------------------------------------------------------------------
// Generations
// ---------------------------------------------------------------------------

// Generation is the platform database's generation, and whether the
// operator confirmed it.
func (p *Platform) Generation() (id string, confirmed bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.generation, p.confirmed
}

// NewGeneration gives the platform a new generation, not yet confirmed, as
// the restore runbook does: every feed answer and document carries it from
// now on.
func (p *Platform) NewGeneration() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.generation, p.confirmed = newUUID(), false
	return p.generation
}

// ConfirmGeneration marks the generation checked: the runbook's last step.
func (p *Platform) ConfirmGeneration() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.confirmed = true
}

// Restore plays a restore from a backup taken before any document was
// published: every app's feed starts again from 0 with no document in it,
// so a cursor above 0 is gone, and a new generation begins, not yet
// confirmed. The directory stays, but such a backup holds no subscription
// and names no workspace to an app, so it holds no snapshot or event of
// one either: they all go. An app gets documents again only for the
// accounts it subscribes to again (PUT), and a snapshot or an event of a
// workspace not named to it again is not_found.
func (p *Platform) Restore() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, app := range p.apps {
		app.head = 0
		app.docs = map[string]contract.AccountDoc{}
		app.follows, app.marks, app.named = map[string]bool{}, map[string]time.Time{}, map[string]bool{}
		app.snapshots, app.events, app.kept = map[string]contract.Snapshot{}, nil, map[string]keptEvent{}
	}
	p.generation, p.confirmed = newUUID(), false
	return p.generation
}

// ---------------------------------------------------------------------------
// What the apps sent
// ---------------------------------------------------------------------------

// Snapshot is the latest snapshot of the workspace ws that app sent and
// the platform kept, as the app sent it; false when there is none.
func (p *Platform) Snapshot(app, ws string) (contract.Snapshot, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil {
		return contract.Snapshot{}, false
	}
	s, ok := st.snapshots[ws]
	return s, ok
}

// Events are the events of app the platform accepted, in the order it
// accepted them, as the app sent them.
func (p *Platform) Events(app string) []contract.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	if st == nil {
		return nil
	}
	return append([]contract.Event(nil), st.events...)
}

// Following reports whether app follows the account sub.
func (p *Platform) Following(app, sub string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	return st != nil && st.follows[sub]
}

// Named reports whether the workspace ws was named to app, in a document of
// one of its people: the only workspaces it may report on.
func (p *Platform) Named(app, ws string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.apps[app]
	return st != nil && st.named[ws]
}

// newUUID is a random UUID of version 4, in lowercase.
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = 0x40 | b[6]&0x0f
	b[8] = 0x80 | b[8]&0x3f
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
