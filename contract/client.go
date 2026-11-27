package contract

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client is an app's side of the contract: it signs each request with the
// app's secret and trusts an answer only once its signature, bound to the
// request's own nonce, holds (VerifyAnswer). The platform's reference app
// (its tools/fakeproduct) and its end-to-end tests use it; it is the shape
// the apps' own clients follow.
//
// An answer that does not verify, or that verifies but is not valid, is
// ErrUnverified, whatever its status, and comes with the zero value: an app
// moves no cursor and marks no outbox row on it. A signed refusal is a
// *Refusal with the platform's code. Every call is bounded in time, whatever
// its context (CallTimeout, FeedGrace), and an error never carries the
// request's URL, which names an account or a workspace.
//
// An app holds a *Client, as contracttest's Platform.Client returns one.
// String, GoString and LogValue hide the secrets, and Secret and Accept
// are no JSON members, but fmt calls String only where it can: a Client
// held by value in an unexported field of the app's own struct prints raw,
// its secrets among them, while a *Client there prints as its address
// under %v, %+v and %#v. A verb a pointer does not take, such as %s, still
// prints what it points to, so an app prints such a struct with %v or not
// at all.
type Client struct {
	// App is the app's id; Secret the secret it signs with; Accept, when
	// not empty, the secrets an answer may be signed with (during a
	// rotation, the current and the next), else Secret alone.
	App    string
	Secret string   `json:"-"`
	Accept []string `json:"-"`
	// Base is the platform's contract address, such as
	// http://127.0.0.1:8291 in development, or http://contract with an HTTP
	// client that dials the unix socket.
	Base string
	// HTTP sends the requests. When nil, a client that follows no redirect
	// and gives up after MaxWait seconds and FeedGrace. One the app supplies
	// has a Timeout of 0 or above that (40 s), or every long-poll fails. The
	// kit has no dialer for the socket: in production the app's transport
	// dials /run/platform/contract.sock whatever the URL's host, and the app
	// may check first that the socket's owner is uid 0, since only root
	// creates an entry under /run/platform (SPEC section 11.17).
	HTTP *http.Client
	// Now is the clock (time.Now when nil).
	Now func() time.Time
}

// CallTimeout bounds each call but the feed's, and FeedGrace is how much
// longer than its wait a feed request may take, whatever the call's
// context: a platform that stalls ends a call in an error
// (context.DeadlineExceeded) rather than holding the app's follower for
// good. A context with an earlier deadline ends the call earlier.
const (
	CallTimeout = 15 * time.Second
	FeedGrace   = 15 * time.Second
)

// callTimeout and feedGrace are the bounds a Client applies; the package's
// tests shorten them.
var callTimeout, feedGrace = CallTimeout, FeedGrace

// trimResultBodyLimit is the bound PostTrimResult holds a body to; the
// package's tests lower it, since no valid result reaches
// TrimResultBodyLimit.
var trimResultBodyLimit = TrimResultBodyLimit

// defaultHTTP is the client of a Client whose HTTP is nil. An answer is its
// request's, so a redirect is never followed: its answer, unsigned for the
// request, fails.
var defaultHTTP = &http.Client{
	Timeout:       MaxWait*time.Second + FeedGrace,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// String hides the secrets.
func (c Client) String() string {
	return fmt.Sprintf("contract.Client{App: %q, Base: %q}", c.App, c.Base)
}

// GoString is String, for %#v.
func (c Client) GoString() string { return c.String() }

// LogValue hides the secrets from a structured log.
func (c Client) LogValue() slog.Value {
	return slog.GroupValue(slog.String("app", c.App), slog.String("base", c.Base))
}

// MaxAnswer is the largest answer a Client reads: the platform ends a feed
// page early, with more, before its documents reach half of it.
const MaxAnswer = 8 << 20

// ErrUnverified means an answer's signature did not hold, or the answer it
// signs is not valid (an error that also matches ErrInvalid) or not the
// one asked for: the app ignores it.
var ErrUnverified = errors.New("contract: the answer is not the platform's")

// ErrForeignDocument means a signed answer of Client.EntitlementsDoc held
// a valid document of another app or another workspace than the one asked
// for. It also matches ErrUnverified, and not ErrInvalid: the app ignores
// it, applies nothing of it, and logs it with ids only (its app and the
// path's workspace_id), as the platform's spec asks; the client logs
// nothing. Its text names no id.
var ErrForeignDocument = fmt.Errorf("contract: an entitlements document of another app or workspace: %w", ErrUnverified)

// Refusal is a signed refusal: the platform's code and message, and the
// HTTP status it came with (which an app never acts on alone).
type Refusal struct {
	Status  int
	Code    string
	Message string
}

func (r *Refusal) Error() string {
	return fmt.Sprintf("contract: refused %s (%d): %s", r.Code, r.Status, r.Message)
}

// Do sends one signed request and returns the verified answer's status and
// body. target is the raw path and query. It gives up after CallTimeout, or,
// for a GET of one of the four feeds, each a long-poll
// (/contract/v1/feed, /contract/v1/tokens, /contract/v1/commands and
// /contract/v1/entitlements), after MaxWait seconds and FeedGrace.
func (c *Client) Do(ctx context.Context, method, target string, body []byte) (int, []byte, error) {
	timeout := callTimeout
	if path, _, _ := strings.Cut(target, "?"); method == http.MethodGet && feedPaths[path] {
		timeout = MaxWait*time.Second + feedGrace
	}
	return c.do(ctx, timeout, method, target, body)
}

// feedPaths are the four feeds' paths, each a long-poll.
var feedPaths = map[string]bool{
	"/contract/v1/feed": true, "/contract/v1/tokens": true, "/contract/v1/commands": true, "/contract/v1/entitlements": true,
}

// do is Do, bounded by timeout.
func (c *Client) do(ctx context.Context, timeout time.Duration, method, target string, body []byte) (int, []byte, error) {
	status, answer, _, err := c.doSigned(ctx, timeout, method, target, body)
	return status, answer, err
}

// doSigned is do, and the time the platform signed the verified answer
// (its X-Happie-Timestamp).
func (c *Client) doSigned(ctx context.Context, timeout time.Duration, method, target string, body []byte) (int, []byte, time.Time, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	hc := c.HTTP
	if hc == nil {
		hc = defaultHTTP
	}
	if err := CheckSecrets(c.Secret, ""); err != nil {
		return 0, nil, time.Time{}, err
	}
	// An empty or malformed key would verify what anyone signs with it.
	for _, a := range c.Accept {
		if err := CheckSecrets(a, ""); err != nil {
			return 0, nil, time.Time{}, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var rd io.Reader = http.NoBody
	if len(body) > 0 {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+target, rd)
	if err != nil {
		return 0, nil, time.Time{}, transportError(method, target, err)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := Scheme().Sign(req.Header, c.Secret, ToPlatform, c.App, method, target, body, now()); err != nil {
		return 0, nil, time.Time{}, err
	}
	nonce := req.Header.Get(HeaderNonce)
	res, err := hc.Do(req)
	if err != nil {
		return 0, nil, time.Time{}, transportError(method, target, err)
	}
	defer func() { _ = res.Body.Close() }()
	answer, err := io.ReadAll(io.LimitReader(res.Body, MaxAnswer+1))
	if err != nil {
		return 0, nil, time.Time{}, transportError(method, target, err)
	}
	if len(answer) > MaxAnswer {
		return 0, nil, time.Time{}, fmt.Errorf("%w: the answer is too large", ErrUnverified)
	}
	accept := c.Accept
	if len(accept) == 0 {
		accept = []string{c.Secret}
	}
	if err := VerifyAnswer(res.Header, accept, c.App, method, target, nonce, answer, now()); err != nil {
		return res.StatusCode, nil, time.Time{}, fmt.Errorf("%w (%d): %w", ErrUnverified, res.StatusCode, err)
	}
	// VerifyAnswer read the timestamp already, as decimal Unix seconds.
	unix, _ := strconv.ParseInt(res.Header.Get(HeaderTimestamp), 10, 64)
	return res.StatusCode, answer, time.Unix(unix, 0).UTC(), nil
}

// transportError is err without the request's URL, which names an account
// or a workspace and which an app would log: the method and the call's
// route, its ids left out, and the cause, which errors.Is and errors.As
// still reach (context.DeadlineExceeded, a *net.OpError).
func transportError(method, target string, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return fmt.Errorf("contract: %s %s: %w", method, route(target), err)
}

// route is a target's path with every segment but the contract's own words
// written {id}, and no query.
func route(target string) string {
	path, _, _ := strings.Cut(target, "?")
	parts := strings.Split(path, "/")
	for i, p := range parts {
		switch p {
		case "", "contract", "v1", "accounts", "workspaces", "access", "feed", "events",
			"tokens", "token-selectors", "applied", "usage", "settings", "commands", "results", "pairing",
			"entitlements", "link-check", "trim":
		default:
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

// call sends a request and decodes a verified answer into out, or a signed
// refusal into a *Refusal.
func (c *Client) call(ctx context.Context, timeout time.Duration, method, target string, in, out any) error {
	_, err := c.callSigned(ctx, timeout, method, target, in, out)
	return err
}

// callSigned is call, and the time the platform signed the answer.
func (c *Client) callSigned(ctx context.Context, timeout time.Duration, method, target string, in, out any) (time.Time, error) {
	var body []byte
	switch in := in.(type) {
	case nil:
	case rawBody:
		body = in
	default:
		var err error
		if body, err = json.Marshal(in); err != nil {
			return time.Time{}, err
		}
	}
	status, answer, signedAt, err := c.doSigned(ctx, timeout, method, target, body)
	if err != nil {
		return time.Time{}, err
	}
	var refusal Error
	if json.Unmarshal(answer, &refusal) == nil && refusal.Code != "" {
		return time.Time{}, &Refusal{Status: status, Code: refusal.Code, Message: refusal.Message}
	}
	if out == nil {
		return signedAt, nil
	}
	if err := json.Unmarshal(answer, out); err != nil {
		return time.Time{}, fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	return signedAt, nil
}

// Subscribe follows the account sub and returns its document, computed now:
// PUT /contract/v1/accounts/{sub}.
func (c *Client) Subscribe(ctx context.Context, sub string) (AccountDoc, error) {
	var d AccountDoc
	if err := c.call(ctx, callTimeout, http.MethodPut, "/contract/v1/accounts/"+sub, nil, &d); err != nil {
		return AccountDoc{}, err
	}
	if err := c.checkDoc(d, sub); err != nil {
		return AccountDoc{}, err
	}
	return d, nil
}

// checkDoc refuses a document that is not valid, or not this app's
// document of sub.
func (c *Client) checkDoc(d AccountDoc, sub string) error {
	if err := d.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	if d.App != c.App || d.Sub != sub {
		return fmt.Errorf("%w: the document is another app's or another account's", ErrUnverified)
	}
	return nil
}

// Account returns the document of an account the app follows, computed now:
// GET /contract/v1/accounts/{sub}.
func (c *Client) Account(ctx context.Context, sub string) (AccountDoc, error) {
	var d AccountDoc
	if err := c.call(ctx, callTimeout, http.MethodGet, "/contract/v1/accounts/"+sub, nil, &d); err != nil {
		return AccountDoc{}, err
	}
	if err := c.checkDoc(d, sub); err != nil {
		return AccountDoc{}, err
	}
	return d, nil
}

// Unsubscribe follows the account no more: DELETE /contract/v1/accounts/{sub}.
func (c *Client) Unsubscribe(ctx context.Context, sub string) error {
	return c.call(ctx, callTimeout, http.MethodDelete, "/contract/v1/accounts/"+sub, nil, nil)
}

// Feed returns the documents after the cursor after, waiting up to wait
// seconds when there are none: GET /contract/v1/feed?after=&wait=. It
// gives up after wait seconds and FeedGrace.
func (c *Client) Feed(ctx context.Context, after int64, wait int) (Feed, error) {
	var f Feed
	target := "/contract/v1/feed?after=" + strconv.FormatInt(after, 10) + "&wait=" + strconv.Itoa(wait)
	timeout := time.Duration(min(max(wait, 0), MaxWait))*time.Second + feedGrace
	if err := c.call(ctx, timeout, http.MethodGet, target, nil, &f); err != nil {
		return Feed{}, err
	}
	if err := f.Validate(c.App); err != nil {
		return Feed{}, fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	return f, nil
}

// PutAccess sends the app's snapshot of the workspace ws:
// PUT /contract/v1/workspaces/{id}/access.
func (c *Client) PutAccess(ctx context.Context, ws string, snap Snapshot) error {
	var r AccessResult
	if err := c.call(ctx, callTimeout, http.MethodPut, "/contract/v1/workspaces/"+ws+"/access", snap, &r); err != nil {
		return err
	}
	if !r.Accepted {
		return fmt.Errorf("%w: the snapshot was not accepted", ErrUnverified)
	}
	return nil
}

// PostEvents sends a batch of events and returns one result per event:
// POST /contract/v1/events. A raw []Event is never logged: each Event's
// String, GoString and LogValue leave its trial codes out, but a handler
// that encodes the slice as JSON writes them; log the batch as Events
// (whose LogValue is its count and ids) or each Event alone.
func (c *Client) PostEvents(ctx context.Context, events []Event) ([]EventResult, error) {
	var r EventResults
	if err := c.call(ctx, callTimeout, http.MethodPost, "/contract/v1/events", Events{Events: events}, &r); err != nil {
		return nil, err
	}
	if len(r.Results) != len(events) {
		return nil, fmt.Errorf("%w: %d results for %d events", ErrUnverified, len(r.Results), len(events))
	}
	return r.Results, nil
}

// Tokens returns the token records after the cursor after, waiting up to
// wait seconds when there are none: GET /contract/v1/tokens?after=&wait=
// (SPEC section 11.18). It gives up after wait seconds and FeedGrace. It
// checks the page (TokenFeed.Validate), not its records, which it leaves as
// they came: a bad record never stalls the feed, so the app decodes each
// one on its own (TokenFeedItem.Record) and decides as TokenFeed.Validate
// says.
func (c *Client) Tokens(ctx context.Context, after int64, wait int) (TokenFeed, error) {
	var f TokenFeed
	target := "/contract/v1/tokens?after=" + strconv.FormatInt(after, 10) + "&wait=" + strconv.Itoa(wait)
	timeout := time.Duration(min(max(wait, 0), MaxWait))*time.Second + feedGrace
	if err := c.call(ctx, timeout, http.MethodGet, target, nil, &f); err != nil {
		return TokenFeed{}, err
	}
	if err := f.Validate(); err != nil {
		return TokenFeed{}, fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	return f, nil
}

// Token returns the record of the token id for this app, computed and
// published now: GET /contract/v1/tokens/{id}. An app reads it before it
// stores a grant to the token's reading key, and refuses the grant without
// a signed answer under a minute old. A token that never named the app, or
// one unknown, is a *Refusal not_found, which never clears a revocation the
// app holds. A record that is not valid, not this app's or not the token
// asked for is ErrUnverified.
func (c *Client) Token(ctx context.Context, id string) (TokenRecord, error) {
	if !ValidUUID(id) {
		return TokenRecord{}, invalid("id")
	}
	var r TokenRecord
	if err := c.call(ctx, callTimeout, http.MethodGet, "/contract/v1/tokens/"+id, nil, &r); err != nil {
		return TokenRecord{}, err
	}
	if err := c.checkRecord(r); err != nil {
		return TokenRecord{}, err
	}
	if r.ID != id {
		return TokenRecord{}, fmt.Errorf("%w: the record is another token's", ErrUnverified)
	}
	return r, nil
}

// TokenBySelector returns the record of the token whose selector is
// selector, as Token does: GET /contract/v1/token-selectors/{selector}. An
// app may call it for a token that parses but whose selector it does not
// hold, behind a limit of its own per client address, and keeps a
// not_found 60 s. It still checks the token's hash itself (VerifyToken).
func (c *Client) TokenBySelector(ctx context.Context, selector string) (TokenRecord, error) {
	if !ValidSelector(selector) {
		return TokenRecord{}, invalid("selector")
	}
	var r TokenRecord
	if err := c.call(ctx, callTimeout, http.MethodGet, "/contract/v1/token-selectors/"+selector, nil, &r); err != nil {
		return TokenRecord{}, err
	}
	if err := c.checkRecord(r); err != nil {
		return TokenRecord{}, err
	}
	if r.Selector != selector {
		return TokenRecord{}, fmt.Errorf("%w: the record is another token's", ErrUnverified)
	}
	return r, nil
}

// checkRecord refuses a record that is not valid or not this app's.
func (c *Client) checkRecord(r TokenRecord) error {
	if err := r.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	if r.App != c.App {
		return fmt.Errorf("%w: the record is another app's", ErrUnverified)
	}
	return nil
}

// TokensApplied acknowledges the token feed: POST
// /contract/v1/tokens/applied. Refused and Held are always sent, [] when
// nil. Another generation, or a through above the feed's head, is a
// *Refusal gone.
func (c *Client) TokensApplied(ctx context.Context, ack TokenApplied) error {
	if ack.Refused == nil {
		ack.Refused = []TokenRefusal{}
	}
	if ack.Held == nil {
		ack.Held = []TokenHeld{}
	}
	return c.accepted(ctx, "/contract/v1/tokens/applied", ack, "the acknowledgement")
}

// TokenUsage reports the tokens' last use and refused uses: POST
// /contract/v1/tokens/usage. Used and Refusals are always sent, [] when
// nil. Both lists are absolute, so it is sent again freely, at most once a
// minute, and split as the app likes to stay within UsageBodyLimit.
func (c *Client) TokenUsage(ctx context.Context, u TokenUsage) error {
	if u.Used == nil {
		u.Used = []TokenUsed{}
	}
	if u.Refusals == nil {
		u.Refusals = []UsageRefusal{}
	}
	return c.accepted(ctx, "/contract/v1/tokens/usage", u, "the usage")
}

// accepted posts body and wants {"accepted": true}.
func (c *Client) accepted(ctx context.Context, target string, body any, what string) error {
	var r AccessResult
	if err := c.call(ctx, callTimeout, http.MethodPost, target, body, &r); err != nil {
		return err
	}
	if !r.Accepted {
		return fmt.Errorf("%w: %s was not accepted", ErrUnverified, what)
	}
	return nil
}

// PutSettings sends one section of one workspace, as one producer measured
// it: PUT /contract/v1/workspaces/{id}/settings/{section} (SPEC section
// 11.19). Data is always sent; a workspace that is no UUID, or a section
// that is not one of the app's, is refused before anything is sent.
func (c *Client) PutSettings(ctx context.Context, doc SettingsDoc) error {
	if !ValidUUID(doc.WorkspaceID) {
		return invalid("workspace_id")
	}
	if _, ok := sectionsOf(c.App)[doc.Section]; !ok || doc.Section == SectionPerson {
		return invalid("section")
	}
	if doc.Accepts == nil {
		doc.Accepts = []string{}
	}
	return c.put(ctx, "/contract/v1/workspaces/"+doc.WorkspaceID+"/settings/"+doc.Section, doc, "the section")
}

// PutPersonSettings sends one person's own settings in the app:
// PUT /contract/v1/accounts/{sub}/settings. A sub that is no UUID is
// refused before anything is sent.
func (c *Client) PutPersonSettings(ctx context.Context, doc PersonSettingsDoc) error {
	if !ValidUUID(doc.Sub) {
		return invalid("sub")
	}
	if doc.Accepts == nil {
		doc.Accepts = []string{}
	}
	return c.put(ctx, "/contract/v1/accounts/"+doc.Sub+"/settings", doc, "the person's settings")
}

// rawBody is a body encoded already.
type rawBody []byte

// marshalPlain is v's JSON with no HTML escaping: encoding/json writes each
// &, < and > as six bytes, which could push a valid document past its
// call's limit. A raw member (a document's data) is written as it is, so a
// producer encodes its data without HTML escaping too.
func marshalPlain(v any) (rawBody, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// put puts body, with no HTML escaping, and wants {"accepted": true}.
func (c *Client) put(ctx context.Context, target string, body any, what string) error {
	raw, err := marshalPlain(body)
	if err != nil {
		return err
	}
	var r AccessResult
	if err := c.call(ctx, callTimeout, http.MethodPut, target, raw, &r); err != nil {
		return err
	}
	if !r.Accepted {
		return fmt.Errorf("%w: %s was not accepted", ErrUnverified, what)
	}
	return nil
}

// Commands returns the commands after the cursor after, waiting up to wait
// seconds when there are none: GET /contract/v1/commands?after=&wait=. It
// gives up after wait seconds and FeedGrace. It checks the page
// (CommandFeed.Validate), not its commands, which it leaves as they came,
// and returns the time the platform signed the answer, its
// X-Happie-Timestamp: the app stores it with each command it takes, and
// runs a command with an expiry only if that time is at or before its
// expires_at, whenever it runs. The app verifies each command on its own
// (VerifyCommand, with its secrets), and acknowledges the page by asking
// after it once it has written each command in its ledger.
func (c *Client) Commands(ctx context.Context, after int64, wait int) (CommandFeed, time.Time, error) {
	var f CommandFeed
	target := "/contract/v1/commands?after=" + strconv.FormatInt(after, 10) + "&wait=" + strconv.Itoa(wait)
	timeout := time.Duration(min(max(wait, 0), MaxWait))*time.Second + feedGrace
	signedAt, err := c.callSigned(ctx, timeout, http.MethodGet, target, nil, &f)
	if err != nil {
		return CommandFeed{}, time.Time{}, err
	}
	if err := f.Validate(); err != nil {
		return CommandFeed{}, time.Time{}, fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	return f, signedAt, nil
}

// PostResults sends a batch of results and returns one answer per result,
// in order: POST /contract/v1/commands/results. An answer that is not one
// per result, for each result's id in order, with an outcome of the
// contract's, is ErrUnverified.
func (c *Client) PostResults(ctx context.Context, results []CommandResult) ([]CommandResultAnswer, error) {
	body, err := marshalPlain(CommandResults{Results: results})
	if err != nil {
		return nil, err
	}
	var r CommandResultsAnswer
	if err := c.call(ctx, callTimeout, http.MethodPost, "/contract/v1/commands/results", body, &r); err != nil {
		return nil, err
	}
	if len(r.Results) != len(results) {
		return nil, fmt.Errorf("%w: %d answers for %d results", ErrUnverified, len(r.Results), len(results))
	}
	for i, a := range r.Results {
		if a.ID != results[i].ID || !oneOf(a.Outcome, []string{OutcomeAccepted, OutcomeDuplicate, OutcomeRejected}) {
			return nil, fmt.Errorf("%w: the answers are not the results'", ErrUnverified)
		}
	}
	return r.Results, nil
}

// PutPairing sends one QR of a running item.relink, the command id:
// PUT /contract/v1/commands/{id}/pairing (SPEC section 11.19). It refuses,
// before it sends anything, an id that is no UUID and a body that fails
// ValidateAt on the app's clock. It returns true when the platform holds
// the QR, and false with no error for a seq at or below the highest it
// kept or a PUT more than PairingHold after the command's first QR: both
// count as delivered. A signed not_found (an id that names no relink of
// the app's the feed carried, or one with a final result: the app sends
// no more QRs for it) or invalid_request is a *Refusal. The QR is never
// in an error.
func (c *Client) PutPairing(ctx context.Context, id string, p PairingQR) (bool, error) {
	if !ValidUUID(id) {
		return false, invalid("id")
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	if err := p.ValidateAt(now()); err != nil {
		return false, err
	}
	body, err := marshalPlain(p)
	if err != nil {
		return false, invalid("pairing")
	}
	var a PairingAnswer
	if err := c.call(ctx, callTimeout, http.MethodPut, "/contract/v1/commands/"+id+"/pairing", body, &a); err != nil {
		return false, err
	}
	return a.Accepted, nil
}

// Entitlements returns the entitlements documents after the cursor after,
// waiting up to wait seconds when there are none:
// GET /contract/v1/entitlements?after=&wait= (SPEC section 11.20). It gives
// up after wait seconds and FeedGrace. It checks the page
// (EntitlementsFeed.Validate), not its documents, which it leaves as they
// came: a page of another generation than the one the app holds is a
// reset, whatever its documents say, and in a page of its own generation
// the app judges each document alone (EntitlementsFeedItem.Document), so
// one bad document never refuses its page.
func (c *Client) Entitlements(ctx context.Context, after int64, wait int) (EntitlementsFeed, error) {
	var f EntitlementsFeed
	target := "/contract/v1/entitlements?after=" + strconv.FormatInt(after, 10) + "&wait=" + strconv.Itoa(wait)
	timeout := time.Duration(min(max(wait, 0), MaxWait))*time.Second + feedGrace
	if err := c.call(ctx, timeout, http.MethodGet, target, nil, &f); err != nil {
		return EntitlementsFeed{}, err
	}
	if err := f.Validate(); err != nil {
		return EntitlementsFeed{}, fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	return f, nil
}

// EntitlementsDoc returns the document of the workspace ws, computed now:
// GET /contract/v1/workspaces/{id}/entitlements. It also returns the time
// the platform signed the answer, its X-Happie-Timestamp, from which the
// document's freshness counts (SPEC section 11.20) when it is of the app's
// generation and at or above the version the app applied there. A ws that
// is no UUID is refused before anything is sent. A document that does not
// decode or validate is ErrUnverified (and ErrInvalid), and a valid one
// that names another app or another workspace than ws is
// ErrForeignDocument (which matches ErrUnverified too), whatever its
// signature: the app applies nothing of either, and logs the second with
// ids only (its app and ws); the client logs nothing. Its generation is the app's to judge:
// another one is a reset. A workspace not named to the app, a closed
// personal workspace and a closed team past its 30 days are a *Refusal
// not_found. The order the document carries, if any, stays as it came
// (EntitlementsDoc.Trim), for VerifyTrimOrder.
func (c *Client) EntitlementsDoc(ctx context.Context, ws string) (EntitlementsDoc, time.Time, error) {
	if !ValidUUID(ws) {
		return EntitlementsDoc{}, time.Time{}, invalid("workspace_id")
	}
	var d EntitlementsDoc
	signedAt, err := c.callSigned(ctx, callTimeout, http.MethodGet, "/contract/v1/workspaces/"+ws+"/entitlements", nil, &d)
	if err != nil {
		return EntitlementsDoc{}, time.Time{}, err
	}
	if err := d.Validate(); err != nil {
		return EntitlementsDoc{}, time.Time{}, fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	if d.App != c.App || d.WorkspaceID != ws {
		return EntitlementsDoc{}, time.Time{}, ErrForeignDocument
	}
	return d, signedAt, nil
}

// EntitlementsApplied acknowledges the entitlements feed:
// POST /contract/v1/entitlements/applied. An acknowledgement that does not
// validate is refused before anything is sent; an empty Refused is sent
// absent, as none. Another generation, or a through above the feed's head,
// is a *Refusal gone.
func (c *Client) EntitlementsApplied(ctx context.Context, ack EntitlementsApplied) error {
	if len(ack.Refused) == 0 {
		ack.Refused = nil
	}
	if err := ack.Validate(); err != nil {
		return err
	}
	return c.accepted(ctx, "/contract/v1/entitlements/applied", ack, "the acknowledgement")
}

// PutUsage sends the app's absolute usage report of the workspace ws:
// PUT /contract/v1/workspaces/{id}/usage. It refuses, before it sends
// anything, a ws that is no UUID, a report of another workspace or app, and
// one that fails ValidateAt on the app's clock; Items is sent [] when nil.
// It returns whether the platform holds a report of this usage_seq with
// this body after the request (kept), and false with no error otherwise:
// both count as delivered. An answer without both accepted true and kept a
// boolean, by their exact names, is ErrUnverified; a member it does not
// know is ignored. No error carries a
// figure of the report.
func (c *Client) PutUsage(ctx context.Context, ws string, u Usage) (bool, error) {
	if !ValidUUID(ws) {
		return false, invalid("workspace_id")
	}
	if u.Items == nil {
		u.Items = []UsageItem{}
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	switch {
	case u.WorkspaceID != ws:
		return false, invalid("workspace_id is the path's")
	case u.App != c.App:
		return false, invalid("app is the caller's")
	}
	if err := u.ValidateAt(now()); err != nil {
		return false, err
	}
	body, err := marshalPlain(u)
	if err != nil {
		return false, invalid("usage")
	}
	var a UsageAnswer
	if err := c.call(ctx, callTimeout, http.MethodPut, "/contract/v1/workspaces/"+ws+"/usage", body, &a); err != nil {
		return false, err
	}
	if err := a.Validate(); err != nil {
		return false, fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	return a.Kept, nil
}

// LinkCheck asks the platform about a link in the workspace ws, with no
// side effect: POST /contract/v1/workspaces/{id}/link-check. With codes it
// comes only once ownership of the item is proven, and before its first
// sync. It refuses, before it sends anything, a ws that is no UUID and a
// check that fails ValidateFor the app; Codes is sent [] when nil. An
// answer that does not validate is ErrUnverified. A workspace not named to
// the app is a *Refusal not_found, and more than LinkChecksPerMinute checks
// with codes a minute in one workspace a *Refusal rate_limited. No error
// carries a code.
func (c *Client) LinkCheck(ctx context.Context, ws string, req LinkCheck) (LinkCheckAnswer, error) {
	if !ValidUUID(ws) {
		return LinkCheckAnswer{}, invalid("workspace_id")
	}
	if req.Codes == nil {
		req.Codes = []string{}
	}
	if err := req.ValidateFor(c.App); err != nil {
		return LinkCheckAnswer{}, err
	}
	var a LinkCheckAnswer
	if err := c.call(ctx, callTimeout, http.MethodPost, "/contract/v1/workspaces/"+ws+"/link-check", req, &a); err != nil {
		return LinkCheckAnswer{}, err
	}
	if err := a.Validate(); err != nil {
		return LinkCheckAnswer{}, fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	return a, nil
}

// PostTrimResult sends what became of a trim order:
// POST /contract/v1/trim/results. It refuses, before it sends anything, a
// result that fails Validate, and one whose body is over
// TrimResultBodyLimit (ErrInvalid; no valid result is); Steps is sent []
// when nil. The answer is the
// platform's signed 200 for this result: accepted, duplicate, or rejected
// with invalid_request, not_found or conflict, each of which ends the
// result's delivery. An answer that does not validate, or names another
// order_id than the result's, is ErrUnverified. A refusal of the request
// itself (another status) is a *Refusal.
func (c *Client) PostTrimResult(ctx context.Context, r TrimResult) (TrimResultAnswer, error) {
	if r.Steps == nil {
		r.Steps = []TrimStepResult{}
	}
	if err := r.Validate(); err != nil {
		return TrimResultAnswer{}, err
	}
	body, err := marshalPlain(r)
	if err != nil {
		return TrimResultAnswer{}, invalid("trim result")
	}
	if len(body) > trimResultBodyLimit {
		return TrimResultAnswer{}, invalid("trim result: over %d bytes", trimResultBodyLimit)
	}
	// The answer carries a code of its own, which is no refusal: only a
	// status other than 200 refuses the request.
	status, answer, _, err := c.doSigned(ctx, callTimeout, http.MethodPost, "/contract/v1/trim/results", body)
	if err != nil {
		return TrimResultAnswer{}, err
	}
	if status != http.StatusOK {
		var refusal Error
		if json.Unmarshal(answer, &refusal) == nil && refusal.Code != "" {
			return TrimResultAnswer{}, &Refusal{Status: status, Code: refusal.Code, Message: refusal.Message}
		}
		return TrimResultAnswer{}, fmt.Errorf("%w: status %d", ErrUnverified, status)
	}
	var a TrimResultAnswer
	if err := json.Unmarshal(answer, &a); err != nil {
		return TrimResultAnswer{}, fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	if err := a.Validate(); err != nil {
		return TrimResultAnswer{}, fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	if a.OrderID != r.OrderID {
		return TrimResultAnswer{}, fmt.Errorf("%w: the answer is another order's", ErrUnverified)
	}
	return a, nil
}
