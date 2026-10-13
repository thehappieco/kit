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

// MaxAnswer is the largest answer a Client reads: a feed of MaxFeedItems
// documents fits well under it.
const MaxAnswer = 8 << 20

// ErrUnverified means an answer's signature did not hold, or the answer it
// signs is not valid (an error that also matches ErrInvalid) or not the
// one asked for: the app ignores it.
var ErrUnverified = errors.New("contract: the answer is not the platform's")

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
// for the feed (a GET of /contract/v1/feed), after MaxWait seconds and
// FeedGrace.
func (c *Client) Do(ctx context.Context, method, target string, body []byte) (int, []byte, error) {
	timeout := callTimeout
	if path, _, _ := strings.Cut(target, "?"); method == http.MethodGet && path == "/contract/v1/feed" {
		timeout = MaxWait*time.Second + feedGrace
	}
	return c.do(ctx, timeout, method, target, body)
}

// do is Do, bounded by timeout.
func (c *Client) do(ctx context.Context, timeout time.Duration, method, target string, body []byte) (int, []byte, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	hc := c.HTTP
	if hc == nil {
		hc = defaultHTTP
	}
	if err := CheckSecrets(c.Secret, ""); err != nil {
		return 0, nil, err
	}
	// An empty or malformed key would verify what anyone signs with it.
	for _, a := range c.Accept {
		if err := CheckSecrets(a, ""); err != nil {
			return 0, nil, err
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
		return 0, nil, transportError(method, target, err)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := Scheme().Sign(req.Header, c.Secret, ToPlatform, c.App, method, target, body, now()); err != nil {
		return 0, nil, err
	}
	nonce := req.Header.Get(HeaderNonce)
	res, err := hc.Do(req)
	if err != nil {
		return 0, nil, transportError(method, target, err)
	}
	defer func() { _ = res.Body.Close() }()
	answer, err := io.ReadAll(io.LimitReader(res.Body, MaxAnswer+1))
	if err != nil {
		return 0, nil, transportError(method, target, err)
	}
	if len(answer) > MaxAnswer {
		return 0, nil, fmt.Errorf("%w: the answer is too large", ErrUnverified)
	}
	accept := c.Accept
	if len(accept) == 0 {
		accept = []string{c.Secret}
	}
	if err := VerifyAnswer(res.Header, accept, c.App, method, target, nonce, answer, now()); err != nil {
		return res.StatusCode, nil, fmt.Errorf("%w (%d): %w", ErrUnverified, res.StatusCode, err)
	}
	return res.StatusCode, answer, nil
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
		case "", "contract", "v1", "accounts", "workspaces", "access", "feed", "events":
		default:
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

// call sends a request and decodes a verified answer into out, or a signed
// refusal into a *Refusal.
func (c *Client) call(ctx context.Context, timeout time.Duration, method, target string, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	status, answer, err := c.do(ctx, timeout, method, target, body)
	if err != nil {
		return err
	}
	var refusal Error
	if json.Unmarshal(answer, &refusal) == nil && refusal.Code != "" {
		return &Refusal{Status: status, Code: refusal.Code, Message: refusal.Message}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(answer, out); err != nil {
		return fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	return nil
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
// POST /contract/v1/events.
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
