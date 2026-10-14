package contracttest_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"
)

// The transport's tests are the platform's internal/contractapi tests at
// ee45e3a, run against the fake over loopback TCP, the platform's
// development transport: no peer uid is read, so the tests of the unix
// socket's uid check stay in the platform.

// Three secrets of the right shape: 42 characters and a last one whose low
// bits are zero.
var (
	secretA = strings.Repeat("A", 43)
	secretB = strings.Repeat("B", 42) + "A"
	secretC = strings.Repeat("C", 42) + "A"
)

const (
	anaSub = "0199a0c2-0000-7000-8000-000000000001"
	bobSub = "0199a0c2-0000-7000-8000-000000000002"
	teamID = "01a034b7-d09c-7121-b7f8-41f210a9244a"
	eventA = "0199d000-0000-7000-8000-000000000001"
	eventB = "0199d000-0000-7000-8000-000000000002"
)

// clock is a test's clock, safe to move while the fake reads it.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// harness is a fake platform on loopback with a clock of its own, unless
// the options bring one.
type harness struct {
	p     *contracttest.Platform
	clock *clock
}

func newHarness(t *testing.T, opts contracttest.Options) *harness {
	t.Helper()
	h := &harness{clock: &clock{t: time.Unix(1_760_300_000, 0)}}
	if opts.Now == nil {
		opts.Now = h.clock.Now
	}
	h.p = contracttest.Start(t, opts)
	return h
}

func wappie() contracttest.App { return contracttest.App{ID: "wappie", Current: secretA} }

type call struct {
	method, target, body string
	app                  string // X-Happie-App and the signer; "" for none
	secret               string
	at                   time.Time
	header               http.Header // extra headers, applied last
	unsignedHeaders      bool
}

type answer struct {
	status int
	header http.Header
	body   []byte
	nonce  string
}

func (h *harness) send(t *testing.T, c call) answer {
	t.Helper()
	if c.secret == "" {
		c.secret = secretA
	}
	if c.at.IsZero() {
		c.at = h.clock.Now()
	}
	req, err := http.NewRequestWithContext(t.Context(), c.method, h.p.URL()+c.target, strings.NewReader(c.body))
	if err != nil {
		t.Fatal(err)
	}
	if c.app != "" && !c.unsignedHeaders {
		if err := contract.Scheme().Sign(req.Header, c.secret, contract.ToPlatform, c.app, c.method, c.target, []byte(c.body), c.at); err != nil {
			t.Fatal(err)
		}
	} else if c.app != "" {
		req.Header.Set(contract.HeaderApp, c.app)
	}
	for k, vs := range c.header {
		req.Header.Del(k)
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return answer{status: res.StatusCode, header: res.Header, body: body, nonce: req.Header.Get(contract.HeaderNonce)}
}

func (a answer) code(t *testing.T) string {
	t.Helper()
	var e contract.Error
	if err := json.Unmarshal(a.body, &e); err != nil {
		t.Fatalf("status %d: not an error body: %s", a.status, a.body)
	}
	return e.Code
}

// wantUnsigned checks a refusal the app cannot trust: no signature.
func (a answer) wantUnsigned(t *testing.T, status int, code string) {
	t.Helper()
	if a.status != status || a.code(t) != code {
		t.Fatalf("got %d %s, want %d %s", a.status, a.body, status, code)
	}
	if a.header.Get(contract.HeaderSignature) != "" || a.header.Get(contract.HeaderNonce) != "" {
		t.Fatalf("a refusal before the signature held is signed: %v", a.header)
	}
}

// wantSigned checks a signed refusal, verifying it as an app does.
func (h *harness) wantSigned(t *testing.T, a answer, c call, status int, code string) {
	t.Helper()
	if a.status != status || a.code(t) != code {
		t.Fatalf("got %d %s, want %d %s", a.status, a.body, status, code)
	}
	h.verified(t, a, []string{secretA}, c.app, c.method, c.target)
}

// verified checks the answer's signature as an app does.
func (h *harness) verified(t *testing.T, a answer, secrets []string, app, method, target string) {
	t.Helper()
	if err := contract.VerifyAnswer(a.header, secrets, app, method, target, a.nonce, a.body, h.clock.Now()); err != nil {
		t.Fatalf("the answer does not verify: %v (%d %s)", err, a.status, a.body)
	}
}

func TestWithNoAppConfiguredEveryRequestIsNotFoundAndUnsigned(t *testing.T) {
	h := newHarness(t, contracttest.Options{})
	h.send(t, call{method: http.MethodGet, target: "/contract/v1/accounts/" + anaSub, app: "wappie"}).
		wantUnsigned(t, http.StatusNotFound, contract.CodeNotFound)
	h.send(t, call{method: http.MethodGet, target: "/"}).wantUnsigned(t, http.StatusNotFound, contract.CodeNotFound)
}

func TestASignedRequestGetsASignedAnswerBoundToItsNonce(t *testing.T) {
	h := newHarness(t, contracttest.Options{Apps: []contracttest.App{wappie()}})
	if _, err := h.p.AddAccount(anaSub); err != nil {
		t.Fatal(err)
	}
	target := "/contract/v1/accounts/" + anaSub
	a := h.send(t, call{method: http.MethodPut, target: target, app: "wappie"})
	if a.status != http.StatusOK {
		t.Fatalf("subscribe: %d %s", a.status, a.body)
	}
	h.verified(t, a, []string{secretA}, "wappie", http.MethodPut, target)
	if a.header.Get(contract.HeaderNonce) != a.nonce {
		t.Fatal("the answer does not echo the request's nonce")
	}
	// The answer is the request's only: another request's nonce refuses it.
	// Another one always: the random nonce may start with any character.
	other := "A" + a.nonce[1:]
	if a.nonce[0] == 'A' {
		other = "B" + a.nonce[1:]
	}
	if err := contract.VerifyAnswer(a.header, []string{secretA}, "wappie", http.MethodPut, target, other, a.body, h.clock.Now()); !errors.Is(err, contract.ErrAnswerNonce) {
		t.Fatalf("an answer verified against another request's nonce: %v", err)
	}
	var got contract.AccountDoc
	dec := json.NewDecoder(bytes.NewReader(a.body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&got); err != nil || got.Validate() != nil || got.Sub != anaSub || got.App != "wappie" {
		t.Fatalf("the document: %v %+v", err, got)
	}
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		a := h.send(t, call{method: method, target: target, app: "wappie"})
		if a.status != http.StatusOK {
			t.Fatalf("%s: %d %s", method, a.status, a.body)
		}
		h.verified(t, a, []string{secretA}, "wappie", method, target)
	}
	if a := h.send(t, call{method: http.MethodDelete, target: target, app: "wappie"}); string(a.body) != `{"subscribed":false}` {
		t.Fatalf("unsubscribe's answer: %s", a.body)
	}
	if h.p.Following("wappie", anaSub) {
		t.Fatal("still following after the unsubscribe")
	}
	// Not followed any more: GET is not_found, signed.
	c := call{method: http.MethodGet, target: target, app: "wappie"}
	h.wantSigned(t, h.send(t, c), c, http.StatusNotFound, contract.CodeNotFound)
}

func TestAnAppIsTheOneItsHeaderNamesOnce(t *testing.T) {
	h := newHarness(t, contracttest.Options{Apps: []contracttest.App{wappie(), {ID: "mailie", Current: secretB}}})
	target := "/contract/v1/accounts/" + anaSub
	for name, c := range map[string]call{
		"an app nobody configured":   {app: "vaultie"},
		"no app header":              {app: "wappie", header: http.Header{contract.HeaderApp: nil}},
		"the header twice":           {app: "wappie", header: http.Header{contract.HeaderApp: {"wappie", "wappie"}}},
		"a header with another case": {app: "wappie", header: http.Header{contract.HeaderApp: {"Wappie"}}},
	} {
		c.method, c.target = http.MethodGet, target
		t.Run(name, func(t *testing.T) {
			h.send(t, c).wantUnsigned(t, http.StatusNotFound, contract.CodeNotFound)
		})
	}
	// Another app's name with that app's own secret is that app, over the
	// development transport: the signature alone authenticates.
	c := call{method: http.MethodGet, target: target, app: "mailie", secret: secretB}
	if a := h.send(t, c); a.status != http.StatusNotFound || a.code(t) != contract.CodeNotFound {
		t.Fatalf("mailie: %d %s", a.status, a.body)
	} else {
		h.verified(t, a, []string{secretB}, "mailie", http.MethodGet, target)
	}
}

func TestASignatureThatDoesNotHoldIsRefusedUnsignedBeforeTheCall(t *testing.T) {
	h := newHarness(t, contracttest.Options{Apps: []contracttest.App{wappie()}})
	if _, err := h.p.AddAccount(anaSub); err != nil {
		t.Fatal(err)
	}
	target := "/contract/v1/accounts/" + anaSub
	for name, tc := range map[string]struct {
		c    call
		code string
	}{
		"another secret":              {call{secret: secretB}, contract.CodeUnauthenticated},
		"no signature":                {call{unsignedHeaders: true}, contract.CodeUnauthenticated},
		"a minute and a second ago":   {call{at: time.Unix(1_760_300_000-61, 0)}, contract.CodeStale},
		"a minute and a second ahead": {call{at: time.Unix(1_760_300_000+61, 0)}, contract.CodeStale},
		"two signatures": {call{header: http.Header{contract.HeaderSignature: {"v1=" + strings.Repeat("0", 64), "v1=" + strings.Repeat("1", 64)}}},
			contract.CodeUnauthenticated},
		"a signature over another target": {call{}, contract.CodeUnauthenticated},
	} {
		t.Run(name, func(t *testing.T) {
			c := tc.c
			c.method, c.target, c.app = http.MethodPut, target, "wappie"
			if name == "a signature over another target" {
				// Signed for the subscription of another account, sent to
				// this one.
				c.target = "/contract/v1/accounts/" + bobSub
				signed := http.Header{}
				_ = contract.Scheme().Sign(signed, secretA, contract.ToPlatform, "wappie", http.MethodPut, target, nil, h.clock.Now())
				c.header = signed
			}
			h.send(t, c).wantUnsigned(t, http.StatusUnauthorized, tc.code)
		})
	}
	// A request's direction cannot be turned: an answer's signature is no
	// request's.
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	contract.SignAnswer(r.Header, secretA, "wappie", http.MethodPut, target, "AAAAAAAAAAAAAAAAAAAAAA", nil, h.clock.Now())
	r.Header.Set(contract.HeaderApp, "wappie")
	h.send(t, call{method: http.MethodPut, target: target, app: "wappie", header: r.Header}).
		wantUnsigned(t, http.StatusUnauthorized, contract.CodeUnauthenticated)
	if h.p.Following("wappie", anaSub) {
		t.Fatal("a request whose signature did not hold subscribed")
	}
}

func TestANonceIsAdmittedOnceAndTheReplayIsRefusedSigned(t *testing.T) {
	h := newHarness(t, contracttest.Options{Apps: []contracttest.App{wappie()}})
	if _, err := h.p.AddAccount(anaSub); err != nil {
		t.Fatal(err)
	}
	target := "/contract/v1/accounts/" + anaSub
	signed := http.Header{}
	if err := contract.Scheme().Sign(signed, secretA, contract.ToPlatform, "wappie", http.MethodPut, target, nil, h.clock.Now()); err != nil {
		t.Fatal(err)
	}
	c := call{method: http.MethodPut, target: target, app: "wappie", header: signed}
	if first := h.send(t, c); first.status != http.StatusOK {
		t.Fatalf("first: %d %s", first.status, first.body)
	}
	h.wantSigned(t, h.send(t, c), c, http.StatusUnauthorized, contract.CodeReplay)
}

func TestDuringARotationEitherSecretSignsARequestAndTheCurrentOneSignsTheAnswer(t *testing.T) {
	app := wappie()
	app.Other = secretB
	h := newHarness(t, contracttest.Options{Apps: []contracttest.App{app}})
	if _, err := h.p.AddAccount(anaSub); err != nil {
		t.Fatal(err)
	}
	target := "/contract/v1/accounts/" + anaSub
	for _, secret := range []string{secretA, secretB} {
		a := h.send(t, call{method: http.MethodPut, target: target, app: "wappie", secret: secret})
		if a.status != http.StatusOK {
			t.Fatalf("signed with one of the two: %d %s", a.status, a.body)
		}
		h.verified(t, a, []string{secretA}, "wappie", http.MethodPut, target)
		if contract.VerifyAnswer(a.header, []string{secretB}, "wappie", http.MethodPut, target, a.nonce, a.body, h.clock.Now()) == nil {
			t.Fatal("the answer is signed with the other secret")
		}
	}
	h.send(t, call{method: http.MethodPut, target: target, app: "wappie", secret: secretC}).
		wantUnsigned(t, http.StatusUnauthorized, contract.CodeUnauthenticated)
	// The promote: B signs the answers, and A is still accepted.
	if err := h.p.SetSecrets("wappie", secretB, secretA); err != nil {
		t.Fatal(err)
	}
	a := h.send(t, call{method: http.MethodPut, target: target, app: "wappie", secret: secretA})
	h.verified(t, a, []string{secretB}, "wappie", http.MethodPut, target)
	for name, pair := range map[string][2]string{"empty": {"", ""}, "equal": {secretB, secretB}, "short": {secretB[:42], ""}} {
		if err := h.p.SetSecrets("wappie", pair[0], pair[1]); !errors.Is(err, contracttest.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAnUnknownCallIsNotFoundAndUnsigned(t *testing.T) {
	h := newHarness(t, contracttest.Options{Apps: []contracttest.App{wappie()}})
	for _, tc := range []struct{ method, target string }{
		{http.MethodGet, "/"},
		{http.MethodGet, "/contract/v1/accounts"},
		{http.MethodGet, "/contract/v1/accounts/"},
		{http.MethodGet, "/contract/v1/accounts/" + strings.ToUpper(anaSub)},
		{http.MethodGet, "/contract/v1/accounts/00000000-0000-0000-0000-000000000000"},
		{http.MethodGet, "/contract/v1/accounts/" + anaSub + "/"},
		{http.MethodPost, "/contract/v1/accounts/" + anaSub},
		{http.MethodPut, "/contract/v1/feed?after=0"},
		{http.MethodGet, "/contract/v1/events"},
		{http.MethodPost, "/contract/v1/workspaces/" + teamID + "/access"},
		{http.MethodPut, "/contract/v1/workspaces/" + teamID},
		{http.MethodPut, "/contract/v1//workspaces/" + teamID + "/access"},
		{http.MethodPut, "/contract/v2/workspaces/" + teamID + "/access"},
	} {
		h.send(t, call{method: tc.method, target: tc.target, app: "wappie", body: "{}"}).
			wantUnsigned(t, http.StatusNotFound, contract.CodeNotFound)
	}
}

func TestABodyOverItsCallsLimitIsRefusedUnsigned(t *testing.T) {
	h := newHarness(t, contracttest.Options{Apps: []contracttest.App{wappie()}})
	for _, tc := range []struct {
		method, target string
		limit          int
	}{
		{http.MethodPut, "/contract/v1/accounts/" + anaSub, contracttest.SmallBodyLimit},
		{http.MethodPost, "/contract/v1/events", contracttest.EventsBodyLimit},
		{http.MethodPut, "/contract/v1/workspaces/" + teamID + "/access", contracttest.SnapshotBodyLimit},
	} {
		h.send(t, call{method: tc.method, target: tc.target, app: "wappie", body: strings.Repeat(" ", tc.limit+1)}).
			wantUnsigned(t, http.StatusRequestEntityTooLarge, contract.CodeTooLarge)
	}
	// A call that takes no body refuses one at its limit, signed.
	c := call{method: http.MethodPut, target: "/contract/v1/accounts/" + anaSub, app: "wappie", body: "{}"}
	h.wantSigned(t, h.send(t, c), c, http.StatusBadRequest, contract.CodeInvalid)
}

func TestEachAppHasItsOwnRate(t *testing.T) {
	h := newHarness(t, contracttest.Options{Apps: []contracttest.App{wappie(), {ID: "mailie", Current: secretB}}, PerSecond: 3})
	target := "/contract/v1/accounts/" + anaSub
	for i := range 3 {
		if a := h.send(t, call{method: http.MethodGet, target: target, app: "wappie"}); a.status != http.StatusNotFound || a.header.Get(contract.HeaderSignature) == "" {
			t.Fatalf("request %d: %d", i, a.status)
		}
	}
	h.send(t, call{method: http.MethodGet, target: target, app: "wappie"}).
		wantUnsigned(t, http.StatusTooManyRequests, contract.CodeRateLimited)
	if a := h.send(t, call{method: http.MethodGet, target: target, app: "mailie", secret: secretB}); a.status == http.StatusTooManyRequests {
		t.Fatalf("another app waits on wappie's rate: %d", a.status)
	}
	h.clock.Add(time.Second)
	if a := h.send(t, call{method: http.MethodGet, target: target, app: "wappie"}); a.status == http.StatusTooManyRequests {
		t.Fatalf("a second later: %d", a.status)
	}
}

// A request with two defects meets the earlier check first, in the
// platform's order (the package's comment).
func TestTheRefusalsComeInThePlatformsOrder(t *testing.T) {
	h := newHarness(t, contracttest.Options{Apps: []contracttest.App{wappie()}, PerSecond: 1})
	account := "/contract/v1/accounts/" + anaSub
	stale := time.Unix(1_760_300_000-61, 0)
	// 1 before 2 and 3: an app nobody configured, with no signature.
	h.send(t, call{method: http.MethodGet, target: account, app: "vaultie", unsignedHeaders: true}).
		wantUnsigned(t, http.StatusNotFound, contract.CodeNotFound)
	// The one request a second: spent on a request whose call is unknown.
	h.send(t, call{method: http.MethodGet, target: "/nowhere", app: "wappie"}).
		wantUnsigned(t, http.StatusNotFound, contract.CodeNotFound)
	// 2 before 3: over the rate, with no signature.
	h.send(t, call{method: http.MethodGet, target: account, app: "wappie", unsignedHeaders: true}).
		wantUnsigned(t, http.StatusTooManyRequests, contract.CodeRateLimited)
	steps := []struct {
		name   string
		c      call
		status int
		code   string
		signed bool
	}{
		{"3 before 4: stale, to no call", call{method: http.MethodGet, target: "/nowhere", app: "wappie", at: stale}, http.StatusUnauthorized, contract.CodeStale, false},
		{"4 before 5: no call, signed with another secret", call{method: http.MethodGet, target: "/nowhere", app: "wappie", secret: secretB}, http.StatusNotFound, contract.CodeNotFound, false},
		{"4 before 5: too large, signed with another secret", call{method: http.MethodPut, target: account, app: "wappie", secret: secretB, body: strings.Repeat(" ", contracttest.SmallBodyLimit+1)}, http.StatusRequestEntityTooLarge, contract.CodeTooLarge, false},
		{"7 before the call: a query on a call that takes none, for an account nobody has", call{method: http.MethodGet, target: account + "?x=1", app: "wappie"}, http.StatusBadRequest, contract.CodeInvalid, true},
	}
	for _, s := range steps {
		h.clock.Add(time.Second)
		a := h.send(t, s.c)
		if s.signed {
			h.wantSigned(t, a, s.c, s.status, s.code)
		} else {
			a.wantUnsigned(t, s.status, s.code)
		}
	}
	// 5 before 6, and 6 before 7: a nonce used once, then sent again with
	// another secret, then with the right one and a query.
	signed := http.Header{}
	if err := contract.Scheme().Sign(signed, secretA, contract.ToPlatform, "wappie", http.MethodGet, account, nil, h.clock.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	h.clock.Add(time.Second)
	if a := h.send(t, call{method: http.MethodGet, target: account, app: "wappie", header: signed}); a.status != http.StatusNotFound {
		t.Fatalf("first: %d %s", a.status, a.body)
	}
	h.clock.Add(time.Second)
	other := http.Header{}
	_ = contract.Scheme().Sign(other, secretB, contract.ToPlatform, "wappie", http.MethodGet, account, nil, h.clock.Now())
	other.Set(contract.HeaderNonce, signed.Get(contract.HeaderNonce))
	h.send(t, call{method: http.MethodGet, target: account, app: "wappie", header: other}).
		wantUnsigned(t, http.StatusUnauthorized, contract.CodeUnauthenticated)
	h.clock.Add(time.Second)
	query := http.Header{}
	_ = contract.Scheme().Sign(query, secretA, contract.ToPlatform, "wappie", http.MethodGet, account+"?x=1", nil, h.clock.Now())
	query.Set(contract.HeaderNonce, signed.Get(contract.HeaderNonce))
	query.Set(contract.HeaderSignature, contract.Scheme().Signature(secretA, contract.ToPlatform, "wappie", http.MethodGet, account+"?x=1",
		query.Get(contract.HeaderTimestamp), signed.Get(contract.HeaderNonce), nil))
	c := call{method: http.MethodGet, target: account + "?x=1", app: "wappie", header: query}
	a := h.send(t, c)
	a.nonce = signed.Get(contract.HeaderNonce)
	h.wantSigned(t, a, c, http.StatusUnauthorized, contract.CodeReplay)
}

func TestTheFeedTakesAfterAndAnOptionalWaitOnly(t *testing.T) {
	h := newHarness(t, contracttest.Options{Apps: []contracttest.App{wappie()}, PerSecond: 1000})
	for _, q := range []string{
		"", "?", "?wait=1", "?after=", "?after=-1", "?after=01", "?after=1&after=2", "?after=0&wait=26", "?after=0&wait=",
		"?after=0&wait=1&wait=1", "?after=0&limit=5", "?after=+1", "?after=1%20", "?after=99999999999999999999", "?after=1;wait=1",
		"?after=%31", "?a%66ter=1", "?after=0&", "?&after=0", "?after=0&&wait=2",
	} {
		c := call{method: http.MethodGet, target: "/contract/v1/feed" + q, app: "wappie"}
		h.wantSigned(t, h.send(t, c), c, http.StatusBadRequest, contract.CodeInvalid)
	}
	for _, q := range []string{"?after=0", "?after=0&wait=0", "?wait=0&after=0"} {
		target := "/contract/v1/feed" + q
		a := h.send(t, call{method: http.MethodGet, target: target, app: "wappie"})
		if a.status != http.StatusOK {
			t.Errorf("%s: %d %s", q, a.status, a.body)
		}
		h.verified(t, a, []string{secretA}, "wappie", http.MethodGet, target)
	}
	// A cursor past the head is gone.
	c := call{method: http.MethodGet, target: "/contract/v1/feed?after=1", app: "wappie"}
	h.wantSigned(t, h.send(t, c), c, http.StatusGone, contract.CodeGone)
}

// longPoll sends a feed request that waits, in the background.
func (h *harness) longPoll(t *testing.T, wait int) <-chan answer {
	t.Helper()
	out := make(chan answer, 1)
	go func() {
		out <- h.send(t, call{method: http.MethodGet, target: fmt.Sprintf("/contract/v1/feed?after=0&wait=%d", wait), app: "wappie"})
	}()
	return out
}

func TestALongPollAnswersWhenADocumentIsPublished(t *testing.T) {
	h := newHarness(t, contracttest.Options{Apps: []contracttest.App{wappie()}, Now: time.Now})
	h.clock = &clock{t: time.Now()}
	got := h.longPoll(t, 25)
	time.Sleep(50 * time.Millisecond) // most likely waiting by now; either way it sees the document
	if _, err := h.p.AddAccount(anaSub); err != nil {
		t.Fatal(err)
	}
	if _, err := h.p.Client("wappie").Subscribe(t.Context(), anaSub); err != nil {
		t.Fatal(err)
	}
	select {
	case a := <-got:
		var f contract.Feed
		if err := json.Unmarshal(a.body, &f); err != nil || len(f.Items) != 1 || f.Items[0].Seq != 1 || f.Items[0].Doc.Sub != anaSub {
			t.Fatalf("woken: %d %s", a.status, a.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the long-poll was not woken")
	}
}

func TestADrainEndsEveryLongPollAtOnceAndNoneWaitsAfter(t *testing.T) {
	p, err := contracttest.New(contracttest.Options{Apps: []contracttest.App{wappie()}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	c := &contract.Client{App: "wappie", Secret: secretA, Base: srv.URL, HTTP: srv.Client()}
	done := make(chan error, 1)
	go func() {
		_, err := c.Feed(t.Context(), 0, 25)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	p.Close()
	for i := range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("drained: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the drain did not end the long-poll")
		}
		if i == 0 {
			go func() {
				_, err := c.Feed(t.Context(), 0, 25)
				done <- err
			}()
		}
	}
}

func TestALongPollEndsOnItsTimerAndOnlyFourWaitAtOnce(t *testing.T) {
	h := newHarness(t, contracttest.Options{Apps: []contracttest.App{wappie()}, Now: time.Now})
	h.clock = &clock{t: time.Now()}
	start := time.Now()
	a := h.send(t, call{method: http.MethodGet, target: "/contract/v1/feed?after=0&wait=1", app: "wappie", at: time.Now()})
	if a.status != http.StatusOK || time.Since(start) < time.Second {
		t.Fatalf("the timer: %d after %v", a.status, time.Since(start))
	}
	var waiting []<-chan answer
	for range contracttest.DefaultLongPolls {
		waiting = append(waiting, h.longPoll(t, 25))
	}
	time.Sleep(200 * time.Millisecond) // the four take their places
	c := call{method: http.MethodGet, target: "/contract/v1/feed?after=0&wait=25", app: "wappie", at: time.Now()}
	fifth := h.send(t, c)
	h.wantSigned(t, fifth, c, http.StatusTooManyRequests, contract.CodeRateLimited)
	h.p.Close()
	for _, w := range waiting {
		<-w
	}
}

func TestASnapshotIsDecodedStrictly(t *testing.T) {
	h := newHarness(t, contracttest.Options{Apps: []contracttest.App{wappie()}, PerSecond: 1000})
	personal, err := h.p.AddAccount(anaSub)
	if err != nil {
		t.Fatal(err)
	}
	target := "/contract/v1/workspaces/" + personal + "/access"
	good := `{"v":1,"snapshot_seq":5,"items":[]}`
	// Not named to the app until a document of one of its people names it.
	c := call{method: http.MethodPut, target: target, app: "wappie", body: good}
	h.wantSigned(t, h.send(t, c), c, http.StatusNotFound, contract.CodeNotFound)
	if _, err := h.p.Client("wappie").Subscribe(t.Context(), anaSub); err != nil {
		t.Fatal(err)
	}
	a := h.send(t, c)
	if a.status != http.StatusOK || string(a.body) != `{"accepted":true}` {
		t.Fatalf("a snapshot: %d %s", a.status, a.body)
	}
	h.verified(t, a, []string{secretA}, "wappie", http.MethodPut, target)
	for _, body := range []string{
		``, `null`, `[]`, `{"v":1,"snapshot_seq":5,"items":[],"extra":1}`, `{"v":1,"v":1,"snapshot_seq":5,"items":[]}`,
		good + good, `{"v":1,"snapshot_seq":"5","items":[]}`, `{"V":1,"snapshot_seq":5,"items":[]}`,
		"{\"v\":1,\"snapshot_seq\":5,\"items\":[{\"id\":\"n\xff\"}]}", `{"v":2,"snapshot_seq":5,"items":[]}`,
		// Half a surrogate pair, escaped: the platform's json/v2 refuses
		// it, where encoding/json would read U+FFFD.
		labelled(`Vendas \ud800`), labelled(`\udc00x`), labelled(`\ud800\u0041`), labelled(`\ud83d`),
		`{"v":1,"snapshot_seq":5,"items":[],"\udc00":1}`,
	} {
		c := call{method: http.MethodPut, target: target, app: "wappie", body: body}
		h.wantSigned(t, h.send(t, c), c, http.StatusBadRequest, contract.CodeInvalid)
	}
	// A whole pair, and an escaped backslash before a "u", are text.
	for _, label := range []string{`Vendas`, `Vendas \ud83d\ude00`, `Vendas \\ud800`} {
		c := call{method: http.MethodPut, target: target, app: "wappie", body: labelled(label)}
		if a := h.send(t, c); a.status != http.StatusOK {
			t.Fatalf("the label %s: %d %s", label, a.status, a.body)
		}
	}
	// An older snapshot is accepted and ignored; one more than a day ahead
	// of the platform's clock is refused.
	older := call{method: http.MethodPut, target: target, app: "wappie", body: `{"v":1,"snapshot_seq":4,"items":[]}`}
	if a := h.send(t, older); a.status != http.StatusOK {
		t.Fatalf("an older snapshot: %d %s", a.status, a.body)
	}
	if s, ok := h.p.Snapshot("wappie", personal); !ok || s.SnapshotSeq != 5 {
		t.Fatalf("kept %+v %v", s, ok)
	}
	ahead := h.clock.Now().Add(contracttest.MaxSnapshotAhead + time.Minute).UnixMilli()
	c = call{method: http.MethodPut, target: target, app: "wappie", body: fmt.Sprintf(`{"v":1,"snapshot_seq":%d,"items":[]}`, ahead)}
	h.wantSigned(t, h.send(t, c), c, http.StatusBadRequest, contract.CodeInvalid)
}

// labelled is a snapshot of one valid number whose label is the JSON text
// label, unquoted.
func labelled(label string) string {
	return `{"v":1,"snapshot_seq":5,"items":[{"id":"n1","kind":"number","label":"` + label + `","hint":null,"state":"active",` +
		`"reason":null,"purge_at":null,"other_backups":0,"people":[],"protected":[]}]}`
}

func TestAnEventThatDoesNotDecodeIsRejectedAloneAndTheBatchGoesOn(t *testing.T) {
	h := newHarness(t, contracttest.Options{Apps: []contracttest.App{wappie()}, PerSecond: 1000})
	personal, err := h.p.AddAccount(anaSub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.p.Client("wappie").Subscribe(t.Context(), anaSub); err != nil {
		t.Fatal(err)
	}
	ev := func(id, ws string) string {
		return `{"event_id":"` + id + `","workspace_id":"` + ws + `","type":"item.recovered","occurred_at":"2026-10-13T12:00:00Z",` +
			`"item":{"id":"n1","kind":"number","label":null,"hint":null},"actor":"` + anaSub + `","actor_kind":"person","readers":[]}`
	}
	bad := strings.Replace(ev(eventB, personal), `"readers":[]`, `"readers":[],"phone":"+5511912345678"`, 1)
	cased := strings.Replace(ev(eventB, personal), `"actor_kind"`, `"Actor_kind"`, 1)
	body := `{"events":[` + ev(eventA, personal) + `,` + bad + `,{"event_id":7},` + cased + `,` + ev(eventB, teamID) + `]}`
	a := h.send(t, call{method: http.MethodPost, target: "/contract/v1/events", app: "wappie", body: body})
	if a.status != http.StatusOK {
		t.Fatalf("events: %d %s", a.status, a.body)
	}
	h.verified(t, a, []string{secretA}, "wappie", http.MethodPost, "/contract/v1/events")
	var got contract.EventResults
	if err := json.Unmarshal(a.body, &got); err != nil || len(got.Results) != 5 {
		t.Fatalf("results: %v %s", err, a.body)
	}
	want := []string{
		eventA + " accepted <nil>", eventB + " rejected invalid_request", " rejected invalid_request",
		eventB + " rejected invalid_request", eventB + " rejected not_found",
	}
	for i, r := range got.Results {
		code := "<nil>"
		if r.Code != nil {
			code = *r.Code
		}
		if s := r.EventID + " " + r.Outcome + " " + code; s != want[i] {
			t.Errorf("result %d: %s, want %s", i, s, want[i])
		}
	}
	if evs := h.p.Events("wappie"); len(evs) != 1 || evs[0].EventID != eventA {
		t.Fatalf("the platform kept %d events", len(evs))
	}
	// The same event again is a duplicate; its id with other content is a
	// conflict.
	again := `{"events":[` + ev(eventA, personal) + `,` + strings.Replace(ev(eventA, personal), `"n1"`, `"n2"`, 1) + `]}`
	a = h.send(t, call{method: http.MethodPost, target: "/contract/v1/events", app: "wappie", body: again})
	if err := json.Unmarshal(a.body, &got); err != nil || len(got.Results) != 2 ||
		got.Results[0].Outcome != contract.OutcomeDuplicate || got.Results[1].Outcome != contract.OutcomeRejected || *got.Results[1].Code != contract.CodeConflict {
		t.Fatalf("again: %s", a.body)
	}
	for _, body := range []string{
		`{"events":[]}`, `{"events":null}`, `{}`, `{"Events":[` + ev(eventA, personal) + `]}`,
		`{"events":[` + strings.Repeat(ev(eventA, personal)+",", 100) + ev(eventA, personal) + `]}`,
		`{"events":[` + strings.Replace(ev(eventA, personal), `"type"`, `"type":"item.purged","type"`, 1) + `]}`,
		// Half a surrogate pair anywhere in the batch: the platform's json/v2
		// refuses the batch's text, so the whole batch.
		`{"events":[` + ev(eventA, personal) + `,` + strings.Replace(ev(eventB, personal), `"label":null`, `"label":"\udc00x"`, 1) + `]}`,
		// A body that is not valid UTF-8 or not JSON, though its first event
		// is good: the whole call (SPEC section 11.17's wire rules).
		`{"events":[` + ev(eventA, personal) + `,` + strings.Replace(ev(eventB, personal), `"label":null`, "\"label\":\"a\xffb\"", 1) + `]}`,
		`{"events":[` + ev(eventA, personal) + `,{"event_id":}]}`,
		`{"events":[` + ev(eventA, personal) + `]}{}`,
	} {
		c := call{method: http.MethodPost, target: "/contract/v1/events", app: "wappie", body: body}
		h.wantSigned(t, h.send(t, c), c, http.StatusBadRequest, contract.CodeInvalid)
	}
}

func TestNewRefusesAppsThatCouldBeMistakenForOneAnother(t *testing.T) {
	for name, apps := range map[string][]contracttest.App{
		"no id":              {{ID: "", Current: secretA}},
		"an id with a dot":   {{ID: "wappie.", Current: secretA}},
		"twice":              {{ID: "wappie", Current: secretA}, {ID: "wappie", Current: secretB}},
		"no secret":          {{ID: "wappie"}},
		"a short secret":     {{ID: "wappie", Current: secretA[:42]}},
		"the other is equal": {{ID: "wappie", Current: secretA, Other: secretA}},
	} {
		if _, err := contracttest.New(contracttest.Options{Apps: apps}); !errors.Is(err, contracttest.ErrOptions) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAnAppNeverPrintsItsSecrets(t *testing.T) {
	a := contracttest.App{ID: "wappie", Current: secretA, Other: secretB}
	var logged strings.Builder
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("app", "app", a)
	slog.New(slog.NewTextHandler(&logged, nil)).Info("app", "app", a)
	encoded, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{fmt.Sprintf("%v %+v %#v %s", a, a, a, a), fmt.Sprintf("%v", &a), logged.String(), string(encoded)} {
		if strings.Contains(s, secretA[:10]) || strings.Contains(s, secretB[:10]) {
			t.Fatalf("an app prints its secret: %s", s)
		}
	}
}
