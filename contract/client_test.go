package contract_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/thehappieco/kit/contract"
)

var clientSecret = strings.Repeat("A", contract.SecretLen)

// platformAnswering serves one signed answer to every request: body, signed
// with secret for app.
func platformAnswering(t *testing.T, secret, app string, body any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(body)
		contract.SignAnswer(w.Header(), secret, app, r.Method, r.RequestURI, r.Header.Get(contract.HeaderNonce), b, time.Now())
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func doc(app, sub string) contract.AccountDoc {
	return contract.AccountDoc{V: contract.DocV, Type: contract.DocType, App: app, Generation: "0199b1e0-0000-7000-8000-000000000001",
		Sub: sub, Version: 1, Status: contract.AccountActive, Workspaces: []contract.Workspace{}}
}

const (
	subA = "0199a0c2-0000-7000-8000-000000000001"
	subB = "0199a0c2-0000-7000-8000-000000000002"
)

func TestTheClientTakesOnlyItsOwnAccountsDocument(t *testing.T) {
	srv := platformAnswering(t, clientSecret, "wappie", doc("wappie", subB))
	c := &contract.Client{App: "wappie", Secret: clientSecret, Base: srv.URL}
	if _, err := c.Subscribe(t.Context(), subA); !errors.Is(err, contract.ErrUnverified) {
		t.Fatalf("another account's document: %v", err)
	}
	other := platformAnswering(t, clientSecret, "wappie", doc("mailie", subA))
	c.Base = other.URL
	if _, err := c.Account(t.Context(), subA); !errors.Is(err, contract.ErrUnverified) {
		t.Fatalf("another app's document: %v", err)
	}
	good := platformAnswering(t, clientSecret, "wappie", doc("wappie", subA))
	c.Base = good.URL
	if d, err := c.Subscribe(t.Context(), subA); err != nil || d.Sub != subA {
		t.Fatalf("its own: %+v %v", d, err)
	}
}

func TestTheClientRefusesAnEmptyKeyAmongTheSecretsItAccepts(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	t.Cleanup(srv.Close)
	c := &contract.Client{App: "wappie", Secret: clientSecret, Accept: []string{clientSecret, ""}, Base: srv.URL}
	if _, _, err := c.Do(t.Context(), http.MethodGet, "/contract/v1/feed?after=0", nil); !errors.Is(err, contract.ErrSecret) || called {
		t.Fatalf("an empty accepted key: %v, sent %t", err, called)
	}
}

func TestTheClientNeverPrintsItsSecrets(t *testing.T) {
	c := contract.Client{App: "wappie", Secret: clientSecret, Accept: []string{clientSecret}, Base: "http://127.0.0.1:8291"}
	var logged strings.Builder
	slog.New(slog.NewTextHandler(&logged, nil)).Info("client", "c", c)
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("client", "c", c)
	for _, s := range []string{fmt.Sprintf("%v %+v %#v %s", c, c, c, c), fmt.Sprintf("%v", &c), logged.String()} {
		if strings.Contains(s, clientSecret[:10]) {
			t.Fatalf("the secret printed: %s", s)
		}
	}
	// The secrets are no JSON members either, whatever the other fields'
	// types make of json.Marshal.
	for _, name := range []string{"Secret", "Accept"} {
		if f, _ := reflect.TypeFor[contract.Client]().FieldByName(name); f.Tag.Get("json") != "-" {
			t.Errorf("Client.%s is a JSON member", name)
		}
	}
}

// An app holds a *Client, as the Client's comment asks: in an unexported
// field of the app's own struct, where fmt cannot call String, a pointer
// prints as its address, while a Client held by value there prints its
// secrets, which is why the comment asks for the pointer.
func TestAnAppHoldsItsClientByPointer(t *testing.T) {
	type server struct {
		name   string
		client *contract.Client
	}
	s := server{name: "wappie", client: &contract.Client{App: "wappie", Secret: clientSecret, Accept: []string{clientSecret}, Base: "http://contract"}}
	var logged strings.Builder
	slog.New(slog.NewTextHandler(&logged, nil)).Info("server", "s", s)
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("server", "s", s)
	for _, printed := range []string{fmt.Sprintf("%v %+v %#v", s, s, s), fmt.Sprintf("%v %+v %#v", &s, &s, &s), logged.String()} {
		if strings.Contains(printed, clientSecret[:10]) {
			t.Fatalf("the secret printed: %s", printed)
		}
	}
	type byValue struct{ client contract.Client }
	if !strings.Contains(fmt.Sprintf("%v", byValue{*s.client}), clientSecret[:10]) {
		t.Fatal("a Client held by value in an unexported field no longer prints raw: the Client's comment can say less")
	}
	// A verb a pointer does not take prints what it points to, so an app
	// prints such a struct with %v or not at all.
	for _, verb := range []string{"%s", "%q"} {
		if !strings.Contains(fmt.Sprintf(verb, s), clientSecret[:10]) || !strings.Contains(fmt.Sprintf(verb, &s), clientSecret[:10]) {
			t.Fatalf("%s no longer prints the secret of a *Client in an unexported field: the Client's comment, SECURITY.md and SPEC 11.17 can say less", verb)
		}
	}
}

// A signed answer that is not valid moves nothing: the call returns the
// zero value, and the error is ErrUnverified, and ErrInvalid where a rule
// failed.
func TestAnAnswerThatDoesNotValidateComesWithNothing(t *testing.T) {
	notAUUID := doc("wappie", subA)
	notAUUID.Generation = "not-a-uuid"
	feed := contract.Feed{Generation: "not-a-uuid", Head: 9, NextAfter: 9, Items: []contract.FeedItem{}}
	for name, tc := range map[string]struct {
		answer  any
		invalid bool
		call    func(c *contract.Client) (any, error)
	}{
		"a feed whose generation is no UUID": {feed, true, func(c *contract.Client) (any, error) { return c.Feed(t.Context(), 0, 0) }},
		"a document that is not valid": {notAUUID, true, func(c *contract.Client) (any, error) {
			return c.Subscribe(t.Context(), subA)
		}},
		"another account's document": {doc("wappie", subB), false, func(c *contract.Client) (any, error) {
			return c.Account(t.Context(), subA)
		}},
		"a document that does not decode": {map[string]any{"version": "five"}, false, func(c *contract.Client) (any, error) {
			return c.Subscribe(t.Context(), subA)
		}},
	} {
		srv := platformAnswering(t, clientSecret, "wappie", tc.answer)
		c := &contract.Client{App: "wappie", Secret: clientSecret, Base: srv.URL}
		got, err := tc.call(c)
		if !errors.Is(err, contract.ErrUnverified) || errors.Is(err, contract.ErrInvalid) != tc.invalid {
			t.Errorf("%s: %v", name, err)
		}
		switch v := got.(type) {
		case contract.Feed:
			if v.NextAfter != 0 || v.Generation != "" || v.Items != nil {
				t.Errorf("%s: came with %+v", name, v)
			}
		case contract.AccountDoc:
			if v.Sub != "" || v.Version != 0 {
				t.Errorf("%s: came with %+v", name, v)
			}
		}
	}
}

// A platform that never answers ends a call in context.DeadlineExceeded,
// whatever the caller's context, and the error names no account.
func TestACallToAPlatformThatStallsEnds(t *testing.T) {
	defer contract.ShortenTimeouts(200*time.Millisecond, 200*time.Millisecond)()
	stalled := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-stalled:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(stalled) })
	c := &contract.Client{App: "wappie", Secret: clientSecret, Base: srv.URL}
	for name, call := range map[string]func() error{
		"Subscribe": func() error { _, err := c.Subscribe(context.Background(), subA); return err },
		"Feed":      func() error { _, err := c.Feed(context.Background(), 0, 0); return err },
		"PutAccess": func() error {
			return c.PutAccess(context.Background(), subB, contract.Snapshot{V: 1, SnapshotSeq: 1, Items: []contract.Item{}})
		},
	} {
		done := make(chan error, 1)
		go func() { done <- call() }()
		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("%s: %v, want context.DeadlineExceeded", name, err)
			} else if strings.Contains(err.Error(), subA) || strings.Contains(err.Error(), subB) || strings.Contains(err.Error(), srv.URL) {
				t.Errorf("%s: the error names the request's URL: %v", name, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: still waiting", name)
		}
	}
}

// A request that never reached the platform says so without its URL.
func TestATransportErrorNamesNoAccountOrWorkspace(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	srv.Close()
	c := &contract.Client{App: "wappie", Secret: clientSecret, Base: base}
	_, err := c.Subscribe(t.Context(), subA)
	if err == nil || strings.Contains(err.Error(), subA) || strings.Contains(err.Error(), base) ||
		!strings.Contains(err.Error(), "PUT /contract/v1/accounts/{id}") {
		t.Fatalf("a refused connection: %v", err)
	}
	err = c.PutAccess(t.Context(), subB, contract.Snapshot{V: 1, SnapshotSeq: 1, Items: []contract.Item{}})
	if err == nil || strings.Contains(err.Error(), subB) || !strings.Contains(err.Error(), "/workspaces/{id}/access") {
		t.Fatalf("a refused connection: %v", err)
	}
	// The token part's calls name their route, never a token's id or
	// selector.
	_, err = c.Token(t.Context(), subA)
	if err == nil || strings.Contains(err.Error(), subA) || !strings.Contains(err.Error(), "GET /contract/v1/tokens/{id}") {
		t.Fatalf("a refused connection: %v", err)
	}
	_, err = c.TokenBySelector(t.Context(), "9f3c0a7be41d2c58")
	if err == nil || strings.Contains(err.Error(), "9f3c0a7be41d2c58") || !strings.Contains(err.Error(), "GET /contract/v1/token-selectors/{id}") {
		t.Fatalf("a refused connection: %v", err)
	}
	err = c.TokenUsage(t.Context(), contract.TokenUsage{Used: []contract.TokenUsed{}, Refusals: []contract.UsageRefusal{}})
	if err == nil || !strings.Contains(err.Error(), "POST /contract/v1/tokens/usage") {
		t.Fatalf("a refused connection: %v", err)
	}
	// The settings part's calls name their route, never a workspace or a
	// person.
	err = c.PutSettings(t.Context(), contract.SettingsDoc{WorkspaceID: subB, Section: contract.SectionNumbers})
	if err == nil || strings.Contains(err.Error(), subB) || !strings.Contains(err.Error(), "PUT /contract/v1/workspaces/{id}/settings/{id}") {
		t.Fatalf("a refused connection: %v", err)
	}
	err = c.PutPersonSettings(t.Context(), contract.PersonSettingsDoc{Sub: subA})
	if err == nil || strings.Contains(err.Error(), subA) || !strings.Contains(err.Error(), "PUT /contract/v1/accounts/{id}/settings") {
		t.Fatalf("a refused connection: %v", err)
	}
	_, _, err = c.Commands(t.Context(), 0, 0)
	if err == nil || !strings.Contains(err.Error(), "GET /contract/v1/commands") {
		t.Fatalf("a refused connection: %v", err)
	}
	_, err = c.PostResults(t.Context(), []contract.CommandResult{})
	if err == nil || !strings.Contains(err.Error(), "POST /contract/v1/commands/results") {
		t.Fatalf("a refused connection: %v", err)
	}
}

// A settings call refuses, before it sends anything, a path it could not
// build: a workspace or sub that is no UUID, or a section of another app.
func TestASettingsCallSendsNothingItCannotRoute(t *testing.T) {
	c := &contract.Client{App: "wappie", Secret: clientSecret, Base: "http://127.0.0.1:1"}
	for _, doc := range []contract.SettingsDoc{
		{WorkspaceID: "../feed", Section: contract.SectionNumbers},
		{WorkspaceID: subB, Section: contract.SectionEmailAccounts},
		{WorkspaceID: subB, Section: contract.SectionPerson},
		{WorkspaceID: subB, Section: "numbers/../../feed"},
	} {
		if err := c.PutSettings(t.Context(), doc); !errors.Is(err, contract.ErrInvalid) {
			t.Errorf("%q %q: %v", doc.WorkspaceID, doc.Section, err)
		}
	}
	if err := c.PutPersonSettings(t.Context(), contract.PersonSettingsDoc{Sub: "x"}); !errors.Is(err, contract.ErrInvalid) {
		t.Errorf("a sub that is no UUID: %v", err)
	}
}

// The default client follows no redirect: its answer is not signed for the
// request.
func TestTheClientFollowsNoRedirect(t *testing.T) {
	followed := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed = true }))
	t.Cleanup(target.Close)
	srv := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusTemporaryRedirect))
	t.Cleanup(srv.Close)
	c := &contract.Client{App: "wappie", Secret: clientSecret, Base: srv.URL}
	if _, err := c.Account(t.Context(), subA); !errors.Is(err, contract.ErrUnverified) || followed {
		t.Fatalf("a redirect: %v, followed %t", err, followed)
	}
}

func TestATimeCarriesAtMostNineFractionalDigitsAndStartsAt1970(t *testing.T) {
	var tm contract.Time
	for _, bad := range []string{
		`"2026-10-13T12:00:00.1234567890Z"`, `"0000-01-01T00:00:00Z"`, `"1969-12-31T23:59:59Z"`,
		// RFC 3339 has no comma before the fraction, though time.Parse takes one.
		`"2026-10-13T12:00:00,5Z"`, `"2026-10-13T12:00:00,123456789123Z"`,
		`"2026-10-13T12:00:00.Z"`, `"2026-10-13 12:00:00Z"`, `"2026-10-13t12:00:00Z"`, `"+2026-10-13T12:00:00Z"`,
	} {
		if err := json.Unmarshal([]byte(bad), &tm); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if err := json.Unmarshal([]byte(`"2026-10-13T12:00:00.123456789Z"`), &tm); err != nil {
		t.Fatal(err)
	}
}
