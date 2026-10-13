package contract_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
	for _, s := range []string{fmt.Sprintf("%v %+v %#v %s", c, c, c, c), fmt.Sprintf("%v", &c), logged.String()} {
		if strings.Contains(s, clientSecret[:10]) {
			t.Fatalf("the secret printed: %s", s)
		}
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
