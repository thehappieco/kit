package contract_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thehappieco/kit/contract"
)

// The client's calls of the entitlements part (SPEC section 11.20): what
// each refuses before it sends anything, and which answers it takes.

// platformAnsweringRaw serves one signed answer to every request: body as
// it is, with status, signed with secret for app. It records the last
// request's body.
func platformAnsweringRaw(t *testing.T, secret, app string, status int, body string, got *[]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got != nil {
			*got, _ = io.ReadAll(r.Body)
		}
		contract.SignAnswer(w.Header(), secret, app, r.Method, r.RequestURI, r.Header.Get(contract.HeaderNonce), []byte(body), time.Now())
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The GET's document must be the app's own document of the workspace it
// asked for, valid, whatever its signature; the call returns the time the
// platform signed it.
func TestTheEntitlementsGETTakesOnlyTheAppsDocumentOfItsWorkspace(t *testing.T) {
	srv := platformAnswering(t, clientSecret, "wappie", entDoc("wappie", nil))
	c := &contract.Client{App: "wappie", Secret: clientSecret, Base: srv.URL}
	before := time.Now().Add(-time.Second)
	d, signedAt, err := c.EntitlementsDoc(t.Context(), vecTeam)
	if err != nil || d.Version != 57 || d.WorkspaceID != vecTeam || signedAt.Before(before.Truncate(time.Second)) || signedAt.After(time.Now()) {
		t.Fatalf("its own document: %+v %v %v", d.Version, signedAt, err)
	}
	if _, _, err := c.EntitlementsDoc(t.Context(), "0199b1e0-0000-7000-8000-0000000000ff"); !errors.Is(err, contract.ErrUnverified) {
		t.Errorf("another workspace's document: %v", err)
	}
	if _, _, err := c.EntitlementsDoc(t.Context(), "0199b1e0-0000-7000-8000-0000000000ff"); !errors.Is(err, contract.ErrForeignDocument) {
		t.Errorf("another workspace's document is not ErrForeignDocument: %v", err)
	}
	for name, body := range map[string]struct {
		body    any
		foreign bool
	}{
		"another app's":        {entDoc("mailie", nil), true},
		"one that is no valid": {entDoc("wappie", func(d *contract.EntitlementsDoc) { d.Version = 0 }), false},
		"one missing a member": {map[string]any{"v": 1}, false},
	} {
		other := platformAnswering(t, clientSecret, "wappie", body.body)
		c := &contract.Client{App: "wappie", Secret: clientSecret, Base: other.URL}
		d, at, err := c.EntitlementsDoc(t.Context(), vecTeam)
		if !errors.Is(err, contract.ErrUnverified) || d.Version != 0 || !at.IsZero() {
			t.Errorf("%s document: %v", name, err)
		}
		// A foreign document is told apart from a bad one by its own
		// sentinel, never by its text; it is not ErrInvalid, and names no
		// id.
		if errors.Is(err, contract.ErrForeignDocument) != body.foreign || errors.Is(err, contract.ErrInvalid) == body.foreign {
			t.Errorf("%s document: %v", name, err)
		}
		if strings.Contains(err.Error(), vecTeam) {
			t.Errorf("%s document: the error names the workspace: %v", name, err)
		}
	}
}

// Each call refuses what it could not send as the contract says, before it
// sends anything: a path that is no UUID, a body that does not validate,
// a report of another workspace or app.
func TestAnEntitlementsCallSendsNothingThatIsNotValid(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	t.Cleanup(srv.Close)
	c := &contract.Client{App: "wappie", Secret: clientSecret, Base: srv.URL, Now: func() time.Time { return usageMeasured }}
	ctx := t.Context()
	for name, call := range map[string]func() error{
		"a GET of no workspace": func() error { _, _, err := c.EntitlementsDoc(ctx, "../feed"); return err },
		"an acknowledgement of no generation": func() error {
			return c.EntitlementsApplied(ctx, contract.EntitlementsApplied{Generation: "x", Through: 1})
		},
		"an acknowledgement refusing past its through": func() error {
			return c.EntitlementsApplied(ctx, contract.EntitlementsApplied{Generation: vecGeneration, Through: 1,
				Refused: contract.EntitlementsRefusals{{Seq: 2, Code: contract.RefusedAnotherApp}}})
		},
		"usage of no workspace": func() error { _, err := c.PutUsage(ctx, "x", usage("wappie", nil)); return err },
		"usage of another workspace": func() error {
			_, err := c.PutUsage(ctx, "0199b1e0-0000-7000-8000-0000000000ff", usage("wappie", nil))
			return err
		},
		"another app's usage": func() error { _, err := c.PutUsage(ctx, vecTeam, usage("mailie", nil)); return err },
		"usage whose total is not its sum": func() error {
			_, err := c.PutUsage(ctx, vecTeam, usage("wappie", func(u *contract.Usage) { u.TotalBytes++ }))
			return err
		},
		"usage measured over a minute ahead of the app's clock": func() error {
			_, err := c.PutUsage(ctx, vecTeam, usage("wappie", func(u *contract.Usage) { u.MeasuredAt = contract.T(usageMeasured.Add(2 * time.Minute)) }))
			return err
		},
		"a link check of another kind": func() error {
			_, err := c.LinkCheck(ctx, vecTeam, contract.LinkCheck{Kind: contract.ItemMailbox})
			return err
		},
		"a link check with codes beside a connected item": func() error {
			_, err := c.LinkCheck(ctx, vecTeam, contract.LinkCheck{Kind: contract.ItemNumber, Codes: codes(t, 1), Connected: true})
			return err
		},
		"a link check of no workspace": func() error {
			_, err := c.LinkCheck(ctx, "x", contract.LinkCheck{Kind: contract.ItemNumber})
			return err
		},
		"a trim result that is not valid": func() error {
			_, err := c.PostTrimResult(ctx, trimResult(func(r *contract.TrimResult) { r.UsageSeq = nil }))
			return err
		},
	} {
		if err := call(); !errors.Is(err, contract.ErrInvalid) || errors.Is(err, contract.ErrUnverified) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if called {
		t.Fatal("a call that is not valid was sent")
	}
}

// A usage report's answer is {"accepted": true, "kept": bool}, a member the
// app does not know ignored; kept false is delivered as well as kept true.
func TestAUsageAnswerIsAcceptedAndKeptWithUnknownMembersIgnored(t *testing.T) {
	for body, want := range map[string]any{
		`{"accepted":true,"kept":true}`:         true,
		`{"accepted":true,"kept":false}`:        false,
		`{"accepted":true}`:                     contract.ErrUnverified,
		`{"accepted":false,"kept":true}`:        contract.ErrUnverified,
		`{"accepted":true,"kept":true,"x":1}`:   true,
		`{"accepted":true,"Kept":true}`:         contract.ErrUnverified,
		`{"accepted":true,"kept":null}`:         contract.ErrUnverified,
		`{"code":"not_found","message":"gone"}`: "not_found",
	} {
		var sent []byte
		srv := platformAnsweringRaw(t, clientSecret, "wappie", http.StatusOK, body, &sent)
		c := &contract.Client{App: "wappie", Secret: clientSecret, Base: srv.URL}
		now := time.Now()
		kept, err := c.PutUsage(t.Context(), vecTeam, usage("wappie", func(u *contract.Usage) {
			u.Items, u.TotalBytes, u.SharedBytes, u.MeasuredAt, u.UsageSeq = nil, 0, 0, contract.T(now), now.UnixMilli()
		}))
		switch want := want.(type) {
		case bool:
			if err != nil || kept != want {
				t.Errorf("%s: %t %v", body, kept, err)
			}
		case error:
			if !errors.Is(err, want) || kept {
				t.Errorf("%s: %t %v", body, kept, err)
			}
		case string:
			var r *contract.Refusal
			if !errors.As(err, &r) || r.Code != want {
				t.Errorf("%s: %v", body, err)
			}
		}
		// An empty report goes with items [], never null.
		if !strings.Contains(string(sent), `"items":[]`) {
			t.Errorf("%s: sent %s", body, sent)
		}
	}
}

// A link check goes with codes [] when it has none, and its answer must
// validate.
func TestALinkChecksAnswerMustValidate(t *testing.T) {
	var sent []byte
	good := `{"place":"free","trial":"not_needed","trial_ends_at":null,"switches":{"new_links":"on"},"computed_at":"2026-12-03T10:00:00Z","x":1}`
	srv := platformAnsweringRaw(t, clientSecret, "wappie", http.StatusOK, good, &sent)
	c := &contract.Client{App: "wappie", Secret: clientSecret, Base: srv.URL}
	a, err := c.LinkCheck(t.Context(), vecTeam, contract.LinkCheck{Kind: contract.ItemNumber})
	if err != nil || *a.Place != contract.PlaceFree || a.Switches.NewLinks != contract.SwitchOn {
		t.Fatalf("a valid answer, with a member the app does not know: %+v %v", a, err)
	}
	if string(sent) != `{"kind":"number","codes":[],"connected":false}` {
		t.Errorf("sent %s", sent)
	}
	for _, body := range []string{
		`{"place":"free","trial":"running","trial_ends_at":null,"switches":{"new_links":"on"},"computed_at":"2026-12-03T10:00:00Z"}`,
		`{"place":"some","trial":"not_needed","trial_ends_at":null,"switches":{"new_links":"on"},"computed_at":"2026-12-03T10:00:00Z"}`,
		`{"place":"free","trial":"not_needed","switches":{"new_links":"on"},"computed_at":"2026-12-03T10:00:00Z"}`,
	} {
		srv := platformAnsweringRaw(t, clientSecret, "wappie", http.StatusOK, body, nil)
		c := &contract.Client{App: "wappie", Secret: clientSecret, Base: srv.URL}
		if a, err := c.LinkCheck(t.Context(), vecTeam, contract.LinkCheck{Kind: contract.ItemNumber}); !errors.Is(err, contract.ErrUnverified) || a.Trial != "" {
			t.Errorf("%s: %+v %v", body, a, err)
		}
	}
}

// A trim result's answer carries a code of its own, which is no refusal:
// rejected comes back as an answer, and ends the result's delivery. Only a
// status other than 200 refuses the request.
func TestATrimResultsRejectionIsAnAnswerNotARefusal(t *testing.T) {
	r := trimResult(nil)
	for body, want := range map[string]string{
		`{"order_id":"` + trimOrderID + `","outcome":"accepted","code":null}`:         contract.OutcomeAccepted,
		`{"order_id":"` + trimOrderID + `","outcome":"rejected","code":"not_found"}`:  contract.OutcomeRejected,
		`{"order_id":"` + trimOrderID + `","outcome":"duplicate","code":null,"x":[]}`: contract.OutcomeDuplicate,
	} {
		srv := platformAnsweringRaw(t, clientSecret, "wappie", http.StatusOK, body, nil)
		c := &contract.Client{App: "wappie", Secret: clientSecret, Base: srv.URL}
		a, err := c.PostTrimResult(t.Context(), r)
		if err != nil || a.Outcome != want || a.OrderID != trimOrderID {
			t.Errorf("%s: %+v %v", body, a, err)
		}
	}
	for _, body := range []string{
		`{"order_id":"0199c3a0-0000-7000-8000-000000000002","outcome":"accepted","code":null}`,
		`{"order_id":"","outcome":"rejected","code":"invalid_request"}`,
		`{"order_id":"` + trimOrderID + `","outcome":"ran","code":null}`,
		`{"order_id":"` + trimOrderID + `","outcome":"accepted"}`,
	} {
		srv := platformAnsweringRaw(t, clientSecret, "wappie", http.StatusOK, body, nil)
		c := &contract.Client{App: "wappie", Secret: clientSecret, Base: srv.URL}
		if a, err := c.PostTrimResult(t.Context(), r); !errors.Is(err, contract.ErrUnverified) || a.Outcome != "" {
			t.Errorf("%s: %+v %v", body, a, err)
		}
	}
	srv := platformAnsweringRaw(t, clientSecret, "wappie", http.StatusBadRequest, `{"code":"invalid_request","message":"no"}`, nil)
	c := &contract.Client{App: "wappie", Secret: clientSecret, Base: srv.URL}
	var refusal *contract.Refusal
	if _, err := c.PostTrimResult(t.Context(), r); !errors.As(err, &refusal) || refusal.Code != contract.CodeInvalid || refusal.Status != http.StatusBadRequest {
		t.Errorf("a refused request: %v", err)
	}
	srv = platformAnsweringRaw(t, clientSecret, "wappie", http.StatusBadGateway, `<html>`, nil)
	c.Base = srv.URL
	if _, err := c.PostTrimResult(t.Context(), r); !errors.Is(err, contract.ErrUnverified) {
		t.Errorf("another status with no code: %v", err)
	}
	// A refused result goes with steps [] when the app leaves it nil.
	var sent []byte
	srv = platformAnsweringRaw(t, clientSecret, "wappie", http.StatusOK, `{"order_id":"`+trimOrderID+`","outcome":"accepted","code":null}`, &sent)
	c.Base = srv.URL
	refused := trimResult(trimRefused(contract.TrimCodeHeld))
	refused.Steps = nil
	if _, err := c.PostTrimResult(t.Context(), refused); err != nil || !strings.Contains(string(sent), `"steps":[]`) {
		t.Errorf("a refused result: %s %v", sent, err)
	}
}

// The acknowledgement goes with no refused member when there are none, and
// a signed gone is a refusal.
func TestAnEntitlementsAcknowledgementLeavesRefusedOutWhenNone(t *testing.T) {
	var sent []byte
	srv := platformAnsweringRaw(t, clientSecret, "wappie", http.StatusOK, `{"accepted":true}`, &sent)
	c := &contract.Client{App: "wappie", Secret: clientSecret, Base: srv.URL}
	if err := c.EntitlementsApplied(t.Context(), contract.EntitlementsApplied{Generation: vecGeneration, Through: 3, Refused: contract.EntitlementsRefusals{}}); err != nil {
		t.Fatal(err)
	}
	if string(sent) != `{"generation":"`+vecGeneration+`","through":3}` {
		t.Errorf("sent %s", sent)
	}
	srv = platformAnsweringRaw(t, clientSecret, "wappie", http.StatusGone, `{"code":"gone","message":"another generation"}`, nil)
	c.Base = srv.URL
	var r *contract.Refusal
	if err := c.EntitlementsApplied(t.Context(), contract.EntitlementsApplied{Generation: vecGeneration, Through: 3}); !errors.As(err, &r) || r.Code != contract.CodeGone {
		t.Errorf("gone: %v", err)
	}
}

// A feed page that does not validate comes with nothing.
func TestAnEntitlementsFeedPageMustValidate(t *testing.T) {
	page := contract.EntitlementsFeed{Generation: vecGeneration, Head: 2, PublishedThrough: contract.T(entComputed),
		Items: []contract.EntitlementsFeedItem{{Seq: 3, Doc: json.RawMessage(`{}`)}}, NextAfter: 2}
	srv := platformAnswering(t, clientSecret, "wappie", page)
	c := &contract.Client{App: "wappie", Secret: clientSecret, Base: srv.URL}
	if f, err := c.Entitlements(t.Context(), 0, 0); !errors.Is(err, contract.ErrUnverified) || f.Items != nil {
		t.Fatalf("an item past the head: %+v %v", f, err)
	}
}

// The entitlements part's calls name their route, never a workspace.
func TestAnEntitlementsTransportErrorNamesNoWorkspace(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	srv.Close()
	c := &contract.Client{App: "wappie", Secret: clientSecret, Base: base, Now: func() time.Time { return usageMeasured }}
	ctx := t.Context()
	for route, call := range map[string]func() error{
		"GET /contract/v1/entitlements":                 func() error { _, err := c.Entitlements(ctx, 0, 0); return err },
		"GET /contract/v1/workspaces/{id}/entitlements": func() error { _, _, err := c.EntitlementsDoc(ctx, vecTeam); return err },
		"POST /contract/v1/entitlements/applied": func() error {
			return c.EntitlementsApplied(ctx, contract.EntitlementsApplied{Generation: vecGeneration})
		},
		"PUT /contract/v1/workspaces/{id}/usage": func() error { _, err := c.PutUsage(ctx, vecTeam, usage("wappie", nil)); return err },
		"POST /contract/v1/workspaces/{id}/link-check": func() error {
			_, err := c.LinkCheck(ctx, vecTeam, contract.LinkCheck{Kind: contract.ItemNumber})
			return err
		},
		"POST /contract/v1/trim/results": func() error { _, err := c.PostTrimResult(ctx, trimResult(nil)); return err },
	} {
		err := call()
		if err == nil || strings.Contains(err.Error(), vecTeam) || strings.Contains(err.Error(), base) || !strings.Contains(err.Error(), route) {
			t.Errorf("%s: %v", route, err)
		}
	}
}

// Do gives every GET of the four feeds, the entitlements feed included, the
// long-poll's bound (MaxWait seconds and FeedGrace), and every other call
// CallTimeout.
func TestDoWaitsOnEveryFeedAsALongPoll(t *testing.T) {
	defer contract.ShortenTimeouts(100*time.Millisecond, 5*time.Second)()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(400 * time.Millisecond)
		body := []byte(`{}`)
		contract.SignAnswer(w.Header(), clientSecret, "wappie", r.Method, r.RequestURI, r.Header.Get(contract.HeaderNonce), body, time.Now())
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	c := &contract.Client{App: "wappie", Secret: clientSecret, Base: srv.URL}
	for _, path := range []string{"/contract/v1/feed", "/contract/v1/tokens", "/contract/v1/commands", "/contract/v1/entitlements"} {
		if status, _, err := c.Do(t.Context(), http.MethodGet, path+"?after=0&wait=25", nil); err != nil || status != http.StatusOK {
			t.Errorf("GET %s?wait=25: %d %v", path, status, err)
		}
	}
	for _, call := range []struct{ method, target string }{
		{http.MethodGet, "/contract/v1/workspaces/" + vecTeam + "/entitlements"},
		{http.MethodPost, "/contract/v1/entitlements"},
		{http.MethodGet, "/contract/v1/entitlements/applied?wait=25"},
	} {
		if _, _, err := c.Do(t.Context(), call.method, call.target, nil); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s %s: %v, want CallTimeout", call.method, call.target, err)
		}
	}
}

// worstTrimResult is the largest valid result: MaxTrimSteps steps of
// 64-character item ids, each step outcome and code that writes longest,
// and the highest usage_seq.
func worstTrimResult(t *testing.T) contract.TrimResult {
	t.Helper()
	var biggest contract.TrimResult
	size := 0
	for _, step := range []func(id string) contract.TrimStepResult{
		func(id string) contract.TrimStepResult {
			return contract.TrimStepResult{Item: id, Outcome: contract.TrimOutcomePartial, BytesAfter: ptr[int64](contract.MaxSafeInteger)}
		},
		func(id string) contract.TrimStepResult {
			return contract.TrimStepResult{Item: id, Outcome: contract.TrimOutcomeRefused, Code: ptr(contract.TrimCodeItemChanged)}
		},
	} {
		r := contract.TrimResult{OrderID: trimOrderID, Outcome: contract.TrimOutcomePartial, UsageSeq: ptr[int64](contract.MaxSafeInteger)}
		for i := range contract.MaxTrimSteps {
			r.Steps = append(r.Steps, step(fmt.Sprintf("%064d", i)))
		}
		if err := r.Validate(); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > size {
			biggest, size = r, len(raw)
		}
	}
	return biggest
}

// The largest valid result fits TrimResultBodyLimit (and not the 256 KiB
// it once was), and PostTrimResult sends it; a body over the bound
// PostTrimResult holds it to is refused, ErrInvalid, before anything is
// sent.
func TestTheLargestValidTrimResultFitsItsBodyLimit(t *testing.T) {
	r := worstTrimResult(t)
	raw, _ := json.Marshal(r)
	if len(raw) > contract.TrimResultBodyLimit || len(raw) <= 256<<10 {
		t.Fatalf("the largest valid result is %d bytes, the limit %d", len(raw), contract.TrimResultBodyLimit)
	}
	var sent []byte
	srv := platformAnsweringRaw(t, clientSecret, "wappie", http.StatusOK, `{"order_id":"`+trimOrderID+`","outcome":"accepted","code":null}`, &sent)
	c := &contract.Client{App: "wappie", Secret: clientSecret, Base: srv.URL}
	if _, err := c.PostTrimResult(t.Context(), r); err != nil || len(sent) != len(raw) {
		t.Fatalf("sent %d bytes: %v", len(sent), err)
	}
	defer contract.LowerTrimResultBodyLimit(len(raw) - 1)()
	sent = nil
	if _, err := c.PostTrimResult(t.Context(), r); !errors.Is(err, contract.ErrInvalid) || sent != nil {
		t.Fatalf("a body over the limit: %v, sent %d bytes", err, len(sent))
	}
}
