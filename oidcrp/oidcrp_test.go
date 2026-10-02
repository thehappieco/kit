package oidcrp_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/thehappieco/kit/oidcrp"
	"github.com/thehappieco/kit/profiles/platform"
)

// The client of these tests is the platform's development one, fakeproduct,
// whose product is Wappie's (the platform's id-v1 section 7.1).
const (
	testIDOrigin = "http://id.thehappie.localhost:8290"
	testIDHost   = "id.thehappie.localhost:8290"
	testClientID = "fakeproduct"
	testProduct  = "wappie"
	testSub      = "01999999-aaaa-7bbb-8ccc-0123456789ab"
	otherSub     = "01999999-aaaa-7bbb-8ccc-ba9876543210"
	testEmail    = "person@example.test"
)

func randomBytes(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// newToken returns a fresh access token in its one spelling.
func newToken(t testing.TB) string {
	t.Helper()
	return oidcrp.AccessTokenPrefix + platform.EncodeB64(randomBytes(t, 32))
}

// newProductKey returns the base64url of a fresh X25519 public key.
func newProductKey(t testing.TB) string {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return platform.EncodeB64(k.PublicKey().Bytes())
}

// fakeID is id.'s userinfo endpoint: each token is answered once, with the
// answer registered for it, and every request is checked for what a
// server-to-server userinfo call must and must not carry.
type fakeID struct {
	t        *testing.T
	srv      *httptest.Server
	mu       sync.Mutex
	answers  map[string]func(w http.ResponseWriter)
	requests atomic.Int64
	paths    []string
}

func newFakeID(t *testing.T) *fakeID {
	t.Helper()
	f := &fakeID{t: t, answers: map[string]func(http.ResponseWriter){}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeID) addr() string { return f.srv.Listener.Addr().String() }

func (f *fakeID) serve(w http.ResponseWriter, r *http.Request) {
	f.requests.Add(1)
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.Path)
	f.mu.Unlock()
	if r.URL.Path == "/steal" {
		f.t.Error("a redirect was followed")
		return
	}
	if r.Host != testIDHost {
		f.t.Errorf("userinfo went to Host %q, want %q", r.Host, testIDHost)
	}
	if r.Method != http.MethodGet || r.URL.Path != oidcrp.UserinfoPath || r.URL.RawQuery != "" {
		f.t.Errorf("userinfo request is %s %s (query %t), want GET %s", r.Method, r.URL.Path, r.URL.RawQuery != "", oidcrp.UserinfoPath)
	}
	if r.Header.Get("Accept") != "application/json" {
		f.t.Error("the userinfo call does not ask for JSON")
	}
	for _, h := range []string{"Cookie", "Origin", "Referer", "Sec-Fetch-Site"} {
		if r.Header.Get(h) != "" {
			f.t.Errorf("the server-to-server userinfo call carries %s", h)
		}
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	answer, known := f.answers[token]
	delete(f.answers, token)
	f.mu.Unlock()
	if !ok || !known {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	answer(w)
}

// answer registers a raw answer for token.
func (f *fakeID) answer(token string, a func(w http.ResponseWriter)) {
	f.mu.Lock()
	f.answers[token] = a
	f.mu.Unlock()
}

// issueRaw registers a body, as JSON, for a fresh token and returns the token.
func (f *fakeID) issueRaw(t *testing.T, body string) string {
	t.Helper()
	token := newToken(t)
	f.answer(token, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, body)
	})
	return token
}

// issue registers a userinfo object for a fresh token and returns the token.
func (f *fakeID) issue(t *testing.T, body map[string]any) string {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return f.issueRaw(t, string(data))
}

// userinfoFor is the userinfo answer of the platform's id-v1 section 7.8 for
// the fakeproduct client.
func userinfoFor(sub, keyID, key string) map[string]any {
	return map[string]any{
		"sub": sub, "client_id": testClientID, "auth_time": 1790000000, "amr": []string{"pwd"},
		"email": testEmail, "email_verified": true, "locale": "pt-BR", "name": "Ana",
		"product_key": key, "product_key_id": keyID,
	}
}

func marshal(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

type harness struct {
	id     *fakeID
	client *oidcrp.Client
	pins   *oidcrp.MemoryPins
}

// newHarness is a client of the fake id. at its development origin, whose
// connections always go to the fake's address (NewHTTPClient's dial).
func newHarness(t *testing.T) *harness {
	t.Helper()
	f := newFakeID(t)
	dialer := &net.Dialer{}
	c := &oidcrp.Client{
		Issuer: testIDOrigin, ClientID: testClientID, Product: testProduct,
		HTTP: oidcrp.NewHTTPClient(func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", f.addr())
		}),
	}
	return &harness{id: f, client: c, pins: oidcrp.NewMemoryPins(1000)}
}

func (h *harness) login(t *testing.T, token string) (*oidcrp.Login, error) {
	t.Helper()
	return h.client.Login(context.Background(), h.pins, token)
}

func TestTheFirstLoginPinsTheKeyAndTheSameKeyLaterIsSame(t *testing.T) {
	h := newHarness(t)
	key := newProductKey(t)
	l, err := h.login(t, h.id.issue(t, userinfoFor(testSub, "wappie:1", key)))
	if err != nil || l.Verdict != oidcrp.PinNew {
		t.Fatalf("first login: %v; want new", err)
	}
	if l.Answer != (oidcrp.Answer{Sub: testSub, ProductKeyID: "wappie:1", ProductKey: key}) {
		t.Error("the answer is not the pinned triple")
	}
	if got := marshal(t, l.Answer); got != `{"sub":"`+testSub+`","product_key_id":"wappie:1","product_key":"`+key+`"}` {
		t.Error("the answer's JSON is not {sub, product_key_id, product_key}")
	}
	ui := l.Userinfo
	if ui.Sub != testSub || ui.ClientID != testClientID || ui.AuthTime != 1790000000 || len(ui.AMR) != 1 || ui.AMR[0] != "pwd" ||
		ui.Email != testEmail || !ui.EmailVerified || ui.Locale != "pt-BR" || ui.Name != "Ana" || ui.ProductKeyID != "wappie:1" ||
		platform.EncodeB64(ui.ProductKey) != key {
		t.Error("the userinfo was not read as it was sent")
	}
	for range 3 {
		l, err = h.login(t, h.id.issue(t, userinfoFor(testSub, "wappie:1", key)))
		if err != nil || l.Verdict != oidcrp.PinSame || l.Answer.ProductKey != key {
			t.Fatalf("a later login with the same key: %v; want same", err)
		}
	}
	// Another account is pinned on its own.
	if l, err := h.login(t, h.id.issue(t, userinfoFor(otherSub, "wappie:1", newProductKey(t)))); err != nil || l.Verdict != oidcrp.PinNew {
		t.Errorf("another account's first login: %v; want new", err)
	}
}

func TestADifferentKeyForAPinnedAccountIsRefusedAndThePinIsKept(t *testing.T) {
	h := newHarness(t)
	key := newProductKey(t)
	if _, err := h.login(t, h.id.issue(t, userinfoFor(testSub, "wappie:1", key))); err != nil {
		t.Fatal(err)
	}
	swapped := newProductKey(t)
	for range 2 {
		l, err := h.login(t, h.id.issue(t, userinfoFor(testSub, "wappie:1", swapped)))
		if !errors.Is(err, oidcrp.ErrAccountKeyChanged) || oidcrp.ErrorCode(err) != "account_key_changed" {
			t.Fatalf("a login with another key: %v; want account_key_changed", err)
		}
		if l == nil || l.Verdict != oidcrp.PinChanged || l.Answer != (oidcrp.Answer{}) {
			t.Fatal("the refusal carries no verdict, or an answer the page could keep a key on")
		}
		if platform.EncodeB64(l.Userinfo.ProductKey) != swapped {
			t.Error("the refusal does not say what was presented")
		}
	}
	// The swap did not replace the pin: the original key still matches.
	if l, err := h.login(t, h.id.issue(t, userinfoFor(testSub, "wappie:1", key))); err != nil || l.Verdict != oidcrp.PinSame || l.Answer.ProductKey != key {
		t.Errorf("the original key after a refused swap: %v; want same", err)
	}
}

func TestAnotherEpochIsPinnedOnItsOwn(t *testing.T) {
	h := newHarness(t)
	for _, id := range []string{"wappie:1", "wappie:2", "wappie:2147483647"} {
		if l, err := h.login(t, h.id.issue(t, userinfoFor(testSub, id, newProductKey(t)))); err != nil || l.Verdict != oidcrp.PinNew {
			t.Errorf("%s with its own key: %v; want new", id, err)
		}
	}
}

// Of two first logins at once with different keys, one pins its key and the
// other is refused: the pin is insert only.
func TestConcurrentFirstLoginsPinOneKey(t *testing.T) {
	for range 20 {
		h := newHarness(t)
		tokens := []string{h.id.issue(t, userinfoFor(testSub, "wappie:1", newProductKey(t))), h.id.issue(t, userinfoFor(testSub, "wappie:1", newProductKey(t)))}
		verdicts := make([]oidcrp.Verdict, 2)
		var wg sync.WaitGroup
		for i, token := range tokens {
			wg.Go(func() {
				l, _ := h.client.Login(context.Background(), h.pins, token)
				if l != nil {
					verdicts[i] = l.Verdict
				}
			})
		}
		wg.Wait()
		if !(verdicts[0] == oidcrp.PinNew && verdicts[1] == oidcrp.PinChanged) && !(verdicts[0] == oidcrp.PinChanged && verdicts[1] == oidcrp.PinNew) {
			t.Fatalf("verdicts %v, want one new and one account_key_changed", verdicts)
		}
	}
}

func TestATokenIssuedToAnotherClientOpensNoSession(t *testing.T) {
	h := newHarness(t)
	for _, other := range []any{"wappie-app", "mailie-console", "thehappie-console", "FakeProduct", "fakeproduct ", "", nil} {
		body := userinfoFor(testSub, "wappie:1", newProductKey(t))
		if other == nil {
			delete(body, "client_id")
		} else {
			body["client_id"] = other
		}
		l, err := h.login(t, h.id.issue(t, body))
		if !errors.Is(err, oidcrp.ErrWrongClient) || oidcrp.ErrorCode(err) != "wrong_client" || l != nil {
			t.Errorf("client_id %v: %v; want wrong_client", other, err)
		}
	}
	if h.pins.Len() != 0 {
		t.Error("a refused client pinned a key")
	}
}

func TestATokenUserinfoRefusesIsTokenRefused(t *testing.T) {
	h := newHarness(t)
	token := h.id.issue(t, userinfoFor(testSub, "wappie:1", newProductKey(t)))
	if _, err := h.login(t, token); err != nil {
		t.Fatal(err)
	}
	// The fake, like id., answers each token once.
	for name, tok := range map[string]string{"a spent token": token, "an unknown token": newToken(t)} {
		if _, err := h.login(t, tok); !errors.Is(err, oidcrp.ErrTokenRefused) || oidcrp.ErrorCode(err) != "token_refused" {
			t.Errorf("%s: %v; want token_refused", name, err)
		}
	}
}

func TestAStringThatIsNotAnAccessTokenNeverReachesID(t *testing.T) {
	h := newHarness(t)
	good := newToken(t)
	rest := strings.TrimPrefix(good, oidcrp.AccessTokenPrefix)
	for _, s := range []string{
		"", rest, "thid_c_" + rest, good + "=", good[:len(good)-1], good + "A", oidcrp.AccessTokenPrefix + strings.Repeat("_", 43),
		good + "\n", " " + good, "THID_AT_" + rest, oidcrp.AccessTokenPrefix + strings.Repeat("a", 2000),
	} {
		if oidcrp.ValidAccessToken(s) {
			t.Errorf("a malformed token (%d characters) is valid", len(s))
		}
		if _, err := h.login(t, s); !errors.Is(err, oidcrp.ErrAccessToken) || oidcrp.ErrorCode(err) != "access_token" {
			t.Errorf("a malformed token (%d characters): %v; want access_token", len(s), err)
		}
	}
	if !oidcrp.ValidAccessToken(good) {
		t.Error("a good token is refused")
	}
	if n := h.id.requests.Load(); n != 0 {
		t.Errorf("a malformed access token reached userinfo %d times", n)
	}
}

func TestAnAnswerOutsideTheProtocolOpensNoSession(t *testing.T) {
	h := newHarness(t)
	low := make([]byte, 32) // the all-zero point: low order
	nonCanonical := bytes.Repeat([]byte{0xff}, 32)
	raw := func(status int, contentType, body string) func(w http.ResponseWriter) {
		return func(w http.ResponseWriter) {
			if contentType != "" {
				w.Header().Set("Content-Type", contentType)
			}
			if status == http.StatusFound {
				w.Header().Set("Location", "/steal")
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}
	}
	ok := marshal(t, userinfoFor(testSub, "wappie:1", newProductKey(t)))
	edited := func(edit func(m map[string]any)) string {
		m := userinfoFor(testSub, "wappie:1", newProductKey(t))
		edit(m)
		return marshal(t, m)
	}
	const js = "application/json"
	cases := map[string]struct {
		answer func(w http.ResponseWriter)
		code   string
	}{
		"500":                              {raw(http.StatusInternalServerError, js, ok), "userinfo"},
		"a redirect":                       {raw(http.StatusFound, "", ""), "userinfo"},
		"403":                              {raw(http.StatusForbidden, js, ok), "userinfo"},
		"not JSON":                         {raw(http.StatusOK, "text/html", ok), "userinfo"},
		"no Content-Type":                  {raw(http.StatusOK, "", ok), "userinfo"},
		"JSON with a charset":              {raw(http.StatusOK, "application/json; charset=utf-8", ok), ""},
		"a JSON array":                     {raw(http.StatusOK, js, "[]"), "userinfo"},
		"null":                             {raw(http.StatusOK, js, "null"), "userinfo"},
		"empty":                            {raw(http.StatusOK, js, ""), "userinfo"},
		"truncated":                        {raw(http.StatusOK, js, ok[:20]), "userinfo"},
		"too large":                        {raw(http.StatusOK, js, `{"sub":"`+strings.Repeat("a", oidcrp.MaxUserinfoBytes)+`"}`), "userinfo"},
		"a value after the object":         {raw(http.StatusOK, js, ok+" {}"), "userinfo"},
		"a second object after the object": {raw(http.StatusOK, js, ok+ok), "userinfo"},
		"whitespace around the object":     {raw(http.StatusOK, js, " \n"+ok+"\r\n\t"), ""},
		"a byte order mark":                {raw(http.StatusOK, js, "\ufeff"+ok), "userinfo"},
		"invalid UTF-8":                    {raw(http.StatusOK, js, strings.Replace(ok, `"Ana"`, "\"An\xff\"", 1)), "userinfo"},
		"a repeated member":                {raw(http.StatusOK, js, strings.Replace(ok, `"sub":`, `"sub":"`+otherSub+`","sub":`, 1)), "userinfo"},
		"a repeated unknown member":        {raw(http.StatusOK, js, strings.Replace(ok, `"sub":`, `"x":1,"x":2,"sub":`, 1)), "userinfo"},
		"a repeated member, once escaped":  {raw(http.StatusOK, js, strings.Replace(ok, `"sub":`, `"sub":"`+otherSub+`","sub":`, 1)), "userinfo"},
		"sub of the wrong shape":           {raw(http.StatusOK, js, edited(func(m map[string]any) { m["sub"] = strings.ToUpper(testSub) })), "userinfo"},
		"sub missing":                      {raw(http.StatusOK, js, edited(func(m map[string]any) { delete(m, "sub") })), "userinfo"},
		"sub only in another case":         {raw(http.StatusOK, js, edited(func(m map[string]any) { m["Sub"] = m["sub"]; delete(m, "sub") })), "userinfo"},
		"sub a number":                     {raw(http.StatusOK, js, edited(func(m map[string]any) { m["sub"] = 7 })), "userinfo"},
		"sub null":                         {raw(http.StatusOK, js, edited(func(m map[string]any) { m["sub"] = nil })), "userinfo"},
		"client_id a number":               {raw(http.StatusOK, js, edited(func(m map[string]any) { m["client_id"] = 1 })), "userinfo"},
		"auth_time with a fraction":        {raw(http.StatusOK, js, edited(func(m map[string]any) { m["auth_time"] = 1.5 })), "userinfo"},
		"auth_time as text":                {raw(http.StatusOK, js, edited(func(m map[string]any) { m["auth_time"] = "1790000000" })), "userinfo"},
		"auth_time with an exponent":       {raw(http.StatusOK, js, strings.Replace(ok, `"auth_time":1790000000`, `"auth_time":1.79e9`, 1)), "userinfo"},
		"auth_time past 64 bits":           {raw(http.StatusOK, js, strings.Replace(ok, `"auth_time":1790000000`, `"auth_time":9223372036854775808`, 1)), "userinfo"},
		"amr a string":                     {raw(http.StatusOK, js, edited(func(m map[string]any) { m["amr"] = "pwd" })), "userinfo"},
		"amr with a number":                {raw(http.StatusOK, js, edited(func(m map[string]any) { m["amr"] = []any{"pwd", 1} })), "userinfo"},
		"email_verified as text":           {raw(http.StatusOK, js, edited(func(m map[string]any) { m["email_verified"] = "true" })), "userinfo"},
		"name null":                        {raw(http.StatusOK, js, edited(func(m map[string]any) { m["name"] = nil })), "userinfo"},
		"no product key":                   {raw(http.StatusOK, js, edited(func(m map[string]any) { delete(m, "product_key") })), "product_key"},
		"no product key id":                {raw(http.StatusOK, js, edited(func(m map[string]any) { delete(m, "product_key_id") })), "product_key"},
		"another product's key":            {raw(http.StatusOK, js, edited(func(m map[string]any) { m["product_key_id"] = "mailie:1" })), "product_key"},
		"epoch 0":                          {raw(http.StatusOK, js, edited(func(m map[string]any) { m["product_key_id"] = "wappie:0" })), "product_key"},
		"epoch with a zero":                {raw(http.StatusOK, js, edited(func(m map[string]any) { m["product_key_id"] = "wappie:01" })), "product_key"},
		"epoch 2^31":                       {raw(http.StatusOK, js, edited(func(m map[string]any) { m["product_key_id"] = "wappie:2147483648" })), "product_key"},
		"no epoch":                         {raw(http.StatusOK, js, edited(func(m map[string]any) { m["product_key_id"] = "wappie" })), "product_key"},
		"a low-order key":                  {raw(http.StatusOK, js, edited(func(m map[string]any) { m["product_key"] = platform.EncodeB64(low) })), "product_key"},
		"a non-canonical key":              {raw(http.StatusOK, js, edited(func(m map[string]any) { m["product_key"] = platform.EncodeB64(nonCanonical) })), "product_key"},
		"a key of 31 bytes":                {raw(http.StatusOK, js, edited(func(m map[string]any) { m["product_key"] = platform.EncodeB64(randomBytes(t, 31)) })), "product_key"},
		"a padded key":                     {raw(http.StatusOK, js, edited(func(m map[string]any) { m["product_key"] = newProductKey(t) + "=" })), "product_key"},
		"a product key of another type":    {raw(http.StatusOK, js, edited(func(m map[string]any) { m["product_key"] = 1 })), "userinfo"},
		"unknown members, nested":          {raw(http.StatusOK, js, edited(func(m map[string]any) { m["x"] = map[string]any{"y": []any{1, map[string]any{}, nil, "z"}} })), ""},
		"an unknown member with a null":    {raw(http.StatusOK, js, edited(func(m map[string]any) { m["picture"] = nil })), ""},
		"only the required members":        {raw(http.StatusOK, js, `{"sub":"`+testSub+`","client_id":"`+testClientID+`","product_key_id":"wappie:1","product_key":"`+newProductKey(t)+`"}`), ""},
		"a member name with an escape":     {raw(http.StatusOK, js, strings.Replace(edited(func(m map[string]any) {}), `"client_id"`, `"client_id"`, 1)), ""},
	}
	for name, c := range cases {
		token := newToken(t)
		h.id.answer(token, c.answer)
		// Each case on its own pins, since each has its own key.
		pins := oidcrp.NewMemoryPins(10)
		l, err := h.client.Login(context.Background(), pins, token)
		if got := oidcrp.ErrorCode(err); got != c.code || (err != nil && got == "") {
			t.Errorf("%s: %v; want %q", name, err, c.code)
			continue
		}
		switch {
		case c.code != "" && (l != nil || pins.Len() != 0):
			t.Errorf("%s: a refusal returned a login or pinned a key", name)
		case c.code == "" && (l.Verdict != oidcrp.PinNew || l.Userinfo.Sub != testSub || l.Userinfo.ClientID != testClientID):
			t.Errorf("%s: not read as sent", name)
		}
	}
}

// A member that encoding/json's Unmarshal would match in another case is
// not that member: the sub and client_id that count are the ones spelled
// so, whatever comes after them in another case (which Unmarshal would let
// win).
func TestAMemberInAnotherCaseIsNotTheMember(t *testing.T) {
	h := newHarness(t)
	body := marshal(t, userinfoFor(testSub, "wappie:1", newProductKey(t)))
	body = strings.TrimSuffix(body, "}") + `,"SUB":"` + otherSub + `","Client_ID":"wappie-app"}`
	l, err := h.login(t, h.id.issueRaw(t, body))
	if err != nil || l.Userinfo.Sub != testSub || l.Userinfo.ClientID != testClientID {
		t.Fatalf("%v: a member in another case was read", err)
	}
}

func TestTheUserinfoCallSendsNoCookieAndFollowsNoRedirectWhateverTheClient(t *testing.T) {
	h := newHarness(t)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(testIDOrigin)
	jar.SetCookies(u, []*http.Cookie{{Name: "__Host-id_session", Value: "x"}})
	followed := false
	custom := *h.client.HTTP
	custom.Jar = jar
	custom.CheckRedirect = func(*http.Request, []*http.Request) error { followed = true; return nil }
	c := *h.client
	c.HTTP = &custom

	token := h.id.issue(t, userinfoFor(testSub, "wappie:1", newProductKey(t)))
	if _, err := c.Login(context.Background(), h.pins, token); err != nil {
		t.Fatal(err)
	}
	redirect := newToken(t)
	h.id.answer(redirect, func(w http.ResponseWriter) {
		w.Header().Set("Location", "/steal")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	if _, err := c.Login(context.Background(), h.pins, redirect); oidcrp.ErrorCode(err) != "userinfo" || followed {
		t.Errorf("a redirect: %v (followed %t); want userinfo, not followed", err, followed)
	}
	if custom.Jar != jar || custom.CheckRedirect == nil {
		t.Error("the caller's client was changed")
	}
}

func TestAUserinfoCallThatCannotConnectFailsWithoutNamingTheToken(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	c := &oidcrp.Client{Issuer: "http://" + addr, ClientID: testClientID, Product: testProduct}
	token := newToken(t)
	_, err = c.FetchUserinfo(context.Background(), token)
	if oidcrp.ErrorCode(err) != "userinfo" || strings.Contains(err.Error(), token) || strings.Contains(err.Error(), oidcrp.AccessTokenPrefix) {
		t.Errorf("a closed port: %v, want userinfo without the token", err)
	}
}

// Nothing a refusal says names the token, the key, the account or the address.
func TestNoErrorNamesTheTokenKeyAccountOrAddress(t *testing.T) {
	h := newHarness(t)
	key := newProductKey(t)
	var secrets []string
	var errs []error
	login := func(token string) {
		secrets = append(secrets, token)
		_, err := h.login(t, token)
		errs = append(errs, err)
	}
	login(h.id.issue(t, userinfoFor(testSub, "wappie:1", key)))
	login(h.id.issue(t, userinfoFor(testSub, "wappie:1", newProductKey(t))))
	login(newToken(t))
	other := userinfoFor(testSub, "wappie:1", key)
	other["client_id"] = "wappie-app"
	login(h.id.issue(t, other))
	login(h.id.issue(t, userinfoFor(strings.ToUpper(testSub), "wappie:1", key)))
	login(h.id.issue(t, userinfoFor(testSub, "mailie:1", key)))
	broken := newToken(t)
	h.id.answer(broken, func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) })
	login(broken)
	secrets = append(secrets, key, testEmail, testSub, strings.ToUpper(testSub), oidcrp.AccessTokenPrefix)
	refused := 0
	for _, err := range errs {
		if err == nil {
			continue
		}
		refused++
		for _, s := range secrets {
			if strings.Contains(err.Error(), s) {
				t.Errorf("an error names a token, a key, an account or an address (%d characters)", len(s))
			}
		}
	}
	if refused < 5 {
		t.Fatalf("only %d refusals; the test would prove little", refused)
	}
}

func TestMemoryPinsAreBoundedAndAnswerCopies(t *testing.T) {
	ctx := context.Background()
	p := oidcrp.NewMemoryPins(1)
	first := []byte{1, 2, 3}
	if v, err := oidcrp.Pin(ctx, p, testSub, "wappie:1", first); err != nil || v != oidcrp.PinNew {
		t.Fatalf("first pin: %q, %v", v, err)
	}
	first[0] = 9 // the caller's slice is not the pin
	if _, err := oidcrp.Pin(ctx, p, otherSub, "wappie:1", []byte{1}); !errors.Is(err, oidcrp.ErrPinStoreFull) || oidcrp.ErrorCode(err) != "pin_store_full" {
		t.Errorf("a full store took a new pin: %v", err)
	}
	if v, err := oidcrp.Pin(ctx, p, testSub, "wappie:1", []byte{1, 2, 3}); err != nil || v != oidcrp.PinSame {
		t.Errorf("a full store no longer recognises a pinned key: %q, %v", v, err)
	}
	pinned, inserted, err := p.InsertPin(ctx, testSub, "wappie:1", []byte{4, 5, 6})
	if err != nil || inserted || !bytes.Equal(pinned, []byte{1, 2, 3}) {
		t.Fatalf("a swapped key is not answered with the pin: %v", err)
	}
	pinned[1] = 9 // nor is the answer
	if v, err := oidcrp.Pin(ctx, p, testSub, "wappie:1", []byte{4, 5, 6}); !errors.Is(err, oidcrp.ErrAccountKeyChanged) || v != oidcrp.PinChanged {
		t.Errorf("a full store no longer refuses a swapped key: %q, %v", v, err)
	}
	if v, err := oidcrp.Pin(ctx, p, testSub, "wappie:1", []byte{1, 2, 3}); err != nil || v != oidcrp.PinSame || p.Len() != 1 {
		t.Errorf("the pin moved: %q, %v", v, err)
	}
}

// A PinStore's own errors pass through as they are, and a store that
// inserts another key than it was given is an error.
type brokenPins struct{ err error }

func (b brokenPins) InsertPin(context.Context, string, string, []byte) ([]byte, bool, error) {
	if b.err != nil {
		return nil, false, b.err
	}
	return []byte{0}, true, nil
}

func TestAPinStoreErrorPassesThrough(t *testing.T) {
	h := newHarness(t)
	down := errors.New("the database is down")
	l, err := h.client.Login(context.Background(), brokenPins{err: down}, h.id.issue(t, userinfoFor(testSub, "wappie:1", newProductKey(t))))
	if !errors.Is(err, down) || l != nil || oidcrp.ErrorCode(err) != "" {
		t.Errorf("%v, want the store's error as it is", err)
	}
	if _, err := oidcrp.Pin(context.Background(), brokenPins{}, testSub, "wappie:1", []byte{1}); err == nil {
		t.Error("a store that pinned another key than it was given was trusted")
	}
	if _, err := oidcrp.Pin(context.Background(), nil, testSub, "wappie:1", []byte{1}); err == nil {
		t.Error("no store was accepted")
	}
}

func TestCheckAcceptsOnlyTheProductsConstantsInTheirOneSpelling(t *testing.T) {
	good := oidcrp.Client{Issuer: "https://id.thehappie.co", ClientID: "wappie-app", Product: "wappie"}
	for _, issuer := range []string{"https://id.thehappie.co", "http://id.thehappie.localhost:8290", "http://localhost:8290", "http://127.0.0.1:8290", "http://[::1]:8290", "https://id.thehappie.co:8443"} {
		c := good
		c.Issuer = issuer
		if err := c.Check(); err != nil {
			t.Errorf("%q: %v", issuer, err)
		}
	}
	bad := map[string]func(c *oidcrp.Client){
		"an issuer with a slash":          func(c *oidcrp.Client) { c.Issuer += "/" },
		"an issuer with a path":           func(c *oidcrp.Client) { c.Issuer += "/oauth2" },
		"an issuer in upper case":         func(c *oidcrp.Client) { c.Issuer = "https://ID.thehappie.co" },
		"a plain-http issuer":             func(c *oidcrp.Client) { c.Issuer = "http://id.thehappie.co" },
		"a plain-http issuer on a LAN IP": func(c *oidcrp.Client) { c.Issuer = "http://192.168.0.2:8290" },
		"an issuer with a user":           func(c *oidcrp.Client) { c.Issuer = "https://x@id.thehappie.co" },
		"an issuer with a query":          func(c *oidcrp.Client) { c.Issuer += "?x" },
		"an issuer without a scheme":      func(c *oidcrp.Client) { c.Issuer = "id.thehappie.co" },
		"an ftp issuer":                   func(c *oidcrp.Client) { c.Issuer = "ftp://id.thehappie.co" },
		"no issuer":                       func(c *oidcrp.Client) { c.Issuer = "" },
		"no client id":                    func(c *oidcrp.Client) { c.ClientID = "" },
		"a client id with a space":        func(c *oidcrp.Client) { c.ClientID = "wappie app" },
		"no product":                      func(c *oidcrp.Client) { c.Product = "" },
		"a product in upper case":         func(c *oidcrp.Client) { c.Product = "Wappie" },
		"a product with an epoch":         func(c *oidcrp.Client) { c.Product = "wappie:1" },
	}
	for name, edit := range bad {
		c := good
		edit(&c)
		err := c.Check()
		if err == nil || oidcrp.ErrorCode(err) != "" {
			t.Errorf("%s: %v; want a programming error", name, err)
		}
		if _, err := c.FetchUserinfo(context.Background(), newToken(t)); err == nil {
			t.Errorf("%s: FetchUserinfo went ahead", name)
		}
	}
	var none *oidcrp.Client
	if none.Check() == nil {
		t.Error("a nil client passes its check")
	}
}

func TestErrorCodeNamesEverySentinel(t *testing.T) {
	for err, code := range map[error]string{
		oidcrp.ErrAccessToken: "access_token", oidcrp.ErrTokenRefused: "token_refused", oidcrp.ErrUserinfo: "userinfo",
		oidcrp.ErrWrongClient: "wrong_client", oidcrp.ErrProductKey: "product_key", oidcrp.ErrAccountKeyChanged: "account_key_changed",
		oidcrp.ErrPinStoreFull: "pin_store_full", nil: "", errors.New("other"): "",
	} {
		if got := oidcrp.ErrorCode(err); got != code {
			t.Errorf("%v: %q, want %q", err, got, code)
		}
	}
}
