package oidcrp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/thehappieco/kit/oidcrp"
	"github.com/thehappieco/kit/profiles/platform"
)

// A product's POST /api/session around Login (SPEC section 11.15). The
// product's own rules come first and are required, not optional: a POST
// from a page of this origin (exactly one Origin, this one, and
// Sec-Fetch-Site: same-origin) with an application/json body, all checked
// before the body is read. Without them another site could sign itself in
// here, keep the unspent access token, and have the person's browser post
// it with fetch(url, {method: "POST", mode: "no-cors", body}): a text/plain
// body needs no preflight, and Login would accept the token (this client, a
// valid key) and the product would open a session for the attacker's
// account in the person's browser (login CSRF). On success it answers its
// page with the pinned triple, which the page's finishSignIn compares with
// the key it opened, and starts its own session.
func Example_sessionHandler() {
	const origin = "https://wappie.thehappie.co" // the product's page, as browsers serialize its origin
	client := &oidcrp.Client{Issuer: "https://id.thehappie.co", ClientID: "wappie-app", Product: "wappie"}
	pins := oidcrp.NewMemoryPins(10_000) // a product implements PinStore on its database
	fail := func(w http.ResponseWriter, status int, code string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, "{\"code\":%q}\n", code)
	}
	session := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			fail(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		// A missing Origin, "null" (a page served with no-referrer), or
		// another origin is refused; so is anything but same-origin.
		if o := r.Header.Values("Origin"); len(o) != 1 || o[0] != origin {
			fail(w, http.StatusForbidden, "forbidden")
			return
		}
		if s := r.Header.Values("Sec-Fetch-Site"); len(s) != 1 || s[0] != "same-origin" {
			fail(w, http.StatusForbidden, "forbidden")
			return
		}
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
			fail(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
			return
		}
		var req struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
			fail(w, http.StatusBadRequest, "bad_request")
			return
		}
		login, err := client.Login(r.Context(), pins, req.AccessToken)
		switch code := oidcrp.ErrorCode(err); code {
		case "":
		case "account_key_changed":
			// The login is refused and the pin kept. Log the product key
			// id only, never the token, the key, the account or the
			// address, and raise the product's alert.
			log.Printf("refused a login whose product key differs from the pinned one: %s", login.Userinfo.ProductKeyID)
			fail(w, http.StatusConflict, "account_key_changed")
			return
		case "access_token":
			fail(w, http.StatusBadRequest, "bad_request")
			return
		case "token_refused":
			fail(w, http.StatusUnauthorized, "unauthorized")
			return
		case "wrong_client":
			fail(w, http.StatusForbidden, "forbidden")
			return
		default:
			log.Printf("userinfo: %v", err) // no error of the package names a secret
			fail(w, http.StatusBadGateway, "unavailable")
			return
		}
		// Here the product starts its own session for login.Userinfo.Sub.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(login.Answer)
	})

	// What another site's no-cors fetch sends, and the same request with
	// the page's own Origin but cross-site, or same-origin but text/plain:
	// none reaches Login, so no token leaves the server.
	token := oidcrp.AccessTokenPrefix + platform.EncodeB64([]byte(strings.Repeat("a", 32)))
	for _, h := range []map[string]string{
		{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site", "Content-Type": "text/plain;charset=UTF-8"},
		{"Origin": origin, "Sec-Fetch-Site": "cross-site", "Content-Type": "application/json"},
		{"Origin": origin, "Sec-Fetch-Site": "same-origin", "Content-Type": "text/plain;charset=UTF-8"},
	} {
		r := httptest.NewRequest(http.MethodPost, origin+"/api/session", strings.NewReader(`{"access_token":"`+token+`"}`))
		for k, v := range h {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		session.ServeHTTP(w, r)
		fmt.Print(w.Code, " ", w.Body.String())
	}
	// Output:
	// 403 {"code":"forbidden"}
	// 403 {"code":"forbidden"}
	// 415 {"code":"unsupported_media_type"}
}

// Login against a stand-in for id.'s userinfo: the first login pins the
// account's product key, the next one with the same key is "same", and one
// with another key is refused.
func ExampleClient_Login() {
	_, pub, _ := platform.ProductKey([]byte(strings.Repeat("r", 32)), "wappie", 1)
	_, other, _ := platform.ProductKey([]byte(strings.Repeat("s", 32)), "wappie", 1)
	key := map[string][]byte{}
	id := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub": "01999999-aaaa-7bbb-8ccc-0123456789ab", "client_id": "wappie-app",
			"product_key_id": "wappie:1", "product_key": platform.EncodeB64(key[r.Header.Get("Authorization")]),
		})
	}))
	defer id.Close()

	client := &oidcrp.Client{Issuer: id.URL, ClientID: "wappie-app", Product: "wappie"}
	pins := oidcrp.NewMemoryPins(10)
	for i, k := range [][]byte{pub, pub, other} {
		token := oidcrp.AccessTokenPrefix + platform.EncodeB64([]byte(strings.Repeat(fmt.Sprint(i), 32)))
		key["Bearer "+token] = k
		login, err := client.Login(context.Background(), pins, token)
		if err != nil {
			fmt.Println(login.Verdict, "refused:", oidcrp.ErrorCode(err))
			continue
		}
		fmt.Println(login.Verdict)
	}
	// Output:
	// new
	// same
	// account_key_changed refused: account_key_changed
}
