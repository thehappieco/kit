package oidcrp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/thehappieco/kit/oidcrp"
	"github.com/thehappieco/kit/profiles/platform"
)

// A product's POST /api/session around Login (SPEC section 11.15). The
// product's own rules come first: this origin only, Sec-Fetch-Site:
// same-origin, a JSON body. On success it answers its page with the pinned
// triple, which the page's finishSignIn compares with the key it opened,
// and starts its own session.
func Example_sessionHandler() {
	client := &oidcrp.Client{Issuer: "https://id.thehappie.co", ClientID: "wappie-app", Product: "wappie"}
	pins := oidcrp.NewMemoryPins(10_000) // a product implements PinStore on its database
	session := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
			http.Error(w, `{"code":"bad_request"}`, http.StatusBadRequest)
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
			http.Error(w, `{"code":"account_key_changed"}`, http.StatusConflict)
			return
		case "access_token":
			http.Error(w, `{"code":"bad_request"}`, http.StatusBadRequest)
			return
		case "token_refused":
			http.Error(w, `{"code":"unauthorized"}`, http.StatusUnauthorized)
			return
		case "wrong_client":
			http.Error(w, `{"code":"forbidden"}`, http.StatusForbidden)
			return
		default:
			log.Printf("userinfo: %v", err) // no error of the package names a secret
			http.Error(w, `{"code":"unavailable"}`, http.StatusBadGateway)
			return
		}
		// Here the product starts its own session for login.Userinfo.Sub.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(login.Answer)
	})
	_ = session
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
