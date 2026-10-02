// Package oidcrp is the server side of a relying party of The Happie Co
// platform's id. (SPEC section 11.15): what a product's server runs when its
// page, at the end of a sign-in (@thehappieco/kit/oidc-rp, section 11.14),
// posts it the single-use access token.
//
// The rule it enforces: a session opens only for an access token id. issued
// to this client, whose userinfo answer reads strictly and names a valid
// product key of this product; and the product key of an account is pinned
// at its first login, insert only, so that a later login presenting another
// key for the same (sub, product_key_id) is refused as account_key_changed
// and the pin is kept. The pinned triple is what the server answers its
// page, which keeps a delivered key only when the triple names it: HPKE base
// mode does not authenticate the sender, so this comparison with an
// insert-only pin is what stops a key substituted by whoever controls id.
// for an account the product already knows. A first login, or a new epoch,
// trusts the registry.
//
// Client.Login runs it all:
//
//  1. the access token is "thid_at_" and the strict base64url of 32 bytes,
//     or it is never sent anywhere (ErrAccessToken);
//  2. GET {issuer}/oauth2/userinfo with Authorization: Bearer, server to
//     server: no redirect is followed, no cookie is sent, and the default
//     HTTP client takes no proxy from the environment and has timeouts. The
//     token works once, so a refusal is never retried: 401 is
//     ErrTokenRefused, any other answer than 200 with application/json of at
//     most 16 KiB is ErrUserinfo;
//  3. the answer is read strictly: valid UTF-8, one JSON object and nothing
//     after it, member names compared exactly and each at most once, unknown
//     members ignored, the known ones of their types, sub a lowercase UUID
//     (ErrUserinfo);
//  4. client_id is this client's (ErrWrongClient): a token issued to the
//     console or to another product never opens a session here;
//  5. product_key_id is this product's, product ":" epoch, and product_key is
//     32 bytes of strict base64url passing the check of section 11.4
//     (ErrProductKey);
//  6. the pin, through a PinStore (ErrAccountKeyChanged on a different key).
//
// It returns the userinfo, the verdict and the Answer the server sends its
// page, before it starts its own session. Nothing here logs, and no error
// names the token, the key, the account or the address.
//
// # The pin table
//
// MemoryPins is for tests and development. A product implements PinStore on
// its database, with a table its role may only insert into and read:
//
//	create table product_key_pins (
//	    sub            uuid  not null,
//	    product_key_id text  not null,
//	    product_key    bytea not null check (octet_length(product_key) = 32),
//	    pinned_at      timestamptz not null default now(),
//	    primary key (sub, product_key_id)
//	);
//	grant select, insert on product_key_pins to product_app;  -- no update, no delete
//
// and InsertPin as two statements:
//
//	insert into product_key_pins (sub, product_key_id, product_key)
//	    values ($1, $2, $3) on conflict do nothing;      -- inserted: one row affected
//	select product_key from product_key_pins where sub = $1 and product_key_id = $2;
//
// What the package does not do: serve HTTP (the session endpoint, its
// same-origin rules and the product's own session are the product's), hold
// an SQL driver, or verify ID tokens (the server trusts only userinfo). The
// same-origin rules are required: the session handler example refuses, before
// it reads the body, any request but a POST with exactly the page's Origin,
// Sec-Fetch-Site: same-origin and an application/json body, or another site
// could post an access token of its own account and open a session for that
// account in the person's browser.
//
// Taken from the platform's tools/fakeproduct at commit 4476bf4 (its
// userinfo client and its pin), without encoding/json/v2, which Go 1.26
// still keeps behind GOEXPERIMENT=jsonv2.
package oidcrp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/thehappieco/kit/profiles/platform"
)

const (
	// UserinfoPath is the userinfo endpoint's path on the issuer.
	UserinfoPath = "/oauth2/userinfo"
	// AccessTokenPrefix starts every access token; 32 bytes of strict
	// base64url follow it.
	AccessTokenPrefix = "thid_at_"
	// MaxUserinfoBytes bounds the userinfo answer, far above any real one.
	MaxUserinfoBytes = 16 << 10
)

// Client is one product's relying party, as the platform's client registry
// has it.
type Client struct {
	// Issuer is exactly the ID token's iss, a bare origin: for example
	// "https://id.thehappie.co", or in development
	// "http://id.thehappie.localhost:8290".
	Issuer string
	// ClientID is this product's client, for example "wappie-app".
	ClientID string
	// Product is the product's key label, the product of product_key_id:
	// "wappie" for "wappie:1".
	Product string
	// HTTP makes the userinfo request; nil is NewHTTPClient(nil). Whatever
	// client is given, redirects are not followed and no cookie jar is used.
	HTTP *http.Client
}

// Check reports whether the client's constants are usable: the issuer a bare
// lowercase origin, https or, for development, http on a loopback address or
// a *.localhost name; the client id non-empty and from the AAD alphabet of
// section 11.1; the product a product id. These are the product's own
// constants, so an error here is a programming error, with no protocol
// name.
func (c *Client) Check() error {
	if c == nil {
		return errors.New("oidcrp: no client")
	}
	if err := checkIssuer(c.Issuer); err != nil {
		return err
	}
	if !validClientID(c.ClientID) {
		return errors.New("oidcrp: the client id is empty or outside [A-Za-z0-9._:/|@-]")
	}
	if !platform.ValidProduct(c.Product) {
		return errors.New("oidcrp: the product is not a product id")
	}
	return nil
}

func checkIssuer(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" ||
		u.ForceQuery || u.Scheme+"://"+u.Host != s || strings.ToLower(s) != s {
		return errors.New("oidcrp: the issuer is not a bare lowercase origin (scheme://host[:port])")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if devHost(u.Hostname()) {
			return nil
		}
	}
	return errors.New("oidcrp: the issuer is not https (or http on a loopback or *.localhost host)")
}

// devHost reports whether a plain-http issuer may be at host: localhost, a
// *.localhost name, or a loopback address.
func devHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validClientID(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '.', c == '_', c == ':', c == '/', c == '|', c == '@', c == '-':
		default:
			return false
		}
	}
	return true
}

// ValidAccessToken reports whether s is an access token in its one
// spelling: AccessTokenPrefix and the strict base64url of 32 bytes.
func ValidAccessToken(s string) bool {
	rest, ok := strings.CutPrefix(s, AccessTokenPrefix)
	if !ok {
		return false
	}
	b, err := platform.DecodeB64(rest, 32)
	clear(b)
	return err == nil
}

// NewHTTPClient returns the HTTP client for userinfo: it takes no proxy from
// the environment, follows no redirect (the token would go with it), keeps
// no cookies, and times out (5 s to connect and for TLS, 10 s for the
// answer's headers, 15 s in all). dial, when not nil, replaces how a
// connection is made: in development, id.thehappie.localhost is a name Go is
// not guaranteed to resolve, so a dial that always connects to
// 127.0.0.1:8290 sends the request there while its Host header still names
// id.
func NewHTTPClient(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Client {
	if dial == nil {
		dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dial,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			MaxIdleConns:          4,
			IdleConnTimeout:       30 * time.Second,
		},
		Timeout:       15 * time.Second,
		CheckRedirect: noRedirect,
	}
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// defaultHTTP is NewHTTPClient(nil), made once, so that every Client
// without its own shares one pool of connections.
var defaultHTTP = sync.OnceValue(func() *http.Client { return NewHTTPClient(nil) })

// httpClient is the client to make the userinfo request with: c.HTTP (or
// the default), with redirects and cookies switched off whatever it says.
func (c *Client) httpClient() *http.Client {
	if c.HTTP == nil {
		return defaultHTTP()
	}
	hc := *c.HTTP
	hc.CheckRedirect = noRedirect
	hc.Jar = nil
	return &hc
}

func (c *Client) userinfoURL() string { return c.Issuer + UserinfoPath }
