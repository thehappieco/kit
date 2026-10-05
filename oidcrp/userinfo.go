package oidcrp

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/thehappieco/kit/profiles/platform"
)

// Userinfo is what userinfo said about the person, read strictly and
// checked: sub is an account id, ClientID is this client, and ProductKey is
// a valid key of this product.
type Userinfo struct {
	Sub           string
	ClientID      string
	AuthTime      int64
	AMR           []string
	Email         string
	EmailVerified bool
	Locale        string
	Name          string
	// ProductKeyID is Product ":" epoch, for example "wappie:1".
	ProductKeyID string
	// ProductKey is pk_p, 32 bytes, passing the check of section 11.4.
	ProductKey []byte
}

// FetchUserinfo takes the access token to id.'s userinfo and checks what
// comes back: steps 1 to 5 of SPEC section 11.15, in that order, with
// ErrAccessToken, ErrTokenRefused, ErrUserinfo, ErrWrongClient and
// ErrProductKey. The token works once, so FetchUserinfo is called once per
// token. Errors never name the token.
func (c *Client) FetchUserinfo(ctx context.Context, accessToken string) (*Userinfo, error) {
	if err := c.Check(); err != nil {
		return nil, err
	}
	// A string that is not an access token never leaves this process.
	if !ValidAccessToken(accessToken) {
		return nil, ErrAccessToken
	}
	body, err := c.get(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	raw, err := readUserinfo(body)
	if err != nil {
		return nil, err
	}
	if !platform.ValidSub(raw.Sub) {
		return nil, fmt.Errorf("%w: sub is not an account id", ErrUserinfo)
	}
	// A token issued to another client never opens a session here, whatever
	// else it says.
	if raw.ClientID != c.ClientID {
		return nil, ErrWrongClient
	}
	pub, err := c.checkProductKey(raw.ProductKeyID, raw.ProductKey)
	if err != nil {
		return nil, err
	}
	return &Userinfo{
		Sub: raw.Sub, ClientID: raw.ClientID, AuthTime: raw.AuthTime, AMR: raw.AMR,
		Email: raw.Email, EmailVerified: raw.EmailVerified, Locale: raw.Locale, Name: raw.Name,
		ProductKeyID: raw.ProductKeyID, ProductKey: pub,
	}, nil
}

// get is GET {issuer}/oauth2/userinfo with the bearer token, and the
// answer's body when it is 200 with application/json of at most
// MaxUserinfoBytes.
func (c *Client) get(ctx context.Context, accessToken string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.userinfoURL(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUserinfo, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	res, err := c.httpClient().Do(req)
	if err != nil {
		// net/http's errors name the URL, which holds no token.
		return nil, fmt.Errorf("%w: %w", ErrUserinfo, err)
	}
	defer res.Body.Close() //nolint:errcheck // the body has been read, or the answer is refused anyway

	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return nil, ErrTokenRefused
	default:
		return nil, fmt.Errorf("%w: status %d", ErrUserinfo, res.StatusCode)
	}
	if media, _, err := mime.ParseMediaType(res.Header.Get("Content-Type")); err != nil || media != "application/json" {
		return nil, fmt.Errorf("%w: not application/json", ErrUserinfo)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, MaxUserinfoBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUserinfo, err)
	}
	if len(body) > MaxUserinfoBytes {
		return nil, fmt.Errorf("%w: the answer is larger than %d bytes", ErrUserinfo, MaxUserinfoBytes)
	}
	return body, nil
}

// checkProductKey checks what userinfo said about the product key: an id of
// this client's product and an epoch, in its one spelling (section 11.12),
// and a public key of 32 bytes of strict base64url that passes the check of
// section 11.4, so that the one spelling of a valid key is what gets
// pinned.
func (c *Client) checkProductKey(id, key string) ([]byte, error) {
	if id == "" || key == "" {
		return nil, fmt.Errorf("%w: product_key or product_key_id is missing", ErrProductKey)
	}
	product, _, _ := strings.Cut(id, ":")
	if !platform.ValidProductKeyID(id) || product != c.Product {
		return nil, fmt.Errorf("%w: product_key_id is not this product's", ErrProductKey)
	}
	pub, err := platform.DecodeB64(key, 32)
	if err != nil {
		return nil, fmt.Errorf("%w: product_key is not 32 bytes of strict base64url", ErrProductKey)
	}
	if err := platform.CheckPublicKey(pub); err != nil {
		return nil, fmt.Errorf("%w: product_key is not an acceptable X25519 public key", ErrProductKey)
	}
	return pub, nil
}
