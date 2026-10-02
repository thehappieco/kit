package oidcrp

import (
	"context"

	"github.com/thehappieco/kit/profiles/platform"
)

// Answer is what the server sends its page after an accepted login (SPEC
// section 11.15, step 7): the sub, product_key_id and product_key it pinned
// and accepted. The page keeps a delivered key only when these name it
// (section 11.14, step 9; oidc-rp's PinnedKey), and the server starts its
// own session after sending it.
type Answer struct {
	Sub          string `json:"sub"`
	ProductKeyID string `json:"product_key_id"`
	// ProductKey is the pinned key in base64url.
	ProductKey string `json:"product_key"`
}

// Login is an accepted or refused login.
type Login struct {
	Userinfo *Userinfo
	Verdict  Verdict
	// Answer is set for PinNew and PinSame.
	Answer Answer
}

// Login runs SPEC section 11.15 for the access token the page posted:
// FetchUserinfo (steps 1 to 5), then Pin (step 6). It returns the userinfo,
// the verdict and the Answer for the page. On PinChanged it returns the
// Login without an Answer and ErrAccountKeyChanged: the product refuses the
// login (409), opens no session, logs the product_key_id and raises its
// alert. Any other error leaves nothing pinned by this call.
func (c *Client) Login(ctx context.Context, pins PinStore, accessToken string) (*Login, error) {
	ui, err := c.FetchUserinfo(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	verdict, pinned, err := pin(ctx, pins, ui.Sub, ui.ProductKeyID, ui.ProductKey)
	switch {
	case verdict == PinChanged:
		return &Login{Userinfo: ui, Verdict: verdict}, err
	case err != nil:
		return nil, err
	}
	return &Login{
		Userinfo: ui,
		Verdict:  verdict,
		Answer:   Answer{Sub: ui.Sub, ProductKeyID: ui.ProductKeyID, ProductKey: platform.EncodeB64(pinned)},
	}, nil
}
