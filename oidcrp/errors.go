package oidcrp

import "errors"

// The sentinel errors. Each one is an error name of SPEC section 11.15,
// which ErrorCode returns. Messages never carry the token, the key, the
// account or the address. A PinStore's own errors pass through unchanged.
var (
	// ErrAccessToken means the string the page sent is not an access token
	// (AccessTokenPrefix and the strict base64url of 32 bytes); it was sent
	// nowhere.
	ErrAccessToken = errors.New("oidcrp: not an access token")
	// ErrTokenRefused means userinfo answered 401: the token is unknown,
	// spent or expired. A token works once, so it is never retried.
	ErrTokenRefused = errors.New("oidcrp: id. refused the access token")
	// ErrUserinfo means the userinfo call failed or its answer is not one
	// this version reads: a transport failure, a status other than 200 and
	// 401, another media type, more than MaxUserinfoBytes, or an answer the
	// strict reader refuses.
	ErrUserinfo = errors.New("oidcrp: unexpected userinfo answer")
	// ErrWrongClient means the token was issued to another client.
	ErrWrongClient = errors.New("oidcrp: the access token was issued to another client")
	// ErrProductKey means userinfo named no product key of this product, or
	// one section 11.4's check refuses.
	ErrProductKey = errors.New("oidcrp: userinfo named no usable product key")
	// ErrAccountKeyChanged means the account presented another key than the
	// one pinned for its product_key_id: the login is refused, the pin is
	// kept, and the product raises an alert.
	ErrAccountKeyChanged = errors.New("oidcrp: the account's product key differs from the pinned one")
	// ErrPinStoreFull means a MemoryPins holds as many pins as it may and
	// this would be a new one.
	ErrPinStoreFull = errors.New("oidcrp: the pin store is full")
)

var errorCodes = []struct {
	err  error
	code string
}{
	{ErrAccessToken, "access_token"},
	{ErrTokenRefused, "token_refused"},
	{ErrUserinfo, "userinfo"},
	{ErrWrongClient, "wrong_client"},
	{ErrProductKey, "product_key"},
	{ErrAccountKeyChanged, "account_key_changed"},
	{ErrPinStoreFull, "pin_store_full"},
}

// ErrorCode returns the error name of err ("access_token", "token_refused",
// "userinfo", "wrong_client", "product_key", "account_key_changed",
// "pin_store_full"), or "" when err is nil or none of this package's.
func ErrorCode(err error) string {
	if err == nil {
		return ""
	}
	for _, e := range errorCodes {
		if errors.Is(err, e.err) {
			return e.code
		}
	}
	return ""
}
