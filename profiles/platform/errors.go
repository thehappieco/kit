package platform

import "errors"

// The sentinel errors. Each one is an error name of the protocol (SPEC
// section 11.10), which ErrorCode returns, the vectors record and the
// TypeScript side throws as PlatformError. Messages never carry the input
// that was refused. Errors from the kit's other packages never escape this
// one: they are reported as one of these.
var (
	// ErrPasswordInvalid means the password is not well-formed Unicode,
	// holds a run of more than 30 combining marks, or holds a control
	// character.
	ErrPasswordInvalid = errors.New("platform: password is not well-formed or holds a control character")
	// ErrPasswordTooShort means a new password has fewer than 12 code points.
	ErrPasswordTooShort = errors.New("platform: password is shorter than 12 code points")
	// ErrPasswordTooLong means a password has more than 256 code points.
	ErrPasswordTooLong = errors.New("platform: password is longer than 256 code points")
	// ErrKDFPolicy means KDF parameters or a salt outside the bounds of
	// section 11.3. It is returned before anything is derived.
	ErrKDFPolicy = errors.New("platform: kdf parameters outside the protocol bounds")
	// ErrWrap means a root wrap is malformed or did not open: wrong key,
	// another account, epoch or kind, or altered bytes. Which one is
	// deliberately not reported.
	ErrWrap = errors.New("platform: root wrap did not open")
	// ErrRecoveryCode means the text is not a recovery code.
	ErrRecoveryCode = errors.New("platform: not a recovery code")
	// ErrEmailInvalid means the address is not accepted by section 11.8.
	ErrEmailInvalid = errors.New("platform: email address not accepted")
	// ErrProductKey means a product id, epoch or product public key is not
	// acceptable, or a listed public key does not match the root.
	ErrProductKey = errors.New("platform: product key not acceptable")
	// ErrBundle means the bytes are not a key bundle this version reads.
	ErrBundle = errors.New("platform: not a key bundle")
	// ErrEncoding means a value is not in its one accepted spelling: strict
	// base64url of the right length, a lowercase UUID, or a restricted JSON
	// array element.
	ErrEncoding = errors.New("platform: value not in its canonical encoding")
)

var errorCodes = []struct {
	err  error
	code string
}{
	{ErrPasswordInvalid, "password_invalid"},
	{ErrPasswordTooShort, "password_too_short"},
	{ErrPasswordTooLong, "password_too_long"},
	{ErrKDFPolicy, "kdf_policy"},
	{ErrWrap, "wrap"},
	{ErrRecoveryCode, "recovery_code"},
	{ErrEmailInvalid, "email"},
	{ErrProductKey, "product_key"},
	{ErrBundle, "bundle"},
	{ErrEncoding, "encoding"},
}

// ErrorCode returns the protocol error name of err ("kdf_policy", "wrap", ...)
// or "" when err is nil or not one of this package's errors. When an error
// wraps more than one sentinel, the first in the order above wins.
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
