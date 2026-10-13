package platform

import (
	"net/http"
	"time"

	"github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/reqhmac"
)

// The product contract's signature (section 11.17): section 9's request
// HMAC under the platform's label, in both directions, with every answer
// bound to its request's nonce. These are the platform profile's names for
// what package contract defines; contract, its wire, its label mask and its
// client use the same values, and so do the platform's server and the apps.

// The contract's two directions: a request goes to the platform, its answer
// to the app.
const (
	ContractToPlatform = contract.ToPlatform
	ContractToApp      = contract.ToApp
)

// ContractSecretLen is the length of an app's contract secret: the
// unpadded base64url text of 32 random bytes, keyed as written.
const ContractSecretLen = contract.SecretLen

// ErrContractSecret means a contract secret is empty, is not 43 base64url
// characters that encode 32 bytes, or the next secret equals the current
// one. The value is never echoed.
var ErrContractSecret = contract.ErrSecret

// ErrAnswerNonce means an answer echoed a nonce other than the one its
// request carried: it answers another request, or was replayed.
var ErrAnswerNonce = contract.ErrAnswerNonce

// ContractHMAC is the contract's request and answer signature,
// thehappie-platform-hmac/v1: the headers X-Happie-App, X-Happie-Timestamp,
// X-Happie-Nonce and X-Happie-Signature, the app's id as the sender in both
// directions, and a skew of 60 s. Every call returns a fresh value.
func ContractHMAC() reqhmac.Scheme { return contract.Scheme() }

// CheckContractSecrets checks an app's current secret and, when not empty,
// its next one (a rotation: signers use the current one, receivers accept
// either). It refuses an empty or malformed secret, and a next one equal to
// the current one, with ErrContractSecret: an empty key is a valid HMAC
// key, so nothing else would.
func CheckContractSecrets(current, next string) error {
	return contract.CheckSecrets(current, next)
}

// SignAnswer signs the platform's answer to a request whose signature held:
// it sets the answer's timestamp, the request's own nonce, echoed, and a
// to-app signature over the request's method and target, the timestamp,
// the nonce and the answer's body, with the app's current secret, which the
// caller checked where it loaded it (CheckContractSecrets): SignAnswer does
// not. The platform signs nothing for a request that did not verify.
func SignAnswer(h http.Header, secret, app, method, target, requestNonce string, body []byte, now time.Time) {
	contract.SignAnswer(h, secret, app, method, target, requestNonce, body, now)
}

// VerifyAnswer checks an answer an app received for its own request, in
// this order: the headers present once each and well formed and the
// timestamp within the skew (reqhmac.ErrMissing, reqhmac.ErrStale); the
// echoed nonce is the one the app sent, never a value taken from the answer
// (ErrAnswerNonce); and one of the app's secrets signed it, direction
// to-app (reqhmac.ErrBad). An app ignores an answer that fails. A list of
// secrets that holds a key that is not one, an empty one above all,
// verifies nothing (reqhmac.ErrBad); the caller checks its secrets where it
// loads them (CheckContractSecrets).
func VerifyAnswer(h http.Header, secrets []string, app, method, target, sentNonce string, body []byte, now time.Time) error {
	return contract.VerifyAnswer(h, secrets, app, method, target, sentNonce, body, now)
}
