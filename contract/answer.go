package contract

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/thehappieco/kit/reqhmac"
)

// ErrAnswerNonce means an answer echoed a nonce other than the one its
// request carried: it answers another request, or was replayed.
var ErrAnswerNonce = errors.New("answer_nonce")

// SignAnswer signs the answer to a request that verified: it sets the
// timestamp, the request's own nonce, echoed, and a to-app signature over the
// request's method and target and the answer's body. secret is the app's
// current secret, which the caller checked where it loaded it
// (CheckSecrets): SignAnswer does not, and under an empty key anyone could
// sign the same. The platform signs nothing for a request that did not
// verify; such an answer reaches the app unsigned, and the app treats it as a
// failure.
func SignAnswer(h http.Header, secret, app, method, target, requestNonce string, body []byte, now time.Time) {
	timestamp := strconv.FormatInt(now.Unix(), 10)
	h.Set(HeaderTimestamp, timestamp)
	h.Set(HeaderNonce, requestNonce)
	h.Set(HeaderSignature, Scheme().Signature(secret, ToApp, app, method, target, timestamp, requestNonce, body))
}

// VerifyAnswer checks an answer the app received for its own request, in
// this order: the headers are present once and well formed and the timestamp
// within the skew (reqhmac.ErrMissing, reqhmac.ErrStale); the echoed nonce is
// the one the app sent, never a value taken from the answer (ErrAnswerNonce);
// and one of the app's secrets signed it, direction to-app
// (reqhmac.ErrBad). An app ignores an answer that fails: no cursor moves and
// no outbox row is marked delivered. The outcome is in the signed body; the
// HTTP status is never trusted.
//
// No answer verifies under a list that holds a key that is not a secret
// (CheckSecrets), an empty one above all, which would verify what anyone
// signs with it: that is reqhmac.ErrBad too. The caller still checks its
// secrets where it loads them (CheckSecrets), which says what is wrong.
func VerifyAnswer(h http.Header, secrets []string, app, method, target, sentNonce string, body []byte, now time.Time) error {
	scheme := Scheme()
	got, err := scheme.Read(h, now)
	if err != nil {
		return err
	}
	if got.Nonce != sentNonce {
		return ErrAnswerNonce
	}
	for _, s := range secrets {
		if !validSecret(s) {
			return reqhmac.ErrBad
		}
	}
	if !scheme.SignedBy(secrets, got, ToApp, app, method, target, body) {
		return reqhmac.ErrBad
	}
	return nil
}
