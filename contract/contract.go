// Package contract is the wire of the contract's membership part (SPEC
// section 11.17; the platform's decision 0040): the scheme that signs every
// request and answer on the contract socket, the types that cross it, and
// the rules that keep their values honest. The platform's transport, its
// reference client and Wappie and Mailie all use it, so a rule here is a
// rule on both sides of the socket. Package contracttest is a fake platform
// for the apps' tests, and profiles/platform names the signature's values
// as the platform profile (ContractHMAC, SignAnswer, VerifyAnswer).
//
// The rules it enforces:
//   - Every request is signed with the kit's reqhmac under
//     thehappie-platform-hmac/v1, direction to-platform, and every answer to
//     a request that verified is signed too, direction to-app, over the
//     request's method and target and the request's own nonce, which the
//     answer echoes. So an answer is bound to its request: it cannot be
//     replayed to another request, and no app needs a replay cache to check
//     one (VerifyAnswer).
//   - The secret is the 43-character base64url text of 32 random bytes,
//     keyed as written (reqhmac keys with the text's bytes, never the decoded
//     ones). CheckSecrets refuses an empty, malformed or repeated secret:
//     an empty key is a valid HMAC key, so nothing else would.
//   - A document, a snapshot and an event carry people by their platform sub
//     only, never an email address, a phone number or a mailbox address. An
//     item's label is a name a person gave it, cleaned and masked here
//     (CleanLabel), and its hint at most the last four digits of a number or
//     the first character and the domain of an address.
//   - Every enum is closed: a value the receiver does not know is refused,
//     never guessed (Validate).
//
// The package uses only the standard library and the kit's reqhmac, and,
// as all of the kit, nothing newer than the Go of the kit's go.mod
// (1.26.7), which go vet's stdversion check holds it to. Decoding is the
// caller's: the platform decodes strictly, an app may ignore members it
// does not know (SPEC section 11.17).
//
// Taken from the platform's internal/contract at commit ee45e3a, with its
// tests; the names are the platform's, so that the platform imports this
// package in place of its own. Where the kit departs from that code (SPEC
// section 11.17), no byte on the wire changes: Client bounds every call and
// returns nothing of an answer it refuses, VerifyAnswer verifies nothing
// under a key that is not a secret, and PauseReasons and StrandedCauses are
// functions that return copies of the closed sets Validate checks.
package contract

import (
	"errors"
	"regexp"
	"time"

	"github.com/thehappieco/kit/reqhmac"
)

// Label is the label of the platform's request signature (decision 0005).
const Label = "thehappie-platform-hmac/v1"

// The headers a signed request and a signed answer carry.
const (
	HeaderApp       = "X-Happie-App"
	HeaderTimestamp = "X-Happie-Timestamp"
	HeaderNonce     = "X-Happie-Nonce"
	HeaderSignature = "X-Happie-Signature"
)

// The two directions: a request goes to the platform, its answer to the app.
const (
	ToPlatform = "to-platform"
	ToApp      = "to-app"
)

// Skew is how far a timestamp may be from the receiver's clock.
const Skew = 60 * time.Second

// ReplayLifetime and ReplayCapacity size the platform's replay cache, one per
// app: a nonce is remembered until its timestamp plus ReplayLifetime, a
// second past the skew.
const (
	ReplayLifetime = Skew + time.Second
	ReplayCapacity = 100_000
)

// Scheme is the request signature of the contract.
func Scheme() reqhmac.Scheme {
	return reqhmac.Scheme{
		Label: Label,
		Headers: reqhmac.Headers{
			Sender:    HeaderApp,
			Timestamp: HeaderTimestamp,
			Nonce:     HeaderNonce,
			Signature: HeaderSignature,
		},
		Skew: Skew,
	}
}

// The refusals of a request's signature, as reqhmac names them.
var (
	ErrMissing    = reqhmac.ErrMissing
	ErrStale      = reqhmac.ErrStale
	ErrBad        = reqhmac.ErrBad
	ErrReplay     = reqhmac.ErrReplay
	ErrReplayFull = reqhmac.ErrReplayFull
)

// NewReplayCache is the platform's replay cache for one app's requests.
func NewReplayCache() *reqhmac.ReplayCache {
	return reqhmac.NewReplayCache(ReplayCapacity, ReplayLifetime)
}

// appRE is an app's id: what the console's shell registry calls it (wappie,
// mailie; fakeproduct, the platform's reference app, in development).
var appRE = regexp.MustCompile(`^[a-z][a-z0-9]{1,31}$`)

// ValidApp reports whether app has the shape of an app's id.
func ValidApp(app string) bool { return appRE.MatchString(app) }

// SecretLen is a secret's length: 32 random bytes in unpadded base64url.
const SecretLen = 43

var (
	// ErrSecret means a secret is empty, not 43 base64url characters, or the
	// next secret equals the current one. The value is never echoed.
	ErrSecret = errors.New("contract: a secret must be 43 base64url characters, and the next one must differ")
)

// CheckSecrets checks an app's current secret and, when not empty, its next
// one (a rotation: signers use current, receivers accept either).
func CheckSecrets(current, next string) error {
	if !validSecret(current) {
		return ErrSecret
	}
	if next != "" && (!validSecret(next) || next == current) {
		return ErrSecret
	}
	return nil
}

// Secrets lists the secrets a receiver accepts: current, then next if set.
func Secrets(current, next string) []string {
	if next == "" {
		return []string{current}
	}
	return []string{current, next}
}

func validSecret(s string) bool {
	if len(s) != SecretLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	// 43 characters carry 258 bits; the last character's low two bits must
	// be zero for the text to be the canonical encoding of 32 bytes.
	return base64Index(s[SecretLen-1])&3 == 0
}

func base64Index(c byte) int {
	switch {
	case c >= 'A' && c <= 'Z':
		return int(c - 'A')
	case c >= 'a' && c <= 'z':
		return int(c-'a') + 26
	case c >= '0' && c <= '9':
		return int(c-'0') + 52
	case c == '-':
		return 62
	default:
		return 63
	}
}
