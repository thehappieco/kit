// Package reqhmac signs HTTP requests between two services that share a
// secret, in both directions, so that neither a bearer token nor a replayed
// request is ever enough.
//
// Every request is signed over its method, target, body and a fresh nonce,
// with a direction so a request signed for one side cannot be replayed to the
// other. The receiver refuses anything stale, anything already seen, and
// anything not signed by one of its current secrets:
//
//	canonical = label "\n" direction "\n" sender "\n" UPPER(method) "\n" target "\n"
//	            timestamp "\n" nonce "\n" hex(SHA-256(body))
//	signature = "v1=" hex(HMAC-SHA256(key = UTF-8(secret), canonical))
//
// The scheme is Wappie's between its server and its attested reader
// (internal/mcpauth/hmac.go, label wappie-mcp-hmac/v1); the platform's product
// contract uses it with its own label. The label, the header names and the
// skew are a Scheme's; the error texts are codes and are kept as Wappie logged
// them.
package reqhmac

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NonceLen is a nonce's length: 16 random bytes in unpadded base64url.
const NonceLen = 22

// The refusals, as codes.
var (
	// ErrMissing is a timestamp, nonce or signature header that is absent,
	// repeated or malformed.
	ErrMissing = errors.New("hmac_missing")
	// ErrStale is a timestamp outside the skew.
	ErrStale = errors.New("hmac_stale")
	// ErrBad is a signature none of the secrets produced. SignedBy reports a
	// bool; this is the code a caller logs for false.
	ErrBad = errors.New("hmac_bad")
	// ErrReplay is a nonce already seen from the same sender and direction.
	ErrReplay = errors.New("hmac_replay")
	// ErrReplayFull is a replay cache with no room. It fails closed.
	ErrReplayFull = errors.New("replay_cache_full")
)

// Headers names the four headers a signed request carries.
type Headers struct {
	Sender, Timestamp, Nonce, Signature string
}

// Scheme is one use of the signature: its label, its headers and how far a
// timestamp may be from the receiver's clock.
type Scheme struct {
	Label   string
	Headers Headers
	Skew    time.Duration
}

// Canonical is the string a signature covers. The target is the raw path and
// query exactly as on the request line.
func (s Scheme) Canonical(direction, sender, method, target, timestamp, nonce string, body []byte) string {
	sum := sha256.Sum256(body)
	return strings.Join([]string{
		s.Label, direction, sender, strings.ToUpper(method), target, timestamp, nonce, hex.EncodeToString(sum[:]),
	}, "\n")
}

// Signature computes the v1 signature of one request, keyed with the secret's
// bytes as written.
func (s Scheme) Signature(secret, direction, sender, method, target, timestamp, nonce string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(s.Canonical(direction, sender, method, target, timestamp, nonce, body)))
	return "v1=" + hex.EncodeToString(mac.Sum(nil))
}

// Sign sets the four headers on an outgoing request, with a fresh nonce and
// the current time.
func (s Scheme) Sign(h http.Header, secret, direction, sender, method, target string, body []byte, now time.Time) error {
	nonce, err := newNonce()
	if err != nil {
		return err
	}
	timestamp := strconv.FormatInt(now.Unix(), 10)
	h.Set(s.Headers.Sender, sender)
	h.Set(s.Headers.Timestamp, timestamp)
	h.Set(s.Headers.Nonce, nonce)
	h.Set(s.Headers.Signature, s.Signature(secret, direction, sender, method, target, timestamp, nonce, body))
	return nil
}

func newNonce() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Signed is what a received request claims about itself.
type Signed struct {
	Timestamp string
	Unix      int64
	Nonce     string
	Signature string
}

// Read checks that the timestamp, nonce and signature headers are each present
// once and well formed, and that the timestamp is within the skew. The sender
// header is the caller's to check, before this.
//
// A timestamp is decimal Unix seconds, 1 to 18 digits, with no sign and no
// leading zero; a nonce is NonceLen base64url characters; a signature is "v1="
// and 64 lower-case hex digits.
func (s Scheme) Read(h http.Header, now time.Time) (Signed, error) {
	one := func(name string) (string, bool) {
		values := h.Values(name)
		return strings.Join(values, ""), len(values) == 1
	}
	timestamp, okT := one(s.Headers.Timestamp)
	nonce, okN := one(s.Headers.Nonce)
	signature, okS := one(s.Headers.Signature)
	if !okT || !okN || !okS || !validTimestamp(timestamp) || !validNonce(nonce) || !validSignature(signature) {
		return Signed{}, ErrMissing
	}
	unix, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return Signed{}, ErrMissing
	}
	skew := int64(s.Skew / time.Second)
	if d := now.Unix() - unix; d > skew || d < -skew {
		return Signed{}, ErrStale
	}
	return Signed{Timestamp: timestamp, Unix: unix, Nonce: nonce, Signature: signature}, nil
}

func validTimestamp(t string) bool {
	if t == "" || len(t) > 18 || t[0] == '0' {
		return false
	}
	return !strings.ContainsFunc(t, func(c rune) bool { return c < '0' || c > '9' })
}

func validNonce(n string) bool {
	return len(n) == NonceLen && !strings.ContainsFunc(n, func(c rune) bool {
		return !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_')
	})
}

func validSignature(sig string) bool {
	digest, ok := strings.CutPrefix(sig, "v1=")
	return ok && len(digest) == 64 && !strings.ContainsFunc(digest, func(c rune) bool {
		return !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f')
	})
}

// SignedBy reports whether any of the secrets produced the signature. Every
// secret is tried, with no early exit, so the time taken does not say which
// one matched. Two secrets is how a secret is rotated.
func (s Scheme) SignedBy(secrets []string, got Signed, direction, sender, method, target string, body []byte) bool {
	matched := 0
	for _, secret := range secrets {
		want := s.Signature(secret, direction, sender, method, target, got.Timestamp, got.Nonce, body)
		matched |= subtle.ConstantTimeCompare([]byte(want), []byte(got.Signature))
	}
	return matched == 1
}

// ReplayCache remembers the nonces of accepted requests until they could no
// longer be accepted anyway. Fill it only after a signature checks, so nobody
// without a secret can put anything in it.
type ReplayCache struct {
	mu       sync.Mutex
	seen     map[string]time.Time
	capacity int
	lifetime time.Duration
}

// NewReplayCache holds up to capacity live nonces, each until its timestamp
// plus lifetime. The lifetime should exceed the skew by at least a second.
func NewReplayCache(capacity int, lifetime time.Duration) *ReplayCache {
	return &ReplayCache{seen: map[string]time.Time{}, capacity: capacity, lifetime: lifetime}
}

// Admit records a nonce, or says it was seen or that there is no room. A full
// cache fails closed: refusing a genuine request is a retry, and accepting one
// unremembered would be a replay window.
func (c *ReplayCache) Admit(direction, sender, nonce string, timestamp int64, now time.Time) error {
	key := direction + "\x00" + sender + "\x00" + nonce
	c.mu.Lock()
	defer c.mu.Unlock()
	if until, ok := c.seen[key]; ok && until.After(now) {
		return ErrReplay
	}
	if len(c.seen) >= c.capacity {
		for k, until := range c.seen {
			if !until.After(now) {
				delete(c.seen, k)
			}
		}
		if len(c.seen) >= c.capacity {
			return ErrReplayFull
		}
	}
	c.seen[key] = time.Unix(timestamp, 0).Add(c.lifetime)
	return nil
}

// Len reports how many nonces the cache holds, expired ones not yet swept
// included.
func (c *ReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}
