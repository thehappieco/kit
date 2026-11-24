package contract

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"time"
)

// The relink's pairing route (SPEC section 11.19; the platform's decision
// 0057): while an item.relink runs, the app sends each QR WhatsApp gives it
// for that command, PUT /contract/v1/commands/{id}/pairing, and the
// platform holds the latest in memory only, for the command's actor's page
// alone, which draws it as a QR and never as text or a link. The route
// names no generation, so it is never gone; a QR's idempotency key is the
// command's id and its seq.
//
// A QR is WhatsApp's link code: its random references, public keys and
// the pairing's own secret. It holds no phone number, name or message, and
// a phone that scans it links only into the number being relinked, since
// the app refuses another account before it stores anything. It is the one
// exception to the never-list, on this route alone, and is never logged:
// PairingQR's String, GoString and LogValue leave it out, and no error of
// this package carries it.

// The values of a pairing.
const (
	// MaxPairingQR is a QR's longest text, in characters (ASCII, so
	// bytes). whatsmeow's measured 277.
	MaxPairingQR = 512
	// PairingBodyLimit is the pairing call's body limit.
	PairingBodyLimit = 4 << 10
	// MaxPairingAhead is how far after the platform's clock a QR's
	// expires_at may be; it is always after that clock.
	MaxPairingAhead = 90 * time.Second
	// PairingHold is how long after a command's first QR the platform
	// takes another: a PUT later than this is answered accepted false, and
	// the QR it holds goes then at the latest.
	PairingHold = 3 * time.Minute
)

// pairingQRGrammar is a QR's alphabet: whatsmeow's text
// (https://wa.me/settings/linked_devices#, then five comma-separated parts
// in base64), and nothing else. The kit checks no structure beyond it.
var pairingQRGrammar = regexp.MustCompile(`^[A-Za-z0-9+/=,@._:#-]{1,512}$`)

// ValidPairingQR reports whether qr is a QR's text: 1 to MaxPairingQR
// characters of the alphabet ^[A-Za-z0-9+/=,@._:#-]$, ASCII only.
func ValidPairingQR(qr string) bool { return pairingQRGrammar.MatchString(qr) }

// PairingQR is the pairing call's body: the QR's text, its rising seq
// within the command (from 1), and when WhatsApp's window for it ends. On
// the wire it is exactly {"seq", "qr", "expires_at"}, read strictly (every
// member present, none null, none unknown, none twice), expires_at RFC 3339
// in UTC with "Z". A seq at or below the highest the platform kept is no
// fault of the body: the platform answers it accepted false, so Validate
// does not judge it.
type PairingQR struct {
	Seq       int64     `json:"seq"`
	QR        string    `json:"qr"`
	ExpiresAt time.Time `json:"expires_at"`
}

// pairingWire is PairingQR as the wire carries it, its time a Time.
type pairingWire struct {
	Seq       int64  `json:"seq"`
	QR        string `json:"qr"`
	ExpiresAt Time   `json:"expires_at"`
}

// MarshalJSON writes the body, expires_at in UTC with "Z".
func (p PairingQR) MarshalJSON() ([]byte, error) {
	return json.Marshal(pairingWire{Seq: p.Seq, QR: p.QR, ExpiresAt: T(p.ExpiresAt)})
}

// UnmarshalJSON reads the body as the platform reads what an app sends
// (DecodeStrict): exactly its three members, none null, and expires_at RFC
// 3339 in UTC with "Z". Any failure is ErrInvalid, and never carries the
// QR.
func (p *PairingQR) UnmarshalJSON(b []byte) error {
	var w pairingWire
	if err := decodeExact(b, &w, "pairing"); err != nil {
		return err
	}
	*p = PairingQR{Seq: w.Seq, QR: w.QR, ExpiresAt: w.ExpiresAt.Time}
	return nil
}

// Validate checks the body's shape: a seq of 1 or more, a QR of the
// alphabet (ValidPairingQR), and an expires_at that is set. Its errors
// name the member, never the QR.
func (p PairingQR) Validate() error {
	switch {
	case p.Seq < 1:
		return invalid("seq")
	case !ValidPairingQR(p.QR):
		return invalid("qr")
	case p.ExpiresAt.IsZero() || p.ExpiresAt.Year() < 1970:
		return invalid("expires_at")
	}
	return nil
}

// ValidateAt is Validate, and an expires_at after now and at most
// MaxPairingAhead after it: the platform checks it on its own clock, and
// the app (Client.PutPairing) on its own before it sends.
func (p PairingQR) ValidateAt(now time.Time) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if !p.ExpiresAt.After(now) || p.ExpiresAt.After(now.Add(MaxPairingAhead)) {
		return invalid("expires_at is after now and at most %s after it", MaxPairingAhead)
	}
	return nil
}

// String leaves the QR out.
func (p PairingQR) String() string {
	return fmt.Sprintf("contract.PairingQR{Seq: %d, QR: %q, ExpiresAt: %s}", p.Seq, Ellipsis, p.ExpiresAt.UTC().Format(time.RFC3339Nano))
}

// GoString is String, for %#v.
func (p PairingQR) GoString() string { return p.String() }

// LogValue leaves the QR out of a structured log.
func (p PairingQR) LogValue() slog.Value {
	return slog.GroupValue(slog.Int64("seq", p.Seq), slog.Time("expires_at", p.ExpiresAt.UTC()))
}

// PairingAnswer is the platform's signed 200 to a pairing call: accepted
// true when it holds the QR; false for a seq at or below the highest it
// kept, or a PUT more than PairingHold after the command's first QR. The
// app counts both as delivered. On the wire it is exactly {"accepted"},
// read strictly as PairingQR is.
type PairingAnswer struct {
	Accepted bool `json:"accepted"`
}

// pairingAnswerWire is PairingAnswer without its own UnmarshalJSON.
type pairingAnswerWire struct {
	Accepted bool `json:"accepted"`
}

// UnmarshalJSON reads the answer strictly: exactly its one member, a
// boolean. Any failure is ErrInvalid.
func (a *PairingAnswer) UnmarshalJSON(b []byte) error {
	var w pairingAnswerWire
	if err := decodeExact(b, &w, "pairing answer"); err != nil {
		return err
	}
	a.Accepted = w.Accepted
	return nil
}
