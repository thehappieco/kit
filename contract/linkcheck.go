package contract

import (
	"fmt"
	"log/slog"
	"slices"
)

// The link check (SPEC section 11.20): POST
// /contract/v1/workspaces/{id}/link-check, with no side effect. With codes,
// it comes only once ownership of the item is proven, and before its first
// sync; without codes it asks for the place alone, and may come before the
// link starts. The answer is advisory for the place: the app decides from
// its own count.

// The values and bounds of a link check.
const (
	// LinkCheckBodyLimit is the body limit of the link check.
	LinkCheckBodyLimit = 4 << 10
	// LinkChecksPerMinute is the most link checks with codes one app makes
	// a minute in one workspace; over it, a signed rate_limited. A check
	// without codes spends the app's 50 requests a second only.
	LinkChecksPerMinute = 30

	// A link check's place: a free one, or none, from the document's places
	// computed now; null while the platform's count is unknown.
	PlaceFree = "free"
	PlaceNone = "none"
)

// linkCheckTrials are the answer's trials: no trial needed (TrialNotNeeded),
// a clock that ended, or one that runs or a link would start.
var linkCheckTrials = []string{TrialNotNeeded, TrialUsedUp, TrialRunning}

// LinkCheckTrials are a link check answer's trial values: not_needed,
// used_up, running. It returns a copy.
func LinkCheckTrials() []string { return slices.Clone(linkCheckTrials) }

// LinkCheck is a link check's body: the item's kind, which is the app's
// (AppItemKind), its trial codes (TrialCode), 0 to MaxTrialCodes, each
// once, and whether the item is a server's being connected, which carries
// no codes. The platform reads it strictly (DecodeStrict): codes is always
// present, [] for none, never null.
type LinkCheck struct {
	Kind      string   `json:"kind"`
	Codes     []string `json:"codes"`
	Connected bool     `json:"connected"`
}

// Validate checks a link check: a kind of number or mailbox, codes listed
// ([] for none), at most MaxTrialCodes, each a trial code and once, and
// none beside connected. Its errors never carry a code.
func (c LinkCheck) Validate() error {
	switch {
	case c.Kind != ItemNumber && c.Kind != ItemMailbox:
		return invalid("kind")
	case c.Codes == nil:
		return invalid("codes is [] when none")
	case c.Connected && len(c.Codes) != 0:
		return invalid("a connected item carries no codes")
	}
	return validTrialCodes(c.Codes, MaxTrialCodes)
}

// ValidateFor is Validate, and that the kind is app's (AppItemKind): another
// is the platform's signed invalid_request.
func (c LinkCheck) ValidateFor(app string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if kind, ok := AppItemKind(app); !ok || c.Kind != kind {
		return invalid("kind is the app's")
	}
	return nil
}

// String leaves the codes out: a code is personal data.
func (c LinkCheck) String() string {
	return fmt.Sprintf("contract.LinkCheck{Kind: %q, Codes: %d, Connected: %t}", c.Kind, len(c.Codes), c.Connected)
}

// GoString is String, for %#v.
func (c LinkCheck) GoString() string { return c.String() }

// LogValue is the check's kind, how many codes it carries and whether the
// item is connected, never a code.
func (c LinkCheck) LogValue() slog.Value {
	return slog.GroupValue(slog.String("kind", c.Kind), slog.Int("codes", len(c.Codes)), slog.Bool("connected", c.Connected))
}

// LinkCheckAnswer is the platform's signed answer to a link check. An app
// reads it as it reads what the platform sends (UnmarshalJSON): members it
// does not know ignored, every member present, null only for place and
// trial_ends_at.
type LinkCheckAnswer struct {
	// Place is PlaceFree or PlaceNone, or nil while the platform's count is
	// unknown. Advisory: the app decides from its own count.
	Place *string `json:"place"`
	// Trial is TrialNotNeeded, TrialUsedUp or TrialRunning.
	Trial string `json:"trial"`
	// TrialEndsAt is set exactly on running, after ComputedAt: the
	// matching clock's end, or ComputedAt plus 360 h for a clock a link
	// would start.
	TrialEndsAt *Time             `json:"trial_ends_at"`
	Switches    LinkCheckSwitches `json:"switches"`
	// ComputedAt is the platform's clock.
	ComputedAt Time `json:"computed_at"`
}

// LinkCheckSwitches are the switches a link check answers: new_links, from
// the document computed now.
type LinkCheckSwitches struct {
	NewLinks string `json:"new_links"`
}

// UnmarshalJSON reads an answer as an app reads what the platform sends:
// one well-formed JSON object, members it does not know ignored, a member
// counted only as exactly named, every member present, and null only for
// place and trial_ends_at. Validate is the reader's next step.
func (a *LinkCheckAnswer) UnmarshalJSON(b []byte) error {
	type answer LinkCheckAnswer
	var v answer
	if err := decodeSent(b, &v, "link check answer"); err != nil {
		return err
	}
	*a = LinkCheckAnswer(v)
	return nil
}

// Validate checks an answer: place free, none or null; trial one of
// LinkCheckTrials; trial_ends_at set exactly on running and after
// computed_at; new_links on or off; computed_at set.
func (a LinkCheckAnswer) Validate() error {
	switch {
	case a.Place != nil && *a.Place != PlaceFree && *a.Place != PlaceNone:
		return invalid("place")
	case !oneOf(a.Trial, linkCheckTrials):
		return invalid("trial")
	case a.ComputedAt.IsZero():
		return invalid("computed_at")
	case (a.TrialEndsAt != nil) != (a.Trial == TrialRunning):
		return invalid("trial_ends_at is set exactly on running")
	case a.TrialEndsAt != nil && !a.TrialEndsAt.After(a.ComputedAt.Time):
		return invalid("trial_ends_at is after computed_at")
	case a.Switches.NewLinks != SwitchOn && a.Switches.NewLinks != SwitchOff:
		return invalid("switches.new_links")
	}
	return nil
}
