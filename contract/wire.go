package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// ErrInvalid is the root of every validation refusal. Wrapped errors say
// which member failed, never its value.
var ErrInvalid = errors.New("contract: invalid")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
}

// Time is a moment on the wire: RFC 3339 in UTC, "Z", with up to nine
// fractional digits. It never carries another zone.
type Time struct{ time.Time }

// T wraps t, in UTC.
func T(t time.Time) Time { return Time{t.UTC()} }

// MarshalJSON writes t in UTC.
func (t Time) MarshalJSON() ([]byte, error) {
	return []byte(`"` + t.UTC().Format(time.RFC3339Nano) + `"`), nil
}

// timeGrammar is RFC 3339's date-time in UTC: a "." before at most nine
// fractional digits (time.Parse would also take a "," and cut the digits
// past nine), and "Z".
var timeGrammar = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$`)

// UnmarshalJSON reads an RFC 3339 time that ends in Z.
func (t *Time) UnmarshalJSON(b []byte) error {
	s := string(b)
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' || !strings.HasSuffix(s, `Z"`) {
		return invalid("a time must be RFC 3339 in UTC")
	}
	text := s[1 : len(s)-1]
	if !timeGrammar.MatchString(text) {
		if dot := strings.IndexByte(text, '.'); dot >= 0 && len(text)-dot-2 > 9 {
			return invalid("a time carries at most nine fractional digits")
		}
		return invalid("a time must be RFC 3339 in UTC")
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	if err != nil || parsed.Year() < 1970 {
		return invalid("a time must be RFC 3339 in UTC")
	}
	t.Time = parsed.UTC()
	return nil
}

// The values of an account document.
const (
	DocV        = 1
	DocType     = "account"
	StatusOpen  = "open"
	StatusClose = "closed"

	AccountActive   = "active"
	AccountDisabled = "disabled"
	AccountClosed   = "closed"

	KindPersonal = "personal"
	KindTeam     = "team"

	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// MaxWorkspaceName is the longest team name, in characters (the platform's
// decision 0037).
const MaxWorkspaceName = 80

// AccountDoc is one account's workspaces, as one app sees them: only the
// account's own memberships, never another member, an email or a name.
type AccountDoc struct {
	V                    int         `json:"v"`
	Type                 string      `json:"type"`
	App                  string      `json:"app"`
	Generation           string      `json:"generation"`
	Sub                  string      `json:"sub"`
	Version              int64       `json:"version"`
	Status               string      `json:"status"`
	DisabledAt           *Time       `json:"disabled_at"`
	SessionsRevokedAt    *Time       `json:"sessions_revoked_at"`
	CredentialsRevokedAt *Time       `json:"credentials_revoked_at"`
	Workspaces           []Workspace `json:"workspaces"`
}

// Workspace is one of an account's workspaces in its document.
type Workspace struct {
	ID       string  `json:"id"`
	Kind     string  `json:"kind"`
	Name     *string `json:"name"`
	Role     string  `json:"role"`
	Status   string  `json:"status"`
	WVersion int64   `json:"wversion"`
	// Owners is a team's number of owners; null for a personal workspace.
	Owners *int `json:"owners"`
}

// Validate checks every member of a document.
func (d AccountDoc) Validate() error {
	switch {
	case d.V != DocV:
		return invalid("v")
	case d.Type != DocType:
		return invalid("type")
	case !ValidApp(d.App):
		return invalid("app")
	case !ValidUUID(d.Generation):
		return invalid("generation")
	case !ValidUUID(d.Sub):
		return invalid("sub")
	case d.Version < 1:
		return invalid("version")
	}
	switch d.Status {
	case AccountActive, AccountDisabled:
	case AccountClosed:
		if len(d.Workspaces) != 0 {
			return invalid("a closed account has no workspaces")
		}
	default:
		return invalid("status")
	}
	if d.Workspaces == nil {
		return invalid("workspaces")
	}
	seen := map[string]bool{}
	for i, w := range d.Workspaces {
		if err := w.validate(); err != nil {
			return err
		}
		if seen[w.ID] {
			return invalid("a workspace appears twice")
		}
		seen[w.ID] = true
		if w.Kind == KindPersonal && i != 0 {
			return invalid("the personal workspace comes first")
		}
	}
	return nil
}

func (w Workspace) validate() error {
	if !ValidUUID(w.ID) {
		return invalid("workspaces[].id")
	}
	switch w.Role {
	case RoleOwner, RoleAdmin, RoleMember:
	default:
		return invalid("workspaces[].role")
	}
	if w.WVersion < 1 {
		return invalid("workspaces[].wversion")
	}
	switch w.Kind {
	case KindPersonal:
		if w.Name != nil || w.Role != RoleOwner || w.Status != StatusOpen || w.Owners != nil {
			return invalid("a personal workspace has no name or owner count, and is open with its owner")
		}
	case KindTeam:
		if w.Name == nil || !validName(*w.Name) {
			return invalid("workspaces[].name")
		}
		if w.Owners == nil || *w.Owners < 0 || (w.Status == StatusOpen && *w.Owners < 1) {
			return invalid("workspaces[].owners")
		}
		if w.Status != StatusOpen && w.Status != StatusClose {
			return invalid("workspaces[].status")
		}
	default:
		return invalid("workspaces[].kind")
	}
	return nil
}

// validName is the wire's floor for a team's name: 1 to 80 characters, no
// control, format or bidirectional character. The platform's own rule (0037)
// is stricter; the console applies it when the name is set.
func validName(s string) bool {
	n := utf8.RuneCountInString(s)
	if n == 0 || n > MaxWorkspaceName || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	return !strings.ContainsFunc(s, hidden)
}

// Feed is one answer of the feed: the documents that changed after a cursor.
type Feed struct {
	Generation          string     `json:"generation"`
	GenerationConfirmed bool       `json:"generation_confirmed"`
	Head                int64      `json:"head"`
	PublishedThrough    Time       `json:"published_through"`
	Items               []FeedItem `json:"items"`
	NextAfter           int64      `json:"next_after"`
	More                bool       `json:"more"`
}

// FeedItem is one document and its place in the feed.
type FeedItem struct {
	Seq int64      `json:"seq"`
	Doc AccountDoc `json:"doc"`
}

// MaxFeedItems is the most documents one feed answer carries.
const MaxFeedItems = 200

// MaxWait is the longest a feed request may ask to be held, in seconds.
const MaxWait = 25

// Validate checks a feed answer, and that every document in it is the app's
// own and in the feed's generation.
func (f Feed) Validate(app string) error {
	switch {
	case !ValidUUID(f.Generation):
		return invalid("generation")
	case f.Head < 0 || f.NextAfter < 0 || f.NextAfter > f.Head:
		return invalid("head")
	case f.Items == nil || len(f.Items) > MaxFeedItems:
		return invalid("items")
	}
	last := int64(-1)
	for _, it := range f.Items {
		if it.Seq <= last || it.Seq > f.Head {
			return invalid("items[].seq")
		}
		last = it.Seq
		if err := it.Doc.Validate(); err != nil {
			return err
		}
		if it.Doc.App != app || it.Doc.Generation != f.Generation {
			return invalid("items[].doc belongs to another app or generation")
		}
	}
	return nil
}

// The values of an access snapshot.
const (
	SnapshotV = 1

	ItemNumber  = "number"
	ItemMailbox = "mailbox"

	StateActive     = "active"
	StateSyncPaused = "sync_paused"
	StateDeleted    = "deleted"

	CanRead   = "read"
	CanSend   = "send"
	CanAct    = "act"
	CanManage = "manage"
)

// pauseReasons are why an item's sync is off.
var pauseReasons = []string{"by_person", "team_closed", "no_reader", "needs_reauth", "quota", "error"}

// PauseReasons are why an item's sync is off. It returns a copy: the set
// Validate checks is closed, and no caller can widen or narrow it.
func PauseReasons() []string { return slices.Clone(pauseReasons) }

// MaxItems is the most items one snapshot carries, and MaxPeople the most
// people one item lists.
const (
	MaxItems  = 1000
	MaxPeople = 5000
	// MaxOtherBackups bounds an item's count of backups without a sub.
	MaxOtherBackups = 1 << 20
)

// Snapshot is what one app reports of one platform workspace: each item, who
// can do what with it, and whom the app's own rule protects.
type Snapshot struct {
	V int `json:"v"`
	// SnapshotSeq is the app's clock, in milliseconds, when it measured.
	SnapshotSeq int64  `json:"snapshot_seq"`
	Items       []Item `json:"items"`
}

// Item is one number or mailbox in a snapshot.
type Item struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	Label        *string  `json:"label"`
	Hint         *string  `json:"hint"`
	State        string   `json:"state"`
	Reason       *string  `json:"reason"`
	PurgeAt      *Time    `json:"purge_at"`
	OtherBackups int      `json:"other_backups"`
	People       []Person `json:"people"`
	Protected    []string `json:"protected"`
	// Ordinal, when not 0, is the app's number for the item, 1 to
	// MaxOrdinal: unique among the snapshot's items and stable for the
	// item's life, across renames. 0 is absent: the app gives none. It
	// names nothing a command acts on; the console names an unlabelled item
	// by it.
	Ordinal Ordinal `json:"ordinal,omitzero"`
	// Tokens, when not nil, are the tokens that hold permissions on the
	// item (SPEC section 11.18). nil is absent: the app does not report
	// tokens; an empty, non-nil list says no token holds the item, so an
	// app that reports tokens sends ItemTokens{} for an item none holds.
	// A token is never in People, Protected or OtherBackups.
	Tokens ItemTokens `json:"tokens,omitzero"`
}

// MaxOrdinal is an item's highest ordinal, and MaxItemTokens the most
// tokens one item lists.
const (
	MaxOrdinal    = 9999
	MaxItemTokens = 1000
)

// Ordinal is an item's number in a snapshot, 1 to MaxOrdinal; 0 is no
// ordinal, and the member is then absent. Present, it is never null or 0.
type Ordinal int

// UnmarshalJSON reads an ordinal that is present: an integer, never null
// or 0, which would read as absent.
func (o *Ordinal) UnmarshalJSON(b []byte) error {
	var n int64
	if string(bytes.TrimSpace(b)) == "null" || json.Unmarshal(b, &n) != nil || n == 0 || n < -MaxOrdinal-1 || n > MaxOrdinal+1 {
		return invalid("items[].ordinal")
	}
	*o = Ordinal(n)
	return nil
}

// ItemTokens are the tokens of an item in a snapshot. Present, the list is
// never null: absent (nil) is what says the app does not report tokens.
type ItemTokens []ItemToken

// UnmarshalJSON reads the list, refusing null, and each entry strictly.
func (t *ItemTokens) UnmarshalJSON(b []byte) error {
	v, err := decodePresent[ItemToken](b, "items[].tokens")
	if err != nil {
		return err
	}
	*t = v
	return nil
}

// ItemToken is one token's standing on an item, named by the token's id,
// never its selector.
type ItemToken struct {
	ID string `json:"id"`
	// Can are the permissions the app applied: a number's read, send and
	// manage; a mailbox's read, act and send.
	Can []string `json:"can"`
	// Reads: in Wappie, the read flag and a grant at the number's current
	// epoch; in Mailie, the flag.
	Reads bool `json:"reads"`
	// Waiting: the read flag without that grant (Wappie only; a mailbox's
	// is always false).
	Waiting bool `json:"waiting"`
}

// Person is one person's standing on an item.
type Person struct {
	Sub      string   `json:"sub"`
	Can      []string `json:"can"`
	Reads    bool     `json:"reads"`
	Waiting  bool     `json:"waiting"`
	Enrolled bool     `json:"enrolled"`
	HoldsKey bool     `json:"holds_key"`
}

// Validate checks a snapshot, its labels included: a label that is not
// clean is refused here. A receiver that would rather keep the snapshot
// cleans the labels first (CleanLabel).
func (s Snapshot) Validate() error {
	switch {
	case s.V != SnapshotV:
		return invalid("v")
	case s.SnapshotSeq < 1:
		return invalid("snapshot_seq")
	case s.Items == nil || len(s.Items) > MaxItems:
		return invalid("items")
	}
	seen := map[string]bool{}
	ordinals := map[Ordinal]bool{}
	for _, it := range s.Items {
		if err := it.validate(); err != nil {
			return err
		}
		// An id is the item's whatever its kind: the platform keeps an
		// app's items of a workspace by id.
		if seen[it.ID] {
			return invalid("an item appears twice")
		}
		seen[it.ID] = true
		if it.Ordinal != 0 {
			if ordinals[it.Ordinal] {
				return invalid("two items share an ordinal")
			}
			ordinals[it.Ordinal] = true
		}
	}
	return nil
}

func (it Item) validate() error {
	if !ValidItemID(it.ID) {
		return invalid("items[].id")
	}
	if it.Kind != ItemNumber && it.Kind != ItemMailbox {
		return invalid("items[].kind")
	}
	if it.Label != nil && !ValidLabel(*it.Label) {
		return invalid("items[].label")
	}
	if it.Hint != nil && !ValidHint(*it.Hint) {
		return invalid("items[].hint")
	}
	switch it.State {
	case StateActive, StateDeleted:
		if it.Reason != nil {
			return invalid("items[].reason is for a paused item")
		}
	case StateSyncPaused:
		if it.Reason == nil || !oneOf(*it.Reason, pauseReasons) {
			return invalid("items[].reason")
		}
	default:
		return invalid("items[].state")
	}
	if (it.State == StateDeleted) != (it.PurgeAt != nil) {
		return invalid("items[].purge_at is for a deleted item, and a deleted item has one")
	}
	if it.OtherBackups < 0 || it.OtherBackups > MaxOtherBackups {
		return invalid("items[].other_backups")
	}
	if it.People == nil || len(it.People) > MaxPeople || it.Protected == nil {
		return invalid("items[].people")
	}
	people := map[string]bool{}
	for _, p := range it.People {
		if !ValidUUID(p.Sub) || people[p.Sub] {
			return invalid("items[].people[].sub")
		}
		people[p.Sub] = true
		if err := validCan(p.Can); err != nil {
			return err
		}
	}
	protected := map[string]bool{}
	for _, sub := range it.Protected {
		if !people[sub] || protected[sub] {
			return invalid("items[].protected names someone the item does not list")
		}
		protected[sub] = true
	}
	if it.Ordinal != 0 && (it.Ordinal < 1 || it.Ordinal > MaxOrdinal) {
		return invalid("items[].ordinal")
	}
	if it.Tokens != nil {
		if len(it.Tokens) > MaxItemTokens {
			return invalid("items[].tokens")
		}
		tokens := map[string]bool{}
		for _, t := range it.Tokens {
			if !ValidUUID(t.ID) || tokens[t.ID] {
				return invalid("items[].tokens[].id")
			}
			tokens[t.ID] = true
			if t.Can == nil {
				return invalid("items[].tokens[].can")
			}
			can := map[string]bool{}
			for _, c := range t.Can {
				if !oneOf(c, tokenPerms[it.Kind]) || can[c] {
					return invalid("items[].tokens[].can")
				}
				can[c] = true
			}
			if t.Waiting && it.Kind == ItemMailbox {
				return invalid("items[].tokens[].waiting is a number's")
			}
		}
	}
	return nil
}

func validCan(can []string) error {
	if can == nil {
		return invalid("items[].people[].can")
	}
	seen := map[string]bool{}
	for _, c := range can {
		if !oneOf(c, []string{CanRead, CanSend, CanAct, CanManage}) || seen[c] {
			return invalid("items[].people[].can")
		}
		seen[c] = true
	}
	return nil
}

// AccessResult is the answer to a snapshot.
type AccessResult struct {
	Accepted bool `json:"accepted"`
}

// The values of an event.
const (
	EventDeleted    = "item.deleted"
	EventSyncPaused = "item.sync_paused"
	EventRecovered  = "item.recovered"
	EventPurged     = "item.purged"
	EventStranded   = "item.stranded"
	EventMovedOut   = "item.moved_out"

	ActorPerson = "person"
	ActorKey    = "key"
	ActorApp    = "app"

	OutcomeAccepted  = "accepted"
	OutcomeDuplicate = "duplicate"
	OutcomeRejected  = "rejected"

	MovedToPersonal = "personal"
)

// strandedCauses are why an item lost the last person who could read it.
var strandedCauses = []string{"disabled", "revoked", "removed", "left", "closed"}

// StrandedCauses are why an item lost the last person who could read it. An
// app sends disabled or revoked when it knows; the platform fills removed,
// left or closed when a membership ended. It returns a copy: the set
// Validate checks is closed, and no caller can widen or narrow it.
func StrandedCauses() []string { return slices.Clone(strandedCauses) }

// MaxEvents is the most events one batch carries, and MaxReaders the most
// readers one event names; above it an app sends readers: null.
const (
	MaxEvents  = 100
	MaxReaders = 5000
)

// Events is a batch of an app's events, in each workspace's order.
type Events struct {
	Events []Event `json:"events"`
}

// Event is one of 0038's events, or a stranding or a move (0040).
type Event struct {
	EventID     string    `json:"event_id"`
	WorkspaceID string    `json:"workspace_id"`
	Type        string    `json:"type"`
	OccurredAt  Time      `json:"occurred_at"`
	Item        EventItem `json:"item"`
	Actor       *string   `json:"actor"`
	ActorKind   string    `json:"actor_kind"`
	// Readers are the item's readers just before, the actor included, or
	// null above MaxReaders.
	Readers *[]string `json:"readers"`
	PurgeAt *Time     `json:"purge_at,omitempty"`
	Person  *string   `json:"person,omitempty"`
	Cause   *string   `json:"cause,omitempty"`
	To      *string   `json:"to,omitempty"`
	// Stop is what an item.sync_paused stopped: StopPause or StopTurnOff,
	// or "", absent, which the platform reads as a pause for a number and a
	// turn-off for a mailbox, what each app sent before the member existed.
	Stop Stop `json:"stop,omitzero"`
}

// Stop is an item.sync_paused's stop. Present, it is never null or "".
type Stop string

// The stops of an item.sync_paused.
const (
	// StopPause: one item's sync (Mailie) or capture (Wappie) was paused;
	// what it holds stays, and it can be resumed.
	StopPause Stop = "pause"
	// StopTurnOff: a team mailbox's sync agreement was withdrawn, which
	// deleted its index for every reader. Mailie only: the item is a
	// mailbox.
	StopTurnOff Stop = "turn_off"
)

// UnmarshalJSON reads a stop that is present: a string, never null or
// empty, which would read as absent. Validate checks its value.
func (s *Stop) UnmarshalJSON(b []byte) error {
	var v string
	if string(bytes.TrimSpace(b)) == "null" || json.Unmarshal(b, &v) != nil || v == "" {
		return invalid("stop is absent, never null or empty")
	}
	*s = Stop(v)
	return nil
}

// EventItem names the item an event is about.
type EventItem struct {
	ID    string  `json:"id"`
	Kind  string  `json:"kind"`
	Label *string `json:"label"`
	Hint  *string `json:"hint"`
}

// Validate checks a batch: its size, every event, and no event id twice.
func (e Events) Validate() error {
	if len(e.Events) == 0 || len(e.Events) > MaxEvents {
		return invalid("events")
	}
	seen := map[string]bool{}
	for _, ev := range e.Events {
		if err := ev.Validate(); err != nil {
			return err
		}
		if seen[ev.EventID] {
			return invalid("an event appears twice")
		}
		seen[ev.EventID] = true
	}
	return nil
}

// Validate checks one event.
func (ev Event) Validate() error {
	switch {
	case !ValidUUID(ev.EventID):
		return invalid("event_id")
	case !ValidUUID(ev.WorkspaceID):
		return invalid("workspace_id")
	case ev.OccurredAt.IsZero():
		return invalid("occurred_at")
	case !ValidItemID(ev.Item.ID):
		return invalid("item.id")
	case ev.Item.Kind != ItemNumber && ev.Item.Kind != ItemMailbox:
		return invalid("item.kind")
	case ev.Item.Label != nil && !ValidLabel(*ev.Item.Label):
		return invalid("item.label")
	case ev.Item.Hint != nil && !ValidHint(*ev.Item.Hint):
		return invalid("item.hint")
	case !oneOf(ev.ActorKind, []string{ActorPerson, ActorKey, ActorApp}):
		return invalid("actor_kind")
	case ev.Actor != nil && !ValidUUID(*ev.Actor):
		return invalid("actor")
	case ev.ActorKind == ActorApp && ev.Actor != nil:
		return invalid("an app's own act has no actor")
	}
	if ev.Readers != nil {
		if len(*ev.Readers) > MaxReaders {
			return invalid("readers")
		}
		seen := map[string]bool{}
		for _, sub := range *ev.Readers {
			if !ValidUUID(sub) || seen[sub] {
				return invalid("readers[]")
			}
			seen[sub] = true
		}
	}
	switch {
	case ev.Stop == "":
	case ev.Type != EventSyncPaused:
		return invalid("stop is an item.sync_paused's")
	case ev.Stop == StopPause:
	case ev.Stop == StopTurnOff:
		if ev.Item.Kind != ItemMailbox {
			return invalid("only a mailbox's sync is turned off")
		}
	default:
		return invalid("stop")
	}
	extra := func(purge, person, cause, to bool) error {
		if (ev.PurgeAt != nil) != purge || (!person && ev.Person != nil) || (!cause && ev.Cause != nil) || (ev.To != nil) != to {
			return invalid("a member belongs to another type of event")
		}
		return nil
	}
	switch ev.Type {
	case EventDeleted:
		// An owner deletes. A person with no sub, a fault in the cloud, goes
		// as actor null with actor_kind person.
		if ev.ActorKind != ActorPerson {
			return invalid("an owner deletes")
		}
		return extra(true, false, false, false)
	case EventRecovered:
		if ev.ActorKind != ActorPerson {
			return invalid("an owner recovers")
		}
		return extra(false, false, false, false)
	case EventSyncPaused:
		return extra(false, false, false, false)
	case EventPurged:
		if ev.ActorKind != ActorApp {
			return invalid("the app purges")
		}
		return extra(false, false, false, false)
	case EventStranded:
		if ev.Person != nil && !ValidUUID(*ev.Person) {
			return invalid("person")
		}
		if ev.Cause != nil && !oneOf(*ev.Cause, strandedCauses) {
			return invalid("cause")
		}
		return extra(false, true, true, false)
	case EventMovedOut:
		if ev.ActorKind != ActorPerson || ev.Item.Kind != ItemNumber || ev.To == nil || *ev.To != MovedToPersonal {
			return invalid("only a number moves, to a personal workspace")
		}
		return extra(false, false, false, true)
	default:
		return invalid("type")
	}
}

// EventResults is the answer to a batch: one result per event, in order.
type EventResults struct {
	Results []EventResult `json:"results"`
}

// EventResult is what became of one event.
type EventResult struct {
	EventID string  `json:"event_id"`
	Outcome string  `json:"outcome"`
	Code    *string `json:"code"`
}

// The error codes of the contract (SPEC section 11.17).
const (
	CodeUnauthenticated = "unauthenticated"
	CodeStale           = "stale_timestamp"
	CodeReplay          = "replay"
	CodeInvalid         = "invalid_request"
	CodeNotFound        = "not_found"
	CodeGone            = "gone"
	CodeConflict        = "conflict"
	CodeTooLarge        = "too_large"
	CodeRateLimited     = "rate_limited"
	CodeUnavailable     = "unavailable"
)

// Error is the body of every refusal.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ValidUUID reports whether s is a canonical lowercase UUID, not the nil one.
func ValidUUID(s string) bool {
	return uuidRE.MatchString(s) && s != "00000000-0000-0000-0000-000000000000"
}

var itemIDRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// ValidItemID reports whether s is an item's id: the app's own opaque id,
// 1 to 64 characters of [A-Za-z0-9_.-].
func ValidItemID(s string) bool { return itemIDRE.MatchString(s) }

func oneOf(s string, set []string) bool {
	for _, v := range set {
		if s == v {
			return true
		}
	}
	return false
}
