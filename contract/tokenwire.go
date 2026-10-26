package contract

import (
	"bytes"
	"encoding/json"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
)

// The token part's wire (SPEC section 11.18; the platform's decision 0053):
// a token's record, one per app the token names, the token feed that
// carries the records, an app's acknowledgement of what it applied, and its
// report of each token's use.

// The values of a token's record.
const (
	TokenRecordV    = 1
	TokenRecordType = "token"

	// MaxTokenItems is the most items one record carries.
	MaxTokenItems = 1000
	// MaxTokenLifetime is the longest a token lives: its expires_at is at
	// most 365 days of 24 hours after its created_at. A calendar year that
	// holds a 29 February is 366 days: the console adds 365 × 24 h, never
	// one year.
	MaxTokenLifetime = 365 * 24 * time.Hour
	// MaxTokenFeedItems is the most records one token feed answer carries.
	MaxTokenFeedItems = 200
)

// The reasons a record is revoked (revoked_reason).
const (
	// RevokedInConsole: an owner or admin revoked it in the console.
	RevokedInConsole = "revoked"
	// RevokedCreatorLeft: its creator left the workspace or was removed.
	RevokedCreatorLeft = "creator_left"
	// RevokedCreatorDisabled: the operator disabled the creator's account.
	RevokedCreatorDisabled = "creator_disabled"
	// RevokedCreatorClosed: the creator's account closed.
	RevokedCreatorClosed = "creator_closed"
	// RevokedCreatorRecovered: the creator recovered their account; a token
	// created before the recovery stops.
	RevokedCreatorRecovered = "creator_recovered"
	// RevokedOperator: the platform's operator revoked it.
	RevokedOperator = "operator"
	// RevokedAppRemoved: the app was taken off the token; only that app's
	// record says so.
	RevokedAppRemoved = "app_removed"
	// RevokedAppHeld: after a reset, the app reported it held the token
	// revoked; only that app's record says so.
	RevokedAppHeld = "app_held"
)

var revokedReasons = []string{
	RevokedInConsole, RevokedCreatorLeft, RevokedCreatorDisabled, RevokedCreatorClosed,
	RevokedCreatorRecovered, RevokedOperator, RevokedAppRemoved, RevokedAppHeld,
}

// RevokedReasons are why a record is revoked. It returns a copy: the set
// Validate checks is closed.
func RevokedReasons() []string { return slices.Clone(revokedReasons) }

// tokenPerms are the permissions a token may hold on an item, by the
// item's kind: a number's (Wappie) are each independent; a mailbox's
// (Mailie) act only beside read.
var tokenPerms = map[string][]string{
	ItemNumber:  {CanRead, CanSend, CanManage},
	ItemMailbox: {CanRead, CanAct, CanSend},
}

// TokenPerms are the permissions a token may hold on an item of kind
// (ItemNumber, ItemMailbox), or nil for another kind. It returns a copy.
func TokenPerms(kind string) []string { return slices.Clone(tokenPerms[kind]) }

// tokenKinds are the item kinds of the apps that hold one kind only. An
// app not listed (the platform's reference app, in development) may list
// either kind, each under its kind's rule.
var tokenKinds = map[string]string{"wappie": ItemNumber, "mailie": ItemMailbox}

// TokenRecord is one token as one app sees it: one record per (app,
// token), only for an app the token names or named and a workspace named
// to that app. It never carries the token's secret, only its hash.
type TokenRecord struct {
	V          int    `json:"v"`
	Type       string `json:"type"`
	App        string `json:"app"`
	Generation string `json:"generation"`
	// ID is the token's stable id, the same in every app; pages, snapshots
	// and commands name a token by it, never by its selector.
	ID string `json:"id"`
	// Version rises whenever this app's record changes, and never repeats.
	Version     int64  `json:"version"`
	Selector    string `json:"selector"`
	Hash        string `json:"hash"`
	WorkspaceID string `json:"workspace_id"`
	// Name is a label a person gave the token (CleanLabel's rule).
	Name      string `json:"name"`
	CreatedBy string `json:"created_by"`
	CreatedAt Time   `json:"created_at"`
	ExpiresAt Time   `json:"expires_at"`
	// RevokedAt and RevokedReason are both null, or both set and never
	// cleared; a revoked record has no items.
	RevokedAt     *Time       `json:"revoked_at"`
	RevokedReason *string     `json:"revoked_reason"`
	Terms         *TokenTerms `json:"terms"`
	ReadingKey    *ReadingKey `json:"reading_key"`
	Items         []TokenItem `json:"items"`
}

// TokenTerms are the app's key terms the creator agreed to when the app
// was added to the token, by revision.
type TokenTerms struct {
	Version  string `json:"version"`
	AgreedAt Time   `json:"agreed_at"`
}

// ReadingKey is a token's reading key: an X25519 public key its client
// made, whose private half never leaves that client. Once set, it never
// changes.
type ReadingKey struct {
	Suite        string `json:"suite"`
	Key          string `json:"key"`
	Fingerprint  string `json:"fingerprint"`
	RegisteredAt Time   `json:"registered_at"`
}

// TokenItem is one item of the app on which the token holds permissions.
type TokenItem struct {
	ID    string      `json:"id"`
	Kind  string      `json:"kind"`
	Perms []TokenPerm `json:"perms"`
}

// TokenPerm is one permission on an item, and who gave it when.
type TokenPerm struct {
	Perm      string `json:"perm"`
	GrantedBy string `json:"granted_by"`
	GrantedAt Time   `json:"granted_at"`
}

// termsRE is a key-terms revision's name, such as 2026-10-api-keys-2.
var termsRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Validate checks every member of a record. A record that fails is a bad
// record: an app applies only what it narrows (a revocation, an earlier
// expires_at, an item or permission it no longer lists), refuses its
// grants as invalid_record, and advances its cursor past it. It does not
// compare the reading key's fingerprint with its key: CheckReadingKey does,
// and a record whose fingerprint is not its key's is refused as
// reading_key_changed.
func (r TokenRecord) Validate() error {
	switch {
	case r.V != TokenRecordV:
		return invalid("v")
	case r.Type != TokenRecordType:
		return invalid("type")
	case !ValidApp(r.App):
		return invalid("app")
	case !ValidUUID(r.Generation):
		return invalid("generation")
	case !ValidUUID(r.ID):
		return invalid("id")
	case r.Version < 1:
		return invalid("version")
	case !ValidSelector(r.Selector):
		return invalid("selector")
	case !validHex(r.Hash, 64):
		return invalid("hash")
	case !ValidUUID(r.WorkspaceID):
		return invalid("workspace_id")
	case !ValidLabel(r.Name):
		return invalid("name")
	case !ValidUUID(r.CreatedBy):
		return invalid("created_by")
	case r.CreatedAt.IsZero() || r.ExpiresAt.IsZero():
		return invalid("created_at, expires_at")
	case !r.ExpiresAt.After(r.CreatedAt.Time) || r.ExpiresAt.Sub(r.CreatedAt.Time) > MaxTokenLifetime:
		return invalid("expires_at is after created_at, and at most 365 days after it")
	case (r.RevokedAt == nil) != (r.RevokedReason == nil):
		return invalid("revoked_at and revoked_reason are both set or both null")
	case r.RevokedReason != nil && !oneOf(*r.RevokedReason, revokedReasons):
		return invalid("revoked_reason")
	case r.RevokedAt != nil && r.RevokedAt.IsZero():
		return invalid("revoked_at")
	}
	if r.Terms != nil && (!termsRE.MatchString(r.Terms.Version) || r.Terms.AgreedAt.IsZero()) {
		return invalid("terms")
	}
	if r.ReadingKey != nil {
		if err := r.ReadingKey.Validate(); err != nil {
			return err
		}
	}
	if r.Items == nil || len(r.Items) > MaxTokenItems {
		return invalid("items")
	}
	if r.RevokedAt != nil && len(r.Items) != 0 {
		return invalid("a revoked record has no items")
	}
	seen := map[string]bool{}
	for _, it := range r.Items {
		if err := it.validate(r.App); err != nil {
			return err
		}
		if seen[it.ID] {
			return invalid("an item appears twice")
		}
		seen[it.ID] = true
	}
	return nil
}

func (it TokenItem) validate(app string) error {
	if !ValidItemID(it.ID) {
		return invalid("items[].id")
	}
	perms := tokenPerms[it.Kind]
	if perms == nil {
		return invalid("items[].kind")
	}
	if kind, ok := tokenKinds[app]; ok && kind != it.Kind {
		return invalid("items[].kind is not the app's")
	}
	if len(it.Perms) == 0 || len(it.Perms) > len(perms) {
		return invalid("items[].perms")
	}
	held := map[string]bool{}
	for _, p := range it.Perms {
		if !oneOf(p.Perm, perms) || held[p.Perm] {
			return invalid("items[].perms[].perm")
		}
		held[p.Perm] = true
		if !ValidUUID(p.GrantedBy) {
			return invalid("items[].perms[].granted_by")
		}
		if p.GrantedAt.IsZero() {
			return invalid("items[].perms[].granted_at")
		}
	}
	// A mailbox's act reaches nothing without read (Mailie's schema).
	if it.Kind == ItemMailbox && held[CanAct] && !held[CanRead] {
		return invalid("items[].perms: act only beside read")
	}
	return nil
}

// Validate checks a reading key's members: its suite, its key
// (ValidReadingKey), the shape of its fingerprint, and its time. That the
// fingerprint is the key's own is CheckReadingKey's.
func (k ReadingKey) Validate() error {
	switch {
	case k.Suite != ReadingKeySuite:
		return invalid("reading_key.suite")
	case ValidReadingKey(k.Key) != nil:
		return invalid("reading_key.key")
	case !validHex(k.Fingerprint, FingerprintLen):
		return invalid("reading_key.fingerprint")
	case k.RegisteredAt.IsZero():
		return invalid("reading_key.registered_at")
	}
	return nil
}

// Check is CheckReadingKey of the key and the fingerprint beside it.
func (k ReadingKey) Check() error { return CheckReadingKey(k.Key, k.Fingerprint) }

// TokenFeed is one answer of the token feed: the records that changed after
// a cursor, the latest version of each, oldest first. It has the account
// feed's grammar and members, with token in place of doc.
type TokenFeed struct {
	Generation          string          `json:"generation"`
	GenerationConfirmed bool            `json:"generation_confirmed"`
	Head                int64           `json:"head"`
	PublishedThrough    Time            `json:"published_through"`
	Items               []TokenFeedItem `json:"items"`
	NextAfter           int64           `json:"next_after"`
	More                bool            `json:"more"`
}

// TokenFeedItem is one record and its place in the token feed. The record
// is kept as it came, and decoded on its own (Record), so that a record
// that does not decode never fails the page it is on.
type TokenFeedItem struct {
	Seq   int64           `json:"seq"`
	Token json.RawMessage `json:"token"`
}

// NewTokenFeedItem is the item of r at seq, as the platform writes it.
func NewTokenFeedItem(seq int64, r TokenRecord) (TokenFeedItem, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return TokenFeedItem{}, err
	}
	return TokenFeedItem{Seq: seq, Token: raw}, nil
}

// Record decodes the item's record on its own, as an app decodes what the
// platform sends: a member it does not know is ignored. Validate is the
// app's next step. A record that does not decode is ErrInvalid, and comes
// with what of it could be read, member by member: a member that does not
// decode is left at its zero value (a zero expires_at is the earliest, so
// the token is past it), except revoked_at, which, present and not null,
// is a zero Time: revoked, at a time unknown. So an app applies of it only
// what it narrows, adds none of its grants, and advances its cursor, as
// for a record that fails Validate (TokenFeed.Validate).
func (it TokenFeedItem) Record() (TokenRecord, error) {
	if trimmed := bytes.TrimSpace(it.Token); len(trimmed) == 0 || trimmed[0] != '{' {
		return TokenRecord{}, invalid("token: not a record")
	}
	var r TokenRecord
	if err := json.Unmarshal(it.Token, &r); err == nil {
		return r, nil
	}
	r = TokenRecord{}
	var members map[string]json.RawMessage
	if json.Unmarshal(it.Token, &members) != nil {
		return TokenRecord{}, invalid("token: not a record")
	}
	for name, into := range map[string]any{
		"v": &r.V, "type": &r.Type, "app": &r.App, "generation": &r.Generation, "id": &r.ID, "version": &r.Version,
		"selector": &r.Selector, "hash": &r.Hash, "workspace_id": &r.WorkspaceID, "name": &r.Name,
		"created_by": &r.CreatedBy, "created_at": &r.CreatedAt, "expires_at": &r.ExpiresAt, "revoked_reason": &r.RevokedReason,
		"terms": &r.Terms, "reading_key": &r.ReadingKey, "items": &r.Items,
	} {
		if raw, ok := members[name]; ok {
			// What does not decode stays as far as it decoded: a list cut
			// short lists less, which only narrows.
			_ = json.Unmarshal(raw, into)
		}
	}
	if raw, ok := members["revoked_at"]; ok && string(bytes.TrimSpace(raw)) != "null" {
		var at Time
		if json.Unmarshal(raw, &at) != nil {
			at = Time{}
		}
		r.RevokedAt = &at
	}
	return r, invalid("token: the record does not decode")
}

// Validate checks a token feed answer itself: its generation, its head and
// cursor, and its records' order. It does not decode or validate the
// records: a bad record never stalls the feed. An app takes each record on
// its own (TokenFeedItem.Record) and decides, in this order:
//   - a record of another app is refused: the app logs it, applies nothing
//     of it and advances its cursor; one app's revocation (app_removed,
//     app_held) never reaches another;
//   - a record of another generation than the one the app holds is a reset
//     (SPEC section 11.18);
//   - a record that does not decode, that fails Validate, or whose reading
//     key's fingerprint is not its key's (ReadingKey.Check) is applied only
//     for what it narrows (a revocation, an earlier expires_at, an item or
//     permission it no longer lists): its grants are refused, as
//     invalid_record or reading_key_changed, and the app advances.
func (f TokenFeed) Validate() error {
	switch {
	case !ValidUUID(f.Generation):
		return invalid("generation")
	case f.Head < 0 || f.NextAfter < 0 || f.NextAfter > f.Head:
		return invalid("head")
	case f.PublishedThrough.IsZero():
		return invalid("published_through")
	case f.Items == nil || len(f.Items) > MaxTokenFeedItems:
		return invalid("items")
	}
	last := int64(-1)
	for _, it := range f.Items {
		if it.Seq <= last || it.Seq > f.Head {
			return invalid("items[].seq")
		}
		last = it.Seq
	}
	return nil
}

// The refusal codes of an acknowledgement (refused[].code): why an app
// would not apply a permission.
const (
	// RefusedGiverNotReader: the giver did not read the item at the app's
	// own check.
	RefusedGiverNotReader = "giver_not_reader"
	// RefusedLocalRole: before the app enforces memberships, its own roles
	// do not make the giver, or the creator, an owner or admin.
	RefusedLocalRole = "local_role"
	// RefusedNotOffered: the app does not offer this permission here.
	RefusedNotOffered = "not_offered"
	// RefusedItemUnknown: no such item in that workspace, or it is deleted.
	RefusedItemUnknown = "item_unknown"
	// RefusedTermsNotCurrent: the creator agreed to a key-terms revision
	// the app did not accept when it was added.
	RefusedTermsNotCurrent = "terms_not_current"
	// RefusedTeamWithheld: the app withholds this team.
	RefusedTeamWithheld = "team_withheld"
	// RefusedReadingKeyChanged: the record's reading key is not the one the
	// app pinned, or its fingerprint is not its key's.
	RefusedReadingKeyChanged = "reading_key_changed"
	// RefusedInvalidRecord: the record fails Validate; only what it narrows
	// was applied.
	RefusedInvalidRecord = "invalid_record"
)

var refusalCodes = []string{
	RefusedGiverNotReader, RefusedLocalRole, RefusedNotOffered, RefusedItemUnknown,
	RefusedTermsNotCurrent, RefusedTeamWithheld, RefusedReadingKeyChanged, RefusedInvalidRecord,
}

// RefusalCodes are the codes of an acknowledgement's refused entries. It
// returns a copy: the set Validate checks is closed.
func RefusalCodes() []string { return slices.Clone(refusalCodes) }

// The causes of an app's own stop of a token (suspended[].cause). An app
// never revokes for these: it reports them, and lifts the stop when its
// rule lifts.
const (
	// SuspendedOperator: the app's operator suspended the selector.
	SuspendedOperator = "operator"
	// SuspendedCreatorDisabledHere: the app's own operator disabled the
	// creator; lifted at the re-enable.
	SuspendedCreatorDisabledHere = "creator_disabled_here"
	// SuspendedLocalRule: before the app enforces memberships, its own
	// removal of the creator, or its own roles.
	SuspendedLocalRule = "local_rule"
)

var suspendCauses = []string{SuspendedOperator, SuspendedCreatorDisabledHere, SuspendedLocalRule}

// SuspendCauses are the causes of an app's own stop of a token. It returns
// a copy: the set Validate checks is closed.
func SuspendCauses() []string { return slices.Clone(suspendCauses) }

// MaxAppliedEntries is the most entries an acknowledgement's four lists
// (refused, waiting, suspended, held) hold together, and the most each of
// waiting and suspended holds alone; MaxHeldRemoved the most a held entry
// keeps off.
const (
	MaxAppliedEntries = 1000
	MaxHeldRemoved    = 1000
)

// TokenApplied is an app's acknowledgement of the token feed:
// POST /contract/v1/tokens/applied.
type TokenApplied struct {
	// Generation is the app's; another one is answered gone.
	Generation string `json:"generation"`
	// Through: the app applied every record of this generation's feed up
	// to this seq.
	Through   int64 `json:"through"`
	AppliedAt Time  `json:"applied_at"`
	// Refused are the permissions the app would not apply: always present,
	// [] when none.
	Refused []TokenRefusal `json:"refused"`
	// Waiting, when present, is the whole set of permissions the app holds
	// back unjudged; absent (nil) means unchanged, and an empty list none.
	Waiting WaitingPerms `json:"waiting,omitzero"`
	// WaitingMore: the app holds more than Waiting lists. Present only as
	// true, and only beside Waiting.
	WaitingMore TrueFlag `json:"waiting_more,omitzero"`
	// Suspended, when present, is the whole set of the app's own stops;
	// absent (nil) means unchanged, and an empty list none.
	Suspended Suspensions `json:"suspended,omitzero"`
	// SuspendedMore is WaitingMore's twin, for Suspended.
	SuspendedMore TrueFlag `json:"suspended_more,omitzero"`
	// Held are the tokens the app holds narrower than a reset's pass listed
	// them: entries only after a reset, and always present, [] when none.
	Held []TokenHeld `json:"held"`
}

// TokenRefusal is one permission an app would not apply, of the record's
// version that carried it.
type TokenRefusal struct {
	Token   string `json:"token"`
	Version int64  `json:"version"`
	Item    string `json:"item"`
	Perm    string `json:"perm"`
	Code    string `json:"code"`
}

// WaitingPerm is one permission an app holds back unjudged, until it
// applies the giver's account document.
type WaitingPerm struct {
	Token     string `json:"token"`
	Item      string `json:"item"`
	Perm      string `json:"perm"`
	GrantedBy string `json:"granted_by"`
	GrantedAt Time   `json:"granted_at"`
}

// Suspension is one of an app's own stops of a token.
type Suspension struct {
	Token string `json:"token"`
	Cause string `json:"cause"`
}

// TokenHeld is one token an app holds narrower than a reset's pass listed
// it.
type TokenHeld struct {
	Token   string `json:"token"`
	Revoked bool   `json:"revoked"`
	// ExpiresAt is the earlier expiry the app keeps, or null.
	ExpiresAt *Time `json:"expires_at"`
	// Removed are the permissions the app keeps off.
	Removed []HeldPerm `json:"removed"`
	// ReadingKey is the fingerprint of the app's pin when the record's key
	// is null, else null.
	ReadingKey *string `json:"reading_key"`
}

// HeldPerm is one permission an app keeps off a token.
type HeldPerm struct {
	Item string `json:"item"`
	Perm string `json:"perm"`
}

// TrueFlag is an optional member present only as true: false is its
// absence, written as nothing, and a receiver refuses false and null, which
// would read as absent.
type TrueFlag bool

// UnmarshalJSON reads a flag that is present: true, and nothing else.
func (f *TrueFlag) UnmarshalJSON(b []byte) error {
	if string(bytes.TrimSpace(b)) != "true" {
		return invalid("a flag is absent, or true")
	}
	*f = true
	return nil
}

// WaitingPerms is an acknowledgement's waiting set. Present, it is never
// null: absent (nil) is what says unchanged.
type WaitingPerms []WaitingPerm

// UnmarshalJSON reads the set, refusing null, and each entry strictly.
func (w *WaitingPerms) UnmarshalJSON(b []byte) error {
	v, err := decodePresent[WaitingPerm](b, "waiting")
	if err != nil {
		return err
	}
	*w = v
	return nil
}

// Suspensions is an acknowledgement's suspended set. Present, it is never
// null: absent (nil) is what says unchanged.
type Suspensions []Suspension

// UnmarshalJSON reads the set, refusing null, and each entry strictly.
func (s *Suspensions) UnmarshalJSON(b []byte) error {
	v, err := decodePresent[Suspension](b, "suspended")
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// allPerms is every permission any kind of item holds.
var allPerms = []string{CanRead, CanSend, CanAct, CanManage}

// Validate checks an acknowledgement: its members, every entry, and the
// sizes of its lists.
func (a TokenApplied) Validate() error {
	switch {
	case !ValidUUID(a.Generation):
		return invalid("generation")
	case a.Through < 0:
		return invalid("through")
	case a.AppliedAt.IsZero():
		return invalid("applied_at")
	case a.Refused == nil:
		return invalid("refused")
	case a.Held == nil:
		return invalid("held")
	case bool(a.WaitingMore) && a.Waiting == nil:
		return invalid("waiting_more without waiting")
	case bool(a.SuspendedMore) && a.Suspended == nil:
		return invalid("suspended_more without suspended")
	case len(a.Waiting) > MaxAppliedEntries:
		return invalid("waiting")
	case len(a.Suspended) > MaxAppliedEntries:
		return invalid("suspended")
	case len(a.Refused)+len(a.Waiting)+len(a.Suspended)+len(a.Held) > MaxAppliedEntries:
		return invalid("the four lists hold at most 1000 entries together")
	}
	for _, r := range a.Refused {
		switch {
		case !ValidUUID(r.Token):
			return invalid("refused[].token")
		case r.Version < 1:
			return invalid("refused[].version")
		case !ValidItemID(r.Item):
			return invalid("refused[].item")
		case !oneOf(r.Perm, allPerms):
			return invalid("refused[].perm")
		case !oneOf(r.Code, refusalCodes):
			return invalid("refused[].code")
		}
	}
	waiting := map[[3]string]bool{}
	for _, w := range a.Waiting {
		key := [3]string{w.Token, w.Item, w.Perm}
		switch {
		case waiting[key]:
			return invalid("a waiting permission appears twice")
		case !ValidUUID(w.Token):
			return invalid("waiting[].token")
		case !ValidItemID(w.Item):
			return invalid("waiting[].item")
		case !oneOf(w.Perm, allPerms):
			return invalid("waiting[].perm")
		case !ValidUUID(w.GrantedBy):
			return invalid("waiting[].granted_by")
		case w.GrantedAt.IsZero():
			return invalid("waiting[].granted_at")
		}
		waiting[key] = true
	}
	stops := map[Suspension]bool{}
	for _, s := range a.Suspended {
		switch {
		case !ValidUUID(s.Token):
			return invalid("suspended[].token")
		case !oneOf(s.Cause, suspendCauses):
			return invalid("suspended[].cause")
		case stops[s]:
			return invalid("a stop appears twice")
		}
		stops[s] = true
	}
	held := map[string]bool{}
	for _, h := range a.Held {
		switch {
		case !ValidUUID(h.Token):
			return invalid("held[].token")
		case held[h.Token]:
			return invalid("a held token appears twice")
		case h.ExpiresAt != nil && h.ExpiresAt.IsZero():
			return invalid("held[].expires_at")
		case h.Removed == nil || len(h.Removed) > MaxHeldRemoved:
			return invalid("held[].removed")
		case h.ReadingKey != nil && !validHex(*h.ReadingKey, FingerprintLen):
			return invalid("held[].reading_key")
		}
		held[h.Token] = true
		removed := map[HeldPerm]bool{}
		for _, p := range h.Removed {
			if !ValidItemID(p.Item) || !oneOf(p.Perm, allPerms) || removed[p] {
				return invalid("held[].removed[]")
			}
			removed[p] = true
		}
	}
	return nil
}

// The refusal codes of a token's use (usage's refusals[].code): why an app
// refused a request a token made, once the token's secret matched.
const (
	UseNoPermission    = "no_permission"
	UseNoGrant         = "no_grant"
	UseSwitchOff       = "switch_off"
	UseAPIPaused       = "api_paused"
	UseCreatorConsent  = "creator_consent"
	UseNotOffered      = "not_offered"
	UseStaleFeed       = "stale_feed"
	UseWorkspaceClosed = "workspace_closed"
	UseRevoked         = "revoked"
	UseExpired         = "expired"
	UseSuspendedHere   = "suspended_here"
)

var usageCodes = []string{
	UseNoPermission, UseNoGrant, UseSwitchOff, UseAPIPaused, UseCreatorConsent, UseNotOffered,
	UseStaleFeed, UseWorkspaceClosed, UseRevoked, UseExpired, UseSuspendedHere,
}

// tokenWide are the use refusals of the token itself, whose item and perm
// are null.
var tokenWide = []string{UseRevoked, UseExpired, UseSuspendedHere}

// UsageRefusalCodes are the codes of a token's refused uses. It returns a
// copy: the set Validate checks is closed. api_paused is reserved until an
// entitlements part of the contract reaches the app.
func UsageRefusalCodes() []string { return slices.Clone(usageCodes) }

// The bounds of a usage report: entries per list, and the call's body.
const (
	MaxUsageEntries = 1000
	UsageBodyLimit  = 256 << 10
)

// TokenUsage is an app's report of its tokens' use:
// POST /contract/v1/tokens/usage. Both lists are absolute, so the app sends
// it again freely and splits it as it likes.
type TokenUsage struct {
	// Used: one entry per token and UTC day on which it was accepted at
	// least once.
	Used []TokenUsed `json:"used"`
	// Refusals: absolute counts per (token, day, item, perm, code) so far
	// that day; the platform keeps the highest.
	Refusals []UsageRefusal `json:"refusals"`
}

// TokenUsed is one day on which a token was accepted.
type TokenUsed struct {
	Token string `json:"token"`
	Day   string `json:"day"`
}

// UsageRefusal is a count of one kind of refused use of a token on a day.
// Item and Perm are null for a refusal of the token itself (revoked,
// expired, suspended_here), and set for every other.
type UsageRefusal struct {
	Token string  `json:"token"`
	Day   string  `json:"day"`
	Item  *string `json:"item"`
	Perm  *string `json:"perm"`
	Code  string  `json:"code"`
	Count int64   `json:"count"`
}

// dayRE is a UTC day: YYYY-MM-DD.
var dayRE = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

// ValidDay reports whether s is a UTC day from 1970, as YYYY-MM-DD.
func ValidDay(s string) bool {
	if !dayRE.MatchString(s) {
		return false
	}
	d, err := time.Parse(time.DateOnly, s)
	return err == nil && d.Year() >= 1970
}

// Validate checks a usage report: each entry, each key once, and the sizes
// of its lists. The call's body limit (UsageBodyLimit) is the transport's.
func (u TokenUsage) Validate() error {
	switch {
	case u.Used == nil || len(u.Used) > MaxUsageEntries:
		return invalid("used")
	case u.Refusals == nil || len(u.Refusals) > MaxUsageEntries:
		return invalid("refusals")
	}
	used := map[TokenUsed]bool{}
	for _, e := range u.Used {
		switch {
		case !ValidUUID(e.Token):
			return invalid("used[].token")
		case !ValidDay(e.Day):
			return invalid("used[].day")
		case used[e]:
			return invalid("a day of a token appears twice")
		}
		used[e] = true
	}
	type key struct{ token, day, item, perm, code string }
	refused := map[key]bool{}
	for _, r := range u.Refusals {
		switch {
		case !ValidUUID(r.Token):
			return invalid("refusals[].token")
		case !ValidDay(r.Day):
			return invalid("refusals[].day")
		case !oneOf(r.Code, usageCodes):
			return invalid("refusals[].code")
		case r.Count < 1:
			return invalid("refusals[].count")
		}
		if oneOf(r.Code, tokenWide) {
			if r.Item != nil || r.Perm != nil {
				return invalid("refusals[]: a refusal of the token itself names no item or perm")
			}
		} else if r.Item == nil || r.Perm == nil || !ValidItemID(*r.Item) || !oneOf(*r.Perm, allPerms) {
			return invalid("refusals[].item, perm")
		}
		k := key{token: r.Token, day: r.Day, code: r.Code}
		if r.Item != nil {
			k.item, k.perm = *r.Item, *r.Perm
		}
		if refused[k] {
			return invalid("a refusal appears twice")
		}
		refused[k] = true
	}
	return nil
}

// decodePresent reads an optional list that is present: never null, each
// entry strictly, with no member the entry does not have, each member's
// name exactly as written and once (the platform decodes what apps send
// strictly, with encoding/json/v2's names compared exactly; an app ignores
// members it does not know only in what the platform sends it).
func decodePresent[T any](b []byte, what string) ([]T, error) {
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		return nil, invalid("%s is absent, never null", what)
	}
	if !exactMembers(b, memberNames[T]()) {
		return nil, invalid("%s: a member not named exactly, or named twice", what)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var v []T
	if err := dec.Decode(&v); err != nil {
		return nil, invalid("%s", what)
	}
	if dec.More() {
		return nil, invalid("%s", what)
	}
	if v == nil {
		v = []T{}
	}
	return v, nil
}

// memberNames are the JSON names of T's members, as their tags write them.
func memberNames[T any]() map[string]bool {
	t := reflect.TypeFor[T]()
	names := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			names[name] = true
		}
	}
	return names
}

// exactMembers reports whether b is an array of objects whose every member
// is one of names, exactly as written, and none twice. encoding/json
// matches a name in any case, Unicode-folded ones included, so ID, Token
// or a second id in other letters would otherwise pass for id.
func exactMembers(b []byte, names map[string]bool) bool {
	dec := json.NewDecoder(bytes.NewReader(b))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return false
	}
	for dec.More() {
		if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
			return false
		}
		seen := map[string]bool{}
		for dec.More() {
			tok, err := dec.Token()
			name, ok := tok.(string)
			if err != nil || !ok || !names[name] || seen[name] {
				return false
			}
			seen[name] = true
			var value json.RawMessage
			if dec.Decode(&value) != nil {
				return false
			}
		}
		if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
			return false
		}
	}
	tok, err := dec.Token()
	return err == nil && tok == json.Delim(']')
}
