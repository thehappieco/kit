package contract

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"time"
)

// The settings part's commands (SPEC section 11.19; the platform's
// decision 0054): one setting change per command, made by a person in the
// console and issued by the platform, which an app takes from its command
// feed, checks again under its own rules, runs or refuses, and answers
// with a result.

// The values of a command.
const (
	CommandV    = 1
	CommandType = "command"

	// CommandLifetime is how long a kind with an expiry lives: its
	// expires_at is its issued_at plus at most this. A tightening kind has
	// no expires_at.
	CommandLifetime = 5 * time.Minute
	// CommandRetention is how long the contract keeps a command and an app
	// its ledger row: a command whose own issued_at is more than this
	// before the app takes it is expired, whatever its kind, unless it is
	// delivered again.
	CommandRetention = 30 * 24 * time.Hour

	// MaxCommandFeedItems is the most commands one command feed answer
	// carries, MaxCommandResults the most results one call carries, and
	// ResultsBodyLimit that call's body limit.
	MaxCommandFeedItems = 100
	MaxCommandResults   = 100
	ResultsBodyLimit    = 256 << 10
	// MaxRetryAfter is a result's longest retry_after, in seconds.
	MaxRetryAfter = 3600
)

// When a kind carries an agreement (CommandKind.Agreement).
const (
	AgreementNever  = "never"
	AgreementAlways = "always"
	// AgreementInTeam: in a team workspace only, never in a personal one.
	AgreementInTeam = "team"
)

// The members of a command's target.
const (
	TargetItem   = "item"
	TargetPerson = "person"
	TargetRow    = "row"
	TargetSwitch = "switch"
)

// CommandKind describes one kind of command of an app.
type CommandKind struct {
	Kind    string
	Section string
	// Tightening: it only takes away (a consent withdrawn, access taken,
	// a revocation, a switch off, a narrowing). It has no expires_at; what
	// is gone counts as done.
	Tightening bool
	// Target are the members of its target, in this order.
	Target []string
	// Confirm is the member of target its confirm repeats, or "".
	Confirm string
	// Agreement is when it carries one: AgreementNever, AgreementAlways or
	// AgreementInTeam.
	Agreement string
	// InProgress: its first result may be in_progress, a final one
	// following.
	InProgress bool
	// Refusals are its own refusal codes, beside every kind's.
	Refusals []string
	// params checks its params (SPEC section 11.19).
	params func(c *Command, p params) error
}

// The command kinds.
const (
	OpItemRename              = "item.rename"
	OpItemSyncStop            = "item.sync_stop"
	OpItemSyncResume          = "item.sync_resume"
	OpItemSyncNow             = "item.sync_now"
	OpItemFlagsRaise          = "item.flags_raise"
	OpItemFlagsDrop           = "item.flags_drop"
	OpItemAccessRemove        = "item.access_remove"
	OpItemRegistrationDelete  = "item.registration_delete"
	OpItemMoveOut             = "item.move_out"
	OpAIProviderKeyDelete     = "ai.provider_key_delete"
	OpAIIntegrationNarrow     = "ai.integration_narrow"
	OpAIIntegrationRevoke     = "ai.integration_revoke"
	OpMCPConnectionRevoke     = "mcp.connection_revoke"
	OpMCPConnectionSeen       = "mcp.connection_seen"
	OpMCPSendPause            = "mcp.send_pause"
	OpMCPSendResume           = "mcp.send_resume"
	OpMCPSwitchOn             = "mcp.switch_on"
	OpMCPSwitchOff            = "mcp.switch_off"
	OpMCPLegacyTokenRevoke    = "mcp.legacy_token_revoke"
	OpInstallationAdd         = "installation.add"
	OpInstallationRename      = "installation.rename"
	OpLicenceRelease          = "licence.release"
	OpItemLiftHold            = "item.lift_hold"
	OpItemTeamSyncOn          = "item.team_sync_on"
	OpItemTeamSyncOff         = "item.team_sync_off"
	OpItemRemove              = "item.remove"
	OpItemRecover             = "item.recover"
	OpItemPurge               = "item.purge"
	OpItemRemovedIndexOff     = "item.removed_index_off"
	OpPersonSignOutEverywhere = "person.sign_out_everywhere"
	OpPersonNoticesDismiss    = "person.notices_dismiss"
	OpConsentAgree            = "consent.agree"
	OpConsentWithdraw         = "consent.withdraw"
)

// kind builds a CommandKind.
func kind(name, section string, tightening bool, target []string, check func(*Command, params) error, refusals ...string) CommandKind {
	return CommandKind{Kind: name, Section: section, Tightening: tightening, Target: target, Agreement: AgreementNever, Refusals: refusals, params: check}
}

func (k CommandKind) confirming(member string) CommandKind { k.Confirm = member; return k }
func (k CommandKind) agreeing(when string) CommandKind     { k.Agreement = when; return k }
func (k CommandKind) inProgress() CommandKind              { k.InProgress = true; return k }

var (
	onItem       = []string{TargetItem}
	onItemPerson = []string{TargetItem, TargetPerson}
	onRow        = []string{TargetRow}
	onSwitch     = []string{TargetSwitch}
	onNothing    = []string{}

	numberFlags  = []string{CanRead, CanSend, CanManage}
	mailboxFlags = []string{CanRead, CanAct, CanSend, CanManage}
)

var personKinds = []CommandKind{
	kind(OpPersonSignOutEverywhere, SectionPerson, true, onNothing, noChange),
	kind(OpPersonNoticesDismiss, SectionPerson, false, onNothing, dismissParams, CodeStateChanged),
}

var wappieKinds = append([]CommandKind{
	kind(OpItemRename, SectionNumbers, false, onItem, renameParams("label"), CodeLabelChanged, CodeStateChanged),
	kind(OpItemSyncStop, SectionNumbers, false, onItem, between("capture", `"on"`, `"paused"`)),
	kind(OpItemSyncResume, SectionNumbers, false, onItem, between("capture", `"paused"`, `"on"`), CodeCapacityReached, CodeStateChanged),
	kind(OpItemSyncNow, SectionNumbers, false, onItem, noChange,
		CodePaused, CodeStoragePaused, CodeCapacityReached, CodeReadOnly, CodeNotLinked, CodeConnectFailed, CodeItemBusy),
	kind(OpItemFlagsRaise, SectionNumbers, false, onItemPerson, flagsParams(numberFlags, raise), CodeGrantNeeded, CodeStateChanged),
	kind(OpItemFlagsDrop, SectionNumbers, true, onItemPerson, flagsParams(numberFlags, drop), CodeLastReader),
	kind(OpItemAccessRemove, SectionNumbers, true, onItemPerson, flagsParams(numberFlags, removeAll), CodeLastReader),
	kind(OpItemRegistrationDelete, SectionNumbers, false, onRow, noChange, CodeStateChanged).confirming(TargetRow),
	kind(OpItemMoveOut, SectionNumbers, false, onItem, moveOutParams,
		CodeNotSoleOwner, CodeOthersHaveAccess, CodeCapacityReached, CodePersonalInactive, CodeMissingOldKeys, CodeStateChanged).
		confirming(TargetItem).inProgress(),
	kind(OpAIProviderKeyDelete, SectionIntegrations, true, onRow, noChange),
	kind(OpAIIntegrationNarrow, SectionIntegrations, true, onRow, narrowParams, CodeInvalidValue),
	kind(OpAIIntegrationRevoke, SectionIntegrations, true, onRow, revokeParams),
	kind(OpMCPConnectionRevoke, SectionMCP, true, onRow, noChange),
	kind(OpMCPConnectionSeen, SectionMCP, false, onRow, noChange),
	kind(OpMCPSendPause, SectionMCP, true, onRow, between("send_paused", `false`, `true`)),
	kind(OpMCPSendResume, SectionMCP, false, onRow, between("send_paused", `true`, `false`), CodeStateChanged),
	kind(OpMCPSwitchOn, SectionMCP, false, onSwitch, between("set", `false|null`, `true`), CodeOperatorOff, CodeSwitchOff, CodeStateChanged),
	kind(OpMCPSwitchOff, SectionMCP, true, onSwitch, between("set", `true|null`, `false`)),
	kind(OpMCPLegacyTokenRevoke, SectionMCP, true, onRow, noChange),
	kind(OpInstallationAdd, SectionInstallations, false, onNothing, addInstallationParams, CodeInvalidValue, CodeAlreadyAdded, CodeLabelChanged),
	kind(OpInstallationRename, SectionInstallations, false, onRow, renameParams("name"), CodeLabelChanged, CodeStateChanged),
	kind(OpLicenceRelease, SectionInstallations, true, onRow, noChange),
}, personKinds...)

var mailieKinds = append([]CommandKind{
	kind(OpItemSyncNow, SectionEmailAccounts, false, onItem, noChange, CodePaused, CodeConsentNeeded, CodeNeedsReauth, CodeItemBusy),
	kind(OpItemSyncStop, SectionEmailAccounts, false, onItem, between("paused", `false`, `true`), CodeStateChanged),
	kind(OpItemSyncResume, SectionEmailAccounts, false, onItem, between("paused", `true`, `false`), CodeStateChanged, CodeNotCurrentText, CodeNoReader).
		agreeing(AgreementInTeam),
	kind(OpItemLiftHold, SectionEmailAccounts, false, onItem, between("held", `true`, `false`), CodeConsentNeeded),
	kind(OpItemTeamSyncOn, SectionEmailAccounts, false, onItem, between("sync", `"off"|"older_revision"|"bound"`, `"on"`), CodeNotCurrentText, CodeNoReader).
		agreeing(AgreementAlways),
	kind(OpItemTeamSyncOff, SectionEmailAccounts, true, onItem, between("sync", `"on"|"older_revision"|"bound"`, `"off"`)),
	kind(OpItemRemove, SectionEmailAccounts, false, onItem, noChange, CodeStateChanged).confirming(TargetItem),
	kind(OpItemRecover, SectionEmailAccounts, false, onItem, noChange, CodeRecoveryClosed, CodeNoReader),
	kind(OpItemPurge, SectionEmailAccounts, false, onItem, noChange, CodeStateChanged).confirming(TargetItem),
	kind(OpItemRemovedIndexOff, SectionEmailAccounts, true, onItem, between("index_kept", `true`, `false`)),
	kind(OpItemFlagsRaise, SectionPermissions, false, onItemPerson, flagsParams(mailboxFlags, raise), CodeGrantNeeded, CodeStateChanged),
	kind(OpItemFlagsDrop, SectionPermissions, true, onItemPerson, flagsParams(mailboxFlags, drop), CodeLastReader),
	kind(OpItemAccessRemove, SectionPermissions, true, onItemPerson, flagsParams(mailboxFlags, removeAll), CodeLastReader),
	kind(OpConsentAgree, SectionPerson, false, onNothing, consentParams(true), CodeNotCurrentText).agreeing(AgreementAlways),
	kind(OpConsentWithdraw, SectionPerson, true, onNothing, consentParams(false)),
}, personKinds...)

var (
	wappieKindsByName = byName(wappieKinds)
	mailieKindsByName = byName(mailieKinds)
)

func byName(kinds []CommandKind) map[string]CommandKind {
	m := map[string]CommandKind{}
	for _, k := range kinds {
		m[k.Kind] = k
	}
	return m
}

// commandKindsOf are app's kinds by name: Wappie's, Mailie's, or, for the
// platform's reference app, Wappie's; none for another app.
func commandKindsOf(app string) map[string]CommandKind {
	switch app {
	case "mailie":
		return mailieKindsByName
	case "wappie", ReferenceApp:
		return wappieKindsByName
	}
	return nil
}

// CommandKinds are app's command kinds, in the order of the SPEC's tables.
// It returns copies: the lists Validate checks are closed.
func CommandKinds(app string) []CommandKind {
	list := wappieKinds
	switch app {
	case "mailie":
		list = mailieKinds
	case "wappie", ReferenceApp:
	default:
		return nil
	}
	out := make([]CommandKind, len(list))
	for i, k := range list {
		k.Target = slices.Clone(k.Target)
		k.Refusals = slices.Clone(k.Refusals)
		out[i] = k
	}
	return out
}

// CommandKindOf is app's kind named kind, as CommandKinds lists it.
func CommandKindOf(app, kind string) (CommandKind, bool) {
	k, ok := commandKindsOf(app)[kind]
	k.Target = slices.Clone(k.Target)
	k.Refusals = slices.Clone(k.Refusals)
	return k, ok
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

// Command is one setting change a person made in the console, which the
// platform issues to an app. An app keeps it as it came (its feed item's
// Command), checks its mac with VerifyCommand, decodes it as VerifyCommand
// does, and checks it with ValidateIn once it knows the workspace's kind.
type Command struct {
	V          int    `json:"v"`
	Type       string `json:"type"`
	App        string `json:"app"`
	Generation string `json:"generation"`
	// ID is the command's UUIDv7, made by the platform: the idempotency
	// key.
	ID string `json:"id"`
	// RetryOf is the first command's id, for a command issued again after
	// a retry code; else null.
	RetryOf *string `json:"retry_of"`
	// CSeq is its place in the app's command feed.
	CSeq int64 `json:"cseq"`
	// WorkspaceID and WSeq, the workspace's command sequence for this app,
	// are null exactly for a person's kind.
	WorkspaceID *string `json:"workspace_id"`
	WSeq        *int64  `json:"wseq"`
	Kind        string  `json:"kind"`
	Section     string  `json:"section"`
	Actor       string  `json:"actor"`
	// ActorRole is the actor's role at issue, for the app's log, which
	// reads the role again itself; null for a person's kind.
	ActorRole *string       `json:"actor_role"`
	Target    CommandTarget `json:"target"`
	// Params are the kind's: one setting, its value before and after as
	// one-member objects named by the setting, and the kind's own members.
	Params  json.RawMessage `json:"params"`
	BasedOn BasedOn         `json:"based_on"`
	// IssuedAt, FirstIssuedAt (the intent's first issued_at, carried by
	// every command issued again) and ExpiresAt (issued_at plus at most
	// CommandLifetime, null exactly for a tightening kind).
	IssuedAt      Time  `json:"issued_at"`
	FirstIssuedAt Time  `json:"first_issued_at"`
	ExpiresAt     *Time `json:"expires_at"`
	// Confirm repeats the target's item or row where the kind asks; else
	// null.
	Confirm   *string    `json:"confirm"`
	Agreement *Agreement `json:"agreement"`
	// Secret is the generation number of the contract secret that made
	// MAC, for the platform's log; an app checks MAC with each secret it
	// holds and never needs it.
	Secret int64  `json:"secret"`
	MAC    string `json:"mac"`
}

// CommandTarget names what a command acts on, by ids only: the members its
// kind names (CommandKind.Target), and no other.
type CommandTarget struct {
	Item   string `json:"item,omitempty"`
	Person string `json:"person,omitempty"`
	Row    string `json:"row,omitempty"`
	Switch string `json:"switch,omitempty"`
}

// BasedOn is what the console drew a command from: the section's (or the
// person's) state_seq, and the account-document versions, for this app,
// of the actor and of every target sub, by sub.
type BasedOn struct {
	StateSeq int64            `json:"state_seq"`
	Docs     map[string]int64 `json:"docs"`
}

// Agreement is the text a person agreed to with a command: the site's
// revision, and the language shown (pt-BR, en or es).
type Agreement struct {
	Revision string `json:"revision"`
	Language string `json:"language"`
}

var languages = []string{"pt-BR", "en", "es"}

// validMAC reports whether s is a command's mac in shape: v1= and 64
// lowercase hex.
func validMAC(s string) bool {
	rest, ok := strings.CutPrefix(s, "v1=")
	return ok && validHex(rest, 64)
}

// Validate checks every member of a command and its kind's rules, but those
// that depend on the workspace's kind (ValidateIn). It does not check the
// mac: VerifyCommand does, over the command as received.
func (c Command) Validate() error {
	kinds := commandKindsOf(c.App)
	k, ok := kinds[c.Kind]
	person := k.Section == SectionPerson
	switch {
	case c.V != CommandV:
		return invalid("v")
	case c.Type != CommandType:
		return invalid("type")
	case kinds == nil:
		return invalid("app")
	case !ValidUUID(c.Generation):
		return invalid("generation")
	case !ValidUUID(c.ID):
		return invalid("id")
	case c.RetryOf != nil && (!ValidUUID(*c.RetryOf) || *c.RetryOf == c.ID):
		return invalid("retry_of")
	case c.CSeq < 1:
		return invalid("cseq")
	case !ok:
		return invalid("kind is not one of the app's")
	case c.Section != k.Section:
		return invalid("section is not the kind's")
	case person && (c.WorkspaceID != nil || c.WSeq != nil):
		return invalid("workspace_id and wseq are null for a person's kind")
	case !person && (c.WorkspaceID == nil || !ValidUUID(*c.WorkspaceID) || c.WSeq == nil || *c.WSeq < 1):
		return invalid("workspace_id, wseq")
	case !ValidUUID(c.Actor):
		return invalid("actor")
	case person && c.ActorRole != nil, !person && (c.ActorRole == nil || !oneOf(*c.ActorRole, roles)):
		return invalid("actor_role is a workspace kind's, null for a person's")
	case c.IssuedAt.IsZero() || c.FirstIssuedAt.IsZero():
		return invalid("issued_at, first_issued_at")
	case c.FirstIssuedAt.After(c.IssuedAt.Time):
		return invalid("first_issued_at is at or before issued_at")
	case c.RetryOf == nil && !c.FirstIssuedAt.Equal(c.IssuedAt.Time):
		return invalid("first_issued_at is issued_at for a first issue")
	case k.Tightening && c.ExpiresAt != nil:
		return invalid("a tightening kind has no expires_at")
	case !k.Tightening && (c.ExpiresAt == nil || !c.ExpiresAt.After(c.IssuedAt.Time) || c.ExpiresAt.Sub(c.IssuedAt.Time) > CommandLifetime):
		return invalid("expires_at is after issued_at, and at most five minutes after it")
	case c.Secret < 1:
		return invalid("secret")
	case !validMAC(c.MAC):
		return invalid("mac")
	}
	if err := c.checkTarget(k); err != nil {
		return err
	}
	if err := c.checkBasedOn(); err != nil {
		return err
	}
	switch {
	case k.Confirm == "" && c.Confirm != nil:
		return invalid("confirm is null for this kind")
	case k.Confirm == TargetItem && (c.Confirm == nil || *c.Confirm != c.Target.Item):
		return invalid("confirm repeats the target's item")
	case k.Confirm == TargetRow && (c.Confirm == nil || *c.Confirm != c.Target.Row):
		return invalid("confirm repeats the target's row")
	case k.Agreement == AgreementNever && c.Agreement != nil:
		return invalid("agreement is null for this kind")
	case k.Agreement == AgreementAlways && c.Agreement == nil:
		return invalid("agreement is required for this kind")
	case c.Agreement != nil && (!ValidRevision(c.Agreement.Revision) || !oneOf(c.Agreement.Language, languages)):
		return invalid("agreement")
	}
	if len(bytes.TrimSpace(c.Params)) == 0 || !wellFormed(c.Params) {
		return invalid("params")
	}
	var p params
	if json.Unmarshal(c.Params, &p) != nil || p == nil {
		return invalid("params is an object")
	}
	return k.params(&c, p)
}

// ValidateIn is Validate, and the rules that depend on the workspace's
// kind: KindPersonal or KindTeam for a workspace's command, "" for a
// person's. A kind that carries an agreement in a team only
// (AgreementInTeam: Mailie's item.sync_resume) carries one exactly there.
func (c Command) ValidateIn(workspaceKind string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	k := commandKindsOf(c.App)[c.Kind]
	switch {
	case k.Section == SectionPerson && workspaceKind != "":
		return invalid("a person's command names no workspace")
	case k.Section != SectionPerson && workspaceKind != KindPersonal && workspaceKind != KindTeam:
		return invalid("the workspace's kind")
	case k.Agreement == AgreementInTeam && (c.Agreement != nil) != (workspaceKind == KindTeam):
		return invalid("agreement is required in a team, and null in a personal workspace")
	}
	return nil
}

func (c Command) checkTarget(k CommandKind) error {
	members := map[string]string{TargetItem: c.Target.Item, TargetPerson: c.Target.Person, TargetRow: c.Target.Row, TargetSwitch: c.Target.Switch}
	for name, v := range members {
		wanted := slices.Contains(k.Target, name)
		switch {
		case !wanted && v != "":
			return invalid("target names a member its kind does not")
		case !wanted:
		case name == TargetItem && !ValidItemID(v), name == TargetRow && !ValidItemID(v):
			return invalid("target.%s", name)
		case name == TargetPerson && !ValidUUID(v):
			return invalid("target.person")
		case name == TargetSwitch && !oneOf(v, mcpSwitches):
			return invalid("target.switch")
		}
	}
	return nil
}

// checkBasedOn wants the state_seq the console drew, and the document
// versions of exactly the actor and the target's person.
func (c Command) checkBasedOn() error {
	if c.BasedOn.StateSeq < 1 {
		return invalid("based_on.state_seq")
	}
	want := map[string]bool{c.Actor: true}
	if c.Target.Person != "" {
		want[c.Target.Person] = true
	}
	if len(c.BasedOn.Docs) != len(want) {
		return invalid("based_on.docs names the actor and the target's person")
	}
	for sub, v := range c.BasedOn.Docs {
		if !want[sub] || v < 1 {
			return invalid("based_on.docs names the actor and the target's person")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Params
// ---------------------------------------------------------------------------

// params are a command's params, member by member: a member the kit does
// not know is ignored, as an app ignores one in what the platform sends.
type params map[string]json.RawMessage

// change reads a kind's one setting: before and after, each an object of
// one member, named alike, by one of the names allowed. Two members in
// either is two settings in one command.
func (p params) change(allowed func(string) bool) (name string, before, after json.RawMessage, err error) {
	var b, a map[string]json.RawMessage
	if json.Unmarshal(p["before"], &b) != nil || json.Unmarshal(p["after"], &a) != nil || len(b) != 1 || len(a) != 1 {
		return "", nil, nil, invalid("params: before and after each name one setting")
	}
	for name = range b {
	}
	if _, ok := a[name]; !ok || !allowed(name) {
		return "", nil, nil, invalid("params: before and after name the kind's setting")
	}
	return name, b[name], a[name], nil
}

// noChange is a kind with no setting: params names no before or after.
func noChange(_ *Command, p params) error {
	if _, ok := p["before"]; ok {
		return invalid("params: this kind changes no setting")
	}
	if _, ok := p["after"]; ok {
		return invalid("params: this kind changes no setting")
	}
	return nil
}

// is reports whether raw is one of the JSON values in alternatives, written
// as `"on"|"paused"`.
func is(raw json.RawMessage, alternatives string) bool {
	return slices.Contains(strings.Split(alternatives, "|"), string(bytes.TrimSpace(raw)))
}

// between is a setting that goes from one of before's values to after's.
func between(setting, before, after string) func(*Command, params) error {
	return func(_ *Command, p params) error {
		_, b, a, err := p.change(func(n string) bool { return n == setting })
		if err != nil {
			return err
		}
		if !is(b, before) || !is(a, after) {
			return invalid("params: %s goes from %s to %s", setting, before, after)
		}
		return nil
	}
}

// renameParams: a label, or null, to a label.
func renameParams(setting string) func(*Command, params) error {
	return func(_ *Command, p params) error {
		_, b, a, err := p.change(func(n string) bool { return n == setting })
		if err != nil {
			return err
		}
		var before *string
		var after string
		if json.Unmarshal(b, &before) != nil || !labelOrNull(before) || json.Unmarshal(a, &after) != nil || !ValidLabel(after) {
			return invalid("params: %s goes from a label or null to a label", setting)
		}
		return nil
	}
}

// The ways flags change.
const (
	raise     = iota // a superset that never adds read
	drop             // a subset
	removeAll        // none
)

// flagsParams: the person's flags on the item (the snapshot's can), each
// once, before and after.
func flagsParams(flags []string, how int) func(*Command, params) error {
	return func(c *Command, p params) error {
		_, b, a, err := p.change(func(n string) bool { return n == "can" })
		if err != nil {
			return err
		}
		var before, after []string
		if json.Unmarshal(b, &before) != nil || json.Unmarshal(a, &after) != nil || !codesOnce(before, flags) || !codesOnce(after, flags) {
			return invalid("params: can lists the item's flags, each once")
		}
		mailbox := slices.Contains(flags, CanAct)
		switch how {
		case raise:
			if len(after) <= len(before) || !subset(before, after) || slices.Contains(after, CanRead) && !slices.Contains(before, CanRead) {
				return invalid("params: a raise adds flags, never read")
			}
		case drop:
			if len(after) >= len(before) || !subset(after, before) {
				return invalid("params: a drop takes flags away, and adds none")
			}
		case removeAll:
			if len(after) != 0 {
				return invalid("params: access removed leaves no flag")
			}
		}
		if mailbox && slices.Contains(after, CanAct) && !slices.Contains(after, CanRead) {
			return invalid("params: a mailbox's act only beside read")
		}
		return nil
	}
}

// subset reports whether every one of a is in b.
func subset(a, b []string) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// moveOutParams: the workspace, from the command's team to the actor's
// personal workspace.
func moveOutParams(c *Command, p params) error {
	_, b, a, err := p.change(func(n string) bool { return n == "workspace" })
	if err != nil {
		return err
	}
	var before, after string
	if json.Unmarshal(b, &before) != nil || json.Unmarshal(a, &after) != nil || c.WorkspaceID == nil ||
		before != *c.WorkspaceID || !ValidUUID(after) || after == before {
		return invalid("params: workspace goes from the command's team to another workspace")
	}
	return nil
}

// narrowParams: an AI integration's one narrowing: paused false to true, a
// function true to false, or its cap to a lower one.
func narrowParams(_ *Command, p params) error {
	setting, b, a, err := p.change(func(n string) bool {
		fn, isFn := strings.CutPrefix(n, "function:")
		return n == "paused" || n == "cap" || isFn && oneOf(fn, aiFunctions)
	})
	if err != nil {
		return err
	}
	switch setting {
	case "paused":
		if !is(b, "false") || !is(a, "true") {
			return invalid("params: paused goes from false to true")
		}
	case "cap":
		var before *int64
		var after int64
		if json.Unmarshal(b, &before) != nil || json.Unmarshal(a, &after) != nil || after < 0 || before != nil && (*before < 0 || after >= *before) {
			return invalid("params: cap goes from null or n to a lower m of at least 0")
		}
	default:
		if !is(b, "true") || !is(a, "false") {
			return invalid("params: a function goes from true to false")
		}
	}
	return nil
}

// revokeParams: whether the integration's results go too.
func revokeParams(c *Command, p params) error {
	if err := noChange(c, p); err != nil {
		return err
	}
	if !is(p["delete_results"], "true|false") {
		return invalid("params.delete_results")
	}
	return nil
}

// addInstallationParams: the origin and the name, a label or null.
func addInstallationParams(c *Command, p params) error {
	if err := noChange(c, p); err != nil {
		return err
	}
	var origin string
	var name *string
	if json.Unmarshal(p["origin"], &origin) != nil || !ValidOrigin(origin) {
		return invalid("params.origin")
	}
	if _, ok := p["name"]; !ok || json.Unmarshal(p["name"], &name) != nil || !labelOrNull(name) {
		return invalid("params.name")
	}
	return nil
}

// NoticeRef names one notice to dismiss, at the version the person saw.
type NoticeRef struct {
	ID      string `json:"id"`
	Version int64  `json:"version"`
}

// dismissParams: 1 to MaxNotices notices, each once.
func dismissParams(c *Command, p params) error {
	if err := noChange(c, p); err != nil {
		return err
	}
	// Each entry's members count only named exactly as written, as an app
	// reads what the platform sends: ID or VERSION is a member it does not
	// know.
	var notices []NoticeRef
	if json.Unmarshal(exactOnly(p["notices"], reflect.TypeFor[[]NoticeRef]()), &notices) != nil || len(notices) == 0 || len(notices) > MaxNotices {
		return invalid("params.notices")
	}
	seen := map[string]bool{}
	for _, n := range notices {
		if !ValidItemID(n.ID) || n.Version < 1 || seen[n.ID] {
			return invalid("params.notices[]")
		}
		seen[n.ID] = true
	}
	return nil
}

// consentParams: one of Mailie's consents, to on (agree) or off
// (withdraw). sync's other state is an older revision, still on; actions'
// and send's is old_text.
func consentParams(agree bool) func(*Command, params) error {
	return func(_ *Command, p params) error {
		setting, b, a, err := p.change(func(n string) bool { return oneOf(n, consents) })
		if err != nil {
			return err
		}
		other := `"old_text"`
		if setting == ConsentSync {
			other = `"older_revision"`
		}
		before, after := `"off"|`+other, `"on"`
		if !agree {
			before, after = `"on"|`+other, `"off"`
		}
		if !is(b, before) || !is(a, after) {
			return invalid("params: %s goes from %s to %s", setting, before, after)
		}
		return nil
	}
}

// ---------------------------------------------------------------------------
// The command feed
// ---------------------------------------------------------------------------

// CommandFeed is one answer of the command feed:
// GET /contract/v1/commands?after=&wait=. It holds every command after the
// cursor with no final result yet, and the commands delivered again after
// an app's restore, oldest first.
type CommandFeed struct {
	Generation string            `json:"generation"`
	Head       int64             `json:"head"`
	Items      []CommandFeedItem `json:"items"`
	NextAfter  int64             `json:"next_after"`
	More       bool              `json:"more"`
}

// CommandFeedItem is one command and its place in the feed. The command is
// kept as it came: its mac covers it as received (VerifyCommand).
type CommandFeedItem struct {
	CSeq    int64           `json:"cseq"`
	Command json.RawMessage `json:"command"`
	// Again: delivered again after the app asked from below the highest
	// cursor it acknowledged; a tightening command that ran in the last 90
	// days, which runs whatever its age.
	Again bool `json:"again"`
}

// Validate checks a command feed answer itself: its generation, its head
// and cursor, and its commands' order. It does not verify or decode the
// commands: an app verifies each one on its own (VerifyCommand), refuses
// one that fails as invalid_command, and refuses a command whose cseq is
// not its item's.
func (f CommandFeed) Validate() error {
	switch {
	case !ValidUUID(f.Generation):
		return invalid("generation")
	case f.Head < 0 || f.NextAfter < 0 || f.NextAfter > f.Head:
		return invalid("head")
	case f.Items == nil || len(f.Items) > MaxCommandFeedItems:
		return invalid("items")
	}
	last := int64(0)
	for _, it := range f.Items {
		if it.CSeq <= last || it.CSeq > f.Head {
			return invalid("items[].cseq")
		}
		if trimmed := bytes.TrimSpace(it.Command); len(trimmed) == 0 || trimmed[0] != '{' {
			return invalid("items[].command")
		}
		last = it.CSeq
	}
	return nil
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

// The outcomes of a result.
const (
	OutcomeRan        = "ran"
	OutcomeRefused    = "refused"
	OutcomeInProgress = "in_progress"
)

// The refusal codes of a result (code). Each is a retry, which the platform
// issues again by itself, or final, which the console shows with its way
// out (CommandRefusalClass). CodeNotFound and CodeRateLimited, the
// transport's, serve here too.
const (
	CodeNotAuthorized          = "not_authorized"
	CodeOwnerOnly              = "owner_only"
	CodeNotHeld                = "not_held"
	CodeStateChanged           = "state_changed"
	CodeMembershipsBehind      = "memberships_behind"
	CodeMembershipsUnconfirmed = "memberships_unconfirmed"
	CodeWorkspaceBusy          = "workspace_busy"
	CodeItemBusy               = "item_busy"
	CodeKindNotAccepted        = "kind_not_accepted"
	CodeConnectFailed          = "connect_failed"
	CodePaused                 = "paused"
	CodeStoragePaused          = "storage_paused"
	CodeCapacityReached        = "capacity_reached"
	CodePersonalInactive       = "personal_inactive"
	CodeNotLinked              = "not_linked"
	CodeReadOnly               = "read_only"
	CodeNeedsReauth            = "needs_reauth"
	CodeConsentNeeded          = "consent_needed"
	CodeNoReader               = "no_reader"
	CodeLastReader             = "last_reader"
	CodeOthersHaveAccess       = "others_have_access"
	CodeNotSoleOwner           = "not_sole_owner"
	CodeMissingOldKeys         = "missing_old_keys"
	CodeAlreadyAdded           = "already_added"
	CodeRecoveryClosed         = "recovery_closed"
	CodeLabelChanged           = "label_changed"
	CodeInvalidValue           = "invalid_value"
	CodeNotCurrentText         = "not_current_text"
	CodeGrantNeeded            = "grant_needed"
	CodeAppOnly                = "app_only"
	CodeTeamWithheld           = "team_withheld"
	CodeTeamClosed             = "team_closed"
	CodeOperatorOff            = "operator_off"
	CodeSwitchOff              = "switch_off"
	CodeExpired                = "expired"
	CodeInvalidCommand         = "invalid_command"
)

// The classes of a refusal code.
const (
	ClassRetry = "retry"
	ClassFinal = "final"
)

// commandCodes are the refusal codes in the SPEC's table's order.
var commandCodes = []string{
	CodeNotAuthorized, CodeOwnerOnly, CodeNotHeld, CodeNotFound, CodeStateChanged, CodeMembershipsBehind,
	CodeMembershipsUnconfirmed, CodeWorkspaceBusy, CodeItemBusy, CodeRateLimited, CodeKindNotAccepted,
	CodeConnectFailed, CodePaused, CodeStoragePaused, CodeCapacityReached, CodePersonalInactive, CodeNotLinked,
	CodeReadOnly, CodeNeedsReauth, CodeConsentNeeded, CodeNoReader, CodeLastReader, CodeOthersHaveAccess,
	CodeNotSoleOwner, CodeMissingOldKeys, CodeAlreadyAdded, CodeRecoveryClosed, CodeLabelChanged, CodeInvalidValue,
	CodeNotCurrentText, CodeGrantNeeded, CodeAppOnly, CodeTeamWithheld, CodeTeamClosed, CodeOperatorOff,
	CodeSwitchOff, CodeExpired, CodeInvalidCommand,
}

// retryOnTime are the retry codes that wait on time, after retry_after or
// a backoff; team_closed waits for the workspace's reopening, and
// kind_not_accepted for the section's accepts to list the kind again.
var retryOnTime = []string{CodeMembershipsBehind, CodeMembershipsUnconfirmed, CodeWorkspaceBusy, CodeItemBusy, CodeRateLimited}

// everyKind are the codes any kind may answer: and state_changed for a
// tightening kind. A person's kind has no workspace, so never team_closed
// or team_withheld.
var everyKind = []string{
	CodeNotHeld, CodeNotFound, CodeNotAuthorized, CodeOwnerOnly, CodeMembershipsBehind, CodeMembershipsUnconfirmed,
	CodeWorkspaceBusy, CodeRateLimited, CodeTeamClosed, CodeTeamWithheld, CodeAppOnly, CodeKindNotAccepted,
	CodeInvalidCommand, CodeExpired,
}

// CommandRefusalCodes are the refusal codes of a result. It returns a copy:
// the set Validate checks is closed.
func CommandRefusalCodes() []string { return slices.Clone(commandCodes) }

// CommandRefusalClass is ClassRetry or ClassFinal for code, answered for a
// kind that tightens or not: kind_not_accepted is a retry for a tightening
// kind and final for any other. It is "" for a code that is none.
func CommandRefusalClass(code string, tightening bool) string {
	switch {
	case !oneOf(code, commandCodes):
		return ""
	case oneOf(code, retryOnTime), code == CodeTeamClosed, code == CodeKindNotAccepted && tightening:
		return ClassRetry
	}
	return ClassFinal
}

// CommandResults is an app's batch of results:
// POST /contract/v1/commands/results. It names no generation: a result is
// matched by its command's id alone.
type CommandResults struct {
	Results []CommandResult `json:"results"`
}

// CommandResult is what became of one command.
type CommandResult struct {
	ID      string  `json:"id"`
	Outcome string  `json:"outcome"`
	Code    *string `json:"code"`
	// RetryAfter is 1 to MaxRetryAfter seconds, only beside a retry code
	// that waits on time; else null.
	RetryAfter *int64 `json:"retry_after"`
	// StateSeq: with ran, the seq at which every document the kind shows in
	// shows its effect; with refused, the seq the app judged on, or null
	// for expired, invalid_command and a person's not_held.
	StateSeq *int64        `json:"state_seq"`
	Detail   *ResultDetail `json:"detail"`
	// At is the app's clock.
	At Time `json:"at"`
}

// ResultDetail is a result's closed detail, one shape per code or kind:
// Cleaned with label_changed; Holders, HoldersMore and Ends with
// others_have_access; SessionsEnded for a person.sign_out_everywhere that
// ran; AlsoOff for an mcp.switch_off that ran; Purged for a Mailie
// item.remove that ran and purged the link at once.
type ResultDetail struct {
	Cleaned       *string   `json:"cleaned,omitempty"`
	Holders       *[]Holder `json:"holders,omitempty"`
	HoldersMore   *int64    `json:"holders_more,omitempty"`
	Ends          *[]string `json:"ends,omitempty"`
	SessionsEnded *int64    `json:"sessions_ended,omitempty"`
	AlsoOff       *[]string `json:"also_off,omitempty"`
	Purged        *bool     `json:"purged,omitempty"`
}

// The shapes of a detail.
const (
	detailNone = iota
	detailCleaned
	detailHolders
	detailSessions
	detailAlsoOff
	detailPurged
	detailMixed
)

func (d *ResultDetail) shape() int {
	if d == nil {
		return detailNone
	}
	set := 0
	shape := detailMixed
	if d.Cleaned != nil {
		set, shape = set+1, detailCleaned
	}
	if d.Holders != nil || d.HoldersMore != nil || d.Ends != nil {
		set++
		shape = detailHolders
		if d.Holders == nil || d.HoldersMore == nil || d.Ends == nil {
			return detailMixed
		}
	}
	if d.SessionsEnded != nil {
		set, shape = set+1, detailSessions
	}
	if d.AlsoOff != nil {
		set, shape = set+1, detailAlsoOff
	}
	if d.Purged != nil {
		set, shape = set+1, detailPurged
	}
	if set != 1 {
		return detailMixed
	}
	return shape
}

// Validate checks a batch: 1 to MaxCommandResults results, each id once,
// each valid whatever its command's kind; ValidateFor checks one result
// against its kind.
func (r CommandResults) Validate() error {
	if len(r.Results) == 0 || len(r.Results) > MaxCommandResults {
		return invalid("results")
	}
	seen := map[string]bool{}
	for _, res := range r.Results {
		if err := res.Validate(); err != nil {
			return err
		}
		if seen[res.ID] {
			return invalid("a result appears twice")
		}
		seen[res.ID] = true
	}
	return nil
}

// Validate checks one result whatever its command's kind: its outcome and
// code, retry_after beside a retry code that waits on time only, state_seq,
// and a detail of the shape its code or outcome allows.
func (r CommandResult) Validate() error {
	shape := r.Detail.shape()
	switch {
	case !ValidUUID(r.ID):
		return invalid("id")
	case r.At.IsZero():
		return invalid("at")
	case r.StateSeq != nil && *r.StateSeq < 1:
		return invalid("state_seq")
	case r.RetryAfter != nil && (*r.RetryAfter < 1 || *r.RetryAfter > MaxRetryAfter):
		return invalid("retry_after")
	case shape == detailMixed:
		return invalid("detail")
	}
	switch r.Outcome {
	case OutcomeRan:
		switch {
		case r.Code != nil:
			return invalid("a result that ran has no code")
		case r.RetryAfter != nil:
			return invalid("retry_after")
		case r.StateSeq == nil:
			return invalid("a result that ran names its state_seq")
		case shape == detailCleaned || shape == detailHolders:
			return invalid("detail belongs to a refusal")
		}
	case OutcomeInProgress:
		if r.Code != nil || r.RetryAfter != nil || shape != detailNone {
			return invalid("a result in progress has no code, retry_after or detail")
		}
	case OutcomeRefused:
		if r.Code == nil || !oneOf(*r.Code, commandCodes) {
			return invalid("code")
		}
		code := *r.Code
		switch {
		case r.RetryAfter != nil && !oneOf(code, retryOnTime):
			return invalid("retry_after only beside a retry code that waits on time")
		case (code == CodeExpired || code == CodeInvalidCommand) && r.StateSeq != nil:
			return invalid("state_seq is null for expired and invalid_command")
		case r.StateSeq == nil && code != CodeExpired && code != CodeInvalidCommand && code != CodeNotHeld:
			return invalid("a refusal names the state_seq it judged on")
		case (shape == detailCleaned) != (code == CodeLabelChanged), (shape == detailHolders) != (code == CodeOthersHaveAccess),
			shape == detailSessions, shape == detailAlsoOff, shape == detailPurged:
			return invalid("detail belongs to another code")
		}
	default:
		return invalid("outcome")
	}
	d := r.Detail
	switch shape {
	case detailCleaned:
		if !ValidLabel(*d.Cleaned) {
			return invalid("detail.cleaned")
		}
	case detailHolders:
		if err := (MoveOut{Holders: *d.Holders, HoldersMore: *d.HoldersMore, Ends: *d.Ends}).validate("detail"); err != nil {
			return err
		}
	case detailSessions:
		if *d.SessionsEnded < 0 {
			return invalid("detail.sessions_ended")
		}
	case detailAlsoOff:
		if !codesOnce(*d.AlsoOff, mcpSwitches) {
			return invalid("detail.also_off")
		}
	case detailPurged:
		if !*d.Purged {
			return invalid("detail.purged is true, or the detail is null")
		}
	}
	return nil
}

// ValidateFor is Validate, and the rules of app's kind: a code its kind may
// answer (every kind's, state_changed for a tightening kind, and its own);
// in_progress only for a kind whose first result may be; a person's
// not_held with no state_seq, and a workspace kind's with one; and a
// detail its kind's: sessions_ended for a person.sign_out_everywhere that
// ran, also_off for an mcp.switch_off that ran, purged or none for a
// Mailie item.remove that ran, none for any other.
func (r CommandResult) ValidateFor(app, kind string) error {
	if err := r.Validate(); err != nil {
		return err
	}
	k, ok := commandKindsOf(app)[kind]
	if !ok {
		return invalid("kind is not one of the app's")
	}
	person := k.Section == SectionPerson
	shape := r.Detail.shape()
	switch r.Outcome {
	case OutcomeInProgress:
		if !k.InProgress {
			return invalid("this kind's results are final")
		}
	case OutcomeRefused:
		code := *r.Code
		allowed := oneOf(code, everyKind) || oneOf(code, k.Refusals) || k.Tightening && code == CodeStateChanged
		switch {
		case !allowed, person && (code == CodeTeamClosed || code == CodeTeamWithheld):
			return invalid("code is not one this kind answers")
		case code == CodeNotHeld && person != (r.StateSeq == nil):
			return invalid("state_seq is null for a person's not_held only")
		}
	case OutcomeRan:
		want := detailNone
		switch {
		case kind == OpPersonSignOutEverywhere:
			want = detailSessions
		case kind == OpMCPSwitchOff && app != "mailie":
			want = detailAlsoOff
		case kind == OpItemRemove && app == "mailie" && shape == detailPurged:
			want = detailPurged
		}
		if shape != want {
			return invalid("detail is not this kind's")
		}
	}
	return nil
}

// CommandResultsAnswer is the platform's answer to a batch of results: one
// per result, in order.
type CommandResultsAnswer struct {
	Results []CommandResultAnswer `json:"results"`
}

// CommandResultAnswer is what became of one result: accepted (kept),
// duplicate (this final result is kept already, or an in_progress came
// after the final one), or rejected with invalid_request, not_found (no
// such command for this app) or conflict (another final result is kept).
// An app marks a result delivered on accepted and duplicate; a rejected
// one ends its delivery too.
type CommandResultAnswer struct {
	ID      string  `json:"id"`
	Outcome string  `json:"outcome"`
	Code    *string `json:"code"`
}
