package contract

import (
	"encoding/json"
	"slices"
)

// The settings part's sections (SPEC section 11.19), one data type per
// section and per app's person, and the closed lists their codes come from.
// A new code ships in the kit first, then in a platform release, then in
// the app that sends it: an unknown code refuses the whole document.

// ---------------------------------------------------------------------------
// The closed lists
// ---------------------------------------------------------------------------

// Wappie's notice codes (notices[].code).
const (
	NoticeSyncPaused     = "sync_paused"
	NoticeNumberDeleted  = "number_deleted"
	NoticeNumberStranded = "number_stranded"
	NoticeNumberMovedOut = "number_moved_out"
)

// Mailie's notice codes (notices[].code).
const (
	NoticeMailboxRemoved    = "mailbox_removed"
	NoticeMailboxSyncOff    = "mailbox_sync_off"
	NoticeMailboxSyncPaused = "mailbox_sync_paused"
)

var (
	wappieNotices = []string{NoticeSyncPaused, NoticeNumberDeleted, NoticeNumberStranded, NoticeNumberMovedOut}
	mailieNotices = []string{NoticeMailboxRemoved, NoticeMailboxSyncOff, NoticeMailboxSyncPaused}
)

// NoticeCodes are app's notice codes: Wappie's or Mailie's (an app other
// than these two, the platform's reference app, has Wappie's). It returns
// a copy: the set Validate checks is closed.
func NoticeCodes(app string) []string {
	if app == "mailie" {
		return slices.Clone(mailieNotices)
	}
	if ValidApp(app) {
		return slices.Clone(wappieNotices)
	}
	return nil
}

// Wappie's AI providers and functions (provider_keys[].provider,
// functions[].id and .provider, alerts[].function and .provider,
// server_off, and ai.integration_narrow's function:<id>). A function is
// named by what it takes, never by what it gives.
const (
	AIAnthropic = "anthropic"
	AIOpenAI    = "openai"
	AIGoogle    = "google"

	AIAudio    = "audio"
	AIVideo    = "video"
	AIImage    = "image"
	AIDocument = "document"
)

var (
	aiProviders = []string{AIAnthropic, AIOpenAI, AIGoogle}
	aiFunctions = []string{AIAudio, AIVideo, AIImage, AIDocument}
)

// AIProviders are Wappie's AI providers. It returns a copy.
func AIProviders() []string { return slices.Clone(aiProviders) }

// AIFunctions are Wappie's AI functions. It returns a copy.
func AIFunctions() []string { return slices.Clone(aiFunctions) }

// Wappie's revoke reasons (connections[].end_reason,
// integrations[].end_reason).
var endReasons = []string{
	"console", "reader", "reuse_detected", "relay_failed", "pending_expired", "expired", "service_removed",
	"service_disabled", "member_removed", "member_disabled", "access_lost", "ai_key_deleted", "replaced", "idle",
}

// EndReasons are why Wappie ended an MCP connection or an AI integration.
// It returns a copy.
func EndReasons() []string { return slices.Clone(endReasons) }

// Wappie's budget hits (connections[].budget_hits[].code).
var budgetHits = []string{"daily_messages", "daily_attachments", "first_hour_messages", "first_hour_attachments", "network"}

// BudgetHits are the limits an MCP connection can reach. It returns a copy.
func BudgetHits() []string { return slices.Clone(budgetHits) }

// Wappie's AI alerts (integrations[].alerts[].code).
var aiAlerts = []string{"ai_key_rejected", "ai_quota", "ai_model_unavailable"}

// AIAlerts are why an AI integration's functions paused. It returns a copy.
func AIAlerts() []string { return slices.Clone(aiAlerts) }

// What Wappie's server allows a workspace (mcp.server_allows), in this
// order: the operator's half only.
const (
	AllowMetadata        = "metadata"
	AllowVerifiedReader  = "verified_reader"
	AllowUntestedClients = "untested_clients"
	AllowUntestedText    = "untested_text"
	AllowOwnChatNotes    = "own_chat_notes"
	AllowDirectSend      = "direct_send"
)

var serverAllows = []string{AllowMetadata, AllowVerifiedReader, AllowUntestedClients, AllowUntestedText, AllowOwnChatNotes, AllowDirectSend}

// ServerAllows are the codes of mcp.server_allows, in the order a list
// keeps them. Absent means not allowed. It returns a copy.
func ServerAllows() []string { return slices.Clone(serverAllows) }

// The MCP switches (switches[].switch, and a switch command's target).
const (
	SwitchText        = "text"
	SwitchAttachments = "attachments"
	SwitchDrafts      = "drafts"
	SwitchAI          = "ai"
)

var mcpSwitches = []string{SwitchText, SwitchAttachments, SwitchDrafts, SwitchAI}

// The bounds of the sections' lists.
const (
	MaxPending           = 50
	MaxSectionItems      = 1000
	MaxMoveOutHolders    = 500
	MaxProviderKeys      = 200
	MaxIntegrations      = 500
	MaxConnections       = 500
	MaxBudgetHits        = 5
	MaxSeenBy            = 5000
	MaxRenewalsWaiting   = 5000
	MaxLegacyTokens      = 200
	MaxActivity          = 5000
	MaxInstallations     = 200
	MaxBindings          = 1000
	MaxNotices           = 300
	MaxPermissionsPeople = 5000
)

// ---------------------------------------------------------------------------
// Wappie: numbers
// ---------------------------------------------------------------------------

// NumbersSettings is Wappie's numbers section.
type NumbersSettings struct {
	// CanLink: a number can be linked now (places, pause, plan).
	CanLink bool `json:"can_link"`
	// PlacesFree are the free places in the plan or trial; null until
	// entitlements reach Wappie.
	PlacesFree    *int64                `json:"places_free"`
	StoragePaused bool                  `json:"storage_paused"`
	Pending       []PendingRegistration `json:"pending"`
	Items         []NumberRow           `json:"items"`
}

// PendingRegistration is a number not linked yet; the snapshot omits it.
type PendingRegistration struct {
	ID        string `json:"id"`
	CreatedAt Time   `json:"created_at"`
	// Pairing: a pairing is under way now.
	Pairing bool `json:"pairing"`
	// CanRetry: the pairing-retry act may start one.
	CanRetry bool `json:"can_retry"`
}

// NumberRow is one number's row, joined to the snapshot's item by its id.
type NumberRow struct {
	ID              string `json:"id"`
	Connection      string `json:"connection"`
	LastConnectedAt *Time  `json:"last_connected_at"`
	// Capture is on or paused: paused keeps what the number holds.
	Capture   string    `json:"capture"`
	PausedBy  *PausedBy `json:"paused_by"`
	CanResume bool      `json:"can_resume"`
	ReadOnly  bool      `json:"read_only"`
	// KeyEpoch is the current epoch only, never a key.
	KeyEpoch *int64 `json:"key_epoch"`
	// MoveOut is a team number's transfer preview, for the team's only
	// owner, else null.
	MoveOut      *MoveOut `json:"move_out"`
	RecoveryOpen bool     `json:"recovery_open"`
	// Bytes is null until the privacy text names it.
	Bytes *int64 `json:"bytes"`
}

// PausedBy is who paused a number's capture: a person, a token with manage
// (its creator's sub), or the app (no sub).
type PausedBy struct {
	Kind string  `json:"kind"`
	Sub  *string `json:"sub"`
	At   Time    `json:"at"`
}

// MoveOut is a team number's transfer preview.
type MoveOut struct {
	// Holders are everyone else with access, at most MaxMoveOutHolders.
	Holders []Holder `json:"holders"`
	// HoldersMore are the holders left out past MaxMoveOutHolders.
	HoldersMore int64 `json:"holders_more"`
	// Ends are the connections the move ends.
	Ends []string `json:"ends"`
}

// Holder is someone, or something, with access to a number.
type Holder struct {
	Kind string `json:"kind"`
	// Sub is a sub, or null.
	Sub *string `json:"sub"`
	// Row is the app's row id, or the token's id.
	Row string `json:"row"`
}

var (
	connectionStates = []string{"pairing", "online", "offline", "logged_out_phone", "logged_out_deletion", "banned"}
	holderKinds      = []string{"person", "service_account", "assistant", "ai", "legacy_key", "token"}
	pausedByKinds    = []string{ActorPerson, ActorKey, ActorApp}
)

func (s *NumbersSettings) validate(string) error {
	switch {
	case s.PlacesFree != nil && *s.PlacesFree < 0:
		return invalid("places_free")
	case s.Pending == nil || len(s.Pending) > MaxPending:
		return invalid("pending")
	case s.Items == nil || len(s.Items) > MaxSectionItems:
		return invalid("items")
	}
	seen := map[string]bool{}
	for _, p := range s.Pending {
		if !ValidItemID(p.ID) || seen[p.ID] || p.CreatedAt.IsZero() {
			return invalid("pending[]")
		}
		seen[p.ID] = true
	}
	items := map[string]bool{}
	for _, it := range s.Items {
		if err := it.validate(); err != nil {
			return err
		}
		if items[it.ID] {
			return invalid("an item appears twice")
		}
		items[it.ID] = true
	}
	return nil
}

func (it NumberRow) validate() error {
	switch {
	case !ValidItemID(it.ID):
		return invalid("items[].id")
	case !oneOf(it.Connection, connectionStates):
		return invalid("items[].connection")
	case !timeOrNull(it.LastConnectedAt):
		return invalid("items[].last_connected_at")
	case it.Capture != "on" && it.Capture != "paused":
		return invalid("items[].capture")
	case it.Capture == "on" && it.PausedBy != nil:
		return invalid("items[].paused_by is null while capture is on")
	case it.KeyEpoch != nil && *it.KeyEpoch < 0:
		return invalid("items[].key_epoch")
	case it.Bytes != nil && *it.Bytes < 0:
		return invalid("items[].bytes")
	}
	if p := it.PausedBy; p != nil {
		switch {
		case !oneOf(p.Kind, pausedByKinds):
			return invalid("items[].paused_by.kind")
		case !subOrNull(p.Sub), p.Kind == ActorApp && p.Sub != nil:
			return invalid("items[].paused_by.sub")
		case p.At.IsZero():
			return invalid("items[].paused_by.at")
		}
	}
	if m := it.MoveOut; m != nil {
		if err := m.validate("items[].move_out"); err != nil {
			return err
		}
	}
	return nil
}

func (m MoveOut) validate(where string) error {
	switch {
	case m.Holders == nil || len(m.Holders) > MaxMoveOutHolders:
		return invalid("%s.holders", where)
	case m.HoldersMore < 0, m.HoldersMore > 0 && len(m.Holders) != MaxMoveOutHolders:
		return invalid("%s.holders_more is past a list of %d holders only", where, MaxMoveOutHolders)
	case !idsOnce(m.Ends, MaxMoveOutHolders, ValidItemID):
		return invalid("%s.ends", where)
	}
	seen := map[[2]string]bool{}
	for _, h := range m.Holders {
		key := [2]string{h.Kind, h.Row}
		if !oneOf(h.Kind, holderKinds) || !subOrNull(h.Sub) || !ValidItemID(h.Row) || seen[key] {
			return invalid("%s.holders[]", where)
		}
		seen[key] = true
	}
	return nil
}

// ---------------------------------------------------------------------------
// Wappie: integrations
// ---------------------------------------------------------------------------

// IntegrationsSettings is Wappie's integrations section: its AI area.
type IntegrationsSettings struct {
	// AIEnabled is the effective ai switch.
	AIEnabled bool `json:"ai_enabled"`
	// ServerOff are the AI functions and providers this server's operator
	// turned off.
	ServerOff    ServerOff       `json:"server_off"`
	ProviderKeys []ProviderKey   `json:"provider_keys"`
	Integrations []AIIntegration `json:"integrations"`
}

// ServerOff are the AI functions and providers a server's operator turned
// off, each once; empty lists for none.
type ServerOff struct {
	Functions []string `json:"functions"`
	Providers []string `json:"providers"`
}

// ProviderKey is an AI provider's key a person registered: never the key.
type ProviderKey struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	// Label tells two keys of one provider apart: a label, or null.
	Label     *string `json:"label"`
	Owner     *string `json:"owner"`
	CreatedAt Time    `json:"created_at"`
}

// AIIntegration is one AI integration.
type AIIntegration struct {
	ID        string       `json:"id"`
	Name      *string      `json:"name"`
	CreatedBy *string      `json:"created_by"`
	Status    string       `json:"status"`
	Functions []AIFunction `json:"functions"`
	Cap       *AICap       `json:"cap"`
	Items     []string     `json:"items"`
	Alerts    []AIAlert    `json:"alerts"`
	CreatedAt Time         `json:"created_at"`
	ExpiresAt *Time        `json:"expires_at"`
	EndedAt   *Time        `json:"ended_at"`
	EndReason *string      `json:"end_reason"`
}

// AIFunction is one function of an integration, and the provider that
// serves it.
type AIFunction struct {
	ID       string `json:"id"`
	On       bool   `json:"on"`
	Provider string `json:"provider"`
}

// AICap is an integration's monthly cap.
type AICap struct {
	Limit  int64  `json:"limit"`
	Used   int64  `json:"used"`
	Period string `json:"period"`
}

// AIAlert is why an integration's functions paused, kept until a renewal.
type AIAlert struct {
	Code     string  `json:"code"`
	Function *string `json:"function"`
	Provider *string `json:"provider"`
	At       Time    `json:"at"`
}

var integrationStatuses = []string{"pending", "active", "paused", "reseal", "ended"}

func (s *IntegrationsSettings) validate(string) error {
	switch {
	case !codesOnce(s.ServerOff.Functions, aiFunctions):
		return invalid("server_off.functions")
	case !codesOnce(s.ServerOff.Providers, aiProviders):
		return invalid("server_off.providers")
	case s.ProviderKeys == nil || len(s.ProviderKeys) > MaxProviderKeys:
		return invalid("provider_keys")
	case s.Integrations == nil || len(s.Integrations) > MaxIntegrations:
		return invalid("integrations")
	}
	keys := map[string]bool{}
	for _, k := range s.ProviderKeys {
		if !ValidItemID(k.ID) || keys[k.ID] || !oneOf(k.Provider, aiProviders) || !labelOrNull(k.Label) || !subOrNull(k.Owner) || k.CreatedAt.IsZero() {
			return invalid("provider_keys[]")
		}
		keys[k.ID] = true
	}
	seen := map[string]bool{}
	for _, in := range s.Integrations {
		if err := in.validate(); err != nil {
			return err
		}
		if seen[in.ID] {
			return invalid("an integration appears twice")
		}
		seen[in.ID] = true
	}
	return nil
}

func (in AIIntegration) validate() error {
	switch {
	case !ValidItemID(in.ID):
		return invalid("integrations[].id")
	case !labelOrNull(in.Name):
		return invalid("integrations[].name")
	case !subOrNull(in.CreatedBy):
		return invalid("integrations[].created_by")
	case !oneOf(in.Status, integrationStatuses):
		return invalid("integrations[].status")
	case in.Functions == nil || len(in.Functions) > len(aiFunctions):
		return invalid("integrations[].functions")
	case in.Cap != nil && (in.Cap.Limit < 0 || in.Cap.Used < 0 || in.Cap.Period != "month"):
		return invalid("integrations[].cap")
	case !idsOnce(in.Items, MaxSectionItems, ValidItemID):
		return invalid("integrations[].items")
	case in.Alerts == nil:
		return invalid("integrations[].alerts")
	case in.CreatedAt.IsZero(), !timeOrNull(in.ExpiresAt), !timeOrNull(in.EndedAt):
		return invalid("integrations[]: a time")
	case (in.Status == "ended") != (in.EndedAt != nil):
		return invalid("integrations[].ended_at is set exactly on an ended integration")
	case !codeOrNull(in.EndReason, endReasons), in.EndReason != nil && in.EndedAt == nil:
		return invalid("integrations[].end_reason")
	}
	fns := map[string]bool{}
	for _, f := range in.Functions {
		if !oneOf(f.ID, aiFunctions) || fns[f.ID] || !oneOf(f.Provider, aiProviders) {
			return invalid("integrations[].functions[]")
		}
		fns[f.ID] = true
	}
	alerts := map[[3]string]bool{}
	for _, a := range in.Alerts {
		key := [3]string{a.Code, "", ""}
		if a.Function != nil {
			key[1] = *a.Function
		}
		if a.Provider != nil {
			key[2] = *a.Provider
		}
		if !oneOf(a.Code, aiAlerts) || !codeOrNull(a.Function, aiFunctions) || !codeOrNull(a.Provider, aiProviders) || a.At.IsZero() || alerts[key] {
			return invalid("integrations[].alerts[]")
		}
		alerts[key] = true
	}
	return nil
}

// ---------------------------------------------------------------------------
// Wappie: mcp
// ---------------------------------------------------------------------------

// MCPSettings is Wappie's mcp section.
type MCPSettings struct {
	// Switches are exactly the four, each once.
	Switches []MCPSwitch `json:"switches"`
	// SwitchedAt and SwitchedBy are the last change to any switch, or null;
	// SwitchedBy may be null beside a time.
	SwitchedAt *Time   `json:"switched_at"`
	SwitchedBy *string `json:"switched_by"`
	// ServerAllows is what this server allows the workspace (ServerAllows),
	// each code once, in the list's order; [] when the connector is off.
	ServerAllows    []string          `json:"server_allows"`
	Connections     []MCPConnection   `json:"connections"`
	RenewalsWaiting []RenewalsWaiting `json:"renewals_waiting"`
	LegacyTokens    []LegacyToken     `json:"legacy_tokens"`
	Activity        []MCPActivity     `json:"activity"`
}

// MCPSwitch is one workspace switch, as computed.
type MCPSwitch struct {
	Switch string `json:"switch"`
	// Set is the workspace's own choice, or null for the default.
	Set     *bool `json:"set"`
	Default bool  `json:"default"`
	// Operator is the operator's half: allow or deny.
	Operator string `json:"operator"`
	// Effective is MCP's gate, what assistants get: the switch commands'
	// before and after.
	Effective bool `json:"effective"`
	// TokenEffective is the token's gate: a bool for text and attachments,
	// null for drafts and ai.
	TokenEffective *bool `json:"token_effective"`
	// Changeable is false when the operator denies the switch.
	Changeable bool `json:"changeable"`
}

// MCPConnection is one assistant's connection (AI rows are integrations).
type MCPConnection struct {
	ID           string     `json:"id"`
	Name         *string    `json:"name"`
	Kind         string     `json:"kind"`
	Status       string     `json:"status"`
	Tier         string     `json:"tier"`
	VerifiedHost *string    `json:"verified_host"`
	MainDomain   *string    `json:"main_domain"`
	CallsItself  *string    `json:"calls_itself"`
	Consent      MCPConsent `json:"consent"`
	// HistoryDays is 7, 30 or 90, or null when Wappie sets no limit.
	HistoryDays *int        `json:"history_days"`
	Items       []string    `json:"items"`
	CreatedAt   Time        `json:"created_at"`
	ActivatedAt *Time       `json:"activated_at"`
	FirstUsedAt *Time       `json:"first_used_at"`
	LastUsedAt  *Time       `json:"last_used_at"`
	ExpiresAt   *Time       `json:"expires_at"`
	EndedAt     *Time       `json:"ended_at"`
	EndReason   *string     `json:"end_reason"`
	BudgetHits  []BudgetHit `json:"budget_hits"`
	Consenter   *string     `json:"consenter"`
	// SeenBy are who marked it seen (mcp.connection_seen).
	SeenBy     []string `json:"seen_by"`
	SendPaused bool     `json:"send_paused"`
}

// MCPConsent is what a connection's consent allows.
type MCPConsent struct {
	Text        bool `json:"text"`
	Attachments bool `json:"attachments"`
	// Send is off, draft or direct.
	Send string `json:"send"`
	// OwnChat: notes to the number's own chat without confirmation.
	OwnChat bool `json:"own_chat"`
	// Groups: drafts to groups.
	Groups bool `json:"groups"`
}

// BudgetHit is a connection's latest hit of one limit.
type BudgetHit struct {
	Code string `json:"code"`
	At   Time   `json:"at"`
}

// RenewalsWaiting counts the renewals waiting for one consenter.
type RenewalsWaiting struct {
	Consenter *string `json:"consenter"`
	Count     int64   `json:"count"`
}

// LegacyToken is an old local MCP token.
type LegacyToken struct {
	ID        string  `json:"id"`
	Name      *string `json:"name"`
	CreatedAt Time    `json:"created_at"`
	CreatedBy *string `json:"created_by"`
}

// MCPActivity counts one connection's drafts and sends on one UTC day.
type MCPActivity struct {
	Day        string `json:"day"`
	Connection string `json:"connection"`
	Drafts     int64  `json:"drafts"`
	Sends      int64  `json:"sends"`
}

var (
	connectionKinds    = []string{"metadata", "content"}
	connectionStatuses = []string{"pending", "active", "reseal", "revoked", "expired"}
	connectionTiers    = []string{"web_tested", "local_tested", "unknown", "token"}
	consentSends       = []string{"off", "draft", "direct"}
)

func (s *MCPSettings) validate(string) error {
	if len(s.Switches) != len(mcpSwitches) {
		return invalid("switches are exactly the four")
	}
	switches := map[string]bool{}
	for _, sw := range s.Switches {
		withToken := sw.Switch == SwitchText || sw.Switch == SwitchAttachments
		switch {
		case !oneOf(sw.Switch, mcpSwitches) || switches[sw.Switch]:
			return invalid("switches[].switch")
		case sw.Operator != "allow" && sw.Operator != "deny":
			return invalid("switches[].operator")
		case withToken != (sw.TokenEffective != nil):
			return invalid("switches[].token_effective is set for text and attachments only")
		case sw.Operator == "deny" && (sw.Effective || sw.Changeable):
			return invalid("switches[]: a switch the operator denies is neither effective nor changeable")
		}
		switches[sw.Switch] = true
	}
	switch {
	case !timeOrNull(s.SwitchedAt), s.SwitchedBy != nil && (s.SwitchedAt == nil || !ValidUUID(*s.SwitchedBy)):
		return invalid("switched_at, switched_by")
	case !codesOnce(s.ServerAllows, serverAllows):
		return invalid("server_allows")
	case s.Connections == nil || len(s.Connections) > MaxConnections:
		return invalid("connections")
	case s.RenewalsWaiting == nil || len(s.RenewalsWaiting) > MaxRenewalsWaiting:
		return invalid("renewals_waiting")
	case s.LegacyTokens == nil || len(s.LegacyTokens) > MaxLegacyTokens:
		return invalid("legacy_tokens")
	case s.Activity == nil || len(s.Activity) > MaxActivity:
		return invalid("activity")
	}
	last := -1
	for _, code := range s.ServerAllows {
		i := slices.Index(serverAllows, code)
		if i <= last {
			return invalid("server_allows keeps the list's order")
		}
		last = i
	}
	seen := map[string]bool{}
	for _, c := range s.Connections {
		if err := c.validate(); err != nil {
			return err
		}
		if seen[c.ID] {
			return invalid("a connection appears twice")
		}
		seen[c.ID] = true
	}
	consenters := map[string]bool{}
	for _, r := range s.RenewalsWaiting {
		key := "null"
		if r.Consenter != nil {
			key = *r.Consenter
		}
		if !subOrNull(r.Consenter) || r.Count < 1 || consenters[key] {
			return invalid("renewals_waiting[]")
		}
		consenters[key] = true
	}
	legacy := map[string]bool{}
	for _, l := range s.LegacyTokens {
		if !ValidItemID(l.ID) || legacy[l.ID] || !labelOrNull(l.Name) || l.CreatedAt.IsZero() || !subOrNull(l.CreatedBy) {
			return invalid("legacy_tokens[]")
		}
		legacy[l.ID] = true
	}
	days := map[[2]string]bool{}
	for _, a := range s.Activity {
		key := [2]string{a.Day, a.Connection}
		if !ValidDay(a.Day) || !ValidItemID(a.Connection) || a.Drafts < 0 || a.Sends < 0 || a.Drafts+a.Sends < 1 || days[key] {
			return invalid("activity[]: a day with activity, each (day, connection) once")
		}
		days[key] = true
	}
	return nil
}

func (c MCPConnection) validate() error {
	hostOrNull := func(p *string) bool { return p == nil || ValidHost(*p) }
	switch {
	case !ValidItemID(c.ID):
		return invalid("connections[].id")
	case !labelOrNull(c.Name), !labelOrNull(c.CallsItself):
		return invalid("connections[].name, calls_itself")
	case !oneOf(c.Kind, connectionKinds):
		return invalid("connections[].kind")
	case !oneOf(c.Status, connectionStatuses):
		return invalid("connections[].status")
	case !oneOf(c.Tier, connectionTiers):
		return invalid("connections[].tier")
	case !hostOrNull(c.VerifiedHost), !hostOrNull(c.MainDomain):
		return invalid("connections[].verified_host, main_domain")
	case c.Tier == "token" && (c.VerifiedHost != nil || c.MainDomain != nil):
		return invalid("connections[]: a token connection names no host")
	case !oneOf(c.Consent.Send, consentSends):
		return invalid("connections[].consent.send")
	case c.HistoryDays != nil && *c.HistoryDays != 7 && *c.HistoryDays != 30 && *c.HistoryDays != 90:
		return invalid("connections[].history_days")
	case !idsOnce(c.Items, MaxSectionItems, ValidItemID):
		return invalid("connections[].items")
	case c.CreatedAt.IsZero(), !timeOrNull(c.ActivatedAt), !timeOrNull(c.FirstUsedAt), !timeOrNull(c.LastUsedAt),
		!timeOrNull(c.ExpiresAt), !timeOrNull(c.EndedAt):
		return invalid("connections[]: a time")
	case !codeOrNull(c.EndReason, endReasons):
		return invalid("connections[].end_reason")
	case c.EndReason != nil && c.Status != "revoked" && c.Status != "expired":
		return invalid("connections[].end_reason is an ended connection's")
	case c.BudgetHits == nil || len(c.BudgetHits) > MaxBudgetHits:
		return invalid("connections[].budget_hits")
	case !subOrNull(c.Consenter):
		return invalid("connections[].consenter")
	case !idsOnce(c.SeenBy, MaxSeenBy, ValidUUID):
		return invalid("connections[].seen_by")
	}
	hits := map[string]bool{}
	for _, h := range c.BudgetHits {
		if !oneOf(h.Code, budgetHits) || hits[h.Code] || h.At.IsZero() {
			return invalid("connections[].budget_hits[]")
		}
		hits[h.Code] = true
	}
	return nil
}

// ---------------------------------------------------------------------------
// Wappie: installations (producer wappie-cloud)
// ---------------------------------------------------------------------------

// InstallationsSettings is Wappie Cloud's installations section.
type InstallationsSettings struct {
	Licences      Licences       `json:"licences"`
	HostedNumbers int64          `json:"hosted_numbers"`
	Installations []Installation `json:"installations"`
	Bindings      []Binding      `json:"bindings"`
}

// Licences are the licences used, and the capacity, or null for no limit.
type Licences struct {
	Used     int64  `json:"used"`
	Capacity *int64 `json:"capacity"`
}

// Installation is one self-hosted installation; its origin is shown as
// text, never as a link.
type Installation struct {
	ID        string  `json:"id"`
	Name      *string `json:"name"`
	Origin    string  `json:"origin"`
	CreatedAt Time    `json:"created_at"`
}

// Binding is one number an installation holds a licence for.
type Binding struct {
	ID           string `json:"id"`
	Installation string `json:"installation"`
	// Label is a label a person set, or null: never a WhatsApp push name.
	Label     *string `json:"label"`
	State     string  `json:"state"`
	BoundAt   Time    `json:"bound_at"`
	ExpiresAt *Time   `json:"expires_at"`
}

func (s *InstallationsSettings) validate(string) error {
	switch {
	case s.Licences.Used < 0, s.Licences.Capacity != nil && *s.Licences.Capacity < 0:
		return invalid("licences")
	case s.HostedNumbers < 0:
		return invalid("hosted_numbers")
	case s.Installations == nil || len(s.Installations) > MaxInstallations:
		return invalid("installations")
	case s.Bindings == nil || len(s.Bindings) > MaxBindings:
		return invalid("bindings")
	}
	seen := map[string]bool{}
	for _, in := range s.Installations {
		if !ValidItemID(in.ID) || seen[in.ID] || !labelOrNull(in.Name) || !ValidOrigin(in.Origin) || in.CreatedAt.IsZero() {
			return invalid("installations[]")
		}
		seen[in.ID] = true
	}
	bound := map[string]bool{}
	for _, b := range s.Bindings {
		if !ValidItemID(b.ID) || bound[b.ID] || !ValidItemID(b.Installation) || !labelOrNull(b.Label) ||
			(b.State != "reserved" && b.State != "active") || b.BoundAt.IsZero() || !timeOrNull(b.ExpiresAt) {
			return invalid("bindings[]")
		}
		bound[b.ID] = true
	}
	return nil
}

// ---------------------------------------------------------------------------
// Mailie: email-accounts
// ---------------------------------------------------------------------------

// EmailAccountsSettings is Mailie's email-accounts section.
type EmailAccountsSettings struct {
	// Availability is usable, withheld (Mailie's team gate) or closed.
	Availability string `json:"availability"`
	// LinkMinRole is who may link a mailbox here, or null for nobody.
	LinkMinRole *string      `json:"link_min_role"`
	Texts       TeamTexts    `json:"texts"`
	Items       []MailboxRow `json:"items"`
}

// TeamTexts is the team sync text's revision Mailie accepts now.
type TeamTexts struct {
	TeamSync string `json:"team_sync"`
}

// MailboxRow is one mailbox's row, joined to the snapshot's item by its id.
type MailboxRow struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	SignIn   string `json:"sign_in"`
	Status   string `json:"status"`
	// Reason is a code on error and needs_reauth only; never last_error.
	Reason      *string         `json:"reason"`
	ConnectedAt *Time           `json:"connected_at"`
	LinkedBy    *string         `json:"linked_by"`
	KeyEpoch    *int64          `json:"key_epoch"`
	CopyOfSent  bool            `json:"copy_of_sent"`
	NoReader    bool            `json:"no_reader"`
	Sync        MailboxSync     `json:"sync"`
	Removed     *MailboxRemoved `json:"removed"`
}

// MailboxSync is a mailbox's sync.
type MailboxSync struct {
	Mode string `json:"mode"`
	// On is the consent side: false once turned off, which deleted the
	// index.
	On bool `json:"on"`
	// Agreement is a team's agreement, or null; a personal mailbox's is the
	// person's own.
	Agreement *SyncAgreement `json:"agreement"`
	// Paused is the per-mailbox pause, which keeps the index, or null.
	Paused *SyncPause `json:"paused"`
	// Held: turned off by Mailie's operator until its person turns sync on
	// again; a personal mailbox's only.
	Held bool `json:"held"`
	// Indexed and LastSyncAt are as of the document's measured_at.
	Indexed    string `json:"indexed"`
	LastSyncAt *Time  `json:"last_sync_at"`
}

// SyncAgreement is a team's agreement to sync a mailbox.
type SyncAgreement struct {
	By       *string `json:"by"`
	At       Time    `json:"at"`
	Revision string  `json:"revision"`
	// Bound: bound to its linker by Mailie's migration 0011, not yet
	// confirmed by an owner or admin.
	Bound bool `json:"bound"`
}

// SyncPause is a mailbox's pause: by a person (no Mailie token pauses).
type SyncPause struct {
	By   *string `json:"by"`
	Kind string  `json:"kind"`
	At   Time    `json:"at"`
}

// MailboxRemoved is a removed mailbox's recovery window.
type MailboxRemoved struct {
	RemovedAt  Time `json:"removed_at"`
	PurgeAfter Time `json:"purge_after"`
	IndexKept  bool `json:"index_kept"`
}

var (
	mailProviders   = []string{"google", "microsoft", "icloud", "imap"}
	mailboxStatuses = []string{"connected", "needs_reauth", "pending_auth", "error", "removed"}
	mailboxReasons  = []string{"scope_missing", "mailbox_refused", "token_rejected", "unproved", "other"}
	indexStates     = []string{"none", "partial", "complete"}
	roles           = []string{RoleOwner, RoleAdmin, RoleMember}
)

func (s *EmailAccountsSettings) validate(string) error {
	switch {
	case !oneOf(s.Availability, []string{"usable", "withheld", "closed"}):
		return invalid("availability")
	case !codeOrNull(s.LinkMinRole, roles):
		return invalid("link_min_role")
	case !ValidRevision(s.Texts.TeamSync):
		return invalid("texts.team_sync")
	case s.Items == nil || len(s.Items) > MaxSectionItems:
		return invalid("items")
	}
	seen := map[string]bool{}
	for _, it := range s.Items {
		if err := it.validate(); err != nil {
			return err
		}
		if seen[it.ID] {
			return invalid("an item appears twice")
		}
		seen[it.ID] = true
	}
	return nil
}

func (it MailboxRow) validate() error {
	sy := it.Sync
	switch {
	case !ValidItemID(it.ID):
		return invalid("items[].id")
	case !oneOf(it.Provider, mailProviders):
		return invalid("items[].provider")
	case it.SignIn != "oauth" && it.SignIn != "password":
		return invalid("items[].sign_in")
	case !oneOf(it.Status, mailboxStatuses):
		return invalid("items[].status")
	case !codeOrNull(it.Reason, mailboxReasons), it.Reason != nil && it.Status != "error" && it.Status != "needs_reauth":
		return invalid("items[].reason is a code on error and needs_reauth only")
	case !timeOrNull(it.ConnectedAt):
		return invalid("items[].connected_at")
	case !subOrNull(it.LinkedBy):
		return invalid("items[].linked_by")
	case it.KeyEpoch != nil && *it.KeyEpoch < 0:
		return invalid("items[].key_epoch")
	case (it.Status == "removed") != (it.Removed != nil):
		return invalid("items[].removed is set exactly on a removed mailbox")
	case it.Removed != nil && (it.Removed.RemovedAt.IsZero() || it.Removed.PurgeAfter.IsZero()):
		return invalid("items[].removed")
	case sy.Mode != KindTeam && sy.Mode != KindPersonal:
		return invalid("items[].sync.mode")
	case sy.Agreement != nil && sy.Mode != KindTeam:
		return invalid("items[].sync.agreement is a team mailbox's")
	case sy.Held && sy.Mode != KindPersonal:
		return invalid("items[].sync.held is a personal mailbox's")
	case !oneOf(sy.Indexed, indexStates):
		return invalid("items[].sync.indexed")
	case !timeOrNull(sy.LastSyncAt):
		return invalid("items[].sync.last_sync_at")
	}
	if a := sy.Agreement; a != nil && (!subOrNull(a.By) || a.At.IsZero() || !ValidRevision(a.Revision)) {
		return invalid("items[].sync.agreement")
	}
	if p := sy.Paused; p != nil && (!subOrNull(p.By) || p.Kind != ActorPerson || p.At.IsZero()) {
		return invalid("items[].sync.paused")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Mailie: permissions
// ---------------------------------------------------------------------------

// PermissionsSettings is Mailie's permissions section: every member Mailie
// holds; each item's flags per person come from the access snapshot.
type PermissionsSettings struct {
	Members []PermissionsMember `json:"members"`
}

// PermissionsMember is one member Mailie holds.
type PermissionsMember struct {
	Sub string `json:"sub"`
	// Status is active, suspended, held or disabled (Mailie's own).
	Status   string `json:"status"`
	Enrolled bool   `json:"enrolled"`
}

func (s *PermissionsSettings) validate(string) error {
	if s.Members == nil || len(s.Members) > MaxPermissionsPeople {
		return invalid("members")
	}
	seen := map[string]bool{}
	for _, m := range s.Members {
		if !ValidUUID(m.Sub) || seen[m.Sub] || !oneOf(m.Status, []string{"active", "suspended", "held", "disabled"}) {
			return invalid("members[]")
		}
		seen[m.Sub] = true
	}
	return nil
}

// ---------------------------------------------------------------------------
// The person
// ---------------------------------------------------------------------------

// WappiePersonSettings is a person's own settings in Wappie.
type WappiePersonSettings struct {
	Notices []Notice `json:"notices"`
	// SignedOutEverywhereAt is the last person.sign_out_everywhere that
	// ran, or null.
	SignedOutEverywhereAt *Time `json:"signed_out_everywhere_at"`
}

// MailiePersonSettings is a person's own settings in Mailie.
type MailiePersonSettings struct {
	// Consents are exactly sync, actions and send, each once.
	Consents []Consent `json:"consents"`
	// Texts are the revisions Mailie accepts now.
	Texts    PersonTexts `json:"texts"`
	Enrolled bool        `json:"enrolled"`
	Notices  []Notice    `json:"notices"`
	// SignedOutEverywhereAt is the last person.sign_out_everywhere that
	// ran, or null.
	SignedOutEverywhereAt *Time `json:"signed_out_everywhere_at"`
}

// Consent is one of a person's consents in Mailie.
type Consent struct {
	Consent string `json:"consent"`
	// State is on, off or old_text (actions and send only: agreed to a
	// revision Mailie no longer accepts, so paused).
	State       string  `json:"state"`
	Revision    *string `json:"revision"`
	AgreedAt    *Time   `json:"agreed_at"`
	WithdrawnAt *Time   `json:"withdrawn_at"`
}

// PersonTexts are the revisions Mailie accepts now, its key terms' among
// them.
type PersonTexts struct {
	Sync    string `json:"sync"`
	Actions string `json:"actions"`
	Send    string `json:"send"`
	Keys    string `json:"keys"`
}

// The consents of a Mailie person.
const (
	ConsentSync    = "sync"
	ConsentActions = "actions"
	ConsentSend    = "send"
)

var consents = []string{ConsentSync, ConsentActions, ConsentSend}

func (s *WappiePersonSettings) validate(app string) error {
	if !timeOrNull(s.SignedOutEverywhereAt) {
		return invalid("signed_out_everywhere_at")
	}
	return validateNotices(app, s.Notices)
}

func (s *MailiePersonSettings) validate(app string) error {
	if len(s.Consents) != len(consents) {
		return invalid("consents are exactly sync, actions and send")
	}
	seen := map[string]bool{}
	for _, c := range s.Consents {
		switch {
		case !oneOf(c.Consent, consents) || seen[c.Consent]:
			return invalid("consents[].consent")
		case !oneOf(c.State, []string{"on", "off", "old_text"}):
			return invalid("consents[].state")
		case c.State == "old_text" && c.Consent == ConsentSync:
			return invalid("consents[]: old_text is for actions and send only")
		case c.Revision != nil && !ValidRevision(*c.Revision), !timeOrNull(c.AgreedAt), !timeOrNull(c.WithdrawnAt):
			return invalid("consents[]")
		case c.State != "off" && (c.Revision == nil || c.AgreedAt == nil):
			return invalid("consents[]: an agreed consent names its revision and time")
		case c.Consent == ConsentSync && c.WithdrawnAt != nil:
			return invalid("consents[]: sync's withdrawn_at is always null")
		}
		seen[c.Consent] = true
	}
	switch {
	case !ValidRevision(s.Texts.Sync), !ValidRevision(s.Texts.Actions), !ValidRevision(s.Texts.Send), !ValidRevision(s.Texts.Keys):
		return invalid("texts")
	case !timeOrNull(s.SignedOutEverywhereAt):
		return invalid("signed_out_everywhere_at")
	}
	return validateNotices(app, s.Notices)
}

// ---------------------------------------------------------------------------
// Notices
// ---------------------------------------------------------------------------

// Notice is one of a person's notices from an app. Its params are closed,
// per code: SyncPausedParams, NumberDeletedParams, NumberStrandedParams,
// NumberMovedOutParams (Wappie), MailboxRemovedParams,
// MailboxSyncOffParams, MailboxSyncPausedParams (Mailie).
type Notice struct {
	// ID is the app's own id for the notice, in an item id's shape.
	ID          string  `json:"id"`
	Code        string  `json:"code"`
	WorkspaceID *string `json:"workspace_id"`
	// Item is the snapshot's id for the item, or null.
	Item *string `json:"item"`
	// At is when it was raised, or last raised for a folded pause.
	At Time `json:"at"`
	// Version rises when the notice changes; Mailie always sends 1.
	Version int64 `json:"version"`
	// Label and Hint are kept by the app with the notice: never an address.
	Label  *string         `json:"label"`
	Hint   *string         `json:"hint"`
	Params json.RawMessage `json:"params"`
}

// SyncPausedParams are Wappie's sync_paused notice's.
type SyncPausedParams struct {
	Actor *string `json:"actor"`
	// ActorKind is person or key (a token: Actor is its creator).
	ActorKind     string `json:"actor_kind"`
	SeveralActors bool   `json:"several_actors"`
	FirstAt       Time   `json:"first_at"`
	ResumedAt     *Time  `json:"resumed_at"`
}

// NumberDeletedParams are Wappie's number_deleted notice's.
type NumberDeletedParams struct {
	Actor *string `json:"actor"`
	// Until is the purge date.
	Until    Time  `json:"until"`
	PurgedAt *Time `json:"purged_at"`
}

// NumberStrandedParams are Wappie's number_stranded notice's.
type NumberStrandedParams struct {
	Actor *string `json:"actor"`
	// Until is null once a recovery clears it.
	Until *Time `json:"until"`
}

// NumberMovedOutParams are Wappie's number_moved_out notice's.
type NumberMovedOutParams struct {
	Actor *string `json:"actor"`
}

// MailboxRemovedParams are Mailie's mailbox_removed notice's.
type MailboxRemovedParams struct {
	// State is removed, then deleted.
	State            string `json:"state"`
	RecoverableUntil Time   `json:"recoverable_until"`
}

// MailboxSyncOffParams are Mailie's mailbox_sync_off notice's.
type MailboxSyncOffParams struct {
	// State is live, removed or deleted.
	State            string  `json:"state"`
	RecoverableUntil *Time   `json:"recoverable_until"`
	Actor            *string `json:"actor"`
	// ActorKind is person beside a named actor, else null.
	ActorKind *string `json:"actor_kind"`
}

// MailboxSyncPausedParams are Mailie's mailbox_sync_paused notice's.
type MailboxSyncPausedParams struct {
	// State is always live.
	State     string  `json:"state"`
	Actor     *string `json:"actor"`
	ActorKind *string `json:"actor_kind"`
}

// noticeParams decodes and checks a notice's params by its code.
func noticeParams(code string, raw json.RawMessage) error {
	mailieActor := func(actor, kind *string) bool {
		return subOrNull(actor) && (kind == nil && actor == nil || kind != nil && *kind == ActorPerson)
	}
	switch code {
	case NoticeSyncPaused:
		var p SyncPausedParams
		if err := decodeExact(raw, &p, "notices[].params"); err != nil {
			return err
		}
		if !subOrNull(p.Actor) || (p.ActorKind != ActorPerson && p.ActorKind != ActorKey) || p.FirstAt.IsZero() || !timeOrNull(p.ResumedAt) {
			return invalid("notices[].params")
		}
	case NoticeNumberDeleted:
		var p NumberDeletedParams
		if err := decodeExact(raw, &p, "notices[].params"); err != nil {
			return err
		}
		if !subOrNull(p.Actor) || p.Until.IsZero() || !timeOrNull(p.PurgedAt) {
			return invalid("notices[].params")
		}
	case NoticeNumberStranded:
		var p NumberStrandedParams
		if err := decodeExact(raw, &p, "notices[].params"); err != nil {
			return err
		}
		if !subOrNull(p.Actor) || !timeOrNull(p.Until) {
			return invalid("notices[].params")
		}
	case NoticeNumberMovedOut:
		var p NumberMovedOutParams
		if err := decodeExact(raw, &p, "notices[].params"); err != nil {
			return err
		}
		if !subOrNull(p.Actor) {
			return invalid("notices[].params")
		}
	case NoticeMailboxRemoved:
		var p MailboxRemovedParams
		if err := decodeExact(raw, &p, "notices[].params"); err != nil {
			return err
		}
		if (p.State != "removed" && p.State != "deleted") || p.RecoverableUntil.IsZero() {
			return invalid("notices[].params")
		}
	case NoticeMailboxSyncOff:
		var p MailboxSyncOffParams
		if err := decodeExact(raw, &p, "notices[].params"); err != nil {
			return err
		}
		if !oneOf(p.State, []string{"live", "removed", "deleted"}) || !timeOrNull(p.RecoverableUntil) || !mailieActor(p.Actor, p.ActorKind) {
			return invalid("notices[].params")
		}
	case NoticeMailboxSyncPaused:
		var p MailboxSyncPausedParams
		if err := decodeExact(raw, &p, "notices[].params"); err != nil {
			return err
		}
		if p.State != "live" || !mailieActor(p.Actor, p.ActorKind) {
			return invalid("notices[].params")
		}
	default:
		return invalid("notices[].code")
	}
	return nil
}

// validateNotices checks a person's notices, at most MaxNotices, each id
// once, each with its app's code and that code's params.
func validateNotices(app string, notices []Notice) error {
	if notices == nil || len(notices) > MaxNotices {
		return invalid("notices")
	}
	mailie := app == "mailie"
	seen := map[string]bool{}
	for _, n := range notices {
		switch {
		case !ValidItemID(n.ID) || seen[n.ID]:
			return invalid("notices[].id")
		case !oneOf(n.Code, NoticeCodes(app)):
			return invalid("notices[].code")
		case n.WorkspaceID != nil && !ValidUUID(*n.WorkspaceID), mailie && n.WorkspaceID == nil:
			return invalid("notices[].workspace_id")
		case n.Item != nil && !ValidItemID(*n.Item), mailie && n.Item == nil:
			return invalid("notices[].item")
		case n.At.IsZero():
			return invalid("notices[].at")
		case n.Version < 1, mailie && n.Version != 1:
			return invalid("notices[].version")
		case !labelOrNull(n.Label):
			return invalid("notices[].label")
		case n.Hint != nil && !ValidHint(*n.Hint):
			return invalid("notices[].hint")
		}
		if err := noticeParams(n.Code, n.Params); err != nil {
			return err
		}
		seen[n.ID] = true
	}
	return nil
}
