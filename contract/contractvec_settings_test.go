package contract_test

// The kit's generator of the settings part's three files (kit v0.10.0, SPEC
// section 11.19), written from the platform's design of 2026-10-26 at
// platform commit 509cc65, its section 7: wire-settings.json,
// wire-commands.json and command-macs.json. Every case states the outcome
// the design asks of it, and the generator fails rather than write a case
// whose outcome the code does not give.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/thehappieco/kit/contract"
)

// The fixed material of the settings part's vectors: made-up ids.
const (
	vecPersonal   = "0199d000-0000-7000-8000-000000000005"
	vecThird      = "0199c3d4-0000-7000-8000-000000000003"
	vecCommand    = "0199f3c4-0000-7000-8000-000000000021"
	vecCommand2   = "0199f3c4-0000-7000-8000-000000000022"
	vecConnection = "conn_7"
	vecSyncText   = "2026-10-sync-3"
)

// vecSeq is the vectors' state_seq: Now in milliseconds.
var vecSeq = Now.UnixMilli()

func ptr[T any](v T) *T { return &v }

func at(d time.Duration) contract.Time { return contract.T(Now.Add(d)) }

// mustRaw is v's JSON, which every builder below can write, with no HTML
// escaping, as contract.Client writes a document.
func mustRaw(v any) json.RawMessage {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

// ---------------------------------------------------------------------------
// The sections' builders
// ---------------------------------------------------------------------------

func vecNumbers(mut func(*contract.NumbersSettings)) contract.NumbersSettings {
	s := contract.NumbersSettings{
		CanLink: true, PlacesFree: ptr[int64](2), StoragePaused: false,
		Pending: []contract.PendingRegistration{{ID: "reg_1", CreatedAt: at(-time.Hour), Pairing: true, CanRetry: false}},
		Items: []contract.NumberRow{{
			ID: vecNumber, Connection: "online", LastConnectedAt: ptr(at(-time.Minute)), Capture: "paused",
			PausedBy: &contract.PausedBy{Kind: contract.ActorPerson, Sub: ptr(vecSub), At: at(-time.Hour)}, CanResume: true,
			KeyEpoch: ptr[int64](3),
			MoveOut: &contract.MoveOut{
				Holders: []contract.Holder{{Kind: "person", Sub: ptr(vecOther), Row: "usr_42"}, {Kind: "token", Row: vecToken}},
				Ends:    []string{vecConnection},
			},
		}},
	}
	if mut != nil {
		mut(&s)
	}
	return s
}

func vecIntegrations(mut func(*contract.IntegrationsSettings)) contract.IntegrationsSettings {
	s := contract.IntegrationsSettings{
		AIEnabled: true,
		ServerOff: contract.ServerOff{Functions: []string{}, Providers: []string{}},
		ProviderKeys: []contract.ProviderKey{
			{ID: "pk_1", Provider: contract.AIOpenAI, Label: ptr("Equipe"), Owner: ptr(vecSub), CreatedAt: at(-48 * time.Hour)},
		},
		Integrations: []contract.AIIntegration{{
			ID: "ai_1", Name: ptr("Transcrições"), CreatedBy: ptr(vecSub), Status: "active",
			Functions: []contract.AIFunction{{ID: contract.AIAudio, On: true, Provider: contract.AIOpenAI}},
			Cap:       &contract.AICap{Limit: 500, Used: 12, Period: "month"},
			Items:     []string{vecNumber}, Alerts: []contract.AIAlert{},
			CreatedAt: at(-24 * time.Hour), ExpiresAt: ptr(at(90 * 24 * time.Hour)),
		}},
	}
	if mut != nil {
		mut(&s)
	}
	return s
}

func vecSwitches() []contract.MCPSwitch {
	return []contract.MCPSwitch{
		{Switch: contract.SwitchText, Set: ptr(true), Default: false, Operator: "allow", Effective: true, TokenEffective: ptr(true), Changeable: true},
		{Switch: contract.SwitchAttachments, Default: true, Operator: "allow", Effective: true, TokenEffective: ptr(true), Changeable: true},
		{Switch: contract.SwitchDrafts, Default: false, Operator: "allow", Effective: false, Changeable: true},
		{Switch: contract.SwitchAI, Set: ptr(false), Default: false, Operator: "deny", Effective: false, Changeable: false},
	}
}

func vecConnectionRow(mut func(*contract.MCPConnection)) contract.MCPConnection {
	c := contract.MCPConnection{
		ID: vecConnection, Name: ptr("Claude"), Kind: "content", Status: "active", Tier: "web_tested",
		VerifiedHost: ptr("claude.ai"), MainDomain: ptr("anthropic.com"), CallsItself: ptr("Claude"),
		Consent: contract.MCPConsent{Text: true, Send: "draft"}, Items: []string{vecNumber},
		CreatedAt: at(-72 * time.Hour), ActivatedAt: ptr(at(-71 * time.Hour)), FirstUsedAt: ptr(at(-70 * time.Hour)),
		LastUsedAt: ptr(at(-time.Hour)), ExpiresAt: ptr(at(30 * 24 * time.Hour)),
		BudgetHits: []contract.BudgetHit{{Code: "daily_messages", At: at(-2 * time.Hour)}},
		Consenter:  ptr(vecSub), SeenBy: []string{vecSub},
	}
	if mut != nil {
		mut(&c)
	}
	return c
}

func vecMCP(mut func(*contract.MCPSettings)) contract.MCPSettings {
	s := contract.MCPSettings{
		Switches: vecSwitches(), SwitchedAt: ptr(at(-24 * time.Hour)), SwitchedBy: ptr(vecSub),
		ServerAllows:    []string{contract.AllowMetadata, contract.AllowVerifiedReader},
		Connections:     []contract.MCPConnection{vecConnectionRow(nil)},
		RenewalsWaiting: []contract.RenewalsWaiting{{Consenter: ptr(vecSub), Count: 2}},
		LegacyTokens:    []contract.LegacyToken{{ID: "key_9", Name: ptr("Exportação antiga"), CreatedAt: at(-90 * 24 * time.Hour), CreatedBy: ptr(vecSub)}},
		Activity:        []contract.MCPActivity{{Day: "2026-10-12", Connection: vecConnection, Drafts: 3, Sends: 1}},
	}
	if mut != nil {
		mut(&s)
	}
	return s
}

func vecInstallations(mut func(*contract.InstallationsSettings)) contract.InstallationsSettings {
	s := contract.InstallationsSettings{
		Licences: contract.Licences{Used: 2, Capacity: ptr[int64](5)}, HostedNumbers: 3,
		Installations: []contract.Installation{{ID: "inst_1", Name: ptr("Matriz"), Origin: "https://wappie.example.com", CreatedAt: at(-30 * 24 * time.Hour)}},
		Bindings:      []contract.Binding{{ID: "bind_1", Installation: "inst_1", State: "active", BoundAt: at(-29 * 24 * time.Hour)}},
	}
	if mut != nil {
		mut(&s)
	}
	return s
}

func vecMailboxRow(mut func(*contract.MailboxRow)) contract.MailboxRow {
	m := contract.MailboxRow{
		ID: vecMailbox, Provider: "google", SignIn: "oauth", Status: "connected", ConnectedAt: ptr(at(-24 * time.Hour)),
		LinkedBy: ptr(vecSub), KeyEpoch: ptr[int64](1),
		Sync: contract.MailboxSync{
			Mode: contract.KindTeam, On: true,
			Agreement: &contract.SyncAgreement{By: ptr(vecSub), At: at(-24 * time.Hour), Revision: vecSyncText},
			Indexed:   "complete", LastSyncAt: ptr(at(-time.Minute)),
		},
	}
	if mut != nil {
		mut(&m)
	}
	return m
}

func vecEmailAccounts(mut func(*contract.EmailAccountsSettings)) contract.EmailAccountsSettings {
	s := contract.EmailAccountsSettings{
		Availability: "usable", LinkMinRole: ptr(contract.RoleAdmin), Texts: contract.TeamTexts{TeamSync: vecSyncText},
		Items: []contract.MailboxRow{vecMailboxRow(nil)},
	}
	if mut != nil {
		mut(&s)
	}
	return s
}

func vecPermissions(mut func(*contract.PermissionsSettings)) contract.PermissionsSettings {
	s := contract.PermissionsSettings{Members: []contract.PermissionsMember{
		{Sub: vecSub, Status: "active", Enrolled: true}, {Sub: vecOther, Status: "held", Enrolled: false},
	}}
	if mut != nil {
		mut(&s)
	}
	return s
}

// The notices of each code, with their params.
func wappieNotice(code string, n int) contract.Notice {
	params := map[string]any{
		contract.NoticeSyncPaused: contract.SyncPausedParams{Actor: ptr(vecOther), ActorKind: contract.ActorKey, SeveralActors: true,
			FirstAt: at(-3 * time.Hour), ResumedAt: ptr(at(-time.Hour))},
		contract.NoticeNumberDeleted:  contract.NumberDeletedParams{Actor: ptr(vecOther), Until: at(30 * 24 * time.Hour)},
		contract.NoticeNumberStranded: contract.NumberStrandedParams{Actor: nil, Until: ptr(at(29 * 24 * time.Hour))},
		contract.NoticeNumberMovedOut: contract.NumberMovedOutParams{Actor: ptr(vecOther)},
	}[code]
	version := int64(1)
	if code == contract.NoticeSyncPaused {
		version = 3
	}
	return contract.Notice{
		ID: fmt.Sprint(810 + n), Code: code, WorkspaceID: ptr(vecTeam), Item: ptr(vecNumber), At: at(-time.Hour),
		Version: version, Label: ptr("Vendas"), Hint: ptr("…5678"), Params: mustRaw(params),
	}
}

func mailieNotice(code string, n int) contract.Notice {
	params := map[string]any{
		contract.NoticeMailboxRemoved: contract.MailboxRemovedParams{State: "removed", RecoverableUntil: at(30 * 24 * time.Hour)},
		contract.NoticeMailboxSyncOff: contract.MailboxSyncOffParams{State: "live"},
		contract.NoticeMailboxSyncPaused: contract.MailboxSyncPausedParams{State: "live", Actor: ptr(vecOther),
			ActorKind: ptr(contract.ActorPerson)},
	}[code]
	return contract.Notice{
		ID: fmt.Sprintf("mbe_%d", n), Code: code, WorkspaceID: ptr(vecTeam), Item: ptr(vecMailbox), At: at(-time.Hour),
		Version: 1, Label: ptr("Suporte"), Hint: ptr("s…@example.com"), Params: mustRaw(params),
	}
}

func vecWappiePerson(mut func(*contract.WappiePersonSettings)) contract.WappiePersonSettings {
	s := contract.WappiePersonSettings{SignedOutEverywhereAt: ptr(at(-24 * time.Hour))}
	for i, code := range contract.NoticeCodes("wappie") {
		s.Notices = append(s.Notices, wappieNotice(code, i))
	}
	if mut != nil {
		mut(&s)
	}
	return s
}

func vecMailiePerson(mut func(*contract.MailiePersonSettings)) contract.MailiePersonSettings {
	s := contract.MailiePersonSettings{
		Consents: []contract.Consent{
			{Consent: contract.ConsentSync, State: "on", Revision: ptr(vecSyncText), AgreedAt: ptr(at(-24 * time.Hour))},
			{Consent: contract.ConsentActions, State: "old_text", Revision: ptr("2026-10-actions-1"), AgreedAt: ptr(at(-48 * time.Hour))},
			{Consent: contract.ConsentSend, State: "off", WithdrawnAt: ptr(at(-time.Hour))},
		},
		Texts:    contract.PersonTexts{Sync: vecSyncText, Actions: "2026-10-actions-2", Send: "2026-10-send-1", Keys: "2026-10-api-keys-2"},
		Enrolled: true,
	}
	for i, code := range contract.NoticeCodes("mailie") {
		s.Notices = append(s.Notices, mailieNotice(code, i))
	}
	if mut != nil {
		mut(&s)
	}
	return s
}

// sectionDoc is app's section document holding data, its header filled as
// the section's producer writes it.
func sectionDoc(app, section string, data any, mut func(*contract.SettingsDoc)) contract.SettingsDoc {
	d := contract.SettingsDoc{
		V: contract.SettingsV, Type: contract.SettingsType, App: app, Section: section,
		Producer: contract.SectionProducer(app, section), WorkspaceID: vecTeam, StateSeq: vecSeq, SnapshotSeq: ptr(vecSeq),
		MeasuredAt: contract.T(Now), Accepts: []string{}, Data: mustRaw(data),
	}
	if d.Producer == contract.ProducerWappieCloud {
		d.SnapshotSeq = nil
	}
	for _, k := range contract.CommandKinds(app) {
		if k.Section == section {
			d.Accepts = append(d.Accepts, k.Kind)
		}
	}
	if mut != nil {
		mut(&d)
	}
	return d
}

func personDoc(app string, data any, mut func(*contract.PersonSettingsDoc)) contract.PersonSettingsDoc {
	d := contract.PersonSettingsDoc{
		V: contract.SettingsV, Type: contract.PersonSettingsType, App: app, Producer: contract.SectionProducer(app, contract.SectionPerson),
		Sub: vecSub, StateSeq: vecSeq, MeasuredAt: contract.T(Now), Accepts: []string{}, Data: mustRaw(data),
	}
	for _, k := range contract.CommandKinds(app) {
		if k.Section == contract.SectionPerson {
			d.Accepts = append(d.Accepts, k.Kind)
		}
	}
	if mut != nil {
		mut(&d)
	}
	return d
}

// many is n values made by f from 0 to n-1.
func many[T any](n int, f func(int) T) []T {
	out := make([]T, n)
	for i := range out {
		out[i] = f(i)
	}
	return out
}

// exactDecode decodes raw as the platform decodes what an app sends: one
// object of valid UTF-8, no escape of half a surrogate pair, no member twice,
// none dst does not have, every name exactly as written, and every member
// present but the optional ones. It is the test's own reading, apart from
// the package's, so that the vectors hold the package to it.
func exactDecode(raw []byte, dst any) error {
	if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) || !strictJSON(raw) || !exactNames(raw, reflect.TypeOf(dst)) {
		return errors.New("not strict")
	}
	return strictDecode(raw, dst)
}

// strictJSON is one well-formed JSON value with no member twice and no
// lone surrogate escaped.
func strictJSON(raw []byte) bool {
	if bytes.Contains(bytes.ToLower(raw), []byte(`\ud`)) {
		// The vectors escape no surrogate but to refuse one.
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var walk func() bool
	walk = func() bool {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		switch tok {
		case json.Delim('{'):
			seen := map[string]bool{}
			for dec.More() {
				t, err := dec.Token()
				name, ok := t.(string)
				if err != nil || !ok || seen[name] {
					return false
				}
				seen[name] = true
				if !walk() {
					return false
				}
			}
			_, err := dec.Token()
			return err == nil
		case json.Delim('['):
			for dec.More() {
				if !walk() {
					return false
				}
			}
			_, err := dec.Token()
			return err == nil
		}
		return true
	}
	if !walk() {
		return false
	}
	_, err := dec.Token()
	return errors.Is(err, io.EOF)
}

// exactNames checks the names of every object raw holds against t's, and
// that null stands only where t holds a pointer.
func exactNames(raw json.RawMessage, t reflect.Type) bool {
	pointer := false
	for t.Kind() == reflect.Pointer {
		t, pointer = t.Elem(), true
	}
	if _, ok := reflect.New(t).Interface().(json.Unmarshaler); ok {
		return true
	}
	if string(bytes.TrimSpace(raw)) == "null" {
		return pointer
	}
	switch t.Kind() {
	case reflect.Struct:
		var members map[string]json.RawMessage
		if json.Unmarshal(raw, &members) != nil || members == nil {
			return true
		}
		fields := map[string]reflect.StructField{}
		for i := 0; i < t.NumField(); i++ {
			name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
			if name != "" && name != "-" {
				fields[name] = t.Field(i)
			}
		}
		for name, v := range members {
			f, ok := fields[name]
			if !ok || !exactNames(v, f.Type) {
				return false
			}
		}
		for name, f := range fields {
			if _, ok := members[name]; !ok && !strings.Contains(f.Tag.Get("json"), "omit") {
				return false
			}
		}
	case reflect.Slice:
		var elems []json.RawMessage
		if json.Unmarshal(raw, &elems) == nil {
			for _, e := range elems {
				if !exactNames(e, t.Elem()) {
					return false
				}
			}
		}
	}
	return true
}

// sectionValid is what the platform makes of a section's document: within
// its call's limit, decoded strictly, and valid.
func sectionValid(raw []byte) bool {
	var d contract.SettingsDoc
	return len(raw) <= contract.SettingsBodyLimit && exactDecode(raw, &d) == nil && d.Validate() == nil
}

// personValid is the same for a person's document.
func personValid(raw []byte) bool {
	var d contract.PersonSettingsDoc
	return len(raw) <= contract.PersonSettingsBodyLimit && exactDecode(raw, &d) == nil && d.Validate() == nil
}

// WireSettings is wire-settings.json.
type WireSettings struct {
	Format      string     `json:"format"`
	Version     int        `json:"version"`
	Kind        string     `json:"kind"`
	Description string     `json:"description"`
	Sections    []WireCase `json:"sections"`
	Persons     []WireCase `json:"persons"`
}

// settingsCase is one case and the validity the design asks of it.
type settingsCase struct {
	name  string
	raw   json.RawMessage
	valid bool
}

// edit is raw with old replaced by new once; it panics when old is not
// there, so a case never silently tests nothing.
func edit(raw json.RawMessage, old, new string) json.RawMessage {
	out, err := replaceOnce(raw, old, new)
	if err != nil {
		panic(err)
	}
	return out
}

func wireSettings() (any, error) {
	out := WireSettings{
		Format: Format, Version: 1, Kind: "wire-settings",
		Description: "The settings part's documents (SPEC section 11.19), each valid when it is within its call's body limit, 1 MiB for a section and 256 KiB for a person, decodes as the platform decodes what an app sends (strictly: one object, no member twice, no member it does not know, every name exactly as written, every member present, null only where a member may be null), and its Validate accepts it, data and all: sections are contract.SettingsDoc (PUT /contract/v1/workspaces/{id}/settings/{section}), persons contract.PersonSettingsDoc (PUT /contract/v1/accounts/{sub}/settings). Every closed list's every code appears in a valid case.",
	}
	w := func(mut func(*contract.SettingsDoc), data any) json.RawMessage {
		return mustRaw(sectionDoc("wappie", contract.SectionNumbers, data, mut))
	}
	sec := func(app, section string, data any) json.RawMessage {
		return mustRaw(sectionDoc(app, section, data, nil))
	}
	numbers := func(mut func(*contract.NumbersSettings)) json.RawMessage {
		return sec("wappie", contract.SectionNumbers, vecNumbers(mut))
	}
	integrations := func(mut func(*contract.IntegrationsSettings)) json.RawMessage {
		return sec("wappie", contract.SectionIntegrations, vecIntegrations(mut))
	}
	mcp := func(mut func(*contract.MCPSettings)) json.RawMessage {
		return sec("wappie", contract.SectionMCP, vecMCP(mut))
	}
	installations := func(mut func(*contract.InstallationsSettings)) json.RawMessage {
		return sec("wappie", contract.SectionInstallations, vecInstallations(mut))
	}
	emails := func(mut func(*contract.EmailAccountsSettings)) json.RawMessage {
		return sec("mailie", contract.SectionEmailAccounts, vecEmailAccounts(mut))
	}
	permissions := func(mut func(*contract.PermissionsSettings)) json.RawMessage {
		return sec("mailie", contract.SectionPermissions, vecPermissions(mut))
	}
	connection := func(mut func(*contract.MCPConnection)) json.RawMessage {
		return mcp(func(s *contract.MCPSettings) { s.Connections = []contract.MCPConnection{vecConnectionRow(mut)} })
	}
	row := func(mut func(*contract.NumberRow)) json.RawMessage {
		return numbers(func(s *contract.NumbersSettings) { mut(&s.Items[0]) })
	}
	mailbox := func(mut func(*contract.MailboxRow)) json.RawMessage {
		return emails(func(s *contract.EmailAccountsSettings) { s.Items = []contract.MailboxRow{vecMailboxRow(mut)} })
	}
	integration := func(mut func(*contract.AIIntegration)) json.RawMessage {
		return integrations(func(s *contract.IntegrationsSettings) { mut(&s.Integrations[0]) })
	}
	holders := func(n int) []contract.Holder {
		return many(n, func(i int) contract.Holder {
			return contract.Holder{Kind: "person", Sub: ptr(vecOther), Row: fmt.Sprintf("usr_%04d", i)}
		})
	}
	ids := func(prefix string, n int) []string {
		return many(n, func(i int) string { return fmt.Sprintf("%s%04d", prefix, i) })
	}
	sub := func(i int) string { return fmt.Sprintf("0199a0c2-0000-7000-8000-%012d", i+1) }
	subs := func(n int) []string { return many(n, sub) }
	label80 := strings.Repeat("Matriz ", 11) + "Sul"
	sections := []settingsCase{
		// Wappie: numbers.
		{"Wappie's numbers", numbers(nil), true},
		{"a number paused by a token, through its creator", row(func(r *contract.NumberRow) { r.PausedBy.Kind = contract.ActorKey }), true},
		{"a number paused by the app, no sub", row(func(r *contract.NumberRow) {
			r.PausedBy = &contract.PausedBy{Kind: contract.ActorApp, At: at(-time.Hour)}
		}), true},
		{"a number paused by someone with no sub", row(func(r *contract.NumberRow) { r.PausedBy.Sub = nil }), true},
		{"every connection state", numbers(func(s *contract.NumbersSettings) {
			s.Items = nil
			for i, state := range []string{"pairing", "online", "offline", "logged_out_phone", "logged_out_deletion", "banned"} {
				s.Items = append(s.Items, contract.NumberRow{ID: fmt.Sprintf("dev_%d", i), Connection: state, Capture: "on",
					ReadOnly: strings.HasPrefix(state, "logged_out") || state == "banned"})
			}
		}), true},
		{"a move-out preview with every kind of holder", row(func(r *contract.NumberRow) {
			r.MoveOut.Holders = nil
			for i, kind := range []string{"person", "service_account", "assistant", "ai", "legacy_key", "token"} {
				r.MoveOut.Holders = append(r.MoveOut.Holders, contract.Holder{Kind: kind, Row: fmt.Sprintf("row_%d", i)})
			}
		}), true},
		{"a deleted number that can still be recovered, with its bytes", row(func(r *contract.NumberRow) {
			r.RecoveryOpen, r.MoveOut, r.Bytes = true, nil, ptr[int64](1<<30)
		}), true},
		{"no free place known yet", numbers(func(s *contract.NumbersSettings) { s.PlacesFree = nil }), true},
		{"500 move-out holders and 7 more", row(func(r *contract.NumberRow) { r.MoveOut.Holders, r.MoveOut.HoldersMore = holders(500), 7 }), true},
		{"501 move-out holders", row(func(r *contract.NumberRow) { r.MoveOut.Holders = holders(501) }), false},
		{"holders_more beside 499 holders", row(func(r *contract.NumberRow) { r.MoveOut.Holders, r.MoveOut.HoldersMore = holders(499), 1 }), false},
		{"500 connections a move ends", row(func(r *contract.NumberRow) { r.MoveOut.Ends = ids("conn_", 500) }), true},
		{"501 connections a move ends", row(func(r *contract.NumberRow) { r.MoveOut.Ends = ids("conn_", 501) }), false},
		{"50 pending registrations", numbers(func(s *contract.NumbersSettings) {
			s.Pending = many(50, func(i int) contract.PendingRegistration {
				return contract.PendingRegistration{ID: fmt.Sprintf("reg_%d", i), CreatedAt: at(-time.Hour)}
			})
		}), true},
		{"51 pending registrations", numbers(func(s *contract.NumbersSettings) {
			s.Pending = many(51, func(i int) contract.PendingRegistration {
				return contract.PendingRegistration{ID: fmt.Sprintf("reg_%d", i), CreatedAt: at(-time.Hour)}
			})
		}), false},
		{"1000 numbers", numbers(func(s *contract.NumbersSettings) {
			s.Items = many(1000, func(i int) contract.NumberRow {
				return contract.NumberRow{ID: fmt.Sprintf("dev_%04d", i), Connection: "online", Capture: "on"}
			})
		}), true},
		{"1001 numbers", numbers(func(s *contract.NumbersSettings) {
			s.Items = many(1001, func(i int) contract.NumberRow {
				return contract.NumberRow{ID: fmt.Sprintf("dev_%04d", i), Connection: "online", Capture: "on"}
			})
		}), false},
		{"an unknown connection state", row(func(r *contract.NumberRow) { r.Connection = "needs_reauth" }), false},
		{"last_error-like free text in a code's place", row(func(r *contract.NumberRow) { r.Connection = "Stream errored (conflict)" }), false},
		{"who paused a number that captures", row(func(r *contract.NumberRow) { r.Capture = "on" }), false},
		{"the app's pause naming a sub", row(func(r *contract.NumberRow) { r.PausedBy.Kind = contract.ActorApp }), false},
		{"a move-out holder of an unknown kind", row(func(r *contract.NumberRow) { r.MoveOut.Holders[0].Kind = "admin" }), false},
		{"a number listed twice", numbers(func(s *contract.NumbersSettings) { s.Items = append(s.Items, s.Items[0]) }), false},

		// Wappie: integrations.
		{"Wappie's integrations", integrations(nil), true},
		{"every AI function and provider turned off by the server", integrations(func(s *contract.IntegrationsSettings) {
			s.ServerOff = contract.ServerOff{Functions: contract.AIFunctions(), Providers: contract.AIProviders()}
		}), true},
		{"each function with its provider, and each alert", integration(func(in *contract.AIIntegration) {
			in.Status = "paused"
			in.Functions = []contract.AIFunction{
				{ID: contract.AIAudio, On: true, Provider: contract.AIGoogle}, {ID: contract.AIVideo, On: false, Provider: contract.AIGoogle},
				{ID: contract.AIImage, On: true, Provider: contract.AIAnthropic}, {ID: contract.AIDocument, On: true, Provider: contract.AIOpenAI},
			}
			in.Alerts = []contract.AIAlert{
				{Code: "ai_key_rejected", Provider: ptr(contract.AIOpenAI), At: at(-time.Hour)},
				{Code: "ai_quota", Function: ptr(contract.AIAudio), Provider: ptr(contract.AIGoogle), At: at(-time.Hour)},
				{Code: "ai_model_unavailable", Function: ptr(contract.AIImage), At: at(-time.Hour)},
			}
		}), true},
		{"a provider key of each provider, one without a label", integrations(func(s *contract.IntegrationsSettings) {
			s.ProviderKeys = nil
			for i, p := range contract.AIProviders() {
				s.ProviderKeys = append(s.ProviderKeys, contract.ProviderKey{ID: fmt.Sprintf("pk_%d", i), Provider: p, Label: ptr("Equipe"), CreatedAt: at(-time.Hour)})
			}
			s.ProviderKeys[0].Label, s.ProviderKeys[0].Owner = nil, nil
		}), true},
		{"every integration status, and an ended one with each revoke reason", integrations(func(s *contract.IntegrationsSettings) {
			base := s.Integrations[0]
			s.Integrations = nil
			for i, status := range []string{"pending", "active", "paused", "reseal"} {
				in := base
				in.ID, in.Status = fmt.Sprintf("ai_%d", i), status
				s.Integrations = append(s.Integrations, in)
			}
			for i, reason := range contract.EndReasons() {
				in := base
				in.ID, in.Status, in.EndedAt, in.EndReason = fmt.Sprintf("ai_end_%d", i), "ended", ptr(at(-time.Hour)), ptr(reason)
				s.Integrations = append(s.Integrations, in)
			}
		}), true},
		{"an integration with no cap, name or expiry", integration(func(in *contract.AIIntegration) { in.Cap, in.Name, in.ExpiresAt = nil, nil, nil }), true},
		{"200 provider keys", integrations(func(s *contract.IntegrationsSettings) {
			s.ProviderKeys = many(200, func(i int) contract.ProviderKey {
				return contract.ProviderKey{ID: fmt.Sprintf("pk_%d", i), Provider: contract.AIGoogle, CreatedAt: at(-time.Hour)}
			})
		}), true},
		{"201 provider keys", integrations(func(s *contract.IntegrationsSettings) {
			s.ProviderKeys = many(201, func(i int) contract.ProviderKey {
				return contract.ProviderKey{ID: fmt.Sprintf("pk_%d", i), Provider: contract.AIGoogle, CreatedAt: at(-time.Hour)}
			})
		}), false},
		{"500 integrations", integrations(func(s *contract.IntegrationsSettings) {
			base := s.Integrations[0]
			s.Integrations = many(500, func(i int) contract.AIIntegration { in := base; in.ID = fmt.Sprintf("ai_%d", i); return in })
		}), true},
		{"501 integrations", integrations(func(s *contract.IntegrationsSettings) {
			base := s.Integrations[0]
			s.Integrations = many(501, func(i int) contract.AIIntegration { in := base; in.ID = fmt.Sprintf("ai_%d", i); return in })
		}), false},
		{"an integration on 1000 numbers", integration(func(in *contract.AIIntegration) { in.Items = ids("dev_", 1000) }), true},
		{"an integration on 1001 numbers", integration(func(in *contract.AIIntegration) { in.Items = ids("dev_", 1001) }), false},
		{"an unknown AI provider", integration(func(in *contract.AIIntegration) { in.Functions[0].Provider = "mistral" }), false},
		{"a function named by what it gives", integration(func(in *contract.AIIntegration) { in.Functions[0].ID = "transcription" }), false},
		{"a function twice", integration(func(in *contract.AIIntegration) { in.Functions = append(in.Functions, in.Functions[0]) }), false},
		{"server_off naming a provider twice", integrations(func(s *contract.IntegrationsSettings) {
			s.ServerOff.Providers = []string{contract.AIOpenAI, contract.AIOpenAI}
		}), false},
		{"an alert twice for one code, function and provider", integration(func(in *contract.AIIntegration) {
			alert := contract.AIAlert{Code: "ai_quota", Provider: ptr(contract.AIOpenAI), At: at(-time.Hour)}
			in.Alerts = []contract.AIAlert{alert, alert}
		}), false},
		{"an unknown AI alert", integration(func(in *contract.AIIntegration) {
			in.Alerts = []contract.AIAlert{{Code: "ai_down", At: at(-time.Hour)}}
		}), false},
		{"an ended integration with no ended_at", integration(func(in *contract.AIIntegration) { in.Status = "ended" }), false},
		{"ended_at on an integration not ended", integration(func(in *contract.AIIntegration) { in.EndedAt = ptr(at(-time.Hour)) }), false},
		{"a revoke reason with no ended_at", integration(func(in *contract.AIIntegration) { in.EndReason = ptr("console") }), false},
		{"an unknown revoke reason", integration(func(in *contract.AIIntegration) {
			in.Status, in.EndedAt, in.EndReason = "ended", ptr(at(-time.Hour)), ptr("user_deleted")
		}), false},
		{"a provider key's label with an address", integrations(func(s *contract.IntegrationsSettings) { s.ProviderKeys[0].Label = ptr("ana@example.com") }), false},

		// Wappie: mcp.
		{"Wappie's mcp", mcp(nil), true},
		{"every server_allows code, in its order", mcp(func(s *contract.MCPSettings) { s.ServerAllows = contract.ServerAllows() }), true},
		{"server_allows empty: the connector is off", mcp(func(s *contract.MCPSettings) { s.ServerAllows = []string{} }), true},
		{"a switch whose token_effective differs from its effective", mcp(func(s *contract.MCPSettings) { s.Switches[0].Effective = false }), true},
		{"no switch changed yet", mcp(func(s *contract.MCPSettings) { s.SwitchedAt, s.SwitchedBy = nil, nil }), true},
		{"a switch changed by someone with no sub", mcp(func(s *contract.MCPSettings) { s.SwitchedBy = nil }), true},
		{"history_days of 7, 30, 90 and none", mcp(func(s *contract.MCPSettings) {
			s.Connections = nil
			for i, days := range []*int{ptr(7), ptr(30), ptr(90), nil} {
				s.Connections = append(s.Connections, vecConnectionRow(func(c *contract.MCPConnection) {
					c.ID, c.Tier, c.HistoryDays = fmt.Sprintf("conn_%d", i), "unknown", days
				}))
			}
		}), true},
		{"every connection kind, status and tier", mcp(func(s *contract.MCPSettings) {
			s.Connections = nil
			for i, kind := range []string{"metadata", "content"} {
				for j, status := range []string{"pending", "active", "reseal", "revoked", "expired"} {
					for k, tier := range []string{"web_tested", "local_tested", "unknown", "token"} {
						s.Connections = append(s.Connections, vecConnectionRow(func(c *contract.MCPConnection) {
							c.ID, c.Kind, c.Status, c.Tier = fmt.Sprintf("conn_%d_%d_%d", i, j, k), kind, status, tier
							if tier == "token" {
								c.VerifiedHost, c.MainDomain = nil, nil
							}
							if status == "revoked" || status == "expired" {
								c.EndedAt, c.EndReason = ptr(at(-time.Hour)), ptr("console")
							}
						}))
					}
				}
			}
		}), true},
		{"each budget hit, each way of sending and each revoke reason", mcp(func(s *contract.MCPSettings) {
			s.Connections = nil
			for i, send := range []string{"off", "draft", "direct"} {
				s.Connections = append(s.Connections, vecConnectionRow(func(c *contract.MCPConnection) {
					c.ID, c.Consent = fmt.Sprintf("conn_send_%d", i), contract.MCPConsent{Text: true, Attachments: true, Send: send, OwnChat: true, Groups: true}
					c.BudgetHits = many(len(contract.BudgetHits()), func(j int) contract.BudgetHit {
						return contract.BudgetHit{Code: contract.BudgetHits()[j], At: at(-time.Hour)}
					})
				}))
			}
			for i, reason := range contract.EndReasons() {
				s.Connections = append(s.Connections, vecConnectionRow(func(c *contract.MCPConnection) {
					c.ID, c.Status, c.EndedAt, c.EndReason = fmt.Sprintf("conn_end_%d", i), "revoked", ptr(at(-time.Hour)), ptr(reason)
				}))
			}
		}), true},
		{"a token connection names no host", connection(func(c *contract.MCPConnection) { c.Tier, c.VerifiedHost, c.MainDomain = "token", nil, nil }), true},
		{"a connection that calls itself nothing", connection(func(c *contract.MCPConnection) { c.Name, c.CallsItself = nil, nil }), true},
		{"500 connections", mcp(func(s *contract.MCPSettings) {
			s.Connections = many(500, func(i int) contract.MCPConnection {
				return vecConnectionRow(func(c *contract.MCPConnection) { c.ID = fmt.Sprintf("conn_%d", i) })
			})
		}), true},
		{"501 connections", mcp(func(s *contract.MCPSettings) {
			s.Connections = many(501, func(i int) contract.MCPConnection {
				return vecConnectionRow(func(c *contract.MCPConnection) { c.ID = fmt.Sprintf("conn_%d", i) })
			})
		}), false},
		{"a connection on 1000 numbers", connection(func(c *contract.MCPConnection) { c.Items = ids("dev_", 1000) }), true},
		{"a connection on 1001 numbers", connection(func(c *contract.MCPConnection) { c.Items = ids("dev_", 1001) }), false},
		{"6 budget hits", connection(func(c *contract.MCPConnection) {
			c.BudgetHits = many(6, func(j int) contract.BudgetHit {
				return contract.BudgetHit{Code: contract.BudgetHits()[j%5], At: at(-time.Hour)}
			})
		}), false},
		{"seen by 5000", connection(func(c *contract.MCPConnection) { c.SeenBy = subs(5000) }), true},
		{"seen by 5001", connection(func(c *contract.MCPConnection) { c.SeenBy = subs(5001) }), false},
		{"5000 consenters waiting for renewals", mcp(func(s *contract.MCPSettings) {
			s.RenewalsWaiting = many(5000, func(i int) contract.RenewalsWaiting {
				return contract.RenewalsWaiting{Consenter: ptr(sub(i)), Count: 1}
			})
			s.RenewalsWaiting[0].Consenter = nil
		}), true},
		{"5001 consenters waiting for renewals", mcp(func(s *contract.MCPSettings) {
			s.RenewalsWaiting = many(5001, func(i int) contract.RenewalsWaiting {
				return contract.RenewalsWaiting{Consenter: ptr(sub(i)), Count: 1}
			})
		}), false},
		{"200 legacy tokens", mcp(func(s *contract.MCPSettings) {
			s.LegacyTokens = many(200, func(i int) contract.LegacyToken {
				return contract.LegacyToken{ID: fmt.Sprintf("key_%d", i), CreatedAt: at(-time.Hour)}
			})
		}), true},
		{"201 legacy tokens", mcp(func(s *contract.MCPSettings) {
			s.LegacyTokens = many(201, func(i int) contract.LegacyToken {
				return contract.LegacyToken{ID: fmt.Sprintf("key_%d", i), CreatedAt: at(-time.Hour)}
			})
		}), false},
		{"5000 days of activity", mcp(func(s *contract.MCPSettings) {
			s.Activity = many(5000, func(i int) contract.MCPActivity {
				return contract.MCPActivity{Day: Now.AddDate(0, 0, -1-i%30).Format(time.DateOnly), Connection: fmt.Sprintf("conn_%d", i/30), Drafts: 1}
			})
		}), true},
		{"5001 days of activity", mcp(func(s *contract.MCPSettings) {
			s.Activity = many(5001, func(i int) contract.MCPActivity {
				return contract.MCPActivity{Day: Now.AddDate(0, 0, -1-i%30).Format(time.DateOnly), Connection: fmt.Sprintf("conn_%d", i/30), Sends: 1}
			})
		}), false},
		{"a truncated section: its oldest days of activity cut", w(func(d *contract.SettingsDoc) {
			d.Section, d.Truncated, d.Accepts = contract.SectionMCP, true, []string{contract.OpMCPConnectionRevoke}
		}, vecMCP(nil)), true},
		{"server_allows with a code twice", mcp(func(s *contract.MCPSettings) {
			s.ServerAllows = []string{contract.AllowMetadata, contract.AllowMetadata}
		}), false},
		{"server_allows out of order", mcp(func(s *contract.MCPSettings) {
			s.ServerAllows = []string{contract.AllowVerifiedReader, contract.AllowMetadata}
		}), false},
		{"an unknown server_allows code", mcp(func(s *contract.MCPSettings) { s.ServerAllows = []string{"text"} }), false},
		{"token_effective on drafts", mcp(func(s *contract.MCPSettings) { s.Switches[2].TokenEffective = ptr(false) }), false},
		{"token_effective on ai", mcp(func(s *contract.MCPSettings) { s.Switches[3].TokenEffective = ptr(false) }), false},
		{"no token_effective on text", mcp(func(s *contract.MCPSettings) { s.Switches[0].TokenEffective = nil }), false},
		{"three switches", mcp(func(s *contract.MCPSettings) { s.Switches = s.Switches[:3] }), false},
		{"a switch twice", mcp(func(s *contract.MCPSettings) { s.Switches[3] = s.Switches[0] }), false},
		{"a switch the operator denies, effective", mcp(func(s *contract.MCPSettings) { s.Switches[3].Effective = true }), false},
		{"consent.send outside off, draft and direct", connection(func(c *contract.MCPConnection) { c.Consent.Send = "auto" }), false},
		{"history_days of 60", connection(func(c *contract.MCPConnection) { c.HistoryDays = ptr(60) }), false},
		{"a token connection with a host", connection(func(c *contract.MCPConnection) { c.Tier = "token" }), false},
		{"a host in capitals", connection(func(c *contract.MCPConnection) { c.VerifiedHost = ptr("Claude.AI") }), false},
		{"a host that is an address", connection(func(c *contract.MCPConnection) { c.MainDomain = ptr("10.0.0.1") }), false},
		{"a name with an @", connection(func(c *contract.MCPConnection) { c.Name = ptr("bot@example.com") }), false},
		{"a name that calls itself with a run of 7 digits", connection(func(c *contract.MCPConnection) { c.CallsItself = ptr("Bot 5511912345678") }), false},
		{"a revoke reason on a live connection", connection(func(c *contract.MCPConnection) { c.EndReason = ptr("console") }), false},
		{"a day of no activity", mcp(func(s *contract.MCPSettings) { s.Activity[0].Drafts, s.Activity[0].Sends = 0, 0 }), false},

		// Wappie: installations, from Wappie Cloud.
		{"Wappie Cloud's installations, with no snapshot_seq", installations(nil), true},
		{"a public IPv4 origin with a port", installations(func(s *contract.InstallationsSettings) {
			s.Installations[0].Origin = "https://8.8.8.8:8443"
		}), true},
		{"no capacity, a reserved binding with a label and an expiry", installations(func(s *contract.InstallationsSettings) {
			s.Licences.Capacity = nil
			s.Bindings[0].State, s.Bindings[0].Label, s.Bindings[0].ExpiresAt = "reserved", ptr("Loja Centro"), ptr(at(24*time.Hour))
		}), true},
		{"an installation's name of 80 code points", installations(func(s *contract.InstallationsSettings) { s.Installations[0].Name = ptr(label80) }), true},
		{"an installation's name of 81 code points", installations(func(s *contract.InstallationsSettings) { s.Installations[0].Name = ptr(label80 + "!") }), false},
		{"an installation's name that cleans to nothing: null", installations(func(s *contract.InstallationsSettings) { s.Installations[0].Name = nil }), true},
		{"200 installations", installations(func(s *contract.InstallationsSettings) {
			s.Installations = many(200, func(i int) contract.Installation {
				return contract.Installation{ID: fmt.Sprintf("inst_%d", i), Origin: fmt.Sprintf("https://w%d.example.com", i), CreatedAt: at(-time.Hour)}
			})
		}), true},
		{"201 installations", installations(func(s *contract.InstallationsSettings) {
			s.Installations = many(201, func(i int) contract.Installation {
				return contract.Installation{ID: fmt.Sprintf("inst_%d", i), Origin: fmt.Sprintf("https://w%d.example.com", i), CreatedAt: at(-time.Hour)}
			})
		}), false},
		{"1000 bindings", installations(func(s *contract.InstallationsSettings) {
			s.Bindings = many(1000, func(i int) contract.Binding {
				return contract.Binding{ID: fmt.Sprintf("bind_%d", i), Installation: "inst_1", State: "active", BoundAt: at(-time.Hour)}
			})
		}), true},
		{"1001 bindings", installations(func(s *contract.InstallationsSettings) {
			s.Bindings = many(1001, func(i int) contract.Binding {
				return contract.Binding{ID: fmt.Sprintf("bind_%d", i), Installation: "inst_1", State: "active", BoundAt: at(-time.Hour)}
			})
		}), false},
		{"an origin with a path", installations(func(s *contract.InstallationsSettings) { s.Installations[0].Origin = "https://wappie.example.com/app" }), false},
		{"an origin over http", installations(func(s *contract.InstallationsSettings) { s.Installations[0].Origin = "http://wappie.example.com" }), false},
		{"an origin with user information", installations(func(s *contract.InstallationsSettings) {
			s.Installations[0].Origin = "https://ana@wappie.example.com"
		}), false},
		{"an origin with a query", installations(func(s *contract.InstallationsSettings) { s.Installations[0].Origin = "https://wappie.example.com?x=1" }), false},
		{"a private IPv4 origin", installations(func(s *contract.InstallationsSettings) { s.Installations[0].Origin = "https://192.168.1.10" }), false},
		{"a port of 0", installations(func(s *contract.InstallationsSettings) { s.Installations[0].Origin = "https://wappie.example.com:0" }), false},
		{"a binding's label with a run of 7 digits", installations(func(s *contract.InstallationsSettings) { s.Bindings[0].Label = ptr("+55 11 91234-5678") }), false},
		{"an unknown binding state", installations(func(s *contract.InstallationsSettings) { s.Bindings[0].State = "expired" }), false},
		{"snapshot_seq from Wappie Cloud", mustRaw(sectionDoc("wappie", contract.SectionInstallations, vecInstallations(nil), func(d *contract.SettingsDoc) {
			d.SnapshotSeq = ptr(vecSeq)
		})), false},

		// Mailie: email-accounts.
		{"Mailie's email accounts", emails(nil), true},
		{"every provider, status and reason", emails(func(s *contract.EmailAccountsSettings) {
			s.Items = nil
			n, reason := 0, 0
			for _, provider := range []string{"google", "microsoft", "icloud", "imap"} {
				for _, status := range []string{"connected", "needs_reauth", "pending_auth", "error", "removed"} {
					s.Items = append(s.Items, vecMailboxRow(func(m *contract.MailboxRow) {
						m.ID, m.Provider, m.Status = fmt.Sprintf("acc_%d", n), provider, status
						if provider == "imap" || provider == "icloud" {
							m.SignIn = "password"
						}
						if status == "removed" {
							m.Removed = &contract.MailboxRemoved{RemovedAt: at(-time.Hour), PurgeAfter: at(30 * 24 * time.Hour), IndexKept: true}
						}
						if status == "error" || status == "needs_reauth" {
							m.Reason = ptr([]string{"scope_missing", "mailbox_refused", "token_rejected", "unproved", "other"}[reason%5])
							reason++
						}
					}))
					n++
				}
			}
		}), true},
		{"a paused team mailbox and a held personal one", emails(func(s *contract.EmailAccountsSettings) {
			s.Items = []contract.MailboxRow{
				vecMailboxRow(func(m *contract.MailboxRow) {
					m.Sync.Paused = &contract.SyncPause{By: ptr(vecOther), Kind: contract.ActorPerson, At: at(-time.Hour)}
					m.Sync.Indexed = "partial"
				}),
				vecMailboxRow(func(m *contract.MailboxRow) {
					m.ID, m.Sync.Mode, m.Sync.Agreement, m.Sync.On, m.Sync.Held, m.Sync.Indexed = "acc_personal", contract.KindPersonal, nil, false, true, "none"
				}),
			}
		}), true},
		{"a consent bound by migration 0011", mailbox(func(m *contract.MailboxRow) { m.Sync.Agreement.Bound, m.Sync.Agreement.By = true, nil }), true},
		{"a withheld team where nobody may link", emails(func(s *contract.EmailAccountsSettings) { s.Availability, s.LinkMinRole = "withheld", nil }), true},
		{"1000 mailboxes", emails(func(s *contract.EmailAccountsSettings) {
			s.Items = many(1000, func(i int) contract.MailboxRow {
				return vecMailboxRow(func(m *contract.MailboxRow) { m.ID = fmt.Sprintf("acc_%04d", i) })
			})
		}), true},
		{"1001 mailboxes", emails(func(s *contract.EmailAccountsSettings) {
			s.Items = many(1001, func(i int) contract.MailboxRow {
				return vecMailboxRow(func(m *contract.MailboxRow) { m.ID = fmt.Sprintf("acc_%04d", i) })
			})
		}), false},
		{"Mailie's sync.held on a team mailbox", mailbox(func(m *contract.MailboxRow) { m.Sync.Held = true }), false},
		{"an agreement on a personal mailbox", mailbox(func(m *contract.MailboxRow) { m.Sync.Mode = contract.KindPersonal }), false},
		{"a reason on a connected mailbox", mailbox(func(m *contract.MailboxRow) { m.Reason = ptr("other") }), false},
		{"last_error text in a reason's place", mailbox(func(m *contract.MailboxRow) {
			m.Status, m.Reason = "error", ptr("AUTHENTICATIONFAILED Invalid credentials")
		}), false},
		{"a removed mailbox without its window", mailbox(func(m *contract.MailboxRow) { m.Status = "removed" }), false},
		{"a pause by a key", mailbox(func(m *contract.MailboxRow) {
			m.Sync.Paused = &contract.SyncPause{By: ptr(vecOther), Kind: contract.ActorKey, At: at(-time.Hour)}
		}), false},
		{"an unknown provider", mailbox(func(m *contract.MailboxRow) { m.Provider = "yahoo" }), false},
		{"an unknown availability", emails(func(s *contract.EmailAccountsSettings) { s.Availability = "open" }), false},

		// Mailie: permissions.
		{"Mailie's permissions, each status", permissions(func(s *contract.PermissionsSettings) {
			s.Members = nil
			for i, status := range []string{"active", "suspended", "held", "disabled"} {
				s.Members = append(s.Members, contract.PermissionsMember{Sub: sub(i), Status: status, Enrolled: i%2 == 0})
			}
		}), true},
		{"5000 members", permissions(func(s *contract.PermissionsSettings) {
			s.Members = many(5000, func(i int) contract.PermissionsMember {
				return contract.PermissionsMember{Sub: sub(i), Status: "active"}
			})
		}), true},
		{"5001 members", permissions(func(s *contract.PermissionsSettings) {
			s.Members = many(5001, func(i int) contract.PermissionsMember {
				return contract.PermissionsMember{Sub: sub(i), Status: "active"}
			})
		}), false},
		{"a member twice", permissions(func(s *contract.PermissionsSettings) { s.Members[1].Sub = vecSub }), false},
		{"an unknown member status", permissions(func(s *contract.PermissionsSettings) { s.Members[1].Status = "invited" }), false},

		// Every closed code in a valid case, and the rules the review
		// found unpinned (kit#11).
		{"a closed team's email accounts", emails(func(s *contract.EmailAccountsSettings) { s.Availability, s.LinkMinRole = "closed", nil }), true},
		{"only owners may link", emails(func(s *contract.EmailAccountsSettings) { s.LinkMinRole = ptr(contract.RoleOwner) }), true},
		{"members may link", emails(func(s *contract.EmailAccountsSettings) { s.LinkMinRole = ptr(contract.RoleMember) }), true},
		{"an unknown link_min_role", emails(func(s *contract.EmailAccountsSettings) { s.LinkMinRole = ptr("guest") }), false},
		{"an unknown sign_in", mailbox(func(m *contract.MailboxRow) { m.SignIn = "app_password" }), false},
		{"an unknown sync mode", mailbox(func(m *contract.MailboxRow) { m.Sync.Mode, m.Sync.Agreement = "shared", nil }), false},
		{"an unknown index state", mailbox(func(m *contract.MailboxRow) { m.Sync.Indexed = "done" }), false},
		{"a mailbox listed twice", emails(func(s *contract.EmailAccountsSettings) { s.Items = append(s.Items, s.Items[0]) }), false},
		{"a mailbox's key_epoch below 0", mailbox(func(m *contract.MailboxRow) { m.KeyEpoch = ptr[int64](-1) }), false},
		{"a cap by the year", integration(func(in *contract.AIIntegration) { in.Cap.Period = "year" }), false},
		{"a cap's limit below 0", integration(func(in *contract.AIIntegration) { in.Cap.Limit = -1 }), false},
		{"a cap's use below 0", integration(func(in *contract.AIIntegration) { in.Cap.Used = -1 }), false},
		{"an integration twice", integrations(func(s *contract.IntegrationsSettings) { s.Integrations = append(s.Integrations, s.Integrations[0]) }), false},
		{"a provider key twice", integrations(func(s *contract.IntegrationsSettings) { s.ProviderKeys = append(s.ProviderKeys, s.ProviderKeys[0]) }), false},
		{"an integration's number twice", integration(func(in *contract.AIIntegration) { in.Items = []string{vecNumber, vecNumber} }), false},
		{"a connection twice", mcp(func(s *contract.MCPSettings) { s.Connections = append(s.Connections, s.Connections[0]) }), false},
		{"a legacy token twice", mcp(func(s *contract.MCPSettings) { s.LegacyTokens = append(s.LegacyTokens, s.LegacyTokens[0]) }), false},
		{"a consenter twice among the renewals waiting", mcp(func(s *contract.MCPSettings) { s.RenewalsWaiting = append(s.RenewalsWaiting, s.RenewalsWaiting[0]) }), false},
		{"no renewal waiting for a consenter", mcp(func(s *contract.MCPSettings) { s.RenewalsWaiting[0].Count = 0 }), false},
		{"a day of activity twice", mcp(func(s *contract.MCPSettings) { s.Activity = append(s.Activity, s.Activity[0]) }), false},
		{"a malformed day of activity", mcp(func(s *contract.MCPSettings) { s.Activity[0].Day = "2026-13-01" }), false},
		{"two budget hits of one code", connection(func(c *contract.MCPConnection) {
			c.BudgetHits = []contract.BudgetHit{{Code: "network", At: at(-time.Hour)}, {Code: "network", At: at(-2 * time.Hour)}}
		}), false},
		{"seen twice by one person", connection(func(c *contract.MCPConnection) { c.SeenBy = []string{vecSub, vecSub} }), false},
		{"a connection's number twice", connection(func(c *contract.MCPConnection) { c.Items = []string{vecNumber, vecNumber} }), false},
		{"a host whose last label is a number in hex", connection(func(c *contract.MCPConnection) { c.MainDomain = ptr("10.0.0.0x1") }), false},
		{"a host whose last label starts with a digit", connection(func(c *contract.MCPConnection) { c.VerifiedHost = ptr("claude.4ai") }), false},
		{"an origin whose host is a number in hex", installations(func(s *contract.InstallationsSettings) {
			s.Installations[0].Origin = "https://0x7f000001:8443"
		}), false},
		{"an installation twice", installations(func(s *contract.InstallationsSettings) { s.Installations = append(s.Installations, s.Installations[0]) }), false},
		{"a binding twice", installations(func(s *contract.InstallationsSettings) { s.Bindings = append(s.Bindings, s.Bindings[0]) }), false},
		{"licences used below 0", installations(func(s *contract.InstallationsSettings) { s.Licences.Used = -1 }), false},
		{"a capacity below 0", installations(func(s *contract.InstallationsSettings) { s.Licences.Capacity = ptr[int64](-1) }), false},
		{"hosted numbers below 0", installations(func(s *contract.InstallationsSettings) { s.HostedNumbers = -1 }), false},
		{"a pending registration twice", numbers(func(s *contract.NumbersSettings) { s.Pending = append(s.Pending, s.Pending[0]) }), false},
		{"free places below 0", numbers(func(s *contract.NumbersSettings) { s.PlacesFree = ptr[int64](-1) }), false},
		{"a number's key_epoch below 0", row(func(r *contract.NumberRow) { r.KeyEpoch = ptr[int64](-1) }), false},
		{"a number's bytes below 0", row(func(r *contract.NumberRow) { r.Bytes = ptr[int64](-1) }), false},
		{"holders_more below 0", row(func(r *contract.NumberRow) { r.MoveOut.HoldersMore = -1 }), false},
		{"a move-out holder twice", row(func(r *contract.NumberRow) { r.MoveOut.Holders = append(r.MoveOut.Holders, r.MoveOut.Holders[0]) }), false},
		{"a connection a move ends twice", row(func(r *contract.NumberRow) { r.MoveOut.Ends = []string{vecConnection, vecConnection} }), false},
		// One fault each, so that every rule and every closed list is
		// pinned on its own (Wappie's second review of kit#11).
		{"every AI alert's function and provider", integration(func(in *contract.AIIntegration) {
			in.Status = "paused"
			in.Alerts = []contract.AIAlert{
				{Code: "ai_quota", Function: ptr(contract.AIVideo), Provider: ptr(contract.AIGoogle), At: at(-time.Hour)},
				{Code: "ai_model_unavailable", Function: ptr(contract.AIDocument), Provider: ptr(contract.AIAnthropic), At: at(-time.Hour)},
				{Code: "ai_key_rejected", Provider: ptr(contract.AIAnthropic), At: at(-time.Hour)},
			}
		}), true},
		{"an alert naming an unknown function", integration(func(in *contract.AIIntegration) {
			in.Alerts = []contract.AIAlert{{Code: "ai_quota", Function: ptr("transcription"), At: at(-time.Hour)}}
		}), false},
		{"an alert naming an unknown provider", integration(func(in *contract.AIIntegration) {
			in.Alerts = []contract.AIAlert{{Code: "ai_quota", Provider: ptr("mistral"), At: at(-time.Hour)}}
		}), false},
		{"an unknown paused_by kind", row(func(r *contract.NumberRow) { r.PausedBy.Kind = "operator" }), false},
		{"a paused_by sub that is no UUID", row(func(r *contract.NumberRow) { r.PausedBy.Sub = ptr("ana") }), false},
		{"an unknown capture", row(func(r *contract.NumberRow) { r.Capture, r.PausedBy = "off", nil }), false},
		{"a number's id that is no item id", row(func(r *contract.NumberRow) { r.ID = "dev 1" }), false},
		{"a move-out holder's sub that is no UUID", row(func(r *contract.NumberRow) { r.MoveOut.Holders[0].Sub = ptr("ana") }), false},
		{"a move-out holder's row that is no id", row(func(r *contract.NumberRow) { r.MoveOut.Holders[0].Row = "" }), false},
		{"an unknown provider of a provider key", integrations(func(s *contract.IntegrationsSettings) { s.ProviderKeys[0].Provider = "mistral" }), false},
		{"a provider key's owner that is no sub", integrations(func(s *contract.IntegrationsSettings) { s.ProviderKeys[0].Owner = ptr("ana") }), false},
		{"server_off naming an unknown function", integrations(func(s *contract.IntegrationsSettings) { s.ServerOff.Functions = []string{"transcription"} }), false},
		{"server_off naming an unknown provider", integrations(func(s *contract.IntegrationsSettings) { s.ServerOff.Providers = []string{"mistral"} }), false},
		{"server_off naming a function twice", integrations(func(s *contract.IntegrationsSettings) {
			s.ServerOff.Functions = []string{contract.AIAudio, contract.AIAudio}
		}), false},
		{"an unknown integration status", integration(func(in *contract.AIIntegration) { in.Status = "running" }), false},
		{"an integration's creator that is no sub", integration(func(in *contract.AIIntegration) { in.CreatedBy = ptr("ana") }), false},
		{"an unknown switch", mcp(func(s *contract.MCPSettings) { s.Switches[0].Switch = "send" }), false},
		{"an unknown operator", mcp(func(s *contract.MCPSettings) { s.Switches[0].Operator = "block" }), false},
		{"a switch the operator denies, changeable", mcp(func(s *contract.MCPSettings) { s.Switches[3].Changeable = true }), false},
		{"switched_by without switched_at", mcp(func(s *contract.MCPSettings) { s.SwitchedAt = nil }), false},
		{"switched_by that is no sub", mcp(func(s *contract.MCPSettings) { s.SwitchedBy = ptr("ana") }), false},
		{"an unknown connection kind", connection(func(c *contract.MCPConnection) { c.Kind = "everything" }), false},
		{"an unknown connection status", connection(func(c *contract.MCPConnection) { c.Status = "paused" }), false},
		{"an unknown connection tier", connection(func(c *contract.MCPConnection) { c.Tier = "trusted" }), false},
		{"an unknown revoke reason on a connection", connection(func(c *contract.MCPConnection) {
			c.Status, c.EndedAt, c.EndReason = "revoked", ptr(at(-time.Hour)), ptr("user_deleted")
		}), false},
		{"an unknown budget hit", connection(func(c *contract.MCPConnection) { c.BudgetHits[0].Code = "hourly_messages" }), false},
		{"a consenter that is no sub", connection(func(c *contract.MCPConnection) { c.Consenter = ptr("ana") }), false},
		{"drafts below 0", mcp(func(s *contract.MCPSettings) { s.Activity[0].Drafts, s.Activity[0].Sends = -1, 5 }), false},
		{"sends below 0", mcp(func(s *contract.MCPSettings) { s.Activity[0].Drafts, s.Activity[0].Sends = 2, -1 }), false},
		{"an unknown mailbox status", mailbox(func(m *contract.MailboxRow) { m.Status = "paused" }), false},
		{"a linked_by that is no sub", mailbox(func(m *contract.MailboxRow) { m.LinkedBy = ptr("ana") }), false},
		{"an agreement's revision that is no revision", mailbox(func(m *contract.MailboxRow) { m.Sync.Agreement.Revision = "sync text 3" }), false},
		{"a team sync text that is no revision", emails(func(s *contract.EmailAccountsSettings) { s.Texts.TeamSync = "" }), false},
		{"snapshot_seq 0", w(func(d *contract.SettingsDoc) { d.SnapshotSeq = ptr[int64](0) }, vecNumbers(nil)), false},
		{"a bool member null", edit(numbers(nil), `"can_link":true`, `"can_link":null`), false},
		{"an integer member null", edit(installations(nil), `"hosted_numbers":3`, `"hosted_numbers":null`), false},
		{"a string member null", edit(numbers(nil), `"connection":"online"`, `"connection":null`), false},
		{"a list member null", numbers(func(s *contract.NumbersSettings) { s.Pending = nil }), false},
		{"a switch's effective null", edit(mcp(nil), `"effective":true`, `"effective":null`), false},
		{"accepts null", w(func(d *contract.SettingsDoc) { d.Accepts = nil }, vecNumbers(nil)), false},
		{"truncated null", edit(numbers(nil), `"truncated":false`, `"truncated":null`), false},
		{"truncated missing", edit(numbers(nil), `"truncated":false,`, ``), false},
		{"snapshot_seq missing from Wappie Cloud", edit(installations(nil), `"snapshot_seq":null,`, ``), false},

		// The document itself.
		{"a section of another app", mustRaw(sectionDoc("wappie", contract.SectionNumbers, vecNumbers(nil), func(d *contract.SettingsDoc) {
			d.Section = contract.SectionEmailAccounts
		})), false},
		{"a producer not the section's", w(func(d *contract.SettingsDoc) { d.Producer = contract.ProducerWappieCloud }, vecNumbers(nil)), false},
		{"accepts naming another section's kind", w(func(d *contract.SettingsDoc) {
			d.Accepts = []string{contract.OpItemRename, contract.OpAIIntegrationRevoke}
		}, vecNumbers(nil)), false},
		{"accepts naming a kind twice", w(func(d *contract.SettingsDoc) { d.Accepts = []string{contract.OpItemRename, contract.OpItemRename} }, vecNumbers(nil)), false},
		{"accepts naming no kind: the console offers nothing", w(func(d *contract.SettingsDoc) { d.Accepts = []string{} }, vecNumbers(nil)), true},
		{"an unknown kind in accepts", w(func(d *contract.SettingsDoc) { d.Accepts = []string{"item.delete"} }, vecNumbers(nil)), false},
		{"snapshot_seq null from wappie", w(func(d *contract.SettingsDoc) { d.SnapshotSeq = nil }, vecNumbers(nil)), false},
		{"snapshot_seq null from mailie", mustRaw(sectionDoc("mailie", contract.SectionEmailAccounts, vecEmailAccounts(nil), func(d *contract.SettingsDoc) {
			d.SnapshotSeq = nil
		})), false},
		{"a section measured with an older snapshot", w(func(d *contract.SettingsDoc) { d.SnapshotSeq = ptr(vecSeq - 60000) }, vecNumbers(nil)), true},
		{"state_seq 0", w(func(d *contract.SettingsDoc) { d.StateSeq = 0 }, vecNumbers(nil)), false},
		{"version 2 of the format", w(func(d *contract.SettingsDoc) { d.V = 2 }, vecNumbers(nil)), false},
		{"a person's type on a section", w(func(d *contract.SettingsDoc) { d.Type = contract.PersonSettingsType }, vecNumbers(nil)), false},
		{"the reference app's numbers, produced under its own id", mustRaw(sectionDoc("fakeproduct", contract.SectionNumbers, vecNumbers(nil), nil)), true},
		{"a member of data twice", edit(numbers(nil), `"can_link":true`, `"can_link":true,"can_link":false`), false},
		{"a member of data in another case", edit(numbers(nil), `"can_link"`, `"Can_link"`), false},
		{"a member of data missing", edit(numbers(nil), `"storage_paused":false,`, ``), false},
		{"a member of data the platform does not know", edit(numbers(nil), `"can_link":true`, `"can_link":true,"last_error":"conflict"`), false},
		{"a member of the document the platform does not know", edit(numbers(nil), `"truncated":false`, `"truncated":false,"note":"x"`), false},
		{"a member of the document in another case", edit(numbers(nil), `"truncated"`, `"Truncated"`), false},
		{"data null", w(func(d *contract.SettingsDoc) { d.Data = json.RawMessage(`null`) }, nil), false},
	}
	persons := []settingsCase{
		{"Wappie's person, a notice of each code", mustRaw(personDoc("wappie", vecWappiePerson(nil), nil)), true},
		{"Mailie's person, a notice of each code", mustRaw(personDoc("mailie", vecMailiePerson(nil), nil)), true},
		{"Wappie's person, no notice and never signed out everywhere", mustRaw(personDoc("wappie", vecWappiePerson(func(s *contract.WappiePersonSettings) {
			s.Notices, s.SignedOutEverywhereAt = []contract.Notice{}, nil
		}), nil)), true},
		{"a pause by a former member, and a notice with no workspace or item", mustRaw(personDoc("wappie", vecWappiePerson(func(s *contract.WappiePersonSettings) {
			s.Notices[0].Params = mustRaw(contract.SyncPausedParams{ActorKind: contract.ActorPerson, FirstAt: at(-time.Hour)})
			s.Notices[3].WorkspaceID, s.Notices[3].Item, s.Notices[3].Label, s.Notices[3].Hint = nil, nil, nil, nil
		}), nil)), true},
		{"Mailie's notices naming nobody", mustRaw(personDoc("mailie", vecMailiePerson(func(s *contract.MailiePersonSettings) {
			s.Notices[2].Params = mustRaw(contract.MailboxSyncPausedParams{State: "live"})
		}), nil)), true},
		{"a sync consent on an older revision stays on", mustRaw(personDoc("mailie", vecMailiePerson(func(s *contract.MailiePersonSettings) {
			s.Consents[0].Revision = ptr("2026-10-sync-2")
		}), nil)), true},
		{"300 notices", mustRaw(personDoc("wappie", vecWappiePerson(func(s *contract.WappiePersonSettings) {
			s.Notices = many(300, func(i int) contract.Notice { return wappieNotice(contract.NoticeNumberMovedOut, i) })
		}), nil)), true},
		{"301 notices", mustRaw(personDoc("wappie", vecWappiePerson(func(s *contract.WappiePersonSettings) {
			s.Notices = many(301, func(i int) contract.Notice { return wappieNotice(contract.NoticeNumberMovedOut, i) })
		}), nil)), false},
		{"a notice with another code's params", mustRaw(personDoc("wappie", vecWappiePerson(func(s *contract.WappiePersonSettings) {
			s.Notices[1].Params = s.Notices[0].Params
		}), nil)), false},
		{"a notice's params with a member missing", mustRaw(personDoc("wappie", vecWappiePerson(func(s *contract.WappiePersonSettings) {
			s.Notices[3].Params = json.RawMessage(`{}`)
		}), nil)), false},
		{"a notice's params null", mustRaw(personDoc("wappie", vecWappiePerson(func(s *contract.WappiePersonSettings) {
			s.Notices[3].Params = json.RawMessage(`null`)
		}), nil)), false},
		{"free text in a notice code's place", mustRaw(personDoc("wappie", vecWappiePerson(func(s *contract.WappiePersonSettings) {
			s.Notices[3].Code = "Número movido"
		}), nil)), false},
		{"Wappie's notice code on Mailie", mustRaw(personDoc("mailie", vecMailiePerson(func(s *contract.MailiePersonSettings) {
			s.Notices[0].Code = contract.NoticeNumberDeleted
		}), nil)), false},
		{"Mailie's notice at version 2", mustRaw(personDoc("mailie", vecMailiePerson(func(s *contract.MailiePersonSettings) { s.Notices[0].Version = 2 }), nil)), false},
		{"Mailie's notice with no item", mustRaw(personDoc("mailie", vecMailiePerson(func(s *contract.MailiePersonSettings) { s.Notices[0].Item = nil }), nil)), false},
		{"Mailie's notice naming the operator as its actor", mustRaw(personDoc("mailie", vecMailiePerson(func(s *contract.MailiePersonSettings) {
			s.Notices[1].Params = mustRaw(contract.MailboxSyncOffParams{State: "live", ActorKind: ptr(contract.ActorApp)})
		}), nil)), false},
		{"a notice's label with an address", mustRaw(personDoc("wappie", vecWappiePerson(func(s *contract.WappiePersonSettings) {
			s.Notices[0].Label = ptr("vendas@loja.com")
		}), nil)), false},
		{"a notice id twice", mustRaw(personDoc("wappie", vecWappiePerson(func(s *contract.WappiePersonSettings) { s.Notices[1].ID = s.Notices[0].ID }), nil)), false},
		{"a notice's id that is no item id", mustRaw(personDoc("wappie", vecWappiePerson(func(s *contract.WappiePersonSettings) { s.Notices[0].ID = "812 " }), nil)), false},
		{"old_text on sync", mustRaw(personDoc("mailie", vecMailiePerson(func(s *contract.MailiePersonSettings) { s.Consents[0].State = "old_text" }), nil)), false},
		{"withdrawn_at on sync", mustRaw(personDoc("mailie", vecMailiePerson(func(s *contract.MailiePersonSettings) {
			s.Consents[0].WithdrawnAt = ptr(at(-time.Hour))
		}), nil)), false},
		{"two consents", mustRaw(personDoc("mailie", vecMailiePerson(func(s *contract.MailiePersonSettings) { s.Consents = s.Consents[:2] }), nil)), false},
		{"a consent twice", mustRaw(personDoc("mailie", vecMailiePerson(func(s *contract.MailiePersonSettings) { s.Consents[2] = s.Consents[1] }), nil)), false},
		{"an agreed consent with no revision", mustRaw(personDoc("mailie", vecMailiePerson(func(s *contract.MailiePersonSettings) {
			s.Consents[0].Revision = nil
		}), nil)), false},
		{"a person's document from another producer", mustRaw(personDoc("mailie", vecMailiePerson(nil), func(d *contract.PersonSettingsDoc) {
			d.Producer = contract.ProducerWappie
		})), false},
		{"a person accepting a workspace's kind", mustRaw(personDoc("wappie", vecWappiePerson(nil), func(d *contract.PersonSettingsDoc) {
			d.Accepts = []string{contract.OpItemRename}
		})), false},
		{"Wappie's person accepting a consent", mustRaw(personDoc("wappie", vecWappiePerson(nil), func(d *contract.PersonSettingsDoc) {
			d.Accepts = []string{contract.OpConsentAgree}
		})), false},
		{"Mailie's data on Wappie's person", mustRaw(personDoc("wappie", vecMailiePerson(nil), nil)), false},
		{"a section's type on a person", mustRaw(personDoc("wappie", vecWappiePerson(nil), func(d *contract.PersonSettingsDoc) { d.Type = contract.SettingsType })), false},
		{"an uppercase sub", mustRaw(personDoc("wappie", vecWappiePerson(nil), func(d *contract.PersonSettingsDoc) { d.Sub = strings.ToUpper(vecSub) })), false},
		{"Mailie's notices in every state, and an actor named", mustRaw(personDoc("mailie", vecMailiePerson(func(s *contract.MailiePersonSettings) {
			s.Notices = []contract.Notice{
				mailieNotice(contract.NoticeMailboxRemoved, 0), mailieNotice(contract.NoticeMailboxRemoved, 1),
				mailieNotice(contract.NoticeMailboxSyncOff, 2), mailieNotice(contract.NoticeMailboxSyncOff, 3),
				mailieNotice(contract.NoticeMailboxSyncOff, 4), mailieNotice(contract.NoticeMailboxSyncPaused, 5),
			}
			s.Notices[1].Params = mustRaw(contract.MailboxRemovedParams{State: "deleted", RecoverableUntil: at(-time.Hour)})
			s.Notices[3].Params = mustRaw(contract.MailboxSyncOffParams{State: "removed", RecoverableUntil: ptr(at(29 * 24 * time.Hour)),
				Actor: ptr(vecOther), ActorKind: ptr(contract.ActorPerson)})
			s.Notices[4].Params = mustRaw(contract.MailboxSyncOffParams{State: "deleted", ActorKind: ptr(contract.ActorPerson)})
		}), nil)), true},
		{"Mailie's notice code on Wappie", mustRaw(personDoc("wappie", vecWappiePerson(func(s *contract.WappiePersonSettings) {
			n := mailieNotice(contract.NoticeMailboxRemoved, 9)
			n.ID = "819"
			s.Notices[3] = n
		}), nil)), false},
		{"an unknown consent", mustRaw(personDoc("mailie", vecMailiePerson(func(s *contract.MailiePersonSettings) { s.Consents[2].Consent = "share" }), nil)), false},
		{"an unknown consent state", mustRaw(personDoc("mailie", vecMailiePerson(func(s *contract.MailiePersonSettings) { s.Consents[2].State = "paused" }), nil)), false},
		{"a text that is no revision", mustRaw(personDoc("mailie", vecMailiePerson(func(s *contract.MailiePersonSettings) { s.Texts.Keys = "" }), nil)), false},
		{"Wappie's pause by the app", mustRaw(personDoc("wappie", vecWappiePerson(func(s *contract.WappiePersonSettings) {
			s.Notices[0].Params = mustRaw(contract.SyncPausedParams{ActorKind: contract.ActorApp, FirstAt: at(-time.Hour)})
		}), nil)), false},
		{"a removal notice in an unknown state", mustRaw(personDoc("mailie", vecMailiePerson(func(s *contract.MailiePersonSettings) {
			s.Notices[0].Params = mustRaw(contract.MailboxRemovedParams{State: "live", RecoverableUntil: at(time.Hour)})
		}), nil)), false},
		{"a turn-off notice in an unknown state", mustRaw(personDoc("mailie", vecMailiePerson(func(s *contract.MailiePersonSettings) {
			s.Notices[1].Params = mustRaw(contract.MailboxSyncOffParams{State: "purged"})
		}), nil)), false},
		{"Mailie's pause by a key", mustRaw(personDoc("mailie", vecMailiePerson(func(s *contract.MailiePersonSettings) {
			s.Notices[2].Params = mustRaw(contract.MailboxSyncPausedParams{State: "live", Actor: ptr(vecOther), ActorKind: ptr(contract.ActorKey)})
		}), nil)), false},
		{"a notice's hint that is no hint", mustRaw(personDoc("wappie", vecWappiePerson(func(s *contract.WappiePersonSettings) { s.Notices[0].Hint = ptr("5678") }), nil)), false},
		{"a notice's workspace that is no UUID", mustRaw(personDoc("wappie", vecWappiePerson(func(s *contract.WappiePersonSettings) {
			s.Notices[0].WorkspaceID = ptr("team")
		}), nil)), false},
		{"Mailie's pause notice in another state than live", mustRaw(personDoc("mailie", vecMailiePerson(func(s *contract.MailiePersonSettings) {
			s.Notices[2].Params = mustRaw(contract.MailboxSyncPausedParams{State: "removed"})
		}), nil)), false},
		{"Wappie's notice at version 0", mustRaw(personDoc("wappie", vecWappiePerson(func(s *contract.WappiePersonSettings) { s.Notices[1].Version = 0 }), nil)), false},
		{"a notice's bool param null", mustRaw(personDoc("wappie", vecWappiePerson(func(s *contract.WappiePersonSettings) {
			s.Notices[0].Params = edit(s.Notices[0].Params, `"several_actors":true`, `"several_actors":null`)
		}), nil)), false},
		{"enrolled null", mustRaw(personDoc("mailie", vecMailiePerson(func(s *contract.MailiePersonSettings) {}), func(d *contract.PersonSettingsDoc) {
			d.Data = edit(d.Data, `"enrolled":true`, `"enrolled":null`)
		})), false},
		{"state_seq 0", mustRaw(personDoc("wappie", vecWappiePerson(nil), func(d *contract.PersonSettingsDoc) { d.StateSeq = 0 })), false},
	}
	for _, c := range sections {
		if got := sectionValid(c.raw); got != c.valid {
			return nil, fmt.Errorf("contractvec: section %q is valid %v, the design asks %v", c.name, got, c.valid)
		}
		if c.valid && len(c.raw) > contract.SettingsBodyLimit {
			return nil, fmt.Errorf("contractvec: section %q is over its call's body limit", c.name)
		}
		out.Sections = append(out.Sections, wireCase(c.name, c.raw, c.valid))
	}
	for _, c := range persons {
		if got := personValid(c.raw); got != c.valid {
			return nil, fmt.Errorf("contractvec: person %q is valid %v, the design asks %v", c.name, got, c.valid)
		}
		if c.valid && len(c.raw) > contract.PersonSettingsBodyLimit {
			return nil, fmt.Errorf("contractvec: person %q is over its call's body limit", c.name)
		}
		out.Persons = append(out.Persons, wireCase(c.name, c.raw, c.valid))
	}
	return out, nil
}
