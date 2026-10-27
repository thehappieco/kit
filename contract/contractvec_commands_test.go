package contract_test

// The kit's generator of wire-commands.json and command-macs.json (kit
// v0.10.0, SPEC section 11.19): commands, what an app does with them,
// results and their classes, and the command's MAC.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/jcs"
)

// vecParams are each kind's params in the vectors, by app.
var vecParams = map[string]map[string]string{
	"wappie": {
		contract.OpItemRename:              `{"before":{"label":"Vendas"},"after":{"label":"Vendas SP"}}`,
		contract.OpItemSyncStop:            `{"before":{"capture":"on"},"after":{"capture":"paused"}}`,
		contract.OpItemSyncResume:          `{"before":{"capture":"paused"},"after":{"capture":"on"}}`,
		contract.OpItemSyncNow:             `{}`,
		contract.OpItemFlagsRaise:          `{"before":{"can":["read"]},"after":{"can":["read","send"]}}`,
		contract.OpItemFlagsDrop:           `{"before":{"can":["read","send","manage"]},"after":{"can":["send"]}}`,
		contract.OpItemAccessRemove:        `{"before":{"can":["read","send"]},"after":{"can":[]}}`,
		contract.OpItemRegistrationDelete:  `{}`,
		contract.OpItemMoveOut:             `{"before":{"workspace":"` + vecTeam + `"},"after":{"workspace":"` + vecPersonal + `"}}`,
		contract.OpAIProviderKeyDelete:     `{}`,
		contract.OpAIIntegrationNarrow:     `{"before":{"paused":false},"after":{"paused":true}}`,
		contract.OpAIIntegrationRevoke:     `{"delete_results":true}`,
		contract.OpMCPConnectionRevoke:     `{}`,
		contract.OpMCPConnectionSeen:       `{}`,
		contract.OpMCPSendPause:            `{"before":{"send_paused":false},"after":{"send_paused":true}}`,
		contract.OpMCPSendResume:           `{"before":{"send_paused":true},"after":{"send_paused":false}}`,
		contract.OpMCPSwitchOn:             `{"before":{"set":false},"after":{"set":true}}`,
		contract.OpMCPSwitchOff:            `{"before":{"set":true},"after":{"set":false}}`,
		contract.OpMCPLegacyTokenRevoke:    `{}`,
		contract.OpInstallationAdd:         `{"origin":"https://wappie.example.com","name":"Matriz"}`,
		contract.OpInstallationRename:      `{"before":{"name":"Matriz"},"after":{"name":"Matriz SP"}}`,
		contract.OpLicenceRelease:          `{}`,
		contract.OpPersonSignOutEverywhere: `{}`,
		contract.OpPersonNoticesDismiss:    `{"notices":[{"id":"812","version":2}]}`,
	},
	"mailie": {
		contract.OpItemSyncNow:             `{}`,
		contract.OpItemSyncStop:            `{"before":{"paused":false},"after":{"paused":true}}`,
		contract.OpItemSyncResume:          `{"before":{"paused":true},"after":{"paused":false}}`,
		contract.OpItemLiftHold:            `{"before":{"held":true},"after":{"held":false}}`,
		contract.OpItemTeamSyncOn:          `{"before":{"sync":"off"},"after":{"sync":"on"}}`,
		contract.OpItemTeamSyncOff:         `{"before":{"sync":"on"},"after":{"sync":"off"}}`,
		contract.OpItemRemove:              `{}`,
		contract.OpItemRecover:             `{}`,
		contract.OpItemPurge:               `{}`,
		contract.OpItemRemovedIndexOff:     `{"before":{"index_kept":true},"after":{"index_kept":false}}`,
		contract.OpItemFlagsRaise:          `{"before":{"can":["read"]},"after":{"can":["read","act"]}}`,
		contract.OpItemFlagsDrop:           `{"before":{"can":["read","act","send"]},"after":{"can":["send"]}}`,
		contract.OpItemAccessRemove:        `{"before":{"can":["read","act"]},"after":{"can":[]}}`,
		contract.OpPersonSignOutEverywhere: `{}`,
		contract.OpPersonNoticesDismiss:    `{"notices":[{"id":"mbe_0","version":1}]}`,
		contract.OpConsentAgree:            `{"before":{"sync":"off"},"after":{"sync":"on"}}`,
		contract.OpConsentWithdraw:         `{"before":{"actions":"on"},"after":{"actions":"off"}}`,
	},
}

// vecCmd is app's command of kind as the platform issues it, before its
// mac: a team's (a personal workspace's for Mailie's item.lift_hold), by
// an owner, at Now.
func vecCmd(app, kind string, mut func(*contract.Command)) contract.Command {
	k, ok := contract.CommandKindOf(app, kind)
	if !ok {
		panic("contractvec: no kind " + kind)
	}
	ps := vecParams[app]
	if ps == nil {
		// The reference app has Wappie's kinds.
		ps = vecParams["wappie"]
	}
	c := contract.Command{
		V: contract.CommandV, Type: contract.CommandType, App: app, Generation: vecGeneration, ID: vecCommand,
		CSeq: 812, Kind: kind, Section: k.Section, Actor: vecSub,
		Params:   json.RawMessage(ps[kind]),
		BasedOn:  contract.BasedOn{StateSeq: vecSeq, Docs: map[string]int64{vecSub: 7}},
		IssuedAt: contract.T(Now), FirstIssuedAt: contract.T(Now), Secret: 2,
	}
	if k.Section != contract.SectionPerson {
		ws := vecTeam
		if kind == contract.OpItemLiftHold {
			ws = vecPersonal
		}
		c.WorkspaceID, c.WSeq, c.ActorRole = ptr(ws), ptr[int64](41), ptr(contract.RoleOwner)
	}
	item := vecNumber
	if app == "mailie" {
		item = vecMailbox
	}
	for _, member := range k.Target {
		switch member {
		case contract.TargetItem:
			c.Target.Item = item
		case contract.TargetPerson:
			c.Target.Person = vecOther
			c.BasedOn.Docs[vecOther] = 3
		case contract.TargetRow:
			c.Target.Row = map[string]string{
				contract.OpItemRegistrationDelete: "reg_1", contract.OpAIProviderKeyDelete: "pk_1", contract.OpAIIntegrationNarrow: "ai_1",
				contract.OpAIIntegrationRevoke: "ai_1", contract.OpMCPLegacyTokenRevoke: "key_9", contract.OpInstallationRename: "inst_1",
				contract.OpLicenceRelease: "bind_1",
			}[kind]
			if c.Target.Row == "" {
				c.Target.Row = vecConnection
			}
		case contract.TargetSwitch:
			c.Target.Switch = contract.SwitchText
		}
	}
	switch k.Confirm {
	case contract.TargetItem:
		c.Confirm = ptr(c.Target.Item)
	case contract.TargetRow:
		c.Confirm = ptr(c.Target.Row)
	}
	if k.Agreement != contract.AgreementNever {
		c.Agreement = &contract.Agreement{Revision: vecSyncText, Language: "pt-BR"}
	}
	if !k.Tightening {
		c.ExpiresAt = ptr(at(contract.CommandLifetime))
	}
	if mut != nil {
		mut(&c)
	}
	return c
}

// signed is c as the platform serves it: its JCS text, with its mac under
// secret for its own app.
func signed(c contract.Command, secret string) json.RawMessage {
	raw, err := contract.SignCommand(mustRaw(c), c.App, secret)
	if err != nil {
		panic(err)
	}
	return raw
}

// workspaceKind is the kind of the workspace a vector command names.
func workspaceKind(c contract.Command) string {
	switch {
	case c.WorkspaceID == nil:
		return ""
	case *c.WorkspaceID == vecPersonal:
		return contract.KindPersonal
	}
	return contract.KindTeam
}

// CommandCase is one command an app receives, signed for it, the kind of
// the workspace it names, and whether it is valid.
type CommandCase struct {
	Name          string          `json:"name"`
	App           string          `json:"app"`
	WorkspaceKind string          `json:"workspace_kind"`
	Value         json.RawMessage `json:"value"`
	Valid         bool            `json:"valid"`
}

// CommandAction is one command an app takes, and what it does with it.
type CommandAction struct {
	Name       string          `json:"name"`
	App        string          `json:"app"`
	Generation string          `json:"generation"`
	SignedAt   string          `json:"signed_at"`
	LastWSeq   *int64          `json:"last_wseq"`
	Again      bool            `json:"again"`
	Value      json.RawMessage `json:"value"`
	Action     string          `json:"action"`
}

// ResultCase is one result of a command of app's kind, and whether it is
// valid.
type ResultCase struct {
	Name  string          `json:"name"`
	App   string          `json:"app"`
	Kind  string          `json:"kind"`
	Value json.RawMessage `json:"value"`
	Valid bool            `json:"valid"`
}

// ClassCase is a refusal code's class for a kind that tightens or not.
type ClassCase struct {
	Code       string `json:"code"`
	Tightening bool   `json:"tightening"`
	Class      string `json:"class"`
}

// WireCommands is wire-commands.json.
type WireCommands struct {
	Format      string          `json:"format"`
	Version     int             `json:"version"`
	Kind        string          `json:"kind"`
	Description string          `json:"description"`
	Commands    []CommandCase   `json:"commands"`
	Feeds       []WireCase      `json:"feeds"`
	Actions     []CommandAction `json:"actions"`
	Results     []ResultCase    `json:"results"`
	Batches     []BodyCase      `json:"batches"`
	Classes     []ClassCase     `json:"classes"`
}

// commandValid is what an app makes of a command: its mac under SecretA,
// as every command of the file is signed, decoded as VerifyCommand
// decodes it, and ValidateIn the workspace's kind.
func commandValid(app, workspaceKind string, raw []byte) bool {
	c, err := contract.VerifyCommand(raw, app, []string{SecretA})
	return err == nil && c.ValidateIn(workspaceKind) == nil
}

// commandAction is what an app does with a command it takes, in this
// order: a body naming another app, invalid_command; a mac that does not
// hold, invalid_command; another generation, a
// reset; a command that is not valid, invalid_command; issued more than
// CommandRetention before the answer that carried it (but delivered
// again), expired; carried after its expires_at, expired; a wseq at or
// below the last one this producer ran in the workspace with another id
// (but delivered again), invalid_command; else it runs.
func commandAction(a CommandAction) string {
	c, err := contract.VerifyCommand(a.Value, a.App, []string{SecretA})
	if err != nil {
		return "invalid_command"
	}
	if contract.ValidUUID(c.Generation) && c.Generation != a.Generation {
		return "reset"
	}
	if c.ValidateIn(workspaceKind(c)) != nil {
		return "invalid_command"
	}
	signedAt, err := time.Parse(time.RFC3339, a.SignedAt)
	if err != nil {
		return "invalid_command"
	}
	switch {
	case !a.Again && signedAt.Sub(c.IssuedAt.Time) > contract.CommandRetention:
		return "expired"
	case c.ExpiresAt != nil && signedAt.After(c.ExpiresAt.Time):
		return "expired"
	case !a.Again && a.LastWSeq != nil && c.WSeq != nil && *c.WSeq <= *a.LastWSeq:
		return "invalid_command"
	}
	return "run"
}

// feedValid is what an app makes of a command feed page: decoded as it
// decodes what the platform sends, and valid.
func feedValid(raw []byte) bool {
	var f contract.CommandFeed
	return json.Unmarshal(raw, &f) == nil && f.Validate() == nil
}

// resultValid is what the platform makes of a result of app's kind:
// decoded strictly, and valid for its kind.
func resultValid(app, kind string, raw []byte) bool {
	var r contract.CommandResult
	return exactDecode(raw, &r) == nil && r.ValidateFor(app, kind) == nil
}

// batchValid is what the platform makes of a body of results: within the
// call's limit, decoded strictly, and valid.
func batchValid(body []byte) bool {
	var b contract.CommandResults
	return len(body) <= contract.ResultsBodyLimit && exactDecode(body, &b) == nil && b.Validate() == nil
}

func wireCommands() (any, error) {
	out := WireCommands{
		Format: Format, Version: 1, Kind: "wire-commands",
		Description: "The settings part's commands and results (SPEC section 11.19). commands: a command as the platform serves it to the app named, signed with SecretA of signatures.json for that app; valid when contract.VerifyCommand takes it (it decodes as an app decodes: a member it does not know is ignored) and its ValidateIn accepts it for the kind of the workspace it names (workspace_kind: personal, team, or \"\" for a person's kind). actions: a command an app holding the generation takes, carried by an answer signed at signed_at, with last_wseq the highest wseq its producer ran in that workspace with another id, and again whether the feed delivered it again; what it does, in this order: invalid_command (a body that names another app, whatever its mac), invalid_command (a mac that does not hold under SecretA), reset (another generation), invalid_command (not valid), expired (issued more than 30 days before signed_at, unless delivered again), expired (signed_at after its expires_at), invalid_command (a wseq at or below last_wseq, unless delivered again), else run. results: one contract.CommandResult of a command of the app's kind, decoded as the platform decodes what an app sends (strictly: no member it does not know, every name exactly as written and present), then its ValidateFor(app, kind). batches: bodies of POST /contract/v1/commands/results: valid when within 256 KiB, decoded strictly as contract.CommandResults and valid. classes: each refusal code's class, retry or final, for a kind that tightens or not (contract.CommandRefusalClass).",
	}
	type cmdCase struct {
		name  string
		c     contract.Command
		raw   json.RawMessage
		valid bool
	}
	var cases []cmdCase
	add := func(name string, c contract.Command, valid bool) {
		cases = append(cases, cmdCase{name: name, c: c, valid: valid})
	}
	// Every kind of both apps, as the console issues it.
	for _, app := range []string{"wappie", "mailie"} {
		for _, k := range contract.CommandKinds(app) {
			add(fmt.Sprintf("%s's %s", app, k.Kind), vecCmd(app, k.Kind, nil), true)
		}
	}
	str := func(s string) json.RawMessage { return json.RawMessage(s) }
	wappie := func(kind string, mut func(*contract.Command)) contract.Command { return vecCmd("wappie", kind, mut) }
	mailie := func(kind string, mut func(*contract.Command)) contract.Command { return vecCmd("mailie", kind, mut) }
	params := func(p string) func(*contract.Command) { return func(c *contract.Command) { c.Params = str(p) } }
	for _, c := range []struct {
		name  string
		c     contract.Command
		valid bool
	}{
		// Valid variations.
		{"a function off", wappie(contract.OpAIIntegrationNarrow, params(`{"before":{"function:audio":true},"after":{"function:audio":false}}`)), true},
		{"a cap lowered", wappie(contract.OpAIIntegrationNarrow, params(`{"before":{"cap":500},"after":{"cap":100}}`)), true},
		{"a first cap", wappie(contract.OpAIIntegrationNarrow, params(`{"before":{"cap":null},"after":{"cap":0}}`)), true},
		{"a number's first label", wappie(contract.OpItemRename, params(`{"before":{"label":null},"after":{"label":"Vendas"}}`)), true},
		{"an installation added with no name", wappie(contract.OpInstallationAdd, params(`{"origin":"https://8.8.8.8:8443","name":null}`)), true},
		{"Mailie's resume of a personal mailbox: no agreement", mailie(contract.OpItemSyncResume, func(c *contract.Command) {
			c.WorkspaceID, c.Agreement = ptr(vecPersonal), nil
		}), true},
		{"a team's sync agreed again to the current text", mailie(contract.OpItemTeamSyncOn, params(`{"before":{"sync":"older_revision"},"after":{"sync":"on"}}`)), true},
		{"a bound consent confirmed", mailie(contract.OpItemTeamSyncOn, params(`{"before":{"sync":"bound"},"after":{"sync":"on"}}`)), true},
		{"sync agreed again to the current text", mailie(contract.OpConsentAgree, params(`{"before":{"sync":"older_revision"},"after":{"sync":"on"}}`)), true},
		{"send agreed from old_text", mailie(contract.OpConsentAgree, params(`{"before":{"send":"old_text"},"after":{"send":"on"}}`)), true},
		{"sync withdrawn", mailie(contract.OpConsentWithdraw, params(`{"before":{"sync":"on"},"after":{"sync":"off"}}`)), true},
		{"a mailbox's read raised with send and manage", mailie(contract.OpItemFlagsRaise, params(`{"before":{"can":["read","act"]},"after":{"can":["read","act","send","manage"]}}`)), true},
		{"access removed from a key holder without read", wappie(contract.OpItemAccessRemove, params(`{"before":{"can":[]},"after":{"can":[]}}`)), true},
		{"300 notices dismissed", wappie(contract.OpPersonNoticesDismiss, func(c *contract.Command) {
			c.Params = mustRaw(map[string]any{"notices": many(300, func(i int) contract.NoticeRef { return contract.NoticeRef{ID: fmt.Sprint(i), Version: 1} })})
		}), true},
		{"a command issued again, with its first issue time", wappie(contract.OpItemSyncStop, func(c *contract.Command) {
			c.ID, c.RetryOf, c.FirstIssuedAt = vecCommand2, ptr(vecCommand), at(-time.Minute)
		}), true},
		{"an expiry under five minutes", wappie(contract.OpItemRename, func(c *contract.Command) { c.ExpiresAt = ptr(at(time.Minute)) }), true},
		{"an unknown member in params", wappie(contract.OpItemRename, params(`{"before":{"label":"Vendas"},"after":{"label":"Vendas SP"},"note":"x"}`)), true},
		{"a tightening issued again keeps no expiry", mailie(contract.OpConsentWithdraw, func(c *contract.Command) {
			c.ID, c.RetryOf, c.IssuedAt, c.FirstIssuedAt = vecCommand2, ptr(vecCommand), at(time.Hour), contract.T(Now)
		}), true},
		{"the reference app's rename", vecCmd("fakeproduct", contract.OpItemRename, nil), true},
		{"a member's role at issue", wappie(contract.OpMCPConnectionSeen, func(c *contract.Command) { c.ActorRole = ptr(contract.RoleMember) }), true},
		{"a team's sync turned off from an older revision", mailie(contract.OpItemTeamSyncOff, params(`{"before":{"sync":"older_revision"},"after":{"sync":"off"}}`)), true},
		{"a bound consent turned off", mailie(contract.OpItemTeamSyncOff, params(`{"before":{"sync":"bound"},"after":{"sync":"off"}}`)), true},
		{"sync withdrawn from an older revision", mailie(contract.OpConsentWithdraw, params(`{"before":{"sync":"older_revision"},"after":{"sync":"off"}}`)), true},
		{"actions withdrawn from old_text", mailie(contract.OpConsentWithdraw, params(`{"before":{"actions":"old_text"},"after":{"actions":"off"}}`)), true},
		{"send withdrawn", mailie(contract.OpConsentWithdraw, params(`{"before":{"send":"on"},"after":{"send":"off"}}`)), true},
		{"actions agreed, in English", mailie(contract.OpConsentAgree, func(c *contract.Command) {
			c.Params, c.Agreement.Language = str(`{"before":{"actions":"off"},"after":{"actions":"on"}}`), "en"
		}), true},
		{"a team's sync agreed in Spanish", mailie(contract.OpItemTeamSyncOn, func(c *contract.Command) { c.Agreement.Language = "es" }), true},
		{"an admin's role at issue", wappie(contract.OpItemRename, func(c *contract.Command) { c.ActorRole = ptr(contract.RoleAdmin) }), true},
		{"attachments turned off", wappie(contract.OpMCPSwitchOff, func(c *contract.Command) { c.Target.Switch = contract.SwitchAttachments }), true},
		{"drafts turned on", wappie(contract.OpMCPSwitchOn, func(c *contract.Command) { c.Target.Switch = contract.SwitchDrafts }), true},
		{"a switch that follows its default of on, turned off", wappie(contract.OpMCPSwitchOff, func(c *contract.Command) {
			c.Target.Switch, c.Params = contract.SwitchAI, str(`{"before":{"set":null},"after":{"set":false}}`)
		}), true},
		{"a switch that follows its default of off, turned on", wappie(contract.OpMCPSwitchOn, params(`{"before":{"set":null},"after":{"set":true}}`)), true},
		// Invalid.
		{"a tightening kind with expires_at", wappie(contract.OpItemFlagsDrop, func(c *contract.Command) { c.ExpiresAt = ptr(at(contract.CommandLifetime)) }), false},
		{"another kind without expires_at", wappie(contract.OpItemRename, func(c *contract.Command) { c.ExpiresAt = nil }), false},
		{"an expiry over five minutes", wappie(contract.OpItemRename, func(c *contract.Command) { c.ExpiresAt = ptr(at(contract.CommandLifetime + time.Second)) }), false},
		{"an expiry at its issue", wappie(contract.OpItemRename, func(c *contract.Command) { c.ExpiresAt = ptr(at(0)) }), false},
		{"first_issued_at after issued_at", wappie(contract.OpItemRename, func(c *contract.Command) {
			c.RetryOf, c.FirstIssuedAt = ptr(vecCommand2), at(time.Second)
		}), false},
		{"first_issued_at differing from issued_at with retry_of null", wappie(contract.OpItemRename, func(c *contract.Command) { c.FirstIssuedAt = at(-time.Minute) }), false},
		{"a retry of itself", wappie(contract.OpItemRename, func(c *contract.Command) { c.RetryOf = ptr(vecCommand) }), false},
		{"wseq set on a person's kind", wappie(contract.OpPersonSignOutEverywhere, func(c *contract.Command) { c.WSeq = ptr[int64](41) }), false},
		{"a workspace on a person's kind", mailie(contract.OpConsentWithdraw, func(c *contract.Command) { c.WorkspaceID = ptr(vecTeam) }), false},
		{"wseq null on a workspace's kind", wappie(contract.OpItemRename, func(c *contract.Command) { c.WSeq = nil }), false},
		{"actor_role on a person's kind", wappie(contract.OpPersonNoticesDismiss, func(c *contract.Command) { c.ActorRole = ptr(contract.RoleOwner) }), false},
		{"flags_raise adding read", wappie(contract.OpItemFlagsRaise, params(`{"before":{"can":["send"]},"after":{"can":["send","read"]}}`)), false},
		{"flags_raise adding nothing", wappie(contract.OpItemFlagsRaise, params(`{"before":{"can":["send"]},"after":{"can":["send"]}}`)), false},
		{"flags_drop adding a flag", wappie(contract.OpItemFlagsDrop, params(`{"before":{"can":["read","send"]},"after":{"can":["manage"]}}`)), false},
		{"flags_drop keeping a mailbox's act without read", mailie(contract.OpItemFlagsDrop, params(`{"before":{"can":["read","act"]},"after":{"can":["act"]}}`)), false},
		{"Wappie's act", wappie(contract.OpItemFlagsRaise, params(`{"before":{"can":["read"]},"after":{"can":["read","act"]}}`)), false},
		{"a flag twice", wappie(contract.OpItemFlagsRaise, params(`{"before":{"can":["read"]},"after":{"can":["read","send","send"]}}`)), false},
		{"access removed leaving a flag", wappie(contract.OpItemAccessRemove, params(`{"before":{"can":["read","send"]},"after":{"can":["send"]}}`)), false},
		{"two settings in one command", wappie(contract.OpItemRename, params(`{"before":{"label":"Vendas","capture":"on"},"after":{"label":"Vendas SP","capture":"paused"}}`)), false},
		{"another setting after than before", wappie(contract.OpItemSyncStop, params(`{"before":{"capture":"on"},"after":{"label":"x"}}`)), false},
		{"a setting on a kind that has none", wappie(contract.OpItemSyncNow, params(`{"before":{"capture":"on"},"after":{"capture":"on"}}`)), false},
		{"another kind's setting", wappie(contract.OpItemSyncStop, params(`{"before":{"paused":false},"after":{"paused":true}}`)), false},
		{"a pause from paused", wappie(contract.OpItemSyncStop, params(`{"before":{"capture":"paused"},"after":{"capture":"paused"}}`)), false},
		{"a label with an @", wappie(contract.OpItemRename, params(`{"before":{"label":"Vendas"},"after":{"label":"vendas@loja.com"}}`)), false},
		{"a cap raised", wappie(contract.OpAIIntegrationNarrow, params(`{"before":{"cap":100},"after":{"cap":500}}`)), false},
		{"an unknown function", wappie(contract.OpAIIntegrationNarrow, params(`{"before":{"function:summary":true},"after":{"function:summary":false}}`)), false},
		{"a revoke with no word on its results", wappie(contract.OpAIIntegrationRevoke, params(`{}`)), false},
		{"an installation added at a private address", wappie(contract.OpInstallationAdd, params(`{"origin":"https://10.0.0.5","name":"Matriz"}`)), false},
		{"a move out to the same team", wappie(contract.OpItemMoveOut, params(`{"before":{"workspace":"`+vecTeam+`"},"after":{"workspace":"`+vecTeam+`"}}`)), false},
		{"remove without confirm", mailie(contract.OpItemRemove, func(c *contract.Command) { c.Confirm = nil }), false},
		{"purge without confirm", mailie(contract.OpItemPurge, func(c *contract.Command) { c.Confirm = nil }), false},
		{"remove confirming another id", mailie(contract.OpItemRemove, func(c *contract.Command) { c.Confirm = ptr("acc_other") }), false},
		{"a registration deleted confirming another row", wappie(contract.OpItemRegistrationDelete, func(c *contract.Command) { c.Confirm = ptr("reg_2") }), false},
		{"confirm on a kind that asks none", wappie(contract.OpItemRename, func(c *contract.Command) { c.Confirm = ptr(vecNumber) }), false},
		{"consent.agree without an agreement", mailie(contract.OpConsentAgree, func(c *contract.Command) { c.Agreement = nil }), false},
		{"item.team_sync_on without an agreement", mailie(contract.OpItemTeamSyncOn, func(c *contract.Command) { c.Agreement = nil }), false},
		{"Mailie's team item.sync_resume without an agreement", mailie(contract.OpItemSyncResume, func(c *contract.Command) { c.Agreement = nil }), false},
		{"an agreement on a personal mailbox's resume", mailie(contract.OpItemSyncResume, func(c *contract.Command) { c.WorkspaceID = ptr(vecPersonal) }), false},
		{"an agreement on Wappie's resume", wappie(contract.OpItemSyncResume, func(c *contract.Command) {
			c.Agreement = &contract.Agreement{Revision: vecSyncText, Language: "pt-BR"}
		}), false},
		{"an agreement in another language", mailie(contract.OpConsentAgree, func(c *contract.Command) { c.Agreement.Language = "fr" }), false},
		{"item.team_sync_on from held", mailie(contract.OpItemTeamSyncOn, params(`{"before":{"sync":"held"},"after":{"sync":"on"}}`)), false},
		{"old_text on sync", mailie(contract.OpConsentAgree, params(`{"before":{"sync":"old_text"},"after":{"sync":"on"}}`)), false},
		{"an unknown kind", wappie(contract.OpItemRename, func(c *contract.Command) { c.Kind = "item.delete" }), false},
		{"Mailie's kind on Wappie", wappie(contract.OpItemRename, func(c *contract.Command) { c.Kind, c.Section = contract.OpItemPurge, contract.SectionEmailAccounts }), false},
		{"a section not the kind's", wappie(contract.OpItemRename, func(c *contract.Command) { c.Section = contract.SectionMCP }), false},
		{"a target member its kind does not name", wappie(contract.OpItemRename, func(c *contract.Command) { c.Target.Row = "reg_1" }), false},
		{"an unknown switch", wappie(contract.OpMCPSwitchOff, func(c *contract.Command) { c.Target.Switch = "send" }), false},
		{"based_on without the target's document", wappie(contract.OpItemFlagsRaise, func(c *contract.Command) { delete(c.BasedOn.Docs, vecOther) }), false},
		{"based_on naming a third person in the target's place", wappie(contract.OpItemFlagsRaise, func(c *contract.Command) {
			delete(c.BasedOn.Docs, vecOther)
			c.BasedOn.Docs[vecThird] = 3
		}), false},
		{"301 notices dismissed", wappie(contract.OpPersonNoticesDismiss, func(c *contract.Command) {
			c.Params = mustRaw(map[string]any{"notices": many(301, func(i int) contract.NoticeRef { return contract.NoticeRef{ID: fmt.Sprint(i), Version: 1} })})
		}), false},
		{"no notice dismissed", wappie(contract.OpPersonNoticesDismiss, params(`{"notices":[]}`)), false},
		{"a switch set to null", wappie(contract.OpMCPSwitchOff, params(`{"before":{"set":true},"after":{"set":null}}`)), false},
		{"a switch turned on from on", wappie(contract.OpMCPSwitchOn, params(`{"before":{"set":true},"after":{"set":true}}`)), false},
		{"a switch command naming effective", wappie(contract.OpMCPSwitchOff, params(`{"before":{"effective":true},"after":{"effective":false}}`)), false},
		{"a generation that is no UUID", wappie(contract.OpItemRename, func(c *contract.Command) { c.Generation = "restored-1" }), false},
		{"cseq 0", wappie(contract.OpItemRename, func(c *contract.Command) { c.CSeq = 0 }), false},
		{"wseq 0", wappie(contract.OpItemRename, func(c *contract.Command) { c.WSeq = ptr[int64](0) }), false},
		{"based_on.state_seq 0", wappie(contract.OpItemRename, func(c *contract.Command) { c.BasedOn.StateSeq = 0 }), false},
		{"a document's version 0", wappie(contract.OpItemRename, func(c *contract.Command) { c.BasedOn.Docs[vecSub] = 0 }), false},
		{"an actor that is no sub", wappie(contract.OpItemRename, func(c *contract.Command) { c.Actor = "owner" }), false},
		{"an installation added with its name missing", wappie(contract.OpInstallationAdd, params(`{"origin":"https://wappie.example.com"}`)), false},
		{"a notice dismissed twice", wappie(contract.OpPersonNoticesDismiss, params(`{"notices":[{"id":"812","version":2},{"id":"812","version":3}]}`)), false},
		{"a notice's id written ID", wappie(contract.OpPersonNoticesDismiss, params(`{"notices":[{"ID":"812","VERSION":2}]}`)), false},
		{"a move out from another workspace", wappie(contract.OpItemMoveOut, params(`{"before":{"workspace":"`+vecThird+`"},"after":{"workspace":"`+vecPersonal+`"}}`)), false},
		{"a cap narrowed to the same", wappie(contract.OpAIIntegrationNarrow, params(`{"before":{"cap":100},"after":{"cap":100}}`)), false},
		{"an integration paused from paused", wappie(contract.OpAIIntegrationNarrow, params(`{"before":{"paused":true},"after":{"paused":true}}`)), false},
		{"send withdrawn from old_text", mailie(contract.OpConsentWithdraw, params(`{"before":{"send":"old_text"},"after":{"send":"off"}}`)), true},
		{"actions agreed from old_text", mailie(contract.OpConsentAgree, params(`{"before":{"actions":"old_text"},"after":{"actions":"on"}}`)), true},
		{"a before on a kind that has no setting", wappie(contract.OpItemSyncNow, params(`{"before":{"capture":"on"}}`)), false},
		{"an after on a kind that has no setting", wappie(contract.OpItemSyncNow, params(`{"after":{"capture":"on"}}`)), false},
		{"a switch turned on to null", wappie(contract.OpMCPSwitchOn, params(`{"before":{"set":false},"after":{"set":null}}`)), false},
		{"a switch turned off from off", wappie(contract.OpMCPSwitchOff, params(`{"before":{"set":false},"after":{"set":false}}`)), false},
		{"sending paused from paused", wappie(contract.OpMCPSendPause, params(`{"before":{"send_paused":true},"after":{"send_paused":true}}`)), false},
		{"a hold lifted from no hold", mailie(contract.OpItemLiftHold, params(`{"before":{"held":false},"after":{"held":false}}`)), false},
		{"a removed index turned off from off", mailie(contract.OpItemRemovedIndexOff, params(`{"before":{"index_kept":false},"after":{"index_kept":false}}`)), false},
		{"Mailie's pause from paused", mailie(contract.OpItemSyncStop, params(`{"before":{"paused":true},"after":{"paused":true}}`)), false},
		{"an unknown role at issue", wappie(contract.OpItemRename, func(c *contract.Command) { c.ActorRole = ptr("guest") }), false},
		{"an id that is no UUID", wappie(contract.OpItemRename, func(c *contract.Command) { c.ID = "812" }), false},
		{"a type that is not command", wappie(contract.OpItemRename, func(c *contract.Command) { c.Type = "result" }), false},
		{"a notice dismissed at version 0", wappie(contract.OpPersonNoticesDismiss, params(`{"notices":[{"id":"812","version":0}]}`)), false},
		{"params null", wappie(contract.OpItemSyncNow, func(c *contract.Command) { c.Params = json.RawMessage(`null`) }), false},
		{"a target's person that is no sub", wappie(contract.OpItemFlagsRaise, func(c *contract.Command) {
			delete(c.BasedOn.Docs, vecOther)
			c.Target.Person, c.BasedOn.Docs["ana"] = "ana", 3
		}), false},
		{"secret 0", wappie(contract.OpItemRename, func(c *contract.Command) { c.Secret = 0 }), false},
		{"version 2 of the format", wappie(contract.OpItemRename, func(c *contract.Command) { c.V = 2 }), false},
	} {
		add(c.name, c.c, c.valid)
	}
	for _, c := range cases {
		raw := signed(c.c, SecretA)
		if got := commandValid(c.c.App, workspaceKind(c.c), raw); got != c.valid {
			return nil, fmt.Errorf("contractvec: command %q is valid %v, the design asks %v", c.name, got, c.valid)
		}
		out.Commands = append(out.Commands, CommandCase{Name: c.name, App: c.c.App, WorkspaceKind: workspaceKind(c.c), Value: raw, Valid: c.valid})
	}
	// A case written by hand: a member the app knows in another case is
	// one it does not know, so the command lacks its target.
	{
		raw := signed(vecCmd("wappie", contract.OpItemRename, nil), SecretA)
		raw, err := contract.SignCommand(edit(raw, `"target":`, `"Target":`), "wappie", SecretA)
		if err != nil {
			return nil, err
		}
		if commandValid("wappie", contract.KindTeam, raw) {
			return nil, fmt.Errorf("contractvec: a miscased target passes")
		}
		out.Commands = append(out.Commands, CommandCase{Name: "a target written Target", App: "wappie", WorkspaceKind: contract.KindTeam, Value: raw})
	}

	// Feeds.
	cmdAt := func(n int, secret string) json.RawMessage {
		return signed(wappie(contract.OpItemSyncNow, func(c *contract.Command) {
			c.ID, c.CSeq, c.WSeq = fmt.Sprintf("0199f3c4-0000-7000-8000-%012d", n), int64(n), ptr(int64(n))
		}), secret)
	}
	page := func(n int, mut func(*contract.CommandFeed)) json.RawMessage {
		f := contract.CommandFeed{Generation: vecGeneration, Head: int64(n), Items: []contract.CommandFeedItem{}, NextAfter: int64(n)}
		for i := 1; i <= n; i++ {
			f.Items = append(f.Items, contract.CommandFeedItem{CSeq: int64(i), Command: cmdAt(i, SecretA)})
		}
		if mut != nil {
			mut(&f)
		}
		return mustRaw(f)
	}
	for _, c := range []struct {
		name  string
		raw   json.RawMessage
		valid bool
	}{
		{"a page of two commands", page(2, nil), true},
		{"no command yet", page(0, nil), true},
		{"100 commands", page(100, nil), true},
		{"101 commands", page(101, nil), false},
		{"a page with more to come", page(2, func(f *contract.CommandFeed) { f.Head, f.NextAfter, f.More = 9, 2, true }), true},
		{"a command delivered again", page(2, func(f *contract.CommandFeed) { f.Items[0].Again = true }), true},
		{"a page that holds a command whose mac does not hold still stands", page(2, func(f *contract.CommandFeed) {
			f.Items[1].Command = cmdAt(2, SecretB)
		}), true},
		{"commands out of order", page(2, func(f *contract.CommandFeed) { f.Items[0], f.Items[1] = f.Items[1], f.Items[0] }), false},
		{"a command twice", page(2, func(f *contract.CommandFeed) { f.Items[1] = f.Items[0] }), false},
		{"a cseq past the head", page(2, func(f *contract.CommandFeed) { f.Head, f.NextAfter = 1, 1 }), false},
		{"cseq 0", page(1, func(f *contract.CommandFeed) { f.Items[0].CSeq = 0 }), false},
		{"next_after past the head", page(2, func(f *contract.CommandFeed) { f.NextAfter = 3 }), false},
		{"a head below 0", page(0, func(f *contract.CommandFeed) { f.Head, f.NextAfter = -1, 0 }), false},
		{"next_after below 0", page(1, func(f *contract.CommandFeed) { f.NextAfter = -1 }), false},
		{"a generation that is no UUID", page(1, func(f *contract.CommandFeed) { f.Generation = "1" }), false},
		{"items null", page(0, func(f *contract.CommandFeed) { f.Items = nil }), false},
		{"a command that is no object", page(1, func(f *contract.CommandFeed) { f.Items[0].Command = json.RawMessage(`"item.sync_now"`) }), false},
	} {
		if got := feedValid(c.raw); got != c.valid {
			return nil, fmt.Errorf("contractvec: feed %q is valid %v, the design asks %v", c.name, got, c.valid)
		}
		out.Feeds = append(out.Feeds, wireCase(c.name, c.raw, c.valid))
	}

	// ValidateIn with another workspace's kind than the command's: a
	// person's kind given a workspace, and a workspace's kind given none.
	for _, c := range []struct {
		name, kind string
		c          contract.Command
	}{
		{"a person's kind given a workspace", contract.KindTeam, wappie(contract.OpPersonSignOutEverywhere, nil)},
		{"a workspace's kind given none", "", wappie(contract.OpItemRename, nil)},
		{"a workspace's kind of an unknown kind", "shared", wappie(contract.OpItemRename, nil)},
	} {
		raw := signed(c.c, SecretA)
		if commandValid(c.c.App, c.kind, raw) {
			return nil, fmt.Errorf("contractvec: %q passes", c.name)
		}
		out.Commands = append(out.Commands, CommandCase{Name: c.name, App: c.c.App, WorkspaceKind: c.kind, Value: raw})
	}

	// Actions.
	tight := mailie(contract.OpConsentWithdraw, nil)
	old := mailie(contract.OpConsentWithdraw, func(c *contract.Command) {
		c.IssuedAt, c.FirstIssuedAt = at(-31*24*time.Hour), at(-31*24*time.Hour)
	})
	for _, a := range []struct {
		name       string
		c          contract.Command
		generation string
		signedAt   time.Time
		lastWSeq   *int64
		again      bool
		action     string
	}{
		{"a command taken in time runs", wappie(contract.OpItemRename, nil), vecGeneration, Now.Add(time.Second), ptr[int64](40), false, "run"},
		{"a command carried at its expiry runs", wappie(contract.OpItemRename, nil), vecGeneration, Now.Add(contract.CommandLifetime), nil, false, "run"},
		{"a command carried a second after its expiry: expired", wappie(contract.OpItemRename, nil), vecGeneration, Now.Add(contract.CommandLifetime + time.Second), nil, false, "expired"},
		{"a command of another generation: a reset", wappie(contract.OpItemRename, nil), vecGeneration2, Now, nil, false, "reset"},
		{"a tightening taken an hour on runs: it has no expiry", tight, vecGeneration, Now.Add(time.Hour), nil, false, "run"},
		{"a tightening issued 30 days ago runs", mailie(contract.OpConsentWithdraw, func(c *contract.Command) {
			c.IssuedAt, c.FirstIssuedAt = at(-30*24*time.Hour), at(-30*24*time.Hour)
		}), vecGeneration, Now, nil, false, "run"},
		{"a tightening issued 31 days ago: expired", old, vecGeneration, Now, nil, false, "expired"},
		{"the same delivered again runs", old, vecGeneration, Now, nil, true, "run"},
		{"a gap in wseq: it runs", wappie(contract.OpItemSyncStop, func(c *contract.Command) { c.WSeq = ptr[int64](45) }), vecGeneration, Now, ptr[int64](41 - 1), false, "run"},
		{"an overtaken wseq: invalid_command", wappie(contract.OpItemSyncStop, nil), vecGeneration, Now, ptr[int64](41), false, "invalid_command"},
		{"a tightening delivered again below the last wseq runs", wappie(contract.OpItemFlagsDrop, nil), vecGeneration, Now, ptr[int64](50), true, "run"},
		{"a command that is not valid: invalid_command", wappie(contract.OpItemRename, func(c *contract.Command) { c.ExpiresAt = nil }), vecGeneration, Now, nil, false, "invalid_command"},
	} {
		c := CommandAction{
			Name: a.name, App: a.c.App, Generation: a.generation, SignedAt: a.signedAt.Format(time.RFC3339),
			LastWSeq: a.lastWSeq, Again: a.again, Value: signed(a.c, SecretA),
		}
		c.Action = a.action
		if got := commandAction(c); got != a.action {
			return nil, fmt.Errorf("contractvec: action %q is %s, the design asks %s", a.name, got, a.action)
		}
		out.Actions = append(out.Actions, c)
	}
	{
		body := signed(mailie(contract.OpConsentWithdraw, nil), SecretA)
		c := CommandAction{Name: "a body naming another app: invalid_command", App: "wappie", Generation: vecGeneration,
			SignedAt: Now.Format(time.RFC3339), Action: "invalid_command",
			Value: json.RawMessage(withMAC(body, macOver([]byte(SecretA), "wappie", []byte(must(canonicalOf(body))))))}
		if commandAction(c) != c.Action {
			return nil, fmt.Errorf("contractvec: a command of another app runs")
		}
		out.Actions = append(out.Actions, c)
	}
	{
		c := CommandAction{Name: "a mac that does not hold: invalid_command", App: "wappie", Generation: vecGeneration,
			SignedAt: Now.Format(time.RFC3339), Value: signed(wappie(contract.OpItemRename, nil), SecretB), Action: "invalid_command"}
		if commandAction(c) != c.Action {
			return nil, fmt.Errorf("contractvec: a command under another secret runs")
		}
		out.Actions = append(out.Actions, c)
	}

	// Results.
	result := func(mut func(*contract.CommandResult)) json.RawMessage {
		r := contract.CommandResult{ID: vecCommand, Outcome: contract.OutcomeRan, StateSeq: ptr(vecSeq + 1), At: at(time.Second)}
		if mut != nil {
			mut(&r)
		}
		return mustRaw(r)
	}
	refused := func(code string, mut func(*contract.CommandResult)) json.RawMessage {
		return result(func(r *contract.CommandResult) {
			r.Outcome, r.Code, r.StateSeq = contract.OutcomeRefused, ptr(code), ptr(vecSeq)
			if mut != nil {
				mut(r)
			}
		})
	}
	holderDetail := func(n int, more int64) func(*contract.CommandResult) {
		return func(r *contract.CommandResult) {
			h := many(n, func(i int) contract.Holder {
				return contract.Holder{Kind: "person", Sub: ptr(vecOther), Row: fmt.Sprintf("usr_%04d", i)}
			})
			r.Detail = &contract.ResultDetail{Holders: &h, HoldersMore: ptr(more), Ends: ptr([]string{vecConnection})}
		}
	}
	for _, c := range []struct {
		name, app, kind string
		raw             json.RawMessage
		valid           bool
	}{
		{"a rename that ran", "wappie", contract.OpItemRename, result(nil), true},
		{"label_changed with the cleaned label", "wappie", contract.OpItemRename, refused(contract.CodeLabelChanged, func(r *contract.CommandResult) {
			r.Detail = &contract.ResultDetail{Cleaned: ptr("Vendas …5678")}
		}), true},
		{"others_have_access naming each holder", "wappie", contract.OpItemMoveOut, refused(contract.CodeOthersHaveAccess, holderDetail(2, 0)), true},
		{"others_have_access with 500 holders and more", "wappie", contract.OpItemMoveOut, refused(contract.CodeOthersHaveAccess, holderDetail(500, 12)), true},
		{"others_have_access with 501 holders", "wappie", contract.OpItemMoveOut, refused(contract.CodeOthersHaveAccess, holderDetail(501, 0)), false},
		{"a move in progress", "wappie", contract.OpItemMoveOut, result(func(r *contract.CommandResult) { r.Outcome, r.StateSeq = contract.OutcomeInProgress, nil }), true},
		{"last_reader on a drop", "mailie", contract.OpItemFlagsDrop, refused(contract.CodeLastReader, nil), true},
		{"memberships_behind, to retry after 30 s", "wappie", contract.OpItemSyncStop, refused(contract.CodeMembershipsBehind, func(r *contract.CommandResult) {
			r.RetryAfter = ptr[int64](30)
		}), true},
		{"rate_limited, to retry after an hour", "wappie", contract.OpItemSyncNow, refused(contract.CodeRateLimited, func(r *contract.CommandResult) {
			r.RetryAfter = ptr[int64](contract.MaxRetryAfter)
		}), true},
		{"item_busy with no retry_after: a backoff", "mailie", contract.OpItemSyncNow, refused(contract.CodeItemBusy, nil), true},
		{"team_closed", "mailie", contract.OpItemTeamSyncOff, refused(contract.CodeTeamClosed, nil), true},
		{"kind_not_accepted on a tightening kind", "wappie", contract.OpLicenceRelease, refused(contract.CodeKindNotAccepted, nil), true},
		{"kind_not_accepted on another kind", "wappie", contract.OpInstallationAdd, refused(contract.CodeKindNotAccepted, nil), true},
		{"a sign-out everywhere that ended 3 sessions", "mailie", contract.OpPersonSignOutEverywhere, result(func(r *contract.CommandResult) {
			r.Detail = &contract.ResultDetail{SessionsEnded: ptr[int64](3)}
		}), true},
		{"text off, and what it turned off with it", "wappie", contract.OpMCPSwitchOff, result(func(r *contract.CommandResult) {
			r.Detail = &contract.ResultDetail{AlsoOff: &[]string{contract.SwitchAttachments, contract.SwitchDrafts, contract.SwitchAI}}
		}), true},
		{"drafts off, turning nothing else off", "wappie", contract.OpMCPSwitchOff, result(func(r *contract.CommandResult) {
			r.Detail = &contract.ResultDetail{AlsoOff: &[]string{}}
		}), true},
		{"a link that never connected, purged at once", "mailie", contract.OpItemRemove, result(func(r *contract.CommandResult) {
			r.Detail = &contract.ResultDetail{Purged: ptr(true)}
		}), true},
		{"a mailbox removed, kept 30 days", "mailie", contract.OpItemRemove, result(nil), true},
		{"expired, no state_seq", "wappie", contract.OpItemRename, refused(contract.CodeExpired, func(r *contract.CommandResult) { r.StateSeq = nil }), true},
		{"expired on a tightening kind", "mailie", contract.OpConsentWithdraw, refused(contract.CodeExpired, func(r *contract.CommandResult) { r.StateSeq = nil }), true},
		{"invalid_command, no state_seq", "wappie", contract.OpItemRename, refused(contract.CodeInvalidCommand, func(r *contract.CommandResult) { r.StateSeq = nil }), true},
		{"a person's not_held, no state_seq", "wappie", contract.OpPersonSignOutEverywhere, refused(contract.CodeNotHeld, func(r *contract.CommandResult) { r.StateSeq = nil }), true},
		{"a workspace kind's not_held", "wappie", contract.OpItemFlagsRaise, refused(contract.CodeNotHeld, nil), true},
		{"state_changed on a tightening kind", "mailie", contract.OpConsentWithdraw, refused(contract.CodeStateChanged, nil), true},
		{"owner_only on a tightening kind", "wappie", contract.OpMCPSwitchOff, refused(contract.CodeOwnerOnly, nil), true},
		{"refused without a code", "wappie", contract.OpItemRename, result(func(r *contract.CommandResult) { r.Outcome = contract.OutcomeRefused }), false},
		{"ran with a code", "wappie", contract.OpItemRename, result(func(r *contract.CommandResult) { r.Code = ptr(contract.CodeStateChanged) }), false},
		{"retry_after on a final code", "wappie", contract.OpItemRename, refused(contract.CodeStateChanged, func(r *contract.CommandResult) {
			r.RetryAfter = ptr[int64](30)
		}), false},
		{"retry_after on team_closed", "mailie", contract.OpItemTeamSyncOff, refused(contract.CodeTeamClosed, func(r *contract.CommandResult) {
			r.RetryAfter = ptr[int64](30)
		}), false},
		{"retry_after on kind_not_accepted", "wappie", contract.OpLicenceRelease, refused(contract.CodeKindNotAccepted, func(r *contract.CommandResult) {
			r.RetryAfter = ptr[int64](30)
		}), false},
		{"retry_after of 0", "wappie", contract.OpItemSyncStop, refused(contract.CodeMembershipsBehind, func(r *contract.CommandResult) {
			r.RetryAfter = ptr[int64](0)
		}), false},
		{"retry_after over an hour", "wappie", contract.OpItemSyncStop, refused(contract.CodeMembershipsBehind, func(r *contract.CommandResult) {
			r.RetryAfter = ptr[int64](contract.MaxRetryAfter + 1)
		}), false},
		{"a detail that belongs to another code", "wappie", contract.OpItemRename, refused(contract.CodeStateChanged, func(r *contract.CommandResult) {
			r.Detail = &contract.ResultDetail{Cleaned: ptr("Vendas")}
		}), false},
		{"label_changed without its detail", "wappie", contract.OpItemRename, refused(contract.CodeLabelChanged, nil), false},
		{"a detail of no shape", "wappie", contract.OpItemRename, edit(result(nil), `"detail":null`, `"detail":{}`), false},
		{"a detail of two shapes", "wappie", contract.OpMCPSwitchOff, result(func(r *contract.CommandResult) {
			r.Detail = &contract.ResultDetail{SessionsEnded: ptr[int64](1), AlsoOff: &[]string{contract.SwitchAI}}
		}), false},
		{"also_off naming an unknown switch", "wappie", contract.OpMCPSwitchOff, result(func(r *contract.CommandResult) {
			r.Detail = &contract.ResultDetail{AlsoOff: &[]string{"send"}}
		}), false},
		{"a holder of an unknown kind in others_have_access", "wappie", contract.OpItemMoveOut, refused(contract.CodeOthersHaveAccess, func(r *contract.CommandResult) {
			holderDetail(1, 0)(r)
			(*r.Detail.Holders)[0].Kind = "admin"
		}), false},
		{"state_seq null with ran", "wappie", contract.OpItemRename, result(func(r *contract.CommandResult) { r.StateSeq = nil }), false},
		{"a refusal with no state_seq", "wappie", contract.OpItemRename, refused(contract.CodeStateChanged, func(r *contract.CommandResult) { r.StateSeq = nil }), false},
		{"expired with a state_seq", "wappie", contract.OpItemRename, refused(contract.CodeExpired, nil), false},
		{"an unknown code", "wappie", contract.OpItemRename, refused("conflict", nil), false},
		{"a code the kind does not answer", "wappie", contract.OpItemRename, refused(contract.CodeLastReader, nil), false},
		{"state_changed on a kind that does not answer it", "wappie", contract.OpMCPConnectionSeen, refused(contract.CodeStateChanged, nil), false},
		{"team_closed on a person's kind", "wappie", contract.OpPersonSignOutEverywhere, refused(contract.CodeTeamClosed, nil), false},
		{"a person's not_held with a state_seq", "wappie", contract.OpPersonSignOutEverywhere, refused(contract.CodeNotHeld, nil), false},
		{"a workspace kind's not_held with no state_seq", "wappie", contract.OpItemFlagsRaise, refused(contract.CodeNotHeld, func(r *contract.CommandResult) { r.StateSeq = nil }), false},
		{"in_progress on a rename", "wappie", contract.OpItemRename, result(func(r *contract.CommandResult) { r.Outcome = contract.OutcomeInProgress }), false},
		{"sessions_ended on a rename", "wappie", contract.OpItemRename, result(func(r *contract.CommandResult) {
			r.Detail = &contract.ResultDetail{SessionsEnded: ptr[int64](1)}
		}), false},
		{"a sign-out everywhere without its count", "wappie", contract.OpPersonSignOutEverywhere, result(nil), false},
		{"also_off on switch_on", "wappie", contract.OpMCPSwitchOn, result(func(r *contract.CommandResult) {
			r.Detail = &contract.ResultDetail{AlsoOff: &[]string{contract.SwitchAI}}
		}), false},
		{"purged false", "mailie", contract.OpItemRemove, result(func(r *contract.CommandResult) {
			r.Detail = &contract.ResultDetail{Purged: ptr(false)}
		}), false},
		{"state_seq 0", "wappie", contract.OpItemRename, result(func(r *contract.CommandResult) { r.StateSeq = ptr[int64](0) }), false},
		{"an id that is no UUID", "wappie", contract.OpItemRename, result(func(r *contract.CommandResult) { r.ID = "812" }), false},
		{"no at", "wappie", contract.OpItemRename, edit(result(nil), `,"at":"2026-10-13T12:00:01Z"`, ``), false},
		{"in_progress with a detail", "wappie", contract.OpItemMoveOut, result(func(r *contract.CommandResult) {
			r.Outcome, r.StateSeq = contract.OutcomeInProgress, nil
			holderDetail(1, 0)(r)
		}), false},
		{"a holders detail on another code", "wappie", contract.OpItemMoveOut, refused(contract.CodeNotSoleOwner, holderDetail(1, 0)), false},
		{"also_off naming a switch twice", "wappie", contract.OpMCPSwitchOff, result(func(r *contract.CommandResult) {
			r.Detail = &contract.ResultDetail{AlsoOff: &[]string{contract.SwitchAI, contract.SwitchAI}}
		}), false},
		{"sessions_ended below 0", "mailie", contract.OpPersonSignOutEverywhere, result(func(r *contract.CommandResult) {
			r.Detail = &contract.ResultDetail{SessionsEnded: ptr[int64](-1)}
		}), false},
		{"outcome null", "wappie", contract.OpItemRename, edit(result(nil), `"outcome":"ran"`, `"outcome":null`), false},
		{"an outcome the contract does not know", "wappie", contract.OpItemRename, result(func(r *contract.CommandResult) { r.Outcome = "done" }), false},
		{"a member written Outcome", "wappie", contract.OpItemRename, edit(result(nil), `"outcome"`, `"Outcome"`), false},
		{"a member missing", "wappie", contract.OpItemRename, edit(result(nil), `,"detail":null`, ``), false},
		{"a member the platform does not know", "wappie", contract.OpItemRename, edit(result(nil), `"detail":null`, `"detail":null,"message":"ok"`), false},
	} {
		if got := resultValid(c.app, c.kind, c.raw); got != c.valid {
			return nil, fmt.Errorf("contractvec: result %q is valid %v, the design asks %v", c.name, got, c.valid)
		}
		out.Results = append(out.Results, ResultCase{Name: c.name, App: c.app, Kind: c.kind, Value: c.raw, Valid: c.valid})
	}

	// Batches.
	batch := func(n int, mut func([]contract.CommandResult)) string {
		rs := many(n, func(i int) contract.CommandResult {
			return contract.CommandResult{ID: fmt.Sprintf("0199f3c4-0000-7000-8000-%012d", i+1), Outcome: contract.OutcomeRan, StateSeq: ptr(vecSeq), At: at(time.Second)}
		})
		if mut != nil {
			mut(rs)
		}
		return string(mustRaw(contract.CommandResults{Results: rs}))
	}
	for _, c := range []struct {
		name  string
		body  string
		valid bool
	}{
		{"one result", batch(1, nil), true},
		{"100 results", batch(100, nil), true},
		{"101 results", batch(101, nil), false},
		{"no result", batch(0, nil), false},
		{"results null", `{"results":null}`, false},
		{"a result twice", batch(2, func(rs []contract.CommandResult) { rs[1].ID = rs[0].ID }), false},
		{"a result that does not validate", batch(2, func(rs []contract.CommandResult) { rs[1].StateSeq = nil }), false},
		{"results written Results", strings.Replace(batch(1, nil), `"results"`, `"Results"`, 1), false},
		{"a generation beside the results", strings.Replace(batch(1, nil), `{"results"`, `{"generation":"`+vecGeneration+`","results"`, 1), false},
		{"a body at 256 KiB", padTo(batch(1, nil), contract.ResultsBodyLimit), true},
		{"a body over 256 KiB", padTo(batch(1, nil), contract.ResultsBodyLimit+1), false},
	} {
		if got := batchValid([]byte(c.body)); got != c.valid {
			return nil, fmt.Errorf("contractvec: batch %q is valid %v, the design asks %v", c.name, got, c.valid)
		}
		out.Batches = append(out.Batches, BodyCase{Name: c.name, Body: c.body, Valid: c.valid})
	}

	// Classes.
	for _, code := range contract.CommandRefusalCodes() {
		for _, tightening := range []bool{false, true} {
			out.Classes = append(out.Classes, ClassCase{Code: code, Tightening: tightening, Class: contract.CommandRefusalClass(code, tightening)})
		}
	}
	return out, nil
}

// padTo is body, a JSON object, padded with spaces after its first member's
// name to n bytes.
func padTo(body string, n int) string {
	i := strings.Index(body, ":") + 1
	return body[:i] + strings.Repeat(" ", n-len(body)) + body[i:]
}

// MACCase is one command as an app receives it, the secrets it holds, its
// canonical text without its mac, the MAC a signer computes over that text
// under the first secret, and whether VerifyCommand takes it.
type MACCase struct {
	Name    string   `json:"name"`
	App     string   `json:"app"`
	Secrets []string `json:"secrets"`
	Command string   `json:"command"`
	JCS     string   `json:"jcs"`
	MAC     string   `json:"mac"`
	Valid   bool     `json:"valid"`
}

// CommandMACs is command-macs.json.
type CommandMACs struct {
	Format      string    `json:"format"`
	Version     int       `json:"version"`
	Kind        string    `json:"kind"`
	Description string    `json:"description"`
	Label       string    `json:"label"`
	MACs        []MACCase `json:"macs"`
}

// macOver is the MAC of msg, the canonical command, for app under key, any
// bytes.
func macOver(key []byte, app string, msg []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(contract.CommandMACLabel + "\n" + app + "\n"))
	h.Write(msg)
	return "v1=" + hex.EncodeToString(h.Sum(nil))
}

// canonicalOf is the JCS text of raw without its mac, as VerifyCommand
// computes it.
func canonicalOf(raw []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		return "", err
	}
	delete(v, "mac")
	b, err := jcs.Marshal(v)
	return string(b), err
}

// macMember is a command's mac member as its text holds it.
var macMember = regexp.MustCompile(`"mac":\s*"[^"]*"`)

// withMAC is raw, a command, with its mac member set to mac, the rest kept
// byte for byte.
func withMAC(raw []byte, mac string) string {
	if !macMember.Match(raw) {
		panic("contractvec: no mac")
	}
	return string(macMember.ReplaceAll(raw, []byte(`"mac":"`+mac+`"`)))
}

func commandMACs() (any, error) {
	out := CommandMACs{
		Format: Format, Version: 1, Kind: "command-macs", Label: contract.CommandMACLabel,
		Description: "The command's MAC (SPEC section 11.19): mac = \"v1=\" + lowercase hex(HMAC-SHA256(key = the secret's 43-character text, msg = label || \"\\n\" || app || \"\\n\" || JCS(the command as received, without mac))). command: the exact text an app receives; jcs: its canonical text without mac (RFC 8785), \"\" when it has none; mac: what a signer computes over jcs for app under the first of secrets, \"\" when jcs is; valid: whether contract.VerifyCommand takes command for app under secrets, each of which it tries.",
	}
	base := vecCmd("wappie", contract.OpItemRename, nil)
	plain := signed(base, SecretA)
	add := func(name, app string, secrets []string, command string, valid bool) error {
		canonical, err := canonicalOf([]byte(command))
		mac := ""
		if err != nil || !strictJSON([]byte(command)) {
			canonical = ""
		} else {
			mac = macOver([]byte(secrets[0]), app, []byte(canonical))
		}
		_, verr := contract.VerifyCommand([]byte(command), app, secrets)
		if (verr == nil) != valid {
			return fmt.Errorf("contractvec: mac %q verifies %v, the design asks %v (%v)", name, verr == nil, valid, verr)
		}
		out.MACs = append(out.MACs, MACCase{Name: name, App: app, Secrets: secrets, Command: command, JCS: canonical, MAC: mac, Valid: valid})
		return nil
	}
	one := []string{SecretA}
	// As served: compact JCS. And as an app may receive it: indented, or
	// with its members in another order; the MAC is over the canonical
	// text, so each verifies.
	var indented bytes.Buffer
	if err := json.Indent(&indented, plain, "", "  "); err != nil {
		return nil, err
	}
	reordered, err := reorder(plain)
	if err != nil {
		return nil, err
	}
	// An unknown member at the top and in params, and a time of 120 ms
	// written .120Z: signed over the text as the platform writes it.
	unknown, err := contract.SignCommand(edit(edit(plain, `"kind":`, `"priority":"high","kind":`), `"after":{`, `"reason":"typo","after":{`), "wappie", SecretA)
	if err != nil {
		return nil, err
	}
	fraction, err := contract.SignCommand(edit(edit(plain, `"issued_at":"2026-10-13T12:00:00Z"`, `"issued_at":"2026-10-13T12:00:00.120Z"`),
		`"first_issued_at":"2026-10-13T12:00:00Z"`, `"first_issued_at":"2026-10-13T12:00:00.120Z"`), "wappie", SecretA)
	if err != nil {
		return nil, err
	}
	escaped, err := contract.SignCommand(edit(plain, `"label":"Vendas SP"`, `"label":"P\u0026D <SP>"`), "wappie", SecretA)
	if err != nil {
		return nil, err
	}
	var re contract.Command
	if err := json.Unmarshal(fraction, &re); err != nil {
		return nil, err
	}
	reencoded := withMAC(fraction, macOver([]byte(SecretA), "wappie", []byte(must(canonicalOf(mustRaw(re))))))
	var unknownStruct contract.Command
	if err := json.Unmarshal(unknown, &unknownStruct); err != nil {
		return nil, err
	}
	dropped := withMAC(unknown, macOver([]byte(SecretA), "wappie", []byte(must(canonicalOf(mustRaw(unknownStruct))))))
	decoded, err := base64.RawURLEncoding.DecodeString(SecretA)
	if err != nil {
		return nil, err
	}
	asText := must(canonicalOf(plain))
	var generic map[string]any
	if err := json.Unmarshal(escaped, &generic); err != nil {
		return nil, err
	}
	delete(generic, "mac")
	goJSON, err := json.Marshal(generic)
	if err != nil {
		return nil, err
	}
	mailieCmd := signed(vecCmd("mailie", contract.OpConsentWithdraw, nil), SecretB)
	mailieBody := signed(vecCmd("mailie", contract.OpConsentWithdraw, nil), SecretA)
	forWappie := withMAC(mailieBody, macOver([]byte(SecretA), "wappie", []byte(must(canonicalOf(mailieBody)))))
	for _, c := range []struct {
		name    string
		app     string
		secrets []string
		command string
		valid   bool
	}{
		{"a command as served: compact JCS", "wappie", one, string(plain), true},
		{"the same indented", "wappie", one, indented.String(), true},
		{"the same with its members in another order", "wappie", one, reordered, true},
		{"an unknown member at the top and in params", "wappie", one, string(unknown), true},
		{"times of 120 milliseconds, written .120Z", "wappie", one, string(fraction), true},
		{"a label with & and <, which JCS writes as they are", "wappie", one, string(escaped), true},
		{"Mailie's tightening, during a rotation: the next secret", "mailie", []string{SecretA, SecretB}, string(mailieCmd), true},
		{"another app", "mailie", one, string(plain), false},
		{"a body naming another app, under a MAC for this one", "wappie", one, forWappie, false},
		{"another secret", "wappie", []string{SecretB}, string(plain), false},
		{"a member changed after signing", "wappie", one, string(edit(plain, `"Vendas SP"`, `"Vendas RJ"`)), false},
		{"a member added after signing", "wappie", one, string(edit(plain, `"kind":`, `"priority":"high","kind":`)), false},
		{"the key decoded as bytes", "wappie", one, withMAC(plain, macOver(decoded, "wappie", []byte(asText))), false},
		{"a MAC over JSON that is not JCS", "wappie", one, withMAC(escaped, macOver([]byte(SecretA), "wappie", goJSON)), false},
		{"a MAC over the received text, not its canonical form", "wappie", one, withMAC([]byte(indented.String()),
			macOver([]byte(SecretA), "wappie", []byte(strings.Replace(indented.String(), `"mac": "`+must(macOf(plain))+`",`, "", 1)))), false},
		{"a MAC over a re-encoded struct: .120Z written .12Z", "wappie", one, reencoded, false},
		{"a MAC over a re-encoded struct: an unknown member dropped", "wappie", one, dropped, false},
		{"no mac", "wappie", one, strings.Replace(string(plain), `,"mac":"`+must(macOf(plain))+`"`, "", 1), false},
		{"a mac in capitals", "wappie", one, withMAC(plain, "v1="+strings.ToUpper(strings.TrimPrefix(must(macOf(plain)), "v1="))), false},
		{"a mac with no version", "wappie", one, withMAC(plain, strings.TrimPrefix(must(macOf(plain)), "v1=")), false},
		{"a member twice", "wappie", one, strings.Replace(string(plain), `"kind":`, `"kind":"item.purge","kind":`, 1), false},
	} {
		if err := add(c.name, c.app, c.secrets, c.command, c.valid); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// macOf is the mac member raw carries.
func macOf(raw []byte) (string, error) {
	var v struct {
		MAC string `json:"mac"`
	}
	err := json.Unmarshal(raw, &v)
	return v.MAC, err
}

// reorder is raw, an object, with its top-level members written in reverse
// order.
func reorder(raw []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.Token(); err != nil {
		return "", err
	}
	var names []string
	values := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return "", err
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return "", err
		}
		names = append(names, tok.(string))
		values[tok.(string)] = v
	}
	var b strings.Builder
	b.WriteString("{")
	for i := len(names) - 1; i >= 0; i-- {
		name, _ := json.Marshal(names[i])
		b.Write(name)
		b.WriteString(":")
		b.Write(values[names[i]])
		if i > 0 {
			b.WriteString(",")
		}
	}
	b.WriteString("}")
	return b.String(), nil
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
