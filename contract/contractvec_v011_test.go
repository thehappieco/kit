package contract_test

// The kit's generator of wire-v011.json (kit v0.11.0, SPEC sections 11.18
// and 11.19): what rides the relink's release but is not the relink. A
// numbers row's can_relink; Mailie's item.rename, its section's accepts
// and a mailbox's grant_ended; a mailbox whose sync is off with its index
// kept; label_changed with a null cleaned; and the token feed's pages, a
// record of another generation than its page's. Every case states the
// outcome the spec asks of it, and the generator fails rather than write a
// case whose outcome the code does not give.

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/thehappieco/kit/contract"
)

// WireV011 is wire-v011.json.
type WireV011 struct {
	Format      string        `json:"format"`
	Version     int           `json:"version"`
	Kind        string        `json:"kind"`
	Description string        `json:"description"`
	Sections    []WireCase    `json:"sections"`
	Commands    []CommandCase `json:"commands"`
	Results     []ResultCase  `json:"results"`
	Pages       []ActionCase  `json:"pages"`
}

// pageAction is what an app holding generation does with a token feed page
// of one record (kit v0.11.0, SPEC section 11.18): a page that does not
// decode or validate, "invalid"; a page of another generation is a reset,
// whatever its record says; in a page of the app's own generation, another
// app's record is refused, and a record whose generation is a valid UUID
// other than its page's is a bad record, narrowed as invalid_record, never
// a reset (the platform never sends a mixed page); else the record is taken
// as recordAction takes it.
func pageAction(app, generation string, raw json.RawMessage) (string, *string) {
	var f contract.TokenFeed
	if json.Unmarshal(raw, &f) != nil || f.Validate() != nil || len(f.Items) != 1 {
		return "invalid", nil
	}
	if f.Generation != generation {
		return "reset", nil
	}
	r, _ := f.Items[0].Record()
	switch {
	case contract.ValidApp(r.App) && r.App != app:
		return "refuse", nil
	case contract.ValidUUID(r.Generation) && r.Generation != f.Generation:
		code := contract.RefusedInvalidRecord
		return "narrow", &code
	}
	return recordAction(app, f.Generation, f.Items[0].Token)
}

func wireV011() (any, error) {
	out := WireV011{
		Format: Format, Version: 1, Kind: "wire-v011",
		Description: "What kit v0.11.0 adds beside the relink (SPEC sections 11.18 and 11.19). sections: settings documents, valid as wire-settings.json's sections are: a Wappie numbers row's optional can_relink, true or false, absent (a reader then falls back to connection logged_out_phone) and never null; the relink in Wappie's accepts and the rename in Mailie's email-accounts accepts; a mailbox's reason grant_ended, on needs_reauth and error only; a mailbox whose sync is off with its index still kept. commands: Mailie's item.rename as the platform serves it, signed with SecretA of signatures.json, valid as wire-commands.json's are (before is the snapshot's label or null, after a label). results: label_changed with a null cleaned, decoded strictly (a cleaned that is null is told from one that is absent), then ValidateFor(app, kind): null only with label_changed and only on an item.rename (Wappie's, the reference app's, Mailie's). pages: a token feed page of one record and what an app holding generation does with it: a page of another generation is a reset whatever its record says; in a page of its own generation a record of another generation is a bad record, narrowed as invalid_record, never a reset; else as wire-tokens.json's actions.",
	}

	// Sections.
	numbers := func(app string, accepts []string, mut func(*contract.NumberRow)) json.RawMessage {
		data := vecNumbers(func(s *contract.NumbersSettings) {
			if mut != nil {
				mut(&s.Items[0])
			}
		})
		return mustRaw(sectionDoc(app, contract.SectionNumbers, data, func(d *contract.SettingsDoc) { d.Accepts = accepts }))
	}
	relinkable := func(can *bool) func(*contract.NumberRow) {
		return func(r *contract.NumberRow) {
			r.Connection, r.LastConnectedAt, r.Capture, r.PausedBy, r.CanResume, r.ReadOnly = "logged_out_phone", ptr(at(-48*time.Hour)), "on", nil, false, true
			r.CanRelink = can
		}
	}
	none := []string{}
	emails := func(accepts []string, mut func(*contract.MailboxRow)) json.RawMessage {
		data := vecEmailAccounts(func(s *contract.EmailAccountsSettings) { s.Items = []contract.MailboxRow{vecMailboxRow(mut)} })
		return mustRaw(sectionDoc("mailie", contract.SectionEmailAccounts, data, func(d *contract.SettingsDoc) { d.Accepts = accepts }))
	}
	mailieAccepts := []string{contract.OpItemRename, contract.OpItemSyncNow, contract.OpItemSyncStop, contract.OpItemSyncResume}
	reason := func(status, reason string) func(*contract.MailboxRow) {
		return func(m *contract.MailboxRow) { m.Status, m.Reason = status, ptr(reason) }
	}
	base := numbers("wappie", none, relinkable(ptr(true)))
	for _, c := range []settingsCase{
		{"a number logged out by its phone, which can be linked again", base, true},
		{"a number logged out by its phone that Wappie holds no identity of: can_relink false", numbers("wappie", none, relinkable(ptr(false))), true},
		{"a number from before kit v0.11.0: can_relink absent", numbers("wappie", none, relinkable(nil)), true},
		{"an online number that cannot be linked again", numbers("wappie", none, func(r *contract.NumberRow) { r.CanRelink = ptr(false) }), true},
		{"the relink in Wappie's accepts", numbers("wappie", []string{contract.OpItemRename, contract.OpItemRelink}, relinkable(ptr(true))), true},
		{"the reference app's number with can_relink, the relink accepted", numbers(contract.ReferenceApp, []string{contract.OpItemRelink}, relinkable(ptr(true))), true},
		{"can_relink null", edit(base, `"can_relink":true`, `"can_relink":null`), false},
		{"can_relink as text", edit(base, `"can_relink":true`, `"can_relink":"true"`), false},
		{"can_relink written Can_relink", edit(base, `"can_relink":true`, `"Can_relink":true`), false},
		{"can_relink twice", edit(base, `"can_relink":true`, `"can_relink":true,"can_relink":false`), false},
		{"the relink in Mailie's accepts", emails([]string{contract.OpItemRelink}, nil), false},
		{"the rename in Mailie's email-accounts accepts", emails(mailieAccepts, nil), true},
		{"the rename in Mailie's permissions accepts", mustRaw(sectionDoc("mailie", contract.SectionPermissions, vecPermissions(nil), func(d *contract.SettingsDoc) {
			d.Accepts = []string{contract.OpItemRename}
		})), false},
		{"a grant the provider ended: needs_reauth, grant_ended", emails(none, reason("needs_reauth", "grant_ended")), true},
		{"a grant the provider ended: error, grant_ended", emails(none, reason("error", "grant_ended")), true},
		{"grant_ended on a connected mailbox", emails(none, reason("connected", "grant_ended")), false},
		{"grant_ended on a removed mailbox", emails(none, func(m *contract.MailboxRow) {
			reason("removed", "grant_ended")(m)
			m.Removed = &contract.MailboxRemoved{RemovedAt: at(-time.Hour), PurgeAfter: at(30 * 24 * time.Hour), IndexKept: true}
		}), false},
		{"a reason written in capitals", emails(none, reason("needs_reauth", "GRANT_ENDED")), false},
		{"sync off with the index still kept", emails(none, func(m *contract.MailboxRow) { m.Sync.On, m.Sync.Indexed = false, "complete" }), true},
		{"sync off with part of the index kept", emails(none, func(m *contract.MailboxRow) { m.Sync.On, m.Sync.Indexed = false, "partial" }), true},
	} {
		if got := sectionValid(c.raw); got != c.valid {
			return nil, fmt.Errorf("contractvec: section %q is valid %v, the spec asks %v", c.name, got, c.valid)
		}
		out.Sections = append(out.Sections, wireCase(c.name, c.raw, c.valid))
	}

	// Commands: Mailie's rename.
	mailie := func(mut func(*contract.Command)) contract.Command {
		return vecCmd("mailie", contract.OpItemRename, mut)
	}
	params := func(p string) func(*contract.Command) {
		return func(c *contract.Command) { c.Params = json.RawMessage(p) }
	}
	for _, c := range []struct {
		name  string
		c     contract.Command
		valid bool
	}{
		{"Mailie's rename of a team's mailbox with no label yet", mailie(nil), true},
		{"Mailie's rename of a labelled mailbox", mailie(params(`{"before":{"label":"Suporte"},"after":{"label":"Suporte SP"}}`)), true},
		{"Mailie's rename of a personal mailbox", mailie(func(c *contract.Command) { c.WorkspaceID = ptr(vecPersonal) }), true},
		{"a member's rename, which Mailie judges", mailie(func(c *contract.Command) { c.ActorRole = ptr(contract.RoleMember) }), true},
		{"a rename to an address", mailie(params(`{"before":{"label":null},"after":{"label":"suporte@loja.com"}}`)), false},
		{"a rename to no label", mailie(params(`{"before":{"label":"Suporte"},"after":{"label":null}}`)), false},
		{"a rename with no before", mailie(params(`{"after":{"label":"Suporte"}}`)), false},
		{"a rename of another setting", mailie(params(`{"before":{"paused":false},"after":{"paused":true}}`)), false},
		{"a rename with no expiry", mailie(func(c *contract.Command) { c.ExpiresAt = nil }), false},
		{"a rename confirming the mailbox", mailie(func(c *contract.Command) { c.Confirm = ptr(vecMailbox) }), false},
		{"Mailie's rename in the permissions section", mailie(func(c *contract.Command) { c.Section = contract.SectionPermissions }), false},
	} {
		raw := signed(c.c, SecretA)
		if got := commandValid(c.c.App, workspaceKind(c.c), raw); got != c.valid {
			return nil, fmt.Errorf("contractvec: command %q is valid %v, the spec asks %v", c.name, got, c.valid)
		}
		out.Commands = append(out.Commands, CommandCase{Name: c.name, App: c.c.App, WorkspaceKind: workspaceKind(c.c), Value: raw, Valid: c.valid})
	}

	// Results: a null cleaned.
	refused := func(code, detail string) json.RawMessage {
		r := contract.CommandResult{ID: vecCommand, Outcome: contract.OutcomeRefused, Code: ptr(code), StateSeq: ptr(vecSeq), At: at(time.Second)}
		return edit(mustRaw(r), `"detail":null`, `"detail":`+detail)
	}
	null := `{"cleaned":null}`
	for _, c := range []struct {
		name, app, kind string
		raw             json.RawMessage
		valid           bool
	}{
		{"a rename to a name Wappie keeps none of: cleaned null", "wappie", contract.OpItemRename, refused(contract.CodeLabelChanged, null), true},
		{"the reference app's rename, cleaned null", contract.ReferenceApp, contract.OpItemRename, refused(contract.CodeLabelChanged, null), true},
		{"Mailie's rename to a name it keeps none of: cleaned null", "mailie", contract.OpItemRename, refused(contract.CodeLabelChanged, null), true},
		{"Mailie's rename with the cleaned label", "mailie", contract.OpItemRename, refused(contract.CodeLabelChanged, `{"cleaned":"Suporte …5678"}`), true},
		{"Mailie's rename refused state_changed", "mailie", contract.OpItemRename, refused(contract.CodeStateChanged, "null"), true},
		{"cleaned null on an installation's rename", "wappie", contract.OpInstallationRename, refused(contract.CodeLabelChanged, null), false},
		{"cleaned null on an installation added", "wappie", contract.OpInstallationAdd, refused(contract.CodeLabelChanged, null), false},
		{"cleaned null with another code", "wappie", contract.OpItemRename, refused(contract.CodeStateChanged, null), false},
		{"cleaned null and a cleaned label", "wappie", contract.OpItemRename, refused(contract.CodeLabelChanged, `{"cleaned":null,"cleaned":"Vendas"}`), false},
		{"cleaned null beside another shape", "wappie", contract.OpItemRename, refused(contract.CodeLabelChanged, `{"cleaned":null,"sessions_ended":1}`), false},
		{"cleaned written Cleaned, null", "wappie", contract.OpItemRename, refused(contract.CodeLabelChanged, `{"Cleaned":null}`), false},
		{"Mailie's rename refused label_changed with no detail", "mailie", contract.OpItemRename, refused(contract.CodeLabelChanged, "null"), false},
		{"Mailie's rename refused last_reader", "mailie", contract.OpItemRename, refused(contract.CodeLastReader, "null"), false},
	} {
		if got := resultValid(c.app, c.kind, c.raw); got != c.valid {
			return nil, fmt.Errorf("contractvec: result %q is valid %v, the spec asks %v", c.name, got, c.valid)
		}
		out.Results = append(out.Results, ResultCase{Name: c.name, App: c.app, Kind: c.kind, Value: c.raw, Valid: c.valid})
	}

	// Pages of the token feed.
	page := func(generation string, r contract.TokenRecord) json.RawMessage {
		it, err := contract.NewTokenFeedItem(90, r)
		if err != nil {
			panic(err)
		}
		return mustRaw(contract.TokenFeed{
			Generation: generation, GenerationConfirmed: true, Head: 90, PublishedThrough: contract.T(Now.Add(4 * time.Second)),
			Items: []contract.TokenFeedItem{it}, NextAfter: 90,
		})
	}
	gen := func(g string) func(*contract.TokenRecord) {
		return func(r *contract.TokenRecord) { r.Version, r.Generation = 90, g }
	}
	for _, c := range []struct {
		name, generation string
		raw              json.RawMessage
		action           string
	}{
		{"a record in a page of the app's generation: it applies", vecGeneration, page(vecGeneration, vecRecord(gen(vecGeneration))), "apply"},
		{"a record whose generation differs from its page's: a bad record, never a reset", vecGeneration, page(vecGeneration, vecRecord(gen(vecGeneration2))), "narrow"},
		{"a revoked record whose generation differs from its page's: a bad record, never a reset", vecGeneration, page(vecGeneration, vecRecord(func(r *contract.TokenRecord) {
			gen(vecGeneration2)(r)
			revoke(contract.RevokedInConsole)(r)
		})), "narrow"},
		{"a page of another generation: a reset", vecGeneration, page(vecGeneration2, vecRecord(gen(vecGeneration2))), "reset"},
		{"a page of another generation whose record names the app's: a reset", vecGeneration, page(vecGeneration2, vecRecord(gen(vecGeneration))), "reset"},
		{"another app's record of another generation, in a page of the app's: refused", vecGeneration, page(vecGeneration, vecMailieRecord(gen(vecGeneration2))), "refuse"},
	} {
		action, code := pageAction("wappie", c.generation, c.raw)
		if action != c.action {
			return nil, fmt.Errorf("contractvec: page %q is %s, the spec asks %s", c.name, action, c.action)
		}
		out.Pages = append(out.Pages, ActionCase{Name: c.name, App: "wappie", Generation: c.generation, Value: c.raw, Action: action, Code: code})
	}
	return out, nil
}
