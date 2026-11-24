package contract_test

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/thehappieco/kit/contract"
)

// shapedMAC is a command's mac in shape, for a command checked without its
// signature.
var shapedMAC = "v1=" + strings.Repeat("5e", 32)

// result is a result of a command, refused with code (or ran when code is
// ""), judged on vecSeq.
func result(outcome, code string, mut func(*contract.CommandResult)) contract.CommandResult {
	r := contract.CommandResult{ID: vecCommand, Outcome: outcome, StateSeq: ptr(vecSeq), At: contract.T(Now)}
	if code != "" {
		r.Code = ptr(code)
	}
	if mut != nil {
		mut(&r)
	}
	return r
}

// item.relink is Wappie's and the reference app's, never Mailie's: a kind
// with an expiry, on an item, with no setting, whose first result may be
// in_progress, with its own ten refusals.
func TestTheRelinkIsWappiesKindOnAnItemWithItsOwnTenRefusals(t *testing.T) {
	for _, app := range []string{"wappie", contract.ReferenceApp} {
		k, ok := contract.CommandKindOf(app, contract.OpItemRelink)
		want := []string{
			contract.CodeOtherAccount, contract.CodeLinkTimeout, contract.CodeConnectFailed, contract.CodeNumberHeld,
			contract.CodeReadOnly, contract.CodeNoReader, contract.CodeCapacityReached, contract.CodeStoragePaused,
			contract.CodeItemBusy, contract.CodeStateChanged,
		}
		switch {
		case !ok, k.Section != contract.SectionNumbers, k.Tightening, !k.InProgress, k.Confirm != "",
			k.Agreement != contract.AgreementNever, !slices.Equal(k.Target, []string{contract.TargetItem}):
			t.Errorf("%s's relink: %+v", app, k)
		case !slices.Equal(k.Refusals, want):
			t.Errorf("%s's relink refuses %v", app, k.Refusals)
		}
	}
	if _, ok := contract.CommandKindOf("mailie", contract.OpItemRelink); ok {
		t.Error("Mailie relinks nothing")
	}
	move, _ := contract.CommandKindOf("wappie", contract.OpItemMoveOut)
	if !slices.Contains(move.Refusals, contract.CodeItemBusy) {
		t.Errorf("item.move_out refuses %v, without item_busy", move.Refusals)
	}
}

// A relink as the console issues it is valid: no params, an expiry at most
// five minutes on, no confirm; with a setting, a confirm, no expiry, a
// person or for Mailie it is not.
func TestARelinkCommandHoldsNoSettingAndExpiresInFiveMinutes(t *testing.T) {
	relink := func(mut func(*contract.Command)) contract.Command {
		return vecCmd("wappie", contract.OpItemRelink, func(c *contract.Command) {
			c.Params = json.RawMessage(`{}`)
			c.MAC = shapedMAC
			if mut != nil {
				mut(c)
			}
		})
	}
	for _, ws := range []string{contract.KindTeam, contract.KindPersonal} {
		c := relink(nil)
		if ws == contract.KindPersonal {
			c.WorkspaceID = ptr(vecPersonal)
		}
		if err := c.ValidateIn(ws); err != nil {
			t.Errorf("a relink in a %s workspace: %v", ws, err)
		}
	}
	for name, mut := range map[string]func(*contract.Command){
		"a setting": func(c *contract.Command) {
			c.Params = json.RawMessage(`{"before":{"connection":"logged_out_phone"},"after":{"connection":"online"}}`)
		},
		"a confirm":  func(c *contract.Command) { c.Confirm = ptr(c.Target.Item) },
		"no expiry":  func(c *contract.Command) { c.ExpiresAt = nil },
		"6 minutes":  func(c *contract.Command) { c.ExpiresAt = ptr(at(contract.CommandLifetime + time.Minute)) },
		"a person":   func(c *contract.Command) { c.Target.Person = vecOther; c.BasedOn.Docs[vecOther] = 3 },
		"for Mailie": func(c *contract.Command) { c.App = "mailie" },
	} {
		if err := relink(mut).ValidateIn(contract.KindTeam); !errors.Is(err, contract.ErrInvalid) {
			t.Errorf("a relink with %s: %v", name, err)
		}
	}
}

// A relink's result: in_progress with or without a state_seq; ran with a
// state_seq and no detail; each of its own refusals and every kind's but
// app_only, which Wappie never answers it; item_busy waiting on time.
func TestARelinkIsAnsweredInProgressThenFinallyAndNeverAppOnly(t *testing.T) {
	ok := func(name string, r contract.CommandResult) {
		t.Helper()
		if err := r.ValidateFor("wappie", contract.OpItemRelink); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := func(name string, r contract.CommandResult) {
		t.Helper()
		if err := r.ValidateFor("wappie", contract.OpItemRelink); !errors.Is(err, contract.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	ok("in_progress", result(contract.OutcomeInProgress, "", nil))
	ok("in_progress with no state_seq", result(contract.OutcomeInProgress, "", func(r *contract.CommandResult) { r.StateSeq = nil }))
	ok("ran", result(contract.OutcomeRan, "", nil))
	k, _ := contract.CommandKindOf("wappie", contract.OpItemRelink)
	for _, code := range k.Refusals {
		ok(code, result(contract.OutcomeRefused, code, nil))
	}
	for _, code := range []string{contract.CodeWorkspaceBusy, contract.CodeNotFound, contract.CodeNotAuthorized, contract.CodeMembershipsBehind} {
		ok(code, result(contract.OutcomeRefused, code, nil))
	}
	ok("item_busy after 160 s", result(contract.OutcomeRefused, contract.CodeItemBusy, func(r *contract.CommandResult) { r.RetryAfter = ptr[int64](160) }))
	ok("expired", result(contract.OutcomeRefused, contract.CodeExpired, func(r *contract.CommandResult) { r.StateSeq = nil }))

	bad("app_only", result(contract.OutcomeRefused, contract.CodeAppOnly, nil))
	bad("ran with a detail", result(contract.OutcomeRan, "", func(r *contract.CommandResult) { r.Detail = &contract.ResultDetail{Purged: ptr(true)} }))
	bad("ran with no state_seq", result(contract.OutcomeRan, "", func(r *contract.CommandResult) { r.StateSeq = nil }))
	bad("in_progress with a code", result(contract.OutcomeInProgress, contract.CodeItemBusy, nil))
	bad("a code outside the kind", result(contract.OutcomeRefused, contract.CodeLastReader, nil))
	bad("link_timeout waiting on time", result(contract.OutcomeRefused, contract.CodeLinkTimeout, func(r *contract.CommandResult) { r.RetryAfter = ptr[int64](5) }))

	// app_only stays every other kind's.
	if err := result(contract.OutcomeRefused, contract.CodeAppOnly, nil).ValidateFor("wappie", contract.OpItemSyncNow); err != nil {
		t.Errorf("app_only on item.sync_now: %v", err)
	}
	if err := result(contract.OutcomeRefused, contract.CodeItemBusy, func(r *contract.CommandResult) { r.RetryAfter = ptr[int64](1) }).
		ValidateFor("wappie", contract.OpItemMoveOut); err != nil {
		t.Errorf("item_busy on item.move_out: %v", err)
	}
}

// The three codes of the relink are final, whether the kind tightens or
// not, and stand after not_linked and before read_only.
func TestTheRelinksCodesAreFinalAndInTheTablesOrder(t *testing.T) {
	codes := contract.CommandRefusalCodes()
	i := slices.Index(codes, contract.CodeNotLinked)
	want := []string{contract.CodeOtherAccount, contract.CodeLinkTimeout, contract.CodeNumberHeld, contract.CodeReadOnly}
	if i < 0 || !slices.Equal(codes[i+1:i+5], want) {
		t.Errorf("the codes after not_linked: %v", codes[i+1:])
	}
	for _, code := range want[:3] {
		for _, tightening := range []bool{false, true} {
			if c := contract.CommandRefusalClass(code, tightening); c != contract.ClassFinal {
				t.Errorf("%s (tightening %v) is %q", code, tightening, c)
			}
		}
	}
}

// Mailie renames a mailbox as Wappie renames a number: a label or null to
// a label, in email-accounts, which its accepts may then list.
func TestMailieRenamesAMailboxInEmailAccounts(t *testing.T) {
	k, ok := contract.CommandKindOf("mailie", contract.OpItemRename)
	if !ok || k.Section != contract.SectionEmailAccounts || k.Tightening ||
		!slices.Equal(k.Refusals, []string{contract.CodeLabelChanged, contract.CodeStateChanged}) {
		t.Fatalf("Mailie's rename: %+v", k)
	}
	rename := func(params string) contract.Command {
		return vecCmd("mailie", contract.OpItemRename, func(c *contract.Command) { c.Params, c.MAC = json.RawMessage(params), shapedMAC })
	}
	for _, params := range []string{
		`{"before":{"label":"Suporte"},"after":{"label":"Suporte SP"}}`,
		`{"before":{"label":null},"after":{"label":"Suporte"}}`,
	} {
		if err := rename(params).ValidateIn(contract.KindTeam); err != nil {
			t.Errorf("%s: %v", params, err)
		}
	}
	for _, params := range []string{
		`{"before":{"label":"Suporte"},"after":{"label":null}}`,
		`{"before":{"name":"Suporte"},"after":{"name":"Suporte SP"}}`,
		`{"before":{"label":"Suporte"},"after":{"label":"a@b.example"}}`,
		`{}`,
	} {
		if err := rename(params).ValidateIn(contract.KindTeam); !errors.Is(err, contract.ErrInvalid) {
			t.Errorf("%s: %v", params, err)
		}
	}
	accepts := func(kinds ...string) error {
		return sectionDoc("mailie", contract.SectionEmailAccounts, vecEmailAccounts(nil), func(d *contract.SettingsDoc) { d.Accepts = kinds }).Validate()
	}
	if err := accepts(contract.OpItemRename, contract.OpItemSyncNow); err != nil {
		t.Errorf("email-accounts accepting item.rename: %v", err)
	}
	if err := sectionDoc("mailie", contract.SectionPermissions, vecPermissions(nil), func(d *contract.SettingsDoc) {
		d.Accepts = []string{contract.OpItemRename}
	}).Validate(); !errors.Is(err, contract.ErrInvalid) {
		t.Errorf("permissions accepting item.rename: %v", err)
	}
}

// label_changed's cleaned may be null, on an item.rename only: the app
// keeps no name of the one asked for. Null and absent read apart, and a
// detail is written back as it was read.
func TestACleanedLabelMayBeNullOnARenameOnly(t *testing.T) {
	read := func(raw string) (contract.CommandResult, error) {
		var r contract.CommandResult
		if err := contract.DecodeStrict([]byte(raw), &r); err != nil {
			return r, err
		}
		return r, nil
	}
	body := func(detail string) string {
		return `{"id":"` + vecCommand + `","outcome":"refused","code":"label_changed","retry_after":null,"state_seq":7,"detail":` +
			detail + `,"at":"2026-11-24T12:00:00Z"}`
	}
	r, err := read(body(`{"cleaned":null}`))
	if err != nil || r.Detail == nil || !r.Detail.CleanedNull || r.Detail.Cleaned != nil {
		t.Fatalf("a null cleaned read as %+v, %v", r.Detail, err)
	}
	for _, app := range []string{"wappie", contract.ReferenceApp, "mailie"} {
		if err := r.ValidateFor(app, contract.OpItemRename); err != nil {
			t.Errorf("%s's rename, cleaned null: %v", app, err)
		}
	}
	for _, kind := range []string{contract.OpInstallationAdd, contract.OpInstallationRename} {
		if err := r.ValidateFor("wappie", kind); !errors.Is(err, contract.ErrInvalid) {
			t.Errorf("%s, cleaned null: %v", kind, err)
		}
	}
	if out, err := json.Marshal(r.Detail); err != nil || string(out) != `{"cleaned":null}` {
		t.Errorf("written back as %s, %v", out, err)
	}

	// A cleaned label still holds as before, and is written as it was.
	r, err = read(body(`{"cleaned":"P&D <SP>"}`))
	if err != nil || r.Detail.CleanedNull || r.Detail.Cleaned == nil || r.ValidateFor("wappie", contract.OpInstallationRename) != nil {
		t.Errorf("a cleaned label: %+v, %v", r.Detail, err)
	}
	if out, _ := json.Marshal(r.Detail); string(out) != `{"cleaned":"P\u0026D \u003cSP\u003e"}` {
		t.Errorf("a cleaned label written as %s", out)
	}
	var unescaped strings.Builder
	enc := json.NewEncoder(&unescaped)
	enc.SetEscapeHTML(false)
	if enc.Encode(r.Detail) != nil || unescaped.String() != `{"cleaned":"P&D <SP>"}`+"\n" {
		t.Errorf("a cleaned label written unescaped as %s", unescaped.String())
	}

	// An absent cleaned is no detail of label_changed.
	if r, err := read(body(`{}`)); err == nil && r.Validate() == nil {
		t.Error("label_changed with an empty detail is valid")
	}
	// A null cleaned beside another code, or another member, is not.
	bad := []string{
		strings.Replace(body(`{"cleaned":null}`), `"label_changed"`, `"state_changed"`, 1),
		body(`{"cleaned":null,"purged":true}`),
	}
	for _, raw := range bad {
		if r, err := read(raw); err == nil && r.ValidateFor("wappie", contract.OpItemRename) == nil {
			t.Errorf("valid: %s", raw)
		}
	}
	// A detail reads strictly: no member it does not have, none named
	// otherwise, none twice.
	for _, detail := range []string{`{"cleaned":null,"other":1}`, `{"Cleaned":null}`, `{"cleaned":null,"cleaned":"Vendas"}`, `{"CleanedNull":true}`} {
		if _, err := read(body(detail)); !errors.Is(err, contract.ErrInvalid) {
			t.Errorf("read %s: %v", detail, err)
		}
	}
	// Set in Go both ways, a detail is mixed.
	both := result(contract.OutcomeRefused, contract.CodeLabelChanged, func(r *contract.CommandResult) {
		r.Detail = &contract.ResultDetail{Cleaned: ptr("Vendas"), CleanedNull: true}
	})
	if err := both.Validate(); !errors.Is(err, contract.ErrInvalid) {
		t.Errorf("cleaned and CleanedNull: %v", err)
	}
}

// can_relink is optional on a number's row: absent, true or false, never
// null, and the row is still read strictly.
func TestCanRelinkIsAbsentTrueOrFalseNeverNull(t *testing.T) {
	doc := func(row string) contract.SettingsDoc {
		raw := strings.Replace(string(mustRaw(vecNumbers(nil))), `"id":"`+vecNumber+`"`, row+`"id":"`+vecNumber+`"`, 1)
		d := sectionDoc("wappie", contract.SectionNumbers, vecNumbers(nil), nil)
		d.Data = json.RawMessage(raw)
		return d
	}
	for _, row := range []string{``, `"can_relink":true,`, `"can_relink":false,`} {
		d := doc(row)
		if err := d.Validate(); err != nil {
			t.Errorf("%q: %v", row, err)
			continue
		}
		data, _ := d.DecodeData()
		got := data.(*contract.NumbersSettings).Items[0].CanRelink
		if (row == "") != (got == nil) || got != nil && *got != strings.Contains(row, "true") {
			t.Errorf("%q read as %v", row, got)
		}
	}
	for _, row := range []string{`"can_relink":null,`, `"can_relink":"true",`, `"Can_relink":true,`, `"other":1,`, `"can_relink":true,"can_relink":false,`} {
		if err := doc(row).Validate(); !errors.Is(err, contract.ErrInvalid) {
			t.Errorf("%q: %v", row, err)
		}
	}
	// A row's own members are still all present.
	missing := sectionDoc("wappie", contract.SectionNumbers, vecNumbers(nil), nil)
	missing.Data = json.RawMessage(strings.Replace(string(missing.Data), `"read_only":false,`, ``, 1))
	if err := missing.Validate(); !errors.Is(err, contract.ErrInvalid) {
		t.Errorf("a row with no read_only: %v", err)
	}
	// Written, an unset can_relink is absent.
	if out := string(mustRaw(vecNumbers(nil))); strings.Contains(out, "can_relink") {
		t.Errorf("written: %s", out)
	}
}

// grant_ended is a mailbox's reason on needs_reauth and error only.
func TestAGrantTheProviderEndedIsAReasonOnNeedsReauthAndErrorOnly(t *testing.T) {
	for status, valid := range map[string]bool{"needs_reauth": true, "error": true, "connected": false, "pending_auth": false} {
		d := sectionDoc("mailie", contract.SectionEmailAccounts, vecEmailAccounts(func(s *contract.EmailAccountsSettings) {
			s.Items[0].Status, s.Items[0].Reason = status, ptr("grant_ended")
		}), nil)
		if err := d.Validate(); (err == nil) != valid {
			t.Errorf("grant_ended on %s: %v", status, err)
		}
	}
	// Sync off with its index kept is a valid row.
	d := sectionDoc("mailie", contract.SectionEmailAccounts, vecEmailAccounts(func(s *contract.EmailAccountsSettings) {
		s.Items[0].Sync.On, s.Items[0].Sync.Indexed = false, "complete"
	}), nil)
	if err := d.Validate(); err != nil {
		t.Errorf("sync off, index kept: %v", err)
	}
}
