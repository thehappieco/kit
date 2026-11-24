package contract_test

// The kit's generator of wire-pairing.json (kit v0.11.0, SPEC section
// 11.19; the platform's spec 14.13 and decision 0057): the relink of a
// number logged out by its phone, item.relink, its results and its three
// new refusal codes, item.move_out's item_busy, and the pairing route a
// running relink sends its QRs to, with the platform's answers. Every case
// states the outcome the spec asks of it, and the generator fails rather
// than write a case whose outcome the code does not give.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/thehappieco/kit/contract"
)

// PairingCase is one body of PUT /contract/v1/commands/{id}/pairing, the
// platform's clock when it reads it, in Unix seconds, and whether it is
// valid.
type PairingCase struct {
	Name  string `json:"name"`
	Body  string `json:"body"`
	Now   int64  `json:"now"`
	Valid bool   `json:"valid"`
}

// WirePairing is wire-pairing.json.
type WirePairing struct {
	Format      string        `json:"format"`
	Version     int           `json:"version"`
	Kind        string        `json:"kind"`
	Description string        `json:"description"`
	Pairings    []PairingCase `json:"pairings"`
	Answers     []WireCase    `json:"answers"`
	Commands    []CommandCase `json:"commands"`
	Results     []ResultCase  `json:"results"`
	Classes     []ClassCase   `json:"classes"`
}

// vecQR is a QR of the shape whatsmeow's MakeQRData writes
// (https://wa.me/settings/linked_devices#, then the pairing's reference
// and three keys in standard base64, and the advertising key's, comma
// separated), from made-up bytes, n characters long: 277 is what every QR
// of the owner's relink measured.
func vecQR(n int) string {
	part := func(seed byte) string {
		b := make([]byte, 32)
		for i := range b {
			b[i] = seed + byte(i)*7
		}
		return base64.StdEncoding.EncodeToString(b)
	}
	head := "https://wa.me/settings/linked_devices#"
	tail := "," + part(1) + "," + part(2) + "," + part(3) + "," + part(4)
	ref := "2@" + strings.Repeat("Qk9HVVM", 80)
	qr := head + ref[:n-len(head)-len(tail)] + tail
	if len(qr) != n {
		panic("contractvec: the QR is not n characters")
	}
	return qr
}

// pairingMirror is the pairing body as the test reads it on its own: its
// three members named exactly, expires_at the contract's Time (RFC 3339,
// "Z").
type pairingMirror struct {
	Seq       int64         `json:"seq"`
	QR        string        `json:"qr"`
	ExpiresAt contract.Time `json:"expires_at"`
}

// pairingValid is what the platform makes of a pairing body at now: within
// the call's limit, decoded strictly (the test's own reading and the
// package's), and valid at now.
func pairingValid(body string, now int64) bool {
	var mirror pairingMirror
	var p contract.PairingQR
	return len(body) <= contract.PairingBodyLimit && exactDecode([]byte(body), &mirror) == nil &&
		contract.DecodeStrict([]byte(body), &p) == nil && p.ValidateAt(time.Unix(now, 0)) == nil
}

// pairingAnswerValid is what an app makes of the platform's answer to a
// pairing: exactly {"accepted": a boolean}.
func pairingAnswerValid(raw []byte) bool {
	var mirror struct {
		Accepted bool `json:"accepted"`
	}
	var a contract.PairingAnswer
	return exactDecode(raw, &mirror) == nil && json.Unmarshal(raw, &a) == nil
}

func wirePairing() (any, error) {
	out := WirePairing{
		Format: Format, Version: 1, Kind: "wire-pairing",
		Description: "The relink of a number logged out by its phone (kit v0.11.0, SPEC section 11.19). pairings: bodies of PUT /contract/v1/commands/{id}/pairing, valid when within 4 KiB, decoded as the platform decodes what an app sends (strictly: exactly seq, qr and expires_at, none null, none twice, names exactly as written), seq 1 or more, qr 1 to 512 characters of ^[A-Za-z0-9+/=,@._:#-]$ (whatsmeow's text, otherwise opaque), and expires_at RFC 3339 in UTC with Z, after now (Unix seconds, the platform's clock) and at most 90 s after it (contract.PairingQR's ValidateAt); a seq at or below the highest the platform kept is no fault of the body, so no case here judges one. answers: the platform's signed 200 to a pairing, valid when exactly {\"accepted\": a boolean} (contract.PairingAnswer). commands: item.relink as the platform serves it to the app named, signed with SecretA of signatures.json, valid as wire-commands.json's commands are. results: one contract.CommandResult of a command of the app's kind, decoded strictly, then its ValidateFor(app, kind): item.relink's and item.move_out's item_busy. classes: the class, retry or final, of each refusal code kit v0.11.0 adds (other_account, link_timeout, number_held), for a kind that tightens or not.",
	}
	now := Now.Unix()
	stamp := func(d time.Duration) string { return Now.Add(d).Format(time.RFC3339) }
	qr := vecQR(277)
	body := func(seq, qr, expires string) string {
		return `{"seq":` + seq + `,"qr":` + string(mustRaw(qr)) + `,"expires_at":"` + expires + `"}`
	}
	good := body("1", qr, stamp(time.Minute))
	for _, c := range []struct {
		name  string
		body  string
		valid bool
	}{
		{"the first QR, 277 characters, its window a minute", good, true},
		{"the next QR, seq 2", body("2", qr, stamp(time.Minute)), true},
		{"a QR of exactly 512 characters", body("1", vecQR(contract.MaxPairingQR), stamp(time.Minute)), true},
		{"a QR of one character", body("1", "2", stamp(time.Minute)), true},
		{"expires_at a second after now", body("1", qr, stamp(time.Second)), true},
		{"expires_at 90 s after now", body("1", qr, stamp(contract.MaxPairingAhead)), true},
		{"expires_at with a fraction", body("1", qr, Now.Add(20*time.Second+120*time.Millisecond).Format(time.RFC3339Nano)), true},
		{"the members in another order", `{"expires_at":"` + stamp(time.Minute) + `","qr":` + string(mustRaw(qr)) + `,"seq":1}`, true},
		{"a body at 4 KiB", padTo(good, contract.PairingBodyLimit), true},
		{"seq 0", body("0", qr, stamp(time.Minute)), false},
		{"seq below 0", body("-1", qr, stamp(time.Minute)), false},
		{"seq as text", body(`"1"`, qr, stamp(time.Minute)), false},
		{"seq 1.5", body("1.5", qr, stamp(time.Minute)), false},
		{"an empty QR", body("1", "", stamp(time.Minute)), false},
		{"a QR of 513 characters", body("1", vecQR(contract.MaxPairingQR+1), stamp(time.Minute)), false},
		{"a QR with a space", body("1", "2@AB CD", stamp(time.Minute)), false},
		{"a QR with a character outside ASCII, escaped", `{"seq":1,"qr":"2@AB\u00e7D","expires_at":"` + stamp(time.Minute) + `"}`, false},
		{"a QR with ?", body("1", "https://wa.me/?x", stamp(time.Minute)), false},
		{"a QR with a line break", body("1", "2@AB\nCD", stamp(time.Minute)), false},
		{"a pairing code beside the QR", strings.Replace(good, `{"seq"`, `{"code":"ABCD-EFGH","seq"`, 1), false},
		{"a member twice", strings.Replace(good, `{"seq":1`, `{"seq":1,"seq":1`, 1), false},
		{"the QR null", `{"seq":1,"qr":null,"expires_at":"` + stamp(time.Minute) + `"}`, false},
		{"expires_at null", `{"seq":1,"qr":` + string(mustRaw(qr)) + `,"expires_at":null}`, false},
		{"expires_at missing", `{"seq":1,"qr":` + string(mustRaw(qr)) + `}`, false},
		{"a member written Seq", strings.Replace(good, `"seq"`, `"Seq"`, 1), false},
		{"expires_at at now", body("1", qr, stamp(0)), false},
		{"expires_at before now", body("1", qr, stamp(-time.Second)), false},
		{"expires_at 91 s after now", body("1", qr, stamp(contract.MaxPairingAhead+time.Second)), false},
		{"expires_at in another zone", body("1", qr, Now.Add(time.Hour+time.Minute).In(time.FixedZone("", 3600)).Format(time.RFC3339)), false},
		{"expires_at written +00:00", body("1", qr, strings.TrimSuffix(stamp(time.Minute), "Z")+"+00:00"), false},
		{"a list, not an object", `[` + good + `]`, false},
		{"a body over 4 KiB", padTo(good, contract.PairingBodyLimit+1), false},
	} {
		if got := pairingValid(c.body, now); got != c.valid {
			return nil, fmt.Errorf("contractvec: pairing %q is valid %v, the spec asks %v", c.name, got, c.valid)
		}
		out.Pairings = append(out.Pairings, PairingCase{Name: c.name, Body: c.body, Now: now, Valid: c.valid})
	}

	// Answers.
	for _, c := range []struct {
		name  string
		raw   string
		valid bool
	}{
		{"the QR held", `{"accepted":true}`, true},
		{"a seq at or below the highest kept, or a PUT past the three minutes: delivered, not held", `{"accepted":false}`, true},
		{"accepted as text", `{"accepted":"true"}`, false},
		{"accepted null", `{"accepted":null}`, false},
		{"no member", `{}`, false},
		{"a member the app does not know", `{"accepted":true,"seq":1}`, false},
		{"a member written Accepted", `{"Accepted":true}`, false},
	} {
		if got := pairingAnswerValid([]byte(c.raw)); got != c.valid {
			return nil, fmt.Errorf("contractvec: answer %q is valid %v, the spec asks %v", c.name, got, c.valid)
		}
		out.Answers = append(out.Answers, WireCase{Name: c.name, Value: json.RawMessage(c.raw), Valid: c.valid})
	}

	// Commands.
	wappie := func(mut func(*contract.Command)) contract.Command {
		return vecCmd("wappie", contract.OpItemRelink, mut)
	}
	for _, c := range []struct {
		name  string
		c     contract.Command
		valid bool
	}{
		{"Wappie's relink in a team", wappie(nil), true},
		{"Wappie's relink in a personal workspace", wappie(func(c *contract.Command) { c.WorkspaceID = ptr(vecPersonal) }), true},
		{"an admin's relink", wappie(func(c *contract.Command) { c.ActorRole = ptr(contract.RoleAdmin) }), true},
		{"a relink issued again, keeping its first expiry", wappie(func(c *contract.Command) {
			c.ID, c.RetryOf, c.FirstIssuedAt = vecCommand2, ptr(vecCommand), at(-time.Minute)
			c.ExpiresAt = ptr(at(contract.CommandLifetime - time.Minute))
		}), true},
		{"the reference app's relink", vecCmd(contract.ReferenceApp, contract.OpItemRelink, nil), true},
		{"a relink with params", wappie(func(c *contract.Command) {
			c.Params = json.RawMessage(`{"before":{"connection":"logged_out_phone"},"after":{"connection":"online"}}`)
		}), false},
		{"a relink with a confirmation", wappie(func(c *contract.Command) { c.Confirm = ptr(vecNumber) }), false},
		{"a relink with no expiry", wappie(func(c *contract.Command) { c.ExpiresAt = nil }), false},
		{"a relink with an expiry over five minutes", wappie(func(c *contract.Command) { c.ExpiresAt = ptr(at(contract.CommandLifetime + time.Second)) }), false},
		{"a relink naming a person", wappie(func(c *contract.Command) {
			c.Target.Person = vecOther
			c.BasedOn.Docs[vecOther] = 3
		}), false},
		{"a relink naming a row", wappie(func(c *contract.Command) { c.Target.Row = "reg_1" }), false},
		{"a relink with an agreement", wappie(func(c *contract.Command) {
			c.Agreement = &contract.Agreement{Revision: vecSyncText, Language: "pt-BR"}
		}), false},
		{"Mailie's relink", wappie(func(c *contract.Command) {
			c.App, c.Section, c.Target.Item = "mailie", contract.SectionEmailAccounts, vecMailbox
		}), false},
	} {
		raw := signed(c.c, SecretA)
		if got := commandValid(c.c.App, workspaceKind(c.c), raw); got != c.valid {
			return nil, fmt.Errorf("contractvec: command %q is valid %v, the spec asks %v", c.name, got, c.valid)
		}
		out.Commands = append(out.Commands, CommandCase{Name: c.name, App: c.c.App, WorkspaceKind: workspaceKind(c.c), Value: raw, Valid: c.valid})
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
	type resultCase struct {
		name, app, kind string
		raw             json.RawMessage
		valid           bool
	}
	cases := []resultCase{
		{"a relink in progress, no state yet", "wappie", contract.OpItemRelink, result(func(r *contract.CommandResult) {
			r.Outcome, r.StateSeq = contract.OutcomeInProgress, nil
		}), true},
		{"a relink in progress, its state sent", "wappie", contract.OpItemRelink, result(func(r *contract.CommandResult) {
			r.Outcome = contract.OutcomeInProgress
		}), true},
		{"a relink that ran", "wappie", contract.OpItemRelink, result(nil), true},
		{"the reference app's relink that ran", contract.ReferenceApp, contract.OpItemRelink, result(nil), true},
	}
	k, _ := contract.CommandKindOf("wappie", contract.OpItemRelink)
	for _, code := range k.Refusals {
		cases = append(cases, resultCase{"a relink refused " + code, "wappie", contract.OpItemRelink, refused(code, nil), true})
	}
	cases = append(cases, []resultCase{
		{"a relink refused item_busy, to retry when WhatsApp's window ends", "wappie", contract.OpItemRelink, refused(contract.CodeItemBusy, func(r *contract.CommandResult) {
			r.RetryAfter = ptr[int64](42)
		}), true},
		{"a relink refused workspace_busy while a move runs", "wappie", contract.OpItemRelink, refused(contract.CodeWorkspaceBusy, nil), true},
		{"a relink refused memberships_behind, to retry", "wappie", contract.OpItemRelink, refused(contract.CodeMembershipsBehind, func(r *contract.CommandResult) {
			r.RetryAfter = ptr[int64](30)
		}), true},
		{"a relink not started by its expires_at: expired, no state_seq", "wappie", contract.OpItemRelink, refused(contract.CodeExpired, func(r *contract.CommandResult) {
			r.StateSeq = nil
		}), true},
		{"a move out refused item_busy while a relink pairs, with the seconds left", "wappie", contract.OpItemMoveOut, refused(contract.CodeItemBusy, func(r *contract.CommandResult) {
			r.RetryAfter = ptr[int64](1)
		}), true},
		{"a move out refused item_busy, no retry_after: a backoff", "wappie", contract.OpItemMoveOut, refused(contract.CodeItemBusy, nil), true},
		{"a relink refused app_only: never Wappie's answer", "wappie", contract.OpItemRelink, refused(contract.CodeAppOnly, nil), false},
		{"a relink that ran with a detail", "wappie", contract.OpItemRelink, result(func(r *contract.CommandResult) {
			r.Detail = &contract.ResultDetail{SessionsEnded: ptr[int64](1)}
		}), false},
		{"a relink that ran with no state_seq", "wappie", contract.OpItemRelink, result(func(r *contract.CommandResult) { r.StateSeq = nil }), false},
		{"a relink in progress with a code", "wappie", contract.OpItemRelink, result(func(r *contract.CommandResult) {
			r.Outcome, r.Code = contract.OutcomeInProgress, ptr(contract.CodeItemBusy)
		}), false},
		{"a relink in progress with a retry_after", "wappie", contract.OpItemRelink, result(func(r *contract.CommandResult) {
			r.Outcome, r.RetryAfter = contract.OutcomeInProgress, ptr[int64](30)
		}), false},
		{"a relink refused with a code not its kind's", "wappie", contract.OpItemRelink, refused(contract.CodeLabelChanged, func(r *contract.CommandResult) {
			r.Detail = &contract.ResultDetail{Cleaned: ptr("Vendas")}
		}), false},
		{"a relink refused last_reader", "wappie", contract.OpItemRelink, refused(contract.CodeLastReader, nil), false},
		{"other_account with a retry_after: a final code", "wappie", contract.OpItemRelink, refused(contract.CodeOtherAccount, func(r *contract.CommandResult) {
			r.RetryAfter = ptr[int64](30)
		}), false},
		{"link_timeout with a retry_after: a final code", "wappie", contract.OpItemRelink, refused(contract.CodeLinkTimeout, func(r *contract.CommandResult) {
			r.RetryAfter = ptr[int64](30)
		}), false},
		{"item_busy with a retry_after over an hour", "wappie", contract.OpItemRelink, refused(contract.CodeItemBusy, func(r *contract.CommandResult) {
			r.RetryAfter = ptr[int64](contract.MaxRetryAfter + 1)
		}), false},
		{"expired with a state_seq", "wappie", contract.OpItemRelink, refused(contract.CodeExpired, nil), false},
		{"number_held on a move out", "wappie", contract.OpItemMoveOut, refused(contract.CodeNumberHeld, nil), false},
		{"other_account on a rename", "wappie", contract.OpItemRename, refused(contract.CodeOtherAccount, nil), false},
		{"link_timeout on Mailie's sync now", "mailie", contract.OpItemSyncNow, refused(contract.CodeLinkTimeout, nil), false},
	}...)
	for _, c := range cases {
		if got := resultValid(c.app, c.kind, c.raw); got != c.valid {
			return nil, fmt.Errorf("contractvec: result %q is valid %v, the spec asks %v", c.name, got, c.valid)
		}
		out.Results = append(out.Results, ResultCase{Name: c.name, App: c.app, Kind: c.kind, Value: c.raw, Valid: c.valid})
	}

	// Classes: the codes kit v0.11.0 adds, all final.
	for _, code := range []string{contract.CodeOtherAccount, contract.CodeLinkTimeout, contract.CodeNumberHeld} {
		for _, tightening := range []bool{false, true} {
			class := contract.CommandRefusalClass(code, tightening)
			if class != contract.ClassFinal {
				return nil, fmt.Errorf("contractvec: %s is %q, the spec asks final", code, class)
			}
			out.Classes = append(out.Classes, ClassCase{Code: code, Tightening: tightening, Class: class})
		}
	}
	return out, nil
}
