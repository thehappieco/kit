package contracttest_test

// The relink (kit v0.11.0; SPEC section 11.19; the platform's decision
// 0057), through an app's contract.Client: item.relink offered to Wappie
// and the reference app, item.rename to Mailie, and the pairing route a
// running relink sends its QRs to.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"
)

// relink is ana linking a number again.
func relink(team string) contracttest.CommandSpec {
	return contracttest.CommandSpec{Kind: contract.OpItemRelink, Workspace: team, Actor: anaSub, Target: contract.CommandTarget{Item: number}}
}

// qrText is a QR of WhatsApp's shape (whatsmeow's MakeQRData), made up:
// 277 characters.
var qrText = func() string {
	head := "https://wa.me/settings/linked_devices#"
	tail := "," + strings.Repeat("QUJD", 11) + "," + strings.Repeat("REVG", 11) + "," + strings.Repeat("R0hJ", 11) + ",AQIDBA=="
	ref := "2@" + strings.Repeat("Qk9HVVM", 40)
	return head + ref[:277-len(head)-len(tail)] + tail
}()

// qr is the QR seq of a relink, which WhatsApp's window ends in 60 s at
// the fake's clock.
func qr(fx settingsFixture, seq int64) contract.PairingQR {
	return contract.PairingQR{Seq: seq, QR: qrText, ExpiresAt: fx.h.clock.Now().Add(time.Minute)}
}

// runningRelink is a relink the app took from its command feed and
// answered in_progress.
func runningRelink(t *testing.T, fx settingsFixture) string {
	t.Helper()
	id := issue(t, fx, relink(fx.team))
	if _, cmds, _ := take(t, fx.c, 0); len(cmds) == 0 || cmds[len(cmds)-1].ID != id {
		t.Fatalf("the relink was not served: %+v", cmds)
	}
	post(t, fx, results(inProgress(fx, id)), contract.OutcomeAccepted)
	return id
}

func putPairing(t *testing.T, fx settingsFixture, id string, q contract.PairingQR, accepted bool) {
	t.Helper()
	got, err := fx.c.PutPairing(t.Context(), id, q)
	if err != nil || got != accepted {
		t.Fatalf("seq %d: accepted %v, %v; want %v", q.Seq, got, err, accepted)
	}
}

func TestTheFakeOffersARelinkToWappieAndTheReferenceAppAndARenameToMailie(t *testing.T) {
	fx := settingsSetup(t, contracttest.Options{Apps: []contracttest.App{
		wappie(), {ID: contract.ReferenceApp, Current: secretB}, {ID: "mailie", Current: secretC},
	}})
	ctx, p := t.Context(), fx.h.p
	// The reference app plays Wappie's kinds.
	ref := p.Client(contract.ReferenceApp)
	if _, err := ref.Subscribe(ctx, anaSub); err != nil {
		t.Fatal(err)
	}
	doc := numbersDoc(fx.team, fx.seq, []string{contract.OpItemRelink})
	doc.App, doc.Producer = contract.ReferenceApp, contract.SectionProducer(contract.ReferenceApp, contract.SectionNumbers)
	if err := ref.PutSettings(ctx, doc); err != nil {
		t.Fatal(err)
	}
	// Mailie's email accounts accept a rename, as a mailbox's.
	m := p.Client("mailie")
	if _, err := m.Subscribe(ctx, anaSub); err != nil {
		t.Fatal(err)
	}
	seq := fx.seq
	mail := contract.SettingsDoc{
		V: contract.SettingsV, Type: contract.SettingsType, App: "mailie", Section: contract.SectionEmailAccounts,
		Producer: contract.SectionProducer("mailie", contract.SectionEmailAccounts), WorkspaceID: fx.team, StateSeq: seq,
		SnapshotSeq: &seq, MeasuredAt: contract.T(time.UnixMilli(seq)), Accepts: []string{contract.OpItemRename},
		Data: json.RawMessage(`{"availability":"usable","link_min_role":"admin","texts":{"team_sync":"2026-10-sync-3"},"items":[]}`),
	}
	if err := m.PutSettings(ctx, mail); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		app  string
		spec contracttest.CommandSpec
	}{
		{"wappie", relink(fx.team)},
		{contract.ReferenceApp, relink(fx.team)},
		{"mailie", contracttest.CommandSpec{
			Kind: contract.OpItemRename, Workspace: fx.team, Actor: anaSub, Target: contract.CommandTarget{Item: "acc_7f3a"},
			Params: json.RawMessage(`{"before":{"label":null},"after":{"label":"Suporte"}}`),
		}},
	} {
		id, err := p.IssueCommand(c.app, c.spec)
		if err != nil {
			t.Fatalf("%s's %s: %v", c.app, c.spec.Kind, err)
		}
		kept, ok := p.Command(c.app, id)
		if !ok || kept.Kind != c.spec.Kind || kept.ExpiresAt == nil || kept.Confirm != nil || string(kept.Params) != map[string]string{
			contract.OpItemRelink: `{}`, contract.OpItemRename: string(c.spec.Params),
		}[c.spec.Kind] {
			t.Fatalf("%s's %s: %+v %v", c.app, c.spec.Kind, kept, ok)
		}
	}
	// Mailie has no relink: its kind is not one of Mailie's.
	if _, err := p.IssueCommand("mailie", contracttest.CommandSpec{
		Kind: contract.OpItemRelink, Workspace: fx.team, Actor: anaSub, Target: contract.CommandTarget{Item: "acc_7f3a"},
	}); !errors.Is(err, contracttest.ErrInvalid) {
		t.Fatalf("Mailie's relink: %v", err)
	}
	// A relink with params, or a confirmation, is no command the console
	// issues.
	bad := relink(fx.team)
	bad.Params = json.RawMessage(`{"before":{"connection":"logged_out_phone"},"after":{"connection":"online"}}`)
	if _, err := p.IssueCommand("wappie", bad); !errors.Is(err, contracttest.ErrInvalid) {
		t.Fatalf("a relink with params: %v", err)
	}
}

func TestThePairingRouteHoldsTheLatestQROfARunningRelink(t *testing.T) {
	if len(qrText) != 277 || !contract.ValidPairingQR(qrText) {
		t.Fatalf("the sample QR is %d characters, valid %v", len(qrText), contract.ValidPairingQR(qrText))
	}
	fx := settingsSetup(t, contracttest.Options{})
	ctx, p := t.Context(), fx.h.p
	// Issued but not yet carried by a command feed answer: not_found.
	id := issue(t, fx, relink(fx.team))
	_, err := fx.c.PutPairing(ctx, id, qr(fx, 1))
	mustRefusal(t, err, contract.CodeNotFound)
	if _, cmds, _ := take(t, fx.c, 0); len(cmds) != 1 || cmds[0].ID != id {
		t.Fatalf("the relink: %+v", cmds)
	}
	// Carried, it takes QRs before its in_progress too.
	putPairing(t, fx, id, qr(fx, 1), true)
	post(t, fx, results(inProgress(fx, id)), contract.OutcomeAccepted)
	if held, ok := p.Pairing("wappie", id); !ok || held.Seq != 1 || held.QR != qrText {
		t.Fatalf("the QR held: %v %v", held, ok)
	}
	// The same seq again, or a lower one, is accepted false and holds
	// nothing; a higher one replaces it.
	fx.h.clock.Add(20 * time.Second)
	putPairing(t, fx, id, qr(fx, 1), false)
	putPairing(t, fx, id, qr(fx, 3), true)
	putPairing(t, fx, id, qr(fx, 2), false)
	if held, ok := p.Pairing("wappie", id); !ok || held.Seq != 3 || !held.ExpiresAt.Equal(fx.h.clock.Now().Add(time.Minute)) {
		t.Fatalf("after seq 3: %v %v", held, ok)
	}
	// The QR goes at its expires_at, and its seq stays.
	fx.h.clock.Add(time.Minute)
	if held, ok := p.Pairing("wappie", id); ok {
		t.Fatalf("a QR past its expires_at: %v", held)
	}
	putPairing(t, fx, id, qr(fx, 3), false)
	putPairing(t, fx, id, qr(fx, 4), true)
	// 3 minutes after the first QR, a PUT is still taken; a second more, it
	// is accepted false, and the QR held goes.
	fx.h.clock.Add(contract.PairingHold - 80*time.Second)
	putPairing(t, fx, id, qr(fx, 5), true)
	fx.h.clock.Add(time.Second)
	if _, ok := p.Pairing("wappie", id); ok {
		t.Fatal("a QR held past the three minutes")
	}
	putPairing(t, fx, id, qr(fx, 6), false)
	// The final result drops everything: the route is not_found.
	post(t, fx, results(ran(fx, id)), contract.OutcomeAccepted)
	_, err = fx.c.PutPairing(ctx, id, qr(fx, 7))
	mustRefusal(t, err, contract.CodeNotFound)
	if _, ok := p.Pairing("wappie", id); ok {
		t.Fatal("a QR held after the final result")
	}
}

func TestAFinalResultDropsTheQRHeld(t *testing.T) {
	fx := settingsSetup(t, contracttest.Options{})
	id := runningRelink(t, fx)
	putPairing(t, fx, id, qr(fx, 1), true)
	post(t, fx, results(refused(fx, id, contract.CodeOtherAccount, 0)), contract.OutcomeAccepted)
	if held, ok := fx.h.p.Pairing("wappie", id); ok {
		t.Fatalf("held after other_account: %v", held)
	}
	r, ok := fx.h.p.CommandResult("wappie", id)
	if !ok || r.Code == nil || *r.Code != contract.CodeOtherAccount {
		t.Fatalf("the result: %+v %v", r, ok)
	}
	// A relink retried after item_busy is a new command; the first is done.
	busy := runningRelink(t, fx)
	post(t, fx, results(refused(fx, busy, contract.CodeItemBusy, 30)), contract.OutcomeAccepted)
	_, err := fx.c.PutPairing(t.Context(), busy, qr(fx, 1))
	mustRefusal(t, err, contract.CodeNotFound)
	// Wappie never answers a relink app_only.
	other := runningRelink(t, fx)
	post(t, fx, results(refused(fx, other, contract.CodeAppOnly, 0)), "rejected:"+contract.CodeInvalid)
}

func TestARestartOrARestoreDropsThePairingsAndTheNextQRIsAFirst(t *testing.T) {
	for _, how := range []string{"NewGeneration", "Restore"} {
		t.Run(how, func(t *testing.T) {
			fx := settingsSetup(t, contracttest.Options{})
			id := runningRelink(t, fx)
			putPairing(t, fx, id, qr(fx, 5), true)
			fx.h.clock.Add(contract.PairingHold + time.Second)
			putPairing(t, fx, id, qr(fx, 6), false)
			if how == "Restore" {
				fx.h.p.Restore()
			} else {
				fx.h.p.NewGeneration()
			}
			if _, ok := fx.h.p.Pairing("wappie", id); ok {
				t.Fatal("a QR outlived the platform's memory")
			}
			// The relink, still without a final result, takes its next QR as a
			// first, whatever its seq.
			putPairing(t, fx, id, qr(fx, 1), true)
			if held, ok := fx.h.p.Pairing("wappie", id); !ok || held.Seq != 1 {
				t.Fatalf("after %s: %v %v", how, held, ok)
			}
		})
	}
}

func TestThePairingRouteReadsItsBodyStrictlyAndNamesOnlyARunningRelink(t *testing.T) {
	if contracttest.PairingBodyLimit != 4<<10 || contract.PairingBodyLimit != 4<<10 {
		t.Fatal("the pairing's body limit is not 4 KiB")
	}
	fx := settingsSetup(t, contracttest.Options{PerSecond: 1000})
	id := runningRelink(t, fx)
	target := "/contract/v1/commands/" + id + "/pairing"
	now := fx.h.clock.Now()
	stamp := func(d time.Duration) string { return now.Add(d).UTC().Format(time.RFC3339) }
	good := fmt.Sprintf(`{"seq":1,"qr":%q,"expires_at":%q}`, qrText, stamp(time.Minute))
	for name, body := range map[string]string{
		"seq 0":                       strings.Replace(good, `"seq":1`, `"seq":0`, 1),
		"an empty QR":                 fmt.Sprintf(`{"seq":1,"qr":"","expires_at":%q}`, stamp(time.Minute)),
		"a QR of 513 characters":      fmt.Sprintf(`{"seq":1,"qr":%q,"expires_at":%q}`, strings.Repeat("A", 513), stamp(time.Minute)),
		"a space in the QR":           fmt.Sprintf(`{"seq":1,"qr":"2@A B","expires_at":%q}`, stamp(time.Minute)),
		"an unknown member":           strings.Replace(good, `{"seq"`, `{"code":"123-456","seq"`, 1),
		"a member twice":              strings.Replace(good, `{"seq":1`, `{"seq":1,"seq":1`, 1),
		"a member missing":            fmt.Sprintf(`{"seq":1,"qr":%q}`, qrText),
		"a member null":               fmt.Sprintf(`{"seq":1,"qr":null,"expires_at":%q}`, stamp(time.Minute)),
		"a member written Seq":        strings.Replace(good, `"seq"`, `"Seq"`, 1),
		"expires_at at the clock":     fmt.Sprintf(`{"seq":1,"qr":%q,"expires_at":%q}`, qrText, stamp(0)),
		"expires_at 91 s ahead":       fmt.Sprintf(`{"seq":1,"qr":%q,"expires_at":%q}`, qrText, stamp(91*time.Second)),
		"expires_at in another zone":  strings.Replace(good, "Z\"", "+00:00\"", 1),
		"no object":                   `[]`,
		"a body padded to the limit:": strings.Repeat(" ", contracttest.PairingBodyLimit-2) + "{}",
	} {
		if !strings.HasSuffix(name, ":") && body == good {
			t.Fatalf("%s is the good body", name)
		}
		cl := call{method: http.MethodPut, target: target, app: "wappie", body: body}
		fx.h.wantSigned(t, fx.h.send(t, cl), cl, http.StatusBadRequest, contract.CodeInvalid)
	}
	if _, ok := fx.h.p.Pairing("wappie", id); ok {
		t.Fatal("a refused body was held")
	}
	// A body at 90 s ahead is taken.
	cl := call{method: http.MethodPut, target: target, app: "wappie",
		body: fmt.Sprintf(`{"seq":1,"qr":%q,"expires_at":%q}`, qrText, stamp(contract.MaxPairingAhead))}
	if a := fx.h.send(t, cl); a.status != http.StatusOK || string(a.body) != `{"accepted":true}` {
		t.Fatalf("got %d %s", a.status, a.body)
	} else {
		fx.h.verified(t, a, []string{secretA}, "wappie", http.MethodPut, target)
	}
	// Over the limit, unsigned; a query, signed.
	cl = call{method: http.MethodPut, target: target, app: "wappie", body: strings.Repeat(" ", contracttest.PairingBodyLimit-1) + "{}"}
	fx.h.send(t, cl).wantUnsigned(t, http.StatusRequestEntityTooLarge, contract.CodeTooLarge)
	cl = call{method: http.MethodPut, target: target + "?seq=2", app: "wappie", body: good}
	fx.h.wantSigned(t, fx.h.send(t, cl), cl, http.StatusBadRequest, contract.CodeInvalid)
	// Another kind's command, an unknown one and another app's are
	// not_found, signed.
	renamed := issue(t, fx, rename(fx.team))
	take(t, fx.c, 0)
	for _, other := range []string{renamed, "0199f3c4-0000-7000-8000-000000000099"} {
		cl := call{method: http.MethodPut, target: "/contract/v1/commands/" + other + "/pairing", app: "wappie", body: good}
		fx.h.wantSigned(t, fx.h.send(t, cl), cl, http.StatusNotFound, contract.CodeNotFound)
	}
	// An id that is no UUID, another method and another shape are no call.
	for _, cl := range []call{
		{method: http.MethodPut, target: "/contract/v1/commands/812/pairing", app: "wappie", body: good},
		{method: http.MethodPut, target: "/contract/v1/commands/" + strings.ToUpper(id) + "/pairing", app: "wappie", body: good},
		{method: http.MethodPost, target: target, app: "wappie", body: good},
		{method: http.MethodGet, target: target, app: "wappie"},
		{method: http.MethodPut, target: target + "/", app: "wappie", body: good},
	} {
		fx.h.send(t, cl).wantUnsigned(t, http.StatusNotFound, contract.CodeNotFound)
	}
}

func TestRefuseAndCorruptReachThePairingCall(t *testing.T) {
	fx := settingsSetup(t, contracttest.Options{})
	ctx, p := t.Context(), fx.h.p
	id := runningRelink(t, fx)
	if err := p.Refuse("wappie", contracttest.CallPairing, contract.CodeUnavailable); err != nil {
		t.Fatal(err)
	}
	_, err := fx.c.PutPairing(ctx, id, qr(fx, 1))
	mustRefusal(t, err, contract.CodeUnavailable)
	if _, ok := p.Pairing("wappie", id); ok {
		t.Fatal("a refused QR was held")
	}
	if err := p.Corrupt("wappie", contracttest.CallPairing, contracttest.AnotherNonce); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.c.PutPairing(ctx, id, qr(fx, 1)); !errors.Is(err, contract.ErrUnverified) {
		t.Fatalf("a corrupted answer: %v", err)
	}
	// The fake held it all the same; the app sends it again, accepted false.
	putPairing(t, fx, id, qr(fx, 1), false)
	if held, ok := p.Pairing("wappie", id); !ok || held.Seq != 1 {
		t.Fatalf("held: %v %v", held, ok)
	}
}
