package contract_test

// The kit's generators of three files of kit v0.12.0 (SPEC sections 11.17,
// 11.19 and 11.20), written ahead of the platform's generator:
// wire-v012.json, what rides the entitlements and usage part's release
// elsewhere (a snapshot item's server and pending, Mailie's email-accounts
// header, Mailie's new refusals); wire-events-codes.json, item.linked and
// item.identity_updated with their trial codes; and wire-link-check.json,
// the link check and its answer. Every case states the outcome the spec
// asks of it, and the generator fails rather than write a case whose
// outcome the code does not give. The trial key and codes every file of
// v0.12.0 uses are here.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/thehappieco/kit/contract"
)

// vecTrialKeyHex is the vectors' K_app: the bytes 0 to 31, a made-up key
// that protects nothing.
const vecTrialKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

// vecTrialKey is vecTrialKeyHex as a key.
func vecTrialKey() contract.TrialKey {
	b, err := hex.DecodeString(vecTrialKeyHex)
	if err != nil {
		panic(err)
	}
	k, err := contract.NewTrialKey(b)
	if err != nil {
		panic(err)
	}
	return k
}

// vecCode is the code of identifier, of kind, for app, under the vectors'
// key; it panics on an identifier that makes none.
func vecCode(app, kind, identifier string) string {
	c, err := contract.TrialCode(vecTrialKey(), app, kind, identifier)
	if err != nil {
		panic(err)
	}
	return c
}

// vecCodes are n distinct codes of Wappie numbers.
func vecCodes(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = vecCode("wappie", contract.TrialKindE164, fmt.Sprintf("+55119888877%02d", i))
	}
	return out
}

// notCanonical is code with its last character one whose low two bits are
// not zero: 43 base64url characters that are not the one spelling of 32
// bytes.
func notCanonical(code string) string {
	last := "B"
	if strings.HasSuffix(code, "B") {
		last = "C"
	}
	return code[:len(code)-1] + last
}

// bigValue is raw as a case's value: over BigValue bytes, held as a
// placeholder that the file's encoding writes back byte for byte, its
// spaces included (wireCase), so that a body padded past its call's limit
// stays so.
func bigValue(raw json.RawMessage) json.RawMessage { return wireCase("", raw, false).Value }

// WireV012 is wire-v012.json.
type WireV012 struct {
	Format      string       `json:"format"`
	Version     int          `json:"version"`
	Kind        string       `json:"kind"`
	Description string       `json:"description"`
	Snapshots   []WireCase   `json:"snapshots"`
	Sections    []WireCase   `json:"sections"`
	Results     []ResultCase `json:"results"`
}

// snapshotValid is what the platform makes of a snapshot: decoded
// strictly, and valid.
func snapshotValid(raw []byte) bool {
	var s contract.Snapshot
	return contract.DecodeStrict(raw, &s) == nil && s.Validate() == nil
}

func wireV012() (any, error) {
	out := WireV012{
		Format: Format, Version: 1, Kind: "wire-v012",
		Description: "What kit v0.12.0 adds beside the entitlements and usage part (SPEC sections 11.17 and 11.19). snapshots: access snapshots, decoded strictly, then Validate: an item's optional server (it lives on a customer's own server connected to the cloud) and pending (a mailbox whose first authorization never completed), each present only as true, never false or null; a server item's protected is [] (a connected item protects nobody); pending is a mailbox's only and never beside server. sections: Mailie's email-accounts with its three optional header members storage_paused, can_link and places_free, all three or none; storage_paused and can_link true or false, never null; places_free an integer 0 or more, or null. results: Mailie's item.sync_now and item.sync_resume refused capacity_reached (an item the plan's places leave stopped), its item.sync_now refused storage_paused, and the same codes on Mailie's kinds that answer neither, decoded strictly, then ValidateFor(app, kind).",
	}

	// Snapshots.
	str := func(s string) *string { return &s }
	person := contract.Person{Sub: vecSub, Can: []string{contract.CanRead}, Reads: true, Enrolled: true, HoldsKey: true}
	number := func(mut func(*contract.Item)) contract.Item {
		it := contract.Item{ID: vecNumber, Kind: contract.ItemNumber, Label: str("Vendas"), Hint: str("…5678"), State: contract.StateActive,
			People: []contract.Person{person}, Protected: []string{vecSub}}
		if mut != nil {
			mut(&it)
		}
		return it
	}
	mailbox := func(mut func(*contract.Item)) contract.Item {
		it := contract.Item{ID: vecMailbox, Kind: contract.ItemMailbox, Hint: str("j…@gmail.com"), State: contract.StateActive,
			People: []contract.Person{person}, Protected: []string{vecSub}}
		if mut != nil {
			mut(&it)
		}
		return it
	}
	server := func(it *contract.Item) { it.Server, it.Protected = true, []string{} }
	pending := func(it *contract.Item) {
		it.Pending, it.State, it.Reason = true, contract.StateSyncPaused, str("needs_reauth")
	}
	snap := func(items ...contract.Item) json.RawMessage {
		return mustRaw(contract.Snapshot{V: contract.SnapshotV, SnapshotSeq: Now.UnixMilli(), Items: items})
	}
	serverNumber := snap(number(server))
	pendingMailbox := snap(mailbox(pending))
	for _, c := range []struct {
		name  string
		raw   json.RawMessage
		valid bool
	}{
		{"a number on a connected server: server true, protected []", serverNumber, true},
		{"a mailbox on a connected server, its key holders reported", snap(mailbox(server)), true},
		{"a mailbox pending its first authorization", pendingMailbox, true},
		{"a pending mailbox that is active", snap(mailbox(func(it *contract.Item) { it.Pending = true })), true},
		{"neither member: a hosted item, linked", snap(number(nil), mailbox(nil)), true},
		{"a hosted number and a connected one", snap(number(nil), number(func(it *contract.Item) {
			server(it)
			it.ID = "dev_9"
		})), true},
		{"server false", edit(serverNumber, `"server":true`, `"server":false`), false},
		{"server null", edit(serverNumber, `"server":true`, `"server":null`), false},
		{"server as text", edit(serverNumber, `"server":true`, `"server":"true"`), false},
		{"server written Server", edit(serverNumber, `"server":true`, `"Server":true`), false},
		{"a server item that protects its reader", snap(number(func(it *contract.Item) { it.Server = true })), false},
		{"pending false", edit(pendingMailbox, `"pending":true`, `"pending":false`), false},
		{"pending null", edit(pendingMailbox, `"pending":true`, `"pending":null`), false},
		{"pending on a number", snap(number(func(it *contract.Item) { it.Pending = true })), false},
		{"pending beside server", snap(mailbox(func(it *contract.Item) {
			server(it)
			it.Pending = true
		})), false},
	} {
		if got := snapshotValid(c.raw); got != c.valid {
			return nil, fmt.Errorf("contractvec: snapshot %q is valid %v, the spec asks %v", c.name, got, c.valid)
		}
		out.Snapshots = append(out.Snapshots, wireCase(c.name, c.raw, c.valid))
	}

	// Mailie's email-accounts header.
	emails := func(l *contract.MailboxLinking) json.RawMessage {
		data := vecEmailAccounts(func(s *contract.EmailAccountsSettings) { s.Linking = l })
		return mustRaw(sectionDoc("mailie", contract.SectionEmailAccounts, data, nil))
	}
	all := emails(&contract.MailboxLinking{StoragePaused: false, CanLink: true, PlacesFree: ptr[int64](2)})
	const members = `"storage_paused":false,"can_link":true,"places_free":2`
	for _, c := range []struct {
		name  string
		raw   json.RawMessage
		valid bool
	}{
		{"all three: Mailie enforces a document with two places free", all, true},
		{"none: a section from before them", emails(nil), true},
		{"places_free 0: every place taken, so no link", emails(&contract.MailboxLinking{CanLink: false, PlacesFree: ptr[int64](0)}), true},
		{"places_free null: Mailie enforces no document", emails(&contract.MailboxLinking{CanLink: true}), true},
		{"storage_paused: the workspace stores nothing new", emails(&contract.MailboxLinking{StoragePaused: true, PlacesFree: ptr[int64](1)}), true},
		{"storage_paused alone", edit(all, members, `"storage_paused":false`), false},
		{"can_link alone", edit(all, members, `"can_link":true`), false},
		{"places_free alone", edit(all, members, `"places_free":2`), false},
		{"storage_paused and can_link without places_free", edit(all, members, `"storage_paused":false,"can_link":true`), false},
		{"can_link and places_free without storage_paused", edit(all, members, `"can_link":true,"places_free":2`), false},
		{"storage_paused null", edit(all, members, `"storage_paused":null,"can_link":true,"places_free":2`), false},
		{"can_link null", edit(all, members, `"storage_paused":false,"can_link":null,"places_free":2`), false},
		{"places_free below 0", edit(all, members, `"storage_paused":false,"can_link":true,"places_free":-1`), false},
		{"places_free as text", edit(all, members, `"storage_paused":false,"can_link":true,"places_free":"2"`), false},
		{"can_link twice", edit(all, members, `"storage_paused":false,"can_link":true,"can_link":false,"places_free":2`), false},
	} {
		if got := sectionValid(c.raw); got != c.valid {
			return nil, fmt.Errorf("contractvec: section %q is valid %v, the spec asks %v", c.name, got, c.valid)
		}
		out.Sections = append(out.Sections, wireCase(c.name, c.raw, c.valid))
	}

	// Mailie's refusals.
	refused := func(code string) json.RawMessage {
		return mustRaw(contract.CommandResult{ID: vecCommand, Outcome: contract.OutcomeRefused, Code: ptr(code), StateSeq: ptr(vecSeq), At: at(time.Second)})
	}
	for _, c := range []struct {
		name, app, kind, code string
		valid                 bool
	}{
		{"Mailie's sync now of a mailbox the places leave stopped: capacity_reached", "mailie", contract.OpItemSyncNow, contract.CodeCapacityReached, true},
		{"Mailie's resume of a mailbox the places leave stopped: capacity_reached", "mailie", contract.OpItemSyncResume, contract.CodeCapacityReached, true},
		{"Mailie's sync now while the workspace stores nothing new: storage_paused", "mailie", contract.OpItemSyncNow, contract.CodeStoragePaused, true},
		{"Wappie's resume of a number the places leave stopped: capacity_reached", "wappie", contract.OpItemSyncResume, contract.CodeCapacityReached, true},
		{"Mailie's resume refused storage_paused", "mailie", contract.OpItemSyncResume, contract.CodeStoragePaused, false},
		{"Mailie's pause refused capacity_reached", "mailie", contract.OpItemSyncStop, contract.CodeCapacityReached, false},
		{"Mailie's rename refused capacity_reached", "mailie", contract.OpItemRename, contract.CodeCapacityReached, false},
		{"Mailie's rename refused storage_paused", "mailie", contract.OpItemRename, contract.CodeStoragePaused, false},
	} {
		raw := refused(c.code)
		if got := resultValid(c.app, c.kind, raw); got != c.valid {
			return nil, fmt.Errorf("contractvec: result %q is valid %v, the spec asks %v", c.name, got, c.valid)
		}
		out.Results = append(out.Results, ResultCase{Name: c.name, App: c.app, Kind: c.kind, Value: raw, Valid: c.valid})
	}
	return out, nil
}

// WireEventsCodes is wire-events-codes.json.
type WireEventsCodes struct {
	Format      string     `json:"format"`
	Version     int        `json:"version"`
	Kind        string     `json:"kind"`
	Description string     `json:"description"`
	Events      []WireCase `json:"events"`
}

// eventValid is what the platform makes of an event: decoded strictly, as
// a body of events is, and valid.
func eventValid(raw []byte) bool {
	var e contract.Event
	return contract.DecodeStrict(raw, &e) == nil && e.Validate() == nil
}

func wireEventsCodes() (any, error) {
	out := WireEventsCodes{
		Format: Format, Version: 1, Kind: "wire-events-codes",
		Description: "The events item.linked and item.identity_updated (SPEC sections 11.17 and 11.20), each decoded strictly, as a body of events is, then Event's Validate. codes, required on both, lists 1 to 4 trial codes, each once, each 43 base64url characters that are the one canonical spelling of 32 bytes (the last character's low two bits zero); every other type carries no codes, not even []. readers is [] on both. item.linked's actor_kind is person, its actor the person who linked or moved it, or null; item.identity_updated takes any actor_kind. Neither carries purge_at, person, cause or stop. The codes are made under the key of trial-codes.json.",
	}
	str := func(s string) *string { return &s }
	readers := func(subs ...string) *[]string { s := append([]string{}, subs...); return &s }
	codes := vecCodes(5)
	ev := func(typ string, mut func(*contract.Event)) contract.Event {
		e := contract.Event{
			EventID: "0199d000-0000-7000-8000-000000000031", WorkspaceID: vecTeam, Type: typ, OccurredAt: contract.T(Now),
			Item:  contract.EventItem{ID: vecNumber, Kind: contract.ItemNumber, Label: str("Vendas"), Hint: str("…5678")},
			Actor: str(vecSub), ActorKind: contract.ActorPerson, Readers: readers(), Codes: codes[:2],
		}
		if mut != nil {
			mut(&e)
		}
		return e
	}
	mailbox := func(e *contract.Event) {
		e.Item = contract.EventItem{ID: vecMailbox, Kind: contract.ItemMailbox, Hint: str("j…@gmail.com")}
		e.Codes = []string{vecCode("mailie", contract.TrialKindGoogleSub, "110248495921238986420"),
			vecCode("mailie", contract.TrialKindAddress, "j.doe@gmail.com")}
	}
	n := func(k int) func(*contract.Event) { return func(e *contract.Event) { e.Codes = codes[:k] } }
	kind := func(k string, actor *string) func(*contract.Event) {
		return func(e *contract.Event) { e.ActorKind, e.Actor = k, actor }
	}
	purge := contract.T(Now.Add(30 * 24 * time.Hour))
	linked := mustRaw(ev(contract.EventLinked, nil))
	updated := mustRaw(ev(contract.EventIdentityUpdated, nil))
	pair := `"codes":["` + codes[0] + `","` + codes[1] + `"]`
	for _, c := range []struct {
		name  string
		raw   json.RawMessage
		valid bool
	}{
		{"a number linked, with its phone number's and its LID's codes", linked, true},
		{"a mailbox linked by Google's sign-in: its sub's and its address's codes", mustRaw(ev(contract.EventLinked, mailbox)), true},
		{"item.linked with one code", mustRaw(ev(contract.EventLinked, n(1))), true},
		{"item.linked with four codes, its most", mustRaw(ev(contract.EventLinked, n(4))), true},
		{"item.linked with no actor: a person no longer known", mustRaw(ev(contract.EventLinked, kind(contract.ActorPerson, nil))), true},
		{"item.identity_updated: a LID seen after pairing, the app the actor", mustRaw(ev(contract.EventIdentityUpdated, kind(contract.ActorApp, nil))), true},
		{"item.identity_updated by a person's re-authorization", updated, true},
		{"item.identity_updated by a key's act", mustRaw(ev(contract.EventIdentityUpdated, kind(contract.ActorKey, str(vecSub)))), true},
		{"item.identity_updated with four codes", mustRaw(ev(contract.EventIdentityUpdated, n(4))), true},
		{"item.linked with no codes", edit(linked, ","+pair, ""), false},
		{"item.linked with codes []", edit(linked, pair, `"codes":[]`), false},
		{"item.linked with codes null", edit(linked, pair, `"codes":null`), false},
		{"item.identity_updated with no codes", edit(updated, ","+pair, ""), false},
		{"item.identity_updated with codes []", edit(updated, pair, `"codes":[]`), false},
		{"item.linked with five codes", mustRaw(ev(contract.EventLinked, n(5))), false},
		{"item.identity_updated with five codes", mustRaw(ev(contract.EventIdentityUpdated, n(5))), false},
		{"item.linked with a code twice", edit(linked, pair, `"codes":["`+codes[0]+`","`+codes[0]+`"]`), false},
		{"item.identity_updated with a code twice", edit(updated, pair, `"codes":["`+codes[1]+`","`+codes[1]+`"]`), false},
		{"a code that is not canonical: its last character's low bits set", edit(linked, codes[1], notCanonical(codes[1])), false},
		{"a code of 42 characters", edit(linked, codes[1], codes[1][:42]), false},
		{"a code of 44 characters", edit(linked, codes[1], codes[1]+"A"), false},
		{"a code in base64 with padding", edit(linked, codes[1], codes[1]+"="), false},
		{"a code with base64's + and /", edit(linked, codes[1], "+/"+codes[1][2:]), false},
		{"a code that is no string", edit(linked, `"`+codes[1]+`"`, `7`), false},
		{"a code written null", edit(linked, `"`+codes[1]+`"`, `null`), false},
		{"codes written Codes", edit(linked, `"codes":`, `"Codes":`), false},
		{"codes on item.deleted", mustRaw(ev(contract.EventDeleted, func(e *contract.Event) { e.PurgeAt, e.Readers = &purge, readers(vecSub) })), false},
		{"codes [] on item.deleted", edit(mustRaw(ev(contract.EventDeleted, func(e *contract.Event) { e.PurgeAt, e.Readers = &purge, readers(vecSub) })),
			pair, `"codes":[]`), false},
		{"codes on item.recovered", mustRaw(ev(contract.EventRecovered, func(e *contract.Event) { e.Readers = readers(vecSub) })), false},
		{"item.linked with a reader", mustRaw(ev(contract.EventLinked, func(e *contract.Event) { e.Readers = readers(vecSub) })), false},
		{"item.identity_updated with a reader", mustRaw(ev(contract.EventIdentityUpdated, func(e *contract.Event) { e.Readers = readers(vecSub) })), false},
		{"item.linked with readers null", edit(linked, `"readers":[]`, `"readers":null`), false},
		{"item.linked by a key", mustRaw(ev(contract.EventLinked, kind(contract.ActorKey, str(vecSub)))), false},
		{"item.linked by the app", mustRaw(ev(contract.EventLinked, kind(contract.ActorApp, nil))), false},
		{"item.identity_updated by an actor kind the part does not know", mustRaw(ev(contract.EventIdentityUpdated, kind("operator", nil))), false},
		{"item.linked with purge_at", mustRaw(ev(contract.EventLinked, func(e *contract.Event) { e.PurgeAt = &purge })), false},
		{"item.identity_updated with stop", mustRaw(ev(contract.EventIdentityUpdated, func(e *contract.Event) { e.Stop = contract.StopPause })), false},
		{"item.linked with a person", mustRaw(ev(contract.EventLinked, func(e *contract.Event) { e.Person = str(vecOther) })), false},
	} {
		if got := eventValid(c.raw); got != c.valid {
			return nil, fmt.Errorf("contractvec: event %q is valid %v, the spec asks %v", c.name, got, c.valid)
		}
		out.Events = append(out.Events, wireCase(c.name, c.raw, c.valid))
	}
	return out, nil
}

// LinkCheckCase is one link check of app, and whether the platform takes
// it.
type LinkCheckCase struct {
	Name  string          `json:"name"`
	App   string          `json:"app"`
	Value json.RawMessage `json:"value"`
	Valid bool            `json:"valid"`
}

// WireLinkCheck is wire-link-check.json.
type WireLinkCheck struct {
	Format      string          `json:"format"`
	Version     int             `json:"version"`
	Kind        string          `json:"kind"`
	Description string          `json:"description"`
	Requests    []LinkCheckCase `json:"requests"`
	Answers     []WireCase      `json:"answers"`
}

// linkCheckValid is what the platform makes of app's link check: within
// its 4 KiB, decoded strictly, and ValidateFor(app).
func linkCheckValid(app string, raw []byte) bool {
	var c contract.LinkCheck
	return len(raw) <= contract.LinkCheckBodyLimit && contract.DecodeStrict(raw, &c) == nil && c.ValidateFor(app) == nil
}

// linkAnswerValid is what an app makes of a link check's answer: read as
// it reads what the platform sends, and valid.
func linkAnswerValid(raw []byte) bool {
	var a contract.LinkCheckAnswer
	return json.Unmarshal(raw, &a) == nil && a.Validate() == nil
}

func wireLinkCheck() (any, error) {
	out := WireLinkCheck{
		Format: Format, Version: 1, Kind: "wire-link-check",
		Description: "The link check (SPEC section 11.20), POST /contract/v1/workspaces/{id}/link-check. requests: a body of app's, within 4 KiB, decoded strictly (kind, codes and connected, each present, none null, none twice or unknown, names exactly as written), then ValidateFor(app): kind the app's (number for Wappie and the reference app, mailbox for Mailie); codes 0 to 4 trial codes, each once, each 43 base64url characters that are the one canonical spelling of 32 bytes, [] for none; none beside connected true. answers: the platform's answer, read as an app reads what the platform sends (members it does not know ignored, every member present, null only for place and trial_ends_at), then Validate: place free, none or null; trial not_needed, used_up or running; trial_ends_at set exactly on running, after computed_at; switches.new_links on or off.",
	}
	codes := vecCodes(5)
	mailieCodes := []string{vecCode("mailie", contract.TrialKindMSTidSub, "9188040d-6c67-4c5b-b112-36a304b66dad/AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ"),
		vecCode("mailie", contract.TrialKindAddress, "ana@contoso.com")}
	check := func(kind string, codes []string, connected bool) json.RawMessage {
		return mustRaw(contract.LinkCheck{Kind: kind, Codes: codes, Connected: connected})
	}
	two := check(contract.ItemNumber, codes[:2], false)
	pair := `["` + codes[0] + `","` + codes[1] + `"]`
	for _, c := range []struct {
		name, app string
		raw       json.RawMessage
		valid     bool
	}{
		{"a number paired: its phone number's and its LID's codes", "wappie", two, true},
		{"the place alone: no codes", "wappie", check(contract.ItemNumber, []string{}, false), true},
		{"four codes, the most", "wappie", check(contract.ItemNumber, codes[:4], false), true},
		{"a mailbox authorized: its tid and sub's and its address's codes", "mailie", check(contract.ItemMailbox, mailieCodes, false), true},
		{"Mailie before it starts a link at the provider: the place alone", "mailie", check(contract.ItemMailbox, []string{}, false), true},
		{"a server's number being connected: no codes", "wappie", check(contract.ItemNumber, []string{}, true), true},
		{"the reference app's number", contract.ReferenceApp, check(contract.ItemNumber, codes[:1], false), true},
		{"codes on a connected item", "wappie", check(contract.ItemNumber, codes[:1], true), false},
		{"five codes", "wappie", check(contract.ItemNumber, codes, false), false},
		{"a code twice", "wappie", edit(two, pair, `["`+codes[0]+`","`+codes[0]+`"]`), false},
		{"a code that is not canonical", "wappie", edit(two, codes[1], notCanonical(codes[1])), false},
		{"a code of 42 characters", "wappie", edit(two, codes[1], codes[1][:42]), false},
		{"a code of 44 characters", "wappie", edit(two, codes[1], codes[1]+"A"), false},
		{"codes null", "wappie", edit(two, pair, `null`), false},
		{"no codes member", "wappie", edit(two, `"codes":`+pair+`,`, ""), false},
		{"no connected member", "wappie", edit(two, `,"connected":false`, ""), false},
		{"a mailbox for Wappie", "wappie", check(contract.ItemMailbox, []string{}, false), false},
		{"a number for Mailie", "mailie", check(contract.ItemNumber, []string{}, false), false},
		{"a kind the part does not know", "wappie", check("phone", []string{}, false), false},
		{"an unknown member", "wappie", edit(two, `"connected":false`, `"connected":false,"label":"Vendas"`), false},
		{"kind written Kind", "wappie", edit(two, `"kind":`, `"Kind":`), false},
		{"connected as text", "wappie", edit(two, `"connected":false`, `"connected":"false"`), false},
		{"over 4 KiB: its members spaced out", "wappie", json.RawMessage(padTo(string(two), BigValue+1)), false},
	} {
		if got := linkCheckValid(c.app, c.raw); got != c.valid {
			return nil, fmt.Errorf("contractvec: link check %q is valid %v, the spec asks %v", c.name, got, c.valid)
		}
		out.Requests = append(out.Requests, LinkCheckCase{Name: c.name, App: c.app, Value: bigValue(c.raw), Valid: c.valid})
	}

	answer := func(place *string, trial string, endsAt *contract.Time, newLinks string) json.RawMessage {
		return mustRaw(contract.LinkCheckAnswer{Place: place, Trial: trial, TrialEndsAt: endsAt,
			Switches: contract.LinkCheckSwitches{NewLinks: newLinks}, ComputedAt: at(0)})
	}
	free, none := ptr(contract.PlaceFree), ptr(contract.PlaceNone)
	running := answer(free, contract.TrialRunning, ptr(at(360*time.Hour)), contract.SwitchOn)
	ends := `"trial_ends_at":"` + at(360*time.Hour).Format(time.RFC3339) + `"`
	for _, c := range []struct {
		name  string
		raw   json.RawMessage
		valid bool
	}{
		{"a free place, no trial needed", answer(free, contract.TrialNotNeeded, nil, contract.SwitchOn), true},
		{"a clock a link would start: running, computed_at plus 360 h", running, true},
		{"a clock that ended: used_up", answer(free, contract.TrialUsedUp, nil, contract.SwitchOn), true},
		{"no place, new links off", answer(none, contract.TrialNotNeeded, nil, contract.SwitchOff), true},
		{"place null: the platform's count unknown", answer(nil, contract.TrialNotNeeded, nil, contract.SwitchOn), true},
		{"a member the app does not know, ignored", edit(running, `"computed_at":`, `"advice":"buy","computed_at":`), true},
		{"running a second after computed_at", answer(free, contract.TrialRunning, ptr(at(time.Second)), contract.SwitchOn), true},
		{"trial_ends_at on not_needed", answer(free, contract.TrialNotNeeded, ptr(at(360*time.Hour)), contract.SwitchOn), false},
		{"trial_ends_at on used_up", answer(free, contract.TrialUsedUp, ptr(at(-time.Hour)), contract.SwitchOn), false},
		{"running without trial_ends_at", edit(running, ends, `"trial_ends_at":null`), false},
		{"running at computed_at", answer(free, contract.TrialRunning, ptr(at(0)), contract.SwitchOn), false},
		{"running before computed_at", answer(free, contract.TrialRunning, ptr(at(-time.Second)), contract.SwitchOn), false},
		{"a place the part does not know", edit(running, `"place":"free"`, `"place":"some"`), false},
		{"a trial the part does not know", edit(running, `"trial":"running"`, `"trial":"pending"`), false},
		{"new_links null", edit(running, `"new_links":"on"`, `"new_links":null`), false},
		{"new_links in capitals", edit(running, `"new_links":"on"`, `"new_links":"ON"`), false},
		{"no trial_ends_at member", edit(running, ","+ends, ""), false},
		{"no switches", edit(running, `,"switches":{"new_links":"on"}`, ""), false},
		{"computed_at null", edit(running, `"computed_at":"`+at(0).Format(time.RFC3339)+`"`, `"computed_at":null`), false},
		{"a member twice", edit(running, `"trial":"running"`, `"trial":"running","trial":"used_up"`), false},
	} {
		if got := linkAnswerValid(c.raw); got != c.valid {
			return nil, fmt.Errorf("contractvec: link check answer %q is valid %v, the spec asks %v", c.name, got, c.valid)
		}
		out.Answers = append(out.Answers, wireCase(c.name, c.raw, c.valid))
	}
	return out, nil
}
