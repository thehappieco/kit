package contract_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/thehappieco/kit/contract"
)

// linked is a valid item.linked of a mailbox with two codes.
func linked(t *testing.T, mut func(*contract.Event)) contract.Event {
	t.Helper()
	ev := contract.Event{
		EventID: "0199d000-0000-7000-8000-000000000001", WorkspaceID: vecTeam, Type: contract.EventLinked,
		OccurredAt: contract.T(time.Date(2026, 12, 3, 10, 0, 0, 0, time.UTC)),
		Item:       contract.EventItem{ID: "mbx_1", Kind: contract.ItemMailbox, Label: ptr("Vendas"), Hint: ptr("a…@example.com")},
		Actor:      ptr(vecSub), ActorKind: contract.ActorPerson, Readers: &[]string{},
		Codes: codes(t, 2),
	}
	if mut != nil {
		mut(&ev)
	}
	return ev
}

// item.linked and item.identity_updated carry 1 to 4 codes, each once,
// readers [], and no member of another type; item.linked is a person's,
// item.identity_updated anyone's. Codes on any other type are refused,
// even [].
func TestTheLinkEventsCarryCodesAndNoOtherTypeDoes(t *testing.T) {
	four := codes(t, 4)
	purge := contract.T(time.Now())
	valid := map[string]contract.Event{
		"linked":                       linked(t, nil),
		"linked with four codes":       linked(t, func(ev *contract.Event) { ev.Codes = four }),
		"linked with no actor":         linked(t, func(ev *contract.Event) { ev.Actor = nil }),
		"a number linked":              linked(t, func(ev *contract.Event) { ev.Item = contract.EventItem{ID: "dev_1", Kind: contract.ItemNumber} }),
		"identity_updated by a person": linked(t, func(ev *contract.Event) { ev.Type = contract.EventIdentityUpdated }),
		"identity_updated by a key": linked(t, func(ev *contract.Event) {
			ev.Type, ev.ActorKind = contract.EventIdentityUpdated, contract.ActorKey
		}),
		"identity_updated by the app": linked(t, func(ev *contract.Event) {
			ev.Type, ev.ActorKind, ev.Actor = contract.EventIdentityUpdated, contract.ActorApp, nil
		}),
	}
	for name, ev := range valid {
		if err := ev.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	both := func(name string, mut func(*contract.Event)) map[string]contract.Event {
		return map[string]contract.Event{
			name + " (linked)": linked(t, mut),
			name + " (identity_updated)": linked(t, func(ev *contract.Event) {
				ev.Type = contract.EventIdentityUpdated
				mut(ev)
			}),
		}
	}
	invalid := map[string]contract.Event{
		"linked by a key": linked(t, func(ev *contract.Event) { ev.ActorKind = contract.ActorKey }),
		"linked by the app": linked(t, func(ev *contract.Event) {
			ev.ActorKind, ev.Actor = contract.ActorApp, nil
		}),
		"codes on item.deleted": {
			EventID: "0199d000-0000-7000-8000-000000000002", WorkspaceID: vecTeam, Type: contract.EventDeleted,
			OccurredAt: contract.T(time.Now()), Item: contract.EventItem{ID: "dev_1", Kind: contract.ItemNumber},
			Actor: ptr(vecSub), ActorKind: contract.ActorPerson, Readers: &[]string{}, PurgeAt: &purge, Codes: four[:1],
		},
		"[] on item.recovered": {
			EventID: "0199d000-0000-7000-8000-000000000002", WorkspaceID: vecTeam, Type: contract.EventRecovered,
			OccurredAt: contract.T(time.Now()), Item: contract.EventItem{ID: "dev_1", Kind: contract.ItemNumber},
			Actor: ptr(vecSub), ActorKind: contract.ActorPerson, Readers: &[]string{}, Codes: contract.TrialCodes{},
		},
	}
	for _, m := range []map[string]contract.Event{
		both("no codes", func(ev *contract.Event) { ev.Codes = nil }),
		both("codes []", func(ev *contract.Event) { ev.Codes = contract.TrialCodes{} }),
		both("five codes", func(ev *contract.Event) { ev.Codes = codes(t, 5) }),
		both("a code twice", func(ev *contract.Event) { ev.Codes = []string{four[0], four[0]} }),
		both("a code not canonical", func(ev *contract.Event) { ev.Codes = []string{four[0][:42] + "B"} }),
		both("a code of 42", func(ev *contract.Event) { ev.Codes = []string{four[0][:42]} }),
		both("readers not empty", func(ev *contract.Event) { ev.Readers = &[]string{vecSub} }),
		both("readers null", func(ev *contract.Event) { ev.Readers = nil }),
		both("purge_at", func(ev *contract.Event) { ev.PurgeAt = &purge }),
		both("person", func(ev *contract.Event) { ev.Person = ptr(vecSub) }),
		both("cause", func(ev *contract.Event) { ev.Cause = ptr("disabled") }),
		both("to", func(ev *contract.Event) { ev.To = ptr(contract.MovedToPersonal) }),
		both("stop", func(ev *contract.Event) { ev.Stop = contract.StopPause }),
	} {
		for name, ev := range m {
			invalid[name] = ev
		}
	}
	for name, ev := range invalid {
		if err := ev.Validate(); !errors.Is(err, contract.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// On the wire, codes are absent on every other type, so the earlier events
// are written as before, and a present codes is never null.
func TestCodesAreAbsentFromOtherEventsAndNeverNull(t *testing.T) {
	ev := linked(t, nil)
	raw, err := json.Marshal(ev)
	if err != nil || !bytes.Contains(raw, []byte(`"codes":["`)) {
		t.Fatalf("%s %v", raw, err)
	}
	var back contract.Event
	if err := contract.DecodeStrict(raw, &back); err != nil || back.Validate() != nil || len(back.Codes) != 2 {
		t.Fatalf("%v %+v", err, back.Codes)
	}
	ev.Type, ev.Codes, ev.Readers = contract.EventRecovered, nil, &[]string{vecSub}
	raw, _ = json.Marshal(ev)
	if bytes.Contains(raw, []byte(`codes`)) {
		t.Errorf("%s", raw)
	}
	ev.Codes = contract.TrialCodes{}
	raw, _ = json.Marshal(ev)
	if !bytes.Contains(raw, []byte(`"codes":[]`)) {
		t.Errorf("[] is not written: %s", raw)
	}
	var e contract.Event
	if err := contract.DecodeStrict(raw, &e); err != nil || e.Codes == nil || e.Validate() == nil {
		t.Errorf("[] on item.recovered reads as absent or passes: %v", err)
	}
	good, _ := json.Marshal(linked(t, nil))
	for name, edit := range map[string]func(m map[string]any){
		"codes null":          func(m map[string]any) { m["codes"] = nil },
		"a code null":         func(m map[string]any) { m["codes"] = []any{nil} },
		"a code not a string": func(m map[string]any) { m["codes"] = []any{1} },
		"codes an object":     func(m map[string]any) { m["codes"] = map[string]any{} },
	} {
		var e contract.Event
		if err := contract.DecodeStrict(entEdit(t, good, edit), &e); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}

// An event never prints its codes, in any verb or in a structured log.
func TestAnEventNeverPrintsItsCodes(t *testing.T) {
	ev := linked(t, nil)
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("event", "event", ev)
	for _, s := range []string{fmt.Sprint(ev), fmt.Sprintf("%v %+v %#v %s", ev, ev, ev, ev), logged.String()} {
		if strings.Contains(s, ev.Codes[0][:12]) || strings.Contains(s, ev.Codes[1][:12]) {
			t.Errorf("printed %s", s)
		}
		if !strings.Contains(s, ev.EventID) || !strings.Contains(s, "item.linked") {
			t.Errorf("printed %s", s)
		}
	}
}
