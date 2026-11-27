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

// codes are n distinct trial codes, made under the test key.
func codes(t *testing.T, n int) []string {
	t.Helper()
	out := make([]string, n)
	for i := range out {
		out[i] = trialCode(t, "mailie", contract.TrialKindGoogleSub, fmt.Sprintf("1101694844743862763%02d", i))
	}
	return out
}

// The spec's link check decodes strictly and validates; codes beside a
// connected item, five codes, a code that is not canonical or twice, a bad
// kind, and codes null or missing are refused.
func TestALinkCheckIsReadStrictlyAndValidated(t *testing.T) {
	two := codes(t, 2)
	example := `{"kind": "mailbox", "codes": ["` + two[0] + `"], "connected": false}`
	var c contract.LinkCheck
	if err := contract.DecodeStrict([]byte(example), &c); err != nil {
		t.Fatal(err)
	}
	if err := c.ValidateFor("mailie"); err != nil {
		t.Fatal(err)
	}
	if c.ValidateFor("wappie") == nil || c.ValidateFor("fakeproduct") == nil || c.ValidateFor("vaultie") == nil {
		t.Error("a mailbox passes for an app of numbers")
	}
	for _, valid := range []contract.LinkCheck{
		{Kind: contract.ItemNumber, Codes: []string{}},
		{Kind: contract.ItemNumber, Codes: []string{}, Connected: true},
		{Kind: contract.ItemMailbox, Codes: codes(t, 4)},
	} {
		if err := valid.Validate(); err != nil {
			t.Errorf("%v: %v", valid, err)
		}
	}
	// B is not among AEIMQUYcgkosw048: its low two bits are not zero.
	notCanonical := two[0][:42] + "B"
	for name, invalid := range map[string]contract.LinkCheck{
		"codes beside connected": {Kind: contract.ItemMailbox, Codes: two[:1], Connected: true},
		"five codes":             {Kind: contract.ItemMailbox, Codes: codes(t, 5)},
		"a code twice":           {Kind: contract.ItemMailbox, Codes: []string{two[0], two[0]}},
		"a code not canonical":   {Kind: contract.ItemMailbox, Codes: []string{notCanonical}},
		"a code of 42":           {Kind: contract.ItemMailbox, Codes: []string{two[0][:42]}},
		"a code of 44":           {Kind: contract.ItemMailbox, Codes: []string{two[0] + "A"}},
		"a bad kind":             {Kind: "phone", Codes: []string{}},
		"codes nil":              {Kind: contract.ItemNumber},
	} {
		if err := invalid.Validate(); !errors.Is(err, contract.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		} else if strings.Contains(err.Error(), two[0][:10]) {
			t.Errorf("%s: the error carries a code", name)
		}
	}
	for _, raw := range []string{
		`{"kind": "number", "codes": null, "connected": false}`,
		`{"kind": "number", "connected": false}`,
		`{"kind": "number", "codes": [], "connected": null}`,
		`{"kind": "number", "codes": [], "connected": false, "trial": "x"}`,
		`{"Kind": "number", "codes": [], "connected": false}`,
		`{"kind": "number", "codes": [], "codes": [], "connected": false}`,
	} {
		var c contract.LinkCheck
		if err := contract.DecodeStrict([]byte(raw), &c); err == nil {
			t.Errorf("%s: read", raw)
		}
	}
}

// A link check never prints its codes.
func TestALinkCheckNeverPrintsItsCodes(t *testing.T) {
	c := contract.LinkCheck{Kind: contract.ItemMailbox, Codes: codes(t, 2)}
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("check", "check", c)
	for _, s := range []string{fmt.Sprint(c), fmt.Sprintf("%v %+v %#v %s", c, c, c, c), logged.String()} {
		if strings.Contains(s, c.Codes[0][:12]) || strings.Contains(s, c.Codes[1][:12]) {
			t.Errorf("printed %s", s)
		}
	}
	if !strings.Contains(logged.String(), `"codes":2`) {
		t.Error(logged.String())
	}
}

// The spec's answer decodes as an app reads what the platform sends, and
// Validate holds trial_ends_at to running and after computed_at.
func TestALinkCheckAnswerIsValidated(t *testing.T) {
	read := func(raw string) (contract.LinkCheckAnswer, error) {
		var a contract.LinkCheckAnswer
		if err := json.Unmarshal([]byte(raw), &a); err != nil {
			return a, err
		}
		return a, a.Validate()
	}
	a, err := read(`{"place": "free", "trial": "not_needed", "trial_ends_at": null,
 "switches": {"new_links": "on"}, "computed_at": "2026-12-03T10:00:00Z"}`)
	if err != nil || *a.Place != contract.PlaceFree || a.Trial != contract.TrialNotNeeded || a.Switches.NewLinks != contract.SwitchOn {
		t.Fatalf("%+v %v", a, err)
	}
	computed := time.Date(2026, 12, 3, 10, 0, 0, 0, time.UTC)
	answer := func(place *string, trial string, ends *time.Duration, newLinks string) string {
		m := map[string]any{"place": place, "trial": trial, "trial_ends_at": nil,
			"switches": map[string]any{"new_links": newLinks}, "computed_at": contract.T(computed), "later": 1}
		if ends != nil {
			m["trial_ends_at"] = contract.T(computed.Add(*ends))
		}
		b, _ := json.Marshal(m)
		return string(b)
	}
	d := func(x time.Duration) *time.Duration { return &x }
	none, free, odd := ptr(contract.PlaceNone), ptr(contract.PlaceFree), ptr("some")
	for name, c := range map[string]struct {
		raw string
		ok  bool
	}{
		"running, 360 h on":            {answer(free, contract.TrialRunning, d(360*time.Hour), "on"), true},
		"running, a nanosecond on":     {answer(free, contract.TrialRunning, d(time.Nanosecond), "on"), true},
		"used_up, no place, links off": {answer(none, contract.TrialUsedUp, nil, "off"), true},
		"place null":                   {answer(nil, contract.TrialNotNeeded, nil, "on"), true},
		"running at computed_at":       {answer(free, contract.TrialRunning, d(0), "on"), false},
		"running before computed_at":   {answer(free, contract.TrialRunning, d(-time.Second), "on"), false},
		"running with no end":          {answer(free, contract.TrialRunning, nil, "on"), false},
		"an end on used_up":            {answer(free, contract.TrialUsedUp, d(time.Hour), "on"), false},
		"an end on not_needed":         {answer(free, contract.TrialNotNeeded, d(time.Hour), "on"), false},
		"another place":                {answer(odd, contract.TrialNotNeeded, nil, "on"), false},
		"another trial":                {answer(free, "maybe", nil, "on"), false},
		"a bad new_links":              {answer(free, contract.TrialNotNeeded, nil, "paused"), false},
		"trial_ends_at missing":        {`{"place": "free", "trial": "not_needed", "switches": {"new_links": "on"}, "computed_at": "2026-12-03T10:00:00Z"}`, false},
		"switches null":                {`{"place": "free", "trial": "not_needed", "trial_ends_at": null, "switches": null, "computed_at": "2026-12-03T10:00:00Z"}`, false},
		"trial null":                   {`{"place": "free", "trial": null, "trial_ends_at": null, "switches": {"new_links": "on"}, "computed_at": "2026-12-03T10:00:00Z"}`, false},
		"a member twice":               {`{"place": "free", "place": "none", "trial": "not_needed", "trial_ends_at": null, "switches": {"new_links": "on"}, "computed_at": "2026-12-03T10:00:00Z"}`, false},
		"a member not named exactly":   {`{"Place": "none", "place": "free", "trial": "not_needed", "trial_ends_at": null, "switches": {"new_links": "on"}, "computed_at": "2026-12-03T10:00:00Z"}`, true},
		"a switch it does not know":    {`{"place": "free", "trial": "not_needed", "trial_ends_at": null, "switches": {"new_links": "on", "sync": "off"}, "computed_at": "2026-12-03T10:00:00Z"}`, true},
	} {
		a, err := read(c.raw)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
		if name == "a member not named exactly" && err == nil && *a.Place != contract.PlaceFree {
			t.Errorf("%s: read %q", name, *a.Place)
		}
	}
	trials := contract.LinkCheckTrials()
	trials[0] = "free"
	if contract.LinkCheckTrials()[0] != contract.TrialNotNeeded {
		t.Error("LinkCheckTrials is not a copy")
	}
}
