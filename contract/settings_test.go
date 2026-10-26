package contract_test

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/thehappieco/kit/contract"
)

// The closed lists are copies: a caller that changes one changes nothing
// Validate checks.
func TestTheSettingsPartsListsAreCopies(t *testing.T) {
	for _, list := range []func() []string{
		contract.AIProviders, contract.AIFunctions, contract.EndReasons, contract.BudgetHits, contract.AIAlerts,
		contract.ServerAllows, contract.CommandRefusalCodes,
		func() []string { return contract.NoticeCodes("wappie") }, func() []string { return contract.Sections("mailie") },
	} {
		a := list()
		a[0] = "changed"
		if list()[0] == "changed" {
			t.Errorf("a list shares its backing array: %v", list())
		}
	}
	k := contract.CommandKinds("wappie")
	k[0].Refusals[0], k[0].Target[0] = "changed", "changed"
	if again := contract.CommandKinds("wappie"); again[0].Refusals[0] == "changed" || again[0].Target[0] == "changed" {
		t.Error("CommandKinds shares its lists")
	}
	one, _ := contract.CommandKindOf("wappie", contract.OpItemRename)
	one.Refusals[0] = "changed"
	if again, _ := contract.CommandKindOf("wappie", contract.OpItemRename); again.Refusals[0] == "changed" {
		t.Error("CommandKindOf shares its lists")
	}
}

// Each app's kinds are its own, each in a section of the app, every one a
// tightening kind or one with an expiry, and an app's id other than the
// two, the reference app's, has Wappie's.
func TestEveryKindIsInASectionOfItsApp(t *testing.T) {
	for _, app := range []string{"wappie", "mailie", "fakeproduct"} {
		sections := append(contract.Sections(app), contract.SectionPerson)
		seen := map[string]bool{}
		for _, k := range contract.CommandKinds(app) {
			if !slices.Contains(sections, k.Section) || seen[k.Kind] {
				t.Errorf("%s's %s: section %s, or twice", app, k.Kind, k.Section)
			}
			seen[k.Kind] = true
			if k.Agreement != contract.AgreementNever && k.Tightening {
				t.Errorf("%s's %s agrees and tightens", app, k.Kind)
			}
			if k.Confirm != "" && !slices.Contains(k.Target, k.Confirm) {
				t.Errorf("%s's %s confirms what it does not target", app, k.Kind)
			}
		}
	}
	if len(contract.CommandKinds("fakeproduct")) != len(contract.CommandKinds("wappie")) || contract.CommandKinds("Wappie") != nil {
		t.Error("the reference app has Wappie's kinds, and an id that is no app none")
	}
	if contract.SectionProducer("fakeproduct", contract.SectionInstallations) != "fakeproduct" ||
		contract.SectionProducer("wappie", contract.SectionInstallations) != contract.ProducerWappieCloud {
		t.Error("producers")
	}
}

// DecodeData gives the section's own type, and only for a valid document.
func TestDecodeDataGivesTheSectionsType(t *testing.T) {
	d := sectionDoc("wappie", contract.SectionNumbers, vecNumbers(nil), nil)
	data, err := d.DecodeData()
	if n, ok := data.(*contract.NumbersSettings); err != nil || !ok || n.Items[0].ID != vecNumber {
		t.Fatalf("%T %v", data, err)
	}
	p := personDoc("mailie", vecMailiePerson(nil), nil)
	if data, err := p.DecodeData(); err != nil || len(data.(*contract.MailiePersonSettings).Consents) != 3 {
		t.Fatalf("%T %v", data, err)
	}
	d.Accepts = []string{contract.OpConsentAgree}
	if _, err := d.DecodeData(); !errors.Is(err, contract.ErrInvalid) {
		t.Errorf("an invalid document's data: %v", err)
	}
}

// What a section never carries: a name that is not a label, wherever a
// name goes, and free text in a code's place.
func TestNoNameInADocumentHoldsAnAddressOrARunOfDigits(t *testing.T) {
	for _, name := range []string{"ana@example.com", "Loja 11912345678", "+55 (11) 91234-5678", "a‮b", " Vendas", ""} {
		raws := []json.RawMessage{
			mustRaw(sectionDoc("wappie", contract.SectionNumbers, vecNumbers(nil), nil)),
			mustRaw(sectionDoc("wappie", contract.SectionMCP, vecMCP(func(s *contract.MCPSettings) { s.Connections[0].Name = &name }), nil)),
			mustRaw(sectionDoc("wappie", contract.SectionMCP, vecMCP(func(s *contract.MCPSettings) { s.LegacyTokens[0].Name = &name }), nil)),
			mustRaw(sectionDoc("wappie", contract.SectionIntegrations, vecIntegrations(func(s *contract.IntegrationsSettings) {
				s.Integrations[0].Name = &name
			}), nil)),
			mustRaw(sectionDoc("wappie", contract.SectionInstallations, vecInstallations(func(s *contract.InstallationsSettings) {
				s.Installations[0].Name = &name
			}), nil)),
			mustRaw(personDoc("wappie", vecWappiePerson(func(s *contract.WappiePersonSettings) { s.Notices[0].Label = &name }), nil)),
		}
		if !sectionValid(raws[0]) {
			t.Fatal("the base document")
		}
		for i, raw := range raws[1:] {
			if sectionValid(raw) || personValid(raw) {
				t.Errorf("%q passes as a name (%d)", name, i)
			}
		}
	}
}

// A command signs and verifies over its canonical text, under its app and
// the secret alone: never under another app or secret, and never under a
// list that holds a key that is not a secret.
func TestACommandVerifiesUnderItsAppAndSecretOnly(t *testing.T) {
	raw := signed(vecCmd("wappie", contract.OpItemRename, nil), SecretA)
	c, err := contract.VerifyCommand(raw, "wappie", []string{SecretB, SecretA})
	if err != nil || c.ID != vecCommand || c.ValidateIn(contract.KindTeam) != nil {
		t.Fatalf("%v", err)
	}
	for _, try := range []struct {
		app     string
		secrets []string
	}{
		{"mailie", []string{SecretA}}, {"wappie", []string{SecretB}}, {"wappie", nil},
		{"wappie", []string{"", SecretA}}, {"wappie", []string{SecretA + "="}}, {"Wappie", []string{SecretA}},
	} {
		if _, err := contract.VerifyCommand(raw, try.app, try.secrets); !errors.Is(err, contract.ErrCommandMAC) {
			t.Errorf("%s %d secrets: %v", try.app, len(try.secrets), err)
		}
	}
	if _, err := contract.SignCommand(raw, "wappie", ""); !errors.Is(err, contract.ErrSecret) {
		t.Errorf("signing under an empty key: %v", err)
	}
	if _, err := contract.SignCommand([]byte(`{"a":1.5}`), "wappie", SecretA); !errors.Is(err, contract.ErrInvalid) {
		t.Errorf("a fraction, which JCS does not write here: %v", err)
	}
	if _, err := contract.VerifyCommand([]byte(`[1]`), "wappie", []string{SecretA}); !errors.Is(err, contract.ErrInvalid) {
		t.Errorf("an array: %v", err)
	}
}

// A command's error names what failed, never a value it holds.
func TestACommandsRefusalNamesNoValue(t *testing.T) {
	c := vecCmd("wappie", contract.OpItemFlagsRaise, func(c *contract.Command) {
		c.Params = json.RawMessage(`{"before":{"can":["read"]},"after":{"can":["read","ana@example.com"]}}`)
		c.MAC = "v1=" + strings.Repeat("0", 64)
	})
	err := c.Validate()
	if err == nil || strings.Contains(err.Error(), "ana@") || strings.Contains(err.Error(), vecSub) {
		t.Fatalf("%v", err)
	}
}
