package kms_test

import (
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/thehappieco/kit/kms"
)

func valid() kms.Context {
	return kms.Context{Service: "platform", Env: "test", Purpose: "config/stripe-secret-key", Ref: "stripe-secret-key"}
}

func TestAContextWithEveryFieldInTheVocabularyIsValid(t *testing.T) {
	for _, ec := range []kms.Context{
		valid(),
		{Service: "platform", Env: "prod", Purpose: "backup", Ref: "20261001t0600z"},
		{Service: "platform", Env: "dev", Purpose: "serverkey/oidc-signing", Ref: "kid_01:a.b-c"},
		{Service: "mailie", Env: "prod", Purpose: "credentials"},
		{Service: "a", Env: "b", Purpose: strings.Repeat("p", kms.MaxFieldLen), Ref: strings.Repeat("r", kms.MaxFieldLen)},
	} {
		if err := ec.Validate(); err != nil {
			t.Errorf("%+v: %v", ec, err)
		}
	}
}

func TestAContextOutsideTheVocabularyIsRefused(t *testing.T) {
	cases := []struct {
		name string
		edit func(*kms.Context)
	}{
		{"empty service", func(c *kms.Context) { c.Service = "" }},
		{"empty env", func(c *kms.Context) { c.Env = "" }},
		{"empty purpose", func(c *kms.Context) { c.Purpose = "" }},
		{"uppercase", func(c *kms.Context) { c.Env = "Prod" }},
		{"space", func(c *kms.Context) { c.Purpose = "config/stripe key" }},
		{"newline", func(c *kms.Context) { c.Ref = "a\nb" }},
		{"at sign, as in an email address", func(c *kms.Context) { c.Ref = "someone@example.com" }},
		{"non-ascii", func(c *kms.Context) { c.Ref = "café" }},
		{"nul", func(c *kms.Context) { c.Service = "plat\x00form" }},
		{"too long", func(c *kms.Context) { c.Ref = strings.Repeat("r", kms.MaxFieldLen+1) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ec := valid()
			tc.edit(&ec)
			if err := ec.Validate(); !errors.Is(err, kms.ErrInvalidContext) {
				t.Fatalf("want ErrInvalidContext, got %v", err)
			}
		})
	}
}

func TestARefusedContextIsNotEchoedInTheError(t *testing.T) {
	ec := valid()
	ec.Ref = "someone@example.com"
	err := ec.Validate()
	if err == nil || strings.Contains(err.Error(), "someone") {
		t.Fatalf("the error must name the field, not repeat its value: %v", err)
	}
}

func TestTheKMSContextCarriesExactlyTheFourFields(t *testing.T) {
	got := valid().Map()
	want := map[string]string{
		"service": "platform", "env": "test", "purpose": "config/stripe-secret-key", "ref": "stripe-secret-key",
	}
	if !maps.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestAnEmptyRefIsLeftOutOfTheKMSContext(t *testing.T) {
	ec := valid()
	ec.Ref = ""
	got := ec.Map()
	if _, ok := got["ref"]; ok || len(got) != 3 {
		t.Fatalf("an empty ref must not be sent: %v", got)
	}
}
