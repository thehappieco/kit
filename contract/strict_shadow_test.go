package contract

import (
	"errors"
	"testing"
)

type shadowInnerRow struct {
	A int `json:"a"`
}

type shadowOuterRow struct {
	B string `json:"b"`
}

type shadowInner struct {
	Items []shadowInnerRow `json:"items"`
	Note  string           `json:"note"`
}

// shadowFirst declares its own items before the embedded struct that also
// names items, as Mailie's probe of 2026-11-26 did; shadowLast after it, as
// the platform's console does. encoding/json reads both alike: the shallower
// member wins whatever the order.
type shadowFirst struct {
	Items []shadowOuterRow `json:"items"`
	shadowInner
}

type shadowLast struct {
	shadowInner
	Items []shadowOuterRow `json:"items"`
}

// ShadowGroup is exported only because encoding/json cannot set an
// embedded pointer to an unexported struct.
type ShadowGroup struct {
	Items []shadowInnerRow `json:"items"`
	Note  string           `json:"note"`
}

type shadowPtrFirst struct {
	Items []shadowOuterRow `json:"items"`
	*ShadowGroup
}

func TestTheStrictReadingLetsTheShallowerMemberWinWhateverTheDeclarationOrder(t *testing.T) {
	body := []byte(`{"items":[{"b":"x"}],"note":"n"}`)
	var first shadowFirst
	if err := DecodeStrict(body, &first); err != nil || len(first.Items) != 1 || first.Items[0].B != "x" || first.Note != "n" {
		t.Errorf("own member first: DecodeStrict gave %+v, %v", first, err)
	}
	var last shadowLast
	if err := DecodeStrict(body, &last); err != nil || len(last.Items) != 1 || last.Items[0].B != "x" || last.Note != "n" {
		t.Errorf("own member last: DecodeStrict gave %+v, %v", last, err)
	}
	// The shadowed member's shape is never the one checked.
	for _, v := range []any{&shadowFirst{}, &shadowLast{}} {
		if err := DecodeStrict([]byte(`{"items":[{"a":1}],"note":"n"}`), v); !errors.Is(err, ErrInvalid) {
			t.Errorf("%T: the shadowed member's shape passed: %v", v, err)
		}
	}
}

func TestTheStrictReadingShadowsAnEmbeddedPointersMemberWithoutRequiringItsGroup(t *testing.T) {
	// items is the outer struct's own; note alone is the pointer's group,
	// absent whole or present whole.
	var v shadowPtrFirst
	if err := DecodeStrict([]byte(`{"items":[{"b":"x"}]}`), &v); err != nil || v.ShadowGroup != nil {
		t.Errorf("DecodeStrict refused or misread the outer member alone: %+v, %v", v, err)
	}
	var w shadowPtrFirst
	if err := DecodeStrict([]byte(`{"items":[{"b":"x"}],"note":"n"}`), &w); err != nil || w.ShadowGroup == nil || w.Note != "n" || w.Items[0].B != "x" {
		t.Errorf("DecodeStrict refused or misread the group present whole: %+v, %v", w, err)
	}
}
