package oidcrp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"testing"
	"unicode/utf8"
)

// FuzzReadUserinfo: no input panics; a refusal is ErrUserinfo; whatever is
// accepted is valid UTF-8 and one JSON object that encoding/json reads too,
// with nothing after it, and the known members are the values encoding/json
// reads under their exact names.
func FuzzReadUserinfo(f *testing.F) {
	for _, s := range []string{
		`{"sub":"01999999-aaaa-7bbb-8ccc-0123456789ab","client_id":"wappie-app","auth_time":1790000000,"amr":["pwd"],` +
			`"email":"a@b.c","email_verified":true,"locale":"pt-BR","name":"Ana","product_key":"x","product_key_id":"wappie:1"}`,
		`{"sub":"a","sub":"b"}`, `{"Sub":"a"}`, `{"sub":"a"}`, `{"x":{"y":[1,{},null]}}`, `{} {}`, `[]`, `null`, ``,
		`{"auth_time":1e3}`, `{"auth_time":-0}`, `{"amr":[]}`, `{"amr":[1]}`, "{\"name\":\"\xff\"}", `{"email_verified":null}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		u, err := readUserinfo(body)
		if err != nil {
			if !errors.Is(err, ErrUserinfo) {
				t.Fatalf("unclassified error: %v", err)
			}
			return
		}
		if !utf8.Valid(body) {
			t.Fatal("accepted invalid UTF-8")
		}
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		var m map[string]any
		if err := dec.Decode(&m); err != nil || m == nil {
			t.Fatalf("accepted what encoding/json does not read as an object: %v", err)
		}
		if _, err := dec.Token(); !errors.Is(err, io.EOF) {
			t.Fatal("accepted something after the object")
		}
		str := func(name, got string) {
			v, ok := m[name]
			if want, _ := v.(string); (ok && want != got) || (!ok && got != "") {
				t.Fatalf("%s is not the value encoding/json reads", name)
			}
		}
		str("sub", u.Sub)
		str("client_id", u.ClientID)
		str("email", u.Email)
		str("locale", u.Locale)
		str("name", u.Name)
		str("product_key", u.ProductKey)
		str("product_key_id", u.ProductKeyID)
		if v, ok := m["auth_time"]; ok {
			n, isNumber := v.(json.Number)
			if !isNumber {
				t.Fatal("auth_time is not a number to encoding/json")
			}
			if i, err := n.Int64(); err != nil || i != u.AuthTime {
				t.Fatal("auth_time is not the value encoding/json reads")
			}
		}
		if v, ok := m["email_verified"]; ok {
			if b, isBool := v.(bool); !isBool || b != u.EmailVerified {
				t.Fatal("email_verified is not the value encoding/json reads")
			}
		}
		if v, ok := m["amr"]; ok {
			list, isList := v.([]any)
			if !isList {
				t.Fatal("amr is not an array to encoding/json")
			}
			got := make([]any, len(u.AMR))
			for i, s := range u.AMR {
				got[i] = s
			}
			if !slices.Equal(list, got) {
				t.Fatal("amr is not the value encoding/json reads")
			}
		}
	})
}
