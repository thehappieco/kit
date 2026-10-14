package contracttest_test

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"
)

// The platform bounds a feed page by the length of each document's text as
// Postgres returns its jsonb column (internal/console's contractFeed, whose
// test sizes the bound with octet_length(doc::text)), not by the
// json.Marshal it stored, and the fake counts the same.
func TestAStoredDocumentIsCountedAsPostgresWritesIt(t *testing.T) {
	name := "Tom & Jerry < >\t\"\\ São\x01\xff"
	owners := 2
	doc := contract.AccountDoc{
		V: contract.DocV, Type: contract.DocType, App: "wappie", Sub: anaSub, Version: 7, Status: contract.AccountActive,
		Workspaces: []contract.Workspace{{
			ID: "0199a0c2-0000-7000-8000-0000000000aa", Kind: contract.KindTeam, Name: &name,
			Role: contract.RoleOwner, Status: contract.StatusOpen, WVersion: 3, Owners: &owners,
		}},
	}
	// Postgres's text of it: ", " and ": ", the keys shorter first, and
	// only '"', '\' and the control characters escaped, so '&', '<', '>',
	// U+2028 and the U+FFFD of the byte that is not UTF-8 come as
	// themselves, where json.Marshal escapes them.
	want := `{"v": 1, "app": "wappie", "sub": "0199a0c2-0000-7000-8000-000000000001", "type": "account", "status": "active", ` +
		`"version": 7, "generation": "", "workspaces": [{"id": "0199a0c2-0000-7000-8000-0000000000aa", "kind": "team", ` +
		`"name": "Tom & Jerry <` + " " + `>\t\"\\ S` + "ã" + `o\u0001` + "�" + `", "role": "owner", ` +
		`"owners": 2, "status": "open", "wversion": 3}], "disabled_at": null, "sessions_revoked_at": null, ` +
		`"credentials_revoked_at": null}`
	if got := jsonbText(t, doc); got != want {
		t.Fatalf("the model of Postgres's text:\n got %s\nwant %s", got, want)
	}
	if got := contracttest.StoredLen(doc); got != len(want) {
		t.Fatalf("StoredLen = %d, want %d", got, len(want))
	}

	// And every document the fake publishes, a team's name with an '&'.
	p, c := start(t, contracttest.Options{})
	ctx := t.Context()
	for _, sub := range []string{anaSub, bobSub} {
		if _, err := p.AddAccount(sub); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Subscribe(ctx, sub); err != nil {
			t.Fatal(err)
		}
	}
	team, err := p.AddTeam("Ana & Bob <Loja>", anaSub)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.SetRole(team, bobSub, contract.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	f, err := c.Feed(ctx, 0, 0)
	if err != nil || len(f.Items) != 2 {
		t.Fatalf("the feed: %+v %v", f, err)
	}
	for _, it := range f.Items {
		it.Doc.Generation = ""
		text := jsonbText(t, it.Doc)
		if got := contracttest.StoredLen(it.Doc); got != len(text) {
			t.Errorf("StoredLen of %s = %d, want %d", it.Doc.Sub, got, len(text))
		}
		if compact, _ := json.Marshal(it.Doc); len(compact) >= len(text) {
			t.Errorf("%s: compact JSON %d bytes, Postgres's text %d", it.Doc.Sub, len(compact), len(text))
		}
	}
}

// jsonbText writes d as Postgres writes a jsonb value as text (jsonb_out):
// the value json.Marshal stores, read back, with ", " between members and
// ": " after a key, an object's keys shorter first and then in byte order,
// and in strings only '"', '\' and the control characters escaped.
func jsonbText(t *testing.T, d contract.AccountDoc) string {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	var text func(v any) string
	text = func(v any) string {
		switch x := v.(type) {
		case map[string]any:
			keys := slices.SortedFunc(maps.Keys(x), func(a, b string) int {
				return cmp.Or(cmp.Compare(len(a), len(b)), strings.Compare(a, b))
			})
			var members []string
			for _, k := range keys {
				members = append(members, jsonbString(k)+": "+text(x[k]))
			}
			return "{" + strings.Join(members, ", ") + "}"
		case []any:
			var values []string
			for _, e := range x {
				values = append(values, text(e))
			}
			return "[" + strings.Join(values, ", ") + "]"
		case string:
			return jsonbString(x)
		case json.Number:
			return x.String()
		case bool:
			return strconv.FormatBool(x)
		case nil:
			return "null"
		}
		t.Fatalf("a value of type %T", v)
		return ""
	}
	return text(v)
}

// jsonbString is Postgres's escape_json.
func jsonbString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			if c < ' ' {
				fmt.Fprintf(&b, `\u%04x`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
