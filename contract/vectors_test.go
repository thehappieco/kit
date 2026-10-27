package contract_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/vectors"
)

// dir is where the contract's vectors are embedded (vectors.FS).
const dir = "platform/contract-v1"

func read(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := fs.ReadFile(vectors.FS, dir+"/"+name)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if dec.More() {
		t.Fatalf("%s: more than one value", name)
	}
}

func TestTheKitWritesTheContractVectorsAgain(t *testing.T) {
	files, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(vectors.FS, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(files) {
		t.Errorf("%s holds %d files, the generator writes %d", dir, len(entries), len(files))
	}
	for _, f := range files {
		have, err := fs.ReadFile(vectors.FS, dir+"/"+f.Name)
		if err != nil || !bytes.Equal(have, f.Data) {
			t.Errorf("%s/%s is missing, or this package writes other bytes: a frozen file never changes, so the package regressed", dir, f.Name)
		}
	}
}

// TestWriteTheContractVectors writes, into the directory
// KIT_CONTRACT_OUT names, each file of the generator that is not there yet,
// and leaves every file that is: a frozen file never changes, so a new
// case goes into a new file. Without KIT_CONTRACT_OUT it does nothing.
// KIT_CONTRACT_OUT=vectors/platform/contract-v1, from the repository's
// root, adds a new file; make manifest then records it.
func TestWriteTheContractVectors(t *testing.T) {
	out := os.Getenv("KIT_CONTRACT_OUT")
	if out == "" {
		t.Skip("KIT_CONTRACT_OUT is not set")
	}
	if !filepath.IsAbs(out) {
		out = filepath.Join("..", out)
	}
	files, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		path := filepath.Join(out, f.Name)
		if _, err := os.Stat(path); err == nil {
			t.Logf("kept %s", path)
			continue
		}
		if err := os.WriteFile(path, f.Data, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d bytes)", path, len(f.Data))
	}
}

func TestEverySignatureVectorHoldsFromItsOwnFields(t *testing.T) {
	var s Signatures
	read(t, "signatures.json", &s)
	if s.Label != contract.Label || s.Format != Format {
		t.Fatalf("label %q, format %q", s.Label, s.Format)
	}
	scheme := contract.Scheme()
	for _, r := range append(append([]Request{}, s.Requests...), s.Answers...) {
		if got := scheme.Canonical(r.Direction, r.App, r.Method, r.Target, r.Timestamp, r.Nonce, []byte(r.Body)); got != r.Canonical {
			t.Errorf("%s: canonical %q", r.Name, got)
		}
		if got := scheme.Signature(r.Secret, r.Direction, r.App, r.Method, r.Target, r.Timestamp, r.Nonce, []byte(r.Body)); got != r.Signature {
			t.Errorf("%s: signature %s", r.Name, got)
		}
	}
	results := map[string]bool{}
	for _, c := range s.Checks {
		h := http.Header{}
		for k, v := range c.Headers {
			h.Set(k, v)
		}
		err := contract.VerifyAnswer(h, c.Secrets, c.App, c.Method, c.Target, c.SentNonce, []byte(c.Body), Now)
		got := "ok"
		if err != nil {
			got = err.Error()
		}
		if got != c.Result {
			t.Errorf("%s: %s, want %s", c.Name, got, c.Result)
		}
		results[got] = true
	}
	for _, want := range []string{"ok", "answer_nonce", "hmac_bad", "hmac_stale", "hmac_missing"} {
		if !results[want] {
			t.Errorf("no answer check ends in %s", want)
		}
	}
	for _, c := range s.Secrets {
		if (contract.CheckSecrets(c.Current, c.Next) == nil) != c.Valid {
			t.Errorf("secret %s: valid should be %v", c.Name, c.Valid)
		}
	}
}

func TestEveryLabelAndHintVectorHolds(t *testing.T) {
	var l Labels
	read(t, "labels.json", &l)
	for _, c := range l.Clean {
		if got := contract.CleanLabel(c.Raw); got != c.Clean {
			t.Errorf("CleanLabel(%q) = %q, want %q", c.Raw, got, c.Clean)
		}
	}
	for _, c := range l.Hints {
		if contract.ValidHint(c.Hint) != c.Valid {
			t.Errorf("ValidHint(%q) should be %v", c.Hint, c.Valid)
		}
	}
}

func TestEveryWireVectorValidatesAsItSays(t *testing.T) {
	for _, file := range []string{"wire.json", "wire-item-ids.json", "wire-snapshot-tokens.json", "wire-events-stop.json"} {
		var w Wire
		read(t, file, &w)
		// Both files are of the wire's kind; the second holds snapshots only.
		if w.Format != Format || w.Version != 1 || w.Kind != "wire" {
			t.Errorf("%s: header %q %d %q", file, w.Format, w.Version, w.Kind)
		}
		if (file == "wire-item-ids.json" || file == "wire-snapshot-tokens.json") && (len(w.Documents) != 0 || len(w.Events) != 0 || len(w.Snapshots) == 0) {
			t.Errorf("%s: %d documents, %d snapshots, %d events; want snapshots only", file, len(w.Documents), len(w.Snapshots), len(w.Events))
		}
		if file == "wire-events-stop.json" && (len(w.Documents) != 0 || len(w.Snapshots) != 0 || len(w.Events) == 0) {
			t.Errorf("%s: %d documents, %d snapshots, %d events; want events only", file, len(w.Documents), len(w.Snapshots), len(w.Events))
		}
		check := func(kind, name string, raw json.RawMessage, valid bool, into interface{ Validate() error }) {
			// A value that does not decode is invalid too (a time with a comma).
			if err := json.Unmarshal(raw, into); err != nil {
				if valid {
					t.Errorf("%s: %s %q: %v", file, kind, name, err)
				}
				return
			}
			if (into.Validate() == nil) != valid {
				t.Errorf("%s: %s %q: valid should be %v", file, kind, name, valid)
			}
		}
		for _, c := range w.Documents {
			var d contract.AccountDoc
			check("document", c.Name, caseValue(c), c.Valid, &d)
		}
		for _, c := range w.Snapshots {
			var s contract.Snapshot
			check("snapshot", c.Name, caseValue(c), c.Valid, &s)
		}
		for _, c := range w.Events {
			var e contract.Event
			check("event", c.Name, caseValue(c), c.Valid, &e)
		}
	}
}

func TestEveryTokenVectorHolds(t *testing.T) {
	var f Tokens
	read(t, "tokens.json", &f)
	if f.Format != Format || f.Version != 1 || f.Kind != "tokens" || f.Label != contract.TokenHashLabel {
		t.Fatalf("header %q %d %q %q", f.Format, f.Version, f.Kind, f.Label)
	}
	hashes := map[string]int{}
	for _, c := range f.Tokens {
		p, err := contract.ParseToken(c.Token)
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		secret, err := hex.DecodeString(c.SecretHex)
		if err != nil || len(secret) != contract.TokenSecretBytes {
			t.Fatalf("%s: secret_hex", c.Name)
		}
		if p.Selector != c.Selector || p.Hash() != c.Hash || contract.TokenHash([32]byte(secret)) != c.Hash {
			t.Errorf("%s: selector %s, hash %s", c.Name, p.Selector, p.Hash())
		}
		// The hash, recomputed from its definition.
		sum := sha256.Sum256(append(append([]byte(f.Label), 0), secret...))
		if hex.EncodeToString(sum[:]) != c.Hash {
			t.Errorf("%s: the hash is not SHA-256 of the label, a zero byte and the secret", c.Name)
		}
		rec := &contract.TokenRecord{Selector: c.Selector, Hash: c.Hash}
		if err := contract.VerifyToken(rec, c.Token); err != nil {
			t.Errorf("%s: VerifyToken: %v", c.Name, err)
		}
		hashes[c.Hash]++
	}
	shared := false
	for _, n := range hashes {
		shared = shared || n > 1
	}
	if !shared {
		t.Error("no two tokens share a hash: the file shows the hash covers the secret alone")
	}
	steps := map[int]bool{}
	for _, c := range f.Refused {
		_, err := contract.ParseToken(c.Token)
		var te *contract.TokenError
		if !errors.As(err, &te) || te.Step != c.Step || !errors.Is(err, contract.ErrToken) {
			t.Errorf("%s: %v, want step %d", c.Name, err, c.Step)
		}
		if err := contract.VerifyToken(&contract.TokenRecord{Selector: f.Tokens[0].Selector, Hash: f.Tokens[0].Hash}, c.Token); !errors.Is(err, contract.ErrToken) {
			t.Errorf("%s: VerifyToken took it", c.Name)
		}
		steps[c.Step] = true
	}
	for step := 1; step <= 6; step++ {
		if !steps[step] {
			t.Errorf("no refused token stops at step %d", step)
		}
	}
	for _, c := range f.Headers {
		tok, err := contract.BearerToken(c.Values)
		if (err == nil) != c.Valid {
			t.Errorf("header %s: %v, valid should be %v", c.Name, err, c.Valid)
		}
		if err == nil {
			if _, err := contract.ParseToken(tok); err != nil {
				t.Errorf("header %s: its token does not parse", c.Name)
			}
		} else if !errors.Is(err, contract.ErrToken) {
			t.Errorf("header %s: %v does not match ErrToken", c.Name, err)
		}
	}
}

func TestEveryReadingKeyVectorHolds(t *testing.T) {
	var f ReadingKeys
	read(t, "reading-keys.json", &f)
	if f.Format != Format || f.Version != 1 || f.Kind != "reading-keys" || f.Label != contract.ReadingKeyLabel {
		t.Fatalf("header %q %d %q %q", f.Format, f.Version, f.Kind, f.Label)
	}
	results := map[string]bool{}
	for _, c := range f.Keys {
		got := keyResult(contract.CheckReadingKey(c.Key, c.Fingerprint))
		if got != c.Result {
			t.Errorf("%s: %s, want %s", c.Name, got, c.Result)
		}
		results[got] = true
		fp, err := contract.ReadingKeyFingerprint(c.Key)
		switch {
		case c.Result == "encoding":
			if !errors.Is(err, contract.ErrReadingKeyEncoding) || c.Fingerprint != "" {
				t.Errorf("%s: a key that does not decode has a fingerprint", c.Name)
			}
		case c.Result == "fingerprint":
			if err != nil || fp == c.Fingerprint {
				t.Errorf("%s: the fingerprint is its key's", c.Name)
			}
		default:
			if err != nil || fp != c.Fingerprint {
				t.Errorf("%s: fingerprint %s, want %s", c.Name, fp, c.Fingerprint)
			}
			if (contract.ValidReadingKey(c.Key) == nil) != (c.Result == "ok") {
				t.Errorf("%s: ValidReadingKey disagrees", c.Name)
			}
		}
	}
	for _, want := range []string{"ok", "encoding", "not_canonical", "low_order", "fingerprint"} {
		if !results[want] {
			t.Errorf("no reading key ends in %s", want)
		}
	}
}

// A big value of the token part's files, and of the settings part's, is
// written compact, on one line, and none is left a placeholder.
func TestEveryBigValueIsWrittenCompact(t *testing.T) {
	for _, file := range []string{"tokens.json", "reading-keys.json", "wire-tokens.json", "wire-snapshot-tokens.json", "wire-events-stop.json",
		"wire-settings.json", "wire-commands.json", "command-macs.json"} {
		raw, err := fs.ReadFile(vectors.FS, dir+"/"+file)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte("big:")) {
			t.Errorf("%s holds a placeholder", file)
		}
		for _, line := range bytes.Split(raw, []byte("\n")) {
			if len(line) > BigValue && !bytes.Contains(line, []byte(`"value": {`)) && !bytes.Contains(line, []byte(`"body": "`)) {
				t.Errorf("%s: a long line that is no value", file)
			}
		}
	}
}

func TestEveryTokenWireVectorValidatesAsItSays(t *testing.T) {
	var w WireTokens
	read(t, "wire-tokens.json", &w)
	if w.Format != Format || w.Version != 1 || w.Kind != "wire-tokens" {
		t.Fatalf("header %q %d %q", w.Format, w.Version, w.Kind)
	}
	// What the platform sends, decoded as an app decodes it.
	for _, c := range w.Records {
		var r contract.TokenRecord
		valid := json.Unmarshal(caseValue(c), &r) == nil && r.Validate() == nil
		if valid != c.Valid {
			t.Errorf("record %q: valid should be %v", c.Name, c.Valid)
		}
	}
	for _, c := range w.Feeds {
		var f contract.TokenFeed
		valid := json.Unmarshal(caseValue(c), &f) == nil && f.Validate() == nil
		if valid != c.Valid {
			t.Errorf("feed %q: valid should be %v", c.Name, c.Valid)
		}
	}
	// What an app sends, decoded as the platform decodes it.
	for _, c := range w.Applied {
		var a contract.TokenApplied
		valid := strictDecode(caseValue(c), &a) == nil && a.Validate() == nil
		if valid != c.Valid {
			t.Errorf("acknowledgement %q: valid should be %v", c.Name, c.Valid)
		}
	}
	for _, c := range w.Usage {
		if usageValid([]byte(c.Body)) != c.Valid {
			t.Errorf("usage %q: valid should be %v", c.Name, c.Valid)
		}
	}
	actions := map[string]bool{}
	for _, c := range w.Actions {
		action, code := recordAction(c.App, c.Generation, c.Value)
		if action != c.Action || (code == nil) != (c.Code == nil) || (code != nil && *code != *c.Code) {
			t.Errorf("action %q: %s %v, want %s %v", c.Name, action, code, c.Action, c.Code)
		}
		actions[action] = true
	}
	for _, want := range []string{"apply", "reset", "revoke", "narrow", "refuse"} {
		if !actions[want] {
			t.Errorf("no record ends in %s", want)
		}
	}
}

// settingsFile is wire-settings.json.
func settingsFile(t *testing.T) WireSettings {
	t.Helper()
	var w WireSettings
	read(t, "wire-settings.json", &w)
	if w.Format != Format || w.Version != 1 || w.Kind != "wire-settings" {
		t.Fatalf("header %q %d %q", w.Format, w.Version, w.Kind)
	}
	return w
}

func TestEverySettingsVectorValidatesAsItSays(t *testing.T) {
	w := settingsFile(t)
	for _, c := range w.Sections {
		if sectionValid(c.Value) != c.Valid {
			t.Errorf("section %q: valid should be %v", c.Name, c.Valid)
		}
		if c.Valid && len(c.Value) > contract.SettingsBodyLimit {
			t.Errorf("section %q is over its call's limit", c.Name)
		}
	}
	for _, c := range w.Persons {
		if personValid(c.Value) != c.Valid {
			t.Errorf("person %q: valid should be %v", c.Name, c.Valid)
		}
		if c.Valid && len(c.Value) > contract.PersonSettingsBodyLimit {
			t.Errorf("person %q is over its call's limit", c.Name)
		}
	}
}

// Every code of every closed list of the settings part is in a valid case,
// at the member's full path in its section (a notice's params under its
// code), and every section of both apps: dropping a code from the
// validator, or from the cases, fails this test.
func TestEveryClosedCodeOfTheSettingsPartIsInAValidCase(t *testing.T) {
	w := settingsFile(t)
	// seen holds section:path=value for every string and number of a
	// valid case's data, the path the members' names joined by dots, []
	// for a list's entries, and a notice's params as params(<code>).
	seen := map[string]bool{}
	var walk func(v any, path string)
	walk = func(v any, path string) {
		switch v := v.(type) {
		case string, json.Number:
			seen[fmt.Sprintf("%s=%v", path, v)] = true
		case []any:
			for _, e := range v {
				walk(e, path+"[]")
			}
		case map[string]any:
			for k, e := range v {
				name := k
				if c, ok := v["code"].(string); ok && k == "params" {
					name = "params(" + c + ")"
				}
				walk(e, path+"."+name)
			}
		}
	}
	sections := map[string]bool{}
	for _, list := range [][]WireCase{w.Sections, w.Persons} {
		for _, c := range list {
			if !c.Valid {
				continue
			}
			var doc struct {
				App     string          `json:"app"`
				Section string          `json:"section"`
				Data    json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal(c.Value, &doc); err != nil {
				t.Fatal(err)
			}
			section := doc.Section
			if section == "" {
				section = doc.App + "-person"
			}
			sections[doc.App+"/"+doc.Section] = true
			dec := json.NewDecoder(bytes.NewReader(doc.Data))
			dec.UseNumber()
			var data any
			if err := dec.Decode(&data); err != nil {
				t.Fatal(err)
			}
			walk(data, section+":")
		}
	}
	for _, app := range []string{"wappie", "mailie"} {
		for _, s := range append(contract.Sections(app), "") {
			if !sections[app+"/"+s] {
				t.Errorf("no valid case of %s's section %q", app, s)
			}
		}
	}
	people := []string{"person", "service_account", "assistant", "ai", "legacy_key", "token"}
	for path, codes := range map[string][]string{
		"numbers:.items[].connection":                                     {"pairing", "online", "offline", "logged_out_phone", "logged_out_deletion", "banned"},
		"numbers:.items[].capture":                                        {"on", "paused"},
		"numbers:.items[].paused_by.kind":                                 {"person", "key", "app"},
		"numbers:.items[].move_out.holders[].kind":                        people,
		"integrations:.server_off.functions[]":                            contract.AIFunctions(),
		"integrations:.server_off.providers[]":                            contract.AIProviders(),
		"integrations:.provider_keys[].provider":                          contract.AIProviders(),
		"integrations:.integrations[].status":                             {"pending", "active", "paused", "reseal", "ended"},
		"integrations:.integrations[].functions[].id":                     contract.AIFunctions(),
		"integrations:.integrations[].functions[].provider":               contract.AIProviders(),
		"integrations:.integrations[].cap.period":                         {"month"},
		"integrations:.integrations[].alerts[].code":                      contract.AIAlerts(),
		"integrations:.integrations[].alerts[].function":                  contract.AIFunctions(),
		"integrations:.integrations[].alerts[].provider":                  contract.AIProviders(),
		"integrations:.integrations[].end_reason":                         contract.EndReasons(),
		"mcp:.switches[].switch":                                          {"text", "attachments", "drafts", "ai"},
		"mcp:.switches[].operator":                                        {"allow", "deny"},
		"mcp:.server_allows[]":                                            contract.ServerAllows(),
		"mcp:.connections[].kind":                                         {"metadata", "content"},
		"mcp:.connections[].status":                                       {"pending", "active", "reseal", "revoked", "expired"},
		"mcp:.connections[].tier":                                         {"web_tested", "local_tested", "unknown", "token"},
		"mcp:.connections[].consent.send":                                 {"off", "draft", "direct"},
		"mcp:.connections[].history_days":                                 {"7", "30", "90"},
		"mcp:.connections[].budget_hits[].code":                           contract.BudgetHits(),
		"mcp:.connections[].end_reason":                                   contract.EndReasons(),
		"installations:.bindings[].state":                                 {"reserved", "active"},
		"email-accounts:.availability":                                    {"usable", "withheld", "closed"},
		"email-accounts:.link_min_role":                                   {"owner", "admin", "member"},
		"email-accounts:.items[].provider":                                {"google", "microsoft", "icloud", "imap"},
		"email-accounts:.items[].sign_in":                                 {"oauth", "password"},
		"email-accounts:.items[].status":                                  {"connected", "needs_reauth", "pending_auth", "error", "removed"},
		"email-accounts:.items[].reason":                                  {"scope_missing", "mailbox_refused", "token_rejected", "unproved", "other"},
		"email-accounts:.items[].sync.mode":                               {"team", "personal"},
		"email-accounts:.items[].sync.paused.kind":                        {"person"},
		"email-accounts:.items[].sync.indexed":                            {"none", "partial", "complete"},
		"permissions:.members[].status":                                   {"active", "suspended", "held", "disabled"},
		"wappie-person:.notices[].code":                                   contract.NoticeCodes("wappie"),
		"wappie-person:.notices[].params(sync_paused).actor_kind":         {"person", "key"},
		"mailie-person:.notices[].code":                                   contract.NoticeCodes("mailie"),
		"mailie-person:.notices[].params(mailbox_removed).state":          {"removed", "deleted"},
		"mailie-person:.notices[].params(mailbox_sync_off).state":         {"live", "removed", "deleted"},
		"mailie-person:.notices[].params(mailbox_sync_off).actor_kind":    {"person"},
		"mailie-person:.notices[].params(mailbox_sync_paused).state":      {"live"},
		"mailie-person:.notices[].params(mailbox_sync_paused).actor_kind": {"person"},
		"mailie-person:.consents[].consent":                               {"sync", "actions", "send"},
		"mailie-person:.consents[].state":                                 {"on", "off", "old_text"},
	} {
		for _, code := range codes {
			if !seen[path+"="+code] {
				t.Errorf("no valid case holds %s %s", path, code)
			}
		}
	}
}

func TestEveryCommandVectorHolds(t *testing.T) {
	var w WireCommands
	read(t, "wire-commands.json", &w)
	if w.Format != Format || w.Version != 1 || w.Kind != "wire-commands" {
		t.Fatalf("header %q %d %q", w.Format, w.Version, w.Kind)
	}
	kinds := map[string]bool{}
	for _, c := range w.Commands {
		if commandValid(c.App, c.WorkspaceKind, c.Value) != c.Valid {
			t.Errorf("command %q: valid should be %v", c.Name, c.Valid)
		}
		cmd, err := contract.VerifyCommand(c.Value, c.App, []string{SecretA})
		if err != nil {
			t.Errorf("command %q is not signed with SecretA for %s", c.Name, c.App)
		}
		if c.Valid {
			kinds[c.App+" "+cmd.Kind] = true
		}
	}
	for _, app := range []string{"wappie", "mailie"} {
		for _, k := range contract.CommandKinds(app) {
			if !kinds[app+" "+k.Kind] {
				t.Errorf("no valid command of %s's %s", app, k.Kind)
			}
		}
	}
	for _, c := range w.Feeds {
		if feedValid(caseValue(c)) != c.Valid {
			t.Errorf("feed %q: valid should be %v", c.Name, c.Valid)
		}
	}
	actions := map[string]bool{}
	for _, a := range w.Actions {
		if got := commandAction(a); got != a.Action {
			t.Errorf("action %q: %s, want %s", a.Name, got, a.Action)
		}
		actions[a.Action] = true
	}
	for _, want := range []string{"run", "reset", "expired", "invalid_command"} {
		if !actions[want] {
			t.Errorf("no command ends in %s", want)
		}
	}
	for _, c := range w.Results {
		if resultValid(c.App, c.Kind, c.Value) != c.Valid {
			t.Errorf("result %q: valid should be %v", c.Name, c.Valid)
		}
	}
	for _, c := range w.Batches {
		if batchValid([]byte(c.Body)) != c.Valid {
			t.Errorf("batch %q: valid should be %v", c.Name, c.Valid)
		}
	}
	codes := map[string]int{}
	for _, c := range w.Classes {
		if got := contract.CommandRefusalClass(c.Code, c.Tightening); got != c.Class || got == "" {
			t.Errorf("class of %s (tightening %v): %q, want %q", c.Code, c.Tightening, got, c.Class)
		}
		codes[c.Code]++
	}
	for _, code := range contract.CommandRefusalCodes() {
		if codes[code] != 2 {
			t.Errorf("%s has %d classes, want one per kind that tightens or not", code, codes[code])
		}
	}
}

func TestEveryCommandMACVectorHolds(t *testing.T) {
	var f CommandMACs
	read(t, "command-macs.json", &f)
	if f.Format != Format || f.Version != 1 || f.Kind != "command-macs" || f.Label != contract.CommandMACLabel {
		t.Fatalf("header %q %d %q %q", f.Format, f.Version, f.Kind, f.Label)
	}
	pass, fail := 0, 0
	for _, c := range f.MACs {
		if c.JCS != "" {
			if got, err := canonicalOf([]byte(c.Command)); err != nil || got != c.JCS {
				t.Errorf("%q: the canonical text is not the file's", c.Name)
			}
			if macOver([]byte(c.Secrets[0]), c.App, []byte(c.JCS)) != c.MAC {
				t.Errorf("%q: the MAC is not the file's", c.Name)
			}
		} else if c.MAC != "" || c.Valid {
			t.Errorf("%q: a command with no canonical text has no MAC, and never verifies", c.Name)
		}
		_, err := contract.VerifyCommand([]byte(c.Command), c.App, c.Secrets)
		if (err == nil) != c.Valid {
			t.Errorf("%q: verifies %v, want %v (%v)", c.Name, err == nil, c.Valid, err)
		}
		if !c.Valid {
			fail++
			continue
		}
		pass++
		// A command that verifies was signed under one of the secrets, and
		// SignCommand under that secret writes the same mac.
		carried := must(macOf([]byte(c.Command)))
		signedBy := ""
		for _, s := range c.Secrets {
			if macOver([]byte(s), c.App, []byte(c.JCS)) == carried {
				signedBy = s
			}
		}
		again, err := contract.SignCommand([]byte(c.Command), c.App, signedBy)
		if err != nil || must(macOf(again)) != carried {
			t.Errorf("%q: SignCommand does not write the mac it carries", c.Name)
		}
	}
	if pass == 0 || fail == 0 {
		t.Errorf("%d commands verify and %d do not; want both", pass, fail)
	}
}
