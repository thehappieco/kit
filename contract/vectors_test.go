package contract_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
			check("document", c.Name, c.Value, c.Valid, &d)
		}
		for _, c := range w.Snapshots {
			var s contract.Snapshot
			check("snapshot", c.Name, c.Value, c.Valid, &s)
		}
		for _, c := range w.Events {
			var e contract.Event
			check("event", c.Name, c.Value, c.Valid, &e)
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

func TestEveryTokenWireVectorValidatesAsItSays(t *testing.T) {
	var w WireTokens
	read(t, "wire-tokens.json", &w)
	if w.Format != Format || w.Version != 1 || w.Kind != "wire-tokens" {
		t.Fatalf("header %q %d %q", w.Format, w.Version, w.Kind)
	}
	// What the platform sends, decoded as an app decodes it.
	for _, c := range w.Records {
		var r contract.TokenRecord
		valid := json.Unmarshal(c.Value, &r) == nil && r.Validate() == nil
		if valid != c.Valid {
			t.Errorf("record %q: valid should be %v", c.Name, c.Valid)
		}
	}
	for _, c := range w.Feeds {
		var f contract.TokenFeed
		valid := json.Unmarshal(c.Value, &f) == nil && f.Validate() == nil
		if valid != c.Valid {
			t.Errorf("feed %q: valid should be %v", c.Name, c.Valid)
		}
	}
	// What an app sends, decoded as the platform decodes it.
	for _, c := range w.Applied {
		var a contract.TokenApplied
		valid := strictDecode(c.Value, &a) == nil && a.Validate() == nil
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
	for _, want := range []string{"apply", "reset", "revoke", "narrow"} {
		if !actions[want] {
			t.Errorf("no record ends in %s", want)
		}
	}
}
