package contract_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net/http"
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
	for _, file := range []string{"wire.json", "wire-item-ids.json"} {
		var w Wire
		read(t, file, &w)
		// Both files are of the wire's kind; the second holds snapshots only.
		if w.Format != Format || w.Version != 1 || w.Kind != "wire" {
			t.Errorf("%s: header %q %d %q", file, w.Format, w.Version, w.Kind)
		}
		if file == "wire-item-ids.json" && (len(w.Documents) != 0 || len(w.Events) != 0 || len(w.Snapshots) == 0) {
			t.Errorf("%s: %d documents, %d snapshots, %d events; want snapshots only", file, len(w.Documents), len(w.Snapshots), len(w.Events))
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
