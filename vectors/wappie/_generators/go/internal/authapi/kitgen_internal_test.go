// Vector generator for github.com/thehappieco/kit, vectors/wappie/golden/passkey-salt-go.json.
//
// This file is not part of Wappie. vectors/wappie/_generators/run.sh copies it
// into a throwaway extraction of Wappie at a recorded commit and runs it there.
// The PRF evaluation salt is computed inside NewPasskeyProvider; this reads it
// back from the provider, so the value is the server's and not a restatement.

package authapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"whatserver2/internal/config"
)

func TestKitGenPasskeySalt(t *testing.T) {
	dir := os.Getenv("KITGEN_OUT")
	if dir == "" {
		t.Skip("KITGEN_OUT is not set; this generator runs only from the kit's run.sh")
	}
	type kgCase struct {
		ID  string         `json:"id"`
		Op  string         `json:"op"`
		In  map[string]any `json:"in"`
		Out map[string]any `json:"out"`
	}
	var cases []kgCase
	for _, c := range []struct{ rpID, origin string }{
		{"wappie.thehappie.co", "https://app.wappie.thehappie.co"},
		{"app.wappie.thehappie.co", "https://app.wappie.thehappie.co"},
		{"localhost", "http://localhost:5173"},
		{"example.com", "https://example.com"},
		{"xn--bcher-kva.example.com", "https://xn--bcher-kva.example.com"},
	} {
		p, err := NewPasskeyProvider(config.Passkeys{RPID: c.rpID, Origins: []string{c.origin}})
		if err != nil || p == nil {
			t.Fatalf("%s: %v", c.rpID, err)
		}
		cases = append(cases, kgCase{ID: "passkey/prf-salt/" + c.rpID, Op: "passkey.prf_salt",
			In: map[string]any{"rp_id": c.rpID}, Out: map[string]any{"salt_b64": base64.StdEncoding.EncodeToString(p.salt)}})
	}
	f := map[string]any{
		"format":  "thehappieco-kit-vectors/1",
		"module":  "passkey",
		"profile": "wappie",
		"generated_by": map[string]any{
			"lang":       "go",
			"source":     "github.com/thehappieco/wappie@" + os.Getenv("KITGEN_COMMIT") + " internal/authapi/passkeys.go",
			"toolchain":  runtime.Version(),
			"randomness": "none",
			"generator":  "vectors/wappie/_generators/go/internal/authapi/kitgen_internal_test.go",
		},
		"note":  "The public PRF evaluation salt Wappie's server hands to WebAuthn, one per RP ID.",
		"cases": cases,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		t.Fatal(err)
	}
	fh, err := os.OpenFile(filepath.Join(dir, "passkey-salt-go.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatalf("refusing to overwrite a vector file: %v", err)
	}
	defer fh.Close()
	if _, err := fh.Write(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
}
