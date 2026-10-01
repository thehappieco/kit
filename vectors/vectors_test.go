package vectors_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/thehappieco/kit/vectors"
)

// Every file in the tree is in MANIFEST.sha256 with its hash, and every line
// of the manifest names a file that is there. The embedded files are checked
// through FS, the generators (which are not embedded) from the directory.
func TestManifest(t *testing.T) {
	raw, err := fs.ReadFile(vectors.FS, "MANIFEST.sha256")
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		sum, name, ok := strings.Cut(sc.Text(), "  ")
		if !ok || len(sum) != 64 {
			t.Fatalf("malformed manifest line %q", sc.Text())
		}
		listed[name] = sum
	}
	for name, want := range listed {
		var data []byte
		if strings.Contains(name, "/_generators/") {
			data, err = os.ReadFile(name)
		} else {
			data, err = fs.ReadFile(vectors.FS, name)
		}
		if err != nil {
			t.Errorf("%s is listed and missing: %v", name, err)
			continue
		}
		if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != want {
			t.Errorf("%s does not match its manifest hash", name)
		}
	}
	for _, root := range []string{"wappie", "kit", "platform"} {
		if err := fs.WalkDir(os.DirFS("."), root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if _, ok := listed[path]; !ok {
				t.Errorf("%s is not in MANIFEST.sha256", path)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, generator := range []string{"wappie/_generators/run.sh", "platform/_generators/tools/vectors/main.go"} {
		if _, err := fs.Stat(vectors.FS, generator); err == nil {
			t.Errorf("the generators are embedded: %s", generator)
		}
	}
}

// Every case SPEC.md cites as `file#case-id` exists: a bare file name is
// under wappie/golden/, and an id ending in * names at least one case. The
// platform's files name their cases instead (`platform/id-v1/kdf.json#the
// floor parameters`).
func TestSpecCitations(t *testing.T) {
	spec, err := os.ReadFile("../SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	cite := regexp.MustCompile("`((?:kit/|wappie/golden/|platform/id-v1/)?[a-z0-9-]+\\.json)#([^`]+)`")
	matches := cite.FindAllStringSubmatch(string(spec), -1)
	if len(matches) < 10 {
		t.Fatalf("only %d citations found", len(matches))
	}
	for _, m := range matches {
		file, id := m[1], m[2]
		if !strings.Contains(file, "/") {
			file = "wappie/golden/" + file
		}
		raw, err := fs.ReadFile(vectors.FS, file)
		if err != nil {
			t.Errorf("%s: %v", m[0], err)
			continue
		}
		var f struct {
			Cases []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"cases"`
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, c := range f.Cases {
			if strings.HasPrefix(file, "platform/") {
				c.ID = c.Name
			}
			if c.ID == id || (strings.HasSuffix(id, "*") && strings.HasPrefix(c.ID, strings.TrimSuffix(id, "*"))) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("SPEC.md cites %s, which is not a case", m[0])
		}
	}
}

// The platform's id-v1 files are the ones captured at platform commit 5e66d84
// (PROVENANCE.md): each has the sha256 recorded there, so a copy from a later
// platform commit or an edit fails here even after `make manifest` has
// recorded it, and no tag can freeze other bytes as these. Then their header,
// ASCII only with exactly one final newline, unique case names, and the
// number of cases and of must-fail cases per kind.
func TestPlatformVectorFiles(t *testing.T) {
	want := []struct {
		kind            string
		cases, mustFail int
		sha256          string
	}{
		{"password-profile", 45, 23, "47803646a66f8a20c5cdb02852b628a5716d1dc4854759367f7f10dba3c5294e"},
		{"kdf", 19, 16, "89b6ffe8d32a65b7c63c88763d3aab5da3f9cf064e548d8cd6abba51df7d7483"},
		{"root-wrap", 31, 26, "54aa88e9e89f143031b4acdc11ab01b31497c3d3a4ef3783ce121ba224733ee1"},
		{"recovery-code", 27, 15, "c3c57217d0a491d84f374c95ff83c5c974126884d741501fef70969ec1ab19fa"},
		{"product-key", 20, 12, "388cae00f034bef42f75e74a4a52f27ff7ff7409ed48b67ba3bc338326cb5601"},
		{"verifier", 10, 5, "394e2bf399bd1a6a23b00e067d71a2f6da70cb2c69a5a2a542efd61322f5a5e4"},
		{"email", 46, 33, "a0cffa73f07782d4feca2c3dea293f3e8de75164b3ee043106b0d6b0b3e0575d"},
		{"key-bundle", 59, 50, "364b4c24046ca70b04dbbc04ead6417445f1aa8bede2c930068cbd1adfc61a6e"},
	}
	entries, err := fs.ReadDir(vectors.FS, "platform/id-v1")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(want) {
		t.Errorf("platform/id-v1 holds %d files, want %d", len(entries), len(want))
	}
	total, failing := 0, 0
	for _, w := range want {
		path := "platform/id-v1/" + w.kind + ".json"
		raw, err := fs.ReadFile(vectors.FS, path)
		if err != nil {
			t.Error(err)
			continue
		}
		if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != w.sha256 {
			t.Errorf("%s is not the file captured at platform 5e66d84 (PROVENANCE.md)", path)
		}
		for i, c := range raw {
			if c >= 0x80 {
				t.Fatalf("%s: a non-ASCII byte at offset %d", path, i)
			}
		}
		if !bytes.HasSuffix(raw, []byte("}\n")) || bytes.HasSuffix(raw, []byte("\n\n")) {
			t.Errorf("%s does not end with exactly one newline", path)
		}
		var f struct {
			Format  string `json:"format"`
			Version int    `json:"version"`
			Kind    string `json:"kind"`
			Cases   []struct {
				Name  string `json:"name"`
				Error string `json:"error"`
			} `json:"cases"`
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if f.Format != "thehappie-id/vectors" || f.Version != 1 || f.Kind != w.kind {
			t.Errorf("%s: header %q %d %q", path, f.Format, f.Version, f.Kind)
		}
		names := map[string]bool{}
		bad := 0
		for _, c := range f.Cases {
			if c.Name == "" || names[c.Name] {
				t.Errorf("%s: an empty or repeated case name %q", path, c.Name)
			}
			names[c.Name] = true
			if c.Error != "" {
				bad++
			}
		}
		if len(f.Cases) != w.cases || bad != w.mustFail {
			t.Errorf("%s: %d cases, %d must fail; want %d and %d", path, len(f.Cases), bad, w.cases, w.mustFail)
		}
		total += len(f.Cases)
		failing += bad
	}
	if total != 257 || failing != 180 {
		t.Errorf("%d cases, %d must fail; want 257 and 180", total, failing)
	}
}
