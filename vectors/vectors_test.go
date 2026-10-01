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
	for _, root := range []string{"wappie", "kit"} {
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
	if _, err := fs.Stat(vectors.FS, "wappie/_generators/run.sh"); err == nil {
		t.Error("the generators are embedded")
	}
}

// Every case SPEC.md cites as `file#case-id` exists: a bare file name is
// under wappie/golden/, and an id ending in * names at least one case.
func TestSpecCitations(t *testing.T) {
	spec, err := os.ReadFile("../SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	cite := regexp.MustCompile("`((?:kit/|wappie/golden/)?[a-z0-9-]+\\.json)#([^`]+)`")
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
				ID string `json:"id"`
			} `json:"cases"`
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, c := range f.Cases {
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
