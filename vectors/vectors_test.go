package vectors_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
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
