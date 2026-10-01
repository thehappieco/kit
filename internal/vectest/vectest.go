// Package vectest loads the kit's vector files for the Go tests.
//
// Each package's conformance test loads the files it owns and dispatches on
// every case's op. A case whose op the test does not handle, and that is not
// marked for another language, fails the test: no vector is skipped silently.
package vectest

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/thehappieco/kit/vectors"
)

// Format is the only vector format this package reads.
const Format = "thehappieco-kit-vectors/1"

// File is one vector file.
type File struct {
	// Path is where the file was read from.
	Path        string         `json:"-"`
	Format      string         `json:"format"`
	Module      string         `json:"module"`
	Profile     string         `json:"profile"`
	GeneratedBy GeneratedBy    `json:"generated_by"`
	Note        string         `json:"note"`
	Keys        map[string]Key `json:"keys"`
	Cases       []Case         `json:"cases"`
}

// GeneratedBy records where a file came from.
type GeneratedBy struct {
	Lang       string `json:"lang"`
	Source     string `json:"source"`
	Toolchain  string `json:"toolchain"`
	Randomness string `json:"randomness"`
	Generator  string `json:"generator"`
}

// Key is a named key pair in a file.
type Key struct {
	PrivateKey string `json:"private_key_b64"`
	PublicKey  string `json:"public_key_b64"`
	Seed       uint64 `json:"seed"`
}

// Case is one vector. Exactly one of Out and Error is set.
type Case struct {
	ID     string          `json:"id"`
	Op     string          `json:"op"`
	Langs  []string        `json:"langs"`
	In     json.RawMessage `json:"in"`
	Out    json.RawMessage `json:"out"`
	Error  string          `json:"error"`
	Reason string          `json:"reason"`
	Note   string          `json:"note"`
}

// ForGo reports whether Go runs the case.
func (c Case) ForGo() bool { return len(c.Langs) == 0 || slices.Contains(c.Langs, "go") }

// Load reads and checks a file from vectors.FS.
func Load(t testing.TB, path string) *File {
	t.Helper()
	raw, err := fs.ReadFile(vectors.FS, path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return parse(t, path, raw)
}

func parse(t testing.TB, path string, raw []byte) *File {
	t.Helper()
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	if f.Format != Format {
		t.Fatalf("%s: format %q, want %q", path, f.Format, Format)
	}
	seen := map[string]bool{}
	for _, c := range f.Cases {
		if seen[c.ID] {
			t.Fatalf("%s: duplicate case id %s", path, c.ID)
		}
		seen[c.ID] = true
		if (len(c.Out) == 0) == (c.Error == "") {
			t.Fatalf("%s: case %s must have exactly one of out and error", path, c.ID)
		}
	}
	f.Path = path
	return &f
}

// Files loads the named files from vectors.FS and, for each kit/*.json name,
// the file of the same base name in $KIT_CROSS_IN when that is set: the fresh
// vectors the other language has just written, in the cross-language job.
func Files(t testing.TB, paths ...string) []*File {
	t.Helper()
	var out []*File
	for _, path := range paths {
		out = append(out, Load(t, path))
		dir := os.Getenv("KIT_CROSS_IN")
		if dir == "" || !strings.HasPrefix(path, "kit/") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, strings.TrimPrefix(path, "kit/")))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, parse(t, filepath.Join(dir, strings.TrimPrefix(path, "kit/")), raw))
	}
	return out
}

// Cases is every case of Files(paths...), in order.
func Cases(t testing.TB, paths ...string) []Case {
	t.Helper()
	var out []Case
	for _, f := range Files(t, paths...) {
		out = append(out, f.Cases...)
	}
	return out
}

// Raw reads a file from vectors.FS, for the legacy files with their own shapes.
func Raw(t testing.TB, path string) []byte {
	t.Helper()
	raw, err := fs.ReadFile(vectors.FS, path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return raw
}

// Decode unmarshals a case's in or out into v.
func Decode(t testing.TB, raw json.RawMessage, v any) {
	t.Helper()
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
}

// B64 decodes standard padded base64.
func B64(t testing.TB, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding base64 %q: %v", s, err)
	}
	return b
}

// UUID parses a textual UUID.
func UUID(t testing.TB, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("parsing uuid %q: %v", s, err)
	}
	return id
}

// Replays reports whether seeded cases can be replayed byte for byte here:
// how the standard library consumes randomness may change between Go
// versions, so a replay runs only on the toolchain that wrote the file.
func (f *File) Replays() bool { return runtime.Version() == f.GeneratedBy.Toolchain }

// SkipReplay skips a replay subtest on any other toolchain, saying why.
func (f *File) SkipReplay(t *testing.T) {
	t.Helper()
	if !f.Replays() {
		t.Skipf("replay needs %s (this is %s): the open-direction checks above still ran", f.GeneratedBy.Toolchain, runtime.Version())
	}
}

// Unhandled fails a case no branch of a dispatcher took.
func Unhandled(t *testing.T, c Case) {
	t.Helper()
	t.Errorf("case %s: op %q is not handled by the Go tests", c.ID, c.Op)
}
