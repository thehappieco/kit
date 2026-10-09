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

// generatorPath matches the generators' directories (wappie/_generators,
// platform/_generators and platform/_generators-<commit>), which go:embed
// leaves out because their names start with an underscore.
var generatorPath = regexp.MustCompile(`(^|/)_generators[^/]*/`)

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
		if generatorPath.MatchString(name) {
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
	for _, root := range []string{"wappie", "kit", "platform", "mailie"} {
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
	for _, generator := range []string{
		"wappie/_generators/run.sh",
		"platform/_generators/tools/vectors/main.go",
		"platform/_generators-4476bf4/tools/vectors/main.go",
		"platform/_generators-b5d9f69/tools/vectors/main.go",
		"platform/_generators-75b6b94/tools/vectors/main.go",
		"wappie/_generators/run-cloud.sh",
		"wappie/_generators/cloud/header-0x03.patch",
	} {
		if _, err := fs.Stat(vectors.FS, generator); err == nil {
			t.Errorf("the generators are embedded: %s", generator)
		}
	}
}

// Every case SPEC.md cites as `file#case-id` exists: a bare file name is
// under wappie/golden/, a file under mailie/golden/ or
// mailie/key-scheme-v1/ is named with its directory, and an id ending in *
// names at least one case. The
// platform's files name their cases instead (`platform/id-v1/kdf.json#the
// floor parameters`), and a case of theirs that carries an op is cited by op
// and name (`platform/id-v1/key-delivery.json#open/a sub in upper case`).
// THCSEAL's file holds two lists, and a case of it is cited by its list and
// name (`platform/thcseal-v1/thcseal-v1.json#invalid/version 2`).
func TestSpecCitations(t *testing.T) {
	spec, err := os.ReadFile("../SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	cite := regexp.MustCompile("`((?:kit/|wappie/golden/|mailie/golden/|mailie/key-scheme-v1/|platform/id-v1/|platform/thcseal-v1/)?[a-z0-9-]+\\.json)#([^`]+)`")
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
		type named struct {
			Name string `json:"name"`
		}
		var f struct {
			Cases []struct {
				ID   string `json:"id"`
				Op   string `json:"op"`
				Name string `json:"name"`
			} `json:"cases"`
			Valid   []named `json:"valid"`
			Invalid []named `json:"invalid"`
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, c := range f.Cases {
			if strings.HasPrefix(file, "platform/id-v1/") {
				c.ID = platformCaseID(c.Op, c.Name)
			}
			ids = append(ids, c.ID)
		}
		for _, c := range f.Valid {
			ids = append(ids, "valid/"+c.Name)
		}
		for _, c := range f.Invalid {
			ids = append(ids, "invalid/"+c.Name)
		}
		found := false
		for _, have := range ids {
			if have == id || (strings.HasSuffix(id, "*") && strings.HasPrefix(have, strings.TrimSuffix(id, "*"))) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("SPEC.md cites %s, which is not a case", m[0])
		}
	}
}

// Every row of a table in SPEC.md has as many cells as its header. GFM
// splits a table row on every '|' not escaped as '\|', inside code spans
// too, so a label such as `thehappie-id/v1/passkey-prf|` written unescaped
// in a table loses its '|' and the rest of its row on GitHub: the label a
// reader copies from the rendered spec would hash to another salt.
func TestSpecTables(t *testing.T) {
	spec, err := os.ReadFile("../SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	separators := func(row string) int {
		n := 0
		for i := 0; i < len(row); i++ {
			if row[i] == '|' && (i == 0 || row[i-1] != '\\') {
				n++
			}
		}
		return n
	}
	header, fenced, tables := 0, false, 0
	for i, line := range strings.Split(string(spec), "\n") {
		if strings.HasPrefix(line, "```") || strings.HasPrefix(line, "~~~") {
			fenced = !fenced
		}
		if fenced || !strings.HasPrefix(line, "|") {
			header = 0
			continue
		}
		if header == 0 {
			header = separators(line)
			tables++
			continue
		}
		if n := separators(line); n != header {
			t.Errorf("SPEC.md line %d: %d cell separators, the header has %d (escape a '|' in a cell as '\\|')", i+1, n, header)
		}
	}
	if tables < 5 {
		t.Fatalf("only %d tables found", tables)
	}
}

// platformCaseID is how the kit identifies and cites a case of the
// platform's format: its name, or op "/" name when it carries an op. The
// platform's key-delivery.json gives five names to two cases each, one with
// op "open" and one with op "seal"; passkey.json's must-fail cases carry an
// op too ("salt", "key" or "open"), under names that are also unique
// (PROVENANCE.md).
func platformCaseID(op, name string) string {
	if op != "" {
		return op + "/" + name
	}
	return name
}

// The platform's id-v1 files are the ones captured at the platform commits
// PROVENANCE.md records: the eight part-1 files at 5e66d84, the three part-2
// files at 4476bf4, the two part-3 files at b5d9f69 and the relying party
// rule's file at 75b6b94. Each has the sha256 recorded there, so a copy from
// another platform commit or an edit fails here even after `make manifest`
// has recorded it, and no tag can freeze other bytes as these. Then their
// header, ASCII only with exactly one final newline, unique case ids (the
// name, or op and name), and the number of cases and of must-fail cases per
// kind.
func TestPlatformVectorFiles(t *testing.T) {
	want := []struct {
		kind            string
		cases, mustFail int
		commit, sha256  string
	}{
		{"password-profile", 45, 23, "5e66d84", "47803646a66f8a20c5cdb02852b628a5716d1dc4854759367f7f10dba3c5294e"},
		{"kdf", 19, 16, "5e66d84", "89b6ffe8d32a65b7c63c88763d3aab5da3f9cf064e548d8cd6abba51df7d7483"},
		{"root-wrap", 31, 26, "5e66d84", "54aa88e9e89f143031b4acdc11ab01b31497c3d3a4ef3783ce121ba224733ee1"},
		{"recovery-code", 27, 15, "5e66d84", "c3c57217d0a491d84f374c95ff83c5c974126884d741501fef70969ec1ab19fa"},
		{"product-key", 20, 12, "5e66d84", "388cae00f034bef42f75e74a4a52f27ff7ff7409ed48b67ba3bc338326cb5601"},
		{"verifier", 10, 5, "5e66d84", "394e2bf399bd1a6a23b00e067d71a2f6da70cb2c69a5a2a542efd61322f5a5e4"},
		{"email", 46, 33, "5e66d84", "a0cffa73f07782d4feca2c3dea293f3e8de75164b3ee043106b0d6b0b3e0575d"},
		{"key-bundle", 59, 50, "5e66d84", "364b4c24046ca70b04dbbc04ead6417445f1aa8bede2c930068cbd1adfc61a6e"},
		{"key-delivery", 73, 64, "4476bf4", "2d7e322b1afc9e021f0fc4707e5fc666d9626608d082b22f2782ee2d4e4d40b2"},
		{"pkce", 18, 12, "4476bf4", "b58002e68fff370e5a9dcc49847b3d4a2b27cd2836a140eb5e1a169c9a9bd010"},
		{"password-stream-safe", 19, 11, "4476bf4", "6c0be5a1e236fab99e97cacbff527674b76f65a9a1c5b2630bdf8558465021cc"},
		{"passkey", 44, 35, "b5d9f69", "dca9707d800996f219b62a5fc09b56b693be98a0487494bebb4bd6ad2606e286"},
		{"client-extensions", 46, 37, "b5d9f69", "e5c6e6a4ac7dad59fbbd131f095721842d53432699fad72a7db82be6884afb3b"},
		{"rp-id-ends-in-number", 29, 17, "75b6b94", "b361d107e1f50d51cd146b6c74b9079676942ab8f01d7b2833d43ee437d33d56"},
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
			t.Errorf("%s is not the file captured at platform %s (PROVENANCE.md)", path, w.commit)
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
				Op    string `json:"op"`
				Error string `json:"error"`
			} `json:"cases"`
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if f.Format != "thehappie-id/vectors" || f.Version != 1 || f.Kind != w.kind {
			t.Errorf("%s: header %q %d %q", path, f.Format, f.Version, f.Kind)
		}
		ids := map[string]bool{}
		bad := 0
		for _, c := range f.Cases {
			id := platformCaseID(c.Op, c.Name)
			if c.Name == "" || ids[id] {
				t.Errorf("%s: an empty or repeated case %q", path, id)
			}
			ids[id] = true
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
	if total != 486 || failing != 356 {
		t.Errorf("%d cases, %d must fail; want 486 and 356", total, failing)
	}
}

// Wappie's platform-wrap files (SPEC section 6.8) are the ones captured from
// Wappie's console at the commit PROVENANCE.md records, with the header
// patch recorded there: each has the sha256 recorded there, so an edit or
// a capture from another commit fails here even after `make manifest` has
// recorded it. The golden files have their counts of cases and of
// must-fail cases; the console's own file its 3 vectors, 15 open refusals
// and 5 seal refusals.
func TestWappiePlatformWrapFiles(t *testing.T) {
	for _, w := range []struct {
		path            string
		cases, mustFail int
		sha256          string
	}{
		{"wappie/golden/platform-wrap-go.json", 55, 31, "e3d5e918fbb239d59e01e22dcffa94ad5e3da111425fe1f386b215f8a1b9e933"},
		{"wappie/golden/platform-wrap-ts.json", 22, 10, "cfb7390af38d26e63acf03004628c9af29595bc47069ce4808bd654e0cd5eb37"},
	} {
		raw, err := fs.ReadFile(vectors.FS, w.path)
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != w.sha256 {
			t.Errorf("%s is not the file captured from the console (PROVENANCE.md)", w.path)
		}
		var f struct {
			Format string `json:"format"`
			Module string `json:"module"`
			Cases  []struct {
				ID    string `json:"id"`
				Error string `json:"error"`
			} `json:"cases"`
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatal(err)
		}
		bad := 0
		for _, c := range f.Cases {
			if c.Error != "" {
				bad++
			}
		}
		if f.Format != "thehappieco-kit-vectors/1" || f.Module != "wappie.platform_wrap" || len(f.Cases) != w.cases || bad != w.mustFail {
			t.Errorf("%s: %q %q, %d cases, %d must fail; want %d and %d", w.path, f.Format, f.Module, len(f.Cases), bad, w.cases, w.mustFail)
		}
	}
	const legacy = "wappie/legacy/platform-wrap-vectors.json"
	raw, err := fs.ReadFile(vectors.FS, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != "fb96f29339e3e9855d3835ef21d3742837f9f760d7748fbce35430ce8b084ec7" {
		t.Errorf("%s is not the file captured from the console (PROVENANCE.md)", legacy)
	}
	var f struct {
		Vectors      []json.RawMessage `json:"vectors"`
		OpenRefusals []json.RawMessage `json:"open_refusals"`
		SealRefusals []json.RawMessage `json:"seal_refusals"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Vectors) != 3 || len(f.OpenRefusals) != 15 || len(f.SealRefusals) != 5 {
		t.Errorf("%s: %d vectors, %d and %d refusals; want 3, 15 and 5", legacy, len(f.Vectors), len(f.OpenRefusals), len(f.SealRefusals))
	}
}

// THCSEAL's file (SPEC sections 12.3 and 14) is the platform's, captured at
// the commit PROVENANCE.md records: it has the sha256 recorded there, so a
// copy from another commit or an edit fails here even after `make manifest`
// has recorded it. Then its directory holds only it; it is ASCII with
// exactly one final newline; and it has 5 valid and 21 invalid cases, 12 of
// them decrypt, 8 malformed and 1 provider_mismatch, under unique names.
// thcseal's own tests open and refuse every case.
func TestTHCSEALVectorFile(t *testing.T) {
	const path = "platform/thcseal-v1/thcseal-v1.json"
	raw, err := fs.ReadFile(vectors.FS, path)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != "8d4c96590d60d076f1eb40c68a67fed5aae876311200e1ea87916881e63df86a" {
		t.Errorf("%s is not the file captured at platform d32b663 (PROVENANCE.md)", path)
	}
	entries, err := fs.ReadDir(vectors.FS, "platform/thcseal-v1")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("platform/thcseal-v1 holds %d files, want 1", len(entries))
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
		Provider string `json:"provider"`
		Valid    []struct {
			Name string `json:"name"`
		} `json:"valid"`
		Invalid []struct {
			Name  string `json:"name"`
			Error string `json:"error"`
		} `json:"invalid"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	names, errs := map[string]bool{}, map[string]int{}
	for _, c := range f.Valid {
		if c.Name == "" || names["valid/"+c.Name] {
			t.Errorf("%s: an empty or repeated valid case %q", path, c.Name)
		}
		names["valid/"+c.Name] = true
	}
	for _, c := range f.Invalid {
		if c.Name == "" || names["invalid/"+c.Name] {
			t.Errorf("%s: an empty or repeated invalid case %q", path, c.Name)
		}
		names["invalid/"+c.Name] = true
		errs[c.Error]++
	}
	if f.Provider != "localkek (0x7f)" || len(f.Valid) != 5 || len(f.Invalid) != 21 ||
		errs["decrypt"] != 12 || errs["malformed"] != 8 || errs["provider_mismatch"] != 1 || len(errs) != 3 {
		t.Errorf("%s: provider %q, %d valid, %d invalid %v; want localkek (0x7f), 5 and 21 (12 decrypt, 8 malformed, 1 provider_mismatch)", path, f.Provider, len(f.Valid), len(f.Invalid), errs)
	}
}

// Mailie's golden file (SPEC section 6.8 and Appendix D) is the one the
// kit's generator wrote at the commit PROVENANCE.md records: it has the
// sha256 recorded there, so an edit or a file from a changed generator
// fails here even after `make manifest` has recorded it; make
// vectors-mailie-regen writes it again byte for byte. Its directory holds
// only it; it is ASCII with exactly one final newline; and it has 60 cases,
// 36 of them must fail, 7 of those across the two products, under unique
// ids.
func TestMailiePlatformWrapFile(t *testing.T) {
	const path = "mailie/golden/platform-wrap-go.json"
	raw, err := fs.ReadFile(vectors.FS, path)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != "1546933624b0355cba4657467552570e20ae6ac7b62735ce0ac4ac316beda864" {
		t.Errorf("%s is not the file PROVENANCE.md records", path)
	}
	entries, err := fs.ReadDir(vectors.FS, "mailie/golden")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("mailie/golden holds %d files, want 1", len(entries))
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
		Module  string `json:"module"`
		Profile string `json:"profile"`
		Cases   []struct {
			ID    string `json:"id"`
			Error string `json:"error"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	ids, bad, cross := map[string]bool{}, 0, 0
	for _, c := range f.Cases {
		if c.ID == "" || ids[c.ID] {
			t.Errorf("%s: an empty or repeated id %q", path, c.ID)
		}
		ids[c.ID] = true
		if c.Error != "" {
			bad++
			if strings.Contains(c.ID, "/cross-product/") {
				cross++
			}
		}
	}
	if f.Format != "thehappieco-kit-vectors/1" || f.Module != "mailie.platform_wrap" || f.Profile != "mailie" || len(f.Cases) != 60 || bad != 36 || cross != 7 {
		t.Errorf("%s: %q %q %q, %d cases, %d must fail, %d across products; want 60, 36 and 7", path, f.Format, f.Module, f.Profile, len(f.Cases), bad, cross)
	}
}

// Mailie's key-scheme files (SPEC Appendix D) are Mailie's own, captured at
// github.com/thehappieco/mailie c9c79cf (PROVENANCE.md): each has the sha256
// recorded there, so an edit or a capture from another commit fails here
// even after `make manifest` has recorded it; profiles/mailie writes them
// again byte for byte (TestTheKitWritesMailiesKeySchemeVectorsAgain) and make
// vectors-mailie-check has Mailie's own generator write them. Their
// directory holds exactly these four; each ends with exactly one newline and
// is in the kit's format, under Mailie's profile and the module named, with
// its counts of cases and of must-fail cases under unique ids: 248 and 150
// in all. Only account-go.json holds bytes outside ASCII, the addresses its
// normalisation cases spell in UTF-8.
func TestMailieKeySchemeFiles(t *testing.T) {
	want := []struct {
		name, module    string
		cases, mustFail int
		ascii           bool
		sha256          string
	}{
		{"account-go.json", "account", 104, 60, false, "2e75516cb5246a0e30db3e940a0c5dff53a449e83b003ed8bb33a1fefdacf6be"},
		{"grant-go.json", "seal", 107, 69, true, "fd6ce1d1ef9d415b756517e939328e56ee819c549e452818453ed6cca8362844"},
		{"platform-wrap-go.json", "platformwrap", 31, 18, true, "f8bd4a8fa6f74697e93ec19d1dba41f38915953319964076a603333808801a68"},
		{"browser-vault-go.json", "browser_account", 6, 3, true, "1988b3bcb61161ace08ee99caa23267f16c692b68cfd02f40f472942b88b7ee3"},
	}
	entries, err := fs.ReadDir(vectors.FS, "mailie/key-scheme-v1")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(want) {
		t.Errorf("mailie/key-scheme-v1 holds %d files, want %d", len(entries), len(want))
	}
	total, failing := 0, 0
	for _, w := range want {
		path := "mailie/key-scheme-v1/" + w.name
		raw, err := fs.ReadFile(vectors.FS, path)
		if err != nil {
			t.Error(err)
			continue
		}
		if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != w.sha256 {
			t.Errorf("%s is not the file captured at Mailie c9c79cf (PROVENANCE.md)", path)
		}
		if ascii := !bytes.ContainsFunc(raw, func(r rune) bool { return r >= 0x80 }); ascii != w.ascii {
			t.Errorf("%s: ASCII only is %v, want %v", path, ascii, w.ascii)
		}
		if !bytes.HasSuffix(raw, []byte("}\n")) || bytes.HasSuffix(raw, []byte("\n\n")) {
			t.Errorf("%s does not end with exactly one newline", path)
		}
		var f struct {
			Format      string `json:"format"`
			Module      string `json:"module"`
			Profile     string `json:"profile"`
			GeneratedBy struct {
				Source    string `json:"source"`
				Toolchain string `json:"toolchain"`
			} `json:"generated_by"`
			Cases []struct {
				ID    string `json:"id"`
				Error string `json:"error"`
			} `json:"cases"`
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		ids, bad := map[string]bool{}, 0
		for _, c := range f.Cases {
			if c.ID == "" || ids[c.ID] {
				t.Errorf("%s: an empty or repeated id %q", path, c.ID)
			}
			ids[c.ID] = true
			if c.Error != "" {
				bad++
			}
		}
		if f.Format != "thehappieco-kit-vectors/1" || f.Module != w.module || f.Profile != "mailie" ||
			f.GeneratedBy.Source != "github.com/thehappieco/mailie internal/keyscheme" || f.GeneratedBy.Toolchain != "go1.27.2" ||
			len(f.Cases) != w.cases || bad != w.mustFail {
			t.Errorf("%s: %q %q %q %+v, %d cases, %d must fail; want %d and %d", path, f.Format, f.Module, f.Profile, f.GeneratedBy, len(f.Cases), bad, w.cases, w.mustFail)
		}
		total += len(f.Cases)
		failing += bad
	}
	if total != 248 || failing != 150 {
		t.Errorf("%d cases, %d must fail; want 248 and 150", total, failing)
	}
}
