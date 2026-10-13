package contract_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// What the contract's packages may link (SPEC section 11.17), read from
// their source whatever their build constraints: contract only the standard
// library and reqhmac, contracttest also contract, and reqhmac the standard
// library alone, so an app that imports either links nothing else of the
// kit and no other module. Test files may import more.
func TestTheContractLinksOnlyTheStandardLibraryAndReqhmac(t *testing.T) {
	const kit = "github.com/thehappieco/kit/"
	allowed := map[string]map[string]bool{
		".":            {kit + "reqhmac": true},
		"contracttest": {kit + "reqhmac": true, kit + "contract": true},
		"../reqhmac":   {},
	}
	for dir, kitImports := range allowed {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		checked := 0
		for _, path := range files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, src, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, spec := range f.Imports {
				imp, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				first, _, _ := strings.Cut(imp, "/")
				if !kitImports[imp] && strings.Contains(first, ".") {
					t.Errorf("%s imports %s", path, imp)
				}
			}
			checked++
		}
		if checked == 0 {
			t.Fatalf("no file in %s", dir)
		}
	}
}
