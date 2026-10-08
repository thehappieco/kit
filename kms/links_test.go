package kms_test

import (
	"bufio"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// What the kit's packages may link (SPEC section 14.3), read from their
// source whatever their build constraints: every .go file of the module that
// is not a _test.go file is parsed for its imports, under every tag and for
// every platform at once, as go mod tidy reads a module it depends on. No
// package but kms/localkek itself reaches kms/localkek, through any chain of
// the kit's packages; no package but kms/awskms reaches a package of
// github.com/aws, itself or through another of the kit's packages; and every
// file of kms/localkek requires the tag kitdevkek. A file under a tag of its
// own, such as a product's dev, or for another platform, is checked like any
// other. make imports-check runs this test first, then checks the build
// contexts the go tool sees (CI).
func TestOnlyTestsLinkTheLocalKEKAndOnlyAWSKMSTheSDK(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	module := modulePath(t, filepath.Join(root, "go.mod"))
	localkek, awskms := module+"/kms/localkek", module+"/kms/awskms"

	// imports[package][import path] is a file of the package that imports it.
	imports := map[string]map[string]string{}
	var kekFiles int
	checked := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			name := d.Name()
			if rel == "js" || name == "testdata" || strings.HasPrefix(name, "_") || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				return filepath.SkipDir // another module
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		checked++
		pkg := module
		if dir := filepath.ToSlash(filepath.Dir(rel)); dir != "." {
			pkg += "/" + dir
		}
		if imports[pkg] == nil {
			imports[pkg] = map[string]string{}
		}
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			if _, ok := imports[pkg][p]; !ok {
				imports[pkg][p] = filepath.ToSlash(rel)
			}
		}
		if pkg == localkek {
			kekFiles++
			if x := buildConstraint(t, path); x == nil || !requires(x, "kitdevkek") {
				t.Errorf("%s does not require the build tag kitdevkek: a build without the tag would compile the local KEK", filepath.ToSlash(rel))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 40 || kekFiles == 0 || imports[awskms] == nil {
		t.Fatalf("only %d files checked (%d of kms/localkek), or no kms/awskms", checked, kekFiles)
	}

	// reach is every package of the kit that p imports, directly or through
	// another package of the kit, and p itself.
	reach := func(p string) []string {
		seen := map[string]bool{p: true}
		for todo := []string{p}; len(todo) > 0; {
			q := todo[len(todo)-1]
			todo = todo[:len(todo)-1]
			for imp := range imports[q] {
				if _, kit := imports[imp]; kit && !seen[imp] {
					seen[imp] = true
					todo = append(todo, imp)
				}
			}
		}
		return slices.Sorted(maps.Keys(seen))
	}
	sdk := false
	for _, p := range slices.Sorted(maps.Keys(imports)) {
		linked := ""
		for _, q := range reach(p) {
			if q == localkek && p != localkek {
				t.Errorf("%s links kms/localkek: only tests may import it", p)
			}
			for _, imp := range slices.Sorted(maps.Keys(imports[q])) {
				if !strings.HasPrefix(imp, "github.com/aws/") {
					continue
				}
				if p == awskms {
					sdk = sdk || q == awskms
				} else if linked == "" {
					linked = imports[q][imp] + " imports " + imp
				}
			}
		}
		if linked != "" {
			t.Errorf("%s links the AWS SDK (%s): only kms/awskms may", p, linked)
		}
	}
	if !sdk {
		t.Fatal("kms/awskms imports no package of github.com/aws, so this test checks nothing")
	}
}

// modulePath is the path on the module line of a go.mod file.
func modulePath(t *testing.T, gomod string) string {
	t.Helper()
	f, err := os.Open(gomod)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if m, ok := strings.CutPrefix(strings.TrimSpace(s.Text()), "module "); ok {
			return strings.TrimSpace(m)
		}
	}
	t.Fatalf("%s has no module line", gomod)
	return ""
}

// buildConstraint is a file's //go:build expression, or nil if it has none.
func buildConstraint(t *testing.T, path string) constraint.Expr {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package ") {
			break
		}
		if constraint.IsGoBuild(line) {
			x, err := constraint.Parse(line)
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			return x
		}
	}
	return nil
}

// requires reports whether x is false whenever tag is off.
func requires(x constraint.Expr, tag string) bool {
	switch x := x.(type) {
	case *constraint.TagExpr:
		return x.Tag == tag
	case *constraint.AndExpr:
		return requires(x.X, tag) || requires(x.Y, tag)
	case *constraint.OrExpr:
		return requires(x.X, tag) && requires(x.Y, tag)
	}
	return false
}
