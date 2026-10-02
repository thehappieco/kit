// Command vectors writes the golden vectors of the id protocol, version 1
// (docs/protocol/id-v1.md, sections 6 and 7.14), one file per kind:
//
//	go run ./tools/vectors                 # writes testdata/vectors/id-v1/*.json
//	go run ./tools/vectors -check          # exits 1 if a file differs
//	go run ./tools/vectors -out some/dir   # writes elsewhere
//
// The files are a pure function of internal/crypto/idcrypto/idvectors, so a
// second run writes the same bytes. The Go tests (TestTheGoldenVectorsAreUpToDate)
// and the TypeScript tests read the same files.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/thehappieco/platform/internal/crypto/idcrypto/idvectors"
)

func main() {
	out := flag.String("out", idvectors.Dir, "directory to write the vector files into")
	check := flag.Bool("check", false, "compare the files in -out with fresh vectors instead of writing them")
	flag.Parse()
	if err := run(*out, *check); err != nil {
		fmt.Fprintf(os.Stderr, "vectors: %v\n", err)
		os.Exit(1)
	}
}

func run(dir string, check bool) error {
	files, err := idvectors.Generate()
	if err != nil {
		return err
	}
	if check {
		stale := 0
		for _, f := range files {
			path := filepath.Join(dir, f.Name)
			have, err := os.ReadFile(path) //nolint:gosec // the path is the operator's own -out flag
			if err != nil || !bytes.Equal(have, f.Data) {
				fmt.Fprintf(os.Stderr, "vectors: %s is missing or out of date\n", path)
				stale++
			}
		}
		if stale > 0 {
			return fmt.Errorf("%d of %d files differ; run go run ./tools/vectors", stale, len(files))
		}
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // public test data, readable by everyone
		return err
	}
	for _, f := range files {
		path := filepath.Join(dir, f.Name)
		if err := os.WriteFile(path, f.Data, 0o644); err != nil { //nolint:gosec // public test data, readable by everyone
			return err
		}
		fmt.Fprintf(os.Stderr, "vectors: wrote %s (%d bytes)\n", path, len(f.Data))
	}
	return nil
}
