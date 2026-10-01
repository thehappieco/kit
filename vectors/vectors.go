// Package vectors embeds the kit's test vectors, so a consumer's tests can
// run them against the kit version it imports:
//
//	data, err := fs.ReadFile(vectors.FS, "wappie/golden/seal-go.json")
//
// The directory layout, the file format and the provenance of every file are
// in README.md and PROVENANCE.md beside this file. The generators under
// wappie/_generators are not embedded.
package vectors

import "embed"

// FS holds MANIFEST.sha256 and every file under wappie/ and kit/.
//
//go:embed MANIFEST.sha256 wappie kit
var FS embed.FS
