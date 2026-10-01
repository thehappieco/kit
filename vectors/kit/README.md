# Vectors written by the kit

Files here are written by the kit's own cross-language harness (`make cross`), never by hand. A `*-go.json` file was written by the kit's Go code and is opened by the TypeScript tests; a `*-ts.json` file was written by the kit's TypeScript and is opened by the Go tests. Once a release is tagged, its files are kept unchanged as golden vectors for every later release.
