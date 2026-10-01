#!/bin/sh
# Regenerates the Wappie vectors from Wappie's own code at a given commit.
#
#   vectors/wappie/_generators/run.sh <wappie-repo> <commit> <out-dir>
#
# It extracts <commit> with `git archive` into a temporary directory (the
# Wappie repository is only read), copies the generators beside the code they
# exercise, runs them, and writes into <out-dir>/golden and <out-dir>/legacy.
# Nothing is ever overwritten: the generators open their files with O_EXCL, so
# <out-dir> must not already hold them. To check the committed vectors, run it
# into an empty directory and compare:
#
#   vectors/wappie/_generators/run.sh ~/src/wappie 8c0c1f74103bc6bb65a93b13613ad1964d4399c4 /tmp/v
#   diff -r /tmp/v/golden vectors/wappie/golden && diff -r /tmp/v/legacy vectors/wappie/legacy
#
# The Go generators need the go1.26.7 toolchain (GOTOOLCHAIN downloads it);
# the TypeScript generators need Node and npm. Never pass -update to Wappie's
# own tests: that flag rewrites Wappie's fixtures with fresh random keys.
set -eu

repo=${1:?usage: run.sh <wappie-repo> <commit> <out-dir>}
commit=${2:?usage: run.sh <wappie-repo> <commit> <out-dir>}
out=${3:?usage: run.sh <wappie-repo> <commit> <out-dir>}

here=$(cd "$(dirname "$0")" && pwd)
commit=$(git -C "$repo" rev-parse --verify "$commit^{commit}")
mkdir -p "$out/golden" "$out/legacy"
out=$(cd "$out" && pwd)

work=$(mktemp -d)
trap 'rm -rf "${work:?}"' EXIT
git -C "$repo" archive "$commit" | tar -x -C "$work"

# Go: internal tests inside the packages they read.
cp "$here/go/internal/crypto/seal/kitgen_internal_test.go" "$work/internal/crypto/seal/"
cp "$here/go/internal/mcpauth/kitgen_internal_test.go" "$work/internal/mcpauth/"
cp "$here/go/internal/authapi/kitgen_internal_test.go" "$work/internal/authapi/"
(
	cd "$work"
	export GOTOOLCHAIN=go1.26.7 GOFLAGS=-mod=readonly KITGEN_OUT="$out/golden" KITGEN_COMMIT="$commit"
	go test -count=1 -run '^TestKitGenSeal$' ./internal/crypto/seal
	go test -count=1 -run '^TestKitGenRequestHMAC$' ./internal/mcpauth
	go test -count=1 -run '^TestKitGenPasskeySalt$' ./internal/authapi
)

# TypeScript: a vitest file inside packages/client, run against its sources
# with its own locked dependencies.
cp "$here/ts/packages/client/test/kitgen.spec.ts" "$here/ts/packages/client/test/kitgen-random.ts" "$work/packages/client/test/"
(
	cd "$work/packages/client"
	npm ci --ignore-scripts --no-audit --no-fund >/dev/null
	KITGEN_OUT="$out/golden" KITGEN_COMMIT="$commit" KITGEN_WAPPIE="$work" npx vitest run test/kitgen.spec.ts
)

# Legacy fixtures: byte-for-byte copies, never rewritten.
for f in \
	internal/crypto/seal/testdata/vectors.json \
	internal/crypto/seal/testdata/draft-vectors.json \
	internal/wsapi/testdata/frames.json \
	packages/client/testdata/browser-grant.json \
	packages/client/testdata/node-draft.json \
	packages/client/testdata/node-derived.json; do
	name=$(basename "$f")
	case "$f" in
	internal/crypto/seal/testdata/vectors.json) name=seal-vectors.json ;;
	esac
	if [ -e "$out/legacy/$name" ]; then
		echo "refusing to overwrite $out/legacy/$name" >&2
		exit 1
	fi
	cp "$work/$f" "$out/legacy/$name"
done
echo "wrote $out from $commit"
