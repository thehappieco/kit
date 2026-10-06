#!/bin/sh
# Writes the vectors of Wappie's platform wrap (SPEC section 6.8) from the
# code of Wappie's console (github.com/thehappieco/wappie-cloud) at a given
# commit.
#
#   vectors/wappie/_generators/run-cloud.sh <wappie-cloud-repo> <commit> <out-dir> [<patch>]
#
# It extracts <commit> with `git archive` into a temporary directory (the
# console's repository is only read), applies <patch> to that copy when one
# is given, copies the kit's two generators beside the code they exercise,
# and writes <out-dir>/golden/platform-wrap-go.json,
# <out-dir>/golden/platform-wrap-ts.json and
# <out-dir>/legacy/platform-wrap-vectors.json. With a patch, the console's
# own testdata/vectors.json is first rewritten by its own test (go test
# ./platformwrap -update), which the console's code allows "for a new
# construction"; its keys and nonces are SHA-256 of fixed labels, so the
# rewrite is deterministic. Either way the console's own Go and TypeScript
# tests then run on the copy and must pass. Nothing is ever overwritten: the
# generators open their files exclusively, and so does the copy here. To
# check the committed vectors, run it into an empty directory and compare
# (make vectors-cloud-regen-check does both):
#
#   vectors/wappie/_generators/run-cloud.sh ../whatserver2/commercial \
#     3bfee279581ad15f6d2d2db3d3a9794c8eac50ca /tmp/v vectors/wappie/_generators/cloud/header-0x03.patch
#   diff /tmp/v/golden/platform-wrap-go.json vectors/wappie/golden/platform-wrap-go.json
#
# The Go generator needs the go1.26.7 toolchain (GOTOOLCHAIN downloads it);
# the TypeScript one needs Node and npm, and installs only vitest and the
# kit release the console's web/package-lock.json pins, both at the versions
# and with the integrity that lockfile records, into the temporary copy: the
# console's web/ package depends on Wappie's core and cannot be installed
# alone.
set -eu

usage='usage: run-cloud.sh <wappie-cloud-repo> <commit> <out-dir> [<patch>]'
repo=${1:?$usage}
commit=${2:?$usage}
out=${3:?$usage}
patch=${4:-}

here=$(cd "$(dirname "$0")" && pwd)
commit=$(git -C "$repo" rev-parse --verify "$commit^{commit}")
mkdir -p "$out/golden" "$out/legacy"
out=$(cd "$out" && pwd)
for f in "$out/golden/platform-wrap-go.json" "$out/golden/platform-wrap-ts.json" "$out/legacy/platform-wrap-vectors.json"; do
	if [ -e "$f" ]; then
		echo "refusing to overwrite $f" >&2
		exit 1
	fi
done

work=$(mktemp -d)
trap 'rm -rf "${work:?}"' EXIT
git -C "$repo" archive "$commit" go.mod go.sum platformwrap web/platform/platformWrap.ts web/test/platformWrap.spec.ts web/package-lock.json | tar -x -C "$work"

patched=
if [ -n "$patch" ]; then
	patch=$(cd "$(dirname "$patch")" && pwd)/$(basename "$patch")
	(cd "$work" && git apply -p1 "$patch")
	sum=$(shasum -a 256 "$patch" | cut -c1-16)
	patched=", with vectors/wappie/_generators/cloud/$(basename "$patch") (sha256 $sum...) applied"
fi

# Go: the console's own tests, then the kit's generator inside the package.
cp "$here/cloud/platformwrap/kitgen_internal_test.go" "$work/platformwrap/"
(
	cd "$work"
	export GOTOOLCHAIN=go1.26.7 GOFLAGS=-mod=readonly
	if [ -n "$patch" ]; then
		go test -count=1 -run '^TestVectors$' ./platformwrap -update
	fi
	go test -count=1 ./platformwrap
	KITGEN_OUT="$out/golden" KITGEN_COMMIT="$commit" KITGEN_PATCHED="$patched" go test -count=1 -run '^TestKitGenPlatformWrap$' ./platformwrap
)

# TypeScript: the console's own spec and the kit's generator, under vitest,
# against the kit release the console pins.
cp "$here/cloud/web/test/kitgen.spec.ts" "$work/web/test/"
(
	cd "$work/web"
	pins=$(node -e '
		const lock = require("./package-lock.json").packages
		const kit = lock["node_modules/@thehappieco/kit"], vitest = lock["node_modules/vitest"]
		console.log([kit.resolved, kit.integrity, vitest.version].join(" "))')
	set -- $pins
	kit_url=$1 kit_integrity=$2 vitest_version=$3
	rm package-lock.json
	printf '{"name":"kitgen-platform-wrap","private":true,"type":"module"}\n' > package.json
	printf "export default { test: { include: ['test/platformWrap.spec.ts', 'test/kitgen.spec.ts'] } }\n" > vitest.config.mjs
	npm install --ignore-scripts --no-audit --no-fund --save-exact "vitest@$vitest_version" "$kit_url" >/dev/null
	got=$(node -p 'require("./package-lock.json").packages["node_modules/@thehappieco/kit"].integrity')
	if [ "$got" != "$kit_integrity" ]; then
		echo "the kit tarball's integrity is $got, the console's lockfile pins $kit_integrity" >&2
		exit 1
	fi
	KITGEN_OUT="$out/golden" KITGEN_COMMIT="$commit" KITGEN_PATCHED="$patched" npx vitest run
)

# The console's own file, as its own test wrote or checked it.
cp "$work/platformwrap/testdata/vectors.json" "$out/legacy/platform-wrap-vectors.json"
echo "wrote $out from $commit$patched"
