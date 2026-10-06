# The kit's checks, the same ones CI runs. Go runs on the explicit package
# list rather than ./..., so a stray .go file under js/node_modules is never
# picked up.

GO_PACKAGES = $$(go list ./... | grep -v /js/)
GO_FILES = $$(find . -name '*.go' -not -path './js/*' -not -path './.git/*')
WAPPIE ?= ../whatserver2
WAPPIE_COMMIT ?= 8c0c1f74103bc6bb65a93b13613ad1964d4399c4
PLATFORM ?= ../platform
PLATFORM_COMMIT ?= 75b6b940df5c6903023f9030f5f3875540f6a36f
PLATFORM_FILES ?= 14
PLATFORM_GENERATOR ?= vectors/platform/_generators-75b6b94
WAPPIE_CLOUD ?= ../whatserver2/commercial
WAPPIE_CLOUD_COMMIT ?= 3bfee279581ad15f6d2d2db3d3a9794c8eac50ca
WAPPIE_CLOUD_PATCH ?= vectors/wappie/_generators/cloud/header-0x03.patch

.PHONY: all test test-go test-go-1.26.7 test-js test-browser test-browser-linux lint-go cross vectors-check manifest vectors-kit vectors-regen-check vectors-platform-check vectors-platform-regen vectors-cloud-regen-check pack reproduce clean

all: lint-go test-go test-js vectors-check cross

test: test-go test-js

lint-go:
	test -z "$$(gofmt -l $(GO_FILES))"
	go vet $(GO_PACKAGES)

test-go:
	go test -race -count=1 $(GO_PACKAGES)

# The seeded replays of Wappie's Go vectors run only on the toolchain that
# wrote them; on any other they skip and say so.
test-go-1.26.7:
	GOTOOLCHAIN=go1.26.7 go test -race -count=1 $(GO_PACKAGES)

test-js:
	cd js && npm ci --ignore-scripts --no-audit --no-fund && npm run typecheck && npm test && npm run build

# The vector specs in real browsers. Needs Playwright's browsers once:
# cd js && npx playwright install chromium firefox webkit
test-browser:
	cd js && npm run test:browser

# The specs of CI's js-browser job, in the browser versions it installs, on
# Linux, where Playwright's WebKit is WPE WebKit, whose WebCrypto is
# libgcrypt's rather than Safari's (SPEC section 13). Needs Docker; runs the
# committed tree in the Playwright image of js/package.json's playwright
# version, and passes KIT_BROWSERS through (KIT_BROWSERS=webkit make
# test-browser-linux). Two things differ from CI: vitest runs on the image's
# Node (24 in v1.63.0-noble), not js/.node-version's 22, and the image runs
# on the host's architecture (aarch64 on Apple silicon), not CI's x86_64.
PLAYWRIGHT_IMAGE ?= mcr.microsoft.com/playwright:v$$(node -p "require('./js/package.json').devDependencies.playwright")-noble
test-browser-linux:
	git archive --format=tar HEAD | docker run --rm -i --ipc=host -e KIT_BROWSERS $(PLAYWRIGHT_IMAGE) \
		bash -c 'mkdir /kit && tar -x -C /kit && cd /kit/js && npm ci --ignore-scripts --no-audit --no-fund && npm run test:browser'

# Fresh round trips: each language writes vectors with fresh keys and the
# other opens them.
cross:
	tmp=$$(mktemp -d) && \
	KIT_CROSS_OUT=$$tmp/go go test -count=1 -run TestWriteCrossVectors ./internal/cross && \
	(cd js && KIT_CROSS_OUT=$$tmp/ts npx vitest run test/cross.spec.ts) && \
	KIT_CROSS_IN=$$tmp/ts go test -count=1 $(GO_PACKAGES) && \
	(cd js && KIT_CROSS_IN=$$tmp/go npx vitest run) && \
	rm -rf "$${tmp:?}"

vectors-check:
	cd vectors && shasum -a 256 -c MANIFEST.sha256 --quiet

manifest:
	cd vectors && find wappie kit platform -type f | LC_ALL=C sort | xargs shasum -a 256 > MANIFEST.sha256

# Writes vectors/kit/*.json from both languages, at release time, into a
# temporary directory, and adds only the files vectors/kit does not hold yet:
# files of a tagged release never change.
vectors-kit:
	tmp=$$(mktemp -d) && \
	KIT_CROSS_OUT=$$tmp go test -count=1 -run TestWriteCrossVectors ./internal/cross && \
	(cd js && KIT_CROSS_OUT=$$tmp npx vitest run test/cross.spec.ts) && \
	for f in $$tmp/*.json; do n=$$(basename "$$f"); if [ -e "vectors/kit/$$n" ]; then echo "kept vectors/kit/$$n"; else cp "$$f" "vectors/kit/$$n" && echo "added vectors/kit/$$n"; fi; done && \
	rm -rf "$${tmp:?}"
	$(MAKE) manifest

# Regenerates Wappie's vectors from Wappie's code at WAPPIE_COMMIT into a
# temporary directory and compares them with the committed ones. The three
# files of Wappie's platform wrap (golden/platform-wrap-go.json,
# golden/platform-wrap-ts.json, legacy/platform-wrap-vectors.json) come from
# Wappie's console, not from WAPPIE_COMMIT, so this diff leaves them out;
# vectors-cloud-regen-check checks them byte for byte.
vectors-regen-check:
	tmp=$$(mktemp -d) && \
	vectors/wappie/_generators/run.sh $(WAPPIE) $(WAPPIE_COMMIT) $$tmp && \
	diff -r -x platform-wrap-go.json -x platform-wrap-ts.json $$tmp/golden vectors/wappie/golden && \
	diff -r -x platform-wrap-vectors.json $$tmp/legacy vectors/wappie/legacy && \
	rm -rf "$${tmp:?}" && echo "vectors reproduce from $(WAPPIE_COMMIT)"

# Regenerates the vectors of Wappie's platform wrap (SPEC section 6.8) from
# the code of Wappie's console (github.com/thehappieco/wappie-cloud, checked
# out at WAPPIE_CLOUD) at WAPPIE_CLOUD_COMMIT, with WAPPIE_CLOUD_PATCH
# applied, into a temporary directory, and compares them with the committed
# ones byte for byte (vectors/wappie/_generators/run-cloud.sh; the console's
# repository is only read). Once the console commits the header 0x03 itself,
# make vectors-cloud-regen-check WAPPIE_CLOUD_COMMIT=<that commit> WAPPIE_CLOUD_PATCH=
# checks that commit: its own testdata/vectors.json must be the kit's legacy
# copy byte for byte, and its modules must write the golden files' cases
# unchanged (their generated_by.source names the other commit). Not in CI:
# the console's repository is private.
vectors-cloud-regen-check:
	tmp=$$(mktemp -d) && \
	vectors/wappie/_generators/run-cloud.sh $(WAPPIE_CLOUD) $(WAPPIE_CLOUD_COMMIT) $$tmp $(WAPPIE_CLOUD_PATCH) && \
	cmp -s $$tmp/legacy/platform-wrap-vectors.json vectors/wappie/legacy/platform-wrap-vectors.json || { echo "the console's testdata/vectors.json at $(WAPPIE_CLOUD_COMMIT) is not vectors/wappie/legacy/platform-wrap-vectors.json"; exit 1; } && \
	for f in platform-wrap-go.json platform-wrap-ts.json; do \
		if [ -n "$(WAPPIE_CLOUD_PATCH)" ]; then cmp -s $$tmp/golden/$$f vectors/wappie/golden/$$f; \
		else node -e 'const [a, b] = process.argv.slice(1).map((p) => JSON.parse(require("fs").readFileSync(p, "utf8")).cases); process.exit(JSON.stringify(a) === JSON.stringify(b) ? 0 : 1)' $$tmp/golden/$$f vectors/wappie/golden/$$f; fi || \
		{ echo "$$f differs from what $(WAPPIE_CLOUD_COMMIT) writes"; exit 1; }; \
	done && \
	rm -rf "$${tmp:?}" && echo "the platform-wrap vectors reproduce from $(WAPPIE_CLOUD_COMMIT)"

# Regenerates the platform's id-v1 vectors from the platform's code at
# PLATFORM_COMMIT (git archive into a temporary directory; the platform's
# repository is only read), compares each file it writes with the committed
# one, and fails unless it wrote exactly PLATFORM_FILES files. At the default,
# 75b6b94, that is all fourteen; the part-3 check is
# make vectors-platform-check PLATFORM_COMMIT=b5d9f69a4836736e792914b20d7c2c4ce573fedf PLATFORM_FILES=13
# the part-2 check
# make vectors-platform-check PLATFORM_COMMIT=4476bf4b446297ee2b74a6f032fede7786345327 PLATFORM_FILES=11
# and the part-1 check
# make vectors-platform-check PLATFORM_COMMIT=5e66d841145b33dcd73cd575f2816a866793d774 PLATFORM_FILES=8
# Not in CI: the platform's repository is private.
vectors-platform-check:
	tmp=$$(mktemp -d) && \
	git -C $(PLATFORM) archive $(PLATFORM_COMMIT) | tar -x -C $$tmp && \
	(cd $$tmp && go run ./tools/vectors -out $$tmp/out) && \
	for f in $$tmp/out/*.json; do n=$${f##*/}; if [ ! -e "vectors/platform/id-v1/$$n" ]; then echo "$$n from $(PLATFORM_COMMIT) is not in the kit"; exit 1; fi; cmp -s "$$f" "vectors/platform/id-v1/$$n" || { echo "$$n differs from $(PLATFORM_COMMIT)"; exit 1; }; done && \
	n=$$(ls $$tmp/out | wc -l | tr -d ' ') && \
	{ test "$$n" -eq $(PLATFORM_FILES) || { echo "the generator at $(PLATFORM_COMMIT) wrote $$n files, want $(PLATFORM_FILES)"; exit 1; }; } && \
	echo "$$n of $$(ls vectors/platform/id-v1 | wc -l | tr -d ' ') platform files reproduce from $(PLATFORM_COMMIT)" && \
	rm -rf "$${tmp:?}"

# Regenerates every platform id-v1 file from the kit's own copy of the
# platform's generator at 75b6b94 (PLATFORM_GENERATOR), which builds on the
# standard library and profiles/platform alone, as a throwaway module against
# this working tree: it runs the generator's own tests, writes the files into
# a temporary directory and compares each with the kit's byte for byte. The
# module takes the platform's module path only so that the generator's own
# import resolves, and the kit's go.sum, so every dependency is checked
# against the kit's hashes. Needs neither the platform's repository nor its
# toolchain, so CI runs it on go1.26.7: since 75b6b94 the generator is a pure
# function of the kit's code, and a file that comes out differently is a
# regression of the kit.
vectors-platform-regen:
	tmp=$$(mktemp -d) && kit=$$(pwd) && \
	cp -R $(PLATFORM_GENERATOR)/. $$tmp/ && cp go.sum $$tmp/go.sum && \
	printf 'module github.com/thehappieco/platform\n\ngo 1.26\n\nrequire github.com/thehappieco/kit v0.0.0\n\nreplace github.com/thehappieco/kit => %s\n' "$$kit" > $$tmp/go.mod && \
	(cd $$tmp && GOFLAGS=-mod=mod go mod tidy && GOFLAGS=-mod=mod go test -count=1 ./... && GOFLAGS=-mod=mod go run ./tools/vectors -out $$tmp/out) && \
	n=0 && for f in vectors/platform/id-v1/*.json; do b=$${f##*/}; cmp -s "$$f" "$$tmp/out/$$b" || { echo "$$b: the generator at $(PLATFORM_GENERATOR) writes other bytes"; exit 1; }; n=$$((n+1)); done && \
	{ test "$$(ls $$tmp/out | wc -l | tr -d ' ')" -eq "$$n" || { echo "the generator at $(PLATFORM_GENERATOR) writes files the kit does not hold"; exit 1; }; } && \
	echo "all $$n platform files reproduce from $(PLATFORM_GENERATOR) on this tree" && \
	rm -rf "$${tmp:?}"

pack:
	cd js && node scripts/pack.mjs

# Builds the tarball twice from clean and compares.
reproduce:
	cd js && node scripts/pack.mjs --reproduce

clean:
	rm -rf js/dist js/*.tgz
