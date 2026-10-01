# The kit's checks, the same ones CI runs. Go runs on the explicit package
# list rather than ./..., so a stray .go file under js/node_modules is never
# picked up.

GO_PACKAGES = $$(go list ./... | grep -v /js/)
GO_FILES = $$(find . -name '*.go' -not -path './js/*' -not -path './.git/*')
WAPPIE ?= ../whatserver2
WAPPIE_COMMIT ?= 8c0c1f74103bc6bb65a93b13613ad1964d4399c4
PLATFORM ?= ../platform
PLATFORM_COMMIT ?= 5e66d841145b33dcd73cd575f2816a866793d774

.PHONY: all test test-go test-go-1.26.7 test-js test-browser lint-go cross vectors-check manifest vectors-kit vectors-regen-check vectors-platform-check pack reproduce clean

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
# temporary directory and compares them with the committed ones.
vectors-regen-check:
	tmp=$$(mktemp -d) && \
	vectors/wappie/_generators/run.sh $(WAPPIE) $(WAPPIE_COMMIT) $$tmp && \
	diff -r $$tmp/golden vectors/wappie/golden && diff -r $$tmp/legacy vectors/wappie/legacy && \
	rm -rf "$${tmp:?}" && echo "vectors reproduce from $(WAPPIE_COMMIT)"

# Regenerates the platform's id-v1 vectors from the platform's code at
# PLATFORM_COMMIT (git archive into a temporary directory; the platform's
# repository is only read) and compares them with the committed ones. Not in
# CI: the platform's repository is private.
vectors-platform-check:
	tmp=$$(mktemp -d) && \
	git -C $(PLATFORM) archive $(PLATFORM_COMMIT) | tar -x -C $$tmp && \
	(cd $$tmp && go run ./tools/vectors -out $$tmp/out) && \
	diff -r $$tmp/out vectors/platform/id-v1 && \
	rm -rf "$${tmp:?}" && echo "platform vectors reproduce from $(PLATFORM_COMMIT)"

pack:
	cd js && node scripts/pack.mjs

# Builds the tarball twice from clean and compares.
reproduce:
	cd js && node scripts/pack.mjs --reproduce

clean:
	rm -rf js/dist js/*.tgz
