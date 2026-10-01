# The Happie Co kit

The client-side cryptography The Happie Co's products share, in Go and TypeScript, with one specification ([SPEC.md](SPEC.md)) and one set of test vectors ([vectors/](vectors/)) that both languages reproduce byte for byte.

It was extracted from [Wappie](https://github.com/thehappieco/wappie) at commit `8c0c1f74103bc6bb65a93b13613ad1964d4399c4`, and every vector Wappie's code produced, along with every fixture Wappie already had, is reproduced by both implementations here. Data Wappie has already sealed keeps opening. The platform profile was taken from the platform's identity service at commit `5e66d84`, and both implementations reproduce the 257 vectors of its protocol `id-v1` unchanged.

| | Go (`github.com/thehappieco/kit/...`) | TypeScript (`@thehappieco/kit/...`) |
|---|---|---|
| HPKE, RFC 9180 base mode with one fixed suite | `hpke` | `hpke` |
| The sealed envelope: direct and batch mode, content keys, rows, grants, the `Sealer` | `seal` | `seal` |
| The zero-knowledge account scheme: Argon2id, the auth/wrap split, wraps, recovery codes | `account` | `account`, `kdf.worker` |
| Passkey PRF wraps and the PRF evaluation salt | `passkey` | `passkey` |
| A key at rest in the browser | | `browserAccount` |
| Request signing between services (HMAC, header grammar, replay cache) | `reqhmac` | `reqhmac` |
| RFC 8785 JSON for additional data | `jcs` | `jcs` |
| Byte and UUID helpers | | `bytes`, `errors` |
| The Wappie profile | `profiles/wappie` | `profiles/wappie` |
| The platform profile, part 1: the account core of id-v1 (password profile, KDF policy, root wraps, recovery code, product keys, verifiers, email, key bundle) | `profiles/platform` | `profiles/platform` |
| The vectors, embedded for consumers' tests | `vectors` | |

## Profiles

Labels, AAD prefixes, magic bytes, kind names and AAD builders are parameters, grouped in a profile; every function of the generic packages takes one. The Wappie profile (`whatserver2/...`, `wsv1`, `wappie/...`) ships here, frozen, so Wappie's data opens unchanged.

The platform profile (`thehappie-id/v1/...`, SPEC.md section 11) is the platform's protocol itself, so its functions take no profile: part 1, the account core, ships in v0.2.0 with the platform's vectors (`vectors/platform/id-v1`); part 2, sealed key delivery and the OIDC relying party, is reserved as sections 11.12 to 11.15. It reuses the generic packages with the platform's values (`account` for Argon2id, wraps and recovery branches, `jcs` for the AAD, `hpke` for product keys). What stays in the platform: the product registry, the account ceremonies built from these pieces, page rules such as refusing a password equal to the address, the decoy salts and every server secret.

## Using it

Go, through the module proxy, pinned in `go.sum` and the checksum database:

```
go get github.com/thehappieco/kit@v0.1.0
```

Do not cover this module with `GOPRIVATE`, `GONOSUMDB` or `GONOPROXY` wildcards such as `github.com/thehappieco/*`: that skips the checksum database. Name only the private repositories.

TypeScript, from the GitHub release asset (the package is not published to a registry); the lockfile records the URL and a sha512 integrity, and `npm ci` refuses other bytes:

```
npm install --save-exact https://github.com/thehappieco/kit/releases/download/v0.1.0/thehappieco-kit-0.1.0.tgz
```

Take the integrity from the published asset, never from a local build: `curl -sL <asset URL> | openssl dgst -sha512 -binary | base64` gives the part after `sha512-`, and the release notes print it. Then remove any older `node_modules/@thehappieco/kit` entry from the lockfile before `npm install`, or npm refuses the new bytes with `EINTEGRITY`.

The tar inside the tarball is reproducible: `cd js && npm ci --ignore-scripts && node scripts/pack.mjs` rebuilds it from the tag, with npm 11.9.0 and any Node 22 or later, and writes its sha256 on the `.tar` line of `SHA256SUMS`; compare it with `gunzip -c thehappieco-kit-<v>.tgz | sha256sum` of the release asset. The `.tgz` bytes around it also depend on Node's zlib: CI builds the asset with the Node in `js/.node-version` on linux-x64, and only that combination reproduces them exactly.

Bundlers that pre-bundle dependencies (Vite in development) should exclude `@thehappieco/kit` (`optimizeDeps: { exclude: ['@thehappieco/kit'] }`), or pass `derive(..., { worker })`, so Argon2id runs in its worker rather than falling back to the main thread.

One version tag, `vX.Y.Z`, covers both languages; `js/package.json` always carries the same version.

## Working on it

```
make test              # Go (race) and TypeScript (typecheck, tests, build)
make test-go-1.26.7    # with the byte-for-byte replays of Wappie's Go vectors
make test-browser      # the TypeScript specs in Chromium, Firefox and WebKit
make cross             # fresh vectors in each direction, opened by the other language
make lint-go vectors-check reproduce
make vectors-platform-check PLATFORM=../platform   # regenerate the platform's vectors and compare
```

The Go code must compile with Go 1.26.7; CI builds and tests it with exactly that toolchain. A `v*` tag publishes a release only after every CI job passes on the tagged commit, browsers included, and only if that commit is on `main`. Everything in this repository is written in English (the platform's decision 0021); products map the kit's error codes to their own messages.

What stays in Wappie: WhatsApp media encryption, contact packs, its draft ledger and row identities, the reader's consent labels, and its API client. The Nitro attestation verifier, the AI keychain and derived records move in a later version; their vectors are already captured here.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Report vulnerabilities as described in [SECURITY.md](SECURITY.md).
