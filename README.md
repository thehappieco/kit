# The Happie Co kit

The client-side cryptography The Happie Co's products share, in Go and TypeScript, with one specification ([SPEC.md](SPEC.md)) and one set of test vectors ([vectors/](vectors/)) that both languages reproduce byte for byte.

It was extracted from [Wappie](https://github.com/thehappieco/wappie) at commit `8c0c1f74103bc6bb65a93b13613ad1964d4399c4`, and every vector Wappie's code produced, along with every fixture Wappie already had, is reproduced by both implementations here. Data Wappie has already sealed keeps opening.

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
| The vectors, embedded for consumers' tests | `vectors` | |

## Profiles

Labels, AAD prefixes, magic bytes, kind names and AAD builders are parameters, grouped in a profile; every function takes one. The Wappie profile (`whatserver2/...`, `wsv1`, `wappie/...`) ships here, frozen, so Wappie's data opens unchanged. The platform's profile (`thehappie-id/v1/...`) arrives with its vector package; the room left for it, per-product key derivation, root wraps, sealed key delivery and the product contract, is SPEC.md section 11.

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

The tarball is reproducible: `cd js && npm ci --ignore-scripts && node scripts/pack.mjs` rebuilds it from the tag byte for byte. Bundlers that pre-bundle dependencies (Vite in development) should exclude `@thehappieco/kit`, or pass `derive(..., { worker })`, so Argon2id runs in its worker rather than falling back to the main thread.

One version tag, `vX.Y.Z`, covers both languages; `js/package.json` always carries the same version.

## Working on it

```
make test              # Go (race) and TypeScript (typecheck, tests, build)
make test-go-1.26.7    # with the byte-for-byte replays of Wappie's Go vectors
make cross             # fresh vectors in each direction, opened by the other language
make lint-go vectors-check reproduce
```

The Go code must compile with Go 1.26.7; CI builds and tests it with exactly that toolchain. Everything in this repository is written in English (the platform's decision 0021); products map the kit's error codes to their own messages.

What stays in Wappie: WhatsApp media encryption, contact packs, its draft ledger and row identities, the reader's consent labels, and its API client. The Nitro attestation verifier, the AI keychain and derived records move in v0.2.0; their vectors are already captured here.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Report vulnerabilities as described in [SECURITY.md](SECURITY.md).
