# The Happie Co kit

The client-side cryptography The Happie Co's products share, in Go and TypeScript, with one specification ([SPEC.md](SPEC.md)) and one set of test vectors ([vectors/](vectors/)) that both languages reproduce byte for byte.

It was extracted from [Wappie](https://github.com/thehappieco/wappie) at commit `8c0c1f74103bc6bb65a93b13613ad1964d4399c4`, and every vector Wappie's code produced, along with every fixture Wappie already had, is reproduced by both implementations here. Data Wappie has already sealed keeps opening. The platform profile was taken from the platform's identity service at commits `5e66d84` (part 1), `4476bf4` (part 2) and `b5d9f69` (part 3), with the relying party rule of `75b6b94`, and both implementations reproduce the 486 vectors of its protocol `id-v1` unchanged. Wappie's platform wrap was taken from Wappie's console, whose code wrote its vectors; since v0.6.0 it is an instance of the kit's generic platform wrap, which Mailie's profile uses too, with vectors the kit wrote under Mailie's labels. THCSEAL v1, the envelope of the platform's tier-2 secrets, and its key wrappers were taken from the platform at commit `d32b663`, with the tests of `d3e8c6d`, and the kit's code opens and writes again, byte for byte, the platform's vectors of it.

| | Go (`github.com/thehappieco/kit/...`) | TypeScript (`@thehappieco/kit/...`) |
|---|---|---|
| HPKE, RFC 9180 base mode with one fixed suite | `hpke` | `hpke` |
| The sealed envelope: direct and batch mode, content keys, rows, grants, the `Sealer` | `seal` | `seal` |
| The zero-knowledge account scheme: Argon2id, the auth/wrap split, wraps, recovery codes | `account` | `account`, `kdf.worker` (Argon2id off the main thread) |
| Passkey PRF wraps, the PRF evaluation salt, and the WHATWG check of a relying party id that ends in a number | `passkey` | `passkey` |
| A key at rest in the browser | | `browserAccount` |
| Request signing between services (HMAC, header grammar, replay cache) | `reqhmac` | `reqhmac` |
| RFC 8785 JSON for additional data | `jcs` | `jcs` |
| Byte and UUID helpers | | `bytes`, `errors` |
| The platform wrap: a product's account key under a key derived from its product key `sk_p`, under the product's labels (SPEC 6.8) | `platformwrap` | `platformwrap` |
| The Wappie profile, and its platform wrap | `profiles/wappie` | `profiles/wappie` |
| The Mailie profile: its platform wrap's labels (SPEC Appendix D) | `profiles/mailie` | `profiles/mailie` |
| The platform profile, part 1: the account core of id-v1 (password profile, KDF policy, root wraps, recovery code, product keys, verifiers, email, key bundle) | `profiles/platform` | `profiles/platform`, and `profiles/platform/core` without the kit's KDF worker |
| The platform profile, part 2: sealed key delivery and PKCE | `profiles/platform` | `profiles/platform` |
| The platform profile, part 3: passkeys with PRF (the relying party id's one spelling, which does not end in a number, the PRF salt, `K_pk`, the kind-3 root wrap) and the allowlist of WebAuthn client extension results | `profiles/platform` | `profiles/platform` |
| The relying party of the platform's id., the page: begin, callback, and keeping a delivered key only once the product's server has pinned it | | `oidc-rp` |
| The relying party's server: the userinfo call and its checks, the client check, the insert-only pin | `oidcrp` | |
| THCSEAL v1, the envelope of a server's tier-2 secrets (SPEC 14): one data key per envelope, AES-256-GCM, the header and the context `{service, env, purpose, ref}` as additional data | `thcseal` | |
| Its key wrappers: the `Wrapper` interface and the context; AWS KMS with one pinned key and the instance role's credentials only; a local key-encryption key for development and tests, which compiles only with the build tag `kitdevkek` | `kms`, `kms/awskms`, `kms/localkek` | |
| The vectors, embedded for consumers' tests | `vectors` | |

## Profiles

Labels, AAD prefixes, magic bytes, kind names and AAD builders are parameters, grouped in a profile; every function of the generic packages takes one. The Wappie profile (`whatserver2/...`, `wsv1`, `wappie/...`) ships here, frozen, so Wappie's data opens unchanged; since v0.5.0 it also holds Wappie's platform wrap (SPEC section 6.8, the platform's decision 0023): Wappie's account key wrapped under a key derived from its product key `sk_p`, 61 bytes with the header `0x03`, bound to Wappie's user id, the platform's `sub`, the `product_key_id` and the account's public key, so that a person who signs in through id. opens what Wappie sealed before, and Wappie's export opens from the key bundle. It was taken from Wappie's console with one byte changed, the header, which was `0x01`, the passkey envelope's.

Since v0.6.0 the platform wrap is generic (`platformwrap` in both languages): a profile names the product of the `product_key_id`, the HKDF salt and the label that opens the info and the AAD, and the header `0x03`, the length and the layout are the same for every product. Wappie's wrap is the profile `wappie.PlatformWrap()` (`wappiePlatformWrap`), to which every v0.5.0 name of `profiles/wappie` is bound, with every byte unchanged. The Mailie profile (`profiles/mailie`) holds Mailie's labels, `mailie/platform-wrap/v1` and `mailie/platform-wrap`, and nothing else of Mailie's yet, with golden vectors the kit wrote (`vectors/mailie/`), among them a Wappie wrap refused under Mailie's labels and the reverse. A product's wraps open only under its own profile; their shape is the same, so each product keeps them in a column of its own, and none of its other envelopes of the account key may start with `0x03`.

The platform profile (`thehappie-id/v1/...`, SPEC.md section 11) is the platform's protocol itself, so its functions take no profile: part 1, the account core, ships since v0.2.0; part 2, sealed key delivery, PKCE and the relying party of its OpenID Connect provider (sections 11.12 to 11.15), since v0.3.0; and part 3, passkeys with PRF (section 11.16: the key a passkey's PRF output gives for the root wrap, and the allowlist of the client extension results the id. server accepts), since v0.4.0, all with the platform's vectors (`vectors/platform/id-v1`). Since v0.5.0 a relying party id that ends in a number by the WHATWG URL Standard (`0x7f000001`, `id.0xff`), which a browser reads as an IPv4 address or refuses, is refused too, as on the platform's server. Section 11.17 (the product contract) is reserved; it follows with the platform's Phase 3. Products run no WebAuthn for platform accounts (the platform's decision 0008): part 3 is for the id. page and the platform's server, and names no product. It reuses the generic packages with the platform's values (`account` for Argon2id, wraps and recovery branches, `jcs` for the AAD, `hpke` for product keys and their delivery, `passkey` for the PRF salt and the passkey wrap key).

The relying party is product-neutral: a product passes its issuer, its `client_id`, its redirect URI, its scopes and its key label (`wappie` for `wappie:1`). HPKE base mode does not authenticate the sender, so the page keeps a delivered key only once its own server has named the same `sub`, `product_key_id` and `product_key` from its insert-only pin: use `finishSignIn` (or `callback` then `keepProductKey`) on the page and `oidcrp.Client.Login` on the server, behind a session endpoint that reads only a POST with the page's own `Origin`, `Sec-Fetch-Site: same-origin` and a JSON body (the package's session handler example), or another site could open a session there for an account of its choosing.

What stays in the platform: the id. server (the client registry, the endpoints, the signing keys, the bind cookie and the blob at rest), the WebAuthn ceremony (the options, `navigator.credentials`, reading the PRF output out of a credential, the credential the page sends, go-webauthn on the server), the id. page's screens, the product registry, the account ceremonies built from these pieces, page rules such as refusing a password equal to the address, the decoy salts, every server secret, and the generator of the vectors. What stays in each product: its session endpoint and session, its pin table and the alert on `account_key_changed`, its vault, its CSP and the callback's headers and logging, and its own check of the relying party id it configures (the kit exports the WHATWG check, `passkey.EndsInANumber` and `endsInANumber`).

## Using it

Go, through the module proxy, pinned in `go.sum` and the checksum database:

```
go get github.com/thehappieco/kit@v0.6.0
```

Do not cover this module with `GOPRIVATE`, `GONOSUMDB` or `GONOPROXY` wildcards such as `github.com/thehappieco/*`: that skips the checksum database. Name only the private repositories.

The kit is one module. Of its packages only `kms/awskms` imports the AWS SDK (`make imports-check` holds it to that): a module that never imports `kms/awskms` compiles nothing of the SDK, downloads none of it, and its `go.mod` and `go.sum` after `go mod tidy` are what they would be without it. Two things still see the SDK's modules, because they are in the kit's `go.mod`: `go list -m all`, and with it SBOM tools and dependency alerts, names them; and minimal version selection raises a module that requires older versions of them to the kit's, which are the platform's (`aws-sdk-go-v2` v1.47.1, `credentials` v1.20.6, `feature/ec2/imds` v1.20.1, `service/kms` v1.61.1).

`kms/localkek`, the local key-encryption key, compiles only with the build tag `kitdevkek`, so a release build, which passes no tag, cannot link it. A module that seals under it in its tests passes `-tags kitdevkek` to those tests, to `go vet` and to its linters (for example `GOFLAGS=-tags=kitdevkek`), and to its development builds that select it (the platform's `-tags dev,kitdevkek`); so does a run of the kit's own tests of `thcseal` and `kms/awskms` from a consumer, such as the platform's `make kit-test`, or they fail with a test that says so. THCSEAL's package is `thcseal`, because the kit's `seal` is Wappie's envelope; its names are the platform's, so the platform imports it as `seal "github.com/thehappieco/kit/thcseal"`, and its error messages start `thcseal:`.

TypeScript, from the GitHub release asset (the package is not published to a registry); the lockfile records the URL and a sha512 integrity, and `npm ci` refuses other bytes:

```
npm install --save-exact https://github.com/thehappieco/kit/releases/download/v0.6.0/thehappieco-kit-0.6.0.tgz
```

Take the integrity from the published asset, never from a local build: `curl -sL <asset URL> | openssl dgst -sha512 -binary | base64` gives the part after `sha512-`, and the release notes print it. Then remove any older `node_modules/@thehappieco/kit` entry from the lockfile before `npm install`, or npm refuses the new bytes with `EINTEGRITY`.

The tar inside the tarball is reproducible: `cd js && npm ci --ignore-scripts && node scripts/pack.mjs` rebuilds it from the tag, with npm 11.9.0 and any Node 22 or later, and writes its sha256 on the `.tar` line of `SHA256SUMS`; compare it with `gunzip -c thehappieco-kit-<v>.tgz | sha256sum` of the release asset. The `.tgz` bytes around it also depend on Node's zlib: CI builds the asset with the Node in `js/.node-version` on linux-x64, and only that combination reproduces them exactly.

Argon2id runs in the kit's KDF worker, `dist/kdf.worker.js`, which `@thehappieco/kit/account` and `@thehappieco/kit/profiles/platform` start where there are Workers; a bundler emits that file for any page that imports them. A page that derives with a worker of its own, or never derives, imports `@thehappieco/kit/profiles/platform/core` instead: the same exports, but `derivePassword`, `derivePasswordKeys` and `openKeyBundle` run Argon2id only in the worker `options.worker` makes, or on the calling thread, and nothing it reaches names the worker file. `@thehappieco/kit/oidc-rp` reaches none either. With Vite, the core entry gets the kit's worker with `import KDFWorker from '@thehappieco/kit/kdf.worker?worker'` and `{ worker: () => new KDFWorker() }`. The page sends the worker the password only after the worker has answered its hello, as a transferred copy, and a worker that fails after that is `kdf_failed`, not retried (SPEC section 13). Bundlers that pre-bundle dependencies (Vite in development) should exclude `@thehappieco/kit` (`optimizeDeps: { exclude: ['@thehappieco/kit'] }`), or pass `derive(..., { worker })`, so Argon2id runs in its worker rather than falling back to the main thread.

One version tag, `vX.Y.Z`, covers both languages; `js/package.json` always carries the same version.

## Working on it

```
make test              # Go (race) and TypeScript (typecheck, tests, build)
make test-go-1.26.7    # with the byte-for-byte replays of Wappie's Go vectors
make test-browser      # the TypeScript specs in Chromium, Firefox and WebKit
make test-browser-linux   # the same in Playwright's Linux image (Docker), where WebKit is WPE with libgcrypt: CI's browser versions, but the image's Node 24 and the host's architecture
make cross             # fresh vectors in each direction, opened by the other language
make lint-go vectors-check reproduce
make vectors-platform-check PLATFORM=../platform   # regenerate all fourteen of the platform's files at 75b6b94 and compare
make vectors-platform-check PLATFORM=../platform PLATFORM_COMMIT=b5d9f69 PLATFORM_FILES=13   # the thirteen files of parts 1 to 3 at b5d9f69
make vectors-platform-check PLATFORM=../platform PLATFORM_COMMIT=4476bf4 PLATFORM_FILES=11   # the eleven files of parts 1 and 2 at 4476bf4
make vectors-platform-check PLATFORM=../platform PLATFORM_COMMIT=5e66d84 PLATFORM_FILES=8   # the eight part-1 files at 5e66d84
make vectors-platform-regen   # the same fourteen files from the kit's own copy of the platform's generator, against this tree (CI runs it)
make vectors-regen-check WAPPIE=../whatserver2   # Wappie's vectors from Wappie's code at 8c0c1f7
make vectors-cloud-regen-check WAPPIE_CLOUD=../whatserver2/commercial   # the platform wrap's vectors from Wappie's console
make vectors-thcseal-check PLATFORM=../platform   # THCSEAL's vectors from the platform's own generator at d32b663
make vectors-mailie-regen   # Mailie's golden file from the kit's own generator, on go1.26.7, against this tree (CI runs it)
make imports-check     # only tests link kms/localkek, only kms/awskms links the AWS SDK, and everything builds without the tag
make identifiers-check   # no identifier of a real AWS account in any commit (KIT_IDENTIFIERS="$(cat <the owner's list>)" make identifiers-check)
```

The Go targets pass `-tags kitdevkek` (`GO_TAGS`); a plain `go test ./...` fails in `thcseal` and `kms/awskms` and says why. The repository is public, history included, so it names no identifier of a real AWS account: AWS's documentation placeholders only (`111122223333`, `alias/example-alias`, `example-…` roles). `make identifiers-check`, which CI runs over every commit and commit message, refuses the classes of identifier and the owner's private list, which CI takes from the repository secret `KIT_IDENTIFIERS` and a local run from that variable or from `identifiers.local.txt` (git-ignored); the list is never committed. Run it before pushing: a value committed and then removed is still published.

The Go code must compile with Go 1.26.7; CI builds and tests it with exactly that toolchain. A `v*` tag publishes a release only after every CI job passes on the tagged commit, browsers included, and only if that commit is on `main`. Everything in this repository is written in English (the platform's decision 0021); products map the kit's error codes to their own messages.

What stays in Wappie: WhatsApp media encryption, contact packs, its draft ledger and row identities, the reader's consent labels, and its API client. The Nitro attestation verifier, the AI keychain and derived records move in a later version; their vectors are already captured here.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Report vulnerabilities as described in [SECURITY.md](SECURITY.md).
