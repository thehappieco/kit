# Changelog

One version covers both languages. Before 1.0.0 a minor version may change APIs but never bytes; a patch changes neither.

## v0.2.0

The release date is the tag's.

- The platform profile, part 1 (SPEC section 11), in Go (`profiles/platform`) and TypeScript (`@thehappieco/kit/profiles/platform`): the account core of the platform's protocol id-v1, taken from the platform at `5e66d84`. It covers:
  - the password profile `thehappie-password/v1`: NFC, mapped spaces, controls refused, 12 to 256 code points, and runs of more than 30 combining marks refused so that Go and ICU prepare the same bytes;
  - the KDF floor and ceiling, refused before anything is derived, with the salt the server hands out (no salt is ever drawn);
  - the 62-byte root wrap, bound by a restricted JCS AAD to the account and the epoch, never the email, and self-tested when sealed;
  - the recovery code's canonical form;
  - per-product keys and the server's check of their public keys (canonical, not of low order);
  - the server verifiers, email normalisation, strict base64url, and the strict key-bundle reader.
- The profile reuses the kit's schemes with the platform's values: Argon2id and the split, the recovery branches and the wrap envelope through `account`, the AAD through `jcs`, product public keys through `hpke`. In TypeScript, derived wrap keys are non-extractable `CryptoKey`s. The Go API keeps the names and signatures of the platform's `internal/crypto/idcrypto`, without the product registry and the ceremony helpers, which stay in the platform.
- Vectors: the platform's id-v1 vectors (257 cases, 180 of which must fail), byte for byte from platform commit `5e66d84`, under `vectors/platform/id-v1/`, with the platform's generator for provenance. Both languages reproduce every case and refuse every must-fail case with its exact error, the TypeScript side in Node and in Chromium, Firefox and WebKit. `make cross` also round-trips the platform profile in both directions, and `vectors/kit/platform-{go,ts}.json` keep those cases as golden vectors. `make vectors-platform-check` regenerates the platform's files from its commit.
- Added, changing nothing that exists:
  - Go: `account.DerivePrepared`.
  - TypeScript: `account.derivePrepared` (and `bind(p).derivePrepared`), `bytes.fromBase64URL`, `bytes.isBase64URL`, `errors.PlatformError`, `errors.isPlatformError`, `errors.PlatformErrorCode` and `errors.Base64Error`.
  - `vectors.FS` also holds `platform/`.
- The Go module now requires `golang.org/x/text` (v0.42.0, which needs Go 1.26.0 or later) for NFC.
- The npm tarball also holds `dist/internal/`, the platform profile's implementation behind its subpath; it is not a subpath export. Every byte of the tarball is new, so an enclave that measures it measures a new image even if it does not import the new subpath.
- `make vectors-kit` adds only the files `vectors/kit` does not hold yet, so it never rewrites a tagged file.
- Nothing changes for Wappie: its profile, its vectors and every byte they pin are as in v0.1.0.
- The Nitro attestation verifier, the AI keychain and derived records, announced for this version, move to a later one; their vectors stay as captured.

## v0.1.0

The release date is the tag's.


- First version, extracted from Wappie at `8c0c1f74103bc6bb65a93b13613ad1964d4399c4`: HPKE, the sealed envelope with content keys, rows, grants and the `Sealer`, the Argon2id account scheme with wraps and recovery codes, the passkey PRF wrap, the browser key at rest, the request HMAC and RFC 8785.
- Labels, prefixes, magic bytes, kind names and AAD builders are parameters, grouped in profiles; the Wappie profile ships frozen.
- New in Go: the account scheme, the passkey wrap and JCS, pinned to Wappie's TypeScript by its vectors, with ECMAScript's `trim`, `toLowerCase` and `toUpperCase` where Wappie's wire bytes depend on them.
- Changes from Wappie that change no byte of any output that opens today: errors carry codes; TypeScript checks that ids are 16 bytes and that epochs and content key ids fit their fields (an epoch of 65536 used to seal an envelope nobody could open), and that a generated key's PKCS#8 export has the expected form; Go reports a low-order encapsulated key as `authentication` like every other direct-mode failure; `hpke.importArchiveKey` is `importPrivateKey`; the `Sealer` takes a clock option instead of a test hook; `KeyStore` no longer declares `CountSeal`, which the `Sealer` never called.
- Checks Wappie did not have, each refusing only input that never produced openable data:
  - TypeScript HPKE rejects an all-zero X25519 output itself (RFC 9180 §7.1.4) instead of relying on WebCrypto: a forged grant under a low-order encapsulated key does not open, and nothing is sealed to a low-order public key (`invalid_key`, also in Go). The vectors carry real forgeries, and the TypeScript tests also run them on an engine that lets the zeros through.
  - The account profile's bounds can fix the salt's length (the platform's policy: 16 bytes).
  - A passkey wrap refuses an empty AAD (`bad_aad`); Wappie's JSON AADs are built with JCS, so a binding with no JSON text (a lone surrogate, invalid UTF-8) is refused rather than escaped, and Go's `PasskeyAAD` returns an error instead of nil.
  - The prepared password, the master key and the raw wrap key are zeroed after a derivation, in the worker too; so are the PKCS#8 buffers `hpke` builds to import a private key and exports to generate one.
- Vectors: Wappie's six fixtures byte for byte, golden vectors from Wappie's Go and TypeScript, vectors for v0.2.0's attestation, keychain and derived records, and the kit's own vectors in both directions.
- CI runs the TypeScript vectors in Chromium, Firefox and WebKit, and a release is published only when every job passes on a commit of `main`, with the Node and npm versions pinned.
