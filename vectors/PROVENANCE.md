# Provenance

## Wappie's vectors

- **Source:** `github.com/thehappieco/wappie`, `main` at `8c0c1f74103bc6bb65a93b13613ad1964d4399c4`.
- **Captured:** 2026-10-01, before any code moved, by `wappie/_generators/run.sh`. The script extracts that commit with `git archive` into a temporary directory (so the tree is exactly the commit, with nothing uncommitted), copies the generators beside the code they exercise, runs them there, and copies the legacy fixtures. Wappie's repository is only read.
- **Toolchains:** go1.26.7 (darwin/arm64); Node v25.6.1 with npm 11.9.0; `@noble/hashes` 2.4.0 and vitest 3.2.7 as locked by Wappie's `packages/client/package-lock.json` at that commit, which vitest uses to transpile the client's TypeScript sources.
- **Determinism:** the Go generators reset `testing/cryptotest.SetGlobalRandom` to the seed recorded in each seeded case; the TypeScript generators replace `crypto.getRandomValues` and X25519 key generation with an HMAC-SHA256 stream keyed by the case id, and each case records the bytes it consumed. Running the script again at the same commit with the same toolchains writes identical files; `make vectors-regen-check` does that and compares.
- **Never** run Wappie's own tests with `-update` to refresh these: that flag rewrites Wappie's fixtures with fresh random keys.

### wappie/golden

| File | Module | Cases | Writer | Wappie code it captures | Toolchain | sha256 |
|---|---|---|---|---|---|---|
| `seal-go.json` | seal | 442 | Go | `internal/crypto/seal` | go1.26.7 | `404c9325bf8b52ff5ddfff4427d7588e45ff6733866764f402bc4237c9ccd218` |
| `reqhmac-go.json` | reqhmac | 59 | Go | `internal/mcpauth/hmac.go` | go1.26.7 | `69cb83be0a6cd0c12bf01aec56b0641f87374a2f96695d4d2fbce8293c9ed31b` |
| `passkey-salt-go.json` | passkey | 5 | Go | `internal/authapi/passkeys.go` (the PRF salt) | go1.26.7 | `4b75807bfc4241a02012a3dc4d1dfa72680a67a8903507bef030aecab57e2e05` |
| `seal-ts.json` | seal | 31 | TS | `packages/client/src/crypto/seal.ts` | Node v25.6.1 | `a0c5cec74a00890fb5477bfe102e69e07bc67aae6af46c5500dbd7bd9c1f9d1b` |
| `hpke-ts.json` | hpke | 21 | TS | `packages/client/src/crypto/hpke.ts` | Node v25.6.1 | `a713d455c8a03795892b75c9204ddbb289c9f94b6c6cb0497e877a66426e451a` |
| `account-ts.json` | account | 136 | TS | `packages/client/src/crypto/account.ts` | Node v25.6.1 | `b08a250ce28933b279613339093fad3cc925f8fa96d40e05f6f7381e473ed282` |
| `passkey-ts.json` | passkey | 23 | TS | `packages/client/src/crypto/passkey.ts` | Node v25.6.1 | `09ac4f8231e8c87449a59cebb33635e8e244ad257a934d770a3258e801545c35` |
| `browser-account-ts.json` | browser_account | 11 | TS | `packages/client/src/crypto/browserAccount.ts` | Node v25.6.1 | `439be2055653db141bff30484484cdf6d8a3dd694686622cfb55f667537431a6` |
| `bytes-jcs-ts.json` | bytes+jcs | 89 | TS | `packages/client/src/crypto/bytes.ts`, `jcs.ts`; JCS texts from `packages/mcp-http/enclave/test/{device-check,ai-config}-vectors.json` | Node v25.6.1 | `acc301591f4690b551c70595d9c31fb7b65958fa913141d7e7503dcd4a3aa4dc` |
| `derived-ts.json` | derived (later) | 22 | TS | `packages/client/src/crypto/derived.ts` | Node v25.6.1 | `1126b160b4ce9a0af5dff96aa4bef6a956114a9923d11de1b6d977b59908a942` |
| `keychain-ts.json` | keychain (later) | 6 | TS | `packages/client/src/crypto/aikeychain.ts` | Node v25.6.1 | `289610947d434178e9bde5544183d07d6e37a92213456b7eb519d696964a7859` |
| `attestation-ts.json` | attestation (later) | 7 | TS | `packages/client/src/crypto/attestation.ts` (user_data) | Node v25.6.1 | `1712c2b61cf2bf121f6e5712e62d66737124f9fd1b8666df8625b5693aacc906` |

Where Wappie's code keeps a value private (an AAD, a non-extractable key), the generator computed it independently and recorded it only after proving it against the code's output (a blob the code produced decrypts under it). Each file's `note` says which values those are.

Where Wappie's code returned an unclassified error, the case carries the code the kit uses and a `note` quoting Wappie's message: the key-id mismatch and the 31-byte content key (Go), the missing key (Go), an encapsulated key of low order (Go returned `seal: hpke recipient: ...`, the kit says `authentication`), and Argon2id's own parameter errors (TypeScript threw `@noble/hashes`' error, the kit says `kdf`/`kdf_failed`).

### wappie/legacy

Byte-for-byte copies at `8c0c1f74`. "Last changed" is the last Wappie commit that touched the file.

| File | Wappie path | Last changed | Written by, read by | sha256 |
|---|---|---|---|---|
| `seal-vectors.json` | `internal/crypto/seal/testdata/vectors.json` | `bd449d2` | Go writes; TS and the reader read | `31192d6dd1a6aba5dbb6200b4a9614a50a0692dd1c3e749351d6c900e97c2467` |
| `draft-vectors.json` | `internal/crypto/seal/testdata/draft-vectors.json` | `e4ff78c` | Go writes; TS reads | `b4c4aa311a556fe113ed9a98598c599c812172bde9ea15f6354c6a7c5c872762` |
| `frames.json` | `internal/wsapi/testdata/frames.json` | `bd449d2` | Go writes; TS reads | `17219bd1e59019b74c2ddaaae36c37e2cb706198866290d130517afd84622048` |
| `browser-grant.json` | `packages/client/testdata/browser-grant.json` | `b01f901` | TS writes; Go reads | `6a8aa3aaa2e8dcfb4efd0be50258f845c80d3ca4590b18eafeaf04f964265d18` |
| `node-draft.json` | `packages/client/testdata/node-draft.json` | `e4ff78c` | Node writes; Go reads | `4200c9ccf244f040ebff099255f819447ac47e3af71138b81e0900b96c5acc25` |
| `node-derived.json` | `packages/client/testdata/node-derived.json` | `3515f3b` | the enclave writes; client, reader and console read | `a9b5b504e65e5f4e48431127fd6e577fe3832fe62c00e38f0b963befa11ef8b0` |

### Baseline of fixtures that stay in Wappie

Not copied: they belong to code that stays in Wappie, or (attestation) to a module that moves into the kit later, with its verifier. Their hashes at `8c0c1f74` are recorded so Wappie's CI can check that nothing drifts (`sha256sum -c` over these lines, from Wappie's root).

```
cbfdc36c14fdf86ea59598498fe77bc7a81b54c547eab7e2acca5c8e7c1cf453  internal/crypto/wamedia/testdata/vectors.json
3c106be13e159f27ba5a102e4c836cbc05c948fef4e6a5364c9bdd4c60002c00  packages/mcp-http/enclave/test/device-check-vectors.json
a48e36ff1c5fa76443e8f6c519cb8f9d17f01503da7a6a774e1751a74263050d  packages/mcp-http/enclave/test/ai-config-vectors.json
792167cec43dec44f6f0b0c3150b5b9b58660e604076481095c4663ac9bda321  packages/mcp-http/enclave/test/send-text-vectors.json
f4f5c850f4bd096ef34c2c6d3270a1a7d11aef8ee5844d8d52a381c0e5fe3647  packages/client/testdata/attestation/README.md
798ec8c60761a79cf7aea326b8bd0aa2e18ac570f5341dce06f5076b42d78a12  packages/client/testdata/attestation/att-debug.b64
c5a21ad5345f9945dae45b9b9772e79f557498efda73a6ca374ddcc7b09fad80  packages/client/testdata/attestation/att-debug.nonce
f87ec8d89a1e4722d0080cf0a120ceef480a295d1d009f9e081acd286d0ec1be  packages/client/testdata/attestation/att.b64
e393bea4b955e5a6e6cd7feea51421a744c363fc378cf04b2bfa06d628c1e6ca  packages/client/testdata/attestation/att.nonce
388a71794da9fa7866a3ae0069ced57c96ea7a7b94aa0c2bb667b2425d0b062b  packages/client/testdata/attestation/measurements.json
31192d6dd1a6aba5dbb6200b4a9614a50a0692dd1c3e749351d6c900e97c2467  internal/crypto/seal/testdata/vectors.json
b4c4aa311a556fe113ed9a98598c599c812172bde9ea15f6354c6a7c5c872762  internal/crypto/seal/testdata/draft-vectors.json
17219bd1e59019b74c2ddaaae36c37e2cb706198866290d130517afd84622048  internal/wsapi/testdata/frames.json
6a8aa3aaa2e8dcfb4efd0be50258f845c80d3ca4590b18eafeaf04f964265d18  packages/client/testdata/browser-grant.json
4200c9ccf244f040ebff099255f819447ac47e3af71138b81e0900b96c5acc25  packages/client/testdata/node-draft.json
a9b5b504e65e5f4e48431127fd6e577fe3832fe62c00e38f0b963befa11ef8b0  packages/client/testdata/node-derived.json
```

### The Wappie sources the kit was taken from

sha256 (first 16 hex digits) at `8c0c1f74`: `internal/crypto/seal/envelope.go` `4886b166943ffeeb`, `seal.go` `c64696e4f3d377b5`, `archive.go` `6e43f4e86f64e5de`; `internal/mcpauth/hmac.go` `896ce87b9c4cbe9f`; `packages/client/src/crypto/bytes.ts` `a33eb31a64caaa6c`, `jcs.ts` `3dbe9dbba4ea2d08`, `hpke.ts` `e1efa435a7f95916`, `seal.ts` `8244270a47ca65c8`, `account.ts` `301cf066e1083694`, `kdf.worker.ts` `a8695a6e30baf924`, `passkey.ts` `d71a5cd083ae7141`, `browserAccount.ts` `8830b0a9cc426eab`.

## The platform's vectors

- **Source:** `github.com/thehappieco/platform` (private), commit `5e66d841145b33dcd73cd575f2816a866793d774` (2026-10-01), `testdata/vectors/id-v1/`. They are the golden vectors of the platform's protocol `id-v1` (its `docs/protocol/id-v1.md`, sections 1, 2 and 6), handed to the kit for SPEC section 11, part 1 (the platform's decision 0017).
- **Generator:** `go run ./tools/vectors` over `internal/crypto/idcrypto/idvectors`, a pure function of the platform's `internal/crypto/idcrypto` at that commit: every input, nonce and root comes from `HKDF(IKM = "thehappie-id/vectors/v1", info = label)`, cases are in a fixed order, and the output is 2-space indented ASCII JSON with one final newline. Each case declares its outcome, and the generator refuses to write a file whose cases do not come out that way. A copy of the generator at that commit is in `platform/_generators/` (not built, not embedded), so that a reader of this public repository can see how each case was made; it imports the platform's private code and does not build here.
- **Captured:** 2026-10-01, byte for byte with `git show <commit>:<path>`; the platform's repository was only read. The platform's working tree held the same bytes.
- **Toolchains:** the platform builds with go1.27.1, and its generator wrote these exact bytes there. On 2026-10-01 the generator was also run from that commit with go1.26.7, `golang.org/x/crypto` v0.55.0 and `golang.org/x/text` v0.42.0 (whose normalisation tables are Unicode 15.0 below Go 1.27, and Unicode 17.0 from it): the same bytes. `make vectors-platform-check PLATFORM=../platform PLATFORM_COMMIT=5e66d841145b33dcd73cd575f2816a866793d774 PLATFORM_FILES=8` repeats the check from a `git archive` of the commit, with the go the platform's `go.mod` asks for, and fails unless the generator writes exactly these eight files.
- **Format:** the platform's own (`"format": "thehappie-id/vectors", "version": 1`), described in `README.md` and SPEC section 12.2. The kit reads it with dedicated runners and never rewrites it.

| File | Kind | Cases | Must fail | sha256 |
|---|---|---|---|---|
| `platform/id-v1/password-profile.json` | password-profile | 45 | 23 | `47803646a66f8a20c5cdb02852b628a5716d1dc4854759367f7f10dba3c5294e` |
| `platform/id-v1/kdf.json` | kdf | 19 | 16 | `89b6ffe8d32a65b7c63c88763d3aab5da3f9cf064e548d8cd6abba51df7d7483` |
| `platform/id-v1/root-wrap.json` | root-wrap | 31 | 26 | `54aa88e9e89f143031b4acdc11ab01b31497c3d3a4ef3783ce121ba224733ee1` |
| `platform/id-v1/recovery-code.json` | recovery-code | 27 | 15 | `c3c57217d0a491d84f374c95ff83c5c974126884d741501fef70969ec1ab19fa` |
| `platform/id-v1/product-key.json` | product-key | 20 | 12 | `388cae00f034bef42f75e74a4a52f27ff7ff7409ed48b67ba3bc338326cb5601` |
| `platform/id-v1/verifier.json` | verifier | 10 | 5 | `394e2bf399bd1a6a23b00e067d71a2f6da70cb2c69a5a2a542efd61322f5a5e4` |
| `platform/id-v1/email.json` | email | 46 | 33 | `a0cffa73f07782d4feca2c3dea293f3e8de75164b3ee043106b0d6b0b3e0575d` |
| `platform/id-v1/key-bundle.json` | key-bundle | 59 | 50 | `364b4c24046ca70b04dbbc04ead6417445f1aa8bede2c930068cbd1adfc61a6e` |

Of the 257 cases, 180 must fail. Both of the kit's implementations reproduce every output and refuse every must-fail case with the error name it records (`profiles/platform/vectors_test.go`, `js/test/platform.spec.ts`); `vectors/vectors_test.go` checks the sha256 and the counts above, so an edited, re-copied or truncated file fails even after `make manifest` has recorded it.

### platform/_generators

| File | Platform path at `5e66d84` | sha256 |
|---|---|---|
| `internal/crypto/idcrypto/idvectors/idvectors.go` | the same | `5300db853a40802342e6e12168b53387fda17db72ec3081dff245dd89415a59b` |
| `internal/crypto/idcrypto/idvectors/password.go` | the same | `fcd109663832b09ca83c0094106115b10b00adc35f592e1112d526f4cc939fd1` |
| `internal/crypto/idcrypto/idvectors/wrap.go` | the same | `9ccf5a45a0781397cca36e7583633ea4bef7386a3d8ee50d4e7c5d040fa44cfc` |
| `internal/crypto/idcrypto/idvectors/recovery.go` | the same | `b95270beee303b98dd995f6b1b3321f7917e1173300e9d7b97c067eae1d80487` |
| `internal/crypto/idcrypto/idvectors/product.go` | the same | `b969b3640b6a9cd1516f60164e5d8a48b13a5b6220c378363ad7bd9c7ba5b4c9` |
| `internal/crypto/idcrypto/idvectors/bundle.go` | the same | `46b1f88b4a4d5e44ebf91db6273858198203103cdab3bd42a25d1c4c3a92322b` |
| `tools/vectors/main.go` | the same | `a90c912c1f8edaa4a69dec6019834d87365247a75198278dd0cd6883bbdab1f2` |

**Frozen once tagged.** After the tag that first carries them, these eight files never change in the kit, like every other vector file. The platform's own copies are rewritten whenever its generator changes, so the platform keeps the eight part-1 files as they are at `5e66d84` and sends any later case as a new file (or as `id-v2`), which the kit adds beside these.

### Part 2, at 4476bf4

- **Source:** commit `4476bf4b446297ee2b74a6f032fede7786345327` (2026-10-01T21:40:06-03:00), the platform's Phase 1c, `testdata/vectors/id-v1/{key-delivery,pkce,password-stream-safe}.json`: the golden vectors of `docs/protocol/id-v1.md` sections 7.5, 7.6 and 7.14, and the cases of the run rule of its section 2.1 step 2, which the platform adopted from the kit's SPEC section 11.2 and wrote as a new file because the part-1 files are frozen. Handed to the kit for SPEC sections 11.12 to 11.15 (the platform's decision 0017).
- **Generator:** the same tool and rules as part 1. The good key-delivery cases are sealed by idvectors' own deterministic RFC 9180 SealBase (`hpke.go`) under the case's `eph_priv`; that seal reproduces the CFRG test vector for mode 0, KEM 0x0020, KDF 0x0001, AEAD 0x0002 (`hpke_test.go`), and every blob it writes is first opened by `idcrypto.OpenProductKey` (crypto/hpke), and the same inputs sealed by `idcrypto.SealProductKey`, before the file is written.
- **Captured:** 2026-10-01, byte for byte with `git show <commit>:<path>`; the platform's repository was only read, and its working tree (at that commit, clean) held the same bytes.
- **The part-1 files at this commit** are byte for byte those of `5e66d84` (the sha256 above), so `make vectors-platform-check`, whose default commit is `4476bf4`, checks all eleven files: it fails when a file the generator writes differs from the kit's or is not in the kit, and when the generator writes other than `PLATFORM_FILES` files (11 by default).
- **Toolchains:** the platform's go1.27.1 wrote these bytes. On 2026-10-01 the generator at this commit also ran with go1.26.7 as a separate module with `golang.org/x/crypto` v0.55.0 and `golang.org/x/text` v0.42.0: the same bytes for all eleven files.
- **Case identity:** `key-delivery.json` gives five names to two cases each, one with `"op": "open"` and one with `"op": "seal"` ("a sub in upper case", "a nonce of 21 characters", "a nonce with a dot", "a code_challenge of 42 characters", "an issuer outside the AAD alphabet"). The kit identifies a case of a file whose cases carry `op` by its op and name, and cites it as `#<op>/<name>`; the platform was asked to keep `(op, name)` unique and to give later files unique names.

| File | Kind | Cases | Must fail | sha256 |
|---|---|---|---|---|
| `platform/id-v1/key-delivery.json` | key-delivery | 73 | 64 | `2d7e322b1afc9e021f0fc4707e5fc666d9626608d082b22f2782ee2d4e4d40b2` |
| `platform/id-v1/pkce.json` | pkce | 18 | 12 | `b58002e68fff370e5a9dcc49847b3d4a2b27cd2836a140eb5e1a169c9a9bd010` |
| `platform/id-v1/password-stream-safe.json` | password-stream-safe | 19 | 11 | `6c0be5a1e236fab99e97cacbff527674b76f65a9a1c5b2630bdf8558465021cc` |

With part 1, 367 cases, 267 of which must fail. Both implementations reproduce every output, the 9 sealed blobs included (by injecting the recorded ephemeral key, which only tests can), and refuse every must-fail case with the error name it records (`profiles/platform/vectors_test.go`, `js/test/platform.spec.ts`); `vectors/vectors_test.go` checks each file's sha256 and counts.

### platform/_generators-4476bf4

The generator at `4476bf4`, kept as `platform/_generators/` keeps the one at `5e66d84`. Not built, not embedded; it imports the platform's private code.

| File | sha256 | Since 5e66d84 |
|---|---|---|
| `internal/crypto/idcrypto/idvectors/idvectors.go` | `bfe7fce72b4c0257747af04e64aef3eaea31538974cb98f6c5bfccce4ddb6f19` | changed |
| `internal/crypto/idcrypto/idvectors/password.go` | `4c1f0077189e0c245419e9451289f65635ad92205010b5bf3d9eae806d9b2031` | changed |
| `internal/crypto/idcrypto/idvectors/keydelivery.go` | `3ff1ddc0b196c8fddc70be320b52b34800ac500757711676415648ceed69545f` | new |
| `internal/crypto/idcrypto/idvectors/hpke.go` | `c211f7181dda55bb43a359fbc4093cd4b5d644c7c12613b8c97a50f078497ba1` | new |
| `internal/crypto/idcrypto/idvectors/hpke_test.go` | `c3f7329fa05753dcdb25089200065dbe31c9c33cbd2d59c2324597c7641149ea` | new (the CFRG check) |
| `internal/crypto/idcrypto/idvectors/bundle.go` | `46b1f88b4a4d5e44ebf91db6273858198203103cdab3bd42a25d1c4c3a92322b` | same |
| `internal/crypto/idcrypto/idvectors/product.go` | `b969b3640b6a9cd1516f60164e5d8a48b13a5b6220c378363ad7bd9c7ba5b4c9` | same |
| `internal/crypto/idcrypto/idvectors/recovery.go` | `b95270beee303b98dd995f6b1b3321f7917e1173300e9d7b97c067eae1d80487` | same |
| `internal/crypto/idcrypto/idvectors/wrap.go` | `9ccf5a45a0781397cca36e7583633ea4bef7386a3d8ee50d4e7c5d040fa44cfc` | same |
| `tools/vectors/main.go` | `9ccd79ae63503fefe60c1adbe2d2cef325a701ce746e55f3d4ca8fa14f9b8010` | changed (doc comment) |

### The sources of part 2

sha256 (first 16 hex digits) at `4476bf4` of what the kit's part 2 was taken from: `internal/crypto/idcrypto/keydelivery.go` `79c4060a46b444f8`, `pkce.go` `99ed1d3e1cd9ad37`; `web/shared/crypto/keydelivery.ts` `9f9e0f277e753e8d`, `pkce.ts` `4867d005fc3485db`, `x25519.ts` `9d563e2a4369275f`, `hpkebase.ts` `d093f11b961686e0`; `web/shared/oidc-rp/index.ts` `7dd0e001af6e68d4`, `flows.ts` `7876e4528a6d9dae`, `idtoken.ts` `ca893e2270e502e9`, `errors.ts` `f843dfaf4d4fba85`; `tools/fakeproduct/server.go` `76b07874f5bf925f`, `userinfo.go` `9ef3416743042c39`.

## The kit's own vectors

`kit/*-go.json` were written by `internal/cross/write_test.go` and `kit/*-ts.json` by `js/test/cross.spec.ts`, each at the kit commit recorded in its `generated_by.source`, with fresh randomness (`make vectors-kit`). They are the golden vectors of the kit's own implementations from v0.1.0 on.

The files of v0.1.0 were written at `9cc95a3d672c3bff0a1fe610a6ec82ba64103fbe` (go1.27.1 and Node v25.6.1 on darwin/arm64), replacing those written at `5c28c42` before any tag existed. They add the forgeries under the all-zero X25519 secret (`hpke/open/forged/*`, `seal/direct/forged/grant/*`, with their `forger-control` cases), the refusals to seal to a low-order key, the bounded derivations and the passkey binding refusals. The forgeries' low-order encodings are those of `internal/forge` (`LowOrder`).

`kit/platform-go.json` and `kit/platform-ts.json`, the platform profile's cases in the kit's format (`"profile": "platform"`), were added at `34940a2e4aa09babb60d554d0257def7ac793009` (go1.26.7 and Node v25.6.1 with `@noble/hashes` 2.4.0, on darwin/arm64) by `make vectors-kit`, which adds only the files `kit/` does not hold yet. Their passwords are random strings from blocks whose normalisation is the same in Unicode 15.0 and 17.0; their roots, keys, salts, nonces and codes are fresh randomness, recorded where the format has room for it.

`kit/platform-password-go.json` and `kit/platform-password-ts.json` were added at `3b3fc301c05f68c9a5499ca1222dc397d145e248` (go1.26.7 and Node v25.6.1 with `@noble/hashes` 2.4.0, on darwin/arm64) by `make vectors-kit`, which kept every other file. They hold no randomness: the same 18 fixed passwords, at the limit of the platform profile's run rule (SPEC section 11.2, step 2) and one past it, 9 of which must fail with `password_invalid`; each writer refuses to write a case whose outcome is not the one it declares, and the two files' cases are identical.

`kit/platform-delivery-go.json` and `kit/platform-delivery-ts.json` were added at `cb0ccf22a351762c3404898dd03dfa2772f0dc13` (go1.26.7 and Node v25.6.1 with `@noble/hashes` 2.4.0, on darwin/arm64) by `make vectors-kit`, which kept every other file. They replace those written at `a111cc7` before any tag carried them, whose `generated_by.randomness` said that their seals record what they drew; these say that nothing drawn is recorded. They hold the round trips of the platform profile's part 2 (SPEC sections 11.12 and 11.13), 410 cases each: 200 key-delivery AADs of random bindings, half with one field broken; 24 fresh deliveries, each also opened in another flow, by another recipient and with a flipped bit, and for four of them a blob whose sealer spelled `enc` with bit 255 set and one carrying another key under the binding; the seal's refusals of every low-order `akd_pub` and of a valid one with bit 255 set; and 96 PKCE verifiers, 32 of them malformed. Their keys, roots and bindings are fresh randomness. A delivery's ephemeral key came from crypto/rand or WebCrypto and is not recorded, so the other language checks a blob by opening it, never by its bytes. Each writer refused to write a case whose outcome was not the one it declares. sha256: `6cac311ab601a3d721f8fa4122d93c9f460a7b780df9ad8d3bec922f8b71a30d` (go), `105ef5b7f7fb490fe4439db826839e0c26c34f25044fa55744b0b04411e904c0` (ts).
