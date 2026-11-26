# Vectors

The kit's conformance data. Go reads it through the `vectors` package (`vectors.FS`, so a consumer's tests can run the vectors of the kit version it imports); the TypeScript tests read it from this directory. It is not in the npm tarball.

There are four file formats: the kit's own (below), used by everything under `wappie/`, `kit/` and `mailie/`; the platform's (`platform/id-v1/`, described in "The platform's format"); THCSEAL's (`platform/thcseal-v1/`, described in "THCSEAL's format"); and the platform's contract's (`platform/contract-v1/`, described in "The contract's format").

## Layout

| Path | What |
|---|---|
| `wappie/legacy/` | Byte-for-byte copies of Wappie's own fixtures, in the shapes Wappie gave them; `platform-wrap-vectors.json` is its console's own file as the console's test writes it with the header patch `PROVENANCE.md` records. Never rewritten. |
| `wappie/golden/` | Vectors written by Wappie's code at the commits in `PROVENANCE.md`, by the generators in `wappie/_generators/`: Wappie's at `8c0c1f7`, and its console's platform wrap (`platform-wrap-{go,ts}.json`) at `3bfee27` with the header patch recorded there. |
| `wappie/_generators/` | The generators, kept for provenance and for `make vectors-regen-check`; `run-cloud.sh` and `cloud/` are those of the console's platform wrap, for `make vectors-cloud-regen-check`. Not built by the go tool, not embedded. |
| `kit/` | Vectors written by the kit itself: `*-go.json` by the Go code for TypeScript to open, `*-ts.json` the reverse. |
| `mailie/golden/` | Mailie's golden vectors: `platform-wrap-go.json`, its platform wrap (SPEC section 6.8 under Mailie's labels, Appendix D), written by the kit's Go code with nothing random, by the generator in `mailie/_generators/` (`PROVENANCE.md`). TypeScript opens every case. |
| `mailie/_generators/` | The generator of `mailie/golden/platform-wrap-go.json`, for `make vectors-mailie-regen`, which CI runs. Not built by the go tool, not embedded. |
| `mailie/key-scheme-v1/` | Mailie's own vectors of its key scheme, version 1 (SPEC Appendix D): `account-go.json`, `grant-go.json`, `platform-wrap-go.json` and `browser-vault-go.json`, byte for byte as Mailie's Go code wrote them at Mailie `c9c79cf` (`PROVENANCE.md`), in the kit's format. Go runs all 248 cases and TypeScript the 224 marked for it; `profiles/mailie` writes all four again byte for byte (the seeded seals of `account-go.json` and `grant-go.json` on the toolchains `PROVENANCE.md` lists), and `make vectors-mailie-check` has Mailie's own generator write them. |
| `platform/id-v1/` | The platform's golden vectors of its protocol `id-v1`, byte for byte as the platform's Go code wrote them at the commits in `PROVENANCE.md`, in the platform's format: part 1 (SPEC sections 11.1 to 11.11) at `5e66d84`, part 2 (sections 11.12 to 11.15) at `4476bf4`, part 3 (section 11.16) at `b5d9f69`, and the relying party rule of section 11.16 at `75b6b94`. |
| `platform/_generators/` | The platform's generator at `5e66d84`, kept for provenance. Not built, not embedded. |
| `platform/_generators-4476bf4/` | The platform's generator at `4476bf4`, which wrote part 2 and writes the part-1 files unchanged. Not built, not embedded. |
| `platform/_generators-b5d9f69/` | The platform's generator at `b5d9f69`, which wrote part 3 and writes the files of parts 1 and 2 unchanged. Not built, not embedded. |
| `platform/thcseal-v1/` | The platform's golden vectors of THCSEAL v1 (SPEC section 14), `thcseal-v1.json`, byte for byte as the platform's Go code wrote them, captured at `d32b663` (`PROVENANCE.md`), in THCSEAL's own format. No copy of its generator is kept here: it is a function of the platform's test, which the kit's `thcseal` tests carry and run, writing the file again byte for byte. |
| `platform/contract-v1/` | The golden vectors of the platform's product contract, in the contract's own format. Of its membership part (SPEC section 11.17), the platform's: `signatures.json`, `wire.json` and `labels.json`, byte for byte as the platform's Go code wrote them, captured at `a78bf16`, and `wire-item-ids.json`, added at `ee45e3a` once `wire.json` was frozen. Of its token part (SPEC section 11.18), with an item's ordinal and tokens and an event's stop, the kit's own, written in v0.9.0 from the platform's design at `509cc65`, ahead of the platform's generator: `tokens.json`, `reading-keys.json`, `wire-tokens.json`, `wire-snapshot-tokens.json` and `wire-events-stop.json` (`PROVENANCE.md`). Of its settings part (SPEC section 11.19), the kit's own too, written in v0.10.0 from the same design: `wire-settings.json`, `wire-commands.json` and `command-macs.json`. Of the relink (SPEC section 11.19) and what rides its release, the kit's own, written in v0.11.0 from the platform's spec 14.13 at `958c3b4` and its logs: `wire-pairing.json` and `wire-v011.json`. Of the entitlements and usage part (SPEC section 11.20) and what rides its release, the kit's own, written in v0.12.0 from the platform's spec section 15 at `a80d9b0`: `wire-entitlements.json`, `wire-usage.json`, `usage-dates.json`, `trial-codes.json`, `wire-link-check.json`, `wire-events-codes.json`, `wire-trim.json`, `trim-macs.json` and `wire-v012.json`. No copy of a generator is kept here: each is a function of the contract's code, and `contract`'s tests carry them and write the twenty-three files again byte for byte in every run (`KIT_CONTRACT_OUT` adds a new one; the generators of v0.10.0's files read kit v0.10.1's kinds and codes, so a later kind or code changes none of them). |
| `platform/_generators-75b6b94/` | The platform's generator at `75b6b94`, which wrote `rp-id-ends-in-number.json` and writes the thirteen earlier files unchanged. It imports only the standard library and the kit's `profiles/platform`, so `make vectors-platform-regen` builds it against the kit's own tree; not built by the go tool, not embedded. |
| `MANIFEST.sha256` | The sha256 of every file above. `make vectors-check`. |

Files are append-only once a release is tagged: a changed case is a new id, and no file present at a tag changes or disappears.

## Format

```json
{
  "format": "thehappieco-kit-vectors/1",
  "module": "seal",
  "profile": "wappie",
  "generated_by": { "lang": "go", "source": "github.com/thehappieco/wappie@<commit> internal/crypto/seal", "toolchain": "go1.26.7", "randomness": "...", "generator": "..." },
  "note": "free text",
  "keys": { "archive": { "private_key_b64": "...", "public_key_b64": "..." } },
  "cases": [
    { "id": "seal/batch/body/epoch-1/id-7", "op": "seal.seal_batch", "in": { "...": "..." }, "out": { "envelope_b64": "..." } },
    { "id": "seal/batch/refuses/row-moved", "op": "seal.open_batch", "in": { "...": "..." }, "error": "authentication" }
  ]
}
```

- Bytes are in fields ending `_b64` (standard base64 with padding), hashes in `_hex`, UUIDs as text, integers as JSON numbers up to 2^53, wire text as JSON strings.
- Each case has exactly one of `out` and `error`. Account errors also carry a `reason`.
- `langs`, when present, narrows which languages run a case; absent means every language that implements the op.
- Seals record the randomness they consumed: `seed` (Go, `testing/cryptotest.SetGlobalRandom`, replayed only on the recorded toolchain, or, for the files of `mailie/key-scheme-v1/`, on the toolchains `PROVENANCE.md` lists as checked, which the recorded one is among; on any other the replay skips and says so), `ephemeral_private_key_b64` or `nonce_b64` (replayed by injecting exactly those bytes). The fresh key deliveries of `kit/platform-delivery-{go,ts}.json` record nothing they drew, as their `generated_by.randomness` says: they are checked by opening.
- Ids are stable and unique within a file.
- A file may name key pairs under `keys` (`private_key_b64`, `public_key_b64`), which its cases refer to by name: `mailie/key-scheme-v1/grant-go.json`'s `key` and `recipient`.
- Refusals that need an input no profile function produces carry it directly: `public_key_b64` (a key of low order, on `hpke.seal` and `seal.seal_direct`), `aad_b64` (an AAD given as is, empty included, on `passkey.wrap` and `passkey.unwrap`), and `<field>_wtf8_b64` in place of a string field: a string that is not Unicode, as WTF-8 bytes, which Go takes as the (invalid UTF-8) string itself and TypeScript decodes to a string with a lone surrogate.
- An `account.derive` case may give `bounds` (`min`, `max`, `max_cost`, `min_salt_len`, `max_salt_len`), which the test adds to the file's profile.
- A forgery carries `forged_plaintext_b64`: what an implementation missing a required check would open it to. The kit's forgeries (`kit/hpke-go.json#hpke/open/forged/*`, `kit/seal-go.json#seal/direct/forged/grant/*`) are sealed under the all-zero X25519 secret of a low-order encapsulated key; a `forger-control` case built the same way from a real X25519 output opens, which shows the construction is HPKE. The TypeScript tests run every forgery twice: on the engine as it is, and on one that, like a non-conforming WebCrypto, answers a low-order point with zeros instead of refusing it, so only the kit's own check stops it.

### Error codes

| Module | Codes |
|---|---|
| seal | `short`, `magic`, `version`, `suite`, `mode`, `key_mismatch`, `authentication`, `invalid_key` (and `invalid_input` from TypeScript's argument checks) |
| account | `password`, `kdf`, `wrap`, `recovery`, with reasons `rejected`, `unsupported_alg`, `kdf_failed`, `out_of_bounds`, `truncated`, `wrong_key`, `recovery_length` |
| passkey | `bad_key`, `bad_aad`, `bad_prf`, `bad_envelope`, `open_failed` |
| hpke | `open_failed`, `invalid_key` |
| reqhmac | `hmac_missing`, `hmac_stale`, `hmac_bad`, `hmac_replay`, `replay_cache_full` |
| jcs | `jcs` |
| wappie.platform_wrap, mailie.platform_wrap | `platform_wrap` |
| Mailie's key scheme (`mailie/key-scheme-v1/`) | its own `binding`, `shape`, `public_key` (Go only) and `vault` (TypeScript only, no vector); and the kit's: account's `password`, `kdf` and `wrap` with their reasons, the platform's `recovery_code` (Mailie's account ops read a recovery code in the platform's canonical form), `platform_wrap`, and seal's |
| platform (its own format) | `password_invalid`, `password_too_short`, `password_too_long`, `kdf_policy`, `wrap`, `recovery_code`, `email`, `product_key`, `bundle`, `key_delivery`, `pkce`, `client_extensions`, `encoding` |
| THCSEAL (its own format) | `malformed`, `provider_mismatch`, `decrypt` |
| the contract (its own format) | an answer check's `result`: reqhmac's `hmac_missing`, `hmac_stale`, `hmac_bad`, and `answer_nonce`; a reading key's `result`: `encoding`, `not_canonical`, `low_order`, `fingerprint`; a refused token's `step`; an action's `code`; a command's `action`: `run`, `reset`, `expired`, `invalid_command`; a token feed page's `action`: `apply`, `reset`, `narrow`, `refuse`; a refusal code's `class`: `retry`, `final`; the other lists record `valid` |

### Op catalogue

"Open" means the recorded output is opened or verified; "replay" means the output is recomputed byte for byte from the recorded randomness.

| Op | Go | TypeScript |
|---|---|---|
| `seal.kind_name`, `seal.info`, `seal.aad`, `seal.row`, `seal.content_key_row`, `seal.grant_row`, `wappie.draft_row` | compute | compute |
| `seal.generate_key_pair` | replay (seed) | key pair consistency |
| `seal.seal_direct` | open; replay (seed) | open; replay (ephemeral) |
| `seal.new_content_key`, `seal.seal_batch` | open; replay (seed) | open |
| `seal.open_direct`, `seal.open_batch`, `seal.open_content_key`, `seal.content_key_id` | compute | compute |
| `seal.sealer` | open; replay the sequence (seed) | open |
| `hpke.seal` | open; refuse | open; replay (ephemeral); refuse |
| `hpke.open`, `hpke.public_from_private` | compute | compute |
| `hpke.generate_key_pair` | | replay |
| `account.default_kdf_params`, `account.derive`, `account.wrap_aad`, `account.unwrap`, `account.normalise_recovery_code`, `account.recovery_key`, `account.recovery_proof` | compute | compute |
| `account.wrap` | replay (nonce) | replay (nonce) |
| `account.recovery_code` | compute from the recorded bytes | replay |
| `account.generate_keys`, `account.fresh_salt` | | replay |
| `passkey.prf_salt`, `passkey.aad`, `passkey.key`, `passkey.unwrap` | compute | compute |
| `passkey.wrap` | replay (nonce) | replay (nonce) |
| `browser_account.aad`, `browser_account.valid_envelope` | | compute |
| `reqhmac.signature`, `reqhmac.read`, `reqhmac.signed_by` | compute | compute |
| `reqhmac.replay`, `reqhmac.sign` | compute; replay (seed) | |
| `bytes.uuid_v5` | compute | compute |
| `bytes.parse_uuid`, `bytes.format_uuid`, `bytes.base64`, `bytes.from_hex`, `jcs.canonical_value` | | compute |
| `jcs.canonical` | compute (integers and strings) | compute |
| `derived.*`, `keychain.*`, `attestation.user_data` | | reference implementation in the tests, until the modules move |
| `platform.prepare_password`, `platform.derive_password`, `platform.open_root_wrap`, `platform.product_key`, `platform.verifier`, `platform.normalize_email`, `platform.key_bundle` | compute | compute |
| `platform.root_wrap` | compute; replay (nonce) | compute; replay (nonce) |
| `platform.recovery_code` | compute from the recorded bytes | compute; replay |
| `platform.check_public_key` (the server's) | compute | |
| `platform.key_delivery_aad`, `platform.pkce_challenge` | compute | compute |
| `platform.open_product_key` (a fresh seal, which cannot be replayed in the other language) | open | open |
| `platform.seal_product_key` (refusals of `akd_pub`) | refuse | refuse |
| `platform.prf_salt`, `platform.check_client_extensions` | compute | compute |
| `wappie.platform_wrap_info`, `wappie.platform_wrap_aad` | compute | compute |
| `wappie.platform_wrap_seal` (`k_pw_b64` from Go only: TypeScript's K_pw is not extractable) | replay (nonce); refuse | replay (nonce); refuse |
| `wappie.platform_wrap_open` (also in Mailie's file: a Mailie wrap refused under Wappie's labels) | compute; refuse | compute; refuse |
| `mailie.platform_wrap_info`, `mailie.platform_wrap_aad` | compute | compute |
| `mailie.platform_wrap_seal` (`k_pw_b64` on every replayed seal) | replay (nonce); refuse | replay (nonce); refuse |
| `mailie.platform_wrap_open` | compute; refuse | compute; refuse |
| `platform.passkey_wrap` (`k_pk_b64` from Go only: TypeScript's K_pk is not extractable) | compute; replay (nonce); open | compute; replay (nonce); open |
| Mailie's key scheme: `mailie.account_profile`, `mailie.seal_profile`, `mailie.browser_vault_profile` | compute | compute |
| `mailie.normalise_address`: Mailie's server's, not the kit's | reference implementation in the tests | reference implementation in the tests |
| `mailie.decoy_salt`: Mailie's server's, not the kit's | reference implementation in the tests | |
| `account.derive`, `account.normalise_recovery_code`, `account.recovery_key`, `account.recovery_proof`, `mailie.recovery_code` (Mailie's profile) | compute | compute |
| `mailie.account_wrap_aad`, `mailie.account_unwrap`, `mailie.account_wrap_shape` | compute; refuse | compute; refuse |
| `mailie.account_wrap` | replay (nonce, which the case's `seed` drew); replay the file (seed, on the toolchains `PROVENANCE.md` lists); refuse | replay (nonce); refuse |
| `seal.kind_name`, `mailie.grant_row`, `mailie.grant_info`, `mailie.grant_aad`, `mailie.grant_open`, `mailie.grant_shape` | compute; refuse | compute; refuse |
| `mailie.grant_seal` | open, and seal and open a fresh one; replay the file (seed, on the toolchains `PROVENANCE.md` lists); refuse | open, and seal and open a fresh one; refuse |
| `mailie.public_key_check` (a server's) | compute; refuse | |
| `mailie.product_key`, `mailie.platform_wrap_binding`, `mailie.platform_wrap_info`, `mailie.platform_wrap_aad`, `mailie.platform_wrap_open` | compute; refuse | compute; refuse |
| `mailie.platform_wrap_seal` (`k_pw_b64` checked by Go) | replay (nonce); refuse | replay (nonce); refuse |
| `mailie.browser_vault_aad` | compute; refuse | compute; refuse |
| `platform.open_passkey_wrap` | refuse | refuse |

Every dispatcher fails on a case for its language whose op it does not handle.

## The platform's format

`platform/id-v1/<kind>.json` are the platform's own files, carried byte for byte. Each is

```json
{
  "format": "thehappie-id/vectors",
  "version": 1,
  "kind": "root-wrap",
  "cases": [
    { "name": "a password wrap", "kind": "password", "key": "...", "nonce": "...", "root": "...", "sub": "...", "epoch": 1, "aad": "...", "wrap": "..." },
    { "name": "truncated to 61 bytes", "kind": "password", "key": "...", "sub": "...", "epoch": 1, "wrap": "...", "error": "wrap" }
  ]
}
```

- A case has a `name`, unique in its file, or, in a file whose cases carry an `op`, a unique `op` and `name` (next bullet), and either its outputs or `"error": "<name>"`, one of the platform profile's error names (SPEC section 11.10). Every implementation runs every case.
- In a file whose cases carry an `op` (`key-delivery`, where a must-fail case says which side refuses it: `open` or `seal`; and `passkey`, where it says which step refuses it: `salt`, `key` or `open`), a case is identified by its `op` and `name` together, which are unique; such a case is cited as `<file>#<op>/<name>` (`platform/id-v1/key-delivery.json#open/a sub in upper case`, `platform/id-v1/passkey.json#salt/an IPv4 address`), and a case without an `op` by its name alone. In `passkey.json` the names are unique too.
- Binary values are base64url without padding (no `_b64` suffix); texts are JSON strings; every file is ASCII, with non-ASCII characters as `\u` escapes, and ends with one newline.
- Kinds and their members:

| Kind | Inputs | Outputs |
|---|---|---|
| `password-profile` | `password`, or `password_utf16` with `password_utf8_b64url` for a string that is not Unicode (each language takes its own form; both are one input); `new` | `prepared_b64url` |
| `kdf` | `prepared_b64url`, `salt`, `kdf` | `k_auth`, `k_wrap`, `auth_key` |
| `root-wrap` | `kind`, `key`, `nonce`, `root`, `sub`, `epoch`, `rp_id`, `credential_id` | `aad`, `wrap` (a refusal gives the `wrap` to open) |
| `recovery-code` | `bytes` or `input` | `display`, `canonical`, `k_rwrap`, `recovery_auth` |
| `product-key` | `root`, `product`, `epoch` | `sk`, `pub`, `product_key_id` |
| `verifier` | `sub`, and `k_auth` or `r_proof` | `auth_verifier` or `recovery_verifier` |
| `email` | `input` | `email_norm` |
| `key-bundle` | `password` or `recovery_code`; `bundle` as a JSON value, or `bundle_text` as the exact text of the file | `root` |
| `password-stream-safe` | as `password-profile`: the cases at and one past the limit of the run rule (SPEC section 11.2, step 2) | as `password-profile` |
| `key-delivery` | `op` on a must-fail case (`open` or `seal`); `root`, `product`, `epoch` (the product key, on good and `seal` cases); `iss`, `client_id`, `redirect_uri`, `sub`, `product_key_id`, `pk_p`, `code_challenge`, `nonce` (the binding); `akd_priv` (good and `open`), `akd_pub` (good and `seal`), `eph_priv` (good: the sender's ephemeral key, which only a test can inject) | `aad`, `akd_sealed` (on an `open` refusal, the blob to open) |
| `pkce` | `code_verifier` | `code_challenge` |
| `passkey` | `op` on a must-fail case (`salt`, `key` or `open`); `rp_id`; `prf` (the PRF output; good, `key` and `open` cases); `root`, `nonce` (good); `sub`, `epoch`, `credential_id` (good and `open`); `wrap` (on an `open` refusal, the wrap to open) | `prf_salt`, `k_pk`, `aad`, `wrap` |
| `client-extensions` | `client_extension_results`: the exact JSON text of a credential's `clientExtensionResults`, as a JSON string, so that a repeated member, a byte order mark or data after the object can be expressed | accepted, or `"error": "client_extensions"` |
| `rp-id-ends-in-number` | `rp_id` | `ends_in_a_number` (the WHATWG URL Standard's "ends in a number checker" on `rp_id`, on every case), and `prf_salt` on an accepted id or `"error": "wrap"` on a refused one |

- A binary member the generator left empty is omitted (`omitempty`): a runner reads a missing `akd_sealed` or `akd_pub` as empty. `prf`, `rp_id` and `client_extension_results` are written even when empty (`passkey.json#key/an empty PRF output`, `#salt/an empty relying party id`, `client-extensions.json#an empty text`), so a missing one fails the run.
- Argon2id cases use the floor parameters (m 65536, t 3, p 1), and one uses p = 4.
- The runners decode strictly: a member a runner does not read fails the run, and so does a refusal with any error other than the recorded one.

## THCSEAL's format

`platform/thcseal-v1/thcseal-v1.json` is the platform's own file, carried byte for byte (SPEC section 12.3):

```json
{
  "comment": ["THCSEAL v1 golden vectors, generated by internal/seal/golden_test.go. Test data only.", "..."],
  "provider": "localkek (0x7f)",
  "kek_hex": "000102...1f",
  "valid": [
    { "name": "a short secret", "context": { "service": "platform", "env": "test", "purpose": "config/smtp-password", "ref": "smtp-password" }, "plaintext_hex": "...", "envelope_hex": "...", "data_key_hex": "...", "aad_hex": "..." }
  ],
  "invalid": [
    { "name": "version 2", "context": { "...": "..." }, "envelope_hex": "...", "error": "malformed" }
  ]
}
```

- Bytes are lowercase hex in fields ending `_hex`; the context is the four fields of SPEC section 14.1, `ref` written even when empty.
- Every envelope is sealed with the local provider (`0x7f`) under `kek_hex`, the published test KEK `000102…1f`. A valid case must open to `plaintext_hex` under its context; `data_key_hex` and `aad_hex` are its intermediate values, which the kit's runner checks too. An invalid case must fail with its `error`, one of `malformed`, `provider_mismatch` and `decrypt` (SPEC section 14.2), checked in that order.
- A case is identified by its list and its name, which are unique, and cited as `platform/thcseal-v1/thcseal-v1.json#valid/<name>` or `#invalid/<name>`.
- The file is ASCII and ends with one newline. The runner (`thcseal/golden_test.go`) decodes strictly: a member it does not read fails the run. Its tests and the fuzzers seeded from the file seal under the local KEK, so they need `-tags kitdevkek`.

## The contract's format

`platform/contract-v1/*.json` are the platform's own files, carried byte for byte (SPEC section 11.17), and the five kit v0.9.0 adds, the three of v0.10.0, the two of v0.11.0 and the nine of v0.12.0, which the kit writes for the platform's generator to write again (SPEC sections 11.18 to 11.20). Each is `{"format": "thehappie-contract/vectors", "version": 1, "kind": "<kind>", "description": "...", ...}`, with the lists of its kind:

| Kind | Lists | A case |
|---|---|---|
| `signatures` | also `label`, `headers` and `skew_seconds`, the scheme's; `requests` (direction `to-platform`) and `answers` (`to-app`) | `name`, `secret`, `direction`, `app`, `method`, `target`, `timestamp`, `nonce`, `body`; `canonical`, `signature` |
| | `answer_checks` | `name`, `headers` (the answer's), `secrets` (those the app accepts), `app`, `method`, `target`, `sent_nonce`, `body`, `now` (Unix seconds); `result`: `ok`, or the code `contract.VerifyAnswer` refuses with (`answer_nonce`, `hmac_bad`, `hmac_stale`, `hmac_missing`) |
| | `secrets` | `name`, `current`, `next`; `valid` (whether `contract.CheckSecrets` accepts the pair) |
| `wire` (`wire.json`; `wire-item-ids.json` and `wire-snapshot-tokens.json` with snapshots only, `wire-events-stop.json` with events only) | `documents`, `snapshots`, `events` | `name`, `value` (a JSON value); `valid`: whether it decodes (a time with a comma does not, nor `"stop": null`, `"ordinal": 0` or `"tokens": null`: an optional member is absent, never null) and its `Validate` accepts it |
| `tokens` (`tokens.json`; also `label`, the hash's) | `tokens` | `name`, `token`, `selector`, `secret_hex` (the secret's 32 bytes), `hash` (`contract.ParseToken`, `contract.TokenHash`) |
| | `refused` | `name`, `token`; `step`, the step of `contract.ParseToken`'s check that refuses it, 1 to 6 |
| | `authorization` | `name`, `values` (an `Authorization` header's values, as the server hands them); `valid` (whether `contract.BearerToken` takes a token from them) |
| `reading-keys` (`reading-keys.json`; also `label`, the fingerprint's, and `check_label`, whose SHA-256 is the low-order check's scalar) | `reading_keys` | `name`, `key`, `fingerprint` (the key's own wherever it decodes, but in the `fingerprint` cases; `""` where it does not); `result`, what `contract.CheckReadingKey` makes of the pair: `ok`, `encoding`, `not_canonical`, `low_order` or `fingerprint` |
| `wire-tokens` (`wire-tokens.json`) | `records`, `feeds` | `name`, `value`; `valid`: whether it decodes as an app decodes what the platform sends (a member it does not know ignored) and `contract.TokenRecord`'s or `contract.TokenFeed`'s `Validate` accepts it; a page's records stay raw, so one that does not decode leaves its page valid |
| | `applied` | `name`, `value`; `valid`: whether it decodes as the platform decodes what an app sends (strictly: no member it does not know, every name of the `waiting` and `suspended` entries exactly as written and once) and `contract.TokenApplied`'s `Validate` accepts it |
| | `usage` | `name`, `body` (the exact text an app sends); `valid`: whether it is within the call's 256 KiB, decodes strictly as `contract.TokenUsage` and validates |
| | `actions` | `name`, `app`, `generation` (the app's), `value` (a record it receives, decoded on its own by `contract.TokenFeedItem.Record`); `action`, what it does, decided in this order: `refuse` (a record whose `app` decodes as another valid app id: nothing of it applies), `reset` (a `generation` that decodes as another valid UUID), `narrow` (a record that does not decode or fails `Validate`, one whose `app` or `generation` does not decode or is written in another case among them, or whose reading key's fingerprint is not its key's; a non-null `revoked_at` or `revoked_reason` revokes it all the same), `revoke`, else `apply`; `code`, the revocation's reason, or the refusal code of a narrowing (`invalid_record`, `reading_key_changed`), or `null` |
| `wire-settings` (`wire-settings.json`) | `sections`, `persons` | `name`, `value` (a `PUT` body); `valid`: whether it is within its call's limit, 1 MiB for a section and 256 KiB for a person, decodes as the platform decodes what an app sends (strictly, `contract.DecodeStrict`: no member it does not know, every name exactly as written, none twice, every member present, `null` only where a member may be null) and `contract.SettingsDoc`'s or `contract.PersonSettingsDoc`'s `Validate` accepts it, its `data` read the same way into the section's type |
| `wire-commands` (`wire-commands.json`) | `feeds` | `name`, `value` (a command feed page); `valid`: whether it decodes as an app decodes what the platform sends and `contract.CommandFeed`'s `Validate` accepts it; a page's commands stay raw, so one whose MAC does not hold leaves its page valid |
| | `commands` | `name`, `app`, `workspace_kind` (`personal`, `team`, or `""` for a person's kind), `value` (a command as served, signed with `SecretA` of `signatures.json` for its app); `valid`: whether `contract.VerifyCommand` takes it, decoding it as an app decodes what the platform sends, and its `ValidateIn(workspace_kind)` accepts it |
| | `actions` | `name`, `app`, `generation` (the app's), `signed_at` (the time the carrying answer was signed, RFC 3339), `last_wseq` (the highest `wseq` its producer ran in that workspace with another id, or `null`), `again`, `value` (a command as served); `action`, what the app does, decided in this order: `invalid_command` (a MAC that does not hold under `SecretA`), `reset` (another generation), `invalid_command` (not valid), `expired` (issued over 30 days before `signed_at`, unless `again`), `expired` (`signed_at` after its `expires_at`), `invalid_command` (a `wseq` at or below `last_wseq`, unless `again`), else `run` |
| | `results` | `name`, `app`, `kind` (the command's), `value` (one result); `valid`: whether it decodes strictly and `contract.CommandResult`'s `ValidateFor(app, kind)` accepts it |
| | `batches` | `name`, `body` (the exact text an app sends); `valid`: whether it is within the call's 256 KiB, decodes strictly as `contract.CommandResults` and validates |
| | `classes` | `code`, `tightening`; `class`, `retry` or `final` (`contract.CommandRefusalClass`); no name: each (code, tightening) once |
| `wire-pairing` (`wire-pairing.json`, kit v0.11.0: the relink) | `pairings` | `name`, `body` (the exact text of `PUT /contract/v1/commands/{id}/pairing`), `now` (the platform's clock, Unix seconds); `valid`: whether it is within the call's 4 KiB, decodes strictly as `contract.PairingQR` (exactly `seq`, `qr` and `expires_at`, none null, none twice, names exactly as written, `expires_at` RFC 3339 in UTC with `Z`) and its `ValidateAt(now)` accepts it: `seq` 1 or more, `qr` 1 to 512 characters of `^[A-Za-z0-9+/=,@._:#-]$`, `expires_at` after `now` and at most 90 s after it. A `seq` at or below the highest the platform kept is no fault of the body (the platform answers it `accepted: false`), so no case judges one |
| | `answers` | `name`, `value` (the platform's signed 200 to a pairing); `valid`: whether it is exactly `{"accepted": a boolean}` (`contract.PairingAnswer`) |
| | `commands`, `results` | as `wire-commands`'s: `item.relink` of Wappie and the reference app, and `item.move_out`'s `item_busy` |
| | `classes` | as `wire-commands`'s, for exactly the three codes v0.11.0 adds: `other_account`, `link_timeout`, `number_held` |
| `wire-v011` (`wire-v011.json`, kit v0.11.0: what rides the relink's release) | `sections` | as `wire-settings`'s: a numbers row's `can_relink` (true, false or absent, never null), the relink in Wappie's `accepts` and the rename in Mailie's email-accounts `accepts`, the mailbox reason `grant_ended`, a mailbox's sync off with its index kept |
| | `commands`, `results` | as `wire-commands`'s: Mailie's `item.rename`, and `label_changed` with a `cleaned` that is null, told from one that is absent: valid only on an `item.rename` |
| | `pages` | `name`, `app`, `generation` (the app's), `value` (a token feed page of one record); `action`, what the app does: `reset` (a page of another generation, whatever its record says); in a page of its own generation, `refuse` (another app's record), `narrow` with `invalid_record` (a record whose `generation` is a valid UUID other than its page's: a bad record, never a reset; the platform never sends a mixed page); else as `wire-tokens`'s `actions`; `code` as there |
| `wire-entitlements` (`wire-entitlements.json`, kit v0.12.0: the entitlements document) | `documents` | `name`, `value` (a document); `valid`: whether it decodes as an app reads what the platform sends (a member it does not know ignored, every member present, `null` only where its rule allows) and `contract.EntitlementsDoc`'s `Validate` accepts it, judging every time against its `computed_at` |
| | `feeds`, `applied` | `name`, `value`; `valid`: a page read as an app reads it (`contract.EntitlementsFeed`'s `UnmarshalJSON`: its seven members present by their exact names and none null; each item's `seq` present by its exact name and never null, and its `doc`, kept byte for byte, which may be null or missing (a bad document, judged alone); no member twice, members it does not know ignored) and `contract.EntitlementsFeed`'s `Validate` (its documents stay raw, byte for byte, judged one by one); an acknowledgement within 4 KiB, decoded strictly, and `contract.EntitlementsApplied`'s `Validate` |
| | `actions` | `name`, `app`, `generation` (the app's), `known` (the workspaces an account document names), `held` (the version applied per workspace), `value` (a page of one document); `action`: `invalid`, `reset`, `refuse` (with `refused`, the acknowledgement's entry), `keep`, `ignore` or `apply`; `through`, where the cursor goes |
| | `gets` | `name`, `app`, `generation`, `workspace` (the path's), `held`, `status` (`200` or a signed refusal's code), `value`; `action`: `not_found`, `none`, `refuse`, `reset`, `ignore`, `fresh` or `apply`; `fresh`, whether it gives freshness |
| | `sequences` | `name`, `app`, `generation`, `known`, `held`, `steps` (each `source` `page` or `get`, `workspace`, `status`, `value`, its `action`, and `held_back`: the workspaces whose freshness from pages is held back after it; a bad document whose `workspace_id` cannot be read holds back every workspace the app keeps a document of, those it applied and those it keeps for a workspace no account document names yet) |
| | `versions` | `name`, `feed`, `get` (a feed's and a GET's document of one version); `same` |
| | `links` | `name`, `release`, `held` and `get_doc` (`{mode, new_links}` or `null`), `fresh_minutes`, `get` (`doc`, `not_found`, `none`, or `""` when not asked); `asks`, `action` (`link`, `refuse_link`), `logged` |
| | `resets` | `name`, `before` and `after` (what the app holds: `generation`, `cursor`, `versions`, `applied`, `stops`, `codes_after`), `generation` (the new page's); `action` `reset` |
| | `freeze` | `name`, `app`, `cause` (`timeline`, `item_trial`, `places`), `at`, `plan_source` and `trial` (an item's), `in_place` (a place stop's item back among the first places, cancelling it), `now`, `fresh_at`; `stops_at`, `action` (`fire`, `hold`, `wait`, `none`) |
| | `caps` | `name`, `app`, `boundary`, `quota_bytes`, `last_granted`, `others_bytes`, `before_sync_step`; `cap_bytes` |
| | `codes_after` | `name`, `last_answered`, `codes_after`; `action` (`send`, `none`) |
| | `places` | `name`, `app`, `frozen` (the document over 24 hours stale: the same action either way), `before` and `after` (`total`, `bindings`, `items` with `id` and `placed_at`); `stopped_before`, `stopped_after`, `action` (`lift`, `stop`, `keep`) |
| | `trial_stops` | `name`, `app`, an item's own trial stop: `trial_ended_at` (the clock end the stop was for), `stopped_at` (when it took effect: that end in Mailie, 72 hours later in Wappie), `plan_source` and `entry` (the next document applied); `action` (`lift`, `keep`), a running entry compared with `trial_ended_at` only |
| | `cap_stops` | `name`, the app's total against `cap_bytes`, `frozen` (the same action either way); `action` (`lift`, `stop`) |
| | `placed_at` | `name`, `app`, `event` (`link`, `first_authorization`, `recovery`, `move_in`, `import`, `relink`, `import_first_pairing`, `reauthorization`), `before` (the item's `placed_at`, or `null`), `at` (the event's time); `after`, `action` (`set`, `keep`) |
| | `link_outcomes` | `name`, `app`, `link` (`new`, or `import_first_pairing`: an imported number's first pairing), `mode`, `total`, `count` (the app's own count, an imported number among it), `answered`, `new_links`, `trial`, `person` (on `used_up`: `go_on`, `decline`, `no_answer`); `action` (`commit`, `link_paused`, `undo_link`, `undo_pairing`), `code` (`retry`, `storage_paused`, `capacity_reached` or `null`), `linked` (whether `item.linked` goes), `logged` |
| `wire-usage` (`wire-usage.json`, kit v0.12.0) | `reports` | `name`, `now` (the platform's clock, Unix seconds), `value` (a body); `valid`: within 1 MiB, decoded strictly as `contract.Usage`, and its `ValidateAt(now)` |
| | `intake` | `name`, `held` (`{usage_seq, body}` or `null`), `mode` (`keep`, `validate`), `workspace` (`open`, `closed_personal`, `closed_team_past`), `value`; `kept`, the answer's |
| | `answers` | `name`, `value`; `valid`: `{"accepted": true, "kept": a boolean}`, both by their exact names, neither `null`, a member the app does not know ignored (`contract.UsageAnswer`) |
| `usage-dates` (`usage-dates.json`, kit v0.12.0) | `dates` | `name`, `app`, `measured_at`, `recent_from`, `rows` (each `id`, `kind`, `what` (a `fixed` row's: Wappie's `chat`, `contact`, `group_member`; Mailie's `folders_row`, `open_draft`), `item`, `ts`, `of`, `refs` (`[]` for an object no message references), `bytes`); `items` (per item `bytes`, `recent_bytes`, `undated_bytes`, `fixed_bytes`), `shared_bytes` |
| | `floors` | `name`, `measured_at`, `issued_at`, `recent_from`, `floor` (`contract.TrimFloor`), `days_less` |
| `trial-codes` (`trial-codes.json`, kit v0.12.0; also `label` and `key_hex`, K_app) | `codes` | `name`, `app`, `kind`, `host` (an IMAP login's, read through `contract.IMAPIdentity`), `input`; `identifier` (normalized), `code` (`contract.TrialCode`) |
| | `meet`, `differ`, `no_code` | `name`, and `a` and `b` (identities as above) whose codes are equal or differ; or one identity that makes no code (`contract.ErrNoCode`) |
| `wire-link-check` (`wire-link-check.json`, kit v0.12.0) | `requests` | `name`, `app`, `value` (a body); `valid`: within 4 KiB, decoded strictly as `contract.LinkCheck`, and its `ValidateFor(app)` |
| | `answers` | `name`, `value`; `valid`: read as an app reads what the platform sends, and `contract.LinkCheckAnswer`'s `Validate` |
| `wire-events-codes` (`wire-events-codes.json`, kit v0.12.0) | `events` | `name`, `value` (one event); `valid`: decoded strictly and `contract.Event`'s `Validate` |
| `wire-trim` (`wire-trim.json`, kit v0.12.0; also `order`, the file's order) | `orders` | `name`, `value` (an order); `valid`: read as an app reads what the platform sends and `contract.TrimOrder`'s `Validate` |
| | `decisions` | `name`, `app`, `now`, `secrets`, `generation_confirmed`, `allow_open`, `held_at_observe`, `recorded`, `feed` (the document carrying the order), `get` and `get_doc`, `basis` and `usage` (`{total_bytes, items}`), `items` (each step's item now: `state`, `purge_at`); `action` (`wait`, `run`, `refused`, `resend`), `code`, `steps` (each `item` and `action`: `run`, `item_changed`, `done`) |
| | `runs` | `name`, `app`, `order`, `steps` (each `before`, `item`, `between`, `bytes_after`, `at_floor`; the events, `feed_same` among them, as the file's description says), `usage_seq`; `reported`, the result the app reports |
| | `results` | `name`, `for_order`, `value`; `valid`: decoded strictly, `contract.TrimResult`'s `Validate`, and with `for_order` its `ValidateFor` the file's order |
| | `answers` | `name`, `value`; `valid`: `contract.TrimResultAnswer`'s `Validate` |
| `trim-macs` (`trim-macs.json`, kit v0.12.0; also `label`, the MAC's) | `macs` | `name`, `app`, `plan_source` (of the expired document carrying the order), `secrets`, `order` (the exact text received); `jcs`, `mac` as `command-macs`'s; `valid`, whether `contract.VerifyTrimOrder` takes it; `mac_fails`, whether it refuses it with `contract.ErrTrimMAC` (it verifies under none of `secrets`, which sends a feed's copy to the GET first) |
| `wire-v012` (`wire-v012.json`, kit v0.12.0: what rides the part's release) | `snapshots` | as `wire`'s, decoded strictly: an item's `server` and `pending` |
| | `sections`, `results` | as `wire-settings`'s and `wire-commands`'s: Mailie's `email-accounts` header (`storage_paused`, `can_link`, `places_free`), and Mailie's `capacity_reached` and `storage_paused` refusals |
| `command-macs` (`command-macs.json`; also `label`, the MAC's) | `macs` | `name`, `app`, `secrets` (those the app holds), `command` (the exact text received); `jcs`, its canonical text without `mac` (`""` when it has none); `mac`, what a signer computes over `jcs` for `app` under the first secret (`""` when `jcs` is); `valid`, whether `contract.VerifyCommand` takes `command` for `app` under `secrets` |
| `labels` | `clean` | `raw`; `clean`, what `contract.CleanLabel` makes of it (`""`: no label) |
| | `hints` | `hint`; `valid` (`contract.ValidHint`) |

- Texts are JSON strings, bodies the exact bytes signed; the made-up secrets protect nothing. The answer checks run at `2026-10-13T12:00:00Z` (`now`, `1791892800`), and their answers' `X-Happie-Timestamp` is that time or, for the stale one, 61 s before it. `1760356800` (2025-10-13T12:00:00Z) is the `timestamp` of the requests and answers of `requests` and `answers`, which enters only their canonical strings: they are checked against no clock.
- The token part's files take their moments from the same `2026-10-13T12:00:00Z`, and their secrets, selectors, reading keys and ids are made up: the first token's secret is the bytes 0 to 31, and reading key n is the X25519 public key of the scalar SHA-256(`thehappie-token/v1/vector-reading-key-<n>`).
- A case is identified by its list and its name, and in `labels.json`, whose cases have none, by its list and its `raw` or `hint`, all unique; cited as `platform/contract-v1/wire.json#events/<name>` or `platform/contract-v1/labels.json#clean/<raw>`.
- The settings part's files take their moments from the same `2026-10-13T12:00:00Z` (a `state_seq` of `1791892800000`, that time in milliseconds), and their ids, names and hosts are made up, but for the public resolver `8.8.8.8`, the vectors' public IPv4 address.
- The entitlements and usage part's files take their moments from the same `2026-10-13T12:00:00Z`; their trial key is the bytes 0 to 31, and their orders are signed with `SecretA` of `signatures.json` (generation 2) but where a case names `SecretB` or a third made-up secret, the bytes 64 to 95. What an app does is written as a small model of the spec in the generator (`contract/contractvec_entitlements_test.go`, `contract/contractvec_trim_test.go`), which the runners replay (`contract/vectors_v012_test.go`).
- `signatures.json`, `wire-item-ids.json`, `reading-keys.json`, `wire-tokens.json` and `command-macs.json` are ASCII, and so are `wire-entitlements.json`, `wire-usage.json`, `usage-dates.json`, `wire-link-check.json`, `wire-trim.json` and `trim-macs.json`; `wire.json`, `labels.json`, `tokens.json`, `wire-snapshot-tokens.json`, `wire-events-stop.json`, `wire-settings.json`, `wire-commands.json`, `trial-codes.json`, `wire-events-codes.json` and `wire-v012.json` hold the UTF-8 of `…` and of the characters their cases spell. Each ends with one newline. `wire-tokens.json` is 2.1 MB: its limits are proved by values at them and one over them (200 and 201 records a page; 1000 and 1001 items, waiting or suspended entries, permissions kept off, days of use, usage refusals and tokens on an item; and a usage body over 256 KiB), and `contract`'s Go tests hold every count limit at its count too (`TestEveryCountLimitHoldsAtItsCount`). `wire-settings.json` is 6.6 MB, for the same reason: every bound of a section's lists at its count and one over it (1000 and 1001 numbers and mailboxes, 5000 and 5001 members, consenters, readers who saw a connection and days of activity, 500 and 501 connections, integrations and move-out holders, and the rest); the documents' call limits are pinned by Go tests instead of documents of megabytes (`TestADocumentAtItsCallsLimitIsValidAndOneByteMoreIsNot`). `wire-commands.json` (1.2 MB) holds results bodies at 256 KiB and over, and feed pages of 100 and 101 commands. The TypeScript tests leave the contract's `wire*.json` files out of their bundle, since only Go reads them. A value whose compact JSON is over 16 KiB is written compact on one line, not indented. The TypeScript reads `reading-keys.json` (`js/test/contract.spec.ts`) for the one function it mirrors, the fingerprint, and `command-macs.json`, whose canonical texts and MACs it reproduces with its `jcs` and WebCrypto's HMAC. The runners (`contract/vectors_test.go`, and `profiles/platform/contract_test.go` for the signatures under the profile's names) decode strictly: a member they do not read fails the run.

## Running

```
make test              # both languages
make test-go-1.26.7    # adds the byte-for-byte replays of Wappie's Go vectors
make test-browser      # the TypeScript specs in Chromium, Firefox and WebKit
make cross             # fresh round trips: each language writes, the other opens
make vectors-check     # the manifest
make vectors-regen-check WAPPIE=../whatserver2   # regenerate from Wappie and compare
make vectors-cloud-regen-check WAPPIE_CLOUD=../whatserver2/commercial   # regenerate the platform wrap's from Wappie's console and compare
make vectors-platform-check PLATFORM=../platform # regenerate from the platform and compare
make vectors-platform-regen      # regenerate the platform's files from the kit's copy of its generator and compare
make vectors-thcseal-check PLATFORM=../platform   # regenerate THCSEAL's file from the platform's own generator at d32b663 and compare
make vectors-mailie-regen        # regenerate Mailie's golden file from the kit's generator, on go1.26.7, and compare
make vectors-mailie-check MAILIE=../mailserver   # regenerate Mailie's key-scheme files from Mailie's own generator at c9c79cf, over kit v0.6.0 and over this tree, and compare
make vectors-contract-check PLATFORM=../platform   # check the contract's files with the platform's own generator at ee45e3a, over its kit and over this tree
```

The Go targets pass `-tags kitdevkek` (`GO_TAGS`), which THCSEAL's runner needs; a plain `go test ./...` fails in `thcseal` and `kms/awskms` with a test that says so.
