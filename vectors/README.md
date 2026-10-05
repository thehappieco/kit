# Vectors

The kit's conformance data. Go reads it through the `vectors` package (`vectors.FS`, so a consumer's tests can run the vectors of the kit version it imports); the TypeScript tests read it from this directory. It is not in the npm tarball.

There are two file formats: the kit's own (below), used by everything under `wappie/` and `kit/`, and the platform's (`platform/id-v1/`, described in "The platform's format").

## Layout

| Path | What |
|---|---|
| `wappie/legacy/` | Byte-for-byte copies of Wappie's own fixtures, in the shapes Wappie gave them. Never rewritten. |
| `wappie/golden/` | Vectors written by Wappie's code at the commit in `PROVENANCE.md`, by the generators in `wappie/_generators/`. |
| `wappie/_generators/` | The generators, kept for provenance and for `make vectors-regen-check`. Not built by the go tool, not embedded. |
| `kit/` | Vectors written by the kit itself: `*-go.json` by the Go code for TypeScript to open, `*-ts.json` the reverse. |
| `platform/id-v1/` | The platform's golden vectors of its protocol `id-v1`, byte for byte as the platform's Go code wrote them at the commits in `PROVENANCE.md`, in the platform's format: part 1 (SPEC sections 11.1 to 11.11) at `5e66d84`, part 2 (sections 11.12 to 11.15) at `4476bf4`, part 3 (section 11.16) at `b5d9f69`. |
| `platform/_generators/` | The platform's generator at `5e66d84`, kept for provenance. Not built, not embedded. |
| `platform/_generators-4476bf4/` | The platform's generator at `4476bf4`, which wrote part 2 and writes the part-1 files unchanged. Not built, not embedded. |
| `platform/_generators-b5d9f69/` | The platform's generator at `b5d9f69`, which wrote part 3 and writes the files of parts 1 and 2 unchanged. Not built, not embedded. |
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
- Seals record the randomness they consumed: `seed` (Go, `testing/cryptotest.SetGlobalRandom`, replayed only on the recorded toolchain), `ephemeral_private_key_b64` or `nonce_b64` (replayed by injecting exactly those bytes). The fresh key deliveries of `kit/platform-delivery-{go,ts}.json` record nothing they drew, as their `generated_by.randomness` says: they are checked by opening.
- Ids are stable and unique within a file.
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
| platform (its own format) | `password_invalid`, `password_too_short`, `password_too_long`, `kdf_policy`, `wrap`, `recovery_code`, `email`, `product_key`, `bundle`, `key_delivery`, `pkce`, `client_extensions`, `encoding` |

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

- A binary member the generator left empty is omitted (`omitempty`): a runner reads a missing `akd_sealed` or `akd_pub` as empty. `prf`, `rp_id` and `client_extension_results` are written even when empty (`passkey.json#key/an empty PRF output`, `#salt/an empty relying party id`, `client-extensions.json#an empty text`), so a missing one fails the run.
- Argon2id cases use the floor parameters (m 65536, t 3, p 1), and one uses p = 4.
- The runners decode strictly: a member a runner does not read fails the run, and so does a refusal with any error other than the recorded one.

## Running

```
make test              # both languages
make test-go-1.26.7    # adds the byte-for-byte replays of Wappie's Go vectors
make test-browser      # the TypeScript specs in Chromium, Firefox and WebKit
make cross             # fresh round trips: each language writes, the other opens
make vectors-check     # the manifest
make vectors-regen-check WAPPIE=../whatserver2   # regenerate from Wappie and compare
make vectors-platform-check PLATFORM=../platform # regenerate from the platform and compare
```
