# Vectors

The kit's conformance data. Go reads it through the `vectors` package (`vectors.FS`, so a consumer's tests can run the vectors of the kit version it imports); the TypeScript tests read it from this directory. It is not in the npm tarball.

## Layout

| Path | What |
|---|---|
| `wappie/legacy/` | Byte-for-byte copies of Wappie's own fixtures, in the shapes Wappie gave them. Never rewritten. |
| `wappie/golden/` | Vectors written by Wappie's code at the commit in `PROVENANCE.md`, by the generators in `wappie/_generators/`. |
| `wappie/_generators/` | The generators, kept for provenance and for `make vectors-regen-check`. Not built by the go tool, not embedded. |
| `kit/` | Vectors written by the kit itself: `*-go.json` by the Go code for TypeScript to open, `*-ts.json` the reverse. |
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
- Seals record the randomness they consumed: `seed` (Go, `testing/cryptotest.SetGlobalRandom`, replayed only on the recorded toolchain), `ephemeral_private_key_b64` or `nonce_b64` (replayed by injecting exactly those bytes).
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
| `derived.*`, `keychain.*`, `attestation.user_data` | | reference implementation in the tests, until the modules move in v0.2.0 |

Every dispatcher fails on a case for its language whose op it does not handle.

## Running

```
make test              # both languages
make test-go-1.26.7    # adds the byte-for-byte replays of Wappie's Go vectors
make test-browser      # the TypeScript specs in Chromium, Firefox and WebKit
make cross             # fresh round trips: each language writes, the other opens
make vectors-check     # the manifest
make vectors-regen-check WAPPIE=../whatserver2   # regenerate from Wappie and compare
```
