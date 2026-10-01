# Changelog

One version covers both languages. Before 1.0.0 a minor version may change APIs but never bytes; a patch changes neither.

## v0.1.0 (unreleased)

- First version, extracted from Wappie at `8c0c1f74103bc6bb65a93b13613ad1964d4399c4`: HPKE, the sealed envelope with content keys, rows, grants and the `Sealer`, the Argon2id account scheme with wraps and recovery codes, the passkey PRF wrap, the browser key at rest, the request HMAC and RFC 8785.
- Labels, prefixes, magic bytes, kind names and AAD builders are parameters, grouped in profiles; the Wappie profile ships frozen.
- New in Go: the account scheme, the passkey wrap and JCS, pinned to Wappie's TypeScript by its vectors, with ECMAScript's `trim`, `toLowerCase` and `toUpperCase` where Wappie's wire bytes depend on them.
- Changes from Wappie that change no byte of any output that opens today: errors carry codes; TypeScript checks that ids are 16 bytes and that epochs and content key ids fit their fields (an epoch of 65536 used to seal an envelope nobody could open), and that a generated key's PKCS#8 export has the expected form; Go reports a low-order encapsulated key as `authentication` like every other direct-mode failure; `hpke.importArchiveKey` is `importPrivateKey`; the `Sealer` takes a clock option instead of a test hook; `KeyStore` no longer declares `CountSeal`, which the `Sealer` never called.
- Vectors: Wappie's six fixtures byte for byte, golden vectors from Wappie's Go and TypeScript, vectors for v0.2.0's attestation, keychain and derived records, and the kit's own vectors in both directions.
