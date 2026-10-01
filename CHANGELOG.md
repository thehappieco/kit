# Changelog

One version covers both languages. Before 1.0.0 a minor version may change APIs but never bytes; a patch changes neither.

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
  - The prepared password, the master key and the raw wrap key are zeroed after a derivation, in the worker too.
- Vectors: Wappie's six fixtures byte for byte, golden vectors from Wappie's Go and TypeScript, vectors for v0.2.0's attestation, keychain and derived records, and the kit's own vectors in both directions.
- CI runs the TypeScript vectors in Chromium, Firefox and WebKit, and a release is published only when every job passes on a commit of `main`, with the Node and npm versions pinned.
