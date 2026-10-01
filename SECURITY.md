# Security

Report vulnerabilities through this repository's private security advisory feature, never in a public issue. Include the affected version, a minimal reproduction with synthetic keys and data, and what you expected the code to refuse. Do not include real keys, passwords, recovery codes, PRF outputs or anybody's content.

## Review status

The kit has not yet had the external cryptographic review that the platform's decision 0018 requires before real customers depend on it; version 1.0.0 waits for that review. Until then the format is pinned by the vectors in `vectors/`, which were produced by the code Wappie runs in production at the commit recorded in `vectors/PROVENANCE.md`.

## What the kit relies on

- WebCrypto in browsers and Node (X25519, AES-GCM, HKDF, HMAC, SHA), `@noble/hashes` for Argon2id, and Go's standard library (`crypto/hpke`, `crypto/ecdh`, `crypto/hkdf`) with `golang.org/x/crypto/argon2`.
- For the platform profile's password preparation: `golang.org/x/text/unicode/norm` in Go and the engine's `String.prototype.normalize` (ICU) in TypeScript. Both must normalise alike; the Unicode caveat is in SPEC.md section 11.2.
- The security considerations of each format are in SPEC.md section 13.
