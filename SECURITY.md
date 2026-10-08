# Security

Report vulnerabilities through this repository's private security advisory feature, never in a public issue. Include the affected version, a minimal reproduction with synthetic keys and data, and what you expected the code to refuse. Do not include real keys, passwords, recovery codes, PRF outputs or anybody's content.

## Review status

The kit has not yet had the external cryptographic review that the platform's decision 0018 requires before real customers depend on it; version 1.0.0 waits for that review. Until then the format is pinned by the vectors in `vectors/`, which were produced by the code Wappie runs in production at the commit recorded in `vectors/PROVENANCE.md`.

## What the kit relies on

- WebCrypto in browsers and Node (X25519, AES-GCM, HKDF, HMAC, SHA), `@noble/hashes` for Argon2id, and Go's standard library (`crypto/hpke`, `crypto/ecdh`, `crypto/hkdf`) with `golang.org/x/crypto/argon2`.
- For the platform profile's password preparation: `golang.org/x/text/unicode/norm` in Go and the engine's `String.prototype.normalize` (ICU) in TypeScript. Both must normalise alike; the Unicode caveat is in SPEC.md section 11.2.
- For the relying party (SPEC sections 11.14 and 11.15): IndexedDB and non-extractable AES-GCM keys for the page's flow store; the issuer's TLS for the ID token, whose signature the page does not check, and for userinfo; Go's `net/http` for the server's userinfo call; and each product's insert-only pin table, which is what stops a substituted product key (HPKE base mode does not authenticate the sender).
- For passkeys with PRF (SPEC section 11.16): WebCrypto's HKDF and AES-GCM, and SHA-256 for the PRF salt; the authenticator's PRF, whose output the kit cannot check (any 32 bytes are accepted); and the id. server applying the client-extension allowlist to the exact text of `clientExtensionResults` before any WebAuthn library reads a credential, finding that member as strictly. The WebAuthn ceremony is the platform's.
- For the relying party id's rule (SPEC section 11.16): the WHATWG URL Standard's host parser in every engine, which reads a host that ends in a number as an IPv4 address or refuses it; the kit's check follows the standard's steps, and its tests hold it to each engine's own `URL` parser.
- For the KDF worker: module workers, structured cloning and transfer of an `ArrayBuffer`; a worker that never answers its hello leaves Argon2id to the calling thread.
- For the platform wrap (SPEC section 6.8), Wappie's and Mailie's: WebCrypto's HKDF and AES-GCM (Go's in Go), X25519 through the kit's engine for the account public key, the page comparing the opened account key's public half with the one the product's server holds for the account (Wappie's `users.public_key`), and the product keeping its wraps in a column of their own, with no other envelope of its account key starting with `0x03`; the wrap itself proves only that a holder of `sk_p` made it.
- For THCSEAL v1 and its key wrappers (SPEC section 14): Go's AES-GCM and `crypto/rand`; for `kms/awskms`, the AWS SDK for Go v2, KMS and its key policy conditioning on the encryption context, and the instance metadata service (IMDSv2 required, a hop limit of 1, the machine's configuration), with the honest limit that any process on the machine that reaches the metadata service uses the instance role; for `kms/localkek`, that release builds pass no `-tags kitdevkek`, on their command line or through `GOFLAGS`, and that its key-encryption key protects development and test data only.
- The security considerations of each format are in SPEC.md section 13.
