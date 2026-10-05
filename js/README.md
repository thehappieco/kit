# @thehappieco/kit

The Happie Co's shared cryptographic kit for the browser and Node: HPKE (RFC 9180, one fixed suite), the sealed envelope, the zero-knowledge account scheme (Argon2id, wraps, recovery codes), passkey PRF wraps, a key at rest in the browser, request signing, the platform's account protocol (id-v1, parts 1 to 3: the account core, sealed key delivery and PKCE, and passkeys with PRF), and the relying party of the platform's id.

Import by subpath (`@thehappieco/kit/seal`, `/account`, `/hpke`, `/passkey`, `/browserAccount`, `/reqhmac`, `/jcs`, `/bytes`, `/errors`, `/profiles/wappie`, `/profiles/platform`, `/oidc-rp`). Every function of the generic modules takes a profile, the product's labels and prefixes, as its first argument. `/profiles/platform` is the platform's protocol itself: its functions take no profile. `/oidc-rp` takes the product's constants (issuer, client, redirect URI, scopes and key label) and keeps a delivered key only once the product's server has named it (`finishSignIn`). Nothing under `dist/internal/` is a subpath export.

The format, the profiles and the test vectors are specified in SPEC.md at https://github.com/thehappieco/kit, at the tag matching this version. Releases are GitHub release assets, pinned by integrity; the package is not published to a registry.

Licensed under Apache-2.0. See LICENSE and NOTICE.
