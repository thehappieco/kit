// The platform profile (SPEC section 11) of The Happie Co platform's
// protocol id-v1 (thehappie-id/v1). Part 1, the account core: the password
// profile thehappie-password/v1 and its KDF bounds, the 62-byte root wrap,
// the recovery code, per-product keys, the server verifiers, email
// normalisation and the strict key-bundle reader. Part 2: the sealed
// delivery of a product key to the product's page (section 11.12), PKCE
// S256 (section 11.13), and the X25519 helpers the relying party's page
// uses. Part 3: passkeys with PRF (section 11.16), the public PRF salt of a
// relying party, K_pk from a passkey's PRF output and the kind-3 root wrap
// under it, and the allowlist of WebAuthn client extension results. The
// same in Go (profiles/platform), and pinned by the platform's vectors
// (vectors/platform/id-v1). The relying party itself is
// @thehappieco/kit/oidc-rp.
//
// Unlike the kit's generic modules, these functions take no profile: they
// are the platform's protocol. Where a generic module already does the work,
// it is handed the platform's values (platformAccount): Argon2id and the
// auth/wrap split are account.derivePrepared, the recovery branches
// account.recoveryKey and account.recoveryProof, a root wrap
// account.wrapPrivateKey and account.unwrapPrivateKey, the AAD jcs, and a
// product's public key hpke. Derived wrap keys are non-extractable
// CryptoKeys; the root-wrap functions also take 32 raw bytes.
//
// Every refusal is a PlatformError whose code is one of the protocol's error
// names, and whose message never holds the refused value. What stays in the
// platform: the product registry, the account ceremonies built from these
// pieces, page rules such as refusing a password equal to the address, the
// WebAuthn ceremony, the decoy salts and every server secret. The
// implementation is in ../internal/platform, taken from the platform's
// web/shared/crypto at commits 5e66d84 (part 1), 4476bf4 (part 2) and
// b5d9f69 (part 3). Key delivery's HPKE wipes its key schedule and is
// internal: no page code can choose an ephemeral key.
//
// This entry is @thehappieco/kit/profiles/platform/core with the kit's own
// KDF worker (kdf.worker.js) as the default of derivePassword,
// derivePasswordKeys and openKeyBundle, so a bundle that imports it emits
// that worker.

import type { Bytes } from '../bytes.js'
import type { DeriveOptions, Derived } from '../internal/accountcore.js'
import { kitWorker } from '../internal/kdfworker.js'
import { derivePasswordKeysWith, derivePasswordWith } from '../internal/platform/kdf.js'
import { openKeyBundleWith } from '../internal/platform/keybundle.js'

export * from './platform/core.js'

/**
 * derivePassword derives K_auth and K_wrap from P' under kdf and the salt
 * the server handed out (SPEC section 11.3). It throws kdf_policy before
 * deriving anything when they are outside the bounds. Argon2id runs in the
 * kit's worker, or options.worker's, where there are Workers, and on the
 * calling thread otherwise. The caller owns prepared and zeroes it.
 */
export function derivePassword(prepared: Bytes, salt: Bytes, kdf: unknown, options?: DeriveOptions): Promise<Derived> {
  return derivePasswordWith(kitWorker, prepared, salt, kdf, options)
}

/**
 * derivePasswordKeys prepares a presented password (no minimum length) and
 * derives its keys, as derivePassword does; the bounds come first. The
 * prepared bytes are zeroed.
 */
export function derivePasswordKeys(password: string, salt: Bytes, kdf: unknown, options?: DeriveOptions): Promise<Derived> {
  return derivePasswordKeysWith(kitWorker, password, salt, kdf, options)
}

/**
 * openKeyBundle opens a key bundle with the password (SPEC section 11.9),
 * deriving as derivePassword does, and returns the root, for the caller to
 * zero, once every product key has been checked against it.
 */
export function openKeyBundle(input: unknown, password: string, options?: DeriveOptions): Promise<Bytes> {
  return openKeyBundleWith(kitWorker, input, password, options)
}
