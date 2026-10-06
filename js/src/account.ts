// An account: what a password turns into, and what that opens.
//
// The password never leaves the client. Argon2id turns it into a master key,
// which HKDF splits into two independent branches:
//
//   auth: sent to the server and stored there only as a slow or
//         domain-separated hash. Proves who you are; opens nothing.
//   wrap: never transmitted. Unwraps the account's key.
//
// A recovery code is the second way back in: 150 random bits, written down by
// hand, split by HKDF into a key that wraps the same account key and a proof
// that is sent.
//
// From Wappie's packages/client/src/crypto/account.ts. The labels, the wrap
// header, the password preparation, the KDF bounds and the text encoding are
// the profile's; what a wrap binds to (its AAD) is the caller's, built by the
// profile's own helper.
//
// The implementation is internal/accountcore.ts, which names no worker file.
// This module adds the kit's own KDF worker (kdf.worker.js) as the default of
// derive, derivePrepared and bind(p).derive, so a bundle that imports it
// emits that worker; a bundle that reaches the account core only through
// @thehappieco/kit/profiles/platform/core or @thehappieco/kit/oidc-rp emits
// none.
//
// Argon2id is the one place the kit uses a dependency (@noble/hashes):
// WebCrypto has PBKDF2 and nothing memory-hard, and the wrapped key sits in a
// server's database, which is the threat this scheme is built against.

import type { Bytes } from './bytes.js'
import { bindWith, deriveWith, derivePreparedWith, type AccountProfile, type DeriveOptions, type Derived, type KDFParams } from './internal/accountcore.js'
import { kitWorker } from './internal/kdfworker.js'

export {
  AccountError,
  checkKDFParams,
  checkSalt,
  defaultKDFParams,
  freshSalt,
  generateAccountKeys,
  newRecoveryCode,
  normaliseRecoveryCode,
  recoveryKey,
  recoveryProof,
  unwrapPrivateKey,
  wrapPrivateKey,
  type AccountErrorCode,
  type AccountErrorReason,
  type AccountKeys,
  type AccountProfile,
  type DeriveOptions,
  type Derived,
  type KDFBounds,
  type KDFParams,
  type Unwrapped,
} from './internal/accountcore.js'

/**
 * derive turns a password into the two branches:
 *
 *   master = Argon2id(prepared password, salt, m, t, p, dkLen 32, version 0x13)
 *   auth   = HKDF-SHA256(master, salt empty, info authLabel)
 *   wrap   = HKDF-SHA256(master, salt empty, info wrapLabel)
 *
 * The parameters and the salt are checked against the profile's bounds before
 * anything is derived. Argon2id runs in the kit's worker, or options.worker's,
 * where there are Workers, and on the calling thread otherwise. The prepared
 * password bytes, the master key and the raw auth and wrap keys are zeroed
 * before it returns; the password string itself cannot be, nor can authKey, a
 * string, which is sent as text anyway.
 */
export async function derive(p: AccountProfile, password: string, salt: Bytes, params: KDFParams, options: DeriveOptions = {}): Promise<Derived> {
  return deriveWith(kitWorker, p, password, salt, params, options)
}

/**
 * derivePrepared is derive for a password the caller has already prepared:
 * the bytes Argon2id reads, such as a profile's own preparation produced
 * them. The profile's prepare is not called. The parameters and the salt are
 * checked exactly as derive checks them, before anything is derived, and the
 * master key and the raw auth and wrap keys are zeroed before it returns;
 * prepared stays the caller's to zero.
 */
export async function derivePrepared(p: AccountProfile, prepared: Bytes, salt: Bytes, params: KDFParams, options: DeriveOptions = {}): Promise<Derived> {
  return derivePreparedWith(kitWorker, p, prepared, salt, params, options)
}

/** bind fixes a profile, for a product's own wrappers. */
export function bind(p: AccountProfile) {
  return bindWith(kitWorker, p)
}
