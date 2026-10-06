// The password KDF (SPEC section 11.3): the prepared password and the
// account's salt become K_auth and K_wrap.
//
//   master = Argon2id(P', salt16, m, t, p, version 0x13, dkLen 32)
//   K_auth = HKDF(master, empty, "thehappie-id/v1/password/auth")
//   K_wrap = HKDF(master, empty, "thehappie-id/v1/password/wrap")
//
// This is account.derivePrepared with platformAccount, after the platform's
// own checks of the server's JSON: parameters and salts outside the bounds
// are refused before a worker is started or anything is derived. K_wrap comes
// back as a non-extractable CryptoKey, as everywhere in the kit. Each
// function takes the default worker factory first, which
// @thehappieco/kit/profiles/platform fills with the kit's own worker and
// @thehappieco/kit/profiles/platform/core leaves empty.

import { derivePreparedWith, type DeriveOptions, type Derived } from '../accountcore.js'
import type { WorkerFactory } from '../kdf.js'
import { AccountError, PlatformError } from '../../errors.js'
import type { Bytes } from '../../bytes.js'
import { checkKDF, checkSalt } from './kdfpolicy.js'
import { preparePassword } from './password.js'
import { platformAccount, ROOT_LEN } from './profile.js'

/**
 * derivePasswordWith derives the two keys from P' under kdf and the salt the
 * server handed out. It throws kdf_policy before deriving anything when they
 * are outside the bounds, and when the KDF worker refuses them. A derivation
 * that fails for no reason of its input (Argon2id itself, or the worker after
 * it was sent the password) is not a verdict on the parameters: it is the
 * account module's AccountError kdf/kdf_failed (SPEC section 11.10). The
 * caller owns prepared and zeroes it.
 */
export async function derivePasswordWith(
  defaultWorker: WorkerFactory | undefined, prepared: Bytes, salt: Bytes, kdf: unknown, options?: DeriveOptions,
): Promise<Derived> {
  const k = checkKDF(kdf)
  checkSalt(salt)
  try {
    return await derivePreparedWith(defaultWorker, platformAccount, prepared, salt, k, options)
  } catch (err) {
    if (err instanceof AccountError && err.code === 'kdf' && err.reason !== 'kdf_failed') throw new PlatformError('the key derivation was refused', 'kdf_policy')
    throw err
  }
}

/**
 * derivePasswordKeysWith prepares a presented password (no minimum length)
 * and derives its keys, as a login, an unlock or a key bundle does. The
 * bounds come first: a refused challenge does not depend on what was typed.
 * The prepared bytes are zeroed.
 */
export async function derivePasswordKeysWith(
  defaultWorker: WorkerFactory | undefined, password: string, salt: Bytes, kdf: unknown, options?: DeriveOptions,
): Promise<Derived> {
  const k = checkKDF(kdf)
  checkSalt(salt)
  const prepared = preparePassword(password, { isNew: false })
  try {
    return await derivePasswordWith(defaultWorker, prepared, salt, k, options)
  } finally {
    prepared.fill(0)
  }
}

/** newRoot returns a fresh 32-byte account root, for the caller to zero. */
export function newRoot(): Bytes {
  return crypto.getRandomValues(new Uint8Array(ROOT_LEN)) as Bytes
}
