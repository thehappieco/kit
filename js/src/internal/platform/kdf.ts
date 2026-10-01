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
// back as a non-extractable CryptoKey, as everywhere in the kit.

import { derivePrepared, type DeriveOptions, type Derived } from '../../account.js'
import { AccountError, PlatformError } from '../../errors.js'
import type { Bytes } from '../../bytes.js'
import { checkKDF, checkSalt } from './kdfpolicy.js'
import { preparePassword } from './password.js'
import { platformAccount, ROOT_LEN } from './profile.js'

/**
 * derivePassword derives the two keys from P' under kdf and the salt the
 * server handed out. It throws kdf_policy before deriving anything when they
 * are outside the bounds. The caller owns prepared and zeroes it.
 */
export async function derivePassword(prepared: Bytes, salt: Bytes, kdf: unknown, options?: DeriveOptions): Promise<Derived> {
  const k = checkKDF(kdf)
  checkSalt(salt)
  try {
    return await derivePrepared(platformAccount, prepared, salt, k, options)
  } catch (err) {
    if (err instanceof AccountError && err.code === 'kdf') throw new PlatformError('the key derivation was refused', 'kdf_policy')
    throw err
  }
}

/**
 * derivePasswordKeys prepares a presented password (no minimum length) and
 * derives its keys, as a login, an unlock or a key bundle does. The bounds
 * come first: a refused challenge does not depend on what was typed. The
 * prepared bytes are zeroed.
 */
export async function derivePasswordKeys(password: string, salt: Bytes, kdf: unknown, options?: DeriveOptions): Promise<Derived> {
  const k = checkKDF(kdf)
  checkSalt(salt)
  const prepared = preparePassword(password, { isNew: false })
  try {
    return await derivePassword(prepared, salt, k, options)
  } finally {
    prepared.fill(0)
  }
}

/** newRoot returns a fresh 32-byte account root, for the caller to zero. */
export function newRoot(): Bytes {
  return crypto.getRandomValues(new Uint8Array(ROOT_LEN)) as Bytes
}
