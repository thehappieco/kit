// The password KDF policy (SPEC section 11.3): the bounds Argon2id parameters
// and the salt must fall within before anything is derived.
//
// The rule it enforces: the server cannot choose how cheap a guess at the
// password is. The parameters come from the server at login (and from a file,
// for a key bundle), so a hostile or broken server could otherwise answer
// m = 8 KiB, t = 1 and turn the next login into an offline target a thousand
// times cheaper, or answer m = 4 GiB and crash the tab. These constants are
// compiled in; the server cannot change them. From the platform's
// web/shared/crypto/kdfpolicy.ts.

import type { Bytes } from '../../bytes.js'
import { PlatformError } from '../../errors.js'

export type KDF = { alg: 'argon2id'; m: number; t: number; p: number }

/** KDF_BOUNDS are the floor and ceiling of every parameter. */
export const KDF_BOUNDS = Object.freeze({
  m: Object.freeze({ floor: 65536, ceiling: 262144 }),
  t: Object.freeze({ floor: 3, ceiling: 10 }),
  p: Object.freeze({ floor: 1, ceiling: 4 }),
  /** Ceiling of m × t, so the slowest allowed derivation stays bearable on a phone. */
  mt: 1048576,
})

/** DEFAULT_KDF is what new password material is derived with: the floor. */
export const DEFAULT_KDF: Readonly<KDF> = Object.freeze({ alg: 'argon2id', m: 65536, t: 3, p: 1 })

/** SALT_LEN is the only accepted salt length. The salt is the server's, fixed per address. */
export const SALT_LEN = 16

const KDF_KEYS = ['alg', 'm', 't', 'p']

function within(v: unknown, b: { floor: number; ceiling: number }): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= b.floor && v <= b.ceiling
}

/**
 * checkKDF returns a clean copy of k if it is inside the bounds, and throws
 * kdf_policy otherwise.
 *
 * It takes unknown because its input is server JSON. Members other than the
 * four are refused rather than ignored: a parameter this version does not
 * know might change the derivation. account.checkKDFParams compares numbers
 * and would let 65536.5 through to Argon2id; this does not.
 */
export function checkKDF(k: unknown): KDF {
  if (typeof k !== 'object' || k === null || Array.isArray(k)) {
    throw new PlatformError('the KDF parameters are not an object', 'kdf_policy')
  }
  const o = k as Record<string, unknown>
  for (const key of Object.keys(o)) {
    if (!KDF_KEYS.includes(key)) throw new PlatformError('unknown KDF parameter', 'kdf_policy')
  }
  if (o['alg'] !== 'argon2id') throw new PlatformError('the KDF is not argon2id', 'kdf_policy')
  const { m, t, p } = o
  if (!within(m, KDF_BOUNDS.m)) throw new PlatformError('m is out of bounds', 'kdf_policy')
  if (!within(t, KDF_BOUNDS.t)) throw new PlatformError('t is out of bounds', 'kdf_policy')
  if (!within(p, KDF_BOUNDS.p)) throw new PlatformError('p is out of bounds', 'kdf_policy')
  if (m * t > KDF_BOUNDS.mt) throw new PlatformError('m*t is out of bounds', 'kdf_policy')
  return { alg: 'argon2id', m, t, p }
}

/** checkSalt refuses a KDF salt that is not exactly 16 bytes. */
export function checkSalt(salt: unknown): asserts salt is Bytes {
  if (!(salt instanceof Uint8Array) || salt.length !== SALT_LEN) {
    throw new PlatformError('the KDF salt is not 16 bytes', 'kdf_policy')
  }
}
