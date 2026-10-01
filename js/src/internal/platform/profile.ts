// The platform profile's values (SPEC section 11.1): its labels, the
// root-wrap header, and its profile for the kit's account scheme.

import type { AccountProfile, KDFBounds } from '../../account.js'
import { PlatformError } from '../../errors.js'
import { KDF_BOUNDS, SALT_LEN } from './kdfpolicy.js'
import { preparePassword } from './password.js'
import { canonicalRecoveryCode } from './recoverycode.js'

// HKDF infos and labels. They name keys; they are not credentials.
export const LABEL_PASSWORD_AUTH = 'thehappie-id/v1/password/auth'
export const LABEL_PASSWORD_WRAP = 'thehappie-id/v1/password/wrap'
export const LABEL_RECOVERY_WRAP = 'thehappie-id/v1/recovery/wrap'
export const LABEL_RECOVERY_AUTH = 'thehappie-id/v1/recovery/auth'
export const LABEL_PRODUCT_KEY = 'thehappie-id/v1/product-key'
export const LABEL_AUTH_VERIFIER = 'thehappie-id/v1/auth-verifier'
export const LABEL_RECOVERY_VERIFIER = 'thehappie-id/v1/recovery-verifier'
export const WRAP_AAD_LABEL = 'thehappie-id/root-wrap'

/** The root-wrap kinds (SPEC section 11.5). */
export type WrapKind = 'password' | 'recovery' | 'passkey'

/** The first byte of every root wrap. */
export const WRAP_VERSION = 0x01
/** The length of every root wrap: 2 + 12 + 32 + 16. */
export const WRAP_LEN = 62
/** The length of the account root. */
export const ROOT_LEN = 32

/** The second byte of a root wrap, by kind. */
export const WRAP_KIND_BYTE: Readonly<Record<WrapKind, number>> = Object.freeze({
  password: 0x01,
  recovery: 0x02,
  passkey: 0x03,
})

/** isWrapKind says whether k is a kind; own members only, so "toString" is not one. */
export function isWrapKind(k: unknown): k is WrapKind {
  return typeof k === 'string' && Object.hasOwn(WRAP_KIND_BYTE, k)
}

const bounds: KDFBounds = Object.freeze({
  min: Object.freeze({ m: KDF_BOUNDS.m.floor, t: KDF_BOUNDS.t.floor, p: KDF_BOUNDS.p.floor }),
  max: Object.freeze({ m: KDF_BOUNDS.m.ceiling, t: KDF_BOUNDS.t.ceiling, p: KDF_BOUNDS.p.ceiling }),
  maxCost: KDF_BOUNDS.mt,
  minSaltLen: SALT_LEN,
  maxSaltLen: SALT_LEN,
})

/**
 * platformAccount is the platform's profile for the kit's account scheme:
 * its labels, the presented-password profile as the preparation, the KDF
 * bounds, base64url text, the canonical recovery code, and the header of a
 * password root wrap with no legacy form. The functions of this module use
 * it; it is exported for code that calls account directly.
 */
export const platformAccount: AccountProfile = Object.freeze({
  authLabel: LABEL_PASSWORD_AUTH,
  wrapLabel: LABEL_PASSWORD_WRAP,
  recoveryKeyLabel: LABEL_RECOVERY_WRAP,
  recoveryProofLabel: LABEL_RECOVERY_AUTH,
  wrapHeader: Object.freeze([WRAP_VERSION, WRAP_KIND_BYTE.password]),
  legacyV1: false,
  encoding: 'base64url',
  prepare: (password: string) => preparePassword(password, { isNew: false }),
  bounds,
  normaliseRecovery: canonicalRecoveryCode,
} as const)

/**
 * platformRootWrap is platformAccount with the header of a root wrap of this
 * kind, 0x01 and the kind's byte: with it, account.wrapPrivateKey and
 * account.unwrapPrivateKey seal and open the 62-byte envelope (the AAD is
 * rootWrapAAD's).
 */
export function platformRootWrap(kind: WrapKind): AccountProfile {
  if (!isWrapKind(kind)) throw new PlatformError('unknown wrap kind', 'wrap')
  return Object.freeze({ ...platformAccount, wrapHeader: Object.freeze([WRAP_VERSION, WRAP_KIND_BYTE[kind]]) })
}
