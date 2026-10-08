// Wappie's platform wrap (SPEC section 6.8, the platform's decision 0023):
// Wappie's account key (section 6.4, the X25519 key every grant, the AI
// keychain and the personal contacts are sealed to) under a key derived
// from sk_p, the product key id. delivers to Wappie's page (section 11.12).
// Since v0.6.0 it is the kit's generic platform wrap
// (@thehappieco/kit/platformwrap) under Wappie's labels, wappiePlatformWrap;
// every byte is v0.5.0's, and these are the names v0.5.0 exported from
// @thehappieco/kit/profiles/wappie, bound to those labels.
//
//   K_pw = HKDF-SHA256(IKM = sk_p (32 bytes), salt = UTF-8("wappie/platform-wrap/v1"),
//                      info = JCS(["wappie/platform-wrap", 1, user_id, sub, product_key_id]), L = 32)
//   aad  = JCS(["wappie/platform-wrap", 1, user_id, sub, product_key_id, base64url(account_public_key)])
//   wrap = 0x03 || nonce (12) || AES-256-GCM(K_pw, nonce, account_key (32), aad)       61 bytes
//
// user_id is Wappie's users.id (the sub itself for an account created
// through id., the old id for a linked one); product_key_id is
// "wappie:<epoch>". Wappie's server never opens a wrap; it checks its shape
// (checkPlatformWrapShape).

import type { Bytes } from '../../bytes.js'
import {
  checkPlatformWrapShape as checkShape,
  openPlatformWrap as open,
  PLATFORM_WRAP_HEADER as HEADER,
  PLATFORM_WRAP_LEN as LEN,
  platformWrapAAD as aad,
  platformWrapInfo as info,
  sealPlatformWrap as seal,
  type PlatformWrapBinding,
  type PlatformWrapProfile,
} from '../platformwrap.js'

export type { PlatformWrapBinding }

/**
 * PLATFORM_WRAP_HEADER is the first byte of a platform wrap. Wappie's other
 * 61-byte envelopes of the account key start with 0x02 (the password and
 * recovery wraps) and 0x01 (the passkey envelope), so a wrap in the wrong
 * column fails at its header, not at its tag.
 */
export const PLATFORM_WRAP_HEADER = HEADER
/** PLATFORM_WRAP_LEN is a wrap's length: the header, the nonce, the 32-byte account key and the tag. */
export const PLATFORM_WRAP_LEN = LEN
/** PLATFORM_WRAP_LABEL opens the HKDF info and the AAD. */
export const PLATFORM_WRAP_LABEL = 'wappie/platform-wrap'
/** PLATFORM_WRAP_SALT is the HKDF salt of K_pw. */
export const PLATFORM_WRAP_SALT = 'wappie/platform-wrap/v1'
/** PLATFORM_WRAP_PRODUCT is the product of the product key ids a wrap is made for. */
export const PLATFORM_WRAP_PRODUCT = 'wappie'

/** wappiePlatformWrap is Wappie's platform-wrap profile, for @thehappieco/kit/platformwrap. */
export const wappiePlatformWrap: PlatformWrapProfile = Object.freeze({ product: PLATFORM_WRAP_PRODUCT, salt: PLATFORM_WRAP_SALT, label: PLATFORM_WRAP_LABEL })

/** platformWrapInfo is the HKDF info of K_pw: JCS(["wappie/platform-wrap", 1, user_id, sub, product_key_id]). */
export function platformWrapInfo(b: PlatformWrapBinding): Bytes {
  return info(wappiePlatformWrap, b)
}

/**
 * platformWrapAAD is the AES-GCM additional data of a wrap:
 * JCS(["wappie/platform-wrap", 1, user_id, sub, product_key_id, base64url(account_public_key)]).
 */
export function platformWrapAAD(b: PlatformWrapBinding): Bytes {
  return aad(wappiePlatformWrap, b)
}

/**
 * sealPlatformWrap wraps the 32-byte account key under the product key sk_p
 * for b, under Wappie's labels, with a fresh nonce: the generic
 * sealPlatformWrap under wappiePlatformWrap. The caller zeroes its keys.
 */
export function sealPlatformWrap(productKey: Uint8Array, accountKey: Uint8Array, b: PlatformWrapBinding): Promise<Bytes> {
  return seal(wappiePlatformWrap, productKey, accountKey, b)
}

/**
 * openPlatformWrap opens a wrap with the product key sk_p for b, under
 * Wappie's labels, and returns the account key, which the caller zeroes and
 * whose public half the caller also compares with users.public_key: the
 * generic openPlatformWrap under wappiePlatformWrap.
 */
export function openPlatformWrap(productKey: Uint8Array, wrap: Uint8Array, b: PlatformWrapBinding): Promise<Bytes> {
  return open(wappiePlatformWrap, productKey, wrap, b)
}

/**
 * checkPlatformWrapShape is what Wappie's server checks of a wrap it is
 * sent, which it cannot open: PLATFORM_WRAP_LEN (61) bytes starting with
 * PLATFORM_WRAP_HEADER (0x03).
 */
export function checkPlatformWrapShape(wrap: Uint8Array): void {
  checkShape(wrap)
}
