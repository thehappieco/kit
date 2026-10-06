// Wappie's platform wrap (SPEC section 6.8, the platform's decision 0023):
// the Wappie account key (section 6.4, the X25519 key every grant, the AI
// keychain and the personal contacts are sealed to) wrapped under a key
// derived from sk_p, the product key id. delivers to Wappie's page (section
// 11.12). The account key is kept, not replaced.
//
//   K_pw = HKDF-SHA256(IKM = sk_p (32 bytes), salt = UTF-8("wappie/platform-wrap/v1"),
//                      info = JCS(["wappie/platform-wrap", 1, user_id, sub, product_key_id]), L = 32)
//   aad  = JCS(["wappie/platform-wrap", 1, user_id, sub, product_key_id, base64url(account_public_key)])
//   wrap = 0x03 || nonce (12) || AES-256-GCM(K_pw, nonce, account_key (32), aad)       61 bytes
//
// user_id is Wappie's users.id (the sub itself for an account created
// through id., the old id for a linked one), sub is id.'s account id, both
// lowercase hyphenated UUIDs; product_key_id is "wappie:<epoch>"; base64url
// is without padding. Every element is in the restricted alphabet of
// section 11.1, so the JSON is the same from any serialiser.
//
// Symmetric on purpose: an HPKE seal to pk_p could be made by anyone holding
// pk_p, the server included, which could then plant an account key of its
// choosing. Only a holder of sk_p makes this wrap. K_pw exists only as a
// non-extractable CryptoKey, and the copies of sk_p and of the account key
// handed to WebCrypto are zeroed; sealPlatformWrap opens what it made and
// compares it (the self-test); openPlatformWrap checks that the key it
// opened is the private half of the binding's account public key, which the
// caller also compares with users.public_key. The account public key is
// computed through hpke.publicFromPrivate, the kit's X25519 engine, so
// WebKit for Linux takes an account key whose first byte is zero.
//
// Exported by @thehappieco/kit/profiles/wappie. From Wappie's console
// (github.com/thehappieco/wappie-cloud, web/platform/platformWrap.ts at
// 3bfee27), with the names it had but PLATFORM_WRAP_HEADER, whose value is
// 0x03 where the console had 0x01, the passkey envelope's (section 7); its
// imports made relative; checkPlatformWrapShape added; and no nonce
// parameter: no function the kit ships seals under a nonce its caller chose
// (the tests replay one by replacing crypto.getRandomValues).

import { equal, encodeUTF8, toBase64URL, type Bytes } from '../../bytes.js'
import { PlatformWrapError } from '../../errors.js'
import { publicFromPrivate } from '../../hpke.js'
import { canonicalJSON } from '../../jcs.js'
import { isProductKeyId } from '../platform/keydelivery.js'
import { isSub } from '../platform/rootwrap.js'

/**
 * PLATFORM_WRAP_HEADER is the first byte of a platform wrap. Wappie's other
 * 61-byte envelopes of the account key start with 0x02 (the password and
 * recovery wraps) and 0x01 (the passkey envelope), so a wrap in the wrong
 * column fails at its header, not at its tag.
 */
export const PLATFORM_WRAP_HEADER = 0x03
/** PLATFORM_WRAP_LEN is a wrap's length: the header, the nonce, the 32-byte account key and the tag. */
export const PLATFORM_WRAP_LEN = 61
/** PLATFORM_WRAP_LABEL opens the HKDF info and the AAD. */
export const PLATFORM_WRAP_LABEL = 'wappie/platform-wrap'
/** PLATFORM_WRAP_SALT is the HKDF salt of K_pw. */
export const PLATFORM_WRAP_SALT = 'wappie/platform-wrap/v1'
/** PLATFORM_WRAP_PRODUCT is the product of the product key ids a wrap is made for. */
export const PLATFORM_WRAP_PRODUCT = 'wappie'

const NONCE_LEN = 12
const KEY_LEN = 32

/** What a wrap is bound to. */
export interface PlatformWrapBinding {
  /** Wappie's users.id. */
  userId: string
  /** id.'s account id. */
  sub: string
  /** "wappie:<epoch>". */
  productKeyId: string
  /** users.public_key: the account key's public half, 32 bytes. */
  accountPublicKey: Uint8Array
}

function bytes(b: Uint8Array): Bytes {
  return new Uint8Array(b) as Bytes
}

function check(b: PlatformWrapBinding): void {
  if (typeof b !== 'object' || b === null) throw new PlatformWrapError('no binding')
  if (!isSub(b.userId)) throw new PlatformWrapError('user_id is not a lowercase UUID')
  if (!isSub(b.sub)) throw new PlatformWrapError('sub is not a lowercase UUID')
  if (!isProductKeyId(b.productKeyId) || !b.productKeyId.startsWith(`${PLATFORM_WRAP_PRODUCT}:`)) {
    throw new PlatformWrapError('product_key_id is not a Wappie product key id')
  }
  if (!(b.accountPublicKey instanceof Uint8Array) || b.accountPublicKey.length !== KEY_LEN) {
    throw new PlatformWrapError('the account public key is not 32 bytes')
  }
}

/** platformWrapInfo is the HKDF info of K_pw: JCS(["wappie/platform-wrap", 1, user_id, sub, product_key_id]). */
export function platformWrapInfo(b: PlatformWrapBinding): Bytes {
  check(b)
  return encodeUTF8(canonicalJSON([PLATFORM_WRAP_LABEL, 1, b.userId, b.sub, b.productKeyId]))
}

/**
 * platformWrapAAD is the AES-GCM additional data of a wrap:
 * JCS(["wappie/platform-wrap", 1, user_id, sub, product_key_id, base64url(account_public_key)]).
 */
export function platformWrapAAD(b: PlatformWrapBinding): Bytes {
  check(b)
  return encodeUTF8(canonicalJSON([PLATFORM_WRAP_LABEL, 1, b.userId, b.sub, b.productKeyId, toBase64URL(bytes(b.accountPublicKey))]))
}

/** wrapKey derives K_pw as a non-extractable AES-256-GCM key; the copy of sk_p is zeroed. */
async function wrapKey(productKey: Uint8Array, b: PlatformWrapBinding): Promise<CryptoKey> {
  if (!(productKey instanceof Uint8Array) || productKey.length !== KEY_LEN) throw new PlatformWrapError('the product key is not 32 bytes')
  const info = platformWrapInfo(b)
  const raw = bytes(productKey)
  try {
    const ikm = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey'])
    return await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: encodeUTF8(PLATFORM_WRAP_SALT), info },
      ikm,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    )
  } catch {
    throw new PlatformWrapError('K_pw cannot be derived')
  } finally {
    raw.fill(0)
  }
}

/** publicHalf is X25519(key, 9), through the kit's X25519 engine; the copy of the key is zeroed. */
async function publicHalf(accountKey: Uint8Array): Promise<Bytes> {
  const raw = bytes(accountKey)
  try {
    return await publicFromPrivate(raw)
  } catch {
    throw new PlatformWrapError('not an X25519 key, or no X25519 here')
  } finally {
    raw.fill(0)
  }
}

/**
 * checkPlatformWrapShape is what Wappie's server checks of a wrap it is
 * sent, which it cannot open: PLATFORM_WRAP_LEN (61) bytes starting with
 * PLATFORM_WRAP_HEADER (0x03).
 */
export function checkPlatformWrapShape(wrap: Uint8Array): void {
  if (!(wrap instanceof Uint8Array) || wrap.length !== PLATFORM_WRAP_LEN || wrap[0] !== PLATFORM_WRAP_HEADER) {
    throw new PlatformWrapError(`not a wrap of ${PLATFORM_WRAP_LEN} bytes starting with 0x03`)
  }
}

/**
 * sealPlatformWrap wraps the 32-byte account key under the product key sk_p
 * for b, with a fresh nonce. It refuses, before anything is encrypted, an
 * account key that is not 32 bytes or whose public half is not
 * b.accountPublicKey (compared in constant time), a product key that is not
 * 32 bytes and a binding outside its spelling; and it opens what it made and
 * compares before it returns it. The caller zeroes its keys.
 */
export async function sealPlatformWrap(productKey: Uint8Array, accountKey: Uint8Array, b: PlatformWrapBinding): Promise<Bytes> {
  if (!(accountKey instanceof Uint8Array) || accountKey.length !== KEY_LEN) throw new PlatformWrapError('the account key is not 32 bytes')
  check(b)
  if (!equal(await publicHalf(accountKey), bytes(b.accountPublicKey))) throw new PlatformWrapError("the account key is not the binding's")
  const key = await wrapKey(productKey, b)
  // Drawn once every input has passed, as in Go.
  const iv = crypto.getRandomValues(new Uint8Array(NONCE_LEN)) as Bytes
  const plain = bytes(accountKey)
  let sealed: Uint8Array
  try {
    sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: platformWrapAAD(b), tagLength: 128 }, key, plain))
  } catch {
    throw new PlatformWrapError('the account key cannot be sealed')
  } finally {
    plain.fill(0)
  }
  const out = new Uint8Array(PLATFORM_WRAP_LEN) as Bytes
  out[0] = PLATFORM_WRAP_HEADER
  out.set(iv, 1)
  out.set(sealed, 1 + NONCE_LEN)
  let again: Bytes | undefined
  try {
    again = await openPlatformWrap(productKey, out, b)
    const want = bytes(accountKey)
    const same = equal(again, want)
    want.fill(0)
    if (!same) throw new Error('mismatch')
  } catch {
    throw new PlatformWrapError('the new wrap failed its self-test')
  } finally {
    again?.fill(0)
  }
  return out
}

/**
 * openPlatformWrap opens a wrap with the product key sk_p for b and returns
 * the account key, which the caller zeroes. It checks the shape first
 * (checkPlatformWrapShape), then the product key, the binding and the tag,
 * and that the key it opened is the private half of b.accountPublicKey,
 * compared in constant time; a key that is not is zeroed and refused.
 */
export async function openPlatformWrap(productKey: Uint8Array, wrap: Uint8Array, b: PlatformWrapBinding): Promise<Bytes> {
  checkPlatformWrapShape(wrap)
  const key = await wrapKey(productKey, b)
  let opened: Bytes
  try {
    opened = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: bytes(wrap.subarray(1, 1 + NONCE_LEN)), additionalData: platformWrapAAD(b), tagLength: 128 },
        key,
        bytes(wrap.subarray(1 + NONCE_LEN)),
      ),
    ) as Bytes
  } catch {
    throw new PlatformWrapError('the wrap does not open')
  }
  try {
    if (opened.length !== KEY_LEN || !equal(await publicHalf(opened), bytes(b.accountPublicKey))) throw new Error('mismatch')
  } catch {
    opened.fill(0)
    throw new PlatformWrapError('the wrap names another account key')
  }
  return opened
}
