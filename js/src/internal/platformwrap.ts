// The platform wrap (SPEC section 6.8): a product's account key (section
// 6.4) wrapped under a key derived from sk_p, the product key the platform's
// id. delivers to the product's page (sections 11.4 and 11.12), under the
// product's labels, a PlatformWrapProfile. The account key is kept, not
// replaced. Wappie's wrap (the platform's decision 0023) is this
// construction under wappiePlatformWrap (@thehappieco/kit/profiles/wappie).
//
//   K_pw = HKDF-SHA256(IKM = sk_p (32 bytes), salt = UTF-8(profile salt),
//                      info = JCS([label, 1, user_id, sub, product_key_id]), L = 32)
//   aad  = JCS([label, 1, user_id, sub, product_key_id, base64url(account_public_key)])
//   wrap = 0x03 || nonce (12) || AES-256-GCM(K_pw, nonce, account_key (32), aad)       61 bytes
//
// user_id is the product's id of the account (the sub itself for an account
// created through id., the product's old id for a linked one), sub is id.'s
// account id, both lowercase hyphenated UUIDs; product_key_id is the
// profile's product, ":" and an epoch; base64url is without padding. Every
// element is in the restricted alphabet of section 11.1, so the JSON is the
// same from any serialiser.
//
// Symmetric on purpose: an HPKE seal to pk_p could be made by anyone holding
// pk_p, the product's server included, which could then plant an account
// key of its choosing. Only a holder of sk_p makes this wrap. K_pw exists
// only as a non-extractable CryptoKey, and the copies of sk_p and of the
// account key handed to WebCrypto are zeroed; sealPlatformWrap opens what it
// made and compares it (the self-test); openPlatformWrap checks that the key
// it opened is the private half of the binding's account public key, which
// the caller also compares with the one its server holds. The account public
// key is computed through hpke.publicFromPrivate, the kit's X25519 engine, so
// WebKit for Linux takes an account key whose first byte is zero. No function
// seals under a nonce its caller chose (the tests replay one by replacing
// crypto.getRandomValues).
//
// Exported by @thehappieco/kit/platformwrap. Generalised in v0.6.0 from
// Wappie's platform wrap of v0.5.0 (src/internal/wappie/platformwrap.ts
// then), which came from Wappie's console (github.com/thehappieco/wappie-cloud,
// web/platform/platformWrap.ts at 3bfee27) with the header 0x03 where the
// console had 0x01: the profile is the first argument, as in every generic
// module of the kit, and the refusal of another product's key id names the
// profile's product.

import { equal, encodeUTF8, toBase64URL, type Bytes } from '../bytes.js'
import { PlatformWrapError } from '../errors.js'
import { publicFromPrivate } from '../hpke.js'
import { canonicalJSON } from '../jcs.js'
import { isProductKeyId } from './platform/keydelivery.js'
import { isProduct } from './platform/productkey.js'
import { isSub } from './platform/rootwrap.js'

/**
 * PLATFORM_WRAP_HEADER is the first byte of every product's wrap. A
 * product's other 61-byte envelopes of its account key must not start with
 * it (Wappie's start with 0x01, its passkey envelope, and 0x02, its password
 * and recovery wraps), so a wrap in the wrong column fails at its header,
 * not at its tag.
 */
export const PLATFORM_WRAP_HEADER = 0x03
/** PLATFORM_WRAP_LEN is a wrap's length: the header, the nonce, the 32-byte account key and the tag. */
export const PLATFORM_WRAP_LEN = 61
/** PLATFORM_WRAP_VERSION is the format's version, the 1 in the info and the AAD. */
export const PLATFORM_WRAP_VERSION = 1

/**
 * A product's labels. Its values are wire format: a wrap opens only under the profile it was sealed under.
 * A product's salt and label must differ from every label of the kit's profiles and from every other
 * product's (SPEC sections 3.3 and 6.8); that is the rule of whoever defines the profile, and nothing here checks it.
 */
export interface PlatformWrapProfile {
  /** The product of the product key ids a wrap is made for, a product id of SPEC section 11.4 ("wappie"). */
  readonly product: string
  /** The HKDF salt of K_pw ("wappie/platform-wrap/v1"). */
  readonly salt: string
  /** Opens the HKDF info and the AAD ("wappie/platform-wrap"). */
  readonly label: string
}

/** What a wrap is bound to. */
export interface PlatformWrapBinding {
  /** The product's id of the account (Wappie's users.id). */
  userId: string
  /** id.'s account id. */
  sub: string
  /** The profile's product, ":" and an epoch ("wappie:1"). */
  productKeyId: string
  /** The account key's public half as the product's server holds it (Wappie's users.public_key), 32 bytes. */
  accountPublicKey: Uint8Array
}

const NONCE_LEN = 12
const KEY_LEN = 32

// A salt or a label is a non-empty string of the restricted JSON AAD's
// alphabet (section 11.1).
const LABEL = /^[A-Za-z0-9._:/|@-]+$/

function bytes(b: Uint8Array): Bytes {
  return new Uint8Array(b) as Bytes
}

function checkProfile(p: PlatformWrapProfile): void {
  if (typeof p !== 'object' || p === null || !isProduct(p.product) ||
    typeof p.salt !== 'string' || !LABEL.test(p.salt) || typeof p.label !== 'string' || !LABEL.test(p.label)) {
    throw new PlatformWrapError('not a platform-wrap profile')
  }
}

function check(p: PlatformWrapProfile, b: PlatformWrapBinding): void {
  checkProfile(p)
  if (typeof b !== 'object' || b === null) throw new PlatformWrapError('no binding')
  if (!isSub(b.userId)) throw new PlatformWrapError('user_id is not a lowercase UUID')
  if (!isSub(b.sub)) throw new PlatformWrapError('sub is not a lowercase UUID')
  if (!isProductKeyId(b.productKeyId) || !b.productKeyId.startsWith(`${p.product}:`)) {
    throw new PlatformWrapError(`product_key_id is not a product key id of ${p.product}`)
  }
  if (!(b.accountPublicKey instanceof Uint8Array) || b.accountPublicKey.length !== KEY_LEN) {
    throw new PlatformWrapError('the account public key is not 32 bytes')
  }
}

/** platformWrapInfo is the HKDF info of K_pw: JCS([label, 1, user_id, sub, product_key_id]). */
export function platformWrapInfo(p: PlatformWrapProfile, b: PlatformWrapBinding): Bytes {
  check(p, b)
  return encodeUTF8(canonicalJSON([p.label, PLATFORM_WRAP_VERSION, b.userId, b.sub, b.productKeyId]))
}

/**
 * platformWrapAAD is the AES-GCM additional data of a wrap:
 * JCS([label, 1, user_id, sub, product_key_id, base64url(account_public_key)]).
 */
export function platformWrapAAD(p: PlatformWrapProfile, b: PlatformWrapBinding): Bytes {
  check(p, b)
  return encodeUTF8(canonicalJSON([p.label, PLATFORM_WRAP_VERSION, b.userId, b.sub, b.productKeyId, toBase64URL(bytes(b.accountPublicKey))]))
}

/** wrapKey derives K_pw as a non-extractable AES-256-GCM key; the copy of sk_p is zeroed. */
async function wrapKey(p: PlatformWrapProfile, productKey: Uint8Array, b: PlatformWrapBinding): Promise<CryptoKey> {
  if (!(productKey instanceof Uint8Array) || productKey.length !== KEY_LEN) throw new PlatformWrapError('the product key is not 32 bytes')
  const info = platformWrapInfo(p, b)
  const raw = bytes(productKey)
  try {
    const ikm = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey'])
    return await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: encodeUTF8(p.salt), info },
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
 * checkPlatformWrapShape is what a product's server checks of a wrap it is
 * sent, which it cannot open: PLATFORM_WRAP_LEN (61) bytes starting with
 * PLATFORM_WRAP_HEADER (0x03). It is the same for every product: a wrap of
 * one product has the shape of another's, and each product keeps its wraps
 * in a column of its own.
 */
export function checkPlatformWrapShape(wrap: Uint8Array): void {
  if (!(wrap instanceof Uint8Array) || wrap.length !== PLATFORM_WRAP_LEN || wrap[0] !== PLATFORM_WRAP_HEADER) {
    throw new PlatformWrapError(`not a wrap of ${PLATFORM_WRAP_LEN} bytes starting with 0x03`)
  }
}

/**
 * sealPlatformWrap wraps the 32-byte account key under the product key sk_p
 * for b, under p's labels, with a fresh nonce. It refuses, before anything
 * is encrypted, an account key that is not 32 bytes or whose public half is
 * not b.accountPublicKey (compared in constant time), a product key that is
 * not 32 bytes, and a profile or a binding outside its spelling; and it
 * opens what it made and compares before it returns it. The caller zeroes
 * its keys.
 */
export async function sealPlatformWrap(p: PlatformWrapProfile, productKey: Uint8Array, accountKey: Uint8Array, b: PlatformWrapBinding): Promise<Bytes> {
  if (!(accountKey instanceof Uint8Array) || accountKey.length !== KEY_LEN) throw new PlatformWrapError('the account key is not 32 bytes')
  check(p, b)
  if (!equal(await publicHalf(accountKey), bytes(b.accountPublicKey))) throw new PlatformWrapError("the account key is not the binding's")
  const key = await wrapKey(p, productKey, b)
  // Drawn once every input has passed, as in Go.
  const iv = crypto.getRandomValues(new Uint8Array(NONCE_LEN)) as Bytes
  const plain = bytes(accountKey)
  let sealed: Uint8Array
  try {
    sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: platformWrapAAD(p, b), tagLength: 128 }, key, plain))
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
    again = await openPlatformWrap(p, productKey, out, b)
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
 * openPlatformWrap opens a wrap with the product key sk_p for b, under p's
 * labels, and returns the account key, which the caller zeroes. It checks
 * the shape first (checkPlatformWrapShape), then the product key, the
 * profile and the binding, the tag, and that the key it opened is the
 * private half of b.accountPublicKey, compared in constant time; a key that
 * is not is zeroed and refused.
 */
export async function openPlatformWrap(p: PlatformWrapProfile, productKey: Uint8Array, wrap: Uint8Array, b: PlatformWrapBinding): Promise<Bytes> {
  checkPlatformWrapShape(wrap)
  const key = await wrapKey(p, productKey, b)
  let opened: Bytes
  try {
    opened = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: bytes(wrap.subarray(1, 1 + NONCE_LEN)), additionalData: platformWrapAAD(p, b), tagLength: 128 },
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

/** A product's platform-wrap functions with its profile fixed (bind). */
export interface BoundPlatformWrap {
  readonly profile: PlatformWrapProfile
  platformWrapInfo(b: PlatformWrapBinding): Bytes
  platformWrapAAD(b: PlatformWrapBinding): Bytes
  sealPlatformWrap(productKey: Uint8Array, accountKey: Uint8Array, b: PlatformWrapBinding): Promise<Bytes>
  openPlatformWrap(productKey: Uint8Array, wrap: Uint8Array, b: PlatformWrapBinding): Promise<Bytes>
  checkPlatformWrapShape(wrap: Uint8Array): void
}

/**
 * bind fixes a profile: the functions of this module under p's labels, as
 * Wappie's profile exports them. It checks p and keeps a frozen copy of it,
 * so a profile outside its spelling is refused where it is bound and a later
 * change to the object passed in changes nothing.
 */
export function bind(profile: PlatformWrapProfile): BoundPlatformWrap {
  checkProfile(profile)
  const p: PlatformWrapProfile = Object.freeze({ product: profile.product, salt: profile.salt, label: profile.label })
  return Object.freeze({
    profile: p,
    platformWrapInfo: (b: PlatformWrapBinding) => platformWrapInfo(p, b),
    platformWrapAAD: (b: PlatformWrapBinding) => platformWrapAAD(p, b),
    sealPlatformWrap: (productKey: Uint8Array, accountKey: Uint8Array, b: PlatformWrapBinding) => sealPlatformWrap(p, productKey, accountKey, b),
    openPlatformWrap: (productKey: Uint8Array, wrap: Uint8Array, b: PlatformWrapBinding) => openPlatformWrap(p, productKey, wrap, b),
    checkPlatformWrapShape,
  })
}
