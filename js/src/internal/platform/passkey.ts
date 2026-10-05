// Passkeys with PRF (SPEC section 11.16, the platform's decision 0008): the
// public PRF salt of a relying party, the key a passkey's PRF output gives,
// and the account root wrapped under it.
//
//   PRF_SALT = SHA-256(UTF-8("thehappie-id/v1/passkey-prf|" + rp_id))        32 bytes
//   prf      = the PRF output for eval.first = PRF_SALT                       32 bytes, per credential
//   K_pk     = HKDF-SHA256(IKM = prf, salt = UTF-8(rp_id), info = "thehappie-id/v1/passkey/wrap", L = 32)
//   wrap     = the root wrap of section 11.5, kind 0x03, under K_pk, with
//              AAD = ["thehappie-id/root-wrap", 1, "passkey", sub, epoch, rp_id, credential_id]
//
// This is section 7, the kit's passkey PRF wrap, with platformPasskey: the
// salt is passkey.prfSalt with that profile, K_pk is the HKDF passkey.ts
// derives, and section 7's envelope with the header 0x01 0x03 and this AAD
// is the 62-byte root wrap. Sealing and opening are sealRootWrap and
// openRootWrap, which add the self-test of section 11.5 and the one error
// name, wrap.
//
// The rule it enforces: a passkey wrap opens only with the PRF output of the
// credential it names, only on the relying party it names, and only for the
// account and epoch it was made for. The relying party is in the PRF salt,
// in the HKDF salt and in the AAD, and has one spelling (isRPID); the
// credential is in the PRF output itself and in the AAD.
//
// K_pk is a non-extractable AES-256-GCM CryptoKey, derived by WebCrypto's
// HKDF, as every derived wrap key of the kit: no raw K_pk is ever on the
// page's heap. The copy of the PRF output handed to WebCrypto is zeroed once
// it is imported; the PRF output itself is the caller's to zero, and the
// root unwrapRootWithPasskey lends is zeroed when its callback settles.
// JavaScript cannot promise that no copy remains (an engine may have moved
// a buffer); what this code holds, it zeroes.
//
// What stays in the platform: the WebAuthn ceremony (the options, the
// credential calls, reading the PRF output out of a credential, the
// credential the page sends) and the page's withRoot helpers built on these
// functions. From the platform's web/shared/crypto/passkey.ts at b5d9f69,
// with its names; passkeyWrapKey returns a CryptoKey rather than bytes.

import { encodeUTF8, fromBase64URL, isBase64URL, toBase64URL, type Bytes } from '../../bytes.js'
import { PlatformError } from '../../errors.js'
import { prfSalt as passkeyPRFSalt, type PasskeyProfile } from '../../passkey.js'
import { zero } from '../zero.js'
import { WRAP_KIND_BYTE, WRAP_LEN, WRAP_VERSION } from './profile.js'
import { isEpoch, isSub, openRootWrap, sealRootWrap, type PasskeyBinding } from './rootwrap.js'

/** PRF_OUTPUT_LEN is the length of results.first, the IKM of K_pk. */
export const PRF_OUTPUT_LEN = 32

/** PRF_SALT_LEN is the length of the PRF salt, a SHA-256 digest. */
export const PRF_SALT_LEN = 32

/** LABEL_PASSKEY_PRF is hashed with the relying party id into the PRF salt; '|' never occurs in one. */
export const LABEL_PASSKEY_PRF = 'thehappie-id/v1/passkey-prf|'

/** LABEL_PASSKEY_WRAP is the HKDF info of K_pk. */
export const LABEL_PASSKEY_WRAP = 'thehappie-id/v1/passkey/wrap'

/**
 * platformPasskey is the platform's profile for the kit's passkey module
 * (SPEC section 7): the PRF evaluation prefix, the HKDF info of K_pk, and
 * the header of a kind-3 root wrap, 0x01 0x03. With it and rootWrapAAD's
 * AAD, passkey.wrapPasskey and passkey.unwrapPasskey seal and open the
 * 62-byte root wrap of section 11.5; the functions of this module use it for
 * the salt, and seal with sealRootWrap, which self-tests.
 */
export const platformPasskey: PasskeyProfile = Object.freeze({
  evalPrefix: LABEL_PASSKEY_PRF,
  wrapInfo: LABEL_PASSKEY_WRAP,
  header: Object.freeze([WRAP_VERSION, WRAP_KIND_BYTE.passkey]),
})

const MAX_RP_ID_LEN = 253
const RP_ID_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
const ALL_DIGITS = /^[0-9]+$/

/**
 * isRPID says whether s is a relying party id in its one spelling, the rule
 * of Go's ValidRPID: a domain name of 1 to 253 characters whose
 * dot-separated labels are each 1 to 63 characters of [a-z0-9-], none
 * starting or ending with '-', and whose last label is not all digits. That
 * is the host of an origin as a browser serializes it: lower case, no port,
 * no scheme, no trailing dot, never an IP address. Go counts bytes and this
 * counts UTF-16 units, but only ASCII is accepted, so both refuse the same
 * inputs.
 *
 * One spelling, because the relying party id is hashed into the PRF salt
 * and the HKDF salt and written into the AAD: a second spelling would be a
 * second key and a wrap that does not open, with nothing to say why. It
 * checks a spelling, never a list.
 */
export function isRPID(s: unknown): s is string {
  if (typeof s !== 'string' || s.length < 1 || s.length > MAX_RP_ID_LEN) return false
  const labels = s.split('.')
  if (!labels.every((l) => RP_ID_LABEL.test(l))) return false
  return !ALL_DIGITS.test(labels[labels.length - 1]!)
}

function checkRPID(rpId: unknown): asserts rpId is string {
  if (!isRPID(rpId)) throw new PlatformError('not a relying party id', 'wrap')
}

/**
 * prfSalt is the public PRF salt of a relying party, the eval.first of
 * every create and get on id. It refuses, with wrap (as Go does), a relying
 * party id isRPID does not accept: the salt is the first step towards a
 * passkey wrap.
 */
export async function prfSalt(rpId: string): Promise<Bytes> {
  checkRPID(rpId)
  return passkeyPRFSalt(platformPasskey, rpId)
}

/**
 * passkeyWrapKey derives K_pk from a PRF output as a non-extractable
 * AES-256-GCM key, for sealRootWrap and openRootWrap. It refuses, with wrap
 * and before anything is derived, a PRF output that is not exactly 32 bytes
 * (an absent result, or first and second run together) and a relying party
 * id isRPID does not accept. Any 32 bytes are a PRF output, 32 zeros
 * included. The copy handed to WebCrypto is zeroed once imported; prf is the
 * caller's to zero.
 */
export async function passkeyWrapKey(prf: Uint8Array, rpId: string): Promise<CryptoKey> {
  if (!(prf instanceof Uint8Array) || prf.length !== PRF_OUTPUT_LEN) {
    throw new PlatformError('a PRF output is 32 bytes', 'wrap')
  }
  checkRPID(rpId)
  const ikm = new Uint8Array(prf) as Bytes
  try {
    let material: CryptoKey
    try {
      material = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey'])
    } finally {
      zero(ikm)
    }
    return await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: encodeUTF8(rpId), info: encodeUTF8(LABEL_PASSKEY_WRAP) },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    )
  } catch {
    throw new PlatformError('the passkey wrap key could not be derived', 'wrap')
  }
}

/** checkBinding checks what a passkey wrap is bound to besides the account. */
function checkBinding(rpId: unknown, credentialId: unknown): PasskeyBinding {
  checkRPID(rpId)
  if (typeof credentialId !== 'string' || credentialId === '' || !isBase64URL(credentialId)) {
    throw new PlatformError('the credential id is not strict base64url', 'wrap')
  }
  return Object.freeze({ rpId, credentialId })
}

function checkAccount(sub: unknown, epoch: unknown): void {
  if (!isSub(sub)) throw new PlatformError('the account id is not a lowercase UUID', 'wrap')
  if (!isEpoch(epoch)) throw new PlatformError('the key epoch is not a positive integer', 'wrap')
}

/** The inputs of a new passkey wrap. */
export interface PasskeyWrapInput extends PasskeyBinding {
  /** The account root, 32 bytes; not zeroed here. */
  root: Uint8Array
  /** The new credential's PRF output, 32 bytes; the caller zeroes it. */
  prf: Uint8Array
  sub: string
  epoch: number
}

/**
 * wrapRootWithPasskey is a new passkey wrap in one call: the account and
 * the binding are checked, K_pk is derived from the credential's PRF output,
 * and the root is sealed under it with a fresh nonce and opened again and
 * compared before it is returned (the self-test of section 11.5). It returns
 * the 62-byte wrap as base64url. Every refusal is wrap. The root and the PRF
 * output belong to the caller.
 */
export async function wrapRootWithPasskey(i: PasskeyWrapInput): Promise<string> {
  checkAccount(i.sub, i.epoch)
  const b = checkBinding(i.rpId, i.credentialId)
  const key = await passkeyWrapKey(i.prf, b.rpId)
  return toBase64URL(await sealRootWrap('passkey', key, i.root, i.sub, i.epoch, b))
}

/** The inputs of a one-shot open of a passkey wrap. */
export interface PasskeyUnwrapInput extends PasskeyBinding {
  /** The credential's PRF output, 32 bytes; the caller zeroes it. */
  prf: Uint8Array
  /** The passkey wrap, base64url of 62 bytes. */
  wrap: string
  sub: string
  epoch: number
}

/**
 * unwrapRootWithPasskey opens a passkey wrap once: it derives K_pk, runs fn
 * with the root, and zeroes the root when fn resolves or throws. A wrap that
 * does not open for this PRF output, relying party, credential, account and
 * epoch is refused with wrap, before fn is called, and the cases are not
 * told apart. A caller that wants the root as bytes of its own opens with
 * openRootWrap('passkey', await passkeyWrapKey(prf, rpId), ...) instead.
 */
export async function unwrapRootWithPasskey<T>(i: PasskeyUnwrapInput, fn: (root: Uint8Array) => Promise<T>): Promise<T> {
  const b = checkBinding(i.rpId, i.credentialId)
  const key = await passkeyWrapKey(i.prf, b.rpId)
  let wrap: Bytes
  try {
    if (typeof i.wrap !== 'string') throw new TypeError('not text')
    wrap = fromBase64URL(i.wrap, WRAP_LEN)
  } catch {
    throw new PlatformError('the passkey wrap is not 62 bytes of strict base64url', 'wrap')
  }
  const root = await openRootWrap('passkey', key, wrap, i.sub, i.epoch, b)
  try {
    return await fn(root)
  } finally {
    zero(root)
  }
}
