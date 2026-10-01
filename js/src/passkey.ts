// A passkey's PRF output wraps the account key, so a passkey unlocks what the
// password unlocks.
//
//   eval input = SHA-256(UTF-8(evalPrefix + rpID))       public, from the server
//   K          = HKDF-SHA256(IKM = PRF output (32), salt = UTF-8(rpID), info = wrapInfo)
//   envelope   = header || nonce (12) || AES-256-GCM(K, nonce, key (32), aad) || tag
//
// The PRF output stays local; only the envelope may be sent. From Wappie's
// packages/client/src/crypto/passkey.ts; the AAD is the profile's.

import { concat, encodeUTF8, type Bytes } from './bytes.js'
import { PasskeyError } from './errors.js'

export { PasskeyError }
export type { PasskeyErrorReason } from './errors.js'

export interface PasskeyProfile {
  /** Precedes the RP ID in the PRF evaluation input. */
  readonly evalPrefix: string
  /** The HKDF info of the wrap key. */
  readonly wrapInfo: string
  /** Prefixes every envelope. */
  readonly header: readonly number[]
}

const NONCE_LEN = 12
const KEY_LEN = 32
const TAG_LEN = 16

/** prfSalt is the public PRF evaluation input of an RP ID. */
export async function prfSalt(p: PasskeyProfile, rpID: string): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', encodeUTF8(p.evalPrefix + rpID)))
}

async function wrappingKey(p: PasskeyProfile, prf: Bytes, rpID: string): Promise<CryptoKey> {
  if (prf.length !== 32) throw new PasskeyError('the passkey gave no usable PRF output', 'bad_prf')
  const material = await crypto.subtle.importKey('raw', prf, 'HKDF', false, ['deriveKey'])
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: encodeUTF8(rpID), info: encodeUTF8(p.wrapInfo) }, material,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}

/** wrapPasskey seals a 32-byte key under a PRF output. */
export async function wrapPasskey(p: PasskeyProfile, privateKey: Bytes, prf: Bytes, rpID: string, aad: Bytes): Promise<Bytes> {
  if (privateKey.length !== KEY_LEN) throw new PasskeyError('the key must contain 32 bytes', 'bad_key')
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN))
  const sealed = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, await wrappingKey(p, prf, rpID), privateKey)
  return concat(new Uint8Array(p.header), nonce, new Uint8Array(sealed))
}

/**
 * unwrapPasskey opens an envelope. A wrong length or header is bad_envelope;
 * everything after, a PRF of the wrong length included, is open_failed.
 */
export async function unwrapPasskey(p: PasskeyProfile, envelope: Bytes, prf: Bytes, rpID: string, aad: Bytes): Promise<Bytes> {
  const h = p.header.length
  if (envelope.length !== h + NONCE_LEN + KEY_LEN + TAG_LEN || !p.header.every((b, i) => envelope[i] === b)) {
    throw new PasskeyError('the passkey envelope is malformed', 'bad_envelope')
  }
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: envelope.subarray(h, h + NONCE_LEN), additionalData: aad },
      await wrappingKey(p, prf, rpID), envelope.subarray(h + NONCE_LEN)))
  } catch {
    throw new PasskeyError('the passkey could not open the envelope', 'open_failed')
  }
}

/** bind fixes a profile, for a product's own wrappers. */
export function bind(p: PasskeyProfile) {
  return {
    profile: p,
    prfSalt: (rpID: string) => prfSalt(p, rpID),
    wrapPasskey: (privateKey: Bytes, prf: Bytes, rpID: string, aad: Bytes) => wrapPasskey(p, privateKey, prf, rpID, aad),
    unwrapPasskey: (envelope: Bytes, prf: Bytes, rpID: string, aad: Bytes) => unwrapPasskey(p, envelope, prf, rpID, aad),
  }
}
