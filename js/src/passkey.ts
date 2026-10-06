// A passkey's PRF output wraps the account key, so a passkey unlocks what the
// password unlocks.
//
//   eval input = SHA-256(UTF-8(evalPrefix + rpID))       public, from the server
//   K          = HKDF-SHA256(IKM = PRF output (32), salt = UTF-8(rpID), info = wrapInfo)
//   envelope   = header || nonce (12) || AES-256-GCM(K, nonce, key (32), aad) || tag
//
// The PRF output stays local; only the envelope may be sent. From Wappie's
// packages/client/src/crypto/passkey.ts; the AAD is the profile's.
//
// The functions of this module do not check the RP ID's spelling: the RP ID
// is the profile's configuration, and the profile or the product checks it
// where it is configured. endsInANumber is the check every product needs.

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

function checkAAD(aad: Bytes): void {
  // A wrap binds its passkey (the RP, the user, the credential); one bound to
  // nothing could be moved to any of them.
  if (!(aad instanceof Uint8Array) || aad.length === 0) throw new PasskeyError('a passkey wrap must be bound to something', 'bad_aad')
}

/** wrapPasskey seals a 32-byte key under a PRF output, bound to aad, which must not be empty. */
export async function wrapPasskey(p: PasskeyProfile, privateKey: Bytes, prf: Bytes, rpID: string, aad: Bytes): Promise<Bytes> {
  if (privateKey.length !== KEY_LEN) throw new PasskeyError('the key must contain 32 bytes', 'bad_key')
  checkAAD(aad)
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN))
  const sealed = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, await wrappingKey(p, prf, rpID), privateKey)
  return concat(new Uint8Array(p.header), nonce, new Uint8Array(sealed))
}

/**
 * unwrapPasskey opens an envelope. An empty aad is bad_aad; a wrong length or
 * header is bad_envelope; everything after, a PRF of the wrong length
 * included, is open_failed.
 */
export async function unwrapPasskey(p: PasskeyProfile, envelope: Bytes, prf: Bytes, rpID: string, aad: Bytes): Promise<Bytes> {
  checkAAD(aad)
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

/**
 * endsInANumber is the "ends in a number checker" of the WHATWG URL Standard
 * (https://url.spec.whatwg.org/#ends-in-a-number-checker), step by step, as
 * the platform's vector generator runs it (rp-id-ends-in-number.json):
 *
 *   1. strictly split input on ".";
 *   2. if the last part is empty, return false when it is the only part, and
 *      otherwise drop it (one trailing empty label only);
 *   3. let last be the last part;
 *   4. if last is non-empty and all ASCII digits, return true;
 *   5. if the standard's IPv4 number parser does not fail on last, return
 *      true;
 *   6. return false.
 *
 * A browser's host parser runs it on every domain; when it is true, the host
 * is parsed as an IPv4 address ("0x7f000001" is 127.0.0.1, "1.2.3.0x4" is
 * 1.2.3.4) or refused ("id.0xff"), and is never a domain, so no passkey is
 * ever made for a relying party id that ends in a number. The functions of
 * this module do not refuse one: the profile or the product checks the id
 * where it is configured (the platform profile's isRPID calls this).
 */
export function endsInANumber(input: string): boolean {
  const parts = input.split('.')
  if (parts[parts.length - 1] === '') {
    if (parts.length === 1) return false
    parts.pop()
  }
  const last = parts[parts.length - 1]!
  if (/^[0-9]+$/.test(last)) return true
  return isIPv4Number(last)
}

/**
 * isIPv4Number says whether the WHATWG "IPv4 number parser"
 * (https://url.spec.whatwg.org/#ipv4-number-parser) does not fail on input;
 * only that matters here, not the value. The empty string fails. A "0x" or
 * "0X" prefix makes the rest radix 16, and a leading "0" of an input of two
 * or more code points makes the rest radix 8; otherwise it is radix 10. The
 * parser succeeds when what follows the prefix is empty (the number zero) or
 * holds only digits of the radix.
 */
function isIPv4Number(input: string): boolean {
  if (input === '') return false
  if (/^0[xX]/.test(input)) return /^[0-9a-fA-F]*$/.test(input.slice(2))
  if (input.length >= 2 && input[0] === '0') return /^[0-7]*$/.test(input.slice(1))
  return /^[0-9]+$/.test(input)
}
