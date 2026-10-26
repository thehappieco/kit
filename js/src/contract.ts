// What a page needs of the platform's product contract (SPEC section 11.18,
// the platform's decision 0053): the fingerprint of a token's reading key,
// which the console and the apps' grant pages show, each computing it from
// the key itself, for the person to compare with the one the client that
// made the key shows. It mirrors Go's contract.ReadingKeyFingerprint, and
// reproduces every fingerprint of vectors/platform/contract-v1/reading-keys.json.
// The rest of the contract is Go's alone: both apps' contract clients are
// servers, and the reading key's other checks are the platform's and the
// apps' (contract.ValidReadingKey).

import { concat, encodeUTF8, fromBase64URL, toHex } from './bytes.js'
import { Base64Error } from './errors.js'

export { Base64Error }

/** READING_KEY_LABEL opens what a reading key's fingerprint hashes, followed by one zero byte. */
export const READING_KEY_LABEL = 'thehappie-token/v1/reading-key'

/** FINGERPRINT_LENGTH is a fingerprint's length: 16 bytes in lowercase hex. */
export const FINGERPRINT_LENGTH = 32

/**
 * readingKeyFingerprint is a reading key's fingerprint: the lowercase hex
 * of the first 16 bytes of SHA-256(READING_KEY_LABEL || 0x00 || the key's
 * 32 bytes). It reads the key's text strictly, as a record carries it (43
 * unpadded base64url characters, the one spelling of 32 bytes), and throws
 * Base64Error, whose message never repeats the key, for anything else. It
 * checks nothing else of the key: the platform refused a key that is not
 * canonical or of low order when it was registered, and an app refuses a
 * record whose fingerprint is not its key's.
 */
export async function readingKeyFingerprint(key: string): Promise<string> {
  const raw = fromBase64URL(key, 32)
  const sum = new Uint8Array(await crypto.subtle.digest('SHA-256', concat(encodeUTF8(READING_KEY_LABEL), new Uint8Array([0]), raw)))
  return toHex(sum.subarray(0, FINGERPRINT_LENGTH / 2))
}
