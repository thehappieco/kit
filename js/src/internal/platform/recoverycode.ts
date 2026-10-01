// The recovery code (SPEC section 11.6): 150 random bits a person writes
// down, generated as in section 6.7 and read back in the platform's own
// canonical form C.
//
// The rule it enforces: whatever a person can plausibly type for a code (in
// lower case, with or without the dashes, an O for a 0, an I or an L for a
// 1) is the same code, and anything else is not a code at all. Unlike
// account.normaliseRecoveryCode (Wappie's), there is no Unicode case mapping,
// a U is refused rather than read as V, and the dashes are not part of C.
// From the platform's web/shared/crypto/recovery.ts.

import type { Bytes } from '../../bytes.js'
import { PlatformError } from '../../errors.js'

/** Crockford's base32 alphabet: no I, L, O or U. */
export const RECOVERY_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

/** The length of C, and the number of random bytes a code is made from. */
export const RECOVERY_CODE_LEN = 30
const GROUP = 5

/** RecoveryCode is one code in both spellings. */
export interface RecoveryCode {
  /** Six groups of five, separated by "-": what is shown. */
  display: string
  /** The 30 characters C that the keys are derived from. */
  canonical: string
}

/** recoveryCodeFromBytes maps exactly 30 bytes to a code: byte b becomes RECOVERY_ALPHABET[b mod 32]. */
export function recoveryCodeFromBytes(bytes: Uint8Array): RecoveryCode {
  if (!(bytes instanceof Uint8Array) || bytes.length !== RECOVERY_CODE_LEN) {
    throw new PlatformError('a recovery code takes 30 random bytes', 'recovery_code')
  }
  let canonical = ''
  // Unbiased: 256 is 8 × 32.
  for (const b of bytes) canonical += RECOVERY_ALPHABET[b & 31]
  return { display: formatRecoveryCode(canonical), canonical }
}

/** newRecoveryCode draws a fresh code from crypto.getRandomValues. */
export function newRecoveryCode(): RecoveryCode {
  const bytes = crypto.getRandomValues(new Uint8Array(RECOVERY_CODE_LEN)) as Bytes
  try {
    return recoveryCodeFromBytes(bytes)
  } finally {
    bytes.fill(0)
  }
}

/** formatRecoveryCode writes any accepted spelling of a code in its six groups. */
export function formatRecoveryCode(code: string): string {
  const c = canonicalRecoveryCode(code)
  const groups: string[] = []
  for (let i = 0; i < c.length; i += GROUP) groups.push(c.slice(i, i + GROUP))
  return groups.join('-')
}

/**
 * canonicalRecoveryCode turns what was typed into C, or throws
 * recovery_code. It removes ASCII spaces, tabs, line breaks and "-";
 * upper-cases ASCII letters; reads O as 0 and I and L as 1. Any other
 * character, a U or anything outside ASCII included, makes the code invalid,
 * as does a result that is not exactly 30 characters.
 */
export function canonicalRecoveryCode(input: string): string {
  if (typeof input !== 'string') throw new PlatformError('a recovery code is text', 'recovery_code')
  let out = ''
  for (let i = 0; i < input.length; i++) {
    let c = input.charCodeAt(i)
    if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d || c === 0x2d) continue
    if (c >= 0x61 && c <= 0x7a) c -= 0x20
    let ch = String.fromCharCode(c)
    if (ch === 'O') ch = '0'
    else if (ch === 'I' || ch === 'L') ch = '1'
    if (c > 0x7f || !RECOVERY_ALPHABET.includes(ch)) {
      throw new PlatformError('a recovery code holds a character outside its alphabet', 'recovery_code')
    }
    out += ch
    // A pasted novel is refused without walking all of it.
    if (out.length > RECOVERY_CODE_LEN) break
  }
  if (out.length !== RECOVERY_CODE_LEN) {
    throw new PlatformError('a recovery code has 30 characters', 'recovery_code')
  }
  return out
}
