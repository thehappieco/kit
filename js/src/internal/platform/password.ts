// The password profile thehappie-password/v1 (SPEC section 11.2).
//
// The rule it enforces: one typed password becomes exactly one byte string
// P', the same in every browser, on every keyboard and in Go
// (profiles/platform). Two spellings that look the same on screen, such as a
// precomposed "é" and "e" followed by a combining accent, or a no-break space
// pasted from a document, must derive the same key, or the person is locked
// out by the way they typed. Anything that cannot be typed reliably again, a
// control character or half of a surrogate pair, is refused instead of
// mapped. From the platform's web/shared/crypto/password.ts.

import { encodeUTF8, type Bytes } from '../../bytes.js'
import { PlatformError } from '../../errors.js'

export const PASSWORD_PROFILE = 'thehappie-password/v1'

/** The minimum for a new password (sign-up, change, recovery), in code points. */
export const PASSWORD_MIN_NEW = 12

/** The maximum for any password, in code points. */
export const PASSWORD_MAX = 256

// A surrogate that is not half of a pair: the string is not Unicode. The same
// test as jcs.ts (String.prototype.isWellFormed is ES2024).
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/

// The spaces Unicode has besides U+0020: the other members of category Zs.
// NFC leaves them alone (they are compatibility characters, which only NFKC
// folds), so they are mapped after it. None has a composition partner, so the
// result stays NFC.
const OTHER_SPACES = /[\u00A0\u1680\u2000-\u200A\u202F\u205F\u3000]/g

// C0 controls, DEL and C1 controls.
const CONTROLS = /[\u0000-\u001F\u007F-\u009F]/

// The longest run of counted code points (COUNTED) the password may hold in
// its compatibility decomposition. Past 30 of them, Go's
// golang.org/x/text/unicode/norm inserts U+034F to keep the text stream-safe
// (UAX #15), so its NFC stops being the NFC of normalize() and the two sides
// would derive different keys from the same password. Such a password is
// refused on both sides instead.
const MAX_MARK_RUN = 30

// What a run counts: a mark (category M), a Hangul vowel or final jamo
// (U+1160 to U+11FF, U+D7B0 to U+D7FF), or U+16D67 KIRAT RAI VOWEL SIGN E.
// Together they cover what Go's normaliser counts as a non-starter: every code
// point with a non-zero combining class (all marks) and every one that
// composes with what precedes it (marks, the Hangul jamo, and from Unicode
// 16.0 U+16D67, a letter). Go's tests walk every code point to keep it so.
const COUNTED = /^[\p{M}\u1160-\u11FF\uD7B0-\uD7FF\u{16D67}]$/u

// markRunTooLong decomposes code point by code point rather than calling
// normalize('NFKD') on the whole password. The runs are the same: a full
// decomposition differs from its code points' decompositions put end to end
// only by canonical reordering, which moves only code points with a non-zero
// combining class, and those are all counted. And the cost is linear: ICU's
// canonical reordering is quadratic in the length of a run, so a pasted wall
// of alternating marks would otherwise hold the main thread for seconds
// before being refused. Once this passes, every run is at most 30 long and
// the normalize('NFC') that follows is linear too.
function markRunTooLong(password: string): boolean {
  let run = 0
  for (const ch of password) {
    if (ch.charCodeAt(0) < 0x80) {
      run = 0 // ASCII decomposes to itself and holds no mark
      continue
    }
    for (const d of ch.normalize('NFKD')) {
      if (!COUNTED.test(d)) run = 0
      else if (++run > MAX_MARK_RUN) return true
    }
  }
  return false
}

/**
 * preparePasswordText runs the profile and returns P' as text, so a product
 * can compare the prepared password with something else (the platform's page
 * refuses one equal to the address); everything that derives keys takes the
 * bytes from preparePassword. In order: well-formed Unicode, the run of
 * marks, NFC, the space mapping, control characters, then the
 * length in code points (at least 12 for a new password, at most 256 for
 * any). Nothing is trimmed.
 */
export function preparePasswordText(password: string, opts: { isNew: boolean }): string {
  if (typeof password !== 'string' || LONE_SURROGATE.test(password)) {
    throw new PlatformError('the password is not well-formed Unicode', 'password_invalid')
  }
  if (markRunTooLong(password)) {
    throw new PlatformError('the password holds a run of more than 30 marks', 'password_invalid')
  }
  const s = password.normalize('NFC').replace(OTHER_SPACES, ' ')
  if (CONTROLS.test(s)) {
    throw new PlatformError('the password holds a control character', 'password_invalid')
  }
  // Code points, not UTF-16 units: an emoji counts once, as in Go.
  const count = Array.from(s).length
  if (opts.isNew && count < PASSWORD_MIN_NEW) {
    throw new PlatformError('a new password needs at least 12 characters', 'password_too_short')
  }
  if (count > PASSWORD_MAX) {
    throw new PlatformError('a password has at most 256 characters', 'password_too_long')
  }
  return s
}

/** preparePassword returns P', the UTF-8 bytes Argon2id reads; the caller zeroes them. */
export function preparePassword(password: string, opts: { isNew: boolean }): Bytes {
  return encodeUTF8(preparePasswordText(password, opts))
}
