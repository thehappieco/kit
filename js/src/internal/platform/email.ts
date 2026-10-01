// Email normalisation, version 1 (SPEC section 11.8), the same function the
// platform's server runs (Go: profiles/platform NormalizeEmail).
//
// The rule it enforces: an address has one spelling, email_norm, and the
// page and the server agree on it byte for byte, so the address a person
// types at login is the address their account was created with. Version 1
// accepts ASCII addresses only. There is no folding of dots or "+" tags:
// that belongs to the platform's trial identity, not to accounts. From the
// platform's web/shared/crypto/email.ts.

import { PlatformError } from '../../errors.js'

const LOCAL_MAX = 64
const DOMAIN_MAX = 253
const LABEL_MAX = 63
const ADDRESS_MAX = 254

const LOCAL_CHARS = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$/
const LABEL_CHARS = /^[a-z0-9-]+$/
const ALL_DIGITS = /^[0-9]+$/

function isTrimmed(c: number): boolean {
  return c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d
}

function refuse(why: string): never {
  throw new PlatformError(why, 'email')
}

/** normalizeEmail returns email_norm, or throws PlatformError email. It normalises its own output to itself. */
export function normalizeEmail(input: string): string {
  if (typeof input !== 'string') refuse('an address is text')
  // 1. Trim ASCII spaces, tabs and line breaks at both ends.
  let start = 0
  let end = input.length
  while (start < end && isTrimmed(input.charCodeAt(start))) start++
  while (end > start && isTrimmed(input.charCodeAt(end - 1))) end--
  const trimmed = input.slice(start, end)
  // 2. Printable ASCII only. Checked on UTF-16 units, which for ASCII are the
  //    bytes; anything above 0x7E is refused before it could be a byte count.
  for (let i = 0; i < trimmed.length; i++) {
    const c = trimmed.charCodeAt(i)
    if (c < 0x21 || c > 0x7e) refuse('an address holds a character outside printable ASCII')
  }
  // 3. Lowercase (ASCII; nothing else is left).
  const s = trimmed.toLowerCase()
  // 6. The whole address, checked early so nothing below walks a long string.
  if (s.length > ADDRESS_MAX) refuse('an address has at most 254 bytes')
  // 4. Exactly one "@", and the local part.
  const at = s.indexOf('@')
  if (at < 0 || s.indexOf('@', at + 1) >= 0) refuse('an address has exactly one @')
  const local = s.slice(0, at)
  const domain = s.slice(at + 1)
  if (local.length < 1 || local.length > LOCAL_MAX) refuse('the local part has 1 to 64 bytes')
  if (!LOCAL_CHARS.test(local)) refuse('the local part holds a character it may not')
  if (local.startsWith('.') || local.endsWith('.') || local.includes('..')) {
    refuse('the local part has a misplaced dot')
  }
  // 5. The domain.
  if (domain.length < 1 || domain.length > DOMAIN_MAX) refuse('the domain has 1 to 253 bytes')
  const labels = domain.split('.')
  if (labels.length < 2) refuse('the domain has at least two labels')
  for (const label of labels) {
    if (label.length < 1 || label.length > LABEL_MAX) refuse('a domain label has 1 to 63 bytes')
    if (!LABEL_CHARS.test(label)) refuse('a domain label holds a character it may not')
    if (label.startsWith('-') || label.endsWith('-')) refuse('a domain label starts or ends with -')
  }
  if (ALL_DIGITS.test(labels[labels.length - 1]!)) refuse('the last domain label is all digits')
  return s
}
