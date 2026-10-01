// Byte plumbing shared by the crypto modules.
//
// Kept apart from the algorithms so the interesting files contain only the
// protocol, and so the encodings, which is where a reimplementation quietly
// goes wrong, are written once. From Wappie's packages/client/src/crypto/bytes.ts;
// the strict base64url decoder is from the platform's web/shared/crypto/bytes.ts.

import { Base64Error } from './errors.js'

export { Base64Error }

/**
 * Bytes is a Uint8Array known to be backed by a plain ArrayBuffer.
 *
 * TypeScript 5.7 made Uint8Array generic over its buffer and WebCrypto refuses
 * anything that might be shared memory. Naming the narrow form once keeps
 * that detail out of every signature.
 */
export type Bytes = Uint8Array<ArrayBuffer>

export function concat(...parts: Bytes[]): Bytes {
  let n = 0
  for (const p of parts) n += p.length
  const out = new Uint8Array(n)
  let at = 0
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return out
}

/** equal compares in time that depends only on the lengths. */
export function equal(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

const utf8 = new TextEncoder()

export function encodeUTF8(s: string): Bytes {
  // Copied rather than returned directly: TextEncoder is typed as producing a
  // possibly-shared buffer, and WebCrypto will not accept one.
  return new Uint8Array(utf8.encode(s))
}

/** i2osp2 is RFC 8017's two-byte big-endian integer, which HPKE uses throughout. */
export function i2osp2(n: number): Bytes {
  return new Uint8Array([(n >>> 8) & 0xff, n & 0xff])
}

export function readUint32BE(b: Bytes, at: number): number {
  return ((b[at] << 24) >>> 0) + (b[at + 1] << 16) + (b[at + 2] << 8) + b[at + 3]
}

export function readUint16BE(b: Bytes, at: number): number {
  return (b[at] << 8) + b[at + 1]
}

/** toBase64 is standard base64 with padding. */
export function toBase64(b: Bytes): string {
  let s = ''
  // Chunked: a single spread of a multi-megabyte array overflows the argument
  // stack, and attachments get that large.
  for (let i = 0; i < b.length; i += 0x8000) {
    s += String.fromCharCode(...b.subarray(i, i + 0x8000))
  }
  return btoa(s)
}

export function fromBase64(s: string): Bytes {
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** toBase64URL is RFC 4648 section 5 base64url without padding. */
export function toBase64URL(b: Bytes): string {
  return toBase64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

const B64URL_VALUE = (() => {
  const t = new Int16Array(128).fill(-1)
  for (let i = 0; i < B64URL.length; i++) t[B64URL.charCodeAt(i)] = i
  return t
})()

/**
 * fromBase64URL decodes the unpadded base64url (RFC 4648 section 5) of
 * exactly n bytes, in its one accepted spelling: what toBase64URL writes.
 *
 * fromBase64 is lenient (atob takes padding, whitespace and the standard
 * alphabet, and ignores non-zero trailing bits), so several strings would
 * name the same bytes. This refuses padding, any character outside the URL
 * alphabet (whitespace and line breaks included), non-zero trailing bits and
 * any length other than n's, with Base64Error, whose message never repeats
 * the input. It accepts exactly what Go's profiles/platform DecodeB64 does.
 */
export function fromBase64URL(s: string, n: number): Bytes {
  if (typeof s !== 'string') throw new Base64Error('not a string')
  if (!Number.isSafeInteger(n) || n < 0) throw new Base64Error('not a byte length')
  if (s.length !== Math.ceil((n * 4) / 3)) throw new Base64Error(`not the base64url of ${n} bytes`)
  const out = new Uint8Array(n)
  let acc = 0
  let bits = 0
  let at = 0
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    const v = c < 128 ? B64URL_VALUE[c] : -1
    if (v < 0) throw new Base64Error('a character outside the base64url alphabet')
    acc = (acc << 6) | v
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out[at++] = (acc >>> bits) & 0xff
    }
    acc &= (1 << bits) - 1
  }
  // What is left over must be zero: otherwise two strings name the same bytes.
  if (acc !== 0) throw new Base64Error('non-zero trailing bits')
  return out
}

/**
 * isBase64URL says whether s is the one accepted spelling (fromBase64URL) of
 * some byte string, of any length: the check for a field whose length is not
 * fixed, such as a WebAuthn credential id.
 */
export function isBase64URL(s: string): boolean {
  if (typeof s !== 'string' || s.length % 4 === 1) return false
  try {
    fromBase64URL(s, Math.floor((s.length * 3) / 4))
    return true
  } catch {
    return false
  }
}

export function toHex(b: Bytes): string {
  let s = ''
  for (const x of b) s += x.toString(16).padStart(2, '0')
  return s
}

export function fromHex(s: string): Bytes {
  const clean = s.trim().replace(/[\s:-]/g, '')
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) {
    throw new Error('not hexadecimal')
  }
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return out
}

// ---------------------------------------------------------------------------
// UUIDs
//
// Carried as 16 raw bytes, not as a string. Sealed values are bound to the
// bytes, so a client that carried the hyphenated text around and converted
// late would have one more place to get it wrong.
// ---------------------------------------------------------------------------

const uuidPattern = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/

export function parseUUID(s: string): Bytes {
  if (!uuidPattern.test(s)) throw new Error(`not a UUID: ${s}`)
  return fromHex(s.replace(/-/g, ''))
}

export function formatUUID(b: Bytes): string {
  if (b.length !== 16) throw new Error('a UUID must contain 16 bytes')
  const h = toHex(b)
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`
}

/**
 * newUUIDv7 mints a time-ordered identifier, matching Go's uuid.NewV7: rows
 * inserted together land together in an index instead of scattering.
 */
export function newUUIDv7(): string {
  const b = crypto.getRandomValues(new Uint8Array(16)) as Bytes
  const ms = Date.now()
  const view = new DataView(b.buffer)
  // 48 bits of milliseconds, big endian, split because DataView has no 48-bit
  // integer and a Number cannot hold one shifted left by 32 without loss.
  view.setUint16(0, Math.floor(ms / 2 ** 32), false)
  view.setUint32(2, ms >>> 0, false)
  b[6] = (b[6] & 0x0f) | 0x70 // version 7
  b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
  return formatUUID(b)
}

/**
 * uuidV5 is the name-based UUID Go's uuid.NewSHA1 produces: SHA-1 of the
 * namespace and the name, with the version and variant bits set. Rows that
 * are derived rather than stored bind to one of these, so the derivation has
 * to match byte for byte.
 */
export async function uuidV5(namespace: Bytes, name: Bytes): Promise<Bytes> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-1', concat(namespace, name)))
  const out = digest.slice(0, 16)
  out[6] = (out[6] & 0x0f) | 0x50 // version 5
  out[8] = (out[8] & 0x3f) | 0x80 // RFC 4122 variant
  return out
}
