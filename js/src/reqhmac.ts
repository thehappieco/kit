// Request signing between two services that share a secret, in both
// directions. Mirrors the Go package reqhmac (from Wappie's
// internal/mcpauth/hmac.go):
//
//   canonical = label \n direction \n sender \n UPPER(method) \n target \n
//               timestamp \n nonce \n hex(SHA-256(body))
//   signature = "v1=" hex(HMAC-SHA256(key = UTF-8(secret), canonical))
//
// This side has the canonical string, the signature, the header grammar and
// the multi-secret check. The replay cache is the receiving server's and is
// in Go only.

import { encodeUTF8, toHex, type Bytes } from './bytes.js'
import { RequestHMACError } from './errors.js'

export { RequestHMACError }
export type { RequestHMACErrorCode } from './errors.js'

export interface HMACScheme {
  readonly label: string
  readonly headers: { readonly sender: string; readonly timestamp: string; readonly nonce: string; readonly signature: string }
  /** How far a timestamp may be from the receiver's clock. */
  readonly skewSeconds: number
}

/** NONCE_LEN is a nonce's length: 16 random bytes in unpadded base64url. */
export const NONCE_LEN = 22

export async function canonical(s: HMACScheme, direction: string, sender: string, method: string, target: string, timestamp: string, nonce: string, body: Bytes): Promise<string> {
  const sum = new Uint8Array(await crypto.subtle.digest('SHA-256', body))
  return [s.label, direction, sender, method.toUpperCase(), target, timestamp, nonce, toHex(sum)].join('\n')
}

export async function signature(s: HMACScheme, secret: string, direction: string, sender: string, method: string, target: string, timestamp: string, nonce: string, body: Bytes): Promise<string> {
  // WebCrypto refuses an empty HMAC key. HMAC pads its key with zeros to the
  // block size, so an empty key and a key of zero bytes are the same key.
  const raw = secret === '' ? new Uint8Array(32) : encodeUTF8(secret)
  const key = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, encodeUTF8(await canonical(s, direction, sender, method, target, timestamp, nonce, body))))
  return 'v1=' + toHex(mac)
}

/** Signed is what a received request claims about itself. */
export interface Signed {
  timestamp: string
  unix: number
  nonce: string
  signature: string
}

/** Headers as a map from name to one value or several; names match case-insensitively. */
export type HeaderValues = Record<string, string | readonly string[] | undefined>

function values(headers: HeaderValues, name: string): string[] {
  const out: string[] = []
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== name.toLowerCase() || value === undefined) continue
    if (typeof value === 'string') out.push(value)
    else out.push(...value)
  }
  return out
}

const timestampShape = /^[1-9][0-9]{0,17}$/
const nonceShape = /^[A-Za-z0-9_-]{22}$/
const signatureShape = /^v1=[0-9a-f]{64}$/

/**
 * readSigned checks that the timestamp, nonce and signature headers are each
 * present once and well formed, and that the timestamp is within the skew of
 * nowSeconds. Throws RequestHMACError hmac_missing or hmac_stale.
 */
export function readSigned(s: HMACScheme, headers: HeaderValues, nowSeconds: number): Signed {
  const one = (name: string) => {
    const v = values(headers, name)
    return v.length === 1 ? v[0] : undefined
  }
  const timestamp = one(s.headers.timestamp)
  const nonce = one(s.headers.nonce)
  const sig = one(s.headers.signature)
  if (timestamp === undefined || nonce === undefined || sig === undefined ||
    !timestampShape.test(timestamp) || !nonceShape.test(nonce) || !signatureShape.test(sig)) {
    throw new RequestHMACError('hmac_missing')
  }
  // Exact for every 18-digit timestamp, which a Number is not.
  const skew = BigInt(nowSeconds) - BigInt(timestamp)
  const limit = BigInt(s.skewSeconds)
  if (skew > limit || skew < -limit) throw new RequestHMACError('hmac_stale')
  return { timestamp, unix: Number(timestamp), nonce, signature: sig }
}

/**
 * signedBy reports whether any of the secrets produced the signature. Every
 * secret is tried and compared in full, so the time taken does not say which
 * one matched.
 */
export async function signedBy(s: HMACScheme, secrets: readonly string[], got: Signed, direction: string, sender: string, method: string, target: string, body: Bytes): Promise<boolean> {
  let matched = 0
  for (const secret of secrets) {
    const want = encodeUTF8(await signature(s, secret, direction, sender, method, target, got.timestamp, got.nonce, body))
    const have = encodeUTF8(got.signature)
    let diff = want.length ^ have.length
    for (let i = 0; i < want.length; i++) diff |= want[i] ^ (have[i] ?? 0)
    matched |= diff === 0 ? 1 : 0
  }
  return matched === 1
}
