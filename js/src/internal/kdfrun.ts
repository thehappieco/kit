// What the kit's KDF worker (kdf.worker.ts) does with a message, kept out of
// the worker's own module so the tests run it without a Worker. It answers
// two protocols.
//
// Version 1 (v0.1.0, KDFRequest): {password, salt, m, t, p}, answered
// {ok: true, master} or {ok: false, error}, as before, for anything that
// drives the worker that way.
//
// Version 2 (v0.5.0), which the kit's own page side speaks (internal/kdf.ts):
//
//   page -> worker  {v: 2}                                      the hello; no secret
//   worker -> page  {ready: true, v: 2}                         the worker's module is running
//   page -> worker  {v: 2, prepared, salt, params, bounds}      prepared: a fresh copy, transferred
//   worker -> page  {ok: true, master}                          32 bytes in a buffer of their own, transferred
//                 | {ok: false, reason}                         unsupported_alg, out_of_bounds or kdf_failed
//
// The page sends the password only to a worker that has answered the hello,
// so a worker that never starts leaves the page holding the only copy. The
// worker checks the parameters and the profile's bounds again before it
// derives, zeroes the password it received whatever happens, and answers a
// refusal (unsupported_alg, out_of_bounds) apart from a failure
// (kdf_failed), never with a message, which is the one thing that could
// carry input back. It posts nothing it was not asked for, so a version-1
// driver never sees a version-2 message. The handshake, the transfer, the
// second check and the split of failures follow the platform's
// web/shared/crypto/kdf.worker.ts and argon2.ts at 75b6b94.

import { argon2id } from '@noble/hashes/argon2.js'

/** KDFWorkerBounds are the bounds a version-2 request carries: the profile's (account.KDFBounds). */
export interface KDFWorkerBounds {
  min: { m: number; t: number; p: number }
  max: { m: number; t: number; p: number }
  maxCost?: number
  minSaltLen?: number
  maxSaltLen?: number
}

/** KDFWorkerParams are the parameters of a version-2 request. */
export interface KDFWorkerParams {
  alg: string
  m: number
  t: number
  p: number
}

/** KDFWorkerHello is the page's first message of version 2. */
export interface KDFWorkerHello {
  v: 2
}

/** KDFWorkerRequest is the derivation of version 2; prepared is transferred. */
export interface KDFWorkerRequest {
  v: 2
  prepared: Uint8Array
  salt: Uint8Array
  params: KDFWorkerParams
  bounds?: KDFWorkerBounds
}

/** Why a version-2 derivation did not happen: a refusal of the parameters, or a failure. */
export type KDFWorkerReason = 'unsupported_alg' | 'out_of_bounds' | 'kdf_failed'

/** KDFWorkerResponse is what the worker posts: version 2's three answers, and version 1's failure. */
export type KDFWorkerResponse =
  | { ready: true; v: 2 }
  | { ok: true; master: Uint8Array }
  | { ok: false; reason: KDFWorkerReason }
  | { ok: false; error: string }

const MASTER_LEN = 32

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null
const isCount = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0
const isNumber = (v: unknown): v is number => typeof v === 'number' && !Number.isNaN(v)
const isLimits = (v: unknown): v is { m: number; t: number; p: number } => isObject(v) && isNumber(v.m) && isNumber(v.t) && isNumber(v.p)
const isOptionalNumber = (v: unknown) => v === undefined || isNumber(v)

/**
 * checkWorkerParams is the page's check (account.checkKDFParams and
 * checkSalt) again, on what the page sent: argon2id only, non-negative safe
 * integers, and the bounds when there are any. Bounds that are not bounds are
 * out_of_bounds. Argon2id's own limits (t and p at least 1, m at least 8p, a
 * salt of at least 8 bytes) are @noble/hashes', and fail as kdf_failed, as
 * on the calling thread.
 */
export function checkWorkerParams(params: unknown, saltLen: number, bounds: unknown): KDFWorkerReason | null {
  if (!isObject(params) || params.alg !== 'argon2id') return 'unsupported_alg'
  const { m, t, p } = params
  if (!isCount(m) || !isCount(t) || !isCount(p)) return 'kdf_failed'
  if (bounds === undefined) return null
  if (!isObject(bounds) || !isLimits(bounds.min) || !isLimits(bounds.max) || !isOptionalNumber(bounds.maxCost) ||
    !isOptionalNumber(bounds.minSaltLen) || !isOptionalNumber(bounds.maxSaltLen)) return 'out_of_bounds'
  const { min, max, maxCost, minSaltLen, maxSaltLen } = bounds as unknown as KDFWorkerBounds
  if (m < min.m || m > max.m || t < min.t || t > max.t || p < min.p || p > max.p || (maxCost !== undefined && m * t > maxCost)) return 'out_of_bounds'
  if ((minSaltLen !== undefined && saltLen < minSaltLen) || (maxSaltLen !== undefined && saltLen > maxSaltLen)) return 'out_of_bounds'
  return null
}

/**
 * runKDFMessage answers one message of either protocol and says which
 * buffers to transfer with the answer. It zeroes the password it received,
 * whatever happens.
 */
export function runKDFMessage(data: unknown): { response: KDFWorkerResponse; transfer: Transferable[] } {
  if (isObject(data) && data.v === 2) return runV2(data)
  return runV1(data)
}

function runV2(d: Record<string, unknown>): { response: KDFWorkerResponse; transfer: Transferable[] } {
  if (!('prepared' in d)) return { response: { ready: true, v: 2 }, transfer: [] }
  const prepared = d.prepared
  try {
    if (!(prepared instanceof Uint8Array) || !(d.salt instanceof Uint8Array)) return { response: { ok: false, reason: 'kdf_failed' }, transfer: [] }
    const refused = checkWorkerParams(d.params, d.salt.length, d.bounds)
    if (refused !== null) return { response: { ok: false, reason: refused }, transfer: [] }
    const { m, t, p } = d.params as unknown as KDFWorkerParams
    const out = argon2id(prepared, d.salt, { m, t, p, dkLen: MASTER_LEN })
    // A buffer of its own, so the transfer carries these 32 bytes and nothing
    // else, whatever view the library returned.
    const master = new Uint8Array(out)
    out.fill(0)
    return { response: { ok: true, master }, transfer: [master.buffer] }
  } catch {
    return { response: { ok: false, reason: 'kdf_failed' }, transfer: [] }
  } finally {
    if (prepared instanceof Uint8Array) prepared.fill(0)
  }
}

function runV1(data: unknown): { response: KDFWorkerResponse; transfer: Transferable[] } {
  const { password, salt, m, t, p } = (isObject(data) ? data : {}) as { password?: unknown; salt?: unknown; m?: number; t?: number; p?: number }
  const bytes = typeof password === 'string' ? new TextEncoder().encode(password) : password
  try {
    const out = argon2id(bytes as Uint8Array, salt as Uint8Array, { m: m as number, t: t as number, p: p as number, dkLen: MASTER_LEN })
    return { response: { ok: true, master: out }, transfer: [out.buffer] }
  } catch (err) {
    return { response: { ok: false, error: err instanceof Error ? err.message : String(err) }, transfer: [] }
  } finally {
    // This worker's copy of the prepared password. The caller zeroes its own.
    if (bytes instanceof Uint8Array) bytes.fill(0)
  }
}
