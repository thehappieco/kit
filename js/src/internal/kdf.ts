// Argon2id for the account module, in a worker where there is one: the page
// side of version 2 of the KDF worker's protocol (internal/kdfrun.ts).
//
// This module names no worker file. The account module and the platform
// profile's default entry pass the kit's own worker (internal/kdfworker.ts);
// @thehappieco/kit/profiles/platform/core passes only the caller's, so a
// bundle that reaches only that entry emits no worker.
//
// The behaviour follows the platform's web/shared/crypto/kdf.ts at 75b6b94:
// the page waits for the worker's ready before it sends the password, and
// derives on the calling thread with the password it still holds when the
// worker never becomes ready; the password goes as a transferred copy; and
// once it is sent, a failure is kdf_failed and is not derived again.

import type { Bytes } from '../bytes.js'
import { AccountError } from '../errors.js'
import type { KDFWorkerBounds, KDFWorkerParams, KDFWorkerRequest } from './kdfrun.js'

/** WorkerFactory makes the kit's KDF worker (kdf.worker.js), wherever a bundler put it. */
export type WorkerFactory = () => Worker

/** How long a worker may take to answer the hello before the page derives by itself. */
export const KDF_READY_TIMEOUT_MS = 10_000

const failed = () => new AccountError('the key derivation failed', 'kdf', 'kdf_failed')

/**
 * stretch runs Argon2id over the prepared password: in the worker the
 * factory makes, when there is one, or on the calling thread.
 *
 * A worker that cannot be made, fails to load, does not answer the hello with
 * {ready: true, v: 2} within KDF_READY_TIMEOUT_MS, or answers anything else
 * first, is terminated before the password is sent, and the page derives
 * itself: a login that works slowly beats one that does not. Once the
 * password is sent, a refusal of the parameters is the worker's reason
 * (out_of_bounds or unsupported_alg) and anything else is kdf_failed; neither
 * is derived again here, since a second derivation on the main thread would
 * freeze the tab and fail the same way. prepared stays the caller's; the copy
 * transferred to the worker is the worker's to zero.
 */
export async function stretch(prepared: Bytes, salt: Bytes, params: KDFWorkerParams, bounds: KDFWorkerBounds | undefined, worker: WorkerFactory | undefined): Promise<Bytes> {
  if (worker !== undefined) {
    let w: Worker | undefined
    try {
      w = worker()
    } catch {
      w = undefined
    }
    if (w !== undefined) {
      try {
        const master = await converse(w, prepared, salt, params, bounds)
        if (master !== null) return master
      } finally {
        w.terminate()
      }
    }
  }
  return direct(prepared, salt, params)
}

async function direct(prepared: Bytes, salt: Bytes, params: KDFWorkerParams): Promise<Bytes> {
  // Loaded on demand: a browser normally derives in the worker, and should
  // not download a second copy of Argon2 for this path.
  const { argon2id } = await import('@noble/hashes/argon2.js')
  try {
    return argon2id(prepared, salt, { m: params.m, t: params.t, p: params.p, dkLen: 32 }) as Bytes
  } catch {
    throw failed()
  }
}

/** plainBounds copies the profile's bounds into a plain object a structured clone carries. */
function plainBounds(b: KDFWorkerBounds | undefined): KDFWorkerBounds | undefined {
  if (b === undefined) return undefined
  const out: KDFWorkerBounds = { min: { m: b.min.m, t: b.min.t, p: b.min.p }, max: { m: b.max.m, t: b.max.t, p: b.max.p } }
  if (b.maxCost !== undefined) out.maxCost = b.maxCost
  if (b.minSaltLen !== undefined) out.minSaltLen = b.minSaltLen
  if (b.maxSaltLen !== undefined) out.maxSaltLen = b.maxSaltLen
  return out
}

/**
 * converse is one derivation in w: the master key, or null when w never
 * became ready, so the caller derives itself.
 */
function converse(w: Worker, prepared: Bytes, salt: Bytes, params: KDFWorkerParams, bounds: KDFWorkerBounds | undefined): Promise<Bytes | null> {
  return new Promise<Bytes | null>((resolve, reject) => {
    let sent = false
    let done = false
    // The copy sent to the worker. A worker that ignored the transfer list
    // (a shim) got a clone of it, and this one is ours to zero; it is zeroed
    // only once the worker has answered, in case a shim handed it on as is.
    let copy: Uint8Array | undefined
    const finish = (f: () => void) => {
      if (done) return
      done = true
      clearTimeout(timer)
      if (copy !== undefined && copy.byteLength !== 0) copy.fill(0)
      f()
    }
    // Only the hello is timed: Argon2id itself may take longer on a slow
    // device, and the timer is cleared once the worker is ready.
    const timer = setTimeout(() => finish(() => resolve(null)), KDF_READY_TIMEOUT_MS)
    const fail = () => finish(() => (sent ? reject(failed()) : resolve(null)))
    w.onerror = (event: ErrorEvent) => {
      // The error stays here: the page reports kdf_failed, never the worker's message.
      event?.preventDefault?.()
      fail()
    }
    w.onmessageerror = fail
    w.onmessage = (event: MessageEvent<unknown>) => {
      const d = event.data
      const answer = typeof d === 'object' && d !== null ? (d as Record<string, unknown>) : undefined
      if (!sent) {
        if (answer === undefined || answer.ready !== true || answer.v !== 2) {
          // Not the kit's worker of version 2 (one of version 1 answers the
          // hello with a failure): set aside before it sees the password.
          finish(() => resolve(null))
          return
        }
        clearTimeout(timer)
        copy = new Uint8Array(prepared)
        const request: KDFWorkerRequest = {
          v: 2,
          prepared: copy,
          salt: new Uint8Array(salt),
          params: { alg: params.alg, m: params.m, t: params.t, p: params.p },
          bounds: plainBounds(bounds),
        }
        try {
          w.postMessage(request, [copy.buffer])
        } catch {
          finish(() => resolve(null))
          return
        }
        sent = true
        return
      }
      if (answer !== undefined && answer.ok === true && answer.master instanceof Uint8Array && answer.master.length === 32) {
        const m = answer.master
        finish(() => resolve(new Uint8Array(m.buffer, m.byteOffset, 32) as Bytes))
      } else if (answer !== undefined && answer.ok === false && (answer.reason === 'out_of_bounds' || answer.reason === 'unsupported_alg')) {
        const reason = answer.reason
        finish(() => reject(new AccountError('the key derivation parameters were refused', 'kdf', reason)))
      } else {
        fail()
      }
    }
    try {
      w.postMessage({ v: 2 })
    } catch {
      finish(() => resolve(null))
    }
  })
}
