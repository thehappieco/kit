// Argon2id, off the main thread.
//
// The derivation is deliberately expensive, and on the main thread it freezes
// the tab for the whole of it. A page that stops responding reads as broken,
// and somebody will reload it halfway through creating an account.
// account.ts starts this worker from ./kdf.worker.js beside itself, or from
// the factory a caller passes. From Wappie's packages/client/src/crypto/kdf.worker.ts.

import { argon2id } from '@noble/hashes/argon2.js'

export interface KDFRequest {
  /** The prepared password bytes; a string is taken as its UTF-8. */
  password: Uint8Array | string
  salt: Uint8Array
  m: number
  t: number
  p: number
}

self.onmessage = (event: MessageEvent<KDFRequest>) => {
  const { password, salt, m, t, p } = event.data
  const bytes = typeof password === 'string' ? new TextEncoder().encode(password) : password
  try {
    const out = argon2id(bytes, salt, { m, t, p, dkLen: 32 })
    // Transferred rather than copied: the buffer is done with here.
    ;(self as unknown as Worker).postMessage({ ok: true, master: out }, [out.buffer])
  } catch (err) {
    ;(self as unknown as Worker).postMessage({ ok: false, error: err instanceof Error ? err.message : String(err) })
  } finally {
    // This worker's copy of the prepared password. The caller zeroes its own.
    bytes.fill(0)
  }
}
