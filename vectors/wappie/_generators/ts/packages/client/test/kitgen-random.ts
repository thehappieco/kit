// Deterministic randomness for the kit's vector generators.
//
// Not part of Wappie: vectors/wappie/_generators/run.sh copies it beside
// kitgen.spec.ts in a throwaway extraction of Wappie. The code under test is
// never edited. Determinism comes from replacing the two sources of randomness
// it reads, for the duration of one case:
//
//   - crypto.getRandomValues, served from a byte stream;
//   - crypto.subtle.generateKey for X25519, which imports a pair whose private
//     half is the next 32 bytes of the same stream.
//
// The stream is HMAC-SHA256 in counter mode, keyed by the case id: block i is
// HMAC(key = UTF-8(id), data = u32be(i)). Every draw is logged, and each case
// records the bytes it consumed, so a replay needs only the case itself.

import { createHmac, createPrivateKey, createPublicKey } from 'node:crypto'
import { vi } from 'vitest'

const PKCS8_X25519_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex')

export class Stream {
  private counter = 0
  private pending = Buffer.alloc(0)
  constructor(readonly label: string) {}

  take(n: number): Uint8Array<ArrayBuffer> {
    while (this.pending.length < n) {
      const block = Buffer.alloc(4)
      block.writeUInt32BE(this.counter++)
      this.pending = Buffer.concat([this.pending, createHmac('sha256', this.label).update(block).digest()])
    }
    const out = new Uint8Array(this.pending.subarray(0, n))
    this.pending = this.pending.subarray(n)
    return out
  }
}

export interface Draw {
  kind: 'bytes' | 'x25519'
  /** The bytes handed out, or the X25519 private key. */
  bytes: Uint8Array
  /** For X25519, the public half. */
  publicRaw?: Uint8Array
}

/** x25519Public is the public half of a raw private key, computed by Node's own crypto. */
export function x25519Public(privateRaw: Uint8Array): Uint8Array<ArrayBuffer> {
  const key = createPrivateKey({ key: Buffer.concat([PKCS8_X25519_PREFIX, privateRaw]), format: 'der', type: 'pkcs8' })
  const spki = createPublicKey(key).export({ format: 'der', type: 'spki' })
  return new Uint8Array(spki.subarray(spki.length - 32))
}

export async function importX25519Pair(privateRaw: Uint8Array, extractable: boolean, usages: KeyUsage[]): Promise<CryptoKeyPair> {
  const publicRaw = x25519Public(privateRaw)
  const privateKey = await crypto.subtle.importKey('pkcs8', Buffer.concat([PKCS8_X25519_PREFIX, privateRaw]), { name: 'X25519' }, extractable, usages)
  const publicKey = await crypto.subtle.importKey('raw', publicRaw, { name: 'X25519' }, true, [])
  return { privateKey, publicKey }
}

/** withRandom runs fn with randomness drawn from a stream keyed by label, and returns what it drew. */
export async function withRandom<T>(label: string, fn: () => Promise<T> | T): Promise<{ value: T; draws: Draw[] }> {
  const stream = new Stream(label)
  const draws: Draw[] = []
  const realGenerateKey = crypto.subtle.generateKey.bind(crypto.subtle)
  const getRandom = vi.spyOn(crypto, 'getRandomValues').mockImplementation(((array: ArrayBufferView) => {
    const view = new Uint8Array(array.buffer, array.byteOffset, array.byteLength)
    const bytes = stream.take(view.length)
    view.set(bytes)
    draws.push({ kind: 'bytes', bytes })
    return array
  }) as never)
  const generateKey = vi.spyOn(crypto.subtle, 'generateKey').mockImplementation((async (algorithm: AlgorithmIdentifier, extractable: boolean, usages: KeyUsage[]) => {
    const name = typeof algorithm === 'string' ? algorithm : algorithm.name
    if (name !== 'X25519') return realGenerateKey(algorithm as never, extractable, usages)
    const privateRaw = stream.take(32)
    draws.push({ kind: 'x25519', bytes: privateRaw, publicRaw: x25519Public(privateRaw) })
    return importX25519Pair(privateRaw, extractable, usages)
  }) as never)
  try {
    return { value: await fn(), draws }
  } finally {
    getRandom.mockRestore()
    generateKey.mockRestore()
  }
}
