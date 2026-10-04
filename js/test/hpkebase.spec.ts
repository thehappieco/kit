// The HPKE key delivery seals and opens with (src/internal/platform/
// hpkebase.ts): it agrees with the hpke module in both directions, it
// refuses what RFC 9180 says to refuse, and it leaves no secret of its key
// schedule in a page buffer, which the hpke module does. The golden vectors
// (platform.spec.ts) check it against Go byte for byte. Ported from the
// platform's web/test/crypto/hpkebase.spec.ts at 4476bf4; it runs in the
// browsers too.

import { afterEach, describe, expect, it, vi } from 'vitest'

import { concat, encodeUTF8, type Bytes } from '../src/bytes.js'
import { generateKeyPair, importPrivateKey, open as referenceOpen, seal as referenceSeal } from '../src/hpke.js'
import { ENC_LEN, openBase, sealBase, TAG_LEN } from '../src/internal/platform/hpkebase.js'
import { HPKEError } from '../src/errors.js'
import { generateX25519KeyPair, importX25519PrivateKey, x25519PublicFromKey } from '../src/internal/platform/x25519.js'
import { withX25519Generation } from './vectors.js'

const INFO = encodeUTF8('thehappie-id/v1/key-delivery')

const random = (n: number) => crypto.getRandomValues(new Uint8Array(n)) as Bytes
const isZero = (b: Uint8Array) => b.every((x) => x === 0)

function same(a: Uint8Array, b: Uint8Array, label: string): void {
  if (a.length !== b.length || a.some((x, i) => x !== b[i])) expect.fail(`${label}: the values differ (not shown)`)
}

afterEach(() => {
  vi.restoreAllMocks()
})

async function recipient(): Promise<{ key: CryptoKey; publicKey: Bytes; raw: Bytes }> {
  const pair = await generateX25519KeyPair()
  return { key: await importX25519PrivateKey(pair.privateKey), publicKey: pair.publicKey, raw: pair.privateKey }
}

/** view is the bytes of a BufferSource argument, sharing its memory. */
function view(v: unknown): Uint8Array | null {
  if (v instanceof ArrayBuffer) return new Uint8Array(v)
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength)
  return null
}

function algorithmName(a: unknown): string {
  return typeof a === 'string' ? a : typeof a === 'object' && a !== null ? String((a as { name?: unknown }).name) : ''
}

/**
 * watchSecrets records, by reference, every buffer that carries a secret of
 * the key schedule through WebCrypto: HMAC and AES keys going in, HMAC
 * outputs and their inputs, exchange outputs, and the AES-GCM nonce.
 */
function watchSecrets(): Uint8Array[] {
  const seen: Uint8Array[] = []
  const keep = (v: unknown): void => {
    const b = view(v)
    if (b !== null && b.length > 0) seen.push(b)
  }
  const subtle = crypto.subtle
  const importKey = subtle.importKey.bind(subtle) as (...a: unknown[]) => Promise<CryptoKey>
  vi.spyOn(subtle, 'importKey').mockImplementation(((format: string, data: unknown, algorithm: unknown, ...rest: unknown[]) => {
    const name = algorithmName(algorithm)
    if (format === 'raw' && (name === 'HMAC' || name === 'AES-GCM')) keep(data)
    return importKey(format, data, algorithm, ...rest)
  }) as typeof subtle.importKey)
  const sign = subtle.sign.bind(subtle) as (...a: unknown[]) => Promise<ArrayBuffer>
  vi.spyOn(subtle, 'sign').mockImplementation((async (algorithm: unknown, key: unknown, data: unknown) => {
    keep(data)
    const out = await sign(algorithm, key, data)
    keep(out)
    return out
  }) as typeof subtle.sign)
  const deriveBits = subtle.deriveBits.bind(subtle) as (...a: unknown[]) => Promise<ArrayBuffer>
  vi.spyOn(subtle, 'deriveBits').mockImplementation((async (...args: unknown[]) => {
    const out = await deriveBits(...args)
    keep(out)
    return out
  }) as typeof subtle.deriveBits)
  for (const method of ['encrypt', 'decrypt'] as const) {
    const original = subtle[method].bind(subtle) as (...a: unknown[]) => Promise<ArrayBuffer>
    vi.spyOn(subtle, method).mockImplementation((async (algorithm: unknown, ...rest: unknown[]) => {
      keep((algorithm as { iv?: unknown }).iv)
      return original(algorithm, ...rest)
    }) as typeof subtle.encrypt)
  }
  return seen
}

describe('the HPKE of key delivery', () => {
  it('opens what the hpke module seals, and the reverse', async () => {
    for (const size of [0, 1, 32, 100]) {
      const pt = random(size)
      const aad = random(size + 3)
      const r = await generateKeyPair()
      const sealed = await sealBase(r.publicKey, INFO, aad, pt)
      expect(sealed.length).toBe(ENC_LEN + size + TAG_LEN)
      const opened = await referenceOpen(await importPrivateKey(r.privateKey), sealed.slice(0, ENC_LEN), INFO, aad, sealed.slice(ENC_LEN))
      same(opened, pt, `the hpke module's open of a ${size}-byte seal`)

      const { enc, ciphertext } = await referenceSeal(r.publicKey, INFO, aad, pt)
      const key = await importX25519PrivateKey(r.privateKey)
      same(await openBase(key, r.publicKey, concat(enc, ciphertext), INFO, aad), pt, `open of the hpke module's ${size}-byte seal`)
    }
  })

  it('opens a seal only for its recipient, info and AAD', async () => {
    const r = await recipient()
    const aad = encodeUTF8('["thehappie-id/key-delivery",1]')
    const pt = random(32)
    const sealed = await sealBase(r.publicKey, INFO, aad, pt)
    same(await openBase(r.key, r.publicKey, sealed, INFO, aad), pt, 'the plaintext')

    const other = await recipient()
    await expect(openBase(other.key, other.publicKey, sealed, INFO, aad)).rejects.toThrow()
    // The right key with another public key in the KEM context.
    await expect(openBase(r.key, other.publicKey, sealed, INFO, aad)).rejects.toThrow()
    await expect(openBase(r.key, r.publicKey, sealed, encodeUTF8('thehappie-id/v1/other'), aad)).rejects.toThrow()
    await expect(openBase(r.key, r.publicKey, sealed, INFO, encodeUTF8('["thehappie-id/key-delivery",2]'))).rejects.toThrow()
    for (const at of [0, 31, 32, sealed.length - 1]) {
      const bent = sealed.slice()
      bent[at] ^= 0x80
      await expect(openBase(r.key, r.publicKey, bent, INFO, aad), `bit flipped at ${at}`).rejects.toThrow()
    }
    await expect(openBase(r.key, r.publicKey, sealed.slice(0, ENC_LEN + TAG_LEN - 1), INFO, aad)).rejects.toThrow()
  })

  it('refuses the all-zero exchange on both sides', async () => {
    // enc, or pkR, of order 1 gives the all-zero shared value (RFC 9180 section 7.1.4).
    const r = await recipient()
    const lowOrder = new Uint8Array(32)
    lowOrder[0] = 1
    await expect(sealBase(lowOrder, INFO, new Uint8Array(0), random(32))).rejects.toThrow()
    await expect(openBase(r.key, r.publicKey, concat(lowOrder, random(48)), INFO, new Uint8Array(0))).rejects.toThrow()
  })

  it('refuses the all-zero exchange itself, on an engine that lets it through', async () => {
    // An engine that answers a low-order point with zeros instead of
    // refusing it: only the code's own check stops the seal and the open.
    // Firefox refuses the point earlier, when it is imported, which this
    // stand-in does not change; there the engine's refusal is what is seen.
    const refused = async (p: Promise<unknown>) => {
      const err = await p.then(() => undefined, (e: unknown) => e)
      expect(err).toBeDefined()
      if (!(err instanceof Error && /all-zero/.test(err.message))) expect((err as { name?: string }).name).toBe('DataError')
    }
    const r = await recipient()
    const real = crypto.subtle.deriveBits.bind(crypto.subtle)
    vi.spyOn(crypto.subtle, 'deriveBits').mockImplementation((async (algorithm: AlgorithmIdentifier, key: CryptoKey, length: number) => {
      try {
        return await real(algorithm as never, key, length)
      } catch {
        return new ArrayBuffer(32)
      }
    }) as never)
    const lowOrder = new Uint8Array(32)
    lowOrder[0] = 1
    await refused(sealBase(lowOrder, INFO, new Uint8Array(0), random(32)))
    await refused(openBase(r.key, r.publicKey, concat(lowOrder, random(48)), INFO, new Uint8Array(0)))
  })

  it('generates the ephemeral key non-extractable', async () => {
    const generated: CryptoKeyPair[] = []
    const generateKey = crypto.subtle.generateKey.bind(crypto.subtle) as (...a: unknown[]) => Promise<CryptoKeyPair>
    vi.spyOn(crypto.subtle, 'generateKey').mockImplementation((async (...args: unknown[]) => {
      const pair = await generateKey(...args)
      generated.push(pair)
      return pair
    }) as typeof crypto.subtle.generateKey)
    const r = await recipient()
    const sealed = await sealBase(r.publicKey, INFO, new Uint8Array(0), random(32))
    const eph = generated.at(-1)!
    expect(eph.privateKey.extractable).toBe(false)
    same(new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey)), sealed.slice(0, ENC_LEN), 'enc')
  })

  it('asks again for the ephemeral key when the engine fails to generate one', async () => {
    // WebKit on Linux fails 1 generateKey in 256 with an OperationError.
    const r = await recipient()
    const pt = random(32)
    const sealed = await withX25519Generation((call) => (call < 3 ? 'OperationError' : null), () => sealBase(r.publicKey, INFO, new Uint8Array(0), pt))
    expect(sealed.calls).toBe(4)
    same(await openBase(r.key, r.publicKey, sealed.value!, INFO, new Uint8Array(0)), pt, 'the plaintext')
    // Four in a row is the engine's failure, not the recipient's.
    const refused = await withX25519Generation(() => 'OperationError', () => sealBase(r.publicKey, INFO, new Uint8Array(0), pt))
    expect(refused.calls).toBe(4)
    expect(refused.error).toBeInstanceOf(HPKEError)
    expect(((refused.error as HPKEError).cause as DOMException).name).toBe('OperationError')
  })

  it('leaves no secret of the key schedule in a page buffer, sealing or opening', async () => {
    const r = await recipient()
    const aad = random(40)
    const pt = random(32)
    const sealing = watchSecrets()
    const sealed = await sealBase(r.publicKey, INFO, aad, pt)
    vi.restoreAllMocks()
    // The exchange output, the HMAC keys and blocks, the AES key bytes and
    // the nonce: at least one of each went through WebCrypto, and all are zero.
    expect(sealing.length).toBeGreaterThan(10)
    for (const [i, b] of sealing.entries()) expect(isZero(b), `seal: buffer ${i} of ${sealing.length} was not wiped`).toBe(true)

    const opening = watchSecrets()
    const opened = await openBase(r.key, r.publicKey, sealed, INFO, aad)
    vi.restoreAllMocks()
    expect(opening.length).toBeGreaterThan(10)
    for (const [i, b] of opening.entries()) expect(isZero(b), `open: buffer ${i} of ${opening.length} was not wiped`).toBe(true)
    same(opened, pt, 'the plaintext')
    // The recipient's public key is the caller's and untouched.
    same(await x25519PublicFromKey(r.key), r.publicKey, 'the recipient public key')
  })

  it('is why key delivery does not use the hpke module: the same watch finds its schedule left behind', async () => {
    // Proof that the tests around this one can fail: the same watch over
    // the hpke module's seal finds secrets left.
    const r = await recipient()
    const seen = watchSecrets()
    await referenceSeal(r.publicKey, INFO, new Uint8Array(0), random(32))
    vi.restoreAllMocks()
    expect(seen.some((b) => !isZero(b))).toBe(true)
  })

  it('wipes on a failed open too, and keeps the caller\'s buffers', async () => {
    const r = await recipient()
    const sealed = await sealBase(r.publicKey, INFO, new Uint8Array(0), random(32))
    const bent = sealed.slice()
    bent[50] ^= 1
    const copy = bent.slice()
    const seen = watchSecrets()
    await expect(openBase(r.key, r.publicKey, bent, INFO, new Uint8Array(0))).rejects.toThrow()
    vi.restoreAllMocks()
    for (const [i, b] of seen.entries()) expect(isZero(b), `buffer ${i} of ${seen.length} was not wiped`).toBe(true)
    same(bent, copy, 'the sealed input')
  })
})
