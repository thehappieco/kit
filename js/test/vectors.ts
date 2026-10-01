// Loads the kit's vector files for the TypeScript tests, and replays recorded
// randomness.
//
// Each spec loads the files it owns and dispatches on every case's op; a case
// for this language whose op no branch handles fails, so no vector is skipped
// silently.

import { existsSync, readFileSync } from 'node:fs'
import { basename, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, vi } from 'vitest'

import type { Bytes } from '../src/bytes.js'

export const FORMAT = 'thehappieco-kit-vectors/1'
export const VECTORS = fileURLToPath(new URL('../../vectors/', import.meta.url))

export interface VectorCase {
  id: string
  op: string
  langs?: string[]
  // Vector inputs and outputs are loosely shaped JSON by design.
  in: any
  out?: any
  error?: string
  reason?: string
  note?: string
}

export interface VectorKey {
  private_key_b64: string
  public_key_b64: string
  x25519_private_key_b64?: string
}

export interface VectorFile {
  format: string
  module: string
  profile: string
  generated_by: { lang: string; source: string; toolchain: string; randomness: string; generator: string }
  note: string
  keys?: Record<string, VectorKey>
  cases: VectorCase[]
}

export function load(path: string): VectorFile {
  return check(path, JSON.parse(readFileSync(VECTORS + path, 'utf8')) as VectorFile)
}

function check(path: string, f: VectorFile): VectorFile {
  if (f.format !== FORMAT) throw new Error(`${path}: format ${f.format}`)
  const ids = new Set<string>()
  for (const c of f.cases) {
    if (ids.has(c.id)) throw new Error(`${path}: duplicate case ${c.id}`)
    ids.add(c.id)
    if ((c.out === undefined) === (c.error === undefined)) throw new Error(`${path}: ${c.id} must have exactly one of out and error`)
  }
  return f
}

/**
 * files loads the named files and, for each kit/*.json name, the file of the
 * same base name in $KIT_CROSS_IN when that is set: the fresh vectors the Go
 * side has just written, in the cross-language job.
 */
export function files(...paths: string[]): [string, VectorFile][] {
  const out: [string, VectorFile][] = []
  for (const path of paths) {
    out.push([path, load(path)])
    const dir = process.env.KIT_CROSS_IN
    if (!dir || !path.startsWith('kit/')) continue
    const fresh = join(dir, basename(path))
    if (existsSync(fresh)) out.push([fresh, check(fresh, JSON.parse(readFileSync(fresh, 'utf8')) as VectorFile)])
  }
  return out
}

/** raw reads a legacy file, which keeps the shape Wappie gave it. */
export function raw(path: string): any {
  return JSON.parse(readFileSync(VECTORS + path, 'utf8'))
}

export const forTS = (c: VectorCase) => !c.langs || c.langs.includes('ts')

export const b64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64')) as Bytes
export const toB64 = (b: Uint8Array) => Buffer.from(b).toString('base64')
export const utf8 = (s: string) => new Uint8Array(Buffer.from(s, 'utf8')) as Bytes

export function unhandled(c: VectorCase): never {
  throw new Error(`case ${c.id}: op ${c.op} is not handled by the TypeScript tests`)
}

const PKCS8_X25519_PREFIX = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20])

/**
 * withDraws runs fn with crypto.getRandomValues serving the recorded byte
 * strings in order and X25519 generateKey importing the recorded private keys
 * in order, and checks fn consumed exactly what was recorded, in the same
 * sizes. This is how a seal is replayed byte for byte.
 */
export async function withDraws<T>(draws: { bytes?: Uint8Array[]; x25519?: Uint8Array[] }, fn: () => Promise<T> | T): Promise<T> {
  const bytes = [...(draws.bytes ?? [])]
  const x25519 = [...(draws.x25519 ?? [])]
  const realGenerateKey = crypto.subtle.generateKey.bind(crypto.subtle)
  const getRandom = vi.spyOn(crypto, 'getRandomValues').mockImplementation(((array: ArrayBufferView) => {
    const next = bytes.shift()
    if (!next || next.length !== array.byteLength) throw new Error(`unexpected draw of ${array.byteLength} bytes`)
    new Uint8Array(array.buffer, array.byteOffset, array.byteLength).set(next)
    return array
  }) as never)
  const generateKey = vi.spyOn(crypto.subtle, 'generateKey').mockImplementation((async (algorithm: AlgorithmIdentifier, extractable: boolean, usages: KeyUsage[]) => {
    const name = typeof algorithm === 'string' ? algorithm : algorithm.name
    if (name !== 'X25519') return realGenerateKey(algorithm as never, extractable, usages)
    const priv = x25519.shift()
    if (!priv) throw new Error('unexpected X25519 key generation')
    const privateKey = await crypto.subtle.importKey('pkcs8', new Uint8Array([...PKCS8_X25519_PREFIX, ...priv]), { name: 'X25519' }, extractable, usages)
    const scalarPublic = await crypto.subtle.deriveBits({ name: 'X25519', public: await basePoint() }, privateKey, 256)
    const publicKey = await crypto.subtle.importKey('raw', scalarPublic, { name: 'X25519' }, true, [])
    return { privateKey, publicKey }
  }) as never)
  try {
    const value = await fn()
    expect(bytes.length, 'unconsumed recorded bytes').toBe(0)
    expect(x25519.length, 'unconsumed recorded X25519 keys').toBe(0)
    return value
  } finally {
    getRandom.mockRestore()
    generateKey.mockRestore()
  }
}

async function basePoint(): Promise<CryptoKey> {
  const nine = new Uint8Array(32)
  nine[0] = 9
  return crypto.subtle.importKey('raw', nine, { name: 'X25519' }, true, [])
}

/** codeOf runs fn and returns the error's code (or reason), or 'none'. */
export async function codeOf(fn: () => unknown): Promise<string> {
  try {
    await fn()
  } catch (err) {
    const e = err as { code?: string; reason?: string; name?: string; message?: string }
    return e.code ?? e.reason ?? `${e.name}: ${e.message}`
  }
  return 'none'
}

/**
 * recording runs fn with real randomness and returns what it drew: the byte
 * strings crypto.getRandomValues filled, and the private keys X25519
 * generateKey made. The kit's own vectors record them, so the other language
 * can replay a seal where it can inject randomness.
 */
export async function recording<T>(fn: () => Promise<T> | T): Promise<{ value: T; bytes: Uint8Array[]; x25519: Uint8Array[] }> {
  const real = crypto.getRandomValues.bind(crypto)
  const realGenerateKey = crypto.subtle.generateKey.bind(crypto.subtle)
  const bytes: Uint8Array[] = []
  const x25519: Uint8Array[] = []
  const getRandom = vi.spyOn(crypto, 'getRandomValues').mockImplementation(((array: ArrayBufferView) => {
    const view = new Uint8Array(array.buffer, array.byteOffset, array.byteLength)
    real(view)
    bytes.push(view.slice())
    return array
  }) as never)
  const generateKey = vi.spyOn(crypto.subtle, 'generateKey').mockImplementation((async (algorithm: AlgorithmIdentifier, extractable: boolean, usages: KeyUsage[]) => {
    const name = typeof algorithm === 'string' ? algorithm : algorithm.name
    if (name !== 'X25519') return realGenerateKey(algorithm as never, extractable, usages)
    const priv = real(new Uint8Array(32))
    x25519.push(priv.slice())
    const privateKey = await crypto.subtle.importKey('pkcs8', new Uint8Array([...PKCS8_X25519_PREFIX, ...priv]), { name: 'X25519' }, extractable, usages)
    const publicRaw = await crypto.subtle.deriveBits({ name: 'X25519', public: await basePoint() }, privateKey, 256)
    return { privateKey, publicKey: await crypto.subtle.importKey('raw', publicRaw, { name: 'X25519' }, true, []) }
  }) as never)
  try {
    return { value: await fn(), bytes, x25519 }
  } finally {
    getRandom.mockRestore()
    generateKey.mockRestore()
  }
}
