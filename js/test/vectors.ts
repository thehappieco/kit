/// <reference types="vite/client" />
// Loads the kit's vector files for the TypeScript tests, and replays recorded
// randomness.
//
// Each spec loads the files it owns and dispatches on every case's op; a case
// for this language whose op no branch handles fails, so no vector is skipped
// silently.
//
// The same specs run in Node and, in the js-browser job, in Chromium, Firefox
// and WebKit (vitest.browser.config.ts), so nothing here may need Node: the
// files are bundled by Vite (import.meta.glob) rather than read with node:fs,
// and bytes are decoded without Buffer.

import { expect, vi } from 'vitest'

import type { Bytes } from '../src/bytes.js'

export const FORMAT = 'thehappieco-kit-vectors/1'

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

// Every file under vectors/, as text, by its path there ("kit/seal-go.json").
const bundled: Record<string, string> = Object.fromEntries(
  Object.entries(import.meta.glob('../../vectors/**/*.json', { query: '?raw', import: 'default', eager: true }) as Record<string, string>)
    .map(([path, text]) => [path.replace(/^\.\.\/\.\.\/vectors\//, ''), text]),
)

function text(path: string): string {
  const t = bundled[path]
  if (t === undefined) throw new Error(`no vector file ${path}`)
  return t
}

// In the cross-language job, which runs in Node only, the other language's
// fresh files from $KIT_CROSS_IN, by base name.
const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env ?? {}
const fresh: Record<string, string> = {}
if (env.KIT_CROSS_IN) {
  const fs = await import('node:fs')
  for (const name of fs.readdirSync(env.KIT_CROSS_IN)) {
    if (name.endsWith('.json')) fresh[name] = fs.readFileSync(`${env.KIT_CROSS_IN}/${name}`, 'utf8')
  }
}

export function load(path: string): VectorFile {
  return check(path, JSON.parse(text(path)) as VectorFile)
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
    const name = path.slice(path.lastIndexOf('/') + 1)
    if (path.startsWith('kit/') && fresh[name] !== undefined) {
      const where = `${env.KIT_CROSS_IN}/${name}`
      out.push([where, check(where, JSON.parse(fresh[name]) as VectorFile)])
    }
  }
  return out
}

/** raw reads a legacy file, which keeps the shape Wappie gave it. */
export function raw(path: string): any {
  return JSON.parse(text(path))
}

export const forTS = (c: VectorCase) => !c.langs || c.langs.includes('ts')

export const b64 = (s: string) => Uint8Array.from(atob(s), (ch) => ch.charCodeAt(0)) as Bytes
export function toB64(b: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < b.length; i += 0x8000) binary += String.fromCharCode(...b.subarray(i, i + 0x8000))
  return btoa(binary)
}
export const utf8 = (s: string) => new TextEncoder().encode(s) as Bytes

/**
 * fromWTF8 decodes WTF-8, UTF-8 that may also encode a lone surrogate: how
 * the vectors carry a string that is not Unicode. In Go the bytes themselves
 * are such a string (invalid UTF-8); here it is a string with a lone
 * surrogate. Either way it has no JSON text.
 */
export function fromWTF8(b: Uint8Array): string {
  let s = ''
  for (let i = 0; i < b.length;) {
    const lead = b[i]
    const n = lead < 0x80 ? 1 : lead >= 0xf0 ? 4 : lead >= 0xe0 ? 3 : 2
    let cp = n === 1 ? lead : lead & (0xff >> (n + 1))
    for (let j = 1; j < n; j++) cp = (cp << 6) | (b[i + j] & 0x3f)
    s += String.fromCodePoint(cp)
    i += n
  }
  return s
}

/** toWTF8 is fromWTF8's inverse. */
export function toWTF8(s: string): Bytes {
  const out: number[] = []
  for (let i = 0; i < s.length; i++) {
    let cp = s.charCodeAt(i)
    const next = s.charCodeAt(i + 1)
    if (cp >= 0xd800 && cp <= 0xdbff && next >= 0xdc00 && next <= 0xdfff) {
      cp = 0x10000 + ((cp - 0xd800) << 10) + (next - 0xdc00)
      i++
    }
    if (cp < 0x80) out.push(cp)
    else if (cp < 0x800) out.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f))
    else if (cp < 0x10000) out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f))
    else out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f))
  }
  return new Uint8Array(out) as Bytes
}

export function unhandled(c: VectorCase): never {
  throw new Error(`case ${c.id}: op ${c.op} is not handled by the TypeScript tests`)
}

/**
 * withLenientX25519 runs fn on a WebCrypto that behaves like a non-conforming
 * engine: where the real X25519 refuses a public key of low order, it answers
 * with the 32 zero bytes the scalar multiplication gives. Under it, only the
 * kit's own check (RFC 9180 section 7.1.4) stands between a forgery sealed
 * under the all-zero secret and its plaintext.
 */
export async function withLenientX25519<T>(fn: () => Promise<T> | T): Promise<T> {
  const real = crypto.subtle.deriveBits.bind(crypto.subtle)
  const spy = vi.spyOn(crypto.subtle, 'deriveBits').mockImplementation((async (algorithm: AlgorithmIdentifier, key: CryptoKey, length: number) => {
    try {
      return await real(algorithm as never, key, length)
    } catch (err) {
      if ((typeof algorithm === 'string' ? algorithm : algorithm.name) !== 'X25519') throw err
      return new ArrayBuffer(32)
    }
  }) as never)
  try {
    return await fn()
  } finally {
    spy.mockRestore()
  }
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
