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

import { toBase64URL, type Bytes } from '../src/bytes.js'
import { importX25519 } from '../src/internal/x25519engine.js'

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

/**
 * freshOnly loads the file of this base name in $KIT_CROSS_IN, the fresh
 * vectors the Go side has just written in the cross-language job, or
 * nothing when that is not set. It is for kit files no release holds yet;
 * once vectors/kit holds the name, files reads both.
 */
export function freshOnly(name: string): [string, VectorFile][] {
  if (!env.KIT_CROSS_IN) return []
  const where = `${env.KIT_CROSS_IN}/${name}`
  if (fresh[name] === undefined) throw new Error(`${where} is missing`)
  return [[where, check(where, JSON.parse(fresh[name]) as VectorFile)]]
}

/** raw reads a legacy file, which keeps the shape Wappie gave it. */
export function raw(path: string): any {
  return JSON.parse(text(path))
}

export const forTS = (c: VectorCase) => !c.langs || c.langs.includes('ts')

// ---------------------------------------------------------------------------
// The platform's own format (vectors/README.md, "The platform's format"), in
// which vectors/platform/id-v1 is written. Bundled like every other file, so
// these run in the browsers too, and never skipped.
// ---------------------------------------------------------------------------

export const PLATFORM_FORMAT = 'thehappie-id/vectors'

export interface PlatformCase {
  name: string
  /** Which side refuses a must-fail key-delivery case: "open" or "seal". */
  op?: string
  error?: string
  // The members are the kind's; each runner reads them by name.
  [member: string]: any
}

export interface PlatformFile {
  format: string
  version: number
  kind: string
  cases: PlatformCase[]
}

/**
 * caseId is how the kit identifies and cites a case of the platform's
 * format: its name, or op "/" name when it carries an op. key-delivery.json
 * gives five names to two cases each, one with op "open" and one with op
 * "seal".
 */
export function caseId(c: PlatformCase): string {
  return c.op === undefined ? c.name : `${c.op}/${c.name}`
}

/** loadPlatform reads platform/id-v1/<kind>.json and checks its header and case ids. */
export function loadPlatform(kind: string): PlatformFile {
  const path = `platform/id-v1/${kind}.json`
  const f = JSON.parse(text(path)) as PlatformFile
  if (f.format !== PLATFORM_FORMAT || f.version !== 1 || f.kind !== kind) throw new Error(`${path}: header ${f.format} ${f.version} ${f.kind}`)
  const ids = new Set<string>()
  for (const c of f.cases) {
    if (typeof c.name !== 'string' || c.name === '' || (c.op !== undefined && typeof c.op !== 'string') || ids.has(caseId(c))) {
      throw new Error(`${path}: an empty or repeated case id`)
    }
    ids.add(caseId(c))
  }
  return f
}

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

/**
 * withEngineRefusingX25519 runs fn on a WebCrypto that throws a DOMException
 * with the given name for every X25519 key it is asked to import or
 * generate: NotSupportedError is an engine without X25519 at all, as Firefox
 * was before version 130; DataError one that refuses the key it is given.
 */
export async function withEngineRefusingX25519<T>(name: string, fn: () => Promise<T> | T): Promise<T> {
  const isX25519 = (algorithm: unknown) => (typeof algorithm === 'string' ? algorithm : (algorithm as { name?: string }).name) === 'X25519'
  const realImport = crypto.subtle.importKey.bind(crypto.subtle)
  const realGenerate = crypto.subtle.generateKey.bind(crypto.subtle)
  const importSpy = vi.spyOn(crypto.subtle, 'importKey').mockImplementation(((format: KeyFormat, data: BufferSource, algorithm: unknown, ...rest: unknown[]) => {
    if (isX25519(algorithm)) return Promise.reject(new DOMException('the engine refuses X25519 here', name))
    return (realImport as (...a: unknown[]) => Promise<CryptoKey>)(format, data, algorithm, ...rest)
  }) as never)
  const generateSpy = vi.spyOn(crypto.subtle, 'generateKey').mockImplementation(((algorithm: unknown, ...rest: unknown[]) => {
    if (isX25519(algorithm)) return Promise.reject(new DOMException('the engine refuses X25519 here', name))
    return (realGenerate as (...a: unknown[]) => Promise<CryptoKeyPair>)(algorithm, ...rest)
  }) as never)
  try {
    return await fn()
  } finally {
    importSpy.mockRestore()
    generateSpy.mockRestore()
  }
}

/**
 * LEADING_ZERO_KEYS are X25519 private keys whose first byte is 0x00, with
 * the public key Go's crypto/ecdh computes for each, in hex: the class
 * WebKit on Linux refuses to import as PKCS#8 (src/internal/x25519engine.ts):
 * the all-zero key; the sk_p of
 * kit/platform-delivery-go.json#platform/open-product-key/13; two zero
 * bytes; a first zero byte and every other bit set; and a key whose last
 * byte is zero too. The third public key ends with a zero byte.
 */
export const LEADING_ZERO_KEYS: readonly (readonly [string, string])[] = [
  ['0000000000000000000000000000000000000000000000000000000000000000', '2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74'],
  ['00277d685c5256c1b0c110819dd6028f827f41c4ad8013e0cc26b5db69907173', '0adb1d2bfd62435c70a0ef7c9c3633db62360dc59504b481dc73edd39113e302'],
  ['0000a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e', 'e524eee8008c95d857c5a486166904a1f2aadde00bc03199e7a2abe0a1a86f00'],
  ['00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', '39b14aa19789cddd964648d85fefb87bd4cb5342e4535fcdd4f6d6c1888f481d'],
  ['005a5d544f4679706b62651c170e0138332a2d24dfd6c9c0fbf2f5ece79e9100', '5456c35bb3f8044e375af4a4b3c0f0de75a071c66b9f5487c1a62db93ddc7334'],
]

export const fromHex = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16)) as Bytes
export const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')

/**
 * withX25519Generation runs fn on a WebCrypto whose X25519 generateKey
 * throws, on each call for which refuse names an error (counting from 0),
 * a DOMException of that name, and generates on the others: OperationError
 * is what WebKit on Linux throws on 1 call in 256, and NotSupportedError an
 * engine without X25519. It returns what fn returned or threw, and how many
 * X25519 pairs fn asked for.
 *
 * Only refuse fails a call. A call it lets through goes to the real engine,
 * which on WebKit for Linux fails 1 time in 256 as well; fn would then ask
 * again, spend the script's next refusals, and the spec's counts would break
 * on that engine alone. So that call asks the real engine again after an
 * OperationError, up to REAL_GENERATE_ATTEMPTS times, and still counts once.
 */
export async function withX25519Generation<T>(
  refuse: (call: number) => string | null,
  fn: () => Promise<T>,
): Promise<{ value?: T; error?: unknown; calls: number }> {
  const realGenerate = crypto.subtle.generateKey.bind(crypto.subtle) as (...a: unknown[]) => Promise<CryptoKeyPair | CryptoKey>
  let calls = 0
  const spy = vi.spyOn(crypto.subtle, 'generateKey').mockImplementation(((algorithm: unknown, ...rest: unknown[]) => {
    const name = typeof algorithm === 'string' ? algorithm : (algorithm as { name?: string }).name
    if (name !== 'X25519') return realGenerate(algorithm, ...rest)
    const error = refuse(calls++)
    if (error !== null) return Promise.reject(new DOMException('the engine refuses to generate this key', error))
    return generateDespiteEngine(() => realGenerate(algorithm, ...rest))
  }) as never)
  try {
    const value = await fn()
    return { value, calls }
  } catch (error) {
    return { error, calls }
  } finally {
    spy.mockRestore()
  }
}

// REAL_GENERATE_ATTEMPTS is how many times withX25519Generation asks the
// real engine for one call the script lets through: all of them fail on
// WebKit for Linux 1 time in 2^128.
const REAL_GENERATE_ATTEMPTS = 16

// generateDespiteEngine calls generate again after an OperationError, the
// engine's own random failure, REAL_GENERATE_ATTEMPTS times in all, and
// throws any other error at once.
async function generateDespiteEngine<K>(generate: () => Promise<K>): Promise<K> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await generate()
    } catch (err) {
      if (attempt >= REAL_GENERATE_ATTEMPTS || (err as { name?: unknown } | null)?.name !== 'OperationError') throw err
    }
  }
}

/**
 * pairFrom is the pair X25519 generateKey would have made with priv as its
 * private key, on every engine, a first byte of zero included: WebKit on
 * Linux refuses such a key as PKCS#8 (src/internal/x25519engine.ts). The
 * public half comes from the kit's own import. A non-extractable private
 * key is that import; an extractable one is imported from a JWK with that
 * public half, since its export must give back priv itself, which the
 * kit's PKCS#8 copy does not hold.
 */
async function pairFrom(priv: Uint8Array, extractable: boolean, usages: KeyUsage[]): Promise<CryptoKeyPair> {
  const derived = await importX25519(priv)
  const publicRaw = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: await basePoint() }, derived, 256))
  const sameUsages = usages.length === 1 && usages[0] === 'deriveBits'
  const privateKey = !extractable && sameUsages
    ? derived
    : await crypto.subtle.importKey(
      'jwk',
      { kty: 'OKP', crv: 'X25519', d: toBase64URL(new Uint8Array(priv)), x: toBase64URL(publicRaw), ext: extractable },
      { name: 'X25519' },
      extractable,
      usages,
    )
  return { privateKey, publicKey: await crypto.subtle.importKey('raw', publicRaw, { name: 'X25519' }, true, []) }
}

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
    return pairFrom(priv, extractable, usages)
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
    return pairFrom(priv, extractable, usages)
  }) as never)
  try {
    return { value: await fn(), bytes, x25519 }
  } finally {
    getRandom.mockRestore()
    generateKey.mockRestore()
  }
}
