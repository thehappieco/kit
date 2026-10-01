// An account: what a password turns into, and what that opens.
//
// The password never leaves the client. Argon2id turns it into a master key,
// which HKDF splits into two independent branches:
//
//   auth: sent to the server and stored there only as a slow or
//         domain-separated hash. Proves who you are; opens nothing.
//   wrap: never transmitted. Unwraps the account's key.
//
// A recovery code is the second way back in: 150 random bits, written down by
// hand, split by HKDF into a key that wraps the same account key and a proof
// that is sent.
//
// From Wappie's packages/client/src/crypto/account.ts. The labels, the wrap
// header, the password preparation, the KDF bounds and the text encoding are
// the profile's; what a wrap binds to (its AAD) is the caller's, built by the
// profile's own helper.
//
// Argon2id is the one place the kit uses a dependency (@noble/hashes):
// WebCrypto has PBKDF2 and nothing memory-hard, and the wrapped key sits in a
// server's database, which is the threat this scheme is built against.

import { concat, encodeUTF8, toBase64, toBase64URL, type Bytes } from './bytes.js'
import { AccountError } from './errors.js'
import { generateKeyPair } from './hpke.js'

export { AccountError }
export type { AccountErrorCode, AccountErrorReason } from './errors.js'

/** KDFParams mirror what the server stores, so the cost can be raised later. */
export interface KDFParams {
  alg: string
  /** Memory in KiB. */
  m: number
  /** Passes. */
  t: number
  p: number
}

export const defaultKDFParams: KDFParams = Object.freeze({ alg: 'argon2id', m: 64 * 1024, t: 3, p: 1 }) as KDFParams

/** KDFBounds are the parameters a client accepts from a server before deriving. */
export interface KDFBounds {
  min: { m: number; t: number; p: number }
  max: { m: number; t: number; p: number }
  /** Bounds m times t; absent means no bound. */
  maxCost?: number
}

/** AccountProfile is everything a product chooses about the scheme. */
export interface AccountProfile {
  readonly authLabel: string
  readonly wrapLabel: string
  readonly recoveryKeyLabel: string
  readonly recoveryProofLabel: string
  /** Prefixes every wrap: header, nonce (12), ciphertext and tag. */
  readonly wrapHeader: readonly number[]
  /** Also open header-less nonce, ciphertext and tag with no AAD, as stale. */
  readonly legacyV1: boolean
  /** How the auth key and the recovery proof are written as text. */
  readonly encoding: 'base64' | 'base64url'
  /** Turns a password into the bytes Argon2id reads; absent means UTF-8, unchanged. */
  readonly prepare?: (password: string) => Bytes
  /** Enforced before any derivation; absent means none. */
  readonly bounds?: KDFBounds
  /** Canonicalises a typed recovery code; absent means normaliseRecoveryCode. */
  readonly normaliseRecovery?: (code: string) => string
}

const SALT_LEN = 16
const NONCE_LEN = 12
const TAG_LEN = 16

function encode(p: AccountProfile, b: Bytes): string {
  return p.encoding === 'base64url' ? toBase64URL(b) : toBase64(b)
}

/** checkKDFParams throws unless params are ones this profile derives with. */
export function checkKDFParams(p: AccountProfile, params: KDFParams): void {
  if (params.alg !== 'argon2id') throw new AccountError('unsupported key derivation', 'kdf', 'unsupported_alg')
  const b = p.bounds
  if (!b) return
  if (params.m < b.min.m || params.m > b.max.m || params.t < b.min.t || params.t > b.max.t || params.p < b.min.p || params.p > b.max.p ||
    (b.maxCost !== undefined && params.m * params.t > b.maxCost)) {
    throw new AccountError('key derivation parameters out of bounds', 'kdf', 'out_of_bounds')
  }
}

/** Derived is the pair a password becomes. Neither half is the password. */
export interface Derived {
  /** Sent to the server, in the profile's encoding. */
  authKey: string
  /** Stays here, non-extractable. Wraps and unwraps the account key. */
  wrapKey: CryptoKey
}

export interface DeriveOptions {
  /**
   * Makes the Argon2id worker. The default loads ./kdf.worker.js beside this
   * module; a bundler that moves files can supply the right URL here.
   */
  worker?: () => Worker
}

/**
 * derive turns a password into the two branches:
 *
 *   master = Argon2id(prepared password, salt, m, t, p, dkLen 32, version 0x13)
 *   auth   = HKDF-SHA256(master, salt empty, info authLabel)
 *   wrap   = HKDF-SHA256(master, salt empty, info wrapLabel)
 */
export async function derive(p: AccountProfile, password: string, salt: Bytes, params: KDFParams, options: DeriveOptions = {}): Promise<Derived> {
  checkKDFParams(p, params)
  let prepared: Bytes
  try {
    prepared = p.prepare ? p.prepare(password) : encodeUTF8(password)
  } catch {
    throw new AccountError('the password was refused', 'password', 'rejected')
  }
  const master = await stretch(prepared, salt, params, options)
  const base = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveBits'])
  const branch = (label: string) =>
    crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: encodeUTF8(label) }, base, 256)
  const [auth, wrap] = await Promise.all([branch(p.authLabel), branch(p.wrapLabel)])
  master.fill(0)
  return {
    authKey: encode(p, new Uint8Array(auth)),
    wrapKey: await crypto.subtle.importKey('raw', wrap, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']),
  }
}

/**
 * stretch runs Argon2id, in a worker where there is one. The fallback is the
 * same function called directly: a login that works slowly beats one that
 * does not, and Node, where the tests run, has no Worker.
 */
async function stretch(password: Bytes, salt: Bytes, params: KDFParams, options: DeriveOptions): Promise<Bytes> {
  const direct = async () => {
    // Loaded on demand: a browser normally derives in the worker, and should
    // not download a second copy of Argon2 for this path.
    const { argon2id } = await import('@noble/hashes/argon2.js')
    try {
      return argon2id(password, salt, { m: params.m, t: params.t, p: params.p, dkLen: 32 }) as Bytes
    } catch {
      throw new AccountError('the key derivation failed', 'kdf', 'kdf_failed')
    }
  }
  if (!options.worker && typeof Worker === 'undefined') return direct()
  try {
    const worker = options.worker ? options.worker() : new Worker(new URL('./kdf.worker.js', import.meta.url), { type: 'module' })
    try {
      return await new Promise<Bytes>((resolve, reject) => {
        worker.onmessage = (event: MessageEvent<{ ok: boolean; master?: Bytes; error?: string }>) => {
          if (event.data.ok && event.data.master) resolve(event.data.master)
          else reject(new AccountError('the key derivation failed', 'kdf', 'kdf_failed'))
        }
        worker.onerror = () => reject(new AccountError('the key derivation failed', 'kdf', 'kdf_failed'))
        worker.postMessage({ password, salt, m: params.m, t: params.t, p: params.p })
      })
    } finally {
      worker.terminate()
    }
  } catch {
    // No module workers, or the bundle could not load one. Slower and
    // blocking, but it works.
    return direct()
  }
}

export function freshSalt(): Bytes {
  return crypto.getRandomValues(new Uint8Array(SALT_LEN))
}

/** AccountKeys is an X25519 pair; the private half is held only to be wrapped. */
export interface AccountKeys {
  publicKey: Bytes
  privateKey: Bytes
}

export async function generateAccountKeys(): Promise<AccountKeys> {
  return generateKeyPair()
}

/** wrapPrivateKey seals a key (an account key, or a root) under a wrap key, bound to aad. */
export async function wrapPrivateKey(p: AccountProfile, privateKey: Bytes, under: CryptoKey, aad: Bytes): Promise<Bytes> {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN))
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, under, privateKey))
  return concat(new Uint8Array(p.wrapHeader), nonce, sealed)
}

/** Unwrapped is the key, and whether the blob it came from needs re-wrapping. */
export interface Unwrapped {
  privateKey: Bytes
  /** True for a legacy blob, which carries no binding. */
  stale: boolean
}

/**
 * unwrapPrivateKey reverses it. A blob with the profile's header is tried
 * under its binding first; with legacyV1 it is then tried as a legacy blob. A
 * wrong key and a wrong binding are the same failure: wrong_key.
 */
export async function unwrapPrivateKey(p: AccountProfile, blob: Bytes, under: CryptoKey, aad: Bytes): Promise<Unwrapped> {
  const h = p.wrapHeader.length
  if (blob.length > NONCE_LEN + h && p.wrapHeader.every((b, i) => blob[i] === b)) {
    try {
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: blob.subarray(h, h + NONCE_LEN), additionalData: aad }, under, blob.subarray(h + NONCE_LEN))
      return { privateKey: new Uint8Array(plain) as Bytes, stale: false }
    } catch {
      // Not this account's wrap, or the wrong key. A legacy blob is tried below.
    }
  }
  if (!p.legacyV1) {
    if (blob.length < h + NONCE_LEN + TAG_LEN) throw new AccountError('the stored key is truncated', 'wrap', 'truncated')
    throw new AccountError('the key does not open this wrap', 'wrap', 'wrong_key')
  }
  if (blob.length <= NONCE_LEN) throw new AccountError('the stored key is truncated', 'wrap', 'truncated')
  try {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: blob.subarray(0, NONCE_LEN) }, under, blob.subarray(NONCE_LEN))
    return { privateKey: new Uint8Array(plain) as Bytes, stale: true }
  } catch {
    throw new AccountError('the key does not open this wrap', 'wrap', 'wrong_key')
  }
}

// ---------------------------------------------------------------------------
// The recovery code
// ---------------------------------------------------------------------------

// Crockford's base32: no I, L, O or U, so nothing reads as a digit and back.
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
const CODE_GROUPS = 6
const GROUP_LEN = 5

function group(chars: string): string {
  const groups: string[] = []
  for (let i = 0; i < CODE_GROUPS; i++) groups.push(chars.slice(i * GROUP_LEN, (i + 1) * GROUP_LEN))
  return groups.join('-')
}

/** newRecoveryCode returns 150 random bits as six groups of five characters. */
export function newRecoveryCode(): string {
  const raw = crypto.getRandomValues(new Uint8Array(CODE_GROUPS * GROUP_LEN))
  // Unbiased: 256 is a multiple of 32.
  return group(Array.from(raw, (b) => ALPHABET[b % ALPHABET.length]).join(''))
}

/** normaliseRecoveryCode accepts what somebody actually types back. */
export function normaliseRecoveryCode(code: string): string {
  const cleaned = code
    .toUpperCase()
    .replace(/[^0-9A-Z]/g, '')
    // The letters the alphabet leaves out, mapped to what they were meant to be.
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1')
    .replace(/U/g, 'V')
  if (cleaned.length !== CODE_GROUPS * GROUP_LEN) {
    throw new AccountError(`a recovery code has ${CODE_GROUPS * GROUP_LEN} characters`, 'recovery', 'recovery_length')
  }
  return group(cleaned)
}

async function recoveryBranch(p: AccountProfile, code: string, label: string): Promise<ArrayBuffer> {
  const normalised = p.normaliseRecovery ? p.normaliseRecovery(code) : normaliseRecoveryCode(code)
  const material = await crypto.subtle.importKey('raw', encodeUTF8(normalised), 'HKDF', false, ['deriveBits'])
  return crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: encodeUTF8(label) }, material, 256)
}

/**
 * recoveryKey derives the wrap key of a recovery code. Not stretched: the
 * code is 150 random bits, so slowing it down would only punish its owner.
 */
export async function recoveryKey(p: AccountProfile, code: string): Promise<CryptoKey> {
  const bits = await recoveryBranch(p, code, p.recoveryKeyLabel)
  return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

/** recoveryProof is the branch of the code that is sent, independent of the key. */
export async function recoveryProof(p: AccountProfile, code: string): Promise<string> {
  return encode(p, new Uint8Array(await recoveryBranch(p, code, p.recoveryProofLabel)))
}

/** bind fixes a profile, for a product's own wrappers. */
export function bind(p: AccountProfile) {
  return {
    profile: p,
    checkKDFParams: (params: KDFParams) => checkKDFParams(p, params),
    derive: (password: string, salt: Bytes, params: KDFParams, options?: DeriveOptions) => derive(p, password, salt, params, options),
    wrapPrivateKey: (privateKey: Bytes, under: CryptoKey, aad: Bytes) => wrapPrivateKey(p, privateKey, under, aad),
    unwrapPrivateKey: (blob: Bytes, under: CryptoKey, aad: Bytes) => unwrapPrivateKey(p, blob, under, aad),
    recoveryKey: (code: string) => recoveryKey(p, code),
    recoveryProof: (code: string) => recoveryProof(p, code),
    freshSalt,
    generateAccountKeys,
    newRecoveryCode,
    normaliseRecoveryCode,
  }
}
