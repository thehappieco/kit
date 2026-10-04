// HPKE (RFC 9180) base mode, single shot.
//
// Suite, frozen to match the Go side (package hpke): DHKEM(X25519,
// HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM. Nothing is negotiated, so there is
// no downgrade to negotiate.
//
// Written against WebCrypto with no third-party dependency. A crypto library
// from npm, or Go compiled to WASM, would put every key behind code that is
// harder to audit than this file, and the supply chain of a package that can
// read every message is not a small thing. WebCrypto's X25519 is native in
// current browsers and in Node.
//
// The risk of a second implementation is that it is silently wrong: it opens
// everything it sealed itself and fails only against real data. The vectors
// are the check: Go's crypto/hpke opens what this seals and the reverse.
// From Wappie's packages/client/src/crypto/hpke.ts; importArchiveKey is
// importPrivateKey here, because the key may be any X25519 key.

import { type Bytes, concat, i2osp2, encodeUTF8 } from './bytes.js'
import { HPKEError } from './errors.js'
import { generateX25519, importX25519 } from './internal/x25519engine.js'

export { HPKEError }

export const KEM_ID = 0x0020 // DHKEM(X25519, HKDF-SHA256)
export const KDF_ID = 0x0001 // HKDF-SHA256
export const AEAD_ID = 0x0002 // AES-256-GCM

const N_SECRET = 32 // KEM shared secret
const N_DH = 32 // X25519 output
const N_K = 32 // AES-256 key
const N_N = 12 // AES-GCM nonce
const HASH_LEN = 32 // SHA-256

/** The X25519 encapsulated key: a public key, 32 bytes. */
export const ENC_LEN = 32

const HPKE_V1 = encodeUTF8('HPKE-v1')
const KEM_SUITE = concat(encodeUTF8('KEM'), i2osp2(KEM_ID))
const HPKE_SUITE = concat(encodeUTF8('HPKE'), i2osp2(KEM_ID), i2osp2(KDF_ID), i2osp2(AEAD_ID))

// ---------------------------------------------------------------------------
// HKDF, split into Extract and Expand.
//
// WebCrypto's HKDF only offers the two fused together, and HPKE needs a PRK
// from one Extract fed into several Expands. So both halves are built on HMAC,
// which WebCrypto does expose.
// ---------------------------------------------------------------------------

async function hmac(key: Bytes, data: Bytes): Promise<Bytes> {
  const k = await crypto.subtle.importKey('raw', key.length === 0 ? new Uint8Array(HASH_LEN) : key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, data))
}

async function extract(salt: Bytes, ikm: Bytes): Promise<Bytes> {
  return hmac(salt, ikm)
}

async function expand(prk: Bytes, info: Bytes, length: number): Promise<Bytes> {
  const out = new Uint8Array(length)
  let previous = new Uint8Array(0)
  let at = 0
  for (let counter = 1; at < length; counter++) {
    previous = await hmac(prk, concat(previous, info, new Uint8Array([counter])))
    const take = Math.min(previous.length, length - at)
    out.set(previous.subarray(0, take), at)
    at += take
  }
  return out
}

async function labeledExtract(suite: Bytes, salt: Bytes, label: string, ikm: Bytes): Promise<Bytes> {
  return extract(salt, concat(HPKE_V1, suite, encodeUTF8(label), ikm))
}

async function labeledExpand(suite: Bytes, prk: Bytes, label: string, info: Bytes, length: number): Promise<Bytes> {
  return expand(prk, concat(i2osp2(length), HPKE_V1, suite, encodeUTF8(label), info), length)
}

// ---------------------------------------------------------------------------
// X25519 over WebCrypto.
// ---------------------------------------------------------------------------

// WebCrypto imports an X25519 private key from PKCS#8 and nothing shorter, so
// the 32 raw bytes get the fixed DER prefix for id-X25519 wrapped round them,
// and it exports a generated one in the same form. Imports and generation go
// through internal/x25519engine.ts, which makes every engine take any 32
// bytes (WebKit on Linux refuses a key whose first byte is zero) and asks
// again where WebKit on Linux fails to generate a key.
const PKCS8_X25519_PREFIX = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20])

// The X25519 base point. Multiplying a private key by it recovers the public
// key: WebCrypto will not export a public half from a key imported as
// private, and DHKEM needs the recipient public key in its context.
const BASE_POINT = new Uint8Array(32)
BASE_POINT[0] = 9

async function importPrivate(raw: Bytes): Promise<CryptoKey> {
  if (raw.length !== 32) throw new Error('an X25519 private key must contain 32 bytes')
  // importX25519 builds a second copy of the key, which WebCrypto copies
  // again when it imports, and zeroes it once it has, so the page's heap does
  // not keep one per import.
  try {
    return await importX25519(raw)
  } catch (err) {
    // A refusal is the kit's own error. The engine's own error is its cause,
    // so a caller can tell an engine without X25519 (NotSupportedError) from
    // one that refused this key.
    throw new HPKEError('the engine refuses this private key', 'invalid_key', { cause: err })
  }
}

async function importPublic(raw: Bytes): Promise<CryptoKey> {
  if (raw.length !== 32) throw new Error('an X25519 public key must contain 32 bytes')
  return crypto.subtle.importKey('raw', raw, { name: 'X25519' }, true, [])
}

/**
 * dh is X25519 with the check RFC 9180 section 7.1.4 requires: an all-zero
 * output means the public key was of low order, and DHKEM must abort.
 *
 * WebCrypto engines are supposed to refuse such a point themselves, and Node's
 * does, but the kit does not rely on it. An engine that returned the zeros
 * instead would let anybody who can write the database forge a grant (an
 * encapsulated key of low order, and a ciphertext sealed under the secret
 * everyone can compute from it), and would let a server hand out a low-order
 * "public key" and open what the browser sealed to it. Both directions go
 * through here: encap when sealing, decap when opening. The bytes are folded
 * together without an early exit, so the time taken does not depend on them.
 */
async function dh(priv: CryptoKey, publicRaw: Bytes): Promise<Bytes> {
  let shared: Bytes
  try {
    const pub = await importPublic(publicRaw)
    shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: pub }, priv, 256)) as Bytes
  } catch (err) {
    throw new HPKEError('no shared secret with this public key', 'invalid_key', { cause: err })
  }
  let any = 0
  for (let i = 0; i < shared.length; i++) any |= shared[i]
  if (shared.length !== N_DH || any === 0) throw new HPKEError('no shared secret with this public key', 'invalid_key')
  return shared
}

/** publicFromPrivate recovers the public half of an X25519 key. */
export async function publicFromPrivate(privRaw: Bytes): Promise<Bytes> {
  return dh(await importPrivate(privRaw), BASE_POINT)
}

/**
 * PrivateKey is an imported X25519 key, kept as a non-extractable CryptoKey
 * so the raw bytes can be dropped after unlocking.
 */
export interface PrivateKey {
  readonly key: CryptoKey
  /** The public half, which DHKEM needs in its context on every open. */
  readonly publicRaw: Bytes
}

/** KeyPair is a fresh X25519 pair with the private half in the clear. */
export interface KeyPair {
  publicKey: Bytes
  privateKey: Bytes
}

/**
 * generateKeyPair mints an X25519 pair with the private half in the clear.
 *
 * Extractable on purpose: the callers hold the raw private key for a moment,
 * to wrap it under a password or seal it to another key. The PKCS#8 export is
 * checked to be the 48-byte form with the fixed prefix before the 32 raw
 * bytes are taken from its end.
 */
export async function generateKeyPair(): Promise<KeyPair> {
  const pair = await generateX25519(true)
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey))
  try {
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))
    if (pkcs8.length !== PKCS8_X25519_PREFIX.length + 32 || PKCS8_X25519_PREFIX.some((b, i) => pkcs8[i] !== b)) {
      throw new Error('unexpected PKCS#8 encoding of an X25519 key')
    }
    return { publicKey: raw as Bytes, privateKey: pkcs8.slice(PKCS8_X25519_PREFIX.length) as Bytes }
  } finally {
    // The export holds the private key too; the caller gets its own copy.
    pkcs8.fill(0)
  }
}

/** importPrivateKey imports a raw 32-byte X25519 key, non-extractable. */
export async function importPrivateKey(privRaw: Bytes): Promise<PrivateKey> {
  const key = await importPrivate(privRaw)
  const publicRaw = await dh(key, BASE_POINT)
  return { key, publicRaw }
}

// ---------------------------------------------------------------------------
// DHKEM and the key schedule.
// ---------------------------------------------------------------------------

/**
 * encap generates an ephemeral key pair and derives the shared secret. A fresh
 * key per seal is what makes base mode safe without a sequence number.
 */
async function encap(publicRaw: Bytes): Promise<{ enc: Bytes; shared: Bytes }> {
  let ephemeral: CryptoKeyPair
  try {
    ephemeral = await generateX25519(true)
  } catch (err) {
    // Not a verdict on the public key: the engine made no key to agree with.
    throw new HPKEError('the engine refuses to generate an X25519 key', 'invalid_key', { cause: err })
  }
  try {
    const enc = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey)) as Bytes
    const shared = await dh(ephemeral.privateKey, publicRaw)
    const context = concat(enc, publicRaw)
    const prk = await labeledExtract(KEM_SUITE, new Uint8Array(0), 'eae_prk', shared)
    return { enc, shared: await labeledExpand(KEM_SUITE, prk, 'shared_secret', context, N_SECRET) }
  } catch (err) {
    // Whatever else the engine throws is the kit's own error, as dh's is.
    if (err instanceof HPKEError) throw err
    throw new HPKEError('no shared secret with this public key', 'invalid_key', { cause: err })
  }
}

async function decap(priv: PrivateKey, enc: Bytes): Promise<Bytes> {
  const shared = await dh(priv.key, enc)
  const context = concat(enc, priv.publicRaw)
  const prk = await labeledExtract(KEM_SUITE, new Uint8Array(0), 'eae_prk', shared)
  return labeledExpand(KEM_SUITE, prk, 'shared_secret', context, N_SECRET)
}

interface Context {
  key: CryptoKey
  baseNonce: Bytes
}

async function keySchedule(shared: Bytes, info: Bytes, use: KeyUsage): Promise<Context> {
  const empty = new Uint8Array(0)
  const mode = new Uint8Array([0x00]) // base: no PSK, no sender authentication
  const pskIDHash = await labeledExtract(HPKE_SUITE, empty, 'psk_id_hash', empty)
  const infoHash = await labeledExtract(HPKE_SUITE, empty, 'info_hash', info)
  const context = concat(mode, pskIDHash, infoHash)
  const secret = await labeledExtract(HPKE_SUITE, shared, 'secret', empty)
  const keyBytes = await labeledExpand(HPKE_SUITE, secret, 'key', context, N_K)
  const baseNonce = await labeledExpand(HPKE_SUITE, secret, 'base_nonce', context, N_N)
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, [use])
  return { key, baseNonce }
}

/**
 * seal produces a single-shot HPKE ciphertext to publicRaw. A public key no
 * secret can be agreed with (one of low order) is HPKEError invalid_key.
 */
export async function seal(publicRaw: Bytes, info: Bytes, aad: Bytes, plaintext: Bytes): Promise<{ enc: Bytes; ciphertext: Bytes }> {
  const { enc, shared } = await encap(publicRaw)
  const ctx = await keySchedule(shared, info, 'encrypt')
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ctx.baseNonce, additionalData: aad, tagLength: 128 }, ctx.key, plaintext),
  ) as Bytes
  return { enc, ciphertext }
}

/**
 * open reverses a single-shot seal. Every failure, an encapsulated key of low
 * order included, is HPKEError open_failed.
 */
export async function open(priv: PrivateKey, enc: Bytes, info: Bytes, aad: Bytes, ciphertext: Bytes): Promise<Bytes> {
  if (enc.length !== ENC_LEN) throw new HPKEError('the encapsulated key must contain 32 bytes', 'open_failed')
  try {
    const shared = await decap(priv, enc)
    const ctx = await keySchedule(shared, info, 'decrypt')
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ctx.baseNonce, additionalData: aad, tagLength: 128 }, ctx.key, ciphertext)
    return new Uint8Array(plaintext)
  } catch {
    throw new HPKEError('open failed', 'open_failed')
  }
}
