// HPKE (RFC 9180) base mode, single shot, for key delivery (SPEC section
// 11.12): the suite of section 3.2, DHKEM(X25519, HKDF-SHA256) 0x0020,
// HKDF-SHA256 0x0001, AES-256-GCM 0x0002, and nothing else, so there is
// nothing to negotiate.
//
// The rule it enforces: every secret of the key schedule is wiped as soon
// as the next step has consumed it. The X25519 exchange output, every
// buffer that carries it into HMAC, the PRKs, each HKDF-Expand block, the
// AEAD key bytes, the base nonce and the context are zeroed before seal or
// open returns, whatever happened. The hpke module (../../hpke.ts), which
// the envelope uses and which stays byte-identical, leaves its schedule as
// garbage it never wipes. WebCrypto keeps its own copies of what it
// imports; those are beyond reach (SPEC section 13).
//
// It is a second implementation of the same key schedule, which is how two
// copies drift; three checks keep this one honest. The golden vectors
// (key-delivery.json) open with it, and seal with it to Go's bytes exactly
// under Go's ephemeral key; the tests seal with it and open with the hpke
// module, and the reverse; and a watcher shows that it leaves no secret in
// a page buffer.
//
// The sender's ephemeral key is generated non-extractable: only its public
// half leaves WebCrypto, as enc. No caller can choose it. Internal: only key
// delivery uses this file, and it is not a subpath export.
//
// From the platform's web/shared/crypto/hpkebase.ts at 4476bf4; the
// all-zero check folds the bytes without an early exit, as the hpke module's
// does.

import { concat, encodeUTF8, i2osp2, type Bytes } from '../../bytes.js'
import { isAllZero, zero } from '../zero.js'

const KEM_ID = 0x0020 // DHKEM(X25519, HKDF-SHA256)
const KDF_ID = 0x0001 // HKDF-SHA256
const AEAD_ID = 0x0002 // AES-256-GCM

const N_SECRET = 32 // the KEM shared secret
const N_K = 32 // an AES-256 key
const N_N = 12 // an AES-GCM nonce
const N_H = 32 // SHA-256

/** ENC_LEN is the length of enc, an X25519 public key. */
export const ENC_LEN = 32

/** TAG_LEN is the length of the AES-GCM tag that ends every ciphertext. */
export const TAG_LEN = 16

const HPKE_V1 = encodeUTF8('HPKE-v1')
const KEM_SUITE = concat(encodeUTF8('KEM'), i2osp2(KEM_ID))
const HPKE_SUITE = concat(encodeUTF8('HPKE'), i2osp2(KEM_ID), i2osp2(KDF_ID), i2osp2(AEAD_ID))
const EMPTY = new Uint8Array(0)
const MODE_BASE = 0x00

// ---------------------------------------------------------------------------
// HKDF over HMAC. WebCrypto's HKDF fuses Extract and Expand, and HPKE needs
// one Extract feeding several Expands, so both are built on HMAC.
// ---------------------------------------------------------------------------

/**
 * hmac is HMAC-SHA256. An empty key is given to WebCrypto as N_H zero bytes,
 * which is the same HMAC key (both are zero-padded to the block size) and
 * what RFC 5869 says an empty salt means.
 */
async function hmac(key: Bytes, data: Bytes): Promise<Bytes> {
  const raw = key.length === 0 ? new Uint8Array(N_H) : key
  const k = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, data))
}

/** labeledExtract is RFC 9180's LabeledExtract; the buffer that carries ikm is zeroed. */
async function labeledExtract(suite: Bytes, salt: Bytes, label: string, ikm: Bytes): Promise<Bytes> {
  const labeled = concat(HPKE_V1, suite, encodeUTF8(label), ikm)
  try {
    return await hmac(salt, labeled)
  } finally {
    zero(labeled)
  }
}

/**
 * labeledExpand is RFC 9180's LabeledExpand. Every T(i) block, and every
 * buffer that carries one into the next HMAC, is zeroed; only the output
 * is left, for the caller to zero.
 */
async function labeledExpand(suite: Bytes, prk: Bytes, label: string, info: Bytes, length: number): Promise<Bytes> {
  const labeledInfo = concat(i2osp2(length), HPKE_V1, suite, encodeUTF8(label), info)
  const out = new Uint8Array(length)
  let previous: Bytes = EMPTY
  try {
    for (let counter = 1, at = 0; at < length; counter++) {
      const input = concat(previous, labeledInfo, new Uint8Array([counter]))
      zero(previous)
      try {
        previous = await hmac(prk, input)
      } finally {
        zero(input)
      }
      const take = Math.min(previous.length, length - at)
      out.set(previous.subarray(0, take), at)
      at += take
    }
    return out
  } catch (err) {
    zero(out)
    throw err
  } finally {
    zero(previous)
  }
}

// ---------------------------------------------------------------------------
// DHKEM(X25519, HKDF-SHA256)
// ---------------------------------------------------------------------------

/**
 * extractAndExpand is DHKEM's ExtractAndExpand. It zeroes dh, the eae_prk
 * and everything between; the shared secret is the caller's.
 */
async function extractAndExpand(dh: Bytes, kemContext: Bytes): Promise<Bytes> {
  let eaePrk: Bytes | undefined
  try {
    eaePrk = await labeledExtract(KEM_SUITE, EMPTY, 'eae_prk', dh)
    return await labeledExpand(KEM_SUITE, eaePrk, 'shared_secret', kemContext, N_SECRET)
  } finally {
    zero(dh, eaePrk)
  }
}

/**
 * x25519 runs the exchange and refuses the all-zero output (RFC 9180
 * section 7.1.4), which a low-order peer key gives. WebCrypto throws on it
 * already; the check, without an early exit, is for an engine that does
 * not.
 */
async function x25519(priv: CryptoKey, publicRaw: Bytes): Promise<Bytes> {
  const pub = await crypto.subtle.importKey('raw', publicRaw, { name: 'X25519' }, true, [])
  const dh = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: pub }, priv, 256))
  if (dh.length !== N_SECRET || isAllZero(dh)) {
    zero(dh)
    throw new Error('hpke: the X25519 exchange gave the all-zero value')
  }
  return dh
}

// ---------------------------------------------------------------------------
// The key schedule (base mode: no PSK, no sender authentication).
// ---------------------------------------------------------------------------

/**
 * withContext derives the AEAD key and the base nonce from the shared
 * secret and runs fn with them. The shared secret, the schedule's secret,
 * the key bytes, the nonce and the context are zeroed when fn has
 * finished.
 */
async function withContext<T>(shared: Bytes, info: Bytes, use: 'encrypt' | 'decrypt', fn: (key: CryptoKey, nonce: Bytes) => Promise<T>): Promise<T> {
  let secret: Bytes | undefined
  let keyBytes: Bytes | undefined
  let nonce: Bytes | undefined
  let context: Bytes | undefined
  try {
    const pskIdHash = await labeledExtract(HPKE_SUITE, EMPTY, 'psk_id_hash', EMPTY)
    const infoHash = await labeledExtract(HPKE_SUITE, EMPTY, 'info_hash', info)
    context = concat(new Uint8Array([MODE_BASE]), pskIdHash, infoHash)
    zero(pskIdHash, infoHash)
    // psk = "" in base mode: the shared secret is the salt.
    secret = await labeledExtract(HPKE_SUITE, shared, 'secret', EMPTY)
    zero(shared)
    keyBytes = await labeledExpand(HPKE_SUITE, secret, 'key', context, N_K)
    nonce = await labeledExpand(HPKE_SUITE, secret, 'base_nonce', context, N_N)
    zero(secret)
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, [use])
    zero(keyBytes)
    return await fn(key, nonce)
  } finally {
    zero(shared, secret, keyBytes, nonce, context)
  }
}

/**
 * sealBase is SealBase(pkR, info, aad, pt) single shot: enc || ct, where ct
 * ends with the 16-byte tag. A fresh ephemeral key per seal is what makes
 * the sequence number zero safe: no two seals share a context. It throws
 * what the engine throws, or an Error for the all-zero exchange; callers
 * classify.
 */
export async function sealBase(recipientPublic: Bytes, info: Bytes, aad: Bytes, plaintext: Bytes): Promise<Bytes> {
  if (recipientPublic.length !== ENC_LEN) throw new Error('hpke: an X25519 public key is 32 bytes')
  const eph = (await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits'])) as CryptoKeyPair
  const enc = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey))
  if (enc.length !== ENC_LEN) throw new Error('hpke: WebCrypto exported an X25519 public key of another length')
  const shared = await extractAndExpand(await x25519(eph.privateKey, recipientPublic), concat(enc, recipientPublic))
  const ct = await withContext(shared, info, 'encrypt', async (key, nonce) =>
    new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, key, plaintext)),
  )
  return concat(enc, ct)
}

/**
 * openBase is OpenBase single shot for the recipient key priv, whose public
 * half is recipientPublic (DHKEM puts it in the KEM context). It returns
 * the plaintext, which is the caller's to zero, and throws on any failure.
 */
export async function openBase(priv: CryptoKey, recipientPublic: Bytes, sealed: Bytes, info: Bytes, aad: Bytes): Promise<Bytes> {
  if (recipientPublic.length !== ENC_LEN) throw new Error('hpke: an X25519 public key is 32 bytes')
  if (sealed.length < ENC_LEN + TAG_LEN) throw new Error('hpke: shorter than enc and a tag')
  const enc = sealed.slice(0, ENC_LEN)
  const ct = sealed.slice(ENC_LEN)
  const shared = await extractAndExpand(await x25519(priv, enc), concat(enc, recipientPublic))
  return withContext(shared, info, 'decrypt', async (key, nonce) =>
    new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, key, ct)),
  )
}
