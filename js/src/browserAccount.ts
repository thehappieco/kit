// A key at rest in the browser: the raw key encrypted under a non-extractable
// AES-256-GCM key, so storage (IndexedDB) never holds an exportable secret.
// WebKit loses IndexedDB records that contain an X25519 CryptoKey, so the
// X25519 key itself is not what is stored.
//
// Used only while the raw key is already in hand (a sign-in, or a product key
// just delivered). Never exports an existing CryptoKey, never persists
// plaintext, and is never sent to a server. From Wappie's
// packages/client/src/crypto/browserAccount.ts; the AAD tag and version are
// the profile's.

import { encodeUTF8, toBase64, type Bytes } from './bytes.js'
import { importPrivateKey, type PrivateKey } from './hpke.js'
import { canonicalJSON } from './jcs.js'

export interface BrowserAccountProfile {
  /** The first element of the JSON AAD. */
  readonly tag: string
  /** The second element of the JSON AAD. */
  readonly version: number
}

export interface BrowserKeyEnvelope {
  version: 1
  key: CryptoKey
  nonce: Bytes
  ciphertext: ArrayBuffer
  publicRaw: Bytes
}

/**
 * browserAccountAAD is the JCS text of the JSON array [tag, version, userID,
 * base64(publicRaw)]. A user id with a lone surrogate throws
 * CanonicalJSONError.
 */
export function browserAccountAAD(p: BrowserAccountProfile, userID: string, publicRaw: Bytes): Bytes {
  return encodeUTF8(canonicalJSON([p.tag, p.version, userID, toBase64(publicRaw)]))
}

export function validBrowserKeyEnvelope(value: unknown): value is BrowserKeyEnvelope {
  const envelope = value as BrowserKeyEnvelope | undefined
  const key = envelope?.key
  return envelope?.version === 1 && typeof CryptoKey !== 'undefined' && key instanceof CryptoKey
    && key.type === 'secret' && !key.extractable && key.algorithm.name === 'AES-GCM'
    && (key.algorithm as AesKeyAlgorithm).length === 256 && key.usages.includes('encrypt') && key.usages.includes('decrypt')
    && envelope.nonce instanceof Uint8Array && envelope.nonce.length === 12
    && envelope.ciphertext instanceof ArrayBuffer && envelope.ciphertext.byteLength === 48
    && envelope.publicRaw instanceof Uint8Array && envelope.publicRaw.length === 32
}

/** sealBrowserAccountKey encrypts a raw 32-byte X25519 key for local storage. */
export async function sealBrowserAccountKey(p: BrowserAccountProfile, raw: Bytes, publicRaw: Bytes, userID: string): Promise<BrowserKeyEnvelope> {
  if (raw.length !== 32 || publicRaw.length !== 32) throw new Error('invalid account key')
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: browserAccountAAD(p, userID, publicRaw) }, key, raw)
  return { version: 1, key, nonce, ciphertext, publicRaw: publicRaw.slice() }
}

/**
 * openBrowserAccountKey decrypts and imports the key, non-extractable, and
 * checks its public half against the one recorded beside it.
 */
export async function openBrowserAccountKey(p: BrowserAccountProfile, envelope: BrowserKeyEnvelope, userID: string): Promise<PrivateKey> {
  if (!validBrowserKeyEnvelope(envelope)) throw new Error('invalid browser account key')
  const raw = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: envelope.nonce,
    additionalData: browserAccountAAD(p, userID, envelope.publicRaw) }, envelope.key, envelope.ciphertext))
  try {
    const account = await importPrivateKey(raw)
    if (!account.publicRaw.every((byte, index) => byte === envelope.publicRaw[index])) throw new Error('invalid browser account key')
    return account
  } finally {
    raw.fill(0)
  }
}

/** bind fixes a profile, for a product's own wrappers. */
export function bind(p: BrowserAccountProfile) {
  return {
    profile: p,
    browserAccountAAD: (userID: string, publicRaw: Bytes) => browserAccountAAD(p, userID, publicRaw),
    sealBrowserAccountKey: (raw: Bytes, publicRaw: Bytes, userID: string) => sealBrowserAccountKey(p, raw, publicRaw, userID),
    openBrowserAccountKey: (envelope: BrowserKeyEnvelope, userID: string) => openBrowserAccountKey(p, envelope, userID),
    validBrowserKeyEnvelope,
  }
}
