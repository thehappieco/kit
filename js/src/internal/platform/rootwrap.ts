// The root-wrap envelope (SPEC section 11.5): the account root sealed under
// one key, 62 bytes.
//
//   offset  size  field
//   0       1     0x01, the format version
//   1       1     kind: 0x01 password, 0x02 recovery, 0x03 passkey
//   2       12    nonce, random
//   14      48    AES-256-GCM(key, nonce, root, AAD): 32 bytes and the tag
//
// This is the wrap envelope of section 6.5 with a two-byte header: sealing
// and opening are account.wrapPrivateKey and account.unwrapPrivateKey with
// platformRootWrap(kind). The AAD is the JCS text of
// ["thehappie-id/root-wrap", 1, kind, sub, epoch] (a passkey wrap appends
// rp_id and the credential id). The rule it enforces: a wrap opens only for
// the account, the epoch and the kind it was made for. Every new wrap is
// opened again and compared with the root before it is returned (the
// self-test), because a wrap that was sealed wrong stores fine and loses the
// account the first time it is needed. From the platform's
// web/shared/crypto/rootwrap.ts.

import { unwrapPrivateKey, wrapPrivateKey } from '../accountcore.js'
import { encodeUTF8, equal, isBase64URL, type Bytes } from '../../bytes.js'
import { PlatformError } from '../../errors.js'
import { canonicalJSON } from '../../jcs.js'
import { isWrapKind, platformRootWrap, ROOT_LEN, WRAP_AAD_LABEL, WRAP_KIND_BYTE, WRAP_LEN, WRAP_VERSION, type WrapKind } from './profile.js'

/** PasskeyBinding is what a passkey wrap adds to its AAD. */
export interface PasskeyBinding {
  rpId: string
  /** The credential id, as base64url. */
  credentialId: string
}

const SUB_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

// Every string in a restricted JSON AAD is drawn from this set, which is
// what makes JCS, JSON.stringify and Go's encoding/json agree byte for byte.
const AAD_STRING = /^[A-Za-z0-9._:/|@-]*$/

/** isSub says whether s is an account id as the protocol writes it: lowercase, hyphenated. */
export function isSub(s: unknown): s is string {
  return typeof s === 'string' && SUB_PATTERN.test(s)
}

/** isEpoch says whether n can be an account key epoch: an integer from 1 to 2^31 - 1. */
export function isEpoch(n: unknown): n is number {
  return typeof n === 'number' && Number.isSafeInteger(n) && n >= 1 && n <= 0x7fffffff
}

/**
 * rootWrapAAD is the AAD text of a wrap of this kind, for this account and
 * epoch. A binding outside its one spelling (an upper-case sub, an epoch out
 * of range, a passkey binding on another kind or none on a passkey wrap, a
 * credential id that is not strict base64url, a string outside the AAD
 * alphabet or empty) is refused with wrap, never escaped.
 */
export function rootWrapAAD(kind: WrapKind, sub: string, epoch: number, passkey?: PasskeyBinding): string {
  if (!isWrapKind(kind)) throw new PlatformError('unknown wrap kind', 'wrap')
  if (!isSub(sub)) throw new PlatformError('the account id is not a lowercase UUID', 'wrap')
  if (!isEpoch(epoch)) throw new PlatformError('the epoch is not a positive integer', 'wrap')
  const items: (string | number)[] = [WRAP_AAD_LABEL, WRAP_VERSION, kind, sub, epoch]
  if (kind === 'passkey') {
    if (typeof passkey !== 'object' || passkey === null || typeof passkey.rpId !== 'string' || typeof passkey.credentialId !== 'string') {
      throw new PlatformError('a passkey wrap needs its binding, two strings', 'wrap')
    }
    if (!isBase64URL(passkey.credentialId)) throw new PlatformError('the credential id is not strict base64url', 'wrap')
    items.push(passkey.rpId, passkey.credentialId)
  } else if (passkey !== undefined) {
    throw new PlatformError('only a passkey wrap has a passkey binding', 'wrap')
  }
  for (const item of items) {
    if (typeof item === 'string' && (item === '' || !AAD_STRING.test(item))) {
      throw new PlatformError('an AAD string is outside the allowed set', 'wrap')
    }
  }
  return canonicalJSON(items)
}

/**
 * wrapKey takes a derived CryptoKey as it is, or imports a raw 32-byte key
 * (a vector's, or a passkey's) as a non-extractable AES-GCM key. A CryptoKey
 * must be AES-GCM with 256 bits, as section 11.5 requires and as Go's wraps
 * are: WebCrypto would seal with a 128- or 192-bit key just as well, and the
 * wrap would open here and never in Go.
 */
async function wrapKey(key: CryptoKey | Uint8Array): Promise<CryptoKey> {
  if (key instanceof Uint8Array) {
    if (key.length !== 32) throw new PlatformError('a wrap key is 32 bytes', 'wrap')
    try {
      return await crypto.subtle.importKey('raw', new Uint8Array(key) as Bytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
    } catch {
      throw new PlatformError('the wrap key does not import', 'wrap')
    }
  }
  if (!(key instanceof CryptoKey) || key.algorithm.name !== 'AES-GCM' || (key.algorithm as AesKeyAlgorithm).length !== 256) {
    throw new PlatformError('a wrap key is a 256-bit AES-GCM key or 32 bytes', 'wrap')
  }
  return key
}

/**
 * openRootWrap returns the root inside a wrap, for the caller to zero. It
 * refuses, with the code wrap, a binding outside its spelling, a wrap of the
 * wrong length, version or kind, and one that does not open for this key,
 * account and epoch; the cases are not told apart. The key is the derived
 * CryptoKey or 32 raw bytes.
 */
export async function openRootWrap(
  kind: WrapKind,
  key: CryptoKey | Uint8Array,
  wrap: Uint8Array,
  sub: string,
  epoch: number,
  passkey?: PasskeyBinding,
): Promise<Bytes> {
  const aad = encodeUTF8(rootWrapAAD(kind, sub, epoch, passkey))
  if (!(wrap instanceof Uint8Array) || wrap.length !== WRAP_LEN) {
    throw new PlatformError('a root wrap is 62 bytes', 'wrap')
  }
  if (wrap[0] !== WRAP_VERSION || wrap[1] !== WRAP_KIND_BYTE[kind]) {
    throw new PlatformError('the wrap header does not match', 'wrap')
  }
  const k = await wrapKey(key)
  let opened: { privateKey: Bytes; stale: boolean }
  try {
    opened = await unwrapPrivateKey(platformRootWrap(kind), new Uint8Array(wrap) as Bytes, k, aad)
  } catch {
    throw new PlatformError('the wrap does not open', 'wrap')
  }
  if (opened.stale || opened.privateKey.length !== ROOT_LEN) {
    opened.privateKey.fill(0)
    throw new PlatformError('the wrap does not hold a root', 'wrap')
  }
  return opened.privateKey
}

/**
 * sealRootWrap seals the 32-byte root under key with a fresh nonce (one
 * 12-byte draw from crypto.getRandomValues), then runs the self-test: the
 * wrap is opened again with the same key and compared with the root, and
 * only a wrap that passes is returned. Every failure is wrap.
 */
export async function sealRootWrap(
  kind: WrapKind,
  key: CryptoKey | Uint8Array,
  root: Uint8Array,
  sub: string,
  epoch: number,
  passkey?: PasskeyBinding,
): Promise<Bytes> {
  const aad = encodeUTF8(rootWrapAAD(kind, sub, epoch, passkey))
  if (!(root instanceof Uint8Array) || root.length !== ROOT_LEN) {
    throw new PlatformError('a root is 32 bytes', 'wrap')
  }
  const k = await wrapKey(key)
  const plain = new Uint8Array(root) as Bytes
  let wrap: Bytes
  try {
    wrap = await wrapPrivateKey(platformRootWrap(kind), plain, k, aad)
  } catch {
    throw new PlatformError('the root could not be sealed', 'wrap')
  } finally {
    plain.fill(0)
  }
  // The self-test: open it again, with the key just used, and compare. Any
  // failure, including one that throws, means this wrap is never returned.
  let back: Bytes | undefined
  try {
    back = await openRootWrap(kind, k, wrap, sub, epoch, passkey)
    if (!equal(back, root as Bytes)) throw new Error('self-test')
  } catch {
    throw new PlatformError('the new wrap failed its self-test', 'wrap')
  } finally {
    back?.fill(0)
  }
  return wrap
}
