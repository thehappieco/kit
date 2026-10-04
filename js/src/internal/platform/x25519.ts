// X25519 over WebCrypto, for key delivery (SPEC sections 11.12 and 11.14):
// the public-key check of section 11.4, non-extractable imports, and the
// ephemeral pair a relying party generates for one authorization request.
//
// The rule it enforces: a private key passes through page memory only in
// buffers this module zeroes, and a public key is accepted only in the one
// spelling the server accepts. WebCrypto imports an X25519 private key only
// as PKCS#8 and exports it only as PKCS#8 or JWK, so every import and export
// goes through a PKCS#8 buffer; each is zeroed as soon as WebCrypto is done
// with it. Imports and generation go through ../x25519engine.ts, so that
// WebKit on Linux takes any 32 bytes as a private key, as the other engines
// do, and a key it fails to generate is asked for again.
//
// An engine refusal surfaces as the hpke module's HPKEError invalid_key, its
// cause what the engine threw, so a caller can tell an engine without X25519
// (a NotSupportedError) from one that refused this key, as v0.2.0's product
// keys do (SPEC section 11.10). An engine that cannot generate a key is not
// a verdict on any input either, and surfaces the same way.
//
// From the platform's web/shared/crypto/x25519.ts at 4476bf4.

import { equal, type Bytes } from '../../bytes.js'
import { HPKEError, PlatformError, type PlatformErrorCode } from '../../errors.js'
import { generateX25519, importX25519 } from '../x25519engine.js'
import { isAllZero, zero } from '../zero.js'

/** X25519_KEY_LEN is the length of every X25519 private and public key. */
export const X25519_KEY_LEN = 32

// The length of the PKCS#8 form of an id-X25519 private key (RFC 8410): a
// 16-byte DER prefix, then the 32 raw bytes.
const PKCS8_LEN = 16 + X25519_KEY_LEN

// The X25519 base point, u = 9.
const BASE_POINT = new Uint8Array(32)
BASE_POINT[0] = 9

/**
 * lacksX25519 says whether err is an engine's refusal because it has no
 * X25519 at all (a DOMException named NotSupportedError, matched by name so
 * that one from another realm counts too), directly or as the cause of an
 * HPKEError. That says nothing about any key.
 */
export function lacksX25519(err: unknown): boolean {
  const named = (e: unknown) => typeof e === 'object' && e !== null && (e as { name?: unknown }).name === 'NotSupportedError'
  return named(err) || (err instanceof HPKEError && named(err.cause))
}

function engineRefused(what: string, err: unknown): HPKEError {
  if (err instanceof HPKEError) return err
  return new HPKEError(`the engine refuses ${what}`, 'invalid_key', { cause: err })
}

/**
 * engineError is what key delivery throws for an engine refusal that is not
 * a verdict on its input (lacksX25519): the hpke module's HPKEError
 * invalid_key with the engine's error as its cause, or err itself when it
 * is one already.
 */
export function engineError(err: unknown): HPKEError {
  return engineRefused('X25519', err)
}

/**
 * importX25519PrivateKey imports 32 raw bytes as a non-extractable X25519
 * key for deriveBits. The PKCS#8 buffer that carries them is zeroed once
 * importKey has finished with it, whatever happened; the raw bytes are the
 * caller's to zero. Any 32 bytes import, on every engine (../x25519engine.ts).
 * Bytes that are not 32 long are a TypeError; an engine refusal is
 * HPKEError invalid_key with the engine's error as its cause.
 */
export async function importX25519PrivateKey(raw: Uint8Array): Promise<CryptoKey> {
  if (!(raw instanceof Uint8Array) || raw.length !== X25519_KEY_LEN) {
    throw new TypeError('an X25519 private key is 32 bytes')
  }
  try {
    return await importX25519(raw)
  } catch (err) {
    throw engineRefused('this X25519 private key', err)
  }
}

/**
 * generateX25519Key generates an X25519 pair for deriveBits, asking again
 * where WebKit on Linux fails to (../x25519engine.ts). A refusal is never a
 * verdict on any input: it is HPKEError invalid_key with the engine's last
 * error as its cause, a NotSupportedError where the engine has no X25519.
 */
export async function generateX25519Key(extractable: boolean): Promise<CryptoKeyPair> {
  try {
    return await generateX25519(extractable)
  } catch (err) {
    throw engineRefused('to generate an X25519 key', err)
  }
}

/** x25519PublicFromKey is X25519(priv, 9): the public half of an imported key. */
export async function x25519PublicFromKey(priv: CryptoKey): Promise<Bytes> {
  try {
    const base = await crypto.subtle.importKey('raw', BASE_POINT, { name: 'X25519' }, true, [])
    return new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: base }, priv, 256))
  } catch (err) {
    throw engineRefused('an X25519 exchange with the base point', err)
  }
}

/**
 * isCanonicalX25519 says whether u, little-endian, is 32 bytes with bit 255
 * clear and below p = 2^255 - 19, whose encoding is ed ff ... ff 7f. X25519
 * accepts the other spellings as aliases of a canonical one; a key compared
 * byte for byte must have only one.
 */
export function isCanonicalX25519(u: Uint8Array): boolean {
  if (!(u instanceof Uint8Array) || u.length !== X25519_KEY_LEN) return false
  const top = u[31]
  if ((top & 0x80) !== 0) return false
  if (top !== 0x7f) return true
  for (let i = 30; i >= 1; i--) if (u[i] !== 0xff) return true
  return u[0] < 0xed
}

/**
 * checkX25519PublicKey is the check of SPEC section 11.4, the one the
 * server runs (Go's profiles/platform CheckPublicKey): 32 bytes; the
 * canonical encoding; it imports as an X25519 public key; and an exchange
 * with a fresh random private key does not give the all-zero output, which
 * refuses the low-order points. WebCrypto itself throws on an all-zero
 * result, and the zero test below, which has no early exit, catches an
 * engine that does not. A refusal throws PlatformError(code). The fresh key
 * says nothing about pub: an engine without X25519, or one that cannot
 * generate that key, throws HPKEError invalid_key with the engine's error
 * as the cause, never PlatformError(code).
 */
export async function checkX25519PublicKey(pub: Uint8Array, code: PlatformErrorCode): Promise<void> {
  if (!(pub instanceof Uint8Array) || pub.length !== X25519_KEY_LEN) {
    throw new PlatformError('an X25519 public key is 32 bytes', code)
  }
  if (!isCanonicalX25519(pub)) throw new PlatformError('not a canonical X25519 encoding', code)
  let peer: CryptoKey
  try {
    peer = await crypto.subtle.importKey('raw', new Uint8Array(pub), { name: 'X25519' }, true, [])
  } catch (err) {
    if (lacksX25519(err)) throw engineError(err)
    // Firefox refuses the low-order points here already.
    throw new PlatformError('not an X25519 public key, or a low-order point', code)
  }
  const probe = await generateX25519Key(false)
  let shared: Bytes | undefined
  try {
    shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: peer }, probe.privateKey, 256))
  } catch (err) {
    if (lacksX25519(err)) throw engineError(err)
    throw new PlatformError('a low-order point', code)
  }
  try {
    if (isAllZero(shared)) throw new PlatformError('a low-order point', code)
  } finally {
    zero(shared)
  }
}

/** X25519KeyPair is a fresh pair with the private half raw, for the caller to zero. */
export interface X25519KeyPair {
  privateKey: Bytes
  publicKey: Bytes
}

// The PKCS#8 (RFC 5958) fields that follow the outer SEQUENCE header: the
// version, the id-X25519 algorithm (RFC 8410) and the OCTET STRING that
// wraps the 32-byte CurvePrivateKey. The version byte is left out: it is 0,
// or 1 when an engine appends the public key after the private one.
const PKCS8_ALGORITHM_AND_KEY = new Uint8Array([0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20])

/**
 * rawFromPKCS8 copies the 32 private bytes out of WebCrypto's PKCS#8
 * export, or returns null for a form it does not know. Chromium, Firefox
 * and WebKit write the 48-byte form that importX25519PrivateKey builds; a
 * version-1 export that also carries the public key (RFC 5958
 * OneAsymmetricKey) is read too, and whatever follows the private key is
 * ignored, because generateX25519KeyPair checks the result against the
 * public key anyway.
 */
export function rawFromPKCS8(der: Uint8Array): Bytes | null {
  // SEQUENCE with a short-form length that covers the whole export.
  if (der.length < PKCS8_LEN || der[0] !== 0x30 || der[1] >= 0x80 || der[1] + 2 !== der.length) return null
  // INTEGER version, 0 or 1.
  if (der[2] !== 0x02 || der[3] !== 0x01 || (der[4] !== 0x00 && der[4] !== 0x01)) return null
  const at = 5
  if (!PKCS8_ALGORITHM_AND_KEY.every((b, i) => der[at + i] === b)) return null
  return der.slice(at + PKCS8_ALGORITHM_AND_KEY.length, at + PKCS8_ALGORITHM_AND_KEY.length + X25519_KEY_LEN) as Bytes
}

/**
 * generateX25519KeyPair mints a pair and hands out the private half as 32
 * raw bytes, which the relying party seals at once (SPEC section 11.14,
 * begin step 2). The key is generated extractable because WebCrypto has no
 * other way to export it but JWK, which would put it in a string nothing
 * can zero; the PKCS#8 export is zeroed once the raw bytes are copied out.
 * The raw bytes are checked against the public half before they are handed
 * out, so a browser that exports in a form this code misreads fails here,
 * in begin, and never after the person has unlocked their account for a
 * key that cannot open.
 */
export async function generateX25519KeyPair(): Promise<X25519KeyPair> {
  const pair = await generateX25519Key(true)
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey))
  let privateKey: Bytes | null = null
  try {
    privateKey = rawFromPKCS8(pkcs8)
    if (privateKey === null) throw new Error('WebCrypto exported an X25519 key in an unexpected form')
    const derived = await x25519PublicFromKey(await importX25519PrivateKey(privateKey))
    if (publicKey.length !== X25519_KEY_LEN || !equal(derived, publicKey)) {
      throw new Error('the exported X25519 private key does not match its public key')
    }
    const out = { privateKey, publicKey }
    privateKey = null
    return out
  } finally {
    zero(pkcs8)
    if (privateKey !== null) zero(privateKey)
  }
}
