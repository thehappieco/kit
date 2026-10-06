// The key bundle (SPEC section 11.9): the file a person downloads so that a
// command-line tool can open their data with the password, or with the
// recovery code, without the platform.
//
// The rule it enforces: a bundle is read only in its one exact shape, and a
// root opened from it is used only after every listed product key has been
// derived from that root and found equal. A bundle is a file that may have
// been edited, so nothing in it is trusted because it parses: the KDF
// parameters are checked against the bounds before deriving, as at login,
// and a public key that the root does not produce means the bundle is not
// this account's.
//
// The checks run in the order Go runs them (profiles/platform ParseKeyBundle
// and OpenKeyBundle), so a bundle with several defects is refused for the
// same one on both sides: first every member's JSON type (bundle), then the
// fields in the order of section 11.9, with KDF parameters outside the
// bounds as kdf_policy; then the password or code; then the wrap (wrap);
// then the product keys (product_key).
//
// Given the text, the reader refuses what Go refuses before any field is
// looked at (../strictjson.ts): a repeated member, a number with a fraction
// or an exponent, an integer past 64 bits. Given a value someone already
// parsed, those are gone (JSON.parse kept the last of a repeated member and
// read 1.0 as 1), so callers that hold the text should pass the text.
//
// Honest limit: a bundle downloaded before a password change still opens
// with the old password, and before a recovery code change with the old
// code. The root does not change, so this is inherent. From the platform's
// web/shared/crypto/keybundle.ts.

import type { DeriveOptions } from '../accountcore.js'
import type { WorkerFactory } from '../kdf.js'
import { Base64Error, equal, fromBase64URL, type Bytes } from '../../bytes.js'
import { PlatformError, type PlatformErrorCode } from '../../errors.js'
import { parseStrictJSON, StrictJSONError, utf8Length } from '../strictjson.js'
import { normalizeEmail } from './email.js'
import { derivePasswordWith } from './kdf.js'
import { checkKDF, type KDF, SALT_LEN } from './kdfpolicy.js'
import { preparePassword } from './password.js'
import { isProduct, productPublicKey } from './productkey.js'
import { WRAP_KIND_BYTE, WRAP_LEN, WRAP_VERSION } from './profile.js'
import { deriveRecovery } from './recovery.js'
import { isEpoch, isSub, openRootWrap } from './rootwrap.js'

export const KEY_BUNDLE_FORMAT = 'thehappie-id/key-bundle'
export const KEY_BUNDLE_VERSION = 1

/** The largest bundle text read, in UTF-8 bytes, as in Go. A real bundle is about 1 KiB. */
const MAX_BUNDLE_TEXT = 64 * 1024
/** A bundle nests three levels deep (bundle, product_keys, a product key). */
const MAX_BUNDLE_DEPTH = 8
/** The issuer is an origin. */
const MAX_ISSUER_LEN = 256

export interface KeyBundleProductKey {
  product: string
  epoch: number
  /** X25519 public key, base64url. */
  pub: string
}

/** KeyBundle is the JSON document of section 11.9. */
export interface KeyBundle {
  format: typeof KEY_BUNDLE_FORMAT
  version: typeof KEY_BUNDLE_VERSION
  issuer: string
  sub: string
  email: string
  account_key_epoch: number
  kdf: KDF
  kdf_salt: string
  password_wrap: string
  recovery_wrap: string
  product_keys: KeyBundleProductKey[]
  created_at: string
}

/** ParsedKeyBundle is a bundle that passed parseKeyBundle, with its binary fields decoded. */
export interface ParsedKeyBundle {
  json: KeyBundle
  salt: Bytes
  passwordWrap: Bytes
  recoveryWrap: Bytes
  productKeys: { product: string; epoch: number; pub: Bytes }[]
}

const BUNDLE_MEMBERS = [
  'format',
  'version',
  'issuer',
  'sub',
  'email',
  'account_key_epoch',
  'kdf',
  'kdf_salt',
  'password_wrap',
  'recovery_wrap',
  'product_keys',
  'created_at',
]

function bad(why: string): never {
  throw new PlatformError(why, 'bundle')
}

/**
 * field decodes a base64url field of exactly n bytes in its one spelling,
 * turning any refusal into the caller's error code. A field that is not even
 * a string is refused the same way.
 */
function field(value: unknown, n: number, code: PlatformErrorCode, what: string): Bytes {
  if (typeof value !== 'string') throw new PlatformError(`${what}: not a string`, code)
  try {
    return fromBase64URL(value, n)
  } catch (err) {
    if (err instanceof Base64Error) throw new PlatformError(`${what}: ${err.message}`, code)
    throw err
  }
}

// ---------------------------------------------------------------------------
// First pass: the JSON shape. Every member present exactly once, spelled
// exactly, and of its own JSON type; null is never a value.
// ---------------------------------------------------------------------------

function exactObject(v: unknown, members: string[], what: string): Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) bad(`${what} is not an object`)
  const o = v as Record<string, unknown>
  const present = Object.keys(o)
  for (const k of present) if (!members.includes(k)) bad(`${what} has an unknown member`)
  for (const k of members) if (!present.includes(k)) bad(`${what} lacks a member`)
  return o
}

function text(o: Record<string, unknown>, member: string): string {
  const v = o[member]
  if (typeof v !== 'string') bad(`${member} is not a string`)
  return v
}

// A JSON integer that Go reads into an int64; the range rules of each field
// come later. From text, the strict reader already refused 1.0, 1e0 and
// anything past 64 bits; a parsed value has lost that spelling, so this
// refuses what it still can see.
function integer(o: Record<string, unknown>, member: string): number {
  const v = o[member]
  if (typeof v !== 'number' || !Number.isInteger(v) || Math.abs(v) > 2 ** 63) bad(`${member} is not an integer`)
  return v
}

// The protocol's integers fit a signed 32-bit integer.
function smallInteger(o: Record<string, unknown>, member: string): number {
  const v = integer(o, member)
  if (v < -(2 ** 31) || v > 2 ** 31 - 1) bad(`${member} is out of range`)
  return v
}

/**
 * parseKeyBundle checks a bundle's shape and fields and decodes its binary
 * fields, opening nothing. It accepts the parsed JSON value or its text.
 * KDF parameters outside the bounds are refused with kdf_policy, as they are
 * at login; every other defect with bundle.
 */
export function parseKeyBundle(input: unknown): ParsedKeyBundle {
  let value = input
  if (typeof input === 'string') {
    // Every UTF-16 unit is at least one UTF-8 byte, so the first test spares
    // a huge string the walk.
    if (input.length > MAX_BUNDLE_TEXT || utf8Length(input) > MAX_BUNDLE_TEXT) bad('the bundle is too large')
    try {
      value = parseStrictJSON(input, MAX_BUNDLE_DEPTH)
    } catch (err) {
      if (err instanceof StrictJSONError) bad('the bundle is not JSON in its one accepted spelling')
      throw err
    }
  }

  const o = exactObject(value, BUNDLE_MEMBERS, 'the bundle')
  const format = text(o, 'format')
  const issuer = text(o, 'issuer')
  const sub = text(o, 'sub')
  const email = text(o, 'email')
  const kdfSalt = text(o, 'kdf_salt')
  const passwordWrapText = text(o, 'password_wrap')
  const recoveryWrapText = text(o, 'recovery_wrap')
  const createdAt = text(o, 'created_at')
  const version = smallInteger(o, 'version')
  const epoch = smallInteger(o, 'account_key_epoch')

  const k = exactObject(o['kdf'], ['alg', 'm', 't', 'p'], 'kdf')
  const kdfShape = { alg: text(k, 'alg'), m: integer(k, 'm'), t: integer(k, 't'), p: integer(k, 'p') }

  const list = o['product_keys']
  if (!Array.isArray(list)) bad('product_keys is not a list')
  const listed: KeyBundleProductKey[] = list.map(item => {
    const pk = exactObject(item, ['product', 'epoch', 'pub'], 'a product key')
    return { product: text(pk, 'product'), epoch: smallInteger(pk, 'epoch'), pub: text(pk, 'pub') }
  })

  // -------------------------------------------------------------------------
  // Second pass: the fields, in Go's order.
  // -------------------------------------------------------------------------
  if (format !== KEY_BUNDLE_FORMAT || version !== KEY_BUNDLE_VERSION) bad('not a key bundle this page reads')
  if (issuer === '' || issuer.length > MAX_ISSUER_LEN || !/^[\x21-\x7e]+$/.test(issuer)) bad('the issuer is not an origin')
  if (!isSub(sub)) bad('the account id is not a lowercase UUID')
  if (!isNormalizedEmail(email)) bad('the address is not normalized')
  if (!isEpoch(epoch)) bad('the key epoch is not a positive integer')
  const kdf = checkKDF(kdfShape)
  const salt = field(kdfSalt, SALT_LEN, 'bundle', 'kdf_salt')
  const passwordWrap = wrapField(passwordWrapText, 'password')
  const recoveryWrap = wrapField(recoveryWrapText, 'recovery')

  if (listed.length === 0) bad('the bundle lists no product keys')
  const productKeys: ParsedKeyBundle['productKeys'] = []
  for (let i = 0; i < listed.length; i++) {
    const { product, epoch: pkEpoch, pub } = listed[i]!
    if (!isProduct(product) || !isEpoch(pkEpoch)) bad('a product key names no product key')
    const raw = field(pub, 32, 'bundle', 'a product public key')
    // Sorted by product, then epoch, each once. The comparison is on UTF-16
    // units, which for product ids (ASCII) is the byte order Go compares.
    const prev = listed[i - 1]
    if (prev !== undefined && !(prev.product < product || (prev.product === product && prev.epoch < pkEpoch))) {
      bad('product_keys is not sorted, or repeats a key')
    }
    productKeys.push({ product, epoch: pkEpoch, pub: raw })
  }
  if (!isUTCTime(createdAt)) bad('created_at is not an RFC 3339 time in UTC')

  const json: KeyBundle = {
    format: KEY_BUNDLE_FORMAT,
    version: KEY_BUNDLE_VERSION,
    issuer,
    sub,
    email,
    account_key_epoch: epoch,
    kdf,
    kdf_salt: kdfSalt,
    password_wrap: passwordWrapText,
    recovery_wrap: recoveryWrapText,
    product_keys: listed,
    created_at: createdAt,
  }
  return { json, salt, passwordWrap, recoveryWrap, productKeys }
}

function wrapField(v: string, kind: 'password' | 'recovery'): Bytes {
  const wrap = field(v, WRAP_LEN, 'bundle', `${kind}_wrap`)
  if (wrap[0] !== WRAP_VERSION || wrap[1] !== WRAP_KIND_BYTE[kind]) bad(`${kind}_wrap has the wrong header`)
  return wrap
}

function isNormalizedEmail(s: string): boolean {
  try {
    return normalizeEmail(s) === s
  } catch {
    return false
  }
}

// RFC 3339 in UTC, in the one shape Go accepts too (profiles/platform
// utcTime): YYYY-MM-DDTHH:MM:SS, optionally "." and 1 to 9 digits,
// then "Z", naming an instant that exists in the proleptic Gregorian
// calendar. The calendar is checked by hand: Date.UTC reads the years 0 to 99
// as 1900 to 1999.
const UTC_TIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?Z$/

function isUTCTime(s: string): boolean {
  const m = UTC_TIME.exec(s)
  if (m === null) return false
  const [y, mo, d, h, mi, se] = m.slice(1, 7).map(Number) as [number, number, number, number, number, number]
  const leap = y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0)
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]
  return days !== undefined && d >= 1 && d <= days && h <= 23 && mi <= 59 && se <= 59
}

/**
 * checkBundleProductKeys derives every listed product's public key from the
 * root and refuses, with product_key, the first one that differs.
 */
export async function checkBundleProductKeys(root: Uint8Array, bundle: ParsedKeyBundle): Promise<void> {
  for (const { product, epoch, pub } of bundle.productKeys) {
    const derived = await productPublicKey(root, product, epoch)
    if (!equal(derived, pub)) throw new PlatformError('a listed product key does not come from this root', 'product_key')
  }
}

async function openWith(bundle: ParsedKeyBundle, kind: 'password' | 'recovery', key: CryptoKey): Promise<Bytes> {
  const wrap = kind === 'password' ? bundle.passwordWrap : bundle.recoveryWrap
  const root = await openRootWrap(kind, key, wrap, bundle.json.sub, bundle.json.account_key_epoch)
  try {
    await checkBundleProductKeys(root, bundle)
    return root
  } catch (err) {
    root.fill(0)
    throw err
  }
}

/**
 * openKeyBundleWith is openKeyBundle with its default worker factory as the
 * first argument. openKeyBundle opens a bundle with the password (the
 * presented-password profile: no minimum length) and returns the root, for
 * the caller to zero,
 * once every product key has been checked against it. A password that does
 * not open the wrap is refused with wrap; a bundle whose product keys do not
 * come from its root, with product_key.
 */
export async function openKeyBundleWith(defaultWorker: WorkerFactory | undefined, input: unknown, password: string, options?: DeriveOptions): Promise<Bytes> {
  const bundle = parseKeyBundle(input)
  const prepared = preparePassword(password, { isNew: false })
  let wrapKey: CryptoKey
  try {
    wrapKey = (await derivePasswordWith(defaultWorker, prepared, bundle.salt, bundle.json.kdf, options)).wrapKey
  } finally {
    prepared.fill(0)
  }
  return openWith(bundle, 'password', wrapKey)
}

/** openKeyBundleWithRecoveryCode opens a bundle with the recovery code, in any spelling it accepts, instead. */
export async function openKeyBundleWithRecoveryCode(input: unknown, code: string): Promise<Bytes> {
  const bundle = parseKeyBundle(input)
  const { wrapKey } = await deriveRecovery(code)
  return openWith(bundle, 'recovery', wrapKey)
}
