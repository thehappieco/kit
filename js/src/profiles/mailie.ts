// The Mailie profile (SPEC Appendix D): the labels, headers, magic, kinds and
// additional data with which Mailie wraps a person's account key, grants a
// mailbox's private key to a person, and keeps the account key in a browser.
// Its values are wire format.
//
// v0.6.0 brought Mailie's platform wrap (SPEC section 6.8): its account key
// under a key derived from its product key sk_p, the kit's generic
// @thehappieco/kit/platformwrap under Mailie's labels. v0.7.0 adds the rest
// of Mailie's key scheme as Mailie specified it (its docs/key-scheme.md,
// version 1, at github.com/thehappieco/mailie c9c79cf), pinned by Mailie's
// own vectors under vectors/mailie/key-scheme-v1: the account scheme
// (mailieAccount and the 61-byte password and recovery wraps, header 0x02,
// bound to the seal id, the kind and the account public key), the seal
// domain and the grants (mailieSeal, grants of a mailbox's key at
// grantRow(namespace, namespace, seal id, epoch) that open only to the
// mailbox's public key), the platform wrap's binding (the seal id as the
// user id, never id.'s sub) and the browser vault (mailieBrowserVault).
//
// Parameters and the checks around them only, never a primitive of its own:
// Argon2id and the auth/wrap split are the account module's (derive with
// mailieAccount from @thehappieco/kit/account), a grant is the seal module's
// direct mode, the platform wrap is the platformwrap module's, the password
// preparation and the recovery code are the platform profile's, and the
// browser vault is browserAccount's. It names no KDF worker: it reaches the
// account scheme's core without one, and derive is the caller's. Nor does
// it reach a value that spells the platform's name, so a product's bundle
// that imports only this module carries none. What stays in Mailie: how its
// server normalises an address and the salt it hands out, drawing seal ids
// and namespaces, the ceremonies, and every server secret.

import {
  AccountError,
  checkKDFParams,
  checkSalt,
  unwrapPrivateKey,
  wrapPrivateKey,
  type AccountProfile,
  type KDFParams,
} from '../internal/accountcore.js'
import {
  browserAccountAAD,
  openBrowserAccountKey,
  sealBrowserAccountKey,
  type BrowserAccountProfile,
  type BrowserKeyEnvelope,
} from '../browserAccount.js'
import { encodeUTF8, equal, parseUUID, toBase64URL, type Bytes } from '../bytes.js'
import { isPlatformWrapError, MailieError, PlatformWrapError, SealError, isMailieError, type MailieErrorCode } from '../errors.js'
import { publicFromPrivate, type PrivateKey } from '../hpke.js'
import { canonicalJSON } from '../jcs.js'
import { checkPlatformWrapShape, openPlatformWrap, sealPlatformWrap, type PlatformWrapBinding, type PlatformWrapProfile } from '../internal/platformwrap.js'
import { KDF_BOUNDS, SALT_LEN } from '../internal/platform/kdfpolicy.js'
import { preparePassword } from '../internal/platform/password.js'
import { canonicalRecoveryCode } from '../internal/platform/recoverycode.js'
import {
  aad as sealAAD,
  DIRECT_OVERHEAD,
  grantRow as kitGrantRow,
  info as sealInfo,
  MODE_DIRECT,
  openDirect,
  parseHeader,
  sealDirect,
  SUITE_V1,
  VERSION,
  type SealProfile,
} from '../seal.js'

export { AccountError, isMailieError, isPlatformWrapError, MailieError, PlatformWrapError, SealError, SALT_LEN }
export type { BrowserKeyEnvelope, Bytes, KDFParams, MailieErrorCode, PlatformWrapBinding, PrivateKey }

const KEY_LEN = 32

function binding(message: string): never {
  throw new MailieError(message, 'binding')
}

function key32(name: string, k: unknown): void {
  if (!(k instanceof Uint8Array) || k.length !== KEY_LEN) binding(`${name} is not ${KEY_LEN} bytes`)
}

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

/**
 * isSealID says whether id is a seal id in its one spelling: a version 4 UUID
 * of the RFC 9562 variant as 36 characters of lowercase hyphenated text.
 * Mailie's server draws a person's seal id once; every wrap and grant binds
 * it, never the address and never id.'s sub. Upper case, braces, a urn:
 * prefix, another version and the nil UUID are refused, never normalised.
 */
export function isSealID(id: unknown): id is string {
  return typeof id === 'string' && UUID_V4.test(id)
}

/** isNamespace says whether ns is a mailbox namespace in its one spelling, the same as a seal id's. */
export function isNamespace(ns: unknown): ns is string {
  return isSealID(ns)
}

// ---------------------------------------------------------------------------
// The platform wrap (SPEC section 6.8 and Appendix D)
// ---------------------------------------------------------------------------

/** PLATFORM_WRAP_LABEL opens the HKDF info and the AAD of Mailie's platform wrap. */
export const PLATFORM_WRAP_LABEL = 'mailie/platform-wrap'
/** PLATFORM_WRAP_SALT is the HKDF salt of Mailie's K_pw. */
export const PLATFORM_WRAP_SALT = 'mailie/platform-wrap/v1'
/** PLATFORM_WRAP_PRODUCT is the product of the product key ids Mailie's wraps are made for, "mailie:<epoch>". */
export const PLATFORM_WRAP_PRODUCT = 'mailie'

/**
 * mailiePlatformWrap is Mailie's platform-wrap profile, for
 * @thehappieco/kit/platformwrap: sealPlatformWrap(mailiePlatformWrap,
 * productKey, accountKey, binding), or bind(mailiePlatformWrap). None of
 * Mailie's other envelopes of its account key may start with
 * PLATFORM_WRAP_HEADER (0x03), and Mailie keeps its wraps in a column of
 * their own: the shape of a wrap is the same for every product.
 */
export const mailiePlatformWrap: PlatformWrapProfile = Object.freeze({ product: PLATFORM_WRAP_PRODUCT, salt: PLATFORM_WRAP_SALT, label: PLATFORM_WRAP_LABEL })

export { checkPlatformWrapShape }

/**
 * platformWrapBinding is what Mailie binds a platform wrap to: the person's
 * seal id as the product's user id, id.'s sub, the product key id
 * "mailie:<epoch>" Mailie's server pinned at the person's sign-in, and the
 * account public key it holds for the person. The user id is the seal id for
 * every person, those created through id. included, and never the sub: a
 * departure from the wording of SPEC section 6.8 (SPEC Appendix D). A seal
 * id that is not a lowercase UUIDv4, a seal id equal to the sub whatever the
 * sub's version, and an epoch outside 1 to 2^31 - 1 are MailieError binding;
 * the platform wrap refuses a sub or a public key outside their spelling
 * when it is sealed or opened. Whatever opens Mailie's export takes the user
 * id from the export, never from the sub.
 */
export function platformWrapBinding(sealID: string, sub: string, productKeyEpoch: number, accountPublicKey: Uint8Array): PlatformWrapBinding {
  if (!isSealID(sealID)) binding('the seal id is not a lowercase UUIDv4')
  if (sealID === sub) binding('the user id is the seal id, never the sub')
  if (!Number.isInteger(productKeyEpoch) || productKeyEpoch < 1 || productKeyEpoch > 2 ** 31 - 1) binding('a product key epoch is from 1 to 2^31 - 1')
  return { userId: sealID, sub, productKeyId: `${PLATFORM_WRAP_PRODUCT}:${productKeyEpoch}`, accountPublicKey }
}

/** sealMailiePlatformWrap is sealPlatformWrap under Mailie's labels. */
export function sealMailiePlatformWrap(productKey: Uint8Array, accountKey: Uint8Array, b: PlatformWrapBinding): Promise<Bytes> {
  return sealPlatformWrap(mailiePlatformWrap, productKey, accountKey, b)
}

/** openMailiePlatformWrap is openPlatformWrap under Mailie's labels. */
export function openMailiePlatformWrap(productKey: Uint8Array, wrap: Uint8Array, b: PlatformWrapBinding): Promise<Bytes> {
  return openPlatformWrap(mailiePlatformWrap, productKey, wrap, b)
}

// ---------------------------------------------------------------------------
// The account (SPEC section 6 with Mailie's values)
// ---------------------------------------------------------------------------

/** PASSWORD_AUTH_LABEL and PASSWORD_WRAP_LABEL are the HKDF infos of the auth key, which is sent, and of the wrap key, which never leaves. */
export const PASSWORD_AUTH_LABEL = 'mailie/v1/password/auth'
export const PASSWORD_WRAP_LABEL = 'mailie/v1/password/wrap'
/** RECOVERY_WRAP_LABEL and RECOVERY_AUTH_LABEL are the HKDF infos of a recovery code's wrap key and of its proof. */
export const RECOVERY_WRAP_LABEL = 'mailie/v1/recovery/wrap'
export const RECOVERY_AUTH_LABEL = 'mailie/v1/recovery/auth'
/** ACCOUNT_WRAP_TAG and ACCOUNT_WRAP_VERSION open the additional data of an account wrap. */
export const ACCOUNT_WRAP_TAG = 'mailie/account-wrap'
export const ACCOUNT_WRAP_VERSION = 1
/** The first byte of a password or recovery wrap; the platform wrap's is 0x03 and a grant's the seal magic 'M'. */
export const ACCOUNT_WRAP_HEADER = 0x02
/** The header, a 12-byte nonce, the 32-byte account key and a 16-byte tag. */
export const ACCOUNT_WRAP_LEN = 61

/** WrapKind says which secret an account wrap is under; it is bound into the wrap's additional data. */
export type WrapKind = 'password' | 'recovery'

/** DEFAULT_KDF is what Mailie's accounts derive with: the floor of the platform's bounds. */
export const DEFAULT_KDF: Readonly<KDFParams> = Object.freeze({ alg: 'argon2id', m: KDF_BOUNDS.m.floor, t: KDF_BOUNDS.t.floor, p: KDF_BOUNDS.p.floor })

/**
 * mailieAccount is Mailie's profile for the account module: its labels, the
 * platform's preparation of a presented password (SPEC section 11.2, no
 * minimum length), the platform's KDF bounds (section 11.3), base64url text,
 * the platform's canonical recovery code (section 11.6), and the one-byte
 * header 0x02 with no legacy form. derive(mailieAccount, password, salt, kdf)
 * of @thehappieco/kit/account gives the auth key to send and the wrap key
 * that never leaves.
 */
export const mailieAccount: AccountProfile = Object.freeze({
  authLabel: PASSWORD_AUTH_LABEL,
  wrapLabel: PASSWORD_WRAP_LABEL,
  recoveryKeyLabel: RECOVERY_WRAP_LABEL,
  recoveryProofLabel: RECOVERY_AUTH_LABEL,
  wrapHeader: Object.freeze([ACCOUNT_WRAP_HEADER]),
  legacyV1: false,
  encoding: 'base64url',
  prepare: (password: string) => preparePassword(password, { isNew: false }),
  bounds: Object.freeze({
    min: Object.freeze({ m: KDF_BOUNDS.m.floor, t: KDF_BOUNDS.t.floor, p: KDF_BOUNDS.p.floor }),
    max: Object.freeze({ m: KDF_BOUNDS.m.ceiling, t: KDF_BOUNDS.t.ceiling, p: KDF_BOUNDS.p.ceiling }),
    maxCost: KDF_BOUNDS.mt,
    minSaltLen: SALT_LEN,
    maxSaltLen: SALT_LEN,
  }),
  normaliseRecovery: canonicalRecoveryCode,
} as const)

/**
 * prepareNewPassword refuses a new password the platform's preparation would
 * not take (12 to 256 code points, no control character), before anything is
 * derived: PlatformError password_too_short, password_too_long or
 * password_invalid.
 */
export function prepareNewPassword(password: string): void {
  preparePassword(password, { isNew: true }).fill(0)
}

/**
 * checkKDF throws unless what a server answered is a KDF this profile derives
 * with: AccountError kdf out_of_bounds for a value that is not an object, a
 * member other than alg, m, t and p, or a parameter that is not an integer,
 * which the bounds alone would let through; then the profile's bounds and
 * salt length.
 */
export function checkKDF(kdf: unknown, salt: Bytes): KDFParams {
  if (typeof kdf !== 'object' || kdf === null || Array.isArray(kdf)) throw new AccountError('not KDF parameters', 'kdf', 'out_of_bounds')
  const o = kdf as Record<string, unknown>
  if (Object.keys(o).some((k) => !['alg', 'm', 't', 'p'].includes(k)) || typeof o.alg !== 'string' || ![o.m, o.t, o.p].every(Number.isSafeInteger)) {
    throw new AccountError('not KDF parameters', 'kdf', 'out_of_bounds')
  }
  const params: KDFParams = { alg: o.alg, m: o.m as number, t: o.t as number, p: o.p as number }
  checkKDFParams(mailieAccount, params)
  checkSalt(mailieAccount, salt)
  return params
}

/**
 * accountWrapAAD is the additional data of an account wrap, a restricted JSON
 * AAD (SPEC section 11.1):
 * JCS(["mailie/account-wrap", 1, kind, seal_id, base64url(account public key)]).
 * The seal id, never the address, so an address change needs no re-wrap; the
 * kind, so a password wrap is never taken for the recovery wrap; the account
 * public key, so a wrap opens only for the key the person's grants are sealed to.
 */
export function accountWrapAAD(kind: WrapKind, sealID: string, accountPublicKey: Uint8Array): Bytes {
  if (kind !== 'password' && kind !== 'recovery') binding('a wrap kind is password or recovery')
  if (!isSealID(sealID)) binding('the seal id is not a lowercase UUIDv4')
  key32('the account public key', accountPublicKey)
  return encodeUTF8(canonicalJSON([ACCOUNT_WRAP_TAG, ACCOUNT_WRAP_VERSION, kind, sealID, toBase64URL(new Uint8Array(accountPublicKey) as Bytes)]))
}

/**
 * sealAccountWrap wraps the 32-byte account key under a wrap key (derive's
 * wrapKey, or recoveryKey(mailieAccount, code)) with the wrap envelope of
 * SPEC section 6.5: 0x02, a fresh nonce, and AES-256-GCM under
 * accountWrapAAD; 61 bytes. It opens what it made and compares before it
 * returns it (the self-test). The account key is the caller's to zero.
 */
export async function sealAccountWrap(kind: WrapKind, wrapKey: CryptoKey, accountKey: Uint8Array, sealID: string): Promise<Bytes> {
  key32('the account key', accountKey)
  const raw = new Uint8Array(accountKey) as Bytes
  try {
    const pub = await publicFromPrivate(raw)
    const wrap = await wrapPrivateKey(mailieAccount, raw, wrapKey, accountWrapAAD(kind, sealID, pub))
    const again = await openAccountWrap(kind, wrapKey, wrap, sealID, pub)
    const same = equal(again, raw)
    again.fill(0)
    if (!same) throw new AccountError('the new wrap failed its self-test', 'wrap', 'wrong_key')
    return wrap
  } finally {
    raw.fill(0)
  }
}

/**
 * openAccountWrap opens an account wrap and returns the account key, which
 * the caller zeroes. The binding first (MailieError binding); then a wrap
 * shorter than 61 bytes is AccountError wrap truncated, and one longer, one
 * not starting with 0x02, one that does not authenticate and one that opens
 * to anything but the private half of accountPublicKey are all wrap wrong_key.
 */
export async function openAccountWrap(kind: WrapKind, wrapKey: CryptoKey, wrap: Uint8Array, sealID: string, accountPublicKey: Uint8Array): Promise<Bytes> {
  const aad = accountWrapAAD(kind, sealID, accountPublicKey)
  if (!(wrap instanceof Uint8Array) || wrap.length < ACCOUNT_WRAP_LEN) throw new AccountError('the wrap is truncated', 'wrap', 'truncated')
  if (wrap.length !== ACCOUNT_WRAP_LEN || wrap[0] !== ACCOUNT_WRAP_HEADER) throw new AccountError('not an account wrap', 'wrap', 'wrong_key')
  const { privateKey } = await unwrapPrivateKey(mailieAccount, new Uint8Array(wrap) as Bytes, wrapKey, aad)
  let ok = false
  try {
    ok = privateKey.length === KEY_LEN && equal(await publicFromPrivate(privateKey), new Uint8Array(accountPublicKey) as Bytes)
  } catch {
    ok = false
  }
  if (!ok) {
    privateKey.fill(0)
    throw new AccountError('the wrap names another account key', 'wrap', 'wrong_key')
  }
  return privateKey
}

/** checkAccountWrapShape is a server's check of a wrap it cannot open: 61 bytes starting with 0x02 (MailieError shape). */
export function checkAccountWrapShape(wrap: Uint8Array): void {
  if (!(wrap instanceof Uint8Array) || wrap.length !== ACCOUNT_WRAP_LEN || wrap[0] !== ACCOUNT_WRAP_HEADER) {
    throw new MailieError('not an account wrap', 'shape')
  }
}

// ---------------------------------------------------------------------------
// The seal domain and the grants (SPEC sections 4 and 5 with Mailie's values)
// ---------------------------------------------------------------------------

/**
 * Kind is what a Mailie sealed value is. The byte is bound into the
 * additional data and the name into a direct envelope's HPKE info, so both
 * are wire format. Mailie seals only MailboxGrant so far; the other bytes it
 * names are reserved for its later phases, nothing is sealed under them yet,
 * and 0x0B to 0x0F are reserved and unnamed.
 */
export enum Kind {
  Headers = 0x01,
  Snippet = 0x02,
  Body = 0x03,
  AttachmentKey = 0x04,
  SearchIndex = 0x05,
  /** The core content key, the seal module's KIND_CONTENT_KEY. */
  ContentKey = 0x06,
  /** The core grant, the seal module's KIND_GRANT: a mailbox's key sealed to one person. */
  MailboxGrant = 0x07,
  /** The core reserved byte, the seal module's KIND_USER_WRAP; never sealed. */
  UserWrap = 0x08,
  FolderName = 0x09,
  Draft = 0x0a,
}

// The names go into a direct envelope's HPKE info: wire format.
const kindNames: Readonly<Record<number, string>> = Object.freeze({
  [Kind.Headers]: 'headers',
  [Kind.Snippet]: 'snippet',
  [Kind.Body]: 'body',
  [Kind.AttachmentKey]: 'attachment_key',
  [Kind.SearchIndex]: 'search_index',
  [Kind.ContentKey]: 'content_key',
  [Kind.MailboxGrant]: 'mailbox_grant',
  [Kind.UserWrap]: 'user_wrap',
  [Kind.FolderName]: 'folder_name',
  [Kind.Draft]: 'draft',
})

/** kindName matches Go's Kind.String: kind(0x..) without leading zeros for an unnamed byte. */
export function kindName(kind: number): string {
  return kindNames[kind] ?? `kind(0x${kind.toString(16)})`
}

/** SEAL_MAGIC is bytes 0-1 of every envelope Mailie seals: "ML". */
export const SEAL_MAGIC: readonly [number, number] = Object.freeze([0x4d, 0x4c] as const)
/** SEAL_LABEL prefixes the additional data and the HPKE info of every envelope Mailie seals. */
export const SEAL_LABEL = 'mlv1'
/** mailieSeal is Mailie's envelope: magic "ML", label "mlv1", its kinds' names. */
export const mailieSeal: SealProfile = Object.freeze({ magic: SEAL_MAGIC, label: SEAL_LABEL, kindName })

/** A mailbox key's epochs: 1 for its first key pair, one more for each new one, up to the header's u16be. */
export const MIN_EPOCH = 1
export const MAX_EPOCH = 0xffff
/** A grant: the 8-byte header, the 32-byte encapsulated key, and the 32-byte mailbox key with its tag. */
export const GRANT_LEN = DIRECT_OVERHEAD + KEY_LEN

function mailboxBinding(namespace: string, epoch: number): void {
  if (!isNamespace(namespace)) binding('the namespace is not a lowercase UUIDv4')
  if (!Number.isInteger(epoch) || epoch < MIN_EPOCH || epoch > MAX_EPOCH) binding(`an epoch is from ${MIN_EPOCH} to ${MAX_EPOCH}`)
}

function grantBinding(namespace: string, sealID: string, epoch: number): void {
  mailboxBinding(namespace, epoch)
  if (!isSealID(sealID)) binding('the seal id is not a lowercase UUIDv4')
}

/** grantRow is the seal module's grantRow with the namespace as tenant and device: Row(namespace, namespace ‖ seal_id ‖ u16be(epoch)). */
export async function grantRow(namespace: string, sealID: string, epoch: number): Promise<Bytes> {
  grantBinding(namespace, sealID, epoch)
  const ns = parseUUID(namespace)
  return kitGrantRow(ns, ns, parseUUID(sealID), epoch)
}

/** grantInfo is a grant's HPKE info: "mlv1/mailbox_grant/<namespace>/<epoch>". */
export function grantInfo(namespace: string, epoch: number): Bytes {
  mailboxBinding(namespace, epoch)
  return sealInfo(mailieSeal, Kind.MailboxGrant, parseUUID(namespace), epoch)
}

/** grantAAD is a grant's additional data: "mlv1" ‖ 0x07 ‖ namespace ‖ grantRow ‖ the direct header at that epoch, 45 bytes. */
export async function grantAAD(namespace: string, sealID: string, epoch: number): Promise<Bytes> {
  const row = await grantRow(namespace, sealID, epoch)
  const header = new Uint8Array([SEAL_MAGIC[0], SEAL_MAGIC[1], VERSION, SUITE_V1, MODE_DIRECT, epoch >> 8, epoch & 0xff, 0]) as Bytes
  return sealAAD(mailieSeal, Kind.MailboxGrant, parseUUID(namespace), row, header)
}

/**
 * sealGrant seals a mailbox's 32-byte private key to a person's account
 * public key: the direct envelope of SPEC section 4.4, kind 0x07, at
 * grantRow, at the mailbox key's epoch; 88 bytes. A low-order public key is
 * refused (SealError invalid_key): whoever handed it out could open the
 * grant. The mailbox key is the caller's to zero.
 */
export async function sealGrant(recipientPublicKey: Uint8Array, namespace: string, sealID: string, epoch: number, mailboxKey: Uint8Array): Promise<Bytes> {
  grantBinding(namespace, sealID, epoch)
  key32('the mailbox key', mailboxKey)
  const row = await grantRow(namespace, sealID, epoch)
  return sealDirect(mailieSeal, new Uint8Array(recipientPublicKey) as Bytes, Kind.MailboxGrant, parseUUID(namespace), row, epoch, new Uint8Array(mailboxKey) as Bytes)
}

/**
 * openGrant opens a grant with the person's account key and returns the
 * mailbox's private key, which the caller zeroes. The binding first
 * (MailieError binding), then the seal module's header checks (short, magic,
 * version, suite, mode); everything else is SealError authentication:
 * another person, mailbox, epoch or kind, a changed byte, and a grant that
 * opens to anything but the private half of mailboxPublicKey, the key the
 * server holds for the mailbox at that epoch. HPKE's base mode does not
 * authenticate the sender, so that last check is what a grant sealed by
 * someone who knows only the person's public key cannot pass.
 */
export async function openGrant(account: PrivateKey, namespace: string, sealID: string, epoch: number, mailboxPublicKey: Uint8Array, grant: Uint8Array): Promise<Bytes> {
  grantBinding(namespace, sealID, epoch)
  key32('the mailbox public key', mailboxPublicKey)
  const row = await grantRow(namespace, sealID, epoch)
  const key = await openDirect(mailieSeal, account, Kind.MailboxGrant, parseUUID(namespace), row, new Uint8Array(grant) as Bytes)
  let ok = false
  try {
    ok = key.length === KEY_LEN && equal(await publicFromPrivate(key), new Uint8Array(mailboxPublicKey) as Bytes)
  } catch {
    ok = false
  }
  if (!ok) {
    key.fill(0)
    throw new SealError('authentication failed', 'authentication')
  }
  return key
}

/** checkGrantShape is a server's check of a grant it cannot open: 88 bytes, Mailie's header in direct mode at the current epoch, a zero reserved byte (MailieError shape). */
export function checkGrantShape(grant: Uint8Array, epoch: number): void {
  const shape = () => new MailieError('not a grant at the current epoch', 'shape')
  if (!(grant instanceof Uint8Array) || grant.length !== GRANT_LEN) throw shape()
  let h
  try {
    h = parseHeader(mailieSeal, new Uint8Array(grant) as Bytes)
  } catch {
    throw shape()
  }
  if (h.mode !== MODE_DIRECT || h.epoch !== epoch || grant[7] !== 0) throw shape()
}

// ---------------------------------------------------------------------------
// The browser vault (SPEC section 8 with Mailie's tag)
// ---------------------------------------------------------------------------

export const BROWSER_VAULT_TAG = 'mailie/browser-account-key'
export const BROWSER_VAULT_VERSION = 1
/** mailieBrowserVault is Mailie's profile for browserAccount: its tag and version. */
export const mailieBrowserVault: BrowserAccountProfile = Object.freeze({ tag: BROWSER_VAULT_TAG, version: BROWSER_VAULT_VERSION })

/**
 * browserVaultAAD is JCS(["mailie/browser-account-key", 1, seal_id, base64(account public key)]):
 * the JSON AAD of SPEC sections 2 and 8, not the restricted one of the other
 * bindings, since standard base64's '+', '/' and '=' are outside its alphabet.
 */
export function browserVaultAAD(sealID: string, accountPublicKey: Uint8Array): Bytes {
  if (!isSealID(sealID)) binding('the seal id is not a lowercase UUIDv4')
  key32('the account public key', accountPublicKey)
  return browserAccountAAD(mailieBrowserVault, sealID, new Uint8Array(accountPublicKey) as Bytes)
}

/** sealBrowserVault keeps the account key at rest under a fresh non-extractable AES key, bound to the seal id and the public key. */
export async function sealBrowserVault(accountKey: Uint8Array, accountPublicKey: Uint8Array, sealID: string): Promise<BrowserKeyEnvelope> {
  key32('the account key', accountKey)
  browserVaultAAD(sealID, accountPublicKey)
  return sealBrowserAccountKey(mailieBrowserVault, new Uint8Array(accountKey) as Bytes, new Uint8Array(accountPublicKey) as Bytes, sealID)
}

/**
 * openBrowserVault opens the record for the person the server says is signed
 * in. The caller first compares the record's public key with the one the
 * server holds for the person; a record of anyone else is wiped, never
 * opened. A record that does not open (another seal id, another public key,
 * not a record at all) is MailieError vault, never the kit's own error, so
 * the product has one code to wipe it on.
 */
export async function openBrowserVault(envelope: BrowserKeyEnvelope, sealID: string): Promise<PrivateKey> {
  if (!isSealID(sealID)) binding('the seal id is not a lowercase UUIDv4')
  try {
    return await openBrowserAccountKey(mailieBrowserVault, envelope, sealID)
  } catch {
    throw new MailieError('the vault record does not open for this person', 'vault')
  }
}
