// The sealed envelope.
//
// Mirrors the Go package seal. Values are sealed to a public key whose private
// half only the reader holds, each bound by the AAD to its tenant, kind, row
// and header. A profile chooses the two magic bytes, the label that prefixes
// the AAD and the HPKE info, and the names of its kinds; everything else is
// the standard (SPEC.md section 4). From Wappie's
// packages/client/src/crypto/seal.ts, with Wappie's constants moved to
// profiles/wappie.ts.
//
// Every function takes the profile first. bind(profile) returns the same
// functions with it fixed, which is how a product keeps its old call sites.

import { type Bytes, concat, encodeUTF8, formatUUID, readUint16BE, readUint32BE, uuidV5 } from './bytes.js'
import { HPKEError, SealError } from './errors.js'
import { ENC_LEN, open as hpkeOpen, seal as hpkeSeal, type PrivateKey } from './hpke.js'

export { SealError }
export type { SealErrorCode } from './errors.js'

/** SealProfile is what a product chooses about the envelope. */
export interface SealProfile {
  /** Bytes 0-1 of every envelope. */
  readonly magic: readonly [number, number]
  /** Prefix of the AAD and of the HPKE info; printable ASCII, not empty. */
  readonly label: string
  /**
   * The wire name of a kind, which goes into a direct envelope's HPKE info:
   * [a-z0-9_]+, or `kind(0x${kind.toString(16)})` for an unnamed byte.
   */
  kindName(kind: number): string
}

export const VERSION = 0x01
export const SUITE_V1 = 0x01
export const MODE_DIRECT = 0x01
export const MODE_BATCH = 0x02
export const HEADER_LEN = 8
export const BATCH_OVERHEAD = 40
export const DIRECT_OVERHEAD = 56

/** The core kind bytes, the same in every profile. */
export const KIND_CONTENT_KEY = 0x06
export const KIND_GRANT = 0x07
export const KIND_USER_WRAP = 0x08

const NONCE_LEN = 12
const TAG_LEN = 16

export interface Header {
  version: number
  suite: number
  mode: number
  epoch: number
}

function invalid(message: string): never {
  throw new SealError(message, 'invalid_input')
}

function checkID(name: string, id: Bytes): void {
  if (!(id instanceof Uint8Array) || id.length !== 16) invalid(`${name} must contain 16 bytes`)
}

function checkUint(name: string, value: number, max: number): void {
  if (!Number.isInteger(value) || value < 0 || value > max) invalid(`${name} must be an integer from 0 to ${max}`)
}

/**
 * parseHeader validates the prefix before any key material is touched. The
 * suite byte is checked rather than guessed at, because a parser that guessed
 * would be the downgrade path the byte exists to close. The reserved byte is
 * not checked here: it is bound by the AAD, so a non-zero one fails as
 * authentication when the envelope is opened.
 */
export function parseHeader(p: SealProfile, envelope: Bytes): Header {
  if (envelope.length < HEADER_LEN) throw new SealError('envelope is too short', 'short')
  if (envelope[0] !== p.magic[0] || envelope[1] !== p.magic[1]) throw new SealError('not an envelope', 'magic')
  const h: Header = { version: envelope[2], suite: envelope[3], mode: envelope[4], epoch: readUint16BE(envelope, 5) }
  if (h.version !== VERSION) throw new SealError(`unknown version: ${h.version}`, 'version')
  if (h.suite !== SUITE_V1) throw new SealError(`unknown suite: ${h.suite}`, 'suite')
  if (h.mode !== MODE_DIRECT && h.mode !== MODE_BATCH) throw new SealError(`unknown mode: ${h.mode}`, 'mode')
  return h
}

/** aad is label, kind (1), tenant (16), row (16), header (8). */
export function aad(p: SealProfile, kind: number, tenant: Bytes, row: Bytes, header: Bytes): Bytes {
  return concat(encodeUTF8(p.label), new Uint8Array([kind]), tenant, row, header)
}

/** info is the HPKE info of a direct envelope: label/name(kind)/tenant/epoch. */
export function info(p: SealProfile, kind: number, tenant: Bytes, epoch: number): Bytes {
  return encodeUTF8(`${p.label}/${p.kindName(kind)}/${formatUUID(tenant)}/${epoch}`)
}

function encodeHeader(p: SealProfile, mode: number, epoch: number): Bytes {
  const b = new Uint8Array(HEADER_LEN) as Bytes
  b[0] = p.magic[0]
  b[1] = p.magic[1]
  b[2] = VERSION
  b[3] = SUITE_V1
  b[4] = mode
  new DataView(b.buffer).setUint16(5, epoch, false)
  // b[7] is reserved and stays zero.
  return b
}

/**
 * sealDirect seals a value straight to a public key: header, the encapsulated
 * key (32), then the HPKE ciphertext. Grants and content keys go this way.
 *
 * Getting the binding wrong fails silently in the worst way: a grant stores,
 * and what it was meant to unlock stays unreadable. So the inputs are checked:
 * ids of 16 bytes, an epoch and a kind that fit their fields. A public key of
 * low order is refused as invalid_key: whoever served it could open the seal.
 */
export async function sealDirect(p: SealProfile, publicRaw: Bytes, kind: number, tenant: Bytes, row: Bytes, epoch: number, plaintext: Bytes): Promise<Bytes> {
  if (!(publicRaw instanceof Uint8Array) || publicRaw.length !== 32) throw new SealError('no public key', 'invalid_key')
  checkUint('the kind', kind, 0xff)
  checkID('the tenant', tenant)
  checkID('the row', row)
  checkUint('the epoch', epoch, 0xffff)
  const header = encodeHeader(p, MODE_DIRECT, epoch)
  let sealed: { enc: Bytes; ciphertext: Bytes }
  try {
    sealed = await hpkeSeal(publicRaw, info(p, kind, tenant, epoch), aad(p, kind, tenant, row, header), plaintext)
  } catch (err) {
    if (err instanceof HPKEError && err.code === 'invalid_key') throw new SealError('no secret can be agreed with this public key', 'invalid_key')
    throw err
  }
  return concat(header, sealed.enc, sealed.ciphertext)
}

/**
 * openDirect opens a value sealed straight to the key. Every failure after the
 * header checks is `authentication`: telling a wrong key from a moved row from
 * a tampered byte would hand an attacker an oracle for the binding.
 */
export async function openDirect(p: SealProfile, priv: PrivateKey, kind: number, tenant: Bytes, row: Bytes, envelope: Bytes): Promise<Bytes> {
  if (!priv || !(priv.key instanceof CryptoKey)) throw new SealError('no private key', 'invalid_key')
  const h = parseHeader(p, envelope)
  if (h.mode !== MODE_DIRECT) throw new SealError('expected direct mode', 'mode')
  if (envelope.length < HEADER_LEN + ENC_LEN + TAG_LEN) throw new SealError('envelope is too short', 'short')
  const header = envelope.subarray(0, HEADER_LEN)
  const enc = envelope.subarray(HEADER_LEN, HEADER_LEN + ENC_LEN)
  const ciphertext = envelope.subarray(HEADER_LEN + ENC_LEN)
  try {
    return await hpkeOpen(priv, enc, info(p, kind, tenant, h.epoch), aad(p, kind, tenant, row, header), ciphertext)
  } catch {
    throw new SealError('authentication failed', 'authentication')
  }
}

/** ContentKey is a symmetric key covering a batch of sealed values. */
export class ContentKey {
  private constructor(
    readonly profile: SealProfile,
    readonly id: number,
    readonly epoch: number,
    private readonly key: CryptoKey,
  ) {}

  /**
   * unwrap opens a stored content key, sealed directly at
   * contentKeyRow(tenant, device, id). Its epoch is the sealed key's header's.
   */
  static async unwrap(p: SealProfile, priv: PrivateKey, tenant: Bytes, device: Bytes, id: number, sealed: Bytes): Promise<ContentKey> {
    const h = parseHeader(p, sealed)
    const row = await contentKeyRow(tenant, device, id)
    const raw = await openDirect(p, priv, KIND_CONTENT_KEY, tenant, row, sealed)
    if (raw.length !== 32) throw new SealError(`content key has ${raw.length} bytes, expected 32`, 'short')
    const key = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt'])
    raw.fill(0)
    return new ContentKey(p, id, h.epoch, key)
  }

  /** open decrypts a batch envelope; the key id is checked before decryption. */
  async open(kind: number, tenant: Bytes, row: Bytes, envelope: Bytes): Promise<Bytes> {
    const h = parseHeader(this.profile, envelope)
    if (h.mode !== MODE_BATCH) throw new SealError('expected batch mode', 'mode')
    if (envelope.length < HEADER_LEN + 4 + NONCE_LEN + TAG_LEN) throw new SealError('envelope is too short', 'short')
    const wants = readUint32BE(envelope, HEADER_LEN)
    if (wants !== this.id) throw new SealError(`envelope requires content key ${wants}, this key is ${this.id}`, 'key_mismatch')
    const header = envelope.subarray(0, HEADER_LEN)
    const nonce = envelope.subarray(HEADER_LEN + 4, HEADER_LEN + 4 + NONCE_LEN)
    const ciphertext = envelope.subarray(HEADER_LEN + 4 + NONCE_LEN)
    try {
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aad(this.profile, kind, tenant, row, header), tagLength: 128 },
        this.key,
        ciphertext,
      )
      return new Uint8Array(plaintext)
    } catch {
      throw new SealError('authentication failed', 'authentication')
    }
  }
}

/** contentKeyID reads which content key a batch envelope needs, without opening it. */
export function contentKeyID(p: SealProfile, envelope: Bytes): { id: number; epoch: number } {
  const h = parseHeader(p, envelope)
  if (h.mode !== MODE_BATCH) throw new SealError('not a batch envelope', 'mode')
  if (envelope.length < HEADER_LEN + 4) throw new SealError('envelope is too short', 'short')
  return { id: readUint32BE(envelope, HEADER_LEN), epoch: h.epoch }
}

/** row is the version 5 UUID of a namespace and the concatenation of the parts. */
export async function row(namespace: Bytes, ...name: Bytes[]): Promise<Bytes> {
  checkID('the namespace', namespace)
  return uuidV5(namespace, concat(...name))
}

/** contentKeyRow is row(tenant, device || u32be id). */
export async function contentKeyRow(tenant: Bytes, device: Bytes, id: number): Promise<Bytes> {
  checkID('the device', device)
  checkUint('the content key id', id, 0xffffffff)
  const name = new Uint8Array(20)
  name.set(device, 0)
  new DataView(name.buffer).setUint32(16, id, false)
  return row(tenant, name)
}

/** grantRow is row(tenant, device || user || u16be epoch). */
export async function grantRow(tenant: Bytes, device: Bytes, user: Bytes, epoch: number): Promise<Bytes> {
  checkID('the device', device)
  checkID('the user', user)
  checkUint('the epoch', epoch, 0xffff)
  const name = new Uint8Array(34)
  name.set(device, 0)
  name.set(user, 16)
  new DataView(name.buffer).setUint16(32, epoch, false)
  return row(tenant, name)
}

/** bind fixes a profile, for a product's own wrappers. */
export function bind(p: SealProfile) {
  return {
    profile: p,
    kindName: (kind: number) => p.kindName(kind),
    parseHeader: (envelope: Bytes) => parseHeader(p, envelope),
    aad: (kind: number, tenant: Bytes, rowID: Bytes, header: Bytes) => aad(p, kind, tenant, rowID, header),
    info: (kind: number, tenant: Bytes, epoch: number) => info(p, kind, tenant, epoch),
    sealDirect: (publicRaw: Bytes, kind: number, tenant: Bytes, rowID: Bytes, epoch: number, plaintext: Bytes) =>
      sealDirect(p, publicRaw, kind, tenant, rowID, epoch, plaintext),
    openDirect: (priv: PrivateKey, kind: number, tenant: Bytes, rowID: Bytes, envelope: Bytes) => openDirect(p, priv, kind, tenant, rowID, envelope),
    ContentKey: {
      unwrap: (priv: PrivateKey, tenant: Bytes, device: Bytes, id: number, sealed: Bytes) => ContentKey.unwrap(p, priv, tenant, device, id, sealed),
    },
    contentKeyID: (envelope: Bytes) => contentKeyID(p, envelope),
    row,
    contentKeyRow,
    grantRow,
  }
}
