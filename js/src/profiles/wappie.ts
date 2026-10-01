// The Wappie profile: the wire constants and AAD builders with which Wappie
// sealed, wrapped and signed its existing data. They are frozen; data already
// stored opens only with exactly these values. What each kind means to Wappie
// stays in Wappie.

import { encodeUTF8, type Bytes } from '../bytes.js'
import { canonicalJSON } from '../jcs.js'
import type { AccountProfile } from '../account.js'
import type { BrowserAccountProfile } from '../browserAccount.js'
import type { PasskeyProfile } from '../passkey.js'
import type { HMACScheme } from '../reqhmac.js'
import type { SealProfile } from '../seal.js'

// ---------------------------------------------------------------------------
// The sealed archive
// ---------------------------------------------------------------------------

/** Kind identifies what a sealed value is in Wappie's archive. */
export enum Kind {
  Body = 0x01,
  RawProto = 0x02,
  MediaKey = 0x03,
  Thumbnail = 0x04,
  ContactName = 0x05,
  ContentKey = 0x06,
  DeviceGrant = 0x07,
  UserWrap = 0x08,
  Payload = 0x09,
  PushName = 0x0a,
  FullName = 0x0b,
  BusinessName = 0x0c,
  Avatar = 0x0d,
  /** A draft an assistant made, sealed in the attested reader; 0x0F stays reserved. */
  McpDraft = 0x0e,
}

// The names go into the HPKE info string, so they are wire format.
const kindNames: Record<number, string> = {
  [Kind.Body]: 'body',
  [Kind.RawProto]: 'raw_proto',
  [Kind.MediaKey]: 'media_key',
  [Kind.Thumbnail]: 'thumbnail',
  [Kind.ContactName]: 'contact_name',
  [Kind.ContentKey]: 'content_key',
  [Kind.DeviceGrant]: 'device_grant',
  [Kind.UserWrap]: 'user_wrap',
  [Kind.Payload]: 'payload',
  [Kind.PushName]: 'push_name',
  [Kind.FullName]: 'full_name',
  [Kind.BusinessName]: 'business_name',
  [Kind.Avatar]: 'avatar',
  [Kind.McpDraft]: 'mcp_draft',
}

/** kindName matches Go's Kind.String, whose default prints kind(0x..) without leading zeros. */
export function kindName(kind: number): string {
  return kindNames[kind] ?? `kind(0x${kind.toString(16)})`
}

/** Wappie's envelope: magic "WS", label "wsv1". */
export const wappieSeal: SealProfile = Object.freeze({ magic: Object.freeze([0x57, 0x53] as const), label: 'wsv1', kindName })

// ---------------------------------------------------------------------------
// The account
// ---------------------------------------------------------------------------

/** No password preparation, no KDF bounds, and version 1 wraps still open. */
export const wappieAccount: AccountProfile = Object.freeze({
  authLabel: 'whatserver2/auth',
  wrapLabel: 'whatserver2/wrap',
  recoveryKeyLabel: 'whatserver2/recovery',
  recoveryProofLabel: 'whatserver2/recovery-auth',
  wrapHeader: Object.freeze([0x02]),
  legacyV1: true,
  encoding: 'base64',
} as const)

/** The AAD of a version 2 wrap, bound to the address the account signed up with. */
export function accountWrapAAD(email: string): Bytes {
  return encodeUTF8('whatserver2/usk|' + email.trim().toLowerCase())
}

// ---------------------------------------------------------------------------
// Passkeys and the key at rest
// ---------------------------------------------------------------------------

export const wappiePasskey: PasskeyProfile = Object.freeze({
  evalPrefix: 'wappie/passkey-vault/v1/',
  wrapInfo: 'wappie/passkey-wrap/v1',
  header: Object.freeze([0x01]),
})

export interface PasskeyBinding {
  rpID: string
  userID: string
  credentialID: string
}

/**
 * The AAD of a passkey wrap: the JCS text of the JSON array of the RP, the
 * user and the credential. A string with a lone surrogate has no JSON text,
 * and throws CanonicalJSONError rather than being bound loosely.
 */
export function passkeyAAD(b: PasskeyBinding): Bytes {
  return encodeUTF8(canonicalJSON(['wappie/passkey-vault', 1, b.rpID, b.userID, b.credentialID]))
}

export const wappieBrowserAccount: BrowserAccountProfile = Object.freeze({ tag: 'wappie/browser-account-key', version: 1 })

// ---------------------------------------------------------------------------
// The request HMAC between Wappie's server and its attested reader
// ---------------------------------------------------------------------------

export const DIRECTION_TO_READER = 'to-reader'
export const DIRECTION_TO_GO = 'to-go'

export const wappieMCPHMAC: HMACScheme = Object.freeze({
  label: 'wappie-mcp-hmac/v1',
  headers: Object.freeze({ sender: 'X-Wappie-Reader', timestamp: 'X-Wappie-Timestamp', nonce: 'X-Wappie-Nonce', signature: 'X-Wappie-Signature' }),
  skewSeconds: 60,
})
