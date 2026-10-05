// The ID token as the relying party's page reads it (SPEC section 11.14,
// callback step 6).
//
// The rule it enforces: the page accepts an ID token only from this issuer,
// for this client, for this flow's nonce, with a lifetime the issuer would
// give it, and, when the flow names the product's key label, for that
// product's key. The signature is not checked: the token comes straight
// from the issuer's token endpoint over TLS, in the response to a request
// only this page could make (OpenID Connect Core section 3.1.3.7), and the
// product's server does not trust it anyway: it asks userinfo with the
// access token (section 11.15). What is checked is everything a token from
// another flow, client or issuer would get wrong, and the shape the issuer
// writes: the header exactly {alg, kid, typ} with a thumbprint kid, and a
// 64-byte signature.
//
// iat and exp are not compared with this device's clock. A phone whose clock
// is minutes off would otherwise fail every sign-in after the code, and with
// key delivery the sealed key, were already spent. The clock adds nothing
// here: the nonce ties the token to this flow, which lives 10 minutes and
// completes once, and the product's server judges freshness on its own clock
// through the single-use access token.
//
// Only the claims of the protocol come out, each with its type checked, so a
// page never reads a member the protocol does not have.
//
// From the platform's web/shared/oidc-rp/idtoken.ts at 4476bf4.

import { fromBase64URL, isBase64URL } from '../../bytes.js'
import { RPError } from '../../errors.js'
import { isProductKeyId } from '../platform/keydelivery.js'
import { isSub } from '../platform/rootwrap.js'

/** MAX_LIFETIME_S bounds exp - iat; the issuer writes 300. */
export const MAX_LIFETIME_S = 600

// The shape the issuer writes: at most 8 KiB, a kid that is an RFC 7638
// thumbprint (43 characters of base64url), and a raw 64-byte r||s signature
// (86 characters).
const MAX_TOKEN_LEN = 8 << 10
const THUMBPRINT_B64_LEN = 43
const SIGNATURE_B64_LEN = 86

/** IdClaims are the claims of the ID token that the page may read. */
export interface IdClaims {
  iss: string
  sub: string
  aud: string
  iat: number
  exp: number
  nonce: string
  auth_time?: number
  jti?: string
  amr?: string[]
  email?: string
  email_verified?: boolean
  name?: string
  locale?: string
  /** b64url of pk_p, for a client with a product. */
  product_key?: string
  /** product + ":" + decimal(epoch). */
  product_key_id?: string
}

/** IdTokenExpectations are what the flow says the token must carry. */
export interface IdTokenExpectations {
  issuer: string
  clientId: string
  nonce: string
  /** With key delivery, product_key and product_key_id must be present. */
  wantKey: boolean
  /** The product's key label: when set, product_key_id must be present and name it. */
  product: string | null
}

function invalid(why: string): never {
  throw new RPError('id_token_invalid', why)
}

const utf8 = new TextDecoder('utf-8', { fatal: true })

function segment(s: string | undefined, what: string): Record<string, unknown> {
  if (s === undefined || s === '' || !isBase64URL(s)) invalid(`the ${what} is not base64url`)
  let value: unknown
  try {
    value = JSON.parse(utf8.decode(fromBase64URL(s, Math.floor((s.length * 3) / 4))))
  } catch {
    invalid(`the ${what} is not JSON`)
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) invalid(`the ${what} is not an object`)
  return value as Record<string, unknown>
}

function optional<T>(claims: Record<string, unknown>, name: string, ok: (v: unknown) => v is T): T | undefined {
  const v = claims[name]
  if (v === undefined) return undefined
  if (!ok(v)) invalid(`${name} has the wrong type`)
  return v
}

const isString = (v: unknown): v is string => typeof v === 'string'
const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v)
const isBool = (v: unknown): v is boolean => typeof v === 'boolean'
const isStrings = (v: unknown): v is string[] => Array.isArray(v) && v.every(isString)

/**
 * checkIdToken decodes a compact JWS without verifying it and checks its
 * header and claims against the flow, or throws RPError('id_token_invalid').
 */
export function checkIdToken(jws: unknown, want: IdTokenExpectations): IdClaims {
  if (typeof jws !== 'string') invalid('not a string')
  if (jws.length > MAX_TOKEN_LEN) invalid('longer than any token the issuer writes')
  const parts = jws.split('.')
  if (parts.length !== 3 || parts[2].length !== SIGNATURE_B64_LEN || !isBase64URL(parts[2])) {
    invalid('not a compact ES256 JWS')
  }
  const header = segment(parts[0], 'header')
  const kid = header['kid']
  if (
    Object.keys(header).sort().join() !== 'alg,kid,typ' ||
    header['alg'] !== 'ES256' ||
    header['typ'] !== 'JWT' ||
    typeof kid !== 'string' ||
    kid.length !== THUMBPRINT_B64_LEN ||
    !isBase64URL(kid)
  ) {
    invalid('the header is not the one the issuer writes')
  }
  const c = segment(parts[1], 'payload')

  if (c['iss'] !== want.issuer) invalid('iss is not the issuer')
  // aud is the client_id as a string; an array is not this issuer's.
  if (c['aud'] !== want.clientId) invalid('aud is not this client')
  if (typeof c['nonce'] !== 'string' || c['nonce'] !== want.nonce) invalid('nonce is not the flow nonce')
  if (!isSub(c['sub'])) invalid('sub is not an account id')
  const iat = c['iat']
  const exp = c['exp']
  if (!isInt(iat) || !isInt(exp)) invalid('iat or exp is not an integer')
  if (exp <= iat) invalid('exp is not after iat')
  if (exp - iat > MAX_LIFETIME_S) invalid('the lifetime is longer than the issuer gives')

  const productKey = optional(c, 'product_key', isString)
  const productKeyId = optional(c, 'product_key_id', isString)
  if (productKey !== undefined || productKeyId !== undefined || want.wantKey || want.product !== null) {
    if (productKey === undefined || productKeyId === undefined) invalid('product_key and product_key_id go together')
    try {
      fromBase64URL(productKey, 32)
    } catch {
      invalid('product_key is not 32 bytes of base64url')
    }
    if (!isProductKeyId(productKeyId)) invalid('product_key_id is not product:epoch')
    if (want.product !== null && productKeyId.slice(0, productKeyId.indexOf(':')) !== want.product) {
      invalid('product_key_id does not name this product')
    }
  }

  const claims: IdClaims = { iss: want.issuer, sub: c['sub'] as string, aud: want.clientId, iat, exp, nonce: want.nonce }
  const authTime = optional(c, 'auth_time', isInt)
  const jti = optional(c, 'jti', isString)
  const amr = optional(c, 'amr', isStrings)
  const email = optional(c, 'email', isString)
  const emailVerified = optional(c, 'email_verified', isBool)
  const name = optional(c, 'name', isString)
  const locale = optional(c, 'locale', isString)
  if (authTime !== undefined) claims.auth_time = authTime
  if (jti !== undefined) claims.jti = jti
  if (amr !== undefined) claims.amr = [...amr]
  if (email !== undefined) claims.email = email
  if (emailVerified !== undefined) claims.email_verified = emailVerified
  if (name !== undefined) claims.name = name
  if (locale !== undefined) claims.locale = locale
  if (productKey !== undefined) claims.product_key = productKey
  if (productKeyId !== undefined) claims.product_key_id = productKeyId
  return claims
}
