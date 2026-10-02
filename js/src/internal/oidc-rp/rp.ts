// The relying party of the platform's id. (SPEC section 11.14): what a
// product's page runs to sign a person in with id. and, when it asks for
// it, to receive the product key sealed to that page alone.
//
// The rule it enforces: a callback completes only the flow this page began,
// once, within 10 minutes, from this issuer; a product key comes out of it
// only when it opens with that flow's ephemeral key and is the private half
// of the product_key the ID token names; and finishSignIn and
// keepProductKey hand that key to the product's storage only when the
// product's own server has named the same sub, product_key_id and
// product_key, because HPKE base mode does not authenticate the sender (an
// ID token and a blob that agree can both be someone else's). Any failure
// throws an RPError and leaves no state that holds a key: the flow is
// deleted before the code is exchanged, whatever happens next, and a key
// that fails a check is zeroed before the error is thrown.
//
// Product-neutral: its parameters are the issuer, the client_id, the
// redirect URI, the scopes and the product's key label. It depends on
// nothing but the kit, WebCrypto, IndexedDB and fetch.
//
// From the platform's web/shared/oidc-rp/index.ts at 4476bf4, with the
// product's key label, keepProductKey, finishSignIn and logoutURL added.

import { equal, encodeUTF8, fromBase64URL, isBase64URL, toBase64URL, type Bytes } from '../../bytes.js'
import { isPlatformError, RPError, type OAuthError } from '../../errors.js'
import { canonicalJSON } from '../../jcs.js'
import { openProductKey } from '../platform/keydelivery.js'
import { newCodeVerifier, pkceChallenge } from '../platform/pkce.js'
import { isProduct } from '../platform/productkey.js'
import { generateX25519KeyPair, importX25519PrivateKey, x25519PublicFromKey } from '../platform/x25519.js'
import { zero } from '../zero.js'
import { deleteFlow, putFlow, takeFlow, type FlowRecord } from './flows.js'
import { checkIdToken, type IdClaims } from './idtoken.js'

/** FLOW_AAD_LABEL opens the AAD that binds a sealed ephemeral key to its flow. */
export const FLOW_AAD_LABEL = 'thehappie-rp/flow'

const IV_LEN = 12
const EPH_LEN = 32
const SEALED_EPH_LEN = EPH_LEN + 16

// The AAD string set of section 11.1: the client id and the redirect URI end
// up in the key-delivery AAD, so a value outside it would start a flow that
// can never open.
const AAD_STRING = /^[A-Za-z0-9._:/|@-]+$/
const SCOPE_TOKEN = /^[\x21\x23-\x5b\x5d-\x7e]+$/
const ACCESS_TOKEN = /^thid_at_[A-Za-z0-9_-]{43}$/
// state is 32 random bytes in base64url (section 11.14, begin step 1).
const STATE = /^[A-Za-z0-9_-]{43}$/
// A logout state is one of the authorization request's: 1 to 512 visible ASCII characters.
const LOGOUT_STATE = /^[\x21-\x7e]{1,512}$/

const OAUTH_ERRORS: readonly OAuthError[] = [
  'access_denied',
  'login_required',
  'interaction_required',
  'consent_required',
  'invalid_request',
  'invalid_scope',
  'unsupported_response_type',
  'unauthorized_client',
  'server_error',
  'temporarily_unavailable',
  'invalid_client',
  'invalid_grant',
  'unsupported_grant_type',
]

/** oauthError narrows a server-supplied error value to the known set. */
function oauthError(v: unknown): OAuthError {
  return typeof v === 'string' && (OAUTH_ERRORS as readonly string[]).includes(v) ? (v as OAuthError) : 'unknown'
}

function isState(s: unknown): s is string {
  return typeof s === 'string' && STATE.test(s)
}

const random = (n: number) => crypto.getRandomValues(new Uint8Array(n)) as Bytes

/** BeginOptions are what begin takes: the product's constants and this sign-in's choices. */
export interface BeginOptions {
  /** The issuer, exactly: an origin such as https://id.thehappie.co. */
  issuer: string
  clientId: string
  /** The client's registered redirect URI, on this page's origin. */
  redirectUri: string
  /** Space-separated scopes; must include openid. account_key is added when wantKey is set. */
  scope: string
  /** Ask for the product key (scope account_key and akd_pub). */
  wantKey: boolean
  /**
   * The product's key label, the product of product_key_id (for example
   * "wappie" for "wappie:1"). Required when wantKey is set; when given, the
   * ID token's product_key_id must name it.
   */
  product?: string
  /** Where to go after the callback: a same-origin path such as "/inbox". */
  returnTo: string
  loginHint?: string
  prompt?: 'none' | 'login'
  /** ui_locales, for example "pt-BR". */
  uiLocales?: string
}

/** CallbackOptions are what the page knows without the flow. */
export interface CallbackOptions {
  issuer: string
  clientId: string
}

/** CallbackResult is what a completed flow gives the page. */
export interface CallbackResult {
  /** The single-use access token, for the product's server to take to userinfo (section 11.15). */
  accessToken: string
  idClaims: IdClaims
  /**
   * sk_p, 32 bytes, with key delivery only. Keep it only once the product's
   * server has named it (keepProductKey); zero this copy in every case.
   */
  productKey?: Uint8Array
  /** The flow's same-origin path. */
  returnTo: string
}

/**
 * PinnedKey is the product's server's answer to its page after an accepted
 * login (section 11.15, step 7; Go's oidcrp.Answer): the sub, the
 * product_key_id and the product_key (base64url) it pinned and accepted.
 */
export interface PinnedKey {
  sub: string
  product_key_id: string
  product_key: string
}

/** FinishOptions are callback's, and the product's two calls. */
export interface FinishOptions extends CallbackOptions {
  /**
   * session sends the access token to the product's own server, which runs
   * section 11.15 and resolves with the pinned triple, or rejects when it
   * refused the login (account_key_changed included).
   */
  session: (accessToken: string, idClaims: IdClaims) => Promise<PinnedKey>
  /**
   * store keeps the product key in the product's vault. It is called only
   * after the server's answer matched, and must copy the key or be done
   * with it when it resolves: the key is zeroed then.
   */
  store: (productKey: Uint8Array, pinned: PinnedKey) => Promise<void> | void
}

/** FinishResult is what a finished sign-in gives the page. */
export interface FinishResult {
  idClaims: IdClaims
  pinned: PinnedKey
  returnTo: string
  /** Whether a delivered key was handed to store. */
  keyStored: boolean
}

// ---------------------------------------------------------------------------
// Arguments. These are the page's own constants, so a bad one is a
// programming error (TypeError), not an RPError.
// ---------------------------------------------------------------------------

/** A development origin may be plain http: a *.localhost name or a loopback address. */
function devHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname.endsWith('.localhost') || hostname === '127.0.0.1' || hostname === '[::1]'
}

function secureURL(u: URL): boolean {
  return u.protocol === 'https:' || (u.protocol === 'http:' && devHost(u.hostname))
}

function pageOrigin(): string | undefined {
  const here = (globalThis as { location?: { origin?: string } }).location?.origin
  return here === undefined || here === 'null' ? undefined : here
}

function checkIssuer(issuer: unknown): string {
  let u: URL | undefined
  try {
    u = typeof issuer === 'string' ? new URL(issuer) : undefined
  } catch {
    u = undefined
  }
  if (u === undefined || u.origin !== issuer || !secureURL(u)) {
    throw new TypeError('the issuer is not an https origin')
  }
  return issuer
}

function checkClientId(clientId: unknown): string {
  if (typeof clientId !== 'string' || !AAD_STRING.test(clientId)) throw new TypeError('not a client id')
  return clientId
}

/** checkPageURL is a redirect URI's rule, which a post-logout URI follows too. */
function checkPageURL(raw: unknown, what: string): URL {
  let u: URL | undefined
  try {
    u = typeof raw === 'string' ? new URL(raw) : undefined
  } catch {
    u = undefined
  }
  if (
    u === undefined ||
    u.href !== raw ||
    !secureURL(u) ||
    u.username !== '' ||
    u.password !== '' ||
    u.search !== '' ||
    u.hash !== '' ||
    !AAD_STRING.test(raw as string)
  ) {
    throw new TypeError(`the ${what} is not an absolute https URL in its canonical form`)
  }
  // The callback must land where the flow is stored: this origin's IndexedDB.
  const here = pageOrigin()
  if (here !== undefined && here !== u.origin) {
    throw new TypeError(`the ${what} is not on the origin of this page`)
  }
  return u
}

function buildScope(scope: unknown, wantKey: boolean): string {
  if (typeof scope !== 'string') throw new TypeError('the scope is not a string')
  const tokens = scope.split(' ')
  if (tokens.some((t) => !SCOPE_TOKEN.test(t)) || new Set(tokens).size !== tokens.length) {
    throw new TypeError('the scope is not space-separated tokens without repeats')
  }
  if (!tokens.includes('openid')) throw new TypeError('the scope does not include openid')
  const hasKey = tokens.includes('account_key')
  if (hasKey && !wantKey) throw new TypeError('account_key is in the scope but wantKey is not set')
  if (wantKey && !hasKey) tokens.push('account_key')
  return tokens.join(' ')
}

/**
 * sameOriginPath returns p as a path on origin, normalised the way the URL
 * parser reads it, or null when it is not one: a scheme, a host ("//x" or
 * "/\x", which browsers read as "//x"), a control character, or a path
 * whose dot segments resolve to "//x". The result never starts with "//",
 * so location.assign(result) cannot leave the origin.
 */
export function sameOriginPath(p: unknown, origin: string): string | null {
  if (typeof p !== 'string' || !p.startsWith('/') || p.startsWith('//') || p.includes('\\')) return null
  if (/[\u0000-\u001f\u007f]/.test(p)) return null
  let u: URL
  try {
    u = new URL(p, origin)
  } catch {
    return null
  }
  if (u.origin !== origin) return null
  const out = u.pathname + u.search + u.hash
  if (!out.startsWith('/') || out.startsWith('//')) return null
  return out
}

/** flowAAD binds a sealed ephemeral key to its client and state (section 11.14, begin step 2). */
function flowAAD(clientId: string, state: string): Bytes {
  return encodeUTF8(canonicalJSON([FLOW_AAD_LABEL, 1, clientId, state]))
}

// ---------------------------------------------------------------------------
// begin
// ---------------------------------------------------------------------------

/**
 * begin starts an authorization request (section 11.14, begin): it stores
 * the flow and returns the authorization URL, which the caller navigates to
 * with location.assign. With wantKey, which needs the product's key label,
 * the ephemeral X25519 private key is stored only sealed under a fresh
 * non-extractable AES-256-GCM key, and its raw bytes are zeroed before this
 * returns. Arguments outside the rules throw TypeError before anything is
 * stored.
 */
export async function begin(o: BeginOptions): Promise<string> {
  if (typeof o !== 'object' || o === null) throw new TypeError('no options')
  const issuer = checkIssuer(o.issuer)
  const clientId = checkClientId(o.clientId)
  const redirect = checkPageURL(o.redirectUri, 'redirect URI')
  const wantKey = o.wantKey === true
  const scope = buildScope(o.scope, wantKey)
  const returnTo = sameOriginPath(o.returnTo, redirect.origin)
  if (returnTo === null) throw new TypeError('returnTo is not a same-origin path')
  if (o.product !== undefined && !isProduct(o.product)) throw new TypeError('the product is not a product id')
  // The key's label: without it, a key delivered for another product of
  // this client would not be told apart.
  if (wantKey && o.product === undefined) throw new TypeError('a key request needs the product')
  if (o.prompt !== undefined && o.prompt !== 'none' && o.prompt !== 'login') throw new TypeError('prompt is none or login')
  // A key-delivery request always asks for an unlock, so prompt=none can
  // only come back as interaction_required; refuse it here rather than
  // store a flow that cannot complete.
  if (o.prompt === 'none' && wantKey) throw new TypeError('prompt=none cannot deliver a key')
  for (const [name, v] of [['loginHint', o.loginHint], ['uiLocales', o.uiLocales]] as const) {
    if (v !== undefined && typeof v !== 'string') throw new TypeError(`${name} is not a string`)
  }

  const state = toBase64URL(random(32))
  const nonce = toBase64URL(random(32))
  const codeVerifier = newCodeVerifier()
  const codeChallenge = await pkceChallenge(codeVerifier)

  let akdPub: string | null = null
  let aesKey: CryptoKey | null = null
  let iv: Bytes | null = null
  let sealedEph: Bytes | null = null
  if (wantKey) {
    const pair = await generateX25519KeyPair()
    try {
      aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
      iv = random(IV_LEN)
      sealedEph = new Uint8Array(
        await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: flowAAD(clientId, state), tagLength: 128 }, aesKey, pair.privateKey),
      )
      akdPub = toBase64URL(pair.publicKey)
    } finally {
      zero(pair.privateKey)
    }
  }

  const now = Date.now()
  const record: FlowRecord = {
    v: 1,
    client_id: clientId,
    redirect_uri: redirect.href,
    product: o.product ?? null,
    nonce,
    code_verifier: codeVerifier,
    akd_pub: akdPub,
    aes_key: aesKey,
    iv,
    sealed_eph: sealedEph,
    return_to: returnTo,
    created_at: now,
  }
  await putFlow(state, record, now)

  const params = new URLSearchParams()
  params.set('response_type', 'code')
  params.set('client_id', clientId)
  params.set('redirect_uri', redirect.href)
  params.set('scope', scope)
  params.set('state', state)
  params.set('nonce', nonce)
  params.set('code_challenge', codeChallenge)
  params.set('code_challenge_method', 'S256')
  if (akdPub !== null) params.set('akd_pub', akdPub)
  if (o.prompt !== undefined) params.set('prompt', o.prompt)
  if (o.loginHint !== undefined && o.loginHint !== '') params.set('login_hint', o.loginHint)
  if (o.uiLocales !== undefined && o.uiLocales !== '') params.set('ui_locales', o.uiLocales)
  const url = new URL('/oauth2/authorize', issuer)
  url.search = params.toString()
  return url.href
}

// ---------------------------------------------------------------------------
// callback
// ---------------------------------------------------------------------------

/** single is a parameter given once, undefined when absent, null when repeated. */
function single(q: URLSearchParams, name: string): string | undefined | null {
  const all = q.getAll(name)
  if (all.length === 0) return undefined
  return all.length === 1 ? all[0] : null
}

/**
 * dropQuery takes the code and state out of the address bar and the
 * session history (callback step 1), before anything can fail, so neither
 * survives a reload, a bookmark or a Referer.
 */
function dropQuery(): void {
  const g = globalThis as { history?: History; location?: Location }
  const h = g.history
  const l = g.location
  if (h === undefined || l === undefined || l.search === '') return
  try {
    h.replaceState(h.state, '', l.pathname)
  } catch {
    // An opaque or sandboxed document: nothing to drop.
  }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

interface TokenResponse {
  accessToken: string
  idToken: string
  sealed: string | undefined
}

/** exchange redeems the code (callback step 5: CORS with credentials, never cached or redirected). */
async function exchange(issuer: string, flow: FlowRecord, code: string): Promise<TokenResponse> {
  const body = new URLSearchParams()
  body.set('grant_type', 'authorization_code')
  body.set('code', code)
  body.set('redirect_uri', flow.redirect_uri)
  body.set('client_id', flow.client_id)
  body.set('code_verifier', flow.code_verifier)
  let res: Response
  try {
    res = await fetch(new URL('/oauth2/token', issuer).href, {
      method: 'POST',
      mode: 'cors',
      // The bind cookie goes with it: it is what ties the code to this browser.
      credentials: 'include',
      cache: 'no-store',
      redirect: 'error',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    })
  } catch {
    throw new RPError('token_error', 'the token request failed')
  }
  let json: unknown
  try {
    json = await res.json()
  } catch {
    json = undefined
  }
  if (res.status !== 200) {
    throw new RPError('token_error', `the token endpoint answered ${res.status}`, oauthError(isObject(json) ? json['error'] : undefined))
  }
  if (!isObject(json)) throw new RPError('token_error', 'the token response is not a JSON object')
  const accessToken = json['access_token']
  const tokenType = json['token_type']
  const idToken = json['id_token']
  const sealed = json['account_key_sealed']
  if (typeof accessToken !== 'string' || !ACCESS_TOKEN.test(accessToken)) throw new RPError('token_error', 'no access token')
  if (typeof tokenType !== 'string' || tokenType.toLowerCase() !== 'bearer') throw new RPError('token_error', 'the token type is not Bearer')
  if (typeof idToken !== 'string') throw new RPError('token_error', 'no ID token')
  const wantKey = flow.akd_pub !== null
  if (wantKey && typeof sealed !== 'string') throw new RPError('token_error', 'no sealed key')
  if (!wantKey && sealed !== undefined) throw new RPError('token_error', 'a sealed key nobody asked for')
  return { accessToken, idToken, sealed: wantKey ? (sealed as string) : undefined }
}

/**
 * openFlowKey opens the flow's ephemeral private key and imports it
 * non-extractable; the raw bytes are zeroed before it returns. It checks
 * that the key is the one whose public half went out as akd_pub.
 */
async function openFlowKey(flow: FlowRecord, state: string): Promise<CryptoKey> {
  if (
    flow.aes_key === null ||
    flow.iv === null ||
    flow.sealed_eph === null ||
    flow.akd_pub === null ||
    flow.iv.length !== IV_LEN ||
    flow.sealed_eph.length !== SEALED_EPH_LEN
  ) {
    throw new RPError('key_open_failed', 'the flow has no sealed ephemeral key')
  }
  let raw: Uint8Array | undefined
  try {
    raw = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(flow.iv), additionalData: flowAAD(flow.client_id, state), tagLength: 128 },
        flow.aes_key,
        new Uint8Array(flow.sealed_eph),
      ),
    )
    if (raw.length !== EPH_LEN) throw new Error('not an X25519 key')
    const key = await importX25519PrivateKey(raw)
    const pub = await x25519PublicFromKey(key)
    if (!equal(pub, fromBase64URL(flow.akd_pub, EPH_LEN))) throw new Error('not the key akd_pub named')
    return key
  } catch {
    throw new RPError('key_open_failed', 'the ephemeral key does not open')
  } finally {
    zero(raw)
  }
}

/**
 * callback completes a flow (section 11.14, callback steps 1 to 7) from the
 * URL the authorization server redirected to. In order: it drops the query
 * from the address bar; checks iss; takes the flow by state, which deletes
 * it; passes on an error response as authorization_error; exchanges the
 * code; checks the ID token; and, with key delivery, opens the product key
 * and checks it against the ID token's product_key. It stores nothing that
 * holds a key.
 *
 * Steps 8 to 10 are finishSignIn's, which a product should call instead:
 * the key returned here must not be kept before the product's server has
 * named it (keepProductKey), and the caller zeroes it in every case.
 */
export async function callback(url: string | URL, o: CallbackOptions): Promise<CallbackResult> {
  dropQuery()
  if (typeof o !== 'object' || o === null) throw new TypeError('no options')
  const issuer = checkIssuer(o.issuer)
  const clientId = checkClientId(o.clientId)
  const q = new URL(String(url), (globalThis as { location?: { href?: string } }).location?.href).searchParams
  const iss = single(q, 'iss')
  const state = single(q, 'state')
  const code = single(q, 'code')
  const error = single(q, 'error')

  // RFC 9207: a response that is not from this issuer is not read further.
  // Its flow, if the state names one, can no longer complete; delete it.
  if (iss !== issuer) {
    if (isState(state)) await deleteFlow(state).catch(() => undefined)
    throw new RPError('iss_mismatch')
  }

  // begin writes 43 characters; anything else names no flow and is not
  // worth a look-up.
  if (!isState(state)) throw new RPError('state_unknown')
  let flow: FlowRecord | null
  try {
    flow = await takeFlow(state, Date.now())
  } catch {
    throw new RPError('state_unknown', 'the flow store is unavailable')
  }
  if (flow === null || flow.client_id !== clientId) throw new RPError('state_unknown')

  if (error !== undefined) throw new RPError('authorization_error', undefined, oauthError(error))
  if (typeof code !== 'string' || code === '') throw new RPError('token_error', 'no code')

  const token = await exchange(issuer, flow, code)
  const wantKey = flow.akd_pub !== null
  const idClaims = checkIdToken(token.idToken, { issuer, clientId, nonce: flow.nonce, wantKey, product: flow.product })
  const returnTo = sameOriginPath(flow.return_to, new URL(flow.redirect_uri).origin) ?? '/'
  if (!wantKey) return { accessToken: token.accessToken, idClaims, returnTo }

  const key = await openFlowKey(flow, state)
  let productKey: Bytes
  try {
    productKey = await openProductKey(key, token.sealed as string, {
      issuer,
      clientId: flow.client_id,
      redirectUri: flow.redirect_uri,
      sub: idClaims.sub,
      productKeyId: idClaims.product_key_id as string,
      productKey: fromBase64URL(idClaims.product_key as string, 32),
      codeChallenge: await pkceChallenge(flow.code_verifier),
      nonce: flow.nonce,
    })
  } catch (err) {
    if (isPlatformError(err, 'product_key')) throw new RPError('key_mismatch', 'the opened key is not the product key')
    throw new RPError('key_open_failed', 'the sealed product key does not open')
  }
  return { accessToken: token.accessToken, idClaims, productKey, returnTo }
}

// ---------------------------------------------------------------------------
// After the product's server has answered (callback steps 8 to 10)
// ---------------------------------------------------------------------------

/** checkPinned reads the server's answer: three strings, product_key the strict base64url of 32 bytes. */
function checkPinned(pinned: unknown): PinnedKey {
  if (!isObject(pinned)) throw new RPError('pin_mismatch', 'the server\'s answer is not an object')
  const { sub, product_key_id: productKeyId, product_key: productKey } = pinned
  if (typeof sub !== 'string' || typeof productKeyId !== 'string' || typeof productKey !== 'string') {
    throw new RPError('pin_mismatch', 'the server\'s answer does not name a sub, a product_key_id and a product_key')
  }
  if (productKey.length !== 43 || !isBase64URL(productKey)) throw new RPError('pin_mismatch', 'the server\'s product_key is not 32 bytes')
  return { sub, product_key_id: productKeyId, product_key: productKey }
}

/**
 * keepProductKey is section 11.14, step 9: it calls store with the
 * delivered key only when the product's server's answer names the ID
 * token's sub and product_key_id and the public half of the key, the last
 * compared in constant time, and throws RPError('pin_mismatch') otherwise.
 * HPKE base mode does not authenticate the sender: anyone who knows akd_pub
 * can seal a key that opens and matches an ID token they also write, so
 * this comparison with the server's insert-only pin is what stops a
 * substituted key. result.productKey is zeroed on every path, once store
 * has resolved or thrown. A result without a key is a TypeError.
 */
export async function keepProductKey(result: CallbackResult, pinned: PinnedKey, store: FinishOptions['store']): Promise<void> {
  const sk = result?.productKey
  try {
    if (!(sk instanceof Uint8Array)) throw new TypeError('the result holds no product key')
    if (typeof store !== 'function') throw new TypeError('store is not a function')
    const p = checkPinned(pinned)
    if (p.sub !== result.idClaims.sub) throw new RPError('pin_mismatch', 'the server pinned another account')
    if (p.product_key_id !== result.idClaims.product_key_id) throw new RPError('pin_mismatch', 'the server pinned another product key id')
    let pub: Bytes
    try {
      pub = await x25519PublicFromKey(await importX25519PrivateKey(sk))
    } catch {
      throw new RPError('pin_mismatch', 'the key\'s public half could not be computed')
    }
    if (!equal(pub, fromBase64URL(p.product_key, 32))) throw new RPError('pin_mismatch', 'the server pinned another key')
    await store(sk, p)
  } finally {
    zero(sk)
  }
}

/**
 * finishSignIn is the whole callback (section 11.14, steps 1 to 10): it
 * completes the flow (callback), sends the access token to the product's
 * own server (session), which runs section 11.15 and resolves with the
 * triple it pinned, and, with a delivered key, keeps it through store only
 * when that triple names it (keepProductKey). Without a key, the answer's
 * sub must still be the ID token's. The key never leaves it unzeroed: a
 * rejection from session (account_key_changed included) or from store, and
 * every RPError, leave it zero and stored nowhere.
 *
 * session and store are checked before the flow is touched, so a page
 * misconfigured in development fails without spending a sign-in.
 */
export async function finishSignIn(url: string | URL, o: FinishOptions): Promise<FinishResult> {
  if (typeof o !== 'object' || o === null) throw new TypeError('no options')
  if (typeof o.session !== 'function') throw new TypeError('session is not a function')
  if (typeof o.store !== 'function') throw new TypeError('store is not a function')
  const r = await callback(url, { issuer: o.issuer, clientId: o.clientId })
  try {
    const pinned = checkPinned(await o.session(r.accessToken, r.idClaims))
    if (r.productKey === undefined) {
      if (pinned.sub !== r.idClaims.sub) throw new RPError('pin_mismatch', 'the server pinned another account')
      return { idClaims: r.idClaims, pinned, returnTo: r.returnTo, keyStored: false }
    }
    await keepProductKey(r, pinned, o.store)
    return { idClaims: r.idClaims, pinned, returnTo: r.returnTo, keyStored: true }
  } finally {
    zero(r.productKey)
  }
}

// ---------------------------------------------------------------------------
// Signing out of id.
// ---------------------------------------------------------------------------

/** LogoutOptions are what logoutURL takes. */
export interface LogoutOptions {
  issuer: string
  clientId: string
  /** The client's registered post-logout URI, on this page's origin (its origin and "/"). */
  postLogoutRedirectUri: string
  /** A state to come back with: 1 to 512 visible ASCII characters; by default 32 fresh random bytes in base64url. */
  state?: string
}

/**
 * logoutURL is the GET that ends the person's id. session (section 11.14,
 * "Signing out"), which id. confirms before it signs anybody out and then
 * comes back to postLogoutRedirectUri. It signs nobody out of a product: the
 * product ends its own session.
 */
export function logoutURL(o: LogoutOptions): string {
  if (typeof o !== 'object' || o === null) throw new TypeError('no options')
  const issuer = checkIssuer(o.issuer)
  const clientId = checkClientId(o.clientId)
  const back = checkPageURL(o.postLogoutRedirectUri, 'post-logout redirect URI')
  const state = o.state ?? toBase64URL(random(32))
  if (typeof state !== 'string' || !LOGOUT_STATE.test(state)) throw new TypeError('the state is not 1 to 512 visible ASCII characters')
  const url = new URL('/oauth2/logout', issuer)
  url.searchParams.set('client_id', clientId)
  url.searchParams.set('post_logout_redirect_uri', back.href)
  url.searchParams.set('state', state)
  return url.href
}

export type { IdClaims }
