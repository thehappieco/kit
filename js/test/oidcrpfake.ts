// A fake id. for the relying party's specs (oidc-rp.spec.ts): it plays the
// id. page (it reads the authorization request, seals the product key with
// the kit's own deliverProductKey, and redirects back with code, state and
// iss) and the token endpoint (it redeems a code once, checks PKCE, and
// answers the token response's JSON). Every answer can be bent by a test to
// produce one failure.
//
// It also gives the specs what a browser would: in Node a location and a
// history (fake-indexeddb is the IndexedDB there); in a real browser the
// page's own location, which cannot be replaced, so the client's origin is
// the test page's (http on localhost, a development origin the module
// accepts), and a history whose replaceState is recorded.
//
// Ported from the platform's web/test/oidc-rp/fakeid.ts at 4476bf4.

import { vi } from 'vitest'

import { toBase64URL } from '../src/bytes.js'
import { DB_NAME, STORE } from '../src/oidc-rp.js'
import { deliverProductKey, pkceChallenge, productPublicKey } from '../src/profiles/platform.js'

/** IN_BROWSER is true in the browser job, where location is the test page's own. */
export const IN_BROWSER = typeof document !== 'undefined'

export const ISSUER = 'http://id.thehappie.localhost:8290'
export const ORIGIN = IN_BROWSER ? globalThis.location.origin : 'http://fakeproduct.thehappie.localhost:8292'
export const CLIENT_ID = 'fakeproduct'
export const REDIRECT_URI = `${ORIGIN}/auth/callback`
export const POST_LOGOUT_REDIRECT_URI = `${ORIGIN}/`
export const TOKEN_ENDPOINT = `${ISSUER}/oauth2/token`
export const SUB = '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b'
export const PRODUCT = 'wappie'
export const EPOCH = 1

/** ROOT is the test account's root, made up for these tests. */
export const ROOT = new Uint8Array(32).map((_, i) => 0x3c ^ (i * 11))

export const random = (n: number) => crypto.getRandomValues(new Uint8Array(n))

/** Authorization is the request begin built, as id. reads it. */
export interface Authorization {
  params: URLSearchParams
  state: string
  nonce: string
  codeChallenge: string
  akdPub: string | null
  scope: string
}

export function readAuthorization(url: string): Authorization {
  const u = new URL(url)
  if (u.origin + u.pathname !== `${ISSUER}/oauth2/authorize`) throw new Error('not the authorization endpoint')
  const p = u.searchParams
  const get = (name: string): string => {
    const all = p.getAll(name)
    if (all.length !== 1) throw new Error(`${name} is not given once`)
    return all[0]
  }
  return { params: p, state: get('state'), nonce: get('nonce'), codeChallenge: get('code_challenge'), akdPub: p.has('akd_pub') ? get('akd_pub') : null, scope: get('scope') }
}

/** KID has the shape of an RFC 7638 thumbprint, as the issuer writes it. */
export const KID = toBase64URL(new Uint8Array(32).fill(0x4b))

/** jws is a compact JWS with the issuer's header and a 64-byte signature nobody checks. */
export function jws(payload: unknown, header: unknown = { alg: 'ES256', kid: KID, typ: 'JWT' }): string {
  const part = (v: unknown): string => toBase64URL(new TextEncoder().encode(JSON.stringify(v)) as Uint8Array<ArrayBuffer>)
  return `${part(header)}.${part(payload)}.${toBase64URL(random(64))}`
}

interface Issued {
  auth: Authorization
  claims: Record<string, unknown>
  sealed: string | undefined
  used: boolean
}

export interface TokenRequest {
  url: string
  init: RequestInit
  form: URLSearchParams
}

/** Bends, each optional, that a test sets before the step they change. */
export interface Bends {
  /** Seal something other than the page would (another root, flow or recipient). */
  seal?: (auth: Authorization) => Promise<string>
  /** Change the ID token's claims. */
  claims?: (claims: Record<string, unknown>) => Record<string, unknown>
  /** Replace the ID token altogether. */
  idToken?: (claims: Record<string, unknown>) => string
  /** Change the token response body, or answer something else entirely. */
  token?: (body: Record<string, unknown>) => Record<string, unknown> | Response
  /** Make the token request fail at the network level. */
  networkError?: boolean
  /** Deliver for another product, root or epoch, consistently in the ID token and the blob. */
  product?: { root: Uint8Array; product: string; epoch: number }
}

export class FakeId {
  readonly bends: Bends = {}
  readonly tokenRequests: TokenRequest[] = []
  readonly accessTokens: string[] = []
  private readonly issued = new Map<string, Issued>()

  /**
   * authorize plays the id. page for one request: login, unlock and, with
   * account_key, the seal. It returns the callback URL id. redirects to.
   */
  async authorize(url: string): Promise<string> {
    const auth = readAuthorization(url)
    const now = Math.floor(Date.now() / 1000)
    const key = this.bends.product ?? { root: ROOT, product: PRODUCT, epoch: EPOCH }
    let claims: Record<string, unknown> = {
      iss: ISSUER,
      sub: SUB,
      aud: CLIENT_ID,
      iat: now,
      exp: now + 300,
      auth_time: now - 30,
      nonce: auth.nonce,
      jti: toBase64URL(random(16)),
      amr: ['pwd'],
      email: 'ana@example.com',
      email_verified: true,
      locale: 'pt-BR',
      // A client with a product gets its product key in the ID token
      // whether or not it asked for the key.
      product_key: toBase64URL(await productPublicKey(key.root, key.product, key.epoch)),
      product_key_id: `${key.product}:${key.epoch}`,
    }
    let sealed: string | undefined
    if (auth.akdPub !== null) {
      const binding = { issuer: ISSUER, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, sub: SUB, codeChallenge: auth.codeChallenge, nonce: auth.nonce }
      const delivered = await deliverProductKey({ root: key.root, product: key.product, epoch: key.epoch, akdPub: auth.akdPub, binding })
      sealed = this.bends.seal === undefined ? delivered.akd_sealed : await this.bends.seal(auth)
      if (delivered.product_key !== claims['product_key'] || delivered.product_key_id !== claims['product_key_id']) {
        throw new Error('the page sealed another product key than the ID token names')
      }
    }
    if (this.bends.claims !== undefined) claims = this.bends.claims(claims)
    const code = `thid_c_${toBase64URL(random(32))}`
    this.issued.set(code, { auth, claims, sealed, used: false })
    const back = new URL(REDIRECT_URI)
    back.searchParams.set('code', code)
    back.searchParams.set('state', auth.state)
    back.searchParams.set('iss', ISSUER)
    return back.href
  }

  /** fetch is the token endpoint, for vi.stubGlobal('fetch', id.fetch). */
  readonly fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = String(input)
    const form = new URLSearchParams(typeof init?.body === 'string' ? init.body : '')
    this.tokenRequests.push({ url, init: init ?? {}, form })
    if (this.bends.networkError === true) throw new TypeError('Failed to fetch')
    if (url !== TOKEN_ENDPOINT || init?.method !== 'POST') return json(404, { error: 'invalid_request' })
    const issued = this.issued.get(form.get('code') ?? '')
    if (issued === undefined || issued.used) return json(400, { error: 'invalid_grant', error_description: 'the code is not valid' })
    issued.used = true
    if (
      form.get('grant_type') !== 'authorization_code' ||
      form.get('client_id') !== CLIENT_ID ||
      form.get('redirect_uri') !== REDIRECT_URI ||
      (await pkceChallenge(form.get('code_verifier') ?? '').catch(() => '')) !== issued.auth.codeChallenge
    ) {
      return json(400, { error: 'invalid_grant', error_description: 'the code is not valid' })
    }
    const accessToken = `thid_at_${toBase64URL(random(32))}`
    this.accessTokens.push(accessToken)
    let body: Record<string, unknown> = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 300,
      scope: issued.auth.scope,
      id_token: this.bends.idToken === undefined ? jws(issued.claims) : this.bends.idToken(issued.claims),
    }
    if (issued.sealed !== undefined) body = { ...body, account_key_sealed: issued.sealed }
    if (this.bends.token !== undefined) {
      const bent = this.bends.token(body)
      if (bent instanceof Response) return bent
      body = bent
    }
    return json(200, body)
  })
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } })
}

/**
 * Browser is the part of window the relying party touches besides
 * IndexedDB and fetch: location and history. visit() puts a URL in the
 * address bar; replaceState records what the page replaced it with. In a
 * real browser only history is replaced, and visit() only records the URL.
 */
export class Browser {
  href = `${ORIGIN}/`
  readonly replaced: string[] = []

  readonly location = {
    get origin(): string {
      return ORIGIN
    },
    href: '',
    pathname: '',
    search: '',
  }

  readonly history = {
    state: null as unknown,
    replaceState: (state: unknown, _unused: string, url?: string | URL | null): void => {
      this.history.state = state
      if (url !== undefined && url !== null) {
        this.replaced.push(String(url))
        this.visit(new URL(String(url), this.href).href)
      }
    },
  }

  constructor() {
    this.visit(this.href)
  }

  visit(href: string): void {
    const u = new URL(href)
    this.href = u.href
    this.location.href = u.href
    this.location.pathname = u.pathname
    this.location.search = u.search
  }
}

// ---------------------------------------------------------------------------
// Direct access to the flow store, as a test (or a hostile script on the
// same origin) would have it.
// ---------------------------------------------------------------------------

function openStore(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME)
    req.onupgradeneeded = () => req.result.createObjectStore(STORE)
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

/** storedFlows returns every [key, value] in thehappie-rp / flows. */
export async function storedFlows(): Promise<[IDBValidKey, unknown][]> {
  const db = await openStore()
  try {
    return await new Promise((resolve, reject) => {
      const out: [IDBValidKey, unknown][] = []
      const tx = db.transaction(STORE, 'readonly')
      const req = tx.objectStore(STORE).openCursor()
      req.onsuccess = () => {
        const c = req.result
        if (c === null) return
        out.push([c.key, c.value])
        c.continue()
      }
      tx.oncomplete = () => resolve(out)
      tx.onerror = () => reject(tx.error)
    })
  } finally {
    db.close()
  }
}

/** storeFlow writes a value under a key, bypassing the relying party. */
export async function storeFlow(key: string, value: unknown): Promise<void> {
  const db = await openStore()
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite')
      tx.objectStore(STORE).put(value, key)
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(tx.error)
    })
  } finally {
    db.close()
  }
}

/** clearDatabase deletes thehappie-rp, for a fresh store in a real browser. */
export function clearDatabase(): Promise<void> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase(DB_NAME)
    req.onsuccess = () => resolve()
    req.onerror = () => reject(req.error)
    req.onblocked = () => reject(new Error('deleting the flow store is blocked'))
  })
}
