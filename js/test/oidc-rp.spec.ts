// The relying party's page (SPEC section 11.14, @thehappieco/kit/oidc-rp)
// against a fake id.: begin and callback, every error code, the single use
// of a flow, the 10-minute purge, the product's key label, and what is left
// in IndexedDB and in what the functions return; then keepProductKey and
// finishSignIn, which keep a delivered key only once the product's server
// has named it, and logoutURL.
//
// In Node, IndexedDB is fake-indexeddb, a fresh factory per test, and
// fetch, location and history are stubs (oidcrpfake.ts). In Chromium,
// Firefox and WebKit, IndexedDB is the browser's own, deleted before each
// test (where WebKit's loss of X25519 CryptoKey records is what the AES
// wrapping avoids), fetch and history are stubs, and the client's origin is
// the test page's. Ported from the platform's web/test/oidc-rp/rp.spec.ts at
// 4476bf4.

import { afterEach, beforeEach, describe, expect, expectTypeOf, it, vi } from 'vitest'

import { encodeUTF8, fromBase64URL, toBase64URL, type Bytes } from '../src/bytes.js'
import { HPKEError, isRPError, RPError, type RPErrorCode } from '../src/errors.js'
import { seal as hpkeSeal } from '../src/hpke.js'
import { canonicalJSON } from '../src/jcs.js'
import type { FlowRecord } from '../src/internal/oidc-rp/flows.js'
import {
  begin,
  callback,
  finishSignIn,
  FLOW_AAD_LABEL,
  FLOW_TTL_MS,
  DB_NAME,
  STORE,
  keepProductKey,
  logoutURL,
  sameOriginPath,
  type BeginOptions,
  type CallbackResult,
  type FinishOptions,
  type KeyStore,
  type PinnedKey,
} from '../src/oidc-rp.js'
import { deriveProductKey, generateX25519KeyPair, keyDeliveryAAD, pkceChallenge, productPublicKey, sealProductKey } from '../src/profiles/platform.js'
import {
  Browser,
  clearDatabase,
  CLIENT_ID,
  EPOCH,
  FakeId,
  IN_BROWSER,
  ISSUER,
  jws,
  KID,
  ORIGIN,
  POST_LOGOUT_REDIRECT_URI,
  PRODUCT,
  random,
  readAuthorization,
  REDIRECT_URI,
  ROOT,
  storedFlows,
  storeFlow,
  SUB,
  TOKEN_ENDPOINT,
} from './oidcrpfake.js'
import { withX25519Generation } from './vectors.js'

const fakeIndexedDB = IN_BROWSER ? undefined : await import('fake-indexeddb')

let id: FakeId
let browser: Browser

beforeEach(async () => {
  id = new FakeId()
  browser = new Browser()
  if (fakeIndexedDB !== undefined) {
    vi.stubGlobal('indexedDB', new fakeIndexedDB.IDBFactory())
    vi.stubGlobal('location', browser.location)
  } else {
    await clearDatabase()
  }
  vi.stubGlobal('fetch', id.fetch)
  vi.stubGlobal('history', browser.history)
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

const isZero = (b: Uint8Array) => b.every((x) => x === 0)

function same(a: string | Uint8Array, b: string | Uint8Array, label: string): void {
  const equal = typeof a === 'string' || typeof b === 'string' ? a === b : a.length === b.length && a.every((x, i) => x === b[i])
  if (!equal) expect.fail(`${label}: the values differ (not shown)`)
}

function options(o: Partial<BeginOptions> = {}): BeginOptions {
  return { issuer: ISSUER, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, scope: 'openid email profile', wantKey: true, product: PRODUCT, returnTo: '/inbox', ...o }
}

const CALLBACK = { issuer: ISSUER, clientId: CLIENT_ID }

/** signIn runs begin, the fake id. and the callback, as the browser would. */
async function signIn(o: Partial<BeginOptions> = {}): Promise<CallbackResult> {
  const back = await id.authorize(await begin(options(o)))
  browser.visit(back)
  return callback(back, CALLBACK)
}

/** caught runs fn and returns what it threw, or undefined. */
async function caught(fn: () => Promise<unknown>): Promise<unknown> {
  try {
    await fn()
  } catch (err) {
    return err
  }
  return undefined
}

/** expectRPError asserts that fn rejects with RPError(code); messages never show values. */
async function expectRPError(fn: () => Promise<unknown>, code: RPErrorCode, label = ''): Promise<void> {
  const at = label === '' ? '' : `${label}: `
  const err = await caught(fn)
  if (!isRPError(err)) expect.fail(`${at}expected RPError(${code}), got ${err === undefined ? 'no error' : err instanceof Error ? err.name : typeof err}`)
  expect(err.code, `${at}expected RPError(${code}), got RPError(${err.code})`).toBe(code)
}

/** callbackFailsWith runs a full sign-in that must stop with code, and checks no flow is left. */
async function callbackFailsWith(code: RPErrorCode, o: Partial<BeginOptions> = {}, label = ''): Promise<void> {
  await expectRPError(() => signIn(o), code, label)
  expect(await storedFlows(), `${label}: no flow is left`).toHaveLength(0)
}

const algorithmName = (a: unknown): unknown => (typeof a === 'string' ? a : (a as { name?: unknown } | null)?.name)

/**
 * idTokenRefused runs a sign-in whose ID token a bend has changed and
 * checks that callback refuses it at step 6 (SPEC section 11.14), before
 * step 7 touches any key: id_token_invalid, with nothing decrypted (the
 * flow's ephemeral key stays sealed) and no X25519 key imported, and no
 * flow left. begin and the fake id. are the setup, and a failure there is
 * not reported as the callback's answer.
 */
async function idTokenRefused(label: string, o: Partial<BeginOptions> = {}): Promise<void> {
  const back = await id.authorize(await begin(options(o)))
  browser.visit(back)
  const decrypt = vi.spyOn(crypto.subtle, 'decrypt')
  const importKey = vi.spyOn(crypto.subtle, 'importKey')
  try {
    await expectRPError(() => callback(back, CALLBACK), 'id_token_invalid', label)
    expect(decrypt, `${label}: the flow's ephemeral key was opened`).not.toHaveBeenCalled()
    expect(importKey.mock.calls.filter((c) => algorithmName(c[2]) === 'X25519'), `${label}: an X25519 key was imported`).toHaveLength(0)
  } finally {
    decrypt.mockRestore()
    importKey.mockRestore()
  }
  expect(await storedFlows(), `${label}: no flow is left`).toHaveLength(0)
}

/** sealedEphemeralKey opens a stored flow's ephemeral key, as only a test should. */
async function sealedEphemeralKey(state: string, flow: FlowRecord): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(flow.iv!), additionalData: encodeUTF8(canonicalJSON([FLOW_AAD_LABEL, 1, flow.client_id, state])) },
      flow.aes_key!,
      new Uint8Array(flow.sealed_eph!),
    ),
  )
}

/** containsBytes says whether needle appears anywhere inside haystack. */
function containsBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer
    return true
  }
  return false
}

/** everyByteString lists every byte string and string (as UTF-8) a stored value holds. */
function everyByteString(v: unknown): Uint8Array[] {
  if (v instanceof Uint8Array) return [v]
  if (typeof v === 'string') return [encodeUTF8(v)]
  if (typeof v === 'object' && v !== null && !(v instanceof CryptoKey)) return Object.values(v).flatMap(everyByteString)
  return []
}

/** watchDecrypt keeps, by reference, every AES-GCM plaintext the relying party sees. */
function watchDecrypt(): Uint8Array[] {
  const opened: Uint8Array[] = []
  const decrypt = crypto.subtle.decrypt.bind(crypto.subtle)
  vi.spyOn(crypto.subtle, 'decrypt').mockImplementation(async (...args) => {
    const out = await decrypt(...args)
    opened.push(new Uint8Array(out))
    return out
  })
  return opened
}

/** sealFor seals the test account's product key the way the id. page would, for the flow a describes. */
async function sealFor(
  a: { akdPub: string | null; codeChallenge: string; nonce: string },
  over: Partial<{ issuer: string; clientId: string; redirectUri: string; sub: string }> = {},
): Promise<string> {
  return sealProductKey({
    root: ROOT,
    product: PRODUCT,
    epoch: EPOCH,
    akdPub: a.akdPub!,
    binding: { issuer: ISSUER, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, sub: SUB, codeChallenge: a.codeChallenge, nonce: a.nonce, ...over },
  })
}

describe('begin', () => {
  it('builds the authorization request', async () => {
    const url = await begin(options({ loginHint: 'ana@example.com', prompt: 'login', uiLocales: 'pt-BR' }))
    const a = readAuthorization(url)
    expect(a.params.get('response_type')).toBe('code')
    expect(a.params.get('client_id')).toBe(CLIENT_ID)
    expect(a.params.get('redirect_uri')).toBe(REDIRECT_URI)
    expect(a.scope).toBe('openid email profile account_key')
    expect(a.params.get('code_challenge_method')).toBe('S256')
    expect(a.params.get('prompt')).toBe('login')
    expect(a.params.get('login_hint')).toBe('ana@example.com')
    expect(a.params.get('ui_locales')).toBe('pt-BR')
    // state, nonce and the verifier are 32 random bytes in base64url.
    expect(a.state).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(a.nonce).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(a.codeChallenge).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(fromBase64URL(a.akdPub!, 32).length).toBe(32)
    expect([...a.params.keys()].sort()).toEqual(
      ['akd_pub', 'client_id', 'code_challenge', 'code_challenge_method', 'login_hint', 'nonce', 'prompt', 'redirect_uri', 'response_type', 'scope', 'state', 'ui_locales'].sort(),
    )
  })

  it('asks again for the ephemeral key when the engine fails to generate one', async () => {
    // WebKit on Linux fails 1 generateKey in 256 with an OperationError.
    const asked = await withX25519Generation((call) => (call < 3 ? 'OperationError' : null), () => begin(options()))
    expect(asked.calls).toBe(4)
    const back = await id.authorize(asked.value!)
    browser.visit(back)
    const r = await callback(back, CALLBACK)
    same(r.productKey!, (await deriveProductKey(ROOT, PRODUCT, EPOCH)).sk, 'the product key')
    r.productKey!.fill(0)
    // Four in a row is the engine's error, before anything is stored.
    const refused = await withX25519Generation(() => 'OperationError', () => begin(options()))
    expect(refused.error).toBeInstanceOf(HPKEError)
    expect(((refused.error as HPKEError).cause as DOMException).name).toBe('OperationError')
    expect(refused.calls).toBe(4)
    expect(await storedFlows()).toHaveLength(0)
  })

  it('asks for identity only without akd_pub, and stores no key', async () => {
    const a = readAuthorization(await begin(options({ wantKey: false, product: undefined })))
    expect(a.akdPub).toBeNull()
    expect(a.scope).toBe('openid email profile')
    const [[state, flow]] = (await storedFlows()) as [[string, FlowRecord]]
    expect(state).toBe(a.state)
    expect([flow.akd_pub, flow.aes_key, flow.iv, flow.sealed_eph, flow.product]).toEqual([null, null, null, null, null])
  })

  it('may ask silently for identity only', async () => {
    // A product that already holds the key asks for identity only, which
    // id. may answer without a page.
    const a = readAuthorization(await begin(options({ wantKey: false, prompt: 'none' })))
    expect(a.params.get('prompt')).toBe('none')
    expect(a.akdPub).toBeNull()
    expect(a.scope.split(' ')).not.toContain('account_key')
  })

  it('stores the flow by state, with the ephemeral key only under a non-extractable AES key', async () => {
    // Every PKCS#8 export of the ephemeral key is kept by reference, so the
    // test can see that the page zeroed it.
    const exported: ArrayBuffer[] = []
    const exportKey = crypto.subtle.exportKey.bind(crypto.subtle) as (format: string, key: CryptoKey) => Promise<ArrayBuffer | JsonWebKey>
    vi.spyOn(crypto.subtle, 'exportKey').mockImplementation((async (format: string, key: CryptoKey) => {
      const out = await exportKey(format, key)
      if (format === 'pkcs8') exported.push(out as ArrayBuffer)
      return out
    }) as typeof crypto.subtle.exportKey)
    const encrypted: Uint8Array[] = []
    const encrypt = crypto.subtle.encrypt.bind(crypto.subtle)
    vi.spyOn(crypto.subtle, 'encrypt').mockImplementation(async (algorithm, key, data) => {
      const v = data as ArrayBufferView
      encrypted.push(new Uint8Array(v.buffer, v.byteOffset, v.byteLength))
      return encrypt(algorithm, key, data)
    })

    const url = await begin(options())
    const a = readAuthorization(url)
    const flows = await storedFlows()
    expect(flows).toHaveLength(1)
    const [state, value] = flows[0] as [string, FlowRecord]
    expect(state).toBe(a.state)
    expect(Object.keys(value).sort()).toEqual(
      ['v', 'issuer', 'client_id', 'redirect_uri', 'product', 'nonce', 'code_verifier', 'akd_pub', 'aes_key', 'iv', 'sealed_eph', 'return_to', 'created_at'].sort(),
    )
    expect(value.v).toBe(1)
    expect(value.issuer).toBe(ISSUER)
    expect(value.client_id).toBe(CLIENT_ID)
    expect(value.redirect_uri).toBe(REDIRECT_URI)
    expect(value.product).toBe(PRODUCT)
    expect(value.nonce).toBe(a.nonce)
    expect(await pkceChallenge(value.code_verifier)).toBe(a.codeChallenge)
    expect(value.akd_pub).toBe(a.akdPub)
    expect(value.return_to).toBe('/inbox')
    expect(Math.abs(value.created_at - Date.now())).toBeLessThan(5000)
    expect(value.iv!.length).toBe(12)
    expect(value.sealed_eph!.length).toBe(48)

    // The AES key is non-extractable, and it is the only key in the record:
    // no X25519 CryptoKey (WebKit loses those records).
    expect(value.aes_key).toBeInstanceOf(CryptoKey)
    expect(value.aes_key!.extractable).toBe(false)
    expect(value.aes_key!.algorithm.name).toBe('AES-GCM')
    await expect(crypto.subtle.exportKey('raw', value.aes_key!)).rejects.toThrow()

    // The raw ephemeral key appears nowhere in the record, and every buffer
    // the page held it in is zero now.
    const raw = await sealedEphemeralKey(state, value)
    expect(raw.length).toBe(32)
    for (const bytes of everyByteString(value)) expect(containsBytes(bytes, raw), 'the raw key is in the record').toBe(false)
    expect(exported).toHaveLength(1)
    expect(isZero(new Uint8Array(exported[0])), 'the PKCS#8 export was zeroed').toBe(true)
    expect(encrypted).toHaveLength(1)
    expect(isZero(encrypted[0]), 'the raw key given to AES-GCM was zeroed').toBe(true)
    // Nor is it in the URL.
    expect(url.includes(toBase64URL(raw as Bytes))).toBe(false)
    expect([DB_NAME, STORE]).toEqual(['thehappie-rp', 'flows'])
  })

  it('binds the sealed ephemeral key to its client and state', async () => {
    await begin(options())
    const [[state, flow]] = (await storedFlows()) as [[string, FlowRecord]]
    const aad = (client: string, s: string) => encodeUTF8(canonicalJSON(['thehappie-rp/flow', 1, client, s]))
    const open = (additionalData: Bytes): Promise<ArrayBuffer> =>
      crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(flow.iv!), additionalData }, flow.aes_key!, new Uint8Array(flow.sealed_eph!))
    await open(aad(CLIENT_ID, state))
    await expect(open(aad('wappie-app', state))).rejects.toThrow()
    await expect(open(aad(CLIENT_ID, toBase64URL(random(32) as Bytes)))).rejects.toThrow()
  })

  it('refuses a returnTo that is not a same-origin path', async () => {
    for (const returnTo of ['https://evil.example/', '//evil.example/x', '/\\evil.example', '\\\\evil.example', '/.//evil.example', '/x/..//evil.example', '/\t/evil.example', 'inbox', '', 'javascript:alert(1)']) {
      await expect(begin(options({ returnTo })), JSON.stringify(returnTo)).rejects.toThrow(TypeError)
    }
    expect(await storedFlows()).toHaveLength(0)
  })

  it('keeps a same-origin path\'s query and fragment', () => {
    expect(sameOriginPath('/inbox?tab=2#top', ORIGIN)).toBe('/inbox?tab=2#top')
    expect(sameOriginPath('/a/../b', ORIGIN)).toBe('/b')
    expect(sameOriginPath('/', ORIGIN)).toBe('/')
    expect(sameOriginPath('/%2F%2Fevil.example', ORIGIN)).toBe('/%2F%2Fevil.example')
    expect(sameOriginPath('//x', ORIGIN)).toBeNull()
    expect(sameOriginPath(42, ORIGIN)).toBeNull()
  })

  it('refuses options outside the protocol before storing anything', async () => {
    const bad: [string, Partial<BeginOptions>][] = [
      ['an issuer with a path', { issuer: `${ISSUER}/` }],
      ['a plain-http issuer off localhost', { issuer: 'http://id.thehappie.co' }],
      ['a redirect URI on another origin', { redirectUri: 'http://other.thehappie.localhost:8292/auth/callback' }],
      ['a redirect URI with a query', { redirectUri: `${REDIRECT_URI}?x=1` }],
      ['a redirect URI not in canonical form', { redirectUri: REDIRECT_URI.replace('auth', 'AUTH/../auth') }],
      ['a scope without openid', { scope: 'email profile' }],
      ['a scope with a repeat', { scope: 'openid openid' }],
      ['account_key without wantKey', { scope: 'openid account_key', wantKey: false }],
      ['prompt=none with a key, which always needs an unlock', { prompt: 'none' }],
      ['a client id outside the AAD set', { clientId: 'fake product' }],
      ['a key request without the product', { product: undefined }],
      ['a product that is not a product id', { product: 'Wappie' }],
      ['a product with a colon', { product: 'wappie:1' }],
      ['a product without a key request, not a product id', { wantKey: false, product: '' }],
    ]
    for (const [label, o] of bad) await expect(begin(options(o)), label).rejects.toThrow(TypeError)
    expect(await storedFlows()).toHaveLength(0)
  })

  it('deletes flows older than ten minutes, and unreadable ones', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    const t0 = new Date('2026-10-01T12:00:00Z').getTime()
    vi.setSystemTime(t0)
    const first = readAuthorization(await begin(options()))
    await storeFlow('garbage', { v: 2, anything: 'else' })
    vi.setSystemTime(t0 + FLOW_TTL_MS - 1000)
    const second = readAuthorization(await begin(options({ wantKey: false })))
    // The first is still young; the unreadable record is gone.
    expect((await storedFlows()).map(([k]) => k).sort()).toEqual([first.state, second.state].sort())
    vi.setSystemTime(t0 + FLOW_TTL_MS + 1000)
    const third = readAuthorization(await begin(options()))
    expect((await storedFlows()).map(([k]) => k).sort()).toEqual([second.state, third.state].sort())
  })
})

describe('callback', () => {
  it('returns the product key with key delivery, and leaves no flow', async () => {
    const r = await signIn()
    const want = await deriveProductKey(ROOT, PRODUCT, EPOCH)
    same(r.productKey!, want.sk, 'the product key')
    expect(r.accessToken).toBe(id.accessTokens[0])
    expect(r.returnTo).toBe('/inbox')
    expect([r.idClaims.sub, r.idClaims.aud, r.idClaims.iss]).toEqual([SUB, CLIENT_ID, ISSUER])
    expect(r.idClaims.product_key).toBe(toBase64URL(want.pub))
    expect(r.idClaims.product_key_id).toBe('wappie:1')
    expect(r.idClaims.email).toBe('ana@example.com')
    expect(r.idClaims.amr).toEqual(['pwd'])
    expect(await storedFlows()).toHaveLength(0)
  })

  it('exchanges the code with a credentialed CORS form POST that is never cached', async () => {
    await signIn()
    expect(id.tokenRequests).toHaveLength(1)
    const { url, init, form } = id.tokenRequests[0]
    expect(url).toBe(TOKEN_ENDPOINT)
    expect([init.method, init.mode, init.credentials, init.cache, init.redirect]).toEqual(['POST', 'cors', 'include', 'no-store', 'error'])
    // The default referrer policy: "no-referrer" would make the browser send
    // Origin: null, which the token endpoint refuses.
    expect(init.referrerPolicy).toBeUndefined()
    expect(new Headers(init.headers).get('Content-Type')).toBe('application/x-www-form-urlencoded')
    expect(typeof init.body).toBe('string')
    expect([...form.keys()].sort()).toEqual(['client_id', 'code', 'code_verifier', 'grant_type', 'redirect_uri'])
    expect([form.get('grant_type'), form.get('client_id'), form.get('redirect_uri')]).toEqual(['authorization_code', CLIENT_ID, REDIRECT_URI])
  })

  it('returns no key for identity only', async () => {
    const r = await signIn({ wantKey: false, product: undefined, returnTo: '/settings?x=1' })
    expect(r.productKey).toBeUndefined()
    expect('productKey' in r).toBe(false)
    expect(r.returnTo).toBe('/settings?x=1')
    // The product claims are there for a client with a product.
    expect(r.idClaims.product_key).toBe(toBase64URL(await productPublicKey(ROOT, PRODUCT, EPOCH)))
    expect(await storedFlows()).toHaveLength(0)
  })

  it.skipIf(IN_BROWSER)('drops the query from the address bar before anything else', async () => {
    const back = await id.authorize(await begin(options()))
    browser.visit(back)
    // fetch sees the address bar already clean.
    let addressAtFetch = ''
    const tokenEndpoint = id.fetch.getMockImplementation()!
    id.fetch.mockImplementationOnce(async (input, init) => {
      addressAtFetch = browser.href
      return tokenEndpoint(input, init)
    })
    const r = await callback(back, CALLBACK)
    r.productKey!.fill(0)
    expect(browser.replaced).toEqual(['/auth/callback'])
    expect(addressAtFetch).toBe(REDIRECT_URI)
    // Also when the callback fails at once.
    browser.visit(`${REDIRECT_URI}?code=x&state=y&iss=nope`)
    await expectRPError(() => callback(browser.href, CALLBACK), 'iss_mismatch')
    expect(browser.href).toBe(REDIRECT_URI)
  })

  it('uses a flow once', async () => {
    const back = await id.authorize(await begin(options()))
    const first = await callback(back, CALLBACK)
    first.productKey!.fill(0)
    await expectRPError(() => callback(back, CALLBACK), 'state_unknown')
    // The second callback never reached the token endpoint.
    expect(id.tokenRequests).toHaveLength(1)
  })

  it('gives a flow to only one of two callbacks at once', async () => {
    const back = await id.authorize(await begin(options()))
    const results = await Promise.allSettled([callback(back, CALLBACK), callback(back, CALLBACK)])
    const fulfilled = results.filter((r) => r.status === 'fulfilled') as PromiseFulfilledResult<CallbackResult>[]
    expect(fulfilled).toHaveLength(1)
    fulfilled[0].value.productKey!.fill(0)
    const rejected = results.find((r) => r.status === 'rejected') as PromiseRejectedResult
    expect(isRPError(rejected.reason, 'state_unknown')).toBe(true)
    expect(id.tokenRequests).toHaveLength(1)
  })

  it('stops with state_unknown on an unknown, missing or expired state', async () => {
    const back = new URL(await id.authorize(await begin(options())))
    const cases: [string, (u: URL) => void][] = [
      ['an unknown state', (u) => u.searchParams.set('state', toBase64URL(random(32) as Bytes))],
      ['no state', (u) => u.searchParams.delete('state')],
      ['an empty state', (u) => u.searchParams.set('state', '')],
      ['a repeated state', (u) => u.searchParams.append('state', u.searchParams.get('state')!)],
      ['the state with a character more', (u) => u.searchParams.set('state', `${u.searchParams.get('state')!}A`)],
      ['a state of another shape', (u) => u.searchParams.set('state', '../flows')],
    ]
    for (const [label, bend] of cases) {
      const u = new URL(back)
      bend(u)
      await expectRPError(() => callback(u.href, CALLBACK), 'state_unknown', label)
    }
    // The real flow is still there, and still works.
    expect(await storedFlows()).toHaveLength(1)
    ;(await callback(back.href, CALLBACK)).productKey!.fill(0)

    // A flow older than ten minutes.
    vi.useFakeTimers({ toFake: ['Date'] })
    const t0 = Date.now()
    const late = await id.authorize(await begin(options()))
    vi.setSystemTime(t0 + FLOW_TTL_MS + 1000)
    await expectRPError(() => callback(late, CALLBACK), 'state_unknown', 'an expired flow')
    expect(await storedFlows()).toHaveLength(0)
  })

  it('does not know a flow begun for another client', async () => {
    const back = await id.authorize(await begin(options()))
    await expectRPError(() => callback(back, { issuer: ISSUER, clientId: 'wappie-app' }), 'state_unknown')
    expect(await storedFlows()).toHaveLength(0)
  })

  it('stops at an iss other than the issuer, and ends the flow', async () => {
    const cases: [string, (u: URL) => void][] = [
      ['another issuer', (u) => u.searchParams.set('iss', 'https://id.thehappie.co')],
      ['a trailing slash', (u) => u.searchParams.set('iss', `${ISSUER}/`)],
      ['no iss', (u) => u.searchParams.delete('iss')],
      ['a repeated iss', (u) => u.searchParams.append('iss', ISSUER)],
    ]
    for (const [label, bend] of cases) {
      const u = new URL(await id.authorize(await begin(options())))
      bend(u)
      await expectRPError(() => callback(u.href, CALLBACK), 'iss_mismatch', label)
      expect(await storedFlows(), label).toHaveLength(0)
    }
    expect(id.tokenRequests).toHaveLength(0)
  })

  it('stops at a flow begun with another issuer, even when iss is the issuer it is given, before sending anything', async () => {
    // RFC 9207, section 2.4: iss is compared with the issuer the request was
    // sent to. A page that serves two issuers (staging and production) and
    // is called back with the other sends the code and its verifier to
    // neither, and asks its server nothing.
    const OTHER = 'https://id.thehappie.co'
    const session = vi.fn(async (): Promise<PinnedKey> => expect.fail('the server was asked'))
    const store = vi.fn(() => expect.fail('a key was stored'))
    const cases = [
      ['begun with the issuer, called back with another', ISSUER, OTHER, false],
      ['begun with another, called back with the issuer', OTHER, ISSUER, false],
      ['begun with the issuer, finished with another', ISSUER, OTHER, true],
    ] as const
    for (const [label, beganWith, calledWith, finish] of cases) {
      const state = new URL(await begin(options({ issuer: beganWith }))).searchParams.get('state')!
      const u = new URL(REDIRECT_URI)
      u.searchParams.set('code', `thid_c_${toBase64URL(random(32) as Bytes)}`)
      u.searchParams.set('state', state)
      u.searchParams.set('iss', calledWith)
      browser.visit(u.href)
      const o = { issuer: calledWith, clientId: CLIENT_ID }
      await expectRPError(() => (finish ? finishSignIn(u.href, { ...o, session, store }) : callback(u.href, o)), 'iss_mismatch', label)
      expect(await storedFlows(), `${label}: the flow is ended`).toHaveLength(0)
    }
    expect(id.tokenRequests).toHaveLength(0)
    expect(session).not.toHaveBeenCalled()
    expect(store).not.toHaveBeenCalled()
  })

  it('passes an error response on as authorization_error, and ends the flow', async () => {
    for (const [error, want] of [['access_denied', 'access_denied'], ['login_required', 'login_required'], ['interaction_required', 'interaction_required'], ['something_new', 'unknown']] as const) {
      const a = readAuthorization(await begin(options()))
      const u = new URL(REDIRECT_URI)
      u.searchParams.set('error', error)
      u.searchParams.set('state', a.state)
      u.searchParams.set('iss', ISSUER)
      const err = await caught(() => callback(u.href, CALLBACK))
      expect(isRPError(err, 'authorization_error'), error).toBe(true)
      expect((err as RPError).oauthError).toBe(want)
      expect(await storedFlows()).toHaveLength(0)
    }
    expect(id.tokenRequests).toHaveLength(0)
  })

  it('calls a failed token request token_error', async () => {
    id.bends.networkError = true
    await callbackFailsWith('token_error', {}, 'a network error')
    id.bends.networkError = false
    const answers: [string, (body: Record<string, unknown>) => Record<string, unknown> | Response][] = [
      ['a 400', () => new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'x' }), { status: 400 })],
      ['a 500 without JSON', () => new Response('oops', { status: 500 })],
      ['a 200 without JSON', () => new Response('<html>', { status: 200 })],
      ['a JSON array', () => new Response('[]', { status: 200 })],
      ['no access token', (b) => ({ ...b, access_token: undefined })],
      ['an access token of another shape', (b) => ({ ...b, access_token: 'thid_c_abc' })],
      ['another token type', (b) => ({ ...b, token_type: 'MAC' })],
      ['no ID token', (b) => ({ ...b, id_token: 42 })],
      ['no sealed key', (b) => ({ ...b, account_key_sealed: undefined })],
    ]
    for (const [label, bend] of answers) {
      id.bends.token = bend
      await callbackFailsWith('token_error', {}, label)
    }
    // A sealed key nobody asked for.
    id.bends.token = (b) => ({ ...b, account_key_sealed: toBase64URL(random(80) as Bytes) })
    await callbackFailsWith('token_error', { wantKey: false }, 'an unasked-for sealed key')
  })

  it('carries the OAuth error value of a token error', async () => {
    id.bends.token = () => new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'x' }), { status: 400 })
    const err = await caught(() => signIn())
    expect(isRPError(err, 'token_error')).toBe(true)
    expect((err as RPError).oauthError).toBe('invalid_grant')
  })

  it('calls a callback without a code token_error', async () => {
    const a = readAuthorization(await begin(options()))
    const u = new URL(REDIRECT_URI)
    u.searchParams.set('state', a.state)
    u.searchParams.set('iss', ISSUER)
    await expectRPError(() => callback(u.href, CALLBACK), 'token_error')
    expect(await storedFlows()).toHaveLength(0)
  })

  // Step 6 comes before step 7: the binding the key opens under is built
  // from the ID token's sub, product_key_id and product_key, so a token that
  // fails its checks is refused before any key is opened. Each bend runs
  // with the key and for identity only, where no key exists at all: the
  // answer is the same, whatever the engine does with keys.
  it('refuses an ID token that fails the checks of step 6, before it touches a key', async () => {
    const now = (): number => Math.floor(Date.now() / 1000)
    const claimBends: [string, (c: Record<string, unknown>) => Record<string, unknown>][] = [
      ['another iss', (c) => ({ ...c, iss: 'https://id.thehappie.co' })],
      ['another aud', (c) => ({ ...c, aud: 'wappie-app' })],
      ['aud as an array', (c) => ({ ...c, aud: [CLIENT_ID] })],
      ['another nonce', (c) => ({ ...c, nonce: toBase64URL(random(32) as Bytes) })],
      ['no nonce', (c) => ({ ...c, nonce: undefined })],
      ['a sub that is not an account id', (c) => ({ ...c, sub: 'ana' })],
      ['exp before iat', (c) => ({ ...c, exp: (c['iat'] as number) - 1 })],
      ['exp equal to iat', (c) => ({ ...c, exp: c['iat'] })],
      ['a lifetime longer than ten minutes', (c) => ({ ...c, iat: now(), exp: now() + 601 })],
      ['iat as text', (c) => ({ ...c, iat: String(c['iat']) })],
      ['no product_key', (c) => ({ ...c, product_key: undefined })],
      ['no product_key_id', (c) => ({ ...c, product_key_id: undefined })],
      ['a short product_key', (c) => ({ ...c, product_key: toBase64URL(random(31) as Bytes) })],
      ['a product_key_id that is not product:epoch', (c) => ({ ...c, product_key_id: 'wappie' })],
      ['amr of another type', (c) => ({ ...c, amr: 'pwd' })],
    ]
    for (const [label, bend] of claimBends) {
      id.bends.claims = bend
      await idTokenRefused(label)
      await idTokenRefused(`${label}, identity only`, { wantKey: false })
    }
    id.bends.claims = undefined
    const tokenBends: [string, (c: Record<string, unknown>) => string][] = [
      ['alg none', (c) => jws(c, { alg: 'none', kid: KID, typ: 'JWT' })],
      ['alg HS256', (c) => jws(c, { alg: 'HS256', kid: KID, typ: 'JWT' })],
      ['no typ', (c) => jws(c, { alg: 'ES256', kid: KID })],
      ['another typ', (c) => jws(c, { alg: 'ES256', kid: KID, typ: 'at+jwt' })],
      ['no kid', (c) => jws(c, { alg: 'ES256', typ: 'JWT' })],
      ['a kid that is not a thumbprint', (c) => jws(c, { alg: 'ES256', kid: 'test-kid', typ: 'JWT' })],
      ['a header member besides alg, kid and typ', (c) => jws(c, { alg: 'ES256', kid: KID, typ: 'JWT', jku: `${ISSUER}/keys` })],
      ['a header that is not an object', (c) => `${toBase64URL(encodeUTF8('"ES256"'))}.${jws(c).split('.').slice(1).join('.')}`],
      ['two parts', (c) => jws(c).split('.').slice(0, 2).join('.')],
      ['four parts', (c) => `${jws(c)}.${toBase64URL(random(64) as Bytes)}`],
      ['an empty signature', (c) => `${jws(c).split('.').slice(0, 2).join('.')}.`],
      ['a signature of 70 bytes, as DER would be', (c) => `${jws(c).split('.').slice(0, 2).join('.')}.${toBase64URL(random(70) as Bytes)}`],
      ['longer than 8 KiB', (c) => jws({ ...c, name: 'a'.repeat(8 << 10) })],
      ['a payload that is not JSON', () => `${jws({}).split('.')[0]}.${toBase64URL(encodeUTF8('{'))}.${toBase64URL(random(64) as Bytes)}`],
      ['a padded payload', (c) => jws(c).replace(/\.([^.]+)\./, (_, p: string) => `.${p}==.`)],
    ]
    for (const [label, bend] of tokenBends) {
      id.bends.idToken = bend
      await idTokenRefused(label)
      await idTokenRefused(`${label}, identity only`, { wantKey: false })
    }
  })

  // The product's key label: a client that asks for its key gets only that
  // product's, and the flow says which.
  it('refuses an ID token whose product_key_id names another product', async () => {
    id.bends.product = { root: ROOT, product: 'mailie', epoch: 1 }
    await callbackFailsWith('id_token_invalid', {}, 'another product with the key')
    await callbackFailsWith('id_token_invalid', { wantKey: false }, 'another product without the key')
    id.bends.product = { root: ROOT, product: PRODUCT, epoch: 7 }
    const r = await signIn()
    expect(r.idClaims.product_key_id).toBe('wappie:7')
    same(r.productKey!, (await deriveProductKey(ROOT, PRODUCT, 7)).sk, 'another epoch of the same product')
    r.productKey!.fill(0)
  })

  it('needs the product claims when the flow names a product, even for identity only', async () => {
    id.bends.claims = (c) => ({ ...c, product_key: undefined, product_key_id: undefined })
    await callbackFailsWith('id_token_invalid', { wantKey: false }, 'identity only for a product')
    const r = await signIn({ wantKey: false, product: undefined })
    expect(r.idClaims.product_key_id).toBeUndefined()
  })

  it('signs in with a device clock hours off', async () => {
    const now = (): number => Math.floor(Date.now() / 1000)
    for (const [label, iat, exp] of [['the device is an hour behind the issuer', 3600, 3900], ['the device is an hour ahead of the issuer', -3600, -3300], ['a ten-minute lifetime', 0, 600]] as const) {
      id.bends.claims = (c) => ({ ...c, iat: now() + iat, exp: now() + exp })
      const r = await signIn()
      expect(r.idClaims.iat, label).toBe(r.idClaims.exp - (exp - iat))
      r.productKey!.fill(0)
    }
  })

  it('calls a sealed key that does not open key_open_failed', async () => {
    const bends: [string, (a: ReturnType<typeof readAuthorization>) => Promise<string>][] = [
      ['a flipped bit', async (a) => {
        const b = fromBase64URL(await sealFor(a), 80)
        b[40] ^= 1
        return toBase64URL(b)
      }],
      ['sealed to another recipient', async (a) => sealFor({ ...a, akdPub: toBase64URL((await generateX25519KeyPair()).publicKey) })],
      ['sealed for another nonce', async (a) => sealFor({ ...a, nonce: toBase64URL(random(32) as Bytes) })],
      ['sealed for another code challenge', async (a) => sealFor({ ...a, codeChallenge: await pkceChallenge(toBase64URL(random(32) as Bytes)) })],
      ['sealed for another account', async (a) => sealFor(a, { sub: '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c' })],
      ['sealed for another client', async (a) => sealFor(a, { clientId: 'wappie-app' })],
      ['sealed for another redirect URI', async (a) => sealFor(a, { redirectUri: `${ORIGIN}/auth/other` })],
      ['sealed by another issuer', async (a) => sealFor(a, { issuer: 'https://id.thehappie.co' })],
      ['79 bytes', async (a) => toBase64URL(fromBase64URL(await sealFor(a), 80).slice(0, 79))],
      ['81 bytes', async (a) => toBase64URL(new Uint8Array([...fromBase64URL(await sealFor(a), 80), 0]) as Bytes)],
      ['not base64url', async (a) => `${await sealFor(a)}=`],
      ['enc spelled with bit 255 set', async (a) => {
        const b = fromBase64URL(await sealFor(a), 80)
        b[31] |= 0x80
        return toBase64URL(b)
      }],
    ]
    for (const [label, seal] of bends) {
      id.bends.seal = seal
      await callbackFailsWith('key_open_failed', {}, label)
    }
  })

  it('calls a tampered ephemeral key key_open_failed', async () => {
    const back = await id.authorize(await begin(options()))
    const [[state, flow]] = (await storedFlows()) as [[string, FlowRecord]]
    const tampered = new Uint8Array(flow.sealed_eph!)
    tampered[0] ^= 1
    await storeFlow(state, { ...flow, sealed_eph: tampered })
    await expectRPError(() => callback(back, CALLBACK), 'key_open_failed')
    expect(await storedFlows()).toHaveLength(0)
  })

  it('calls a key that opens but is not the product key key_mismatch, and zeroes it', async () => {
    // A page that seals some other key under the binding of the product key
    // the ID token names: the AAD matches, so the blob opens, and only the
    // comparison catches it.
    const wrong = await deriveProductKey(new Uint8Array(32).fill(1), PRODUCT, EPOCH)
    id.bends.seal = async (a) => {
      const binding = {
        issuer: ISSUER, clientId: CLIENT_ID, redirectUri: REDIRECT_URI, sub: SUB, productKeyId: 'wappie:1',
        productKey: await productPublicKey(ROOT, PRODUCT, EPOCH), codeChallenge: a.codeChallenge, nonce: a.nonce,
      }
      const { enc, ciphertext } = await hpkeSeal(fromBase64URL(a.akdPub!, 32), encodeUTF8('thehappie-id/v1/key-delivery'), encodeUTF8(keyDeliveryAAD(binding)), wrong.sk)
      return toBase64URL(new Uint8Array([...enc, ...ciphertext]) as Bytes)
    }
    const back = await id.authorize(await begin(options()))
    // Every AES-GCM plaintext the relying party sees (its ephemeral key, then
    // the opened product key) is kept by reference.
    const opened = watchDecrypt()
    await expectRPError(() => callback(back, CALLBACK), 'key_mismatch')
    expect(opened).toHaveLength(2)
    expect(opened.every(isZero), 'every opened key was zeroed').toBe(true)
    expect(await storedFlows()).toHaveLength(0)
  })

  it('leaves only the returned key after a successful callback', async () => {
    const opened = watchDecrypt()
    const r = await signIn()
    // The ephemeral key is zero; the product key is the one returned, which
    // the caller zeroes.
    expect(opened).toHaveLength(2)
    expect(isZero(opened[0]), 'the ephemeral key was zeroed').toBe(true)
    expect(opened[1].buffer).toBe(r.productKey!.buffer)
    r.productKey!.fill(0)
    expect(isZero(opened[1])).toBe(true)
    // Nothing in the result but the product key holds key material: the
    // claims carry the public key only.
    const sk = (await deriveProductKey(ROOT, PRODUCT, EPOCH)).sk
    const { productKey: _, ...rest } = r
    for (const bytes of everyByteString(rest)) expect(containsBytes(bytes, sk)).toBe(false)
    expect(JSON.stringify(rest).includes(toBase64URL(sk))).toBe(false)
    expect(await storedFlows()).toHaveLength(0)
  })

  // A product key whose sk_p starts with a zero byte (1 in 256; this root's
  // wappie:125) is one WebKit on Linux used to refuse as PKCS#8, on the id.
  // page and on the product's page alike: it is delivered, opened and
  // checked as any other.
  it('delivers a product key whose sk_p starts with a zero byte', async () => {
    const want = await deriveProductKey(ROOT, PRODUCT, 125)
    expect(want.sk[0]).toBe(0)
    id.bends.product = { root: ROOT, product: PRODUCT, epoch: 125 }
    const r = await signIn()
    expect(r.idClaims.product_key_id).toBe('wappie:125')
    same(r.productKey!, want.sk, 'the product key')
    const stored: Uint8Array[] = []
    await keepProductKey(r, { sub: SUB, product_key_id: 'wappie:125', product_key: toBase64URL(want.pub) }, (sk) => {
      stored.push(sk.slice())
    })
    same(stored[0], want.sk, 'the kept key')
    expect(isZero(r.productKey!)).toBe(true)
  })

  it('falls back to the root for a tampered returnTo', async () => {
    const back = await id.authorize(await begin(options()))
    const [[state, flow]] = (await storedFlows()) as [[string, FlowRecord]]
    await storeFlow(state, { ...flow, return_to: '//evil.example/' })
    const r = await callback(back, CALLBACK)
    r.productKey!.fill(0)
    expect(r.returnTo).toBe('/')
  })

  it('does not read a flow record it cannot read, nor one the platform\'s copy wrote', async () => {
    for (const [label, bend] of [
      ['no AES key', (f: FlowRecord) => ({ ...f, aes_key: null })],
      // The platform's web/shared/oidc-rp writes no product: a flow in
      // flight when a page switches to the kit says "start again".
      ['no product, as the platform\'s copy writes it', (f: FlowRecord) => {
        const { product: _, ...rest } = f
        return rest
      }],
      // Nor does it write the issuer.
      ['no issuer', (f: FlowRecord) => {
        const { issuer: _, ...rest } = f
        return rest
      }],
      ['an issuer that is not a string', (f: FlowRecord) => ({ ...f, issuer: null })],
      ['a key without a product', (f: FlowRecord) => ({ ...f, product: null })],
      ['a product that is not a string', (f: FlowRecord) => ({ ...f, product: 7 })],
    ] as const) {
      const back = await id.authorize(await begin(options()))
      const [[state, flow]] = (await storedFlows()) as [[string, FlowRecord]]
      await storeFlow(state, bend(flow))
      await expectRPError(() => callback(back, CALLBACK), 'state_unknown', label)
      expect(await storedFlows(), label).toHaveLength(0)
    }
  })
})

describe('keeping the key (step 9)', () => {
  const PINNED = async (): Promise<PinnedKey> => ({ sub: SUB, product_key_id: 'wappie:1', product_key: toBase64URL(await productPublicKey(ROOT, PRODUCT, EPOCH)) })

  it('stores the key only when the server named the same sub, product_key_id and product_key, and zeroes it', async () => {
    const r = await signIn()
    const want = (await deriveProductKey(ROOT, PRODUCT, EPOCH)).sk
    const stored: Uint8Array[] = []
    const pinned = await PINNED()
    await keepProductKey(r, pinned, (sk, p) => {
      stored.push(sk.slice())
      expect(p).toEqual(pinned)
    })
    expect(stored).toHaveLength(1)
    same(stored[0], want, 'the stored key')
    expect(isZero(r.productKey!), 'the key was zeroed').toBe(true)
  })

  it('refuses every other answer as pin_mismatch, stores nothing and zeroes the key', async () => {
    const other = await productPublicKey(new Uint8Array(32).fill(5), PRODUCT, EPOCH)
    const good = await PINNED()
    const answers: [string, unknown][] = [
      ['another sub', { ...good, sub: '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c' }],
      ['the sub in upper case', { ...good, sub: SUB.toUpperCase() }],
      ['another product_key_id', { ...good, product_key_id: 'wappie:2' }],
      ['another product', { ...good, product_key_id: 'mailie:1' }],
      ['another product_key', { ...good, product_key: toBase64URL(other) }],
      ['a product_key of 31 bytes', { ...good, product_key: toBase64URL(other.slice(1)) }],
      ['a padded product_key', { ...good, product_key: `${good.product_key}=` }],
      ['no sub', { product_key_id: good.product_key_id, product_key: good.product_key }],
      ['no product_key', { sub: good.sub, product_key_id: good.product_key_id }],
      ['a product_key_id that is a number', { ...good, product_key_id: 1 }],
      ['null', null],
      ['an array', [good.sub, good.product_key_id, good.product_key]],
    ]
    for (const [label, answer] of answers) {
      const r = await signIn()
      const store = vi.fn()
      await expectRPError(() => keepProductKey(r, answer as PinnedKey, store), 'pin_mismatch', label)
      expect(store, label).not.toHaveBeenCalled()
      expect(isZero(r.productKey!), `${label}: the key was zeroed`).toBe(true)
    }
  })

  it('zeroes the key when store throws, and passes the error on', async () => {
    const r = await signIn()
    const boom = new Error('the vault is full')
    expect(await caught(() => keepProductKey(r, PINNED() as never, () => undefined))).toBeInstanceOf(RPError)
    const r2 = await signIn()
    expect(await caught(async () => keepProductKey(r2, await PINNED(), () => Promise.reject(boom)))).toBe(boom)
    expect(isZero(r2.productKey!)).toBe(true)
    expect(isZero(r.productKey!)).toBe(true)
  })

  it('takes only a result with a key and a store that is a function', async () => {
    const r = await signIn({ wantKey: false, product: undefined })
    expect(await caught(async () => keepProductKey(r, await PINNED(), () => undefined))).toBeInstanceOf(TypeError)
    const k = await signIn()
    expect(await caught(async () => keepProductKey(k, await PINNED(), 'store' as never))).toBeInstanceOf(TypeError)
    expect(isZero(k.productKey!)).toBe(true)
  })
})

describe('finishSignIn', () => {
  const pinnedFor = async (over: Partial<PinnedKey> = {}): Promise<PinnedKey> => ({
    sub: SUB, product_key_id: 'wappie:1', product_key: toBase64URL(await productPublicKey(ROOT, PRODUCT, EPOCH)), ...over,
  })

  it('completes the callback, asks the server, then keeps the key, in that order', async () => {
    const back = await id.authorize(await begin(options()))
    const events: string[] = []
    const kept: Uint8Array[] = []
    const opened = watchDecrypt()
    const r = await finishSignIn(back, {
      ...CALLBACK,
      session: async (accessToken, claims) => {
        events.push('session')
        expect(accessToken).toBe(id.accessTokens[0])
        expect(claims.sub).toBe(SUB)
        return pinnedFor()
      },
      store: (sk, pinned) => {
        events.push('store')
        expect(pinned.product_key_id).toBe('wappie:1')
        kept.push(sk.slice())
      },
    })
    expect(events).toEqual(['session', 'store'])
    expect(r.keyStored).toBe(true)
    expect(r.returnTo).toBe('/inbox')
    expect(r.pinned).toEqual(await pinnedFor())
    same(kept[0], (await deriveProductKey(ROOT, PRODUCT, EPOCH)).sk, 'the kept key')
    expect('productKey' in r).toBe(false)
    expect(opened.every(isZero), 'every opened key was zeroed').toBe(true)
    expect(await storedFlows()).toHaveLength(0)
  })

  it('stores nothing and zeroes the key when the server refuses the login', async () => {
    const back = await id.authorize(await begin(options()))
    const opened = watchDecrypt()
    const refused = new Error('account_key_changed')
    const store = vi.fn()
    expect(await caught(() => finishSignIn(back, { ...CALLBACK, session: () => Promise.reject(refused), store }))).toBe(refused)
    expect(store).not.toHaveBeenCalled()
    expect(opened).toHaveLength(2)
    expect(opened.every(isZero), 'every opened key was zeroed').toBe(true)
  })

  it('stores nothing and zeroes the key when the server pinned another triple', async () => {
    for (const over of [{ sub: '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c' }, { product_key_id: 'wappie:2' }, { product_key: toBase64URL(await productPublicKey(new Uint8Array(32).fill(6), PRODUCT, EPOCH)) }]) {
      const back = await id.authorize(await begin(options()))
      const opened = watchDecrypt()
      const store = vi.fn()
      const answer = await pinnedFor(over)
      await expectRPError(() => finishSignIn(back, { ...CALLBACK, session: async () => answer, store }), 'pin_mismatch', Object.keys(over).join())
      expect(store).not.toHaveBeenCalled()
      expect(opened.every(isZero)).toBe(true)
      vi.restoreAllMocks()
      vi.stubGlobal('fetch', id.fetch)
    }
  })

  // Rule (b) of SPEC section 11.12: a key that opens and matches an ID token
  // (here both written by whoever controls the issuer, which base mode
  // allows) is not kept when the product's server pinned another one.
  it('does not keep a substituted key that opens and matches the ID token', async () => {
    const attacker = { root: new Uint8Array(32).fill(0x66), product: PRODUCT, epoch: EPOCH }
    id.bends.product = attacker
    const back = await id.authorize(await begin(options()))
    const store = vi.fn()
    // The callback alone accepts it: it opens and matches the ID token.
    await expectRPError(() => finishSignIn(back, { ...CALLBACK, session: async () => pinnedFor(), store }), 'pin_mismatch')
    expect(store).not.toHaveBeenCalled()
    const back2 = await id.authorize(await begin(options()))
    const r = await callback(back2, CALLBACK)
    same(r.productKey!, (await deriveProductKey(attacker.root, PRODUCT, EPOCH)).sk, 'what the callback alone hands out')
    r.productKey!.fill(0)
  })

  it('checks the sub without a key, and stores nothing', async () => {
    const back = await id.authorize(await begin(options({ wantKey: false, product: undefined })))
    const store = vi.fn()
    const r = await finishSignIn(back, { ...CALLBACK, session: async () => pinnedFor(), store })
    expect([r.keyStored, r.pinned.sub]).toEqual([false, SUB])
    expect(store).not.toHaveBeenCalled()
    const back2 = await id.authorize(await begin(options({ wantKey: false, product: undefined })))
    await expectRPError(() => finishSignIn(back2, { ...CALLBACK, session: async () => pinnedFor({ sub: '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c' }), store }), 'pin_mismatch')
  })

  it('refuses a session or store that is not a function before touching the flow', async () => {
    const back = await id.authorize(await begin(options()))
    for (const o of [{ session: undefined, store: () => undefined }, { session: async () => pinnedFor(), store: 'vault' }]) {
      expect(await caught(() => finishSignIn(back, { ...CALLBACK, ...o } as never))).toBeInstanceOf(TypeError)
    }
    expect(await storedFlows()).toHaveLength(1)
    expect(id.tokenRequests).toHaveLength(0)
  })
})

describe('logoutURL', () => {
  it('is the GET of id.\'s logout with the client, its post-logout URI and a fresh state', () => {
    const u = new URL(logoutURL({ issuer: ISSUER, clientId: CLIENT_ID, postLogoutRedirectUri: POST_LOGOUT_REDIRECT_URI }))
    expect(u.origin + u.pathname).toBe(`${ISSUER}/oauth2/logout`)
    expect([...u.searchParams.keys()].sort()).toEqual(['client_id', 'post_logout_redirect_uri', 'state'])
    expect(u.searchParams.get('client_id')).toBe(CLIENT_ID)
    expect(u.searchParams.get('post_logout_redirect_uri')).toBe(POST_LOGOUT_REDIRECT_URI)
    expect(u.searchParams.get('state')).toMatch(/^[A-Za-z0-9_-]{43}$/)
    const again = new URL(logoutURL({ issuer: ISSUER, clientId: CLIENT_ID, postLogoutRedirectUri: POST_LOGOUT_REDIRECT_URI }))
    expect(again.searchParams.get('state')).not.toBe(u.searchParams.get('state'))
    expect(new URL(logoutURL({ issuer: ISSUER, clientId: CLIENT_ID, postLogoutRedirectUri: POST_LOGOUT_REDIRECT_URI, state: 'abc' })).searchParams.get('state')).toBe('abc')
  })

  it('refuses arguments outside the rules', () => {
    for (const o of [
      { issuer: `${ISSUER}/`, clientId: CLIENT_ID, postLogoutRedirectUri: POST_LOGOUT_REDIRECT_URI },
      { issuer: ISSUER, clientId: 'fake product', postLogoutRedirectUri: POST_LOGOUT_REDIRECT_URI },
      { issuer: ISSUER, clientId: CLIENT_ID, postLogoutRedirectUri: 'http://other.thehappie.localhost:8292/' },
      { issuer: ISSUER, clientId: CLIENT_ID, postLogoutRedirectUri: `${POST_LOGOUT_REDIRECT_URI}?x=1` },
      { issuer: ISSUER, clientId: CLIENT_ID, postLogoutRedirectUri: POST_LOGOUT_REDIRECT_URI, state: '' },
      { issuer: ISSUER, clientId: CLIENT_ID, postLogoutRedirectUri: POST_LOGOUT_REDIRECT_URI, state: 'a b' },
      { issuer: ISSUER, clientId: CLIENT_ID, postLogoutRedirectUri: POST_LOGOUT_REDIRECT_URI, state: 'x'.repeat(513) },
    ]) {
      expect(() => logoutURL(o), JSON.stringify(o)).toThrow(TypeError)
    }
  })
})

describe('the module', () => {
  it('names its errors, and passes an engine without X25519 through', async () => {
    expect(new RPError('pin_mismatch').message).toBe('oidc-rp: pin_mismatch')
    expect(isRPError(new RPError('state_unknown'), 'state_unknown')).toBe(true)
    expect(isRPError(new Error('x'))).toBe(false)
    expect(new HPKEError('x', 'invalid_key')).not.toBeInstanceOf(RPError)
  })

  it('names keepProductKey\'s store KeyStore, as the platform does', () => {
    expectTypeOf<KeyStore>().toEqualTypeOf<FinishOptions['store']>()
    expectTypeOf(keepProductKey).parameter(2).toEqualTypeOf<KeyStore>()
    const store: KeyStore = (productKey: Uint8Array, pinned: PinnedKey) => {
      expect(productKey.length + pinned.sub.length).toBeGreaterThan(0)
    }
    expect(typeof store).toBe('function')
  })
})
