// Wappie's platform wrap (SPEC section 6.8), in Node and in Chromium, Firefox
// and WebKit: the golden vectors the console's Go and TypeScript modules
// wrote (wappie/golden/platform-wrap-{go,ts}.json), every seal replayed from
// its nonce and every refusal a PlatformWrapError; K_pw checked through the
// wrap envelope of section 6.5 (account.unwrapPrivateKey with the header
// 0x03); the console's own file (wappie/legacy/platform-wrap-vectors.json),
// run in its own shape and written again byte for byte; and what the module
// leaves the caller.

import { afterEach, describe, expect, it, vi } from 'vitest'

import { unwrapPrivateKey, type AccountProfile } from '../src/account.js'
import { encodeUTF8, type Bytes } from '../src/bytes.js'
import { isPlatformWrapError as isPlatformWrapErrorFromErrors, PlatformWrapError as PlatformWrapErrorFromErrors } from '../src/errors.js'
import { publicFromPrivate } from '../src/hpke.js'
import {
  checkPlatformWrapShape,
  isPlatformWrapError,
  openPlatformWrap,
  PLATFORM_WRAP_HEADER,
  PLATFORM_WRAP_LABEL,
  PLATFORM_WRAP_LEN,
  PLATFORM_WRAP_PRODUCT,
  PLATFORM_WRAP_SALT,
  platformWrapAAD,
  platformWrapInfo,
  PlatformWrapError,
  sealPlatformWrap,
  wappieAccount,
  wappiePasskey,
  type PlatformWrapBinding,
} from '../src/profiles/wappie.js'
import { b64, files, forTS, freshOnly, raw, text, toB64, unhandled, withDraws, withEngineRefusingX25519, type VectorCase } from './vectors.js'

afterEach(() => {
  vi.restoreAllMocks()
})

const IN = ['user_id', 'sub', 'product_key_id', 'account_public_key_b64', 'product_key_b64', 'account_key_b64', 'nonce_b64', 'wrap_b64']
const OUT = ['info_b64', 'aad_b64', 'wrap_b64', 'k_pw_b64', 'account_key_b64']

function binding(i: Record<string, string>): PlatformWrapBinding {
  return { userId: i.user_id!, sub: i.sub!, productKeyId: i.product_key_id!, accountPublicKey: b64(i.account_public_key_b64!) }
}

/** refused expects a PlatformWrapError and nothing else. */
async function refused(id: string, fn: () => Promise<unknown>): Promise<void> {
  const err = await fn().then(() => null, (e: unknown) => e)
  if (!isPlatformWrapError(err)) expect.fail(`case ${id}: expected platform_wrap, got ${err === null ? 'none' : (err as Error).name}`)
  expect(err.code).toBe('platform_wrap')
}

const wrapProfile: AccountProfile = {
  authLabel: '-', wrapLabel: '-', recoveryKeyLabel: '-', recoveryProofLabel: '-',
  wrapHeader: [PLATFORM_WRAP_HEADER], legacyV1: false, encoding: 'base64',
}

const counts: Record<string, number> = {}

for (const [path, f] of files('wappie/golden/platform-wrap-go.json', 'wappie/golden/platform-wrap-ts.json')) {
  describe(path, () => {
    it('is the module the kit carries', () => {
      expect([f.module, f.profile]).toEqual(['wappie.platform_wrap', 'wappie'])
    })
    for (const c of f.cases.filter(forTS)) {
      counts[c.op] = (counts[c.op] ?? 0) + 1
      if (c.error !== undefined) counts.refused = (counts.refused ?? 0) + 1
      it(c.id, async () => run(c))
    }
  })
}

async function run(c: VectorCase): Promise<void> {
  const i = c.in as Record<string, string>
  for (const m of Object.keys(i)) expect(IN.includes(m), `case ${c.id}: a member no runner reads: ${m}`).toBe(true)
  for (const m of Object.keys(c.out ?? {})) expect(OUT.includes(m), `case ${c.id}: a member no runner reads: ${m}`).toBe(true)
  if (c.error !== undefined) expect(c.error).toBe('platform_wrap')
  const b = binding(i)
  switch (c.op) {
    case 'wappie.platform_wrap_info':
      expect(toB64(platformWrapInfo(b))).toBe(c.out.info_b64)
      return
    case 'wappie.platform_wrap_aad':
      expect(toB64(platformWrapAAD(b))).toBe(c.out.aad_b64)
      return
    case 'wappie.platform_wrap_seal': {
      const sk = b64(i.product_key_b64!), usk = b64(i.account_key_b64!)
      if (c.error !== undefined) return refused(c.id, () => sealPlatformWrap(sk, usk, b))
      const wrap = await withDraws({ bytes: [b64(i.nonce_b64!)] }, () => sealPlatformWrap(sk, usk, b))
      expect(toB64(wrap)).toBe(c.out.wrap_b64)
      checkPlatformWrapShape(wrap)
      expect(toB64(await openPlatformWrap(sk, wrap, b))).toBe(i.account_key_b64)
      if (c.out.k_pw_b64 !== undefined) {
        // Section 6.5's envelope, header 0x03, no legacy form, under K_pw.
        const kpw = await crypto.subtle.importKey('raw', b64(c.out.k_pw_b64), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
        const opened = await unwrapPrivateKey(wrapProfile, wrap, kpw, platformWrapAAD(b))
        expect([toB64(opened.privateKey), opened.stale]).toEqual([i.account_key_b64, false])
      }
      return
    }
    case 'wappie.platform_wrap_open': {
      const sk = b64(i.product_key_b64!), wrap = b64(i.wrap_b64!)
      if (c.error !== undefined) return refused(c.id, () => openPlatformWrap(sk, wrap, b))
      const key = await openPlatformWrap(sk, wrap, b)
      expect(toB64(key)).toBe(c.out.account_key_b64)
      expect(toB64(await publicFromPrivate(key))).toBe(i.account_public_key_b64)
      return
    }
  }
  unhandled(c)
}

// The kit's own round trips that the Go side wrote: the fresh file of that
// name in $KIT_CROSS_IN in the cross-language job.
for (const [path, f] of freshOnly('wappie-platform-wrap-go.json')) {
  describe(path, () => {
    for (const c of f.cases.filter(forTS)) it(c.id, async () => run(c))
  })
}

describe('the golden files', () => {
  it('hold 77 cases, 41 of them refusals', () => {
    expect(counts).toEqual({ 'wappie.platform_wrap_info': 9, 'wappie.platform_wrap_aad': 9, 'wappie.platform_wrap_seal': 23, 'wappie.platform_wrap_open': 36, refused: 41 })
  })
})

// The console's own shapes (platformwrap/platformwrap_test.go at 3bfee27).
interface ConsoleVector {
  name: string
  product_key: string
  account_key: string
  account_public_key: string
  user_id: string
  sub: string
  product_key_id: string
  nonce: string
  info: string
  aad: string
  wrap: string
}
type ConsoleRefusal = { name: string; vector: number } & Partial<Omit<ConsoleVector, 'name' | 'nonce' | 'info' | 'aad'>>
interface ConsoleFile {
  description: string
  construction: string[]
  vectors: ConsoleVector[]
  open_refusals: ConsoleRefusal[]
  seal_refusals: ConsoleRefusal[]
}

const hex = (s: string) => new Uint8Array((s.match(/../g) ?? []).map((x) => parseInt(x, 16))) as Bytes
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
const consoleBinding = (v: ConsoleVector): PlatformWrapBinding => ({ userId: v.user_id, sub: v.sub, productKeyId: v.product_key_id, accountPublicKey: hex(v.account_public_key) })
const utf8 = (b: Uint8Array) => new TextDecoder().decode(b)

/** consoleFile is the console's generate() with this module's functions, so it writes the console's file. */
async function consoleFile(): Promise<ConsoleFile> {
  const digest = async (label: string) => new Uint8Array(await crypto.subtle.digest('SHA-256', encodeUTF8(`wappie/platform-wrap vectors/${label}`))) as Bytes
  const make1 = async (name: string, label: string, userId: string, sub: string, productKeyId: string): Promise<ConsoleVector> => {
    const sk = await digest(`${label}/product key`), usk = await digest(`${label}/account key`), nonce = (await digest(`${label}/nonce`)).slice(0, 12) as Bytes
    const pub = await publicFromPrivate(usk)
    const b = { userId, sub, productKeyId, accountPublicKey: pub }
    const wrap = await withDraws({ bytes: [nonce] }, () => sealPlatformWrap(sk, usk, b))
    return {
      name, product_key: toHex(sk), account_key: toHex(usk), account_public_key: toHex(pub), user_id: userId, sub, product_key_id: productKeyId,
      nonce: toHex(nonce), info: utf8(platformWrapInfo(b)), aad: utf8(platformWrapAAD(b)), wrap: toHex(wrap),
    }
  }
  const vs = [
    await make1('an account created through id. (users.id = sub)', 'new', '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b', '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b', 'wappie:1'),
    await make1('a linked pilot account (users.id kept)', 'linked', '01a08e0e-5a1c-7b2d-9e3f-4a5b6c7d8e9f', '019a2b3c-4d5e-7f60-8172-93a4b5c6d7e8', 'wappie:1'),
    await make1('the linked account at epoch 2', 'epoch2', '01a08e0e-5a1c-7b2d-9e3f-4a5b6c7d8e9f', '019a2b3c-4d5e-7f60-8172-93a4b5c6d7e8', 'wappie:2'),
  ]
  const flip = (i: number) => {
    const w = hex(vs[1]!.wrap)
    w[i]! ^= 0x01
    return toHex(w)
  }
  const other = await publicFromPrivate(await digest('other/account key'))
  // A wrap that authenticates under vector 1's K_pw and AAD but holds
  // another account's key, sealed here from section 6.8, since
  // sealPlatformWrap refuses to make it and K_pw is not extractable.
  const v1 = vs[1]!
  const ikm = await crypto.subtle.importKey('raw', hex(v1.product_key), 'HKDF', false, ['deriveKey'])
  const kpw = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: encodeUTF8(PLATFORM_WRAP_SALT), info: encodeUTF8(v1.info) }, ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt'])
  const fnonce = (await digest('foreign/nonce')).slice(0, 12)
  const fsealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: fnonce, additionalData: encodeUTF8(v1.aad) }, kpw, await digest('other/account key')))
  const foreign = toHex(Uint8Array.of(PLATFORM_WRAP_HEADER, ...fnonce, ...fsealed))
  return {
    description: "Wappie's platform wrap: the Wappie account key under a key derived from id.'s product key sk_p (platform decision 0023). " +
      'Keys, nonces and wraps are hex; info and aad are their UTF-8 text.',
    construction: [
      'K_pw = HKDF-SHA256(IKM = product_key, salt = UTF-8("wappie/platform-wrap/v1"), info = JCS(["wappie/platform-wrap", 1, user_id, sub, product_key_id]), L = 32)',
      'aad = JCS(["wappie/platform-wrap", 1, user_id, sub, product_key_id, base64url-unpadded(account_public_key)])',
      'wrap = 0x03 || nonce (12) || AES-256-GCM(K_pw, nonce, account_key (32), aad), 61 bytes',
      'Open also requires X25519(account_key, 9) == account_public_key; Seal refuses an account key whose public half is not account_public_key.',
    ],
    vectors: vs,
    open_refusals: [
      { name: 'another user_id', vector: 1, user_id: '01a08e0e-5a1c-7b2d-9e3f-4a5b6c7d8e90' },
      { name: 'another sub', vector: 1, sub: '019a2b3c-4d5e-7f60-8172-93a4b5c6d7e9' },
      { name: 'another epoch', vector: 1, product_key_id: 'wappie:2' },
      { name: 'another account public key', vector: 1, account_public_key: toHex(other) },
      { name: 'another product key', vector: 1, product_key: vs[2]!.product_key },
      { name: 'the epoch 2 wrap under epoch 1', vector: 1, wrap: vs[2]!.wrap },
      { name: 'a flipped nonce byte', vector: 1, wrap: flip(1) },
      { name: 'a flipped ciphertext byte', vector: 1, wrap: flip(20) },
      { name: 'a flipped tag byte', vector: 1, wrap: flip(60) },
      { name: 'version 2', vector: 1, wrap: '02' + vs[1]!.wrap.slice(2) },
      { name: '60 bytes', vector: 1, wrap: vs[1]!.wrap.slice(0, 120) },
      { name: '62 bytes', vector: 1, wrap: vs[1]!.wrap + '00' },
      { name: 'an uppercase sub', vector: 1, sub: '019A2B3C-4D5E-7F60-8172-93A4B5C6D7E8' },
      { name: "another product's key id", vector: 1, product_key_id: 'mailie:1' },
      { name: "a wrap that opens under its AAD to another account's key", vector: 1, wrap: foreign },
    ],
    seal_refusals: [
      { name: "an account key that is not the public key's", vector: 0, account_key: toHex(await digest('other/account key')) },
      { name: 'a 31-byte product key', vector: 0, product_key: vs[0]!.product_key.slice(0, 62) },
      { name: 'a user_id that is not a lowercase UUID', vector: 0, user_id: 'not-a-uuid' },
      { name: 'an epoch with a leading zero', vector: 0, product_key_id: 'wappie:01' },
      { name: "another product's key id", vector: 0, product_key_id: 'mailie:1' },
    ],
  }
}

describe('wappie/legacy/platform-wrap-vectors.json, the console\'s own file', () => {
  const file = raw('wappie/legacy/platform-wrap-vectors.json') as ConsoleFile
  const apply = (r: ConsoleRefusal): ConsoleVector => {
    const { name: _name, vector, ...over } = r
    return { ...file.vectors[vector]!, ...over }
  }

  it('is in the console\'s shape, with 3 vectors, 15 open refusals and 5 seal refusals', () => {
    expect(Object.keys(file)).toEqual(['description', 'construction', 'vectors', 'open_refusals', 'seal_refusals'])
    const vector = ['name', 'product_key', 'account_key', 'account_public_key', 'user_id', 'sub', 'product_key_id', 'nonce', 'info', 'aad', 'wrap']
    for (const v of file.vectors) expect(Object.keys(v)).toEqual(vector)
    for (const r of [...file.open_refusals, ...file.seal_refusals]) {
      for (const k of Object.keys(r)) expect(['name', 'vector', 'product_key', 'account_key', 'account_public_key', 'user_id', 'sub', 'product_key_id', 'wrap'].includes(k), k).toBe(true)
    }
    expect([file.vectors.length, file.open_refusals.length, file.seal_refusals.length]).toEqual([3, 15, 5])
  })

  it('reproduces every vector', async () => {
    for (const v of file.vectors) {
      const b = consoleBinding(v)
      expect(utf8(platformWrapInfo(b)), v.name).toBe(v.info)
      expect(utf8(platformWrapAAD(b)), v.name).toBe(v.aad)
      const wrap = await withDraws({ bytes: [hex(v.nonce)] }, () => sealPlatformWrap(hex(v.product_key), hex(v.account_key), b))
      expect(toHex(wrap), v.name).toBe(v.wrap)
      expect(toHex(await openPlatformWrap(hex(v.product_key), hex(v.wrap), b)), v.name).toBe(v.account_key)
    }
  })

  it('refuses every refusal', async () => {
    for (const r of file.open_refusals) {
      const v = apply(r)
      await refused(r.name, () => openPlatformWrap(hex(v.product_key), hex(v.wrap), consoleBinding(v)))
    }
    for (const r of file.seal_refusals) {
      const v = apply(r)
      await refused(r.name, () => sealPlatformWrap(hex(v.product_key), hex(v.account_key), consoleBinding(v)))
    }
  })

  it('is written again by this module, byte for byte', async () => {
    expect(JSON.stringify(await consoleFile(), null, 2) + '\n' === text('wappie/legacy/platform-wrap-vectors.json')).toBe(true)
  })
})

describe('the module', () => {
  const sk = new Uint8Array(32).fill(7) as Bytes, usk = new Uint8Array(32).fill(9) as Bytes
  const at = async (over: Partial<PlatformWrapBinding> = {}): Promise<PlatformWrapBinding> => ({
    userId: '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b', sub: '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b', productKeyId: 'wappie:1', accountPublicKey: await publicFromPrivate(usk), ...over,
  })

  it('has the values of SPEC section 6.8, apart from every other envelope of the account key', () => {
    expect([PLATFORM_WRAP_HEADER, PLATFORM_WRAP_LEN, PLATFORM_WRAP_LABEL, PLATFORM_WRAP_SALT, PLATFORM_WRAP_PRODUCT]).toEqual([0x03, 61, 'wappie/platform-wrap', 'wappie/platform-wrap/v1', 'wappie'])
    expect(wappieAccount.wrapHeader).toEqual([0x02])
    expect(wappiePasskey.header).toEqual([0x01])
    expect(PlatformWrapError).toBe(PlatformWrapErrorFromErrors)
    expect(isPlatformWrapError).toBe(isPlatformWrapErrorFromErrors)
  })

  it('draws a fresh nonce, never exports K_pw, and leaves the caller\'s keys as they were', async () => {
    const derive = vi.spyOn(crypto.subtle, 'deriveKey')
    const b = await at()
    const one = await sealPlatformWrap(sk, usk, b)
    const two = await sealPlatformWrap(sk, usk, b)
    expect(toHex(one.subarray(1, 13))).not.toBe(toHex(two.subarray(1, 13)))
    expect([one.length, one[0]]).toEqual([61, 0x03])
    expect(derive.mock.calls.length).toBeGreaterThan(0)
    for (const call of derive.mock.calls) expect(call[3]).toBe(false)
    expect(toHex(await openPlatformWrap(sk, one, b))).toBe(toHex(usk))
    expect([sk.every((x) => x === 7), usk.every((x) => x === 9)]).toEqual([true, true])
  })

  it('checks the shape the server checks', async () => {
    const w = await sealPlatformWrap(sk, usk, await at())
    checkPlatformWrapShape(w)
    for (const bad of [new Uint8Array(0), w.subarray(0, 60), Uint8Array.of(...w, 0), Uint8Array.of(0x01, ...w.subarray(1)), Uint8Array.of(0x02, ...w.subarray(1)), Uint8Array.of(0x00, ...w.subarray(1)), 'not bytes']) {
      expect(() => checkPlatformWrapShape(bad as Uint8Array)).toThrow(PlatformWrapError)
      await refused('a shape', async () => openPlatformWrap(sk, bad as Uint8Array, await at()))
    }
  })

  it('refuses a binding that is not one, and a wrap under another binding', async () => {
    const w = await sealPlatformWrap(sk, usk, await at())
    for (const b of [await at({ userId: '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c' }), await at({ productKeyId: 'wappie:2' }), await at({ productKeyId: 'mailie:1' })]) {
      await refused('another binding', () => openPlatformWrap(sk, w, b))
    }
    for (const b of [null, {}, await at({ accountPublicKey: new Uint8Array(31) }), await at({ sub: 'x' })]) {
      await refused('no binding', () => sealPlatformWrap(sk, usk, b as PlatformWrapBinding))
      expect(() => platformWrapAAD(b as PlatformWrapBinding)).toThrow(PlatformWrapError)
    }
    await refused('a product key that is not bytes', async () => sealPlatformWrap('x' as unknown as Uint8Array, usk, await at()))
    await refused('a product key of 33 bytes', async () => sealPlatformWrap(new Uint8Array(33), usk, await at()))
  })

  it('reports an engine without X25519 as a PlatformWrapError too', async () => {
    const b = await at()
    const w = await sealPlatformWrap(sk, usk, b)
    await withEngineRefusingX25519('NotSupportedError', async () => {
      await refused('no X25519, seal', () => sealPlatformWrap(sk, usk, b))
      await refused('no X25519, open', () => openPlatformWrap(sk, w, b))
    })
  })
})
