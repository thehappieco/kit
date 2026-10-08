// The generic platform wrap (SPEC section 6.8, @thehappieco/kit/platformwrap),
// in Node and in Chromium, Firefox and WebKit: every product's golden file
// through the generic module under the op's profile, Wappie's bound
// functions as the generic ones under wappiePlatformWrap, the refusal of a
// profile outside its spelling, and products kept apart by their labels.

import { afterEach, describe, expect, it, vi } from 'vitest'

import type { Bytes } from '../src/bytes.js'
import { isPlatformWrapError as isPlatformWrapErrorFromErrors, PlatformWrapError as PlatformWrapErrorFromErrors } from '../src/errors.js'
import { publicFromPrivate } from '../src/hpke.js'
import {
  bind,
  checkPlatformWrapShape,
  isPlatformWrapError,
  openPlatformWrap,
  PLATFORM_WRAP_HEADER,
  PLATFORM_WRAP_LEN,
  PLATFORM_WRAP_VERSION,
  platformWrapAAD,
  platformWrapInfo,
  PlatformWrapError,
  sealPlatformWrap,
  type PlatformWrapBinding,
  type PlatformWrapProfile,
} from '../src/platformwrap.js'
import { mailiePlatformWrap } from '../src/profiles/mailie.js'
import * as wappie from '../src/profiles/wappie.js'
import { b64, files, toB64, withDraws, withEngineRefusingX25519 } from './vectors.js'

afterEach(() => {
  vi.restoreAllMocks()
})

/** vaultie is a profile of no product the kit carries, for the tests that need a second product's labels. */
const vaultie: PlatformWrapProfile = Object.freeze({ product: 'vaultie', salt: 'vaultie/platform-wrap/v1', label: 'vaultie/platform-wrap' })

/** refused expects a PlatformWrapError and nothing else. */
async function refused(id: string, fn: () => Promise<unknown> | unknown): Promise<void> {
  const err = await (async () => fn())().then(() => null, (e: unknown) => e)
  if (!isPlatformWrapError(err)) expect.fail(`${id}: expected platform_wrap, got ${err === null ? 'none' : (err as Error).name}`)
  expect(err.code).toBe('platform_wrap')
}

/** profileOf is the profile a golden case's op runs under. */
function profileOf(op: string): PlatformWrapProfile | undefined {
  if (op.startsWith('wappie.platform_wrap_')) return wappie.wappiePlatformWrap
  if (op.startsWith('mailie.platform_wrap_')) return mailiePlatformWrap
  return undefined
}

const goldenFiles = ['wappie/golden/platform-wrap-go.json', 'wappie/golden/platform-wrap-ts.json', 'mailie/golden/platform-wrap-go.json']

const binding = (i: Record<string, string>): PlatformWrapBinding => ({ userId: i.user_id!, sub: i.sub!, productKeyId: i.product_key_id!, accountPublicKey: b64(i.account_public_key_b64!) })

describe('every golden file through the generic module', () => {
  for (const [path, f] of files(...goldenFiles)) {
    it(`${path}: every seal replays and every refused open is refused`, async () => {
      let n = 0
      for (const c of f.cases) {
        const p = profileOf(c.op)
        if (p === undefined) expect.fail(`${c.id}: op ${c.op}`)
        const i = c.in as Record<string, string>
        if (c.op.endsWith('_seal') && c.error === undefined) {
          const wrap = await withDraws({ bytes: [b64(i.nonce_b64!)] }, () => sealPlatformWrap(p, b64(i.product_key_b64!), b64(i.account_key_b64!), binding(i)))
          expect(toB64(wrap), c.id).toBe(c.out.wrap_b64)
          n++
        } else if (c.op.endsWith('_open') && c.error !== undefined) {
          await refused(c.id, () => openPlatformWrap(p, b64(i.product_key_b64!), b64(i.wrap_b64!), binding(i)))
          n++
        }
      }
      expect(n).toBeGreaterThan(0)
    })
  }
})

describe('the module', () => {
  const sk = new Uint8Array(32).fill(7) as Bytes, usk = new Uint8Array(32).fill(9) as Bytes
  const at = async (p: PlatformWrapProfile, over: Partial<PlatformWrapBinding> = {}): Promise<PlatformWrapBinding> => ({
    userId: '019a7c1e-2b3d-7e4f-8a5b-6c7d8e9f0a1b', sub: '019a7c1e-2b3d-7e4f-8a5b-6c7d8e9f0a1b', productKeyId: `${p.product}:1`, accountPublicKey: await publicFromPrivate(usk), ...over,
  })

  it('has the fixed values of SPEC section 6.8, and Wappie\'s labels', () => {
    expect([PLATFORM_WRAP_HEADER, PLATFORM_WRAP_LEN, PLATFORM_WRAP_VERSION]).toEqual([0x03, 61, 1])
    expect(wappie.wappiePlatformWrap).toEqual({ product: 'wappie', salt: 'wappie/platform-wrap/v1', label: 'wappie/platform-wrap' })
    expect(wappie.wappiePlatformWrap).toEqual({ product: wappie.PLATFORM_WRAP_PRODUCT, salt: wappie.PLATFORM_WRAP_SALT, label: wappie.PLATFORM_WRAP_LABEL })
    expect(Object.isFrozen(wappie.wappiePlatformWrap)).toBe(true)
    expect([wappie.PLATFORM_WRAP_HEADER, wappie.PLATFORM_WRAP_LEN]).toEqual([PLATFORM_WRAP_HEADER, PLATFORM_WRAP_LEN])
    expect(PlatformWrapError).toBe(PlatformWrapErrorFromErrors)
    expect(isPlatformWrapError).toBe(isPlatformWrapErrorFromErrors)
    expect(wappie.PlatformWrapError).toBe(PlatformWrapError)
  })

  it("is Wappie's wrap under Wappie's labels, bound or not", async () => {
    const b = await at(wappie.wappiePlatformWrap)
    const w = bind(wappie.wappiePlatformWrap)
    expect(w.profile).toEqual(wappie.wappiePlatformWrap)
    expect(toB64(w.platformWrapInfo(b))).toBe(toB64(wappie.platformWrapInfo(b)))
    expect(toB64(platformWrapInfo(wappie.wappiePlatformWrap, b))).toBe(toB64(wappie.platformWrapInfo(b)))
    expect(toB64(w.platformWrapAAD(b))).toBe(toB64(wappie.platformWrapAAD(b)))
    expect(toB64(platformWrapAAD(wappie.wappiePlatformWrap, b))).toBe(toB64(wappie.platformWrapAAD(b)))
    const nonce = new Uint8Array(12).fill(5)
    const generic = await withDraws({ bytes: [nonce] }, () => sealPlatformWrap(wappie.wappiePlatformWrap, sk, usk, b))
    const bound = await withDraws({ bytes: [nonce] }, () => w.sealPlatformWrap(sk, usk, b))
    const wappies = await withDraws({ bytes: [nonce] }, () => wappie.sealPlatformWrap(sk, usk, b))
    expect([toB64(generic), toB64(bound)]).toEqual([toB64(wappies), toB64(wappies)])
    expect(toB64(await w.openPlatformWrap(sk, wappies, b))).toBe(toB64(usk))
    expect(toB64(await wappie.openPlatformWrap(sk, generic, b))).toBe(toB64(usk))
    expect(w.checkPlatformWrapShape).toBe(checkPlatformWrapShape)
  })

  it('refuses a profile outside its spelling, before anything is derived, and bind keeps a copy', async () => {
    const b = await at(vaultie)
    const wrap = await sealPlatformWrap(vaultie, sk, usk, b)
    for (const p of [
      null,
      {},
      { product: 'Vaultie', salt: vaultie.salt, label: vaultie.label },
      { product: '1vaultie', salt: vaultie.salt, label: vaultie.label },
      { product: '-vaultie', salt: vaultie.salt, label: vaultie.label },
      { product: 'vault|ie', salt: vaultie.salt, label: vaultie.label },
      { product: 'v'.repeat(33), salt: vaultie.salt, label: vaultie.label },
      { product: vaultie.product, salt: '', label: vaultie.label },
      { product: vaultie.product, salt: vaultie.salt, label: '' },
      { product: vaultie.product, salt: 'vaultie platform-wrap', label: vaultie.label },
      { product: vaultie.product, salt: vaultie.salt, label: 'vaultie/platform-wrap"' },
      { product: vaultie.product, salt: vaultie.salt, label: 'vaultie/platform-wrapé' },
      { product: vaultie.product, salt: 'vaultie/platform-wrap/v1\n', label: vaultie.label },
      { product: vaultie.product, salt: 1, label: vaultie.label },
    ] as unknown as PlatformWrapProfile[]) {
      const id = JSON.stringify(p)
      expect(() => platformWrapInfo(p, b), id).toThrow(/not a platform-wrap profile/)
      expect(() => platformWrapAAD(p, b), id).toThrow(/not a platform-wrap profile/)
      expect(() => bind(p), id).toThrow(/not a platform-wrap profile/)
      await refused(`seal under ${id}`, () => sealPlatformWrap(p, sk, usk, b))
      await refused(`open under ${id}`, () => openPlatformWrap(p, sk, wrap, b))
    }
    const mutable = { product: vaultie.product, salt: vaultie.salt, label: vaultie.label }
    const v = bind(mutable)
    mutable.salt = 'vaultie/platform-wrap/v2'
    expect(Object.isFrozen(v.profile)).toBe(true)
    expect(toB64(await v.openPlatformWrap(sk, wrap, b))).toBe(toB64(usk))
  })

  it('opens a wrap under its own profile only', async () => {
    const b = await at(vaultie)
    const wrap = await sealPlatformWrap(vaultie, sk, usk, b)
    expect(toB64(await openPlatformWrap(vaultie, sk, wrap, b))).toBe(toB64(usk))
    // Under Wappie's labels with the same key bytes, the binding naming
    // Wappie's key id or still Vaultie's; under one label changed; and under
    // the same labels for another product.
    await refused("another product's labels", async () => openPlatformWrap(wappie.wappiePlatformWrap, sk, wrap, { ...b, productKeyId: 'wappie:1' }))
    await refused("another product's binding", () => openPlatformWrap(wappie.wappiePlatformWrap, sk, wrap, b))
    await refused('another salt', () => openPlatformWrap({ ...vaultie, salt: 'vaultie/platform-wrap/v2' }, sk, wrap, b))
    await refused('another label', () => openPlatformWrap({ ...vaultie, label: 'vaultie/platform-wrap/x' }, sk, wrap, b))
    // The same labels under another product, the binding's key id naming it: the key id alone.
    await refused('another product with the same labels', () => openPlatformWrap({ ...vaultie, product: 'vaultie-two' }, sk, wrap, { ...b, productKeyId: 'vaultie-two:1' }))
    expect(() => platformWrapInfo(vaultie, { ...b, productKeyId: 'wappie:1' })).toThrow(/product_key_id is not a product key id of vaultie/)
  })

  it("draws a fresh nonce, never exports K_pw, and leaves the caller's keys as they were", async () => {
    const derive = vi.spyOn(crypto.subtle, 'deriveKey')
    const b = await at(vaultie)
    const one = await sealPlatformWrap(vaultie, sk, usk, b)
    const two = await sealPlatformWrap(vaultie, sk, usk, b)
    expect(toB64(one.subarray(1, 13))).not.toBe(toB64(two.subarray(1, 13)))
    expect([one.length, one[0]]).toEqual([61, 0x03])
    expect(derive.mock.calls.length).toBeGreaterThan(0)
    for (const call of derive.mock.calls) expect(call[3]).toBe(false)
    expect([sk.every((x) => x === 7), usk.every((x) => x === 9)]).toEqual([true, true])
    for (const bad of [new Uint8Array(0), one.subarray(0, 60), Uint8Array.of(...one, 0), Uint8Array.of(0x01, ...one.subarray(1)), Uint8Array.of(0x02, ...one.subarray(1)), 'not bytes']) {
      expect(() => checkPlatformWrapShape(bad as Uint8Array)).toThrow(PlatformWrapError)
      await refused('a shape', () => openPlatformWrap(vaultie, sk, bad as Uint8Array, b))
    }
  })

  it('reports an engine without X25519 as a PlatformWrapError too', async () => {
    const b = await at(vaultie)
    const w = await sealPlatformWrap(vaultie, sk, usk, b)
    await withEngineRefusingX25519('NotSupportedError', async () => {
      await refused('no X25519, seal', () => sealPlatformWrap(vaultie, sk, usk, b))
      await refused('no X25519, open', () => openPlatformWrap(vaultie, sk, w, b))
    })
  })
})
