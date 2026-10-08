// Mailie's platform wrap (SPEC section 6.8 under Mailie's labels, Appendix
// D), in Node and in Chromium, Firefox and WebKit: the golden vectors the
// kit's Go code wrote (mailie/golden/platform-wrap-go.json), every seal
// replayed from its nonce, every open back to its account key, and every
// refusal a PlatformWrapError, the cross-product ones included (a Wappie
// wrap opened under Mailie's labels and a Mailie wrap under Wappie's); K_pw
// checked through the wrap envelope of section 6.5 (account.unwrapPrivateKey
// with the header 0x03).

import { describe, expect, it } from 'vitest'

import { unwrapPrivateKey, type AccountProfile } from '../src/account.js'
import { publicFromPrivate } from '../src/hpke.js'
import {
  checkPlatformWrapShape,
  isPlatformWrapError,
  openPlatformWrap,
  PLATFORM_WRAP_HEADER,
  platformWrapAAD,
  platformWrapInfo,
  sealPlatformWrap,
  type PlatformWrapBinding,
  type PlatformWrapProfile,
} from '../src/platformwrap.js'
import { mailiePlatformWrap, PLATFORM_WRAP_LABEL, PLATFORM_WRAP_PRODUCT, PLATFORM_WRAP_SALT } from '../src/profiles/mailie.js'
import { wappiePlatformWrap } from '../src/profiles/wappie.js'
import { b64, files, forTS, toB64, unhandled, withDraws, type VectorCase } from './vectors.js'

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

/** profileOf is the profile an op runs under, and the op's last part. */
function profileOf(op: string): [PlatformWrapProfile, string] | undefined {
  for (const p of [mailiePlatformWrap, wappiePlatformWrap]) {
    const prefix = `${p.product}.platform_wrap_`
    if (op.startsWith(prefix)) return [p, op.slice(prefix.length)]
  }
  return undefined
}

const counts: Record<string, number> = {}

for (const [path, f] of files('mailie/golden/platform-wrap-go.json')) {
  describe(path, () => {
    it('is the module the kit carries', () => {
      expect([f.module, f.profile, f.generated_by.lang]).toEqual(['mailie.platform_wrap', 'mailie', 'go'])
    })
    for (const c of f.cases.filter(forTS)) {
      counts[c.op] = (counts[c.op] ?? 0) + 1
      if (c.error !== undefined) counts.refused = (counts.refused ?? 0) + 1
      if (c.id.includes('/cross-product/')) counts['cross-product'] = (counts['cross-product'] ?? 0) + 1
      it(c.id, async () => run(c))
    }
  })
}

async function run(c: VectorCase): Promise<void> {
  const i = c.in as Record<string, string>
  for (const m of Object.keys(i)) expect(IN.includes(m), `case ${c.id}: a member no runner reads: ${m}`).toBe(true)
  for (const m of Object.keys(c.out ?? {})) expect(OUT.includes(m), `case ${c.id}: a member no runner reads: ${m}`).toBe(true)
  if (c.error !== undefined) expect(c.error).toBe('platform_wrap')
  const po = profileOf(c.op)
  if (po === undefined) return unhandled(c)
  const [p, op] = po
  const b = binding(i)
  switch (op) {
    case 'info':
      expect(toB64(platformWrapInfo(p, b))).toBe(c.out.info_b64)
      return
    case 'aad':
      expect(toB64(platformWrapAAD(p, b))).toBe(c.out.aad_b64)
      return
    case 'seal': {
      const sk = b64(i.product_key_b64!), usk = b64(i.account_key_b64!)
      if (c.error !== undefined) return refused(c.id, () => sealPlatformWrap(p, sk, usk, b))
      const wrap = await withDraws({ bytes: [b64(i.nonce_b64!)] }, () => sealPlatformWrap(p, sk, usk, b))
      expect(toB64(wrap)).toBe(c.out.wrap_b64)
      checkPlatformWrapShape(wrap)
      expect(toB64(await openPlatformWrap(p, sk, wrap, b))).toBe(i.account_key_b64)
      if (c.out.k_pw_b64 !== undefined) {
        // Section 6.5's envelope, header 0x03, no legacy form, under K_pw.
        const kpw = await crypto.subtle.importKey('raw', b64(c.out.k_pw_b64), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
        const opened = await unwrapPrivateKey(wrapProfile, wrap, kpw, platformWrapAAD(p, b))
        expect([toB64(opened.privateKey), opened.stale]).toEqual([i.account_key_b64, false])
      }
      return
    }
    case 'open': {
      const sk = b64(i.product_key_b64!), wrap = b64(i.wrap_b64!)
      if (c.error !== undefined) return refused(c.id, () => openPlatformWrap(p, sk, wrap, b))
      const key = await openPlatformWrap(p, sk, wrap, b)
      expect(toB64(key)).toBe(c.out.account_key_b64)
      expect(toB64(await publicFromPrivate(key))).toBe(i.account_public_key_b64)
      return
    }
  }
  unhandled(c)
}

describe('the golden file', () => {
  it('holds 60 cases, 36 of them refusals, 7 across the two products', () => {
    expect(counts).toEqual({
      'mailie.platform_wrap_info': 6, 'mailie.platform_wrap_aad': 6, 'mailie.platform_wrap_seal': 17,
      'mailie.platform_wrap_open': 28, 'wappie.platform_wrap_open': 3, refused: 36, 'cross-product': 7,
    })
  })
})

describe("Mailie's profile", () => {
  it('has the labels of SPEC Appendix D, none of them Wappie\'s', () => {
    expect(mailiePlatformWrap).toEqual({ product: 'mailie', salt: 'mailie/platform-wrap/v1', label: 'mailie/platform-wrap' })
    expect([PLATFORM_WRAP_LABEL, PLATFORM_WRAP_SALT, PLATFORM_WRAP_PRODUCT]).toEqual(['mailie/platform-wrap', 'mailie/platform-wrap/v1', 'mailie'])
    expect(Object.isFrozen(mailiePlatformWrap)).toBe(true)
    for (const v of Object.values(mailiePlatformWrap)) expect(Object.values(wappiePlatformWrap)).not.toContain(v)
  })
})
