// The kit's generator of vectors/wappie/golden/platform-wrap-ts.json. The
// kit's vectors/wappie/_generators/run-cloud.sh places it beside the
// console's web/platform/platformWrap.ts, in a git archive of the console
// commit PROVENANCE.md records (with the header patch recorded there, if
// any), and runs it with vitest against the kit release the console's
// lockfile pins. It writes the kit's format from that module's own
// functions. Every key and nonce is SHA-256 of a fixed label, other labels
// than the Go generator's, so each language reproduces cases the other
// wrote; the module's K_pw is a non-extractable CryptoKey and is not
// recorded. Every refusal is checked against the module before it is
// written, and the file is opened with the wx flag (O_EXCL).
import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { it } from 'vitest'
import { publicFromPrivate } from '@thehappieco/kit/hpke'
import {
  isPlatformWrapError,
  openPlatformWrap,
  PLATFORM_WRAP_VERSION,
  platformWrapAAD,
  platformWrapInfo,
  sealPlatformWrap,
  type PlatformWrapBinding,
} from '../platform/platformWrap'

const digest = async (label: string) => new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`wappie/platform-wrap kit vectors/ts/${label}`)))
const std = (b: Uint8Array) => btoa(String.fromCharCode(...b))
const unstd = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0))

interface KitCase { id: string; op: string; in: Record<string, unknown>; out?: Record<string, unknown>; error?: string }

/** version is the installed version of a package of the directory vitest runs in. */
function version(name: string): string {
  return JSON.parse(readFileSync(join(process.cwd(), 'node_modules', name, 'package.json'), 'utf8')).version
}

it.skipIf(!process.env.KITGEN_OUT)('writes platform-wrap-ts.json', async () => {
  if (PLATFORM_WRAP_VERSION !== 0x03) throw new Error(`the module's first byte is ${PLATFORM_WRAP_VERSION}; SPEC section 6.8 fixes 0x03`)
  const cases: KitCase[] = []
  const zeroFirst = async (label: string) => {
    for (let i = 0; ; i++) {
      const k = await digest(`${label}/${i}`)
      if (k[0] === 0) return k
    }
  }
  const vs = [
    { name: 'new', userId: '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a30', sub: '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a30', productKeyId: 'wappie:1', sk: await digest('new/product key'), usk: await digest('new/account key'), nonce: (await digest('new/nonce')).subarray(0, 12) },
    { name: 'linked', userId: '01a08e0e-5a1c-7b2d-9e3f-4a5b6c7d8e30', sub: '019a2b3c-4d5e-7f60-8172-93a4b5c6d730', productKeyId: 'wappie:7', sk: await digest('linked/product key'), usk: await digest('linked/account key'), nonce: (await digest('linked/nonce')).subarray(0, 12) },
    { name: 'account-key-zero-first-byte', userId: '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a31', sub: '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a31', productKeyId: 'wappie:1', sk: await digest('zero/product key'), usk: await zeroFirst('zero/account key'), nonce: (await digest('zero/nonce')).subarray(0, 12) },
  ]
  const wraps: Record<string, Uint8Array> = {}
  const bindingIn = (b: PlatformWrapBinding) => ({ user_id: b.userId, sub: b.sub, product_key_id: b.productKeyId, account_public_key_b64: std(b.accountPublicKey) })
  const bindingOf = (i: Record<string, unknown>): PlatformWrapBinding => ({
    userId: i.user_id as string, sub: i.sub as string, productKeyId: i.product_key_id as string, accountPublicKey: unstd(i.account_public_key_b64 as string),
  })
  for (const v of vs) {
    const b: PlatformWrapBinding = { userId: v.userId, sub: v.sub, productKeyId: v.productKeyId, accountPublicKey: await publicFromPrivate(new Uint8Array(v.usk)) }
    const wrap = await sealPlatformWrap(v.sk, v.usk, b, v.nonce)
    const opened = await openPlatformWrap(v.sk, wrap, b)
    if (std(opened) !== std(v.usk)) throw new Error(`${v.name}: does not open`)
    wraps[v.name] = wrap
    const i = bindingIn(b)
    cases.push(
      { id: `wappie/platform-wrap/info/${v.name}`, op: 'wappie.platform_wrap_info', in: i, out: { info_b64: std(platformWrapInfo(b)) } },
      { id: `wappie/platform-wrap/aad/${v.name}`, op: 'wappie.platform_wrap_aad', in: i, out: { aad_b64: std(platformWrapAAD(b)) } },
      { id: `wappie/platform-wrap/seal/${v.name}`, op: 'wappie.platform_wrap_seal', in: { ...i, product_key_b64: std(v.sk), account_key_b64: std(v.usk), nonce_b64: std(v.nonce) }, out: { wrap_b64: std(wrap) } },
      { id: `wappie/platform-wrap/open/${v.name}`, op: 'wappie.platform_wrap_open', in: { ...i, product_key_b64: std(v.sk), wrap_b64: std(wrap) }, out: { account_key_b64: std(v.usk) } },
    )
  }
  // Open refusals, all of the binding "linked", one thing changed each.
  const l = vs[1]!
  const lb: PlatformWrapBinding = { userId: l.userId, sub: l.sub, productKeyId: l.productKeyId, accountPublicKey: await publicFromPrivate(new Uint8Array(l.usk)) }
  const lw = wraps.linked!
  const edit = (f: (w: Uint8Array) => Uint8Array) => f(new Uint8Array(lw))
  const base = { ...bindingIn(lb), product_key_b64: std(l.sk) }
  const openRefusals: [string, Record<string, unknown>][] = [
    ['another-user-id', { ...base, wrap_b64: std(lw), user_id: '01a08e0e-5a1c-7b2d-9e3f-4a5b6c7d8e31' }],
    ['another-epoch', { ...base, wrap_b64: std(lw), product_key_id: 'wappie:8' }],
    ['header-0x01-the-passkey-envelope', { ...base, wrap_b64: std(edit((w) => { w[0] = 0x01; return w })) }],
    ['header-0x02-the-password-wrap', { ...base, wrap_b64: std(edit((w) => { w[0] = 0x02; return w })) }],
    ['flipped-tag', { ...base, wrap_b64: std(edit((w) => { w[60]! ^= 1; return w })) }],
    ['length-60', { ...base, wrap_b64: std(lw.subarray(0, 60)) }],
    ['the-new-accounts-wrap', { ...base, wrap_b64: std(wraps.new!) }],
  ]
  for (const [id, i] of openRefusals) {
    const err = await openPlatformWrap(unstd(i.product_key_b64 as string), unstd(i.wrap_b64 as string), bindingOf(i)).then(() => null, (e: unknown) => e)
    if (!isPlatformWrapError(err)) throw new Error(`open refusal ${id}: opened`)
    cases.push({ id: `wappie/platform-wrap/open/refuses/${id}`, op: 'wappie.platform_wrap_open', in: i, error: 'platform_wrap' })
  }
  // Seal refusals, of the binding "new".
  const n = vs[0]!
  const nb = { ...bindingIn({ userId: n.userId, sub: n.sub, productKeyId: n.productKeyId, accountPublicKey: await publicFromPrivate(new Uint8Array(n.usk)) }), product_key_b64: std(n.sk), account_key_b64: std(n.usk) }
  const sealRefusals: [string, Record<string, unknown>][] = [
    ['account-key-not-the-public-keys', { ...nb, account_key_b64: std(l.usk) }],
    ['user-id-with-a-brace', { ...nb, user_id: '{0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a30}' }],
    ['product-key-id-of-another-product', { ...nb, product_key_id: 'vaultie:1' }],
  ]
  for (const [id, i] of sealRefusals) {
    const err = await sealPlatformWrap(unstd(i.product_key_b64 as string), unstd(i.account_key_b64 as string), bindingOf(i)).then(() => null, (e: unknown) => e)
    if (!isPlatformWrapError(err)) throw new Error(`seal refusal ${id}: sealed`)
    cases.push({ id: `wappie/platform-wrap/seal/refuses/${id}`, op: 'wappie.platform_wrap_seal', in: i, error: 'platform_wrap' })
  }
  const file = {
    format: 'thehappieco-kit-vectors/1',
    module: 'wappie.platform_wrap',
    profile: 'wappie',
    generated_by: {
      lang: 'ts',
      source: `github.com/thehappieco/wappie-cloud@${process.env.KITGEN_COMMIT} web/platform/platformWrap.ts${process.env.KITGEN_PATCHED ?? ''}`,
      toolchain: `node ${process.version}; @thehappieco/kit ${version('@thehappieco/kit')}; vitest ${version('vitest')} (sources transpiled by vitest)`,
      randomness: 'none: every key and nonce is SHA-256 of a fixed label',
      generator: 'vectors/wappie/_generators/cloud/web/test/kitgen.spec.ts',
    },
    note: "Wappie's platform wrap (SPEC section 6.8), written by the console's TypeScript module; its K_pw is a non-extractable CryptoKey and is not recorded. The bindings use labels of their own, one with an account key whose first byte is zero.",
    cases,
  }
  writeFileSync(join(process.env.KITGEN_OUT!, 'platform-wrap-ts.json'), JSON.stringify(file, null, 2) + '\n', { flag: 'wx' })
})
