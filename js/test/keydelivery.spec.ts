// Key delivery (SPEC section 11.12), PKCE (section 11.13) and the X25519
// helpers on this side alone: round trips, every AAD field, the akd_pub
// check, the 80-byte length, the canonical enc, engines without X25519, and
// what is left in memory afterwards. The golden vectors (platform.spec.ts)
// check the same functions against Go. Ported from the platform's
// web/test/crypto/keydelivery.spec.ts at 4476bf4; it runs in the browsers
// too.

import { afterEach, describe, expect, it, vi } from 'vitest'

import { concat, encodeUTF8, fromBase64URL, toBase64URL, type Bytes } from '../src/bytes.js'
import { HPKEError, PlatformError, type PlatformErrorCode } from '../src/errors.js'
import { seal as hpkeSeal } from '../src/hpke.js'
import { openBase, sealBase } from '../src/internal/platform/hpkebase.js'
import { rawFromPKCS8 } from '../src/internal/platform/x25519.js'
import * as platform from '../src/profiles/platform.js'
import { withEngineRefusingX25519 } from './vectors.js'

const ROOT = new Uint8Array(32).map((_, i) => 0x5a ^ (i * 7))

const random = (n: number) => crypto.getRandomValues(new Uint8Array(n)) as Bytes
const isZero = (b: Uint8Array) => b.every((x) => x === 0)

function same(a: string | Uint8Array, b: string | Uint8Array, label: string): void {
  const equal = typeof a === 'string' || typeof b === 'string' ? a === b : a.length === b.length && a.every((x, i) => x === b[i])
  if (!equal) expect.fail(`${label}: the values differ (not shown)`)
}

async function expectRefusal(fn: () => unknown, code: PlatformErrorCode, label = ''): Promise<void> {
  const at = label === '' ? '' : `${label}: `
  let caught: unknown
  try {
    await fn()
  } catch (err) {
    caught = err
  }
  if (!(caught instanceof PlatformError)) {
    expect.fail(`${at}expected PlatformError(${code}), got ${caught === undefined ? 'no error' : caught instanceof Error ? caught.name : typeof caught}`)
  }
  expect(caught.code, `${at}expected PlatformError(${code})`).toBe(code)
}

afterEach(() => {
  vi.restoreAllMocks()
})

async function request(): Promise<platform.KeyDeliveryRequest> {
  return {
    issuer: 'https://id.thehappie.co',
    clientId: 'wappie-app',
    redirectUri: 'https://app.wappie.thehappie.co/auth/callback',
    sub: '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b',
    codeChallenge: await platform.pkceChallenge(platform.newCodeVerifier()),
    nonce: toBase64URL(random(32)),
  }
}

async function bindingFor(r: platform.KeyDeliveryRequest, product = 'wappie', epoch = 1): Promise<platform.KeyDeliveryBinding> {
  const { sk, pub, id } = await platform.deriveProductKey(ROOT, product, epoch)
  sk.fill(0)
  return { ...r, productKeyId: id, productKey: pub }
}

/** The hex of the low-order and non-canonical points the check must refuse. */
const BAD_PUBLIC_KEYS: Record<string, string> = {
  zero: '0000000000000000000000000000000000000000000000000000000000000000',
  one: '0100000000000000000000000000000000000000000000000000000000000000',
  'order 8': 'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
  'order 8, the other': '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
  'p - 1': 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'p (non-canonical zero)': 'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'p + 1 (non-canonical one)': 'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'bit 255 set': '0900000000000000000000000000000000000000000000000000000000000080',
}

function hex(s: string): Bytes {
  return Uint8Array.from(s.match(/../g)!.map((h) => parseInt(h, 16))) as Bytes
}

describe('key delivery', () => {
  it('opens a key sealed for a flow with that flow\'s key, to the product key', async () => {
    const pair = await platform.generateX25519KeyPair()
    const r = await request()
    const delivered = await platform.deliverProductKey({ root: ROOT, product: 'wappie', epoch: 1, akdPub: toBase64URL(pair.publicKey), binding: r })
    expect(delivered.product_key_id).toBe('wappie:1')
    expect(fromBase64URL(delivered.akd_sealed, platform.SEALED_PRODUCT_KEY_LEN).length).toBe(80)
    const want = await platform.deriveProductKey(ROOT, 'wappie', 1)
    same(delivered.product_key, toBase64URL(want.pub), 'product_key')

    const binding = await bindingFor(r)
    // By raw bytes (the vectors, a command-line tool) and by a non-extractable key (oidc-rp).
    const byRaw = await platform.openProductKey(pair.privateKey, delivered.akd_sealed, binding)
    const byKey = await platform.openProductKey(await platform.importX25519PrivateKey(pair.privateKey), fromBase64URL(delivered.akd_sealed, 80), binding)
    same(byRaw, want.sk, 'sk_p opened by the raw key')
    same(byKey, want.sk, 'sk_p opened by the imported key')
  })

  it('seals with sealProductKey the blob deliverProductKey returns', async () => {
    const pair = await platform.generateX25519KeyPair()
    const r = await request()
    const sealed = await platform.sealProductKey({ root: ROOT, product: 'mailie', epoch: 3, akdPub: toBase64URL(pair.publicKey), binding: r })
    const sk = await platform.openProductKey(pair.privateKey, sealed, await bindingFor(r, 'mailie', 3))
    same(sk, (await platform.deriveProductKey(ROOT, 'mailie', 3)).sk, 'sk_p')
  })

  it('seals the same key for the same flow differently each time', async () => {
    // A fresh ephemeral key per seal: no two blobs share a context.
    const pair = await platform.generateX25519KeyPair()
    const r = await request()
    const input = { root: ROOT, product: 'wappie', epoch: 1, akdPub: toBase64URL(pair.publicKey), binding: r }
    expect(await platform.sealProductKey(input)).not.toBe(await platform.sealProductKey(input))
  })

  it('does not open a blob moved to another flow', async () => {
    const pair = await platform.generateX25519KeyPair()
    const r = await request()
    const sealed = await platform.sealProductKey({ root: ROOT, product: 'wappie', epoch: 1, akdPub: toBase64URL(pair.publicKey), binding: r })
    const good = await bindingFor(r)
    const other = await platform.deriveProductKey(new Uint8Array(32).fill(7), 'wappie', 1)
    const changes: [string, Partial<platform.KeyDeliveryBinding>][] = [
      ['issuer', { issuer: 'https://id.thehappie.co.evil.example' }],
      ['client_id', { clientId: 'mailie-console' }],
      ['redirect_uri', { redirectUri: 'https://app.wappie.thehappie.co/auth/callback2' }],
      ['sub', { sub: '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c' }],
      ['product_key_id', { productKeyId: 'wappie:2' }],
      ['product_key', { productKey: other.pub }],
      ['code_challenge', { codeChallenge: await platform.pkceChallenge(platform.newCodeVerifier()) }],
      ['nonce', { nonce: toBase64URL(random(32)) }],
    ]
    for (const [field, change] of changes) {
      // Each one alone; the error says no more than "does not open".
      await expectRefusal(() => platform.openProductKey(pair.privateKey, sealed, { ...good, ...change }), 'key_delivery', field)
    }
    // Another recipient.
    const stranger = await platform.generateX25519KeyPair()
    await expectRefusal(() => platform.openProductKey(stranger.privateKey, sealed, good), 'key_delivery')
  })

  it('does not open a blob that is not 80 bytes or was altered, or with a recipient key that is not 32 bytes', async () => {
    const pair = await platform.generateX25519KeyPair()
    const r = await request()
    const sealed = fromBase64URL(await platform.sealProductKey({ root: ROOT, product: 'wappie', epoch: 1, akdPub: toBase64URL(pair.publicKey), binding: r }), 80)
    const binding = await bindingFor(r)
    await expectRefusal(() => platform.openProductKey(pair.privateKey, sealed.slice(0, 79), binding), 'key_delivery')
    await expectRefusal(() => platform.openProductKey(pair.privateKey, concat(sealed, new Uint8Array(1)), binding), 'key_delivery')
    await expectRefusal(() => platform.openProductKey(pair.privateKey, toBase64URL(sealed.slice(0, 79)), binding), 'key_delivery')
    await expectRefusal(() => platform.openProductKey(pair.privateKey, `${toBase64URL(sealed)}=`, binding), 'key_delivery')
    for (const at of [0, 31, 32, 63, 64, 79]) {
      const flipped = sealed.slice()
      flipped[at] ^= 0x01
      await expectRefusal(() => platform.openProductKey(pair.privateKey, flipped, binding), 'key_delivery')
    }
    // A low-order enc fails in the exchange, the same way.
    const lowOrder = concat(new Uint8Array(32), sealed.slice(32))
    await expectRefusal(() => platform.openProductKey(pair.privateKey, lowOrder, binding), 'key_delivery')
    for (const n of [0, 31, 33]) await expectRefusal(() => platform.openProductKey(new Uint8Array(n), sealed, binding), 'key_delivery', `a ${n}-byte recipient key`)
  })

  it('refuses a blob whose sealer spelled enc with bit 255 set, though HPKE would open it', async () => {
    // A sealer that writes enc with bit 255 set into the blob and into its
    // KEM context alike: key delivery's own sealer, with WebCrypto's export
    // of the ephemeral public key spelled that way. X25519 reads that
    // spelling as the same point, so the HPKE layer opens the blob; only
    // the canonical check of openProductKey refuses it, as Go's does (the
    // golden vector of the same name).
    const pair = await platform.generateX25519KeyPair()
    const binding = await bindingFor(await request())
    const { sk } = await platform.deriveProductKey(ROOT, 'wappie', 1)
    const info = encodeUTF8(platform.KEY_DELIVERY_INFO)
    const aad = encodeUTF8(platform.keyDeliveryAAD(binding))
    const exportKey = crypto.subtle.exportKey.bind(crypto.subtle) as (format: string, key: CryptoKey) => Promise<ArrayBuffer | JsonWebKey>
    const spy = vi.spyOn(crypto.subtle, 'exportKey').mockImplementation((async (format: string, key: CryptoKey) => {
      const out = await exportKey(format, key)
      if (format !== 'raw' || key.type !== 'public') return out
      const aliased = new Uint8Array(out as ArrayBuffer)
      aliased[31] |= 0x80
      return aliased.buffer
    }) as typeof crypto.subtle.exportKey)
    let aliased: Bytes
    try {
      aliased = await sealBase(pair.publicKey, info, aad, sk)
    } finally {
      spy.mockRestore()
    }
    expect(aliased[31] & 0x80, 'the blob carries the bit-255 spelling').toBe(0x80)
    const recipient = await platform.importX25519PrivateKey(pair.privateKey)
    same(await openBase(recipient, pair.publicKey, aliased, info, aad), sk, 'what HPKE opens')
    await expectRefusal(() => platform.openProductKey(pair.privateKey, aliased, binding), 'key_delivery')
    await expectRefusal(() => platform.openProductKey(recipient, toBase64URL(aliased), binding), 'key_delivery')
    // The canonical spelling of a seal of the same key opens.
    same(await platform.openProductKey(recipient, await sealBase(pair.publicKey, info, aad, sk), binding), sk, 'the canonical seal')
  })

  it('refuses a blob that opens to another key than the product key as product_key, and zeroes it', async () => {
    // A page that seals some other key under the binding of the product key
    // the ID token names: the AAD matches, so it opens, and only the
    // comparison with product_key catches it.
    const pair = await platform.generateX25519KeyPair()
    const binding = await bindingFor(await request())
    const wrong = await platform.deriveProductKey(new Uint8Array(32).fill(9), 'wappie', 1)
    const { enc, ciphertext } = await hpkeSeal(pair.publicKey, encodeUTF8(platform.KEY_DELIVERY_INFO), encodeUTF8(platform.keyDeliveryAAD(binding)), wrong.sk)
    const opened: Uint8Array[] = []
    const decrypt = crypto.subtle.decrypt.bind(crypto.subtle)
    vi.spyOn(crypto.subtle, 'decrypt').mockImplementation(async (...args) => {
      const out = await decrypt(...args)
      opened.push(new Uint8Array(out))
      return out
    })
    await expectRefusal(() => platform.openProductKey(pair.privateKey, concat(enc, ciphertext), binding), 'product_key')
    vi.restoreAllMocks()
    expect(opened).toHaveLength(1)
    expect(isZero(opened[0]), 'the opened key was zeroed').toBe(true)
  })

  it('refuses to seal to an akd_pub that is low order, non-canonical or not 32 bytes of strict base64url', async () => {
    const r = await request()
    for (const [name, h] of Object.entries(BAD_PUBLIC_KEYS)) {
      await expectRefusal(() => platform.sealProductKey({ root: ROOT, product: 'wappie', epoch: 1, akdPub: toBase64URL(hex(h)), binding: r }), 'key_delivery', name)
    }
    for (const akdPub of ['', 'AAAA', toBase64URL(random(31)), toBase64URL(random(33)), `${toBase64URL(random(32))}=`]) {
      await expectRefusal(() => platform.sealProductKey({ root: ROOT, product: 'wappie', epoch: 1, akdPub, binding: r }), 'key_delivery')
    }
  })

  it('refuses to seal under a binding the AAD cannot carry', async () => {
    const pair = await platform.generateX25519KeyPair()
    const akdPub = toBase64URL(pair.publicKey)
    const r = await request()
    const bad: Partial<platform.KeyDeliveryRequest>[] = [
      { issuer: '' },
      { issuer: 'https://id.thehappie.co/?x' },
      { issuer: 'https://id.thehappie.coé' },
      { clientId: 'wappie app' },
      { clientId: 'wappie"app' },
      { redirectUri: 'https://app.wappie.thehappie.co/auth/callback?x=1' },
      { sub: '0199A1B2-C3D4-7E5F-8A6B-7C8D9E0F1A2B' },
      { sub: '0199a1b2c3d47e5f8a6b7c8d9e0f1a2b' },
      { codeChallenge: r.codeChallenge.slice(0, 42) },
      { codeChallenge: `${r.codeChallenge}A` },
      // 43 characters whose last two bits are not zero: not the spelling of any digest.
      { codeChallenge: `${'A'.repeat(42)}B` },
      { nonce: 'a'.repeat(21) },
      { nonce: 'a'.repeat(129) },
      { nonce: `${'a'.repeat(30)}.` },
    ]
    for (const [i, change] of bad.entries()) {
      await expectRefusal(
        () => platform.sealProductKey({ root: ROOT, product: 'wappie', epoch: 1, akdPub, binding: { ...r, ...change } }),
        'key_delivery',
        `bad binding ${i} (${Object.keys(change).join()})`,
      )
    }
    // The bounds of the nonce are inside.
    for (const nonce of ['a'.repeat(22), 'A-_9'.repeat(32)]) {
      await platform.sealProductKey({ root: ROOT, product: 'wappie', epoch: 1, akdPub, binding: { ...r, nonce } })
    }
  })

  it('binds the JCS array of section 11.12 as its AAD', async () => {
    const r = await request()
    const b = await bindingFor(r)
    expect(platform.keyDeliveryAAD(b)).toBe(
      `["thehappie-id/key-delivery",1,"https://id.thehappie.co","wappie-app","https://app.wappie.thehappie.co/auth/callback",` +
        `"${r.sub}","wappie:1","${toBase64URL(b.productKey as Bytes)}","${r.codeChallenge}","${r.nonce}"]`,
    )
    for (const productKeyId of ['wappie', 'wappie:0', 'wappie:01', 'wappie:+1', 'Wappie:1', 'wappie:2147483648', ':1', 'wappie:1:1', 'wappie:1 ']) {
      expect(platform.isProductKeyId(productKeyId), productKeyId).toBe(false)
      await expectRefusal(() => platform.keyDeliveryAAD({ ...b, productKeyId }), 'key_delivery')
    }
    await expectRefusal(() => platform.keyDeliveryAAD({ ...b, productKey: b.productKey.slice(1) }), 'key_delivery')
    expect(platform.keyDeliveryAAD({ ...b, productKeyId: 'wappie:2147483647' })).toContain('"wappie:2147483647"')
    expect(platform.isProductKeyId('wappie:2147483647')).toBe(true)
    expect(platform.KEY_DELIVERY_AAD_LABEL).toBe('thehappie-id/key-delivery')
    expect(platform.KEY_DELIVERY_VERSION).toBe(1)
  })

  it('refuses a root, product or epoch that names no product key as product_key', async () => {
    const pair = await platform.generateX25519KeyPair()
    const r = await request()
    const akdPub = toBase64URL(pair.publicKey)
    await expectRefusal(() => platform.sealProductKey({ root: ROOT.slice(1), product: 'wappie', epoch: 1, akdPub, binding: r }), 'product_key')
    await expectRefusal(() => platform.sealProductKey({ root: ROOT, product: 'Wappie', epoch: 1, akdPub, binding: r }), 'product_key')
    await expectRefusal(() => platform.sealProductKey({ root: ROOT, product: 'wappie', epoch: 0, akdPub, binding: r }), 'product_key')
  })

  it('leaves no copy of the product private key in a page buffer after sealing', async () => {
    // sk_p is derived, sealed and zeroed; every PKCS#8 buffer that carried a
    // private key into WebCrypto is zeroed too, and nothing the seal hands
    // to encrypt keeps sk_p once it returns.
    const pair = await platform.generateX25519KeyPair()
    const r = await request()
    const want = await platform.deriveProductKey(ROOT, 'wappie', 1)
    const importSpy = vi.spyOn(crypto.subtle, 'importKey')
    const encryptSpy = vi.spyOn(crypto.subtle, 'encrypt')
    await platform.sealProductKey({ root: ROOT, product: 'wappie', epoch: 1, akdPub: toBase64URL(pair.publicKey), binding: r })
    const views = (calls: unknown[][], at: number): Uint8Array[] =>
      calls
        .map((c) => c[at])
        .filter((d): d is ArrayBufferView => ArrayBuffer.isView(d))
        .map((v) => new Uint8Array(v.buffer, v.byteOffset, v.byteLength))
    const pkcs8 = importSpy.mock.calls.filter(([format]) => format === 'pkcs8')
    expect(pkcs8.length).toBeGreaterThan(0)
    for (const buf of views(pkcs8, 1)) expect(isZero(buf), 'a PKCS#8 import buffer was zeroed').toBe(true)
    // The plaintext handed to AES-GCM was sk_p; it is zero now.
    const plaintexts = views(encryptSpy.mock.calls, 2)
    expect(plaintexts).toHaveLength(1)
    expect(isZero(plaintexts[0]), 'sk_p was zeroed after the seal').toBe(true)
    vi.restoreAllMocks()
    expect(isZero(want.sk)).toBe(false)
  })

  // An engine without X25519 is not a verdict on a blob or a key (SPEC
  // section 11.10): the hpke module's HPKEError invalid_key passes through,
  // its cause the engine's NotSupportedError. An engine that refuses the
  // key it is given is still key_delivery.
  it('is not refused as key_delivery by an engine without X25519', async () => {
    const pair = await platform.generateX25519KeyPair()
    const r = await request()
    const input = { root: ROOT, product: 'wappie', epoch: 1, akdPub: toBase64URL(pair.publicKey), binding: r }
    const sealed = await platform.sealProductKey(input)
    const binding = await bindingFor(r)
    const noEngine = async (fn: () => Promise<unknown>) => {
      let caught: unknown
      await withEngineRefusingX25519('NotSupportedError', async () => {
        try {
          await fn()
        } catch (err) {
          caught = err
        }
      })
      expect(caught).toBeInstanceOf(HPKEError)
      expect((caught as HPKEError).code).toBe('invalid_key')
      expect(((caught as HPKEError).cause as DOMException).name).toBe('NotSupportedError')
    }
    await noEngine(() => platform.sealProductKey(input))
    await noEngine(() => platform.openProductKey(pair.privateKey, sealed, binding))
    await noEngine(() => platform.checkX25519PublicKey(pair.publicKey, 'key_delivery'))
    await noEngine(() => platform.generateX25519KeyPair())
    await noEngine(() => platform.importX25519PrivateKey(pair.privateKey))
    await withEngineRefusingX25519('DataError', async () => {
      await expectRefusal(() => platform.sealProductKey(input), 'key_delivery')
      await expectRefusal(() => platform.openProductKey(pair.privateKey, sealed, binding), 'key_delivery')
    })
  })
})

describe('the X25519 public key check (section 11.4)', () => {
  it('refuses the low-order and non-canonical points', async () => {
    for (const [name, h] of Object.entries(BAD_PUBLIC_KEYS)) {
      await expectRefusal(() => platform.checkX25519PublicKey(hex(h), 'key_delivery'), 'key_delivery', name)
      await expectRefusal(() => platform.checkX25519PublicKey(hex(h), 'product_key'), 'product_key', name)
    }
    await expectRefusal(() => platform.checkX25519PublicKey(new Uint8Array(31), 'key_delivery'), 'key_delivery')
    expect(platform.isCanonicalX25519(hex(BAD_PUBLIC_KEYS['bit 255 set']))).toBe(false)
    expect(platform.isCanonicalX25519(new Uint8Array(31))).toBe(false)
  })

  it('accepts what X25519 produces', async () => {
    for (let i = 0; i < 8; i++) {
      const { publicKey } = await platform.generateX25519KeyPair()
      expect(platform.isCanonicalX25519(publicKey)).toBe(true)
      await platform.checkX25519PublicKey(publicKey, 'key_delivery')
    }
    // The largest canonical value that is not low order: p - 2.
    await platform.checkX25519PublicKey(hex('ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'), 'key_delivery')
  })

  it('generates a consistent pair and zeroes its export buffer', async () => {
    const exported: ArrayBuffer[] = []
    const exportKey = crypto.subtle.exportKey.bind(crypto.subtle) as (format: string, key: CryptoKey) => Promise<ArrayBuffer | JsonWebKey>
    vi.spyOn(crypto.subtle, 'exportKey').mockImplementation((async (format: string, key: CryptoKey) => {
      const out = await exportKey(format, key)
      if (format === 'pkcs8') exported.push(out as ArrayBuffer)
      return out
    }) as typeof crypto.subtle.exportKey)
    const pair = await platform.generateX25519KeyPair()
    same(await platform.x25519PublicFromKey(await platform.importX25519PrivateKey(pair.privateKey)), pair.publicKey, 'the public half')
    vi.restoreAllMocks()
    expect(exported).toHaveLength(1)
    expect(isZero(new Uint8Array(exported[0])), 'the PKCS#8 export was zeroed').toBe(true)
    expect(platform.X25519_KEY_LEN).toBe(32)
  })

  it('reads a generated pair from either PKCS#8 form, and refuses one that does not match', async () => {
    // What an engine's export is turned into, from the 48-byte form every
    // current engine writes.
    const forms: [string, (der: Uint8Array) => Uint8Array, boolean][] = [
      ['the 48-byte form', (der) => der, true],
      // RFC 5958 version 1, with the public key as [1] after the private one.
      ['version 1 with the public key', (der) => Uint8Array.of(0x30, 0x51, 0x02, 0x01, 0x01, ...der.slice(5, 48), 0x81, 0x21, 0x00, ...new Uint8Array(32).fill(0xaa)), true],
      ['a long-form length', (der) => Uint8Array.of(0x30, 0x81, 0x2e, ...der.slice(2)), false],
      ['a length that does not cover the export', (der) => Uint8Array.of(...der, 0x00), false],
      ['version 2', (der) => Uint8Array.of(...der.slice(0, 4), 0x02, ...der.slice(5)), false],
      ['the Ed25519 algorithm', (der) => Uint8Array.of(...der.slice(0, 11), 0x70, ...der.slice(12)), false],
      ['another private key than the public one', (der) => Uint8Array.of(...der.slice(0, 16), ...der.slice(16).map((b) => b ^ 0x01)), false],
    ]
    const exportKey = crypto.subtle.exportKey.bind(crypto.subtle) as (format: string, key: CryptoKey) => Promise<ArrayBuffer | JsonWebKey>
    for (const [name, reshape, ok] of forms) {
      const handed: Uint8Array[] = []
      vi.spyOn(crypto.subtle, 'exportKey').mockImplementation((async (format: string, key: CryptoKey) => {
        const out = await exportKey(format, key)
        if (format !== 'pkcs8') return out
        const der = reshape(new Uint8Array(out as ArrayBuffer))
        handed.push(der)
        return der.buffer
      }) as typeof crypto.subtle.exportKey)
      try {
        if (ok) {
          const pair = await platform.generateX25519KeyPair()
          same(await platform.x25519PublicFromKey(await platform.importX25519PrivateKey(pair.privateKey)), pair.publicKey, name)
        } else {
          await expect(platform.generateX25519KeyPair(), name).rejects.toThrow()
        }
      } finally {
        vi.restoreAllMocks()
      }
      expect(handed, name).toHaveLength(1)
      expect(isZero(handed[0]), `${name}: the export was zeroed`).toBe(true)
    }
    expect(rawFromPKCS8(new Uint8Array(47))).toBeNull()
  })

  it('imports a private key only of 32 bytes, through a buffer it zeroes', async () => {
    for (const n of [0, 31, 33]) await expect(platform.importX25519PrivateKey(new Uint8Array(n))).rejects.toThrow(TypeError)
    const importSpy = vi.spyOn(crypto.subtle, 'importKey')
    const key = await platform.importX25519PrivateKey(random(32))
    expect(key.extractable).toBe(false)
    const pkcs8 = importSpy.mock.calls.filter(([format]) => format === 'pkcs8').map((c) => c[1] as Uint8Array)
    expect(pkcs8).toHaveLength(1)
    expect(isZero(pkcs8[0])).toBe(true)
  })
})

describe('PKCE S256', () => {
  it('gives the challenge of the RFC 7636 example', async () => {
    // RFC 7636, appendix B.
    expect(await platform.pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
  })

  it('refuses a verifier outside the alphabet or the lengths', async () => {
    for (const v of ['a'.repeat(42), 'a'.repeat(129), `${'a'.repeat(42)}+`, `${'a'.repeat(42)}/`, `${'a'.repeat(42)}=`, `${'a'.repeat(42)} `, `${'a'.repeat(42)}é`]) {
      expect(platform.isCodeVerifier(v)).toBe(false)
      await expectRefusal(() => platform.pkceChallenge(v), 'pkce')
    }
    for (const v of ['a'.repeat(43), 'a'.repeat(128), `${'A0'.repeat(21)}._~-`]) {
      expect((await platform.pkceChallenge(v)).length).toBe(platform.CODE_CHALLENGE_LEN)
    }
    // Every byte outside the unreserved set, in a verifier otherwise valid.
    for (let c = 0; c < 256; c++) {
      const ch = String.fromCharCode(c)
      if (/[A-Za-z0-9._~-]/.test(ch)) continue
      await expectRefusal(() => platform.pkceChallenge(`${'a'.repeat(42)}${ch}`), 'pkce', `0x${c.toString(16)}`)
    }
  })

  it('makes new verifiers of 43 characters that it accepts', () => {
    for (let i = 0; i < 16; i++) {
      const v = platform.newCodeVerifier()
      expect(v.length).toBe(43)
      expect(platform.isCodeVerifier(v)).toBe(true)
      expect(platform.CODE_VERIFIER_PATTERN.test(v)).toBe(true)
    }
  })
})
