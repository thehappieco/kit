// The platform profile's own rules, beyond what its vectors pin: the order
// of refusals (the KDF bounds before any derivation, observed through the
// worker factory, which runs only once every check has passed), zeroing,
// the self-test of a new wrap, and the strictness of the key-bundle reader.
// Ported from the platform's web/test/crypto, without Node APIs: these run
// in the browsers too.

import { argon2id } from '@noble/hashes/argon2.js'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { derive } from '../src/account.js'
import { encodeUTF8, fromBase64URL, toBase64URL, type Bytes } from '../src/bytes.js'
import { HPKEError, isPlatformError, PlatformError, type PlatformErrorCode } from '../src/errors.js'
import * as platform from '../src/profiles/platform.js'
import { loadPlatform, withDraws, withEngineRefusingX25519 } from './vectors.js'

const ch = (...cps: number[]) => String.fromCodePoint(...cps)

async function refusal(fn: () => unknown): Promise<string> {
  try {
    await fn()
  } catch (err) {
    if (err instanceof PlatformError) return err.code
    return `not a PlatformError: ${err instanceof Error ? err.name : typeof err}`
  }
  return 'none'
}

async function expectRefusal(fn: () => unknown, code: PlatformErrorCode): Promise<void> {
  expect(await refusal(fn)).toBe(code)
}

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')

/** A stand-in KDF worker that derives as kdf.worker.ts does and keeps what it was sent. */
function fakeWorker() {
  const state = { started: 0, sent: [] as Uint8Array[] }
  const factory = () => {
    state.started++
    const w = {
      onmessage: null as ((e: MessageEvent) => void) | null,
      onerror: null as (() => void) | null,
      postMessage(msg: { password: Uint8Array; salt: Uint8Array; m: number; t: number; p: number }) {
        state.sent.push(msg.password)
        const master = argon2id(msg.password.slice(), msg.salt, { m: msg.m, t: msg.t, p: msg.p, dkLen: 32 })
        queueMicrotask(() => w.onmessage?.({ data: { ok: true, master } } as MessageEvent))
      },
      terminate() {},
    }
    return w as unknown as Worker
  }
  return { state, factory }
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('the profile', () => {
  it('is the kit\'s account scheme with the platform\'s values', async () => {
    const p = platform.platformAccount
    expect([p.authLabel, p.wrapLabel, p.recoveryKeyLabel, p.recoveryProofLabel]).toEqual([
      'thehappie-id/v1/password/auth', 'thehappie-id/v1/password/wrap', 'thehappie-id/v1/recovery/wrap', 'thehappie-id/v1/recovery/auth',
    ])
    expect([Array.from(p.wrapHeader), p.legacyV1, p.encoding]).toEqual([[1, 1], false, 'base64url'])
    expect(p.bounds).toEqual({ min: { m: 65536, t: 3, p: 1 }, max: { m: 262144, t: 10, p: 4 }, maxCost: 1048576, minSaltLen: 16, maxSaltLen: 16 })
    expect(Object.isFrozen(p)).toBe(true)
    for (const [kind, byte] of [['password', 1], ['recovery', 2], ['passkey', 3]] as [platform.WrapKind, number][]) {
      expect(Array.from(platform.platformRootWrap(kind).wrapHeader)).toEqual([1, byte])
    }
    await expectRefusal(() => platform.platformRootWrap('toString' as platform.WrapKind), 'wrap')
    expect(platform.DEFAULT_KDF).toEqual({ alg: 'argon2id', m: 65536, t: 3, p: 1 })
    // account.derive with the platform's profile prepares the presented
    // password and derives what the vectors record.
    const c = loadPlatform('kdf').cases.find((x) => x.name === 'the floor parameters')!
    const d = await derive(p, 'correct horse battery staple', fromBase64URL(c.salt, 16), c.kdf)
    expect(d.authKey).toBe(c.k_auth)
  })
})

describe('the password profile', () => {
  const NEW = { isNew: true }
  const OLD = { isNew: false }

  it('composes, maps every other space, and does not trim', () => {
    expect(platform.preparePasswordText('cafe' + ch(0x301) + ' au lait 42', NEW)).toBe('caf' + ch(0xe9) + ' au lait 42')
    for (const cp of [0xa0, 0x1680, 0x2000, 0x2001, 0x2005, 0x200a, 0x202f, 0x205f, 0x3000]) {
      expect(platform.preparePasswordText('correct' + ch(cp) + 'horse battery', NEW)).toBe('correct horse battery')
    }
    // U+200B ZERO WIDTH SPACE is a format character, not a space separator.
    expect(platform.preparePasswordText('correct' + ch(0x200b) + 'horse', OLD)).toBe('correct' + ch(0x200b) + 'horse')
    expect(platform.preparePasswordText('  twelve chars  ', NEW)).toBe('  twelve chars  ')
    expect(toBase64URL(platform.preparePassword('caf' + ch(0xe9), OLD))).toBe(toBase64URL(encodeUTF8('caf' + ch(0xe9))))
  })

  it('refuses controls and lone surrogates, before the length', async () => {
    for (let cp = 0; cp < 0xa0; cp++) {
      const control = cp <= 0x1f || cp >= 0x7f
      expect(await refusal(() => platform.preparePassword('password-' + ch(cp) + '-1234', OLD)), `U+${cp.toString(16)}`).toBe(control ? 'password_invalid' : 'none')
    }
    for (const s of ['correct horse ' + String.fromCharCode(0xd800) + ' battery', String.fromCharCode(0xdc00), String.fromCharCode(0xdc00, 0xd800), 'end' + String.fromCharCode(0xdbff)]) {
      await expectRefusal(() => platform.preparePassword(s, OLD), 'password_invalid')
    }
    await expectRefusal(() => platform.preparePassword(ch(7), NEW), 'password_invalid')
  })

  it('counts code points after NFC: at least 12 for a new password, at most 256 for any', async () => {
    const face = ch(0x1f600)
    await expectRefusal(() => platform.preparePassword(face.repeat(11), NEW), 'password_too_short')
    expect(platform.preparePassword(face.repeat(12), NEW).length).toBe(48)
    expect(platform.preparePassword('elevenchars', OLD).length).toBe(11)
    expect(platform.preparePassword('', OLD).length).toBe(0)
    expect(Array.from(platform.preparePasswordText('cafe' + ch(0x301) + ' au lait', NEW)).length).toBe(12)
    expect(platform.preparePassword('x'.repeat(256), NEW).length).toBe(256)
    await expectRefusal(() => platform.preparePassword(face.repeat(257), OLD), 'password_too_long')
  })

  it('refuses more than 30 combining marks in a row', async () => {
    for (const mark of [0x301, 0x323, 0x93e, 0x5b0]) {
      expect(platform.preparePassword('a' + ch(mark).repeat(30) + 'bcdefghijk', NEW).length).toBeGreaterThan(0)
      await expectRefusal(() => platform.preparePassword('a' + ch(mark).repeat(31), OLD), 'password_invalid')
    }
  })

  // The runs Go's normaliser counts and category M alone does not: the
  // compatibility decomposition, the Hangul vowel and final jamo, U+16D67.
  // At the limit the password prepares to exactly its NFC; one past it is
  // refused (Go would insert U+034F there, and ICU does not).
  it('counts runs in the compatibility decomposition, the Hangul jamo included', async () => {
    const acutes = (n: number) => ch(0x301).repeat(n)
    const cases: [string, string, string][] = [
      ['a compatibility jamo (U+3160)', ch(0x3160).repeat(30), ch(0x3160).repeat(31)],
      ['a Hangul syllable, then acutes', ch(0xac01) + acutes(28), ch(0xac01) + acutes(29)],
      ['U+00B4, then acutes', ch(0xb4) + acutes(29), ch(0xb4) + acutes(30)],
      ['a vowel jamo, then acutes', ch(0x1161) + acutes(29), ch(0x1161) + acutes(30)],
      ['a halfwidth voiced mark (U+FF9E)', 'a' + ch(0xff9e).repeat(30), 'a' + ch(0xff9e).repeat(31)],
      ['a halfwidth jamo (U+FFA3)', 'a' + ch(0xffa3).repeat(30), 'a' + ch(0xffa3).repeat(31)],
      ['U+0344, two marks each', 'a' + ch(0x344).repeat(15), 'a' + ch(0x344).repeat(16)],
    ]
    for (const [name, at, over] of cases) {
      expect(platform.preparePasswordText(at, OLD), name).toBe(at.normalize('NFC'))
      await expectRefusal(() => platform.preparePassword(over, OLD), 'password_invalid')
    }
    // Counted whatever the engine's Unicode version: unassigned before 16.0,
    // a letter that composes with what precedes it from 16.0.
    await expectRefusal(() => platform.preparePassword('a' + ch(0x16d67).repeat(31), OLD), 'password_invalid')
    expect(platform.preparePasswordText(ch(0x1100, 0x1161, 0x11a8).repeat(11), OLD)).toBe(ch(0xac01).repeat(11))
    expect(platform.preparePassword(ch(0xac01).repeat(31), NEW).length).toBe(93)
  })

  // ICU's canonical reordering is quadratic in a run's length, and the
  // profile runs on the page's main thread. The run is counted code point by
  // code point, so a pasted wall of alternating marks (about 13 s for 100,000
  // in Node when the whole text was decomposed first) is refused at once, and
  // a long text of short runs reaches the length check in linear time.
  it('refuses a long run without normalising the whole text first', async () => {
    const wall = 'a' + (ch(0x316) + ch(0x301)).repeat(50_000)
    const short = ('a' + (ch(0x316) + ch(0x301)).repeat(15)).repeat(3_300)
    const started = performance.now()
    await expectRefusal(() => platform.preparePassword(wall, OLD), 'password_invalid')
    await expectRefusal(() => platform.preparePassword(short, OLD), 'password_too_long')
    expect(performance.now() - started).toBeLessThan(3_000)
  })

  it('is idempotent', () => {
    for (const pw of ['cafe' + ch(0x301) + ' au lait', 'a' + ch(0xa0) + 'b' + ch(0x3000) + 'c d' + ch(0x307, 0x323), ch(0x212b) + 'ngstr' + ch(0xf6) + 'm units']) {
      const once = platform.preparePasswordText(pw, OLD)
      expect(platform.preparePasswordText(once, OLD)).toBe(once)
    }
  })
})

describe('the KDF policy', () => {
  const SALT = new Uint8Array(16).fill(7) as Bytes
  const PREPARED = encodeUTF8('correct horse battery staple')
  const OUT_OF_BOUNDS: [string, unknown][] = [
    ['m below the floor', { alg: 'argon2id', m: 65535, t: 3, p: 1 }],
    ['m above the ceiling', { alg: 'argon2id', m: 262145, t: 3, p: 1 }],
    ['t below the floor', { alg: 'argon2id', m: 65536, t: 2, p: 1 }],
    ['t above the ceiling', { alg: 'argon2id', m: 65536, t: 11, p: 1 }],
    ['p below the floor', { alg: 'argon2id', m: 65536, t: 3, p: 0 }],
    ['p above the ceiling', { alg: 'argon2id', m: 65536, t: 3, p: 5 }],
    ['m times t above the ceiling', { alg: 'argon2id', m: 262144, t: 5, p: 1 }],
    ['another algorithm', { alg: 'argon2i', m: 65536, t: 3, p: 1 }],
    ['a fractional m', { alg: 'argon2id', m: 65536.5, t: 3, p: 1 }],
    ['m as a string', { alg: 'argon2id', m: '65536', t: 3, p: 1 }],
    ['a missing parameter', { alg: 'argon2id', m: 65536, t: 3 }],
    ['an unknown parameter', { alg: 'argon2id', m: 65536, t: 3, p: 1, version: 16 }],
    ['null', null],
    ['an array', [65536, 3, 1]],
  ]

  it('accepts the floor and the ceilings', () => {
    expect(platform.checkKDF(platform.DEFAULT_KDF)).toEqual({ alg: 'argon2id', m: 65536, t: 3, p: 1 })
    expect(platform.checkKDF({ alg: 'argon2id', m: 262144, t: 4, p: 4 })).toEqual({ alg: 'argon2id', m: 262144, t: 4, p: 4 })
    expect(platform.checkKDF({ alg: 'argon2id', m: 104857, t: 10, p: 1 })).toEqual({ alg: 'argon2id', m: 104857, t: 10, p: 1 })
  })

  it('refuses everything else before a worker is started or anything derived', async () => {
    const { state, factory } = fakeWorker()
    for (const [name, kdf] of OUT_OF_BOUNDS) {
      expect(await refusal(() => platform.checkKDF(kdf)), name).toBe('kdf_policy')
      expect(await refusal(() => platform.derivePassword(PREPARED, SALT, kdf, { worker: factory })), name).toBe('kdf_policy')
      // Even with a password the profile refuses: the challenge is judged first.
      expect(await refusal(() => platform.derivePasswordKeys('bad' + ch(0) + 'password', SALT, kdf, { worker: factory })), name).toBe('kdf_policy')
    }
    for (const salt of [new Uint8Array(15), new Uint8Array(17), new Uint8Array(0), 'AAAAAAAAAAAAAAAAAAAAAA']) {
      expect(await refusal(() => platform.checkSalt(salt))).toBe('kdf_policy')
      expect(await refusal(() => platform.derivePassword(PREPARED, salt as Bytes, platform.DEFAULT_KDF, { worker: factory }))).toBe('kdf_policy')
    }
    // A bundle's parameters below the floor, with any password.
    const good = loadPlatform('key-bundle').cases.find((c) => c.name === 'opens with the password')!
    const low = { ...good.bundle, kdf: { alg: 'argon2id', m: 8, t: 1, p: 1 } }
    expect(await refusal(() => platform.openKeyBundle(low, 'any password', { worker: factory }))).toBe('kdf_policy')
    expect(await refusal(() => platform.openKeyBundle(good.bundle, 'bad' + ch(0) + 'password', { worker: factory }))).toBe('password_invalid')
    expect(state.started).toBe(0)
  })

  it('derives through the worker it is given, and zeroes the password it prepared', async () => {
    const { state, factory } = fakeWorker()
    const c = loadPlatform('kdf').cases.find((x) => x.name === 'the floor parameters')!
    const d = await platform.derivePasswordKeys('correct horse battery staple', fromBase64URL(c.salt, 16), c.kdf, { worker: factory })
    expect(d.authKey).toBe(c.k_auth)
    expect(state.started).toBe(1)
    expect(state.sent[0].length).toBeGreaterThan(0)
    expect(state.sent[0].every((x) => x === 0)).toBe(true)
    // derivePassword leaves the caller's bytes alone.
    const prepared = fromBase64URL(c.prepared_b64url, 28)
    expect((await platform.derivePassword(prepared, fromBase64URL(c.salt, 16), c.kdf, { worker: factory })).authKey).toBe(c.k_auth)
    expect(toBase64URL(prepared)).toBe(c.prepared_b64url)
  })
})

describe('root wraps', () => {
  const SUB = '0199a5b2-c3d4-7e5f-8a6b-0c1d2e3f4a5b'
  const OTHER_SUB = '0199a5b2-c3d4-7e5f-8a6b-0c1d2e3f4a5c'
  const KEY = new Uint8Array(32).fill(0x11) as Bytes
  const ROOT = new Uint8Array(32).map((_, i) => i + 1) as Bytes

  it('are 62 bytes, open for their binding only, and take a CryptoKey too', async () => {
    const w = await platform.sealRootWrap('password', KEY, ROOT, SUB, 1)
    expect([w.length, w[0], w[1]]).toEqual([62, 1, 1])
    expect((await platform.sealRootWrap('recovery', KEY, ROOT, SUB, 1))[1]).toBe(2)
    expect(hex(await platform.openRootWrap('password', KEY, w, SUB, 1))).toBe(hex(ROOT))
    const k = await crypto.subtle.importKey('raw', KEY, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
    expect(hex(await platform.openRootWrap('password', k, await platform.sealRootWrap('password', k, ROOT, SUB, 1), SUB, 1))).toBe(hex(ROOT))
    const again = await platform.sealRootWrap('password', KEY, ROOT, SUB, 1)
    expect(hex(again.subarray(2, 14))).not.toBe(hex(w.subarray(2, 14)))
    await expectRefusal(() => platform.openRootWrap('password', KEY, w, OTHER_SUB, 1), 'wrap')
    await expectRefusal(() => platform.openRootWrap('password', KEY, w, SUB, 2), 'wrap')
    await expectRefusal(() => platform.openRootWrap('recovery', KEY, w, SUB, 1), 'wrap')
    const relabelled = new Uint8Array(w)
    relabelled[1] = 2
    await expectRefusal(() => platform.openRootWrap('recovery', KEY, relabelled, SUB, 1), 'wrap')
    await expectRefusal(() => platform.openRootWrap('password', new Uint8Array(32).fill(0x12), w, SUB, 1), 'wrap')
    await expectRefusal(() => platform.openRootWrap('password', new Uint8Array(16), w, SUB, 1), 'wrap')
    await expectRefusal(() => platform.openRootWrap('password', KEY, w.slice(0, 61), SUB, 1), 'wrap')
    await expectRefusal(() => platform.openRootWrap('password', KEY, new Uint8Array([...w, 0]), SUB, 1), 'wrap')
    for (let i = 0; i < w.length; i++) {
      const t = new Uint8Array(w)
      t[i] ^= 0x01
      await expectRefusal(() => platform.openRootWrap('password', KEY, t, SUB, 1), 'wrap')
    }
  })

  it('draw exactly one 12-byte nonce, which a replay reproduces', async () => {
    const nonce = new Uint8Array(12).fill(0x22) as Bytes
    const a = await withDraws({ bytes: [nonce] }, () => platform.sealRootWrap('password', KEY, ROOT, SUB, 1))
    const b = await withDraws({ bytes: [nonce] }, () => platform.sealRootWrap('password', KEY, ROOT, SUB, 1))
    expect(toBase64URL(a)).toBe(toBase64URL(b))
    expect(hex(a.subarray(2, 14))).toBe(hex(nonce))
  })

  it('refuse a binding outside its one spelling', async () => {
    expect(platform.rootWrapAAD('password', SUB, 1)).toBe(`["thehappie-id/root-wrap",1,"password","${SUB}",1]`)
    expect(platform.rootWrapAAD('passkey', SUB, 1, { rpId: 'id.thehappie.co', credentialId: 'AAEC' })).toBe(`["thehappie-id/root-wrap",1,"passkey","${SUB}",1,"id.thehappie.co","AAEC"]`)
    for (const [sub, epoch] of [[SUB.toUpperCase(), 1], [SUB.replace(/-/g, ''), 1], [SUB, 0], [SUB, 2 ** 31], [SUB, 1.5]] as [string, number][]) {
      await expectRefusal(() => platform.sealRootWrap('password', KEY, ROOT, sub, epoch), 'wrap')
    }
    await expectRefusal(() => platform.rootWrapAAD('passkey', SUB, 1), 'wrap')
    await expectRefusal(() => platform.rootWrapAAD('password', SUB, 1, { rpId: 'id.thehappie.co', credentialId: 'AAEC' }), 'wrap')
    for (const b of [{ rpId: 'id.thehappie.co', credentialId: 'AAE=' }, { rpId: 'id thehappie', credentialId: 'AAEC' }, { rpId: '', credentialId: 'AAEC' }, { rpId: 'x', credentialId: '' }]) {
      await expectRefusal(() => platform.rootWrapAAD('passkey', SUB, 1, b), 'wrap')
    }
    for (const kind of ['toString', 'constructor', '__proto__', 'hasOwnProperty']) {
      await expectRefusal(() => platform.rootWrapAAD(kind as platform.WrapKind, SUB, 1), 'wrap')
      await expectRefusal(() => platform.sealRootWrap(kind as platform.WrapKind, KEY, ROOT, SUB, 1), 'wrap')
    }
    await expectRefusal(() => platform.sealRootWrap('password', KEY, ROOT.subarray(0, 16), SUB, 1), 'wrap')
    // A binding that is not two strings is wrap too, never another
    // language's AAD ([..., 1, 7, "AAEC"]), a CanonicalJSONError or a
    // TypeError.
    const bindings: unknown[] = [null, 'id.thehappie.co', { rpId: 7, credentialId: 'AAEC' }, { credentialId: 'AAEC' }, { rpId: 'id.thehappie.co' }, { rpId: 'id.thehappie.co', credentialId: ['AAEC'] }]
    for (const b of bindings) {
      await expectRefusal(() => platform.rootWrapAAD('passkey', SUB, 1, b as platform.PasskeyBinding), 'wrap')
      await expectRefusal(() => platform.sealRootWrap('passkey', KEY, ROOT, SUB, 1, b as platform.PasskeyBinding), 'wrap')
    }
  })

  // Section 11.5 is AES-256-GCM, and Go's Wrap and Unwrap take only 32-byte
  // keys: a wrap sealed under a shorter AES key, or opened with one, is wrap,
  // whatever WebCrypto would do with it.
  it('take a CryptoKey only if it is a 256-bit AES-GCM key', async () => {
    const w = await platform.sealRootWrap('password', KEY, ROOT, SUB, 1)
    const keys = [
      await crypto.subtle.importKey('raw', KEY.subarray(0, 16), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']),
      await crypto.subtle.importKey('raw', KEY.subarray(0, 24), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']).catch(() => undefined),
      await crypto.subtle.importKey('raw', KEY, { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']),
      await crypto.subtle.importKey('raw', KEY, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']),
    ]
    for (const k of keys) {
      if (k === undefined) continue // an engine without 192-bit AES (Chromium) refuses to import it at all
      await expectRefusal(() => platform.sealRootWrap('password', k, ROOT, SUB, 1), 'wrap')
      await expectRefusal(() => platform.openRootWrap('password', k, w, SUB, 1), 'wrap')
    }
    for (const k of [{}, { algorithm: { name: 'AES-GCM', length: 256 } }, 'key', 32]) {
      await expectRefusal(() => platform.sealRootWrap('password', k as unknown as CryptoKey, ROOT, SUB, 1), 'wrap')
    }
  })

  it('are never returned when they fail their self-test', async () => {
    const real = crypto.subtle.decrypt.bind(crypto.subtle)
    vi.spyOn(crypto.subtle, 'decrypt').mockImplementation(async (alg, key, data) => {
      const plain = new Uint8Array(await real(alg, key, data))
      plain[0] ^= 0xff
      return plain.buffer
    })
    await expectRefusal(() => platform.sealRootWrap('password', KEY, ROOT, SUB, 1), 'wrap')
    vi.restoreAllMocks()
    vi.spyOn(crypto.subtle, 'decrypt').mockRejectedValue(new DOMException('broken', 'OperationError'))
    await expectRefusal(() => platform.sealRootWrap('recovery', KEY, ROOT, SUB, 1), 'wrap')
  })
})

describe('the recovery code', () => {
  it('maps each byte by its value modulo 32, eight byte values to a character', () => {
    const counts = new Map<string, number>()
    for (let b = 0; b < 256; b += 30) {
      const { canonical } = platform.recoveryCodeFromBytes(new Uint8Array(30).map((_, i) => (b + i) & 0xff))
      for (let i = 0; i < 30 && b + i < 256; i++) counts.set(canonical[i], (counts.get(canonical[i]) ?? 0) + 1)
    }
    expect(counts.size).toBe(32)
    for (const n of counts.values()) expect(n).toBe(8)
  })

  it('is shown in six groups of five, and read back from what a person types', async () => {
    for (let i = 0; i < 20; i++) {
      const code = platform.newRecoveryCode()
      expect(code.display).toMatch(/^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){5}$/)
      expect(platform.formatRecoveryCode(code.canonical)).toBe(code.display)
    }
    const c = '0123456789ABCDEFGHJKMNPQRSTVWX'
    for (const typed of [c, '01234-56789-abcde-fghjk-mnpqr-stvwx', ' 01234 56789\tABCDE\nFGHJK\r\nMNPQR-STVWX ', 'O1234-56789-ABCDE-FGHJK-MNPQR-STVWX', 'oi234-56789-ABCDE-FGHJK-MNPQR-STVWX', '0l234-56789-ABCDE-FGHJK-MNPQR-STVWX']) {
      expect(platform.canonicalRecoveryCode(typed)).toBe(c)
    }
    const base = '01234-56789-ABCDE-FGHJK-MNPQR-STVW'
    for (const bad of ['U', 'u', '_', '.', '/', ch(0x131), ch(0x17f), ch(0xff10), ch(0xa0), ch(0xb), ch(0xc)]) {
      await expectRefusal(() => platform.canonicalRecoveryCode(base + bad), 'recovery_code')
    }
    for (const bad of [base, base + 'XY', '', '0'.repeat(10_000)]) await expectRefusal(() => platform.canonicalRecoveryCode(bad), 'recovery_code')
    await expectRefusal(() => platform.deriveRecovery('not a code'), 'recovery_code')
    await expectRefusal(() => platform.recoveryCodeFromBytes(new Uint8Array(29)), 'recovery_code')
  })

  it('derives one pair of keys from every spelling', async () => {
    const code = platform.newRecoveryCode()
    const a = await platform.deriveRecovery(code.display)
    const b = await platform.deriveRecovery(code.canonical.toLowerCase())
    expect(a.recoveryAuth).toBe(b.recoveryAuth)
    expect(a.recoveryAuth).toMatch(/^[A-Za-z0-9_-]{43}$/)
    const iv = new Uint8Array(12)
    const probe = async (k: CryptoKey) => toBase64URL(new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, new Uint8Array(4))))
    expect(await probe(a.wrapKey)).toBe(await probe(b.wrapKey))
  })
})

describe('product keys', () => {
  const ROOT = new Uint8Array(32).map((_, i) => 0xa0 ^ i)

  it('are separated by product and epoch, for any product id', async () => {
    const seen = new Set<string>()
    for (const product of ['mailie', 'wappie', 'wappie-2', 'a-future-product']) {
      for (const epoch of [1, 2, 10]) seen.add(hex(await platform.productPublicKey(ROOT, product, epoch)))
    }
    expect(seen.size).toBe(12)
    expect(platform.productKeyId('wappie', 1)).toBe('wappie:1')
    expect((await platform.productPublicKey(ROOT, 'a'.repeat(32), 1)).length).toBe(32)
  })

  it('refuse a product id, an epoch or a root that names no key', async () => {
    for (const product of ['', 'Wappie', '1wappie', '-wappie', 'wap|pie', 'wap pie', 'a'.repeat(33), 'w' + ch(0xe1) + 'ppie']) {
      await expectRefusal(() => platform.productPublicKey(ROOT, product, 1), 'product_key')
    }
    for (const epoch of [0, -1, 1.5, 2 ** 31, Number.NaN]) await expectRefusal(() => platform.productPublicKey(ROOT, 'wappie', epoch), 'product_key')
    await expectRefusal(() => platform.productPublicKey(new Uint8Array(31), 'wappie', 1), 'product_key')
  })

  // product_key says a key bundle's listed keys are not this root's. An
  // engine without X25519 says nothing about the key, so hpke's error comes
  // through as it is, with the engine's NotSupportedError as its cause; an
  // engine that refuses the key is still product_key.
  it('are not refused as product_key by an engine without X25519', async () => {
    let caught: unknown
    await withEngineRefusingX25519('NotSupportedError', async () => {
      try {
        await platform.productPublicKey(ROOT, 'wappie', 1)
      } catch (err) {
        caught = err
      }
    })
    expect(caught).toBeInstanceOf(HPKEError)
    expect((caught as HPKEError).code).toBe('invalid_key')
    expect(((caught as HPKEError).cause as DOMException).name).toBe('NotSupportedError')
    await withEngineRefusingX25519('DataError', () => expectRefusal(() => platform.productPublicKey(ROOT, 'wappie', 1), 'product_key'))
  })
})

describe('email normalisation', () => {
  it('trims and lower-cases ASCII, and keeps dots and tags', () => {
    expect(platform.normalizeEmail('  Ana.Maria+News@Example.COM\r\n')).toBe('ana.maria+news@example.com')
    expect(platform.normalizeEmail("!#$%&'*+/=?^_`{|}~-@example.com")).toBe("!#$%&'*+/=?^_`{|}~-@example.com")
    const local = 'a'.repeat(64)
    const domain = `${'c'.repeat(61)}.${'d'.repeat(61)}.${'e'.repeat(61)}.com`
    expect(platform.normalizeEmail(`${local}@${domain}`).length).toBe(254)
  })

  it('refuses every printable ASCII byte outside the local part\'s set, and anything else', async () => {
    const allowed = "abcdefghijklmnopqrstuvwxyz0123456789.!#$%&'*+/=?^_`{|}~-"
    for (let c = 0x21; c <= 0x7e; c++) {
      if (c === 0x2e || c === 0x40) continue
      const lower = String.fromCharCode(c).toLowerCase()
      const ok = allowed.includes(lower)
      expect(await refusal(() => platform.normalizeEmail('a' + String.fromCharCode(c) + 'b@example.com')), `0x${c.toString(16)}`).toBe(ok ? 'none' : 'email')
    }
    for (const s of ['', 'ana', 'ana@example', '"ana"@example.com', ch(0x212a) + 'elvin@example.com', 'ana' + ch(0xb) + '@example.com', ch(0x130) + 'van@example.com']) {
      await expectRefusal(() => platform.normalizeEmail(s), 'email')
    }
  })
})

describe('the key bundle', () => {
  const vectors = loadPlatform('key-bundle').cases
  const good = vectors.find((c) => c.name === 'opens with the recovery code')!
  const CODE: string = good.recovery_code
  const BUNDLE = good.bundle as Record<string, unknown>
  const edited = (change: (b: Record<string, any>) => void): unknown => {
    const b = JSON.parse(JSON.stringify(BUNDLE)) as Record<string, any>
    change(b)
    return b
  }

  it('opens to the root its product keys come from, from the value and the text', async () => {
    const a = await platform.openKeyBundleWithRecoveryCode(BUNDLE, CODE)
    const b = await platform.openKeyBundleWithRecoveryCode(JSON.stringify(BUNDLE, null, 2), CODE.toLowerCase().replace(/-/g, ' '))
    expect(hex(a)).toBe(hex(b))
    expect(toBase64URL(a)).toBe(good.root)
    const parsed = platform.parseKeyBundle(BUNDLE)
    await platform.checkBundleProductKeys(a, parsed)
    await expectRefusal(() => platform.checkBundleProductKeys(new Uint8Array(32), parsed), 'product_key')
    expect(parsed.json).toEqual(BUNDLE)
  })

  it('is read in its one exact shape', async () => {
    const cases: unknown[] = [
      edited((x) => (x.note = 'hello')),
      edited((x) => delete x.created_at),
      edited((x) => (x.version = 2)),
      edited((x) => (x.account_key_epoch = '1')),
      edited((x) => (x.kdf_salt = `${x.kdf_salt}==`)),
      edited((x) => (x.password_wrap = ` ${x.password_wrap}`)),
      edited((x) => ([x.password_wrap, x.recovery_wrap] = [x.recovery_wrap, x.password_wrap])),
      edited((x) => x.product_keys.reverse()),
      edited((x) => x.product_keys.push(x.product_keys[1])),
      edited((x) => (x.product_keys[0].id = 'mailie:1')),
      edited((x) => (x.product_keys = {})),
      edited((x) => (x.product_keys = [])),
      edited((x) => (x.created_at = '2026-02-30T12:00:00Z')),
      edited((x) => (x.issuer = null)),
      edited((x) => (x.issuer = 'https://id thehappie.co')),
      edited((x) => (x.version = 1.5)),
      edited((x) => (x.kdf = { alg: 'argon2id', m: '65536', t: 3, p: 1 })),
      edited((x) => (x.kdf = { alg: 'argon2id', m: 65536, t: 3, p: 1, s: 1 })),
      '{"format":',
      null,
    ]
    for (const [i, b] of cases.entries()) expect(await refusal(() => platform.parseKeyBundle(b)), `edit ${i}`).toBe('bundle')
    for (const kdf of [{ alg: 'argon2id', m: 65536, t: 2, p: 1 }, { alg: 'argon2i', m: 65536, t: 3, p: 1 }, { alg: 'argon2id', m: -1, t: 3, p: 1 }]) {
      await expectRefusal(() => platform.parseKeyBundle(edited((x) => (x.kdf = kdf))), 'kdf_policy')
    }
  })

  it('refuses from the text what a parsed value has lost', async () => {
    const text = JSON.stringify(BUNDLE, null, 2)
    const repeated = text.replace('"issuer":', '"issuer": "https://other.example",\n  "issuer":')
    await expectRefusal(() => platform.parseKeyBundle(repeated), 'bundle')
    expect(platform.parseKeyBundle(JSON.parse(repeated)).json).toEqual(BUNDLE)
    await expectRefusal(() => platform.parseKeyBundle(text.replace('"version": 1,', '"version": 1.0,')), 'bundle')
    await expectRefusal(() => platform.parseKeyBundle(text.replace('"t": 3,', '"t": 3e0,')), 'bundle')
    await expectRefusal(() => platform.parseKeyBundle(text.replace('"m": 65536,', '"m": 9223372036854775808,')), 'bundle')
    await expectRefusal(() => platform.parseKeyBundle(text.replace('"m": 65536,', '"m": 9223372036854775807,')), 'kdf_policy')
    // More than 64 KiB of UTF-8 in fewer than 64 Ki UTF-16 units.
    const big = `${text.slice(0, -1)},"note":"${ch(0x20ac).repeat(22_000)}"}`
    expect(big.length).toBeLessThan(64 * 1024)
    let message = ''
    try {
      platform.parseKeyBundle(big)
    } catch (err) {
      expect(isPlatformError(err, 'bundle')).toBe(true)
      message = (err as Error).message
    }
    expect(message).toBe('the bundle is too large')
  })

  it('takes created_at in one UTC shape of the proleptic Gregorian calendar', async () => {
    const at = (created_at: string) => edited((x) => (x.created_at = created_at))
    for (const ok of ['0050-01-01T00:00:00Z', '0000-02-29T00:00:00Z', '2000-02-29T23:59:59Z', '2026-10-01T12:00:00.5Z', '2026-10-01T12:00:00.123456789Z']) {
      expect(platform.parseKeyBundle(at(ok)).json.created_at).toBe(ok)
    }
    for (const bad of ['1900-02-29T00:00:00Z', '2026-10-01T12:00:00+00:00', '2026-10-01T12:00:00,5Z', '2026-10-01T12:00:00.1234567891Z',
      '2026-10-01T12:00:00z', '2026-13-01T12:00:00Z', '2026-10-01T12:60:00Z', '10000-01-01T00:00:00Z', '2026-10-01T23:59:60Z']) {
      await expectRefusal(() => platform.parseKeyBundle(at(bad)), 'bundle')
    }
  })

  it('zeroes the password it prepared when it opens', async () => {
    const pw = vectors.find((c) => c.name === 'opens with the password')!
    const { state, factory } = fakeWorker()
    const root = await platform.openKeyBundle(pw.bundle, pw.password, { worker: factory })
    expect(toBase64URL(root)).toBe(pw.root)
    expect(state.started).toBe(1)
    expect(state.sent[0].every((x) => x === 0)).toBe(true)
  })
})

describe('refusals', () => {
  it('never repeat the refused value', async () => {
    const marker = 'zq7marker'
    const attempts: (() => unknown)[] = [
      () => platform.normalizeEmail(marker + '@@example.com'),
      () => platform.preparePassword(marker, { isNew: true }),
      () => platform.preparePassword(marker + ch(0), { isNew: false }),
      () => platform.canonicalRecoveryCode(marker + 'U'),
      () => platform.authVerifier(marker, new Uint8Array(32)),
      () => platform.productPublicKey(new Uint8Array(32), marker + '|', 1),
      () => platform.parseKeyBundle(`{"${marker}":1}`),
      () => platform.openKeyBundle('[]', marker),
      () => platform.rootWrapAAD('password', marker, 1),
    ]
    for (const [i, fn] of attempts.entries()) {
      let caught: unknown
      try {
        await fn()
      } catch (err) {
        caught = err
      }
      expect(caught, `attempt ${i}`).toBeInstanceOf(PlatformError)
      expect((caught as Error).message, `attempt ${i}`).not.toContain(marker)
    }
  })
})
