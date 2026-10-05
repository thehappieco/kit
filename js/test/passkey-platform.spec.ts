// Passkeys with PRF and the client-extension allowlist (SPEC section 11.16)
// on this side alone: the PRF salt and K_pk against an independent
// computation, the relying party's one spelling, round trips, every
// binding, the self-test, the allowlist's shapes, and what is left in memory
// afterwards. Ported from the platform's web/test/crypto/passkey.spec.ts and
// the allowlist block of webauthn.spec.ts at b5d9f69, without Node APIs:
// these run in the browsers too. The golden vectors (platform.spec.ts,
// passkey.json and client-extensions.json) check the same functions against
// Go.

import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { encodeUTF8, fromBase64URL, toBase64URL, type Bytes } from '../src/bytes.js'
import { PlatformError, type PlatformErrorCode } from '../src/errors.js'
import { unwrapPasskey, wrapPasskey } from '../src/passkey.js'
import * as platform from '../src/profiles/platform.js'

const RP = 'id.thehappie.co'
const DEV_RP = 'id.thehappie.localhost'
const SUB = '0199a5b2-c3d4-7e5f-8a6b-0c1d2e3f4a5b'
const OTHER_SUB = '0199a5b2-c3d4-7e5f-8a6b-0c1d2e3f4a5c'
const ROOT = new Uint8Array(32).map((_, i) => 0xa5 ^ i) as Bytes
const PRF = new Uint8Array(32).map((_, i) => 0x3c ^ (i * 5)) as Bytes
const OTHER_PRF = new Uint8Array(32).map((_, i) => 0x3d ^ (i * 5)) as Bytes
const CRED = toBase64URL(new Uint8Array(16).map((_, i) => i * 11) as Bytes)
const OTHER_CRED = toBase64URL(new Uint8Array(16).map((_, i) => i * 13) as Bytes)

// A made-up PRF output in base64url, shaped like a real one.
const FAKE_PRF_OUTPUT = 'EhJD599fFQOFAB7ZW0Br9KT5OkI77uQwiPBVpt38MNM'

afterEach(() => {
  vi.restoreAllMocks()
})

async function refusal(fn: () => unknown): Promise<{ code: string; message: string }> {
  try {
    await fn()
  } catch (err) {
    if (err instanceof PlatformError) return { code: err.code, message: err.message }
    return { code: `not a PlatformError: ${err instanceof Error ? err.name : typeof err}`, message: '' }
  }
  return { code: 'none', message: '' }
}

async function expectRefusal(fn: () => unknown, code: PlatformErrorCode, label = ''): Promise<void> {
  expect((await refusal(fn)).code, label).toBe(code)
}

/** same compares two byte strings or texts without showing them. */
function same(a: Uint8Array | string, b: Uint8Array | string, label: string): void {
  const x = typeof a === 'string' ? a : toBase64URL(new Uint8Array(a) as Bytes)
  const y = typeof b === 'string' ? b : toBase64URL(new Uint8Array(b) as Bytes)
  if (x !== y) expect.fail(`${label}: the values differ (not shown)`)
}

function different(a: Uint8Array | string, b: Uint8Array | string, label: string): void {
  const x = typeof a === 'string' ? a : toBase64URL(new Uint8Array(a) as Bytes)
  const y = typeof b === 'string' ? b : toBase64URL(new Uint8Array(b) as Bytes)
  if (x === y) expect.fail(`${label}: the values are equal (not shown)`)
}

const isZero = (b: Uint8Array) => b.every((x) => x === 0)

/** probe seals a fixed plaintext with a fixed nonce: two keys that give the same probe are one key. */
async function probe(key: CryptoKey | Uint8Array): Promise<string> {
  const k = key instanceof Uint8Array
    ? await crypto.subtle.importKey('raw', new Uint8Array(key) as Bytes, { name: 'AES-GCM' }, false, ['encrypt'])
    : key
  return toBase64URL(new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(12).fill(7) }, k, encodeUTF8('probe'))) as Bytes)
}

type Over = Partial<{ prf: Uint8Array; rpId: string; credentialId: string; sub: string; epoch: number }>

/** wrapped is ROOT wrapped for the default binding. */
function wrapped(over: Over = {}): Promise<string> {
  return platform.wrapRootWithPasskey({ root: ROOT, prf: PRF, rpId: RP, credentialId: CRED, sub: SUB, epoch: 1, ...over })
}

/** opened opens a wrap once and returns a copy of the root. */
function opened(wrap: string, over: Over = {}): Promise<Uint8Array> {
  return platform.unwrapRootWithPasskey({ prf: PRF, wrap, rpId: RP, credentialId: CRED, sub: SUB, epoch: 1, ...over }, async (root) => new Uint8Array(root))
}

describe('the PRF salt and K_pk', () => {
  it('the PRF salt is the SHA-256 of the label and the relying party id', async () => {
    for (const rp of [RP, DEV_RP, 'localhost']) {
      same(await platform.prfSalt(rp), sha256(encodeUTF8(`thehappie-id/v1/passkey-prf|${rp}`)), `the salt of ${rp}`)
      expect((await platform.prfSalt(rp)).length).toBe(platform.PRF_SALT_LEN)
    }
    expect(platform.LABEL_PASSKEY_PRF).toBe('thehappie-id/v1/passkey-prf|')
  })

  it('each relying party has its own PRF salt', async () => {
    different(await platform.prfSalt(RP), await platform.prfSalt(DEV_RP), 'production and development salts')
  })

  it('K_pk is the HKDF of the PRF output salted with the relying party id', async () => {
    const want = hkdf(sha256, PRF, encodeUTF8(RP), encodeUTF8('thehappie-id/v1/passkey/wrap'), 32)
    same(await probe(await platform.passkeyWrapKey(PRF, RP)), await probe(want), 'K_pk')
    expect(platform.LABEL_PASSKEY_WRAP).toBe('thehappie-id/v1/passkey/wrap')
    // The relying party is the HKDF salt: another one is another key.
    different(await probe(await platform.passkeyWrapKey(PRF, DEV_RP)), await probe(want), 'K_pk on another relying party')
    different(await probe(await platform.passkeyWrapKey(OTHER_PRF, RP)), await probe(want), 'K_pk of another PRF output')
  })

  it('K_pk is a non-extractable AES-256-GCM key', async () => {
    const key = await platform.passkeyWrapKey(PRF, RP)
    expect(key.extractable).toBe(false)
    expect(key.type).toBe('secret')
    expect(key.algorithm.name).toBe('AES-GCM')
    expect((key.algorithm as AesKeyAlgorithm).length).toBe(256)
    expect([...key.usages].sort()).toEqual(['decrypt', 'encrypt'])
    await expect(crypto.subtle.exportKey('raw', key)).rejects.toThrow()
  })

  it('zeroes the copy of the PRF output it hands to WebCrypto, and leaves the caller\'s', async () => {
    const seen: Uint8Array[] = []
    const importKey = crypto.subtle.importKey.bind(crypto.subtle) as (...a: unknown[]) => Promise<CryptoKey>
    vi.spyOn(crypto.subtle, 'importKey').mockImplementation((async (...args: unknown[]) => {
      if (args[0] === 'raw' && args[1] instanceof Uint8Array) seen.push(args[1])
      return importKey(...args)
    }) as typeof crypto.subtle.importKey)
    const prf = new Uint8Array(PRF)
    await platform.passkeyWrapKey(prf, RP)
    expect(seen.length).toBe(1)
    expect(seen[0] === prf).toBe(false)
    expect(isZero(seen[0]!)).toBe(true)
    same(prf, PRF, 'the caller\'s PRF output')
    // And through a whole wrap and open.
    seen.length = 0
    const wrap = await platform.wrapRootWithPasskey({ root: ROOT, prf, rpId: RP, credentialId: CRED, sub: SUB, epoch: 1 })
    await platform.unwrapRootWithPasskey({ prf, wrap, rpId: RP, credentialId: CRED, sub: SUB, epoch: 1 }, async () => undefined)
    const hkdfInputs = seen.filter((b) => b.length === platform.PRF_OUTPUT_LEN)
    expect(hkdfInputs.length).toBeGreaterThanOrEqual(2)
    for (const b of hkdfInputs) expect(isZero(b)).toBe(true)
    same(prf, PRF, 'the caller\'s PRF output after a wrap and an open')
  })

  it('a PRF output that is not 32 bytes gives no key, and any 32 bytes do', async () => {
    for (const n of [0, 1, 16, 31, 33, 64]) {
      await expectRefusal(() => platform.passkeyWrapKey(new Uint8Array(n).fill(7), RP), 'wrap', `${n} bytes`)
      await expectRefusal(() => wrapped({ prf: new Uint8Array(n).fill(7) }), 'wrap', `a wrap with ${n} bytes`)
    }
    await expectRefusal(() => platform.passkeyWrapKey('a'.repeat(32) as unknown as Uint8Array, RP), 'wrap', 'a string')
    await expectRefusal(() => platform.passkeyWrapKey(undefined as unknown as Uint8Array, RP), 'wrap', 'nothing')
    await platform.passkeyWrapKey(new Uint8Array(32), RP)
  })

  it('the relying party id has one spelling', async () => {
    const longest = `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(61)}`
    for (const ok of [RP, DEV_RP, 'localhost', 'a', 'x1', '1x', '123.example.com', 'xn--bcher-kva.example', 'a-b.c-d', `${'a'.repeat(63)}.com`, longest]) {
      expect(platform.isRPID(ok), ok.slice(0, 40)).toBe(true)
      await platform.prfSalt(ok)
      await platform.passkeyWrapKey(PRF, ok)
      // Every accepted id is drawn from the AAD alphabet.
      platform.rootWrapAAD('passkey', SUB, 1, { rpId: ok, credentialId: CRED })
    }
    const bad = [
      '', '.', '..', 'ID.thehappie.co', 'id.Thehappie.co', `${RP}:443`, `https://${RP}`, `${RP}/`, `${RP}.`, `.${RP}`, 'id..thehappie.co',
      '-id.thehappie.co', 'id-.thehappie.co', 'id.thehappie.co-', `${'a'.repeat(64)}.com`, `e${longest}`, '127.0.0.1', '1', 'example.123',
      '[::1]', '::1', 'id_1.thehappie.co', 'id thehappie.co', ` ${RP}`, `${RP}\n`, 'id.th\u00e9happie.co', 'id.thehappie.co\u0000',
      'user@id.thehappie.co', 'id|thehappie.co', '*.thehappie.co', 'id.thehappie.co\ud800', '\u0430.com',
    ]
    for (const rp of bad) {
      const label = JSON.stringify(rp).slice(0, 40)
      expect(platform.isRPID(rp), label).toBe(false)
      await expectRefusal(() => platform.prfSalt(rp), 'wrap', label)
      await expectRefusal(() => platform.passkeyWrapKey(PRF, rp), 'wrap', label)
      await expectRefusal(() => wrapped({ rpId: rp }), 'wrap', label)
    }
    for (const v of [undefined, null, 7, ['localhost'], { toString: () => RP }]) expect(platform.isRPID(v)).toBe(false)
  })
})

describe('the passkey wrap', () => {
  it('is a kind-3 root wrap that opens back to the root', async () => {
    const wrap = await wrapped()
    const bytes = fromBase64URL(wrap, platform.WRAP_LEN)
    expect([bytes[0], bytes[1]]).toEqual([1, 3])
    same(await opened(wrap), ROOT, 'the opened root')
    // It is the root wrap of section 11.5 under K_pk, nothing more.
    const kPk = await platform.passkeyWrapKey(PRF, RP)
    same(await platform.openRootWrap('passkey', kPk, bytes, SUB, 1, { rpId: RP, credentialId: CRED }), ROOT, 'opened as a root wrap')
  })

  it('is section 7 with platformPasskey, in both directions', async () => {
    const aad = encodeUTF8(platform.rootWrapAAD('passkey', SUB, 1, { rpId: RP, credentialId: CRED }))
    const generic = await wrapPasskey(platform.platformPasskey, ROOT, PRF, RP, aad)
    same(await opened(toBase64URL(generic)), ROOT, 'section 7\'s envelope opened as a passkey wrap')
    same(await unwrapPasskey(platform.platformPasskey, fromBase64URL(await wrapped(), platform.WRAP_LEN), PRF, RP, aad), ROOT, 'a passkey wrap opened by section 7')
    expect(platform.platformPasskey).toEqual({ evalPrefix: 'thehappie-id/v1/passkey-prf|', wrapInfo: 'thehappie-id/v1/passkey/wrap', header: [1, 3] })
    expect(Object.isFrozen(platform.platformPasskey) && Object.isFrozen(platform.platformPasskey.header)).toBe(true)
  })

  it('two wraps of the same root differ', async () => {
    different(await wrapped(), await wrapped(), 'two wraps under fresh nonces')
  })

  it('opens only for its credential, relying party, account and epoch', async () => {
    const wrap = await wrapped()
    await expectRefusal(() => opened(wrap, { prf: OTHER_PRF }), 'wrap', 'the PRF output of another credential')
    await expectRefusal(() => opened(wrap, { credentialId: OTHER_CRED }), 'wrap', 'another credential id')
    await expectRefusal(() => opened(wrap, { rpId: DEV_RP }), 'wrap', 'another relying party')
    await expectRefusal(() => opened(wrap, { sub: OTHER_SUB }), 'wrap', 'another account')
    await expectRefusal(() => opened(wrap, { epoch: 2 }), 'wrap', 'another epoch')
  })

  it('is neither a password nor a recovery wrap', async () => {
    const bytes = fromBase64URL(await wrapped(), platform.WRAP_LEN)
    const kPk = await platform.passkeyWrapKey(PRF, RP)
    await expectRefusal(() => platform.openRootWrap('password', kPk, bytes, SUB, 1), 'wrap', 'as a password wrap')
    await expectRefusal(() => platform.openRootWrap('recovery', kPk, bytes, SUB, 1), 'wrap', 'as a recovery wrap')
    const relabelled = new Uint8Array(bytes)
    relabelled[1] = 1
    await expectRefusal(() => platform.openRootWrap('password', kPk, relabelled, SUB, 1), 'wrap', 'relabelled as a password wrap')
    // And a password wrap under the same key does not open as a passkey wrap.
    const password = await platform.sealRootWrap('password', kPk, ROOT, SUB, 1)
    await expectRefusal(() => opened(toBase64URL(password)), 'wrap', 'a password wrap')
  })

  it('is refused with any byte altered, truncated, extended or padded', async () => {
    const bytes = fromBase64URL(await wrapped(), platform.WRAP_LEN)
    for (let i = 0; i < platform.WRAP_LEN; i++) {
      const t = new Uint8Array(bytes) as Bytes
      t[i]! ^= 0x01
      await expectRefusal(() => opened(toBase64URL(t)), 'wrap', `byte ${i}`)
    }
    await expectRefusal(() => opened(toBase64URL(bytes.slice(0, 61))), 'wrap', 'truncated')
    await expectRefusal(() => opened(`${toBase64URL(bytes)}AA`), 'wrap', 'extended')
    await expectRefusal(() => opened(`${toBase64URL(bytes)}=`), 'wrap', 'padded')
    await expectRefusal(() => opened(bytes as unknown as string), 'wrap', 'bytes instead of text')
  })

  it('is never returned when it fails its self-test', async () => {
    const real = crypto.subtle.decrypt.bind(crypto.subtle)
    vi.spyOn(crypto.subtle, 'decrypt').mockImplementation(async (alg, key, data) => {
      const plain = new Uint8Array(await real(alg, key, data))
      plain[0]! ^= 0xff
      return plain.buffer
    })
    await expectRefusal(() => wrapped(), 'wrap')
  })

  it('needs a binding in its one spelling', async () => {
    await expectRefusal(() => wrapped({ credentialId: '' }), 'wrap', 'no credential id')
    await expectRefusal(() => wrapped({ credentialId: 'AAE=' }), 'wrap', 'a padded credential id')
    await expectRefusal(() => wrapped({ credentialId: 'AAE+' }), 'wrap', 'a standard-alphabet credential id')
    await expectRefusal(() => wrapped({ credentialId: 7 as unknown as string }), 'wrap', 'a number')
    await expectRefusal(() => wrapped({ rpId: 'ID.thehappie.co' }), 'wrap', 'a relying party id in upper case')
    await expectRefusal(() => wrapped({ sub: SUB.toUpperCase() }), 'wrap', 'an upper-case sub')
    await expectRefusal(() => wrapped({ epoch: 0 }), 'wrap', 'epoch 0')
    await expectRefusal(() => wrapped({ epoch: 2 ** 31 }), 'wrap', 'epoch 2^31')
    await expectRefusal(() => wrapped({ prf: new Uint8Array(31) }), 'wrap', 'a short PRF output')
    await expectRefusal(() => platform.wrapRootWithPasskey({ root: ROOT.slice(1), prf: PRF, rpId: RP, credentialId: CRED, sub: SUB, epoch: 1 }), 'wrap', 'a 31-byte root')
  })

  // The root-wrap AAD keeps v0.2.0's rule for the relying party (the AAD
  // alphabet), so "ID.thehappie.co" still has an AAD; section 11.16's
  // spelling is enforced where K_pk is made.
  it('enforces the relying party\'s spelling where K_pk is made, not in the AAD', async () => {
    expect(platform.rootWrapAAD('passkey', SUB, 1, { rpId: 'ID.thehappie.co', credentialId: CRED })).toBe(
      `["thehappie-id/root-wrap",1,"passkey","${SUB}",1,"ID.thehappie.co","${CRED}"]`,
    )
    const wrap = await wrapped()
    await expectRefusal(() => opened(wrap, { rpId: 'ID.thehappie.co' }), 'wrap', 'opened under an upper-case relying party')
  })

  it('lends the root to its callback and zeroes it when the callback returns or throws', async () => {
    const wrap = await wrapped()
    let seen: Uint8Array | undefined
    await platform.unwrapRootWithPasskey({ prf: PRF, wrap, rpId: RP, credentialId: CRED, sub: SUB, epoch: 1 }, async (root) => {
      seen = root
      same(root, ROOT, 'the root inside the callback')
    })
    expect(seen !== undefined && isZero(seen)).toBe(true)
    seen = undefined
    await expect(
      platform.unwrapRootWithPasskey({ prf: PRF, wrap, rpId: RP, credentialId: CRED, sub: SUB, epoch: 1 }, async (root) => {
        seen = root
        throw new Error('the callback failed')
      }),
    ).rejects.toThrow('the callback failed')
    expect(seen !== undefined && isZero(seen)).toBe(true)
    // A refusal never calls it.
    let called = false
    await expectRefusal(
      () => platform.unwrapRootWithPasskey({ prf: OTHER_PRF, wrap, rpId: RP, credentialId: CRED, sub: SUB, epoch: 1 }, async () => {
        called = true
      }),
      'wrap',
    )
    expect(called).toBe(false)
  })

  it('leaves the caller\'s root and PRF output as they were', async () => {
    const prf = new Uint8Array(PRF)
    const root = new Uint8Array(ROOT)
    const wrap = await platform.wrapRootWithPasskey({ root, prf, rpId: RP, credentialId: CRED, sub: SUB, epoch: 1 })
    await opened(wrap)
    same(prf, PRF, 'the PRF output')
    same(root, ROOT, 'the root')
  })

  it('takes the longest credential id WebAuthn allows', async () => {
    const credentialId = toBase64URL(new Uint8Array(1023).fill(0xfe) as Bytes)
    same(await opened(await wrapped({ credentialId }), { credentialId }), ROOT, 'a credential id of 1023 bytes')
  })
})

describe('the client-extension allowlist', () => {
  it('accepts exactly the two flags, every subset and order', () => {
    const credProps = ['"credProps":{"rk":true}', '"credProps":{"rk":false}']
    const prf = ['"prf":{"enabled":true}', '"prf":{"enabled":false}']
    const accepted = ['{}']
    for (const c of credProps) {
      accepted.push(`{${c}}`)
      for (const p of prf) accepted.push(`{${c},${p}}`, `{${p},${c}}`)
    }
    for (const p of prf) accepted.push(`{${p}}`)
    expect(accepted.length).toBe(1 + 2 + 8 + 2)
    for (const text of accepted) {
      platform.checkClientExtensionsText(text)
      platform.checkClientExtensions(JSON.parse(text))
    }
    const value: platform.AllowedClientExtensionResults = { credProps: { rk: true }, prf: { enabled: false } }
    platform.checkClientExtensions(value)
    platform.checkClientExtensions(Object.assign(Object.create(null) as object, { prf: { enabled: true } }))
  })

  it('lets no PRF output past, in any spelling, and never repeats what it refused', async () => {
    const results = `{"first":"${FAKE_PRF_OUTPUT}"}`
    for (const text of [
      `{"prf":{"enabled":true,"results":${results}}}`,
      `{"prf":{"results":${results},"enabled":true}}`,
      `{"prf":{"results":${results}}}`,
      '{"prf":{"results":{}}}',
      '{"prf":{"results":null}}',
      '{"prf":{"results":[]}}',
      `{"prf":{"enabled":true},"results":${results}}`,
      `{"credProps":{"rk":true,"results":${results}}}`,
      `{"prf":{"enabled":false},"prf":{"results":${results}}}`,
      `{"prf":{"results":${results}},"prf":{"enabled":false}}`,
      `{"prf":{"enabled":{"results":${results}}}}`,
      `{"Prf":{"results":${results}}}`,
      `{"prf":{"Results":${results}}}`,
      `{"prf":{"enabled":true}}${results}`,
      `[{"prf":{"results":${results}}}]`,
      `"${FAKE_PRF_OUTPUT}"`,
    ]) {
      const r = await refusal(() => platform.checkClientExtensionsText(text))
      expect(r.code, text.slice(0, 40)).toBe('client_extensions')
      expect(r.message.includes(FAKE_PRF_OUTPUT) || r.message.includes('first')).toBe(false)
    }
  })

  it('refuses every other value', async () => {
    const symbol = Symbol('prf')
    const accessor = {}
    Object.defineProperty(accessor, 'prf', { enumerable: true, get: () => ({ enabled: true }) })
    const innerAccessor = { prf: {} }
    Object.defineProperty(innerAccessor.prf, 'enabled', { enumerable: true, get: () => true })
    const bad: [string, unknown][] = [
      ['a PRF output', { prf: { enabled: true, results: { first: FAKE_PRF_OUTPUT } } }],
      ['an empty results', { prf: { results: {} } }],
      ['an empty prf', { prf: {} }],
      ['an empty credProps', { credProps: {} }],
      ['a flag of another type', { prf: { enabled: 'true' } }],
      ['a null flag', { credProps: { rk: null } }],
      ['a null member', { prf: null }],
      ['an unknown member', { largeBlob: { supported: true } }],
      ['a member in another case', { PRF: { enabled: true } }],
      ['null', null],
      ['undefined', undefined],
      ['an array', []],
      ['a string', '{}'],
      ['an object that is not plain', new (class Results {
        prf = { enabled: true }
      })()],
      ['a flags object that is not plain', { prf: Object.assign(Object.create({ results: 1 }) as object, { enabled: true }) }],
      ['an inherited member', Object.create({ prf: { enabled: true } }) as object],
      ['a symbol key', { [symbol]: { enabled: true } }],
      ['a symbol key in the flags', { prf: { enabled: true, [symbol]: 1 } }],
      ['an accessor', accessor],
      ['an accessor flag', innerAccessor],
      ['a Map', new Map([['prf', { enabled: true }]])],
    ]
    for (const [label, value] of bad) await expectRefusal(() => platform.checkClientExtensions(value), 'client_extensions', label)
  })

  it('refuses every other text', async () => {
    for (const text of [
      '', ' ', 'null', 'true', '0', '"{}"', '[]', '{', '}', '{}}', '{}{}', '{} {}', '{},',
      '{"prf":{"enabled":true},}', '{"prf":{"enabled":true,}}', '{,}', '{"prf"}', '{"prf":}',
      "{'prf':{'enabled':true}}", '{prf:{enabled:true}}', '{"prf":{"enabled":True}}', '{"prf":{"enabled":tru}}',
      '{"prf":{"enabled":true}}/**/', '\ufeff{}', '\u00a0{}', '{}\u2028', '{"prf":{"enabled":true},"prf":{"enabled":true}}',
      '{"credProps":{"rk":true,"rk":true}}', '{"prf ":{"enabled":true}}', '{"":{}}', '{"prf\u0000":{"enabled":true}}',
      '{"prf":{"enabled":true}', '{"pr\ud800":{}}', '{"prf":{"enabled":true}}\ud800', '\udc00{}',
      `{"pr\\u0066":{"enabled":true},"prf":{"enabled":true}}`, `{"pr\\ud800":{"enabled":true}}`,
      '{"prf":{"enabled":1.0}}', '{"prf":{"enabled":1e0}}',
    ]) {
      await expectRefusal(() => platform.checkClientExtensionsText(text), 'client_extensions', JSON.stringify(text).slice(0, 40))
    }
    await expectRefusal(() => platform.checkClientExtensionsText(undefined as unknown as string), 'client_extensions', 'not a string')
    await expectRefusal(() => platform.checkClientExtensionsText(new TextEncoder().encode('{}') as unknown as string), 'client_extensions', 'bytes')
  })

  it('reads member names as every JSON reader reads them', async () => {
    platform.checkClientExtensionsText('{"pr\\u0066":{"en\\u0061bled":true}}')
    await expectRefusal(() => platform.checkClientExtensionsText('{"prf":{"enabled":true},"pr\\u0066":{"enabled":true}}'), 'client_extensions', 'a repeat spelled with an escape')
  })

  it('refuses deep nesting without exhausting the stack', async () => {
    for (const depth of [100, 20000]) {
      const deep = `{"prf":{"enabled":${'['.repeat(depth)}${']'.repeat(depth)}}}`
      await expectRefusal(() => platform.checkClientExtensionsText(deep), 'client_extensions', `depth ${depth}`)
    }
  })

  // Bytes are the caller's to decode: with fatal and ignoreBOM, the text is
  // the one that was sent, and a byte order mark is refused; the default
  // decoder drops the mark (and replaces invalid UTF-8), so the refusal is
  // lost. Documented, not a kit path.
  it('keeps the byte order mark refusal only for bytes decoded with ignoreBOM', async () => {
    const bytes = new Uint8Array([0xef, 0xbb, 0xbf, ...encodeUTF8('{}')])
    const strict = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
    await expectRefusal(() => platform.checkClientExtensionsText(strict.decode(bytes)), 'client_extensions', 'decoded keeping the mark')
    platform.checkClientExtensionsText(new TextDecoder().decode(bytes))
    expect(() => strict.decode(new Uint8Array([0x7b, 0xff, 0x7d]))).toThrow()
  })
})
