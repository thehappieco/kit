// The platform's golden vectors (vectors/platform/id-v1), written by the
// platform's Go and read here unchanged, in Node and in Chromium, Firefox
// and WebKit: every output must match byte for byte, and every must-fail
// case must be refused with a PlatformError of exactly the error name it
// records. Anything else thrown (an AccountError, an HPKEError, a
// DOMException) is a failure of this implementation, not a refusal. Failure
// messages name the case and the codes, never the values.

import { describe, expect, it } from 'vitest'

import { unwrapPrivateKey } from '../src/account.js'
import { encodeUTF8, fromBase64URL, toBase64URL, type Bytes } from '../src/bytes.js'
import { PlatformError } from '../src/errors.js'
import * as platform from '../src/profiles/platform.js'
import { b64 as std, files, forTS, loadPlatform, toB64, unhandled, withDraws, type PlatformCase, type VectorCase } from './vectors.js'

/** The members each kind's cases may have, which are the members the runners below read. */
const MEMBERS: Record<string, readonly string[]> = {
  'password-profile': ['name', 'error', 'password', 'password_utf16', 'password_utf8_b64url', 'new', 'prepared_b64url'],
  kdf: ['name', 'error', 'prepared_b64url', 'salt', 'kdf', 'k_auth', 'k_wrap', 'auth_key'],
  'root-wrap': ['name', 'error', 'kind', 'key', 'nonce', 'root', 'sub', 'epoch', 'rp_id', 'credential_id', 'aad', 'wrap'],
  'recovery-code': ['name', 'error', 'bytes', 'input', 'display', 'canonical', 'k_rwrap', 'recovery_auth'],
  'product-key': ['name', 'error', 'root', 'product', 'epoch', 'sk', 'pub', 'product_key_id'],
  verifier: ['name', 'error', 'sub', 'k_auth', 'r_proof', 'auth_verifier', 'recovery_verifier'],
  email: ['name', 'error', 'input', 'email_norm'],
  'key-bundle': ['name', 'error', 'password', 'recovery_code', 'bundle', 'bundle_text', 'root'],
}

/** The number of cases and of must-fail cases per kind (vectors/PROVENANCE.md). */
const COUNTS: Record<string, [number, number]> = {
  'password-profile': [45, 23],
  kdf: [19, 16],
  'root-wrap': [31, 26],
  'recovery-code': [27, 15],
  'product-key': [20, 12],
  verifier: [10, 5],
  email: [46, 33],
  'key-bundle': [59, 50],
}

const NAMES = new Set(['password_invalid', 'password_too_short', 'password_too_long', 'kdf_policy', 'wrap', 'recovery_code', 'email', 'product_key', 'bundle', 'encoding'])

function str(c: PlatformCase, member: string): string {
  const v = c[member]
  if (typeof v !== 'string') expect.fail(`case "${c.name}": ${member} is not a string`)
  return v
}

function int(c: PlatformCase, member: string): number {
  const v = c[member]
  if (typeof v !== 'number' || !Number.isInteger(v)) expect.fail(`case "${c.name}": ${member} is not an integer`)
  return v
}

/** b64 decodes a binary member of whatever length it has, strictly. */
function b64(c: PlatformCase, member: string): Bytes {
  const s = str(c, member)
  if (s.length % 4 === 1) expect.fail(`case "${c.name}": ${member} is not base64url`)
  return fromBase64URL(s, Math.floor((s.length * 3) / 4))
}

function same(got: string, want: string, label: string): void {
  if (got !== want) expect.fail(`${label}: the values differ (not shown)`)
}

/**
 * outcome runs one case: its checks when it records no error, and when it
 * does, a PlatformError of exactly that code and nothing else.
 */
async function outcome(c: PlatformCase, run: () => Promise<void>, form = ''): Promise<void> {
  const label = form === '' ? `case "${c.name}"` : `case "${c.name}" (${form})`
  if (c.error === undefined) {
    await run()
    return
  }
  let caught: unknown
  try {
    await run()
  } catch (err) {
    caught = err
  }
  if (caught === undefined) expect.fail(`${label}: expected the error ${c.error}, got none`)
  if (!(caught instanceof PlatformError)) {
    expect.fail(`${label}: expected the error ${c.error}, got ${caught instanceof Error ? caught.name : typeof caught}`)
  }
  expect(caught.code, label).toBe(c.error)
}

const rawKey = (raw: Bytes) => crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])

/** probe seals a fixed plaintext with a fixed nonce: two keys that give the same probe are one key. */
async function probe(key: CryptoKey): Promise<string> {
  return toBase64URL(new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(12).fill(7) }, key, encodeUTF8('probe'))))
}

/**
 * wtf8 encodes UTF-16 code units as a lax encoder would: pairs as one code
 * point, lone surrogates as their own three bytes. It checks that the two
 * forms of an ill-formed password case are one input.
 */
function wtf8(units: number[]): Bytes {
  const out: number[] = []
  for (let i = 0; i < units.length; i++) {
    let u = units[i]
    const next = units[i + 1]
    if (u >= 0xd800 && u <= 0xdbff && next !== undefined && next >= 0xdc00 && next <= 0xdfff) {
      u = 0x10000 + ((u - 0xd800) << 10) + (next - 0xdc00)
      i++
    }
    if (u < 0x80) out.push(u)
    else if (u < 0x800) out.push(0xc0 | (u >> 6), 0x80 | (u & 0x3f))
    else if (u < 0x10000) out.push(0xe0 | (u >> 12), 0x80 | ((u >> 6) & 0x3f), 0x80 | (u & 0x3f))
    else out.push(0xf0 | (u >> 18), 0x80 | ((u >> 12) & 0x3f), 0x80 | ((u >> 6) & 0x3f), 0x80 | (u & 0x3f))
  }
  return new Uint8Array(out) as Bytes
}

const runners: Record<string, (c: PlatformCase) => Promise<void>> = {
  'password-profile': async (c) => {
    let password: string
    if (typeof c.password === 'string') {
      if (c.password_utf16 !== undefined || c.password_utf8_b64url !== undefined) expect.fail(`case "${c.name}": two forms`)
      password = c.password
    } else {
      // Lone surrogates have no JSON string Go can write, so these cases
      // carry the UTF-16 code units a browser would hold, and Go's bytes.
      const units = c.password_utf16
      if (!Array.isArray(units)) expect.fail(`case "${c.name}": no password`)
      same(toBase64URL(wtf8(units)), str(c, 'password_utf8_b64url'), `case "${c.name}" utf-8 form`)
      password = String.fromCharCode(...units)
    }
    await outcome(c, async () => {
      const prepared = platform.preparePassword(password, { isNew: c.new === true })
      same(toBase64URL(prepared), str(c, 'prepared_b64url'), `case "${c.name}"`)
    })
  },

  kdf: async (c) => {
    const prepared = b64(c, 'prepared_b64url')
    const salt = b64(c, 'salt')
    await outcome(c, async () => {
      const d = await platform.derivePassword(prepared, salt, c.kdf)
      same(d.authKey, str(c, 'k_auth'), `case "${c.name}" k_auth`)
      same(d.authKey, str(c, 'auth_key'), `case "${c.name}" auth_key`)
      // K_wrap is non-extractable: it must seal what the recorded bytes seal.
      same(await probe(d.wrapKey), await probe(await rawKey(b64(c, 'k_wrap'))), `case "${c.name}" k_wrap`)
    })
  },

  'root-wrap': async (c) => {
    const kind = str(c, 'kind') as platform.WrapKind
    const key = b64(c, 'key')
    const sub = str(c, 'sub')
    const epoch = int(c, 'epoch')
    // The binding carries exactly what the case gives, as Go's Binding does.
    const passkey: platform.PasskeyBinding | undefined =
      c.rp_id !== undefined || c.credential_id !== undefined ? { rpId: c.rp_id ?? '', credentialId: c.credential_id ?? '' } : undefined
    const wrap = b64(c, 'wrap')
    for (const [form, k] of [['raw key', key], ['CryptoKey', await rawKey(key)]] as [string, Bytes | CryptoKey][]) {
      await outcome(
        c,
        async () => {
          const root = await platform.openRootWrap(kind, k, wrap, sub, epoch, passkey)
          same(toBase64URL(root), str(c, 'root'), `case "${c.name}" root`)
          same(platform.rootWrapAAD(kind, sub, epoch, passkey), str(c, 'aad'), `case "${c.name}" aad`)
          // Sealing with the recorded nonce, drawn once, gives the recorded bytes.
          const sealed = await withDraws({ bytes: [b64(c, 'nonce')] }, () => platform.sealRootWrap(kind, k, b64(c, 'root'), sub, epoch, passkey))
          same(toBase64URL(sealed), str(c, 'wrap'), `case "${c.name}" wrap`)
          // The envelope of section 6.5 with the header 0x01 || kind.
          const opened = await unwrapPrivateKey(platform.platformRootWrap(kind), wrap, await rawKey(key), encodeUTF8(str(c, 'aad')))
          same(toBase64URL(opened.privateKey), str(c, 'root'), `case "${c.name}" account's root`)
          expect(opened.stale).toBe(false)
        },
        form,
      )
    }
  },

  'recovery-code': async (c) => {
    if ((c.bytes === undefined) === (c.input === undefined)) expect.fail(`case "${c.name}": needs exactly one of bytes and input`)
    await outcome(c, async () => {
      let canonical: string
      if (c.bytes !== undefined) {
        const code = platform.recoveryCodeFromBytes(b64(c, 'bytes'))
        same(code.display, str(c, 'display'), `case "${c.name}" display`)
        canonical = code.canonical
        const drawn = await withDraws({ bytes: [b64(c, 'bytes')] }, platform.newRecoveryCode)
        same(drawn.canonical, canonical, `case "${c.name}" drawn`)
      } else {
        canonical = platform.canonicalRecoveryCode(str(c, 'input'))
        same(platform.formatRecoveryCode(canonical), str(c, 'display'), `case "${c.name}" display`)
      }
      same(canonical, str(c, 'canonical'), `case "${c.name}" canonical`)
      // What was typed, the canonical form and the display form derive the
      // same keys.
      const forms = [canonical, str(c, 'display')]
      if (c.input !== undefined) forms.push(str(c, 'input'))
      const want = await probe(await rawKey(b64(c, 'k_rwrap')))
      for (const typed of forms) {
        const keys = await platform.deriveRecovery(typed)
        same(keys.recoveryAuth, str(c, 'recovery_auth'), `case "${c.name}" recovery_auth`)
        same(await probe(keys.wrapKey), want, `case "${c.name}" k_rwrap`)
      }
    })
  },

  'product-key': async (c) => {
    const root = b64(c, 'root')
    await outcome(c, async () => {
      const { sk, pub, id } = await platform.deriveProductKey(root, str(c, 'product'), int(c, 'epoch'))
      same(toBase64URL(sk), str(c, 'sk'), `case "${c.name}" sk`)
      same(toBase64URL(pub), str(c, 'pub'), `case "${c.name}" pub`)
      same(id, str(c, 'product_key_id'), `case "${c.name}" product_key_id`)
      same(platform.productKeyId(str(c, 'product'), int(c, 'epoch')), id, `case "${c.name}" productKeyId`)
      same(toBase64URL(await platform.productPublicKey(root, str(c, 'product'), int(c, 'epoch'))), str(c, 'pub'), `case "${c.name}" productPublicKey`)
    })
  },

  verifier: async (c) => {
    if ((c.k_auth === undefined) === (c.r_proof === undefined)) expect.fail(`case "${c.name}": needs exactly one of k_auth and r_proof`)
    const sub = str(c, 'sub')
    await outcome(c, async () => {
      if (c.k_auth !== undefined) {
        same(toBase64URL(await platform.authVerifier(sub, b64(c, 'k_auth'))), str(c, 'auth_verifier'), `case "${c.name}"`)
      } else {
        same(toBase64URL(await platform.recoveryVerifier(sub, b64(c, 'r_proof'))), str(c, 'recovery_verifier'), `case "${c.name}"`)
      }
    })
  },

  email: async (c) => {
    await outcome(c, async () => {
      const norm = platform.normalizeEmail(str(c, 'input'))
      same(norm, str(c, 'email_norm'), `case "${c.name}"`)
      same(platform.normalizeEmail(norm), norm, `case "${c.name}" normalised twice`)
    })
  },

  'key-bundle': async (c) => {
    // A bundle given as a JSON value is read both as that value and as its
    // text; one given as text (a repeated member, the spelling of a number, a
    // byte order mark) only as text, which is what a tool holds.
    const inputs: [string, unknown][] = []
    if (c.bundle_text !== undefined) {
      if (c.bundle !== undefined) expect.fail(`case "${c.name}": both bundle and bundle_text`)
      inputs.push(['text', str(c, 'bundle_text')])
    } else {
      if (c.bundle === undefined) expect.fail(`case "${c.name}": no bundle`)
      inputs.push(['value', c.bundle], ['text', JSON.stringify(c.bundle)])
    }
    if ((c.password === undefined) === (c.recovery_code === undefined)) {
      expect.fail(`case "${c.name}": needs exactly one of password and recovery_code`)
    }
    for (const [form, input] of inputs) {
      await outcome(
        c,
        async () => {
          const root = c.password !== undefined
            ? await platform.openKeyBundle(input, str(c, 'password'))
            : await platform.openKeyBundleWithRecoveryCode(input, str(c, 'recovery_code'))
          same(toBase64URL(root), str(c, 'root'), `case "${c.name}" (${form}) root`)
        },
        form,
      )
    }
  },
}

describe('the platform\'s id-v1 vectors', () => {
  it('are all here, in their recorded shape', () => {
    let total = 0
    let failing = 0
    for (const [kind, [cases, mustFail]] of Object.entries(COUNTS)) {
      const f = loadPlatform(kind)
      const bad = f.cases.filter((c) => c.error !== undefined)
      expect([f.cases.length, bad.length], kind).toEqual([cases, mustFail])
      for (const c of f.cases) {
        for (const member of Object.keys(c)) expect(MEMBERS[kind].includes(member), `case "${c.name}": a member no runner reads: ${member}`).toBe(true)
        if (c.error !== undefined) expect(NAMES.has(c.error), `case "${c.name}": ${c.error}`).toBe(true)
      }
      total += cases
      failing += mustFail
    }
    expect([total, failing]).toEqual([257, 180])
  })
})

for (const kind of Object.keys(COUNTS)) {
  const f = loadPlatform(kind)
  describe(`platform/id-v1/${kind}.json`, () => {
    for (const c of f.cases) it(c.name, () => runners[kind](c))
  })
}

// The kit's own platform cases, in the kit's format: those Go wrote
// (kit/platform-go.json and kit/platform-password-go.json, and the fresh
// files of the same names in $KIT_CROSS_IN in the cross-language job) and
// those this side wrote at release time (kit/platform-ts.json and
// kit/platform-password-ts.json), which keep later versions to the same
// bytes.
async function kitCase(c: VectorCase): Promise<void> {
  const i = c.in
  const code = async (fn: () => unknown) => {
    try {
      await fn()
    } catch (err) {
      if (err instanceof PlatformError) return err.code
      return `not a PlatformError: ${err instanceof Error ? err.name : typeof err}`
    }
    return 'none'
  }
  const passkey = i.rp_id !== undefined || i.credential_id !== undefined ? { rpId: i.rp_id ?? '', credentialId: i.credential_id ?? '' } : undefined
  switch (c.op) {
    case 'platform.prepare_password':
      if (c.error) expect(await code(() => platform.preparePassword(i.password, { isNew: i.new }))).toBe(c.error)
      else expect(toB64(platform.preparePassword(i.password, { isNew: i.new }))).toBe(c.out.prepared_b64)
      return
    case 'platform.derive_password': {
      if (c.error) {
        expect(await code(() => platform.derivePassword(std(i.prepared_b64), std(i.salt_b64), i.kdf))).toBe(c.error)
        return
      }
      const d = await platform.derivePassword(std(i.prepared_b64), std(i.salt_b64), i.kdf)
      expect(d.authKey).toBe(c.out.auth_key)
      expect(await probe(d.wrapKey)).toBe(await probe(await rawKey(std(c.out.wrap_b64))))
      return
    }
    case 'platform.root_wrap': {
      expect(platform.rootWrapAAD(i.kind, i.sub, i.epoch, passkey)).toBe(c.out.aad)
      const wrap = await withDraws({ bytes: [std(i.nonce_b64)] }, () => platform.sealRootWrap(i.kind, std(i.key_b64), std(i.root_b64), i.sub, i.epoch, passkey))
      expect(toB64(wrap)).toBe(c.out.wrap_b64)
      expect(toB64(await platform.openRootWrap(i.kind, std(i.key_b64), std(c.out.wrap_b64), i.sub, i.epoch, passkey))).toBe(i.root_b64)
      return
    }
    case 'platform.open_root_wrap':
      expect(await code(() => platform.openRootWrap(i.kind, std(i.key_b64), std(i.wrap_b64), i.sub, i.epoch, passkey))).toBe(c.error)
      return
    case 'platform.recovery_code': {
      if (c.error) {
        expect(await code(() => platform.canonicalRecoveryCode(i.typed))).toBe(c.error)
        return
      }
      if (i.random_b64 !== undefined) {
        expect(platform.recoveryCodeFromBytes(std(i.random_b64)).canonical).toBe(c.out.canonical)
        expect((await withDraws({ bytes: [std(i.random_b64)] }, platform.newRecoveryCode)).display).toBe(c.out.display)
      }
      expect(platform.canonicalRecoveryCode(i.typed)).toBe(c.out.canonical)
      expect(platform.formatRecoveryCode(i.typed)).toBe(c.out.display)
      const keys = await platform.deriveRecovery(i.typed)
      expect(keys.recoveryAuth).toBe(c.out.recovery_auth)
      expect(await probe(keys.wrapKey)).toBe(await probe(await rawKey(std(c.out.wrap_b64))))
      return
    }
    case 'platform.product_key': {
      const k = await platform.deriveProductKey(std(i.root_b64), i.product, i.epoch)
      expect([toB64(k.sk), toB64(k.pub), k.id]).toEqual([c.out.sk_b64, c.out.pub_b64, c.out.product_key_id])
      return
    }
    case 'platform.verifier':
      if (i.k_auth_b64 !== undefined) expect(toB64(await platform.authVerifier(i.sub, std(i.k_auth_b64)))).toBe(c.out.auth_verifier_b64)
      else expect(toB64(await platform.recoveryVerifier(i.sub, std(i.r_proof_b64)))).toBe(c.out.recovery_verifier_b64)
      return
    case 'platform.normalize_email':
      if (c.error) expect(await code(() => platform.normalizeEmail(i.input))).toBe(c.error)
      else expect(platform.normalizeEmail(i.input)).toBe(c.out.email_norm)
      return
    case 'platform.key_bundle': {
      const open = () => i.recovery_code !== undefined ? platform.openKeyBundleWithRecoveryCode(i.bundle_text, i.recovery_code) : platform.openKeyBundle(i.bundle_text, i.password)
      if (c.error) expect(await code(open)).toBe(c.error)
      else expect(toB64(await open())).toBe(c.out.root_b64)
      return
    }
  }
  unhandled(c)
}

for (const [path, f] of files('kit/platform-go.json', 'kit/platform-ts.json', 'kit/platform-password-go.json', 'kit/platform-password-ts.json')) {
  describe(path, () => {
    expect(f.profile).toBe('platform')
    for (const c of f.cases.filter(forTS)) it(c.id, () => kitCase(c))
  })
}
