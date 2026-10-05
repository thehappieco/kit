// The platform's golden vectors (vectors/platform/id-v1), written by the
// platform's Go and read here unchanged, in Node and in Chromium, Firefox
// and WebKit: every output must match byte for byte, and every must-fail
// case must be refused with a PlatformError of exactly the error name it
// records. Anything else thrown (an AccountError, an HPKEError, a
// DOMException) is a failure of this implementation, not a refusal. Failure
// messages name the case and the codes, never the values. A case is named
// by its id: its name, or op/name for a key-delivery or passkey case with an
// op.

import { describe, expect, it } from 'vitest'

import { unwrapPrivateKey } from '../src/account.js'
import { prfSalt as passkeyPRFSalt, unwrapPasskey } from '../src/passkey.js'
import { encodeUTF8, fromBase64URL, toBase64URL, type Bytes } from '../src/bytes.js'
import { HPKEError, PlatformError } from '../src/errors.js'
import * as platform from '../src/profiles/platform.js'
import { open as hpkeOpen, importPrivateKey } from '../src/hpke.js'
import { b64 as std, caseId, files, forTS, freshOnly, loadPlatform, toB64, unhandled, withDraws, type PlatformCase, type VectorCase } from './vectors.js'

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
  'password-stream-safe': ['name', 'error', 'password', 'password_utf16', 'password_utf8_b64url', 'new', 'prepared_b64url'],
  'key-delivery': [
    'name', 'op', 'error', 'root', 'product', 'epoch', 'iss', 'client_id', 'redirect_uri', 'sub', 'product_key_id', 'pk_p',
    'code_challenge', 'nonce', 'akd_priv', 'akd_pub', 'eph_priv', 'aad', 'akd_sealed',
  ],
  pkce: ['name', 'error', 'code_verifier', 'code_challenge'],
  passkey: ['name', 'op', 'error', 'rp_id', 'prf', 'root', 'sub', 'epoch', 'credential_id', 'nonce', 'prf_salt', 'k_pk', 'aad', 'wrap'],
  'client-extensions': ['name', 'error', 'client_extension_results'],
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
  'key-delivery': [73, 64],
  pkce: [18, 12],
  'password-stream-safe': [19, 11],
  passkey: [44, 35],
  'client-extensions': [46, 37],
}

const NAMES = new Set([
  'password_invalid', 'password_too_short', 'password_too_long', 'kdf_policy', 'wrap', 'recovery_code', 'email', 'product_key', 'bundle',
  'key_delivery', 'pkce', 'client_extensions', 'encoding',
])

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

/** b64Empty is b64 for a member the generator omits when it is empty (Go's omitempty). */
function b64Empty(c: PlatformCase, member: string): Bytes {
  return c[member] === undefined ? (new Uint8Array(0) as Bytes) : b64(c, member)
}

/** strEmpty is str for a member the generator omits when it is empty. */
function strEmpty(c: PlatformCase, member: string): string {
  return c[member] === undefined ? '' : str(c, member)
}

function same(got: string, want: string, label: string): void {
  if (got !== want) expect.fail(`${label}: the values differ (not shown)`)
}

/**
 * outcome runs one case: its checks when it records no error, and when it
 * does, a PlatformError of exactly that code and nothing else.
 */
async function outcome(c: PlatformCase, run: () => Promise<void>, form = ''): Promise<void> {
  const label = form === '' ? `case "${caseId(c)}"` : `case "${caseId(c)}" (${form})`
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

// password-stream-safe.json holds the platform's cases of the run rule of
// section 11.2, step 2, in the members of password-profile.json.
runners['password-stream-safe'] = runners['password-profile']

runners.pkce = async (c) => {
  await outcome(c, async () => {
    same(await platform.pkceChallenge(str(c, 'code_verifier')), str(c, 'code_challenge'), `case "${c.name}"`)
  })
}

// The probe of the akd_pub check, which deliverProductKey generates before
// the ephemeral key: any valid scalar, since it never reaches the output.
const PROBE = new Uint8Array(32).fill(0x42)

/**
 * key-delivery: a good case is derived, its AAD and akd_pub recomputed, its
 * blob opened with the raw key and with a non-extractable imported one, and
 * sealed again byte for byte under its recorded ephemeral key (withDraws:
 * the akd_pub check's probe, then the ephemeral key; no shipped function
 * takes one). An "open" case is refused by openProductKey and a "seal" case
 * by sealProductKey, each with exactly its code.
 */
runners['key-delivery'] = async (c) => {
  const request: platform.KeyDeliveryRequest = {
    issuer: str(c, 'iss'),
    clientId: str(c, 'client_id'),
    redirectUri: str(c, 'redirect_uri'),
    sub: str(c, 'sub'),
    codeChallenge: str(c, 'code_challenge'),
    nonce: str(c, 'nonce'),
  }
  const binding: platform.KeyDeliveryBinding = { ...request, productKeyId: str(c, 'product_key_id'), productKey: b64(c, 'pk_p') }
  const id = caseId(c)
  if (c.error === undefined) {
    if (c.op !== undefined) expect.fail(`case "${id}": a good case with an op`)
    const root = b64(c, 'root')
    const product = str(c, 'product')
    const epoch = int(c, 'epoch')
    const { sk, pub, id: productKeyId } = await platform.deriveProductKey(root, product, epoch)
    same(toBase64URL(pub), str(c, 'pk_p'), `case "${id}" pk_p`)
    same(productKeyId, str(c, 'product_key_id'), `case "${id}" product_key_id`)
    same(platform.keyDeliveryAAD(binding), str(c, 'aad'), `case "${id}" aad`)
    const akdPriv = b64(c, 'akd_priv')
    const recipient = await platform.importX25519PrivateKey(akdPriv)
    same(toBase64URL(await platform.x25519PublicFromKey(recipient)), str(c, 'akd_pub'), `case "${id}" akd_pub`)
    await platform.checkX25519PublicKey(b64(c, 'akd_pub'), 'key_delivery')
    same(toBase64URL(await platform.openProductKey(akdPriv, str(c, 'akd_sealed'), binding)), toBase64URL(sk), `case "${id}" opened by the raw key`)
    same(toBase64URL(await platform.openProductKey(recipient, b64(c, 'akd_sealed'), binding)), toBase64URL(sk), `case "${id}" opened by the imported key`)
    const input = { root, product, epoch, akdPub: str(c, 'akd_pub'), binding: request }
    const replay = await withDraws({ x25519: [PROBE, b64(c, 'eph_priv')] }, () => platform.deliverProductKey(input))
    same(replay.akd_sealed, str(c, 'akd_sealed'), `case "${id}" akd_sealed (replayed)`)
    same(replay.product_key, str(c, 'pk_p'), `case "${id}" delivered product_key`)
    same(replay.product_key_id, str(c, 'product_key_id'), `case "${id}" delivered product_key_id`)
    const fresh = await platform.sealProductKey(input)
    if (fresh === str(c, 'akd_sealed')) expect.fail(`case "${id}": a fresh seal repeats the recorded one`)
    same(toBase64URL(await platform.openProductKey(recipient, fresh, binding)), toBase64URL(sk), `case "${id}" a fresh seal`)
    return
  }
  if (c.op === 'open') {
    for (const member of ['root', 'product', 'epoch', 'akd_pub', 'eph_priv', 'aad']) {
      if (c[member] !== undefined) expect.fail(`case "${id}": an open case with ${member}`)
    }
    const akdPriv = b64(c, 'akd_priv')
    const sealed = strEmpty(c, 'akd_sealed')
    await outcome(c, async () => {
      await platform.openProductKey(akdPriv, sealed, binding)
    }, 'raw key, text')
    await outcome(c, async () => {
      await platform.openProductKey(akdPriv, b64Empty(c, 'akd_sealed'), binding)
    }, 'raw key, bytes')
    if (akdPriv.length === platform.X25519_KEY_LEN) {
      const recipient = await platform.importX25519PrivateKey(akdPriv)
      await outcome(c, async () => {
        await platform.openProductKey(recipient, sealed, binding)
      }, 'imported key')
    }
    return
  }
  if (c.op === 'seal') {
    for (const member of ['akd_priv', 'akd_sealed', 'eph_priv', 'aad']) {
      if (c[member] !== undefined) expect.fail(`case "${id}": a seal case with ${member}`)
    }
    const root = b64(c, 'root')
    const { sk, pub, id: productKeyId } = await platform.deriveProductKey(root, str(c, 'product'), int(c, 'epoch'))
    sk.fill(0)
    same(toBase64URL(pub), str(c, 'pk_p'), `case "${id}" pk_p`)
    same(productKeyId, str(c, 'product_key_id'), `case "${id}" product_key_id`)
    await outcome(c, async () => {
      await platform.sealProductKey({ root, product: str(c, 'product'), epoch: int(c, 'epoch'), akdPub: strEmpty(c, 'akd_pub'), binding: request })
    })
    return
  }
  expect.fail(`case "${id}": a must-fail case needs op open or seal`)
}

/**
 * passkey: a good case gives its salt and its K_pk (a non-extractable key,
 * compared by what it seals), its AAD, and its wrap byte for byte from the
 * recorded nonce, both through wrapRootWithPasskey and through sealRootWrap
 * under K_pk; it opens back to its root through unwrapRootWithPasskey and
 * openRootWrap, and it is section 7 with platformPasskey on the root wrap of
 * section 11.5: the generic passkey and account modules give the same salt
 * and open the same bytes. A must-fail case is refused at the step its op
 * names, salt, key or open, with wrap, and the callback of an open never
 * runs.
 */
runners.passkey = async (c) => {
  const id = caseId(c)
  const rpId = str(c, 'rp_id')
  if (c.error !== undefined) {
    for (const member of ['root', 'nonce', 'prf_salt', 'k_pk', 'aad']) {
      if (c[member] !== undefined) expect.fail(`case "${id}": a must-fail case with ${member}`)
    }
  }
  if (c.op === undefined) {
    if (c.error !== undefined) expect.fail(`case "${id}": a good case with an error`)
    const prf = b64(c, 'prf')
    const root = b64(c, 'root')
    const nonce = b64(c, 'nonce')
    const sub = str(c, 'sub')
    const epoch = int(c, 'epoch')
    const binding: platform.PasskeyBinding = { rpId, credentialId: str(c, 'credential_id') }
    const aad = str(c, 'aad')
    expect(platform.isRPID(rpId), `case "${id}"`).toBe(true)
    same(toBase64URL(await platform.prfSalt(rpId)), str(c, 'prf_salt'), `case "${id}" prf_salt`)
    const key = await platform.passkeyWrapKey(prf, rpId)
    expect(key.extractable, `case "${id}": K_pk is extractable`).toBe(false)
    const raw = await rawKey(b64(c, 'k_pk'))
    same(await probe(key), await probe(raw), `case "${id}" k_pk`)
    same(platform.rootWrapAAD('passkey', sub, epoch, binding), aad, `case "${id}" aad`)
    const input = { root, prf, sub, epoch, ...binding }
    same(await withDraws({ bytes: [nonce] }, () => platform.wrapRootWithPasskey(input)), str(c, 'wrap'), `case "${id}" wrap`)
    const under = await withDraws({ bytes: [nonce] }, () => platform.sealRootWrap('passkey', key, root, sub, epoch, binding))
    same(toBase64URL(under), str(c, 'wrap'), `case "${id}" the wrap under K_pk`)
    const wrap = b64(c, 'wrap')
    let lent: Uint8Array | undefined
    const opened = await platform.unwrapRootWithPasskey({ prf, wrap: str(c, 'wrap'), sub, epoch, ...binding }, async (r) => {
      lent = r
      return toBase64URL(new Uint8Array(r) as Bytes)
    })
    same(opened, str(c, 'root'), `case "${id}" root`)
    if (lent === undefined || lent.some((x) => x !== 0)) expect.fail(`case "${id}": the lent root is not zeroed`)
    same(toBase64URL(await platform.openRootWrap('passkey', key, wrap, sub, epoch, binding)), str(c, 'root'), `case "${id}" root under K_pk`)
    // A fresh wrap draws its own nonce and opens alike.
    const fresh = await platform.wrapRootWithPasskey(input)
    if (fresh === str(c, 'wrap')) expect.fail(`case "${id}": a fresh wrap repeats the recorded nonce`)
    same(toBase64URL(await platform.openRootWrap('passkey', key, fromBase64URL(fresh, platform.WRAP_LEN), sub, epoch, binding)), str(c, 'root'), `case "${id}" a fresh wrap`)
    // Section 7 with platformPasskey, and section 6.5 with the header 0x01 0x03.
    same(toBase64URL(await passkeyPRFSalt(platform.platformPasskey, rpId)), str(c, 'prf_salt'), `case "${id}" passkey.prfSalt`)
    same(toBase64URL(await unwrapPasskey(platform.platformPasskey, wrap, prf, rpId, encodeUTF8(aad))), str(c, 'root'), `case "${id}" passkey.unwrapPasskey`)
    const account = await unwrapPrivateKey(platform.platformRootWrap('passkey'), wrap, raw, encodeUTF8(aad))
    same(toBase64URL(account.privateKey), str(c, 'root'), `case "${id}" account's root`)
    expect(account.stale).toBe(false)
    return
  }
  if (c.error !== 'wrap') expect.fail(`case "${id}": a passkey refusal is wrap`)
  if (c.op === 'salt') {
    for (const member of ['prf', 'wrap', 'sub', 'epoch', 'credential_id']) {
      if (c[member] !== undefined) expect.fail(`case "${id}": a salt case with ${member}`)
    }
    expect(platform.isRPID(rpId), `case "${id}"`).toBe(false)
    await outcome(c, async () => {
      await platform.prfSalt(rpId)
    }, 'salt')
    // An id refused at the salt has no key either, whatever the PRF output.
    await outcome(c, async () => {
      await platform.passkeyWrapKey(new Uint8Array(platform.PRF_OUTPUT_LEN).fill(0x5a), rpId)
    }, 'key')
    return
  }
  if (c.op === 'key') {
    for (const member of ['wrap', 'sub', 'epoch', 'credential_id']) {
      if (c[member] !== undefined) expect.fail(`case "${id}": a key case with ${member}`)
    }
    const prf = b64(c, 'prf')
    await outcome(c, async () => {
      await platform.passkeyWrapKey(prf, rpId)
    })
    return
  }
  if (c.op === 'open') {
    const prf = b64(c, 'prf')
    const sub = str(c, 'sub')
    const epoch = int(c, 'epoch')
    const binding: platform.PasskeyBinding = { rpId, credentialId: str(c, 'credential_id') }
    await outcome(c, async () => {
      await platform.unwrapRootWithPasskey({ prf, wrap: str(c, 'wrap'), sub, epoch, ...binding }, async () => expect.fail(`case "${id}": opened`))
    }, 'one shot')
    await outcome(c, async () => {
      await platform.openRootWrap('passkey', await platform.passkeyWrapKey(prf, rpId), b64(c, 'wrap'), sub, epoch, binding)
    }, 'under K_pk')
    return
  }
  expect.fail(`case "${id}": a must-fail case needs op salt, key or open`)
}

/**
 * client-extensions: checkClientExtensionsText on the exact text; an
 * accepted text is accepted as the value JSON.parse makes of it too.
 */
runners['client-extensions'] = async (c) => {
  const text = c.client_extension_results
  if (typeof text !== 'string') expect.fail(`case "${c.name}": no client_extension_results`)
  if (c.op !== undefined) expect.fail(`case "${c.name}": an op`)
  await outcome(c, async () => {
    platform.checkClientExtensionsText(text)
  })
  if (c.error === undefined) platform.checkClientExtensions(JSON.parse(text))
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
        for (const member of Object.keys(c)) expect(MEMBERS[kind].includes(member), `case "${caseId(c)}": a member no runner reads: ${member}`).toBe(true)
        if (c.error !== undefined) expect(NAMES.has(c.error), `case "${caseId(c)}": ${c.error}`).toBe(true)
      }
      total += cases
      failing += mustFail
    }
    expect([total, failing]).toEqual([457, 339])
  })
})

for (const kind of Object.keys(COUNTS)) {
  const f = loadPlatform(kind)
  describe(`platform/id-v1/${kind}.json`, () => {
    for (const c of f.cases) it(caseId(c), () => runners[kind](c))
  })
}

describe('platform/id-v1/key-delivery.json', () => {
  it('counts 9 good cases, 39 refused by the open and 25 by the seal', () => {
    const cases = loadPlatform('key-delivery').cases
    const count = (f: (c: PlatformCase) => boolean) => cases.filter(f).length
    expect([count((c) => c.op === undefined), count((c) => c.op === 'open'), count((c) => c.op === 'seal')]).toEqual([9, 39, 25])
    expect([count((c) => c.error === 'key_delivery'), count((c) => c.error === 'product_key')]).toEqual([61, 3])
    expect(count((c) => c.op === undefined && c.error !== undefined) + count((c) => c.op !== undefined && c.error === undefined)).toBe(0)
  })

  // The blob whose sealer spelled enc with bit 255 set, in the blob and in
  // the KEM context alike: plain RFC 9180 (the hpke module) may open it, as
  // every engine checked so far does, or refuse it with an HPKEError; only
  // the canonical check of openProductKey must refuse it, everywhere.
  it('refuses the aliased enc that plain HPKE may open', async () => {
    const cases = loadPlatform('key-delivery').cases
    const c = cases.find((x) => caseId(x) === 'open/enc spelled with bit 255 set by the sealer, in the blob and in the KEM context alike')!
    const good = cases.find((x) => x.name === 'wappie-app in production')!
    const sealed = b64(c, 'akd_sealed')
    expect(sealed[31] & 0x80).toBe(0x80)
    const binding = { issuer: c.iss, clientId: c.client_id, redirectUri: c.redirect_uri, sub: c.sub, codeChallenge: c.code_challenge, nonce: c.nonce, productKeyId: c.product_key_id, productKey: b64(c, 'pk_p') }
    same(platform.keyDeliveryAAD(binding), str(good, 'aad'), 'the aliased case\'s binding')
    try {
      const pt = await hpkeOpen(await importPrivateKey(b64(c, 'akd_priv')), sealed.slice(0, 32), encodeUTF8(platform.KEY_DELIVERY_INFO), encodeUTF8(str(good, 'aad')), sealed.slice(32))
      const { sk } = await platform.deriveProductKey(b64(good, 'root'), good.product, good.epoch)
      same(toBase64URL(pt), toBase64URL(sk), 'what plain HPKE opens')
    } catch (err) {
      expect(err).toBeInstanceOf(HPKEError)
    }
    await outcome(c, async () => {
      await platform.openProductKey(b64(c, 'akd_priv'), sealed, binding)
    })
  })
})

// The kit's own platform cases, in the kit's format: those Go wrote
// (kit/platform-go.json, kit/platform-password-go.json and
// kit/platform-delivery-go.json, and the fresh files of the same names in
// $KIT_CROSS_IN in the cross-language job) and those this side wrote at
// release time (kit/platform-ts.json, kit/platform-password-ts.json and
// kit/platform-delivery-ts.json), which keep later versions to the same
// bytes, or, for fresh seals, to opening them.
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
  return kitDeliveryCase(c, code)
}

// The kit's own cases of part 2 (SPEC sections 11.12 and 11.13), in the
// kit's format: key-delivery AADs, fresh deliveries opened (a fresh seal
// cannot be replayed in the other language), the seal's refusals of akd_pub,
// and PKCE challenges.
async function kitDeliveryCase(c: VectorCase, code: (fn: () => unknown) => Promise<string>): Promise<void> {
  const i = c.in
  const request: platform.KeyDeliveryRequest = { issuer: i.iss, clientId: i.client_id, redirectUri: i.redirect_uri, sub: i.sub, codeChallenge: i.code_challenge, nonce: i.nonce }
  const binding = (): platform.KeyDeliveryBinding => ({ ...request, productKeyId: i.product_key_id, productKey: std(i.pk_p_b64) })
  switch (c.op) {
    case 'platform.key_delivery_aad':
      if (c.error) expect(await code(() => platform.keyDeliveryAAD(binding()))).toBe(c.error)
      else expect(platform.keyDeliveryAAD(binding())).toBe(c.out.aad)
      return
    case 'platform.open_product_key': {
      const open = () => platform.openProductKey(std(i.akd_priv_b64), std(i.akd_sealed_b64), binding())
      if (c.error) expect(await code(open)).toBe(c.error)
      else expect(toB64(await open())).toBe(c.out.sk_b64)
      return
    }
    case 'platform.seal_product_key':
      expect(await code(() => platform.sealProductKey({ root: std(i.root_b64), product: i.product, epoch: i.epoch, akdPub: toBase64URL(std(i.akd_pub_b64)), binding: request }))).toBe(c.error)
      return
    case 'platform.pkce_challenge':
      if (c.error) expect(await code(() => platform.pkceChallenge(i.code_verifier))).toBe(c.error)
      else expect(await platform.pkceChallenge(i.code_verifier)).toBe(c.out.code_challenge)
      return
  }
  return kitPasskeyCase(c, code)
}

// The kit's own cases of part 3 (SPEC section 11.16), in the kit's format:
// PRF salts of relying party ids, fresh passkey wraps replayed byte for
// byte from the nonce each drew and opened (K_pk, when Go recorded it,
// compared by what it seals), the same wraps refused with one thing
// changed, and the allowlist's verdict on client extension results.
async function kitPasskeyCase(c: VectorCase, code: (fn: () => unknown) => Promise<string>): Promise<void> {
  const i = c.in
  const binding = { rpId: i.rp_id, credentialId: i.credential_id }
  switch (c.op) {
    case 'platform.prf_salt':
      expect(platform.isRPID(i.rp_id)).toBe(c.error === undefined)
      if (c.error) expect(await code(() => platform.prfSalt(i.rp_id))).toBe(c.error)
      else expect(toB64(await platform.prfSalt(i.rp_id))).toBe(c.out.prf_salt_b64)
      return
    case 'platform.passkey_wrap': {
      const prf = std(i.prf_b64)
      expect(platform.rootWrapAAD('passkey', i.sub, i.epoch, binding)).toBe(c.out.aad)
      const wrap = await withDraws({ bytes: [std(i.nonce_b64)] }, () => platform.wrapRootWithPasskey({ root: std(i.root_b64), prf, sub: i.sub, epoch: i.epoch, ...binding }))
      expect(toB64(fromBase64URL(wrap, platform.WRAP_LEN))).toBe(c.out.wrap_b64)
      const root = await platform.unwrapRootWithPasskey({ prf, wrap: toBase64URL(std(c.out.wrap_b64)), sub: i.sub, epoch: i.epoch, ...binding }, async (r) => toB64(r))
      expect(root).toBe(i.root_b64)
      if (c.out.k_pk_b64 !== undefined) expect(await probe(await platform.passkeyWrapKey(prf, i.rp_id))).toBe(await probe(await rawKey(std(c.out.k_pk_b64))))
      return
    }
    case 'platform.open_passkey_wrap':
      expect(c.error).toBe('wrap')
      expect(await code(() => platform.unwrapRootWithPasskey({ prf: std(i.prf_b64), wrap: toBase64URL(std(i.wrap_b64)), sub: i.sub, epoch: i.epoch, ...binding }, async () => expect.fail(`${c.id}: opened`)))).toBe(c.error)
      return
    case 'platform.check_client_extensions':
      if (typeof i.text !== 'string') expect.fail(`${c.id}: no text`)
      if (c.error) expect(await code(() => platform.checkClientExtensionsText(i.text))).toBe(c.error)
      else {
        platform.checkClientExtensionsText(i.text)
        expect(c.out.accepted).toBe(true)
      }
      return
  }
  unhandled(c)
}

for (const [path, f] of [
  ...files(
    'kit/platform-go.json',
    'kit/platform-ts.json',
    'kit/platform-password-go.json',
    'kit/platform-password-ts.json',
    'kit/platform-delivery-go.json',
    'kit/platform-delivery-ts.json',
  ),
  ...freshOnly('platform-passkey-go.json'),
]) {
  describe(path, () => {
    expect(f.profile).toBe('platform')
    for (const c of f.cases.filter(forTS)) it(c.id, () => kitCase(c))
  })
}

describe('platform/id-v1/passkey.json', () => {
  it('counts 9 good cases and 35 wrap refusals: 16 at the salt, 6 at the key, 13 at the open', () => {
    const cases = loadPlatform('passkey').cases
    const count = (f: (c: PlatformCase) => boolean) => cases.filter(f).length
    expect([count((c) => c.op === undefined), count((c) => c.op === 'salt'), count((c) => c.op === 'key'), count((c) => c.op === 'open')]).toEqual([9, 16, 6, 13])
    expect(count((c) => c.error === 'wrap')).toBe(35)
    expect(count((c) => c.op === undefined && c.error !== undefined) + count((c) => c.op !== undefined && c.error === undefined)).toBe(0)
    expect(new Set(cases.map((c) => c.name)).size).toBe(cases.length)
  })
})

describe('platform/id-v1/client-extensions.json', () => {
  it('counts 9 accepted texts and 37 refused, all client_extensions, none with an op', () => {
    const cases = loadPlatform('client-extensions').cases
    expect(cases.filter((c) => c.error === undefined).length).toBe(9)
    expect(cases.filter((c) => c.error === 'client_extensions').length).toBe(37)
    expect(cases.filter((c) => c.op !== undefined).length).toBe(0)
  })

  // An allowlist over JSON.parse, which keeps the last of two members,
  // passes the repeats the vectors refuse; checkClientExtensionsText reads
  // the text and refuses them.
  it('tests the strict reader: a check over JSON.parse passes the three repeats', () => {
    const lenient = (text: string) => {
      try {
        platform.checkClientExtensions(JSON.parse(text))
        return true
      } catch {
        return false
      }
    }
    const passed = loadPlatform('client-extensions').cases.filter((c) => c.error !== undefined && lenient(c.client_extension_results)).map((c) => c.name)
    expect(passed).toEqual(['a duplicate member', 'a duplicate member inside prf', 'a duplicate member spelled with an escape'])
  })
})
