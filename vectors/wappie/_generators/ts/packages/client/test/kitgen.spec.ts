// Vector generator for github.com/thehappieco/kit, vectors/wappie/golden/*-ts.json.
//
// Not part of Wappie: vectors/wappie/_generators/run.sh copies this file and
// kitgen-random.ts into packages/client/test of a throwaway extraction of
// Wappie at a recorded commit and runs it with vitest there, so every value
// below comes from the client's code at that commit. Nothing in src/ is edited;
// randomness is replaced for the duration of each case (kitgen-random.ts) and
// the bytes each case consumed are recorded in it.
//
// Where the code keeps a value private (an AAD, a non-extractable key), the
// generator computes it independently and records it only after proving it:
// the code's own output must decrypt or verify under the recorded value.
// Files are opened with 'wx': nothing here overwrites a vector.

import { describe, expect, it } from 'vitest'
import { closeSync, openSync, readFileSync, writeSync } from 'node:fs'
import { diffieHellman, createPrivateKey, createPublicKey, hkdfSync, createHash } from 'node:crypto'
import { join } from 'node:path'
import { argon2id } from '@noble/hashes/argon2.js'

import * as account from '../src/crypto/account'
import * as bytes from '../src/crypto/bytes'
import * as hpke from '../src/crypto/hpke'
import * as seal from '../src/crypto/seal'
import * as passkey from '../src/crypto/passkey'
import * as browserAccount from '../src/crypto/browserAccount'
import { canonicalJSON } from '../src/crypto/jcs'
import * as derived from '../src/crypto/derived'
import * as keychain from '../src/crypto/aikeychain'
import { attestationUserData } from '../src/crypto/attestation'
import { importX25519Pair, withRandom, x25519Public, type Draw } from './kitgen-random'

const OUT = process.env.KITGEN_OUT ?? ''
const COMMIT = process.env.KITGEN_COMMIT ?? ''
const WAPPIE = process.env.KITGEN_WAPPIE ?? ''

type Bytes = Uint8Array<ArrayBuffer>
interface Case {
  id: string
  op: string
  langs?: string[]
  in: Record<string, unknown>
  out?: Record<string, unknown>
  error?: string
  reason?: string
  note?: string
}

const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64')
const unb64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64')) as Bytes
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex')
const utf8 = (s: string) => new Uint8Array(Buffer.from(s, 'utf8')) as Bytes
const pattern = (n: number, mul: number, add: number) => new Uint8Array(Array.from({ length: n }, (_, i) => (i * mul + add) & 0xff)) as Bytes
const version = (name: string) => JSON.parse(readFileSync(join('node_modules', name, 'package.json'), 'utf8')).version as string
const RANDOMNESS = 'crypto.getRandomValues and X25519 crypto.subtle.generateKey replaced for each case by an HMAC-SHA256 counter stream keyed by the case id (kitgen-random.ts); each case records the bytes it consumed'

function only(draws: Draw[], kind: Draw['kind']): Draw {
  const matching = draws.filter(d => d.kind === kind)
  if (matching.length !== 1) throw new Error(`expected one ${kind} draw, got ${matching.length}`)
  return matching[0]
}

async function aesOpen(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, aad?: Uint8Array): Promise<Bytes> {
  const k = await crypto.subtle.importKey('raw', key as Bytes, 'AES-GCM', false, ['decrypt'])
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce as Bytes, ...(aad ? { additionalData: aad as Bytes } : {}) }, k, data as Bytes))
}

async function aesSeal(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, aad?: Uint8Array): Promise<Bytes> {
  const k = await crypto.subtle.importKey('raw', key as Bytes, 'AES-GCM', false, ['encrypt'])
  return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce as Bytes, ...(aad ? { additionalData: aad as Bytes } : {}) }, k, data as Bytes))
}

const hkdf = (ikm: Uint8Array, salt: Uint8Array, info: Uint8Array) => new Uint8Array(hkdfSync('sha256', ikm, salt, info, 32)) as Bytes

function write(name: string, module: string, source: string, note: string, cases: Case[], keys?: Record<string, unknown>, randomness = RANDOMNESS) {
  const ids = new Set<string>()
  for (const c of cases) {
    if (ids.has(c.id)) throw new Error(`duplicate case id ${c.id}`)
    ids.add(c.id)
    if ((c.out === undefined) === (c.error === undefined)) throw new Error(`${c.id}: exactly one of out and error`)
  }
  const file = {
    format: 'thehappieco-kit-vectors/1',
    module,
    profile: 'wappie',
    generated_by: {
      lang: 'ts',
      source: `github.com/thehappieco/wappie@${COMMIT} ${source}`,
      toolchain: `node ${process.version}; @noble/hashes ${version('@noble/hashes')}; vitest ${version('vitest')} (sources transpiled by vitest)`,
      randomness,
      generator: 'vectors/wappie/_generators/ts/packages/client/test/kitgen.spec.ts',
    },
    note,
    ...(keys ? { keys } : {}),
    cases,
  }
  const fd = openSync(join(OUT, name), 'wx')
  try { writeSync(fd, JSON.stringify(file, null, 2) + '\n') } finally { closeSync(fd) }
}

/** The error a Wappie call threw, named by the code the vector format uses. */
async function failure(fn: () => Promise<unknown> | unknown, reasons: Record<string, string> = {}): Promise<{ error: string; reason?: string; note?: string }> {
  try {
    await fn()
  } catch (err) {
    const e = err as Error & { code?: string }
    if (e.name === 'AccountError') return { error: e.code!, reason: reasons[e.message] ?? 'unmapped:' + e.message }
    if (e.name === 'SealError') return { error: e.code! }
    if (e.name === 'CanonicalJSONError') return { error: 'jcs' }
    if (e.name === 'DerivedError' || e.name === 'KeychainError' || e.name === 'AttestationError') return { error: e.message || e.name }
    if (reasons[e.message]) return { error: reasons[e.message] }
    return { error: 'error', note: `${e.name}: ${e.message}` }
  }
  throw new Error('expected a failure')
}

const ACCOUNT_REASONS: Record<string, string> = {
  'senha incorreta': 'wrong_key',
  'a chave guardada está truncada': 'truncated',
  'um código de recuperação tem 30 caracteres': 'recovery_length',
  'Esta conta usa uma proteção que esta versão ainda não reconhece.': 'unsupported_alg',
  'Não foi possível preparar a proteção da conta. Tente novamente.': 'kdf_failed',
}
const PASSKEY_REASONS: Record<string, string> = {
  'A passkey não forneceu uma chave de desbloqueio válida.': 'bad_prf',
  'Chave da conta inválida.': 'bad_key',
  'O registro desta passkey está inválido. Entre com sua senha.': 'bad_envelope',
  'Esta passkey não conseguiu abrir seus dados. Entre com sua senha e cadastre uma passkey compatível.': 'open_failed',
}

describe.skipIf(!OUT)('kit vectors from Wappie\'s client', () => {
  it('account-ts.json', async () => {
    const cases: Case[] = []
    cases.push({ id: 'account/default-kdf-params', op: 'account.default_kdf_params', in: {}, out: { params: account.defaultKDFParams } })

    const saltA = pattern(16, 1, 0), saltB = pattern(16, 1, 0xf0)
    const cheap = { alg: 'argon2id', m: 8, t: 1, p: 1 }
    const passwords: [string, string][] = [
      ['ascii', 'correct horse battery staple'], ['portuguese', 'senha correta'], ['empty', ''],
      ['nfc', 'pässwörd'], ['nfd', 'pa\u0308sswo\u0308rd'], ['emoji', '😀🔑'], ['spaces', '  spaced out  '],
      ['kibibyte', 'ação🔑-'.repeat(128)],
    ]
    const derivedKeys = new Map<string, { wrap: Bytes; wrapKey: CryptoKey }>()
    const derive = async (id: string, password: string, salt: Bytes, params: account.KDFParams) => {
      const d = await account.derive(password, salt, params)
      const master = argon2id(utf8(password), salt, { m: params.m, t: params.t, p: params.p, dkLen: 32 })
      const auth = hkdf(master, new Uint8Array(0), utf8('whatserver2/auth'))
      const wrap = hkdf(master, new Uint8Array(0), utf8('whatserver2/wrap'))
      expect(b64(auth)).toBe(d.authKey)
      // The wrap key is non-extractable: prove the recorded bytes are it.
      const probe = pattern(32, 3, 1)
      const nonce = pattern(12, 5, 2)
      const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, d.wrapKey, probe))
      expect(Array.from(await aesOpen(wrap, nonce, sealed))).toEqual(Array.from(probe))
      derivedKeys.set(id, { wrap, wrapKey: d.wrapKey })
      cases.push({ id, op: 'account.derive', in: { password, salt_b64: b64(salt), params },
        out: { auth_key: d.authKey, master_b64: b64(master), auth_b64: b64(auth), wrap_b64: b64(wrap) } })
    }
    for (const [name, password] of passwords) await derive(`account/derive/${name}/m8-t1-p1`, password, saltA, cheap)
    await derive('account/derive/ascii/m8-t1-p1/salt-b', 'correct horse battery staple', saltB, cheap)
    for (const params of [{ m: 16, t: 2, p: 1 }, { m: 64, t: 3, p: 1 }, { m: 1024, t: 1, p: 1 }, { m: 32, t: 1, p: 2 }, { m: 9, t: 1, p: 1 }, { m: 31, t: 2, p: 2 }]) {
      await derive(`account/derive/ascii/m${params.m}-t${params.t}-p${params.p}`, 'correct horse battery staple', saltA, { alg: 'argon2id', ...params })
    }
    await derive('account/derive/ascii/default', 'correct horse battery staple', saltA, account.defaultKDFParams)
    for (const [name, params] of [['scrypt', { ...cheap, alg: 'scrypt' }], ['m4', { ...cheap, m: 4 }], ['t0', { ...cheap, t: 0 }], ['p0', { ...cheap, p: 0 }]] as const) {
      const f = await failure(() => account.derive('x', saltA, params), ACCOUNT_REASONS)
      const c: Case = { id: `account/derive/refuses/${name}`, op: 'account.derive', in: { password: 'x', salt_b64: b64(saltA), params }, error: f.error === 'error' ? 'kdf' : f.error, reason: f.reason ?? 'kdf_failed' }
      if (f.note) c.note = `Wappie's client threw @noble/hashes' own error (${f.note}); the kit reports it as an AccountError with code kdf.`
      cases.push(c)
    }

    // The wrap AAD is private to account.ts. It is computed here and proven:
    // a blob the code wrapped must open under it.
    const emails: [string, string][] = [
      ['plain', 'ana@example.com'], ['case-and-spaces', '  Ana@Example.COM '], ['tab-newline', '\tANA@EXAMPLE.COM\n'],
      ['dotted-capital-i', 'İstanbul@example.com'], ['dotted-capital-i-alone', 'İ'],
      ['final-sigma', 'ΑΣ@example.gr'], ['odysseus', 'ΟΔΥΣΣΕΥΣ@example.gr'],
      ['sigma-alone', 'Σ@example.gr'], ['sigma-at-end', 'ΑΣ'], ['sigma-then-period', 'ΑΣ.'],
      ['sigma-period-letter', 'ΑΣ.Α'], ['sigma-combining', 'ΑΣ\u0301'], ['combining-then-sigma', '\u0301Σ'],
      ['sigma-digit', 'aΣ1'], ['sigma-apostrophe-letter', 'ΑΣ\'a'],
      ['bom', '\ufeffana@example.com\ufeff'], ['nbsp', '\u00a0ana@example.com\u00a0'], ['nel', '\u0085ana@example.com'],
      ['line-separator-ideographic-space', '\u2028ana@example.com\u3000'], ['mongolian-vowel-separator', '\u180eana@example.com'],
      ['zero-width-space', '\u200bana@example.com'], ['capital-sharp-s', 'ẞ@x.io'], ['kelvin', 'K@x.io'], ['ohm', 'Ω@x.io'],
      ['titlecase-dz', 'ǅ@x.io'], ['roman-twelve', 'Ⅻ@x.io'], ['fullwidth', 'Ａ@ｘ.io'], ['deseret', '\u{10400}@x.io'],
      ['empty', ''], ['only-spaces', '   '],
    ]
    const wrapKey = derivedKeys.get('account/derive/ascii/m8-t1-p1')!
    const accountKey = pattern(32, 7, 0x11)
    const wrapAAD = (email: string) => utf8('whatserver2/usk|' + email.trim().toLowerCase())
    const blobs = new Map<string, Bytes>()
    for (const [name, email] of emails) {
      const { value: blob, draws } = await withRandom(`account/wrap/${name}`, () => account.wrapPrivateKey(accountKey, wrapKey.wrapKey, email))
      const nonce = only(draws, 'bytes').bytes
      expect(Array.from(await aesOpen(wrapKey.wrap, blob.subarray(1, 13), blob.subarray(13), wrapAAD(email)))).toEqual(Array.from(accountKey))
      expect(Array.from(blob.subarray(1, 13))).toEqual(Array.from(nonce))
      blobs.set(name, blob)
      cases.push({ id: `account/wrap-aad/${name}`, op: 'account.wrap_aad', in: { email }, out: { aad_b64: b64(wrapAAD(email)) } })
      cases.push({ id: `account/wrap/${name}`, op: 'account.wrap', in: { wrap_key_b64: b64(wrapKey.wrap), private_key_b64: b64(accountKey), email, nonce_b64: b64(nonce) },
        out: { blob_b64: b64(blob) } })
    }

    // Unwrap: v2, v1 (stale), a v1 blob that starts with the v2 marker, and refusals.
    const plainBlob = blobs.get('plain')!
    const unwrap = async (id: string, blob: Uint8Array, key: Bytes, keyHandle: CryptoKey, email: string) => {
      const input = { wrap_key_b64: b64(key), blob_b64: b64(blob), email }
      try {
        const got = await account.unwrapPrivateKey(blob as Bytes, keyHandle, email)
        cases.push({ id, op: 'account.unwrap', in: input, out: { private_key_b64: b64(got.privateKey), stale: got.stale } })
      } catch {
        const f = await failure(() => account.unwrapPrivateKey(blob as Bytes, keyHandle, email), ACCOUNT_REASONS)
        cases.push({ id, op: 'account.unwrap', in: input, error: f.error, reason: f.reason })
      }
    }
    await unwrap('account/unwrap/v2', plainBlob, wrapKey.wrap, wrapKey.wrapKey, 'ana@example.com')
    await unwrap('account/unwrap/v2-email-normalised', plainBlob, wrapKey.wrap, wrapKey.wrapKey, '  ANA@example.com\t')
    await unwrap('account/unwrap/v2-final-sigma', blobs.get('final-sigma')!, wrapKey.wrap, wrapKey.wrapKey, 'ΑΣ@example.gr')
    await unwrap('account/unwrap/v2-dotted-capital-i', blobs.get('dotted-capital-i')!, wrapKey.wrap, wrapKey.wrapKey, 'İSTANBUL@EXAMPLE.COM')
    const v1 = async (nonce: Bytes) => new Uint8Array([...nonce, ...await aesSeal(wrapKey.wrap, nonce, accountKey)]) as Bytes
    await unwrap('account/unwrap/v1-stale', await v1(pattern(12, 9, 0x40)), wrapKey.wrap, wrapKey.wrapKey, 'ana@example.com')
    await unwrap('account/unwrap/v1-starting-0x02', await v1(pattern(12, 9, 0x02)), wrapKey.wrap, wrapKey.wrapKey, 'ana@example.com')
    await unwrap('account/unwrap/refuses/other-email', plainBlob, wrapKey.wrap, wrapKey.wrapKey, 'bob@example.com')
    const other = derivedKeys.get('account/derive/portuguese/m8-t1-p1')!
    await unwrap('account/unwrap/refuses/wrong-key', plainBlob, other.wrap, other.wrapKey, 'ana@example.com')
    for (const n of [0, 1, 12, 13, 28, 29, 60]) {
      await unwrap(`account/unwrap/refuses/length-${n}`, plainBlob.subarray(0, n), wrapKey.wrap, wrapKey.wrapKey, 'ana@example.com')
    }
    const flipped = plainBlob.slice(); flipped[0] = 0x03
    await unwrap('account/unwrap/refuses/version-3', flipped, wrapKey.wrap, wrapKey.wrapKey, 'ana@example.com')

    // Recovery codes.
    const fixed = async (bytesOut: Uint8Array, fn: () => string) => {
      const original = crypto.getRandomValues
      ;(crypto as { getRandomValues: unknown }).getRandomValues = (array: Uint8Array) => { array.set(bytesOut); return array }
      try { return fn() } finally { (crypto as { getRandomValues: unknown }).getRandomValues = original }
    }
    const codes: string[] = []
    for (const [name, raw] of [['zeros', new Uint8Array(30)], ['ones', new Uint8Array(30).fill(0xff)], ['counting', pattern(30, 1, 0)], ['stride-37', pattern(30, 37, 5)]] as const) {
      const code = await fixed(raw, account.newRecoveryCode)
      codes.push(code)
      cases.push({ id: `account/recovery-code/${name}`, op: 'account.recovery_code', in: { random_b64: b64(raw) }, out: { code } })
    }
    for (let i = 0; i < 2; i++) {
      const { value: code, draws } = await withRandom(`account/recovery-code/stream-${i}`, account.newRecoveryCode)
      codes.push(code)
      cases.push({ id: `account/recovery-code/stream-${i}`, op: 'account.recovery_code', in: { random_b64: b64(only(draws, 'bytes').bytes) }, out: { code } })
    }
    const code = codes[4]
    const variants: [string, string][] = [
      ['exact', code], ['lowercase', code.toLowerCase()], ['spaces', code.replace(/-/g, ' ')], ['no-separators', code.replace(/-/g, '')],
      ['o-for-zero', code.replace(/0/g, 'O')], ['i-for-one', code.replace(/1/g, 'I')], ['l-for-one', code.replace(/1/g, 'l')],
      ['u-for-v', code.replace(/V/g, 'U')], ['punctuation', `#${code.replace(/-/g, '_.')}!`], ['dotless-i', code.replace(/1/g, 'ı')],
      ['long-s', code.replace(/S/g, 'ſ')], ['sharp-s', 'ß' + code.replace(/-/g, '').slice(2)], ['fi-ligature', 'ﬁ' + code.replace(/-/g, '').slice(2)],
      ['fullwidth-digit', '１' + code], ['arabic-indic-digit', '١' + code], ['ascii-codes', '0123456789abcdefghjkmnpqrstvwx'],
      ['too-short', code.replace(/-/g, '').slice(1)], ['too-long', code + 'A'], ['empty', ''],
    ]
    for (const [name, typed] of variants) {
      try {
        cases.push({ id: `account/normalise/${name}`, op: 'account.normalise_recovery_code', in: { code: typed }, out: { code: account.normaliseRecoveryCode(typed) } })
      } catch {
        const f = await failure(() => account.normaliseRecoveryCode(typed), ACCOUNT_REASONS)
        cases.push({ id: `account/normalise/${name}`, op: 'account.normalise_recovery_code', in: { code: typed }, error: f.error, reason: f.reason })
      }
    }
    for (const [i, c] of [codes[0], codes[4], code.toLowerCase().replace(/-/g, ' ')].entries()) {
      const key = hkdf(utf8(account.normaliseRecoveryCode(c)), new Uint8Array(0), utf8('whatserver2/recovery'))
      const proofBytes = hkdf(utf8(account.normaliseRecoveryCode(c)), new Uint8Array(0), utf8('whatserver2/recovery-auth'))
      const proof = await account.recoveryProof(c)
      expect(proof).toBe(b64(proofBytes))
      const { value: blob, draws } = await withRandom(`account/recovery-wrap/${i}`, async () => account.wrapPrivateKey(accountKey, await account.recoveryKey(c), 'ana@example.com'))
      expect(Array.from(await aesOpen(key, blob.subarray(1, 13), blob.subarray(13), wrapAAD('ana@example.com')))).toEqual(Array.from(accountKey))
      cases.push({ id: `account/recovery-key/${i}`, op: 'account.recovery_key', in: { code: c }, out: { key_b64: b64(key) } })
      cases.push({ id: `account/recovery-proof/${i}`, op: 'account.recovery_proof', in: { code: c }, out: { proof } })
      cases.push({ id: `account/recovery-wrap/${i}`, op: 'account.wrap', in: { wrap_key_b64: b64(key), private_key_b64: b64(accountKey), email: 'ana@example.com', nonce_b64: b64(only(draws, 'bytes').bytes) },
        out: { blob_b64: b64(blob) } })
    }
    for (const name of ['short']) {
      const f = await failure(() => account.recoveryProof('ABC-DEF'), ACCOUNT_REASONS)
      cases.push({ id: `account/recovery-proof/refuses/${name}`, op: 'account.recovery_proof', in: { code: 'ABC-DEF' }, error: f.error, reason: f.reason })
    }

    // Account keys and salts, as the stubbed randomness hands them out.
    for (let i = 0; i < 2; i++) {
      const { value: keys, draws } = await withRandom(`account/generate-keys/${i}`, account.generateAccountKeys)
      expect(Array.from(keys.privateKey)).toEqual(Array.from(only(draws, 'x25519').bytes))
      cases.push({ id: `account/generate-keys/${i}`, op: 'account.generate_keys', langs: ['ts'], in: { x25519_private_key_b64: b64(only(draws, 'x25519').bytes) },
        out: { private_key_b64: b64(keys.privateKey), public_key_b64: b64(keys.publicKey) } })
      const { value: salt, draws: saltDraws } = await withRandom(`account/fresh-salt/${i}`, account.freshSalt)
      cases.push({ id: `account/fresh-salt/${i}`, op: 'account.fresh_salt', langs: ['ts'], in: { random_b64: b64(only(saltDraws, 'bytes').bytes) }, out: { salt_b64: b64(salt) } })
    }

    write('account-ts.json', 'account', 'packages/client/src/crypto/account.ts',
      'Wappie\'s account scheme as its browser client computes it: Argon2id, the HKDF split, the v2 wrap bound to the email, v1 blobs, and the recovery code. ' +
      'master_b64, auth_b64, wrap_b64 and the wrap AAD were computed independently by the generator and proven against the code\'s output. Passwords, keys and codes are fixture material.',
      cases)
  }, 120_000)

  it('passkey-ts.json', async () => {
    const cases: Case[] = []
    const aadOf = (b: passkey.PasskeyBinding) => utf8(JSON.stringify(['wappie/passkey-vault', 1, b.rpID, b.userID, b.credentialID]))
    const bindings: [string, passkey.PasskeyBinding][] = [
      ['production', { rpID: 'wappie.thehappie.co', userID: '018f3a2b-0000-7000-8000-000000000003', credentialID: 'AQIDBAUGBwgJCgsMDQ4PEA' }],
      ['localhost', { rpID: 'localhost', userID: '018f3a2b-0000-7000-8000-000000000004', credentialID: 'x-y_z' }],
      ['json-escapes', { rpID: 'example.com', userID: 'a"b\\c\u0001', credentialID: '\u2028é\u{1f511}' }],
    ]
    const key = pattern(32, 11, 0x21)
    const prf = pattern(32, 13, 0x42)
    const envelopes = new Map<string, Bytes>()
    for (const [name, b] of bindings) {
      const k = hkdf(prf, utf8(b.rpID), utf8('wappie/passkey-wrap/v1'))
      const { value: env, draws } = await withRandom(`passkey/wrap/${name}`, () => passkey.wrapPasskey(key, prf, b))
      expect(Array.from(await aesOpen(k, env.subarray(1, 13), env.subarray(13), aadOf(b)))).toEqual(Array.from(key))
      envelopes.set(name, env)
      cases.push({ id: `passkey/aad/${name}`, op: 'passkey.aad', in: { rp_id: b.rpID, user_id: b.userID, credential_id: b.credentialID }, out: { aad_b64: b64(aadOf(b)) } })
      cases.push({ id: `passkey/key/${name}`, op: 'passkey.key', in: { prf_b64: b64(prf), rp_id: b.rpID }, out: { key_b64: b64(k) } })
      cases.push({ id: `passkey/wrap/${name}`, op: 'passkey.wrap', in: { private_key_b64: b64(key), prf_b64: b64(prf), rp_id: b.rpID, user_id: b.userID, credential_id: b.credentialID, nonce_b64: b64(only(draws, 'bytes').bytes) },
        out: { envelope_b64: b64(env) } })
    }
    const prod = bindings[0][1]
    const env = envelopes.get('production')!
    const unwrap = async (id: string, envelope: Uint8Array, p: Uint8Array, b: passkey.PasskeyBinding) => {
      const input = { envelope_b64: b64(envelope), prf_b64: b64(p), rp_id: b.rpID, user_id: b.userID, credential_id: b.credentialID }
      try {
        cases.push({ id, op: 'passkey.unwrap', in: input, out: { private_key_b64: b64(await passkey.unwrapPasskey(envelope as Bytes, p as Bytes, b)) } })
      } catch {
        const f = await failure(() => passkey.unwrapPasskey(envelope as Bytes, p as Bytes, b), PASSKEY_REASONS)
        cases.push({ id, op: 'passkey.unwrap', in: input, error: f.error })
      }
    }
    await unwrap('passkey/unwrap/production', env, prf, prod)
    await unwrap('passkey/unwrap/refuses/other-rp', env, prf, { ...prod, rpID: 'evil.example' })
    await unwrap('passkey/unwrap/refuses/other-user', env, prf, { ...prod, userID: '018f3a2b-0000-7000-8000-000000000009' })
    await unwrap('passkey/unwrap/refuses/other-credential', env, prf, { ...prod, credentialID: 'AQIDBAUGBwgJCgsMDQ4PEB' })
    const v2 = env.slice(); v2[0] = 2
    await unwrap('passkey/unwrap/refuses/version-2', v2, prf, prod)
    await unwrap('passkey/unwrap/refuses/length-60', env.subarray(0, 60), prf, prod)
    await unwrap('passkey/unwrap/refuses/length-62', new Uint8Array([...env, 0]), prf, prod)
    await unwrap('passkey/unwrap/refuses/wrong-prf', env, pattern(32, 13, 0x43), prod)
    await unwrap('passkey/unwrap/refuses/prf-31', env, prf.subarray(0, 31), prod)
    const tampered = env.slice(); tampered[30] ^= 1
    await unwrap('passkey/unwrap/refuses/tampered', tampered, prf, prod)
    for (const [name, k, p] of [['key-31', key.subarray(0, 31), prf], ['key-33', new Uint8Array(33), prf], ['prf-31', key, prf.subarray(0, 31)], ['prf-33', key, new Uint8Array(33)]] as const) {
      const f = await failure(() => withRandom(`passkey/wrap/refuses/${name}`, () => passkey.wrapPasskey(k as Bytes, p as Bytes, prod)), PASSKEY_REASONS)
      cases.push({ id: `passkey/wrap/refuses/${name}`, op: 'passkey.wrap', in: { private_key_b64: b64(k), prf_b64: b64(p), rp_id: prod.rpID, user_id: prod.userID, credential_id: prod.credentialID, nonce_b64: b64(new Uint8Array(12)) },
        error: f.error })
    }
    write('passkey-ts.json', 'passkey', 'packages/client/src/crypto/passkey.ts',
      'Wappie\'s passkey PRF wrap as its browser client computes it. key_b64 and the AAD were computed independently and proven against the code\'s output. ' +
      'Unwrapping with a PRF of the wrong length fails as open_failed, not bad_prf: the client checks the PRF inside the step that catches decryption failures.',
      cases)
  })

  it('browser-account-ts.json', async () => {
    const cases: Case[] = []
    const aadOf = (userID: string, pub: Uint8Array) => utf8(JSON.stringify(['wappie/browser-account-key', 1, userID, b64(pub)]))
    const priv = pattern(32, 5, 9)
    const pub = x25519Public(priv)
    for (const [name, userID] of [['uuid', '018f3a2b-0000-7000-8000-000000000003'], ['escapes', 'user "one"\\\u2028']] as const) {
      const envelope = await browserAccount.sealBrowserAccountKey(priv, pub, userID)
      const raw = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: envelope.nonce, additionalData: aadOf(userID, pub) }, envelope.key, envelope.ciphertext))
      expect(Array.from(raw)).toEqual(Array.from(priv))
      cases.push({ id: `browser-account/aad/${name}`, op: 'browser_account.aad', langs: ['ts'], in: { user_id: userID, public_key_b64: b64(pub) }, out: { aad_b64: b64(aadOf(userID, pub)) } })
    }
    const good = { version: 1, extractable: false, algorithm: 'AES-GCM', length: 256, usages: ['encrypt', 'decrypt'], nonce_len: 12, ciphertext_len: 48, public_len: 32 }
    const descriptors: [string, typeof good][] = [
      ['valid', good], ['version-2', { ...good, version: 2 }], ['extractable', { ...good, extractable: true }], ['aes-128', { ...good, length: 128 }],
      ['decrypt-only', { ...good, usages: ['decrypt'] }], ['nonce-11', { ...good, nonce_len: 11 }], ['ciphertext-47', { ...good, ciphertext_len: 47 }],
      ['public-31', { ...good, public_len: 31 }], ['hmac-key', { ...good, algorithm: 'HMAC' }],
    ]
    for (const [name, d] of descriptors) {
      const key = d.algorithm === 'HMAC'
        ? await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256', length: 256 }, d.extractable, ['sign'])
        : await crypto.subtle.generateKey({ name: 'AES-GCM', length: d.length }, d.extractable, d.usages as KeyUsage[])
      const valid = browserAccount.validBrowserKeyEnvelope({ version: d.version, key, nonce: new Uint8Array(d.nonce_len), ciphertext: new ArrayBuffer(d.ciphertext_len), publicRaw: new Uint8Array(d.public_len) })
      cases.push({ id: `browser-account/valid-envelope/${name}`, op: 'browser_account.valid_envelope', langs: ['ts'], in: d, out: { valid } })
    }
    write('browser-account-ts.json', 'browser_account', 'packages/client/src/crypto/browserAccount.ts',
      'The browser key-at-rest envelope. The key itself is non-extractable, so only its AAD (computed independently and proven by decryption) and the envelope validation are vectored.',
      cases, undefined, 'none recorded: the AES key is generated non-extractable and cannot be replayed')
  })

  it('seal-ts.json and hpke-ts.json', async () => {
    const cases: Case[] = []
    const keys: Record<string, unknown> = {}
    const accounts = new Map<string, { publicKey: Bytes; privateKey: Bytes }>()
    for (const name of ['account-1', 'account-2']) {
      const { value: pair, draws } = await withRandom(`seal/keys/${name}`, account.generateAccountKeys)
      accounts.set(name, pair)
      keys[name] = { private_key_b64: b64(pair.privateKey), public_key_b64: b64(pair.publicKey), x25519_private_key_b64: b64(only(draws, 'x25519').bytes) }
    }
    const tenant = bytes.parseUUID('018f3a2b-0000-7000-8000-000000000001')
    const device = bytes.parseUUID('018f3a2b-0000-7000-8000-000000000002')
    const users = ['018f3a2b-0000-7000-8000-000000000003', '00000000-0000-4000-8000-0000000000aa'].map(bytes.parseUUID)
    for (const epoch of [0, 1, 2, 3, 255, 256, 65535]) {
      for (const [i, user] of users.entries()) {
        cases.push({ id: `seal/grant-row/user-${i}/epoch-${epoch}`, op: 'seal.grant_row',
          in: { tenant: bytes.formatUUID(tenant), device: bytes.formatUUID(device), user: bytes.formatUUID(user), epoch },
          out: { row: bytes.formatUUID(await seal.grantRow(tenant, device, user, epoch)) } })
      }
    }
    const connection = bytes.parseUUID('018f3a2b-0000-7000-8000-000000000013')
    const draft = bytes.parseUUID('0b6f8a52-1c1e-4b3f-9d6a-3c0e2a7f4d11')
    const reply = bytes.parseUUID('018f3a2b-0000-7000-8000-000000000014')
    const drafts: [string, Bytes | null, string][] = [['direct', null, '5511999990000@s.whatsapp.net'], ['reply', reply, '5511999990000@s.whatsapp.net'],
      ['group', null, '120363041234567890@g.us'], ['lid', null, '240392312345678@lid'], ['non-ascii', null, 'ação@s.whatsapp.net'], ['empty-chat', reply, '']]
    for (const [name, r, chat] of drafts) {
      cases.push({ id: `wappie/draft-row/${name}`, op: 'wappie.draft_row',
        in: { tenant: bytes.formatUUID(tenant), device: bytes.formatUUID(device), connection: bytes.formatUUID(connection), draft: bytes.formatUUID(draft), reply: r ? bytes.formatUUID(r) : null, chat_key: chat },
        out: { row: bytes.formatUUID(await seal.draftRow(tenant, device, connection, draft, r, chat)) } })
    }
    const sealDirect = async (id: string, key: string, kind: number, row: Bytes, epoch: number, plaintext: Bytes) => {
      const pair = accounts.get(key)!
      const { value: env, draws } = await withRandom(id, () => seal.sealDirect(pair.publicKey, kind, tenant, row, epoch, plaintext))
      const opened = await seal.openDirect(await hpke.importArchiveKey(pair.privateKey), kind, tenant, row, env)
      expect(Array.from(opened)).toEqual(Array.from(plaintext))
      cases.push({ id, op: 'seal.seal_direct', in: { key, kind, tenant: bytes.formatUUID(tenant), row: bytes.formatUUID(row), epoch, plaintext_b64: b64(plaintext), ephemeral_private_key_b64: b64(only(draws, 'x25519').bytes) },
        out: { envelope_b64: b64(env) } })
    }
    for (const epoch of [1, 3, 65535]) {
      for (const [i, user] of users.entries()) {
        await sealDirect(`seal/direct/grant/user-${i}/epoch-${epoch}`, i === 0 ? 'account-1' : 'account-2', seal.Kind.DeviceGrant, await seal.grantRow(tenant, device, user, epoch), epoch, pattern(32, 3 + i, epoch & 0xff))
      }
    }
    for (const [name, r, chat] of drafts.slice(0, 3)) {
      const plaintext = utf8(JSON.stringify({ v: 1, connection_id: bytes.formatUUID(connection), device_id: bytes.formatUUID(device), chat_key: chat, reply_to_uid: r ? bytes.formatUUID(r) : null,
        text: 'Combinado: sexta às 15h.\nLevo os documentos.', created_at: '2026-10-01T09:30:15.123Z', cross_chat: [] }))
      await sealDirect(`seal/direct/draft/${name}`, 'account-1', seal.Kind.McpDraft, await seal.draftRow(tenant, device, connection, draft, r, chat), 2, plaintext)
    }
    await sealDirect('seal/direct/content-key-kind', 'account-1', seal.Kind.ContentKey, bytes.parseUUID('11111111-1111-7111-8111-111111111111'), 1, pattern(32, 1, 0))
    await sealDirect('seal/direct/reserved-kind', 'account-2', 0x0f, bytes.parseUUID('22222222-2222-7222-8222-222222222222'), 9, utf8(''))
    write('seal-ts.json', 'seal', 'packages/client/src/crypto/seal.ts',
      'The reverse direction: grants and drafts sealed by Wappie\'s TypeScript (the browser seals grants, the attested reader seals drafts with this code in Node), for Go to open. ' +
      'Each seal records the ephemeral X25519 private key it consumed.', cases, keys)

    // HPKE on its own.
    const hcases: Case[] = []
    const hkeys: Record<string, unknown> = {}
    const recipients = new Map<string, { publicKey: Bytes; privateKey: Bytes }>()
    for (const name of ['r1', 'r2']) {
      const { value: pair, draws } = await withRandom(`hpke/keys/${name}`, hpke.generateKeyPair)
      recipients.set(name, pair)
      hkeys[name] = { private_key_b64: b64(pair.privateKey), public_key_b64: b64(pair.publicKey) }
      hcases.push({ id: `hpke/generate-key-pair/${name}`, op: 'hpke.generate_key_pair', langs: ['ts'], in: { x25519_private_key_b64: b64(only(draws, 'x25519').bytes) },
        out: { private_key_b64: b64(pair.privateKey), public_key_b64: b64(pair.publicKey) } })
    }
    const shapes: [string, Bytes, Bytes, Bytes][] = [
      ['empty', new Uint8Array(0), new Uint8Array(0), new Uint8Array(0)],
      ['product-key-delivery', utf8('thehappie-id/v1/key-delivery'), utf8(canonicalJSON(['thehappie-id/key-delivery', 1, 'https://id.thehappie.co', 'wappie-app'])), pattern(32, 1, 7)],
      ['wsv1-info', utf8('wsv1/device_grant/018f3a2b-0000-7000-8000-000000000001/1'), pattern(45, 1, 0), pattern(32, 2, 1)],
      ['long', pattern(200, 3, 1), pattern(1000, 5, 2), pattern(4096, 7, 3)],
      ['one-byte', pattern(1, 1, 9), pattern(1, 1, 8), pattern(1, 1, 7)],
    ]
    for (const [name, info, aad, plaintext] of shapes) {
      for (const r of ['r1', 'r2']) {
        const id = `hpke/seal/${name}/${r}`
        const pair = recipients.get(r)!
        const { value, draws } = await withRandom(id, () => hpke.seal(pair.publicKey, info, aad, plaintext))
        const opened = await hpke.open(await hpke.importArchiveKey(pair.privateKey), value.enc, info, aad, value.ciphertext)
        expect(Array.from(opened)).toEqual(Array.from(plaintext))
        hcases.push({ id, op: 'hpke.seal', in: { key: r, info_b64: b64(info), aad_b64: b64(aad), plaintext_b64: b64(plaintext), ephemeral_private_key_b64: b64(only(draws, 'x25519').bytes) },
          out: { enc_b64: b64(value.enc), ciphertext_b64: b64(value.ciphertext) } })
      }
    }
    const base = hcases.find(c => c.id === 'hpke/seal/product-key-delivery/r1')!
    const open = async (id: string, key: string, mutate: (input: Record<string, Bytes>) => void) => {
      const input = { enc: unb64(base.out!.enc_b64 as string), info: unb64(base.in.info_b64 as string), aad: unb64(base.in.aad_b64 as string), ciphertext: unb64(base.out!.ciphertext_b64 as string) }
      mutate(input)
      // WebCrypto's own OperationError; its message varies by runtime, so it is not recorded.
      await failure(async () => hpke.open(await hpke.importArchiveKey(recipients.get(key)!.privateKey), input.enc, input.info, input.aad, input.ciphertext))
      hcases.push({ id, op: 'hpke.open', in: { key, enc_b64: b64(input.enc), info_b64: b64(input.info), aad_b64: b64(input.aad), ciphertext_b64: b64(input.ciphertext) }, error: 'open_failed' })
    }
    await open('hpke/open/refuses/wrong-key', 'r2', () => {})
    await open('hpke/open/refuses/other-info', 'r1', i => { i.info = utf8('thehappie-id/v1/key-delivery!') })
    await open('hpke/open/refuses/other-aad', 'r1', i => { i.aad = i.aad.slice(0, -1) as Bytes })
    await open('hpke/open/refuses/enc-flipped', 'r1', i => { i.enc = i.enc.slice() as Bytes; i.enc[0] ^= 1 })
    await open('hpke/open/refuses/ciphertext-flipped', 'r1', i => { i.ciphertext = i.ciphertext.slice() as Bytes; i.ciphertext[0] ^= 1 })
    for (const [name, priv] of [['zeros', new Uint8Array(32)], ['ones', new Uint8Array(32).fill(0xff)], ['counting', pattern(32, 1, 1)], ['account-1', recipients.get('r1')!.privateKey]] as const) {
      hcases.push({ id: `hpke/public-from-private/${name}`, op: 'hpke.public_from_private', in: { private_key_b64: b64(priv) }, out: { public_key_b64: b64(await hpke.publicFromPrivate(priv as Bytes)) } })
    }
    write('hpke-ts.json', 'hpke', 'packages/client/src/crypto/hpke.ts',
      'RFC 9180 base mode, single shot, suite KEM 0x0020 / KDF 0x0001 / AEAD 0x0002, as Wappie\'s WebCrypto implementation computes it. Each seal records its ephemeral key.',
      hcases, hkeys)
  })

  it('bytes-jcs-ts.json', async () => {
    const cases: Case[] = []
    const namespaces = ['018f3a2b-0000-7000-8000-000000000001', 'cc7d6b51-db4b-40d2-8e40-7826c8e4d835', '00000000-0000-0000-0000-000000000000']
    const names: [string, Bytes][] = [['empty', new Uint8Array(0)], ['x', utf8('x')], ['twenty', pattern(20, 3, 1)], ['utf8', utf8('ação 🔑')], ['hundred', pattern(100, 7, 5)]]
    for (const ns of namespaces) {
      for (const [name, value] of names) {
        cases.push({ id: `bytes/uuid-v5/${ns.slice(0, 8)}/${name}`, op: 'bytes.uuid_v5', in: { namespace: ns, name_b64: b64(value) }, out: { uuid: bytes.formatUUID(await bytes.uuidV5(bytes.parseUUID(ns), value)) } })
      }
    }
    for (const [name, text] of [['lower', '018f3a2b-0000-7000-8000-00000000000a'], ['upper', '018F3A2B-0000-7000-8000-00000000000A'], ['nil', '00000000-0000-0000-0000-000000000000'],
      ['no-hyphens', '018f3a2b000070008000000000000001'], ['braces', '{018f3a2b-0000-7000-8000-000000000001}'], ['urn', 'urn:uuid:018f3a2b-0000-7000-8000-000000000001'],
      ['not-hex', '018f3a2b-0000-7000-8000-00000000000g'], ['short', '018f3a2b-0000-7000-8000-00000000001']] as const) {
      try {
        cases.push({ id: `bytes/parse-uuid/${name}`, op: 'bytes.parse_uuid', langs: ['ts'], in: { text }, out: { bytes_b64: b64(bytes.parseUUID(text)) } })
      } catch {
        cases.push({ id: `bytes/parse-uuid/${name}`, op: 'bytes.parse_uuid', langs: ['ts'], in: { text }, error: 'invalid_uuid' })
      }
    }
    for (const [name, value] of [['counting', pattern(16, 1, 0)], ['ones', new Uint8Array(16).fill(0xff)]] as const) {
      cases.push({ id: `bytes/format-uuid/${name}`, op: 'bytes.format_uuid', langs: ['ts'], in: { bytes_b64: b64(value) }, out: { text: bytes.formatUUID(value as Bytes) } })
    }
    cases.push({ id: 'bytes/format-uuid/refuses/15', op: 'bytes.format_uuid', langs: ['ts'], in: { bytes_b64: b64(new Uint8Array(15)) }, error: 'invalid_uuid' })
    for (const n of [0, 1, 2, 3, 4, 5, 32, 0x8000, 0x8001, 65536]) {
      const value = pattern(n, 31, 7)
      const text = bytes.toBase64(value)
      expect(Array.from(bytes.fromBase64(text))).toEqual(Array.from(value))
      const out = n <= 32 ? { base64: text } : { base64_sha256_hex: hex(createHash('sha256').update(text).digest()) }
      cases.push({ id: `bytes/base64/${n}`, op: 'bytes.base64', langs: ['ts'], in: { length: n, pattern: { mul: 31, add: 7 } }, out })
    }
    for (const [name, text] of [['plain', '00ff10'], ['upper', '00FF10'], ['separators', ' 00:ff-10 \n'], ['spaces-inside', '00 ff 10'], ['empty', ''], ['odd', '0ff'], ['not-hex', '0g']] as const) {
      try {
        cases.push({ id: `bytes/from-hex/${name}`, op: 'bytes.from_hex', langs: ['ts'], in: { text }, out: { bytes_b64: b64(bytes.fromHex(text)) } })
      } catch {
        cases.push({ id: `bytes/from-hex/${name}`, op: 'bytes.from_hex', langs: ['ts'], in: { text }, error: 'invalid_hex' })
      }
    }

    // JCS. Inputs are JSON texts; each language parses one with its own parser
    // and canonicalises the result.
    const jcs = (id: string, json: string, langs?: string[]) => {
      try {
        cases.push({ id, op: 'jcs.canonical', ...(langs ? { langs } : {}), in: { json }, out: { jcs: canonicalJSON(JSON.parse(json)) } })
      } catch {
        cases.push({ id, op: 'jcs.canonical', ...(langs ? { langs } : {}), in: { json }, error: 'jcs' })
      }
    }
    jcs('jcs/rfc8785/3.2.2', '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}', ['ts'])
    jcs('jcs/rfc8785/3.2.2-strings', '{"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}')
    jcs('jcs/rfc8785/3.2.3-sorting', '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}')
    for (const [name, text] of [['zero', '0'], ['minus-zero', '-0'], ['min-subnormal', '5e-324'], ['max', '1.7976931348623157e308'], ['two-to-53', '9007199254740992'],
      ['big', '295147905179352830000'], ['1e21', '1e21'], ['near-1e23', '9.999999999999997e22'], ['micro', '0.000001'], ['1e-7', '1e-7'], ['minus-two', '-1.9999999999999998']] as const) {
      jcs(`jcs/rfc8785/appendix-b/${name}`, text, ['ts'])
    }
    for (const [name, text] of [['safe-max', '9007199254740991'], ['safe-min', '-9007199254740991'], ['small-ints', '[0,1,-1,42,65535,2147483647]'], ['controls', '"\\u0000\\u0001\\b\\t\\n\\u000b\\f\\r\\u001f\\u007f"'],
      ['line-separators', '"\\u2028\\u2029"'], ['html', '"<script>&amp;</script>"'], ['astral', '"\\ud83d\\ude00 \\ud834\\udd1e"'], ['nested', '{"b":[3,{"y":1,"x":2}],"a":"á","c":null}'],
      ['empty-object', '{}'], ['empty-array', '[]'], ['empty-string', '""'], ['keys-utf16-order', '{"\\ud83d\\ude00":1,"\\uffff":2,"\\ue000":3,"a":4}'],
      ['passkey-aad', '["wappie/passkey-vault",1,"wappie.thehappie.co","018f3a2b-0000-7000-8000-000000000003","AQIDBAUGBwgJCgsMDQ4PEA"]']] as const) {
      jcs(`jcs/integers-and-strings/${name}`, text)
    }
    jcs('jcs/refuses/lone-high-surrogate', '"\\ud800"', ['ts'])
    jcs('jcs/refuses/lone-low-surrogate-key', '{"\\udc00":1}', ['ts'])
    jcs('jcs/refuses/trailing-high-surrogate', '"a\\ud83d"', ['ts'])
    for (const expr of ['NaN', 'Infinity', '-Infinity', 'undefined', 'function', 'bigint', 'symbol', 'date', 'map', 'object-with-undefined']) {
      const value = ({ NaN: Number.NaN, Infinity, '-Infinity': -Infinity, undefined, function: () => 1, bigint: 1n, symbol: Symbol('x'), date: new Date(0), map: new Map(), 'object-with-undefined': { a: undefined } } as Record<string, unknown>)[expr]
      const f = await failure(() => canonicalJSON(value))
      cases.push({ id: `jcs/refuses/${expr}`, op: 'jcs.canonical_value', langs: ['ts'], in: { expr }, error: f.error })
    }
    // Wappie's reader-protocol vectors hash JCS texts; each must already be canonical.
    for (const [file, field] of [['packages/mcp-http/enclave/test/device-check-vectors.json', 'scope_jcs'], ['packages/mcp-http/enclave/test/ai-config-vectors.json', 'config_jcs']] as const) {
      const vectors = JSON.parse(readFileSync(join(WAPPIE, file), 'utf8')).vectors as Record<string, unknown>[]
      for (const [i, v] of vectors.entries()) {
        const text = v[field]
        if (typeof text !== 'string') continue
        expect(canonicalJSON(JSON.parse(text))).toBe(text)
        jcs(`jcs/wappie/${field.replace('_jcs', '')}/${i}`, text)
      }
    }
    write('bytes-jcs-ts.json', 'bytes+jcs', 'packages/client/src/crypto/bytes.ts and jcs.ts',
      'Byte plumbing and RFC 8785 as Wappie\'s client computes them. jcs.canonical inputs are JSON texts each language parses itself; cases marked langs ["ts"] hold numbers or strings Go does not accept (non-integers, integers beyond 2^53, lone surrogates). ' +
      'The jcs/wappie cases are the JCS texts in Wappie\'s device-check and AI-config vectors, re-canonicalised.',
      cases, undefined, 'none')
  })

  it('derived-ts.json, keychain-ts.json and attestation-ts.json (for kit v0.2.0)', async () => {
    // Derived records.
    const node = JSON.parse(readFileSync('testdata/node-derived.json', 'utf8'))
    const url = (s: string) => new Uint8Array(Buffer.from(s, 'base64url')) as Bytes
    const dsk = url(node.dsk)
    const dcases: Case[] = []
    const scope = (message_uid: string, feature: derived.Feature, epoch = node.epoch): derived.DerivedScope => ({ namespace: node.namespace, device_id: node.device_id, message_uid, feature, epoch })
    const keyOf = (epoch: number, label = 'wappie-derived/v1') => hkdf(dsk, bytes.parseUUID(node.namespace), new Uint8Array([...utf8(label), ...bytes.parseUUID(node.device_id), epoch >> 8, epoch & 0xff]))
    for (const [i, item] of (node.records as { message_uid: string; feature: derived.Feature; record: derived.DerivedRecord }[]).entries()) {
      const s = scope(item.message_uid, item.feature)
      const { value: env, draws } = await withRandom(`derived/seal/${i}`, () => derived.sealDerived(dsk, s, item.record))
      const plaintext = derived.derivedPlaintext(item.record)
      expect(new TextDecoder().decode(await aesOpen(keyOf(s.epoch), env.subarray(7, 19), env.subarray(19), derived.derivedAAD(s)))).toBe(plaintext)
      expect(await derived.openDerived(dsk, s, env)).toEqual(item.record)
      dcases.push({ id: `derived/aad/${i}`, op: 'derived.aad', langs: ['ts'], in: { scope: s }, out: { aad_b64: b64(derived.derivedAAD(s)) } })
      dcases.push({ id: `derived/seal/${i}`, op: 'derived.seal', langs: ['ts'], in: { dsk_b64: b64(dsk), scope: s, plaintext, nonce_b64: b64(only(draws, 'bytes').bytes) }, out: { envelope_b64: b64(env), key_b64: b64(keyOf(s.epoch)) } })
    }
    const first = dcases.find(c => c.op === 'derived.seal')!
    const firstScope = first.in.scope as derived.DerivedScope
    for (const [name, s] of [['other-message', { ...firstScope, message_uid: '018f3a2b-0000-7000-8000-000000000099' }], ['other-feature', { ...firstScope, feature: 'video' }],
      ['other-namespace', { ...firstScope, namespace: '018f3a2b-0000-7000-8000-000000000098' }], ['other-epoch', { ...firstScope, epoch: firstScope.epoch + 1 }]] as const) {
      const f = await failure(() => derived.openDerived(dsk, s as derived.DerivedScope, unb64(first.out!.envelope_b64 as string)))
      dcases.push({ id: `derived/open/refuses/${name}`, op: 'derived.open', langs: ['ts'], in: { dsk_b64: b64(dsk), scope: s, envelope_b64: first.out!.envelope_b64 }, error: f.error })
    }
    for (const [i, d] of (node.dedupe as { scope: derived.DerivedScope; input: derived.DedupeInput }[]).entries()) {
      dcases.push({ id: `derived/dedupe-tag/${i}`, op: 'derived.dedupe_tag', langs: ['ts'], in: { dsk_b64: b64(dsk), scope: d.scope, input: d.input }, out: { tag_hex: hex(await derived.dedupeTag(dsk, d.scope, d.input)) } })
    }
    write('derived-ts.json', 'derived', 'packages/client/src/crypto/derived.ts',
      'Captured for kit v0.2.0, which moves derived records into the kit. Records and DSK come from Wappie\'s packages/client/testdata/node-derived.json; key_b64 and the plaintext were computed independently and proven by decryption.',
      dcases)

    // The AI keychain.
    const kcases: Case[] = []
    const accountPriv = pattern(32, 3, 0x33)
    const accountPub = x25519Public(accountPriv)
    const pair = await importX25519Pair(accountPriv, false, ['deriveBits'])
    const accountKey = { key: pair.privateKey, publicRaw: accountPub as Bytes }
    const nodePriv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), accountPriv]), format: 'der', type: 'pkcs8' })
    const shared = diffieHellman({ privateKey: nodePriv, publicKey: createPublicKey(nodePriv) })
    const items = [
      { server_origin: 'https://api.wappie.thehappie.co', user_id: '018f3a2b-0000-7000-8000-000000000003', id: '018f3a2b-0000-7000-8000-0000000000a1', provider: 'anthropic' as const, api_key: 'sk-ant-fixture-0123456789abcdef', label: 'Trabalho', created_at: '2026-10-01T09:30:15.123Z' },
      { server_origin: 'http://localhost:8080', user_id: '018f3a2b-0000-7000-8000-000000000004', id: '018f3a2b-0000-7000-8000-0000000000a2', provider: 'google' as const, api_key: 'AIzaFixture0123456789abcdefghij', label: 'Pessoal 🔑', created_at: '2026-10-01T09:30:16Z' },
    ]
    for (const [i, item] of items.entries()) {
      const k = hkdf(shared, utf8(item.user_id), utf8('wappie/ai-keychain/v1'))
      const aad = utf8(JSON.stringify(['wappie/ai-keychain', 1, item.server_origin, item.user_id, item.id, item.provider]))
      const { value: env, draws } = await withRandom(`keychain/seal/${i}`, () => keychain.sealKeychainItem(accountKey, item))
      const plaintext = new TextDecoder().decode(await aesOpen(k, env.subarray(4, 16), env.subarray(16), aad))
      expect(await keychain.openKeychainItem(accountKey, { server_origin: item.server_origin, user_id: item.user_id, id: item.id, provider: item.provider, envelope: env })).toEqual(JSON.parse(plaintext))
      kcases.push({ id: `keychain/seal/${i}`, op: 'keychain.seal', langs: ['ts'], in: { account_private_key_b64: b64(accountPriv), item, nonce_b64: b64(only(draws, 'bytes').bytes) },
        out: { envelope_b64: b64(env), key_b64: b64(k), aad_b64: b64(aad), plaintext } })
    }
    const k0 = kcases[0]
    const row0 = { server_origin: items[0].server_origin, user_id: items[0].user_id, id: items[0].id, provider: items[0].provider }
    for (const [name, row] of [['other-origin', { ...row0, server_origin: 'https://evil.example' }], ['other-user', { ...row0, user_id: '018f3a2b-0000-7000-8000-000000000009' }],
      ['other-item', { ...row0, id: '018f3a2b-0000-7000-8000-0000000000a9' }], ['other-provider', { ...row0, provider: 'openai' }]] as const) {
      const f = await failure(() => keychain.openKeychainItem(accountKey, { ...row, envelope: unb64(k0.out!.envelope_b64 as string) }))
      kcases.push({ id: `keychain/open/refuses/${name}`, op: 'keychain.open', langs: ['ts'], in: { account_private_key_b64: b64(accountPriv), row, envelope_b64: k0.out!.envelope_b64 }, error: f.error })
    }
    write('keychain-ts.json', 'keychain', 'packages/client/src/crypto/aikeychain.ts',
      'Captured for kit v0.2.0, which moves the AI keychain into the kit. key_b64 and aad_b64 were computed independently and proven by decryption. API keys are fixture strings.',
      kcases)

    // Attestation user_data.
    const acases: Case[] = []
    const fields = { request_id: 'AAAAAAAAAAAAAAAAAAAAAA', resource: 'https://mcp.wappie.thehappie.co/mcp', tls_spki_sha256: 'a'.repeat(64), policy_sha256: 'b'.repeat(64), reader_version: '0.2.0' }
    for (const [name, f] of [['contract-shape', fields], ['other-version', { ...fields, reader_version: '1.10.3' }], ['unicode-resource', { ...fields, resource: 'https://mcp.example/ação' }]] as const) {
      const preimage = ['wappie-mcp-attest/v1', f.request_id, f.resource, f.tls_spki_sha256, f.policy_sha256, f.reader_version].join('\0')
      const got = hex(await attestationUserData(f))
      expect(got).toBe(hex(createHash('sha256').update(preimage).digest()))
      acases.push({ id: `attestation/user-data/${name}`, op: 'attestation.user_data', langs: ['ts'], in: { fields: f }, out: { user_data_hex: got } })
    }
    for (const [name, f] of [['nul-in-resource', { ...fields, resource: 'a\0b' }], ['bad-version', { ...fields, reader_version: 'v0.2' }], ['uppercase-hash', { ...fields, tls_spki_sha256: 'A'.repeat(64) }], ['short-hash', { ...fields, policy_sha256: 'b'.repeat(63) }]] as const) {
      const fl = await failure(() => attestationUserData(f))
      acases.push({ id: `attestation/user-data/refuses/${name}`, op: 'attestation.user_data', langs: ['ts'], in: { fields: f }, error: fl.error === 'error' ? (fl.note ?? 'error') : fl.error })
    }
    write('attestation-ts.json', 'attestation', 'packages/client/src/crypto/attestation.ts',
      'Captured for kit v0.2.0: the user_data commitment of the Nitro attestation verifier (SHA-256 of the label and five fields joined by 0x00).', acases, undefined, 'none')
  })
})
