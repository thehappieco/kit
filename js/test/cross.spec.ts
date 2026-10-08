// Writes fresh vectors with the kit's TypeScript for the Go tests to open: the
// TypeScript-to-Go half of the cross-language check (internal/cross writes
// the other half).
//
//   KIT_CROSS_OUT=/tmp/x npx vitest run test/cross.spec.ts
//
// Every run uses fresh keys and nonces, and records what each seal drew so Go
// can reproduce wraps byte for byte. `make vectors-kit` runs it into
// vectors/kit at release time; the files written then stay as golden.

import { execSync } from 'node:child_process'
import { closeSync, mkdirSync, openSync, readFileSync, writeSync } from 'node:fs'
import { join } from 'node:path'
import { argon2id } from '@noble/hashes/argon2.js'
import { describe, expect, it, vi } from 'vitest'

import { derive, newRecoveryCode, normaliseRecoveryCode, recoveryProof, unwrapPrivateKey, wrapPrivateKey, type AccountProfile, type KDFParams } from '../src/account.js'
import { formatUUID, fromBase64URL, parseUUID, toBase64URL, uuidV5, type Bytes } from '../src/bytes.js'
import { generateKeyPair, importPrivateKey, publicFromPrivate, seal as hpkeSeal } from '../src/hpke.js'
import { canonicalJSON, CanonicalJSONError } from '../src/jcs.js'
import { endsInANumber, prfSalt, unwrapPasskey, wrapPasskey } from '../src/passkey.js'
import { canonical, signature } from '../src/reqhmac.js'
import { grantRow, openDirect, sealDirect } from '../src/seal.js'
import {
  isPlatformWrapError, openPlatformWrap, PLATFORM_WRAP_LEN, platformWrapAAD, platformWrapInfo, sealPlatformWrap, type PlatformWrapBinding, type PlatformWrapProfile,
} from '../src/platformwrap.js'
import { mailiePlatformWrap } from '../src/profiles/mailie.js'
import {
  accountWrapAAD, DIRECTION_TO_READER, Kind, passkeyAAD, wappieAccount, wappieMCPHMAC, wappiePasskey, wappiePlatformWrap, wappieSeal,
} from '../src/profiles/wappie.js'
import * as platform from '../src/profiles/platform.js'
import { sealBase } from '../src/internal/platform/hpkebase.js'
import { codeOf, recording, toB64, toWTF8, utf8, type VectorCase } from './vectors.js'

// X25519 public keys of low order, which nothing may be sealed to (the same
// list as the Go side's internal/forge).
const lowOrder: [string, string][] = [
  ['zero', '0000000000000000000000000000000000000000000000000000000000000000'],
  ['one', '0100000000000000000000000000000000000000000000000000000000000000'],
  ['order-8-a', 'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800'],
  ['order-8-b', '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157'],
  ['p-minus-1', 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'],
  ['p', 'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'],
  ['p-plus-1', 'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'],
  ['zero-bit-255', '0000000000000000000000000000000000000000000000000000000000000080'],
  ['order-8-a-bit-255', 'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880'],
]
const hex = (h: string) => new Uint8Array(h.match(/../g)!.map((b) => parseInt(b, 16))) as Bytes

const OUT = process.env.KIT_CROSS_OUT ?? ''
const fromB64URL = (s: string) => fromBase64URL(s, Math.floor((s.length * 3) / 4))

function source(): string {
  try {
    const rev = execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim()
    // The files this writes are not part of the source they record.
    const dirty = execSync("git status --porcelain -- . ':(exclude)vectors/kit' ':(exclude)vectors/MANIFEST.sha256'", { encoding: 'utf8' }).trim() !== ''
    return `github.com/thehappieco/kit@${rev}${dirty ? '+dirty' : ''}`
  } catch {
    return 'github.com/thehappieco/kit@unknown'
  }
}

// RANDOMNESS is what a file's generated_by says of the randomness its cases
// drew, unless write is given its own account.
const RANDOMNESS = 'crypto.getRandomValues; each case records the bytes and X25519 keys it drew'

function write(name: string, module: string, note: string, cases: VectorCase[], keys?: Record<string, unknown>, profile = 'wappie', randomness = RANDOMNESS) {
  const pkg = JSON.parse(readFileSync(new URL('../node_modules/@noble/hashes/package.json', import.meta.url), 'utf8'))
  const file = {
    format: 'thehappieco-kit-vectors/1', module, profile,
    generated_by: {
      lang: 'ts', source: `${source()} js/src`, toolchain: `node ${process.version}; @noble/hashes ${pkg.version}`,
      randomness, generator: 'js/test/cross.spec.ts',
    },
    note, ...(keys ? { keys } : {}), cases,
  }
  mkdirSync(OUT, { recursive: true })
  const fd = openSync(join(OUT, name), 'wx')
  try { writeSync(fd, JSON.stringify(file, null, 2) + '\n') } finally { closeSync(fd) }
}

const hkdf = async (ikm: Bytes, salt: Bytes, info: string) => {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: utf8(info) }, key, 256)) as Bytes
}

/**
 * writePlatformWrap writes kit/<product>-platform-wrap-ts.json: fresh
 * platform wraps under the profile p by the kit's TypeScript, for Go. Each
 * has a random binding (an account created through id., whose user id is
 * its sub, or a linked one; a random epoch), random product and account
 * keys (some with a first byte of zero), the nonce it drew, its info and
 * AAD (K_pw is a non-extractable key here, so it is not recorded: Go checks
 * it by the wrap); each is also opened with one thing changed, and, when
 * other is given, under other's labels with the same key bytes and the key
 * id of other's product (the op of other's product). Then seals refused for
 * a key or a binding outside the rules; otherKeyIds are product key ids of
 * other products.
 */
async function writePlatformWrap(p: PlatformWrapProfile, name: string, otherKeyIds: string[], other?: PlatformWrapProfile): Promise<void> {
  const cases: VectorCase[] = []
  const op = (q: PlatformWrapProfile, what: string) => `${q.product}.platform_wrap_${what}`
  const below = (n: number) => crypto.getRandomValues(new Uint32Array(1))[0] % n
  const bytes = (n: number) => crypto.getRandomValues(new Uint8Array(n)) as Bytes
  const epoch = () => (below(2) === 0 ? 1 + below(3) : 1 + below(2 ** 31 - 1))
  const refused = async (id: string, fn: () => Promise<unknown>) => {
    const err = await fn().then(() => null, (e: unknown) => e)
    if (!isPlatformWrapError(err)) expect.fail(`${id}: not refused`)
  }
  const bindingIn = (b: PlatformWrapBinding) => ({ user_id: b.userId, sub: b.sub, product_key_id: b.productKeyId, account_public_key_b64: toB64(b.accountPublicKey) })
  const newBinding = async (usk: Bytes): Promise<PlatformWrapBinding> => {
    const sub = crypto.randomUUID()
    return { userId: below(2) === 0 ? sub : crypto.randomUUID(), sub, productKeyId: `${p.product}:${epoch()}`, accountPublicKey: await publicFromPrivate(usk) }
  }

  // Fresh wraps, each with the nonce it drew, then opened with one thing
  // changed at a time.
  for (let n = 0; n < 32; n++) {
    const sk = bytes(32), usk = bytes(32)
    if (n % 8 === 0) sk[0] = 0
    if (n % 8 === 1) usk[0] = 0
    const b = await newBinding(usk)
    const id = `${p.product}/platform-wrap/${n}`
    const { value: wrap, bytes: drawn } = await recording(() => sealPlatformWrap(p, sk, usk, b))
    expect(drawn.map((d) => d.length), id).toEqual([12])
    expect(toB64(await openPlatformWrap(p, sk, wrap, b)), id).toBe(toB64(usk))
    const i = bindingIn(b)
    cases.push(
      { id: `${id}/info`, op: op(p, 'info'), in: i, out: { info_b64: toB64(platformWrapInfo(p, b)) } },
      { id: `${id}/aad`, op: op(p, 'aad'), in: i, out: { aad_b64: toB64(platformWrapAAD(p, b)) } },
      { id: `${id}/seal`, op: op(p, 'seal'), in: { ...i, product_key_b64: toB64(sk), account_key_b64: toB64(usk), nonce_b64: toB64(drawn[0]!) }, out: { wrap_b64: toB64(wrap) } },
      { id: `${id}/open`, op: op(p, 'open'), in: { ...i, product_key_b64: toB64(sk), wrap_b64: toB64(wrap) }, out: { account_key_b64: toB64(usk) } },
    )
    const openUnder = async (q: PlatformWrapProfile, what: string, key: Bytes, w: Uint8Array, bb: PlatformWrapBinding) => {
      await refused(`${id}/${what}`, () => openPlatformWrap(q, key, w, bb))
      cases.push({ id: `${id}/open/refuses/${what}`, op: op(q, 'open'), in: { ...bindingIn(bb), product_key_b64: toB64(key), wrap_b64: toB64(w) }, error: 'platform_wrap' })
    }
    const open = (what: string, key: Bytes, w: Uint8Array, bb: PlatformWrapBinding) => openUnder(p, what, key, w, bb)
    const flipped = new Uint8Array(wrap)
    const bit = 8 + below(flipped.length * 8 - 8)
    flipped[bit >> 3]! ^= 1 << (bit & 7)
    await open(`flipped-bit-${bit}`, sk, flipped, b)
    const header = new Uint8Array(wrap)
    header[0] = [0x00, 0x01, 0x02, 0x04, 0xff][below(5)]!
    await open(`header-0x${header[0]!.toString(16).padStart(2, '0')}`, sk, header, b)
    if (below(2) === 0) await open('length', sk, wrap.subarray(0, PLATFORM_WRAP_LEN - 1 - below(3)), b)
    else await open('length', sk, Uint8Array.of(...wrap, ...bytes(1 + below(3))), b)
    await open('other-product-key', bytes(32), wrap, b)
    await open('other-user-id', sk, wrap, { ...b, userId: crypto.randomUUID() })
    await open('other-sub', sk, wrap, { ...b, sub: crypto.randomUUID() })
    let otherEpoch = b.productKeyId
    while (otherEpoch === b.productKeyId) otherEpoch = `${p.product}:${epoch()}`
    await open('other-epoch', sk, wrap, { ...b, productKeyId: otherEpoch })
    await open('other-account-public-key', sk, wrap, { ...b, accountPublicKey: await publicFromPrivate(bytes(32)) })
    if (other !== undefined) {
      const productKeyId = `${other.product}:${b.productKeyId.slice(b.productKeyId.indexOf(':') + 1)}`
      await openUnder(other, `under-${other.product}s-labels`, sk, wrap, { ...b, productKeyId })
    }
  }

  // Seals refused before anything is encrypted.
  for (let n = 0; n < 16; n++) {
    let sk = bytes(32), usk = bytes(32)
    const b = await newBinding(usk)
    let how = ''
    switch (n % 8) {
      case 0: usk = bytes(32); how = 'account-key-not-the-public-keys'; break
      case 1: usk = usk.slice(0, 31) as Bytes; how = 'account-key-of-31-bytes'; break
      case 2: sk = Uint8Array.of(...sk, ...bytes(1)) as Bytes; how = 'product-key-of-33-bytes'; break
      case 3: b.userId = b.userId.toUpperCase(); how = 'user-id-in-upper-case'; break
      case 4: b.sub = `{${b.sub}}`; how = 'sub-in-braces'; break
      case 5: b.productKeyId = otherKeyIds[below(otherKeyIds.length)]!; how = 'another-products-key-id'; break
      case 6: b.productKeyId = [`${p.product}:0`, `${p.product}:01`, `${p.product}:2147483648`, p.product, `${p.product}:-1`][below(5)]!; how = 'epoch-out-of-range'; break
      default: b.accountPublicKey = b.accountPublicKey.slice(0, 31); how = 'account-public-key-of-31-bytes'
    }
    const id = `${p.product}/platform-wrap/seal/refuses/${n}/${how}`
    await refused(id, () => sealPlatformWrap(p, sk, usk, b))
    cases.push({ id, op: op(p, 'seal'), in: { ...bindingIn(b), product_key_b64: toB64(sk), account_key_b64: toB64(usk) }, error: 'platform_wrap' })
  }
  const crossNote = other === undefined ? '' : `, and under ${other.product}'s labels with the same key bytes and the key id of ${other.product}'s product (op ${op(other, 'open')})`
  write(`${p.product}-platform-wrap-ts.json`, `${p.product}.platform_wrap`, `Fresh platform wraps of the ${name} profile (SPEC section 6.8) by the kit's TypeScript, for Go: 32 random bindings (an account created through id., whose user id is its sub, or a linked one; a random epoch), random product and account keys, some with a first byte of zero, each wrap with the nonce it drew, its info and AAD (K_pw is a non-extractable key here, so it is not recorded), each also opened with one thing changed (a bit, the header, the length, the product key, the user id, the sub, the epoch, the account public key)${crossNote}; and 16 seals refused for a key or a binding outside the rules.`, cases, undefined, p.product)
}

describe.skipIf(!OUT)('fresh vectors for Go', () => {
  it('writes seal-ts.json and hpke-ts.json', async () => {
    const pair = await generateKeyPair()
    const keys = { archive: { private_key_b64: toB64(pair.privateKey), public_key_b64: toB64(pair.publicKey) } }
    const tenant = parseUUID(crypto.randomUUID()), device = parseUUID(crypto.randomUUID()), user = parseUUID(crypto.randomUUID())
    const cases: VectorCase[] = []
    for (const epoch of [0, 1, 65535]) {
      const row = await grantRow(tenant, device, user, epoch)
      const pt = crypto.getRandomValues(new Uint8Array(32)) as Bytes
      const { value: env, x25519 } = await recording(() => sealDirect(wappieSeal, pair.publicKey, Kind.DeviceGrant, tenant, row, epoch, pt))
      cases.push({ id: `seal/direct/grant/epoch-${epoch}`, op: 'seal.seal_direct',
        in: { key: 'archive', kind: Kind.DeviceGrant, tenant: formatUUID(tenant), row: formatUUID(row), epoch, plaintext_b64: toB64(pt), ephemeral_private_key_b64: toB64(x25519[0]) },
        out: { envelope_b64: toB64(env) } })
      cases.push({ id: `seal/grant-row/epoch-${epoch}`, op: 'seal.grant_row',
        in: { tenant: formatUUID(tenant), device: formatUUID(device), user: formatUUID(user), epoch }, out: { row: formatUUID(row) } })
      cases.push({ id: `seal/direct/grant/epoch-${epoch}/kind-swapped`, op: 'seal.open_direct',
        in: { key: 'archive', kind: Kind.ContentKey, tenant: formatUUID(tenant), row: formatUUID(row), envelope_b64: toB64(env) }, error: 'authentication' })
    }
    const draftPT = utf8(JSON.stringify({ v: 1, text: 'Combinado \u2014 at\u00e9 amanh\u00e3 \u{1f642}' }))
    const { value: draft, x25519 } = await recording(() => sealDirect(wappieSeal, pair.publicKey, Kind.McpDraft, tenant, device, 2, draftPT))
    expect(new TextDecoder().decode(await openDirect(wappieSeal, await importPrivateKey(pair.privateKey), Kind.McpDraft, tenant, device, draft))).toContain('Combinado')
    cases.push({ id: 'seal/direct/draft', op: 'seal.seal_direct',
      in: { key: 'archive', kind: Kind.McpDraft, tenant: formatUUID(tenant), row: formatUUID(device), epoch: 2, plaintext_b64: toB64(draftPT), ephemeral_private_key_b64: toB64(x25519[0]) },
      out: { envelope_b64: toB64(draft) } })
    for (const [name, point] of lowOrder) {
      const pt = new Uint8Array(32).fill(0x66) as Bytes
      const row = await grantRow(tenant, device, user, 1)
      expect(await codeOf(() => sealDirect(wappieSeal, hex(point), Kind.DeviceGrant, tenant, row, 1, pt))).toBe('invalid_key')
      cases.push({ id: `seal/direct/refuses/low-order-key/${name}`, op: 'seal.seal_direct',
        in: { public_key_b64: toB64(hex(point)), kind: Kind.DeviceGrant, tenant: formatUUID(tenant), row: formatUUID(row), epoch: 1, plaintext_b64: toB64(pt) }, error: 'invalid_key' })
    }
    write('seal-ts.json', 'seal', 'Fresh grants and a draft sealed by the kit\'s TypeScript with the Wappie profile, for Go to open, and low-order keys it refuses to seal to.', cases, keys)

    const hcases: VectorCase[] = []
    for (const [n, [info, aad, pt]] of ([[utf8(''), utf8(''), utf8('')], [utf8('thehappie-id/v1/key-delivery'), utf8(canonicalJSON(['thehappie-id/key-delivery', 1, 'sub'])), crypto.getRandomValues(new Uint8Array(32))],
      [crypto.getRandomValues(new Uint8Array(300)), crypto.getRandomValues(new Uint8Array(1000)), crypto.getRandomValues(new Uint8Array(5000))]] as Bytes[][]).entries()) {
      const { value, x25519: eph } = await recording(() => hpkeSeal(pair.publicKey, info, aad, pt))
      hcases.push({ id: `hpke/seal/${n}`, op: 'hpke.seal',
        in: { key: 'r1', info_b64: toB64(info), aad_b64: toB64(aad), plaintext_b64: toB64(pt), ephemeral_private_key_b64: toB64(eph[0]) },
        out: { enc_b64: toB64(value.enc), ciphertext_b64: toB64(value.ciphertext) } })
    }
    for (let n = 0; n < 3; n++) {
      const priv = crypto.getRandomValues(new Uint8Array(32)) as Bytes
      hcases.push({ id: `hpke/public-from-private/${n}`, op: 'hpke.public_from_private', in: { private_key_b64: toB64(priv) }, out: { public_key_b64: toB64(await publicFromPrivate(priv)) } })
    }
    for (const [name, point] of lowOrder) {
      const [info, aad, pt] = [utf8('thehappie-id/v1/key-delivery'), utf8('["thehappie-id/key-delivery",1]'), new Uint8Array(32).fill(0x66) as Bytes]
      expect(await codeOf(() => hpkeSeal(hex(point), info, aad, pt))).toBe('invalid_key')
      hcases.push({ id: `hpke/seal/refuses/low-order-key/${name}`, op: 'hpke.seal',
        in: { public_key_b64: toB64(hex(point)), info_b64: toB64(info), aad_b64: toB64(aad), plaintext_b64: toB64(pt) }, error: 'invalid_key' })
    }
    write('hpke-ts.json', 'hpke', 'Fresh HPKE seals by the kit\'s WebCrypto implementation, for Go\'s crypto/hpke to open, and low-order keys it refuses to seal to.', hcases, { r1: keys.archive })
  })

  it('writes account-ts.json and passkey-ts.json', async () => {
    const p = wappieAccount
    const params = { alg: 'argon2id', m: 16, t: 2, p: 1 }
    const salt = crypto.getRandomValues(new Uint8Array(16)) as Bytes
    const cases: VectorCase[] = []
    let wrapRaw: Bytes | undefined, wrapKey: CryptoKey | undefined
    for (const [n, pw] of ['senha do kit', '', 'p\u00e4ssw\u00f6rd \u{1f511}', '\u00e7'.repeat(300)].entries()) {
      const d = await derive(p, pw, salt, params)
      const master = argon2id(utf8(pw), salt, { m: params.m, t: params.t, p: params.p, dkLen: 32 }) as Bytes
      const auth = await hkdf(master, new Uint8Array(0) as Bytes, p.authLabel)
      const wrap = await hkdf(master, new Uint8Array(0) as Bytes, p.wrapLabel)
      expect(toB64(auth)).toBe(d.authKey)
      if (n === 0) { wrapRaw = wrap; wrapKey = d.wrapKey }
      cases.push({ id: `account/derive/${n}`, op: 'account.derive', in: { password: pw, salt_b64: toB64(salt), params }, out: { auth_key: d.authKey, auth_b64: toB64(auth), wrap_b64: toB64(wrap) } })
    }
    const key = crypto.getRandomValues(new Uint8Array(32)) as Bytes
    for (const [n, email] of ['ana@example.com', ' \u0130stanbul@EXAMPLE.com\ufeff', '\u039f\u0394\u03a5\u03a3\u03a3\u0395\u03a5\u03a3@x.gr'].entries()) {
      const aad = accountWrapAAD(email)
      const { value: blob, bytes } = await recording(() => wrapPrivateKey(p, key, wrapKey!, aad))
      expect((await unwrapPrivateKey(p, blob, wrapKey!, aad)).stale).toBe(false)
      cases.push({ id: `account/wrap-aad/${n}`, op: 'account.wrap_aad', in: { email }, out: { aad_b64: toB64(aad) } })
      cases.push({ id: `account/wrap/${n}`, op: 'account.wrap', in: { wrap_key_b64: toB64(wrapRaw!), private_key_b64: toB64(key), email, nonce_b64: toB64(bytes[0]) }, out: { blob_b64: toB64(blob) } })
      cases.push({ id: `account/unwrap/${n}/other-email`, op: 'account.unwrap', in: { wrap_key_b64: toB64(wrapRaw!), blob_b64: toB64(blob), email: 'bob@example.com' }, error: 'wrap', reason: 'wrong_key' })
    }
    for (let n = 0; n < 2; n++) {
      const code = newRecoveryCode()
      const typed = code.toLowerCase().replace(/-/g, ' ')
      cases.push({ id: `account/normalise/${n}`, op: 'account.normalise_recovery_code', in: { code: typed }, out: { code: normaliseRecoveryCode(typed) } })
      cases.push({ id: `account/recovery-proof/${n}`, op: 'account.recovery_proof', in: { code: typed }, out: { proof: await recoveryProof(p, typed) } })
      cases.push({ id: `account/recovery-key/${n}`, op: 'account.recovery_key', in: { code }, out: { key_b64: toB64(await hkdf(utf8(code), new Uint8Array(0) as Bytes, p.recoveryKeyLabel)) } })
    }
    // The Wappie profile has no bounds; these cases give it some, shaped like
    // the platform's policy (a salt of exactly 16 bytes), to pin the checks.
    const jsonBounds = { min: { m: 8, t: 1, p: 1 }, max: { m: 1024, t: 3, p: 1 }, max_cost: 2048, min_salt_len: 16, max_salt_len: 16 }
    const bounded: AccountProfile = { ...p, bounds: { min: jsonBounds.min, max: jsonBounds.max, maxCost: 2048, minSaltLen: 16, maxSaltLen: 16 } }
    for (const [name, len, kdf] of [['salt-16', 16, params], ['refuses/salt-15', 15, params], ['refuses/salt-17', 17, params], ['refuses/salt-8', 8, params],
      ['refuses/m-2048', 16, { alg: 'argon2id', m: 2048, t: 1, p: 1 }], ['refuses/cost-3072', 16, { alg: 'argon2id', m: 1024, t: 3, p: 1 }]] as [string, number, KDFParams][]) {
      const s = crypto.getRandomValues(new Uint8Array(len)) as Bytes
      const c: VectorCase = { id: `account/derive/bounded/${name}`, op: 'account.derive', in: { password: 'senha do kit', salt_b64: toB64(s), params: kdf, bounds: jsonBounds } }
      if (name.startsWith('refuses/')) {
        expect(await codeOf(() => derive(bounded, 'senha do kit', s, kdf))).toBe('kdf')
        Object.assign(c, { error: 'kdf', reason: 'out_of_bounds' })
      } else {
        const d = await derive(bounded, 'senha do kit', s, kdf)
        const master = argon2id(utf8('senha do kit'), s, { m: kdf.m, t: kdf.t, p: kdf.p, dkLen: 32 }) as Bytes
        c.out = { auth_key: d.authKey, auth_b64: toB64(await hkdf(master, new Uint8Array(0) as Bytes, p.authLabel)), wrap_b64: toB64(await hkdf(master, new Uint8Array(0) as Bytes, p.wrapLabel)) }
      }
      cases.push(c)
    }
    write('account-ts.json', 'account', 'Fresh derivations and wraps by the kit\'s TypeScript account scheme with the Wappie profile, and derivations refused by KDF and salt bounds, for Go.', cases)

    const pk = wappiePasskey
    const pcases: VectorCase[] = []
    const prf = crypto.getRandomValues(new Uint8Array(32)) as Bytes
    for (const [n, rp] of ['wappie.thehappie.co', 'localhost'].entries()) {
      const binding = { rpID: rp, userID: crypto.randomUUID(), credentialID: `Y3JlZGVudGlhbC${n}` }
      const aad = passkeyAAD(binding)
      const { value: env, bytes } = await recording(() => wrapPasskey(pk, key, prf, rp, aad))
      const k = await hkdf(prf, utf8(rp), pk.wrapInfo)
      const ids = { rp_id: rp, user_id: binding.userID, credential_id: binding.credentialID }
      pcases.push({ id: `passkey/prf-salt/${n}`, op: 'passkey.prf_salt', in: { rp_id: rp }, out: { salt_b64: toB64(await prfSalt(pk, rp)) } })
      pcases.push({ id: `passkey/aad/${n}`, op: 'passkey.aad', in: ids, out: { aad_b64: toB64(aad) } })
      pcases.push({ id: `passkey/key/${n}`, op: 'passkey.key', in: { prf_b64: toB64(prf), ...ids }, out: { key_b64: toB64(k) } })
      pcases.push({ id: `passkey/wrap/${n}`, op: 'passkey.wrap', in: { private_key_b64: toB64(key), prf_b64: toB64(prf), ...ids, nonce_b64: toB64(bytes[0]) }, out: { envelope_b64: toB64(env) } })
      pcases.push({ id: `passkey/unwrap/${n}/other-user`, op: 'passkey.unwrap', in: { envelope_b64: toB64(env), prf_b64: toB64(prf), ...ids, user_id: 'someone-else' }, error: 'open_failed' })
    }
    // Bindings with no JSON text (a lone surrogate, carried as WTF-8), and a
    // wrap bound to nothing: refused.
    for (const [name, field, value] of [['lone-high-surrogate-user', 'user_id', 'user-\ud800'], ['lone-low-surrogate-credential', 'credential_id', '\udc00cred']]) {
      const b = { rpID: 'wappie.thehappie.co', userID: field === 'user_id' ? value : 'u', credentialID: field === 'credential_id' ? value : 'c' }
      expect(() => passkeyAAD(b)).toThrow(CanonicalJSONError)
      const ids: Record<string, string> = { rp_id: b.rpID, user_id: b.userID, credential_id: b.credentialID }
      delete ids[field]
      pcases.push({ id: `passkey/aad/refuses/${name}`, op: 'passkey.aad', in: { ...ids, [`${field}_wtf8_b64`]: toB64(toWTF8(value)) }, error: 'jcs' })
    }
    const env = await wrapPasskey(pk, key, prf, 'localhost', utf8('aad'))
    expect(await codeOf(() => wrapPasskey(pk, key, prf, 'localhost', new Uint8Array(0) as Bytes))).toBe('bad_aad')
    expect(await codeOf(() => unwrapPasskey(pk, env, prf, 'localhost', new Uint8Array(0) as Bytes))).toBe('bad_aad')
    pcases.push({ id: 'passkey/wrap/refuses/empty-aad', op: 'passkey.wrap', in: { private_key_b64: toB64(key), prf_b64: toB64(prf), rp_id: 'localhost', aad_b64: '', nonce_b64: toB64(new Uint8Array(12)) }, error: 'bad_aad' })
    pcases.push({ id: 'passkey/unwrap/refuses/empty-aad', op: 'passkey.unwrap', in: { envelope_b64: toB64(env), prf_b64: toB64(prf), rp_id: 'localhost', aad_b64: '' }, error: 'bad_aad' })
    write('passkey-ts.json', 'passkey', 'Fresh passkey wraps by the kit\'s TypeScript with the Wappie profile, for Go, with bindings that must be refused.', pcases)
  })

  it('writes reqhmac-ts.json and jcs-ts.json', async () => {
    const s = wappieMCPHMAC
    const cases: VectorCase[] = []
    for (const [n, [secret, method, target]] of [[crypto.randomUUID(), 'post', '/internal/requests/x/prepare'], ['segredo-\u00e7\u00e3o-\u{1f511}', 'GET', '/v1/x?y=%2F'], ['', 'DELETE', '/']].entries()) {
      const body = utf8(crypto.randomUUID())
      const nonce = String.fromCharCode(65 + n).repeat(22)
      cases.push({ id: `reqhmac/signature/${n}`, op: 'reqhmac.signature',
        in: { secret, direction: DIRECTION_TO_READER, sender: 'enclave', method, target, timestamp: '1790300000', nonce, body_b64: toB64(body) },
        out: { signature: await signature(s, secret, DIRECTION_TO_READER, 'enclave', method, target, '1790300000', nonce, body),
          canonical: await canonical(s, DIRECTION_TO_READER, 'enclave', method, target, '1790300000', nonce, body) } })
    }
    write('reqhmac-ts.json', 'reqhmac', 'Signatures by the kit\'s TypeScript with Wappie\'s scheme, for Go.', cases)

    const jcases: VectorCase[] = []
    for (const [n, value] of [
      { z: [1, 'two', null, true], a: { '\u{1f600}': 1, '\ue000': 2, '<&>': '\u2028' } },
      ['wappie/passkey-vault', 1, 'wappie.thehappie.co', 'a"b\\c\u0001', '\u2028\u00e9'],
      { max: 9007199254740991, min: -9007199254740991, ctl: '\u0000\u001f\u007f' },
    ].entries()) {
      jcases.push({ id: `jcs/canonical/${n}`, op: 'jcs.canonical', in: { json: JSON.stringify(value) }, out: { jcs: canonicalJSON(value) } })
    }
    const ns = parseUUID(crypto.randomUUID())
    for (const [n, name] of [new Uint8Array(0), utf8('a\u00e7\u00e3o'), new Uint8Array(70).fill(9)].entries()) {
      jcases.push({ id: `bytes/uuid-v5/${n}`, op: 'bytes.uuid_v5', in: { namespace: formatUUID(ns), name_b64: toB64(name) }, out: { uuid: formatUUID(await uuidV5(ns, name as Bytes)) } })
    }
    write('jcs-ts.json', 'bytes+jcs', 'Canonical JSON and UUIDv5 by the kit\'s TypeScript, for Go. Each input is JSON.stringify of the value.', jcases)
  })

  it('writes platform-ts.json', async () => {
    const cases: VectorCase[] = []
    const below = (n: number) => crypto.getRandomValues(new Uint32Array(1))[0] % n
    const bytes = (n: number) => crypto.getRandomValues(new Uint8Array(n)) as Bytes
    const ch = (...cps: number[]) => String.fromCodePoint(...cps)
    // Code points assigned long before Unicode 15.0, whose normalisation is
    // the same in ICU and in Go's tables: the same blocks as the Go writer.
    const blocks: [number, number][] = [
      [0x61, 0x7a], [0x41, 0x5a], [0x30, 0x39], [0x20, 0x7e], [0xc0, 0xff], [0x100, 0x17f], [0x300, 0x34e], [0x391, 0x3c9],
      [0x410, 0x44f], [0x905, 0x939], [0x93e, 0x94c], [0x1100, 0x1112], [0x1161, 0x1175], [0x11a8, 0x11c2], [0xac00, 0xd7a3],
      [0x4e00, 0x9fa5], [0x2000, 0x200a], [0xa0, 0xa0], [0x3000, 0x3000], [0x1f600, 0x1f64f],
    ]
    const randomPassword = () => {
      let s = ''
      for (let n = 12 + below(30); n > 0; n--) {
        const [lo, hi] = blocks[below(blocks.length)]
        s += ch(lo + below(hi - lo + 1))
      }
      return s
    }
    const names = ['password_invalid', 'password_too_short', 'password_too_long', 'kdf_policy', 'wrap', 'recovery_code', 'email', 'product_key', 'bundle', 'encoding']
    const code = async (fn: () => unknown) => {
      const c = await codeOf(fn)
      if (!names.includes(c)) throw new Error(`a refusal outside the protocol's names: ${c}`)
      return c
    }
    const empty = new Uint8Array(0) as Bytes

    // The password profile.
    const inputs: [string, boolean][] = [
      ['a' + ch(0x301) + ch(0x323).repeat(29) + 'bcdefghijk', true],
      ['a' + ch(0x301).repeat(31), false],
      [ch(0x1100, 0x1161, 0x11a8) + ' ' + ch(0x212b) + 'ngstr' + ch(0xf6) + 'm' + ch(0xa0, 0x3000), false],
      ['short', true],
      ['pass' + ch(0x85) + 'word-1234', false],
    ]
    for (let i = 0; i < 12; i++) inputs.push([randomPassword(), below(2) === 1])
    for (const [n, [password, isNew]] of inputs.entries()) {
      const c: VectorCase = { id: `platform/prepare-password/${n}`, op: 'platform.prepare_password', in: { password, new: isNew } }
      try {
        c.out = { prepared_b64: toB64(platform.preparePassword(password, { isNew })) }
      } catch {
        c.error = await code(() => platform.preparePassword(password, { isNew }))
      }
      cases.push(c)
    }

    // The KDF at the floor, its wrap key computed beside the kit's.
    {
      const prepared = platform.preparePassword(randomPassword(), { isNew: true })
      const salt = bytes(16)
      const d = await platform.derivePassword(prepared, salt, platform.DEFAULT_KDF)
      const master = argon2id(prepared, salt, { m: 65536, t: 3, p: 1, dkLen: 32 }) as Bytes
      expect(toBase64URL(await hkdf(master, empty, platform.LABEL_PASSWORD_AUTH))).toBe(d.authKey)
      cases.push({ id: 'platform/derive-password/0', op: 'platform.derive_password', in: { prepared_b64: toB64(prepared), salt_b64: toB64(salt), kdf: platform.DEFAULT_KDF },
        out: { auth_key: d.authKey, wrap_b64: toB64(await hkdf(master, empty, platform.LABEL_PASSWORD_WRAP)) } })
      cases.push({ id: 'platform/derive-password/refuses/fractional-m', op: 'platform.derive_password',
        in: { prepared_b64: toB64(prepared), salt_b64: toB64(salt), kdf: { alg: 'argon2id', m: 65536.5, t: 3, p: 1 } }, error: 'kdf_policy', langs: ['ts'] })
    }

    // Root wraps of each kind, with the nonce they drew.
    for (const kind of ['password', 'recovery', 'passkey'] as platform.WrapKind[]) {
      const sub = crypto.randomUUID()
      const epoch = 1 + below(2 ** 31 - 1)
      const passkey = kind === 'passkey' ? { rpId: 'id.thehappie.co', credentialId: toBase64URL(bytes(16)) } : undefined
      const key = bytes(32), root = bytes(32)
      const { value: wrap, bytes: drawn } = await recording(() => platform.sealRootWrap(kind, key, root, sub, epoch, passkey))
      const extra = passkey ? { rp_id: passkey.rpId, credential_id: passkey.credentialId } : {}
      cases.push({ id: `platform/root-wrap/${kind}`, op: 'platform.root_wrap', in: { kind, key_b64: toB64(key), root_b64: toB64(root), sub, epoch, nonce_b64: toB64(drawn[0]), ...extra },
        out: { aad: platform.rootWrapAAD(kind, sub, epoch, passkey), wrap_b64: toB64(wrap) } })
      cases.push({ id: `platform/root-wrap/${kind}/other-epoch`, op: 'platform.open_root_wrap', in: { kind, key_b64: toB64(key), sub, epoch: epoch === 1 ? 2 : epoch - 1, wrap_b64: toB64(wrap), ...extra }, error: 'wrap' })
    }

    // Recovery codes.
    for (let n = 0; n < 2; n++) {
      const raw = bytes(30)
      const rc = platform.recoveryCodeFromBytes(raw)
      const keys = await platform.deriveRecovery(rc.display)
      cases.push({ id: `platform/recovery-code/${n}`, op: 'platform.recovery_code', in: { random_b64: toB64(raw), typed: rc.display.toLowerCase().replace(/-/g, ' ') },
        out: { canonical: rc.canonical, display: rc.display, wrap_b64: toB64(await hkdf(utf8(rc.canonical), empty, platform.LABEL_RECOVERY_WRAP)), recovery_auth: keys.recoveryAuth } })
    }
    cases.push({ id: 'platform/recovery-code/refuses/dotless-i', op: 'platform.recovery_code', in: { typed: ch(0x131) + '0'.repeat(29) }, error: 'recovery_code' })

    // Product keys, verifiers and addresses.
    for (const [n, product] of ['mailie', 'a-future-product'].entries()) {
      const root = bytes(32), epoch = 1 + below(2 ** 31 - 1)
      const k = await platform.deriveProductKey(root, product, epoch)
      cases.push({ id: `platform/product-key/${n}`, op: 'platform.product_key', in: { root_b64: toB64(root), product, epoch }, out: { sk_b64: toB64(k.sk), pub_b64: toB64(k.pub), product_key_id: k.id } })
    }
    for (const [n, recovery] of [false, true].entries()) {
      const sub = crypto.randomUUID(), key = bytes(32)
      cases.push(recovery
        ? { id: `platform/verifier/${n}`, op: 'platform.verifier', in: { sub, r_proof_b64: toB64(key) }, out: { recovery_verifier_b64: toB64(await platform.recoveryVerifier(sub, key)) } }
        : { id: `platform/verifier/${n}`, op: 'platform.verifier', in: { sub, k_auth_b64: toB64(key) }, out: { auth_verifier_b64: toB64(await platform.authVerifier(sub, key)) } })
    }
    for (const [n, input] of ['\tBia+Kit@Mail.Example.ORG ', 'a@b.c0', 'a..b@example.com', 'ana@ex' + ch(0xe4) + 'mple.com'].entries()) {
      const c: VectorCase = { id: `platform/normalize-email/${n}`, op: 'platform.normalize_email', in: { input } }
      try {
        c.out = { email_norm: platform.normalizeEmail(input) }
      } catch {
        c.error = await code(() => platform.normalizeEmail(input))
      }
      cases.push(c)
    }

    // A key bundle, written as JSON.stringify writes it, opened with the
    // password and with the recovery code.
    {
      const root = platform.newRoot(), salt = bytes(16), sub = crypto.randomUUID(), password = randomPassword()
      const d = await platform.derivePasswordKeys(password, salt, platform.DEFAULT_KDF)
      const rc = platform.newRecoveryCode()
      const rk = await platform.deriveRecovery(rc.canonical)
      const b64url = toBase64URL
      const bundle = {
        format: platform.KEY_BUNDLE_FORMAT, version: platform.KEY_BUNDLE_VERSION, issuer: 'https://id.thehappie.co', sub, email: 'ana@example.com',
        account_key_epoch: 1, kdf: platform.DEFAULT_KDF, kdf_salt: b64url(salt),
        password_wrap: b64url(await platform.sealRootWrap('password', d.wrapKey, root, sub, 1)),
        recovery_wrap: b64url(await platform.sealRootWrap('recovery', rk.wrapKey, root, sub, 1)),
        product_keys: [
          { product: 'mailie', epoch: 1, pub: b64url(await platform.productPublicKey(root, 'mailie', 1)) },
          { product: 'wappie', epoch: 1, pub: b64url(await platform.productPublicKey(root, 'wappie', 1)) },
        ],
        created_at: new Date().toISOString(),
      }
      const text = JSON.stringify(bundle, null, 2) + '\n'
      expect(toB64(await platform.openKeyBundleWithRecoveryCode(text, rc.display))).toBe(toB64(root))
      cases.push({ id: 'platform/key-bundle/password', op: 'platform.key_bundle', in: { bundle_text: text, password }, out: { root_b64: toB64(root) } })
      cases.push({ id: 'platform/key-bundle/recovery-code', op: 'platform.key_bundle', in: { bundle_text: text, recovery_code: rc.display }, out: { root_b64: toB64(root) } })
      cases.push({ id: 'platform/key-bundle/repeated-member', op: 'platform.key_bundle',
        in: { bundle_text: text.replace('"issuer":', '"issuer": "https://other.example",\n  "issuer":'), recovery_code: rc.display }, error: 'bundle' })
    }
    write('platform-ts.json', 'platform', 'Fresh cases of the platform profile (SPEC section 11) by the kit\'s TypeScript, for Go: random passwords from blocks whose normalisation is stable since Unicode 15.0, a derivation, root wraps with the nonce they drew, recovery codes with the bytes they came from, product keys, verifiers, addresses and a key bundle written by JSON.stringify.', cases, undefined, 'platform')
  })

  // Fresh cases of part 2 (SPEC sections 11.12 and 11.13): the same kinds
  // as internal/cross/platform_delivery_test.go writes. A fresh seal's
  // ephemeral key comes from the engine, so deliveries are checked by
  // opening. Each case's outcome is first checked here.
  it('writes platform-delivery-ts.json', async () => {
    const cases: VectorCase[] = []
    const below = (n: number) => crypto.getRandomValues(new Uint32Array(1))[0] % n
    const bytes = (n: number) => crypto.getRandomValues(new Uint8Array(n)) as Bytes
    const pickOf = <T>(from: T[]) => from[below(from.length)]
    const AAD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/|@-'
    const NONCE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-'
    const VERIFIER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'
    const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
    const from = (alphabet: string, n: number) => Array.from({ length: n }, () => alphabet[below(alphabet.length)]).join('')
    const text = (known: string[]) => (below(2) === 0 ? pickOf(known) : from(AAD, 1 + below(60)))
    const product = () => [() => 'wappie', () => 'mailie', () => from('abcdefghijklmnopqrstuvwxyz', 1) + from('abcdefghijklmnopqrstuvwxyz0123456789-', below(32))][below(3)]()
    const epoch = () => (below(2) === 0 ? 1 + below(3) : 1 + below(2 ** 31 - 1))
    const verifier = () => from(VERIFIER, 43 + below(86))
    const request = async (): Promise<platform.KeyDeliveryRequest> => ({
      issuer: text(['https://id.thehappie.co', 'http://id.thehappie.localhost:8290']),
      clientId: text(['wappie-app', 'mailie-app', 'mailie-console', 'fakeproduct']),
      redirectUri: text(['https://app.wappie.thehappie.co/auth/callback', 'http://fakeproduct.thehappie.localhost:8292/auth/callback']),
      sub: crypto.randomUUID(),
      codeChallenge: await platform.pkceChallenge(verifier()),
      nonce: from(NONCE, 22 + below(107)),
    })
    const bindingIn = (b: platform.KeyDeliveryBinding) => ({
      iss: b.issuer, client_id: b.clientId, redirect_uri: b.redirectUri, sub: b.sub,
      product_key_id: b.productKeyId, pk_p_b64: toB64(b.productKey), code_challenge: b.codeChallenge, nonce: b.nonce,
    })
    const expectCode = async (id: string, fn: () => unknown, want: string) => expect(await codeOf(fn), id).toBe(want)
    const outside = [' ', '?', '#', '"', '\\', '%', '+', ',', '~', '\u00e9', '\u2028', '\t']
    const insert = (s: string) => {
      const at = below(s.length + 1)
      return s.slice(0, at) + pickOf(outside) + s.slice(at)
    }
    const breakBinding = (b: platform.KeyDeliveryBinding): [platform.KeyDeliveryBinding, string] => {
      const o = { ...b, productKey: b.productKey.slice() }
      const [prod, ep] = o.productKeyId.split(':')
      switch (below(8)) {
        case 0: o.issuer = below(2) === 0 ? '' : insert(o.issuer); return [o, 'iss']
        case 1: o.clientId = below(2) === 0 ? '' : insert(o.clientId); return [o, 'client_id']
        case 2: o.redirectUri = below(2) === 0 ? '' : insert(o.redirectUri); return [o, 'redirect_uri']
        case 3:
          o.sub = pickOf([o.sub.slice(0, 9).toUpperCase() + 'A' + o.sub.slice(10), o.sub.replace(/-/g, ''), `{${o.sub}}`])
          return [o, 'sub']
        case 4:
          o.productKeyId = pickOf([`${prod}:0${ep}`, `${prod}:0`, prod, `${prod}:`, `${prod}:+${ep}`, `${prod}:2147483648`, `${prod[0].toUpperCase()}${prod.slice(1)}:${ep}`,
            `${prod}:${ep}:${ep}`, `${prod}|${ep}`, `${prod}:${ep} `])
          return [o, 'product_key_id']
        case 5: o.productKey = below(2) === 0 ? o.productKey.slice(0, 31) : new Uint8Array([...o.productKey, 0]); return [o, 'pk_p']
        case 6: {
          const c = o.codeChallenge
          const at = B64URL.indexOf(c[42])
          o.codeChallenge = pickOf([c.slice(0, 42), `${c}A`, `${c}=`, c.slice(0, 42) + B64URL[at | 3], `${c.slice(0, 20)}+${c.slice(21)}`])
          return [o, 'code_challenge']
        }
        default:
          o.nonce = pickOf([from(NONCE, 21), from(NONCE, 129), insert(o.nonce.slice(1))])
          return [o, 'nonce']
      }
    }
    const otherBinding = async (b: platform.KeyDeliveryBinding): Promise<[platform.KeyDeliveryBinding, string]> => {
      const o = { ...b }
      const r = await request()
      const [prod, ep] = o.productKeyId.split(':')
      switch (below(8)) {
        case 0: o.issuer += '/'; return [o, 'iss']
        case 1: o.clientId += '-2'; return [o, 'client_id']
        case 2: o.redirectUri += '/'; return [o, 'redirect_uri']
        case 3: o.sub = r.sub; return [o, 'sub']
        case 4: o.productKeyId = `${prod}:${ep === '1' ? 2 : 1}`; return [o, 'product_key_id']
        case 5: o.productKey = bytes(32); return [o, 'pk_p']
        case 6: o.codeChallenge = r.codeChallenge; return [o, 'code_challenge']
        default: o.nonce = r.nonce; return [o, 'nonce']
      }
    }

    // The AAD, of valid bindings and of bindings with one field broken.
    for (let n = 0; n < 200; n++) {
      let b: platform.KeyDeliveryBinding = { ...(await request()), productKeyId: `${product()}:${epoch()}`, productKey: bytes(32) }
      let id = `platform/key-delivery-aad/${n}`
      if (n % 2 === 1) {
        let field: string
        ;[b, field] = breakBinding(b)
        id += `/refuses/${field}`
        await expectCode(id, () => platform.keyDeliveryAAD(b), 'key_delivery')
        cases.push({ id, op: 'platform.key_delivery_aad', in: bindingIn(b), error: 'key_delivery' })
      } else {
        cases.push({ id, op: 'platform.key_delivery_aad', in: bindingIn(b), out: { aad: platform.keyDeliveryAAD(b) } })
      }
    }

    // Fresh deliveries, each also opened in another flow, by another
    // recipient and with a flipped bit; for a few, what a sealer outside the
    // rules can make: enc spelled with bit 255 set (WebCrypto's export of the
    // ephemeral public key respelled), and another key under the binding.
    for (let n = 0; n < 24; n++) {
      const akd = await platform.generateX25519KeyPair()
      const root = bytes(32), prod = product(), ep = epoch()
      const k = await platform.deriveProductKey(root, prod, ep)
      const r = await request()
      const b: platform.KeyDeliveryBinding = { ...r, productKeyId: k.id, productKey: k.pub }
      const sealed = fromB64URL(await platform.sealProductKey({ root, product: prod, epoch: ep, akdPub: toBase64URL(akd.publicKey), binding: r }))
      const id = `platform/open-product-key/${n}`
      expect(toB64(await platform.openProductKey(akd.privateKey, sealed, b)), id).toBe(toB64(k.sk))
      const base = { ...bindingIn(b), akd_priv_b64: toB64(akd.privateKey), akd_sealed_b64: toB64(sealed) }
      cases.push({ id, op: 'platform.open_product_key', in: base, out: { sk_b64: toB64(k.sk) } })

      const [other, field] = await otherBinding(b)
      await expectCode(`${id}/other-${field}`, () => platform.openProductKey(akd.privateKey, sealed, other), 'key_delivery')
      cases.push({ id: `${id}/refuses/other-${field}`, op: 'platform.open_product_key', in: { ...bindingIn(other), akd_priv_b64: toB64(akd.privateKey), akd_sealed_b64: toB64(sealed) }, error: 'key_delivery' })

      const stranger = bytes(32)
      await expectCode(`${id}/other-recipient`, () => platform.openProductKey(stranger, sealed, b), 'key_delivery')
      cases.push({ id: `${id}/refuses/other-recipient`, op: 'platform.open_product_key', in: { ...base, akd_priv_b64: toB64(stranger) }, error: 'key_delivery' })

      const flipped = sealed.slice()
      const bit = below(flipped.length * 8)
      flipped[bit >> 3] ^= 1 << (bit & 7)
      await expectCode(`${id}/flipped-bit`, () => platform.openProductKey(akd.privateKey, flipped, b), 'key_delivery')
      cases.push({ id: `${id}/refuses/flipped-bit-${bit}`, op: 'platform.open_product_key', in: { ...base, akd_sealed_b64: toB64(flipped) }, error: 'key_delivery' })

      if (n >= 4) continue
      const info = utf8(platform.KEY_DELIVERY_INFO)
      const aad = utf8(platform.keyDeliveryAAD(b))
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
        aliased = await sealBase(akd.publicKey, info, aad, k.sk)
      } finally {
        spy.mockRestore()
      }
      expect(aliased[31] & 0x80).toBe(0x80)
      await expectCode(`${id}/aliased-enc`, () => platform.openProductKey(akd.privateKey, aliased, b), 'key_delivery')
      cases.push({ id: `${id}/refuses/aliased-enc`, op: 'platform.open_product_key', in: { ...base, akd_sealed_b64: toB64(aliased) }, error: 'key_delivery' })

      const wrong = await platform.deriveProductKey(bytes(32), prod, ep)
      const { enc, ciphertext } = await hpkeSeal(akd.publicKey, info, aad, wrong.sk)
      const wrongSealed = new Uint8Array([...enc, ...ciphertext]) as Bytes
      await expectCode(`${id}/another-key`, () => platform.openProductKey(akd.privateKey, wrongSealed, b), 'product_key')
      cases.push({ id: `${id}/refuses/another-key`, op: 'platform.open_product_key', in: { ...base, akd_sealed_b64: toB64(wrongSealed) }, error: 'product_key' })
    }

    // The seal's refusals of akd_pub: every low-order encoding, and a valid
    // key spelled with bit 255 set.
    const high = (await platform.generateX25519KeyPair()).publicKey
    high[31] |= 0x80
    for (const [name, pub] of [['bit-255', high], ...lowOrder.map(([n, h]) => [n, hex(h)] as [string, Bytes])] as [string, Bytes][]) {
      const root = bytes(32), prod = product(), ep = epoch()
      const r = await request()
      const id = `platform/seal-product-key/refuses/${name}`
      await expectCode(id, () => platform.sealProductKey({ root, product: prod, epoch: ep, akdPub: toBase64URL(pub), binding: r }), 'key_delivery')
      cases.push({ id, op: 'platform.seal_product_key', in: {
        root_b64: toB64(root), product: prod, epoch: ep, akd_pub_b64: toB64(pub),
        iss: r.issuer, client_id: r.clientId, redirect_uri: r.redirectUri, sub: r.sub, code_challenge: r.codeChallenge, nonce: r.nonce,
      }, error: 'key_delivery' })
    }

    // PKCE: verifiers of every length the RFC allows, and malformed ones.
    for (let n = 0; n < 64; n++) {
      const v = verifier()
      cases.push({ id: `platform/pkce-challenge/${n}`, op: 'platform.pkce_challenge', in: { code_verifier: v }, out: { code_challenge: await platform.pkceChallenge(v) } })
    }
    for (let n = 0; n < 32; n++) {
      let v = verifier()
      switch (below(3)) {
        case 0: v = from(VERIFIER, below(43)); break
        case 1: v = from(VERIFIER, 129 + below(64)); break
        default: {
          const at = below(v.length)
          v = v.slice(0, at) + pickOf(['+', '/', '=', ' ', '%7E', '\u00e9', '\uff21', '\n', '\u0000', '!', '*']) + v.slice(at + 1)
        }
      }
      await expectCode(`pkce ${n}`, () => platform.pkceChallenge(v), 'pkce')
      cases.push({ id: `platform/pkce-challenge/refuses/${n}`, op: 'platform.pkce_challenge', in: { code_verifier: v }, error: 'pkce' })
    }
    write('platform-delivery-ts.json', 'platform', 'Fresh cases of the platform profile\'s part 2 (SPEC sections 11.12 and 11.13) by the kit\'s TypeScript, for Go: key-delivery AADs of random bindings, half with one field broken; fresh deliveries sealed by sealProductKey, each also opened in another flow, by another recipient and with a flipped bit, and a few blobs a sealer outside the rules can make (enc spelled with bit 255 set, which RFC 9180 opens; another key under the binding, which opens and is product_key); the seal\'s refusals of low-order and non-canonical akd_pub; and PKCE verifiers of every length, and malformed ones. A fresh seal\'s ephemeral key comes from the engine, so deliveries are checked by opening.', cases, undefined, 'platform',
      'crypto.getRandomValues and WebCrypto X25519; nothing drawn is recorded, so seals are checked by opening')
  })

  it('writes wappie-platform-wrap-ts.json', async () => {
    await writePlatformWrap(wappiePlatformWrap, 'Wappie', ['mailie:1', 'vaultie:2', 'platform:1'])
  })

  it('writes mailie-platform-wrap-ts.json', async () => {
    await writePlatformWrap(mailiePlatformWrap, 'Mailie', ['wappie:1', 'vaultie:2', 'platform:1'], wappiePlatformWrap)
  })

  it('writes platform-passkey-ts.json', async () => {
    const cases: VectorCase[] = []
    const below = (n: number) => crypto.getRandomValues(new Uint32Array(1))[0] % n
    const bytes = (n: number) => crypto.getRandomValues(new Uint8Array(n)) as Bytes
    const pickOf = <T>(from: T[]) => from[below(from.length)]
    const from = (alphabet: string, n: number) => Array.from({ length: n }, () => alphabet[below(alphabet.length)]).join('')
    const epoch = () => (below(2) === 0 ? 1 + below(3) : 1 + below(2 ** 31 - 1))
    const expectCode = async (id: string, fn: () => unknown, want: string) => expect(await codeOf(fn), id).toBe(want)

    // Relying party ids in their one spelling (SPEC section 11.16), and
    // broken ones: the same generator as internal/cross/platform_passkey_test.go.
    const EDGE = 'abcdefghijklmnopqrstuvwxyz0123456789'
    const label = (n: number) => (n === 1 ? from(EDGE, 1) : from(EDGE, 1) + from(`${EDGE}-`, n - 2) + from(EDGE, 1))
    // None ends in a number (endsInANumber), which the spelling refuses since v0.5.0.
    const rpId = (): string => {
      switch (below(4)) {
        case 0: return pickOf(['id.thehappie.co', 'id.thehappie.localhost', 'localhost'])
        case 1:
          for (;;) {
            const s = `${label(63)}.${label(63)}.${label(63)}.${label(61)}`
            if (!endsInANumber(s)) return s
          }
      }
      for (;;) {
        const labels = Array.from({ length: 1 + below(4) }, () => label(below(8) === 0 ? 1 + below(63) : 1 + below(12)))
        const last = labels[labels.length - 1]
        if (/^[0-9]+$/.test(last)) labels[labels.length - 1] = `x${last.slice(1)}`
        const s = labels.join('.')
        if (s.length <= 253 && !endsInANumber(s)) return s
      }
    }
    const breakRPID = (rp: string): [string, string] => {
      const insert = (s: string, what: string) => {
        const at = below(s.length + 1)
        return s.slice(0, at) + what + s.slice(at)
      }
      for (;;) {
        let broken: string
        let how: string
        switch (below(17)) {
          case 0: [broken, how] = [insert(rp, pickOf(['A', 'Z', 'Q'])), 'upper-case']; break
          case 1: [broken, how] = [rp + pickOf([':443', ':8290', ':']), 'port']; break
          case 2: [broken, how] = [pickOf(['https://', 'http://', '//']) + rp, 'scheme']; break
          case 3: [broken, how] = [`${rp}.`, 'trailing-dot']; break
          case 4: [broken, how] = [`.${rp}`, 'leading-dot']; break
          case 5: [broken, how] = [insert(rp, '..'), 'empty-label']; break
          case 6: [broken, how] = [`-${rp}`, 'leading-dash']; break
          case 7: [broken, how] = [`${rp}-`, 'trailing-dash']; break
          case 8: [broken, how] = [`${label(64)}.${rp}`, 'label-64']; break
          case 9: [broken, how] = [`${label(63)}.${label(63)}.${label(63)}.${label(62)}`, 'length-254']; break
          case 10: [broken, how] = [`${below(256)}.${below(256)}.${below(256)}.${below(256)}`, 'ipv4']; break
          case 11: [broken, how] = [`${rp}.${from('0123456789', 1 + below(4))}`, 'digits']; break
          case 12: [broken, how] = [pickOf(['[::1]', '::1', '[2001:db8::1]']), 'ipv6']; break
          case 13: [broken, how] = [insert(rp, pickOf(['_', ' ', '/', '@', '|', '*', '\t', '\u0000'])), 'character']; break
          case 14: [broken, how] = [insert(rp, pickOf(['\u00e9', '\u0131', '\u0430', '\u00fc', '\u2028'])), 'non-ascii']; break
          case 15: [broken, how] = [`${rp}.0x${from('0123456789abcdef', below(9))}`, 'hex-number']; break
          default: [broken, how] = ['', 'empty']
        }
        if (!platform.isRPID(broken)) return [broken, how]
      }
    }
    const credentialId = () => {
      const sizes = [1, 16, 32, 64, 1023]
      const i = below(sizes.length + 1)
      return toBase64URL(bytes(i < sizes.length ? sizes[i] : 1 + below(1023)))
    }

    // The PRF salt of relying party ids, half of them broken.
    for (let n = 0; n < 200; n++) {
      let rp = rpId()
      let id = `platform/prf-salt/${n}`
      if (n % 2 === 1) {
        let how: string
        ;[rp, how] = breakRPID(rp)
        id += `/refuses/${how}`
        await expectCode(id, () => platform.prfSalt(rp), 'wrap')
        cases.push({ id, op: 'platform.prf_salt', in: { rp_id: rp }, error: 'wrap' })
      } else {
        cases.push({ id, op: 'platform.prf_salt', in: { rp_id: rp }, out: { prf_salt_b64: toB64(await platform.prfSalt(rp)) } })
      }
    }

    // Fresh passkey wraps, each with the nonce it drew, then opened with one
    // thing changed at a time. K_pk is non-extractable here, so it is not
    // recorded: Go checks it by the wrap.
    for (let n = 0; n < 32; n++) {
      const prf = bytes(32)
      const root = bytes(32)
      const b = { sub: crypto.randomUUID(), epoch: epoch(), rpId: rpId(), credentialId: credentialId() }
      const id = `platform/passkey-wrap/${n}`
      const { value: wrap, bytes: drawn } = await recording(() => platform.wrapRootWithPasskey({ root, prf, ...b }))
      expect(drawn.map((d) => d.length), id).toEqual([12])
      const opened = await platform.unwrapRootWithPasskey({ prf, wrap, ...b }, async (r) => toB64(r))
      expect(opened, id).toBe(toB64(root))
      const w = fromB64URL(wrap)
      const aad = platform.rootWrapAAD('passkey', b.sub, b.epoch, { rpId: b.rpId, credentialId: b.credentialId })
      cases.push({ id, op: 'platform.passkey_wrap', in: {
        rp_id: b.rpId, prf_b64: toB64(prf), root_b64: toB64(root), sub: b.sub, epoch: b.epoch, credential_id: b.credentialId, nonce_b64: toB64(drawn[0]),
      }, out: { aad, wrap_b64: toB64(w) } })

      const refuse = async (what: string, prf: Bytes, wrap: Bytes, o: typeof b) => {
        await expectCode(`${id}/${what}`, () => platform.unwrapRootWithPasskey({ prf, wrap: toBase64URL(wrap), ...o }, async () => expect.fail(`${id}/${what}: opened`)), 'wrap')
        cases.push({ id: `${id}/refuses/${what}`, op: 'platform.open_passkey_wrap', in: {
          rp_id: o.rpId, prf_b64: toB64(prf), sub: o.sub, epoch: o.epoch, credential_id: o.credentialId, wrap_b64: toB64(wrap),
        }, error: 'wrap' })
      }
      const flipped = w.slice()
      const bit = below(flipped.length * 8)
      flipped[bit >> 3] ^= 1 << (bit & 7)
      await refuse(`flipped-bit-${bit}`, prf, flipped, b)
      const header = w.slice()
      if (below(2) === 0) header[0] = 2 + below(254)
      else header[1] = pickOf([0x00, 0x01, 0x02, 0x04, 0xff])
      await refuse('header', prf, header, b)
      await refuse('length', prf, below(2) === 0 ? w.slice(0, 61 - below(3)) : new Uint8Array([...w, ...bytes(1 + below(3))]) as Bytes, b)
      await refuse('other-prf', bytes(32), w, b)
      let rp = b.rpId
      while (rp === b.rpId) rp = rpId()
      await refuse('other-rp-id', prf, w, { ...b, rpId: rp })
      let cred = b.credentialId
      while (cred === b.credentialId) cred = credentialId()
      await refuse('other-credential', prf, w, { ...b, credentialId: cred })
      await refuse('other-sub', prf, w, { ...b, sub: crypto.randomUUID() })
      await refuse('other-epoch', prf, w, { ...b, epoch: b.epoch === 2 ** 31 - 1 ? b.epoch - 1 : b.epoch + 1 })
    }

    // Client extension results edited at random from the allowed ones. Only
    // well-formed text is written: a JSON file carries a lone surrogate to
    // Go as U+FFFD (the unit tests have those).
    const seeds = [
      '{}', '{"credProps":{"rk":true}}', '{"credProps":{"rk":false}}', '{"prf":{"enabled":true}}', '{"prf":{"enabled":false}}',
      '{"credProps":{"rk":true},"prf":{"enabled":true}}', '{"prf":{"enabled":false},"credProps":{"rk":true}}',
      ' {"pr\u0066" : {"en\u0061bled" : true}} ',
    ]
    const pieces = [
      '{', '}', '[', ']', ':', ',', '"', '\\', 'u', '0', '6', 'f', 't', 'r', 'e', 'n', 'l', 'a', 's', ' ', '\t', '\n', '\r',
      '\ufeff', 'P', 'R', 'F', 'k', 'd', 'b', '1', '-', '.', '\u00e9', '\u0000', '\u0066', '\u0000', '\ud800', '\\/',
      '"prf"', '"credProps"', '"rk"', '"enabled"', '"results"', '"first"', 'true', 'false', 'null', '1.0', '1e0',
      '{"enabled":true}', '{"rk":false}', '"results":{}', '"results":{"first":"EhJD599fFQOFAB7ZW0Br9KT5OkI77uQwiPBVpt38MNM"}',
      '\u2028', '\u00a0', '\ud83d\ude00',
    ]
    const mutate = (s: string) => {
      for (let k = 1 + below(3); k > 0; k--) {
        const at = below(s.length + 1)
        const piece = pickOf(pieces)
        const op = below(4)
        if (op <= 1) s = s.slice(0, at) + piece + s.slice(at)
        else if (op === 2 && at < s.length) s = s.slice(0, at) + s.slice(at + 1)
        else if (op === 3 && at < s.length) s = s.slice(0, at) + piece + s.slice(at + 1)
      }
      return s
    }
    const loneSurrogate = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/
    let accepted = 0
    for (let n = 0; n < 1000;) {
      const text = mutate(pickOf(seeds))
      if (loneSurrogate.test(text)) continue
      const id = `platform/check-client-extensions/${n++}`
      const code = await codeOf(() => platform.checkClientExtensionsText(text))
      if (code === 'none') {
        accepted++
        cases.push({ id, op: 'platform.check_client_extensions', in: { text }, out: { accepted: true } })
      } else {
        expect(code, id).toBe('client_extensions')
        cases.push({ id, op: 'platform.check_client_extensions', in: { text }, error: 'client_extensions' })
      }
    }
    expect(accepted).toBeGreaterThan(0)
    write('platform-passkey-ts.json', 'platform', 'Fresh cases of the platform profile\'s part 3 (SPEC section 11.16) by the kit\'s TypeScript, for Go: the PRF salt of 200 relying party ids, half of them in a spelling the protocol refuses; 32 fresh passkey wraps (random PRF output, root, account, epoch, relying party and a credential id of 1 to 1023 bytes) with the nonce each drew and its AAD (K_pk is a non-extractable key here, so it is not recorded), each also opened with one thing changed (a bit, a header byte, the length, the PRF output, the relying party, the credential, the sub, the epoch); and 1000 client extension results edited at random from the allowed ones, with the allowlist\'s verdict.', cases, undefined, 'platform')
  })

  // Fixed passwords at the limit of the run rule (SPEC section 11.2, step 2)
  // and one past it, where Go's normaliser inserts U+034F and ICU's does not:
  // the same list as internal/cross/platform_test.go (streamSafeCases), each
  // with its declared outcome.
  it('writes platform-password-ts.json', async () => {
    const ch = (...cps: number[]) => String.fromCodePoint(...cps)
    const acutes = (n: number) => ch(0x301).repeat(n)
    const fixed: [string, string, boolean, string][] = [
      ['compatibility-vowel-jamo/31', ch(0x3160).repeat(31), false, 'password_invalid'],
      ['compatibility-vowel-jamo/30', ch(0x3160).repeat(30), true, ''],
      ['syllable-then-acutes/29', ch(0xac01) + acutes(29), false, 'password_invalid'],
      ['syllable-then-acutes/28', ch(0xac01) + acutes(28), false, ''],
      ['acute-accent-then-acutes/30', ch(0xb4) + acutes(30), false, 'password_invalid'],
      ['acute-accent-then-acutes/29', ch(0xb4) + acutes(29), false, ''],
      ['vowel-jamo-then-acutes/30', ch(0x1161) + acutes(30), false, 'password_invalid'],
      ['vowel-jamo-then-acutes/29', ch(0x1161) + acutes(29), false, ''],
      ['halfwidth-voiced-mark/31', 'a' + ch(0xff9e).repeat(31), false, 'password_invalid'],
      ['halfwidth-voiced-mark/30', 'a' + ch(0xff9e).repeat(30), true, ''],
      ['halfwidth-jamo/31', 'a' + ch(0xffa3).repeat(31), false, 'password_invalid'],
      ['halfwidth-jamo/30', 'a' + ch(0xffa3).repeat(30), true, ''],
      ['two-marks-each/16', 'a' + ch(0x344).repeat(16), false, 'password_invalid'],
      ['two-marks-each/15', 'a' + ch(0x344).repeat(15), true, ''],
      ['kirat-rai-vowel-sign-e/31', 'a' + ch(0x16d67).repeat(31), false, 'password_invalid'],
      ['alternating-marks/31', 'a' + ch(0x316, 0x301).repeat(15) + ch(0x316), false, 'password_invalid'],
      ['conjoining-jamo/11', ch(0x1100, 0x1161, 0x11a8).repeat(11), false, ''],
      ['syllables/31', ch(0xac01).repeat(31), true, ''],
    ]
    const cases: VectorCase[] = []
    for (const [slug, password, isNew, error] of fixed) {
      const c: VectorCase = { id: `platform/prepare-password/stream-safe/${slug}`, op: 'platform.prepare_password', in: { password, new: isNew } }
      const got = await codeOf(() => platform.preparePassword(password, { isNew }))
      expect(got, slug).toBe(error === '' ? 'none' : error)
      if (error !== '') {
        c.error = error
      } else {
        expect(platform.preparePasswordText(password, { isNew }), slug).toBe(password.normalize('NFC'))
        c.out = { prepared_b64: toB64(platform.preparePassword(password, { isNew })) }
      }
      cases.push(c)
    }
    write('platform-password-ts.json', 'platform', 'Fixed passwords at the limit of the platform profile\'s run rule (SPEC section 11.2, step 2) and one past it, by the kit\'s TypeScript, for Go: runs that only the compatibility decomposition or the Hangul vowel and final jamo make (compatibility and halfwidth jamo, Hangul syllables, U+00B4, U+FF9E), U+16D67, and marks for comparison. Past the limit Go\'s normaliser would insert U+034F and ICU\'s would not, so both refuse; at it both prepare the password\'s NFC.', cases, undefined, 'platform')
  })
})
