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
import { describe, expect, it } from 'vitest'

import { derive, newRecoveryCode, normaliseRecoveryCode, recoveryProof, unwrapPrivateKey, wrapPrivateKey } from '../src/account.js'
import { formatUUID, parseUUID, uuidV5, type Bytes } from '../src/bytes.js'
import { generateKeyPair, importPrivateKey, publicFromPrivate, seal as hpkeSeal } from '../src/hpke.js'
import { canonicalJSON } from '../src/jcs.js'
import { prfSalt, wrapPasskey } from '../src/passkey.js'
import { canonical, signature } from '../src/reqhmac.js'
import { grantRow, openDirect, sealDirect } from '../src/seal.js'
import { accountWrapAAD, DIRECTION_TO_READER, Kind, passkeyAAD, wappieAccount, wappieMCPHMAC, wappiePasskey, wappieSeal } from '../src/profiles/wappie.js'
import { recording, toB64, utf8, type VectorCase } from './vectors.js'

const OUT = process.env.KIT_CROSS_OUT ?? ''

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

function write(name: string, module: string, note: string, cases: VectorCase[], keys?: Record<string, unknown>) {
  const pkg = JSON.parse(readFileSync(new URL('../node_modules/@noble/hashes/package.json', import.meta.url), 'utf8'))
  const file = {
    format: 'thehappieco-kit-vectors/1', module, profile: 'wappie',
    generated_by: {
      lang: 'ts', source: `${source()} js/src`, toolchain: `node ${process.version}; @noble/hashes ${pkg.version}`,
      randomness: 'crypto.getRandomValues; each case records the bytes and X25519 keys it drew', generator: 'js/test/cross.spec.ts',
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
    write('seal-ts.json', 'seal', 'Fresh grants and a draft sealed by the kit\'s TypeScript with the Wappie profile, for Go to open.', cases, keys)

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
    write('hpke-ts.json', 'hpke', 'Fresh HPKE seals by the kit\'s WebCrypto implementation, for Go\'s crypto/hpke to open.', hcases, { r1: keys.archive })
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
    write('account-ts.json', 'account', 'Fresh derivations and wraps by the kit\'s TypeScript account scheme with the Wappie profile, for Go.', cases)

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
    write('passkey-ts.json', 'passkey', 'Fresh passkey wraps by the kit\'s TypeScript with the Wappie profile, for Go.', pcases)
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
})
