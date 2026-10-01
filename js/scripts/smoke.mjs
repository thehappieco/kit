// Installs the packed tarball into an empty directory, as a consumer would,
// and exercises every subpath export from there.
//
//   node scripts/pack.mjs && node scripts/smoke.mjs

import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
const tarball = join(root, `thehappieco-kit-${pkg.version}.tgz`)
const dir = mkdtempSync(join(tmpdir(), 'kit-smoke-'))
try {
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'kit-smoke', private: true, type: 'module' }))
  execFileSync('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', tarball], { cwd: dir, stdio: 'inherit' })
  writeFileSync(join(dir, 'smoke.mjs'), `
import assert from 'node:assert/strict'
import * as bytes from '@thehappieco/kit/bytes'
import { canonicalJSON } from '@thehappieco/kit/jcs'
import { SealError } from '@thehappieco/kit/errors'
import * as hpke from '@thehappieco/kit/hpke'
import * as seal from '@thehappieco/kit/seal'
import * as account from '@thehappieco/kit/account'
import * as passkey from '@thehappieco/kit/passkey'
import * as browserAccount from '@thehappieco/kit/browserAccount'
import * as reqhmac from '@thehappieco/kit/reqhmac'
import * as wappie from '@thehappieco/kit/profiles/wappie'

const pair = await hpke.generateKeyPair()
const id = bytes.parseUUID('018f3a2b-0000-7000-8000-000000000001')
const s = seal.bind(wappie.wappieSeal)
const env = await s.sealDirect(pair.publicKey, wappie.Kind.DeviceGrant, id, id, 1, new Uint8Array(32))
assert.equal((await s.openDirect(await hpke.importPrivateKey(pair.privateKey), wappie.Kind.DeviceGrant, id, id, env)).length, 32)
await assert.rejects(s.openDirect(await hpke.importPrivateKey(pair.privateKey), wappie.Kind.Body, id, id, env), SealError)
const d = await account.derive(wappie.wappieAccount, 'pw', new Uint8Array(16), { alg: 'argon2id', m: 8, t: 1, p: 1 })
assert.equal(d.authKey.length, 44)
const blob = await account.wrapPrivateKey(wappie.wappieAccount, pair.privateKey, d.wrapKey, wappie.accountWrapAAD('a@b.c'))
assert.equal(blob.length, 61)
const pk = await passkey.wrapPasskey(wappie.wappiePasskey, pair.privateKey, new Uint8Array(32), 'x', wappie.passkeyAAD({ rpID: 'x', userID: 'u', credentialID: 'c' }))
assert.equal(pk.length, 61)
await assert.rejects(passkey.wrapPasskey(wappie.wappiePasskey, pair.privateKey, new Uint8Array(32), 'x', new Uint8Array(0)), passkey.PasskeyError)
await assert.rejects(hpke.seal(new Uint8Array(32), new Uint8Array(0), new Uint8Array(0), new Uint8Array(0)), hpke.HPKEError)
assert.equal(typeof browserAccount.validBrowserKeyEnvelope, 'function')
assert.match(await reqhmac.signature(wappie.wappieMCPHMAC, 's', 'to-go', 'r', 'GET', '/', '1', 'n', new Uint8Array(0)), /^v1=[0-9a-f]{64}$/)
assert.equal(canonicalJSON({ b: 1, a: 2 }), '{"a":2,"b":1}')
await import('@thehappieco/kit/kdf.worker').catch(err => assert.match(String(err), /self/))
console.log('smoke: every export loads and works from the installed tarball')
`)
  execFileSync('node', ['smoke.mjs'], { cwd: dir, stdio: 'inherit' })
} finally {
  rmSync(dir, { recursive: true, force: true })
}
