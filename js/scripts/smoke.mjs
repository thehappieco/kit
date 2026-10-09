// Installs the packed tarball into an empty directory, as a consumer would,
// and exercises every subpath export from there; then bundles Mailie's
// profile from there, as Mailie's console does.
//
//   node scripts/pack.mjs && node scripts/smoke.mjs

import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'esbuild'

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
import * as platformwrap from '@thehappieco/kit/platformwrap'
import * as wappie from '@thehappieco/kit/profiles/wappie'
import * as mailie from '@thehappieco/kit/profiles/mailie'
import * as platform from '@thehappieco/kit/profiles/platform'
import * as platformCore from '@thehappieco/kit/profiles/platform/core'
import * as errors from '@thehappieco/kit/errors'
import * as rp from '@thehappieco/kit/oidc-rp'

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
const sub = '0199e4b2-3c41-7a52-8f3e-9b1d2c4e5f60'
assert.equal(platform.rootWrapAAD('password', sub, 1), '["thehappie-id/root-wrap",1,"password","' + sub + '",1]')
const rootWrap = await platform.sealRootWrap('recovery', new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), sub, 1)
assert.deepEqual([rootWrap.length, rootWrap[0], rootWrap[1]], [62, 1, 2])
assert.equal(platform.normalizeEmail(' Ana@Example.COM '), 'ana@example.com')
assert.equal(platform.canonicalRecoveryCode('oi234-56789-abcde-fghjk-mnpqr-stvwx'), '0123456789ABCDEFGHJKMNPQRSTVWX')
assert.throws(() => platform.normalizeEmail('ana'), platform.PlatformError)
await assert.rejects(platform.derivePassword(new Uint8Array(1), new Uint8Array(16), { alg: 'argon2id', m: 8, t: 1, p: 1 }), (err) => platform.isPlatformError(err, 'kdf_policy'))
assert.equal((await platform.deriveProductKey(new Uint8Array(32).fill(3), 'wappie', 1)).pub.length, 32)
assert.equal(await platform.pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'), 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
await assert.rejects(platform.pkceChallenge('short'), (err) => platform.isPlatformError(err, 'pkce'))
const request = { issuer: 'https://id.thehappie.co', clientId: 'wappie-app', redirectUri: 'https://app.wappie.thehappie.co/auth/callback', sub, codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', nonce: 'n-0S6_WzA2Mj4Rm7tBQdLwK1vHqXf9cUe3yPbJsZkGo' }
const productKey = await platform.deriveProductKey(new Uint8Array(32).fill(4), 'wappie', 1)
const binding = { ...request, productKeyId: productKey.id, productKey: productKey.pub }
assert.ok(platform.keyDeliveryAAD(binding).startsWith('["thehappie-id/key-delivery",1,"https://id.thehappie.co","wappie-app",'))
const akd = await platform.generateX25519KeyPair()
const delivered = await platform.deliverProductKey({ root: new Uint8Array(32).fill(4), product: 'wappie', epoch: 1, akdPub: bytes.toBase64URL(akd.publicKey), binding: request })
assert.deepEqual(await platform.openProductKey(akd.privateKey, delivered.akd_sealed, binding), productKey.sk)
assert.equal(bytes.toBase64URL(await platform.prfSalt('id.thehappie.co')), 'bfXhmXwNWTxBlIM_eJeGrFssTtbVypdC50j3PKYUeH4')
await assert.rejects(platform.prfSalt('ID.thehappie.co'), (err) => platform.isPlatformError(err, 'wrap'))
platform.checkClientExtensionsText('{"credProps":{"rk":true},"prf":{"enabled":true}}')
assert.throws(() => platform.checkClientExtensionsText('{"prf":{"enabled":true,"results":{"first":"AA"}}}'), (err) => platform.isPlatformError(err, 'client_extensions'))
const passkeyIn = { prf: new Uint8Array(32).fill(6), rpId: 'id.thehappie.co', credentialId: 'AQ', sub, epoch: 1 }
const passkeyWrap = await platform.wrapRootWithPasskey({ ...passkeyIn, root: new Uint8Array(32).fill(5) })
assert.deepEqual([...bytes.fromBase64URL(passkeyWrap, 62).subarray(0, 2)], [1, 3])
assert.deepEqual(await platform.unwrapRootWithPasskey({ ...passkeyIn, wrap: passkeyWrap }, async (root) => [...root]), Array(32).fill(5))
assert.equal((await platform.passkeyWrapKey(passkeyIn.prf, passkeyIn.rpId)).extractable, false)
await assert.rejects(platform.prfSalt('0x7f000001'), (err) => platform.isPlatformError(err, 'wrap'))
assert.deepEqual([passkey.endsInANumber('id.0xff'), passkey.endsInANumber('id.0x1g'), platform.isRPID('id.0x1g')], [true, false, true])
assert.deepEqual(Object.keys(platformCore).sort(), Object.keys(platform).sort())
for (const name of Object.keys(platformCore)) {
  if (['derivePassword', 'derivePasswordKeys', 'openKeyBundle'].includes(name)) assert.notEqual(platformCore[name], platform[name], name)
  else assert.equal(platformCore[name], platform[name], name)
}
const coreKeys = await platformCore.derivePasswordKeys('correct horse battery staple', new Uint8Array(16).fill(7), platformCore.DEFAULT_KDF)
assert.equal(coreKeys.authKey, (await platform.derivePasswordKeys('correct horse battery staple', new Uint8Array(16).fill(7), platform.DEFAULT_KDF)).authKey)
const accountKey = new Uint8Array(32).fill(9)
const wrapBinding = { userId: sub, sub, productKeyId: 'wappie:1', accountPublicKey: await hpke.publicFromPrivate(accountKey) }
const platformWrap = await wappie.sealPlatformWrap(productKey.sk, accountKey, wrapBinding)
wappie.checkPlatformWrapShape(platformWrap)
assert.deepEqual([platformWrap.length, platformWrap[0]], [61, 3])
assert.deepEqual(await wappie.openPlatformWrap(productKey.sk, platformWrap, wrapBinding), accountKey)
await assert.rejects(wappie.openPlatformWrap(productKey.sk, platformWrap, { ...wrapBinding, productKeyId: 'wappie:2' }), (err) => wappie.isPlatformWrapError(err) && err instanceof errors.PlatformWrapError && err.code === 'platform_wrap')
assert.throws(() => wappie.checkPlatformWrapShape(Uint8Array.of(1, ...platformWrap.subarray(1))), wappie.PlatformWrapError)
assert.deepEqual(await platformwrap.openPlatformWrap(wappie.wappiePlatformWrap, productKey.sk, platformWrap, wrapBinding), accountKey)
assert.deepEqual(wappie.platformWrapAAD(wrapBinding), platformwrap.bind(wappie.wappiePlatformWrap).platformWrapAAD(wrapBinding))
assert.deepEqual(mailie.mailiePlatformWrap, { product: 'mailie', salt: 'mailie/platform-wrap/v1', label: 'mailie/platform-wrap' })
const mailieKey = await platform.deriveProductKey(new Uint8Array(32).fill(4), 'mailie', 1)
const mailieBinding = { ...wrapBinding, productKeyId: mailieKey.id }
const mailieWrap = await platformwrap.sealPlatformWrap(mailie.mailiePlatformWrap, mailieKey.sk, accountKey, mailieBinding)
platformwrap.checkPlatformWrapShape(mailieWrap)
assert.deepEqual([mailieWrap.length, mailieWrap[0], platformwrap.PLATFORM_WRAP_HEADER, platformwrap.PLATFORM_WRAP_LEN, platformwrap.PLATFORM_WRAP_VERSION], [61, 3, 3, 61, 1])
assert.deepEqual(await platformwrap.openPlatformWrap(mailie.mailiePlatformWrap, mailieKey.sk, mailieWrap, mailieBinding), accountKey)
await assert.rejects(platformwrap.openPlatformWrap(wappie.wappiePlatformWrap, mailieKey.sk, mailieWrap, wrapBinding), (err) => platformwrap.isPlatformWrapError(err) && err instanceof errors.PlatformWrapError)
await assert.rejects(wappie.openPlatformWrap(productKey.sk, mailieWrap, wrapBinding), wappie.PlatformWrapError)
const sealID = 'b8cbc8a8-0c90-48ac-9233-fbdace9d7bf4'
const mailboxNS = '9d035f2b-81d0-420e-90e2-bb16e950497b'
const accountPub = await hpke.publicFromPrivate(accountKey)
assert.equal(new TextDecoder().decode(mailie.accountWrapAAD('password', sealID, accountPub)), '["mailie/account-wrap",1,"password","' + sealID + '","' + bytes.toBase64URL(accountPub) + '"]')
const recoveryWrapKey = await account.recoveryKey(mailie.mailieAccount, 'o1234 56789 abcde fghjk mnpqr stvwx')
const accountWrap = await mailie.sealAccountWrap('recovery', recoveryWrapKey, accountKey, sealID)
mailie.checkAccountWrapShape(accountWrap)
assert.deepEqual([accountWrap.length, accountWrap[0]], [61, 2])
assert.deepEqual(await mailie.openAccountWrap('recovery', recoveryWrapKey, accountWrap, sealID, accountPub), accountKey)
await assert.rejects(mailie.openAccountWrap('password', recoveryWrapKey, accountWrap, sealID, accountPub), (err) => err instanceof mailie.AccountError && err.reason === 'wrong_key')
const mailboxKey = new Uint8Array(32).fill(8)
const grant = await mailie.sealGrant(accountPub, mailboxNS, sealID, 1, mailboxKey)
mailie.checkGrantShape(grant, 1)
assert.deepEqual([grant.length, String.fromCharCode(grant[0], grant[1])], [88, 'ML'])
assert.deepEqual(await mailie.openGrant(await hpke.importPrivateKey(accountKey), mailboxNS, sealID, 1, await hpke.publicFromPrivate(mailboxKey), grant), mailboxKey)
assert.equal(new TextDecoder().decode(mailie.grantInfo(mailboxNS, 1)), 'mlv1/mailbox_grant/' + mailboxNS + '/1')
assert.throws(() => mailie.platformWrapBinding(sub, sub, 1, accountPub), (err) => mailie.isMailieError(err, 'binding') && err instanceof errors.MailieError)
const mailieSealBinding = mailie.platformWrapBinding(sealID, sub, 1, accountPub)
assert.deepEqual(await mailie.openMailiePlatformWrap(mailieKey.sk, await mailie.sealMailiePlatformWrap(mailieKey.sk, accountKey, mailieSealBinding), mailieSealBinding), accountKey)
assert.ok(new TextDecoder().decode(mailie.browserVaultAAD(sealID, accountPub)).startsWith('["mailie/browser-account-key",1,"' + sealID + '","'))
assert.equal(mailie.kindName(mailie.Kind.MailboxGrant), 'mailbox_grant')
assert.equal(rp.sameOriginPath('//x', 'https://app.wappie.thehappie.co'), null)
const logout = new URL(rp.logoutURL({ issuer: 'https://id.thehappie.co', clientId: 'wappie-app', postLogoutRedirectUri: 'https://app.wappie.thehappie.co/' }))
assert.deepEqual([logout.origin + logout.pathname, logout.searchParams.get('client_id'), logout.searchParams.get('post_logout_redirect_uri'), logout.searchParams.get('state').length], ['https://id.thehappie.co/oauth2/logout', 'wappie-app', 'https://app.wappie.thehappie.co/', 43])
assert.equal(typeof rp.begin, 'function')
assert.equal(typeof rp.finishSignIn, 'function')
assert.ok(rp.isRPError(new rp.RPError('pin_mismatch'), 'pin_mismatch'))
await import('@thehappieco/kit/kdf.worker').catch(err => assert.match(String(err), /self/))
console.log('smoke: every export loads and works from the installed tarball')
`)
  execFileSync('node', ['smoke.mjs'], { cwd: dir, stdio: 'inherit' })

  // The Mailie build rule: Mailie's open console fails on any output that
  // names the platform, and derives through @thehappieco/kit/account with a
  // worker of its own. Every export of @thehappieco/kit/profiles/mailie,
  // bundled from the installed tarball with tree-shaking, must name neither
  // the platform nor a KDF worker. The entry's module graph does reach
  // internal modules that hold the platform's labels, which tree-shaking
  // drops, so a bundle without it would not pass. Whitespace is minified,
  // which drops comments, among them the path comments that name the
  // package's scope; identifiers and strings are kept as written.
  const bundled = await build({
    stdin: { contents: "export * from '@thehappieco/kit/profiles/mailie'", resolveDir: dir, loader: 'js' },
    absWorkingDir: dir,
    bundle: true,
    write: false,
    format: 'esm',
    platform: 'browser',
    treeShaking: true,
    minifyWhitespace: true,
    logLevel: 'silent',
  })
  const text = bundled.outputFiles[0].text
  for (const [what, pattern] of [["the platform's name", /happie/i], ['a KDF worker', /kdf\.worker|new Worker\b/]]) {
    if (pattern.test(text)) throw new Error(`smoke: the bundle of @thehappieco/kit/profiles/mailie names ${what}`)
  }
  console.log(`smoke: @thehappieco/kit/profiles/mailie bundles (${text.length} bytes) naming neither the platform nor a KDF worker`)
} finally {
  rmSync(dir, { recursive: true, force: true })
}
