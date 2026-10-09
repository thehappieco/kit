// Mailie's key scheme (SPEC Appendix D), in Node and in Chromium, Firefox and
// WebKit: Mailie's own vectors, frozen byte for byte from
// github.com/thehappieco/mailie c9c79cf under vectors/mailie/key-scheme-v1,
// run with @thehappieco/kit/profiles/mailie. Every case marked for
// TypeScript, or for every language, is computed, opened, replayed or
// refused here, every refusal with its exact code and reason: the account
// wraps and the platform wraps are replayed byte for byte from their
// recorded nonces; Go's grants, sealed under a seed only Go replays, are
// opened, and a fresh grant is sealed and opened beside each. How Mailie's
// server normalises an address is its own (Mailie's spec, section 2), not
// the kit's: those cases run against that rule, written here as test code.

import { describe, expect, it } from 'vitest'

import { derive, recoveryKey, recoveryProof } from '../src/account.js'
import { equal, formatUUID, fromBase64URL, type Bytes } from '../src/bytes.js'
import { isPlatformError, isPlatformWrapError, MailieError } from '../src/errors.js'
import { importPrivateKey, publicFromPrivate } from '../src/hpke.js'
import { platformWrapAAD, platformWrapInfo, type PlatformWrapBinding } from '../src/platformwrap.js'
import { deriveProductKey, PASSWORD_PROFILE, recoveryCodeFromBytes } from '../src/profiles/platform/core.js'
import {
  ACCOUNT_WRAP_HEADER,
  ACCOUNT_WRAP_LEN,
  ACCOUNT_WRAP_TAG,
  ACCOUNT_WRAP_VERSION,
  AccountError,
  accountWrapAAD,
  BROWSER_VAULT_TAG,
  BROWSER_VAULT_VERSION,
  browserVaultAAD,
  checkAccountWrapShape,
  checkGrantShape,
  checkKDF,
  DEFAULT_KDF,
  GRANT_LEN,
  grantAAD,
  grantInfo,
  grantRow,
  isMailieError,
  isNamespace,
  isSealID,
  Kind,
  kindName,
  MAX_EPOCH,
  MIN_EPOCH,
  mailieAccount,
  mailieBrowserVault,
  mailiePlatformWrap,
  mailieSeal,
  openAccountWrap,
  openBrowserVault,
  openGrant,
  openMailiePlatformWrap,
  PASSWORD_AUTH_LABEL,
  PASSWORD_WRAP_LABEL,
  platformWrapBinding,
  prepareNewPassword,
  RECOVERY_AUTH_LABEL,
  RECOVERY_WRAP_LABEL,
  SALT_LEN,
  SEAL_LABEL,
  SEAL_MAGIC,
  SealError,
  sealAccountWrap,
  sealBrowserVault,
  sealGrant,
  sealMailiePlatformWrap,
  type WrapKind,
} from '../src/profiles/mailie.js'
import { KIND_CONTENT_KEY, KIND_GRANT, KIND_USER_WRAP } from '../src/seal.js'
import { b64, forTS, load, toB64, withDraws, type VectorCase, type VectorFile } from './vectors.js'

const DIR = 'mailie/key-scheme-v1/'

// The files, with the module each names, its cases and must-fail cases, and
// how many of each are TypeScript's (the others are Go's only: the server's
// salt, its check of a public key, a wrap key of 31 bytes).
const FILES = [
  { name: 'account-go.json', module: 'account', cases: 104, mustFail: 60, ts: 94, tsMustFail: 59 },
  { name: 'grant-go.json', module: 'seal', cases: 107, mustFail: 69, ts: 93, tsMustFail: 57 },
  { name: 'platform-wrap-go.json', module: 'platformwrap', cases: 31, mustFail: 18, ts: 31, tsMustFail: 18 },
  { name: 'browser-vault-go.json', module: 'browser_account', cases: 6, mustFail: 3, ts: 6, tsMustFail: 3 },
] as const

// The white space Go's strings.TrimSpace removes (unicode.IsSpace), by code
// point: not ECMAScript's trim, which also removes U+FEFF and keeps U+0085.
const GO_WHITE_SPACE: ReadonlySet<number> = new Set([
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008,
  0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
])

/**
 * normaliseAddress is an address as Mailie's server stores it (Mailie's
 * spec, section 2): Go's strings.TrimSpace, then Unicode's simple lowercase
 * mapping of each code point, as Go's strings.ToLower. Test code: Mailie's
 * rule, not the kit's.
 */
function normaliseAddress(address: string): string {
  const cps = Array.from(address, (c) => c.codePointAt(0) ?? 0)
  let start = 0
  let end = cps.length
  while (start < end && GO_WHITE_SPACE.has(cps[start] ?? 0)) start++
  while (end > start && GO_WHITE_SPACE.has(cps[end - 1] ?? 0)) end--
  let out = ''
  for (let i = start; i < end; i++) {
    const cp = cps[i] ?? 0
    if (cp === 0x130) {
      out += 'i'
      continue
    }
    const one = String.fromCodePoint(cp)
    const lower = one.toLowerCase()
    out += Array.from(lower).length === 1 ? lower : one
  }
  return out
}

/** Input reads a case's inputs and records which it read: a member no handler reads fails the case. */
class Input {
  readonly read = new Set<string>()
  constructor(readonly c: VectorCase) {}
  has(k: string): boolean {
    return k in this.c.in
  }
  str(k: string): string {
    this.read.add(k)
    const v = this.c.in[k]
    if (typeof v !== 'string') throw new Error(`${this.c.id}: ${k} is not a string`)
    return v
  }
  num(k: string): number {
    this.read.add(k)
    const v = this.c.in[k]
    if (typeof v !== 'number' || !Number.isInteger(v)) throw new Error(`${this.c.id}: ${k} is not an integer`)
    return v
  }
  bytes(k: string): Bytes {
    return b64(this.str(k))
  }
  obj(k: string): Record<string, unknown> {
    this.read.add(k)
    const v = this.c.in[k]
    if (typeof v !== 'object' || v === null || Array.isArray(v)) throw new Error(`${this.c.id}: ${k} is not an object`)
    return v as Record<string, unknown>
  }
  /** seed is a seal's recorded seed, which only Go replays; it is read so that it is not taken for an unknown member. */
  seed(): void {
    if (this.num('seed') < 1) throw new Error(`${this.c.id}: a seed below 1`)
  }
  unread(): string[] {
    return Object.keys(this.c.in).filter((k) => !this.read.has(k))
  }
}

/** sameAESKey says whether a non-extractable AES-GCM key is the raw key: both encrypt one block alike. */
async function sameAESKey(key: CryptoKey, raw: Uint8Array): Promise<boolean> {
  const probe = { name: 'AES-GCM', iv: new Uint8Array(12) }
  const want = await crypto.subtle.importKey('raw', new Uint8Array(raw), 'AES-GCM', false, ['encrypt'])
  const a = new Uint8Array(await crypto.subtle.encrypt(probe, key, new Uint8Array(16))) as Bytes
  const b = new Uint8Array(await crypto.subtle.encrypt(probe, want, new Uint8Array(16))) as Bytes
  return equal(a, b)
}

function aesKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', new Uint8Array(raw), 'AES-GCM', false, ['encrypt', 'decrypt'])
}

/** errorOf is how the vectors name an error (Mailie's spec, section 13). */
function errorOf(err: unknown): { code: string; reason?: string } {
  if (err instanceof MailieError) return { code: err.code }
  if (err instanceof AccountError) return { code: err.code, reason: err.reason }
  if (err instanceof SealError) return { code: err.code }
  if (isPlatformWrapError(err)) return { code: 'platform_wrap' }
  if (isPlatformError(err)) return { code: err.code }
  return { code: `unclassified: ${String(err)}` }
}

async function wrapKeyOf(input: Input): Promise<CryptoKey> {
  if (input.has('wrap_key_b64')) return aesKey(input.bytes('wrap_key_b64'))
  if (input.has('recovery_code')) return recoveryKey(mailieAccount, input.str('recovery_code'))
  if (input.has('password')) {
    const salt = input.bytes('salt_b64')
    const params = checkKDF(input.obj('params'), salt)
    return (await derive(mailieAccount, input.str('password'), salt, params)).wrapKey
  }
  throw new Error(`${input.c.id}: no wrap key`)
}

async function privateKeyOf(file: VectorFile, name: string) {
  const key = file.keys?.[name]
  if (!key) throw new Error(`no key ${name}`)
  const priv = await importPrivateKey(b64(key.private_key_b64))
  if (toB64(priv.publicRaw) !== key.public_key_b64) throw new Error(`key ${name} is not a key pair`)
  return priv
}

function wrapBinding(input: Input): PlatformWrapBinding {
  return { userId: input.str('user_id'), sub: input.str('sub'), productKeyId: input.str('product_key_id'), accountPublicKey: input.bytes('account_public_key_b64') }
}

type Out = Record<string, unknown>
type Op = (input: Input, file: VectorFile, c: VectorCase) => Promise<Out>

const ops: Record<string, Op> = {
  // The account.
  'mailie.account_profile': async () => {
    const b = mailieAccount.bounds!
    return {
      auth_label: mailieAccount.authLabel,
      wrap_label: mailieAccount.wrapLabel,
      recovery_key_label: mailieAccount.recoveryKeyLabel,
      recovery_proof_label: mailieAccount.recoveryProofLabel,
      wrap_header_b64: toB64(new Uint8Array(mailieAccount.wrapHeader)),
      wrap_len: ACCOUNT_WRAP_LEN,
      legacy_v1: mailieAccount.legacyV1,
      wrap_aad_tag: ACCOUNT_WRAP_TAG,
      wrap_aad_version: ACCOUNT_WRAP_VERSION,
      wrap_kinds: ['password', 'recovery'],
      encoding: mailieAccount.encoding,
      password_preparation: PASSWORD_PROFILE,
      recovery_normalisation: 'platform-canonical',
      kdf: { ...DEFAULT_KDF },
      bounds: { min: { ...b.min }, max: { ...b.max }, max_cost: b.maxCost, min_salt_len: b.minSaltLen, max_salt_len: b.maxSaltLen },
      // Mailie's server's label for the salts it hands out, not the kit's.
      salt_label: 'mailie/v1/kdf-salt',
    }
  },
  'mailie.normalise_address': async (input) => ({ address: normaliseAddress(input.str('address')) }),
  'account.derive': async (input, _, c) => {
    const d = await derive(mailieAccount, input.str('password'), input.bytes('salt_b64'), input.obj('params') as never)
    if (!(await sameAESKey(d.wrapKey, b64(c.out.wrap_b64)))) throw new Error('another wrap key')
    return { auth_b64: toB64(fromBase64URL(d.authKey, 32)), auth_key: d.authKey, wrap_b64: c.out.wrap_b64 }
  },
  'mailie.recovery_code': async (input) => {
    const code = recoveryCodeFromBytes(input.bytes('bytes_b64'))
    return { code: code.canonical, display: code.display }
  },
  'account.normalise_recovery_code': async (input) => ({ code: mailieAccount.normaliseRecovery!(input.str('code')) }),
  'account.recovery_key': async (input, _, c) => {
    const key = await recoveryKey(mailieAccount, input.str('code'))
    if (!(await sameAESKey(key, b64(c.out.key_b64)))) throw new Error('another recovery key')
    return { key_b64: c.out.key_b64 }
  },
  'account.recovery_proof': async (input) => ({ proof: await recoveryProof(mailieAccount, input.str('code')) }),
  'mailie.account_wrap_aad': async (input) => ({
    aad_b64: toB64(accountWrapAAD(input.str('kind') as WrapKind, input.str('seal_id'), input.bytes('account_public_key_b64'))),
  }),
  'mailie.account_wrap': async (input) => {
    const kind = input.str('kind') as WrapKind
    const sealID = input.str('seal_id')
    const key = input.bytes('account_key_b64')
    const wrapKey = await aesKey(input.bytes('wrap_key_b64'))
    if (!input.has('nonce_b64')) {
      await sealAccountWrap(kind, wrapKey, key, sealID)
      throw new Error('a refusal sealed')
    }
    input.seed()
    // Replayed byte for byte: the one draw of the seal is the recorded nonce.
    const wrap = await withDraws({ bytes: [input.bytes('nonce_b64')] }, () => sealAccountWrap(kind, wrapKey, key, sealID))
    const pub = await publicFromPrivate(key)
    checkAccountWrapShape(wrap)
    if (!equal(await openAccountWrap(kind, wrapKey, wrap, sealID, pub), key)) throw new Error('the wrap opens to another key')
    return { account_public_key_b64: toB64(pub), aad_b64: toB64(accountWrapAAD(kind, sealID, pub)), wrap_b64: toB64(wrap) }
  },
  'mailie.account_unwrap': async (input) => {
    const [kind, wrap, sealID, pub] = [input.str('kind') as WrapKind, input.bytes('wrap_b64'), input.str('seal_id'), input.bytes('account_public_key_b64')]
    const key = await openAccountWrap(kind, await wrapKeyOf(input), wrap, sealID, pub)
    return { account_key_b64: toB64(key) }
  },
  'mailie.account_wrap_shape': async (input) => {
    checkAccountWrapShape(input.bytes('wrap_b64'))
    return { accepted: true }
  },

  // The seal domain and the grants.
  'mailie.seal_profile': async () => ({
    magic_b64: toB64(new Uint8Array(mailieSeal.magic)),
    label: mailieSeal.label,
    grant_kind: Kind.MailboxGrant,
    content_key_kind: Kind.ContentKey,
    grant_len: GRANT_LEN,
    min_epoch: MIN_EPOCH,
    max_epoch: MAX_EPOCH,
  }),
  'seal.kind_name': async (input) => ({ name: kindName(input.num('kind')) }),
  'mailie.grant_row': async (input) => ({ row: formatUUID(await grantRow(input.str('namespace'), input.str('seal_id'), input.num('epoch'))) }),
  'mailie.grant_info': async (input) => {
    const info = grantInfo(input.str('namespace'), input.num('epoch'))
    return { info_b64: toB64(info), info: new TextDecoder().decode(info) }
  },
  'mailie.grant_aad': async (input) => ({ aad_b64: toB64(await grantAAD(input.str('namespace'), input.str('seal_id'), input.num('epoch'))) }),
  'mailie.grant_seal': async (input, file, c) => {
    const [pub, ns, sealID, epoch, key] = [input.bytes('recipient_public_key_b64'), input.str('namespace'), input.str('seal_id'), input.num('epoch'), input.bytes('mailbox_key_b64')]
    if (!input.has('recipient')) {
      await sealGrant(pub, ns, sealID, epoch, key)
      throw new Error('a refusal sealed')
    }
    // Go's grant, sealed under a seed only Go replays, opened here; then
    // one sealed here, opened here.
    input.seed()
    const recipient = await privateKeyOf(file, input.str('recipient'))
    const mailboxPub = await publicFromPrivate(key)
    const recorded = b64(c.out.grant_b64)
    const ours = await sealGrant(pub, ns, sealID, epoch, key)
    for (const g of [recorded, ours]) {
      checkGrantShape(g, epoch)
      if (!equal(await openGrant(recipient, ns, sealID, epoch, mailboxPub, g), key)) throw new Error('a grant opens to another key')
    }
    return { grant_b64: c.out.grant_b64, mailbox_public_key_b64: toB64(mailboxPub) }
  },
  'mailie.grant_open': async (input, file) => {
    if (input.has('seed')) input.seed()
    const key = await openGrant(
      await privateKeyOf(file, input.str('key')),
      input.str('namespace'),
      input.str('seal_id'),
      input.num('epoch'),
      input.bytes('mailbox_public_key_b64'),
      input.bytes('grant_b64'),
    )
    return { mailbox_key_b64: toB64(key) }
  },
  'mailie.grant_shape': async (input) => {
    checkGrantShape(input.bytes('grant_b64'), input.num('epoch'))
    return { accepted: true }
  },

  // The platform wrap.
  'mailie.product_key': async (input) => {
    const k = await deriveProductKey(input.bytes('root_b64'), 'mailie', input.num('epoch'))
    return { product_key_b64: toB64(k.sk), product_public_key_b64: toB64(k.pub), product_key_id: k.id }
  },
  'mailie.platform_wrap_binding': async (input) => {
    const b = platformWrapBinding(input.str('seal_id'), input.str('sub'), input.num('product_key_epoch'), input.bytes('account_public_key_b64'))
    return { user_id: b.userId, sub: b.sub, product_key_id: b.productKeyId }
  },
  'mailie.platform_wrap_info': async (input) => ({ info_b64: toB64(platformWrapInfo(mailiePlatformWrap, wrapBinding(input))) }),
  'mailie.platform_wrap_aad': async (input) => ({ aad_b64: toB64(platformWrapAAD(mailiePlatformWrap, wrapBinding(input))) }),
  'mailie.platform_wrap_seal': async (input, _, c) => {
    const [sk, accountKey, b, nonce] = [input.bytes('product_key_b64'), input.bytes('account_key_b64'), wrapBinding(input), input.bytes('nonce_b64')]
    if (c.error !== undefined) {
      await sealMailiePlatformWrap(sk, accountKey, b)
      throw new Error('a refusal sealed')
    }
    // Replayed byte for byte from the recorded nonce. K_pw is a
    // non-extractable CryptoKey here; the Go side proves k_pw_b64.
    const wrap = await withDraws({ bytes: [nonce] }, () => sealMailiePlatformWrap(sk, accountKey, b))
    return { wrap_b64: toB64(wrap), k_pw_b64: c.out.k_pw_b64 }
  },
  'mailie.platform_wrap_open': async (input) => ({
    account_key_b64: toB64(await openMailiePlatformWrap(input.bytes('product_key_b64'), input.bytes('wrap_b64'), wrapBinding(input))),
  }),

  // The browser vault.
  'mailie.browser_vault_profile': async () => ({ tag: mailieBrowserVault.tag, version: mailieBrowserVault.version }),
  'mailie.browser_vault_aad': async (input) => ({ aad_b64: toB64(browserVaultAAD(input.str('seal_id'), input.bytes('account_public_key_b64'))) }),
}

/** run runs one case: exactly its output, or its error with its code and reason. */
async function run(file: VectorFile, c: VectorCase): Promise<void> {
  const op = ops[c.op]
  if (!op) throw new Error(`case ${c.id}: op ${c.op} is not handled by the TypeScript tests`)
  const input = new Input(c)
  let out: Out | undefined
  let caught: unknown
  try {
    out = await op(input, file, c)
  } catch (err) {
    caught = err
  }
  expect(input.unread(), `case ${c.id}: members no handler reads`).toEqual([])
  if (c.error !== undefined) {
    if (caught === undefined) expect.fail(`case ${c.id}: no error, want ${c.error} ${c.reason ?? ''}`)
    expect(errorOf(caught), `case ${c.id}`).toEqual(c.reason === undefined ? { code: c.error } : { code: c.error, reason: c.reason })
    return
  }
  if (caught !== undefined) throw caught
  expect(out).toEqual(c.out)
}

for (const want of FILES) {
  const f = load(DIR + want.name)
  describe(DIR + want.name, () => {
    it('is Mailie’s file at c9c79cf, with its counts', () => {
      expect([f.module, f.profile, f.generated_by.lang, f.generated_by.toolchain, f.generated_by.source]).toEqual([
        want.module, 'mailie', 'go', 'go1.27.2', 'github.com/thehappieco/mailie internal/keyscheme',
      ])
      const ts = f.cases.filter(forTS)
      expect([f.cases.length, f.cases.filter((c) => c.error !== undefined).length]).toEqual([want.cases, want.mustFail])
      expect([ts.length, ts.filter((c) => c.error !== undefined).length]).toEqual([want.ts, want.tsMustFail])
    })
    for (const c of f.cases.filter(forTS)) it(c.id, () => run(f, c), 120_000)
  })
}

describe('Mailie’s profile', () => {
  const sealID = 'd1a4c6e8-2b3f-4a5d-9e7f-0a1b2c3d4e5f'

  it('names its values as SPEC Appendix D does', () => {
    expect([PASSWORD_AUTH_LABEL, PASSWORD_WRAP_LABEL, RECOVERY_WRAP_LABEL, RECOVERY_AUTH_LABEL]).toEqual([
      'mailie/v1/password/auth', 'mailie/v1/password/wrap', 'mailie/v1/recovery/wrap', 'mailie/v1/recovery/auth',
    ])
    expect([ACCOUNT_WRAP_TAG, ACCOUNT_WRAP_VERSION, ACCOUNT_WRAP_HEADER, ACCOUNT_WRAP_LEN]).toEqual(['mailie/account-wrap', 1, 0x02, 61])
    expect([Kind.ContentKey, Kind.MailboxGrant, Kind.UserWrap]).toEqual([KIND_CONTENT_KEY, KIND_GRANT, KIND_USER_WRAP])
    expect([String.fromCharCode(...SEAL_MAGIC), SEAL_LABEL, GRANT_LEN, MIN_EPOCH, MAX_EPOCH]).toEqual(['ML', 'mlv1', 88, 1, 65535])
    expect([BROWSER_VAULT_TAG, BROWSER_VAULT_VERSION, SALT_LEN]).toEqual(['mailie/browser-account-key', 1, 16])
    expect(mailiePlatformWrap).toEqual({ product: 'mailie', salt: 'mailie/platform-wrap/v1', label: 'mailie/platform-wrap' })
    expect([kindName(0), kindName(0x0b), kindName(0xff)]).toEqual(['kind(0x0)', 'kind(0xb)', 'kind(0xff)'])
  })

  it('takes from a server only KDF parameters of its bounds, as integers, with no other member', () => {
    expect(checkKDF({ ...DEFAULT_KDF }, new Uint8Array(16) as Bytes)).toEqual(DEFAULT_KDF)
    for (const bad of [{ ...DEFAULT_KDF, m: 65536.5 }, { ...DEFAULT_KDF, extra: 1 }, { ...DEFAULT_KDF, m: 32768 }, null, [], 'argon2id']) {
      expect(() => checkKDF(bad, new Uint8Array(16) as Bytes)).toThrow(expect.objectContaining({ code: 'kdf', reason: 'out_of_bounds' }))
    }
    expect(() => checkKDF({ ...DEFAULT_KDF }, new Uint8Array(15) as Bytes)).toThrow(expect.objectContaining({ code: 'kdf', reason: 'out_of_bounds' }))
  })

  it('refuses a new password under twelve code points before anything is derived, and keeps no minimum for one being presented', () => {
    expect(() => prepareNewPassword('eleven char')).toThrow(expect.objectContaining({ code: 'password_too_short' }))
    expect(() => prepareNewPassword('twelve chars')).not.toThrow()
    expect(() => prepareNewPassword('twelve\u0007chars')).toThrow(expect.objectContaining({ code: 'password_invalid' }))
    expect(() => prepareNewPassword('a'.repeat(257))).toThrow(expect.objectContaining({ code: 'password_too_long' }))
    expect(mailieAccount.prepare!('short')).toEqual(new TextEncoder().encode('short'))
  })

  it('recognises seal ids and namespaces in their one spelling', () => {
    const ns = crypto.randomUUID()
    expect([isNamespace(ns), isSealID(ns)]).toEqual([true, true])
    for (const bad of [ns.toUpperCase(), `{${ns}}`, `urn:uuid:${ns}`, '019a8b2c-3d4e-7f60-8a71-b2c3d4e5f607', '00000000-0000-0000-0000-000000000000', '', 7]) {
      expect([isSealID(bad), isNamespace(bad)]).toEqual([false, false])
    }
  })

  it('wraps a fresh account key that opens under its own binding only, with a fresh nonce', async () => {
    const key = crypto.getRandomValues(new Uint8Array(32)) as Bytes
    const pub = await publicFromPrivate(key)
    const wrapKey = await aesKey(crypto.getRandomValues(new Uint8Array(32)))
    const wrap = await sealAccountWrap('password', wrapKey, key, sealID)
    const again = await sealAccountWrap('password', wrapKey, key, sealID)
    expect([wrap.length, wrap[0], equal(wrap.subarray(1, 13), again.subarray(1, 13))]).toEqual([ACCOUNT_WRAP_LEN, ACCOUNT_WRAP_HEADER, false])
    expect(await openAccountWrap('password', wrapKey, wrap, sealID, pub)).toEqual(key)
    await expect(openAccountWrap('recovery', wrapKey, wrap, sealID, pub)).rejects.toMatchObject({ code: 'wrap', reason: 'wrong_key' })
    await expect(sealAccountWrap('passkey' as WrapKind, wrapKey, key, sealID)).rejects.toSatisfy((e: unknown) => isMailieError(e, 'binding'))
  })

  it('keeps the account key at rest only for the person and the public key it was sealed for', async () => {
    const key = crypto.getRandomValues(new Uint8Array(32)) as Bytes
    const pub = await publicFromPrivate(key)
    const record = await sealBrowserVault(key, pub, sealID)
    expect((await openBrowserVault(record, sealID)).publicRaw).toEqual(pub)
    await expect(openBrowserVault(record, 'd1a4c6e8-2b3f-4a5d-9e7f-0a1b2c3d4e50')).rejects.toMatchObject({ code: 'vault' })
    const other = await publicFromPrivate(crypto.getRandomValues(new Uint8Array(32)) as Bytes)
    await expect(openBrowserVault({ ...record, publicRaw: other }, sealID)).rejects.toMatchObject({ code: 'vault' })
    await expect(openBrowserVault({ ...record, nonce: new Uint8Array(11) as Bytes }, sealID)).rejects.toMatchObject({ code: 'vault' })
    expect(() => browserVaultAAD('ana@example.com', pub)).toThrow(MailieError)
    await expect(sealBrowserVault(key.subarray(0, 31), pub, sealID)).rejects.toMatchObject({ code: 'binding' })
  })

  it('binds the seal id as the platform wrap’s user id, never the sub, and refuses the sub as the seal id whatever its version', async () => {
    const accountKey = crypto.getRandomValues(new Uint8Array(32)) as Bytes
    const pub = await publicFromPrivate(accountKey)
    const subV7 = '019a8b2c-3d4e-7f60-8a71-b2c3d4e5f607'
    const b = platformWrapBinding(sealID, subV7, 1, pub)
    expect([b.userId, b.sub, b.productKeyId]).toEqual([sealID, subV7, 'mailie:1'])
    for (const s of [sealID, subV7]) expect(() => platformWrapBinding(s, s, 1, pub)).toThrow(expect.objectContaining({ code: 'binding' }))
    for (const e of [0, 2 ** 31, 1.5]) expect(() => platformWrapBinding(sealID, subV7, e, pub)).toThrow(expect.objectContaining({ code: 'binding' }))
    const sk = (await deriveProductKey(crypto.getRandomValues(new Uint8Array(32)), 'mailie', 1)).sk
    const wrap = await sealMailiePlatformWrap(sk, accountKey, b)
    expect(await openMailiePlatformWrap(sk, wrap, b)).toEqual(accountKey)
    await expect(openMailiePlatformWrap(sk, wrap, { ...b, userId: subV7 })).rejects.toSatisfy(isPlatformWrapError)
  })

  it('opens a grant only to the mailbox’s key, and never one sealed to a low-order key', async () => {
    const ns = crypto.randomUUID()
    const alice = crypto.getRandomValues(new Uint8Array(32)) as Bytes
    const mailboxKey = crypto.getRandomValues(new Uint8Array(32)) as Bytes
    const g = await sealGrant(await publicFromPrivate(alice), ns, sealID, 3, mailboxKey)
    checkGrantShape(g, 3)
    expect(() => checkGrantShape(g, 4)).toThrow(expect.objectContaining({ code: 'shape' }))
    const priv = await importPrivateKey(alice)
    expect(await openGrant(priv, ns, sealID, 3, await publicFromPrivate(mailboxKey), g)).toEqual(mailboxKey)
    const forged = await sealGrant(await publicFromPrivate(alice), ns, sealID, 3, crypto.getRandomValues(new Uint8Array(32)) as Bytes)
    await expect(openGrant(priv, ns, sealID, 3, await publicFromPrivate(mailboxKey), forged)).rejects.toMatchObject({ code: 'authentication' })
    await expect(sealGrant(new Uint8Array(32), ns, sealID, 1, mailboxKey)).rejects.toMatchObject({ code: 'invalid_key' })
    await expect(grantRow(ns, sealID, 0)).rejects.toSatisfy((e: unknown) => isMailieError(e, 'binding'))
  })
})
