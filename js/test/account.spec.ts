import { describe, expect, it } from 'vitest'

import {
  AccountError, bind, checkKDFParams, defaultKDFParams, derive, freshSalt, generateAccountKeys, newRecoveryCode,
  normaliseRecoveryCode, recoveryKey, recoveryProof, unwrapPrivateKey, wrapPrivateKey, type AccountProfile, type KDFParams,
} from '../src/account.js'
import { type Bytes } from '../src/bytes.js'
import { accountWrapAAD, wappieAccount } from '../src/profiles/wappie.js'
import { b64, files, forTS, toB64, unhandled, utf8, withDraws } from './vectors.js'

const p = wappieAccount
const cheap: KDFParams = { alg: 'argon2id', m: 8, t: 1, p: 1 }

async function failure(fn: () => unknown): Promise<{ error: string; reason?: string }> {
  try {
    await fn()
  } catch (err) {
    if (err instanceof AccountError) return { error: err.code, reason: err.reason }
    return { error: `${(err as Error).name}: ${(err as Error).message}` }
  }
  return { error: 'none' }
}

const aesKey = (raw: Bytes) => crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])

for (const [path, f] of files('wappie/golden/account-ts.json', 'kit/account-go.json')) {
  describe(path, () => {
    for (const c of f.cases.filter(forTS)) {
      it(c.id, async () => {
        const i = c.in
        switch (c.op) {
          case 'account.default_kdf_params':
            expect(defaultKDFParams).toEqual(c.out.params)
            return
          case 'account.derive': {
            if (c.error) {
              expect(await failure(() => derive(p, i.password, b64(i.salt_b64), i.params))).toEqual({ error: c.error, reason: c.reason })
              return
            }
            const d = await derive(p, i.password, b64(i.salt_b64), i.params)
            expect(d.authKey).toBe(c.out.auth_key)
            // The wrap key is non-extractable; it must seal what the recorded bytes seal.
            const nonce = new Uint8Array(12).fill(7)
            const probe = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, d.wrapKey, new Uint8Array(4))
            const want = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, await aesKey(b64(c.out.wrap_b64)), new Uint8Array(4))
            expect(toB64(new Uint8Array(probe))).toBe(toB64(new Uint8Array(want)))
            return
          }
          case 'account.wrap_aad':
            expect(toB64(accountWrapAAD(i.email))).toBe(c.out.aad_b64)
            return
          case 'account.wrap': {
            const key = await aesKey(b64(i.wrap_key_b64))
            const blob = await withDraws({ bytes: [b64(i.nonce_b64)] }, () => wrapPrivateKey(p, b64(i.private_key_b64), key, accountWrapAAD(i.email)))
            expect(toB64(blob)).toBe(c.out.blob_b64)
            const back = await unwrapPrivateKey(p, blob, key, accountWrapAAD(i.email))
            expect([toB64(back.privateKey), back.stale]).toEqual([i.private_key_b64, false])
            return
          }
          case 'account.unwrap': {
            const attempt = async () => unwrapPrivateKey(p, b64(i.blob_b64), await aesKey(b64(i.wrap_key_b64)), accountWrapAAD(i.email))
            if (c.error) {
              expect(await failure(attempt)).toEqual({ error: c.error, reason: c.reason })
              return
            }
            const back = await attempt()
            expect([toB64(back.privateKey), back.stale]).toEqual([c.out.private_key_b64, c.out.stale])
            return
          }
          case 'account.recovery_code':
            expect(await withDraws({ bytes: [b64(i.random_b64)] }, newRecoveryCode)).toBe(c.out.code)
            return
          case 'account.normalise_recovery_code':
            if (c.error) expect(await failure(() => normaliseRecoveryCode(i.code))).toEqual({ error: c.error, reason: c.reason })
            else expect(normaliseRecoveryCode(i.code)).toBe(c.out.code)
            return
          case 'account.recovery_key': {
            // Non-extractable: it must seal what the recorded bytes seal.
            const nonce = new Uint8Array(12).fill(3)
            const a = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, await recoveryKey(p, i.code), new Uint8Array(4))
            const b = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, await aesKey(b64(c.out.key_b64)), new Uint8Array(4))
            expect(toB64(new Uint8Array(a))).toBe(toB64(new Uint8Array(b)))
            return
          }
          case 'account.recovery_proof':
            if (c.error) expect(await failure(() => recoveryProof(p, i.code))).toEqual({ error: c.error, reason: c.reason })
            else expect(await recoveryProof(p, i.code)).toBe(c.out.proof)
            return
          case 'account.generate_keys': {
            const keys = await withDraws({ x25519: [b64(i.x25519_private_key_b64)] }, generateAccountKeys)
            expect([toB64(keys.privateKey), toB64(keys.publicKey)]).toEqual([c.out.private_key_b64, c.out.public_key_b64])
            return
          }
          case 'account.fresh_salt':
            expect(toB64(await withDraws({ bytes: [b64(i.random_b64)] }, freshSalt))).toBe(c.out.salt_b64)
            return
        }
        unhandled(c)
      })
    }
  })
}

describe('the Argon2id worker', () => {
  it('is used when a factory is given, and its output is what direct derivation gives', async () => {
    const salt = new Uint8Array(16).fill(1) as Bytes
    const posted: unknown[] = []
    const { argon2id } = await import('@noble/hashes/argon2.js')
    // A stand-in Worker: answers like kdf.worker.ts does.
    const fake = {
      onmessage: null as ((e: MessageEvent) => void) | null,
      onerror: null as (() => void) | null,
      postMessage(msg: { password: Uint8Array; salt: Uint8Array; m: number; t: number; p: number }) {
        posted.push(msg)
        const master = argon2id(msg.password, msg.salt, { m: msg.m, t: msg.t, p: msg.p, dkLen: 32 })
        queueMicrotask(() => this.onmessage?.({ data: { ok: true, master } } as MessageEvent))
      },
      terminate() {},
    }
    const viaWorker = await derive(p, 'senha correta', salt, cheap, { worker: () => fake as unknown as Worker })
    const direct = await derive(p, 'senha correta', salt, cheap)
    expect(posted.length).toBe(1)
    expect(viaWorker.authKey).toBe(direct.authKey)
  })

  it('falls back to direct derivation when the worker fails', async () => {
    const broken = { postMessage() { queueMicrotask(() => this.onerror?.()) }, terminate() {}, onmessage: null, onerror: null as (() => void) | null }
    const salt = new Uint8Array(16).fill(2) as Bytes
    const d = await derive(p, 'x', salt, cheap, { worker: () => broken as unknown as Worker })
    expect(d.authKey).toBe((await derive(p, 'x', salt, cheap)).authKey)
  })
})

describe('another profile', () => {
  // Shaped like the platform's draft: own labels, a two-byte header, bounds,
  // base64url text, a password preparation, no legacy form.
  const other: AccountProfile = {
    authLabel: 'test/v1/password/auth', wrapLabel: 'test/v1/password/wrap',
    recoveryKeyLabel: 'test/v1/recovery/wrap', recoveryProofLabel: 'test/v1/recovery/auth',
    wrapHeader: [0x01, 0x01], legacyV1: false, encoding: 'base64url',
    prepare: (pw) => { if (pw.length < 12) throw new Error('short'); return utf8(pw.normalize('NFC')) },
    bounds: { min: { m: 8, t: 1, p: 1 }, max: { m: 1024, t: 3, p: 1 }, maxCost: 2048 },
  }
  const salt = new Uint8Array(16).fill(5) as Bytes

  it('enforces its bounds and its password rules before deriving', async () => {
    expect(() => checkKDFParams(other, { ...cheap, m: 4096 })).toThrow(AccountError)
    expect(await failure(() => derive(other, 'long enough password', salt, { ...cheap, m: 1024, t: 3 }))).toEqual({ error: 'kdf', reason: 'out_of_bounds' })
    expect(await failure(() => derive(other, 'short', salt, cheap))).toEqual({ error: 'password', reason: 'rejected' })
  })

  it('derives its own keys, prepared, and wraps with its header', async () => {
    const decomposed = await derive(other, 'pa\u0308ssword long', salt, cheap)
    const composed = await derive(other, 'p\u00e4ssword long', salt, cheap)
    expect(decomposed.authKey).toBe(composed.authKey)
    expect(decomposed.authKey).toMatch(/^[A-Za-z0-9_-]{43}$/)
    // Wappie's profile prepares nothing, so its two spellings differ.
    expect((await derive(p, 'p\u00e4ssword long', salt, cheap)).authKey).not.toBe((await derive(p, 'pa\u0308ssword long', salt, cheap)).authKey)
    const a = bind(other)
    const blob = await a.wrapPrivateKey(new Uint8Array(32).fill(3) as Bytes, decomposed.wrapKey, utf8('aad'))
    expect(Array.from(blob.subarray(0, 2))).toEqual([1, 1])
    expect(blob.length).toBe(62)
    expect((await a.unwrapPrivateKey(blob, decomposed.wrapKey, utf8('aad'))).stale).toBe(false)
    expect(await failure(() => a.unwrapPrivateKey(blob.subarray(2) as Bytes, decomposed.wrapKey, utf8('aad')))).toEqual({ error: 'wrap', reason: 'wrong_key' })
    expect(await failure(() => a.unwrapPrivateKey(blob.subarray(0, 20) as Bytes, decomposed.wrapKey, utf8('aad')))).toEqual({ error: 'wrap', reason: 'truncated' })
    expect(await a.recoveryProof('A'.repeat(30))).toMatch(/^[A-Za-z0-9_-]{43}$/)
  })
})
