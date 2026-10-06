import { describe, expect, it, vi } from 'vitest'

import {
  AccountError, bind, checkKDFParams, checkSalt, defaultKDFParams, derive, derivePrepared, freshSalt, generateAccountKeys, newRecoveryCode,
  normaliseRecoveryCode, recoveryKey, recoveryProof, unwrapPrivateKey, wrapPrivateKey, type AccountProfile, type KDFBounds, type KDFParams,
} from '../src/account.js'
import { type Bytes } from '../src/bytes.js'
import { accountWrapAAD, wappieAccount } from '../src/profiles/wappie.js'
import { runKDFMessage } from '../src/internal/kdfrun.js'
import { fakeKDFWorker } from './kdfworkerfake.js'
import { b64, files, forTS, toB64, unhandled, utf8, withDraws } from './vectors.js'

/** The bounds a case gives Wappie's profile, which has none of its own. */
function bounded(b?: { min: KDFBounds['min']; max: KDFBounds['max']; max_cost?: number; min_salt_len?: number; max_salt_len?: number }): AccountProfile {
  if (!b) return wappieAccount
  return { ...wappieAccount, bounds: { min: b.min, max: b.max, maxCost: b.max_cost, minSaltLen: b.min_salt_len, maxSaltLen: b.max_salt_len } }
}

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
            const q = bounded(i.bounds)
            if (c.error) {
              expect(await failure(() => derive(q, i.password, b64(i.salt_b64), i.params))).toEqual({ error: c.error, reason: c.reason })
              return
            }
            const d = await derive(q, i.password, b64(i.salt_b64), i.params)
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

describe('zeroisation', () => {
  it('zeroes the prepared password after deriving, and after a failure', async () => {
    const seen: Bytes[] = []
    const keeping: AccountProfile = { ...p, prepare: (pw) => { const b = utf8(pw); seen.push(b); return b } }
    const salt = new Uint8Array(16).fill(4) as Bytes
    const d = await derive(keeping, 'senha correta', salt, cheap)
    expect(d.authKey).toBe((await derive(p, 'senha correta', salt, cheap)).authKey)
    expect(await failure(() => derive(keeping, 'senha correta', new Uint8Array(4) as Bytes, cheap))).toEqual({ error: 'kdf', reason: 'kdf_failed' })
    expect(seen.length).toBe(2)
    for (const b of seen) expect(b.every((x) => x === 0)).toBe(true)
  })

  it('zeroes the raw auth key once it is text, and the recovery proof once it is text', async () => {
    const outputs: ArrayBuffer[] = []
    const real = crypto.subtle.deriveBits.bind(crypto.subtle)
    const spy = vi.spyOn(crypto.subtle, 'deriveBits').mockImplementation(async (...args: Parameters<SubtleCrypto['deriveBits']>) => {
      const out = await real(...args)
      outputs.push(out)
      return out
    })
    try {
      const salt = new Uint8Array(16).fill(8) as Bytes
      for (const run of [() => derive(p, 'senha correta', salt, cheap), () => derivePrepared(p, utf8('senha correta'), salt, cheap)]) {
        outputs.length = 0
        expect((await run()).authKey.length).toBe(44)
        expect(outputs.length).toBe(2)
        for (const o of outputs) expect(new Uint8Array(o).every((x) => x === 0)).toBe(true)
      }
      outputs.length = 0
      expect((await recoveryProof(p, '01234-56789-ABCDE-FGHJK-MNPQR-STVWX')).length).toBe(44)
      expect(outputs.length).toBe(1)
      expect(new Uint8Array(outputs[0]!).every((x) => x === 0)).toBe(true)
    } finally {
      spy.mockRestore()
    }
  })

  it('zeroes what the worker was sent: the transferred copy in the worker, the caller\'s copy here', async () => {
    const { state, factory } = fakeKDFWorker()
    const seen: Bytes[] = []
    const keeping: AccountProfile = { ...p, prepare: (pw) => { const b = utf8(pw); seen.push(b); return b } }
    await derive(keeping, 'senha correta', new Uint8Array(16).fill(6) as Bytes, cheap, { worker: factory })
    expect(state.passwords.length).toBe(1)
    expect(state.passwords[0]!.length).toBeGreaterThan(0)
    expect(state.passwords[0]!.every((x) => x === 0)).toBe(true)
    expect(seen[0]!.every((x) => x === 0)).toBe(true)
  })
})

describe('the Argon2id worker', () => {
  const direct = async (password: string, salt: Bytes) => (await derive(p, password, salt, cheap)).authKey

  it('is used when a factory is given: a hello, then the password, and its output is what direct derivation gives', async () => {
    const salt = new Uint8Array(16).fill(1) as Bytes
    const { state, factory } = fakeKDFWorker()
    const viaWorker = await derive(p, 'senha correta', salt, cheap, { worker: factory })
    expect(state.started).toBe(1)
    expect(state.terminated).toBe(1)
    expect(state.received.length).toBe(2)
    expect(state.received[0]).toEqual({ v: 2 })
    expect(state.answers[0]).toEqual({ ready: true, v: 2 })
    expect(state.received[1]).toMatchObject({ v: 2, params: { alg: 'argon2id', m: 8, t: 1, p: 1 } })
    expect((state.received[1] as Record<string, unknown>).bounds).toBeUndefined()
    expect(viaWorker.authKey).toBe(await direct('senha correta', salt))
  })

  it('tells the worker the profile\'s bounds, which it checks again', async () => {
    const bounded: AccountProfile = { ...p, bounds: { min: { m: 8, t: 1, p: 1 }, max: { m: 64, t: 2, p: 1 }, maxCost: 64, minSaltLen: 16, maxSaltLen: 16 } }
    const { state, factory } = fakeKDFWorker()
    const salt = new Uint8Array(16).fill(1) as Bytes
    expect((await derive(bounded, 'senha correta', salt, cheap, { worker: factory })).authKey).toBe(await direct('senha correta', salt))
    expect(state.received[1]).toMatchObject({ bounds: { min: { m: 8, t: 1, p: 1 }, max: { m: 64, t: 2, p: 1 }, maxCost: 64, minSaltLen: 16, maxSaltLen: 16 } })
  })

  it('derives on the calling thread when the worker fails before it was sent the password', async () => {
    const salt = new Uint8Array(16).fill(2) as Bytes
    const want = await direct('x', salt)
    for (const o of [{ failToLoad: true }, { hello: { ok: false, error: 'not a password' } }, { hello: { ready: true } }, { hello: { ready: true, v: 3 } }, { hello: 'ready' }]) {
      const w = fakeKDFWorker(o)
      expect((await derive(p, 'x', salt, cheap, { worker: w.factory })).authKey, JSON.stringify(o)).toBe(want)
      // Set aside before it saw the password, and terminated.
      expect(w.state.received, JSON.stringify(o)).toEqual([{ v: 2 }])
      expect(w.state.terminated).toBe(1)
    }
    // A factory that throws, as where module workers are not supported.
    expect((await derive(p, 'x', salt, cheap, { worker: () => { throw new Error('no workers') } })).authKey).toBe(want)
    // A worker whose postMessage throws.
    const refusing = { postMessage() { throw new Error('no') }, terminate() {}, onmessage: null, onerror: null } as unknown as Worker
    expect((await derive(p, 'x', salt, cheap, { worker: () => refusing })).authKey).toBe(want)
  })

  it('derives on the calling thread when the worker never answers the hello', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    try {
      const salt = new Uint8Array(16).fill(3) as Bytes
      const silent = fakeKDFWorker({ silent: true })
      const pending = derive(p, 'x', salt, cheap, { worker: silent.factory })
      await vi.advanceTimersByTimeAsync(9_999)
      expect(silent.state.terminated).toBe(0)
      await vi.advanceTimersByTimeAsync(2)
      const d = await pending
      expect(silent.state.received).toEqual([{ v: 2 }])
      expect(silent.state.terminated).toBe(1)
      vi.useRealTimers()
      expect(d.authKey).toBe(await direct('x', salt))
    } finally {
      vi.useRealTimers()
    }
  })

  it('waits for a derivation that takes longer than the hello may: only the hello is timed', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    try {
      const salt = new Uint8Array(16).fill(5) as Bytes
      const { argon2id } = await import('@noble/hashes/argon2.js')
      const master = argon2id(utf8('x'), salt, { ...cheap, dkLen: 32 })
      let answer: ((e: MessageEvent) => void) | undefined
      const slow = {
        onmessage: null as ((e: MessageEvent) => void) | null, onerror: null, onmessageerror: null, posted: [] as unknown[],
        postMessage(msg: Record<string, unknown>) {
          this.posted.push(msg)
          if (!('prepared' in msg)) setTimeout(() => this.onmessage?.({ data: { ready: true, v: 2 } } as MessageEvent), 0)
          else answer = (e) => this.onmessage?.(e)
        },
        terminate() {},
      }
      const pending = derive(p, 'x', salt, cheap, { worker: () => slow as unknown as Worker })
      await vi.advanceTimersByTimeAsync(60_000)
      expect(slow.posted.length).toBe(2)
      answer!({ data: { ok: true, master } } as MessageEvent)
      const d = await pending
      vi.useRealTimers()
      expect(d.authKey).toBe(await direct('x', salt))
    } finally {
      vi.useRealTimers()
    }
  })

  // The parameters are good, so a derivation on the calling thread would
  // succeed: kdf_failed shows the page did not derive again.
  it('fails with kdf_failed, and does not derive again, when the worker fails after it was sent the password', async () => {
    const salt = new Uint8Array(16).fill(4) as Bytes
    for (const o of [{ dieAfterSend: true }, { unreadableAnswer: true }, { answer: { ok: false, reason: 'kdf_failed' } }, { answer: { ok: true, master: new Uint8Array(31) } }, { answer: 'done' }]) {
      const w = fakeKDFWorker(o)
      expect(await failure(() => derive(p, 'x', salt, cheap, { worker: w.factory })), JSON.stringify(o)).toEqual({ error: 'kdf', reason: 'kdf_failed' })
      expect(w.state.passwords[0]!.every((x) => x === 0)).toBe(true)
      expect(w.state.terminated).toBe(1)
    }
  })

  it('reports the worker\'s refusal of the parameters as the account module\'s reason', async () => {
    const salt = new Uint8Array(16).fill(4) as Bytes
    for (const reason of ['out_of_bounds', 'unsupported_alg'] as const) {
      const w = fakeKDFWorker({ answer: { ok: false, reason } })
      expect(await failure(() => derive(p, 'x', salt, cheap, { worker: w.factory }))).toEqual({ error: 'kdf', reason })
    }
  })
})

describe('the KDF worker\'s handler', () => {
  it('answers the hello with ready, and nothing else unasked', () => {
    expect(runKDFMessage({ v: 2 })).toEqual({ response: { ready: true, v: 2 }, transfer: [] })
  })

  it('derives what direct derivation gives, into a buffer of its own, and zeroes the password it received', async () => {
    const { argon2id } = await import('@noble/hashes/argon2.js')
    const salt = new Uint8Array(16).fill(9) as Bytes
    const prepared = utf8('senha correta')
    const r = runKDFMessage({ v: 2, prepared, salt, params: cheap })
    expect(prepared.every((x) => x === 0)).toBe(true)
    const master = (r.response as { master: Uint8Array }).master
    expect(toB64(master)).toBe(toB64(argon2id(utf8('senha correta'), salt, { ...cheap, dkLen: 32 })))
    expect(master.buffer.byteLength).toBe(32)
    expect(r.transfer).toEqual([master.buffer])
  })

  it('checks the parameters and the bounds again, and tells a refusal from a failure', () => {
    const salt = new Uint8Array(16) as Bytes
    const bounds = { min: { m: 16, t: 1, p: 1 }, max: { m: 64, t: 2, p: 1 }, maxCost: 64, minSaltLen: 16, maxSaltLen: 16 }
    const cases: [unknown, unknown, Bytes, string][] = [
      [{ ...cheap, alg: 'argon2i' }, undefined, salt, 'unsupported_alg'],
      [{ ...cheap, alg: 'ARGON2ID' }, undefined, salt, 'unsupported_alg'],
      ['argon2id', undefined, salt, 'unsupported_alg'],
      [cheap, bounds, salt, 'out_of_bounds'],
      [{ ...cheap, m: 65 }, bounds, salt, 'out_of_bounds'],
      [{ ...cheap, m: 64, t: 2 }, bounds, salt, 'out_of_bounds'],
      [{ ...cheap, m: 16, p: 2 }, bounds, salt, 'out_of_bounds'],
      [{ ...cheap, m: 16 }, bounds, new Uint8Array(15) as Bytes, 'out_of_bounds'],
      [{ ...cheap, m: 16 }, { min: { m: 16 }, max: {} }, salt, 'out_of_bounds'],
      [{ ...cheap, m: 16 }, 'none', salt, 'out_of_bounds'],
      [{ ...cheap, m: 16 }, null, salt, 'out_of_bounds'],
      [{ ...cheap, m: 8.5 }, undefined, salt, 'kdf_failed'],
      [{ ...cheap, t: '1' }, undefined, salt, 'kdf_failed'],
      [{ ...cheap, p: -1 }, undefined, salt, 'kdf_failed'],
      [{ ...cheap, t: 0 }, undefined, salt, 'kdf_failed'],
      [cheap, undefined, new Uint8Array(4) as Bytes, 'kdf_failed'],
    ]
    for (const [params, b, s, reason] of cases) {
      const prepared = utf8('x')
      expect(runKDFMessage({ v: 2, prepared, salt: s, params, bounds: b }).response, JSON.stringify([params, b])).toEqual({ ok: false, reason })
      expect(prepared.every((x) => x === 0)).toBe(true)
    }
    expect(runKDFMessage({ v: 2, prepared: 'x', salt, params: cheap }).response).toEqual({ ok: false, reason: 'kdf_failed' })
    expect(runKDFMessage({ v: 2, prepared: utf8('x'), salt: [1, 2], params: cheap }).response).toEqual({ ok: false, reason: 'kdf_failed' })
    expect(runKDFMessage({ v: 2, prepared: utf8('x'), salt, params: { ...cheap, m: 16 }, bounds }).response).toMatchObject({ ok: true })
  })

  it('still answers version 1 as in v0.1.0', async () => {
    const { argon2id } = await import('@noble/hashes/argon2.js')
    const salt = new Uint8Array(16).fill(9) as Bytes
    const password = utf8('senha correta')
    const r = runKDFMessage({ password, salt, m: 8, t: 1, p: 1 })
    expect(toB64((r.response as { master: Uint8Array }).master)).toBe(toB64(argon2id(utf8('senha correta'), salt, { ...cheap, dkLen: 32 })))
    expect(password.every((x) => x === 0)).toBe(true)
    expect(toB64((runKDFMessage({ password: 'senha correta', salt, m: 8, t: 1, p: 1 }).response as { master: Uint8Array }).master)).toBe(toB64((r.response as { master: Uint8Array }).master))
    expect(runKDFMessage({ password: 'x', salt: new Uint8Array(4), m: 8, t: 1, p: 1 }).response).toMatchObject({ ok: false, error: expect.any(String) })
    expect(runKDFMessage(undefined).response).toMatchObject({ ok: false, error: expect.any(String) })
  })
})

// In a browser (the js-browser job): kdf.worker.ts itself, as a module worker.
describe.skipIf(typeof Worker === 'undefined')('the Argon2id worker module', () => {
  it('derives off the main thread what direct derivation gives, after a ready', async () => {
    const replies: Record<string, unknown>[] = []
    const worker = () => {
      const w = new Worker(new URL('../src/kdf.worker.ts', import.meta.url), { type: 'module' })
      w.addEventListener('message', (e: MessageEvent<Record<string, unknown>>) => replies.push(e.data))
      return w
    }
    const salt = new Uint8Array(16).fill(7) as Bytes
    const { argon2id } = await import('@noble/hashes/argon2.js')
    const master = argon2id(utf8('senha correta'), salt, { ...cheap, dkLen: 32 }) as Bytes
    const auth = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8(p.authLabel) },
      await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveBits']), 256)
    const d = await derive(p, 'senha correta', salt, cheap, { worker })
    expect(replies.map((r) => (r.ready === true && r.v === 2 ? 'ready' : r.ok))).toEqual(['ready', true])
    expect(d.authKey).toBe(toB64(new Uint8Array(auth)))
  })

  it('answers version 1 as in v0.1.0, and posts nothing unasked', async () => {
    const w = new Worker(new URL('../src/kdf.worker.ts', import.meta.url), { type: 'module' })
    try {
      const replies: Record<string, unknown>[] = []
      const salt = new Uint8Array(16).fill(7) as Bytes
      const got = new Promise<void>((resolve) => w.addEventListener('message', (e: MessageEvent<Record<string, unknown>>) => { replies.push(e.data); resolve() }))
      w.postMessage({ password: utf8('senha correta'), salt, m: 8, t: 1, p: 1 })
      await got
      await new Promise((r) => setTimeout(r, 50))
      const { argon2id } = await import('@noble/hashes/argon2.js')
      expect(replies.length).toBe(1)
      expect(replies[0]!.ok).toBe(true)
      expect(toB64(replies[0]!.master as Uint8Array)).toBe(toB64(argon2id(utf8('senha correta'), salt, { ...cheap, dkLen: 32 })))
    } finally {
      w.terminate()
    }
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

  it('enforces a salt length, the platform\'s policy, before deriving', async () => {
    const fixed: AccountProfile = { ...other, bounds: { ...other.bounds!, minSaltLen: 16, maxSaltLen: 16 } }
    for (const n of [8, 15, 17, 32]) {
      expect(() => checkSalt(fixed, new Uint8Array(n) as Bytes)).toThrow(AccountError)
      expect(await failure(() => derive(fixed, 'long enough password', new Uint8Array(n).fill(5) as Bytes, cheap))).toEqual({ error: 'kdf', reason: 'out_of_bounds' })
    }
    expect((await derive(fixed, 'long enough password', salt, cheap)).authKey).toBe((await derive(other, 'long enough password', salt, cheap)).authKey)
    // Without the bound, Argon2id takes any salt of 8 bytes or more.
    expect((await derive(other, 'long enough password', new Uint8Array(9) as Bytes, cheap)).authKey).toMatch(/^[A-Za-z0-9_-]{43}$/)
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

describe('derivePrepared', () => {
  const salt = new Uint8Array(16).fill(8) as Bytes

  it('is derive without the preparation, and leaves the caller\'s bytes alone', async () => {
    const prepared = utf8('senha correta')
    const d = await derivePrepared(p, prepared, salt, cheap)
    expect(d.authKey).toBe((await derive(p, 'senha correta', salt, cheap)).authKey)
    expect(new TextDecoder().decode(prepared)).toBe('senha correta')
    const upper: AccountProfile = { ...p, prepare: (pw) => utf8(pw.toUpperCase()) }
    expect((await derivePrepared(upper, utf8('SENHA CORRETA'), salt, cheap)).authKey).toBe((await derive(upper, 'senha correta', salt, cheap)).authKey)
    expect((await derivePrepared(upper, utf8('senha correta'), salt, cheap)).authKey).not.toBe((await derive(upper, 'senha correta', salt, cheap)).authKey)
    expect((await bind(p).derivePrepared(prepared, salt, cheap)).authKey).toBe(d.authKey)
  })

  it('refuses what derive refuses, before starting a worker', async () => {
    const bounded: AccountProfile = { ...p, bounds: { min: { m: 8, t: 1, p: 1 }, max: { m: 1024, t: 3, p: 1 }, maxCost: 2048, minSaltLen: 16, maxSaltLen: 16 } }
    let started = 0
    const worker = () => { started++; throw new Error('no worker here') }
    for (const [s, params, want] of [
      [salt, { ...cheap, alg: 'argon2i' }, { error: 'kdf', reason: 'unsupported_alg' }],
      [salt, { ...cheap, m: 2048 }, { error: 'kdf', reason: 'out_of_bounds' }],
      [salt.subarray(0, 15) as Bytes, cheap, { error: 'kdf', reason: 'out_of_bounds' }],
    ] as [Bytes, KDFParams, { error: string; reason: string }][]) {
      expect(await failure(() => derivePrepared(bounded, utf8('x'), s, params, { worker }))).toEqual(want)
      expect(await failure(() => derive(bounded, 'x', s, params, { worker }))).toEqual(want)
    }
    expect(started).toBe(0)
  })
})
