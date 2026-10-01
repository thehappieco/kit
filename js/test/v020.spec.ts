// Vectors captured now for kit v0.2.0, which moves Wappie's attestation
// verifier, AI keychain and derived records into the kit.
//
// The kit does not ship those modules yet, so these tests hold the vectors to
// an independent reference written here from the formats Wappie documents
// (packages/client/src/crypto/{derived,aikeychain,attestation}.ts). When the
// modules move, their own tests must reproduce the same files.

import { createHash, createPrivateKey, createPublicKey, diffieHellman, hkdfSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'

import { b64, forTS, load, raw, toB64, unhandled, utf8 } from './vectors.js'

const hkdf = (ikm: Uint8Array, salt: Uint8Array, info: Uint8Array) => new Uint8Array(hkdfSync('sha256', ikm, salt, info, 32))
const uuidBytes = (s: string) => new Uint8Array(Buffer.from(s.replace(/-/g, ''), 'hex'))
const u16 = (n: number) => new Uint8Array([n >> 8, n & 0xff])
const cat = (...parts: Uint8Array[]) => new Uint8Array(Buffer.concat(parts))

async function gcm(mode: 'encrypt' | 'decrypt', key: Uint8Array, iv: Uint8Array, data: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', new Uint8Array(key), 'AES-GCM', false, [mode])
  return new Uint8Array(await crypto.subtle[mode]({ name: 'AES-GCM', iv: new Uint8Array(iv), additionalData: new Uint8Array(aad) }, k, new Uint8Array(data)))
}

// ---- derived records: "WDRV" || 0x01 || u16be epoch || iv (12) || AES-256-GCM ----

interface Scope { namespace: string; device_id: string; message_uid: string; feature: string; epoch: number }

const derivedAAD = (s: Scope) => utf8(JSON.stringify(['wappie/derived', 1, s.namespace, s.device_id, s.message_uid, s.feature, s.epoch]))
const derivedKey = (dsk: Uint8Array, s: Pick<Scope, 'namespace' | 'device_id' | 'epoch'>, label = 'wappie-derived/v1') =>
  hkdf(dsk, uuidBytes(s.namespace), cat(utf8(label), uuidBytes(s.device_id), u16(s.epoch)))

async function openDerived(dsk: Uint8Array, s: Scope, envelope: Uint8Array): Promise<string> {
  if (Buffer.from(envelope.subarray(0, 4)).toString() !== 'WDRV' || envelope[4] !== 1 || ((envelope[5] << 8) | envelope[6]) !== s.epoch) throw new Error('header')
  return new TextDecoder().decode(await gcm('decrypt', derivedKey(dsk, s), envelope.subarray(7, 19), envelope.subarray(19), derivedAAD(s)))
}

interface DedupeInput { source_sha256: string; feature: string; provider: string; model: string; prompt_version: string; lang?: string }

function dedupeTag(dsk: Uint8Array, s: Pick<Scope, 'namespace' | 'device_id' | 'epoch'>, input: DedupeInput): string {
  const key = derivedKey(dsk, s, 'wappie-ai-dedupe/v1')
  const zero = new Uint8Array([0])
  const message = cat(utf8('wappie-ai-dedupe/v1'), zero, new Uint8Array(Buffer.from(input.source_sha256, 'hex')), zero, utf8(input.feature), zero,
    utf8(input.provider), zero, utf8(input.model), zero, utf8(input.prompt_version), zero, utf8(input.lang ?? ''))
  return Buffer.from(hmac(key, message)).toString('hex')
}

function hmac(key: Uint8Array, data: Uint8Array): Uint8Array {
  // HMAC-SHA256 written out, so the reference shares no code with WebCrypto's.
  const block = 64
  const k = key.length > block ? createHash('sha256').update(key).digest() : Buffer.from(key)
  const pad = (byte: number) => Buffer.from(Array.from({ length: block }, (_, i) => (k[i] ?? 0) ^ byte))
  const inner = createHash('sha256').update(pad(0x36)).update(data).digest()
  return createHash('sha256').update(pad(0x5c)).update(inner).digest()
}

describe('wappie/golden/derived-ts.json', () => {
  const f = load('wappie/golden/derived-ts.json')
  for (const c of f.cases.filter(forTS)) {
    it(c.id, async () => {
      const i = c.in
      switch (c.op) {
        case 'derived.aad':
          expect(toB64(derivedAAD(i.scope))).toBe(c.out.aad_b64)
          return
        case 'derived.seal': {
          const dsk = b64(i.dsk_b64)
          expect(toB64(derivedKey(dsk, i.scope))).toBe(c.out.key_b64)
          const sealed = await gcm('encrypt', derivedKey(dsk, i.scope), b64(i.nonce_b64), utf8(i.plaintext), derivedAAD(i.scope))
          expect(toB64(cat(utf8('WDRV'), new Uint8Array([1]), u16(i.scope.epoch), b64(i.nonce_b64), sealed))).toBe(c.out.envelope_b64)
          expect(await openDerived(dsk, i.scope, b64(c.out.envelope_b64))).toBe(i.plaintext)
          return
        }
        case 'derived.open':
          await expect(openDerived(b64(i.dsk_b64), i.scope, b64(i.envelope_b64))).rejects.toThrow()
          expect(c.error).toBe('invalid_derived')
          return
        case 'derived.dedupe_tag':
          expect(dedupeTag(b64(i.dsk_b64), i.scope, i.input)).toBe(c.out.tag_hex)
          return
      }
      unhandled(c)
    })
  }
})

describe('wappie/legacy/node-derived.json', () => {
  const v = raw('wappie/legacy/node-derived.json')
  const dsk = new Uint8Array(Buffer.from(v.dsk, 'base64url'))
  const scope = (r: { message_uid: string; feature: string }): Scope => ({ namespace: v.namespace, device_id: v.device_id, epoch: v.epoch, message_uid: r.message_uid, feature: r.feature })
  for (const r of v.records) {
    it(`opens ${r.name}`, async () => {
      expect(await openDerived(dsk, scope(r), new Uint8Array(Buffer.from(r.sealed, 'base64url')))).toBe(r.plaintext)
    })
  }
  for (const n of v.negatives) {
    it(`refuses ${n.why}`, async () => {
      await expect(openDerived(dsk, n.scope, new Uint8Array(Buffer.from(n.sealed, 'base64url')))).rejects.toThrow()
    })
  }
  for (const d of v.dedupe) {
    it(`computes the dedupe tag of ${d.name}`, () => expect(dedupeTag(dsk, d.scope, d.input)).toBe(d.tag))
  }
})

// ---- the AI keychain: "WKC1" || iv (12) || AES-256-GCM ----

describe('wappie/golden/keychain-ts.json', () => {
  const f = load('wappie/golden/keychain-ts.json')
  const keyOf = (privB64: string, userID: string) => {
    const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), b64(privB64)]), format: 'der', type: 'pkcs8' })
    return hkdf(diffieHellman({ privateKey: priv, publicKey: createPublicKey(priv) }), utf8(userID), utf8('wappie/ai-keychain/v1'))
  }
  const aadOf = (row: { server_origin: string; user_id: string; id: string; provider: string }) =>
    utf8(JSON.stringify(['wappie/ai-keychain', 1, row.server_origin, row.user_id, row.id, row.provider]))
  for (const c of f.cases.filter(forTS)) {
    it(c.id, async () => {
      const i = c.in
      switch (c.op) {
        case 'keychain.seal': {
          const key = keyOf(i.account_private_key_b64, i.item.user_id)
          expect(toB64(key)).toBe(c.out.key_b64)
          expect(toB64(aadOf(i.item))).toBe(c.out.aad_b64)
          const plaintext = JSON.stringify({ provider: i.item.provider, api_key: i.item.api_key, label: i.item.label, created_at: i.item.created_at })
          expect(plaintext).toBe(c.out.plaintext)
          const sealed = await gcm('encrypt', key, b64(i.nonce_b64), utf8(plaintext), aadOf(i.item))
          expect(toB64(cat(utf8('WKC1'), b64(i.nonce_b64), sealed))).toBe(c.out.envelope_b64)
          return
        }
        case 'keychain.open': {
          const env = b64(i.envelope_b64)
          await expect(gcm('decrypt', keyOf(i.account_private_key_b64, i.row.user_id), env.subarray(4, 16), env.subarray(16), aadOf(i.row))).rejects.toThrow()
          expect(c.error).toBe('invalid_keychain_item')
          return
        }
      }
      unhandled(c)
    })
  }
})

// ---- attestation user_data: SHA-256 of the label and five fields joined by 0x00 ----

describe('wappie/golden/attestation-ts.json', () => {
  const f = load('wappie/golden/attestation-ts.json')
  const fields = ['request_id', 'resource', 'tls_spki_sha256', 'policy_sha256', 'reader_version'] as const
  const userData = (x: Record<string, string>) => {
    if (fields.some(name => x[name].includes('\0'))) return 'attestation_user_data'
    if (!/^[0-9]+\.[0-9]+\.[0-9]+$/.test(x.reader_version)) return 'attestation_version'
    if (!/^[0-9a-f]{64}$/.test(x.tls_spki_sha256) || !/^[0-9a-f]{64}$/.test(x.policy_sha256)) return 'attestation_user_data'
    return createHash('sha256').update(['wappie-mcp-attest/v1', ...fields.map(name => x[name])].join('\0')).digest('hex')
  }
  for (const c of f.cases.filter(forTS)) {
    it(c.id, () => {
      if (c.op !== 'attestation.user_data') unhandled(c)
      expect(userData(c.in.fields)).toBe(c.error ?? c.out.user_data_hex)
    })
  }
})
