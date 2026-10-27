import { describe, expect, it } from 'vitest'

import { encodeUTF8, toHex } from '../src/bytes.js'
import { Base64Error, FINGERPRINT_LENGTH, READING_KEY_LABEL, readingKeyFingerprint } from '../src/contract.js'
import { canonicalJSON } from '../src/jcs.js'
import { raw } from './vectors.js'

// The contract's format (vectors/README.md, "The contract's format"):
// reading-keys.json, which Go writes, read here for the one function the
// TypeScript mirrors. Bundled like every other file, so it runs in the
// browsers too.
const f = raw('platform/contract-v1/reading-keys.json') as {
  format: string
  version: number
  kind: string
  label: string
  reading_keys: { name: string; key: string; fingerprint: string; result: string }[]
}

describe('platform/contract-v1/reading-keys.json', () => {
  it('is the contract format, under the label', () => {
    expect([f.format, f.version, f.kind, f.label]).toEqual(['thehappie-contract/vectors', 1, 'reading-keys', READING_KEY_LABEL])
    expect(f.reading_keys.length).toBeGreaterThan(0)
  })

  for (const c of f.reading_keys) {
    it(`${c.result}: ${c.name}`, async () => {
      switch (c.result) {
        case 'encoding':
          // A key that is not the one spelling of 32 bytes has no fingerprint.
          await expect(readingKeyFingerprint(c.key)).rejects.toBeInstanceOf(Base64Error)
          expect(c.fingerprint).toBe('')
          return
        case 'fingerprint': {
          // The pair is refused: the fingerprint beside the key is not its own.
          const fp = await readingKeyFingerprint(c.key)
          expect(fp).not.toBe(c.fingerprint)
          expect(fp).toHaveLength(FINGERPRINT_LENGTH)
          return
        }
        default:
          // ok, not_canonical and low_order: the fingerprint is the key's own;
          // what else is wrong with the key is Go's to refuse.
          expect(await readingKeyFingerprint(c.key)).toBe(c.fingerprint)
      }
    })
  }

  it('never repeats the key in its refusal', async () => {
    const key = f.reading_keys.find((c) => c.result === 'ok')!.key
    const err = await readingKeyFingerprint(key + '=').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(Base64Error)
    expect(String((err as Error).message)).not.toContain(key.slice(0, 8))
  })
})

// command-macs.json, which Go writes (SPEC section 11.19): the TypeScript
// mirrors no part of the settings part, and checks no command's MAC, since
// both apps' contract clients are servers; but a command's MAC covers its
// canonical text, RFC 8785, which this package's canonicalJSON writes as
// Go's jcs does. So every canonical text, and every MAC over it, is
// reproduced here from the command as received, through a generic decode,
// as an app does, and with WebCrypto's HMAC.
const macs = raw('platform/contract-v1/command-macs.json') as {
  format: string
  version: number
  kind: string
  label: string
  macs: { name: string; app: string; secrets: string[]; command: string; jcs: string; mac: string; valid: boolean }[]
}

describe('platform/contract-v1/command-macs.json', () => {
  it('is the contract format, under the label', () => {
    expect([macs.format, macs.version, macs.kind, macs.label]).toEqual([
      'thehappie-contract/vectors',
      1,
      'command-macs',
      'thehappie-platform-command/v1',
    ])
    expect(macs.macs.length).toBeGreaterThan(0)
  })

  for (const c of macs.macs.filter((c) => c.jcs !== '')) {
    it(`the canonical text and MAC: ${c.name}`, async () => {
      const { mac: _mac, ...rest } = JSON.parse(c.command) as Record<string, unknown>
      expect(canonicalJSON(rest)).toBe(c.jcs)
      const key = await crypto.subtle.importKey('raw', encodeUTF8(c.secrets[0]!), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
      const sum = new Uint8Array(await crypto.subtle.sign('HMAC', key, encodeUTF8(`${macs.label}\n${c.app}\n${c.jcs}`)))
      expect(`v1=${toHex(sum)}`).toBe(c.mac)
    })
  }
})
