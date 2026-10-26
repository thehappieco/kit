import { describe, expect, it } from 'vitest'

import { Base64Error, FINGERPRINT_LENGTH, READING_KEY_LABEL, readingKeyFingerprint } from '../src/contract.js'
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
