import { describe, expect, it, vi } from 'vitest'

import { generateAccountKeys } from '../src/account.js'
import { browserAccountAAD, openBrowserAccountKey, sealBrowserAccountKey, validBrowserKeyEnvelope } from '../src/browserAccount.js'
import { CanonicalJSONError } from '../src/jcs.js'
import { wappieBrowserAccount } from '../src/profiles/wappie.js'
import { b64, forTS, load, toB64, unhandled, utf8 } from './vectors.js'

const p = wappieBrowserAccount
const f = load('wappie/golden/browser-account-ts.json')

describe('wappie/golden/browser-account-ts.json', () => {
  for (const c of f.cases.filter(forTS)) {
    it(c.id, async () => {
      const i = c.in
      switch (c.op) {
        case 'browser_account.aad':
          expect(toB64(browserAccountAAD(p, i.user_id, b64(i.public_key_b64)))).toBe(c.out.aad_b64)
          return
        case 'browser_account.valid_envelope': {
          const key = i.algorithm === 'HMAC'
            ? await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256', length: 256 }, i.extractable, ['sign'])
            : await crypto.subtle.generateKey({ name: 'AES-GCM', length: i.length }, i.extractable, i.usages)
          const envelope = { version: i.version, key, nonce: new Uint8Array(i.nonce_len), ciphertext: new ArrayBuffer(i.ciphertext_len), publicRaw: new Uint8Array(i.public_len) }
          expect(validBrowserKeyEnvelope(envelope)).toBe(c.out.valid)
          return
        }
      }
      unhandled(c)
    })
  }
})

describe('the key at rest', () => {
  it('reopens the key without exporting any key', async () => {
    const pair = await generateAccountKeys()
    const exported = vi.spyOn(crypto.subtle, 'exportKey')
    try {
      const envelope = await sealBrowserAccountKey(p, pair.privateKey, pair.publicKey, 'user-one')
      expect(envelope.key.extractable).toBe(false)
      expect(envelope.ciphertext.byteLength).toBe(48)
      const restored = await openBrowserAccountKey(p, structuredClone(envelope), 'user-one')
      expect(toB64(restored.publicRaw)).toBe(toB64(pair.publicKey))
      expect(exported).not.toHaveBeenCalled()
    } finally {
      pair.privateKey.fill(0)
      exported.mockRestore()
    }
  })

  it('refuses another user, another public key and a changed ciphertext', async () => {
    const pair = await generateAccountKeys()
    const envelope = await sealBrowserAccountKey(p, pair.privateKey, pair.publicKey, 'user-one')
    await expect(openBrowserAccountKey(p, envelope, 'user-two')).rejects.toThrow()
    const publicRaw = envelope.publicRaw.slice(); publicRaw[0] ^= 1
    await expect(openBrowserAccountKey(p, { ...envelope, publicRaw }, 'user-one')).rejects.toThrow()
    const ciphertext = envelope.ciphertext.slice(0); new Uint8Array(ciphertext)[0] ^= 1
    await expect(openBrowserAccountKey(p, { ...envelope, ciphertext }, 'user-one')).rejects.toThrow()
    await expect(openBrowserAccountKey({ ...p, tag: 'other' }, envelope, 'user-one')).rejects.toThrow()
  })
})

describe('the AAD', () => {
  it('is JCS: the bytes JSON.stringify gave for a well-formed user id, and a lone surrogate refused', async () => {
    const { publicKey } = await generateAccountKeys()
    const user = '018f3a2b-0000-7000-8000-000000000003 \u2028\u{1f511}"'
    expect(toB64(browserAccountAAD(p, user, publicKey))).toBe(toB64(utf8(JSON.stringify([p.tag, p.version, user, toB64(publicKey)]))))
    for (const bad of ['\ud800', 'user-\udfff']) expect(() => browserAccountAAD(p, bad, publicKey)).toThrow(CanonicalJSONError)
  })
})
