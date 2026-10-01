import { describe, expect, it } from 'vitest'

import { type Bytes } from '../src/bytes.js'
import { ENC_LEN, generateKeyPair, HPKEError, importPrivateKey, open, publicFromPrivate, seal } from '../src/hpke.js'
import { b64, codeOf, files, forTS, toB64, unhandled, utf8, withDraws } from './vectors.js'

for (const [path, f] of files('wappie/golden/hpke-ts.json', 'kit/hpke-go.json')) {
  const keys = new Map<string, { priv: Bytes; pub: Bytes }>()
  for (const [name, k] of Object.entries(f.keys ?? {})) keys.set(name, { priv: b64(k.private_key_b64), pub: b64(k.public_key_b64) })

  describe(path, () => {
    for (const c of f.cases.filter(forTS)) {
      it(c.id, async () => {
        const i = c.in
        switch (c.op) {
          case 'hpke.seal': {
            const k = keys.get(i.key)!
            const opened = await open(await importPrivateKey(k.priv), b64(c.out.enc_b64), b64(i.info_b64), b64(i.aad_b64), b64(c.out.ciphertext_b64))
            expect(toB64(opened)).toBe(i.plaintext_b64)
            if (!i.ephemeral_private_key_b64) return // sealed by Go: its ephemeral key is not recorded
            const again = await withDraws({ x25519: [b64(i.ephemeral_private_key_b64)] }, () => seal(k.pub, b64(i.info_b64), b64(i.aad_b64), b64(i.plaintext_b64)))
            expect([toB64(again.enc), toB64(again.ciphertext)]).toEqual([c.out.enc_b64, c.out.ciphertext_b64])
            return
          }
          case 'hpke.open':
            expect(await codeOf(async () => open(await importPrivateKey(keys.get(i.key)!.priv), b64(i.enc_b64), b64(i.info_b64), b64(i.aad_b64), b64(i.ciphertext_b64)))).toBe(c.error)
            return
          case 'hpke.public_from_private':
            expect(toB64(await publicFromPrivate(b64(i.private_key_b64)))).toBe(c.out.public_key_b64)
            return
          case 'hpke.generate_key_pair': {
            const pair = await withDraws({ x25519: [b64(i.x25519_private_key_b64)] }, generateKeyPair)
            expect([toB64(pair.privateKey), toB64(pair.publicKey)]).toEqual([c.out.private_key_b64, c.out.public_key_b64])
            return
          }
        }
        unhandled(c)
      })
    }
  })
}

describe('hpke', () => {
  it('round-trips and refuses a short encapsulated key with a code', async () => {
    const pair = await generateKeyPair()
    const { enc, ciphertext } = await seal(pair.publicKey, utf8('info'), utf8('aad'), utf8('pt'))
    expect(enc.length).toBe(ENC_LEN)
    const priv = await importPrivateKey(pair.privateKey)
    expect(new TextDecoder().decode(await open(priv, enc, utf8('info'), utf8('aad'), ciphertext))).toBe('pt')
    await expect(open(priv, enc.subarray(0, 31) as Bytes, utf8('info'), utf8('aad'), ciphertext)).rejects.toThrow(HPKEError)
    await expect(open(priv, new Uint8Array(32) as Bytes, utf8('info'), utf8('aad'), ciphertext)).rejects.toThrow(HPKEError)
  })

  it('checks the PKCS#8 export before taking the raw key from it', async () => {
    const pair = await generateKeyPair()
    expect(pair.privateKey.length).toBe(32)
    expect(toB64(await publicFromPrivate(pair.privateKey))).toBe(toB64(pair.publicKey))
  })
})
