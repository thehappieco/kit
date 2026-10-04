import { describe, expect, it, vi } from 'vitest'

import { type Bytes } from '../src/bytes.js'
import { ENC_LEN, generateKeyPair, HPKEError, importPrivateKey, open, publicFromPrivate, seal } from '../src/hpke.js'
import {
  b64,
  codeOf,
  files,
  forTS,
  fromHex,
  LEADING_ZERO_KEYS,
  toB64,
  toHex,
  unhandled,
  utf8,
  withDraws,
  withEngineRefusingX25519,
  withLenientX25519,
} from './vectors.js'

for (const [path, f] of files('wappie/golden/hpke-ts.json', 'kit/hpke-go.json')) {
  const keys = new Map<string, { priv: Bytes; pub: Bytes }>()
  for (const [name, k] of Object.entries(f.keys ?? {})) keys.set(name, { priv: b64(k.private_key_b64), pub: b64(k.public_key_b64) })

  describe(path, () => {
    for (const c of f.cases.filter(forTS)) {
      it(c.id, async () => {
        const i = c.in
        switch (c.op) {
          case 'hpke.seal': {
            if (c.error) {
              // A low-order public key: refused, by the engine or by the kit.
              const attempt = () => seal(b64(i.public_key_b64), b64(i.info_b64), b64(i.aad_b64), b64(i.plaintext_b64))
              expect(await codeOf(attempt)).toBe(c.error)
              expect(await codeOf(() => withLenientX25519(attempt))).toBe(c.error)
              return
            }
            const k = keys.get(i.key)!
            const opened = await open(await importPrivateKey(k.priv), b64(c.out.enc_b64), b64(i.info_b64), b64(i.aad_b64), b64(c.out.ciphertext_b64))
            expect(toB64(opened)).toBe(i.plaintext_b64)
            if (!i.ephemeral_private_key_b64) return // sealed by Go: its ephemeral key is not recorded
            const again = await withDraws({ x25519: [b64(i.ephemeral_private_key_b64)] }, () => seal(k.pub, b64(i.info_b64), b64(i.aad_b64), b64(i.plaintext_b64)))
            expect([toB64(again.enc), toB64(again.ciphertext)]).toEqual([c.out.enc_b64, c.out.ciphertext_b64])
            return
          }
          case 'hpke.open': {
            const attempt = async () => open(await importPrivateKey(keys.get(i.key)!.priv), b64(i.enc_b64), b64(i.info_b64), b64(i.aad_b64), b64(i.ciphertext_b64))
            if (!c.error) {
              expect(toB64(await attempt())).toBe(c.out.plaintext_b64)
              return
            }
            expect(await codeOf(attempt)).toBe(c.error)
            // A forgery under the all-zero secret: refused even where WebCrypto would let it through.
            if (i.forged_plaintext_b64) expect(await codeOf(() => withLenientX25519(attempt))).toBe(c.error)
            return
          }
          case 'hpke.public_from_private':
            // The all-zero key included (hpke/public-from-private/zeros),
            // which every engine now takes, WebKit on Linux too.
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

  it('runs the forgeries on an engine that would let them through', async () => {
    // What withLenientX25519 simulates: X25519 with a low-order point gives 32 zero bytes.
    const pair = await generateKeyPair()
    const priv = await importPrivateKey(pair.privateKey)
    let zeros: Uint8Array | string
    try {
      const low = await crypto.subtle.importKey('raw', new Uint8Array(32), { name: 'X25519' }, true, [])
      zeros = await withLenientX25519(async () => new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: low }, priv.key, 256)))
    } catch (err) {
      zeros = `this engine refuses the point on import: ${err}`
    }
    if (typeof zeros !== 'string') expect(Array.from(zeros)).toEqual(Array.from(new Uint8Array(32)))
    // And the kit refuses to seal to such a key there too.
    expect(await codeOf(() => withLenientX25519(() => seal(new Uint8Array(32) as Bytes, utf8('i'), utf8('a'), utf8('p'))))).toBe('invalid_key')
  })

  it('zeroes its own PKCS#8 copies of a private key', async () => {
    const imported: Uint8Array[] = []
    const realImport = crypto.subtle.importKey.bind(crypto.subtle)
    const importSpy = vi.spyOn(crypto.subtle, 'importKey').mockImplementation(((format: KeyFormat, data: BufferSource, ...rest: unknown[]) => {
      if (format === 'pkcs8') imported.push(data as Uint8Array)
      return (realImport as (...a: unknown[]) => Promise<CryptoKey>)(format, data, ...rest)
    }) as never)
    const exported: ArrayBuffer[] = []
    const realExport = crypto.subtle.exportKey.bind(crypto.subtle)
    const exportSpy = vi.spyOn(crypto.subtle, 'exportKey').mockImplementation((async (format: KeyFormat, key: CryptoKey) => {
      const out = (await realExport(format as 'pkcs8', key)) as ArrayBuffer
      if (format === 'pkcs8') exported.push(out)
      return out
    }) as never)
    try {
      const pair = await generateKeyPair()
      const priv = await importPrivateKey(pair.privateKey)
      expect(toB64(priv.publicRaw)).toBe(toB64(pair.publicKey))
      expect(pair.privateKey.some((b) => b !== 0)).toBe(true)
    } finally {
      importSpy.mockRestore()
      exportSpy.mockRestore()
    }
    expect(imported.length).toBe(1)
    expect(exported.length).toBe(1)
    for (const b of [...imported, ...exported.map((x) => new Uint8Array(x))]) expect(b.every((x) => x === 0)).toBe(true)
  })

  // v0.1.0's codes stay as they were: an engine's refusal is invalid_key.
  // What the engine threw is the error's cause, so a caller can tell an
  // engine without X25519 (NotSupportedError) from one that refused the key.
  it('keeps what the engine threw as the cause of invalid_key', async () => {
    const pair = await generateKeyPair()
    for (const name of ['NotSupportedError', 'DataError']) {
      for (const fn of [() => importPrivateKey(pair.privateKey), () => publicFromPrivate(pair.privateKey), () => seal(pair.publicKey, utf8('i'), utf8('a'), utf8('p'))]) {
        let caught: unknown
        await withEngineRefusingX25519(name, async () => {
          try {
            await fn()
          } catch (err) {
            caught = err
          }
        })
        expect(caught).toBeInstanceOf(HPKEError)
        expect((caught as HPKEError).code).toBe('invalid_key')
        expect(((caught as HPKEError).cause as DOMException).name).toBe(name)
      }
    }
  })

  // Any 32 bytes are an X25519 private key (SPEC section 6.4) on every
  // engine. WebKit on Linux refuses a PKCS#8 key whose first byte is zero;
  // the kit's copy has bit 0 of that byte set, which X25519 clears anyway.
  it('takes a private key whose first byte is zero, on every engine', async () => {
    for (const [privHex, pubHex] of LEADING_ZERO_KEYS) {
      const priv = fromHex(privHex)
      expect(toHex(await publicFromPrivate(priv)), privHex).toBe(pubHex)
      const key = await importPrivateKey(priv)
      expect(toHex(key.publicRaw), privHex).toBe(pubHex)
      const { enc, ciphertext } = await seal(fromHex(pubHex), utf8('info'), utf8('aad'), utf8('pt'))
      expect(new TextDecoder().decode(await open(key, enc, utf8('info'), utf8('aad'), ciphertext)), privHex).toBe('pt')
      expect(toHex(priv), 'the caller\'s bytes').toBe(privHex)
      // X25519 clears the three low bits of the first byte: 1 to 7 are the
      // same key, and 8 is another.
      for (let low = 1; low < 8; low++) {
        const alias = priv.slice()
        alias[0] = low
        expect(toHex(await publicFromPrivate(alias)), `${privHex} with ${low} first`).toBe(pubHex)
      }
      const other = priv.slice()
      other[0] = 8
      expect(toHex(await publicFromPrivate(other)), `${privHex} with 8 first`).not.toBe(pubHex)
    }
  })

  // Node, Firefox and Safari generate such keys (1 in 256, or 1 in 32 where
  // the engine stores them clamped); WebKit on Linux never does, so the draw
  // is replayed.
  it('hands out a generated key whose first byte is zero as it is', async () => {
    for (const [privHex, pubHex] of LEADING_ZERO_KEYS) {
      const pair = await withDraws({ x25519: [fromHex(privHex)] }, generateKeyPair)
      expect([toHex(pair.privateKey), toHex(pair.publicKey)]).toEqual([privHex, pubHex])
    }
  })

  it('checks the PKCS#8 export before taking the raw key from it', async () => {
    const pair = await generateKeyPair()
    expect(pair.privateKey.length).toBe(32)
    expect(toB64(await publicFromPrivate(pair.privateKey))).toBe(toB64(pair.publicKey))
  })
})
