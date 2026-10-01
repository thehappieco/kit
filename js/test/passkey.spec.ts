import { describe, expect, it } from 'vitest'

import { type Bytes } from '../src/bytes.js'
import { CanonicalJSONError } from '../src/jcs.js'
import { bind, prfSalt, unwrapPasskey, wrapPasskey, type PasskeyProfile } from '../src/passkey.js'
import { passkeyAAD, wappiePasskey } from '../src/profiles/wappie.js'
import { b64, codeOf, files, forTS, fromWTF8, toB64, unhandled, utf8, withDraws } from './vectors.js'

const p = wappiePasskey

/** The binding of a case; a string that is not Unicode comes as WTF-8. */
function binding(i: Record<string, string>) {
  const field = (name: string) => (i[`${name}_wtf8_b64`] !== undefined ? fromWTF8(b64(i[`${name}_wtf8_b64`])) : i[name])
  return { rpID: field('rp_id'), userID: field('user_id'), credentialID: field('credential_id') }
}

for (const [path, f] of files('wappie/golden/passkey-ts.json', 'wappie/golden/passkey-salt-go.json', 'kit/passkey-go.json')) {
  describe(path, () => {
    for (const c of f.cases.filter(forTS)) {
      it(c.id, async () => {
        const i = c.in
        // The case's own AAD when it gives one (aad_b64, possibly empty), else its binding's.
        const aadOf = () => (i.aad_b64 !== undefined ? b64(i.aad_b64) : passkeyAAD(binding(i)))
        switch (c.op) {
          case 'passkey.prf_salt':
            expect(toB64(await prfSalt(p, i.rp_id))).toBe(c.out.salt_b64)
            return
          case 'passkey.aad':
            if (c.error) {
              expect(c.error).toBe('jcs')
              expect(() => passkeyAAD(binding(i))).toThrow(CanonicalJSONError)
            } else expect(toB64(aadOf())).toBe(c.out.aad_b64)
            return
          case 'passkey.key': {
            // The wrap key is non-extractable; it must open what the recorded key seals.
            const aad = utf8('any binding')
            const nonce = new Uint8Array(12) as Bytes
            const raw = await crypto.subtle.importKey('raw', b64(c.out.key_b64), 'AES-GCM', false, ['encrypt'])
            const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, raw, new Uint8Array(32)))
            const envelope = new Uint8Array([...p.header, ...nonce, ...sealed]) as Bytes
            expect(toB64(await unwrapPasskey(p, envelope, b64(i.prf_b64), i.rp_id, aad))).toBe(toB64(new Uint8Array(32)))
            return
          }
          case 'passkey.wrap':
            if (c.error) {
              expect(await codeOf(() => withDraws({ bytes: [b64(i.nonce_b64)] }, () => wrapPasskey(p, b64(i.private_key_b64), b64(i.prf_b64), i.rp_id, aadOf())))).toBe(c.error)
              return
            }
            expect(toB64(await withDraws({ bytes: [b64(i.nonce_b64)] }, () => wrapPasskey(p, b64(i.private_key_b64), b64(i.prf_b64), i.rp_id, aadOf())))).toBe(c.out.envelope_b64)
            return
          case 'passkey.unwrap': {
            const attempt = () => unwrapPasskey(p, b64(i.envelope_b64), b64(i.prf_b64), i.rp_id, aadOf())
            if (c.error) expect(await codeOf(attempt)).toBe(c.error)
            else expect(toB64(await attempt())).toBe(c.out.private_key_b64)
            return
          }
        }
        unhandled(c)
      })
    }
  })
}

describe('another profile', () => {
  it('uses its own prefix, info and header', async () => {
    const other: PasskeyProfile = { evalPrefix: 'test/v1/passkey-prf|', wrapInfo: 'test/v1/passkey/wrap', header: [1, 3] }
    const key = new Uint8Array(32).fill(1) as Bytes, prf = new Uint8Array(32).fill(2) as Bytes, aad = new Uint8Array(3) as Bytes
    const k = bind(other)
    const env = await k.wrapPasskey(key, prf, 'id.example', aad)
    expect(env.length).toBe(62)
    expect(toB64(await k.unwrapPasskey(env, prf, 'id.example', aad))).toBe(toB64(key))
    expect(await codeOf(() => unwrapPasskey(p, env, prf, 'id.example', aad))).toBe('bad_envelope')
    expect(toB64(await k.prfSalt('x'))).not.toBe(toB64(await prfSalt(p, 'x')))
  })
})

describe('the binding', () => {
  const key = new Uint8Array(32).fill(1) as Bytes, prf = new Uint8Array(32).fill(2) as Bytes

  it('is refused when empty, both ways: a wrap bound to nothing could be moved to any passkey', async () => {
    expect(await codeOf(() => wrapPasskey(p, key, prf, 'x', new Uint8Array(0) as Bytes))).toBe('bad_aad')
    const env = await wrapPasskey(p, key, prf, 'x', utf8('aad'))
    expect(await codeOf(() => unwrapPasskey(p, env, prf, 'x', new Uint8Array(0) as Bytes))).toBe('bad_aad')
  })

  it('is JCS: the bytes JSON.stringify gave for well-formed strings, and a lone surrogate refused', () => {
    const b = { rpID: 'wappie.thehappie.co', userID: '018f3a2b-0000-7000-8000-000000000003', credentialID: 'a"b\\c\u0001\u2028\u{1f511}' }
    expect(toB64(passkeyAAD(b))).toBe(toB64(utf8(JSON.stringify(['wappie/passkey-vault', 1, b.rpID, b.userID, b.credentialID]))))
    for (const bad of ['\ud800', 'x\udc00', '\udbff\ud800']) {
      expect(() => passkeyAAD({ ...b, userID: bad })).toThrow(CanonicalJSONError)
      expect(() => passkeyAAD({ ...b, credentialID: bad })).toThrow(CanonicalJSONError)
    }
  })
})
