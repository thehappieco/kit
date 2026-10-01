import { describe, expect, it } from 'vitest'

import { type Bytes } from '../src/bytes.js'
import { bind, prfSalt, unwrapPasskey, wrapPasskey, type PasskeyProfile } from '../src/passkey.js'
import { passkeyAAD, wappiePasskey } from '../src/profiles/wappie.js'
import { b64, codeOf, files, forTS, toB64, unhandled, withDraws } from './vectors.js'

const p = wappiePasskey

for (const [path, f] of files('wappie/golden/passkey-ts.json', 'wappie/golden/passkey-salt-go.json', 'kit/passkey-go.json')) {
  describe(path, () => {
    for (const c of f.cases.filter(forTS)) {
      it(c.id, async () => {
        const i = c.in
        const aad = passkeyAAD({ rpID: i.rp_id, userID: i.user_id, credentialID: i.credential_id })
        switch (c.op) {
          case 'passkey.prf_salt':
            expect(toB64(await prfSalt(p, i.rp_id))).toBe(c.out.salt_b64)
            return
          case 'passkey.aad':
            expect(toB64(aad)).toBe(c.out.aad_b64)
            return
          case 'passkey.key': {
            // The wrap key is non-extractable; it must open what the recorded key seals.
            const nonce = new Uint8Array(12) as Bytes
            const raw = await crypto.subtle.importKey('raw', b64(c.out.key_b64), 'AES-GCM', false, ['encrypt'])
            const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, raw, new Uint8Array(32)))
            const envelope = new Uint8Array([...p.header, ...nonce, ...sealed]) as Bytes
            expect(toB64(await unwrapPasskey(p, envelope, b64(i.prf_b64), i.rp_id, aad))).toBe(toB64(new Uint8Array(32)))
            return
          }
          case 'passkey.wrap':
            if (c.error) {
              expect(await codeOf(() => withDraws({ bytes: [b64(i.nonce_b64)] }, () => wrapPasskey(p, b64(i.private_key_b64), b64(i.prf_b64), i.rp_id, aad)))).toBe(c.error)
              return
            }
            expect(toB64(await withDraws({ bytes: [b64(i.nonce_b64)] }, () => wrapPasskey(p, b64(i.private_key_b64), b64(i.prf_b64), i.rp_id, aad)))).toBe(c.out.envelope_b64)
            return
          case 'passkey.unwrap': {
            const attempt = () => unwrapPasskey(p, b64(i.envelope_b64), b64(i.prf_b64), i.rp_id, aad)
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
