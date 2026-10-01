import { describe, expect, it } from 'vitest'

import { canonical, readSigned, signature, signedBy } from '../src/reqhmac.js'
import { DIRECTION_TO_GO, wappieMCPHMAC } from '../src/profiles/wappie.js'
import { b64, codeOf, files, forTS, unhandled, utf8 } from './vectors.js'

const s = wappieMCPHMAC
for (const [path, f] of files('wappie/golden/reqhmac-go.json', 'kit/reqhmac-go.json')) {
  describe(path, () => {
    for (const c of f.cases.filter(forTS)) {
      it(c.id, async () => {
        const i = c.in
        const body = b64(i.body_b64 ?? '')
        switch (c.op) {
          case 'reqhmac.signature':
            expect(await canonical(s, i.direction, i.sender, i.method, i.target, i.timestamp, i.nonce, body)).toBe(c.out.canonical)
            expect(await signature(s, i.secret, i.direction, i.sender, i.method, i.target, i.timestamp, i.nonce, body)).toBe(c.out.signature)
            return
          case 'reqhmac.read':
            if (c.error) expect(await codeOf(() => readSigned(s, i.headers, i.now))).toBe(c.error)
            else expect(readSigned(s, i.headers, i.now)).toEqual({ timestamp: c.out.timestamp, unix: c.out.unix, nonce: c.out.nonce, signature: c.out.signature })
            return
          case 'reqhmac.signed_by':
            expect(await signedBy(s, i.secrets, { timestamp: i.timestamp, unix: Number(i.timestamp), nonce: i.nonce, signature: i.signature }, i.direction, i.sender, i.method, i.target, body)).toBe(c.out.ok)
            return
        }
        unhandled(c)
      })
    }
  })
}

describe('the scheme', () => {
  it('reads header names case-insensitively, and refuses a repeated one', () => {
    const sig = 'v1=' + '0'.repeat(64)
    expect(readSigned(s, { 'x-wappie-timestamp': '1790300000', 'X-WAPPIE-NONCE': 'A'.repeat(22), 'x-wappie-signature': sig }, 1790300000).nonce).toBe('A'.repeat(22))
    expect(() => readSigned(s, { 'x-wappie-timestamp': ['1790300000', '1790300000'], 'x-wappie-nonce': 'A'.repeat(22), 'x-wappie-signature': sig }, 1790300000)).toThrow('hmac_missing')
  })

  it('signs under another label differently', async () => {
    const other = { ...s, label: 'thehappie-platform-hmac/v1' }
    const a = await signature(s, 'k', DIRECTION_TO_GO, 'r', 'GET', '/', '1', 'n', utf8(''))
    const b = await signature(other, 'k', DIRECTION_TO_GO, 'r', 'GET', '/', '1', 'n', utf8(''))
    expect(a).not.toBe(b)
  })
})
