import { describe, expect, it } from 'vitest'

import { Base64Error, formatUUID, fromBase64, fromBase64URL, fromHex, isBase64URL, parseUUID, toBase64, toBase64URL, uuidV5, type Bytes } from '../src/bytes.js'
import { canonicalJSON, CanonicalJSONError } from '../src/jcs.js'
import { b64, codeOf, files, forTS, toB64, unhandled } from './vectors.js'


const exprs: Record<string, unknown> = {
  NaN: Number.NaN, Infinity, '-Infinity': -Infinity, undefined, function: () => 1, bigint: 1n, symbol: Symbol('x'),
  date: new Date(0), map: new Map(), 'object-with-undefined': { a: undefined },
}

const pattern = (n: number, mul: number, add: number) => new Uint8Array(Array.from({ length: n }, (_, i) => (i * mul + add) & 0xff)) as Bytes

for (const [path, f] of files('wappie/golden/bytes-jcs-ts.json', 'kit/jcs-go.json')) {
  describe(path, () => {
    for (const c of f.cases.filter(forTS)) {
      it(c.id, async () => {
        const i = c.in
        const fails = async (fn: () => unknown) => expect(await codeOf(fn)).not.toBe('none')
        switch (c.op) {
          case 'bytes.uuid_v5':
            expect(formatUUID(await uuidV5(parseUUID(i.namespace), b64(i.name_b64)))).toBe(c.out.uuid)
            return
          case 'bytes.parse_uuid':
            if (c.error) await fails(() => parseUUID(i.text))
            else expect(toB64(parseUUID(i.text))).toBe(c.out.bytes_b64)
            return
          case 'bytes.format_uuid':
            if (c.error) await fails(() => formatUUID(b64(i.bytes_b64)))
            else expect(formatUUID(b64(i.bytes_b64))).toBe(c.out.text)
            return
          case 'bytes.base64': {
            const value = pattern(i.length, i.pattern.mul, i.pattern.add)
            const text = toBase64(value)
            if (c.out.base64 !== undefined) expect(text).toBe(c.out.base64)
            else expect(Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))), (b) => b.toString(16).padStart(2, '0')).join('')).toBe(c.out.base64_sha256_hex)
            expect(toB64(fromBase64(text))).toBe(toB64(value))
            return
          }
          case 'bytes.from_hex':
            if (c.error) await fails(() => fromHex(i.text))
            else expect(toB64(fromHex(i.text))).toBe(c.out.bytes_b64)
            return
          case 'jcs.canonical':
            if (c.error) expect(() => canonicalJSON(JSON.parse(i.json))).toThrow(CanonicalJSONError)
            else expect(canonicalJSON(JSON.parse(i.json))).toBe(c.out.jcs)
            return
          case 'jcs.canonical_value':
            expect(() => canonicalJSON(exprs[i.expr])).toThrow(CanonicalJSONError)
            return
        }
        unhandled(c)
      })
    }
  })
}

it('writes base64url without padding', () => {
  expect(toBase64URL(new Uint8Array([0xfb, 0xff]) as Bytes)).toBe('-_8')
})

describe('strict base64url', () => {
  it('reads back what toBase64URL writes, at every length, and only at that length', () => {
    for (let n = 0; n <= 70; n++) {
      const b = pattern(n, 37, n * 101)
      const s = toBase64URL(b)
      expect(s).toBe(toBase64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''))
      expect(s.length).toBe(Math.ceil((n * 4) / 3))
      expect(toB64(fromBase64URL(s, n))).toBe(toB64(b))
      expect(isBase64URL(s)).toBe(true)
      if (n > 0) expect(() => fromBase64URL(s, n - 1)).toThrow(Base64Error)
      expect(() => fromBase64URL(s, n + 1)).toThrow(Base64Error)
    }
  })

  it('refuses padding, other alphabets, whitespace and non-zero trailing bits', () => {
    for (const [s, n] of [['AA==', 1], ['AAA=', 2], ['AA=', 1], ['AA+A', 3], ['AA/A', 3], ['AA A', 3], ['AAA\n', 3], ['\nAAA', 3], ['AA\tA', 3], ['AA\u00c0A', 3], ['AA.A', 3],
      ['AB', 1], ['AAB', 2], ['A', 0], ['', 1]] as [string, number][]) {
      expect(() => fromBase64URL(s, n), JSON.stringify(s)).toThrow(Base64Error)
    }
    expect(toB64(fromBase64URL('AA', 1))).toBe('AA==')
    expect(fromBase64URL('', 0).length).toBe(0)
    expect(() => fromBase64URL('AA', -1)).toThrow(Base64Error)
    expect(() => fromBase64URL('AA', 1.5)).toThrow(Base64Error)
    for (const s of ['A', 'AAAAA', 'AB', 'AA==', 'A A']) expect(isBase64URL(s), s).toBe(false)
  })

  it('never repeats the refused text', () => {
    try {
      fromBase64URL('zq7marker=', 7)
      expect.fail('accepted')
    } catch (err) {
      expect(err).toBeInstanceOf(Base64Error)
      expect((err as Error).message).not.toContain('zq7marker')
    }
  })
})
