// The strict JSON reader of the platform profile's key bundle
// (src/internal/strictjson.ts) against JSON.parse:
// it reads what JSON.parse reads, to the same value, and refuses besides
// what Go's key-bundle reader refuses (a repeated member, a number that is
// not a plain integer within 64 bits, deep nesting).

import { describe, expect, test } from 'vitest'
import { parseStrictJSON, StrictJSONError, utf8Length } from '../src/internal/strictjson.js'

const randomBytes = (n: number) => crypto.getRandomValues(new Uint8Array(n))

function refused(text: string, maxDepth?: number): boolean {
  try {
    parseStrictJSON(text, maxDepth)
    return false
  } catch (err) {
    if (err instanceof StrictJSONError) return true
    throw err
  }
}

function below(n: number): number {
  return randomBytes(4).reduce((a, b) => a * 256 + b, 0) % n
}

/** randomText is a string of random UTF-16 units, lone surrogates and controls included. */
function randomText(max: number): string {
  const units: number[] = []
  for (let i = below(max + 1); i > 0; i--) {
    units.push(
      [
        () => 0x20 + below(0x5f),
        () => below(0x20),
        () => 0x80 + below(0x780),
        () => 0xd800 + below(0x800),
        () => 0xe000 + below(0x2000),
        () => below(0x10000),
      ][below(6)]!(),
    )
  }
  return String.fromCharCode(...units)
}

/** randomValue is a JSON value whose numbers are integers, as a key bundle's are. */
function randomValue(depth: number): unknown {
  const kind = below(depth > 3 ? 4 : 6)
  switch (kind) {
    case 0:
      return [null, true, false][below(3)]
    case 1:
      return (below(2) === 0 ? -1 : 1) * below(2 ** 31)
    case 2:
    case 3:
      return randomText(12)
    case 4:
      return Array.from({ length: below(4) }, () => randomValue(depth + 1))
    default: {
      const o: Record<string, unknown> = {}
      for (let i = below(4); i > 0; i--) {
        Object.defineProperty(o, randomText(6), { value: randomValue(depth + 1), enumerable: true, writable: true, configurable: true })
      }
      return o
    }
  }
}

describe('strict JSON', () => {
  test('TestTheStrictReaderReadsWhatJSONParseReadsToTheSameValue', () => {
    const texts = [
      '{}',
      '[]',
      ' \t\r\n{ "a" : [ 1 , -2 , 0 , true , false , null , "x" ] } \n',
      '{"a":{"b":{"c":[[]]}}}',
      '"a string"',
      '123',
      '9223372036854775807',
      '-9223372036854775808',
      '{"esc":"\\"\\\\\\/\\b\\f\\n\\r\\t\\u00e9\\ud83d\\ude00\\ud800\\u0000"}',
      '{"\\u0073ub":1,"Sub":2}',
    ]
    for (const t of texts) expect(parseStrictJSON(t), t).toEqual(JSON.parse(t))
    expect(Object.is(parseStrictJSON('-0'), -0)).toBe(true)
  })

  test('TestAMemberNamedProtoIsAMemberAndNotAPrototype', () => {
    const v = parseStrictJSON('{"__proto__": {"polluted": 1}}') as Record<string, unknown>
    expect(Object.getPrototypeOf(v)).toBe(Object.prototype)
    expect(Object.keys(v)).toEqual(['__proto__'])
    expect((v as { polluted?: unknown }).polluted).toBeUndefined()
    expect(v).toEqual(JSON.parse('{"__proto__": {"polluted": 1}}'))
  })

  test('TestRandomValuesReadAsJSONParseReadsThem', () => {
    for (let i = 0; i < 300; i++) {
      const text = JSON.stringify(randomValue(0), null, [undefined, 2, '\t'][below(3)])
      expect(parseStrictJSON(text), `value ${i}`).toEqual(JSON.parse(text))
    }
  })

  test('TestARepeatedMemberIsRefusedAtAnyDepth', () => {
    for (const t of [
      '{"a":1,"a":1}',
      '{"a":1,"b":2,"a":3}',
      '{"x":{"b":1,"b":2}}',
      '[{"a":1,"a":2}]',
      // The same name once decoded, as Go compares them.
      '{"a":1,"\\u0061":2}',
    ]) {
      expect(refused(t), t).toBe(true)
      expect(() => JSON.parse(t), t).not.toThrow()
    }
  })

  test('TestOnlyThePlainSpellingOfAnIntegerIsRead', () => {
    for (const t of ['1.0', '1e0', '1E+2', '0.5', '-1.5e-3', '{"a":1.0}', '[3E0]']) {
      expect(refused(t), t).toBe(true)
      expect(() => JSON.parse(t), t).not.toThrow()
    }
  })

  test('TestIntegersPast64BitsAreRefused', () => {
    for (const t of ['9223372036854775808', '-9223372036854775809', '100000000000000000000', '1'.repeat(40), `[${'9'.repeat(400)}]`]) {
      expect(refused(t), t).toBe(true)
    }
    expect(refused('9223372036854775807')).toBe(false)
    expect(refused('-9223372036854775808')).toBe(false)
  })

  test('TestWhatJSONParseRefusesIsRefused', () => {
    const texts = [
      '',
      ' ',
      '{',
      '{"a":1,}',
      '[1,]',
      "{'a':1}",
      '{"a":01}',
      '-',
      '--1',
      '+1',
      '.5',
      '1.',
      'NaN',
      'Infinity',
      `"${String.fromCharCode(1)}"`,
      `"a${String.fromCharCode(0x0a)}b"`,
      '"\\x41"',
      '"\\u12"',
      '"\\u12G4"',
      '"\\a"',
      '{"a" 1}',
      '{a:1}',
      '{"a":1 "b":2}',
      '[1 2]',
      'tru',
      'nul',
      'True',
      '"abc',
      '{} {}',
      '{}x',
      `${String.fromCharCode(0xfeff)}{}`,
      `{}${String.fromCharCode(0xa0)}`,
      '/* c */ {}',
    ]
    for (const t of texts) {
      expect(refused(t), JSON.stringify(t)).toBe(true)
      expect(() => JSON.parse(t), JSON.stringify(t)).toThrow()
    }
  })

  test('TestNestingIsBoundedWithoutExhaustingTheStack', () => {
    expect(refused(`${'['.repeat(16)}${']'.repeat(16)}`, 16)).toBe(false)
    expect(refused(`${'['.repeat(17)}${']'.repeat(17)}`, 16)).toBe(true)
    expect(refused(`${'{"a":'.repeat(17)}1${'}'.repeat(17)}`, 16)).toBe(true)
    expect(refused('['.repeat(100_000))).toBe(true)
  })

  test('TestUTF8LengthIsWhatTextEncoderWrites', () => {
    const encoder = new TextEncoder()
    const fixed = ['', 'abc', String.fromCharCode(0xe9), String.fromCharCode(0x20ac), String.fromCodePoint(0x1f600)]
    // Lone, reversed and trailing surrogates become U+FFFD, three bytes.
    fixed.push(String.fromCharCode(0xd800), String.fromCharCode(0xdc00, 0xd800), `a${String.fromCharCode(0xd83d)}`)
    for (const s of fixed) expect(utf8Length(s)).toBe(encoder.encode(s).length)
    for (let i = 0; i < 300; i++) {
      const s = randomText(40)
      expect(utf8Length(s), `string ${i}`).toBe(encoder.encode(s).length)
    }
  })
})
