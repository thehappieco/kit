// A strict reader for JSON text whose members gate key material: the
// platform profile's key bundle (SPEC section 11.9), read the way Go's
// profiles/platform reads it (json.go there). From the platform's
// web/shared/crypto/strictjson.ts. Internal: not a subpath export.
//
// The rule it enforces: a text is read only in its one accepted spelling, so
// a file opens on one side exactly when it opens on the other. JSON.parse is
// too forgiving for that, in the ways encoding/json is too: a repeated member
// silently replaces the first, so {"issuer": "x", "issuer": "y"} reads as
// whichever came last; and 1, 1.0 and 1e0 are one number once parsed. Go
// refuses a repeated member and reads an integer only in its plain spelling,
// within a 64-bit integer. This reader refuses the same texts:
//
//   - RFC 8259 syntax, whitespace being space, tab, line feed and carriage
//     return, and nothing after the value (a byte order mark is refused);
//   - a member name repeated in the same object;
//   - a number with a fraction or an exponent, or outside [-2^63, 2^63 - 1];
//   - nesting deeper than the caller allows.
//
// What it returns is what JSON.parse would have returned for the same text.

export class StrictJSONError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'StrictJSONError'
  }
}

const INT64_MAX = '9223372036854775807'
const INT64_MIN_ABS = '9223372036854775808'

function fail(why: string): never {
  throw new StrictJSONError(why)
}

/**
 * parseStrictJSON reads one JSON value from text, or throws StrictJSONError.
 * maxDepth bounds the nesting of objects and arrays; the default is far
 * beyond any protocol document and far below any stack limit.
 */
export function parseStrictJSON(text: string, maxDepth = 16): unknown {
  if (typeof text !== 'string') fail('not text')
  let at = 0

  const space = (): void => {
    while (at < text.length) {
      const c = text.charCodeAt(at)
      if (c !== 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) return
      at++
    }
  }

  const literal = (word: string, v: unknown): unknown => {
    if (!text.startsWith(word, at)) fail('an unknown literal')
    at += word.length
    return v
  }

  const string = (): string => {
    // at is on the opening quote.
    at++
    let out = ''
    let from = at
    for (;;) {
      if (at >= text.length) fail('an unterminated string')
      const c = text.charCodeAt(at)
      if (c === 0x22) {
        out += text.slice(from, at)
        at++
        return out
      }
      if (c < 0x20) fail('a control character in a string')
      if (c !== 0x5c) {
        at++
        continue
      }
      out += text.slice(from, at)
      const e = text[at + 1]
      switch (e) {
        case '"':
        case '\\':
        case '/':
          out += e
          at += 2
          break
        case 'b':
          out += '\b'
          at += 2
          break
        case 'f':
          out += '\f'
          at += 2
          break
        case 'n':
          out += '\n'
          at += 2
          break
        case 'r':
          out += '\r'
          at += 2
          break
        case 't':
          out += '\t'
          at += 2
          break
        case 'u': {
          const hex = text.slice(at + 2, at + 6)
          if (!/^[0-9A-Fa-f]{4}$/.test(hex)) fail('a bad \\u escape')
          out += String.fromCharCode(parseInt(hex, 16))
          at += 6
          break
        }
        default:
          fail('an unknown escape')
      }
      from = at
    }
  }

  const number = (): number => {
    const m = /^-?(?:0|[1-9][0-9]*)/.exec(text.slice(at, at + 32))
    if (m === null) fail('not a number')
    const digits = m[0]
    const next = text[at + digits.length]
    if (next === '.' || next === 'e' || next === 'E') fail('a number with a fraction or an exponent')
    if (next !== undefined && next >= '0' && next <= '9') fail('a number too long to read')
    const negative = digits.startsWith('-')
    const abs = negative ? digits.slice(1) : digits
    const limit = negative ? INT64_MIN_ABS : INT64_MAX
    // Same-length digit strings compare as numbers do.
    if (abs.length > limit.length || (abs.length === limit.length && abs > limit)) {
      fail('an integer outside 64 bits')
    }
    at += digits.length
    return Number(digits)
  }

  const value = (depth: number): unknown => {
    space()
    const c = text[at]
    switch (c) {
      case '{': {
        if (depth >= maxDepth) fail('nested too deeply')
        at++
        // A plain object, as JSON.parse makes, with members defined rather
        // than assigned so that "__proto__" is a member like any other.
        const o: Record<string, unknown> = {}
        const seen = new Set<string>()
        space()
        if (text[at] === '}') {
          at++
          return o
        }
        for (;;) {
          space()
          if (text[at] !== '"') fail('a member name that is not a string')
          const name = string()
          if (seen.has(name)) fail('a repeated member')
          seen.add(name)
          space()
          if (text[at] !== ':') fail('a member without a colon')
          at++
          const v = value(depth + 1)
          Object.defineProperty(o, name, { value: v, enumerable: true, writable: true, configurable: true })
          space()
          if (text[at] === ',') {
            at++
            continue
          }
          if (text[at] === '}') {
            at++
            return o
          }
          fail('an object that does not close')
        }
      }
      case '[': {
        if (depth >= maxDepth) fail('nested too deeply')
        at++
        const a: unknown[] = []
        space()
        if (text[at] === ']') {
          at++
          return a
        }
        for (;;) {
          a.push(value(depth + 1))
          space()
          if (text[at] === ',') {
            at++
            continue
          }
          if (text[at] === ']') {
            at++
            return a
          }
          fail('an array that does not close')
        }
      }
      case '"':
        return string()
      case 't':
        return literal('true', true)
      case 'f':
        return literal('false', false)
      case 'n':
        return literal('null', null)
      default:
        if (c === '-' || (c !== undefined && c >= '0' && c <= '9')) return number()
        fail('not a JSON value')
    }
  }

  const v = value(0)
  space()
  if (at !== text.length) fail('data after the JSON value')
  return v
}

/** utf8Length is the length of text in UTF-8, as TextEncoder would write it. */
export function utf8Length(text: string): number {
  let n = 0
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i)
    if (c < 0x80) n += 1
    else if (c < 0x800) n += 2
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length) {
      const d = text.charCodeAt(i + 1)
      if (d >= 0xdc00 && d <= 0xdfff) {
        n += 4
        i++
      } else n += 3
    } else n += 3
  }
  return n
}
