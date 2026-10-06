// The relying party rule (SPEC section 11.16) against this engine's own
// WHATWG URL parser, in Node and in Chromium, Firefox and WebKit: a spelling
// of labels that ends in a number becomes an IPv4 address or is refused, and
// isRPID refuses it; any other spelling of labels is accepted by isRPID and,
// unless it has a label that starts with "xn--", kept as written as the host
// of an https origin. It holds the kit to the parser the rule is about, on
// every engine CI runs.
//
// The exception: the rule does not check that an "xn--" label is valid
// Punycode, on which the engines disagree (Firefox and Node refuse "xn--a",
// Chromium and WebKit keep it). Such hosts are only checked against the
// ends-in-a-number half of the comparison.

import { describe, expect, it } from 'vitest'

import { endsInANumber } from '../src/passkey.js'
import * as platform from '../src/profiles/platform.js'
import { loadPlatform } from './vectors.js'

/** hostOf is the host a URL parser makes of h, or null when it refuses it. */
function hostOf(h: string): string | null {
  try {
    return new URL(`https://${h}/`).hostname
  } catch {
    return null
  }
}

const IPV4 = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$/

/** notADomain: the parser refuses h or reads it as an IPv4 address. */
const notADomain = (h: string) => {
  const r = hostOf(h)
  return r === null || IPV4.test(r)
}

/** spelled: labels of [a-z0-9-], 1 to 63 each, none starting or ending with '-', 1 to 253 characters in all. */
const spelled = (h: string) => h.length >= 1 && h.length <= 253 && h.split('.').every((l) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l))

/** aLabel: h has a label that starts with "xn--", which a parser may refuse as Punycode (see the header). */
const aLabel = (h: string) => h.split('.').some((l) => l.startsWith('xn--'))

describe('the relying party rule against the URL parser', () => {
  it('agrees on every case of rp-id-ends-in-number.json', () => {
    for (const c of loadPlatform('rp-id-ends-in-number').cases) {
      const h = c.rp_id as string
      if (platform.isRPID(h) && !aLabel(h)) expect(hostOf(h), h).toBe(h)
      if (endsInANumber(h)) expect(notADomain(h), h).toBe(true)
    }
  })

  it('accepts an xn-- label without checking its Punycode, as the platform does', () => {
    // Engines disagree on these; the rule takes no side, and each engine
    // either keeps the host as written or refuses it.
    for (const h of ['xn--a', 'xn--a.com', 'id.xn--zz', 'xn--0']) {
      expect(platform.isRPID(h), h).toBe(true)
      expect(endsInANumber(h), h).toBe(false)
      const r = hostOf(h)
      expect(r === null || r === h, h).toBe(true)
    }
  })

  it('agrees on 200,000 random hosts', () => {
    // 'n' and '-' let "xn--" labels occur, which aLabel exempts from the
    // parser's verdict on keeping the host (see the header).
    const alphabet = '0123456789abcdefxX.-gn'
    let seed = 0x12345678
    const next = (n: number) => {
      seed = (Math.imul(seed, 1103515245) + 12345) >>> 0
      return (seed >>> 8) % n
    }
    let accepted = 0
    let numbers = 0
    for (let i = 0; i < 200_000; i++) {
      let h = ''
      const len = 1 + next(12)
      for (let j = 0; j < len; j++) h += alphabet[next(alphabet.length)]
      if (platform.isRPID(h)) {
        accepted++
        if (!aLabel(h)) expect(hostOf(h), h).toBe(h)
      }
      if (!spelled(h)) continue
      if (endsInANumber(h)) {
        numbers++
        expect(platform.isRPID(h), h).toBe(false)
        expect(notADomain(h), h).toBe(true)
      } else {
        expect(platform.isRPID(h), h).toBe(true)
        if (!aLabel(h)) expect(hostOf(h), h).toBe(h)
      }
    }
    expect(accepted).toBeGreaterThan(10_000)
    expect(numbers).toBeGreaterThan(1_000)
  })
})
