// The allowlist of WebAuthn client extension results (SPEC section 11.16).
//
// A credential reports its extension outputs in clientExtensionResults, and
// for the PRF extension that output is the secret K_pk is derived from. The
// page never serializes a credential with toJSON(); it copies an allowlist,
// and the id. server refuses anything outside the same allowlist, so a page
// bug that lets a PRF output through is a refused request rather than a
// secret in a request body, a log line or a database row. The allowlist,
// exactly:
//
//   {}                       or any subset, each member at most once, of
//   "credProps": {"rk": true | false}
//   "prf":       {"enabled": true | false}
//
// Everything else is refused with client_extensions: prf.results in any
// form, an empty credProps or prf, a flag of another type (null included),
// any other member at either level, a member name in another case, a
// repeated member, and a text that is not one JSON object. A refusal never
// says what it found: it may be a PRF output.
//
// The server's check reads the exact JSON text (checkClientExtensionsText,
// Go's CheckClientExtensions), because a parsed value cannot show what JSON
// readers resolve silently, and they do not all resolve it alike; the page
// checks the value it built (checkClientExtensions). The WebAuthn ceremony
// that builds and sends the credential is the platform's. From the
// allowlist of the platform's web/shared/crypto/webauthn.ts at b5d9f69.

import { PlatformError } from '../../errors.js'
import { parseStrictJSON, StrictJSONError } from '../strictjson.js'

/** AllowedClientExtensionResults is everything section 11.16 lets a credential carry in clientExtensionResults. */
export interface AllowedClientExtensionResults {
  credProps?: { rk: boolean }
  prf?: { enabled: boolean }
}

// A surrogate that is not half of a pair: the text is not Unicode. The same
// test as jcs.ts and password.ts (String.prototype.isWellFormed is ES2024).
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/

function refuse(why: string): never {
  throw new PlatformError(why, 'client_extensions')
}

/** isPlainObject is a JSON object: not null, not an array, no prototype but Object's. */
function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return false
  const proto = Object.getPrototypeOf(v) as unknown
  return proto === Object.prototype || proto === null
}

/**
 * member reads an own data member once. An accessor is refused, so what is
 * checked is what a later JSON.stringify of the same object writes.
 */
function member(o: object, key: string | symbol, what: string): unknown {
  const d = Object.getOwnPropertyDescriptor(o, key)
  if (d === undefined || !('value' in d)) refuse(`${what}: not a data member`)
  return d.value
}

/** checkFlagObject accepts exactly {name: true | false}, the rule of the Go function of that name. */
function checkFlagObject(v: unknown, name: string, what: string): void {
  if (!isPlainObject(v)) refuse(`${what}: not an object`)
  const keys = Reflect.ownKeys(v)
  if (keys.length !== 1 || keys[0] !== name || typeof member(v, name, what) !== 'boolean') {
    refuse(`${what}: not exactly {${name}: boolean}`)
  }
}

/**
 * checkClientExtensions refuses, with client_extensions, a
 * clientExtensionResults value that holds anything outside the allowlist:
 * accepted are {} and any subset of credProps: {rk: boolean} and prf:
 * {enabled: boolean}. It is for a value the page built itself, before it
 * sends it, and also refuses a value JSON could not carry the same way: an
 * object that is not plain (a class instance, an array), an inherited or
 * accessor member, a symbol key. A parsed value cannot show a repeated
 * member; checkClientExtensionsText reads the text and refuses that too.
 */
export function checkClientExtensions(results: unknown): void {
  if (!isPlainObject(results)) refuse('not an object')
  for (const key of Reflect.ownKeys(results)) {
    if (key === 'credProps') checkFlagObject(member(results, key, 'credProps'), 'rk', 'credProps')
    else if (key === 'prf') checkFlagObject(member(results, key, 'prf'), 'enabled', 'prf')
    else refuse('a member outside the allowlist')
  }
}

/**
 * checkClientExtensionsText is checkClientExtensions for the exact JSON text
 * of clientExtensionResults, read as Go's CheckClientExtensions reads it:
 * well-formed Unicode, one JSON value with JSON's four whitespace characters
 * only, nothing before it (a byte order mark is refused) or after it, no
 * repeated member, member names compared after unescaping. It is what the
 * client-extensions vectors run.
 *
 * A caller that holds bytes decodes them with
 * new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }): the default
 * decoder silently drops a leading byte order mark, and replaces invalid
 * UTF-8, so the text it gives is not the text that was sent.
 */
export function checkClientExtensionsText(text: string): void {
  if (typeof text !== 'string' || LONE_SURROGATE.test(text)) refuse('not text')
  let value: unknown
  try {
    value = parseStrictJSON(text)
  } catch (err) {
    if (err instanceof StrictJSONError) refuse('not one JSON value')
    throw err
  }
  checkClientExtensions(value)
}
