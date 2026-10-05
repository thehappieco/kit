// PKCE S256 (RFC 7636), SPEC section 11.13.
//
//   code_verifier  = 43 to 128 characters from [A-Za-z0-9._~-]
//   code_challenge = BASE64URL(SHA-256(ASCII(code_verifier)))      43 characters
//
// The rule it enforces: a verifier outside RFC 7636's alphabet and lengths
// is refused rather than hashed, exactly where the token endpoint would
// refuse it, so the relying party can never hold a flow whose code cannot be
// redeemed. The challenge is also bound into the key-delivery AAD (section
// 11.12), which is why it has a function of its own and golden vectors
// (pkce.json). TypeScript counts UTF-16 units where Go counts bytes; every
// accepted character is ASCII, so both refuse the same verifiers.
//
// From the platform's web/shared/crypto/pkce.ts at 4476bf4.

import { encodeUTF8, toBase64URL } from '../../bytes.js'
import { PlatformError } from '../../errors.js'

/** The verifier's alphabet and lengths (RFC 7636 section 4.1). */
export const CODE_VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/

/** A code_challenge is the base64url of a SHA-256 digest: 43 characters. */
export const CODE_CHALLENGE_LEN = 43

/** isCodeVerifier says whether s is a verifier RFC 7636 and SPEC section 11.13 accept. */
export function isCodeVerifier(s: unknown): s is string {
  return typeof s === 'string' && CODE_VERIFIER_PATTERN.test(s)
}

/**
 * pkceChallenge returns the S256 challenge of a verifier, or refuses a
 * verifier outside the alphabet or the lengths with PlatformError pkce.
 */
export async function pkceChallenge(verifier: string): Promise<string> {
  if (!isCodeVerifier(verifier)) throw new PlatformError('not a code verifier', 'pkce')
  return toBase64URL(new Uint8Array(await crypto.subtle.digest('SHA-256', encodeUTF8(verifier))))
}

/** newCodeVerifier is 32 random bytes in base64url: 43 characters (SPEC section 11.14). */
export function newCodeVerifier(): string {
  return toBase64URL(crypto.getRandomValues(new Uint8Array(32)))
}
