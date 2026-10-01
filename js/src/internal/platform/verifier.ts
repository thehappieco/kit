// The server verifiers (SPEC section 11.7), here for parity with Go and for
// the vectors: a page never computes one, the server derives them from the
// auth_key and recovery_auth it receives.
//
//   auth_verifier     = SHA-256("thehappie-id/v1/auth-verifier"     || 0x00 || sub16 || K_auth)
//   recovery_verifier = SHA-256("thehappie-id/v1/recovery-verifier" || 0x00 || sub16 || R_proof)
//
// The label and the account id make a verifier useless for any other
// account or purpose. From the platform's web/shared/crypto/verifier.ts.

import { concat, encodeUTF8, parseUUID, type Bytes } from '../../bytes.js'
import { PlatformError } from '../../errors.js'
import { LABEL_AUTH_VERIFIER, LABEL_RECOVERY_VERIFIER } from './profile.js'
import { isSub } from './rootwrap.js'

async function verifier(label: string, sub: string, key: Uint8Array): Promise<Bytes> {
  if (!isSub(sub)) throw new PlatformError('the account id is not a lowercase UUID', 'encoding')
  if (!(key instanceof Uint8Array) || key.length !== 32) throw new PlatformError('a verifier key is 32 bytes', 'encoding')
  const input = concat(encodeUTF8(label), new Uint8Array([0]), parseUUID(sub), new Uint8Array(key) as Bytes)
  try {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', input))
  } finally {
    input.fill(0)
  }
}

/** authVerifier is what the server stores for K_auth; a malformed sub or key is encoding. */
export function authVerifier(sub: string, kAuth: Uint8Array): Promise<Bytes> {
  return verifier(LABEL_AUTH_VERIFIER, sub, kAuth)
}

/** recoveryVerifier is what the server stores for R_proof; a malformed sub or key is encoding. */
export function recoveryVerifier(sub: string, rProof: Uint8Array): Promise<Bytes> {
  return verifier(LABEL_RECOVERY_VERIFIER, sub, rProof)
}
