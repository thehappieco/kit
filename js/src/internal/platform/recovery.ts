// The recovery code's two keys (SPEC section 11.6):
//
//   K_rwrap       = HKDF(ASCII(C), empty, "thehappie-id/v1/recovery/wrap")
//   R_proof       = HKDF(ASCII(C), empty, "thehappie-id/v1/recovery/auth")
//   recovery_auth = base64url(R_proof)
//
// account.recoveryKey and account.recoveryProof with platformAccount, whose
// normalisation is the canonical form C. No slow KDF: 150 bits cannot be
// guessed offline. The proof and the wrap key are separate HKDF branches, so
// the server, which sees R_proof, learns nothing about K_rwrap.

import { recoveryKey, recoveryProof } from '../accountcore.js'
import { canonicalRecoveryCode } from './recoverycode.js'
import { platformAccount } from './profile.js'

/** RecoveryKeys are what a recovery code becomes. */
export interface RecoveryKeys {
  /** K_rwrap, non-extractable: opens the recovery wrap. It never leaves. */
  wrapKey: CryptoKey
  /** recovery_auth: what is sent. */
  recoveryAuth: string
}

/** deriveRecovery derives both branches from a code, typed or canonical; an invalid code is recovery_code. */
export async function deriveRecovery(code: string): Promise<RecoveryKeys> {
  const c = canonicalRecoveryCode(code)
  const [wrapKey, recoveryAuth] = await Promise.all([recoveryKey(platformAccount, c), recoveryProof(platformAccount, c)])
  return { wrapKey, recoveryAuth }
}
