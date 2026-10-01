// The kit's errors carry codes, never text meant for a person. A product maps
// the codes to its own messages, in its own languages.

/** SealError says which check an envelope failed. */
export type SealErrorCode =
  | 'short'
  | 'magic'
  | 'version'
  | 'suite'
  | 'mode'
  | 'key_mismatch'
  | 'authentication'
  | 'invalid_key'
  | 'invalid_input'

export class SealError extends Error {
  constructor(
    message: string,
    readonly code: SealErrorCode,
  ) {
    super(message)
    this.name = 'SealError'
  }
}

/** AccountError: the code is the step, the reason the check that failed. */
export type AccountErrorCode = 'password' | 'kdf' | 'wrap' | 'recovery'
export type AccountErrorReason =
  | 'rejected'
  | 'unsupported_alg'
  | 'kdf_failed'
  | 'out_of_bounds'
  | 'truncated'
  | 'wrong_key'
  | 'recovery_length'

export class AccountError extends Error {
  constructor(
    message: string,
    readonly code: AccountErrorCode,
    readonly reason: AccountErrorReason,
  ) {
    super(message)
    this.name = 'AccountError'
  }
}

export type PasskeyErrorReason = 'bad_prf' | 'bad_key' | 'bad_aad' | 'bad_envelope' | 'open_failed'

export class PasskeyError extends Error {
  constructor(
    message: string,
    readonly reason: PasskeyErrorReason,
  ) {
    super(message)
    this.name = 'PasskeyError'
  }
}

export type HPKEErrorCode = 'open_failed' | 'invalid_key'

export class HPKEError extends Error {
  constructor(
    message: string,
    readonly code: HPKEErrorCode,
  ) {
    super(message)
    this.name = 'HPKEError'
  }
}

export class CanonicalJSONError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CanonicalJSONError'
  }
}

/** The refusals of the request HMAC, with the codes the Go side logs. */
export type RequestHMACErrorCode = 'hmac_missing' | 'hmac_stale'

export class RequestHMACError extends Error {
  constructor(readonly code: RequestHMACErrorCode) {
    super(code)
    this.name = 'RequestHMACError'
  }
}
