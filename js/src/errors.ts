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

/**
 * HPKEError is the hpke module's error. Where the engine refused an
 * operation, cause is what the engine threw: a DOMException named
 * NotSupportedError means it has no X25519 at all, rather than that it
 * refused this key.
 */
export class HPKEError extends Error {
  constructor(
    message: string,
    readonly code: HPKEErrorCode,
    options?: ErrorOptions,
  ) {
    super(message, options)
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

/**
 * Base64Error says a string is not the one accepted spelling of the bytes
 * asked for (bytes.fromBase64URL). The message never repeats the input.
 */
export class Base64Error extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'Base64Error'
  }
}

/**
 * The error names of the platform profile (SPEC section 11.10), the same in
 * Go (profiles/platform ErrorCode) and in the platform's vectors.
 */
export type PlatformErrorCode =
  /** Not well-formed Unicode, a run of more than 30 marks or Hangul vowel and final jamo (SPEC section 11.2), or a control character. */
  | 'password_invalid'
  /** A new password under 12 code points. */
  | 'password_too_short'
  /** A password over 256 code points. */
  | 'password_too_long'
  /** KDF parameters or a salt outside the profile's bounds, refused before anything is derived. */
  | 'kdf_policy'
  /** A root wrap that is malformed, does not open, or failed its self-test; which one is not said. */
  | 'wrap'
  /** Not a recovery code. */
  | 'recovery_code'
  /** An address the profile's email normalisation does not accept. */
  | 'email'
  /** A product id, epoch or root that names no product key, a listed key the root does not derive, or a delivered key whose public half is not the binding's (SPEC section 11.12). */
  | 'product_key'
  /** Not a key bundle this version reads. */
  | 'bundle'
  /** A key delivery that cannot be sealed or did not open (SPEC section 11.12); which check failed is not said. */
  | 'key_delivery'
  /** A PKCE code verifier outside RFC 7636: not 43 to 128 characters of [A-Za-z0-9._~-] (SPEC section 11.13). */
  | 'pkce'
  /** A value not in its one accepted spelling where no other name fits (a verifier's inputs). */
  | 'encoding'

/**
 * PlatformError is the one error the platform profile
 * (@thehappieco/kit/profiles/platform) throws on purpose. The message names
 * what kind of input was refused and never its value.
 */
export class PlatformError extends Error {
  constructor(
    message: string,
    readonly code: PlatformErrorCode,
  ) {
    super(message)
    this.name = 'PlatformError'
  }
}

/** isPlatformError narrows a caught value, optionally to one code. */
export function isPlatformError(err: unknown, code?: PlatformErrorCode): err is PlatformError {
  return err instanceof PlatformError && (code === undefined || err.code === code)
}
