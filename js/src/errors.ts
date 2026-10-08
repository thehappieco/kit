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
  /** A root wrap that is malformed, does not open, or failed its self-test, or a passkey wrap key that cannot be made (SPEC section 11.16); which one is not said. */
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
  /** WebAuthn client extension results outside the allowlist of SPEC section 11.16, above all a PRF output; what was there is not said. */
  | 'client_extensions'
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

/**
 * The refusals of the relying party's page (@thehappieco/kit/oidc-rp, SPEC
 * section 11.14). A page maps state_unknown, and authorization_error after
 * a denial, to "start again", and the rest to a security error, in its own
 * language.
 */
export type RPErrorCode =
  /** No live flow for this state: unknown, used already, another client's, or older than 10 minutes. */
  | 'state_unknown'
  /** The callback's iss is not the issuer, exactly, or the flow's request went to another issuer (RFC 9207). */
  | 'iss_mismatch'
  /** The authorization server answered with an error; oauthError says which. */
  | 'authorization_error'
  /** No code, or the token request failed or answered outside the protocol. */
  | 'token_error'
  /** The ID token is malformed or fails a check of section 11.14, step 6. */
  | 'id_token_invalid'
  /** The ephemeral key or the sealed product key does not open. */
  | 'key_open_failed'
  /** The opened key is not the private half of the ID token's product_key. */
  | 'key_mismatch'
  /**
   * The product's server did not name the same sub, product_key_id and
   * product_key as the ID token and the opened key (section 11.14, step 9):
   * the key is not kept.
   */
  | 'pin_mismatch'

/** OAuthError is an OAuth error value the relying party passes on; any other is "unknown". */
export type OAuthError =
  | 'access_denied'
  | 'login_required'
  | 'interaction_required'
  | 'consent_required'
  | 'invalid_request'
  | 'invalid_scope'
  | 'unsupported_response_type'
  | 'unauthorized_client'
  | 'server_error'
  | 'temporarily_unavailable'
  | 'invalid_client'
  | 'invalid_grant'
  | 'unsupported_grant_type'
  | 'unknown'

/**
 * RPError is the one error the relying party's page throws on purpose. Its
 * message names the step that failed, never a value from the response, the
 * flow or the key.
 */
export class RPError extends Error {
  readonly code: RPErrorCode
  /** For authorization_error and token_error: the OAuth error value, when there was one. */
  readonly oauthError: OAuthError | undefined

  constructor(code: RPErrorCode, message?: string, oauthError?: OAuthError) {
    super(message === undefined ? `oidc-rp: ${code}` : `oidc-rp: ${code}: ${message}`)
    this.name = 'RPError'
    this.code = code
    this.oauthError = oauthError
  }
}

/** isRPError narrows a caught value, optionally to one code. */
export function isRPError(err: unknown, code?: RPErrorCode): err is RPError {
  return err instanceof RPError && (code === undefined || err.code === code)
}

/**
 * PlatformWrapError is every refusal of the platform wrap (SPEC section 6.8,
 * @thehappieco/kit/platformwrap under any product's profile, and Wappie's
 * bound functions in @thehappieco/kit/profiles/wappie), an engine without
 * X25519 included. Which check failed is not said beyond the message, which
 * never repeats a key. The name and the message prefix are those of Wappie's
 * console, whose module the wrap came from.
 */
export class PlatformWrapError extends Error {
  readonly code = 'platform_wrap'
  constructor(message: string) {
    super(`platform wrap: ${message}`)
    this.name = 'PlatformWrapError'
  }
}

/** isPlatformWrapError narrows a caught value. */
export function isPlatformWrapError(err: unknown): err is PlatformWrapError {
  return err instanceof PlatformWrapError
}
