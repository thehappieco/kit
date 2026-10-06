// @thehappieco/kit/profiles/platform/core: the platform profile (SPEC
// section 11) without the kit's KDF worker. Every export is the one of
// @thehappieco/kit/profiles/platform, the same value, except derivePassword,
// derivePasswordKeys and openKeyBundle, which here run Argon2id in the worker
// options.worker makes, and on the calling thread without one: nothing this
// entry reaches names kdf.worker.js, so a bundle that imports it (and not
// @thehappieco/kit/account or @thehappieco/kit/profiles/platform) emits no
// worker file. For a page that derives with a worker of its own or with the
// kit's worker under a URL of its bundler's (Vite: import KDFWorker from
// '@thehappieco/kit/kdf.worker?worker', then { worker: () => new KDFWorker() }),
// a page that never derives, and servers.

export { isPlatformError, PlatformError, type PlatformErrorCode } from '../../errors.js'
export type { DeriveOptions, Derived } from '../../internal/accountcore.js'
export {
  isWrapKind,
  LABEL_AUTH_VERIFIER,
  LABEL_PASSWORD_AUTH,
  LABEL_PASSWORD_WRAP,
  LABEL_PRODUCT_KEY,
  LABEL_RECOVERY_AUTH,
  LABEL_RECOVERY_VERIFIER,
  LABEL_RECOVERY_WRAP,
  platformAccount,
  platformRootWrap,
  ROOT_LEN,
  WRAP_AAD_LABEL,
  WRAP_KIND_BYTE,
  WRAP_LEN,
  WRAP_VERSION,
  type WrapKind,
} from '../../internal/platform/profile.js'
export { PASSWORD_MAX, PASSWORD_MIN_NEW, PASSWORD_PROFILE, preparePassword, preparePasswordText } from '../../internal/platform/password.js'
export { checkKDF, checkSalt, DEFAULT_KDF, KDF_BOUNDS, SALT_LEN, type KDF } from '../../internal/platform/kdfpolicy.js'
export { newRoot } from '../../internal/platform/kdf.js'
export { isEpoch, isSub, openRootWrap, rootWrapAAD, sealRootWrap, type PasskeyBinding } from '../../internal/platform/rootwrap.js'
export {
  canonicalRecoveryCode,
  formatRecoveryCode,
  newRecoveryCode,
  RECOVERY_ALPHABET,
  RECOVERY_CODE_LEN,
  recoveryCodeFromBytes,
  type RecoveryCode,
} from '../../internal/platform/recoverycode.js'
export { deriveRecovery, type RecoveryKeys } from '../../internal/platform/recovery.js'
export { deriveProductKey, isProduct, productKeyId, productPublicKey, type ProductKey } from '../../internal/platform/productkey.js'
export { authVerifier, recoveryVerifier } from '../../internal/platform/verifier.js'
export { normalizeEmail } from '../../internal/platform/email.js'
export {
  checkBundleProductKeys,
  KEY_BUNDLE_FORMAT,
  KEY_BUNDLE_VERSION,
  openKeyBundleWithRecoveryCode,
  parseKeyBundle,
  type KeyBundle,
  type KeyBundleProductKey,
  type ParsedKeyBundle,
} from '../../internal/platform/keybundle.js'
export {
  deliverProductKey,
  isProductKeyId,
  KEY_DELIVERY_AAD_LABEL,
  KEY_DELIVERY_INFO,
  KEY_DELIVERY_VERSION,
  keyDeliveryAAD,
  openProductKey,
  SEALED_PRODUCT_KEY_LEN,
  sealProductKey,
  type DeliveredProductKey,
  type KeyDeliveryBinding,
  type KeyDeliveryRequest,
  type SealProductKeyInput,
} from '../../internal/platform/keydelivery.js'
export { CODE_CHALLENGE_LEN, CODE_VERIFIER_PATTERN, isCodeVerifier, newCodeVerifier, pkceChallenge } from '../../internal/platform/pkce.js'
export {
  checkX25519PublicKey,
  generateX25519KeyPair,
  importX25519PrivateKey,
  isCanonicalX25519,
  X25519_KEY_LEN,
  x25519PublicFromKey,
  type X25519KeyPair,
} from '../../internal/platform/x25519.js'
export {
  isRPID,
  LABEL_PASSKEY_PRF,
  LABEL_PASSKEY_WRAP,
  passkeyWrapKey,
  platformPasskey,
  PRF_OUTPUT_LEN,
  PRF_SALT_LEN,
  prfSalt,
  unwrapRootWithPasskey,
  wrapRootWithPasskey,
  type PasskeyUnwrapInput,
  type PasskeyWrapInput,
} from '../../internal/platform/passkey.js'
export { checkClientExtensions, checkClientExtensionsText, type AllowedClientExtensionResults } from '../../internal/platform/extensions.js'

import type { Bytes } from '../../bytes.js'
import type { DeriveOptions, Derived } from '../../internal/accountcore.js'
import { derivePasswordKeysWith, derivePasswordWith } from '../../internal/platform/kdf.js'
import { openKeyBundleWith } from '../../internal/platform/keybundle.js'

/**
 * derivePassword derives K_auth and K_wrap from P' under kdf and the salt
 * the server handed out (SPEC section 11.3). It throws kdf_policy before
 * deriving anything when they are outside the bounds. Argon2id runs in the
 * worker options.worker makes (the kit's kdf.worker.js), or on the calling
 * thread without one. The caller owns prepared and zeroes it.
 */
export function derivePassword(prepared: Bytes, salt: Bytes, kdf: unknown, options?: DeriveOptions): Promise<Derived> {
  return derivePasswordWith(undefined, prepared, salt, kdf, options)
}

/**
 * derivePasswordKeys prepares a presented password (no minimum length) and
 * derives its keys, as derivePassword does; the bounds come first. The
 * prepared bytes are zeroed.
 */
export function derivePasswordKeys(password: string, salt: Bytes, kdf: unknown, options?: DeriveOptions): Promise<Derived> {
  return derivePasswordKeysWith(undefined, password, salt, kdf, options)
}

/**
 * openKeyBundle opens a key bundle with the password (SPEC section 11.9),
 * deriving as derivePassword does, and returns the root, for the caller to
 * zero, once every product key has been checked against it.
 */
export function openKeyBundle(input: unknown, password: string, options?: DeriveOptions): Promise<Bytes> {
  return openKeyBundleWith(undefined, input, password, options)
}
