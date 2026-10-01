// The platform profile, part 1 (SPEC section 11): the account core of The
// Happie Co platform's protocol id-v1 (thehappie-id/v1). The password
// profile thehappie-password/v1 and its KDF bounds, the 62-byte root wrap,
// the recovery code, per-product keys, the server verifiers, email
// normalisation and the strict key-bundle reader, the same in Go
// (profiles/platform) and pinned by the platform's vectors
// (vectors/platform/id-v1).
//
// Unlike the kit's generic modules, these functions take no profile: they
// are the platform's protocol. Where a generic module already does the work,
// it is handed the platform's values (platformAccount): Argon2id and the
// auth/wrap split are account.derivePrepared, the recovery branches
// account.recoveryKey and account.recoveryProof, a root wrap
// account.wrapPrivateKey and account.unwrapPrivateKey, the AAD jcs, and a
// product's public key hpke. Derived wrap keys are non-extractable
// CryptoKeys; the root-wrap functions also take 32 raw bytes.
//
// Every refusal is a PlatformError whose code is one of the protocol's error
// names, and whose message never holds the refused value. What stays in the
// platform: the product registry, the account ceremonies built from these
// pieces, page rules such as refusing a password equal to the address, the
// decoy salts and every server secret. The implementation is in
// ../internal/platform, taken from the platform's web/shared/crypto at
// commit 5e66d84.

export { isPlatformError, PlatformError, type PlatformErrorCode } from '../errors.js'
export type { DeriveOptions, Derived } from '../account.js'
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
} from '../internal/platform/profile.js'
export { PASSWORD_MAX, PASSWORD_MIN_NEW, PASSWORD_PROFILE, preparePassword, preparePasswordText } from '../internal/platform/password.js'
export { checkKDF, checkSalt, DEFAULT_KDF, KDF_BOUNDS, SALT_LEN, type KDF } from '../internal/platform/kdfpolicy.js'
export { derivePassword, derivePasswordKeys, newRoot } from '../internal/platform/kdf.js'
export { isEpoch, isSub, openRootWrap, rootWrapAAD, sealRootWrap, type PasskeyBinding } from '../internal/platform/rootwrap.js'
export {
  canonicalRecoveryCode,
  formatRecoveryCode,
  newRecoveryCode,
  RECOVERY_ALPHABET,
  RECOVERY_CODE_LEN,
  recoveryCodeFromBytes,
  type RecoveryCode,
} from '../internal/platform/recoverycode.js'
export { deriveRecovery, type RecoveryKeys } from '../internal/platform/recovery.js'
export { deriveProductKey, isProduct, productKeyId, productPublicKey, type ProductKey } from '../internal/platform/productkey.js'
export { authVerifier, recoveryVerifier } from '../internal/platform/verifier.js'
export { normalizeEmail } from '../internal/platform/email.js'
export {
  checkBundleProductKeys,
  KEY_BUNDLE_FORMAT,
  KEY_BUNDLE_VERSION,
  openKeyBundle,
  openKeyBundleWithRecoveryCode,
  parseKeyBundle,
  type KeyBundle,
  type KeyBundleProductKey,
  type ParsedKeyBundle,
} from '../internal/platform/keybundle.js'
