// The platform profile (SPEC section 11) of The Happie Co platform's
// protocol id-v1 (thehappie-id/v1). Part 1, the account core: the password
// profile thehappie-password/v1 and its KDF bounds, the 62-byte root wrap,
// the recovery code, per-product keys, the server verifiers, email
// normalisation and the strict key-bundle reader. Part 2: the sealed
// delivery of a product key to the product's page (section 11.12), PKCE
// S256 (section 11.13), and the X25519 helpers the relying party's page
// uses. Part 3: passkeys with PRF (section 11.16), the public PRF salt of a
// relying party, K_pk from a passkey's PRF output and the kind-3 root wrap
// under it, and the allowlist of WebAuthn client extension results. The
// same in Go (profiles/platform), and pinned by the platform's vectors
// (vectors/platform/id-v1). The relying party itself is
// @thehappieco/kit/oidc-rp.
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
// WebAuthn ceremony, the decoy salts and every server secret. The
// implementation is in ../internal/platform, taken from the platform's
// web/shared/crypto at commits 5e66d84 (part 1), 4476bf4 (part 2) and
// b5d9f69 (part 3). Key delivery's HPKE wipes its key schedule and is
// internal: no page code can choose an ephemeral key.

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
} from '../internal/platform/keydelivery.js'
export { CODE_CHALLENGE_LEN, CODE_VERIFIER_PATTERN, isCodeVerifier, newCodeVerifier, pkceChallenge } from '../internal/platform/pkce.js'
export {
  checkX25519PublicKey,
  generateX25519KeyPair,
  importX25519PrivateKey,
  isCanonicalX25519,
  X25519_KEY_LEN,
  x25519PublicFromKey,
  type X25519KeyPair,
} from '../internal/platform/x25519.js'
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
} from '../internal/platform/passkey.js'
export { checkClientExtensions, checkClientExtensionsText, type AllowedClientExtensionResults } from '../internal/platform/extensions.js'
