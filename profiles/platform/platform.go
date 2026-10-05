// Package platform is the platform profile (SPEC section 11) of The Happie
// Co platform's protocol id-v1 (thehappie-id/v1). Part 1, the account core,
// covers the password profile thehappie-password/v1 and its KDF bounds, the
// root-wrap envelope, the recovery code, the per-product keys and the
// server's check of their public keys, the server verifiers, email
// normalisation, strict base64url, the restricted JSON arrays used as
// additional data, and the key bundle. Part 2 covers the sealed delivery of
// a product key to the product's page (SealProductKey, OpenProductKey,
// section 11.12) and PKCE S256 (PKCEChallenge, section 11.13); the relying
// party built on them is package oidcrp (its server side) and
// @thehappieco/kit/oidc-rp (its page). Part 3 covers passkeys with PRF
// (section 11.16): the public PRF salt of a relying party (PRFSalt), the key
// a passkey's PRF output gives (PasskeyWrapKey) and the kind-3 root wrap
// under it (NewPasskeyWrap, OpenPasskeyWrap), and the allowlist of WebAuthn
// client extension results the id. server applies (CheckClientExtensions).
// The WebAuthn ceremony itself stays in the platform.
//
// The rule it enforces: the account root opens only for the account, epoch
// and kind it was wrapped for, and only with a key derived from the
// password, the recovery code or a passkey's PRF output. Everything that
// feeds a key derivation has exactly one spelling, so two implementations
// either agree byte for byte or refuse the same inputs, with the same error
// name.
// The platform's golden vectors (vectors/platform/id-v1) pin both.
//
// Unlike the kit's generic packages, the functions here take no profile
// argument: they are the platform's protocol. Where a generic package
// already does the work, this one hands it the platform's values: Argon2id
// and the auth/wrap split are account.DerivePrepared with Account(), the
// recovery branches are account.RecoveryKey and account.RecoveryProof with
// the platform's canonical form, opening a root wrap is account.Unwrap with
// RootWrapProfile, the AAD is written by jcs, and a product's public key by
// hpke.
//
// The page on id. runs the same protocol in TypeScript
// (@thehappieco/kit/profiles/platform). This package also plays the browser
// in Go tests and is what a command-line tool uses to open a key bundle. The
// server runs only a small part of it, and never sees a password, a root or
// a product private key:
//
//   - KDF.Check and CheckSalt, to refuse parameters outside the bounds;
//   - CheckWrapShape, to check a wrap's length, version and kind;
//   - CheckPublicKey, to refuse malformed and low-order product keys;
//   - AuthVerifier, RecoveryVerifier and VerifierMatches, with DummySub for
//     equal work;
//   - NormalizeEmail and DecodeB64;
//   - MarshalKeyBundle, since a bundle holds only what the server stores;
//   - CheckPublicKey again for akd_pub, and PKCEChallenge, in the
//     authorization and token endpoints;
//   - PRFSalt, for the WebAuthn options it sends, and CheckClientExtensions,
//     on every credential it receives, before any WebAuthn library reads it.
//
// What stays in the platform: the product registry, the account ceremonies
// built from these pieces, page rules such as refusing a password equal to
// the address, the decoy salts and every server secret.
//
// Sensitive byte slices this package allocates (derived keys, roots it
// unwraps on its own behalf, prepared passwords) are cleared when the
// package is done with them. That is best effort: Go may have copied them,
// strings cannot be cleared, and a slice returned to the caller is the
// caller's to clear (PasswordKeys.Zero, RecoveryKeys.Zero, clear(root)).
//
// Taken from the platform's internal/crypto/idcrypto at commits 5e66d84
// (part 1), 4476bf4 (part 2) and b5d9f69 (part 3), which was written to move
// here; the names and signatures are idcrypto's, except that the product
// registry and the sign-up and recovery helpers stay in the platform.
package platform

import (
	"encoding/base64"

	"github.com/thehappieco/kit/account"
)

// The HKDF infos and labels of id-v1 (SPEC section 11.1). They name keys;
// they are not credentials.
const (
	labelPasswordAuth     = "thehappie-id/v1/password/auth"
	labelPasswordWrap     = "thehappie-id/v1/password/wrap"
	labelRecoveryWrap     = "thehappie-id/v1/recovery/wrap"
	labelRecoveryAuth     = "thehappie-id/v1/recovery/auth"
	labelProductKey       = "thehappie-id/v1/product-key"
	labelAuthVerifier     = "thehappie-id/v1/auth-verifier"
	labelRecoveryVerifier = "thehappie-id/v1/recovery-verifier"
	wrapAADLabel          = "thehappie-id/root-wrap"
)

// PasswordProfile names the password preparation of section 11.2.
const PasswordProfile = "thehappie-password/v1"

// Account is the platform's account profile for package account: its labels,
// the presented-password preparation (PreparePassword), the KDF bounds of
// section 11.3, base64url text, the canonical recovery code, and the header
// of a password root wrap with no legacy form. Every call returns a fresh
// value.
func Account() account.Profile {
	return account.Profile{
		AuthLabel:          labelPasswordAuth,
		WrapLabel:          labelPasswordWrap,
		RecoveryKeyLabel:   labelRecoveryWrap,
		RecoveryProofLabel: labelRecoveryAuth,
		WrapHeader:         []byte{WrapVersion, byte(WrapPassword)},
		LegacyV1:           false,
		Prepare:            PreparePassword,
		Bounds:             KDFBounds(),
		Encoding:           base64.RawURLEncoding,
		NormaliseRecovery:  CanonicalRecoveryCode,
	}
}

// RootWrapProfile is Account with the header of a root wrap of kind:
// 0x01 ‖ kind. With it, account.Wrap and account.Unwrap seal and open the
// 62-byte envelope of section 11.5 (the AAD is WrapAAD's).
func RootWrapProfile(kind WrapKind) account.Profile {
	p := Account()
	p.WrapHeader = []byte{WrapVersion, byte(kind)}
	return p
}

// KDFBounds are the bounds of section 11.3 for package account: m from
// 65536 to 262144 KiB, t from 3 to 10, p from 1 to 4, m × t at most 1048576,
// and a salt of exactly 16 bytes. Every call returns a fresh value.
func KDFBounds() *account.Bounds {
	return &account.Bounds{
		Min:        account.KDFParams{Alg: KDFAlg, M: KDFMinM, T: KDFMinT, P: KDFMinP},
		Max:        account.KDFParams{Alg: KDFAlg, M: KDFMaxM, T: KDFMaxT, P: KDFMaxP},
		MaxCost:    KDFMaxMT,
		MinSaltLen: SaltLen,
		MaxSaltLen: SaltLen,
	}
}
