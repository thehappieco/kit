// The relying party of the platform's id. for a product's page (SPEC
// section 11.14): begin a sign-in, complete it on the redirect URI, and,
// when the page asked for it, receive the product key sealed to this page
// alone, keeping it only once the product's own server has named it.
//
// Product-neutral: a product passes its constants, the issuer, its
// client_id, its redirect URI, its scopes and its key label (product, the
// "wappie" of "wappie:1"), and nothing else in the module is specific to
// it. The product's server half is the Go package oidcrp (SPEC section
// 11.15).
//
//   const rp = { issuer: 'https://id.thehappie.co', clientId: 'wappie-app',
//                redirectUri: 'https://app.wappie.thehappie.co/auth/callback',
//                scope: 'openid email profile', product: 'wappie' }
//   location.assign(await begin({ ...rp, wantKey: true, returnTo: '/inbox' }))
//   // on /auth/callback:
//   const r = await finishSignIn(location.href, {
//     ...rp,
//     session: (accessToken) => postSession(accessToken), // the product's POST to its server (11.15)
//     store: (sk, pinned) => vault.keep(sk, pinned),       // must copy: sk is zeroed afterwards
//   })
//   location.replace(r.returnTo)
//
// HPKE base mode does not authenticate the sender, so a delivered key that
// opens and matches the ID token is still not to be kept until the
// product's server, from its insert-only pin, names the same sub,
// product_key_id and product_key: finishSignIn and keepProductKey do that
// and throw pin_mismatch otherwise. callback alone returns the key for the
// caller to handle; a product that uses it must make that comparison
// itself (keepProductKey).
//
// Every refusal is an RPError with a code (errors); arguments outside the
// rules are the page's own constants and throw TypeError. The flow store is
// IndexedDB "thehappie-rp", object store "flows". The implementation is in
// internal/oidc-rp, taken from the platform's web/shared/oidc-rp at commit
// 4476bf4.

export { isRPError, RPError, type OAuthError, type RPErrorCode } from './errors.js'
export { DB_NAME, FLOW_TTL_MS, STORE } from './internal/oidc-rp/flows.js'
export type { IdClaims } from './internal/oidc-rp/idtoken.js'
export {
  begin,
  callback,
  finishSignIn,
  FLOW_AAD_LABEL,
  keepProductKey,
  logoutURL,
  sameOriginPath,
  type BeginOptions,
  type CallbackOptions,
  type CallbackResult,
  type FinishOptions,
  type FinishResult,
  type LogoutOptions,
  type PinnedKey,
} from './internal/oidc-rp/rp.js'
