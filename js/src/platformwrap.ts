// The platform wrap (SPEC section 6.8): a product's account key under a key
// derived from its product key sk_p, under the product's labels, a
// PlatformWrapProfile. Wappie's labels are wappiePlatformWrap, exported by
// @thehappieco/kit/profiles/wappie with the functions of v0.5.0 bound to them.

export { isPlatformWrapError, PlatformWrapError } from './errors.js'
export {
  bind,
  checkPlatformWrapShape,
  openPlatformWrap,
  PLATFORM_WRAP_HEADER,
  PLATFORM_WRAP_LEN,
  PLATFORM_WRAP_VERSION,
  platformWrapAAD,
  platformWrapInfo,
  sealPlatformWrap,
  type BoundPlatformWrap,
  type PlatformWrapBinding,
  type PlatformWrapProfile,
} from './internal/platformwrap.js'
