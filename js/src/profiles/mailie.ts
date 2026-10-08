// The Mailie profile: the labels Mailie seals and wraps under. Its values
// are wire format. Since v0.6.0 it holds Mailie's platform wrap (SPEC
// section 6.8 and Appendix D): Mailie's account key under a key derived from
// its product key sk_p, the kit's generic @thehappieco/kit/platformwrap
// under Mailie's labels. Mailie's other labels join this module when its
// scheme has vectors (SPEC section 3.3). It imports only a type, so it pulls
// in no code of its own.

import type { PlatformWrapProfile } from '../platformwrap.js'

/** PLATFORM_WRAP_LABEL opens the HKDF info and the AAD of Mailie's platform wrap. */
export const PLATFORM_WRAP_LABEL = 'mailie/platform-wrap'
/** PLATFORM_WRAP_SALT is the HKDF salt of Mailie's K_pw. */
export const PLATFORM_WRAP_SALT = 'mailie/platform-wrap/v1'
/** PLATFORM_WRAP_PRODUCT is the product of the product key ids Mailie's wraps are made for, "mailie:<epoch>". */
export const PLATFORM_WRAP_PRODUCT = 'mailie'

/**
 * mailiePlatformWrap is Mailie's platform-wrap profile, for
 * @thehappieco/kit/platformwrap: sealPlatformWrap(mailiePlatformWrap,
 * productKey, accountKey, binding), or bind(mailiePlatformWrap). None of
 * Mailie's other envelopes of its account key may start with
 * PLATFORM_WRAP_HEADER (0x03), and Mailie keeps its wraps in a column of
 * their own: the shape of a wrap is the same for every product.
 */
export const mailiePlatformWrap: PlatformWrapProfile = Object.freeze({ product: PLATFORM_WRAP_PRODUCT, salt: PLATFORM_WRAP_SALT, label: PLATFORM_WRAP_LABEL })
