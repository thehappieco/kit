// Per-product keys (SPEC section 11.4).
//
//   sk_p = HKDF(IKM = root, salt = "thehappie-id/v1/product-key",
//               info = product + "|" + decimal(epoch), L = 32)
//   pk_p = X25519(sk_p, 9)
//   product_key_id = product + ":" + decimal(epoch)
//
// The rule it enforces: each product gets its own X25519 key from the one
// root, and no product key opens another product's data. Any 32 bytes are a
// valid X25519 private key, so the HKDF output is used as it is. pk_p is
// hpke.publicFromPrivate, which zeroes the PKCS#8 copy of sk_p it builds for
// WebCrypto. The product registry is the platform's: any valid id derives.
// From the platform's web/shared/crypto/productkey.ts.

import { encodeUTF8, type Bytes } from '../../bytes.js'
import { HPKEError, PlatformError } from '../../errors.js'
import { publicFromPrivate } from '../../hpke.js'
import { LABEL_PRODUCT_KEY, ROOT_LEN } from './profile.js'
import { isEpoch } from './rootwrap.js'

const PRODUCT_PATTERN = /^[a-z][a-z0-9-]{0,31}$/

/** isProduct says whether s is a product id: [a-z][a-z0-9-]{0,31}. */
export function isProduct(s: unknown): s is string {
  return typeof s === 'string' && PRODUCT_PATTERN.test(s)
}

function check(product: string, epoch: number): void {
  if (!isProduct(product)) throw new PlatformError('not a product id', 'product_key')
  if (!isEpoch(epoch)) throw new PlatformError('not a key epoch', 'product_key')
}

/** productKeyId is "product:epoch", for example "wappie:1". */
export function productKeyId(product: string, epoch: number): string {
  check(product, epoch)
  return `${product}:${epoch}`
}

/** ProductKey is one product's pair; sk is for the caller to zero. */
export interface ProductKey {
  sk: Bytes
  pub: Bytes
  id: string
}

// lacksX25519 says whether err is hpke's refusal because the engine has no
// X25519 at all (its cause a NotSupportedError, a DOMException, matched by
// name so that one from another realm counts too), which says nothing about
// the key.
function lacksX25519(err: unknown): err is HPKEError {
  if (!(err instanceof HPKEError)) return false
  const cause = err.cause
  return typeof cause === 'object' && cause !== null && (cause as { name?: unknown }).name === 'NotSupportedError'
}

/**
 * deriveProductKey derives sk_p and pk_p from the root; a product id, epoch
 * or root that names no key is product_key. An engine without X25519 is not
 * a verdict on the key: hpke's HPKEError (invalid_key, its cause the
 * engine's NotSupportedError) is thrown as it is, rather than product_key,
 * which would say that a key bundle's listed keys are not this root's.
 */
export async function deriveProductKey(root: Uint8Array, product: string, epoch: number): Promise<ProductKey> {
  check(product, epoch)
  if (!(root instanceof Uint8Array) || root.length !== ROOT_LEN) {
    throw new PlatformError('a root is 32 bytes', 'product_key')
  }
  const ikm = new Uint8Array(root) as Bytes
  let sk: Bytes
  try {
    const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
    sk = new Uint8Array(
      await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: encodeUTF8(LABEL_PRODUCT_KEY), info: encodeUTF8(`${product}|${epoch}`) }, base, 256),
    ) as Bytes
  } finally {
    ikm.fill(0)
  }
  try {
    return { sk, pub: await publicFromPrivate(sk), id: `${product}:${epoch}` }
  } catch (err) {
    sk.fill(0)
    if (lacksX25519(err)) throw err
    throw new PlatformError('the engine refuses this product key', 'product_key')
  }
}

/** productPublicKey derives pk_p alone; sk_p never leaves this function. */
export async function productPublicKey(root: Uint8Array, product: string, epoch: number): Promise<Bytes> {
  const { sk, pub } = await deriveProductKey(root, product, epoch)
  sk.fill(0)
  return pub
}
