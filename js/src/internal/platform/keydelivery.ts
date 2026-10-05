// Key delivery (SPEC section 11.12): the product key sealed in the id. page
// to a key that only the product's page holds, and opened there.
//
//   sk_p, pk_p     = the product key pair (section 11.4) for (product, epoch)
//   product_key_id = product + ":" + decimal(epoch)
//   info = "thehappie-id/v1/key-delivery"
//   aad  = JCS(["thehappie-id/key-delivery", 1, iss, client_id, redirect_uri, sub,
//               product_key_id, b64url(pk_p), code_challenge, nonce])
//   (enc, ct)  = HPKE.SealBase(pkR = akd_pub, info, aad, pt = sk_p)
//   akd_sealed = enc (32) || ct (32) || tag (16)                      80 bytes
//
// The rule it enforces: sk_p opens only with the ephemeral private key of
// the one authorization request it was sealed for, and only for the issuer,
// client, redirect URI, account, product key, PKCE challenge and nonce of
// that request. A blob moved to another flow, another client or another
// account does not open; a blob whose enc is not the canonical spelling of
// its point does not open, whatever the engine would do; and a blob that
// opens must hold the private half of the product key the ID token names,
// compared in constant time.
//
// What it does not do: HPKE base mode does not authenticate the sender.
// Anyone who knows akd_pub can seal a key of their choosing under a binding
// they also write into an ID token, and it opens and matches. The relying
// party (@thehappieco/kit/oidc-rp) keeps a delivered key only once its own
// server has named the same sub, product_key_id and product_key (section
// 11.14 step 9).
//
// The seal runs on the id. page (deliverProductKey); the open on the
// product's page (openProductKey, from oidc-rp). The HPKE is hpkebase.ts,
// whose key schedule is wiped; the keys around it go through x25519.ts,
// which zeroes the PKCS#8 buffers that carry them into WebCrypto.
// JavaScript cannot guarantee that memory is wiped (SPEC section 13); what
// this code holds, it zeroes.
//
// Every refusal is PlatformError key_delivery, or product_key for a root,
// product or epoch that names no key and for a blob that opens to another
// key than pk_p. An engine without X25519 is not a verdict on a blob: the
// hpke module's HPKEError invalid_key, its cause the engine's
// NotSupportedError, passes through (SPEC section 11.10), as it does, its
// cause the engine's last error, from an engine that cannot generate the
// akd_pub check's probe or the ephemeral key.
//
// From the platform's web/shared/crypto/keydelivery.ts at 4476bf4.

import { Base64Error, encodeUTF8, equal, fromBase64URL, toBase64URL, type Bytes } from '../../bytes.js'
import { HPKEError, PlatformError, type PlatformErrorCode } from '../../errors.js'
import { canonicalJSON } from '../../jcs.js'
import { zero } from '../zero.js'
import { openBase, sealBase } from './hpkebase.js'
import { CODE_CHALLENGE_LEN } from './pkce.js'
import { deriveProductKey, isProduct } from './productkey.js'
import { isEpoch, isSub } from './rootwrap.js'
import { checkX25519PublicKey, engineError, importX25519PrivateKey, isCanonicalX25519, lacksX25519, X25519_KEY_LEN, x25519PublicFromKey } from './x25519.js'

/** KEY_DELIVERY_INFO is the HPKE info of every key delivery, as discovery publishes it. */
export const KEY_DELIVERY_INFO = 'thehappie-id/v1/key-delivery'

/** KEY_DELIVERY_AAD_LABEL opens every key-delivery AAD. */
export const KEY_DELIVERY_AAD_LABEL = 'thehappie-id/key-delivery'

/** KEY_DELIVERY_VERSION follows the label in the AAD. */
export const KEY_DELIVERY_VERSION = 1

/** SEALED_PRODUCT_KEY_LEN is the length of akd_sealed: enc, sk_p and the tag. */
export const SEALED_PRODUCT_KEY_LEN = 80

/**
 * KeyDeliveryRequest is what the authorization request binds the seal to:
 * every AAD field except the two the product key gives (its id and public
 * key).
 */
export interface KeyDeliveryRequest {
  /** The issuer, exactly as in the ID token's iss. */
  issuer: string
  clientId: string
  redirectUri: string
  /** The account id, lowercase and hyphenated. */
  sub: string
  /** The request's code_challenge: 43 characters of base64url. */
  codeChallenge: string
  /** The request's nonce: 22 to 128 characters from [A-Za-z0-9_-]. */
  nonce: string
}

/** KeyDeliveryBinding is every AAD field: the request and the product key. */
export interface KeyDeliveryBinding extends KeyDeliveryRequest {
  /** product + ":" + decimal(epoch), for example "wappie:1". */
  productKeyId: string
  /** pk_p, 32 bytes. */
  productKey: Uint8Array
}

// Every string in a restricted JSON AAD is drawn from this set, non-empty
// here (SPEC section 11.1).
const AAD_STRING = /^[A-Za-z0-9._:/|@-]+$/
const NONCE = /^[A-Za-z0-9_-]{22,128}$/
const EPOCH_TEXT = /^[1-9][0-9]{0,9}$/

function aadText(value: unknown, what: string): string {
  if (typeof value !== 'string' || !AAD_STRING.test(value)) {
    throw new PlatformError(`${what}: empty or outside the AAD string set`, 'key_delivery')
  }
  return value
}

/** field decodes a base64url field of exactly n bytes, any refusal becoming code. */
function field(value: unknown, n: number, code: PlatformErrorCode, what: string): Bytes {
  if (typeof value !== 'string') throw new PlatformError(`${what}: not a string`, code)
  try {
    return fromBase64URL(value, n)
  } catch (err) {
    if (err instanceof Base64Error) throw new PlatformError(`${what}: ${err.message}`, code)
    throw err
  }
}

/** isProductKeyId says whether s is product:epoch with a valid product id and epoch, in its one spelling. */
export function isProductKeyId(s: unknown): s is string {
  if (typeof s !== 'string') return false
  const at = s.indexOf(':')
  if (at < 0) return false
  const product = s.slice(0, at)
  const epoch = s.slice(at + 1)
  return isProduct(product) && EPOCH_TEXT.test(epoch) && isEpoch(Number(epoch))
}

function checkRequest(r: KeyDeliveryRequest): void {
  if (typeof r !== 'object' || r === null) throw new PlatformError('no binding', 'key_delivery')
  aadText(r.issuer, 'issuer')
  aadText(r.clientId, 'client_id')
  aadText(r.redirectUri, 'redirect_uri')
  if (!isSub(r.sub)) throw new PlatformError('sub: not a lowercase UUID', 'key_delivery')
  // The challenge is the base64url of a SHA-256 digest; decoding it refuses
  // every other spelling.
  if (typeof r.codeChallenge !== 'string' || r.codeChallenge.length !== CODE_CHALLENGE_LEN) {
    throw new PlatformError('code_challenge: not 43 characters', 'key_delivery')
  }
  zero(field(r.codeChallenge, 32, 'key_delivery', 'code_challenge'))
  if (typeof r.nonce !== 'string' || !NONCE.test(r.nonce)) {
    throw new PlatformError('nonce: not 22 to 128 characters of [A-Za-z0-9_-]', 'key_delivery')
  }
}

/**
 * keyDeliveryAAD is the AAD text of SPEC section 11.12. It refuses, with
 * the code key_delivery, any field outside its spelling: a string outside
 * the AAD set or empty, a sub that is not a lowercase UUID, a product key id
 * that is not product:epoch, a product key that is not 32 bytes, a challenge
 * that is not 43 characters of strict base64url and a nonce that is not 22
 * to 128 characters of [A-Za-z0-9_-].
 */
export function keyDeliveryAAD(b: KeyDeliveryBinding): string {
  checkRequest(b)
  if (!isProductKeyId(b.productKeyId)) throw new PlatformError('product_key_id: not product:epoch', 'key_delivery')
  if (!(b.productKey instanceof Uint8Array) || b.productKey.length !== X25519_KEY_LEN) {
    throw new PlatformError('product_key: not 32 bytes', 'key_delivery')
  }
  return canonicalJSON([
    KEY_DELIVERY_AAD_LABEL,
    KEY_DELIVERY_VERSION,
    b.issuer,
    b.clientId,
    b.redirectUri,
    b.sub,
    b.productKeyId,
    toBase64URL(new Uint8Array(b.productKey)),
    b.codeChallenge,
    b.nonce,
  ])
}

/** DeliveredProductKey is what the id. page sends to complete the authorization. */
export interface DeliveredProductKey {
  /** b64url of the 80-byte sealed key. */
  akd_sealed: string
  /** b64url of pk_p: the product key the server checks or registers. */
  product_key: string
  /** product + ":" + decimal(epoch). */
  product_key_id: string
}

/** The inputs of a seal: the root, which product key, to whom, for which request. */
export interface SealProductKeyInput {
  /** The account root, 32 bytes; the caller zeroes it. */
  root: Uint8Array
  product: string
  /** The account key epoch. */
  epoch: number
  /** akd_pub from the authorization request, base64url of 32 bytes. */
  akdPub: string
  binding: KeyDeliveryRequest
}

/**
 * deliverProductKey seals sk_p for one authorization request and returns
 * the blob with the public key it carries, which is what the id. page sends
 * to complete. In this order it checks the request's spelling, akd_pub (32
 * bytes of strict base64url passing the check of section 11.4, whatever the
 * server checked), derives the product key (product_key for a root,
 * product or epoch that names none), builds the AAD and seals under a fresh
 * ephemeral key. sk_p is zeroed before it returns, whatever happened.
 */
export async function deliverProductKey(i: SealProductKeyInput): Promise<DeliveredProductKey> {
  if (typeof i !== 'object' || i === null) throw new PlatformError('no input', 'key_delivery')
  checkRequest(i.binding)
  const akdPub = field(i.akdPub, X25519_KEY_LEN, 'key_delivery', 'akd_pub')
  await checkX25519PublicKey(akdPub, 'key_delivery')
  const { sk, pub, id } = await deriveProductKey(i.root, i.product, i.epoch)
  try {
    const aad = keyDeliveryAAD({ ...i.binding, productKeyId: id, productKey: pub })
    let sealed: Bytes
    try {
      sealed = await sealBase(akdPub, encodeUTF8(KEY_DELIVERY_INFO), encodeUTF8(aad), sk)
    } catch (err) {
      // An HPKEError is the engine's, which made no ephemeral key: not a
      // verdict on akd_pub.
      if (err instanceof HPKEError || lacksX25519(err)) throw engineError(err)
      throw new PlatformError('the product key could not be sealed to akd_pub', 'key_delivery')
    }
    if (sealed.length !== SEALED_PRODUCT_KEY_LEN) {
      throw new PlatformError('the sealed key is not 80 bytes', 'key_delivery')
    }
    return { akd_sealed: toBase64URL(sealed), product_key: toBase64URL(pub), product_key_id: id }
  } finally {
    zero(sk)
  }
}

/**
 * sealProductKey is deliverProductKey's akd_sealed alone: the base64url of
 * the 80-byte blob.
 */
export async function sealProductKey(i: SealProductKeyInput): Promise<string> {
  return (await deliverProductKey(i)).akd_sealed
}

/**
 * openProductKey is the relying party's open (SPEC section 11.12, and step
 * 7 of section 11.14): it opens a sealed key with the flow's ephemeral
 * private key, as a non-extractable CryptoKey or as 32 raw bytes, and
 * returns sk_p for the caller to zero.
 *
 * It refuses with key_delivery a binding with no AAD, a blob that is not 80
 * bytes, whose enc is not the canonical encoding of an X25519 point, that
 * does not open for this key and binding, or that does not hold 32 bytes,
 * and a raw recipient key that is not 32 bytes; and with product_key a blob
 * that opens to a key whose public half is not binding.productKey (compared
 * in constant time), whose bytes are zeroed before it throws.
 *
 * The canonical enc is stricter than RFC 9180, which lets X25519 read the
 * other spellings of a point (bit 255 set, or a value from p upwards) as the
 * point itself. WebCrypto engines and Go's crypto/hpke open a blob whose
 * sealer wrote such a spelling into both the blob and its KEM context, and
 * an engine that refuses to import it would not; an honest sealer never
 * writes one, because X25519(skE, 9) is always canonical. Refusing it here
 * and in Go's OpenProductKey gives every blob one spelling and every engine
 * one answer, as section 11.4 does for pk_p.
 *
 * A key that opens and matches is still not to be kept before the
 * product's server has named it (section 11.14 step 9; oidc-rp's
 * keepProductKey and finishSignIn do that).
 */
export async function openProductKey(recipient: CryptoKey | Uint8Array, sealed: string | Uint8Array, binding: KeyDeliveryBinding): Promise<Bytes> {
  const aad = encodeUTF8(keyDeliveryAAD(binding))
  const blob = typeof sealed === 'string' ? field(sealed, SEALED_PRODUCT_KEY_LEN, 'key_delivery', 'akd_sealed') : sealed
  if (!(blob instanceof Uint8Array) || blob.length !== SEALED_PRODUCT_KEY_LEN) {
    throw new PlatformError('a sealed key is 80 bytes', 'key_delivery')
  }
  if (!isCanonicalX25519(blob.subarray(0, X25519_KEY_LEN))) {
    throw new PlatformError('enc is not a canonical X25519 encoding', 'key_delivery')
  }
  const key = recipient instanceof Uint8Array ? await importRecipient(recipient) : recipient
  let sk: Bytes
  try {
    sk = await openBase(key, await x25519PublicFromKey(key), new Uint8Array(blob), encodeUTF8(KEY_DELIVERY_INFO), aad)
  } catch (err) {
    if (lacksX25519(err)) throw engineError(err)
    throw new PlatformError('the sealed key does not open', 'key_delivery')
  }
  if (sk.length !== X25519_KEY_LEN) {
    zero(sk)
    throw new PlatformError('the sealed key does not hold 32 bytes', 'key_delivery')
  }
  let pub: Bytes | undefined
  try {
    pub = await x25519PublicFromKey(await importX25519PrivateKey(sk))
    if (!equal(pub, new Uint8Array(binding.productKey))) {
      throw new PlatformError('the opened key is not the product key', 'product_key')
    }
  } catch (err) {
    zero(sk)
    if (err instanceof PlatformError) throw err
    throw new PlatformError('the opened key is not an X25519 key', 'key_delivery')
  }
  return sk
}

async function importRecipient(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.length !== X25519_KEY_LEN) throw new PlatformError('a recipient key is 32 bytes', 'key_delivery')
  try {
    return await importX25519PrivateKey(raw)
  } catch (err) {
    if (lacksX25519(err)) throw err
    // Every engine takes any 32 bytes (x25519.ts); one that does not has
    // refused this key.
    throw new PlatformError('the engine refuses this recipient key', 'key_delivery')
  }
}
