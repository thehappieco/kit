// X25519 private keys into WebCrypto, and fresh pairs out of it, the same
// way on every engine. The hpke module and the platform profile (x25519.ts,
// and hpkebase.ts through it) do both only through here.
//
// WebKit's WebCrypto on Linux, which WebKitGTK and WPE WebKit build on
// libgcrypt (Playwright's WebKit for Linux is WPE), carries the 32 bytes of
// an X25519 private key through a libgcrypt MPI and back. That drops a
// leading zero byte, and the 31 bytes left are refused:
//
//   - importKey('pkcs8') throws a DataError for every key whose first byte,
//     the low byte of the little-endian scalar, is 0x00: the all-zero key,
//     1 in 256 uniform keys (product keys sk_p among them), and 1 in 32 of
//     the keys Safari and OpenSSL generate, which they store clamped;
//   - generateKey throws an OperationError when its own random draw starts
//     with 0x00: 1 call in 256.
//
// Neither says anything about a key: X25519 is defined for any 32 bytes,
// and Chromium, Firefox, Node and WebKit on Apple's platforms take them all.
// So the kit goes round both, and every engine gives the same answer:
//
//   - importX25519 sets bit 0 of the first byte in the PKCS#8 copy it
//     builds. X25519 clears bits 0 to 2 of that byte before it multiplies
//     (decodeScalar25519, RFC 7748 section 5), so the imported key computes
//     exactly what the given bytes do, on every engine, and the copy never
//     starts with 0x00. The key is imported non-extractable, so the changed
//     bit never leaves WebCrypto. A JWK import would need the public key,
//     which is often what the import is for, and would put the private key
//     in a string nothing can zero;
//   - generateX25519 asks again after an OperationError, four attempts in
//     all; four in a row on that engine is 1 in 2^32. A refused draw is
//     discarded and says nothing about the key returned after it. Any other
//     error, a NotSupportedError first of all, is thrown at once.
//
// What either throws is the engine's own error: each caller names it.

import { zero } from './zero.js'

const KEY_LEN = 32

// The fixed DER prefix of a PKCS#8 id-X25519 private key (RFC 8410); the 32
// raw bytes follow it.
const PKCS8_PREFIX = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20])

// GENERATE_ATTEMPTS is how many times generateX25519 asks the engine.
const GENERATE_ATTEMPTS = 4

/**
 * importX25519 imports 32 raw bytes as a non-extractable X25519 key for
 * deriveBits. The PKCS#8 copy that carries them, with bit 0 of the first
 * byte set, is zeroed once importKey has finished with it, whatever
 * happened; the raw bytes are the caller's. Bytes that are not 32 long are
 * a TypeError; anything else is what the engine threw.
 */
export async function importX25519(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.length !== KEY_LEN) throw new TypeError('an X25519 private key is 32 bytes')
  const pkcs8 = new Uint8Array(PKCS8_PREFIX.length + KEY_LEN)
  try {
    pkcs8.set(PKCS8_PREFIX)
    pkcs8.set(raw, PKCS8_PREFIX.length)
    pkcs8[PKCS8_PREFIX.length] |= 0x01
    return await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'X25519' }, false, ['deriveBits'])
  } finally {
    zero(pkcs8)
  }
}

/**
 * generateX25519 is generateKey for an X25519 pair whose private half is
 * for deriveBits, asked again after an OperationError, GENERATE_ATTEMPTS
 * times in all. It throws the engine's last error.
 */
export async function generateX25519(extractable: boolean): Promise<CryptoKeyPair> {
  for (let attempt = 1; ; attempt++) {
    try {
      return (await crypto.subtle.generateKey({ name: 'X25519' }, extractable, ['deriveBits'])) as CryptoKeyPair
    } catch (err) {
      if (attempt >= GENERATE_ATTEMPTS || !isOperationError(err)) throw err
    }
  }
}

// An OperationError is matched by name, so that one from another realm
// counts too.
function isOperationError(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { name?: unknown }).name === 'OperationError'
}
