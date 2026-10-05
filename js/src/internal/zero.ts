// zero overwrites key material with zeros once the code holding it is done,
// in finally blocks. JavaScript cannot promise that no copy remains (an
// engine may have moved or copied a buffer, and a string cannot be cleared);
// what the kit holds, it zeroes.

/** zero fills every given buffer with zeros; undefined and null are skipped. */
export function zero(...buffers: (Uint8Array | undefined | null)[]): void {
  for (const b of buffers) b?.fill(0)
}

/**
 * isAllZero says whether every byte of b is zero, folding the bytes together
 * without an early exit, so the time taken depends only on the length.
 */
export function isAllZero(b: Uint8Array): boolean {
  let any = 0
  for (let i = 0; i < b.length; i++) any |= b[i]
  return any === 0
}
