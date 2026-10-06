// The kit's own KDF worker, dist/kdf.worker.js. This is the one module that
// names the file: a bundler that sees the pattern below (Vite, webpack 5,
// esbuild-based tools) emits the worker as a file of its own whether or not
// the code that starts it survives, so only the entries that should start it
// import this module (@thehappieco/kit/account and
// @thehappieco/kit/profiles/platform), and nothing they share with other
// entries does.

/** kitWorker starts the kit's KDF worker as a module worker. */
export function kitWorker(): Worker {
  return new Worker(new URL('../kdf.worker.js', import.meta.url), { type: 'module' })
}
