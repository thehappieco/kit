// Argon2id, off the main thread.
//
// The derivation is deliberately expensive, and on the main thread it freezes
// the tab for the whole of it. A page that stops responding reads as broken,
// and somebody will reload it halfway through creating an account.
//
// The account module (and the platform profile's default entry) starts this
// worker from ./kdf.worker.js, or from the factory a caller passes as
// options.worker, and speaks version 2 of its protocol to it: a hello
// answered with ready before the password is transferred, the bounds checked
// again here, a refusal told apart from a failure. Version 1 (KDFRequest) is
// still answered as in v0.1.0, and nothing is posted unasked. The logic is
// internal/kdfrun.ts, so the tests run it without a Worker; this module only
// wires it to the message port. From Wappie's
// packages/client/src/crypto/kdf.worker.ts, with the platform's handshake
// (its web/shared/crypto/kdf.worker.ts and argon2.ts at 75b6b94).

import { runKDFMessage } from './internal/kdfrun.js'

export type {
  KDFWorkerBounds,
  KDFWorkerHello,
  KDFWorkerParams,
  KDFWorkerReason,
  KDFWorkerRequest,
  KDFWorkerResponse,
} from './internal/kdfrun.js'

/** KDFRequest is version 1 of the protocol (v0.1.0), still answered: {ok: true, master} or {ok: false, error}. */
export interface KDFRequest {
  /** The prepared password bytes; a string is taken as its UTF-8. */
  password: Uint8Array | string
  salt: Uint8Array
  m: number
  t: number
  p: number
}

const scope = self as unknown as {
  onmessage: ((event: MessageEvent<unknown>) => void) | null
  postMessage(message: unknown, transfer?: Transferable[]): void
}

scope.onmessage = (event: MessageEvent<unknown>) => {
  const { response, transfer } = runKDFMessage(event.data)
  // Transferred rather than copied: the buffer is done with here.
  scope.postMessage(response, transfer)
}
