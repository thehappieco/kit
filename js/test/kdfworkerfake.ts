// A stand-in for the kit's KDF worker: the worker's real handler
// (internal/kdfrun.ts) behind a message boundary that clones what is posted
// and transfers what is listed, as a real postMessage does, and a record of
// what it saw. It runs where there is no Worker (Node), and lets a test make
// the worker fail in each of the ways a page must survive.

import { runKDFMessage } from '../src/internal/kdfrun.js'

export interface FakeState {
  /** How many workers the factory made. */
  started: number
  /** Every message the page posted, in order, as the worker received it. */
  received: unknown[]
  /** Every answer the worker posted, as the page received it. */
  answers: unknown[]
  /** The password buffers the worker received, which it must zero. */
  passwords: Uint8Array[]
  /** How many workers were terminated. */
  terminated: number
}

export interface FakeOptions {
  /** Answer the hello with this instead (a version-1 worker answers it with a failure). */
  hello?: unknown
  /** Never answer anything. */
  silent?: boolean
  /** An error event instead of the answer to the hello, as a worker that fails to load. */
  failToLoad?: boolean
  /** An error event once the password is sent, instead of deriving. */
  dieAfterSend?: boolean
  /** A messageerror event once the password is sent: an answer that could not be read. */
  unreadableAnswer?: boolean
  /** Answer the derivation with this instead. */
  answer?: unknown
}

export function fakeKDFWorker(o: FakeOptions = {}) {
  const state: FakeState = { started: 0, received: [], answers: [], passwords: [], terminated: 0 }
  const factory = () => {
    state.started++
    let terminated = false
    const w = {
      onmessage: null as ((e: MessageEvent) => void) | null,
      onerror: null as ((e: ErrorEvent) => void) | null,
      onmessageerror: null as ((e: MessageEvent) => void) | null,
      postMessage(msg: unknown, transfer: Transferable[] = []) {
        const data = structuredClone(msg, { transfer })
        state.received.push(data)
        const d = data as Record<string, unknown>
        const isHello = d !== null && typeof d === 'object' && d.v === 2 && !('prepared' in d)
        if (d !== null && typeof d === 'object' && d.prepared instanceof Uint8Array) state.passwords.push(d.prepared)
        setTimeout(() => {
          if (o.silent || terminated) return
          if (isHello && o.failToLoad) return w.onerror?.({ preventDefault() {} } as ErrorEvent)
          if (isHello && o.hello !== undefined) return answer(o.hello, [])
          if (!isHello && o.dieAfterSend) {
            ;(d.prepared as Uint8Array).fill(0)
            return w.onerror?.({ preventDefault() {} } as ErrorEvent)
          }
          if (!isHello && o.unreadableAnswer) {
            ;(d.prepared as Uint8Array).fill(0)
            return w.onmessageerror?.({} as MessageEvent)
          }
          const { response, transfer: back } = runKDFMessage(data)
          answer(!isHello && o.answer !== undefined ? o.answer : response, back)
        }, 0)
      },
      terminate() {
        if (!terminated) state.terminated++
        terminated = true
      },
    }
    const answer = (msg: unknown, transfer: Transferable[]) => {
      const data = structuredClone(msg, { transfer })
      state.answers.push(data)
      w.onmessage?.({ data } as MessageEvent)
    }
    return w as unknown as Worker
  }
  return { state, factory }
}
