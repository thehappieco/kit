// The relying party's flow store (SPEC section 11.14, begin step 3): one
// record per pending authorization request, in IndexedDB database
// "thehappie-rp", object store "flows", keyed by state.
//
// The rule it enforces: a flow is used at most once and lives at most 10
// minutes. takeFlow reads and deletes a record in the same transaction, so
// two callbacks with one state (a reload, a second tab, a replayed URL)
// cannot both get it; every write and every take first deletes the records
// older than FLOW_TTL_MS, and a record this code cannot read is deleted as
// if it had expired.
//
// What a record holds never opens anything on its own: the ephemeral X25519
// private key is there only sealed under a non-extractable AES-GCM key
// (rp.ts), because WebKit loses IndexedDB records that hold X25519
// CryptoKeys, and a non-extractable AES key is a key no script can export.
//
// Each operation opens the database, runs one transaction and closes it.
// IndexedDB commits a transaction as soon as no request is pending at the
// end of a task, so nothing here awaits anything but IndexedDB between the
// requests of one transaction.
//
// From the platform's web/shared/oidc-rp/flows.ts at 4476bf4; the record
// also holds the product's key label (product), which the platform's
// records lack, so a record the platform's copy wrote is not read.

export const DB_NAME = 'thehappie-rp'
export const DB_VERSION = 1
export const STORE = 'flows'

/** FLOW_TTL_MS is how long a flow may wait for its callback: 10 minutes. */
export const FLOW_TTL_MS = 10 * 60 * 1000

/** FlowRecord is what begin stores (section 11.14, begin step 3). */
export interface FlowRecord {
  v: 1
  client_id: string
  redirect_uri: string
  /** The product's key label, the product of product_key_id; required with key delivery, else optional. */
  product: string | null
  nonce: string
  code_verifier: string
  /** The ephemeral public key sent as akd_pub, base64url; null without key delivery. */
  akd_pub: string | null
  /** The non-extractable AES-256-GCM key that seals the ephemeral private key. */
  aes_key: CryptoKey | null
  /** The AES-GCM nonce, 12 bytes. */
  iv: Uint8Array | null
  /** The ephemeral private key under aes_key: 32 bytes and the 16-byte tag. */
  sealed_eph: Uint8Array | null
  /** A same-origin path to go to after the callback. */
  return_to: string
  /** Milliseconds since the epoch. */
  created_at: number
}

function isCryptoKey(v: unknown): v is CryptoKey {
  return typeof CryptoKey !== 'undefined' && v instanceof CryptoKey
}

/** isLive says whether a stored value is a readable flow that has not expired. */
export function isLive(value: unknown, now: number): value is FlowRecord {
  if (typeof value !== 'object' || value === null) return false
  const r = value as Record<keyof FlowRecord, unknown>
  if (r.v !== 1 || typeof r.created_at !== 'number' || !Number.isFinite(r.created_at)) return false
  for (const text of [r.client_id, r.redirect_uri, r.nonce, r.code_verifier, r.return_to]) {
    if (typeof text !== 'string') return false
  }
  if (r.product !== null && typeof r.product !== 'string') return false
  // With key delivery all four key fields are set, and the product; without
  // it, none of the four is.
  const keyed = [typeof r.akd_pub === 'string', isCryptoKey(r.aes_key), r.iv instanceof Uint8Array, r.sealed_eph instanceof Uint8Array, typeof r.product === 'string']
  const unkeyed = r.akd_pub === null && r.aes_key === null && r.iv === null && r.sealed_eph === null
  if (!keyed.every(Boolean) && !unkeyed) return false
  const age = now - r.created_at
  // A record from the future (the clock moved back) is as stale as an old one.
  return age >= -FLOW_TTL_MS && age <= FLOW_TTL_MS
}

function factory(): IDBFactory {
  const f = (globalThis as { indexedDB?: IDBFactory | null }).indexedDB
  if (f === undefined || f === null) throw new Error('IndexedDB is not available')
  return f
}

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = factory().open(DB_NAME, DB_VERSION)
    req.onupgradeneeded = () => {
      const db = req.result
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE)
    }
    req.onsuccess = () => {
      const db = req.result
      // A newer version elsewhere (another tab after an upgrade) must not
      // wait on this connection.
      db.onversionchange = () => db.close()
      resolve(db)
    }
    req.onerror = () => reject(req.error ?? new Error('IndexedDB open failed'))
    req.onblocked = () => reject(new Error('IndexedDB open blocked'))
  })
}

/**
 * withStore runs body in one readwrite transaction and resolves with what
 * body set once the transaction has committed, so a caller never acts on a
 * write or a delete that was rolled back.
 */
async function withStore<T>(body: (store: IDBObjectStore, set: (v: T) => void) => void, initial: T): Promise<T> {
  const db = await openDB()
  try {
    return await new Promise<T>((resolve, reject) => {
      let result = initial
      const tx = db.transaction(STORE, 'readwrite')
      tx.oncomplete = () => resolve(result)
      tx.onerror = () => reject(tx.error ?? new Error('IndexedDB transaction failed'))
      tx.onabort = () => reject(tx.error ?? new Error('IndexedDB transaction aborted'))
      try {
        body(tx.objectStore(STORE), (v) => {
          result = v
        })
      } catch (err) {
        tx.abort()
        reject(err)
      }
    })
  } finally {
    db.close()
  }
}

/** purge deletes, inside the caller's transaction, every record that is not a live flow. */
function purge(store: IDBObjectStore, now: number, keep?: string): void {
  const req = store.openCursor()
  req.onsuccess = () => {
    const cursor = req.result
    if (cursor === null) return
    if (cursor.key !== keep && !isLive(cursor.value, now)) cursor.delete()
    cursor.continue()
  }
}

/** putFlow stores a flow under its state, after deleting the stale ones. */
export async function putFlow(state: string, record: FlowRecord, now: number): Promise<void> {
  await withStore<undefined>((store) => {
    purge(store, now)
    store.put(record, state)
  }, undefined)
}

/**
 * takeFlow returns the live flow stored under state, or null, and deletes
 * it either way, in one transaction; stale records go with it.
 */
export async function takeFlow(state: string, now: number): Promise<FlowRecord | null> {
  return withStore<FlowRecord | null>((store, set) => {
    const get = store.get(state)
    get.onsuccess = () => {
      const value: unknown = get.result
      store.delete(state)
      set(isLive(value, now) ? value : null)
    }
    purge(store, now, state)
  }, null)
}

/** deleteFlow deletes the flow stored under state, if any. */
export async function deleteFlow(state: string): Promise<void> {
  await withStore<undefined>((store) => {
    store.delete(state)
  }, undefined)
}
