import { describe, expect, it } from 'vitest'

import { formatUUID, parseUUID, type Bytes } from '../src/bytes.js'
import { importPrivateKey, publicFromPrivate, type PrivateKey } from '../src/hpke.js'
import { bind, ContentKey, contentKeyID, aad, info, openDirect, row, sealDirect, SealError, contentKeyRow, grantRow, parseHeader } from '../src/seal.js'
import { Kind, kindName, wappieSeal } from '../src/profiles/wappie.js'
import { b64, codeOf, files, forTS, raw, toB64, unhandled, withDraws, withLenientX25519, type VectorCase, type VectorFile } from './vectors.js'

const p = wappieSeal
const u = parseUUID

/** draftRow is how Wappie keeps its DraftRow on top of the kit's row. */
async function draftRow(tenant: Bytes, device: Bytes, connection: Bytes, draft: Bytes, reply: Bytes | null, chatKey: string): Promise<Bytes> {
  return row(tenant, device, connection, draft, reply ?? new Uint8Array(16), new TextEncoder().encode(chatKey) as Bytes)
}

async function keysOf(f: VectorFile): Promise<Map<string, { priv: PrivateKey; pub: Bytes }>> {
  const keys = new Map<string, { priv: PrivateKey; pub: Bytes }>()
  for (const [name, k] of Object.entries(f.keys ?? {})) {
    const priv = await importPrivateKey(b64(k.private_key_b64))
    expect(toB64(priv.publicRaw), `key ${name}`).toBe(k.public_key_b64)
    keys.set(name, { priv, pub: b64(k.public_key_b64) })
  }
  return keys
}

async function runSealCase(c: VectorCase, keys: Map<string, { priv: PrivateKey; pub: Bytes }>) {
  const i = c.in
  const priv = keys.get(i.key)?.priv as PrivateKey
  const ck = (ref: { tenant: string; device: string; id: number; sealed_b64: string }) =>
    ContentKey.unwrap(p, priv, u(ref.tenant), u(ref.device), ref.id, b64(ref.sealed_b64))
  switch (c.op) {
    case 'seal.generate_key_pair':
      // Go's randomness cannot be replayed here; the pair must still be one.
      expect(toB64(await publicFromPrivate(b64(c.out.private_key_b64)))).toBe(c.out.public_key_b64)
      return
    case 'seal.kind_name':
      expect(kindName(i.kind)).toBe(c.out.name)
      return
    case 'seal.info':
      expect(new TextDecoder().decode(info(p, i.kind, u(i.tenant), i.epoch))).toBe(c.out.info)
      return
    case 'seal.aad':
      expect(toB64(aad(p, i.kind, u(i.tenant), u(i.row), b64(i.header_b64)))).toBe(c.out.aad_b64)
      return
    case 'seal.content_key_row':
      expect(formatUUID(await contentKeyRow(u(i.tenant), u(i.device), i.id))).toBe(c.out.row)
      return
    case 'seal.grant_row':
      expect(formatUUID(await grantRow(u(i.tenant), u(i.device), u(i.user), i.epoch))).toBe(c.out.row)
      return
    case 'seal.row':
      expect(formatUUID(await row(u(i.namespace), b64(i.name_b64)))).toBe(c.out.row)
      return
    case 'wappie.draft_row':
      expect(formatUUID(await draftRow(u(i.tenant), u(i.device), u(i.connection), u(i.draft), i.reply ? u(i.reply) : null, i.chat_key))).toBe(c.out.row)
      return
    case 'seal.seal_direct': {
      if (c.error) {
        const pub = i.public_key_b64 !== undefined ? b64(i.public_key_b64) : keys.get(i.key)?.pub ?? new Uint8Array(0)
        const attempt = () => sealDirect(p, pub as Bytes, i.kind, u(i.tenant), u(i.row), i.epoch, b64(i.plaintext_b64))
        expect(await codeOf(attempt)).toBe(c.error)
        // A low-order key: refused even where WebCrypto would agree a secret with it.
        if (i.public_key_b64 !== undefined) expect(await codeOf(() => withLenientX25519(attempt))).toBe(c.error)
        return
      }
      const opened = await openDirect(p, priv, i.kind, u(i.tenant), u(i.row), b64(c.out.envelope_b64))
      expect(toB64(opened)).toBe(i.plaintext_b64)
      if (i.ephemeral_private_key_b64) {
        // Sealed by TypeScript: replay it with the ephemeral key it drew.
        const env = await withDraws({ x25519: [b64(i.ephemeral_private_key_b64)] },
          () => sealDirect(p, keys.get(i.key)!.pub, i.kind, u(i.tenant), u(i.row), i.epoch, b64(i.plaintext_b64)))
        expect(toB64(env)).toBe(c.out.envelope_b64)
      }
      return
    }
    case 'seal.open_direct': {
      const attempt = () => openDirect(p, priv, i.kind, u(i.tenant), u(i.row), b64(i.envelope_b64))
      if (c.error) {
        expect(await codeOf(attempt)).toBe(c.error)
        // A forged grant: refused even where WebCrypto would let it through.
        if (i.forged_plaintext_b64) expect(await codeOf(() => withLenientX25519(attempt))).toBe(c.error)
      } else expect(toB64(await attempt())).toBe(c.out.plaintext_b64)
      return
    }
    case 'seal.new_content_key': {
      const key = await ContentKey.unwrap(p, priv, u(i.tenant), u(i.device), i.id, b64(c.out.sealed_b64))
      expect([key.id, key.epoch]).toEqual([i.id, i.epoch])
      return
    }
    case 'seal.open_content_key': {
      const attempt = () => ContentKey.unwrap(p, priv, u(i.tenant), u(i.device), i.id, b64(i.sealed_b64))
      if (c.error) expect(await codeOf(attempt)).toBe(c.error)
      else expect((await attempt()).epoch).toBe(c.out.epoch)
      return
    }
    case 'seal.seal_batch':
      expect(toB64(await (await ck(i.content_key)).open(i.kind, u(i.tenant), u(i.row), b64(c.out.envelope_b64)))).toBe(i.plaintext_b64)
      return
    case 'seal.open_batch': {
      const key = await ck(i.content_key)
      const attempt = () => key.open(i.kind, u(i.tenant), u(i.row), b64(i.envelope_b64))
      if (c.error) expect(await codeOf(attempt)).toBe(c.error)
      else expect(toB64(await attempt())).toBe(c.out.plaintext_b64)
      return
    }
    case 'seal.content_key_id': {
      const attempt = () => contentKeyID(p, b64(i.envelope_b64))
      if (c.error) expect(await codeOf(attempt)).toBe(c.error)
      else expect(attempt()).toEqual({ id: c.out.id, epoch: c.out.epoch })
      return
    }
    case 'seal.sealer': {
      // Go's Sealer is Go only; everything it produced must open here.
      const stored = new Map<number, string>(c.out.content_keys.map((k: { id: number; sealed_b64: string }) => [k.id, k.sealed_b64]))
      const open = async (keyID: number, kind: number, rowID: string, env: string) =>
        toB64(await (await ContentKey.unwrap(p, priv, u(i.tenant), u(i.device), keyID, b64(stored.get(keyID)!))).open(kind, u(i.tenant), u(rowID), b64(env)))
      for (const [n, step] of (i.steps as { action: string; kind: number; row: string; plaintext_b64: string; values?: { kind: number; plaintext_b64: string }[] }[]).entries()) {
        const got = c.out.steps[n]
        if (step.action === 'seal') expect(await open(got.key_id, step.kind, step.row, got.envelope_b64)).toBe(step.plaintext_b64)
        if (step.action === 'seal_all') {
          for (const [j, v] of step.values!.entries()) expect(await open(got.key_id, v.kind, step.row, got.envelopes[j].envelope_b64)).toBe(v.plaintext_b64)
        }
      }
      return
    }
  }
  unhandled(c)
}

for (const [path, f] of files('wappie/golden/seal-go.json', 'wappie/golden/seal-ts.json', 'kit/seal-go.json')) {
  const keys = await keysOf(f)
  describe(path, () => {
    for (const c of f.cases.filter(forTS)) it(c.id, () => runSealCase(c, keys))
  })
}

// ---------------------------------------------------------------------------
// Legacy fixtures: byte-for-byte copies of Wappie's, read as Wappie reads them.
// ---------------------------------------------------------------------------

describe('wappie/legacy/seal-vectors.json', async () => {
  const v = raw('wappie/legacy/seal-vectors.json')
  const tenant = u(v.tenant), device = u(v.device)
  const priv = await importPrivateKey(b64(v.private_key))
  it('recovers the recorded public key', () => expect(toB64(priv.publicRaw)).toBe(v.public_key))
  const key = await ContentKey.unwrap(p, priv, tenant, device, v.content_key.id, b64(v.content_key.sealed))
  it('unwraps the content key, and not under another id or device', async () => {
    expect([key.id, key.epoch]).toEqual([v.content_key.id, v.content_key.epoch])
    await expect(ContentKey.unwrap(p, priv, tenant, device, v.content_key.id + 1, b64(v.content_key.sealed))).rejects.toThrow(SealError)
    await expect(ContentKey.unwrap(p, priv, tenant, u('00000000-0000-4000-8000-0000000000ff'), v.content_key.id, b64(v.content_key.sealed))).rejects.toThrow(SealError)
  })
  for (const b of v.batch) it(`opens ${b.kind_name}`, async () => expect(toB64(await key.open(b.kind, tenant, u(b.row), b64(b.sealed)))).toBe(b.plaintext))
  for (const d of v.direct) it(`opens direct ${d.kind_name}`, async () => expect(toB64(await openDirect(p, priv, d.kind, tenant, u(d.row), b64(d.sealed)))).toBe(d.plaintext))
  it('opens the grant only for its user', async () => {
    const r = await grantRow(tenant, device, u(v.grant.user), v.grant.epoch)
    expect(toB64(await openDirect(p, priv, Kind.DeviceGrant, tenant, r, b64(v.grant.sealed)))).toBe(v.grant.device_key)
    const other = await grantRow(tenant, device, u('00000000-0000-4000-8000-0000000000aa'), v.grant.epoch)
    await expect(openDirect(p, priv, Kind.DeviceGrant, tenant, other, b64(v.grant.sealed))).rejects.toThrow(SealError)
  })
  for (const bad of v.negatives) {
    it(`refuses ${bad.why}`, async () => {
      const attempt = bad.mode === 'direct' ? openDirect(p, priv, bad.kind, tenant, u(bad.row), b64(bad.sealed)) : key.open(bad.kind, tenant, u(bad.row), b64(bad.sealed))
      await expect(attempt).rejects.toThrow(SealError)
    })
  }
})

describe('wappie/legacy/draft-vectors.json', async () => {
  const v = raw('wappie/legacy/draft-vectors.json')
  const tenant = u(v.tenant)
  type R = { device: string; connection: string; draft: string; reply: string | null; chat_key: string; row: string; note?: string }
  const rowOf = (r: R) => draftRow(tenant, u(r.device), u(r.connection), u(r.draft), r.reply ? u(r.reply) : null, r.chat_key)
  const priv = await importPrivateKey(b64(v.private_key))
  for (const r of v.rows as R[]) it(`derives ${r.note}`, async () => expect(formatUUID(await rowOf(r))).toBe(r.row))
  it('opens the draft Go sealed', async () => {
    const opened = await openDirect(p, priv, Kind.McpDraft, tenant, await rowOf(v.draft), b64(v.draft.sealed))
    expect(new TextDecoder().decode(opened)).toBe(v.draft.plaintext)
  })
  for (const bad of v.negatives) {
    it(`refuses ${bad.why}`, async () => {
      await expect(openDirect(p, priv, bad.kind, tenant, await rowOf(bad), b64(v.draft.sealed))).rejects.toThrow(SealError)
    })
  }
})

describe('wappie/legacy/browser-grant.json and node-draft.json', () => {
  it('opens the grant the browser sealed', async () => {
    const g = raw('wappie/legacy/browser-grant.json')
    const r = await grantRow(u(g.tenant), u(g.device), u(g.user), g.epoch)
    expect(formatUUID(r)).toBe(g.grant_row)
    const priv = await importPrivateKey(b64(g.account_private_key))
    expect(toB64(await openDirect(p, priv, Kind.DeviceGrant, u(g.tenant), r, b64(g.sealed)))).toBe(g.device_key)
    await expect(openDirect(p, priv, Kind.ContentKey, u(g.tenant), r, b64(g.sealed))).rejects.toThrow(SealError)
  })
  it('opens the draft Node sealed, and not moved', async () => {
    const n = raw('wappie/legacy/node-draft.json')
    const r = await draftRow(u(n.tenant), u(n.device), u(n.connection), u(n.draft), n.reply_to_uid ? u(n.reply_to_uid) : null, n.chat_key)
    expect(formatUUID(r)).toBe(n.draft_row)
    const priv = await importPrivateKey(b64(n.archive_private_key))
    expect(new TextDecoder().decode(await openDirect(p, priv, Kind.McpDraft, u(n.tenant), r, b64(n.sealed)))).toBe(n.plaintext)
    const moved = await draftRow(u(n.tenant), u(n.device), u(n.connection), u(n.draft), null, n.chat_key)
    await expect(openDirect(p, priv, Kind.McpDraft, u(n.tenant), moved, b64(n.sealed))).rejects.toThrow(SealError)
  })
})

describe('wappie/legacy/frames.json', async () => {
  const f = raw('wappie/legacy/frames.json')
  const tenant = u(f.tenant)
  const priv = await importPrivateKey(b64(f.private_key))
  const key = await ContentKey.unwrap(p, priv, tenant, u(f.device), f.content_key.id, b64(f.content_key.sealed))
  const text = async (uid: string, kind: number, sealed: string) => new TextDecoder().decode(await key.open(kind, tenant, u(uid), b64(sealed)))
  const m = f.message
  it('opens every field of a message frame against its uid', async () => {
    expect(await text(m.uid, Kind.Body, m.body_sealed)).toBe(f.expected.body)
    expect(await text(m.uid, Kind.Payload, m.payload_sealed)).toBe(f.expected.payload)
    expect(toB64(await key.open(Kind.MediaKey, tenant, u(m.uid), b64(m.media.media_key_sealed)))).toBe(f.expected.media_key)
    expect(toB64(await key.open(Kind.Thumbnail, tenant, u(m.uid), b64(m.media.thumb_sealed)))).toBe(f.expected.thumbnail)
    expect(await text(m.uid, Kind.ContactName, m.media.filename_sealed)).toBe(f.expected.file_name)
  })
  it('opens a chat name, contact names and an avatar', async () => {
    expect(await text(f.chat.uid, Kind.ContactName, f.chat.name_sealed)).toBe(f.chat_name)
    expect(await text(f.contact.uid, Kind.PushName, f.contact.push_name_sealed)).toBe(f.contact_names.push)
    expect(await text(f.contact.uid, Kind.FullName, f.contact.full_name_sealed)).toBe(f.contact_names.full)
    expect(await text(f.contact.uid, Kind.BusinessName, f.contact.business_name_sealed)).toBe(f.contact_names.business)
    expect(toB64(await key.open(Kind.Avatar, tenant, u(f.avatar.uid), b64(f.avatar.sealed)))).toBe(f.avatar_bytes)
  })
  it('opens nothing of a frame relocated to another uid', async () => {
    for (const [kind, sealed] of [[Kind.Body, f.relocated.body_sealed], [Kind.Payload, f.relocated.payload_sealed]] as const) {
      expect(await codeOf(() => key.open(kind, tenant, u(f.relocated.uid), b64(sealed)))).toBe('authentication')
    }
  })
})

// ---------------------------------------------------------------------------
// What the move added: validation that only refuses unopenable input, and bind.
// ---------------------------------------------------------------------------

describe('input validation', () => {
  const id = u('018f3a2b-0000-7000-8000-000000000001')
  const pub = new Uint8Array(32).fill(9) as Bytes
  it('refuses an epoch that does not fit, which used to seal an unopenable blob', async () => {
    expect(await codeOf(() => sealDirect(p, pub, Kind.DeviceGrant, id, id, 65536, new Uint8Array(1) as Bytes))).toBe('invalid_input')
    expect(await codeOf(() => grantRow(id, id, id, 65536))).toBe('invalid_input')
    expect(await codeOf(() => grantRow(id, id, id, 1.5))).toBe('invalid_input')
  })
  it('refuses ids that are not 16 bytes, and content key ids out of range', async () => {
    expect(await codeOf(() => sealDirect(p, pub, Kind.DeviceGrant, id, id.subarray(0, 15) as Bytes, 1, new Uint8Array(1) as Bytes))).toBe('invalid_input')
    expect(await codeOf(() => grantRow(id, id.subarray(0, 15) as Bytes, id, 1))).toBe('invalid_input')
    expect(await codeOf(() => contentKeyRow(id, id, 2 ** 32))).toBe('invalid_input')
    expect(await codeOf(() => contentKeyRow(id, id, -1))).toBe('invalid_input')
    expect(await codeOf(() => sealDirect(p, new Uint8Array(31) as Bytes, 1, id, id, 1, new Uint8Array(1) as Bytes))).toBe('invalid_key')
  })
  it('binds a profile', async () => {
    const s = bind(p)
    expect(s.kindName(Kind.McpDraft)).toBe('mcp_draft')
    expect(s.parseHeader(new Uint8Array([0x57, 0x53, 1, 1, 2, 0, 7, 0]) as Bytes)).toEqual({ version: 1, suite: 1, mode: 2, epoch: 7 })
    expect(() => parseHeader({ ...p, magic: [1, 2] }, new Uint8Array([0x57, 0x53, 1, 1, 2, 0, 7, 0]) as Bytes)).toThrow(SealError)
  })
})
