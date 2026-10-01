# The Happie Co kit: specification

- Spec version: 1 (kit v0.1.0)
- Status: normative for the Wappie profile, which is frozen. Sections 11 and the platform's profile are reserved.
- Vectors: every byte below is pinned by a case in `vectors/`. A case is cited as `file#case-id`.

## 1. Status and scope

The kit standardises the client-side cryptography The Happie Co's products share:

- HPKE with one fixed suite (section 4.4, and `hpke` on its own for product-key delivery);
- the sealed envelope, in direct and batch mode, with content keys, rows and grants (sections 4 and 5);
- the zero-knowledge account scheme: Argon2id, the auth/wrap split, wraps and recovery codes (section 6);
- the passkey PRF wrap (section 7);
- a key at rest in the browser (section 8);
- the request HMAC between two services (section 9);
- RFC 8785 for JSON additional data (section 10).

What a product chooses is a **profile** (section 3): labels, prefixes, magic bytes, kind names, AAD builders and bounds. Everything else is fixed, and changing it is a new format version, never a profile.

**Conformance.** An implementation conforms to a profile when it reproduces every case of that profile's vector files that is marked for its language (section 12). The Go module and the TypeScript package in this repository conform to the Wappie profile.

**Versioning.** The spec changes only additively within a major kit version: new sections, new profiles, new ops and new cases. A byte that changes is a new format version byte or a new profile, with new vectors, and the old vectors keep passing.

## 2. Conventions

- `||` is concatenation. `u16be(n)` and `u32be(n)` are big-endian unsigned integers of 2 and 4 bytes.
- `UTF-8(s)` is the UTF-8 encoding of a string.
- A **UUID** is 16 bytes in RFC 9562 order when it is bound into data, and lowercase hyphenated text (36 characters) when it is written into a string such as an HPKE info.
- **base64** is RFC 4648 section 4 with padding; **base64url** is section 5 without padding. Vector files use base64.
- **HKDF** is HKDF-SHA256 (RFC 5869). "salt = empty" means the zero-length salt, which RFC 5869 treats as `HashLen` zero bytes.
- **AES-GCM** is AES-256-GCM with a 12-byte nonce and a 16-byte tag; "ciphertext" includes the tag at its end.
- A **JSON AAD** is the UTF-8 of the JCS serialisation (section 10) of a JSON array. For the arrays in use (well-formed strings and small integers) it equals ECMAScript `JSON.stringify`. A string that is not Unicode (invalid UTF-8 in Go, a lone surrogate in TypeScript) has no JCS text, and a builder refuses it rather than writing an escape or a replacement character, so two such bindings never share an AAD (`kit/passkey-go.json#passkey/aad/refuses/*`).

## 3. Profiles

### 3.1 Parameters

| Module | Parameter | Wappie value (frozen) |
|---|---|---|
| seal | magic, bytes 0-1 | `0x57 0x53` ("WS") |
| seal | label: AAD prefix and HPKE info prefix | `wsv1` |
| seal | kind names | section 4.8 |
| account | password preparation | none: the UTF-8 bytes of the password as typed |
| account | KDF and salt bounds enforced by the client | none |
| account | auth label | `whatserver2/auth` |
| account | wrap label | `whatserver2/wrap` |
| account | wrap header | `0x02` |
| account | wrap AAD builder | `UTF-8("whatserver2/usk|" + email.trim().toLowerCase())`, ECMAScript semantics (section 6.6) |
| account | legacy v1 blobs opened as stale | yes |
| account | recovery key label | `whatserver2/recovery` |
| account | recovery proof label | `whatserver2/recovery-auth` |
| account | text encoding of auth key and recovery proof | base64 |
| account | recovery code normalisation | the standard one (section 6.7) |
| passkey | PRF evaluation prefix | `wappie/passkey-vault/v1/` |
| passkey | HKDF info | `wappie/passkey-wrap/v1` |
| passkey | envelope header | `0x01` |
| passkey | AAD builder | JSON AAD `["wappie/passkey-vault",1,rpID,userID,credentialID]` |
| browser key | AAD tag and version | `wappie/browser-account-key`, `1` |
| reqhmac | label | `wappie-mcp-hmac/v1` |
| reqhmac | headers | `X-Wappie-Reader`, `X-Wappie-Timestamp`, `X-Wappie-Nonce`, `X-Wappie-Signature` |
| reqhmac | directions | `to-reader`, `to-go` |
| reqhmac | skew; replay lifetime; replay capacity | 60 s; 61 s; 100,000 |

Appendix A lists the Wappie profile's every value in one place.

### 3.2 Fixed values

- HPKE: RFC 9180 base mode, single shot; KEM `0x0020` DHKEM(X25519, HKDF-SHA256), KDF `0x0001` HKDF-SHA256, AEAD `0x0002` AES-256-GCM.
- AES-256-GCM, 12-byte nonce, 16-byte tag; HKDF-SHA256.
- Argon2id version `0x13`, output 32 bytes.
- The envelope header layout, the AAD layout, the info grammar and the batch layout (section 4).
- The row derivation (section 4.7).
- The recovery code's generation: 150 bits, Crockford's alphabet, 6 groups of 5 (section 6.7).
- Key lengths: 32 bytes for X25519 keys, content keys, wrap keys and account keys.
- The request HMAC's canonical string and signature shape (section 9).

### 3.3 Adding a profile

A profile enters the kit when it has golden vectors in the format of section 12. Its seal kinds must pass `ValidateKinds` (Go): names unique and matching `[a-z0-9_]+`, the default `kind(0x..)` for an unnamed byte, 0x00 unnamed, the core kinds (section 4.8) named. In Go, a profile's kind type carries its domain, so a value of one profile's kind type cannot be sealed under another's label.

## 4. The envelope

### 4.1 Header

| Byte | Field | Value |
|---|---|---|
| 0-1 | magic | the profile's |
| 2 | version | `0x01` |
| 3 | suite | `0x01` (section 3.2) |
| 4 | mode | `0x01` direct, `0x02` batch |
| 5-6 | epoch | `u16be` |
| 7 | reserved | `0x00` when sealing |

A reader checks, in this order, failing with the code in brackets: length at least 8 [`short`], magic [`magic`], version [`version`], suite [`suite`], mode is 1 or 2 [`mode`], then the mode the operation expects [`mode`]. The reserved byte is not checked here: it is bound by the AAD, so a non-zero one fails as [`authentication`] (`seal-go.json#seal/batch/refuses/reserved-1`).

### 4.2 Additional data

```
AAD = UTF-8(label) || kind (1) || tenant (16) || row (16) || header (8)
```

The suffix after the label is a fixed 41 bytes, so two AADs are equal only if their labels are. Wappie's is 45 bytes. Example (`seal-go.json#seal/aad/body/batch-epoch-0`): kind 1, tenant `cc7d6b51-…`, row `11111111-…`, header `5753010102000000` gives

```
77737631 01 cc7d6b51db4b40d28e407826c8e4d835 11111111111171118111111111111111 5753010102000000
```

### 4.3 HPKE info (direct mode)

```
info = UTF-8(label "/" name(kind) "/" tenant-text "/" decimal(epoch))
```

`name(kind)` is the profile's wire name for the kind; an unnamed byte is `kind(0x` lowercase hex without leading zeros `)`, so 0x0F is `kind(0xf)` (`seal-go.json#seal/info/kind(0xf)/epoch-65535`). The string parses unambiguously from the right even when the label contains `/`. Example: `wsv1/content_key/cc7d6b51-db4b-40d2-8e40-7826c8e4d835/1` (`seal-go.json#seal/info/content_key/epoch-1`).

### 4.4 Direct mode

```
envelope = header (mode 0x01) || enc (32) || HPKE.SealBase(pk, info, AAD, plaintext)
```

At least 56 bytes (`DirectOverhead`). Any failure after the header checks, including an encapsulated key that yields no shared secret, is [`authentication`] (`seal-go.json#seal/direct/refuses/enc-zero`).

**Low-order keys** (RFC 9180 §7.1.4). An X25519 public key of low order gives an all-zero Diffie-Hellman output whatever the private key, and DHKEM must abort there, in both directions:

- Opening: with such an encapsulated key, anybody who knows the recipient's public key can compute the shared secret and seal a value of their choosing, such as a grant of a device key they hold. An implementation checks the X25519 output itself, rejecting 32 zero bytes, and does not rely on its crypto library to: such an envelope is [`authentication`]. The kit's vectors carry these forgeries, each sealed under the all-zero secret, for every low-order encoding (`kit/seal-go.json#seal/direct/forged/grant/zero`, `kit/hpke-go.json#hpke/open/forged/order-8-a`); `kit/seal-go.json#seal/direct/forger-control/grant` is the same construction with a real secret, and opens.
- Sealing: a server that hands out a low-order "public key" could open whatever is sealed to it. Sealing refuses such a key [`invalid_key`] (`kit/seal-go.json#seal/direct/refuses/low-order-key/one`); `hpke.seal` alone refuses it too [`invalid_key`] (`kit/hpke-go.json#hpke/seal/refuses/low-order-key/p`).

### 4.5 Batch mode

```
envelope = header (mode 0x02) || u32be(key_id) || nonce (12) || AES-256-GCM(content_key, nonce, plaintext, AAD)
```

At least 40 bytes (`BatchOverhead`). The key id is compared with the content key's before decryption [`key_mismatch`]. It is not in the AAD: it is bound only through the content key's own row (section 4.6), which is enough because a content key opens only at the row its id derives.

### 4.6 Content keys

A content key is 32 random bytes sealed in direct mode with kind `0x06` at `ContentKeyRow(tenant, device, id)`, at the epoch of the sealer. Its epoch is the one in the sealed key's header. A sealed key whose plaintext is not 32 bytes is [`short`]. The format allows ids 0 to 2^32−1 (`seal-go.json#seal/content-key/epoch-1/id-4294967295`). Non-normative: Wappie's store allocates 1 to 2^31−1, and uses id 0 to mean "sealed directly to the device key".

### 4.7 Rows

```
Row(ns, parts...)          = UUIDv5(ns, parts concatenated)            (SHA-1, version 5, RFC 4122 variant)
ContentKeyRow(t, d, id)    = Row(t, d || u32be(id))
GrantRow(t, d, user, e)    = Row(t, d || user || u16be(e))
```

"Tenant" is the immutable namespace values bind to, not the workspace that currently stores them: a device that moves between workspaces keeps its namespace, so what was sealed before still opens (`seal-go.json#seal/sealer/archive-namespace`). A product may derive its own rows with `Row`; Wappie's draft row is `Row(t, device || connection || draft || (reply or 16 zero bytes) || UTF-8(chat_key))` (`seal-go.json#wappie/draft-row/0`).

### 4.8 Kinds

The core kinds mean the same in every profile and every profile names them: `0x06` content key, `0x07` grant, `0x08` reserved (Wappie's `user_wrap`, never sealed). `0x00` is never named.

Wappie's kinds: `0x01 body`, `0x02 raw_proto`, `0x03 media_key`, `0x04 thumbnail`, `0x05 contact_name`, `0x06 content_key`, `0x07 device_grant`, `0x08 user_wrap`, `0x09 payload`, `0x0A push_name`, `0x0B full_name`, `0x0C business_name`, `0x0D avatar`, `0x0E mcp_draft`; `0x0F` is reserved and unnamed. Renaming a kind ever sealed in direct mode makes those envelopes unopenable.

### 4.9 Rotation (non-normative)

A sealer rotates its content key after 1000 values or 15 minutes. With random 96-bit nonces, a key must never cover more than 2^20 values; the Go `Sealer` fails rather than exceed it.

### 4.10 Overheads

Batch: 40 bytes per value. Direct: 56 bytes per value. Wappie's storage estimate depends on these.

## 5. Grants

A grant is a direct envelope with kind `0x07` at `GrantRow(tenant, device, user, epoch)`, whose plaintext is a 32-byte X25519 private key: one device's key, sealed to one person's public key, so that person reads the device's archive by signing in. Binding the device stops a grant from unlocking another device; binding the user stops a grant issued to one person from being presented as another's (`seal-go.json#seal/direct/refuses/other-user`). The user is an id the product chooses; when it changes (for example, when Wappie's `users.id` becomes the platform's `sub`), existing grants must be issued again or mapped.

## 6. The account scheme

### 6.1 Password preparation

Per profile. Wappie prepares nothing: two Unicode spellings of the same password are different passwords (`account-ts.json#account/derive/nfc/m8-t1-p1` against `.../nfd/...`).

### 6.2 KDF parameters

```json
{"alg": "argon2id", "m": 65536, "t": 3, "p": 1}
```

`m` is in KiB. A client refuses any other `alg` [`kdf`/`unsupported_alg`] and, when the profile has bounds, parameters outside them and a salt whose length is outside them [`kdf`/`out_of_bounds`], before deriving anything. Bounds are a minimum and maximum for each of m, t and p, optionally a maximum for m×t, and optionally a minimum and maximum salt length in bytes (equal values fix it; the platform's policy is exactly 16) (`kit/account-go.json#account/derive/bounded/refuses/salt-15`). Argon2id's own limits (t ≥ 1, p ≥ 1, m ≥ 8p, salt at least 8 bytes) fail as [`kdf`/`kdf_failed`]. Security note: without bounds (the Wappie profile), whoever writes the server's database can hand a client cheap parameters, or a short or reused salt.

### 6.3 Derivation

```
master = Argon2id(prepared password, salt, m, t, p, dkLen = 32, version 0x13)
auth   = HKDF(IKM = master, salt = empty, info = UTF-8(auth label),  L = 32)
wrap   = HKDF(IKM = master, salt = empty, info = UTF-8(wrap label),  L = 32)
```

The auth key is sent, written in the profile's encoding (Wappie: base64, 44 characters; `account-ts.json#account/derive/ascii/m8-t1-p1` gives `1QxiQXvUS83pJ9QLQKiPAnPaJYhx/X3R+IQS64FgiTk=`). The wrap key never leaves the client. How a server stores the auth key is the server's (Wappie: an Argon2id hash of the text; the platform: a domain-separated SHA-256).

### 6.4 The account key

An X25519 key pair; the private key is 32 raw bytes. Any 32 bytes are a valid private key.

### 6.5 Wrap envelope

```
blob = header || nonce (12) || AES-256-GCM(wrap key, nonce, key, AAD)
```

With Wappie's one-byte header and a 32-byte key, 61 bytes. Opening: if the blob is longer than `len(header) + 12` and starts with the header, try it with the AAD. Otherwise, or if that fails: a profile with legacy v1 blobs requires more than 12 bytes [`wrap`/`truncated`] and tries `nonce (12) || AES-256-GCM(wrap key, nonce, key)` with no AAD, which opens as **stale** (the caller re-wraps it); anything else is [`wrap`/`wrong_key`]. A v1 blob whose first byte happens to be the header still opens, at the cost of one failed attempt (`account-ts.json#account/unwrap/v1-starting-0x02`). A profile without legacy blobs fails a blob shorter than `len(header) + 28` as `truncated`, and everything else as `wrong_key`.

### 6.6 Wappie's wrap AAD

```
AAD = UTF-8("whatserver2/usk|" + email.trim().toLowerCase())
```

with ECMAScript's `String.prototype.trim` (WhiteSpace and LineTerminator: TAB, VT, FF, U+FEFF, every Zs character, LF, CR, U+2028, U+2029) and `toLowerCase` (full case mapping: U+0130 becomes `i` followed by U+0307, and Σ becomes ς in final position by the Final_Sigma rule). Go's `strings.TrimSpace` and `ToLower` differ on ten of the vectors (U+FEFF, U+0085, U+0130, final sigma); the Go side implements the ECMAScript rules (`account-ts.json#account/wrap-aad/*`). Because the AAD holds the email, changing the email means re-wrapping.

### 6.7 Recovery code

- Generation: 30 random bytes; each byte modulo 32 indexes `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (unbiased, as 256 is a multiple of 32); six groups of five joined by `-`. 150 bits. (`account-ts.json#account/recovery-code/counting`: bytes 0 to 29 give `01234-56789-ABCDE-FGHJK-MNPQR-STVWX`.)
- Normalisation: ECMAScript `toUpperCase` (so `ß` becomes `SS` and `ﬁ` becomes `FI`); remove everything outside `[0-9A-Z]`; `O` to `0`, `I` and `L` to `1`, `U` to `V`; require exactly 30 characters [`recovery`/`recovery_length`]; regroup as six groups of five joined by `-`.
- `recovery key = HKDF(IKM = UTF-8(normalised code, dashes included), salt = empty, info = recovery key label)`, used as a wrap key (section 6.5).
- `recovery proof = encoding(HKDF(…, info = recovery proof label))`, sent to the server, which releases the recovery wrap only against it.

## 7. Passkey PRF wrap

```
evaluation input = SHA-256(UTF-8(prefix + rpID))                    (computed by the server; one per RP)
K                = HKDF(IKM = PRF first output (32), salt = UTF-8(rpID), info = UTF-8(wrap info), L = 32)
envelope         = header || nonce (12) || AES-256-GCM(K, nonce, key (32), AAD)
```

Wrapping refuses a key that is not 32 bytes [`bad_key`], then an empty AAD [`bad_aad`], then a PRF output that is not 32 bytes [`bad_prf`]. Opening refuses an empty AAD [`bad_aad`], then an envelope of the wrong length or header [`bad_envelope`]; every other failure, a PRF output of the wrong length included, is [`open_failed`] (`passkey-ts.json#passkey/unwrap/refuses/prf-31`). A wrap bound to nothing could be presented for any passkey, so an AAD is never empty (`kit/passkey-go.json#passkey/wrap/refuses/empty-aad`); Wappie's builder refuses a binding with no JSON text (section 2). The PRF output never leaves the client, and a server must refuse to receive it. Passkeys are bound to their RP ID; a passkey of one RP never opens another's envelope.

## 8. A key at rest in the browser

A raw 32-byte X25519 private key is kept encrypted under a fresh non-extractable AES-256-GCM key, with a 12-byte nonce and a 48-byte ciphertext, and

```
AAD = JSON AAD [tag, version, userID, base64(public key)]
```

A user id with no JSON text (section 2) is refused.

On open, the key's public half is recomputed and compared with the recorded one. There are no vectors of the envelope itself, because its key cannot be exported; its AAD and its validation are vectored (`browser-account-ts.json`).

## 9. Request HMAC

```
canonical = label "\n" direction "\n" sender "\n" UPPER(method) "\n" target "\n" timestamp "\n" nonce "\n" hex(SHA-256(body))
signature = "v1=" lowercase-hex(HMAC-SHA256(key = UTF-8(secret), UTF-8(canonical)))
```

No trailing newline; the target is the raw path and query as on the request line. An empty secret is HMAC's empty key. Example (`reqhmac-go.json#reqhmac/signature/contract-to-reader`): `v1=4966d2e42ab13456589657b9df8429cd70b95f1ec2f9273e6e27b76aabe53456`.

A receiver:
1. checks the sender header itself;
2. requires the timestamp, nonce and signature headers present exactly once each and well formed: timestamp 1 to 18 decimal digits with no leading zero; nonce 22 base64url characters; signature `v1=` and 64 lowercase hex digits [`hmac_missing`];
3. requires the timestamp within the skew of its clock [`hmac_stale`];
4. computes the signature under each current secret, comparing in constant time with no early exit, and accepts if any matches [`hmac_bad`] (two secrets is a rotation);
5. admits the nonce: the key is `(direction, sender, nonce)`, kept until timestamp + lifetime; a nonce already held is [`hmac_replay`]; a cache full of live nonces fails closed [`replay_cache_full`].

Note: Wappie's Node guard also accepts the timestamp `"0"` and caps timestamps at 16 digits. Both are observable only as which refusal is logged, since such timestamps are always stale.

## 10. JCS (RFC 8785)

Both implementations write RFC 8785 text: object keys sorted by UTF-16 code units, strings with the minimal escapes (`\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, other controls as `\u00xx` in lowercase hex, everything else as itself, U+2028, U+2029, `<`, `>` and `&` included).

| | TypeScript | Go |
|---|---|---|
| null, booleans, strings, arrays, objects | yes | yes |
| integers within ±(2^53−1) | yes | yes |
| other numbers | ECMAScript formatting | refused |
| lone surrogates, invalid UTF-8 | refused | refused |
| values JSON has no word for | refused | refused |

## 11. Reserved

These sections are reserved for the platform's package, which arrives with its own vectors:

- **11.1 Per-product key derivation**: `sk_p = HKDF(IKM = root, salt = UTF-8(label), info = UTF-8(product "|" epoch))`, 32 bytes in the account key format.
- **11.2 Root wraps**: the wrap envelope of section 6.5 with the platform's header and AADs.
- **11.3 Sealed key delivery**: an HPKE seal (`hpke`) to the product's ephemeral key, with the platform's info and JSON AAD.
- **11.4 The contract**: its types, and its HMAC as section 9 with the platform's label.

## 12. Vectors

The format, the layout, the op catalogue and the provenance of every file are in `vectors/README.md` and `vectors/PROVENANCE.md`. Run the conformance suites with `make test` (both languages), `make test-go-1.26.7` (adds the byte-for-byte replays of Wappie's Go vectors), and `make cross` (fresh round trips in both directions).

## 13. Security considerations

- **The key id is outside the batch AAD** (section 4.5): bound through the content key's row instead.
- **Zeroisation is best effort.** Neither language can clear a string (the password as typed), and Go's runtime may have copied a buffer before it is cleared. What each clears:
  - Go: in `account.Derive`, the prepared password bytes and the Argon2id master key.
  - TypeScript: in `derive`, the prepared password bytes, the master key and the raw wrap key, success or failure; the KDF worker clears its own copy of the password bytes; the recovery code's HKDF input and the raw recovery key after import; a content key's raw bytes after import (`ContentKey.unwrap`); the raw key after import in `openBrowserAccountKey`.
  - Keys held as values (Go's content keys and private keys, TypeScript's non-extractable `CryptoKey`s) live as long as the values that hold them.
- **Random nonces.** At most 2^20 values per content key (section 4.9).
- **Wappie's wrap binds the email** (section 6.6): an email change needs a re-wrap.
- **No KDF bounds in the Wappie profile** (section 6.2): a downgrade by whoever writes the database. New profiles set bounds.
- **Passkeys are bound to the RP ID** (section 7).
- **All-zero shared secrets** (section 4.4). A public or encapsulated key of low order yields an all-zero X25519 output. Go's `crypto/ecdh` refuses it. The TypeScript implementation checks the output itself, with no early exit, whatever WebCrypto does, in sealing and in opening; its tests run every forgery also on a stand-in engine that lets the zeros through. The vectors carry real forgeries, which an implementation missing the check opens.
- **The reserved header byte** is bound by the AAD, not checked (section 4.1).
- **Decoy salts** for unknown accounts are a server concern and outside the kit.
- **Error codes, not messages.** Direct-mode failures are one code, so a reader is not an oracle for which binding failed.

## Appendix A. The Wappie profile

| Value | |
|---|---|
| Seal magic, label | `0x57 0x53`, `wsv1` |
| Seal kinds | section 4.8 |
| Account labels | `whatserver2/auth`, `whatserver2/wrap`, `whatserver2/recovery`, `whatserver2/recovery-auth` |
| Account wrap header; legacy v1 | `0x02`; yes |
| Account wrap AAD | `whatserver2/usk|` + `email.trim().toLowerCase()` |
| Account default KDF | `argon2id`, m 65536, t 3, p 1; no bounds; no preparation |
| Text encoding | base64 with padding |
| Passkey prefix, info, header | `wappie/passkey-vault/v1/`, `wappie/passkey-wrap/v1`, `0x01` |
| Passkey AAD | `["wappie/passkey-vault",1,rpID,userID,credentialID]` |
| Browser key AAD | `["wappie/browser-account-key",1,userID,base64(public key)]` |
| Request HMAC | `wappie-mcp-hmac/v1`; `X-Wappie-Reader`, `-Timestamp`, `-Nonce`, `-Signature`; `to-reader`, `to-go`; skew 60 s; replay lifetime 61 s; capacity 100,000 |

## Appendix B. Changes

- Spec 1 (kit v0.1.0): first version, from Wappie at `8c0c1f74103bc6bb65a93b13613ad1964d4399c4`. Beyond Wappie, and only for inputs that never produced openable data: the low-order checks of section 4.4 in TypeScript, the salt bound of section 6.2, the refusal of empty passkey AADs (section 7) and of JSON AADs with no JCS text (section 2).
