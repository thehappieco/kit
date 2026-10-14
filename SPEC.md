# The Happie Co kit: specification

- Spec version: 8 (kit v0.8.0)
- Status: normative for the Wappie profile, which is frozen but for the addition of its platform wrap (section 6.8), for the Mailie profile (Appendix D: its account scheme, seal domain and grants, browser vault and platform wrap), for parts 1 to 3 of the platform profile (section 11), for the membership part of the platform's product contract (section 11.17), and for THCSEAL v1 and its key wrappers (section 14).
- Vectors: every byte below is pinned by a case in `vectors/`. A case is cited as `file#case-id`, the file by its bare name under `vectors/wappie/golden/` and by its path under `vectors/` otherwise (Mailie's as `mailie/golden/platform-wrap-go.json` and `mailie/key-scheme-v1/grant-go.json`), or for the platform's files as `platform/id-v1/<kind>.json#<case name>`, and `#<op>/<case name>` for a case that carries an op; a case of THCSEAL's file, `platform/thcseal-v1/thcseal-v1.json`, is cited by its list and name, `#valid/<case name>` or `#invalid/<case name>`, and so is a case of the contract's files, `platform/contract-v1/<file>.json#<list>/<case name>` (the file `<kind>.json` or `wire-item-ids.json`), or in `labels.json`, whose cases have no name, by its list and its raw label or hint (`#clean/<raw>`, `#hints/<hint>`).

## 1. Status and scope

The kit standardises the client-side cryptography The Happie Co's products share:

- HPKE with one fixed suite (section 4.4, and on its own for product-key delivery, section 11.12);
- the sealed envelope, in direct and batch mode, with content keys, rows and grants (sections 4 and 5);
- the zero-knowledge account scheme: Argon2id, the auth/wrap split, wraps and recovery codes, and a product's wrap of its account key under its product key, the platform wrap, under Wappie's and Mailie's labels (section 6);
- the passkey PRF wrap (section 7);
- a key at rest in the browser (section 8);
- the request HMAC between two services (section 9);
- RFC 8785 for JSON additional data (section 10);
- the platform's account core: its password profile, KDF policy, root wraps, recovery code, per-product keys, server verifiers, email normalisation and key bundle (section 11);
- the platform's sealed key delivery, PKCE and the relying party of its OpenID Connect provider, page and server (sections 11.12 to 11.15);
- the platform's passkeys with PRF: the key a passkey's PRF output gives for the root wrap, and the allowlist of the client extension results the id. server accepts (section 11.16);
- the membership part of the platform's product contract, Go only: the signature of its requests and answers, the types that cross it and their rules, the mask of an item's label, an app's client and a fake platform for an app's tests (section 11.17);
- the envelope of a server's tier-2 secrets, THCSEAL v1, and its key wrappers, AWS KMS and a local key-encryption key for development and tests (section 14).

What a product chooses is a **profile** (section 3): labels, prefixes, magic bytes, kind names, AAD builders and bounds. Everything else is fixed, and changing it is a new format version, never a profile.

**Conformance.** An implementation conforms to a profile when it reproduces every case of that profile's vector files that is marked for its language (section 12). The Go module and the TypeScript package in this repository conform to the Wappie profile, to the Mailie profile (its account scheme, seal domain and grants, browser vault and platform wrap) and to parts 1 to 3 of the platform profile. An implementation of THCSEAL v1 conforms when it opens every valid envelope of its vector file and refuses every invalid one with its error (sections 12.3 and 14); the Go module does, and there is no TypeScript, since only servers seal tier-2 secrets. An implementation of the contract conforms when it reproduces every canonical string and signature of its vector files, ends every answer check as they record, and accepts and refuses every secret, document, snapshot, event, label and hint as they say (section 11.17); the Go module does, and there is no TypeScript, since both apps' contract clients are servers.

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
| account | wrap AAD builder | `UTF-8("whatserver2/usk\|" + email.trim().toLowerCase())`, ECMAScript semantics (section 6.6) |
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
| platformwrap | product, HKDF salt, label (section 6.8) | `wappie`, `wappie/platform-wrap/v1`, `wappie/platform-wrap` |

Appendix A lists the Wappie profile's every value in one place, and Appendix D the Mailie profile's. The platform profile (section 11) sets these parameters too, listed in Appendix C; its root wrap is the wrap envelope of section 6.5 with a two-byte header.

### 3.2 Fixed values

- HPKE: RFC 9180 base mode, single shot; KEM `0x0020` DHKEM(X25519, HKDF-SHA256), KDF `0x0001` HKDF-SHA256, AEAD `0x0002` AES-256-GCM.
- AES-256-GCM, 12-byte nonce, 16-byte tag; HKDF-SHA256.
- Argon2id version `0x13`, output 32 bytes.
- The envelope header layout, the AAD layout, the info grammar and the batch layout (section 4).
- The row derivation (section 4.7).
- The recovery code's generation: 150 bits, Crockford's alphabet, 6 groups of 5 (section 6.7).
- Key lengths: 32 bytes for X25519 keys, content keys, wrap keys and account keys.
- The request HMAC's canonical string and signature shape (section 9).
- THCSEAL v1 and its key wrappers (section 14), which take no profile: the magic, the version, the provider bytes, the layout and the local KEK's label are the format's, and the encryption context is the caller's.

### 3.3 Adding a profile

A profile enters the kit when it has golden vectors in a format section 12 describes. Its labels are distinct from every label of the profiles already in the kit (Appendices A, C and D) and from every other product's; the implementations do not check this (section 6.8). Its seal kinds must pass `ValidateKinds` (Go): names unique and matching `[a-z0-9_]+`, the default `kind(0x..)` for an unnamed byte, 0x00 unnamed, the core kinds (section 4.8) named. In Go, a profile's kind type carries its domain, so a value of one profile's kind type cannot be sealed under another's label.

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

The platform profile uses its own canonical form of a recovery code (section 11.6).

### 6.8 The platform wrap

When a product's accounts sign in through the platform's id., the product keeps its account key (section 6.4) and wraps it under a key derived from its product key `sk_p` (section 11.4, delivered by section 11.12), so that what a person unlocks on id. opens what the product sealed before, and the product's export carries the wrap, so that a command-line tool opens the product's data starting from the key bundle (section 11.9: the root, then `sk_p` by 11.4, then the account key). Wappie's wrap is the platform's decision 0023; Mailie's is the same construction under its own labels. Each product's labels are a profile:

| Profile | Product (of `product_key_id`) | HKDF salt | Label (info and AAD) |
|---|---|---|---|
| Wappie (Appendix A) | `wappie` | `wappie/platform-wrap/v1` | `wappie/platform-wrap` |
| Mailie (Appendix D) | `mailie` | `mailie/platform-wrap/v1` | `mailie/platform-wrap` |

```
K_pw = HKDF(IKM = sk_p (32), salt = UTF-8(salt),
            info = JSON AAD [label, 1, user_id, sub, product_key_id], L = 32)
AAD  = JSON AAD [label, 1, user_id, sub, product_key_id, base64url(account public key)]
wrap = 0x03 || nonce (12) || AES-256-GCM(K_pw, nonce, account key (32), AAD)          61 bytes
```

- **The profile.** The product is a product id of section 11.4; the salt and the label are non-empty strings from the alphabet of section 11.1. A profile outside these is refused before anything is derived. A product's salt and label must also be distinct from every label of Appendices A, C and D and from every other product's: a rule for whoever defines the profile, held when a profile enters the kit (section 3.3), which no implementation checks, since none knows every product's labels; a profile that reuses another product's labels in that alphabet is accepted. The header, the `1` (the format's version) and the layout are the construction's, the same for every product.
- **The binding.** `user_id` is the product's id of the account: the `sub` itself for an account created through id., the product's old id for an account it had before (Wappie's `users.id`, `platform-wrap-go.json#wappie/platform-wrap/seal/linked`; `mailie/golden/platform-wrap-go.json#mailie/platform-wrap/seal/user-id-is-not-the-sub`). `sub` is id.'s account id. Both are lowercase hyphenated UUIDs (section 11.1). `product_key_id` is the profile's product, `:` and an epoch, in the grammar of section 11.12, for that product only (`platform-wrap-go.json#wappie/platform-wrap/seal/refuses/another-products-key-id`, `mailie/golden/platform-wrap-go.json#mailie/platform-wrap/seal/refuses/cross-product/a-wappie-product-key-id`, `platform-wrap-go.json#wappie/platform-wrap/seal/refuses/epoch-with-a-leading-zero`). The account public key is `X25519(account key, 9)`, 32 bytes, written in base64url without padding. Every element is drawn from the restricted alphabet of section 11.1, so the info and the AAD are the same text from any JCS or `JSON.stringify`; a binding outside these is refused before anything is derived (`platform-wrap-go.json#wappie/platform-wrap/seal/refuses/user-id-in-upper-case`). A profile may bind one id for every account instead: Mailie's user id is the person's seal id, never the sub, a departure from this rule's wording that Appendix D records; so whatever opens a product's export takes the user id from the export, never assuming the sub. The email is not bound, so an address change needs no re-wrap. The epoch is, so a new product-key epoch is a new wrap (`platform-wrap-go.json#wappie/platform-wrap/open/refuses/another-epoch`, `platform-wrap-go.json#wappie/platform-wrap/open/refuses/the-epoch-2-wrap`), and so are the user and the account (`platform-wrap-go.json#wappie/platform-wrap/open/refuses/another-user-id`, `platform-wrap-go.json#wappie/platform-wrap/open/refuses/another-sub`).
- **The key** is an HKDF branch of `sk_p` under the product's labels. `sk_p` is also an X25519 private key (section 11.4); the branch keeps the two uses apart. The binding is the HKDF info as well as the AAD, so every binding has a key of its own.
- **Products apart.** A person has a product key per product (section 11.4), and a wrap opens only under the profile it was sealed under: a Wappie wrap does not open as Mailie's, nor a Mailie wrap as Wappie's, with the same person's key of the other product (`mailie/golden/platform-wrap-go.json#mailie/platform-wrap/open/refuses/cross-product/the-same-persons-wappie-wrap`, `mailie/golden/platform-wrap-go.json#wappie/platform-wrap/open/refuses/cross-product/the-same-persons-mailie-wrap`), with the very same key bytes, where only the labels and the key id's product differ (`mailie/golden/platform-wrap-go.json#mailie/platform-wrap/open/refuses/cross-product/a-wappie-wrap-under-the-same-key-bytes`, `mailie/golden/platform-wrap-go.json#wappie/platform-wrap/open/refuses/cross-product/a-mailie-wrap-under-the-same-key-bytes`), or with its own binding, whose `product_key_id` names the other product, which is refused before anything is derived (`mailie/golden/platform-wrap-go.json#mailie/platform-wrap/open/refuses/cross-product/a-wappie-wrap-with-its-own-binding`). The header is the same for every product, so the shape check does not tell products apart: each keeps its wraps in a column of its own.
- **The envelope** is the wrap envelope of section 6.5 with the one-byte header `0x03` and no legacy form: section 6.5's opener with that header and no legacy blobs opens it under `K_pw` (`platform-wrap-go.json#wappie/platform-wrap/seal/linked`). A product's other 61-byte envelopes of its account key do not start with `0x03`: Wappie's start with `0x02` (the password and recovery wraps, section 6.5) and `0x01` (the passkey envelope, section 7), so a blob in the wrong column fails at its header, not at its tag (`platform-wrap-go.json#wappie/platform-wrap/open/refuses/header-0x01-the-passkey-envelope`, `platform-wrap-go.json#wappie/platform-wrap/open/refuses/header-0x02-the-password-wrap`, `mailie/golden/platform-wrap-go.json#mailie/platform-wrap/open/refuses/header-0x02`). The header is not in the AAD; it is checked exactly, and `K_pw` keys nothing else.
- **Sealing** refuses, before anything is encrypted, an account key that is not 32 bytes or whose public half is not the binding's, compared in constant time (`platform-wrap-go.json#wappie/platform-wrap/seal/refuses/account-key-not-the-public-keys`), a product key that is not 32 bytes (`platform-wrap-go.json#wappie/platform-wrap/seal/refuses/product-key-of-31-bytes`), and a profile or a binding outside its spelling; it then draws a fresh random nonce, and self-tests: the new wrap is opened again and compared with the account key, and a wrap that fails is never returned.
- **Opening** checks 61 bytes and the header `0x03` first, then the product key's 32 bytes, the profile and the binding, the tag, and that the opened key's public half is the binding's, compared in constant time, clearing the key otherwise (`platform-wrap-go.json#wappie/platform-wrap/open/refuses/opens-to-another-accounts-key`, `mailie/golden/platform-wrap-go.json#mailie/platform-wrap/open/refuses/opens-to-another-accounts-key`: a wrap that authenticates under its own AAD around another account's key). The caller also compares the public key with the one the product's server holds for the account (Wappie's `users.public_key`).
- **Every refusal is one error** (`platform_wrap`: Go `platformwrap.ErrPlatformWrap`, which Wappie's profile names `ErrPlatformWrap`; TypeScript `PlatformWrapError`), so the order of the checks is not observable, and which one failed is not said beyond a message that never repeats a key.
- **The server** cannot open a wrap: it checks the length and the header only (`CheckShape`, `checkPlatformWrapShape`).
- **Symmetric on purpose.** An HPKE seal to `pk_p` could be made by anyone who holds `pk_p`, the product's server included, which could then plant an account key of its choosing; only a holder of `sk_p` makes this wrap.

Implementations: Go `platformwrap` with a `Profile` (`profiles/wappie.PlatformWrap()`, `profiles/mailie.PlatformWrap()`; Wappie's profile keeps the names of v0.5.0, `SealPlatformWrap` and the rest, bound to its labels), TypeScript `@thehappieco/kit/platformwrap` with a `PlatformWrapProfile` (`wappiePlatformWrap` of `profiles/wappie`, which keeps v0.5.0's bound functions, and `mailiePlatformWrap` of `profiles/mailie`).

Vectors: Wappie's, `wappie/golden/platform-wrap-go.json` (55 cases, 31 must fail) and `wappie/golden/platform-wrap-ts.json` (22 cases, 10 must fail), written by the Go and TypeScript modules of Wappie's console with the header of this section (`vectors/PROVENANCE.md`), and the console's own file, `wappie/legacy/platform-wrap-vectors.json`, which both implementations run and write again byte for byte; Mailie's, `mailie/golden/platform-wrap-go.json` (60 cases, 36 must fail, 7 of them across the two products), written by the kit's Go implementation, which TypeScript opens; and Mailie's own, `mailie/key-scheme-v1/platform-wrap-go.json` (31 cases, 18 must fail), which binds the seal id as the user id (Appendix D). Every refusal of the construction is `platform_wrap`; those of Mailie's binding in Mailie's file are `binding` (`mailie/key-scheme-v1/platform-wrap-go.json#mailie/platform-wrap-binding/refuses/seal-id-the-sub`). The console's module had the header `0x01`, the passkey envelope's; every other byte of its wraps is unchanged. The kit's own round trips, in the format of section 12.1, are `kit/wappie-platform-wrap-go.json` and `kit/wappie-platform-wrap-ts.json` for Wappie's wrap, and `kit/mailie-platform-wrap-go.json` and `kit/mailie-platform-wrap-ts.json` for Mailie's, each of whose wraps is also refused under Wappie's labels. Kit v0.6.0 made the construction generic; no byte of Wappie's wrap moved.

## 7. Passkey PRF wrap

```
evaluation input = SHA-256(UTF-8(prefix + rpID))                    (computed by the server; one per RP)
K                = HKDF(IKM = PRF first output (32), salt = UTF-8(rpID), info = UTF-8(wrap info), L = 32)
envelope         = header || nonce (12) || AES-256-GCM(K, nonce, key (32), AAD)
```

Wrapping refuses a key that is not 32 bytes [`bad_key`], then an empty AAD [`bad_aad`], then a PRF output that is not 32 bytes [`bad_prf`]. Opening refuses an empty AAD [`bad_aad`], then an envelope of the wrong length or header [`bad_envelope`]; every other failure, a PRF output of the wrong length included, is [`open_failed`] (`passkey-ts.json#passkey/unwrap/refuses/prf-31`). A wrap bound to nothing could be presented for any passkey, so an AAD is never empty (`kit/passkey-go.json#passkey/wrap/refuses/empty-aad`); Wappie's builder refuses a binding with no JSON text (section 2). The PRF output never leaves the client, and a server must refuse to receive it. Passkeys are bound to their RP ID; a passkey of one RP never opens another's envelope.

The scheme does not check the relying party id's spelling: the profile or the product checks it where the id is configured. An id that ends in a number (section 11.16), which a browser reads as an IPv4 address or refuses, is never a relying party; the kit exports that check (Go `passkey.EndsInANumber`, TypeScript `endsInANumber` of the `passkey` module) and the platform profile applies it.

The platform profile's passkeys are this scheme with the platform's passkey profile, its root-wrap header and AAD (section 11.16).

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

The platform's product contract uses this scheme under its own label and headers, signs its answers too, with the other direction, and binds each answer to its request by echoing the request's nonce (section 11.17).

## 10. JCS (RFC 8785)

Both implementations write RFC 8785 text: object keys sorted by UTF-16 code units, strings with the minimal escapes (`\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, other controls as `\u00xx` in lowercase hex, everything else as itself, U+2028, U+2029, `<`, `>` and `&` included).

| | TypeScript | Go |
|---|---|---|
| null, booleans, strings, arrays, objects | yes | yes |
| integers within ±(2^53−1) | yes | yes |
| other numbers | ECMAScript formatting | refused |
| lone surrogates, invalid UTF-8 | refused | refused |
| values JSON has no word for | refused | refused |

## 11. The platform profile

- Status: **parts 1 to 3 are normative**: the account core of the platform's protocol `id-v1` (`thehappie-id/v1`, sections 11.1 to 11.11), from the platform's `docs/protocol/id-v1.md` sections 1, 2 and 6 at platform commit `5e66d84`, with one change: the run rule of the password profile (section 11.2, step 2) counts more, so that Go and ICU never prepare one password two ways; key delivery, PKCE and the relying party (sections 11.12 to 11.15), from its sections 7.5, 7.6, 7.8, 7.10 and 7.14 at platform commit `4476bf4`; and passkeys with PRF (section 11.16), from its sections 8.2 and 8.5 at platform commit `b5d9f69`, with the relying party rule of its section 8.1 at platform commit `75b6b94`; and, Go only, the membership part of the platform's product contract (section 11.17), from its `docs/contract/v1/README.md` and `internal/contract`, taken at platform commit `a78bf16` and brought to `ee45e3a`, and the README to `8a7b73c`, whose `internal/contract` is unchanged.
- Implementations: Go `profiles/platform`, TypeScript `@thehappieco/kit/profiles/platform`; for the relying party, Go `oidcrp` (its server) and TypeScript `@thehappieco/kit/oidc-rp` (its page); for the contract, Go `contract` and `contract/contracttest`, with the signature's values named in `profiles/platform` too. Unlike the other modules, their functions take no profile argument: they are the platform's protocol. Where a generic module does the work, they hand it the platform's values (Appendix C): sections 6.3, 6.5 and 6.7 with the platform's labels, header and canonical form, section 10 for the AAD, and section 4.4's suite for product keys and their delivery.
- Vectors: `vectors/platform/id-v1/*.json`, written by the platform's Go code and carried byte for byte (section 12.2), and the contract's, `vectors/platform/contract-v1/*.json` (section 12.4). An implementation conforms when it reproduces every case and refuses every must-fail case with the error name the case records.

### 11.1 Values and conventions

| Value | |
|---|---|
| Password profile | `thehappie-password/v1` (11.2) |
| Password branches (HKDF info) | `thehappie-id/v1/password/auth`, `thehappie-id/v1/password/wrap` |
| Recovery branches (HKDF info) | `thehappie-id/v1/recovery/wrap`, `thehappie-id/v1/recovery/auth` |
| Product keys (HKDF salt) | `thehappie-id/v1/product-key` |
| Root-wrap AAD tag | `thehappie-id/root-wrap` |
| Verifiers | `thehappie-id/v1/auth-verifier`, `thehappie-id/v1/recovery-verifier` |
| Key bundle | format `thehappie-id/key-bundle`, version 1 |
| Key delivery (HPKE info) | `thehappie-id/v1/key-delivery` (11.12) |
| Key-delivery AAD tag | `thehappie-id/key-delivery` (11.12) |
| Relying-party flow AAD tag | `thehappie-rp/flow` (11.14) |
| Passkey PRF salt (SHA-256 input prefix) | `thehappie-id/v1/passkey-prf\|` (11.16) |
| Passkey wrap key (HKDF info) | `thehappie-id/v1/passkey/wrap` (11.16) |
| Text encoding of keys and proofs | base64url without padding |

The platform's server-side labels (`thehappie-platform/v1/...`: decoy salts, email codes, mail references) and its secrets are the platform's and are not in the kit.

- **Strict base64url.** RFC 4648 section 5 without padding, with exactly one accepted spelling per value: a decoder refuses padding, characters outside the alphabet (whitespace and line breaks included), non-zero trailing bits and any length other than the one expected (`platform/id-v1/key-bundle.json#a padded kdf_salt`).
- **sub.** An account id as lowercase hyphenated UUID text, 36 characters; `sub16` is its 16 bytes. The version nibble is not checked: the server issues UUIDv7, and the nil UUID is the dummy sub of section 11.7 (`platform/id-v1/verifier.json#a sub in upper case`).
- **epoch.** An integer from 1 to 2^31 − 1 (`platform/id-v1/root-wrap.json#an epoch of 2^31`).
- **Restricted JSON AAD.** The JCS text (section 10) of an array whose strings are drawn from `[A-Za-z0-9._:/|@-]` and whose integers are 0 to 2^31. For such arrays JCS, `JSON.stringify` and Go's `encoding/json` agree byte for byte. Anything else is refused, never escaped (`platform/id-v1/root-wrap.json#a relying party outside the AAD alphabet`). In a root-wrap AAD every string is also non-empty.
- **Errors** are the names of section 11.10. Messages never contain the refused value.

### 11.2 Password profile `thehappie-password/v1`

Given the password as typed, in this order:

1. It is well-formed Unicode; otherwise `password_invalid` (`platform/id-v1/password-profile.json#a lone high surrogate`).
2. Its compatibility decomposition (NFKD) holds no run of more than 30 consecutive counted code points; otherwise `password_invalid` (`platform/id-v1/password-profile.json#thirty-one combining accents on one letter are refused`, `platform/id-v1/password-profile.json#thirty-one spacing marks are refused too`, `kit/platform-password-go.json#platform/prepare-password/stream-safe/compatibility-vowel-jamo/31`, `kit/platform-password-go.json#platform/prepare-password/stream-safe/syllable-then-acutes/29`, `kit/platform-password-go.json#platform/prepare-password/stream-safe/acute-accent-then-acutes/30`; at the limit, `kit/platform-password-go.json#platform/prepare-password/stream-safe/syllable-then-acutes/28`). A code point is counted if it is of general category M, a Hangul vowel or final jamo (U+1160 to U+11FF, U+D7B0 to U+D7FF), or U+16D67 KIRAT RAI VOWEL SIGN E. Why: Go's `golang.org/x/text/unicode/norm` applies the Stream-Safe Text Format, inserting U+034F after 30 non-starters, and ICU does not, so beyond that limit the two would prepare different bytes. What it counts as a non-starter, in each character's compatibility decomposition, is a code point with a non-zero combining class (always a mark) or one that composes with what precedes it (a mark, a Hangul vowel or final jamo, or, from Unicode 16.0, U+16D67, a letter). So Hangul syllables, the compatibility and halfwidth jamo, and characters such as U+00B4 and U+FF9E whose compatibility decomposition holds a mark all count, as they do here; U+034F is itself a mark. Canonical reordering moves only code points with a non-zero combining class, all counted, so the runs of the whole text's NFKD are those of its code points' decompositions put end to end, and an implementation counts them code point by code point, in linear time.
3. NFC (`platform/id-v1/password-profile.json#e and a combining acute compose under NFC`), not NFKC (`platform/id-v1/password-profile.json#NFC is not NFKC: a ligature stays`).
4. U+00A0, U+1680, U+2000 to U+200A, U+202F, U+205F and U+3000 become U+0020 (`platform/id-v1/password-profile.json#every space separator becomes U+0020`). They have no composition partner, so the result stays NFC.
5. A code point from U+0000 to U+001F or from U+007F to U+009F is refused: `password_invalid`, before the length is counted (`platform/id-v1/password-profile.json#a control character is refused before the length is counted`).
6. Nothing is trimmed (`platform/id-v1/password-profile.json#spaces are not trimmed`).
7. Code points are counted. A new password (sign-up, change, recovery) has at least 12, otherwise `password_too_short`; any password has at most 256, otherwise `password_too_long` (`platform/id-v1/password-profile.json#eleven emoji are eleven code points, not twenty-two UTF-16 units`).
8. P′ is the UTF-8 of the result.

A password being presented (login, unlock, opening a key bundle) goes through every step but the minimum length.

Step 2 counts more than the platform's `id-v1.md` at `5e66d84`, which counted only category M in the NFD form: with that rule Go and ICU accepted some passwords and prepared different bytes for them (thirty-one U+3160, a Hangul syllable followed by twenty-nine acute accents), and refused others on one side only (U+00B4 followed by thirty acute accents). Every case of `platform/id-v1/password-profile.json` keeps its outcome. The platform adopted this rule (its `46cb346` and `4476bf4`); its `password-stream-safe.json` holds 19 cases at and one past the limit, each with the outcome given here (`platform/id-v1/password-stream-safe.json#thirty-one compatibility vowel jamo (U+3160) are refused`, `platform/id-v1/password-stream-safe.json#a Hangul syllable then twenty-eight acute accents is prepared`).

**Unicode versions.** NFC is stable only for characters assigned in the Unicode version both sides use. Go before 1.27 uses Unicode 15.0 tables, in `unicode` and in `x/text/unicode/norm`; Go 1.27 and current browsers use 17.0. A password with characters assigned after 15.0 that have canonical mappings could prepare differently on an older side. The vectors use only characters assigned by 15.0, apart from a refusal of thirty-one U+16D67, which every version counts. The kit's Go tests walk every code point with the toolchain's tables to check that its normaliser inserts U+034F only where step 2 refuses; should later tables count a code point step 2 does not, the Go implementation refuses (`password_invalid`) a password into which its NFC would still insert one, rather than prepare bytes ICU would not.

### 11.3 Password KDF and policy

```
master = Argon2id(P', salt (16), m, t, p, version 0x13, dkLen 32)
K_auth = HKDF(IKM = master, salt = empty, info = "thehappie-id/v1/password/auth", L = 32)
K_wrap = HKDF(IKM = master, salt = empty, info = "thehappie-id/v1/password/wrap", L = 32)
auth_key = base64url(K_auth)                                   (43 characters)
```

This is section 6.3 with the platform's labels. The bounds are compiled in; the server cannot move them.

| | floor | default | ceiling |
|---|---|---|---|
| `alg` | `argon2id` only (case-sensitive) | | |
| m (KiB) | 65536 | 65536 | 262144 |
| t | 3 | 3 | 10 |
| p | 1 | 1 | 4 |
| m × t | | | 1048576 |
| salt | exactly 16 bytes | | |

Parameters or a salt outside these are refused with `kdf_policy` **before anything is derived**, and before the password is prepared (`platform/id-v1/kdf.json#m times t over the cap with each inside its bounds`, `platform/id-v1/kdf.json#alg in another case`, `platform/id-v1/kdf.json#a salt of 15 bytes`). A parameter that is not an integer, or a member other than `alg`, `m`, `t` and `p`, is refused the same way.

**The salt is the server's.** An account's salt is fixed per address for life and handed out by the server, which derives it as the platform's decoy salt. A client of this profile never draws a salt: every derivation takes it as an argument. Raising the default or the floor is a new protocol version.

### 11.4 Account root and per-product keys

```
root = 32 random bytes, made by the client at sign-up, never sent or stored in clear
sk_p = HKDF(IKM = root, salt = UTF-8("thehappie-id/v1/product-key"), info = UTF-8(product "|" decimal(epoch)), L = 32)
pk_p = X25519(sk_p, 9)
product_key_id = product ":" decimal(epoch)
```

`sk_p` is used as is, because any 32 bytes are an X25519 private key (section 6.4). A product id matches `[a-z][a-z0-9-]{0,31}`; since it never holds `|` and the epoch has no leading zero, each (product, epoch) has exactly one info. A root of another length, another id or an epoch out of range is `product_key` (`platform/id-v1/product-key.json#a product id with a pipe`). The product registry is the platform's: any valid id derives (`platform/id-v1/product-key.json#a valid product id outside the registry`).

**The server's check of a submitted `pk_p`:** 32 bytes; the canonical encoding (bit 255 clear and the value below 2^255 − 19), because X25519 accepts other spellings as aliases and a pinned key must have one; and an X25519 exchange with a fresh private key does not give 32 zero bytes, which refuses the low-order points (section 4.4). Any failure is `product_key`. This check is also the one of 11.12 for `akd_pub`.

A product may wrap its own keys under a key derived from `sk_p`, an HKDF branch under labels of its own: the platform wrap, section 6.8, under each product's labels.

### 11.5 Root wraps

```
wrap = 0x01 || kind || nonce (12) || AES-256-GCM(key, nonce, root, AAD)          62 bytes
```

This is the wrap envelope of section 6.5 with the two-byte header `0x01 || kind` and no legacy form.

| kind | byte | key | AAD |
|---|---|---|---|
| password | `0x01` | `K_wrap` (11.3) | `["thehappie-id/root-wrap",1,"password",sub,epoch]` |
| recovery | `0x02` | `K_rwrap` (11.6) | `["thehappie-id/root-wrap",1,"recovery",sub,epoch]` |
| passkey | `0x03` | `K_pk` (11.16) | `["thehappie-id/root-wrap",1,"passkey",sub,epoch,rp_id,credential_id]` |

The AAD is a restricted JSON AAD (11.1). It repeats the version and the kind, so both header bytes are authenticated. It binds the immutable `sub` and the epoch, never the email: an email change needs no re-wrap, and a wrap moved to another account, epoch or kind does not open (`platform/id-v1/root-wrap.json#another sub`, `platform/id-v1/root-wrap.json#the kind byte relabelled and opened as that kind`). `rp_id` and the base64url `credential_id` are present for the passkey kind only, and non-empty; the credential id is strict base64url (`platform/id-v1/root-wrap.json#a padded credential id`, `platform/id-v1/root-wrap.json#a password wrap opened with passkey fields`). The relying party's one spelling is enforced where `K_pk` is made (11.16).

**Opening** checks the binding, the length (62), the version byte, that the kind byte is the expected kind, the key's length, and the tag. The plaintext is 32 bytes. Every failure is `wrap`, and which one is not reported, so the order of these checks is not observable (`platform/id-v1/root-wrap.json#truncated to 61 bytes`, `platform/id-v1/root-wrap.json#a flipped tag bit`).

**Sealing** uses a fresh random nonce. Before returning a new wrap, the client opens it again with the same key and compares the result with the root (the self-test); a wrap that fails it is never returned, and the failure is `wrap`.

**The server** cannot open a wrap. It checks only the length, the version and that the kind byte matches the field it was submitted in.

### 11.6 Recovery code

- **Generation and display:** as in section 6.7: 30 random bytes, `ALPHABET[b mod 32]`, six groups of five joined by `-` (`platform/id-v1/recovery-code.json#bytes 0 to 29`). A byte string of another length is `recovery_code` (`platform/id-v1/recovery-code.json#29 bytes`).
- **Canonical form C:** remove ASCII space, tab, line feed, carriage return and `-`; turn ASCII lower-case letters to upper case; read `O` as `0` and `I` and `L` as `1`. Any other character (a `U`, a vertical tab, a no-break space, anything outside ASCII) is `recovery_code`, as is a result that is not exactly 30 characters (`platform/id-v1/recovery-code.json#a U`, `platform/id-v1/recovery-code.json#a dotless i (U+0131) is not an I`, `platform/id-v1/recovery-code.json#a non-breaking space is not a space`). Unlike section 6.7's standard normalisation there is no Unicode case mapping, `U` is refused rather than read as `V`, and the dashes are not part of C.

```
K_rwrap = HKDF(IKM = ASCII(C), salt = empty, info = "thehappie-id/v1/recovery/wrap", L = 32)
R_proof = HKDF(IKM = ASCII(C), salt = empty, info = "thehappie-id/v1/recovery/auth", L = 32)
recovery_auth = base64url(R_proof)
```

No slow KDF: 150 bits cannot be guessed offline.

### 11.7 Server verifiers

```
auth_verifier     = SHA-256("thehappie-id/v1/auth-verifier"     || 0x00 || sub16 || K_auth)
recovery_verifier = SHA-256("thehappie-id/v1/recovery-verifier" || 0x00 || sub16 || R_proof)
```

This is how the platform's server stores what section 6.3 leaves to the server. A sub that is not lowercase hyphenated, or a key that is not 32 bytes, is `encoding` (`platform/id-v1/verifier.json#a 33-byte r_proof`). Comparisons are constant time. For an unknown or disabled account the server computes a verifier with the nil UUID as the sub, so both paths do the same work (`platform/id-v1/verifier.json#an auth verifier for the dummy sub`). A fast hash is enough: the password wrap stored beside the verifier is an equally good offline oracle, so only the client's Argon2id sets the cost of a guess.

### 11.8 Email normalisation, version 1

1. Trim ASCII space, tab, carriage return and line feed at both ends.
2. Every remaining byte is printable ASCII, 0x21 to 0x7E (`platform/id-v1/email.json#a Kelvin sign (U+212A) is not a k`).
3. Lower-case ASCII letters.
4. Exactly one `@`. The local part has 1 to 64 bytes of ``[a-z0-9.!#$%&'*+/=?^_`{|}~-]``, does not start or end with `.`, and holds no `..`.
5. The domain has 1 to 253 bytes and at least two labels separated by `.`. Each label has 1 to 63 bytes of `[a-z0-9-]` and does not start or end with `-`. The last label is not all digits (`platform/id-v1/email.json#an IPv4 address`).
6. The whole address has at most 254 bytes (`platform/id-v1/email.json#an address of 255 bytes`).

Any refusal is `email`. Dots and `+` tags are kept. The result, `email_norm`, normalises to itself.

### 11.9 Key bundle

The key bundle is the file a person downloads so that a command-line tool can open their data with the password or the recovery code, without the platform. It holds only what the server stores:

```json
{"format": "thehappie-id/key-bundle", "version": 1, "issuer": "<origin>", "sub": "<sub>",
 "email": "<email_norm>", "account_key_epoch": 1, "kdf": {"alg": "argon2id", "m": 65536, "t": 3, "p": 1},
 "kdf_salt": "<b64url, 16 bytes>", "password_wrap": "<b64url, 62 bytes>", "recovery_wrap": "<b64url, 62 bytes>",
 "product_keys": [{"product": "<id>", "epoch": 1, "pub": "<b64url, 32 bytes>"}, ...],
 "created_at": "<YYYY-MM-DDTHH:MM:SS[.fraction]Z>"}
```

**Reading is strict.** At most 64 KiB of UTF-8 holding one JSON value. Whitespace is space, tab, line feed and carriage return only. Nothing may come before the value (a byte order mark is refused) or after it. The value is an object with exactly these members, compared case-sensitively after unescaping (`platform/id-v1/key-bundle.json#a member name with an escape` opens), each once and none `null`. `kdf` and each product key are objects under the same rules. Integers have no fraction or exponent and lie within a signed 64-bit integer (`platform/id-v1/key-bundle.json#version written as 1.0`, `platform/id-v1/key-bundle.json#kdf m of 2^63, past a 64-bit integer`). `version` and the epochs lie within a signed 32-bit integer. KDF parameters beyond 32 bits are out of bounds, not malformed (`platform/id-v1/key-bundle.json#kdf m of 2^63 - 1, a 64-bit integer out of bounds`, which is `kdf_policy`). Any other defect is `bundle`.

**The fields are checked in this order:**

1. format and version;
2. `issuer`: 1 to 256 printable ASCII characters (its value is the deployment's; a reader may compare it with the issuer it expects);
3. `sub`;
4. `email` is already `email_norm`;
5. `account_key_epoch`;
6. the KDF bounds of 11.3 (`kdf_policy`);
7. `kdf_salt`: 16 bytes;
8. the wraps: 62 bytes, version `0x01`, and each with its own kind byte (`platform/id-v1/key-bundle.json#the wraps swapped`);
9. `product_keys`: not empty, every id and epoch valid, every `pub` 32 bytes, strictly sorted by product then epoch, compared bytewise (`platform/id-v1/key-bundle.json#product keys out of order`);
10. `created_at`: exactly `YYYY-MM-DDTHH:MM:SS`, optionally `.` and 1 to 9 digits, then `Z`, naming an instant of the proleptic Gregorian calendar, years 0000 to 9999, with no leap second (`platform/id-v1/key-bundle.json#created_at with the offset +00:00`, `platform/id-v1/key-bundle.json#created_at on February 29 of the year 0, a leap year`).

Every failure in this list is `bundle`, except step 6.

**Opening:**

1. Read and check the bundle.
2. With the password: the profile of 11.2 for a presented password (no minimum length), then 11.3 under the bundle's parameters and salt. With the recovery code: its canonical form (11.6).
3. Open the matching wrap with the bundle's `sub` and `account_key_epoch` (`wrap`, which a changed sub or epoch also gives: `platform/id-v1/key-bundle.json#another sub`).
4. Derive every listed product key from the root and compare its public key with `pub` (`product_key`).

A reader uses the root and the product keys only after step 4. A writer (the platform's server) writes 2-space indented JSON with a final newline, the product keys sorted and `created_at` in UTC to the second, and never writes what a reader refuses.

**Honest limit.** A bundle downloaded before a password or recovery code change still opens with the old password or code. The root does not change, so this is inherent.

### 11.10 Errors

| Name | Meaning |
|---|---|
| `password_invalid` | not well-formed Unicode, a run of more than 30 marks or Hangul vowel and final jamo (11.2), or a control character |
| `password_too_short` | a new password under 12 code points |
| `password_too_long` | a password over 256 code points |
| `kdf_policy` | KDF parameters or a salt outside the bounds of 11.3 |
| `wrap` | a root wrap that is malformed, does not open, or failed its self-test, or a passkey wrap key that cannot be made: a relying party id outside its spelling, one that ends in a number included, or a PRF output that is not 32 bytes (11.16) |
| `recovery_code` | not a recovery code |
| `email` | an address 11.8 does not accept |
| `product_key` | a product id, epoch or root that names no product key, a public key the server refuses, a listed key the root does not derive, or a delivered key whose public half is not the binding's `pk_p` (11.12) |
| `bundle` | not a key bundle this version reads |
| `key_delivery` | a key delivery that cannot be sealed or did not open (11.12): an `akd_pub` 11.4 refuses, a binding with no AAD, a sealed key that is not 80 bytes, an `enc` that is not canonical, another recipient or flow, altered bytes; which one is not said |
| `pkce` | a code verifier outside RFC 7636 (11.13) |
| `client_extensions` | WebAuthn client extension results outside the allowlist of 11.16; what was there is not said |
| `encoding` | a value not in its one accepted spelling where no other name fits (a verifier's inputs) |

Where an input has several defects, the order of checks in sections 11.2 to 11.9 decides the name. Errors of the kit's generic modules never escape the platform profile: they are reported as one of these names. The one exception is an engine that lacks a primitive, which is not a verdict on any input: in TypeScript, on an engine without X25519, deriving a product key (and so opening a key bundle), sealing or opening a key delivery, and the X25519 helpers of 11.12 throw the `hpke` module's `HPKEError` `invalid_key`, with the engine's `NotSupportedError` as its `cause`, rather than `product_key` or `key_delivery`, which would say that a bundle's listed keys are not its root's or that a blob is bad. An engine that fails to generate an X25519 key four times in a row (section 13) is the same `HPKEError`, with its last error as the `cause`, wherever key delivery and those helpers generate one: the probe of the check of 11.4, the sealer's ephemeral key and a relying party's pair (11.14). Nor is a derivation that fails for no reason of its input (Argon2id itself, or the KDF worker after it was sent the password, section 13): it throws the account module's `AccountError` `kdf`/`kdf_failed`, not `kdf_policy`, which says that the parameters are outside the bounds. A product's own rules (for example a page refusing a password equal to the address) use the product's own codes.

### 11.11 Vectors

The format and the files are described in section 12.2. Cited as `platform/id-v1/<kind>.json#<case name>`; a case of a file whose cases carry an `op` (`key-delivery.json`, `passkey.json`) is cited as `platform/id-v1/<kind>.json#<op>/<case name>`. Part 2's files are `key-delivery.json`, `pkce.json` and `password-stream-safe.json`; part 3's are `passkey.json` and `client-extensions.json`, and the relying party rule's, at `75b6b94`, is `rp-id-ends-in-number.json`. The kit's own round trips of this profile are `kit/platform-go.json` and `kit/platform-ts.json`, of part 2 `kit/platform-delivery-go.json` and `kit/platform-delivery-ts.json`, of part 3 `kit/platform-passkey-go.json` and `kit/platform-passkey-ts.json`, and its fixed cases at and one past the limit of the run rule of 11.2 are `kit/platform-password-go.json` and `kit/platform-password-ts.json`, all in the format of section 12.1.

### 11.12 Sealed key delivery

A product that asks for it receives its product key (11.4) sealed by the id. page to an X25519 key that only the product's page holds (`akd_pub`, sent in the authorization request). The id. server stores and forwards the blob and cannot open it.

```
sk_p, pk_p     = the product key pair of 11.4 for (product, epoch)
product_key_id = product ":" decimal(epoch)
info       = UTF-8("thehappie-id/v1/key-delivery")
aad        = JSON AAD ["thehappie-id/key-delivery", 1, iss, client_id, redirect_uri, sub,
                       product_key_id, base64url(pk_p), code_challenge, nonce]
(enc, ct)  = HPKE.SealBase(pkR = akd_pub, info, aad, pt = sk_p)      section 4.4's suite, single shot
akd_sealed = enc (32) || ct (32) || tag (16)                         80 bytes
```

The AAD is a restricted JSON AAD (11.1) whose every field has one spelling; a binding outside these has no AAD, and both sides refuse it with `key_delivery` before anything is sealed or opened:

- `iss`, `client_id`, `redirect_uri`: non-empty strings from the alphabet of 11.1. The issuer is written exactly as the ID token's `iss` (`platform/id-v1/key-delivery.json#open/opened for the issuer with a trailing slash`, `platform/id-v1/key-delivery.json#seal/an issuer outside the AAD alphabet`, `platform/id-v1/key-delivery.json#open/an empty client_id`). The values are the deployment's and the client registry's; an implementation checks only their spelling.
- `sub`: as 11.1 (`platform/id-v1/key-delivery.json#open/a sub in upper case`).
- `product_key_id`: a product id of 11.4, `:`, and an epoch from 1 to 2^31 − 1 in decimal without sign or leading zero (`platform/id-v1/key-delivery.json#open/a product_key_id with a leading zero`, `platform/id-v1/key-delivery.json#open/a product_key_id without an epoch`).
- `pk_p`: 32 bytes, written in base64url (`platform/id-v1/key-delivery.json#open/a 31-byte pk_p`).
- `code_challenge`: 43 characters, the strict base64url of 32 bytes (11.13) (`platform/id-v1/key-delivery.json#seal/a code_challenge with non-zero trailing bits`).
- `nonce`: 22 to 128 characters from `[A-Za-z0-9_-]` (`platform/id-v1/key-delivery.json#seal/a nonce of 129 characters`, `platform/id-v1/key-delivery.json#open/a nonce with a dot`).

**Sealing** (the id. page), in this order: the binding; `akd_pub` passes the check of 11.4 whatever the server checked (`platform/id-v1/key-delivery.json#seal/akd_pub is a valid key with bit 255 set`, `platform/id-v1/key-delivery.json#seal/akd_pub is the low-order point 0`, `platform/id-v1/key-delivery.json#seal/a 31-byte akd_pub`); the product key pair and `product_key_id` from the root; the AAD; SealBase with a fresh ephemeral key; 80 bytes. Every refusal is `key_delivery`, except a root, product or epoch that names no product key, which is `product_key` (11.4). The page zeroes the root, `sk_p` and every intermediate of the key schedule (section 13).

**Opening** (the relying party), in any order, every failure `key_delivery` and which one not said: exactly 80 bytes (`platform/id-v1/key-delivery.json#open/truncated to 79 bytes`, `platform/id-v1/key-delivery.json#open/extended to 81 bytes`); a 32-byte recipient private key (`platform/id-v1/key-delivery.json#open/a 31-byte recipient private key`); the binding; **`enc` is the canonical encoding of an X25519 point, bit 255 clear and below 2^255 − 19, checked before any exchange whatever the engine would do**; OpenBase, refusing an all-zero exchange output (section 4.4; `platform/id-v1/key-delivery.json#open/enc replaced by the low-order point 0`); exactly 32 bytes of plaintext. Then the public key `X25519(plaintext, 9)` must equal `pk_p`, compared in constant time; otherwise the plaintext is zeroed and the error is `product_key` (`platform/id-v1/key-delivery.json#open/a product key that does not match: another epoch's key`). The opener returns `sk_p`, which the caller zeroes once it has kept it (11.14).

**The canonical `enc`** is stricter than RFC 9180, under which X25519 reads the other spellings of a point (bit 255 set, or a value of 2^255 − 19 or more) as the point itself. A sealer that writes such a spelling into both the blob and its KEM context makes a blob that crypto/hpke and WebCrypto engines open and that an engine refusing to import the spelling would not (`platform/id-v1/key-delivery.json#open/enc spelled with bit 255 set by the sealer, in the blob and in the KEM context alike`). An honest sealer never writes one, since `X25519(skE, 9)` is canonical. Refusing it gives every blob one spelling and every engine one answer, as 11.4 does for `pk_p`.

**What this does not do.** HPKE base mode does not authenticate the sender. Anyone who knows `akd_pub` (the id. server, which relays it, included) can seal a key of their choosing under a binding they also write into an ID token, and it opens and matches. A delivered key is kept only once the product's server has named it (11.14 step 9, 11.15).

The suite is fixed (section 3.2); discovery publishes it as `{"param": "akd_pub", "info": "thehappie-id/v1/key-delivery", "suite": "DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM", "sealed_len": 80}`.

### 11.13 PKCE S256

```
code_verifier  = 43 to 128 characters from [A-Za-z0-9._~-]                      (RFC 7636 section 4.1)
code_challenge = base64url(SHA-256(ASCII(code_verifier)))                       43 characters
```

A verifier outside these is refused with `pkce`, never hashed (`platform/id-v1/pkce.json#42 characters`, `platform/id-v1/pkce.json#129 characters`, `platform/id-v1/pkce.json#a percent-encoded tilde`, `platform/id-v1/pkce.json#a non-ASCII letter`): the token endpoint refuses it, so a relying party that hashed one would hold a flow it can never redeem. Example: `platform/id-v1/pkce.json#the example of RFC 7636 appendix B`. A relying party makes its verifier from 32 random bytes in base64url (43 characters). A server compares challenges in constant time. Only S256 exists. The challenge is bound into the key-delivery AAD (11.12), so a blob moved to another flow does not open.

### 11.14 The relying party: the product's page

What a product's page runs to sign a person in with id. and, when it asks, to receive its product key (TypeScript `@thehappieco/kit/oidc-rp`). Its parameters are the product's constants: the issuer (an origin: https, or http on a `*.localhost` or loopback host in development), the `client_id`, the redirect URI (absolute, in its canonical form, on the page's own origin, without query, fragment or user information, from the alphabet of 11.1), the scopes (space-separated, without repeats, including `openid`; `account_key` is added when the key is wanted) and the product's key label (`product`, the product of `product_key_id`, a product id of 11.4), which a key request requires. Nothing else in it is product-specific. Arguments outside these rules are programming errors (`TypeError`), thrown before anything is stored, not refusals.

**Begin**

1. Make `state`, `nonce` and `code_verifier` from 32 random bytes each, in base64url, and the challenge (11.13).
2. With the key: generate an ephemeral X25519 pair; seal the raw private key under a fresh **non-extractable** AES-256-GCM key, with a 12-byte random nonce and the AAD JSON AAD `["thehappie-rp/flow", 1, client_id, state]`; zero the raw bytes. No X25519 `CryptoKey` is stored: WebKit loses IndexedDB records that hold one.
3. Store the flow `{v: 1, issuer, client_id, redirect_uri, product, nonce, code_verifier, akd_pub, aes_key, iv, sealed_eph, return_to, created_at}` (`issuer` the one the request of step 4 goes to; `akd_pub`, `aes_key`, `iv` and `sealed_eph` `null` without the key, `product` `null` when the page gave none) in IndexedDB database `thehappie-rp`, store `flows`, keyed by `state`, after deleting every record that is unreadable, older than 10 minutes, or dated more than 10 minutes ahead. A record without `issuer` or `product` is unreadable: the platform's own relying party writes neither, so a flow in flight when a page switches to this one says "start again".
4. Navigate to `{issuer}/oauth2/authorize` with `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge`, `code_challenge_method=S256`, `akd_pub` with the key, and optionally `prompt`, `login_hint`, `ui_locales`. A key request never asks `prompt=none`, which cannot complete; it is refused before anything is stored.

**Callback** (on the redirect URI), in this order:

1. Read the query, then drop it from the address bar and the history.
2. `iss` must equal the issuer exactly (RFC 9207), and so, in step 3, must the flow's `issuer`: section 2.4 of RFC 9207 compares `iss` with the issuer the request was sent to, so that a page serving more than one issuer never sends a code and its verifier to another; otherwise `iss_mismatch`, and the flow its `state` names, if any, is deleted.
3. Take the flow by `state`, reading and deleting it in one transaction; an unknown, expired or other client's flow is `state_unknown`, and a flow whose `issuer` is not the issuer is `iss_mismatch`, before anything is sent. A flow is used once.
4. An error response is `authorization_error`, carrying the OAuth error code (`unknown` outside the protocol's list).
5. Exchange the code: `POST {issuer}/oauth2/token`, a CORS request with credentials (the bind cookie ties the code to this browser), not cached, redirects refused, form fields `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier`. The answer must be 200 with a JSON object holding `access_token` (`thid_at_` and 43 base64url characters), `token_type` Bearer, `id_token`, and `account_key_sealed` if and only if the key was asked; otherwise `token_error`, carrying the OAuth error code when there is one.
6. The ID token, whose signature is not checked (it comes from the issuer's token endpoint over TLS in answer to a request only this page could make, OpenID Connect Core 3.1.3.7, and the product's server trusts only userinfo): at most 8 KiB; three base64url segments; the header exactly `{"alg":"ES256","kid":<43 base64url characters>,"typ":"JWT"}`; an 86-character signature; `iss` the issuer; `aud` the `client_id`, as a string; `nonce` the flow's; `sub` as 11.1; `iat` and `exp` integers with `0 < exp − iat ≤ 600`, **never compared with the device's clock**; `product_key` (32 bytes) and `product_key_id` (11.12) together, required with the key; and, when the flow has a product, `product_key_id` names it. Otherwise `id_token_invalid`.
7. With the key: open the ephemeral key and check its public half is the flow's `akd_pub` (`key_open_failed`); rebuild the binding from the flow (issuer, `client_id`, redirect URI, the challenge of its verifier, nonce) and the ID token (`sub`, `product_key_id`, `product_key`); open 11.12. A `product_key` refusal is `key_mismatch`; any other is `key_open_failed`.
8. Send the access token to the product's own server (11.15) while the key stays in memory.
9. **Keep the key only when the server accepted the login and its answer names the same `sub`, `product_key_id` and `product_key`**: the ID token's `sub` and `product_key_id`, and `X25519(sk_p, 9)`, the last compared in constant time. Otherwise `pin_mismatch`, and the key never reaches storage. In every case the page zeroes its copy once it is done. HPKE base mode does not authenticate the sender (11.12): anyone who knows `akd_pub` can seal a key of their choosing that opens and matches an ID token they also write, so this comparison with the server's insert-only pin is what stops a substituted key. Without the key, the answer's `sub` must still be the ID token's. (TypeScript: `finishSignIn` runs steps 1 to 9 with the product's own server call and store; `keepProductKey` is step 9 alone; `callback` stops after step 7 and returns the key for the caller to handle.)
10. Go to the flow's `return_to` only if it is a same-origin path (it starts with one `/`, holds no `\` or control character, and does not resolve to `//`); otherwise to `/`.

Any failure shows a security error and leaves no state that holds a key: the flow is deleted before the code is exchanged, and a key that fails a check is zeroed before the error is thrown.

**Serving the callback.** The route is served with `Referrer-Policy: strict-origin` or stricter, so its own subresource requests do not carry the code in `Referer`; never `no-referrer` for the page's same-origin POST to its server, which would then carry `Origin: null`, unless that request sets its own `referrerPolicy` (for example `'same-origin'`), under which Chromium, Firefox and WebKit send the page's real origin. It is logged without its query string. The page's `connect-src` includes the issuer.

**Identity only.** A product that already holds the key for (`sub`, `product_key_id`) asks without `account_key`; with an id. session that is silent (`prompt=none` allowed). **Signing out** of id. is `GET {issuer}/oauth2/logout?client_id&post_logout_redirect_uri&state`, with the client's post-logout URI on the page's origin and a state of 1 to 512 visible ASCII characters (by default 32 random bytes in base64url), which id. confirms; it signs nobody out of a product.

**Errors** (the page's): `state_unknown`, `iss_mismatch`, `authorization_error`, `token_error`, `id_token_invalid`, `key_open_failed`, `key_mismatch`, `pin_mismatch`.

### 11.15 The relying party: the product's server

The page posts the access token to its own server, same origin. The server reads the body only of a POST with exactly its own `Origin`, `Sec-Fetch-Site: same-origin` and `Content-Type: application/json`, which no other site's page can send; otherwise another site could post an access token of its own account and open a session for that account in the person's browser (login CSRF). These checks are the product's: Go `oidcrp` serves no HTTP, and its session handler example makes them. The server (Go `oidcrp`, whose parameters are the issuer, the `client_id` and the product's key label):

1. Refuses a string that is not `thid_at_` followed by the strict base64url of 32 bytes, without sending it anywhere (`access_token`).
2. Calls `GET {issuer}/oauth2/userinfo` with `Authorization: Bearer <token>`, server to server: GET only, no redirect followed, no cookie. The token works once and lives 300 seconds, so a refusal is never retried. A 401 is `token_refused`; any answer but 200 with `application/json`, at most 16 KiB, is `userinfo`.
3. Reads the answer strictly: valid UTF-8, one JSON object and nothing after it, member names compared exactly and each at most once, unknown members ignored, and `sub` (11.1), `client_id`, `auth_time` (an integer), `amr` (strings), `email`, `email_verified` (a boolean), `locale`, `name`, `product_key`, `product_key_id` of their types; otherwise `userinfo`.
4. Requires `client_id` to be its own (`wrong_client`): a token issued to another client never opens a session here.
5. Requires `product_key_id` to be its product's (11.12's grammar) and `product_key` to be 32 bytes passing 11.4's check, so the one spelling of a valid key is pinned (`product_key`).
6. Pins `(sub, product_key_id) -> product_key` at the first login, insert only: a later login with the same key is `same`; one with a different key is refused with `account_key_changed`, the pin is kept, and the product raises an alert. A login never replaces or deletes a pin. The pin covers a `product_key_id` once pinned; the first login trusts the registry, and a new epoch is a new pin.
7. Answers its page, for `new` and `same` only, with the pinned and accepted `{"sub", "product_key_id", "product_key"}` (base64url), which the page compares (11.14 step 9), and then starts its own session. On `account_key_changed` it opens no session and the page keeps nothing.

The pin store is the product's database: a table of (`sub`, `product_key_id`) to `product_key`, written with an insert that does nothing on conflict and read back, under a role that may insert and select but neither update nor delete; two first logins at once with different keys pin one of them.

Nothing the server logs names the token, the key, the account or the address. **Errors** (the server's): `access_token`, `token_refused`, `userinfo`, `wrong_client`, `product_key`, `account_key_changed`.

### 11.16 Passkeys with PRF: the passkey root-wrap key and the client-extension allowlist

A passkey on id. signs a person in, and, when its authenticator supports the WebAuthn PRF extension, also opens the account root, so it can stand in for the password wherever the id. page unlocks, key delivery included (the platform's decision 0008). Products run no WebAuthn for platform accounts. What this section fixes is what the page derives from a PRF output and what the id. server accepts in a credential; the ceremony itself is the platform's.

```
PRF_SALT = SHA-256(UTF-8("thehappie-id/v1/passkey-prf|" + rp_id))                     32 bytes
prf      = the PRF output for eval.first = PRF_SALT                                      32 bytes, per credential
K_pk     = HKDF(IKM = prf, salt = UTF-8(rp_id), info = "thehappie-id/v1/passkey/wrap", L = 32)
wrap     = 0x01 || 0x03 || nonce (12) || AES-256-GCM(K_pk, nonce, root, AAD)             62 bytes (11.5)
AAD      = ["thehappie-id/root-wrap",1,"passkey",sub,epoch,rp_id,credential_id]
```

This is section 7 with the platform's passkey profile (evaluation prefix `thehappie-id/v1/passkey-prf|`, HKDF info `thehappie-id/v1/passkey/wrap`, header `0x01 0x03`) and the AAD of 11.5: section 7's envelope with that header is the kind-3 root wrap of 11.5, byte for byte (`platform/id-v1/passkey.json#a passkey on the production relying party`).

- **The relying party id** has one spelling, because it is hashed into the PRF salt and the HKDF salt and written into the AAD, and a second spelling would be a second key and a wrap that does not open: a domain name of 1 to 253 bytes whose dot-separated labels are each 1 to 63 bytes of `[a-z0-9-]`, none starting or ending with `-`, that does not end in a number. That is the host of an origin as a browser serialises it: lower case, no port, scheme or trailing dot, and nothing a browser's URL parser reads as an IPv4 address or refuses for ending in a number (`platform/id-v1/passkey.json#salt/a relying party id in upper case`, `platform/id-v1/passkey.json#salt/a relying party id with a port`, `platform/id-v1/passkey.json#salt/an origin instead of a relying party id`, `platform/id-v1/passkey.json#salt/a relying party id with a trailing dot`, `platform/id-v1/passkey.json#salt/an IPv4 address`, `platform/id-v1/passkey.json#salt/a non-ASCII relying party id`; at the limits, `platform/id-v1/passkey.json#a relying party of 253 bytes` and `platform/id-v1/passkey.json#a single-label relying party`). The rule does not check that an `xn--` label is valid Punycode, on which engines disagree: Firefox and Node refuse `xn--a`, Chromium and WebKit keep it. The platform's are `id.thehappie.co` and, in development, `id.thehappie.localhost`; an implementation checks the spelling, never a list.
- **Ends in a number** is the WHATWG URL Standard's "ends in a number checker", which a browser's host parser runs on every domain: strictly split the id on `.`; if the last part is empty, the id does not end in a number when that part is the only one, and otherwise the part is dropped (one trailing empty label only); the id ends in a number when the last part is non-empty and all ASCII digits, or when the standard's IPv4 number parser does not fail on it. That parser fails on the empty string; it reads `0x` or `0X` and what follows as radix 16, a `0` followed by at least one more code point as radix 8, and anything else as radix 10, and succeeds when what follows the prefix is empty or holds only digits of the radix. Under the spelling above (no upper case, no empty label, no trailing dot), what this refuses is a last label of decimal digits or of `0x` and zero or more hex digits: a browser reads `0x7f000001` as `127.0.0.1` and `1.2.3.0x4` as `1.2.3.4`, and refuses `id.0xff` (`platform/id-v1/rp-id-ends-in-number.json#a hexadecimal IPv4 address in one label`, `platform/id-v1/rp-id-ends-in-number.json#a dotted address whose last part is hexadecimal`, `platform/id-v1/rp-id-ends-in-number.json#a hexadecimal last label`, `platform/id-v1/rp-id-ends-in-number.json#0x alone, which is the number zero`, `platform/id-v1/rp-id-ends-in-number.json#a hexadecimal last label past 32 bits`, `platform/id-v1/rp-id-ends-in-number.json#a dotted-decimal IPv4 address`, `platform/id-v1/rp-id-ends-in-number.json#a decimal last label with a leading zero and a digit that is not octal`). A number in another label, and a last label that only looks like one, pass (`platform/id-v1/rp-id-ends-in-number.json#a hexadecimal number as the first label, which does not count`, `platform/id-v1/rp-id-ends-in-number.json#a last label of 0x and a letter that is no hex digit`, `platform/id-v1/rp-id-ends-in-number.json#a last label of 0x twice, whose second x is no hex digit`, `platform/id-v1/rp-id-ends-in-number.json#a last label of 00x1: a leading zero makes it octal, and x is no octal digit`, `platform/id-v1/rp-id-ends-in-number.json#a last label of a decimal with an exponent`). Kit v0.4.0 refused only an all-decimal last label; the platform's server refuses the rest since its `75b6b94`, and so does the kit since v0.5.0. No frozen vector changes: the only relying party id of the earlier files that ends in a number, `127.0.0.1`, was refused already.
- The root-wrap AAD of 11.5 still checks only its alphabet. The spelling is enforced where `PRF_SALT` and `K_pk` are made, and the functions that seal and open a passkey wrap in one call (Go `NewPasskeyWrap` and `OpenPasskeyWrap`, TypeScript `wrapRootWithPasskey` and `unwrapRootWithPasskey`) take the relying party id once, for both the key and the AAD. The lower-level path does not tie the two together: Go's `Wrap` with `WrapPasskey` and a key from `PasskeyWrapKey`, `passkey.Wrap` with `PasskeyProfile`, and TypeScript's `sealRootWrap` with a key from `passkeyWrapKey` seal under whatever binding they are given, and a wrap whose key and AAD name different relying parties passes its self-test and the server's shape check and never opens with `OpenPasskeyWrap` or `unwrapRootWithPasskey`. A caller that seals with them must pass the same relying party id to both; the one-call functions are how a passkey wrap is sealed, and the raw key is for opening.
- **One public salt per relying party**, so that a discoverable sign-in can ask for the PRF before anyone knows which account will answer. The salt is public; the PRF output is secret, and different for every credential.
- **K_pk** is refused, before anything is derived, for a PRF output that is not exactly 32 bytes (`platform/id-v1/passkey.json#key/an empty PRF output`, `platform/id-v1/passkey.json#key/the first and second PRF outputs run together`) and for a relying party id outside its spelling (`platform/id-v1/passkey.json#key/a good PRF output with a relying party id in upper case`). Any 32 bytes are a PRF output, 32 zeros included (`platform/id-v1/passkey.json#an all-zero PRF output, root and nonce`). A page that reads the output out of a credential may refuse an all-zero one, which no authenticator gives (the platform's page does); that is the ceremony's rule, not this section's.
- **The wrap** is 11.5's: sealed under a fresh nonce and self-tested, it opens only with the PRF output of the credential it names, on the relying party it names, for the account and epoch it was made for (`platform/id-v1/passkey.json#open/another relying party`, `platform/id-v1/passkey.json#open/the development wrap opened on the production relying party`, `platform/id-v1/passkey.json#open/another credential id`, `platform/id-v1/passkey.json#open/the PRF output of another credential`, `platform/id-v1/passkey.json#open/another sub`, `platform/id-v1/passkey.json#open/another epoch`, `platform/id-v1/passkey.json#open/the password kind byte`, `platform/id-v1/passkey.json#open/truncated to 61 bytes`). The credential id is the strict base64url of the credential's raw id, of 1 to 1023 bytes as WebAuthn allows (`platform/id-v1/passkey.json#a credential id of one byte`, `platform/id-v1/passkey.json#a credential id of 1023 bytes`).
- **Every refusal is `wrap`**, whichever step refuses: the salt, the key or the open (a vector's `op`). Which check failed is not said.

**The client-extension allowlist.** A credential reports its extension outputs in `clientExtensionResults`, and the PRF's output there is the secret `K_pk` comes from. The page never sends it: it builds the credential it sends member by member, never with `toJSON()`. The id. server refuses, with `client_extensions` and before any WebAuthn library reads the credential, a `clientExtensionResults` that is anything but `{}` or a subset, each member at most once, of

```
"credProps": {"rk": true | false}
"prf":       {"enabled": true | false}
```

(`platform/id-v1/client-extensions.json#both, as a create sends them`, `platform/id-v1/client-extensions.json#both, prf first`). Refused: `prf.results` in any form (`platform/id-v1/client-extensions.json#a create result with the PRF output, as the browser reports it`, `platform/id-v1/client-extensions.json#prf.results present but empty`); a flag of another JSON type, `null` included (`platform/id-v1/client-extensions.json#prf.enabled null`); an empty `prf` or `credProps`; any other member at either level (`platform/id-v1/client-extensions.json#credProps with another member`, `platform/id-v1/client-extensions.json#the hmac-secret extension`); a member name in another case (`platform/id-v1/client-extensions.json#prf in another case`); and a repeated member (`platform/id-v1/client-extensions.json#a duplicate member that would replace the first`).

The check reads the exact JSON text of that one member: UTF-8; one JSON value, whitespace being space, tab, line feed and carriage return only, with nothing before it (a byte order mark is refused: `platform/id-v1/client-extensions.json#a byte order mark`) and nothing after it (`platform/id-v1/client-extensions.json#two objects`); member names compared exactly as written after JSON unescaping, so `"pr\u0066"` is `prf` here as it is to every JSON reader (`platform/id-v1/client-extensions.json#member names spelled with escapes`), and a repeat spelled that way is still a repeat (`platform/id-v1/client-extensions.json#a duplicate member spelled with an escape`). It reads text because a parsed value cannot show what JSON readers resolve silently: Go's `encoding/json`, which WebAuthn libraries use, keeps the last of two members and matches names case-insensitively, so a check that read the text another way could pass a value the library reads as a PRF output. Finding the member in the credential is the server's, and it must read the credential as strictly. A page checks its own value before it sends it, against the same allowlist.

**What stays in the platform:** the WebAuthn ceremony. The options (the relying party, user verification and a resident key required, the PRF asked with `eval.first = PRF_SALT` on every create and get, `credProps` on create), `navigator.credentials`, reading the PRF output out of a credential and zeroing it there, the credential the page sends, go-webauthn on the server (attestation, signatures, counters, challenges), sign-in-only passkeys and the fallback to the password, and the limits and tables of the platform's `id-v1.md` section 8.

Vectors: `passkey.json` (44 cases, 35 must fail, all `wrap`: 16 at the salt, 6 at the key and 13 at the open) and `client-extensions.json` (46 cases, 37 must fail, all `client_extensions`), from platform commit `b5d9f69`, and `rp-id-ends-in-number.json` (29 cases, 17 must fail, all `wrap`, 8 of them the hex forms v0.4.0 accepted; every case also records the checker's answer, `ends_in_a_number`), from platform commit `75b6b94`.

### 11.17 The product contract: its membership part

The contract (the platform's decision 0005) is what the platform and each app's server exchange, server to server. Its first part, the membership part (decision 0040, amended by 0041), is the one built: the platform tells an app which workspaces each of its people belongs to and with which role; the app reports who can do what with each of its numbers and mailboxes, and sends the events from which the platform mails a team's owners and readers. This section is the platform's `docs/contract/v1/README.md` at platform commit `8a7b73c`, for what crosses the wire and the rules an app's side keeps; where that file and decision 0040 differ, the decision wins (at `8a7b73c` they agree on everything below). Implementations: Go `contract`, on the standard library and `reqhmac` alone, with `contract/contracttest`, a fake platform for an app's tests; `profiles/platform` names the signature's values as the profile names every other (`ContractHMAC`, `ContractToPlatform`, `ContractToApp`, `ContractSecretLen`, `CheckContractSecrets`, `SignAnswer`, `VerifyAnswer`), the same functions. The kit's code departs from the platform's at `ee45e3a` (the same at `8a7b73c`) in what its review found, none of it a byte on the wire: `contract.Client` bounds every call in time, returns nothing of an answer it refuses and names no account in an error; `VerifyAnswer` verifies nothing under a key that is not a secret; and the closed sets of pause reasons and stranding causes are returned as copies. The platform's own copy takes these on until it imports the kit's. There is no TypeScript: both apps' contract clients are server-side Go. Vectors: `vectors/platform/contract-v1/` (the end of this section).

**The transport is the platform's.** In production the platform serves the contract on the unix socket `/run/platform/contract.sock`, which systemd makes `root:platform-contract` with mode 0660, so only the apps' service users, whose units join the group `platform-contract`, can reach it, and it checks the peer's uid (`SO_PEERCRED`) before anything else; in development, on loopback TCP (`127.0.0.1:8291`), the signature alone authenticates. HTTP/1.1 on both, with no TLS: the answers are signed. Nothing reads a client address. Every byte below is the same on both. The peer's own check is the app's: only root can create an entry under `/run/platform`, so an app may check that the socket's owner is uid 0 before it dials it. The kit has no dialer for the socket: an app's HTTP client dials it whatever the URL's host (`contract.Client`'s `Base` is then `http://contract`).

**The signature** is section 9 under these values (`contract.Scheme()`, `profiles/platform.ContractHMAC()`):

| | |
|---|---|
| Label | `thehappie-platform-hmac/v1` |
| Headers | `X-Happie-App` (the sender), `X-Happie-Timestamp`, `X-Happie-Nonce`, `X-Happie-Signature` |
| Sender | the app's id, in both directions: `^[a-z][a-z0-9]{1,31}$` (`wappie`, `mailie`; `fakeproduct` in development) |
| Directions | `to-platform` (requests), `to-app` (answers) |
| Skew | 60 s; the platform's replay cache keeps a nonce 61 s, at most 100 000 per app, and fails closed when full |
| Nonce | 16 random bytes, unpadded base64url, fresh for every request, retries included |

`platform/contract-v1/signatures.json#requests/subscribe at a sign-in` signs `PUT /contract/v1/accounts/0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20` with no body to `v1=76dc354f2da04d8fd1afd67f46f8e941e5e4f9ca325909e7dd92020a4e1249d8`; the target is the raw path and query (`platform/contract-v1/signatures.json#requests/the feed, a target with a query`), and the method is signed in upper case (`platform/contract-v1/signatures.json#requests/a lowercase method is signed in upper case`).

- **The secret** is the 43-character unpadded base64url text of 32 random bytes, one per app, and it is keyed as written: the HMAC key is the text's bytes, never the 32 decoded ones (`platform/contract-v1/signatures.json#answer_checks/the key taken as the 32 decoded bytes`). Both sides refuse, before they sign or verify anything, an empty secret, one of another length, a padded one, one whose last character is not the canonical encoding of 32 bytes, and a next secret equal to the current one (`contract.CheckSecrets`, `profiles/platform.CheckContractSecrets`; `platform/contract-v1/signatures.json#secrets/empty`, `platform/contract-v1/signatures.json#secrets/42 characters`, `platform/contract-v1/signatures.json#secrets/padded`, `platform/contract-v1/signatures.json#secrets/not the canonical encoding of 32 bytes`, `platform/contract-v1/signatures.json#secrets/the next equal to the current`). An empty key is a valid HMAC key, so this check is the only guard against one; a client checks every secret it accepts, too.
- **A rotation** has two secrets: the platform accepts a request signed with either and signs its answers with its current one; an app accepts answers signed with either of its own (`platform/contract-v1/signatures.json#answer_checks/during a rotation, the next secret first`). The app keeps its secret tier 2 (decision 0003), never in plain text in its environment. The rotation, each step on its own: (1) platform: `admin contract secret-next <app>`, then a restart; (2) platform: `export-contract-secret <app> --next` into the app's own root step, which installs it as the app's next; (3) app: signs with the next secret (promotes); (4) platform: `admin contract secret-promote <app>`, then a restart: answers are signed with the new secret, and the old one is still accepted; (5) app: drops the old secret; (6) platform: `admin contract secret-drop <app>`, then a restart. No request fails at any step, and each step refuses out of turn. A rotation is abandoned before its promote (the next secret was exposed, or the app never took it) with `admin contract secret-cancel <app>`, then a restart: the next secret is accepted no more and never used again, and the app drops it; after the promote, the rotation finishes instead.
- **The app's half of a rotation**, with `contract.Client`: at step 2 it installs the next secret beside the old one as a secret it accepts (`Accept` is `contract.Secrets(old, next)`, which `contract.CheckSecrets(old, next)` checks first), and still signs with the old one (`Secret`); at step 3, which comes only after step 2, it signs with the next one, which the platform has accepted beside the old one since step 1, and still accepts answers signed with either, as the platform signs its answers with the old one until its promote; it drops the old secret (step 5: `Accept` holds the new one alone) only once the platform's promote (step 4) is done. On a `secret-cancel`, it drops the next secret, and signs with the old one again if it had begun signing with the next.

**The platform's order.** Each check refuses before the next one runs, and everything before step 6 is refused unsigned, an answer that tells the app nothing it can trust:

1. the peer: on the socket, a uid mapped to an app, else `404 not_found`;
2. `X-Happie-App` exactly once, naming that uid's app (over TCP, a configured app), else `404 not_found`;
3. the app's rate, 50 requests a second, else `429 rate_limited`;
4. the timestamp, nonce and signature headers, each present once and well formed, and the timestamp within 60 s (section 9, steps 2 and 3), else `401 unauthenticated` or `401 stale_timestamp`;
5. the call, by method and raw path, else `404 not_found`; then the body, up to the call's limit, else `413 too_large`;
6. the signature, by the app's current or other secret, direction `to-platform`, over the raw request-target, else `401 unauthenticated`;
7. the nonce, admitted once in the app's replay cache, else `401 replay`, signed (`503 unavailable`, signed, when the cache is full); then a query on any call but the feed, `400 invalid_request`, signed; then the call.

**Signed answers.** Every answer to a request whose signature held is signed, refusals included (`contract.SignAnswer`): `X-Happie-Timestamp` is the answer's own time, `X-Happie-Nonce` the request's nonce, echoed, and `X-Happie-Signature` the signature with direction `to-app` over the request's method and target, the answer's timestamp, the echoed nonce and the answer's body (`platform/contract-v1/signatures.json#answers/the answer to a subscription`, `platform/contract-v1/signatures.json#answers/a signed refusal`). The app checks an answer to its own request (`contract.VerifyAnswer`), in this order:

1. the three headers present once each and well formed, and the timestamp within 60 s [`hmac_missing`, `hmac_stale`] (`platform/contract-v1/signatures.json#answer_checks/unsigned`, `platform/contract-v1/signatures.json#answer_checks/a minute and a second late`);
2. the echoed nonce equal to the one the app sent, never a value taken from the answer [`answer_nonce`] (`platform/contract-v1/signatures.json#answer_checks/a swapped nonce: the answer to another request`);
3. the signature, by one of the secrets the app accepts, direction `to-app`, for this app [`hmac_bad`]; a list of secrets that holds a key that is not a secret, an empty one above all, verifies nothing, also `hmac_bad` (`platform/contract-v1/signatures.json#answer_checks/a request's signature presented as an answer`, `platform/contract-v1/signatures.json#answer_checks/an answer signed for the other app`, `platform/contract-v1/signatures.json#answer_checks/another body`, `platform/contract-v1/signatures.json#answer_checks/another app's secret`).

An answer that fails any check is ignored: no cursor moves and no outbox row is marked delivered. The outcome is in the signed body; the HTTP status is never trusted alone, and an unsigned answer is a failure. The nonce binds an answer to its request, so an app needs no replay cache. `contract.Client` signs with the app's secret, verifies every answer before it reads it, reports a signed refusal as a `*contract.Refusal` with its code, and anything else that fails as `contract.ErrUnverified`, with the zero value; it also refuses an answer that does not decode, a document that is not valid or is of another app or account, a feed that does not validate for the app, and a batch of results that does not match the events sent. It bounds every call whatever its context, 15 s (`contract.CallTimeout`), and a feed request its wait and 15 s more (`contract.FeedGrace`), so a platform that stalls ends a call in an error rather than holding the app's follower, which carries disables and revocations, for good; an HTTP client an app gives it has a timeout of 0 or above 40 s, and the default one follows no redirect. Its errors name the call's route with its ids left out, never the URL, which names an account or a workspace. Its `String`, `GoString` and `LogValue` leave out its secrets, which are no JSON members either; an app holds a `*contract.Client`, since `fmt` prints a `Client` held by value in an unexported field of the app's own struct as it is, secrets included; and it prints a struct of its own that holds one with `%v` (or `%+v`, `%#v`) or not at all, as `%s` and `%q` print what the pointer points to, secrets included.

**Wire rules.**

- **JSON, UTF-8.** The platform decodes strictly: one object, valid UTF-8 with no escape of half a UTF-16 surrogate pair (`\ud800` alone), no unknown member, no member twice, names compared exactly. An event of a batch that does not decode is rejected alone, but a batch whose text is not valid UTF-8, escapes half a surrogate pair or repeats a member anywhere is refused whole. An app ignores members it does not know, and refuses an unknown `v` or enum value. Every enum is closed (the `Validate` of each document, feed, snapshot and event, which also checks what they hold).
- **Times** are RFC 3339 in UTC with `Z`, from 1970, with at most nine fractional digits after a `.`, never a `,` (`contract.Time`; `platform/contract-v1/wire.json#events/a time with a comma before its fraction`, `platform/contract-v1/wire.json#events/a time with ten fractional digits`, `platform/contract-v1/wire.json#events/a time in another zone`). The platform keeps microseconds.
- **Ids.** Accounts (subs) and workspaces are canonical lowercase UUIDs, never the nil UUID (`platform/contract-v1/wire.json#documents/an uppercase sub`). An item's id is the app's own opaque id: 1 to 64 characters of `[A-Za-z0-9_.-]`.
- **Body limits:** `POST /contract/v1/events` 256 KiB; `PUT /contract/v1/workspaces/{id}/access` 1 MiB; every other call 4 KiB, and those calls take no body: a non-empty one is `invalid_request`.
- **Errors.** An error body is `{"code": "...", "message": "..."}`; the message is for logs, never parsed (`contract.Error`). The codes:

| Code | Status | Signed | When |
|---|---|---|---|
| `not_found` | 404 | no | an unknown peer, app or call (before the signature) |
| `unauthenticated` | 401 | no | missing or malformed signature headers, or a signature that does not hold |
| `stale_timestamp` | 401 | no | the timestamp is more than 60 s away |
| `too_large` | 413 | no | the body exceeds the call's limit |
| `rate_limited` | 429 | no, or yes | over 50 requests a second for the app (unsigned); a fifth feed request waiting at once (signed) |
| `replay` | 401 | yes | the nonce was admitted already |
| `invalid_request` | 400 | yes | the body, the query or a value is not valid |
| `not_found` | 404 | yes | an account the platform does not have; one the app does not follow; a workspace never named to the app |
| `gone` | 410 | yes | the feed's cursor is past its head: the platform's database was restored |
| `conflict` | 409 | yes | in an event's result: its `event_id` is kept with other content |
| `unavailable` | 503 | yes | the platform could not answer (a fault in an events call fails the whole call, below), or its replay cache is full; retried with a fresh nonce |

**The calls** (`contract.Client`; every body and answer is one JSON object):

| Call | Body | Answer |
|---|---|---|
| `PUT /contract/v1/accounts/{sub}` (`Subscribe`) | none | The account's document, computed now; the app follows the account from now on. `not_found` for an account the platform has neither in its directory nor in its closing records, which is a platform fault, never a closing, as long as the platform keeps a closing's record (13 months, the retention below). |
| `GET /contract/v1/accounts/{sub}` (`Account`) | none | The document of an account the app follows, computed now; `not_found` for one it does not follow. |
| `DELETE /contract/v1/accounts/{sub}` (`Unsubscribe`) | none | `{"subscribed": false}`; not following the account is no error. |
| `GET /contract/v1/feed?after={seq}&wait={0..25}` (`Feed`) | none | The documents published after the cursor (below). |
| `PUT /contract/v1/workspaces/{id}/access` (`PutAccess`) | a snapshot | `{"accepted": true}` |
| `POST /contract/v1/events` (`PostEvents`) | `{"events": [...]}`, 1 to 100 | `{"results": [...]}`, one per event, in order |

An app subscribes at every sign-in through id., before its own sign-in transaction, and once for every person it holds when it connects; it asks again (`GET`) before any act the freshness rule below gates when its freshness for the person is over an hour old (for an act that narrows who holds a key, when its last trusted `published_through` is over a minute old, below), and refuses the act when no signed answer comes; it unsubscribes once it has forgotten a closed account, or when it refuses a sign-in after subscribing.

**Freshness.** An app measures its freshness per sub: the later of its last signed answer for that sub and its last trusted `published_through` (the feed's, trusted only when `more` is false). Its `GET` never runs inside a write transaction.

- **Sign-in.** Every sign-in through id. sends `PUT`, so a removed or disabled person is refused at once while the platform answers. When it does not answer, a returning person signs in on their last applied document only while the app's last trusted `published_through` is under an hour old.
- **Acts that widen access or touch shared data** need a freshness under an hour for the actor, and, for sharing a key or raising permissions, for the recipient too; else a fresh `GET`; else the act is refused (decision 0040). They are: sharing a key, or raising someone's permissions; creating an API key, a service account, or an MCP or AI connection; linking a number or mailbox to a team; sending from a team item; turning off a team item's sync or capture; and, in Wappie, deleting a team's number (its WhatsApp logout cannot be undone) and moving a number out of a team (always with a fresh `GET`).
- **Acts that narrow who holds a key** (in Wappie, revoking a grant or withholding Read, in a platform team) count a person as an item's backup only on a fresh document: when the app's last trusted `published_through` is over a minute old, it first sends `GET` for the remaining holders, and refuses the act when no signed answer comes (decision 0040, "No dormant keys"). Otherwise acts that lower access keep each app's own refusals.
- **Never gated:** reading, capture, export, a deletion that can be undone (decisions 0005 and 0014), and an API key's own acts (a key acts for the workspace, and ends when its creator's removal is applied).

**The document** (`contract.AccountDoc`, one per app and account; `platform/contract-v1/wire.json#documents/an account with a personal workspace and a team`):

| Member | Rule |
|---|---|
| `v`, `type`, `app` | `1`, `"account"`, and the app it was published for; an app refuses a document of another app or account (`platform/contract-v1/wire.json#documents/version 2 of the format`) |
| `generation` | the platform database's identity, a UUID |
| `sub` | the account |
| `version` | at least 1; the document's place in the app's feed: it only rises and never repeats, even across an unsubscribe and a new subscription. An app applies a document only of the current generation and of a higher version than the one it applied. |
| `status` | `active`, `disabled` (suspended by the operator) or `closed`, whose `workspaces` is `[]` (`platform/contract-v1/wire.json#documents/a suspended account`, `platform/contract-v1/wire.json#documents/a closed account`, `platform/contract-v1/wire.json#documents/a closed account with workspaces`, `platform/contract-v1/wire.json#documents/an unknown status`). `closed` comes from a record of the closing, never from an absence. |
| `disabled_at`, `sessions_revoked_at`, `credentials_revoked_at` | times or `null`: the latest disable (whenever it rises, the app suspends the person, even if `status` is `active` again), the latest revocation of every session, which sign-out everywhere, a password change that signs the other sessions out, a recovery, and an operator's disable or revocation each set (the app ends every session begun before it), and the latest recovery (the app also stops the integrations the person made before it) (`platform/contract-v1/wire.json#documents/sessions and integrations revoked by a recovery`) |
| `workspaces` | an array, every workspace the account belongs to, each id once, the personal one first (`platform/contract-v1/wire.json#documents/the personal workspace not first`) |
| `workspaces[].kind`, `name`, `owners` | a workspace's kind never changes, and an app refuses, and alerts on, a document that says otherwise; `personal`, with `name` and `owners` `null`, role `owner` and status `open`; or `team`, with a `name` of 1 to 80 characters with no control, format or bidirectional character and no space at either end (`platform/contract-v1/wire.json#documents/a team name with a bidirectional control`), and `owners`, its count of owners, at least 1 while it is open (`platform/contract-v1/wire.json#documents/an open team with no owner`) |
| `workspaces[].role` | `owner`, `admin` or `member` (`platform/contract-v1/wire.json#documents/the role of a service account`) |
| `workspaces[].status` | `open` or `closed`; a closed team keeps its members (`platform/contract-v1/wire.json#documents/a closed team keeps its members`) |
| `workspaces[].wversion` | at least 1; rises whenever the workspace's name or status changes, and an app applies a name or status only with a higher one |

A document never lists another member, an email address or a name a person chose for themselves.

**The feed** (`contract.Feed`). `after` is required and `wait` optional (default 0, at most 25 seconds), each once, as a decimal with no sign or leading zero, read as written and never percent-decoded; anything else is `invalid_request`. The answer has `generation`, `generation_confirmed`, `head` (the app's last seq), `published_through` (the oldest change not yet published to the app, or now: an app measures its freshness from it, and only when `more` is false), `items` (`{"seq", "doc"}`, the documents published after `after`, the latest of each account only, oldest first, at most 200; a page also ends, with `more`, before its documents reach 4 MiB, half of `contract.MaxAnswer`, so it stays under what a client reads, though a first document over that still comes alone), `next_after` (the last item's seq when `more` is true, else `max(after, head)`) and `more`. `Feed.Validate(app)` refuses a generation that is no UUID, a `next_after` outside 0 to `head`, items that are `null` or more than 200, seqs that do not rise or pass `head`, and a document that is not valid, not the app's or not of the feed's generation. With no new document, the request waits up to `wait` seconds and answers early only for a new document published for the app (a `PUT` or `GET` that leaves the account's document as it was wakes no request), or empty when the time is up or the platform shuts down; at most four requests of one app wait at once. A publisher that is stuck shows as a `published_through` that grows old while the feed still answers.

**A new generation.** On `gone`, or a feed whose generation is not the one the app holds, the app forgets its cursor and its stored versions (keeping the memberships it applied), subscribes again for every person it holds, follows the feed from 0, never lets an older document undo a disable or a revocation it applied, holds any removal that would strand an item until the feed says `generation_confirmed: true`, and sends a snapshot again for every workspace. Without the platform, an app keeps its last applied documents and never deletes on them.

**Access snapshots** (`contract.Snapshot`, `PUT /contract/v1/workspaces/{id}/access`): what an app reports of one platform workspace, absolute (`platform/contract-v1/wire.json#snapshots/a number with its reader and a person waiting for the key`):

| Member | Rule |
|---|---|
| `v` | `1` |
| `snapshot_seq` | the app's clock in milliseconds when it measured, at least 1, rising across an app's restore; the platform ignores one at or below the one it holds and refuses one more than a day ahead of its own clock |
| `items` | an array of at most 1000, each id once, whatever its kind: the platform keeps an app's items of a workspace by id (`platform/contract-v1/wire-item-ids.json#snapshots/one id for a number and a mailbox`, `platform/contract-v1/wire-item-ids.json#snapshots/one number listed twice`); a deleted item stays listed until its purge |
| `items[].kind` | `number` or `mailbox` |
| `items[].label`, `hint` | a label and a hint as below, or `null` (`platform/contract-v1/wire.json#snapshots/a mailbox with no name, its hint only`, `platform/contract-v1/wire.json#snapshots/a label that is a phone number`) |
| `items[].state`, `reason` | `active`, `deleted`, or `sync_paused` with a `reason`: `by_person`, `team_closed`, `no_reader`, `needs_reauth`, `quota` or `error`; any other state has `null` (`platform/contract-v1/wire.json#snapshots/a paused item says why`, `platform/contract-v1/wire.json#snapshots/a pause with no reason`) |
| `items[].purge_at` | when a deleted item goes for good: only, and always, on a deleted item (`platform/contract-v1/wire.json#snapshots/a deleted item until its purge`, `platform/contract-v1/wire.json#snapshots/a deleted item with no purge date`) |
| `items[].other_backups` | how many key holders without a sub the app's rule counts as a backup, 0 to 2^20 |
| `items[].people` | an array of at most 5000, each sub once: everyone with a flag, a permission or a key at an epoch not retired, by platform sub only |
| `items[].people[].can` | an array of the stored flags, each once: `read`, `send`, `act`, `manage` (`platform/contract-v1/wire.json#snapshots/an unknown flag`) |
| `items[].people[].reads` | they read it now, computed without the workspace's status: `state` and `reason` carry a closure |
| `items[].people[].waiting`, `enrolled`, `holds_key` | they may read it and wait for the key; they set up their key in the app, so a key can be shared with them; they hold a key to it at an epoch not retired, with or without Read |
| `items[].protected` | an array of the subs the app's own rule says the item cannot lose, each listed in `people` and once (`platform/contract-v1/wire.json#snapshots/protecting someone the item does not list`) |

The answer is `{"accepted": true}`, also for a snapshot older than the one kept, which is ignored, and for one of a closed personal workspace, which is not kept. A workspace never named to the app, in a document of one of its people, is `not_found`, a platform fault the app retries for 24 hours, then parks and logs; once named, it stays named, so the app may still report on it, and send its events, after its last person there left.

- **Cadence.** An app sends a snapshot after any change to what it reports (debounced to 2 s), after it applies a document that changes the workspace's members, and hourly; a failed send is retried with the outbox's backoff. At enforce, it sends one for every platform workspace, an empty one where it holds no item.
- **Intake.** The platform drops any sub that is not a current member, keeps only the latest snapshot of each workspace, and measures its age from its own time of receipt. A snapshot older than 90 minutes is stale: the protection of a member it lists is then unknown, as is that of a member the app follows in a workspace named to it for which it sent none, and the platform refuses that member's removal as it refuses a protected one's (`protected`; only an owner may remove them anyway, after a recent sign-in).

**Labels and hints.** A label is a name a person gave the item, never its number or its address. The app sets aside placeholders, opaque ids and the number or address itself, applies NFC, and then `contract.CleanLabel`, which returns `""` (no label) when nothing is left:

- any text with `@`, or a character that reads as one (U+FF20, U+FE6B), is dropped (`platform/contract-v1/labels.json#clean/vendas@loja.com`, `platform/contract-v1/labels.json#clean/joao＠gmail.com`);
- C0 and C1 controls, every format character (bidirectional controls, zero-width characters, the soft hyphen, the word joiner) and the combining grapheme joiner go (the file's cases with U+202E, U+200B, U+00AD and U+034F, which this text does not spell);
- whitespace collapses to single spaces, and the ends are trimmed (`platform/contract-v1/labels.json#clean/Suporte   24h`);
- each run of 7 or more decimal digits of any script, with spaces, `.`, `,`, `/`, `_`, `(`, `)`, `+`, `-`, `·`, `•`, `*`, `#`, any dash or the minus sign U+2212 between them, becomes `…` (U+2026) and its last four digits, and a `+` or `(` just before it goes with it (`platform/contract-v1/labels.json#clean/+55 (11) 91234-5678`, `platform/contract-v1/labels.json#clean/Loja 11912345678`, `platform/contract-v1/labels.json#clean/Loja 1 - 12345`, `platform/contract-v1/labels.json#clean/Safra 2024−2025`, `platform/contract-v1/labels.json#clean/１１９１２３４５６７８`);
- it is cut at 80 code points, never leaving half a flag.

A label is valid when it is not empty and `CleanLabel` leaves it unchanged (`contract.ValidLabel`); cleaning twice changes nothing. The platform applies NFC and `CleanLabel` again on intake, as a backstop, and drops a hint that is not one. A hint (`contract.ValidHint`) is `…` and the last four ASCII digits of a number (never of a WhatsApp LID), or a lowercase letter or digit, `…@` and the domain of an address, of lowercase labels with a dot, no empty label and fewer than 7 digits (`platform/contract-v1/labels.json#hints/…5678`, `platform/contract-v1/labels.json#hints/j…@gmail.com`, `platform/contract-v1/labels.json#hints/j…@localhost`, `platform/contract-v1/labels.json#hints/a…@5511912345678.com`); nothing else. The console names an item by its label, else its hint; a mail names a mailbox by its label only.

**Events** (`contract.Events`, `contract.Event`): a batch of 1 to 100 from an outbox written in the same transaction as the change, each workspace's in its order (`platform/contract-v1/wire.json#events/an owner deleted a number`):

| Type | When | `actor_kind` | Only on this type |
|---|---|---|---|
| `item.deleted` | an owner deleted it | `person` | `purge_at`, required (`platform/contract-v1/wire.json#events/a deletion with no purge date`, `platform/contract-v1/wire.json#events/a deletion by an API key`) |
| `item.recovered` | an owner recovered it | `person` | |
| `item.sync_paused` | a person, or an API key, turned off a mailbox's sync or a number's capture; never for a pause the app or the platform makes on its own | any | |
| `item.purged` | the app deleted it for good | `app` | |
| `item.stranded` | it lost the last person who could read it | any | `person` (the sub it lost, or `null`) and `cause` (`disabled` or `revoked` when the app knows; `null`, and the platform fills `removed`, `left` or `closed`) |
| `item.moved_out` | a Wappie number moved out of a team into a person's personal workspace, allowed only when nobody else has access to it (the owner, 2026-10-13) | `person` | `to: "personal"`, required; `item.kind` is `number` (`platform/contract-v1/wire.json#events/a mailbox moved`) |

- `event_id` is the idempotency key, a UUID (version 7); `workspace_id` a workspace named to the app; `occurred_at` the app's time of it; `item` its `id`, `kind`, `label` and `hint`, under the rules above (`platform/contract-v1/wire.json#events/a label that is an address`).
- `actor` is the sub of the person who acted, an API key's creator's for an API key, and `null` when no person did; always `null` with `actor_kind: app` (`platform/contract-v1/wire.json#events/the app's own act with an actor`). A person with no sub goes as `actor: null`, `actor_kind: person`.
- `readers` are the item's readers just before, the actor included, each once, at most 5000; above that, `null`, and the platform uses the readers of its latest snapshot (`platform/contract-v1/wire.json#events/more readers than an event carries`).
- A member of another type of event is refused (`platform/contract-v1/wire.json#events/a cause on a pause`).
- **The results** (`contract.EventResults`), one per event, in order, `{"event_id", "outcome", "code"}`: `accepted` (kept); `duplicate` (an event with this `event_id`, workspace, type, item and time, at microseconds, is kept already: the app marks it delivered; the inbox keeps an event 30 days from its arrival, the retention below, and an event sent again after that is taken as a new one); or `rejected` with `invalid_request` (the event alone, which includes one that does not decode: the rest of the batch goes on), `not_found` (a workspace never named to the app) or `conflict` (the `event_id` is kept with other content), and no other code. A row is delivered only on a signed `accepted` or `duplicate`.
- **A fault is no verdict.** A fault that says nothing of an event (the platform's database, a deadlock) fails the whole call with a signed `503 unavailable`, never an event `rejected`: the app sends the batch again, with a fresh nonce, and the events kept before the fault come back `duplicate`.
- **Order** is per workspace: one queue per platform workspace, each sent in order; a failure stops only that workspace's queue, retried with a backoff of 5 s × 2ⁿ capped at an hour.
- **When not to send.** No `item.sync_paused` when the item's readers, less the actor, are none; `item.deleted`, `item.recovered` and `item.purged` are always sent. At most one `item.sync_paused` per item and actor an hour, with the union of their readers. Events from before an app's transport went live are not sent.

**What the platform mails** of the events it keeps (decision 0039), which an app does not send itself:

| Event | To whom |
|---|---|
| `item.deleted`, `item.stranded`, `item.moved_out` | the workspace's owners |
| `item.sync_paused` | the item's readers who are still members; nobody when its `actor_kind` is `app` |
| `item.recovered`, `item.purged` | nobody |

Never the actor, about their own act, and nobody for a personal workspace's own acts. An actor who is not a current member is not named, the link is the app's origin from the platform's registry, never from the event, and no name a person chose goes in a subject. Past its caps, 50 events a day per app and workspace and 200 per app, the mails wait for the next day; none is dropped for the cap. A waiting mail is withdrawn only when its person is no longer who it was for: their account closed, their membership ended, or, for the owners' mails, they are no longer an owner. Waiting mails go `deleted`, `stranded` and `moved_out` first, then `sync_paused`.

**Retention** (decisions 0027 and 0040):

| Data | Kept |
|---|---|
| The platform's inbox of events | 30 days |
| The latest snapshot of a workspace | until the next one replaces it; an item's rows go with `item.purged` |
| A closed account's documents | until the app unsubscribes, at most 30 days |
| A closed account's record of closing (sub and time) | 13 months |

**What stays in the platform:** the socket and its peer check; the console's service behind the calls (the documents computed from its database, the publisher, the inbox and its retention, the mails of decision 0039 and their caps, the protection verdicts of the console's Access section); the secrets' storage, tier 2, and the rotation's commands; and in each app, its follower, its outbox and what it does with a document (the platform's design of the membership part). `contracttest` plays the platform's development transport, in the order above, before an in-memory directory a test sets; it reads no uid, mails no one, lets nothing expire (the retention above) and is for tests only. A test may hold its publisher for an app (`HoldPublishing`, then `Release`) to play a stuck one: the feed answers while its `published_through` grows old.

Vectors: `signatures.json` (4 requests and 3 answers with their canonical strings and signatures; 10 answer checks, 2 `ok`, 1 `answer_nonce`, 5 `hmac_bad`, 1 `hmac_stale`, 1 `hmac_missing`; 7 pairs of secrets, 2 valid), `wire.json` (13 documents, 9 snapshots and 17 events, of which 5, 4 and 8 validate) and `labels.json` (34 labels before and after `CleanLabel`, 14 hints, 3 valid), from platform commit `a78bf16` and the same at `ee45e3a` and `8a7b73c`, and `wire-item-ids.json` (3 snapshots whose items share an id, 1 valid), from `ee45e3a` and the same at `8a7b73c`, which the platform added once `wire.json` was frozen, in the contract's format (section 12.4). An implementation conforms when it reproduces every canonical string and signature, ends every answer check as it records, and accepts and refuses every secret, document, snapshot, event, label and hint as they say.

## 12. Vectors

The layout, the op catalogue and the provenance of every file are in `vectors/README.md` and `vectors/PROVENANCE.md`. Mailie's golden file of its platform wrap is under `vectors/mailie/golden/`, in the kit's format, written by the kit's own generator, which `make vectors-mailie-regen` runs again; Mailie's own files of its key scheme are under `vectors/mailie/key-scheme-v1/`, in the kit's format, carried byte for byte from Mailie (`vectors/PROVENANCE.md`): the kit's Go code writes them again byte for byte in every test run, the seeded seals of two of them on the toolchains `vectors/PROVENANCE.md` lists (on any other those skip and say so, and the seals are opened), and `make vectors-mailie-check` has Mailie's own generator write them. The platform's contract's files are under `vectors/platform/contract-v1/`, in their own format (section 12.4), carried byte for byte from the platform: the kit's Go code writes them again byte for byte in every test run, and `make vectors-contract-check` has the platform's own generator check them. Run the conformance suites with `make test` (both languages), `make test-go-1.26.7` (adds the byte-for-byte replays of Wappie's Go vectors), and `make cross` (fresh round trips in both directions); the Go targets pass the build tag `kitdevkek`, which THCSEAL's runner needs (section 14.3). Files are append-only once a release is tagged.

### 12.1 The kit's format

Everything under `vectors/wappie/`, `vectors/kit/` and `vectors/mailie/` is in the kit's format, `thehappieco-kit-vectors/1`: cases with an `id`, an `op`, `in`, and exactly one of `out` and `error`, bytes in standard base64 (`vectors/README.md`, "Format").

### 12.2 The platform's format

`vectors/platform/id-v1/*.json` are the platform's own files, carried byte for byte (provenance in `vectors/PROVENANCE.md`). Each is `{"format": "thehappie-id/vectors", "version": 1, "kind": "<kind>", "cases": [...]}`; a case has a unique `name`, or, in a file whose cases carry `op`, a unique `op` and `name`, and either its outputs or `"error": "<name>"` (section 11.10). Binary values are base64url without padding; texts are JSON strings; the files are ASCII. Kinds and members: `password-profile` (`password`, or `password_utf16` with `password_utf8_b64url` for a string that is not Unicode, each language taking its own form; `new`; `prepared_b64url`), `kdf` (`prepared_b64url`, `salt`, `kdf`; `k_auth`, `k_wrap`, `auth_key`), `root-wrap` (`kind`, `key`, `nonce`, `root`, `sub`, `epoch`, `rp_id`, `credential_id`; `aad`, `wrap`), `recovery-code` (`bytes` or `input`; `display`, `canonical`, `k_rwrap`, `recovery_auth`), `product-key` (`root`, `product`, `epoch`; `sk`, `pub`, `product_key_id`), `verifier` (`sub`, `k_auth` or `r_proof`; `auth_verifier` or `recovery_verifier`), `email` (`input`; `email_norm`), `key-bundle` (`password` or `recovery_code`, `bundle` as a JSON value or `bundle_text` as the exact file text; `root`), `password-stream-safe` (the members of `password-profile`), `key-delivery` (`op` on must-fail cases, `open` or `seal`; `root`, `product`, `epoch`, `iss`, `client_id`, `redirect_uri`, `sub`, `product_key_id`, `pk_p`, `code_challenge`, `nonce`, `akd_priv`, `akd_pub`, `eph_priv`; `aad`, `akd_sealed`), `pkce` (`code_verifier`; `code_challenge`), `passkey` (`op` on must-fail cases, `salt`, `key` or `open`; `rp_id`, `prf`, `root`, `sub`, `epoch`, `credential_id`, `nonce`; `prf_salt`, `k_pk`, `aad`, `wrap`), `client-extensions` (`client_extension_results`, the exact JSON text as a string), `rp-id-ends-in-number` (`rp_id`; `ends_in_a_number`, `prf_salt`). A binary member the generator left empty is omitted; `prf`, `rp_id` and `client_extension_results` are written even when empty, and `rp_id` and `ends_in_a_number` on every case of their kind. Argon2id cases use the floor parameters, and one uses p = 4. A runner decodes strictly: a member it does not read fails it.

### 12.3 THCSEAL's format

`vectors/platform/thcseal-v1/thcseal-v1.json` is the platform's own file, carried byte for byte (provenance in `vectors/PROVENANCE.md`): `{"comment": [...], "provider": "localkek (0x7f)", "kek_hex": "<32 bytes>", "valid": [...], "invalid": [...]}`. Every envelope in it is sealed with the local provider (section 14.3) under `kek_hex`, the published test key `000102…1f`. A valid case has a `name`, a `context` (`service`, `env`, `purpose` and `ref`, written even when empty), `plaintext_hex`, `envelope_hex`, and the intermediate values `data_key_hex` and `aad_hex`; an invalid case has a `name`, a `context`, `envelope_hex` and an `error`, one of `malformed`, `provider_mismatch` and `decrypt` (section 14.2), which an opener reaches in that order. Bytes are lowercase hex. Names are unique within each list, and a case is identified and cited by its list and its name (`platform/thcseal-v1/thcseal-v1.json#invalid/version 2`). The file is ASCII and ends with one newline. A runner decodes strictly: a member it does not read fails it.

### 12.4 The contract's format

`vectors/platform/contract-v1/*.json` are the platform's own files, carried byte for byte (provenance in `vectors/PROVENANCE.md`). Each is `{"format": "thehappie-contract/vectors", "version": 1, "kind": "<kind>", "description": "...", ...}` with the lists of its kind. `signatures` also holds the scheme (`label`, `headers`, `skew_seconds`) and the lists `requests` and `answers` (`name`, `secret`, `direction`, `app`, `method`, `target`, `timestamp`, `nonce`, `body`; `canonical`, `signature`), `answer_checks` (`name`, `headers`, the answer's; `secrets`, those the app accepts; `app`, `method`, `target`, `sent_nonce`, `body`, `now` in Unix seconds; `result`, `ok` or the refusal's code) and `secrets` (`name`, `current`, `next`; `valid`). `wire` holds `documents`, `snapshots` and `events` (`name`, `value`, a JSON value; `valid`: whether it decodes and its `Validate` accepts it; a value that does not decode is invalid); `wire-item-ids.json` is of this kind too, with snapshots only. `labels` holds `clean` (`raw`; `clean`, `""` for no label) and `hints` (`hint`; `valid`). Texts are JSON strings and bodies the exact bytes signed. A case is identified and cited by its list and its name, and in `labels.json` by its list and its `raw` or `hint`, all unique (`platform/contract-v1/wire.json#events/a mailbox moved`, `platform/contract-v1/labels.json#clean/Loja 11912345678`). `signatures.json` and `wire-item-ids.json` are ASCII, `wire.json` and `labels.json` UTF-8; each ends with one newline. A runner decodes strictly: a member it does not read fails it.

## 13. Security considerations

- **The key id is outside the batch AAD** (section 4.5): bound through the content key's row instead.
- **Zeroisation is best effort.** Neither language can clear a string (the password as typed), and Go's runtime may have copied a buffer before it is cleared. What each clears:
  - Go: in `account.Derive` and `DeriveBytes`, the one copy of the password as bytes they hold (what the profile's preparation returns, also when it refuses the password, or the UTF-8 bytes when the profile has none) and the Argon2id master key; in `account.DerivePrepared` and `DerivePreparedBytes`, the master key (the prepared bytes it is given are the caller's to clear); in `account.RecoveryKey`, `RecoveryProof` and `RecoveryProofBytes`, the copy of the normalised code, and in `RecoveryProof` the proof once it is encoded. The auth key, the wrap key and their text (`Derived.AuthText`) are the caller's to clear (`Derived.Clear`), as are the recovery key and `RecoveryProofBytes`' proof. `Derived.AuthKey`, a string nothing can clear, is deprecated: `DeriveBytes` and `DerivePreparedBytes` make no string of the auth key.
  - TypeScript: the UTF-8 encoder's own output once it is copied, so the copy of a password or recovery code the kit zeroes is the only one it made; in `derive`, the prepared password bytes, the master key and the raw auth and wrap keys, success or failure; in `derivePrepared`, the master key and the raw auth and wrap keys (the prepared bytes it is given are the caller's to zero); the KDF worker is sent the prepared password only after it has answered the page's hello, as a copy that is transferred and which the worker zeroes whatever happens, and it copies the master key into a buffer of its own before transferring it back; the recovery code's HKDF input, the raw recovery key after import and the recovery proof's bytes once they are text; the auth key and the recovery proof are strings, which cannot be cleared and are sent as text anyway; a content key's raw bytes after import (`ContentKey.unwrap`); the raw key after import in `openBrowserAccountKey`; in `hpke`, the PKCS#8 buffer built to import a private key and the PKCS#8 export of a generated one. The raw private key a caller passes in or receives (`generateKeyPair`) is the caller's to clear.
  - Keys held as values (Go's content keys and private keys, TypeScript's non-extractable `CryptoKey`s) live as long as the values that hold them.
- **The KDF worker** (TypeScript, `kdf.worker`). The page posts a hello and waits up to 10 seconds for `{ready: true, v: 2}`; a worker that cannot be made, fails to load, answers anything else or does not answer in time is terminated before it is sent the password, and Argon2id runs on the calling thread with the password the page still holds. Once the password is sent, as a transferred copy, the worker checks the algorithm, the parameters and the profile's bounds again and answers a refusal (`out_of_bounds`, `unsupported_alg`) apart from a failure (`kdf_failed`), never with a message; a failure, or a worker that dies, is `kdf`/`kdf_failed` and is not derived again on the calling thread. The worker answers version 1 of its protocol (kit v0.1.0) as before and posts nothing it was not asked for. Only the entries that start the kit's worker name its file (`account` and `profiles/platform`); `profiles/platform/core` runs Argon2id only in the worker the caller's `options.worker` makes, or on the calling thread, and `oidc-rp` reaches no worker.
- **Random nonces.** At most 2^20 values per content key (section 4.9).
- **Wappie's wrap binds the email** (section 6.6): an email change needs a re-wrap.
- **The platform wrap is symmetric** (section 6.8): an HPKE seal to `pk_p` could be made by anyone who holds `pk_p`, the product's server included; only a holder of `sk_p` makes the wrap, and an opener checks the opened key's public half against the binding's, which the page compares with the account's (Wappie's `users.public_key`). It binds the account, the sub and the product key's epoch, never the email. In TypeScript `K_pw` is a non-extractable `CryptoKey`, and the copies of `sk_p` and of the account key handed to WebCrypto are zeroed; in Go `K_pw` is cleared once the cipher holds it. The account key it opens is the caller's to clear.
- **The platform wrap's header is the same for every product** (section 6.8): products are kept apart by `sk_p`, the labels and the `product_key_id`: all three go into `K_pw`, and the labels and the key id into the AAD as well, so a second header would be a second knob with no cryptographic effect. Another `sk_p` alone fails at the tag (`mailie/golden/platform-wrap-go.json#mailie/platform-wrap/open/refuses/another-product-key`), and so do a salt alone, a label alone, and a product with the binding's key id alone under the same labels (the unit tests `TestUnits` of `platformwrap/platformwrap_test.go` and "opens a wrap under its own profile only" of `js/test/platformwrap.spec.ts`; a vector cannot show these, since its profile is a shipped product's). The cross-product vectors change several at once: the same person's wrap of the other product differs in all three (`mailie/golden/platform-wrap-go.json#mailie/platform-wrap/open/refuses/cross-product/the-same-persons-wappie-wrap`), a wrap of the other product under the same key bytes in the labels and the key id's product (`mailie/golden/platform-wrap-go.json#mailie/platform-wrap/open/refuses/cross-product/a-wappie-wrap-under-the-same-key-bytes`), and a wrap with its own binding, or a seal with the other product's key id, is refused before anything is derived, by the check of the key id's product (`mailie/golden/platform-wrap-go.json#mailie/platform-wrap/open/refuses/cross-product/a-wappie-wrap-with-its-own-binding`, `mailie/golden/platform-wrap-go.json#mailie/platform-wrap/seal/refuses/cross-product/a-wappie-product-key-id`); the three cases of opening have their reverse under Wappie's labels (`mailie/golden/platform-wrap-go.json#wappie/platform-wrap/open/refuses/cross-product/*`). A product's other envelopes of its account key must not start with `0x03`, and each product keeps its wraps in a column of its own, since the shape check cannot tell a Wappie wrap from a Mailie one.
- **No KDF bounds in the Wappie profile** (section 6.2): a downgrade by whoever writes the database. New profiles set bounds.
- **Passkeys are bound to the RP ID** (section 7).
- **All-zero shared secrets** (section 4.4). A public or encapsulated key of low order yields an all-zero X25519 output. Go's `crypto/ecdh` refuses it. The TypeScript implementation checks the output itself, with no early exit, whatever WebCrypto does, in sealing and in opening; its tests run every forgery also on a stand-in engine that lets the zeros through. The vectors carry real forgeries, which an implementation missing the check opens.
- **Any 32 bytes are an X25519 private key, on every engine** (sections 6.4 and 11.4). WebKit's WebCrypto on Linux (WebKitGTK and WPE WebKit, built on libgcrypt; Playwright's WebKit for Linux is WPE) drops a leading zero byte of a private key: it refuses to import one whose first byte is zero (the all-zero key, 1 in 256 uniform keys and so 1 product key in 256, 1 in 32 of the keys Safari and OpenSSL generate, which they store clamped), and fails 1 X25519 key generation in 256 with an `OperationError`. The TypeScript side imports every private key through a PKCS#8 copy with bit 0 of the first byte set, which X25519 clears before it multiplies (RFC 7748 section 5), so the key computes the same on every engine and the changed bit never leaves the non-extractable key; and it asks again when a generation fails with an `OperationError`, four attempts in all: four failures in a row are 1 in 2^32 there, and the draws the engine refused cost the key under 0.01 bit. No other refusal is asked again. The tests run the class on every engine (`hpke-ts.json#hpke/public-from-private/zeros`, `kit/platform-delivery-go.json#platform/open-product-key/13`, and fixed keys and product keys with a zero first byte) and refuse generations as that engine does.
- **The reserved header byte** is bound by the AAD, not checked (section 4.1).
- **Decoy salts** for unknown accounts are a server concern and outside the kit, and so are the salts Mailie's server hands out for every address (Appendix D).
- **Mailie's grants check what HPKE cannot** (Appendix D). Base mode authenticates no sender, so anyone who knows a person's public key, a server included, can seal them a rightly bound grant of a key of its choosing; Mailie's opener refuses a grant whose key's public half is not the mailbox's public key, so such a forgery opens only for a sealer that holds the mailbox's real key (`mailie/key-scheme-v1/grant-go.json#mailie/grant-open/refuses/a-key-the-sealer-chose`). A server can check a grant's shape only, and cannot check that a public key it hands out is its person's: Mailie's threat model states that residual, key substitution, and what phase 4 would add against it.
- **The platform's KDF bounds are compiled in** (section 11.3). A server can still give two addresses the same salt; the client cannot tell. The bound fixes only the length. The decoy-salt derivation is the server's.
- **Unicode versions and Stream-Safe text** (section 11.2): a password whose compatibility decomposition holds more than 30 marks or Hangul vowel and final jamo in a row is refused rather than prepared two ways, because Go's normaliser would insert U+034F there and ICU's would not; the Go side also refuses a password into which its normaliser would still insert one. Characters assigned after Unicode 15.0 with canonical mappings may prepare differently on sides with older tables. The rule is counted code point by code point, so a long pasted run is refused in linear time on the page's main thread.
- **The platform's verifiers are a fast hash on purpose** (section 11.7).
- **Product public keys are pinned in one spelling** (section 11.4). Sealing to a low-order key is refused by `hpke` anyway (section 4.4).
- **Strict reading of files that gate key material** (section 11.9): repeated members, number spellings and unknown members are refused rather than resolved.
- **The key bundle's honest limit** (section 11.9): an old bundle opens with an old password or code.
- **Zeroisation in the platform profile** follows the rest of the kit: Go clears the Argon2id master key, the prepared password it made, and the roots and keys it derives on its own behalf, and `DerivePassword` and `DeriveRecovery` make no string of `K_auth` or `R_proof` (only `PasswordKeys.AuthKey` and `RecoveryKeys.RecoveryAuth` do, when the caller asks for the wire value); TypeScript zeroes the prepared password it made, the master key and raw wrap key (in `account`), the PKCS#8 copy of a product key (in `hpke`), and the raw root it seals. Derived wrap keys are non-extractable `CryptoKey`s in TypeScript.
- **Key delivery does not authenticate the sender** (section 11.12). The page keeps a delivered key only after its server's insert-only pin names it (section 11.14 step 9, section 11.15). The pin protects only a `product_key_id` already pinned: a first login, or a new epoch, trusts the registry. A page that stores the key `callback` returns without the comparison of step 9 skips it.
- **One spelling of `enc`** (section 11.12): both openers refuse a non-canonical one that RFC 9180 engines would open.
- **Deterministic seals exist only in tests.** The vectors' `eph_priv` make their blobs readable by anyone; the kit's ways to seal under a chosen ephemeral key are test code (Go `internal/forge`, TypeScript `withDraws`), and no shipped function takes one.
- **Zeroisation in key delivery.** TypeScript: key delivery's HPKE zeroes every secret of its key schedule, the PKCS#8 buffers that carry X25519 keys into WebCrypto are zeroed, `sk_p` is zeroed after sealing, an opened key that fails a check is zeroed, and the relying party zeroes the raw ephemeral key after sealing it and the delivered key after keeping it, on every path. The `hpke` module, which `seal` uses, does not wipe its key schedule. Go: crypto/hpke's internal schedule is beyond reach; `OpenProductKey` clears what it refuses. WebCrypto's own copies are beyond reach everywhere.
- **The page does not verify the ID token's signature** and never compares its times with the device clock (section 11.14 step 6): the nonce ties it to a flow used once within 10 minutes, and the server trusts only userinfo, on its own clock, through a single-use token.
- **The flow store** holds the ephemeral key only under a non-extractable AES key, bound to the client and the state; a flow is used once and lives 10 minutes.
- **The callback's code** never leaves in `Referer` or in logs (section 11.14).
- **No PRF output leaves the page** (11.16). The page builds what it sends from an allowlist, and the server refuses rather than drops anything outside it, so a page bug is a refused request, not a secret in a request body, a log line or a database row. Refusals never repeat what they refused.
- **One spelling of the relying party id** (11.16): a second spelling would be a second salt and a second key, and a wrap that never opens. The functions that seal and open in one call take the id once, for the key and the AAD; a caller of the lower-level path must give both the same id.
- **A relying party id that ends in a number** (11.16) is never a host a browser serves, so a check of the spelling that let one through would mis-key nothing that exists; the platform profile refuses it so that a configuration error is reported where it is made. The generic passkey scheme leaves the check to the profile or the product (section 7).
- **The allowlist reads text** (11.16), as the key bundle's reader does (11.9): a repeated member, a name in another case, a byte order mark and trailing data are refused rather than resolved, because the WebAuthn library resolves them its own way. A TypeScript caller that decodes bytes keeps a leading byte order mark only with `ignoreBOM: true`.
- **K_pk** is a non-extractable `CryptoKey` in TypeScript, and the copy of the PRF output handed to WebCrypto is zeroed; Go's `PasskeyWrapKey` returns bytes the caller clears, and `NewPasskeyWrap` and `OpenPasskeyWrap` clear theirs. The PRF output is the caller's to zero in both languages, and the root `unwrapRootWithPasskey` lends is zeroed when its callback settles.
- **A passkey wrap is as strong as the passkey.** Whoever holds the authenticator (or, for a synced passkey, any device it syncs to) and a copy of the wrap opens the root. Recovery revokes every passkey on the platform's server, but the root does not change, so a wrap copied before keeps opening with that passkey's PRF: the honest limit of the key bundle (11.9), for passkeys.
- **An all-zero PRF output** is a valid input here; refusing one read out of a credential is the ceremony's rule (11.16).
- **Error codes, not messages.** Direct-mode failures are one code, so a reader is not an oracle for which binding failed.
- **A contract answer is its request's** (section 11.17). The platform signs every answer to a request whose signature held over the request's method, target and nonce, which the answer echoes, with the other direction: an answer cannot be replayed to another request nor presented as a request, and an app needs no replay cache to check one. An app compares the echoed nonce with the one it sent, never one read from the answer, and never acts on an HTTP status alone or on an unsigned answer: a refusal sent before a signature held tells it nothing. The platform's own replay cache lives in memory, so every write is idempotent by its own key (the subscription, `snapshot_seq`, `event_id`) and correctness never rests on the cache.
- **The contract's secret is checked, and keyed as written** (section 11.17). An empty key is a valid HMAC key, so both sides check a secret's length and alphabet wherever they load it, and `contract.Client` refuses an empty or malformed secret among those it accepts before it sends anything. The key is the secret's 43 characters, never the 32 bytes they encode: an implementation that decodes them signs differently and every answer it checks fails.
- **No number or address in a label** (section 11.17). An app sets them aside before it masks, and both sides apply the mask: the platform cleans every label again on intake and drops a hint that is not one, and its mails never name a mailbox by its hint, whose domain a sender could choose. The mask reads the Unicode tables of the Go it is built with (Unicode 15.0 below Go 1.27), so a digit or a format character assigned after one side's tables may be masked on one side only; the platform's backstop is what holds.
- **A contract call ends** (section 11.17). Disables and revocations reach an app through the feed, a long-poll: a follower blocked for good on a platform that stalled would apply none of them, and log nothing. `contract.Client` bounds every call whatever its context; an app's own client does the same.
- **`contracttest` is no platform** (section 11.17). It reads no peer uid, keeps everything in memory and mails no one; an app's tests use it, never its production configuration.
- **Tier-2 secrets** (section 14). The context is in the envelope's AAD, so a wrapper that ignored it would still not open an envelope moved to another row; an unwrap that fails and a tag that fails are one error, `decrypt`, while a wrapper that cannot be reached (an outage, a refused permission, a cancelled request) is reported as itself and never as tampering. The context is written to KMS's audit log in clear, so it never carries personal data, which its alphabet makes hard to do by accident. The local KEK cannot be linked into a build without the tag `kitdevkek`, and its envelopes carry a provider byte that every other wrapper refuses. The AWS wrapper takes its credentials from the instance role alone, so anything on the machine that reaches the instance metadata service acts with the whole role: the honest limit of the platform's decision 0003, which the machine narrows (IMDSv2 required and a hop limit of 1, so containers on it cannot reach the role: the platform's decision 0020).

## 14. Tier-2 secrets: THCSEAL v1 and the key wrappers

- Status: normative, from the platform's `internal/seal` and `internal/kms` at platform commit `d32b663` (the platform's decisions 0003 and 0017), with their tests at `d3e8c6d`. Only servers seal tier-2 secrets, so there is no TypeScript.
- Implementations: Go `thcseal` (the envelope), `kms` (the encryption context, the `Wrapper` interface and the provider bytes), `kms/awskms` (AWS KMS) and `kms/localkek` (a local key-encryption key, for development and tests only, which compiles only with the build tag `kitdevkek`).
- Vectors: `platform/thcseal-v1/thcseal-v1.json`, the platform's file, carried byte for byte (section 12.3).

A tier-2 secret is one a server uses on its own: the platform's OIDC signing key and HMAC keys, Stripe and SMTP credentials, a product's mail provider credentials, the database backups (the platform's decision 0003). It exists at rest only inside an envelope whose data key is wrapped by a key wrapper, and the envelope opens only for the exact encryption context it was sealed under, and only with the provider that sealed it.

### 14.1 The encryption context

```
context = {service, env, purpose, ref}
```

`service` is the product (`platform`, `mailie`), `env` the deployment (`prod`, `dev`, `test`), `purpose` what the secret is (`config/stripe-secret-key`, `serverkey/oidc-signing`, `backup`, `credentials`) and `ref` which one (a key id, a secret name, a backup stamp). `service`, `env` and `purpose` are required and `ref` may be empty; every field is at most 128 bytes of `[a-z0-9._:/-]`, so that it stays short and holds no personal data: KMS writes the context to its audit log in clear, and the key policy conditions on it. A context outside these is refused before any wrapper is called, with an error that names the field and never its value (Go `kms.ErrInvalidContext`). The context is bound into every envelope, and an envelope of one service does not open as another's (`platform/thcseal-v1/thcseal-v1.json#valid/another service`, `platform/thcseal-v1/thcseal-v1.json#invalid/another service`). As KMS takes it, the context is the map of the four fields with `ref` left out when it is empty; since `ref` is the only optional field, the mapping stays one to one.

### 14.2 The envelope

```
envelope = "THCSEAL" (7) || 0x01 || provider (1) || u16be(L) || wrapped data key (L)
           || nonce (12) || AES-256-GCM(data key, nonce, plaintext, AAD)
AAD      = envelope bytes [0, 11 + L) || u16be(len(service)) || service || u16be(len(env)) || env
           || u16be(len(purpose)) || purpose || u16be(len(ref)) || ref
```

- **One data key per envelope**, 32 bytes, made by the wrapper together with its wrapped form and bound to the context; it is zeroed after use. Sealing is rare (key generation, secret entry, backups), so there is no nonce accounting.
- **Every header byte is authenticated**: the magic, the version, the provider byte, `L` and the wrapped key are in the AAD, so a change to any of them never opens and never changes behaviour. Which error it is depends on the field and on the checks of opening below, which come before decryption: another magic or version is `malformed`, refused by decoding (`platform/thcseal-v1/thcseal-v1.json#invalid/magic altered`, `platform/thcseal-v1/thcseal-v1.json#invalid/version 2`); another provider byte is `provider_mismatch` (`platform/thcseal-v1/thcseal-v1.json#invalid/provider relabelled as aws-kms`), unless it names the opener's own provider, and then `decrypt`; another `L` is `malformed` when it is out of bounds or runs past the end (`platform/thcseal-v1/thcseal-v1.json#invalid/wrapped key length 0`, `platform/thcseal-v1/thcseal-v1.json#invalid/wrapped key length past the end`) and `decrypt` otherwise (`platform/thcseal-v1/thcseal-v1.json#invalid/wrapped key length one short`); a changed byte of the wrapped key is `decrypt` (`platform/thcseal-v1/thcseal-v1.json#invalid/wrapped key byte flipped`). The nonce is not in the AAD, but it is the cipher's, so a changed one is `decrypt` too (`platform/thcseal-v1/thcseal-v1.json#invalid/nonce byte flipped`). The context in the AAD binds the envelope to its row as well as to its wrapped key: an envelope moved to another purpose, ref or env does not open, even under a wrapper that ignored the context (`platform/thcseal-v1/thcseal-v1.json#invalid/another purpose`, `platform/thcseal-v1/thcseal-v1.json#invalid/another ref`, `platform/thcseal-v1/thcseal-v1.json#invalid/no ref`, `platform/thcseal-v1/thcseal-v1.json#invalid/another env`).
- **Bounds.** `L` is 1 to 6144, the largest ciphertext KMS returns; a plaintext is at most 256 MiB, because a GCM message is held whole to be authenticated, and anything bigger needs a chunked format, not a bigger envelope. An empty plaintext seals and opens (`platform/thcseal-v1/thcseal-v1.json#valid/empty plaintext`); the smallest envelope is 40 bytes, a one-byte wrapped key and an empty plaintext.
- **Decoding** checks only the structure, in this order: at least the smallest length, the magic, the version `0x01`, `L` within its bounds, then that the nonce and a tag fit and the ciphertext is within the plaintext bound. A failure of any of these is `malformed` (`platform/thcseal-v1/thcseal-v1.json#invalid/empty input`, `platform/thcseal-v1/thcseal-v1.json#invalid/magic altered`, `platform/thcseal-v1/thcseal-v1.json#invalid/version 2`, `platform/thcseal-v1/thcseal-v1.json#invalid/wrapped key length 0`, `platform/thcseal-v1/thcseal-v1.json#invalid/wrapped key length 6145`, `platform/thcseal-v1/thcseal-v1.json#invalid/wrapped key length past the end`, `platform/thcseal-v1/thcseal-v1.json#invalid/truncated after the nonce`). Nothing decoded is authenticated until the envelope opens.
- **Opening**, in this order: the context (section 14.1); decoding (`malformed`); the provider byte must be the wrapper's own, or the envelope is `provider_mismatch` before the wrapper is asked anything (`platform/thcseal-v1/thcseal-v1.json#invalid/provider relabelled as aws-kms`); the wrapper unwraps the data key under the context; AES-256-GCM with the AAD. A wrapped key that does not unwrap, a data key that is not 32 bytes and a tag that fails are all `decrypt`, and which one is not said (`platform/thcseal-v1/thcseal-v1.json#invalid/tag byte flipped`, `platform/thcseal-v1/thcseal-v1.json#invalid/truncated by one byte`, `platform/thcseal-v1/thcseal-v1.json#invalid/a trailing byte`). A failure to reach the wrapper (KMS unavailable, access denied, a cancelled request) is returned as it is, never as `decrypt`, because it says nothing about the envelope and the operator needs to see it.
- **Sealing** refuses an invalid context and a plaintext over the bound before a data key is made, and a wrapper that returns a data key that is not 32 bytes or a wrapped key outside 1 to 6144 bytes; it draws a fresh random nonce.

Go: `thcseal.Seal(ctx, w, ec, plaintext)`, `thcseal.Open(ctx, w, ec, envelope)` and `thcseal.Decode`, with the errors `thcseal.ErrMalformed`, `ErrProviderMismatch`, `ErrDecrypt` and `ErrTooLarge` (matched with `errors.Is`), and `kms.ErrInvalidContext`. The names are the platform's; only the package's name and the prefix of its messages, `thcseal:`, differ, because the kit's `seal` is section 4's envelope.

### 14.3 The key wrappers

A wrapper (`kms.Wrapper`) has a provider byte, which it writes into byte 8 of every envelope it seals and requires on every envelope it opens, so a production wrapper never opens an envelope sealed with a development key. It makes fresh 32-byte data keys together with their wrapped form, bound to a context, and unwraps a wrapped form only under the same context; a wrapped form that does not unwrap is `kms.ErrUnwrap`, and every other failure is reported as itself.

| Provider | Byte | Wrapped data key |
|---|---|---|
| AWS KMS (`kms/awskms`) | `0x01` | KMS's `CiphertextBlob` of `GenerateDataKey` (`AES_256`) under one key, with the context as KMS's encryption context |
| reserved | `0x02` | the platform's transitional host-key provider |
| local KEK (`kms/localkek`) | `0x7F` | `nonce (12) \|\| AES-256-GCM(KEK, nonce, data key, aad)`, 60 bytes, with `aad = "thcseal-localkek/v1\n" + service + "\n" + env + "\n" + purpose + "\n" + ref` |

- **AWS KMS.** The key is a full key ARN, never an alias or a bare key id, in the wrapper's own region (a multi-region key's ARN included), and every call names it. At start, `DescribeKey` must show that exact ARN, enabled, `SYMMETRIC_DEFAULT` and `ENCRYPT_DECRYPT`, or the wrapper is not made. Every response must name the same ARN and carry a 32-byte key; any other answer is refused, and the key it carried is zeroed. Unwrapping names the key, the symmetric algorithm and the context. Credentials come only from the EC2 instance role through IMDSv2, at the fixed metadata address, with the IMDSv1 fallback off: environment variables, shared credential and config files, profiles, endpoint overrides and proxy variables are never read, so nothing on the machine can make the wrapper act as someone else or talk to another endpoint. KMS's refusal of a ciphertext (another key, another context, altered bytes: `InvalidCiphertextException`, `IncorrectKeyException`) is `kms.ErrUnwrap`; any other failure is returned as it is. Every request to KMS and to the metadata service has a 5-second timeout. The provider has no vectors, since its wrapped keys are KMS's; its tests run the real SDK client against a fake metadata service and a fake KMS on loopback.
- **The local KEK** is for development and tests only. Its package compiles only with the build tag `kitdevkek`, and no package of the kit imports it outside tests (`make imports-check`, in CI), so a binary built without the tag cannot link it; its envelopes carry `0x7F`, which every other wrapper refuses. The context's alphabet has no newline, so the separators of its AAD are unambiguous: a key wrapped for one purpose does not unwrap for the same bytes split differently between purpose and ref. A consumer passes `-tags kitdevkek` to the tests, vet and linters of every package whose tests use it and to its development builds, and no tag to its release builds, never through a `GOFLAGS` its release builds also read; the tests of the kit's `thcseal` and `kms/awskms` need it too.
- **The AWS SDK** is a dependency of `kms/awskms` alone (`make imports-check`): a module that never imports that package compiles nothing of the SDK, and its `go.mod` and `go.sum` gain no line for it, though `go list -m all` names the SDK's modules, which are in the kit's `go.mod`.

Go: `kms.Context` (`Validate`, `Map`), `kms.Wrapper`, `kms.ProviderAWS`, `kms.ProviderLocal`, `kms.DataKeyLen`, `kms.MaxFieldLen`, `kms.ErrUnwrap`; `awskms.New(ctx, region, keyARN)`, `awskms.NewWithAPI` (the same checks over a given client, for tests and for an owner's tool that runs outside the server), `awskms.RoleCredentials` (the same instance-role credentials for the server's other AWS client), with `ErrKeyARN`, `ErrKeyRefused` and `ErrUnexpectedResponse`; `localkek.New(kek)`, with `ErrKEKLength`.

Vectors: `platform/thcseal-v1/thcseal-v1.json`, 26 cases: 5 envelopes that open under the published test KEK `000102…1f` with the local provider (an empty plaintext, a short secret, a 32-byte server key, every byte value with no ref, another service), each with its data key and AAD, and 21 that must fail, 12 `decrypt`, 8 `malformed` and 1 `provider_mismatch`. The kit's Go implementation opens and refuses every one, and writes the file again byte for byte with the platform's generator in every test run.

## Appendix A. The Wappie profile

| Value | |
|---|---|
| Seal magic, label | `0x57 0x53`, `wsv1` |
| Seal kinds | section 4.8 |
| Account labels | `whatserver2/auth`, `whatserver2/wrap`, `whatserver2/recovery`, `whatserver2/recovery-auth` |
| Account wrap header; legacy v1 | `0x02`; yes |
| Account wrap AAD | `whatserver2/usk\|` + `email.trim().toLowerCase()` |
| Account default KDF | `argon2id`, m 65536, t 3, p 1; no bounds; no preparation |
| Text encoding | base64 with padding |
| Passkey prefix, info, header | `wappie/passkey-vault/v1/`, `wappie/passkey-wrap/v1`, `0x01` |
| Passkey AAD | `["wappie/passkey-vault",1,rpID,userID,credentialID]` |
| Browser key AAD | `["wappie/browser-account-key",1,userID,base64(public key)]` |
| Request HMAC | `wappie-mcp-hmac/v1`; `X-Wappie-Reader`, `-Timestamp`, `-Nonce`, `-Signature`; `to-reader`, `to-go`; skew 60 s; replay lifetime 61 s; capacity 100,000 |
| Platform wrap | header `0x03`, 61 bytes; product `wappie`; `K_pw` HKDF salt `wappie/platform-wrap/v1`, info JSON AAD `["wappie/platform-wrap",1,user_id,sub,product_key_id]`; AAD `["wappie/platform-wrap",1,user_id,sub,product_key_id,base64url(account public key)]` (section 6.8) |

## Appendix B. Changes

- Spec 1 (kit v0.1.0): first version, from Wappie at `8c0c1f74103bc6bb65a93b13613ad1964d4399c4`. Beyond Wappie, and only for inputs that never produced openable data: the low-order checks of section 4.4 in TypeScript, the salt bound of section 6.2, the refusal of empty passkey AADs (section 7) and of JSON AADs with no JCS text (section 2).
- Spec 2 (kit v0.2.0): section 11 part 1, the platform profile, with the platform's id-v1 vectors at `5e66d84`; sections 1, 3, 6.7, 12 and 13 extended; Appendix C. Nothing in the Wappie profile changed.
- Spec 3 (kit v0.3.0): section 11 part 2 (sections 11.12 to 11.15), with the platform's vectors at `4476bf4`; the reservations for the passkey root-wrap key and the product contract move to sections 11.16 and 11.17; sections 1, 11.1, 11.2, 11.4, 11.5, 11.10, 11.11, 12.2 and 13 extended. Nothing in the Wappie profile or in part 1 changed.
- Spec 4 (kit v0.4.0): section 11 part 3 (section 11.16), with the platform's vectors at `b5d9f69`; section 6.8 reserved for Wappie's platform wrap; sections 1, 7, 11, 11.1, 11.5, 11.10, 11.11, 12.2 and 13 and Appendices A and C extended. Nothing in the Wappie profile or in parts 1 and 2 changed.
- Spec 5 (kit v0.5.0): section 6.8, Wappie's platform wrap, replaces its reservation, an addition to the Wappie profile, with vectors written by Wappie's console; section 11.16 refuses a relying party id that ends in a number, with the platform's vectors at `75b6b94`, a refusal of ids no browser serves; sections 1, 7, 11, 11.4, 11.10, 11.11, 12.2 and 13 and Appendix A extended. No byte of the Wappie profile or of parts 1 to 3 changed.
- Spec 6 (kit v0.6.0): section 6.8 generalised to any product's labels, Wappie's wrap an instance of it, with the Mailie profile (Appendix D) and its vectors, written by the kit; section 14, THCSEAL v1 and its key wrappers, from the platform at `d32b663` with its vectors, and section 12.3, their file's format; sections 1, 3.1, 3.2, 3.3, 11.4, 12, 12.1 and 13 and Appendix A extended. No byte of the Wappie profile or of the platform profile changed.
- Spec 7 (kit v0.7.0): Appendix D holds the whole Mailie profile, from Mailie's specification at Mailie commit `c9c79cf`: its account scheme, seal domain and kinds, grants, browser vault, and the platform wrap's user id, the seal id, never the sub, a departure from the wording of section 6.8; with Mailie's vectors, carried byte for byte. Sections 1, 3.1, 6.8, 12 and 13 extended. No byte of the Wappie profile, of the platform profile or of Mailie's platform wrap changed.
- Spec 8 (kit v0.8.0): section 11.17, the membership part of the platform's product contract, replaces its reservation, Go only: the signature of its requests and answers, the wire's types and rules, the label mask and an app's client, from the platform's `docs/contract/v1/README.md` at platform commit `8a7b73c` and `internal/contract` at `ee45e3a`, the same at `8a7b73c`, with the platform's vectors and their format (section 12.4, new); section 9 extended with a paragraph that names the contract, and sections 1, 11, 12 and 13 and Appendix C extended. Section 9's scheme and every value and byte of the Wappie, Mailie and platform profiles are unchanged.

## Appendix C. The platform profile

| Value | |
|---|---|
| Account labels | `thehappie-id/v1/password/auth`, `thehappie-id/v1/password/wrap`, `thehappie-id/v1/recovery/wrap`, `thehappie-id/v1/recovery/auth` |
| Password preparation | `thehappie-password/v1` (section 11.2) |
| KDF bounds | m 65536 to 262144, t 3 to 10, p 1 to 4, m × t at most 1048576, salt exactly 16 bytes; default the floor (section 11.3) |
| Text encoding | base64url without padding |
| Recovery code normalisation | the canonical form C (section 11.6) |
| Account wrap header; legacy v1 | `0x01 0x01` (password), `0x01 0x02` (recovery), `0x01 0x03` (passkey); no |
| Root-wrap AAD | `["thehappie-id/root-wrap",1,kind,sub,epoch]`, and `rp_id`, `credential_id` for a passkey (section 11.5) |
| Product keys | HKDF salt `thehappie-id/v1/product-key`, info `product\|epoch` (section 11.4) |
| Verifiers | `thehappie-id/v1/auth-verifier`, `thehappie-id/v1/recovery-verifier` (section 11.7) |
| Key bundle | `thehappie-id/key-bundle`, version 1 (section 11.9) |
| Key delivery | info `thehappie-id/v1/key-delivery`; AAD `["thehappie-id/key-delivery",1,iss,client_id,redirect_uri,sub,product_key_id,pk_p,code_challenge,nonce]`; 80 bytes (section 11.12) |
| PKCE | S256; verifier 43 to 128 characters of `[A-Za-z0-9._~-]` (section 11.13) |
| Relying party | flow AAD `["thehappie-rp/flow",1,client_id,state]`; IndexedDB `thehappie-rp`, store `flows`; 10 minutes (section 11.14) |
| Pin verdicts | `new`, `same`, `account_key_changed` (section 11.15) |
| Passkeys | PRF salt SHA-256(`thehappie-id/v1/passkey-prf\|` + rp_id); `K_pk` HKDF info `thehappie-id/v1/passkey/wrap`, salt rp_id; the kind-3 root wrap (section 11.16) |
| Client extensions | `{}` or a subset of `credProps {rk: boolean}` and `prf {enabled: boolean}`, read on the exact text (section 11.16) |
| Contract signature | section 9 under `thehappie-platform-hmac/v1`; `X-Happie-App`, `-Timestamp`, `-Nonce`, `-Signature`; `to-platform`, `to-app`; skew 60 s; replay lifetime 61 s, capacity 100,000 per app; an answer signed over its request's method, target and nonce, which it echoes (section 11.17) |
| Contract secret | 43 characters of unpadded base64url, the text of 32 random bytes, keyed as written; a next secret differs from the current one (section 11.17) |
| Contract labels and hints | a label cleaned by the mask of section 11.17 (`…` and the last four of a run of 7 or more digits, at most 80 code points); a hint `…` and four ASCII digits, or a lowercase letter or digit, `…@` and a lowercase domain with a dot and fewer than 7 digits |

## Appendix D. The Mailie profile

Mailie's key scheme as Mailie specifies it: its `docs/key-scheme.md`, version 1, with its threat model `docs/key-scheme-threat-model.md`, at commit `c9c79cf` of `github.com/thehappieco/mailie`. It is the generic constructions of sections 4 to 8 under Mailie's values, with no construction of its own. Implementations: Go `profiles/mailie`, TypeScript `@thehappieco/kit/profiles/mailie`. Vectors: Mailie's own, `mailie/key-scheme-v1/account-go.json`, `mailie/key-scheme-v1/grant-go.json`, `mailie/key-scheme-v1/platform-wrap-go.json` and `mailie/key-scheme-v1/browser-vault-go.json` (248 cases, 150 must fail), written by Mailie's Go code and carried byte for byte, which the kit's Go code writes again byte for byte (the seeded seals on the toolchains `vectors/PROVENANCE.md` lists) and the kit runs, Go every case and TypeScript the 224 marked for it (137 must fail); and the kit's own of the platform wrap under Mailie's labels, `mailie/golden/platform-wrap-go.json` (section 6.8).

| Value | |
|---|---|
| Identities | a seal id, a person's, drawn once by Mailie's server and never changed; a namespace, a mailbox's, drawn by the browser that makes its key pair; each a UUID of version 4 and the RFC 9562 variant in lowercase hyphenated text, and nothing else |
| Account labels (HKDF info) | `mailie/v1/password/auth`, `mailie/v1/password/wrap`, `mailie/v1/recovery/wrap`, `mailie/v1/recovery/auth` |
| Password preparation | `thehappie-password/v1` (section 11.2): a password presented has no minimum length; a new one has 12 to 256 code points |
| KDF | `argon2id`, m 65536, t 3, p 1; bounds m 65536 to 262144, t 3 to 10, p 1 to 4, m × t at most 1048576, salt exactly 16 bytes (section 11.3) |
| Text encoding | base64url without padding |
| Recovery code | section 6.7's generation; the canonical form C of section 11.6 |
| Account wrap | section 6.5's envelope, header `0x02`, 61 bytes, no legacy form; AAD the restricted JSON AAD `["mailie/account-wrap",1,kind,seal_id,base64url(account public key)]`, kind `password` (under the wrap key) or `recovery` (under the recovery key) |
| Seal domain | magic `0x4d 0x4c` ("ML"), label `mlv1` |
| Kinds | `0x06` `content_key`, `0x07` `mailbox_grant`, `0x08` `user_wrap` (never sealed); reserved for Mailie's phase 4, with nothing sealed under them: `0x01` `headers`, `0x02` `snippet`, `0x03` `body`, `0x04` `attachment_key`, `0x05` `search_index`, `0x09` `folder_name`, `0x0A` `draft`, and `0x0B` to `0x0F` unnamed |
| Grant | a direct envelope of kind `0x07` of the mailbox's 32-byte private key, sealed to the person's account public key at `GrantRow(namespace, namespace, seal_id, epoch)`, info `mlv1/mailbox_grant/<namespace>/<epoch>`; 88 bytes; epochs 1 to 65535 |
| Platform wrap | section 6.8: header `0x03`, 61 bytes; product `mailie`; `K_pw` HKDF salt `mailie/platform-wrap/v1`, info JSON AAD `["mailie/platform-wrap",1,user_id,sub,product_key_id]`; AAD `["mailie/platform-wrap",1,user_id,sub,product_key_id,base64url(account public key)]`; `user_id` the person's seal id, never the sub |
| Browser vault | section 8 with the tag `mailie/browser-account-key`, version 1, and the seal id as the user id: AAD `["mailie/browser-account-key",1,seal_id,base64(account public key)]`, the JSON AAD of section 2, not the restricted one, since standard base64's `+`, `/` and `=` are outside its alphabet |

- **One spelling of an id.** A seal id or a namespace in upper case, in braces, with a `urn:` prefix, of another version, or nil is refused before anything is derived, sealed or opened, never normalised (`mailie/key-scheme-v1/account-go.json#mailie/account-wrap-aad/refuses/seal-id-in-upper-case`, `mailie/key-scheme-v1/account-go.json#mailie/account-wrap-aad/refuses/seal-id-in-braces`, `mailie/key-scheme-v1/account-go.json#mailie/account-wrap-aad/refuses/seal-id-a-uuidv7`, `mailie/key-scheme-v1/grant-go.json#mailie/grant-row/refuses/namespace-the-nil-uuid`).
- **The account scheme** is section 6 under these values: the derivation of section 6.3 (`mailie/key-scheme-v1/account-go.json#account/derive/ascii`; one password typed in NFC and in NFD with no-break spaces derives one key, `mailie/key-scheme-v1/account-go.json#account/derive/nfd-with-no-break-spaces`), parameters outside the bounds refused before anything is derived (`mailie/key-scheme-v1/account-go.json#account/derive/refuses/m-times-t-over-the-cap`, `mailie/key-scheme-v1/account-go.json#account/derive/refuses/salt-15`), and a recovery code read in the canonical form, a `U` refused (`mailie/key-scheme-v1/account-go.json#account/normalise/typed-back`, `mailie/key-scheme-v1/account-go.json#account/normalise/refuses/a-u`).
- **The account wrap** binds the seal id, never the address, so an address change needs no re-wrap and Unicode case mapping stays out of the AAD (unlike section 6.6); the kind, so a wrap moved to the other column fails at its AAD (`mailie/key-scheme-v1/account-go.json#mailie/account-unwrap/refuses/the-recovery-wrap-in-the-password-column`); and the account public key. Sealing refuses a kind, a seal id or an account key outside its spelling (`binding`), computes the public key from the account key, draws a fresh nonce and self-tests (`mailie/key-scheme-v1/account-go.json#mailie/account-wrap/password`, `mailie/key-scheme-v1/account-go.json#mailie/account-wrap/account-key-with-a-zero-first-byte`). Opening, in order: the binding (`binding`); a wrap shorter than 61 bytes is `wrap`/`truncated`, a longer one or another first byte `wrap`/`wrong_key`; in Go, a wrap key that is not 32 bytes is `wrap`/`bad_key` (`mailie/key-scheme-v1/account-go.json#mailie/account-unwrap/refuses/wrap-key-of-31-bytes`, Go only: TypeScript's wrap key is a `CryptoKey`); the tag; and the opened key's public half must be the bound public key, compared in constant time, the key cleared otherwise. Every other failure after the binding, a short wrap and a wrap key of the wrong length aside, is `wrap`/`wrong_key` (`mailie/key-scheme-v1/account-go.json#mailie/account-unwrap/refuses/another-seal-id`, `mailie/key-scheme-v1/account-go.json#mailie/account-unwrap/refuses/opens-to-another-accounts-key`). A server checks the shape only, 61 bytes starting with `0x02` (`shape`, `mailie/key-scheme-v1/account-go.json#mailie/account-wrap-shape/refuses/header-0x03`).
- **The grant** is section 5's with the namespace as both the tenant and the device of `GrantRow`: binding the seal id keeps a person's grant from being presented as another's, the namespace from opening another mailbox, the epoch (in the header, the row and the info) from opening at another, and the kind from being taken for a content key (`mailie/key-scheme-v1/grant-go.json#mailie/grant-open/refuses/another-user`, `mailie/key-scheme-v1/grant-go.json#mailie/grant-open/refuses/another-namespace`, `mailie/key-scheme-v1/grant-go.json#mailie/grant-open/refuses/the-epoch-2-grant-at-epoch-1`, `mailie/key-scheme-v1/grant-go.json#mailie/grant-open/refuses/another-kind-content-key`). Sealing refuses a binding or a mailbox key outside its spelling (`binding`) and a recipient key of low order (`invalid_key`, `mailie/key-scheme-v1/grant-go.json#mailie/grant-seal/refuses/low-order-recipient/*`). Opening takes the account private key, the binding and the mailbox's public key at that epoch, as the server holds it: the binding (`binding`); the header checks of section 4.1 (`mailie/key-scheme-v1/grant-go.json#mailie/grant-open/refuses/a-wappie-device-grant-of-the-same-binding`: Wappie's magic); HPKE; and the plaintext is 32 bytes whose public half is the mailbox's public key, compared in constant time, the key cleared otherwise. Every failure after the header checks is `authentication`. The last check is the profile's addition to section 5: HPKE's base mode authenticates no sender, so a grant rightly bound around a key its sealer chose opens under HPKE, and is refused here (`mailie/key-scheme-v1/grant-go.json#mailie/grant-open/refuses/a-key-the-sealer-chose`). A server checks the shape only: 88 bytes, Mailie's header in direct mode at the mailbox's current epoch, a zero reserved byte (`shape`, `mailie/key-scheme-v1/grant-go.json#mailie/grant-shape/refuses/not-the-current-epoch`). The grants of the vectors were sealed under a seed; TypeScript opens them and seals its own.
- **The platform wrap's user id is the seal id, never the sub.** This departs from the wording of section 6.8, which makes the user id the `sub` itself for an account created through id.: Mailie binds the person's seal id for every person, those created through id. included, one rule for its self-hosted edition, which has no `sub`, and its hosted one, and a value its server draws once rather than one id. issues. The construction takes any lowercase UUID as the user id, so no byte of section 6.8 or of its vectors moves (`mailie/golden/platform-wrap-go.json#mailie/platform-wrap/seal/user-id-is-not-the-sub`). `PlatformWrapBinding` (Go) and `platformWrapBinding` (TypeScript) build the binding from the seal id, the `sub`, the pinned epoch and the account public key, and refuse a seal id equal to the `sub` whatever the `sub`'s version (`binding`, `mailie/key-scheme-v1/platform-wrap-go.json#mailie/platform-wrap-binding/refuses/seal-id-the-sub`, with a `sub` of version 4, which the platform accepts as a `sub`: `mailie/key-scheme-v1/platform-wrap-go.json#mailie/platform-wrap-binding/a-uuidv4-sub`); a wrap bound to the seal id does not open with the `sub` as its user id (`mailie/key-scheme-v1/platform-wrap-go.json#mailie/platform-wrap/open/refuses/the-sub-as-the-user-id`). Whatever opens Mailie's export outside Mailie's console, such as the command-line tool of section 6.8 that starts from the key bundle, takes the user id from the export, which carries each person's seal id beside the person's wrap, and never assumes the `sub`. Every other rule of section 6.8 holds unchanged, and products stay apart (`mailie/key-scheme-v1/platform-wrap-go.json#mailie/platform-wrap/open/refuses/the-same-persons-wappie-wrap`).
- **Three envelopes, three first bytes.** A person's account wraps start with `0x02`, platform wraps with `0x03` and grants with `M`, so a blob in the wrong column fails at its first byte (`mailie/key-scheme-v1/account-go.json#mailie/account-unwrap/refuses/header-0x03-the-platform-wraps`, `mailie/key-scheme-v1/platform-wrap-go.json#mailie/platform-wrap/open/refuses/header-0x02-an-account-wrap`). Two of these bytes are Wappie's too, on purpose: `0x02`, the header Mailie chose for its account wraps, as Wappie's password and recovery wraps have it (section 6.8 asks only that a product's other envelopes of its account key not start with `0x03`), and `0x03`, the platform wrap's for every product. Their AADs and keys differ, so a Wappie blob of either in Mailie's column fails at its tag, not its first byte (`mailie/key-scheme-v1/platform-wrap-go.json#mailie/platform-wrap/open/refuses/the-same-persons-wappie-wrap`): each product keeps them in columns of its own. No other header of the kit is one of the three bytes: Wappie's passkey envelope and the platform's root wraps start with `0x01`, Wappie's seal envelopes with `W` and THCSEAL's with `T` (Wappie's legacy v1 wraps have no header).
- **The browser vault** binds the seal id and the account public key, whose standard base64 may hold `+` and end in `=` (`mailie/key-scheme-v1/browser-vault-go.json#mailie/browser-vault/aad/alice`); the vectors pin its AAD, since its AES key cannot be exported. A record that does not open for the person named, another seal id, another public key or not a record at all, is one refusal, `vault` (TypeScript only), which the product wipes.
- **Errors.** Mailie's own codes are `binding` (an input outside its spelling, refused before anything is derived, sealed or opened), `shape` (a server's check of a wrap or grant it stores), `public_key` (a server's refusal of a public key to store, section 11.4's check, Go only; `mailie/key-scheme-v1/grant-go.json#mailie/public-key-check/refuses/*`) and `vault`: Go `mailie.ErrBinding`, `ErrShape` and `ErrPublicKey`, TypeScript `MailieError` with the code. The kit's other codes pass through: the account scheme's with their reasons, the platform's `recovery_code` and `password_*`, `platform_wrap`, and the envelope's.
- **What stays in Mailie.** How its server normalises an address (Go's `strings.TrimSpace`, then `strings.ToLower`) and derives from it the salt it hands out for every address (the first 16 bytes of HMAC-SHA256 under a server secret of `mailie/v1/kdf-salt|` and the normalised address), which the vectors carry (`mailie/key-scheme-v1/account-go.json#mailie/normalise-address/*`, `mailie/key-scheme-v1/account-go.json#mailie/decoy-salt/*`) and the kit's runners check against those formulas as test code; drawing seal ids and namespaces; the step-up, the ceremonies, and what its server stores and checks. Mailie's specification is the normative text for them.
