# The Happie Co kit: specification

- Spec version: 2 (kit v0.2.0)
- Status: normative for the Wappie profile, which is frozen, and for part 1 of the platform profile (section 11). Section 11's part 2 is reserved.
- Vectors: every byte below is pinned by a case in `vectors/`. A case is cited as `file#case-id`, or for the platform's files as `platform/id-v1/<kind>.json#<case name>`.

## 1. Status and scope

The kit standardises the client-side cryptography The Happie Co's products share:

- HPKE with one fixed suite (section 4.4, and `hpke` on its own for product-key delivery);
- the sealed envelope, in direct and batch mode, with content keys, rows and grants (sections 4 and 5);
- the zero-knowledge account scheme: Argon2id, the auth/wrap split, wraps and recovery codes (section 6);
- the passkey PRF wrap (section 7);
- a key at rest in the browser (section 8);
- the request HMAC between two services (section 9);
- RFC 8785 for JSON additional data (section 10);
- the platform's account core: its password profile, KDF policy, root wraps, recovery code, per-product keys, server verifiers, email normalisation and key bundle (section 11).

What a product chooses is a **profile** (section 3): labels, prefixes, magic bytes, kind names, AAD builders and bounds. Everything else is fixed, and changing it is a new format version, never a profile.

**Conformance.** An implementation conforms to a profile when it reproduces every case of that profile's vector files that is marked for its language (section 12). The Go module and the TypeScript package in this repository conform to the Wappie profile and to part 1 of the platform profile.

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

Appendix A lists the Wappie profile's every value in one place. The platform profile (section 11) sets these parameters too, listed in Appendix C; its root wrap is the wrap envelope of section 6.5 with a two-byte header.

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

A profile enters the kit when it has golden vectors in a format section 12 describes. Its seal kinds must pass `ValidateKinds` (Go): names unique and matching `[a-z0-9_]+`, the default `kind(0x..)` for an unnamed byte, 0x00 unnamed, the core kinds (section 4.8) named. In Go, a profile's kind type carries its domain, so a value of one profile's kind type cannot be sealed under another's label.

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

## 11. The platform profile

- Status: **part 1 is normative**: the account core of the platform's protocol `id-v1` (`thehappie-id/v1`), from the platform's `docs/protocol/id-v1.md` sections 1, 2 and 6 at platform commit `5e66d84`, with one change: the run rule of the password profile (section 11.2, step 2) counts more, so that Go and ICU never prepare one password two ways. **Part 2 is reserved** (sections 11.12 to 11.15).
- Implementations: Go `profiles/platform`, TypeScript `@thehappieco/kit/profiles/platform`. Unlike the other modules, their functions take no profile argument: they are the platform's protocol. Where a generic module does the work, they hand it the platform's values (Appendix C): sections 6.3, 6.5 and 6.7 with the platform's labels, header and canonical form, section 10 for the AAD, and section 4.4's X25519 for product keys.
- Vectors: `vectors/platform/id-v1/*.json`, written by the platform's Go code and carried byte for byte (section 12.2). An implementation conforms when it reproduces every case and refuses every must-fail case with the error name the case records.

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
2. Its compatibility decomposition (NFKD) holds no run of more than 30 consecutive counted code points; otherwise `password_invalid` (`platform/id-v1/password-profile.json#thirty-one combining accents on one letter are refused`, `platform/id-v1/password-profile.json#thirty-one spacing marks are refused too`). A code point is counted if it is of general category M, a Hangul vowel or final jamo (U+1160 to U+11FF, U+D7B0 to U+D7FF), or U+16D67 KIRAT RAI VOWEL SIGN E. Why: Go's `golang.org/x/text/unicode/norm` applies the Stream-Safe Text Format, inserting U+034F after 30 non-starters, and ICU does not, so beyond that limit the two would prepare different bytes. What it counts as a non-starter, in each character's compatibility decomposition, is a code point with a non-zero combining class (always a mark) or one that composes with what precedes it (a mark, a Hangul vowel or final jamo, or, from Unicode 16.0, U+16D67, a letter). So Hangul syllables, the compatibility and halfwidth jamo, and characters such as U+00B4 and U+FF9E whose compatibility decomposition holds a mark all count, as they do here; U+034F is itself a mark. Canonical reordering moves only code points with a non-zero combining class, all counted, so the runs of the whole text's NFKD are those of its code points' decompositions put end to end, and an implementation counts them code point by code point, in linear time.
3. NFC (`platform/id-v1/password-profile.json#e and a combining acute compose under NFC`), not NFKC (`platform/id-v1/password-profile.json#NFC is not NFKC: a ligature stays`).
4. U+00A0, U+1680, U+2000 to U+200A, U+202F, U+205F and U+3000 become U+0020 (`platform/id-v1/password-profile.json#every space separator becomes U+0020`). They have no composition partner, so the result stays NFC.
5. A code point from U+0000 to U+001F or from U+007F to U+009F is refused: `password_invalid`, before the length is counted (`platform/id-v1/password-profile.json#a control character is refused before the length is counted`).
6. Nothing is trimmed (`platform/id-v1/password-profile.json#spaces are not trimmed`).
7. Code points are counted. A new password (sign-up, change, recovery) has at least 12, otherwise `password_too_short`; any password has at most 256, otherwise `password_too_long` (`platform/id-v1/password-profile.json#eleven emoji are eleven code points, not twenty-two UTF-16 units`).
8. P′ is the UTF-8 of the result.

A password being presented (login, unlock, opening a key bundle) goes through every step but the minimum length.

Step 2 counts more than the platform's `id-v1.md` at `5e66d84`, which counted only category M in the NFD form: with that rule Go and ICU accepted some passwords and prepared different bytes for them (thirty-one U+3160, a Hangul syllable followed by twenty-nine acute accents), and refused others on one side only (U+00B4 followed by thirty acute accents). Every case of `platform/id-v1/password-profile.json` keeps its outcome.

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

**The server's check of a submitted `pk_p`:** 32 bytes; the canonical encoding (bit 255 clear and the value below 2^255 − 19), because X25519 accepts other spellings as aliases and a pinned key must have one; and an X25519 exchange with a fresh private key does not give 32 zero bytes, which refuses the low-order points (section 4.4). Any failure is `product_key`.

### 11.5 Root wraps

```
wrap = 0x01 || kind || nonce (12) || AES-256-GCM(key, nonce, root, AAD)          62 bytes
```

This is the wrap envelope of section 6.5 with the two-byte header `0x01 || kind` and no legacy form.

| kind | byte | key | AAD |
|---|---|---|---|
| password | `0x01` | `K_wrap` (11.3) | `["thehappie-id/root-wrap",1,"password",sub,epoch]` |
| recovery | `0x02` | `K_rwrap` (11.6) | `["thehappie-id/root-wrap",1,"recovery",sub,epoch]` |
| passkey | `0x03` | `K_pk` (reserved, 11.15) | `["thehappie-id/root-wrap",1,"passkey",sub,epoch,rp_id,credential_id]` |

The AAD is a restricted JSON AAD (11.1). It repeats the version and the kind, so both header bytes are authenticated. It binds the immutable `sub` and the epoch, never the email: an email change needs no re-wrap, and a wrap moved to another account, epoch or kind does not open (`platform/id-v1/root-wrap.json#another sub`, `platform/id-v1/root-wrap.json#the kind byte relabelled and opened as that kind`). `rp_id` and the base64url `credential_id` are present for the passkey kind only, and non-empty; the credential id is strict base64url (`platform/id-v1/root-wrap.json#a padded credential id`, `platform/id-v1/root-wrap.json#a password wrap opened with passkey fields`).

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
| `wrap` | a root wrap that is malformed, does not open, or failed its self-test |
| `recovery_code` | not a recovery code |
| `email` | an address 11.8 does not accept |
| `product_key` | a product id, epoch or root that names no product key, a public key the server refuses, or a listed key the root does not derive |
| `bundle` | not a key bundle this version reads |
| `encoding` | a value not in its one accepted spelling where no other name fits (a verifier's inputs) |

Where an input has several defects, the order of checks in sections 11.2 to 11.9 decides the name. Errors of the kit's generic modules never escape the platform profile: they are reported as one of these names. The one exception is an engine that lacks a primitive, which is not a verdict on any input: in TypeScript, on an engine without X25519, deriving a product key (and so opening a key bundle) throws the `hpke` module's `HPKEError` `invalid_key` as it is, with the engine's `NotSupportedError` as its `cause`, rather than `product_key`, which would say that a bundle's listed keys are not its root's. A product's own rules (for example a page refusing a password equal to the address) use the product's own codes.

### 11.11 Vectors

The format and the files are described in section 12.2. Cited as `platform/id-v1/<kind>.json#<case name>`. The kit's own round trips of this profile are `kit/platform-go.json` and `kit/platform-ts.json`, in the format of section 12.1.

### 11.12 to 11.15 Reserved (part 2)

- **11.12 Sealed key delivery:** an HPKE seal (section 4.4's suite, `hpke`) of `sk_p` to the product's ephemeral key, with the platform's info and a restricted JSON AAD (11.1).
- **11.13 The OIDC relying party:** what a product checks in an ID token and how a key delivery is bound to the login.
- **11.14 The product contract:** its types, and its HMAC as section 9 with the platform's label.
- **11.15 Passkey root-wrap key:** `K_pk` from a passkey's PRF output (section 7 with the platform's passkey profile), for the passkey kind of 11.5.

## 12. Vectors

The layout, the op catalogue and the provenance of every file are in `vectors/README.md` and `vectors/PROVENANCE.md`. Run the conformance suites with `make test` (both languages), `make test-go-1.26.7` (adds the byte-for-byte replays of Wappie's Go vectors), and `make cross` (fresh round trips in both directions). Files are append-only once a release is tagged.

### 12.1 The kit's format

Everything under `vectors/wappie/` and `vectors/kit/` is in the kit's format, `thehappieco-kit-vectors/1`: cases with an `id`, an `op`, `in`, and exactly one of `out` and `error`, bytes in standard base64 (`vectors/README.md`, "Format").

### 12.2 The platform's format

`vectors/platform/id-v1/*.json` are the platform's own files, carried byte for byte (provenance in `vectors/PROVENANCE.md`). Each is `{"format": "thehappie-id/vectors", "version": 1, "kind": "<kind>", "cases": [...]}`; a case has a unique `name` and either its outputs or `"error": "<name>"` (section 11.10). Binary values are base64url without padding; texts are JSON strings; the files are ASCII. Kinds and members: `password-profile` (`password`, or `password_utf16` with `password_utf8_b64url` for a string that is not Unicode, each language taking its own form; `new`; `prepared_b64url`), `kdf` (`prepared_b64url`, `salt`, `kdf`; `k_auth`, `k_wrap`, `auth_key`), `root-wrap` (`kind`, `key`, `nonce`, `root`, `sub`, `epoch`, `rp_id`, `credential_id`; `aad`, `wrap`), `recovery-code` (`bytes` or `input`; `display`, `canonical`, `k_rwrap`, `recovery_auth`), `product-key` (`root`, `product`, `epoch`; `sk`, `pub`, `product_key_id`), `verifier` (`sub`, `k_auth` or `r_proof`; `auth_verifier` or `recovery_verifier`), `email` (`input`; `email_norm`), `key-bundle` (`password` or `recovery_code`, `bundle` as a JSON value or `bundle_text` as the exact file text; `root`). Argon2id cases use the floor parameters, and one uses p = 4. A runner decodes strictly: a member it does not read fails it.

## 13. Security considerations

- **The key id is outside the batch AAD** (section 4.5): bound through the content key's row instead.
- **Zeroisation is best effort.** Neither language can clear a string (the password as typed), and Go's runtime may have copied a buffer before it is cleared. What each clears:
  - Go: in `account.Derive`, the prepared password bytes and the Argon2id master key; in `account.DerivePrepared`, the master key (the prepared bytes it is given are the caller's to clear).
  - TypeScript: in `derive`, the prepared password bytes, the master key and the raw wrap key, success or failure; in `derivePrepared`, the master key and the raw wrap key (the prepared bytes it is given are the caller's to zero); the KDF worker clears its own copy of the password bytes; the recovery code's HKDF input and the raw recovery key after import; a content key's raw bytes after import (`ContentKey.unwrap`); the raw key after import in `openBrowserAccountKey`; in `hpke`, the PKCS#8 buffer built to import a private key and the PKCS#8 export of a generated one. The raw private key a caller passes in or receives (`generateKeyPair`) is the caller's to clear.
  - Keys held as values (Go's content keys and private keys, TypeScript's non-extractable `CryptoKey`s) live as long as the values that hold them.
- **Random nonces.** At most 2^20 values per content key (section 4.9).
- **Wappie's wrap binds the email** (section 6.6): an email change needs a re-wrap.
- **No KDF bounds in the Wappie profile** (section 6.2): a downgrade by whoever writes the database. New profiles set bounds.
- **Passkeys are bound to the RP ID** (section 7).
- **All-zero shared secrets** (section 4.4). A public or encapsulated key of low order yields an all-zero X25519 output. Go's `crypto/ecdh` refuses it. The TypeScript implementation checks the output itself, with no early exit, whatever WebCrypto does, in sealing and in opening; its tests run every forgery also on a stand-in engine that lets the zeros through. The vectors carry real forgeries, which an implementation missing the check opens.
- **The reserved header byte** is bound by the AAD, not checked (section 4.1).
- **Decoy salts** for unknown accounts are a server concern and outside the kit.
- **The platform's KDF bounds are compiled in** (section 11.3). A server can still give two addresses the same salt; the client cannot tell. The bound fixes only the length. The decoy-salt derivation is the server's.
- **Unicode versions and Stream-Safe text** (section 11.2): a password whose compatibility decomposition holds more than 30 marks or Hangul vowel and final jamo in a row is refused rather than prepared two ways, because Go's normaliser would insert U+034F there and ICU's would not; the Go side also refuses a password into which its normaliser would still insert one. Characters assigned after Unicode 15.0 with canonical mappings may prepare differently on sides with older tables. The rule is counted code point by code point, so a long pasted run is refused in linear time on the page's main thread.
- **The platform's verifiers are a fast hash on purpose** (section 11.7).
- **Product public keys are pinned in one spelling** (section 11.4). Sealing to a low-order key is refused by `hpke` anyway (section 4.4).
- **Strict reading of files that gate key material** (section 11.9): repeated members, number spellings and unknown members are refused rather than resolved.
- **The key bundle's honest limit** (section 11.9): an old bundle opens with an old password or code.
- **Zeroisation in the platform profile** follows the rest of the kit: Go clears the Argon2id master key, the prepared password it made, and the roots and keys it derives on its own behalf; TypeScript zeroes the prepared password it made, the master key and raw wrap key (in `account`), the PKCS#8 copy of a product key (in `hpke`), and the raw root it seals. Derived wrap keys are non-extractable `CryptoKey`s in TypeScript.
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
- Spec 2 (kit v0.2.0): section 11 part 1, the platform profile, with the platform's id-v1 vectors at `5e66d84`; sections 1, 3, 6.7, 12 and 13 extended; Appendix C. Nothing in the Wappie profile changed.

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
