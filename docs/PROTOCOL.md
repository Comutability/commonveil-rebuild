# Commonveil protocol, version 1

Status: implemented and tested; **not independently audited**. This document describes exactly what the code does.
If the two disagree, the code is wrong or this document is out of date: please report it.

Code: `src/lib/crypto/*` (primitives), `src/lib/secure/protocol.js` (client flows), `base44/shared/*` (server checks).

## 1. Goals and non-goals

Goals:
- Message content and group names are readable only on the devices of a conversation's current members.
- The server, or anyone holding a member's password, cannot add a device that receives keys, cannot sign as a member,
  and cannot change a member's keys without contacts being told.
- An account can be recovered from a 24-word phrase without the server learning anything usable.
- The protocol is small enough to review in an afternoon.

Not provided in v1 (see `THREAT_MODEL.md`): metadata privacy, forward secrecy, post-quantum confidentiality, deniability,
cryptographic group membership, and protection against malicious code served to the browser.

## 2. Primitives

| Use | Primitive |
|---|---|
| Key agreement | ECDH on P-256 (WebCrypto `deriveBits`, 256 bits = shared x-coordinate) |
| Signatures | ECDSA P-256 with SHA-256, IEEE P1363 encoding (r‖s, 64 bytes) |
| Key derivation | HKDF-SHA-256 |
| Encryption | AES-256-GCM, 96-bit random IV, 128-bit tag |
| Hash | SHA-256 |
| Recovery phrase | BIP-39 English wordlist, 24 words, 256 bits of entropy (`@scure/bip39`) |
| Recovery key maths | `@noble/curves` P-256 (scalar to point, and ECDH with the derived scalar) |

Encodings: bytes are standard padded base64. Public keys are raw uncompressed P-256 points (65 bytes, leading `0x04`).
Private keys exist in exportable form only inside the account keyring (PKCS#8). Identifiers chosen by clients
(`device_id`, message ids, nonces) are 12 or 16 random bytes, base64url.

## 3. Keys

**Account keyring.** Each account has numbered key versions `v = 1, 2, …`. Version `v` is an ECDH key pair `E_v` and an
ECDSA key pair `S_v`. Every active device holds the whole keyring (all versions), serialised as JSON with
`format: "commonveil.keyring.v1"`. Versions are contiguous; after a reset the keyring starts at the reset version.

**Device keys.** Each browser generates, non-extractable: a signing pair `D` (ECDSA) and a box pair `B` (ECDH), and a random
`device_id`. They are stored in that browser's IndexedDB as `CryptoKey` objects and never leave it.

**Recovery key.** From the phrase's 32 bytes of BIP-39 entropy: for `c = 0..7`,
`sk = HKDF(ikm = entropy, salt = "commonveil/recovery/v1", info = "p256-secret|" + c, 32 bytes)`; the first `sk` with
`1 ≤ sk < n` is the recovery secret, `R = sk·G` the recovery public key. The phrase is never stored or transmitted.

## 4. Signed statements

All signatures are over canonical text:

```
commonveil/<context>\n<number of fields>\n<field 1>\n<field 2>\n…
```

Fields are strings and may not contain CR or LF. Numbers are written in decimal. A `*_hash` field is
`base64(SHA-256(UTF-8 of the exact JSON string sent))`. Client and server implementations are separate files
(`src/lib/crypto/canonical.js`, `base44/shared/canonical.ts`) and a test checks they produce identical bytes.

| Context | Fields, in order | Signed by |
|---|---|---|
| `account-key/v1` | user_id, version, ecdh_pub, sign_pub, recovery_pub, signed_by_version, issued_at | `S_v` itself (first key, reset) or `S_{v−1}` (rotation) |
| `device-cert/v1` | user_id, device_id, sign_pub, box_pub, key_version, issued_at | `S_key_version` |
| `device-proof/v1` | user_id, device_id, action, payload_hash, issued_at, nonce | the device's `D` |
| `item/v1` | kind, conversation_id, item_id, sender_id, device_id, envelope_hash, sent_at | the sending device's `D` |

## 5. The account key chain

Each published key version is an `account-key/v1` statement. Version 1 and resets are self-signed
(`signed_by_version = version`); every other version must be signed by the version before it.

A client verifies a chain by checking versions run `1..n` with no gaps, each signature against its signer, and each
non-self-signed statement points at exactly the previous version. The **root** of the latest key is the most recent
self-signed statement it descends from.

Clients pin other members' keys on first use (`{version, sign_pub}`). On every later fetch:
- the pinned statement is in the latest key's unbroken segment (`pin.version ≥ root` and same `sign_pub`): **rotated**,
  so the pin moves forward silently, because every step since the pin was signed by the previous key;
- otherwise: **changed** (a reset, or someone substituting keys). The app shows a warning and pauses sending to that
  person until the user acknowledges it. A 60-digit safety number (below) lets two people check in person.

Safety number: for each person, `h = SHA-256("commonveil/safety/v1|" + user_id + "|" + sign_pub)`, then 4096 times
`h = SHA-256(h ‖ sign_pub)`; 30 digits are taken from the first 30 bytes as six 5-byte groups modulo 100000. The two
halves are concatenated in user-id order, so both people see the same 60 digits.

## 6. Sealed values

`seal(P, plaintext, ctx)`: fresh ephemeral P-256 pair `e`; `z = ECDH(e, P)`;
`k = HKDF(z, salt = epk ‖ P, info = ctx)`; output `{epk, iv, ct = AES-GCM(k, iv, plaintext, aad = ctx)}`.
The context string is both the HKDF info and the AEAD associated data, so a sealed value opens only in the exact
context it was made for.

| Context string | Used for |
|---|---|
| `commonveil/keyring-to-device/v1\|user_id\|device_id\|version` | keyring to a device's `B` (linking, rotation, repair) |
| `commonveil/keyring-recovery/v1\|user_id\|version` | keyring to the recovery key `R` |
| `commonveil/wrap/v1\|kind\|conversation_id\|item_id\|recipient_user_id\|key_version` | a message key to a member's `E_v` |

After opening a keyring, a client checks that every private key matches its listed public key and that every version
matches the account's verified published statements, before using it.

## 7. Messages and group names

For each message (`kind = "message"`) or group-name update (`kind = "title"`), the sender picks a random `item_id` and a
fresh 256-bit content key `K`:

- `ct = AES-GCM(K, iv, JSON payload, aad = "commonveil/content/v1|kind|conversation_id|item_id|sender_id|device_id")`
- for every current member `u` (including the sender): `wrap_u = seal(E_{u, current}.pub, K, wrap context)`
- envelope: `{"v":1, "iv", "ct", "wraps":[{"u", "kv", "epk", "iv", "wk"}]}`
- the sending device signs `item/v1` over the exact envelope JSON.

Payloads are `{"type":"text","text":…}` (at most 4000 characters) and `{"type":"title","title":…}` (at most 80).

A reader decrypts with its own wrap, then marks the item **verified** only if the sending device appears in the sender's
device list, that device's certificate verifies against the sender's verified key chain, and the item signature
verifies against the device key. Otherwise it is shown as **unverified**. Anything that fails to decrypt is shown as
unreadable and never partially displayed.

## 8. Flows

**First device.** Generate `S_1, E_1`, device keys and a phrase locally. The phrase is shown and three words are checked
back before anything is sent. Then publish, signed by the new device: the self-signed statement for version 1, a
certificate for the device under `S_1`, and the keyring sealed to `R`.

**Adding a device by approval.** The new browser registers its device keys (pending, 15 minutes). Both screens show a
20-digit link code, `SHA-256("commonveil/link-code/v1|user_id|device_id|sign_pub|box_pub")` as five groups of four digits
(about 66 bits). After the person confirms the codes match, an active device signs a certificate for the new device and
seals the keyring to its `B`. The new device opens it, checks it against the published chain, and acknowledges, which
deletes the server's copy.

**Adding a device with the phrase.** The new browser fetches the recovery backup (requires sign-in), derives `R` from the
phrase, opens the keyring, checks it, and certifies itself with the latest `S`. The server accepts the device because the
certificate verifies against the latest published signing key, which only keyring holders can produce.

**Removing a device and rotating.** An active device revokes the target (immediately refused by the server for anything
it signs from then on), then publishes version `v+1` signed by `S_v`, new certificates for every remaining active
device, the new keyring sealed to each other active device's `B`, and a new recovery backup. The client refuses to seal
keys to any device whose current certificate doesn't verify against its own chain, so a device inserted by the server
never receives keys.

**Changing the phrase.** A rotation with a new `R`. The server deletes every backup sealed to the old recovery key.

**Repair.** A device that missed a rotation (its `synced_key_version` is behind) is sent the current keyring by any
up-to-date device, again only after its certificate verifies.

**Reset (lost every device and the phrase).** A new self-signed statement at the next version, a new phrase and a new
device. The server revokes every other device and deletes every backup. Contacts see a "changed" warning; earlier
messages stay unreadable to the new identity.

**Group membership.** The server holds each conversation's member list. Adding members, leaving a group and deleting a
message require a device proof (`device-proof/v1` over the exact payload). Each client also remembers who was in each
conversation when it last confirmed it, and refuses to encrypt to anyone new until the user has seen who it is; the
member who made the addition is not asked. A direct message must have exactly two members, or sending is blocked.

## 9. What the server enforces

The server never holds a private key. It checks, and refuses otherwise:

- a real signed-in user on every action (`auth.me()`); no action mints, accepts or forwards session tokens;
- version 1 is self-signed; later versions are signed by the previous one unless they are an explicit reset;
- certificates name exactly the stored device keys and are signed by the current account key;
- device proofs are by an active device of the caller, at most 5 minutes old, over the exact payload, for the named action;
- a pending device can't approve itself, approvals expire after 15 minutes, at most 3 pending and 10 live devices;
- messages: caller is a member, sending device is active and the caller's, the signature verifies, the wraps cover exactly
  the current members at their latest key versions, `sent_at` is within 10 minutes of server time, message ids are unique
  per conversation (a resend is idempotent), 30 messages per minute;
- blocks stop direct messages in both directions and hide each person from the other's username lookup;
- usernames: exact-match lookup only, no directory; profiles and public keys only for people you share a conversation with;
- groups of at most 32; reports readable only by admins.

Replay: proofs carry a timestamp and nonce, and every proof-protected action is either one-shot (initialise, register,
approve) or idempotent (revoke, acknowledge, delete), or gated on state that a replay can't satisfy (rotation requires
exactly the next version). There is no nonce store.

## 10. Tests

- `tests/crypto.test.mjs`: primitives, chains, envelopes, recovery, linking, tampering (17 tests).
- `tests/functions.test.mjs`: the real backend handlers driven by the real client code, with only the database
  replaced, including attack cases (23 tests).
- `tests/e2e/`: live browser runs against the real platform (see its README).
