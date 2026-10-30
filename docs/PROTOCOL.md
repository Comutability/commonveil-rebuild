# Commonveil protocol, version 2

Status: implemented and tested; **not independently audited**. This document describes exactly what the code does.
If the two disagree, the code is wrong or this document is out of date: please report it.

Code: `src/lib/crypto/*` (primitives), `src/lib/secure/protocol.js` (client flows), `src/lib/secure/SecureContext.jsx` and
`ChatContext.jsx` (client state and pinning), `base44/shared/*` (server checks).

Version 2 follows an independent review of version 1 in October 2026. What changed, and why, is summarised in
`REBUILD_REVIEW.md`.

## 1. Goals and non-goals

Goals:
- Message content and group names are readable only on the devices of the people they were sent to.
- The server, or anyone holding a member's password, cannot add a device that receives keys, cannot sign as a member,
  and cannot change a member's keys, now or anywhere in their history, without contacts being told.
- Someone with only a member's password cannot take over the account's encryption before its owner has had time to stop it.
- An account can be recovered from a 24-word phrase without the server learning anything usable.
- The protocol is small enough to review in an afternoon.

Not provided (see `THREAT_MODEL.md`): metadata privacy, forward secrecy, post-quantum confidentiality, deniability,
cryptographic group membership, and protection against malicious code served to the browser.

## 2. Primitives

| Use | Primitive |
|---|---|
| Key agreement | ECDH on P-256 (WebCrypto `deriveBits`, 256 bits = shared x-coordinate) |
| Signatures | ECDSA P-256 with SHA-256, IEEE P1363 encoding (r‖s, 64 bytes) |
| Key derivation | HKDF-SHA-256 |
| Encryption | AES-256-GCM, 96-bit random IV, 128-bit tag, with a key commitment (section 7) |
| Hash, MAC | SHA-256, HMAC-SHA-256 |
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

**Recovery key and anchor key.** From the phrase's 32 bytes of BIP-39 entropy, with `salt = "commonveil/recovery/v1"`:
- recovery secret: for `c = 0..7`, `sk = HKDF(entropy, salt, info = "p256-secret|" + c, 32 bytes)`; the first `sk` with
  `1 ≤ sk < n` is used, and `R = sk·G` is the recovery public key;
- anchor key: `A = HKDF(entropy, salt, info = "anchor-hmac", 32 bytes)`.

The phrase is never stored or transmitted, and `sk` and `A` are wiped after use.

## 4. Signed statements

All signatures are over canonical text:

```
commonveil/<context>\n<number of fields>\n<field 1>\n<field 2>\n…
```

Fields are strings and may not contain CR or LF. Numbers are written in decimal. A `*_hash` field is
`base64(SHA-256(UTF-8 of the exact JSON string sent))`. Client and server implementations are separate files
(`src/lib/crypto/canonical.js`, `base44/shared/canonical.ts`) and a test checks they produce identical bytes.

| Context | Fields, in order | Made with |
|---|---|---|
| `account-key/v1` | user_id, version, ecdh_pub, sign_pub, recovery_pub, signed_by_version, issued_at | `S_v` itself (first key, reset) or `S_{v−1}` (rotation) |
| `recovery-anchor/v1` | the same fields as `account-key/v1` | HMAC with the anchor key `A` (section 5) |
| `device-cert/v1` | user_id, device_id, sign_pub, box_pub, key_version, issued_at | `S_key_version` |
| `device-proof/v1` | user_id, device_id, action, payload_hash, issued_at, nonce | the device's `D` |
| `item/v1` | kind, conversation_id, item_id, sender_id, device_id, envelope_hash, sent_at | the sending device's `D` |

## 5. The account key chain

Each published key version is an `account-key/v1` statement. Version 1 and resets are self-signed
(`signed_by_version = version`); every other version must be signed by the version before it.

A client verifies a chain by checking versions run `1..n` with no gaps, each signature against its signer, and each
non-self-signed statement points at exactly the previous version. The **root** of the latest key is the most recent
self-signed statement it descends from.

**History digests.** While verifying, the client hashes the whole history: `d_0 = ""` and
`d_v = base64(SHA-256("commonveil/chain-digest/v1\n" + d_{v−1} + "\n" + canonical account-key text of v + "\n" + signature_v))`.
The **head digest** is `d_n`. Pins, safety numbers and link codes commit to it, so they cover every key the account has
ever published, not just the latest one.

**Recovery anchors.** A statement made while the phrase is to hand (version 1, a new phrase, a reset) carries
`recovery_mac = base64(HMAC-SHA-256(A, canonical recovery-anchor text))`. Only someone holding the phrase can make one.
The server stores it and returns it only to the account itself; it requires one to be present where the phrase is used,
but can't check it. Clients check it when recovering (section 8).

**Pinning other members.** On first use a client pins `{version, digest = d_version, sign_pub, statements, verified}`.
On every later fetch it compares:
- **same**: the pinned version is the latest and its digest matches;
- **rotated**: the digest at the pinned version still matches and the pinned version is at or after the root, so every
  key since was signed by the one before it: the pin moves forward silently (keeping a "verified" mark);
- **changed**: anything else (a reset, or someone substituting any key at or before the pinned one). The app warns, pauses
  sending to that person until the user acknowledges it, and meanwhile checks that person's signatures against the pinned
  history rather than the new one.

Pins from version 1 of the protocol (`{version, sign_pub}`, no digest) are accepted once if the key at that version still
matches, and re-pinned with a digest.

**Safety numbers.** For each person, `h = SHA-256("commonveil/safety/v2|" + user_id + "|" + head digest)`, then 4096 times
`h = SHA-256(h ‖ head digest)`; 30 digits are taken from the first 30 bytes as six 5-byte groups modulo 100000. The two
halves are concatenated in user-id order, so both people see the same 60 digits.

**Anchoring your own account.** A device never takes the server's word for its own account's keys. Before using them it
checks the published chain against the keyring it holds: every keyring version must be published with the same public
keys (otherwise it refuses: the keys were rolled back or substituted), later versions must follow by rotation, and a
self-signed statement after the keyring's latest version means the account was reset elsewhere. A device that holds no
keyring yet anchors to the history it showed in its link code (section 8).

## 6. Sealed values

`seal(P, plaintext, ctx)`: fresh ephemeral P-256 pair `e`; `z = ECDH(e, P)`;
`k = HKDF(z, salt = epk ‖ P, info = ctx)`; output `{epk, iv, ct = AES-GCM(k, iv, plaintext, aad = ctx)}`.
The context string is both the HKDF info and the AEAD associated data, so a sealed value opens only in the exact
context it was made for.

| Context string | Used for |
|---|---|
| `commonveil/keyring-to-device/v1\|user_id\|device_id\|version` | keyring to a device's `B` (linking, rotation, repair) |
| `commonveil/keyring-recovery/v1\|user_id\|version` | keyring to the recovery key `R` |
| `commonveil/wrap/v1\|kind\|conversation_id\|item_id\|recipient_user_id\|key_version` | a content key to a member's `E_v` |

After opening a keyring, a client checks that every private key matches its listed public key and that every version
matches the account's verified, anchored statements, before using it.

## 7. Messages and group names

For each message (`kind = "message"`) or group-name update (`kind = "title"`), the sender picks a random `item_id` and a
fresh 256-bit content key `K`:

- content context `c = "commonveil/content/v1|kind|conversation_id|item_id|sender_id|device_id"`
- `ct = AES-GCM(K, iv, JSON payload, aad = c)`
- key commitment `kc = base64(SHA-256(UTF-8("commonveil/key-commitment/v1|" + c + "|") ‖ K))`
- for every current member `u` (including the sender): `wrap_u = seal(E_{u, current}.pub, K, wrap context)`
- envelope: `{"v":2, "iv", "ct", "kc", "wraps":[{"u", "kv", "epk", "iv", "wk"}]}`
- the sending device signs `item/v1` over the exact envelope JSON.

A reader unwraps `K` and refuses it unless `kc` matches before decrypting. Without the commitment, a sender could craft one
ciphertext that different members' wraps open to different texts, since AES-GCM doesn't commit to its key.

Payloads are `{"type":"title","title":…}` (at most 80 characters) for group names, and for messages one of:

- `{"type":"text","text":…, "reply_to"?: msg_id}`: text of at most 4000 characters, optionally answering another message.
  Only the id of the message answered is sent, never a copy of it.
- `{"type":"reaction","target": msg_id, "emoji":…, "remove"?: true}`: one of six fixed emoji, added or taken back.
- `{"type":"edit","target": msg_id, "text":…}`: new text for one of the sender's own messages.

Any message payload also carries `"expire_seconds"` when the conversation has a disappearing-message timer (below). To the
server these are all the same: one envelope, one signature, one row. Readers check every field and treat anything else
(an unknown type, an emoji outside the set, a malformed id) as unreadable.

The server stores, beside each message, the list of accounts its key was sealed to (`recipient_ids`, taken from the wraps).
Members are only ever sent messages that list them, so someone added to a group isn't shown that earlier messages exist.

**Putting a conversation together** (`src/lib/secure/thread.js`). Reactions and edits never show on their own; they change
the message they point at, and only when they check out:
- an edit counts only if it and the original are both verified, come from the same account, the original isn't deleted,
  and the edit's `sent_at` is within 24 hours of the original's; the latest edit wins, and the message is marked edited;
- a reaction counts only if it's verified; for each person, message and emoji, their latest reaction says whether it stands;
- "latest" means by the sender's signed `sent_at`, then by `msg_id`, so every member settles on the same result. A sender
  can only reorder their own edits and reactions this way.

**Disappearing messages.** A conversation can have a timer: off, 1 day, 1 week or 4 weeks. When a message arrives, the
server stores `expires_at = arrival + timer` beside it, stops listing it once that passes, and a scheduled task deletes it
(blanked first) every 30 minutes. The sender also puts the timer inside the signed payload, and readers hide a message at
the earlier of `expires_at` and `sent_at + expire_seconds`, so the server can't keep a message showing longer than its
sender chose. Apps also drop it from memory. Nothing stops a member copying a message before then.

A reader marks an item **verified** only if the sending device appears in the sender's device list, that device's
certificate verifies against the sender's chain (the pinned history while a change awaits review; for your own account,
only certificates from key versions your keyring holds), and the item signature verifies against the device key.

**Removed devices.** Every rotation re-certifies each remaining device under the new key, so a device whose newest
certificate is for version `c` was removed at the rotation to `c + 1`. If that rotation's statement was issued more than
10 minutes before an item's `sent_at`, the item is shown as "sent from a removed device", not verified. Items such a
device sent earlier stay verified and are marked as coming from a device since removed.

Otherwise an item is shown as **unverified**. Anything that fails to decrypt is shown as unreadable and never partially
displayed.

## 8. Flows

**First device.** Generate `S_1, E_1`, device keys and a phrase locally. The phrase is shown and three words are checked
back before anything is sent. Then publish, signed by the new device: the self-signed statement for version 1 with its
recovery anchor, a certificate for the device under `S_1`, and the keyring sealed to `R`.

**Adding a device by approval.** The new browser registers its device keys (pending, 15 minutes) and pins the account
history it was shown (`{version, digest}`). Both screens show a 20-digit link code,
`SHA-256("commonveil/link-code/v2|user_id|device_id|sign_pub|box_pub|account digest")` as five groups of four digits
(about 66 bits), each side using the head digest as it sees it. Matching codes mean the new device's keys weren't swapped
and the new device was shown the real account. The approving device certifies exactly the keys it compared (not whatever
the server lists by then) and seals the keyring to that `B`. The new device accepts the keyring only if the published
chain matches its pinned history and continues from it by rotation, then acknowledges, which deletes the server's copy.

**Adding a device with the phrase.** The new browser fetches the published chain and the recovery backup (requires
sign-in) and derives `R` and `A`. It refuses unless the latest statement's recovery key is `R` and, walking back from the
latest version while the recovery key stays `R`, it finds a statement whose recovery anchor verifies with `A`. Only then
does it open the backup, check the keyring against the chain, and certify itself with the latest `S`. (The backup is
sealed to a public key, so a server could forge one of its own; the anchor is what it can't forge.) Using the phrase
cancels any waiting reset.

**Removing a device and rotating.** An active device revokes the target, then publishes version `v+1` signed by `S_v`,
new certificates for every device it keeps, the new keyring sealed to each of them, and a new recovery backup. It keeps
only devices whose certificate is for the current key and leaves the removed one out itself, rather than relying on the
server's list; a device inserted by the server never receives keys.

**Changing the phrase.** A rotation with a new `R` and a recovery anchor made with the new phrase. The server deletes every
backup sealed to the old recovery key.

**Repair.** A device that missed a rotation (its `synced_key_version` is behind) is sent the current keyring by any
up-to-date device, only if its certificate is for the current key. The receiving device checks that the keyring continues
the one it already holds.

**Reset (lost every device and the phrase).** A new browser makes a new self-signed statement at the next version (with a
new phrase and its anchor), a certificate for itself and a sealed backup, and asks for a reset. Nothing changes yet:
- the request waits 7 days; the new keys wait in that browser;
- every device on the account shows the request and can cancel it (device-signed), using the phrase cancels it, and the
  account's sign-in email is sent a notice (best effort);
- the requesting browser can withdraw it; only one browser's request can wait at a time; 3 requests a day;
- once the wait is over, only the requesting browser can finish it (signed with the device key in the request). The server
  then publishes the statement, revokes every other device, deletes every sealed copy of the old keyring and activates
  the new device. If the keys changed in the meantime, the request is cancelled instead.

Contacts then see a "changed" warning; earlier messages stay unreadable to the new identity. Devices that held the old keys
show that the account was reset elsewhere. They keep their keys until the person deletes them: the server can claim a
device was removed, but can't make it forget anything.

**Security emails.** The account's sign-in address is emailed (best effort, never blocking the change) when a device is
approved, when the recovery phrase is used to add a device, when a reset is asked for and when one completes. Emails say
what happened and when; they never include device names, usernames or anything about conversations.

**Passcode lock (one browser, optional).** The keyring is stored as
`{"v":1,"locked":true, iv, ct}` = AES-256-GCM under a key derived from the passcode with PBKDF2-SHA-256 (600,000
rounds, 16-byte random salt), with associated data `commonveil-lock:keyring:<user id>`. Beside it, the lock record holds
the salt, the round count, the idle time and a check value (a fixed string sealed the same way) so a wrong passcode is
recognised. The record and the keyring are written in one IndexedDB transaction. Unlocked, the derived key is held in
memory as a non-extractable `CryptoKey`; locking drops it and the keyring. Device private keys are non-extractable, so they
can't be wrapped and aren't covered. Locking one tab locks the others (`BroadcastChannel`). Forgetting the passcode means
removing the browser (its signing key can still sign its own removal) and setting it up again.

**Auto-delete (opt-in).** A member can choose to have the account deleted after 183 or 365 days without use. Only then
does the server keep the day (not the time) the app was last opened, updated at most once a day. A daily scheduled task
emails a warning once the account is within 7 days of its date; opening the app withdraws it. The account is deleted at
the later of its date and 7 days after the warning, exactly as a self-service deletion, then its sign-in is removed. If
the warning can't be sent it's tried again each day, and the account is deleted 7 days after its date regardless. Staff
accounts are never deleted this way.

**Download my data.** Built in the browser: profile, devices, public key versions, every conversation with each message
the member can read (decrypted and verified there, with edits and reactions applied), blocks and the member's own reports.
It never includes keys or the phrase.

**Conversations.** Starting a direct message or group, adding or removing members, choosing admins, setting the timer,
leaving a group and deleting a message require a device proof (`device-proof/v1` over the exact payload). Whoever starts a
group is its admin and can make others admins. Only admins can add or remove people, rename the group, change its timer or
choose admins; an admin can step down while another admin remains. A group whose admins have all gone (or that predates
admins) is run by its creator if they're still in it, otherwise by its longest-standing member. In a direct message both
people manage the timer. Everyone sees who last changed the timer, and when. The server holds member lists, so each client also pins who was
in each conversation and refuses to encrypt to anyone it hasn't seen: a direct message is pinned on first sight (it must
have exactly two members, or sending is blocked); a group started on this browser is pinned with the people chosen; any
other group pins only yourself, so on first sight you're shown everyone in it before you can send. After that, anyone
new is shown before sending; the member who made the addition is not asked.

## 9. What the server enforces

The server never holds a private key. It checks, and refuses otherwise:

- a real signed-in user on every action (`auth.me()`); no action mints, accepts or forwards session tokens;
- version 1 is self-signed; later versions are signed by the previous one, except a reset that has waited out its 7 days;
  statements made with the phrase to hand carry a recovery anchor; at most 250 key versions;
- certificates name exactly the stored device keys and are signed by the current account key;
- device proofs are by an active device of the caller, at most 5 minutes old, over the exact payload, for the named action;
- a pending device can't approve itself, approvals expire after 15 minutes, at most 3 pending and 10 live devices,
  10 device registrations a day;
- messages: the caller is a member, the sending device is active and the caller's, the signature verifies, the envelope is
  version 2 with a 32-byte key commitment, the wraps cover exactly the current members at their latest key versions,
  `sent_at` is within 10 minutes of server time, message ids are unique per conversation (a resend of the same message is
  idempotent);
- rate limits, counted before writing and checked again afterwards so a burst of simultaneous requests can't slip past:
  30 messages a minute, 30 new conversations an hour, 20 reports a day, 3 reset requests a day; security reports 5 a day
  per member, and 10 an hour and 40 a day from people who aren't signed in;
- blocks stop direct messages in both directions and hide each person from the other's username lookup;
- usernames: exact-match lookup only, no directory; a deleted or erased account's username is retired, never reissued;
- profiles and public keys only for people you share a conversation with; groups of at most 32; reports readable only
  by admins;
- group changes (adding or removing people, names, the timer, admins) only by the group's admins, never leaving a group
  without one; timers only from the offered choices; expired messages are never listed;
- auto-delete only from the offered choices, signed by a device, and never for staff.

**Scheduled tasks.** One function, `maintenance`, is started by two automations: `expire` every 30 minutes, `inactive`
daily. Like every function its address is public, so it takes nothing but a task name and acts only on what's already due
by the server's clock; calling it early, late or twice does nothing extra, and a repeat within a minute (fifteen for
`inactive`) is skipped without touching the database. It answers with counts only.

**Data access.** Every table is closed to direct writes. Reads that run constantly (polling, page loads) are made with the
member's own access, and row rules allow only rows that name them: messages sealed to them, conversations they're in, and
their own profile, keys, devices, sealed keyrings and reset requests. Everything else, and every write, goes through the
backend's service role. (On Base44, service-role calls share one allowance for the whole app, while a member's own calls
count against theirs.)

**Replay.** Proofs carry a timestamp and nonce, but there's no nonce store, so a captured request could be replayed for up
to 5 minutes. Every proof-protected action is one-shot, idempotent, or gated on state a replay can't satisfy, except
starting a group: a replay would create a second, empty group with the same people (within the hourly limit). Capturing a
request needs TLS to be broken or the server itself, which can do worse.

**Deleting an account.** Needs a device proof and the word DELETE (or just the word, if the account never set up keys).
Every record is overwritten with blanks before it's deleted (Base44 keeps deleted records in a recycle bin): conversations
first (direct messages for both people; groups lose the member, and a group name they set is cleared), then messages they
sent, blocks either way, reports they made, reset requests, sealed keyrings, published keys, devices, and last the
profile, after retiring its username. Reports others made about them are kept for staff. Security reports they sent are
kept without their name. The work resumes where it stopped if it runs out of time. Staff can run the same erasure for an
account whose sign-in was removed in Base44, only after two separate checks confirm the sign-in is gone.

## 10. Tests

- `tests/crypto.test.mjs`: primitives, chains and digests, anchoring, envelopes and key commitment, recovery anchors,
  linking, tampering, the passcode lock (22 tests).
- `tests/functions.test.mjs`: the real backend handlers driven by the real client code, with only the database replaced
  (it applies the real row rules to members' own reads), including attack cases, a regression test for each review
  finding, disappearing messages, group admins, security emails, auto-delete and the scheduled tasks (53 tests).
- `tests/thread.test.mjs`: replies, reactions, edits, timers and on-device search (8 tests).
- `tests/site.test.mjs`: saved pages, guide progress and site search on the public site (2 tests).
- `tests/schema.test.mjs`: table definitions: no clashes with Base44's own fields, and the exact access rules (3 tests).
- `tests/e2e/`: live browser runs against the real platform (see its README).
