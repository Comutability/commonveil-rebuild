# CVP-016: End-to-end sessions

| | |
| --- | --- |
| Status | Draft (merged into the reference implementation; awaiting human cryptographic review) |
| Version | 1 |
| Feature | `cvp.sessions` (version 1) |
| Depends on | CVP-002 |
| Code | `src/session/` |
| Proposed in | [SNIP-0003](../snips/SNIP-0003.md) |

How two devices agree keys, exchange messages and keep them private, including from an attacker
who records everything today and has a large quantum computer later. It covers one-to-one
messages, a person's several devices, groups, and moving history to a new device.

Implemented in Secure Net 0.4.0. Not yet reviewed by a qualified human cryptographer; nothing
here should be relied on until it has been.

The design follows Signal's: an X3DH-style handshake made post-quantum as in PQXDH, then a double
ratchet. Unlike Signal's original ratchet, every DH ratchet step here also mixes in a fresh
ML-KEM-768 secret, so recovery after a compromise does not rest on X25519 alone.

## What it protects, and from whom

| Property | How | Holds against |
| --- | --- | --- |
| Confidentiality of content | AES-256-GCM under keys from X25519 **and** ML-KEM-768 | Sites, relays, networks, and a future quantum computer, unless both X25519 and ML-KEM-768 are broken |
| Forward secrecy | Message keys are deleted after use; chain keys move one way; ratchet keys are replaced every round trip | Someone who steals a device later can't read earlier messages |
| Recovery after compromise | Each round trip mixes in new X25519 and ML-KEM-768 secrets | Someone who copied a device's state once loses access after the next round trip, if they're not actively in the middle |
| Who is talking | Account keys sign device lists, devices sign prekeys, all with Ed25519 + ML-DSA-65; the handshake binds both parties' keys | A site serving fake keys (caught once people compare safety numbers) |
| Integrity and order | AEAD with the header as associated data; counters; one-time message keys | Tampering, replay, reordering beyond the stated window |

### What isn't protected

- **Metadata.** Sites still see which device sends to which, when, and how much. The sealed
  relay (CVP-015) hides it from the network between sites, not from the two sites.
- **First contact.** Until two people compare safety numbers, a site that controls the first
  key fetch can sit in the middle. Apps MUST show the safety number and MUST warn when a pinned
  account key changes.
- **Group authenticity against a quantum attacker.** Group messages are signed with Ed25519
  only (an ML-DSA-65 signature on every group message would add 3.3 KB). Forging one needs a
  quantum computer at the time of the attack **and** membership of the group; it doesn't help
  anyone read recordings. Group confidentiality is post-quantum.
- **A device someone controls now.** Encryption can't protect what's on an unlocked, compromised
  device.
- **Replay of a first message made with the last-resort prekey and no one-time X25519 prekey.**
  Receivers MUST remember the handshake ids (`handshakeId`) of first messages for as long as the
  signed prekey is live and refuse repeats.

## Keys

| Key | Algorithm | Held by | Purpose |
| --- | --- | --- | --- |
| Account key | Ed25519 + ML-DSA-65 | trusted devices or a recovery phrase | Signs the device list. Its fingerprint is what people compare. |
| Device signing key | Ed25519 + ML-DSA-65 | one device | Signs that device's prekeys |
| Device identity key (IK) | X25519 | one device | Long-term key agreement |
| Signed prekey (SPK) | X25519, expires (30 days by default) | one device | Handshake; rotated with `rotateSignedPrekeys` |
| Last-resort ML-KEM prekey (PQSPK) | ML-KEM-768, expires | one device | Handshake when one-time ML-KEM prekeys run out |
| One-time prekeys (OPK, PQOPK) | X25519 and ML-KEM-768 | one device | Handshake, used once then deleted |

Every public prekey is a signed record (CVP-002) of kind `session.prekey`:

```
{ device, type: "x25519" | "ml-kem-768", id, pub, expires?, lastResort?, oneTime? }
```

The device list is a signed record of kind `session.device-list`, signed by the account key:

```
{ account: <account public key>, devices: [{ kid, sign, dh }], seq, issued }
```

`seq` MUST increase with every change. A receiver MUST remember the highest `seq` it has seen
for each account and MUST refuse a lower one, so a site can't bring back a removed device.

## Bundles

A site hands out, for one device: the device list, the signed prekey, one ML-KEM-768 prekey (a
one-time one if any remain, otherwise the last-resort one) and one one-time X25519 prekey if any
remain. A site MUST NOT hand out a one-time prekey more than once.

The initiator MUST check (`verifyBundle`): the device list verifies under the account key it
trusts for that person and isn't older than one already seen; the device is on it; each prekey
is signed by that device's signing key, is of the right type and hasn't expired; the ML-KEM
prekey is marked one-time or last-resort; the X25519 one-time prekey, if present, is marked
one-time.

## Handshake

Initiator A, responder device B. A makes an ephemeral X25519 key EK, then:

```
DH1 = X25519(IK_A, SPK_B)
DH2 = X25519(EK_A, IK_B)
DH3 = X25519(EK_A, SPK_B)
DH4 = X25519(EK_A, OPK_B)          only if a one-time prekey was given
(CT, SS) = ML-KEM-768.Encaps(PQPK_B)
```

Any X25519 output of all zeros MUST be refused. The transcript is the canonical JSON (CVP-002) of

```
{ v: 1,
  initiator: { account, device, sign, dh },
  responder: { account, device, sign, dh },
  ek, ct: base64url(SHA-256(CT)), signed: <SPK id>, pq: <PQ prekey id>, oneTime: <OPK id or null> }
```

and `TH = SHA-256("secure-net/session/v1/transcript" || transcript)`. Then

```
SK = HKDF-SHA-256(salt = 32 zero bytes,
                  ikm  = 32 bytes of 0xFF || DH1 || DH2 || DH3 [|| DH4] || SS,
                  info = "secure-net/session/v1/handshake" || TH, length 32)
```

`TH` is also the session's associated data, so every message is bound to both parties' account
and device keys. The handshake fields `x` travel with A's messages until A hears back:

```
x = { list: <A's device list>, device: <A's kid>, ek, ct, signed, pq, oneTime }
```

B checks A's device list against the account key B trusts for A (apps look it up with
`initialSender` first), finds the prekey secrets by id, computes the same SK, and deletes the
one-time prekeys used once the first message has decrypted. A first message naming an unknown
or used prekey MUST be refused.

## Ratchet

State per session: root key RK; our ratchet X25519 key DHs and ML-KEM-768 key KEMs; the peer's
DHr and KEMr; sending and receiving chain keys; counters Ns, Nr, PN; skipped message keys.

```
KDF_RK(rk, dh, ss)  = HKDF-SHA-256(salt = rk, ikm = dh || ss, info = "secure-net/session/v1/root", 64)
                      -> (rk' = first 32 bytes, ck = last 32 bytes)
KDF_CK(ck)          = (mk = HMAC-SHA-256(ck, 0x01), ck' = HMAC-SHA-256(ck, 0x02))
message key         = HKDF-SHA-256(salt = 32 zero bytes, ikm = mk, info = "secure-net/session/v1/message", 44)
                      -> AES-256-GCM key (32) and nonce (12)
```

**Start.** A: `RK = SK`, DHr = SPK_B, new DHs and KEMs, `(RK, CKs) = KDF_RK(RK, X25519(DHs, DHr), "")`.
B: `RK = SK`, DHs = SPK_B, no KEMs yet.

**Sending.** `(mk, CKs) = KDF_CK(CKs)`. The header is `{ dh: DHs.pub, kem: KEMs.pub, ct?, pn: PN, n: Ns }`,
where `ct` is the ML-KEM ciphertext made when this sending chain started (absent only on A's
first chain). The message is

```
{ v: 1, h: header, x?: handshake, c: AES-256-GCM(mk, plaintext, ad = TH || canonical({ h, x? })) }
```

**Receiving a new ratchet key** (header `dh` differs from DHr):

1. If we have sent a KEMs and the header has no `ct`, refuse (`DOWNGRADE`).
2. Keep the remaining keys of the current receiving chain up to `pn` (skipped keys).
3. `SS = ML-KEM-768.Decaps(ct, KEMs)` (empty if no KEMs yet); `(RK, CKr) = KDF_RK(RK, X25519(DHs, dh), SS)`.
4. New DHs and KEMs; `(CT', SS') = Encaps(header.kem)`; `(RK, CKs) = KDF_RK(RK, X25519(DHs, dh), SS')`;
   CT' goes in every header of the new sending chain.

Every round trip so replaces both an X25519 and an ML-KEM-768 key on each side.

**Skipped keys.** At most 1,000 missing messages in one chain and 2,000 stored keys per session
(oldest dropped first). A used or skipped key is deleted once it decrypts a message, so a replay
fails.

**Failure.** A message that fails any check MUST leave the state unchanged. The reference code
returns new state from every call and never changes what it was given.

## Devices

A person's devices are the ones on their current device list. To send, a device encrypts the
message separately for every device on the recipient's list and every other device on its own
(`planFanOut`, `encryptToDevices`). When a list drops a device, sessions with it are deleted.
If both sides start a session at once, apps SHOULD keep, for each device, the session they most
recently received a message on (the reference code leaves this choice to the app).

## Groups

Each member device has a sender key per group: a random 32-byte chain key, a counter and an
Ed25519 key pair. It sends `{ type: "sender-key", group, id, ck, n, sign }` to every other member
device over their one-to-one sessions; the receiver records which session it came on, never
trusting a name inside it. A group message is

```
{ v: 1, group, id, n, c, sig }
c   = AES-256-GCM(message key from KDF_CK, info "secure-net/session/v1/group", ad = canonical({ v, group, id, n }))
sig = Ed25519 over "secure-net/session/v1/group-sig\n" || canonical({ v, group, id, n, c })
```

When anyone leaves, every remaining member MUST make a new sender key and send it only to the
remaining members. When someone joins, members SHOULD make new sender keys, so the newcomer can't
read earlier messages.

## New devices

1. **Link.** The new device shows a link code (`linkCode`: 30 digits from SHA-256 of its signing
   and identity keys), as text or a QR code. An existing device computes the code from what it
   received, the person checks they match, and the existing device signs a new device list with
   the new device added (`approveLink`).
2. **History.** The existing device seals the history (`sealHistory`): a fresh 32-byte key,
   chunks encrypted with AES-256-GCM under per-chunk keys, each bound to the transfer id, its
   index and the chunk count, plus a digest over all chunks. The chunks can go through any
   untrusted store. The key and manifest go to the new device over their one-to-one session.
   The new device refuses missing, reordered or altered chunks (`openHistory`).
3. With no existing device available, a new device starts with no history.

## Sizes and cost

Measured with the reference code (JSON on the wire, base64url):

| Item | Size |
| --- | --- |
| Bundle for one device | about 26 KB (mostly ML-DSA-65 signatures and ML-KEM-768 keys) |
| First message (carries the handshake and the sender's device list) | about 13 KB |
| Ordinary message | about 3.1 KB plus the content (the ML-KEM key and ciphertext of the current chain) |
| Session state | about 11 KB |
| A full ratchet round trip | about 10 ms in the cloud test environment (not yet measured on phones) |

Sending the ML-KEM fields only until the peer acknowledges them, or splitting them across
messages as Signal's SPQR does, would cut the per-message cost; that is future work and would be
a new version.

## Conformance

`test/session.test.mjs` and the vectors in [vectors/cvp-016-v1.json](vectors/cvp-016-v1.json)
(written by `scripts/vectors.mjs`). The X25519, HKDF, HMAC and AES-GCM vectors have been checked
against Node's built-in crypto, an independent implementation; the ML-KEM-768 vector comes from
@noble/post-quantum and has not been checked against a second implementation yet.
`examples/two-party.mjs` runs the whole protocol through a relay that keeps a copy of everything
and checks no plaintext is in it.

## Relation to older parts

`crypto/envelope` (CVP-003) seals content to an account's shared key, so it has no forward
secrecy and keeps a classical fallback. New messages SHOULD use sessions. Commonveil's switch is
a separate change with its own migration plan.

## Changes

| Version | Date | SNIP | Change |
| --- | --- | --- | --- |
| 1 | 2026-11-13 | SNIP-0003 | First version, in Secure Net 0.4.0 |
| 1 | 2026-11-13 | SNIP-0004 | Editorial: standard header; labels registered |
