# The Secure Net layer (experimental)

Commonveil 0.23.0 starts moving onto the [Secure Net](https://github.com/Comutability/secure-net)
protocol (the Commonveil Protocol, CVP). This first step is off unless a person turns it on in
**Settings, Devices and keys**, and is labelled experimental there, because the protocol has not
had an independent security review.

## What it does

A direct message is protected as it always has been (see [PROTOCOL.md](PROTOCOL.md)). With the
layer on for **both** people, its content is then sealed a second time under a one-off key:

1. Each account gets a Secure Net **actor** (CVP-017): a quantum-resistant account key
   (Ed25519 with ML-DSA-65), a signed actor document with the handle `@username@site`, and a
   signed list of the account's devices.
2. Devices hold **post-quantum sessions** with each other (CVP-016): a handshake using X25519 and
   ML-KEM-768 together, then a ratchet that mixes in fresh keys of both kinds on every round trip.
3. For each message, the sending device makes a random 32-byte key, seals the message content
   under it (AES-256-GCM, bound to the conversation, message id and sender), and sends the key to
   every device of the other person, and to the sender's own other devices, over those sessions.
   The key travels as a signed activity (CVP-018) in a direct envelope (CVP-019).
4. The sealed content then goes through Commonveil's existing encryption and checks unchanged.

Reading the message needs both the account keys and the one-off key. So the layer adds forward
secrecy and can't make a conversation weaker than it is without it: someone who later obtains an
account's keys, or its recovery phrase, still can't read these messages.

## What it doesn't do yet

- **Only direct messages**, and only new text messages and attachments' message bodies. Groups,
  servers, edits, reactions, polls, calls, scheduled messages and messages written offline go as
  before.
- **A device only reads what was sent while it was linked.** A device added later, or restored
  with the recovery phrase, shows those messages as "Sent with extra protection before this
  device was linked". Copying history between devices (CVP-016, "New devices") isn't wired up.
- **Within one site.** Actors are looked up on the same site only. Delivery between sites, public
  discovery, repositories and lexicons (CVP-019 to CVP-021) come in later releases.
- **No passcode lock.** The layer's keys are stored in the browser like device keys without a
  lock; the passcode lock doesn't cover them, so the two can't be on together.
- **First sight is trusted.** A device pins each person's actor the first time it sees it, and
  refuses a different one afterwards (messages then go without the layer, and Settings says so).
  Safety numbers for comparing actors aren't shown in the app yet.
- **Not reviewed.** Secure Net's sessions and social protocol are marked Draft in its own
  standard. Treat this as a preview.

## What the site stores and sees

The `protocol` function (the same code on Base44 and on self-hosted sites) stores:

| Table | Holds | The site can read |
| --- | --- | --- |
| `ProtoActor` | Each account's signed actor document, and its account key sealed to the account's own keyring | The document (handle, public keys, how many devices). Not the sealed key |
| `ProtoPrekey` | Each device's signed prekeys; one-time ones are deleted when handed out | Public keys only |
| `ProtoMail` | Sealed envelopes waiting for one device; deleted when collected, or after 30 days | Who sent to which device, when, and the size. Nothing inside |

The site checks shapes, sizes, who may write what, and rate. It does **not** verify the
post-quantum signatures: devices verify every document and prekey themselves. That keeps
post-quantum code out of Base44's functions, where it hasn't been proven to run, and it means a
site that lied could only stop the layer working. Only people who share a conversation can fetch
each other's actor documents and prekeys or write to each other's mailboxes, and blocked people
can't.

Turning the layer off, or deleting an account, deletes all three kinds of row for that account.

## Keeping in step with the protocol

`packages/secure-net` is a checked copy of Secure Net. Whenever Secure Net changes, Commonveil is
updated to it as part of the next release (see AGENTS.md, "Keeping up with the protocol").
