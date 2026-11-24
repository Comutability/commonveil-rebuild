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
- **No portable identity yet.** Settings, Protocol identity shows your actor and checks an actor
  document made with another application, but an outside actor can't be attached to your account:
  that needs a server challenge signed by both keys, with replay protection, which isn't built
  (docs/IDENTITY.md, "Protocol actors"). A move to another site can only be prepared, not made.
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

Secure Net is Rust only from 0.7.0. The Rust server that self-hosted sites run uses Secure Net's
crates, pinned to one Secure Net commit, and a daily workflow opens a pull request when Secure
Net's version moves on. `packages/secure-net` is a checked copy of Secure Net 0.5.0, the last
version with JavaScript, which the browser app and the Base44 functions use until they move to
Rust. Whenever Secure Net changes, Commonveil is updated to it as part of the next release (see
AGENTS.md, "Keeping up with the protocol").

## Experimental destination staging (0.24.11)

The self-hosted Rust server contains a disabled-by-default SNIP-0007 ciphertext
staging prototype: see [MIGRATION_STAGING.md](MIGRATION_STAGING.md).
It verifies independent hybrid actor keys, does not issue identities, cannot
decrypt messages, and does not bind existing accounts or switch inboxes.
It must not advertise production migration support.

## Secure Net draft alignment and Docker traceability (0.24.14)

The self-hosted Rust server and Rust/WebAssembly client source now pin the exact
experimental Secure Net SNIP-0007 draft commit
12ab6f3e351bb348aed75f864095e50965be9239. The corresponding OpenMLS
dependency forks are pinned to the same commit in rust/Cargo.toml and
rust/Cargo.lock. The staging service uses Secure Net's Rust transfer module
to verify transfer-intent authorisations against the destination's durable
challenge/sequence state and to compute the canonical signed ciphertext
manifest commitment, avoiding duplicated versioned protocol rules.

The installed Docker image's OCI labels include the source Secure Net
revision when built by the release workflow. Docker Compose explicitly
keeps EXPERIMENTAL_TRANSFER_STAGING=false by default. If an operator tests
the feature on an **isolated development site only**, the Rust server provides
the staged encrypted-report and owner-signed reconciliation endpoints in
docs/MIGRATION_STAGING.md. These endpoints do not create identities, change
messages or perform live migration. No CVP transfer capability is advertised
in the site's public federation document.

The hosted Commonveil site and browser still use the frozen Secure Net 0.5.0
JavaScript compatibility code for existing messages and actor verification.
They display a read-only protocol readiness description and destination
compatibility checklist but cannot use the experimental Rust staging API.
A protected client-side, recipient-authorised importer and independent
cross-implementation tests are required before enabling actual migration.

**Status:** SNIP-0007 and the 0.7.0 migration helpers are draft/unaudited.
A green Rust build and Docker image do not constitute protocol adoption,
post-quantum recipient key enrolment, cryptographic security review or a
working account/inbox cutover.


## Secure Net provisional reconciliation integration (Commonveil 0.24.15)

The Commonveil Rust workspace and Docker builds now pin draft Secure Net
revision e82fd9e453f5c145e0f6e7892dd57e958db38ff2, which passed both
Secure Net CI workflows. The isolated Rust staging route delegates hybrid
signed transfer.reconcile schema, owner identity, stage, destination,
ciphertext root, challenge, encrypted report digest and short expiry checks
to the provider-neutral Secure Net crate. The same crate rejects invalid
CVRPT version-1 framing on report upload, download and signed receipt
verification. Legacy draft reports without the header are refused.

Commonveil's JavaScript helper computes the same associated-data bytes and
report digest entirely on the authorised device, using an existing
non-extractable AES-256-GCM recipient key. Its conformance test consumes
Secure Net's synthetic Rust vector. It cannot enrol another device,
transfer private history, sign a two-phase cutover or redirect an inbox.

The GitHub Docker image integration tests now assert that the image's OCI
protocol-commit label equals the exact Cargo.lock commit and that the
Compose transfer-staging setting defaults to false. The separate opt-in
:edge image is rebuilt after all CI tests pass; existing production :latest
is deliberately unchanged. **No public live account migration is enabled**.

SNIP-0007 is still a draft, and Secure Net's public CVP capability
advertisement is unchanged. Passing CI does not replace an independent
cryptographic review or cross-implementation import/decryption tests.


## Secure Net recipient-grant draft integration (Commonveil 0.24.16)

The self-hosted Rust server, Rust browser client core and Docker build pin
experimental Secure Net revision fe44f0d09c77d941a92fbf319a7deaeb6947bf69.
This includes independently signed transfer.recipient-request,
transfer.recipient-grant and a prototype KEM possession verifier. Only
the first two signed public authorisation records are accepted by the
Commonveil Rust stage service, behind **two separate private-test gates**.
The service checks the signed recipient public MLKEM768-P256 key with the
provider-neutral Secure Net verifier, persists identical request/grant
records in the existing FULL-synchronous SQLite staging database, and
returns them after restart. Conflicting replacements and unauthorised
bearer access are refused. Abort removes the records with the stage.

No KEM possession proof is accepted or claimed: that protocol helper is
still in-memory-only and requires a crash-safe, one-use implementation
before cross-instance use. No history keys, cryptographic session secrets,
live account ownership or inbox routing change in this release. Docker
Compose and its CI require both EXPERIMENTAL_TRANSFER_STAGING=false
and EXPERIMENTAL_RECIPIENT_CONSENT=false by default. The public hosted
application only clarifies the protocol readiness status.
