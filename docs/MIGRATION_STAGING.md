# Experimental destination ciphertext staging

This is an **opt-in, private-test-only** self-hosted Rust-server foundation for
Secure Net SNIP-0007: https://github.com/Comutability/secure-net/pull/16.
It is not full account migration, an identity issuer, an accepted protocol
or a zero-knowledge proof system. No independent security review has occurred.

**Disabled by default.** On a private development instance only, an operator
may set EXPERIMENTAL_TRANSFER_STAGING=true. Do not enable it on production.
The site does not advertise transfer capability.

## Independent identities

A user may create a hybrid Ed25519 + ML-DSA-65 actor identity in any
compatible client. Commonveil does not issue it for the protocol. The
destination verifies both owner signatures against the key-derived actor ID,
issues one-use destination challenges and persists the highest transfer
sequence across restarts.

This does not establish ownership of an existing remote account, validate
external key rotation, bind an actor to Commonveil sign-in, import contacts,
migrate DM session keys, change mailboxes or delete source accounts.
Digital signatures are not zero-knowledge proofs.

## Test-only endpoints

All paths begin with /cvp/v2/experimental-transfer. Every stage operation
requires Authorization: Bearer with the secret token returned by prepare.

1. POST /challenge issues a short-lived random challenge to a hybrid actor.
2. POST /prepare checks a hybrid-signed transfer.intent, fresh challenge,
   destination, increasing sequence and ordered ciphertext manifest. Returns
   a stage ID and a random bearer token. Never log or share the token.
3. POST /stages/{id}/chunks/{index} stores an opaque ciphertext chunk only
   if its hash and size match the owner-signed manifest. Identical retries
   are idempotent; corrupted or conflicting chunks are refused.
4. POST /stages/{id}/status returns missing-chunk cursors and separate
   ciphertext/report/owner-attested states.
5. GET /stages/{id}/chunks/{index} returns base64url ciphertext for the
   authorised device to authenticate and decrypt locally.
6. POST /stages/{id}/report stages an already device-encrypted private
   reconciliation report, 48 bytes to 64 KiB, only after all archive chunks
   arrived. The now-shared Secure Net Rust helper requires the experimental
   CVRPT version 1 header and checks the exact byte digest. Unsupported
   versions, missing headers and malformed lengths fail closed. Conflicting
   uploads are refused; identical retries are safe. The server still cannot
   authenticate the AES-GCM tag without the recipient's device key.
7. GET /stages/{id}/report returns the staged, hash-verified opaque report
   as base64url bytes and SHA-256.
8. POST /stages/{id}/reconcile invokes Secure Net's provider-neutral
   hybrid signature/schema verifier for transfer.reconcile. It checks the
   independent actor, destination, stage, signed root, random challenge,
   expiry and SHA-256 of the **actual staged encrypted report**. The server
   re-hashes the report and all archive ciphertext in a transaction before
   storing the receipt. Extra unsigned metadata, wrong keys and altered
   records are refused. This is only a client assertion, not an import.
9. GET /stages/{id}/reconcile returns the signed client statement for
   independent checking. The exact same statement is idempotent.
10. POST /stages/{id}/abort deletes only staged data and its signed receipt.
    Existing source accounts, keys and inbox routes are never changed.

The separate SQLite staging database uses FULL synchronous transactions,
foreign-key cascade cleanup and restricted 0600 file permissions in a
private data directory. Bounds: 64 chunks of 256 KiB, 16 MiB total archive
ciphertext, one 64 KiB private report, eight active stages, 32 pending
challenges, two per actor and one-hour stage expiry. This is **not** enough
for a complete real-world history migration.

## Client-side encrypted reconciliation reports

The browser helper and Rust verification now share the byte-level
synthetic fixture at tests/fixtures/secure-net-transfer-report-v1.json,
copied from Secure Net's draft conformance vector. It verifies the exact
five recipient-bound associated-data fields and the format commitment.
The fixture contains synthetic bytes, **not valid AES-GCM ciphertext**.

Earlier experimental reports without a CVRPT v1 header are refused.
Operators must discard and re-stage such test-only data. No real accounts
or message data should have been in these stages.

The test-only helper at src/lib/identity/migrationReport.js uses WebCrypto
AES-256-GCM with a pre-existing, authorised, non-extractable device key.
It does **not** create, authorise, export, wrap or distribute that key.
Independent device enrolment and reviewed post-quantum key agreement are
required before a real recipient can retrieve private history.

Envelope layout: ASCII CVRPT, byte 0x01, a fresh 12-byte AES-GCM nonce,
and authenticated ciphertext with a 128-bit tag. The associated data
is the domain secure-net/transfer.report/v1 and an ordered array of
actor ID, stage ID, destination, ciphertext root and recipient device ID.
The device must independently verify and decrypt this report before
signing reconciliation. The owner signs the SHA-256 of the entire binary
envelope, not plaintext report fields.

Private missing-message identifiers and counts may appear **only inside**
the encrypted report. Public manifests and receipts must not expose
contacts, filenames or message bodies. The host sees routing, timing,
sizes and hashes. It cannot prove that arbitrary uploaded bytes are
encrypted or that a client actually opened the data. Hash verification
is **not** a zero-knowledge proof or recipient-authentication mechanism.

## Limited cross-host staging test

The Rust HTTP integration test now starts two independent destinations,
site B and site C, with different private SQLite databases. The user-held
Secure Net actor key, created without a Commonveil account or identity
issuer, can authorise an A-to-B staging intent and then a B-to-C staging
intent. The original A server is intentionally unavailable. Both hosts
reject another destination's signed statement, classical-only owner keys
and bearer tokens issued by the other host.

The test confirms **provider-neutral actor signature verification and
staging only**. It does NOT prove an old server owned the identity, provide
a verified cross-site key-rotation history, move account state, forward
any mail, recover unavailable messages or finish migration. The full
adversarial A-to-B-to-C acceptance test remains open.

## Remaining work and safety boundaries

Recording a transfer.reconcile receipt does **not** import history,
verify the user's decryption, bind the account, authorise a destination
move or permit old-site deletion. The status remains imported=false
and cutover=false. A malicious client can assert client_checked=true
without reading private history. This requires independent reconciliation
and device-authorisation tests before live use.

Still required: versioned and streamed authenticated-encryption archive
and attachment manifests, post-quantum recipient key wrapping, signed
actor/device rotation, user-owned graph and permission import, forward-
secret history handover, Secure Net independent inbox/outbox delivery,
reviewed two-phase cutover, stale-handle delivery, source-offline
recovery, reversibility, multi-instance hostile-host tests, Docker
validation and an independent cryptographic security review.

No live Commonveil account, encryption key, database or message route
is modified by this opt-in test-only service. Do not expose it publicly.
