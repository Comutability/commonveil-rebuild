# Experimental destination ciphertext staging

This is a **test-only** self-hosted Rust-server foundation for
[Secure Net SNIP-0007](https://github.com/Comutability/secure-net/pull/16).
It is not full account migration, an identity issuer, an accepted protocol,
or a zero-knowledge proof system. No independent security review has occurred.

**Disabled by default.** On a private development instance only, an operator
may explicitly set EXPERIMENTAL_TRANSFER_STAGING=true. Do not enable it on
production sites. This server does not advertise a working CVP transfer.

## Independent identities and security limits

A user can create their own hybrid Ed25519 and ML-DSA-65 actor key using any
compatible client, without Commonveil as issuer. The server verifies both
signatures against the supplied key-derived actor identity, signs nothing
on the user's behalf, issues a fresh one-use destination challenge, and
persists monotonically increasing transfer sequences across restarts.

It does NOT prove the key holder owns an existing account on another site,
bind that key to a Commonveil account, validate external rotation history,
import messages, redirect inboxes, grant memberships, escrow keys, or delete
source accounts. Possession of a signature key is not a general ZK proof.

The client must encrypt every chunk before transmission. A server cannot
prove submitted bytes are encrypted without a separate verifiable mechanism.
The outer manifest accepts exactly the fields i, sha256 and bytes, so
contact names and message contents are not stored in manifest metadata.

## Test-only endpoints

All paths begin with /cvp/v2/experimental-transfer.

1. POST /challenge accepts owner_public and returns a random 32-byte
   single-use destination-bound challenge, actor ID and expiry.
2. POST /prepare accepts owner_public, signed transfer.intent and an ordered
   manifest array. Both hybrid signatures, destination, nonce, increasing
   sequence, expiry and ciphertext hash root are checked. It returns a
   random stage ID and 256-bit bearer stage token. Never log the token.
3. POST /stages/{id}/chunks/{index} accepts raw already-encrypted bytes with
   Authorization: Bearer <stage token>; verifies size and SHA-256 before
   acknowledging. Identical retries are idempotent.
4. POST /stages/{id}/status uses the token and optional JSON cursor/limit
   to list missing chunk indices. Complete ciphertext is not an import.
5. GET /stages/{id}/chunks/{index} returns base64url ciphertext if authorised.
6. POST /stages/{id}/abort deletes only the staged ciphertext. Replay floors
   remain in place and all old accounts/routes remain unchanged.

The service uses a separate SQLite database with FULL synchronous commits,
transactional one-use challenges, 0600 file permissions and the existing
private DATA_DIR. Bounds: 64 chunks of 256 KiB (16 MiB), eight active stages,
32 pending challenges, two per actor and one-hour stage expiry. This is
not enough for a real large-history move. It lacks production IP admission,
independent identity directory validation, an importer and security review.

## Remaining work

Reviewed client streaming AEAD, hybrid recipient key wrapping, account-bound
ownership proof, permission and contact portability, encrypted message/
attachment import, fresh device history handover, reconciled signed cutover,
Secure Net independent inbox/outbox redirection, deduplication, reversible
recovery, cross-instance integration tests and independent cryptography audit.
