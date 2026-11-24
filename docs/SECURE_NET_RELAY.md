# Independent Secure Net inbox/outbox trial in Commonveil Rust

**Status: experimental, unaudited, disabled by default.** The hosted
Commonveil application does not offer this service. It has not passed a
real third-party interoperability or independent security assessment.

This separate Rust module stores independent CVP-017 actors and encrypted
messages in a separate SQLite database named
`secure-net-relay-experimental.sqlite`. It does not use or change
Commonveil accounts, existing `commonveil/1` federation, rooms, sessions,
private histories or inboxes. Commonveil remains an adopting application,
not Secure Net's mandatory server or identity authority.

## Docker controls

Both settings are disabled or empty for ordinary self-hosted installations:

```env
EXPERIMENTAL_SECURE_NET_RELAY=false
SECURE_NET_RELAY_ADMIN=
```

**Test on an isolated disposable server and independent data volume only.**
Set a long, random, URL-safe operator token of at least 32 characters to
enable manual actor registration and site-key pinning. Keep the token
private. Docker operators can inspect container environment secrets.

## Independent actor and endpoint operations

| Method | Prototype URL | Who may call it |
| --- | --- | --- |
| GET | `/cvp/v2/relay/site` | Read public experimental site key, sealed relay keys and endpoints |
| POST | `/cvp/v2/relay/admin/actors` | Operator registers signed independent CVP-017 actor documents |
| POST | `/cvp/v2/relay/admin/trust` | Operator manually pins another site's Ed25519 and PQ relay keys |
| GET | `/cvp/v2/actor/{actor}` | Fetch a signed, discoverable actor document |
| POST | `/cvp/v2/prekeys` | Actor credential publishes independently signed public device prekeys |
| GET | `/cvp/v2/prekeys/{actor}/{device}` | Public, atomically consumes one-time device prekeys |
| POST | `/cvp/v2/outbox` | Local actor credential submits bounded recipient/envelope entries |
| GET | `/cvp/v2/mailbox?device={device}` | Site-local actor credential retrieves opaque encrypted mail |
| POST | `/cvp/v2/mailbox/ack` | Actor credential acknowledges specific device mail |
| POST | `/cvp/v2/deliver` | Remote site, manually pinned keys, both signed and PQ sealed |
| POST | `/cvp/v2/outbox/flush` | Operator initiates queued remote deliveries |

The admin actor registration API takes a **genuinely signed** independent
actor document under a single `document` property. The operator must
authenticate its owner through a trusted channel. The site issues a random
site-local actor credential **once**, and stores only its SHA-256 digest.
This is not a cryptographic proof that a specific recipient device holds
a private decryption key.

An outbox request uses the CVP-019 list shape:

```json
{
  "items": [
    {
      "host": "recipient.example",
      "to": "recipient-actor-id",
      "envelope": {
        "v": 2,
        "mode": "direct",
        "device": "recipient-device-id",
        "message": {
          "v": 2,
          "h": "base64url-header",
          "c": "base64url-ciphertext"
        }
      }
    }
  ]
}
```

These are **shape placeholders, not valid credentials or encrypted
messages**. The site validates the complete envelope and destination.
This prototype supports version 1 and 2 encrypted **direct** envelopes
only. Other audience, group and public modes are rejected until their
separate membership and signed-content rules are implemented.

## Site-to-site authentication and queues

The operator pins a peer site's Ed25519 public signing key and CVP-015
post-quantum relay public keys. Unknown sites and unexpected key changes
are refused. Deliveries use a CVP-005 signed request and its ML-DSA-65
signature, with the body sealed using P-256 + ML-KEM-768 and AES-256-GCM.
The destination checks the site, date, nonce, digest, signatures and
sealing **before** accepting an envelope.

Mailboxes and replay records are kept in private SQLite transactions
with a full-synchronous write policy. A nonce is consumed durably so a
replayed request after server restart fails. One-time signed public
prekeys are atomically consumed. Mailbox reads do not delete entries
until a valid acknowledgement or the 30-day retention period expires.

Remote messages are durably queued. The operator invokes the experimental
flush operation to attempt delivery; a failed delivery stays queued.
Only a validated sealed acknowledgement permits removal of the queued
message. **No automatic retry worker is included.**

```text
Independent app A          Site A                 Site B          Independent app B
device-sealed message -> outbox queue -> signed + PQ sealed deliver -> mailbox
                                                                    |
                                                              device decrypts
```

## Deliberate limitations

- No production-wide CVP-019 feature advertisement. The trial site
  document has an empty advertised feature set and is **not** the
  proposed brand-neutral well-known discovery endpoint of SNIP-0008.
- No independent external-app security audit, automated site discovery
  or independently verified real HTTPS exchange between separate vendor
  implementations. A Rust HTTP integration test now exercises two separate
  server processes, private SQLite databases, manual mutual site trust,
  authenticated post-quantum sealed delivery, the opaque recipient mailbox
  and the source's signed receipt. Both servers use the **same Rust
  implementation**, local test HTTP transport and a structural ciphertext
  fixture. This does not constitute two independent implementations or an
  actual end-to-end decrypted conversation.
- No Commonveil user-login integration. The actor bearer authenticates
  an actor, not the physical presence of a particular device. Never
  confuse it with a private recipient KEM-key possession proof.
- No public or audience/group envelope delivery, production group
  membership management, key-package distribution or full actor migration.
- Manual trust is operator-authorised. Backups, abuse controls, host
  authenticity, independent threat-model and real cross-provider audit
  are necessary before wider deployment.
- No history-key transport, full inbox cutover or source-account erasure.

See the independent
[Secure Net CVP-019 specification](https://github.com/Comutability/secure-net/blob/main/spec/CVP-019-delivery.md),
[CVP-015](https://github.com/Comutability/secure-net/blob/main/spec/CVP-015-sealed-relay.md),
[SNIP-0008](https://github.com/Comutability/secure-net/blob/main/snips/SNIP-0008.md)
and [Comutability documentation](https://comutability.org/docs).
