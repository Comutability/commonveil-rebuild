# Secure Net integration: independent protocol, any application

Secure Net is a separate, community-led, open-source communication protocol.
**Commonveil is its first adopting application, not the protocol's owner,
identity issuer, mandatory gateway or sole permitted client.**

Independent websites, mobile applications and self-hosted projects may
implement Secure Net using the published specifications and Rust library,
or implement the standard themselves. They do not need Commonveil
sign-in, the Commonveil server binary, a Base44 account or approval from
Commonveil. Actual interoperation still requires compatible features and
independent conformance tests.

## What belongs to which layer?

| Layer | Responsibilities |
| --- | --- |
| Secure Net, CVP specifications and public SNIPs | Shared actor and device document format, authenticated encrypted sessions, signed site-to-site transport, negotiated relay, inbox/outbox/mailbox contracts, conformance vectors and protocol governance |
| Each adopting application | Its own user interface, login, user-facing permissions, private device keys, moderation policies and app-specific content |
| Each compatible relay or site | Site-key authentication, replay protection, durable encrypted delivery queues, envelope validation, signed and post-quantum sealed transport where negotiated, retry/acknowledgement and abuse controls |
| Commonveil | Its own product, its older Commonveil-to-Commonveil federation compatibility layer and its integration of the independent Secure Net protocol |

## Private communication between two different applications

1. The sender's app independently verifies the recipient's Secure Net actor
   document, device history and current public keys (CVP-017).
2. The sending device encrypts and authenticates a message envelope for the
   intended recipient devices (CVP-016/019). The relay does not get the
   private keys or message plaintext.
3. The app submits to the authenticated site outbox (normally POST
   /cvp/v2/outbox). Its site validates permissions and queues delivery.
4. A site-to-site delivery (normally POST /cvp/v2/deliver) is signed with
   the sending site's key, checked for replay and digest integrity, and
   post-quantum sealed under CVP-015 when the receiving site advertises
   compatible relay keys.
5. The receiving site validates the transport and stores an opaque envelope
   in the recipient's mailbox (normally GET /cvp/v2/mailbox). The receiving
   app independently authenticates and decrypts.
6. The recipient devices acknowledge consumption. Operators must implement
   durable retries and de-duplication, bounded queues, blocking, expiration
   and key rotation. Metadata still reveals recipients, timing and sizes.

There is **no compulsory central Commonveil relay**. Multiple compatible
sites may exchange sealed messages, and another developer may build a relay
service independently. A site must advertise only endpoints and negotiated
features it actually implements. Having a CVP-shaped URL is not proof of
interoperability or secure deployment.

## Commonveil's current compatibility boundary

Commonveil has a mature but application-specific federation interface called
commonveil/1, with /cvp/v1/act and /cvp/v1/inbox. It supports existing
Commonveil installations and is documented in FEDERATION.md. It is NOT
equivalent to the independent CVP-019 outbox, deliver and mailbox contract.

The Secure Net Rust core contains provider-neutral cryptographic,
federation and reference-delivery code. Its social reference sites are
in-memory examples, not deployed production HTTP servers. Commonveil's
hosted backend and browser have **not** yet passed an independent,
other-vendor CVP-019 exchange of real encrypted messages.

Commonveil Docker runs the Commonveil application, not a standalone generic
Secure Net relay. Its self-hosted Rust server pins an exact Secure Net draft
commit; the browser still contains earlier JavaScript compatibility
functions. Experimental SNIP-0007 migration staging and recipient consent
are disabled by default and do not move accounts or inboxes.

## Independent developer checklist

1. Read Secure Net's README, CVP-010 conformance specification, CVP-017
   actors, CVP-019 delivery and INTEROPERABILITY.md in the Secure Net repo:
   https://github.com/Comutability/secure-net
2. Implement the CVP-005 site keys and signed requests, CVP-015 sealed relay,
   CVP-016 encryption, CVP-017 actor/device documents and CVP-019
   outbox/delivery/mailbox contracts. Do not rely on Commonveil-only APIs.
3. Run the shared Rust reference tests, then deploy **two separate application
   implementations** with different code and databases and test real HTTP
   delivery in both directions. A shared-library example is not enough.
4. Test wrong signatures, changed devices, nonces and replay after restart,
   blocked actors, duplicate delivery, unavailable hosts, DNS and site-key
   changes, sealed relay downgrade, privacy leakage and disaster recovery.
5. Propose changes through numbered public SNIPs. A Commonveil release cannot
   approve a protocol change. Security-sensitive changes require qualified
   human review.

Secure Net is a **draft, unaudited protocol**. Do not claim its reference
tests establish live production interoperability or cryptographic safety.


## Independently authenticated CVP-019 trial in Commonveil Rust (0.24.18)

The self-hosted server has a **separately disabled** experimental direct
message relay at /cvp/v2/outbox, /cvp/v2/deliver and /cvp/v2/mailbox.
It accepts independently owned signed actors, stores only validated public
prekeys and ciphertext, uses site-local actor credentials, and requires
manually pinned Ed25519+ML-DSA-65 signed, post-quantum sealed remote
deliveries. Data is separate from Commonveil accounts and rooms.
See [SECURE_NET_RELAY.md](SECURE_NET_RELAY.md) for the exact API and
security limits. It is **not** a complete deployed or audited CVP-019
implementation. The hosted site does not enable it, no feature is
advertised as production ready, and SNIP-0008's discovery format is
not changed.
