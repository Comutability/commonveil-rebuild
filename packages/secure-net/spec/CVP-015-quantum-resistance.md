# CVP-015: Quantum resistance

What in the protocol resists an attacker with a large quantum computer, including one who
records traffic today to decrypt later, and what doesn't yet.

| Part | Protection | Status |
| --- | --- | --- |
| Message content, attachments, community keys | Hybrid: ECDH P-256 and ML-KEM-768, AES-256-GCM (`crypto/kem`) | Quantum-resistant already |
| The relay between sites (who writes to whom, where, when) | Sealed site to site: ECDH P-256 and ML-KEM-768 (FIPS 203), HKDF-SHA-256, AES-256-GCM (`wire/sealed`) | Quantum-resistant |
| Relay authenticity (which site sent it) | Ed25519 and ML-DSA-65 (FIPS 204); both must verify | Quantum-resistant |
| Signed records: ledger blocks, motions, ballots, results, consent, manifests | Ed25519 and ML-DSA-65 with a quantum-resistant key (`generateSigningKey({ pq: true })`) | Quantum-resistant when such a key is used |
| Account and device signatures on messages | ECDSA P-256 | Classical. Forging needs a quantum computer at the time, not a recording; moving to hybrid needs every device to re-certify. Next. |
| Private tokens (CVP-013) | VOPRF on P-256 | Unlinkability doesn't rest on any hardness assumption; forging a token is classical. No standardised post-quantum VOPRF exists yet. |
| Symmetric encryption and hashes | AES-256-GCM, SHA-256, HKDF | Adequate against known quantum attacks |

Everything post-quantum is hybrid: the classical algorithm stays alongside, so a flaw found in
a new algorithm doesn't make anything weaker than it was.

## The sealed relay

A site publishes relay keys in its site document:

```
"pq": { "suite": "p256-mlkem768+mldsa65", "kem": "<P-256 public>.<ML-KEM-768 public>", "sig": "<ML-DSA-65 public>" }
```

Sending to a site that publishes them, a site MUST:

1. seal the request body for that site, bound to `from \n to \n path` (it won't open as any
   other request), and send `{"sealed": "..."}` with the header `CV-Sealed: 1`;
2. sign the usual signature base (CVP-005, which covers the digest of the sealed body) with
   Ed25519 (`CV-Signature`) and ML-DSA-65 (`CV-PQ-Signature`).

The receiving site verifies both signatures before opening, then answers `{"sealed": "..."}`
under the one-time reply key from inside the request.

Relay keys are pinned with the site's Ed25519 key on first contact. A site may start publishing
relay keys; once it has, other sites refuse it if the keys change or disappear (until an admin
accepts the change), and refuse unsealed or singly-signed requests from it. So an attacker who
can break the classical parts can't talk a site back down to them.

"End to end" here means site to site: nothing between the two sites (network, CDN, hosting
platform proxy) can read or alter a relayed request. The two sites themselves still see what
they need to route it, as before; message content stays readable only on people's devices.
