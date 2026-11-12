# Secure Net specifications

The Commonveil Protocol, in parts. Each part says what two implementations must agree on. The
code in `src/` is the reference implementation and the tests in `test/` are its conformance
tests (CVP-010).

| Part | Subject | Status | Code |
| --- | --- | --- | --- |
| CVP-000 | Scope, terms, goals, threat model | This page and INTEROPERABILITY.md | |
| CVP-001 | Identifiers, keys, signatures, rotation, recovery, personas, migration | Implemented | `crypto/identity`, `crypto/recovery`, `identity/portable` |
| CVP-002 | Canonical encoding, signed records, replay protection | Implemented | `core/canonical`, `core/signed` |
| CVP-003 | Direct and group encryption, devices | Implemented (pairwise sealing; MLS is future work) | `crypto/envelope`, `crypto/serverKeys`, `crypto/kem` |
| CVP-004 | Spaces, channels, membership, policy | Implemented in the ledger | `commons/ledger` |
| CVP-005 | Site-to-site federation | Implemented (`commonveil/1`) | `wire/federation` |
| CVP-006 | Attachments, retention, backup | In Commonveil; to move here | |
| CVP-007 | Reports, disclosures, federation controls | In Commonveil; to move here | |
| CVP-008 | Extensions, themes, feature negotiation | Implemented | `extensions/manifest`, `wire/features` |
| CVP-009 | Bridges and labels | Not started | |
| CVP-010 | Conformance tests and vectors | `test/` | |
| CVP-011 | Commons ledger: replication and failover | Implemented | `commons/ledger` ([CVP-011](CVP-011-commons-ledger.md)) |
| CVP-012 | Governance: motions, debates, votes | Implemented | `governance/*` ([CVP-012](CVP-012-governance.md)) |
| CVP-013 | Private tokens (RFC 9497) | Implemented | `tokens/voprf` ([CVP-013](CVP-013-tokens.md)) |
| CVP-014 | Consent capsules | Implemented | `consent/capsule` |

## Goals (CVP-000)

1. **Private by default.** Content is end-to-end encrypted on people's devices. Sites carry
   ciphertext and the least metadata that still lets them deliver it.
2. **No site is trusted with identity.** Keys, not sites, say who someone is. A site can refuse
   or delay, but not forge.
3. **Anyone can run a site, and sites talk.** A person on one site can talk to, and join
   communities on, any other.
4. **Communities outlive their host.** A community's history and rules are signed and can be
   mirrored, so it survives its home site going away (CVP-011).
5. **Say what isn't protected.** Network addresses, timing, membership seen by hosts and
   replicas, and anything a recipient chooses to copy. Interfaces must say so.

## Normative words

MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Where the spec and the reference code
disagree, the disagreement is a bug in one of them, and conformance tests decide.
