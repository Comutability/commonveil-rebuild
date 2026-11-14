# CVP-010: Conformance

| | |
| --- | --- |
| Status | Draft |
| Version | 1 |
| Feature | none |
| Depends on | CVP-000 |
| Code | `test/`, `scripts/vectors.mjs`, `scripts/standards.mjs` |
| Proposed in | [SNIP-0004](../snips/SNIP-0004.md) |

## Summary

How an implementation shows that it keeps to the protocol: which groups of parts (**profiles**)
make sense to implement together, what each requires, and the **conformance statement** an
implementation publishes so others know what to expect from it. Anyone may write an
implementation, in any language, and say it conforms, provided they say it in this form.

## Definitions

- **Implementation**: software that sends or receives anything defined in a part (a site, an app,
  a library).
- **Profile**: a named set of parts, listed in the registry (`profiles`).
- **Release**: a Secure Net release, which fixes the documents, registries and vectors (CVP-000, 4.1).

## Specification

### 1. Profiles

| Profile | Parts | For |
| --- | --- | --- |
| `core` | CVP-002 | Anything that creates or checks signed records. Every other profile includes it. |
| `messaging` | CVP-002, CVP-016 | Apps that send end-to-end encrypted messages |
| `site` | CVP-002, CVP-005, CVP-008, CVP-015 | Servers that talk to other sites |
| `community` | CVP-002, CVP-004, CVP-011 | Sites that host or mirror communities |
| `governance` | CVP-002, CVP-011, CVP-012, CVP-013 | Motions, debates and ballots |
| `extensions` | CVP-002, CVP-008, CVP-014 | Hosts that run extensions or honour consent capsules |
| `commonveil-compatible` | CVP-001, CVP-002, CVP-003, CVP-005 | Talking to today's Commonveil sites before they move to CVP-016 |

The registry is the authoritative list; this table is a copy for reading.

### 2. What conforming to a profile means

An implementation conforms to a profile, at a release, when for **every** part in the profile:

1. it meets every MUST and MUST NOT in the part that applies to the roles it plays (sender,
   receiver, site, app);
2. it passes that part's vectors, where it has any (`spec/vectors/`);
3. it refuses everything the part says to refuse, with no option that turns the refusal off by
   default;
4. if the part has a feature, it announces that feature at the version it implements (CVP-008),
   and announces nothing it doesn't implement.

Partial conformance can't be claimed for a part: either all of a part, or say "not implemented".
An implementation MAY implement more than a profile, and MAY add things under `x-` names
(CVP-000, section 7) that never cross between sites run by different people.

**SHOULD** requirements are not needed to conform, but a conformance statement MUST list any
SHOULD it deliberately doesn't follow, with the reason.

### 3. Roles

Some parts have separate requirements for senders and receivers. A statement says which roles it
claims, per part: `send`, `receive`, or both. A receiver that can't send still conforms as a
receiver.

### 4. Conformance statements

An implementation that claims conformance publishes a statement, as JSON, in its repository or
release files as `secure-net-conformance.json`. A site MAY also serve it at a URL of its choosing;
a fixed location for sites would need registering first (CVP-000, section 7).

```json
{
  "implementation": "Example Server",
  "version": "2.3.0",
  "source": "https://example.org/example-server",
  "licence": "AGPL-3.0-only",
  "release": "0.4.1",
  "profiles": ["core", "site"],
  "parts": {
    "CVP-002": { "roles": ["send", "receive"], "vectors": ["cvp-002-v1.json"] },
    "CVP-005": { "roles": ["send", "receive"] },
    "CVP-008": { "roles": ["send", "receive"] },
    "CVP-015": { "roles": ["send", "receive"] }
  },
  "features": { "cvp.federation": 2, "cvp.sealed-relay": 1, "cvp.pq-signatures": 1 },
  "deviations": [
    { "part": "CVP-015", "requirement": "SHOULD ...", "reason": "..." }
  ],
  "tested": { "date": "2026-11-13", "how": "Ran every vector in spec/vectors/cvp-002-v1.json; interoperated with Secure Net 0.4.1 over CVP-005" },
  "contact": "security@example.org"
}
```

`release` is the Secure Net release whose documents, registries and vectors were used. `deviations`
lists any SHOULD not followed (a MUST not followed means the profile isn't met). `tested` says
what was actually run: claims without it are not conformance statements.

The statement is published information, not an endorsement: until an independent conformance
suite and a process for checking claims exist (section 6), conformance is **self-declared**.
Comutability does not certify implementations.

### 5. The reference implementation

The reference implementation (Secure Net) implements every profile above. Its tests (`npm test`)
cover each part, and CI checks that its vectors and registries match its code
(`node scripts/vectors.mjs --check`, `node scripts/standards.mjs`). Its statement is
`secure-net-conformance.json` in the repository root.

Where a part has no document yet (the registry lists them), the reference code and its tests are
for now the only definition of that part, so "conforms" can only mean "behaves like the reference".
Writing those documents is what turns the reference into a standard others can check against.

### 6. Still to do

- **An implementation-independent test runner.** Today the vectors are language-neutral but the
  behavioural tests are JavaScript. A runner that drives any implementation over HTTP (sites) or a
  small command-line adapter (libraries) would let others test themselves the same way.
- **Vectors for every part.** Only CVP-002 and CVP-016 have them so far; the registry lists which
  parts are missing theirs.
- **Interoperability events**: two independent implementations talking to each other in public,
  which is also what moves a part to Stable (CVP-000, 3.2).

## Security and privacy

A conformance statement is self-published and can be wrong or false. Nothing in the protocol may
depend on one: implementations MUST still check everything they receive. A statement names the
software and its version, which tells an attacker what to target; a site that would rather not say
need not serve one.

## Conformance

This part is met by publishing a statement in the form of section 4 that is true.

## Changes

| Version | Date | SNIP | Change |
| --- | --- | --- | --- |
| 1 | 2026-11-13 | SNIP-0004 | First version, replacing "CVP-010: conformance tests and vectors: `test/`" |
