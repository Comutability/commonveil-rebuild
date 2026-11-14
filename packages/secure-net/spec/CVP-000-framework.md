# CVP-000: How the standard works

| | |
| --- | --- |
| Status | Draft |
| Version | 1 |
| Feature | none (applies to every part) |
| Depends on | nothing |
| Code | `scripts/standards.mjs` (checks the code against this standard) |
| Proposed in | [SNIP-0004](../snips/SNIP-0004.md) |

The rules every part of the Commonveil Protocol (CVP) follows: how parts are written, numbered
and versioned, what counts as a compatible change, how anything is retired, how shared names are
registered, and what an implementation must do to say it conforms. They exist so the protocol can
change without breaking the sites and apps already using it, and so someone who has never read
our code can build something that works with ours.

## 1. Normative language

MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are
used as described in RFC 2119 and RFC 8174: they carry these meanings only when written in
capitals. Everything else (examples, explanations, notes, "why" sections) is informative.

A requirement applies to the party named in it: a **sender** (whoever makes a record or message),
a **receiver** (whoever checks or opens one), a **site** (a server that stores and relays), or an
**app** (the software a person uses). A requirement that names no party applies to all of them.

## 2. What is normative

In order of authority:

1. The **part documents** in `spec/` (`CVP-NNN-*.md`) and the **registries** (`spec/registry.json`).
2. The **test vectors** in `spec/vectors/`. A vector that disagrees with a part document is a bug
   in one of them; until it is fixed, say so in the part's errata, and implementations SHOULD
   follow the vector, since that is what deployed code does.
3. The **reference implementation** (`src/`) and its tests. Where it disagrees with the documents
   or vectors, that is a bug to be fixed in one of them. It is not a third source of truth.

Accepted SNIPs are the record of why the standard changed; they are not themselves normative
once their content is in the part documents.

## 3. Parts

The protocol is split into numbered parts, `CVP-000` to `CVP-999`. A number is never reused, even
for a part that is withdrawn.

### 3.1 What every part document contains

A part document MUST begin with a header table:

| Field | Meaning |
| --- | --- |
| Status | One of the statuses in 3.2 |
| Version | A whole number, starting at 1 (see 4.2) |
| Feature | The feature name(s) in the registry that announce support for this part, or "none" |
| Depends on | The parts an implementation of this one also needs |
| Code | Where the reference implementation is |
| Proposed in | The SNIP(s) that introduced or last changed it |

and then, in this order (headings may be worded to suit, but the content MUST be there):

1. **Summary**: one paragraph saying what the part is for.
2. **Definitions**: terms not already defined in another part.
3. **Specification**: the wire formats, processing rules and failure behaviour, normatively.
4. **Security and privacy**: what it protects, from whom, and **what it does not**, plainly.
5. **Conformance**: what an implementation must pass, and which vectors apply.
6. **Changes**: a list of versions with the SNIP and date for each.

[`PART-TEMPLATE.md`](PART-TEMPLATE.md) has this layout ready to copy. Parts written before this
framework are being brought into line; the registry records which ones still fall short.

### 3.2 Statuses

| Status | Meaning | May sites depend on it? |
| --- | --- | --- |
| Reserved | Number and subject set aside; no specification yet | No |
| Draft | Written and usually implemented, not yet through Technical Review | No: experimental only, never the only option between sites |
| Proposed | Through Technical Review, decision pending | No |
| Accepted | Accepted by the TSC; wire formats frozen except for errata | Yes, behind its feature flag |
| Stable | Accepted, and implemented independently by at least two implementations that pass its vectors | Yes |
| Deprecated | Still accepted from others, but new implementations SHOULD NOT send it (see 6) | Receive only |
| Withdrawn | No longer part of the protocol | No |

A part's status moves with its SNIP's decisions (GOVERNANCE.md), never by editing the table alone.

## 4. Versions

Four separate things carry versions. They change for different reasons and MUST NOT be confused.

### 4.1 Releases

A **release** of the standard is a Secure Net release: one version number (semantic versioning)
for the documents, registries, vectors and reference code together, recorded as `release` in the
registry. Releases are what applications pin.

| Change | Release version |
| --- | --- |
| Editorial only: wording, typos, examples, informative text | patch |
| Clarification that changes no conforming implementation's behaviour; errata; new vectors for existing behaviour | patch |
| Additive: a new part, feature, record kind, field, label or registry entry that older implementations can safely ignore | minor |
| Breaking: anything an up-to-date implementation and one a release behind would disagree about | major (minor while the major version is 0) |

### 4.2 Part versions

A part's **Version** goes up by one each time its normative content changes (anything above
"editorial"). Editorial changes do not change it.

### 4.3 Feature versions

Sites announce what they speak as **features** (CVP-008): `"cvp.sessions": 1`. A feature's version
goes up when the wire behaviour behind it changes in a way the other side needs to know about.
Two sites use the lower of the two versions they both announce. An implementation MUST ignore
features it doesn't know, MUST NOT treat an unknown feature as an error, and MUST keep speaking a
lower version of a feature it still announces.

### 4.4 Labels inside the cryptography

Every signature, hash and key derivation is separated by a **label** (`secure-net/session/v1/root`,
`secure-net/<kind>/v1`). The `vN` in a label is part of what is signed or derived. A change to what
is signed or derived under a label MUST use a new label (`v2`). A label's meaning MUST NEVER
change once it is in a release, because old signatures and old ciphertexts would silently mean
something else.

## 5. Compatible change

### 5.1 Rules for receivers

- **Unsigned JSON** (site documents, API responses): receivers MUST ignore members they don't
  recognise.
- **Signed records** (CVP-002): a signature covers the whole canonical body. Receivers MUST verify
  over the body exactly as received, MUST keep unknown members when storing or forwarding a
  record, and MUST NOT act on members they don't understand. A part MAY say that a record with a
  particular unknown member must be refused (a "critical" member); if it does, the list of such
  members is part of its specification.
- **Enumerations** (record kinds, ledger events, permissions): a receiver MUST refuse a value it
  doesn't know in any position where accepting it would grant something (a capability, a
  permission, a ledger change), and SHOULD ignore it elsewhere.
- **Limits** (sizes, counts, clock skew): a receiver MUST accept anything within the stated
  limits and MAY refuse anything beyond them.

### 5.2 Rules for changes

A change is **additive** only if every implementation conforming to the previous release keeps
working with it unchanged. In practice that means: new optional fields, new record kinds, new
features, new registry entries, new labels. Anything else is **breaking**, including:

- changing or removing a field, a label, a canonical form or a default;
- making something optional required, or refusing something that used to be accepted;
- changing an algorithm, a key size or a limit in a way older implementations would refuse.

Breaking changes need what GOVERNANCE.md requires: a higher approval threshold and a published
migration plan. Wherever practical, a breaking change is made as an additive one first (a new
feature version or label used only when both sides announce it), then the old way is deprecated.

## 6. Retiring things

Nothing is removed without passing through these stages, each recorded in the registry with the
release it happened in:

1. **Active.**
2. **Deprecated**: implementations SHOULD stop sending it but MUST still accept it. Announced in a
   release's notes with the replacement and the earliest removal date.
3. **Legacy**: implementations MUST NOT send it and MAY refuse it.
4. **Removed**: gone from the registry's active list (the entry stays, marked removed, so the name
   is never reused).

At least **two minor releases and six months** separate Deprecated from Removed, unless the thing
is being removed because it is insecure. A security removal can skip stages; the advisory says
what to do instead.

## 7. Registries

Names that two implementations must agree on are listed in [`registry.json`](registry.json), with a
readable copy in [`REGISTRIES.md`](REGISTRIES.md). Each entry names the part that defines it and
its status (section 6). The registries are:

| Registry | Naming rule | Example |
| --- | --- | --- |
| Parts | `CVP-NNN` | `CVP-016` |
| Features | `cvp.<name>`, lower case, hyphens | `cvp.sealed-relay` |
| Record kinds | `<area>.<name>`, matching `^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$` | `session.prekey` |
| Ledger events and capabilities | as record kinds; capabilities are single words | `member.add`, `members` |
| Extension execution models and permissions | `<verb>.<object>` | `read.selected` |
| Consent actions, vote methods | single lower-case words | `replicate`, `ranked` |
| Algorithm suites | as published on the wire | `Ed25519+ML-DSA-65` |
| Labels | `secure-net/<purpose>/vN[/<sub>]`; `<placeholders>` for variable parts | `secure-net/session/v1/root` |
| Endpoints and paths | absolute paths; `{placeholders}` | `/cvp/v1/inbox` |
| HTTP headers | `CV-<Name>` | `CV-PQ-Signature` |

Rules:

- A registry entry is added, changed or retired only by a SNIP, in the same pull request as the
  part text that defines it and the code that implements it.
- A name, once registered, is never given a different meaning, even after it is removed.
- Names starting `x-` (record kinds, features: `x-example.thing`, `cvp.x-example`) are reserved for
  private experiments. They MUST NOT appear between sites run by different people, and are never
  registered.
- Labels starting `commonveil` belong to the older Commonveil-derived code (`src/crypto`) and are
  registered so they are never reused; new labels MUST start `secure-net/`.

`scripts/standards.mjs` checks the reference code against the registries on every build: a record
kind, feature, ledger event, permission, suite, endpoint or label in the code that isn't
registered (or the other way round, where the code is the only definition) fails the build.

## 8. Test vectors

- Every part that defines a byte format, a signature, a hash, or a key derivation MUST have test
  vectors in `spec/vectors/`, as JSON, named `cvp-NNN-vN.json` (the part and its version).
- Vectors use fixed inputs only (no randomness), say what every field is, and are written by a
  script in `scripts/` so they can be regenerated. CI MUST check that the committed vectors match
  what the reference code produces.
- Where the reference code's own primitives could hide a mistake, vectors SHOULD be checked
  against an independent implementation, and the part says which ones have been.
- Vectors are never edited to make code pass. A changed vector means a changed part version.

## 9. Conformance

[`CONFORMANCE.md`](CONFORMANCE.md) defines **profiles** (sets of parts that make sense to implement
together) and the **conformance statement** an implementation publishes to say which it meets.
Conformance is claimed per profile and per release. Until an independent conformance suite exists,
claims are self-declared and must say which vectors and tests were run.

## 10. Errata

A mistake in a released part that doesn't change what conforming implementations do (a typo in a
formula that the vectors get right, say) is corrected as an erratum: a patch release, a line in
the part's Changes section saying what was wrong, and no part-version change. A mistake whose fix
would change behaviour is a normal change and goes through a SNIP.

## 11. Security fixes

A security problem may be fixed privately first, as GOVERNANCE.md allows. The fix is then published
as a release with an advisory, the part's Changes section and, if the fix is breaking, a SNIP
written after the fact with the migration plan. Being urgent does not exempt a change from human
security review; it only changes the order.

## 12. Writing style

Parts are written in plain British English, for implementers who have not read our code: short
sentences, active voice, one requirement per sentence where possible, every term defined once.
They say what isn't protected as clearly as what is. They don't use em dashes. Byte layouts are
given exactly, including encodings (base64url without padding unless stated, UTF-8, canonical JSON
from CVP-002) and every label in full.

## Changes

| Version | Date | SNIP | Change |
| --- | --- | --- | --- |
| 1 | 2026-11-13 | SNIP-0004 | First version |
