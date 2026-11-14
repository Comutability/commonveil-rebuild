# CVP-NNN: Title

<!--
Copy this file to spec/CVP-NNN-short-name.md, take the next free number from spec/registry.json,
and add the part there in the same pull request (status Draft, version 1). Keep the header table
and every section: scripts/standards.mjs checks them. Delete these comments.
Rules for writing parts: CVP-000, section 12. Plain British English, one requirement per sentence,
every byte and label in full, and say plainly what isn't protected.
-->

| | |
| --- | --- |
| Status | Draft |
| Version | 1 |
| Feature | `cvp.name` (version 1), or "none" |
| Depends on | CVP-002, ... |
| Code | `src/area/module.js` |
| Proposed in | [SNIP-NNNN](../snips/SNIP-NNNN.md) |

## Summary

One paragraph: what this part is for, and who needs to implement it.

## Definitions

Terms this part introduces. Terms defined in another part are referenced, not redefined.

## Specification

The normative content, in numbered sections:

- **Formats**: every record kind (registered, signed per CVP-002), message and field, with types,
  limits and encodings.
- **Processing**: what senders do, and what receivers MUST check, in order.
- **Failure**: what happens when a check fails. Failure MUST leave state unchanged unless the part
  says otherwise.
- **Cryptography**: every algorithm, key size and label (registered, `secure-net/<purpose>/v1`).
- **Limits**: sizes, counts, times; what receivers MUST accept and MAY refuse beyond.
- **Compatibility**: how this interacts with older versions, and which members are critical
  (CVP-000, 5.1).

## Security and privacy

What this protects, from whom, and **what it doesn't**: metadata, timing, trust on first use,
anything an attacker with a large quantum computer could do, anything left to apps.

## Conformance

What an implementation must pass: the vectors (`spec/vectors/cvp-NNN-v1.json`, written by a script
in `scripts/`), and which roles (send, receive) have which requirements. Say which vectors have
been checked against an independent implementation.

## Changes

| Version | Date | SNIP | Change |
| --- | --- | --- | --- |
| 1 | YYYY-MM-DD | SNIP-NNNN | First version |
