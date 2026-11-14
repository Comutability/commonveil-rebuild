# CVP-021: Lexicons

| | |
| --- | --- |
| Status | Draft |
| Version | 1 |
| Feature | `cvp.lexicons` (version 1) |
| Depends on | CVP-002, CVP-017, CVP-018 |
| Code | `src/social/lexicon.js`, `src/social/vocabulary.js` |
| Proposed in | [SNIP-0005](../snips/SNIP-0005.md) |

## Summary

How anyone adds a new kind of object (a recipe, a book review, a chess move) without changing
this standard or asking anyone's permission. As in the AT Protocol, a new type is named by a
reverse domain name, and whoever controls that domain publishes its schema, a **lexicon**. Here a
lexicon is a signed record from that domain's `lexicons` actor. Apps that know a lexicon check objects
against it. Apps that don't still show the object as an ordinary post.

## Definitions

- **Extension type**: an object `type` that is a reverse domain name of three or more segments,
  lower case, at most 200 characters: `org.example.recipe`.
- **Authority**: the domain an extension type belongs to: all but the last segment, reversed
  (`example.org`).

## Specification

### 1. Extension objects

An object (CVP-018, section 3) whose `type` is an extension type:

- MUST satisfy every rule for the common members (`id`, `attributedTo`, `published`, `content`,
  `name`, `attachment` and the rest), exactly as a registered type does;
- MAY carry further members, defined by its lexicon.

A receiver that doesn't know the lexicon MUST still accept the activity, MUST NOT act on the
members it doesn't understand, and SHOULD show `name`, `content` and attachments as it would for
a `Note`, with the type's name. Authors SHOULD therefore put a readable form in `content`.

Extension types are for objects only. Activity types and actor types are fixed by this standard,
because they have side effects every implementation must agree on.

### 2. Lexicons

A lexicon is a signed record of kind `lexicon.schema`, signed by an actor's account key:

| Member | Type | Meaning |
| --- | --- | --- |
| `v` | 1 | Version |
| `id` | string | The extension type |
| `revision` | integer | Starts at 1 and goes up |
| `description` | string, optional | At most 1,000 characters |
| `fields` | object | At most 50 fields: name to field definition |

Field names match `^[a-z][A-Za-z0-9]{0,39}$` and MUST NOT be a common member's name. A field
definition is `{ type, required?, min?, max?, items? }`:

| `type` | Value | `min` / `max` |
| --- | --- | --- |
| `string` | text | `max`: characters (default 10,000) |
| `integer` | a safe integer | smallest and largest value |
| `boolean` | true or false | |
| `id` | an object id | |
| `actor` | an actor id | |
| `array` | a list of `items` (any type but `array`) | `max`: entries (default 100) |

A receiver MUST refuse a lexicon unless it is signed by the account key of the actor whose handle
is **`lexicons@<the type's authority>`**, and its `revision` is at least the highest seen for that
type. A site MUST reserve the handle name `lexicons` for its operator, so that ordinary users of a
site can't define types for its domain. The authority's site serves lexicons at `GET <lexicon>`
(default `/cvp/v2/lexicon/{id}`).

### 3. Checking an object against its lexicon

An object is valid under a lexicon when every required field is present, every present field has
the right type and limits, and it has no members other than the common ones and the lexicon's
fields. An app that knows the lexicon SHOULD show an invalid object as a plain post instead of
with its special interface.

### 4. Changing a lexicon

A new revision MUST only add optional fields or relax limits, so objects valid under an older
revision stay valid (CVP-000, section 5). Anything else is a new type: `org.example.recipe2`.

## Security and privacy

- **Protected.** Only the domain's `lexicons` actor can define or change a type, checked with Ed25519
  and ML-DSA-65. A lexicon can't be rolled back for someone who has seen a later one.
- **Not protected.**
  - Authority rests on the handle `lexicons@<domain>`, so whoever controls that domain's site
    controls its types, and losing the domain loses them. A site that hands `lexicons` to an
    ordinary user hands them its types. The reference site doesn't enforce the reservation.
  - A lexicon limits shapes and sizes, not meaning: an app decides what to do with a field.
  - Fetching a lexicon tells its site which types an app is interested in.
  - Extension fields in public activities are public; in encrypted ones they are encrypted with
    the rest.

## Conformance

[`vectors/cvp-021-v1.json`](vectors/cvp-021-v1.json): accept `lexicon` from `publisher`; refuse it
from `notPublisher` and from the same key's actor on another domain; judge each of `objects` valid or invalid as stated.
Tests: `test/social.test.mjs`.

## Changes

| Version | Date | SNIP | Change |
| --- | --- | --- | --- |
| 1 | 2026-11-14 | SNIP-0005 | First version |
