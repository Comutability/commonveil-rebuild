# CVP-018: Activities and objects

| | |
| --- | --- |
| Status | Draft |
| Version | 1 |
| Feature | `cvp.activities` (version 1) |
| Depends on | CVP-002, CVP-017 |
| Code | `src/social/vocabulary.js`, `src/social/activity.js` |
| Proposed in | [SNIP-0005](../snips/SNIP-0005.md) |

## Summary

What actors say to each other: posting, replying, following, liking, sharing, reporting. The
vocabulary is ActivityStreams 2.0's (the one ActivityPub uses), so the names and meanings will be
familiar and a bridge can translate them one to one. The encoding is not: activities are plain
canonical JSON (CVP-002) with one fixed shape for every field, no JSON-LD, integer times, and
identifiers derived from keys. And every activity is **signed on the device that made it** with
Ed25519 and ML-DSA-65, so it can be checked wherever it goes, including after it has been
decrypted on someone's device.

## Definitions

- **Activity**: something an actor does (`Create`, `Follow`, `Like`...), carrying an object.
- **Object**: something an activity is about (`Note`, `Image`, `Event`...).
- **Object id**: `<actor id>:<random>`, where the random part is 16 to 64 base64url characters
  (22 recommended: 16 random bytes). Every object and activity id starts with its author's actor id,
  so ownership is visible in the id itself and can't be claimed by anyone else.
- **Address**: `public`, `followers`, an actor id, or a group id (`group:<random>`).
- **Encrypted**: the activity travels in a direct or audience envelope (CVP-019); otherwise it is
  public.

## Specification

### 1. Activities

An activity is a signed record of kind `social.activity`, signed by a device's quantum-resistant
signing key, with this body:

| Member | Type | Meaning |
| --- | --- | --- |
| `type` | string | A registered activity type (section 2) |
| `id` | string | An object id owned by `actor` |
| `actor` | string | The actor id |
| `device` | string | The signing device's key id; MUST equal `sig.kid` |
| `published` | integer | Milliseconds since 1970 |
| `to`, `cc` | arrays of addresses | Who it is for. At least one address in total, at most 1,000 |
| `object` | object or string | What it is about; its form depends on `type` (section 2) |
| `target` | string | For `Move`, `Add` and `Remove` |
| `content` | string | For `Flag`: the reason, at most 2,000 characters |

The canonical body MUST NOT exceed 256 KiB. Members not listed are allowed (CVP-000, 5.1):
receivers keep them and ignore them.

A receiver MUST refuse an activity unless:

1. `actor` is the actor whose document (CVP-017) it is checked against;
2. `device` spoke for that actor at `published` (CVP-017, section 2), its key is
   quantum-resistant, and both signatures verify;
3. `published` is no more than 5 minutes in the future by the receiver's clock;
4. it follows every rule in sections 2 and 3, for the way it travelled (encrypted or public).

### 2. Activity types

| Type | `object` | Meaning and side effects (applied by the receiving client) |
| --- | --- | --- |
| `Create` | an object (section 3) | A new post, reply, event or poll |
| `Update` | an object of the actor's, or the actor (`{ type, id }` with `id` = actor) | A changed post (same `id`), or a changed profile: fetch the new actor document |
| `Delete` | an object id of the actor's | Remove it; show a tombstone |
| `Follow` | an actor id | Ask to follow. The followed actor's client answers with `Accept` or `Reject` |
| `Accept`, `Reject` | the id of the `Follow` | Answer a follow. An `Accept` comes with the followers audience key (CVP-019) |
| `Undo` | an activity id of the actor's | Take back a `Follow`, `Like`, `Announce` or `Block` |
| `Like` | an object id | Like it. Only the author's clients count likes |
| `Announce` | an object id | Share (boost) it. Only public objects can be shared beyond their audience |
| `Add`, `Remove` | an object id; `target`: a group or collection id | Add to or remove from a group or collection |
| `Block` | an actor id | Stop seeing them. Clients MUST NOT deliver a Block to the blocked actor; they remove them from their audiences (CVP-019) |
| `Flag` | an object id or actor id | Report it, with `content` as the reason, to the moderators it is addressed to |
| `Join`, `Leave` | a group id | Join or leave a group |
| `Invite` | an actor id | Invite someone into a group (`target`) |
| `Move` | the old actor id; `target`: the new actor id | The actor has moved (CVP-017, section 5) |

`Delete`, `Update` and `Undo` MUST only act on the actor's own objects and activities: a receiver
MUST refuse one whose object id belongs to another actor. A receiver MUST NOT apply an activity
type it doesn't know.

### 3. Objects

#### 3.1 Common members

| Member | Type | Meaning |
| --- | --- | --- |
| `type` | string | A registered object type |
| `id` | string | An object id owned by the activity's actor |
| `attributedTo` | string | MUST equal the activity's `actor` |
| `published`, `updated` | integer | Milliseconds |
| `content` | string | At most 50,000 characters |
| `mediaType` | string | `text/plain` or `text/markdown` (clients MUST NOT render HTML from content) |
| `name` | string | Title, at most 200 characters |
| `summary` | string | Content warning, at most 500 characters |
| `sensitive` | boolean | Hide media until the reader chooses to see it |
| `language` | string | BCP 47 tag |
| `inReplyTo` | object id | The post this replies to |
| `context` | object id or group id | The conversation or group it belongs to |
| `attachment` | array, at most 20 | Attachment references (3.4) |
| `tag` | array, at most 100 | `{ type: "Mention", href: <actor id> }` or `{ type: "Hashtag", name: "#word" }` |

#### 3.2 Types

`Note` (a short post), `Article`, `Page`, `Document`, `Image`, `Video`, `Audio`, `Place`,
`Tombstone` (what remains of a deleted object: `type`, `id`, `attributedTo` only), and:

- `Event`: `startTime` (integer, required), `endTime`;
- `Question` (a poll): `oneOf` or `anyOf` (not both), 2 to 50 options of `{ type: "Note", name }`,
  and `endTime`. Votes are `Create`s of a `Note` whose `name` is the option and `inReplyTo` is the
  question, sent directly to the author.

An object's `type` may also be an **extension type** named by a reverse domain name
(`org.example.recipe`), defined by a lexicon (CVP-021). It follows every rule in 3.1, and
receivers that don't know it show it as a plain post.

#### 3.3 Times and numbers

All times are integer milliseconds since 1970 UTC, and every number is an integer, so that
activities have exactly one canonical form (CVP-002).

#### 3.4 Attachment references

Files are stored outside activities and referenced:

```
{ type: "Image" | "Video" | "Audio" | "Document", url: "https://...", mediaType, size, sha256,
  key?, name?, width?, height? }
```

`sha256` is the base64url SHA-256 of the stored bytes; clients MUST check it. In an **encrypted**
activity the stored file MUST itself be encrypted with AES-256-GCM under a fresh random key, given
in `key` (base64url, 32 bytes), with the first 12 stored bytes as the nonce and no associated data,
so the file store sees only ciphertext. In a **public** activity `key` MUST NOT appear. `name` is the
description for people who can't see the file, and clients SHOULD ask for one.

### 4. Addressing

`to` and `cc` say who an activity is for, as in ActivityStreams. `public` means anyone, and an
activity addressed to `public` MUST travel in a public envelope, never encrypted (CVP-019), so
that "public" means the same thing to everyone who handles it. `followers` means the author's
followers. Actor ids and group ids mean those actors or group members. Inside encrypted
envelopes, addresses tell recipients' clients who else received the activity; they are not used
for routing (CVP-019 routes by envelope).

### 5. Relation to ActivityPub and the AT Protocol (informative)

What this protocol takes from each, and where it differs from both:

| | ActivityPub | AT Protocol | Here |
| --- | --- | --- | --- |
| Vocabulary | ActivityStreams | Lexicons | ActivityStreams names, plus lexicons for new object types (CVP-021) |
| Identity | A URL on a server | A DID, with a handle pointing to it | A quantum-resistant key's id, with a handle pointing to it (CVP-017) |
| Moving servers | Followers only, with the old server's help | Yes | Yes, keeping id, keys, followers and sessions (CVP-017) |
| Public data | Fetched object by object | Signed repositories and a firehose | Signed repositories and a change feed (CVP-020) |
| Who signs | The server, for the actor | The account's signing key | The actor's own devices, with Ed25519 and ML-DSA-65 |
| Private posts and messages | Readable by servers | Repositories are public; private data is still being designed, and end-to-end encrypted messaging comes from separate apps (as of November 2026) | Part of the protocol: end to end encrypted, post-quantum, to followers, groups or individuals (CVP-019) |
| Delivery | Server inboxes | Relays and app views read everything public | Sealed envelopes to mailboxes; only public posts are readable |

In detail, against ActivityPub:

| ActivityPub | Here | Why |
| --- | --- | --- |
| JSON-LD with `@context` | Plain canonical JSON | One encoding to sign; no remote contexts to fetch |
| `id`: a URL on the server | `<actor id>:<random>` | Encrypted objects can't be fetched from a server, and an id shouldn't depend on one |
| `as:Public` | `public` | Shorter; same meaning |
| `followers` collection URL | `followers` | The followers list is kept by the author's clients, not published (CVP-019) |
| `published`: date-time string | integer milliseconds | No second spelling of the same time |
| HTTP Signatures by the server, for the actor | Signatures by the actor's device, on the activity itself | The server can't speak for the actor, and the signature survives forwarding and decryption |
| HTML `content` | `text/plain` or `text/markdown` | Nothing to sanitise, nothing to inject |

A bridge to ActivityPub or the AT Protocol (CVP-009, reserved) could carry public activities both
ways by mapping these names. It could never carry encrypted ones, because servers on those
networks read everything they carry.

## Security and privacy

- **Protected.** Who wrote an activity, and that it hasn't been changed, against anyone without
  the device's key, using Ed25519 and ML-DSA-65. That includes the sites that carry it and the
  recipients who might pass it on. Ownership of ids can't be faked.
- **Not protected.**
  - A signed activity is proof of what someone said, to anyone it is shown to. This is
    deliberate, since moderators need to check reports. But people can't later deny what they
    signed, even in direct messages. A future version may offer deniable direct messages.
  - `published` is the signer's own claim, checked only against the future.
  - Public activities, and everything in them, are public.

## Conformance

[`vectors/cvp-018-v1.json`](vectors/cvp-018-v1.json):

- each of the `examples` MUST be judged valid or invalid as stated, when travelling encrypted
  or not as stated;
- `signed.record` MUST verify against the actor document in `cvp-017-v1.json` at `signed.now`.

Tests: `test/social.test.mjs`.

## Changes

| Version | Date | SNIP | Change |
| --- | --- | --- | --- |
| 1 | 2026-11-14 | SNIP-0005 | First version |
