# CVP-017: Actors and discovery

| | |
| --- | --- |
| Status | Draft |
| Version | 1 |
| Feature | `cvp.actors` (version 1) |
| Depends on | CVP-002, CVP-016 |
| Code | `src/social/actor.js` |
| Proposed in | [SNIP-0005](../snips/SNIP-0005.md) |

## Summary

Who is who in the social protocol (CVP-017 to CVP-019). An **actor** is anyone or anything that
posts, follows or is followed: a person, a group, an organisation, a service or an app, as in
ActivityPub. Unlike ActivityPub, an actor isn't a URL a server controls: it is a
quantum-resistant key, and its **actor document** is signed by that key. A site hosts actors and
serves their documents, but can't forge, alter or take one over.

## Definitions

- **Account key**: an Ed25519 + ML-DSA-65 signing key (CVP-002). Classical-only keys MUST NOT be
  used for actors.
- **Actor id**: the key id (CVP-002, section 2) of the account key: 22 base64url characters.
- **Handle**: `name@host`, written `@name@host` to people. `name` is lower case, matching
  `^[a-z0-9_]([a-z0-9_.-]{0,62}[a-z0-9_])?$`; `host` is the actor's site.
- **Device list**: the CVP-016 `session.device-list` record signed by the account key.

## Specification

### 1. Actor documents

An actor document is a signed record (CVP-002) of kind `actor.document`, signed by the actor's
account key, with this body:

| Member | Type | Meaning |
| --- | --- | --- |
| `v` | 1 | Version |
| `type` | string | `Person`, `Group`, `Organization`, `Service` or `Application` (registry: actor types) |
| `id` | string | The actor id. MUST equal the key id of `account` |
| `handle` | string | `name@host`, lower case |
| `account` | string | The account public key (`<Ed25519>.<ML-DSA-65>`) |
| `seq` | integer | Starts at 1 and goes up with every change |
| `devices` | record | The current device list (CVP-016) |
| `former` | array | Devices removed from the list: `{ kid, sign, until }`, at most 200, where `until` is when the device stopped speaking for the actor (milliseconds) |
| `discoverable` | boolean | Whether the actor wants to be listed and searchable |
| `updated` | integer | When this version was made (milliseconds) |
| `name` | string, optional | Display name, at most 200 characters |
| `summary` | string, optional | Profile text, at most 2,000 characters |
| `icon` | object, optional | An attachment reference (CVP-018, 3.4) for the avatar |

A receiver MUST refuse an actor document unless:

1. it verifies under its own `account` key, which is quantum-resistant, and `id` is that key's id;
2. `devices` verifies as a CVP-016 device list for the same account key;
3. each `former` entry's `kid` is the key id of its `sign`;
4. `type` is registered, `handle` is well formed, and `seq` and `updated` are integers;
5. `seq` is at least the highest it has seen for this actor (no rollback);
6. if it was fetched by handle, `handle` equals the handle asked for; if by id, `id` equals the id
   asked for.

### 2. Which devices speak for an actor

A device speaks for an actor at time `t` if it is on the current device list, or if it is in
`former` and `t` is before its `until`. Activities (CVP-018) are checked against this. A device
that is lost or compromised is moved to `former` with `until` set to when it was lost, so what it
signed before still verifies and anything later doesn't.

### 3. Discovery

To find an actor by handle, a client asks the handle's host:

```
GET https://<host><actor endpoint>?handle=<name>
GET https://<host><actor endpoint>?id=<actor id>
```

The actor endpoint defaults to `/.well-known/commonveil/actor` and may be moved in the site
document (CVP-005); the response is the actor document as JSON. This plays the part of
WebFinger plus the actor object in ActivityPub, in one request.

A site MUST give each handle name to one actor at a time, and MUST NOT serve a document whose
handle names a different host.

### 4. Prekeys

Each device of an actor publishes CVP-016 prekeys to the actor's site. Anyone may ask for a
bundle:

```
POST https://<host><prekeys endpoint>    with {actor} and {device} filled in
```

(default `/cvp/v2/prekeys/{actor}/{device}`). The site answers with one bundle (CVP-016,
"Bundles") and MUST NOT give out the same one-time prekey twice. POST is used because the answer
changes what the site holds.

### 5. Pinning

Clients MUST remember, for each actor id they have talked to, the highest `seq` seen. Because an
actor id is its key, a site cannot substitute a different key for an id. It can only claim that a
handle now belongs to a different id. Clients MUST show when a handle they knew resolves to a
different id, and SHOULD offer the safety number (CVP-016) for checking.

### 6. Moving to another site

An actor's id, keys, followers and sessions don't depend on its site, so an actor can move and
keep all of them (as an AT Protocol account can, and an ActivityPub one can't). To move:

1. The client makes a new actor document with the new handle and a higher `seq`, and publishes it,
   its prekeys and its repository (CVP-020) to the new site.
2. It gives the new document to the old site. The old site checks it (same id, higher `seq`,
   handle elsewhere), stops hosting the actor, and from then on answers lookups for the old
   handle or the id with `{ "moved": <the new actor document> }`. It MUST NOT give the old handle
   name to a different actor.
3. The client sends `Update` of its actor (CVP-018), with the new document, end to end to its
   followers and everyone it follows. Their clients then deliver to the new site.

A client that receives `moved` MUST verify the document, fetch the actor by id from the site in
its handle, and accept the move only if that site serves the same actor. The old site SHOULD keep
answering `moved`, and forward mailbox items, for at least 30 days. An old site that refuses to
co-operate can't stop a move: step 3 reaches everyone the actor already knows without it.

Changing the account key itself (a new actor id) is a `Move` activity (CVP-018) signed by a device
of the old actor. In version 1 clients show it and let people follow the new actor themselves.
Recovering an actor whose account key is lost is not part of this version.

## Security and privacy

- **Protected.** Actor documents can't be forged or altered by any site, including the actor's
  own: they are signed with Ed25519 and ML-DSA-65. Rolling back to an older document (to bring
  back a removed device) is refused.
- **Not protected.**
  - A site can bind a handle to the wrong actor, or answer `moved` falsely for one it hosted. On first contact a client has no way to tell;
    after that, it notices the id has changed. People compare safety numbers to be sure.
  - Actor documents are public: anyone can see an actor's handle, display name, profile text and
    how many devices it has.
  - Fetching an actor document tells the host who is asking (by network address) and whom they
    are looking for.
  - A device that is lost before it is moved to `former` can sign as the actor until it is.
    A compromised device can also backdate what it signs to before its `until`. Receivers can't
    detect this from the signature alone.

## Conformance

[`vectors/cvp-017-v1.json`](vectors/cvp-017-v1.json):

- `actor.record` MUST be accepted when looked up as `lookedUpAs`, and gives `actorId`.
- Every `mustRefuse` record MUST be refused, under the conditions given (`lookup`, `minSeq`).

The keys are made from fixed seeds and listed, so an implementation can rebuild every record.
Tests: `test/social.test.mjs`.

## Changes

| Version | Date | SNIP | Change |
| --- | --- | --- | --- |
| 1 | 2026-11-14 | SNIP-0005 | First version |
