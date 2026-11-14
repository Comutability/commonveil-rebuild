# CVP-020: Repositories and sync

| | |
| --- | --- |
| Status | Draft |
| Version | 1 |
| Feature | `cvp.repos` (version 1) |
| Depends on | CVP-002, CVP-017, CVP-018 |
| Code | `src/social/repo.js`, `src/social/site.js` (reference site) |
| Proposed in | [SNIP-0005](../snips/SNIP-0005.md) |

## Summary

An actor's public activities, kept as one signed set: a **repository**. Anyone who gets a copy,
from the actor's site, a mirror, a search service or a friend, can check that it is complete and
exactly what the actor published. An actor who moves to another site (CVP-017) takes it with
them. This is the idea behind the AT Protocol's repositories, applied to our keys: commits are
signed with Ed25519 and ML-DSA-65, and a repository only ever holds public activities. Encrypted
activities live on people's devices (CVP-019) and are never in one.

## Definitions

- **Record**: a signed public activity (CVP-018): one addressed to `public`.
- **Record id**: the CVP-002 record id of that signed activity.
- **Commit**: a signed statement of exactly which records are in the repository.
- **Head**: the latest commit.

## Specification

### 1. The Merkle root

The records are kept in the order they were added. With `id_i` the record ids as UTF-8:

```
leaf(id)        = SHA-256( "secure-net/repo/v1/leaf"  || 0x0a || id )
node(l, r)      = SHA-256( "secure-net/repo/v1/node"  || 0x0a || l || r )
root([])        = SHA-256( "secure-net/repo/v1/empty" || 0x0a )
root([h])       = h
root(h_0..h_n-1) = node( root(h_0..h_k-1), root(h_k..h_n-1) )     k = the largest power of two below n
```

(the tree shape of RFC 6962). An **inclusion proof** for record `i` is the list of sibling hashes
from its leaf up to the root, in base64url. It lets someone holding one record and a head check
that the record is in the repository without the rest.

### 2. Commits

A commit is a signed record of kind `repo.commit`, signed by a device of the actor:

| Member | Type | Meaning |
| --- | --- | --- |
| `v` | 1 | Version |
| `actor` | string | The actor id |
| `device` | string | The signing device's key id; MUST equal `sig.kid` |
| `seq` | integer | 1 for the first commit, then one more each time |
| `prev` | string or null | The record id of the previous commit |
| `root` | string | The Merkle root of the record ids, base64url |
| `count` | integer | How many records |
| `at` | integer | When (milliseconds) |

A device makes a commit whenever it adds a record (a new public activity) or removes one. After a
`Delete`, the deleted activity is removed, so the next root no longer covers it and honest copies
drop it. A repository holds at most 100,000 records.

### 3. Checking a repository

A repository is exchanged as `{ v: 1, actor: <actor document>, head: <commit>, records: [...] }`.
A receiver MUST refuse it unless:

1. the actor document verifies (CVP-017) and is the actor asked for;
2. the head verifies under a device that spoke for the actor at `at`, with a quantum-resistant
   key, and its `seq` is at least the highest the receiver has seen for this actor;
3. there are exactly `count` records, each a valid public activity of that actor (CVP-018);
4. the Merkle root of their record ids, in order, equals `root`.

### 4. Serving and following repositories

- `GET <repo>` (default `/cvp/v2/repo/{actor}`): the repository of an actor the site hosts.
- `GET <changes>?cursor=<n>` (default `/cvp/v2/changes`): `{ cursor, commits: [{ actor, head }] }`,
  the commits the site has accepted since a cursor, in order. Mirrors, search services and feed
  builders follow this, fetch the repositories that changed, and check them as in section 3. It
  plays the part of the AT Protocol's firehose.

A site MUST check a repository as in section 3 before accepting it from its own actor, and MUST
refuse a head whose `seq` isn't higher than the one it holds. Anyone MAY mirror and re-serve a
repository: it carries its own proof.

### 5. Moving

When an actor moves (CVP-017, section 5), its client publishes the same repository to the new
site. Nothing in it names a site, so every signature still verifies.

## Security and privacy

- **Protected.** A copy of a repository can't have records added, altered, dropped or reordered
  by whoever serves it without failing the check, and can't be rolled back for someone who has
  seen a later head. Signatures are Ed25519 and ML-DSA-65.
- **Not protected.**
  - Everything in a repository is public, and stays in any copy made before it was deleted.
    Deleting removes a record from honest copies only.
  - A site can serve an old head to someone who has never seen a newer one, or refuse to serve.
  - The record count and the times of commits are public.
  - A compromised device can commit as the actor until it is removed from the device list.

## Conformance

[`vectors/cvp-020-v1.json`](vectors/cvp-020-v1.json): reproduce every root and proof; accept
`repository.export` at `repository.now`; refuse every `mustRefuse` repository. The roots have been
reproduced by a separate implementation in Python written from section 1. Tests:
`test/social.test.mjs`.

## Changes

| Version | Date | SNIP | Change |
| --- | --- | --- | --- |
| 1 | 2026-11-14 | SNIP-0005 | First version |
