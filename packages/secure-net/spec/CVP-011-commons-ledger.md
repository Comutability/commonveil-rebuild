# CVP-011: The Commons ledger

| | |
| --- | --- |
| Status | Draft |
| Version | 1 |
| Feature | `cvp.commons-ledger` (version 1) |
| Depends on | CVP-002 |
| Code | `src/commons/ledger.js` |
| Proposed in | none (written before the proposal process; recorded in [SNIP-0004](../snips/SNIP-0004.md)) |

A community's history as a chain of signed blocks that any approved site keeps a full copy of.
If the community's home site goes down, a copy keeps it running. If the home site is gone for
good, the community moves to a copy and keeps its id, history and members.

## Why a chain, and why not a blockchain

The useful properties of a blockchain are that history can't be rewritten quietly and that every
copy can check everything itself. Those are kept. What isn't needed: mining, tokens, fees and one
global chain everyone shares. Each community has its own chain, and **who may write is decided by
the community's own keys**, not by computing power or stake. That makes it cheap, fast, private
to the community, and impossible for outsiders to take over.

## Blocks

A block is a signed record (CVP-002) of kind `commons.block`:

```
body: { community, height, prev, epoch, at, events: [ { type, ... }, ... ] }
sig:  the author's signature
cosigs: further signatures, for changes that need several
```

- `community` is the id of the first block (`""` in the first block itself).
- `height` counts from 0. `prev` is the id of the block before (`""` for the first).
- A block's id is the SHA-256 of exactly what was signed.
- `epoch` counts changes of authority. A block MUST carry the current epoch: anything prepared
  under an old authority is refused.
- `at` is the author's clock. It is information only and MUST NOT decide anything.

## Who may write what

Keys have capabilities: `authority` (everything), `govern`, `members`, `roles`, `moderate`,
`channels`, `content`. The first block names the community's keys, its authority threshold, its
home site, its replicas and their succession order, and its policy.

| Events | Needs |
| --- | --- |
| `keys.set`, `replicas.set`, `policy.set`, `host.move` | `threshold` distinct authority signatures. Starts a new epoch (`keys.set`, `host.move`). If the policy says `authority_change: "vote"`, also a passed vote for exactly this change (CVP-012). |
| `governance.result` | `govern` (the result must be signed by one of the community's keys) |
| `member.add`, `member.remove` | `members` (anyone may remove themselves) |
| `role.set` / `ban.set` / `channel.set`, `channel.remove` | `roles` / `moderate` / `channels` |
| `content.ref`, `note` | `content`: every member has it |

The home site and replicas hold `members` and `content` by default, so they can admit people with
valid invitations and carry messages, but never change who's in charge.

## What's in the clear

Structure (members' key ids, roles, channel ids, which sites host) is readable by every copy, so
any copy can enforce the rules. Content is only ever ciphertext (`sealed`), so no copy can read
it. A replica therefore learns who's in the community. Communities SHOULD choose replicas run by
people they'd trust with their member list, and clients MUST say so when someone joins.

## Copies and catching up

A copy is checked from the first block, every time it's received. `reconcile(local, remote)`
brings a copy up to date:

- Where they agree, nothing changes. Where one is simply longer, the extra valid blocks are added.
- A copy is good only up to its first invalid block.
- Where they split, every site chooses the same branch: more authority signatures on the first
  differing block, then the longer valid branch, then the lower block id. Never the clock.
- A key that signed blocks on both sides of a split is reported with both blocks as proof.

This settles the "two admins remove each other during a partition" case deterministically: the
side with more of the community's authority behind it wins, everywhere.

## Failover

Sites announce that they're serving a community with a short-lived signed `commons.host` record
(`community, site, role, height, head, at, until`), signed by that site's key as listed in the
ledger. To pick a site, a client:

1. uses the home site while it answers;
2. if not, and the policy has `auto_failover` (the default), uses the first site in succession
   order that answers and whose announced copy is as current as any announced;
3. otherwise waits for the community's keys to make a decision (`host.move`).

The acting site keeps everything running (members join, messages flow) because it holds the
same `members` and `content` capabilities as the home site. It can't change authority. When home
returns, clients go back to it, and home catches up with `reconcile`.

Host failover is not governance failover: if the community's authority keys are lost, no site can
take over the community. That's deliberate.

## A planned move

`host.move` (threshold-signed) names a new home. The community keeps its id, history and members;
clients follow the change from the ledger itself.

## Security and privacy

- **Integrity.** Every block is a signed record (CVP-002) and every copy checks the whole chain
  from the first block, so no site, including the home site, can rewrite or forge history.
  Communities that use quantum-resistant keys get that protection against a quantum attacker too.
- **What every copy sees.** As "What's in the clear" says: the structure of the community (member
  key ids, roles, channels, hosting sites) is readable by every copy; only content is encrypted.
- **Availability, not authority.** Failover keeps a community running when its home site is down,
  but an acting site can't change authority, and lost authority keys can't be replaced by any
  site.
- **Not protected:** who is in a community, from the sites that copy it; timing of activity;
  a split where both sides have the same authority behind them is settled by a fixed rule, not by
  what anyone intended.

## Conformance

`test/ledger.test.mjs` covers replay, reconciliation, splits and failover. There are no
language-neutral vectors for this part yet (CVP-010, section 6).

## Changes

| Version | Date | SNIP | Change |
| --- | --- | --- | --- |
| 1 | 2026-11-12 | none | First version, in Secure Net 0.1.0 |
