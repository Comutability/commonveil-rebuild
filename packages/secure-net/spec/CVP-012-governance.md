# CVP-012: Governance, debates and votes

| | |
| --- | --- |
| Status | Draft |
| Version | 1 |
| Feature | `cvp.governance` (version 1) |
| Depends on | CVP-002, CVP-011, CVP-013 |
| Code | `src/governance/vote.js`, `src/governance/debate.js` |
| Proposed in | none (written before the proposal process; recorded in [SNIP-0004](../snips/SNIP-0004.md)) |

DAO-style decisions without a blockchain: proposals, structured debate and votes, all as signed
records any member or site can check, counted the same way everywhere, and able to authorise
changes in the community's ledger (CVP-011).

## Motions

A `governance.motion` names the community, the question, 2 to 50 options, a counting method, the
passing option, a quorum (minimum ballots), opening and closing times, the ballot kind, and the
eligible voters' key ids, taken from the ledger at a stated height so every site counts the same
people. A motion that would authorise a ledger change carries that change's `action` hash.

Methods: `majority` (more than half), `supermajority` (at least `num/den`, such as 2/3),
`approval` (most approvals wins) and `ranked` (instant runoff; ties broken by option order, the
same everywhere).

## Ballots

**Public** (`vote.ballot`): signed by the voter's key. Anyone can recount. Raise `seq` to change
your vote; the highest counts. Two different ballots with the same `seq` from one voter cancel.

**Secret** (`vote.secret-ballot`): unsigned, carrying one token (CVP-013) issued for this vote.
Eligibility is checked when tokens are issued, so the ballot names no one. Only the issuer can
check tokens, so the count is as honest as the issuer; and the network can link a ballot to an
address unless it's sent through something that hides addresses. Choose secret ballots knowing
both.

A ballot counts if the collecting site received it between opening and closing. Results commit
to the exact set of ballots counted (`ballots`, `ballots_hash`), so anyone can tell if their
ballot was left out.

## Results

`vote.result` is signed by the tallier and holds the counts, any runoff rounds, the winner, the
totals, whether quorum was met, whether it passed, and the action it authorises. For public
ballots, `verifyResult` recounts and refuses a result that differs.

A passed result is recorded in the ledger as `governance.result`. If a community's policy is
`authority_change: "vote"`, every authority change must carry the id of a passed result whose
`action` is exactly that change, so a vote for one change can't authorise another.

## Debates

Debates are typed, signed records: `debate.position`, `debate.argument` (with an optional
parent), `debate.rebuttal`, `debate.evidence`, `debate.round` (time-boxed phases set by
moderators, optionally for named debaters only) and `debate.moderation` (hide or restore).
`arrange()` checks them, applies rounds and moderation, drops anything replying to something not
in the debate, and gives both a tree (for a map of the argument) and a flattened thread with
depths (for keyboards, screen readers and narrow screens).

Roles (debater, voter, moderator, observer) belong to the community: the caller says who may
post and who moderates.

## Security and privacy

- **Public ballots** are signed records: anyone can recount, and a result that doesn't match the
  ballots is refused. Everyone can see how everyone voted.
- **Secret ballots** name no one, but the count is only as honest as the token issuer (CVP-013),
  and the network can link a ballot to an address unless it is sent through something that hides
  addresses. Apps MUST say both when someone chooses a secret ballot.
- **Results commit to the ballots counted**, so a voter can tell if theirs was left out; nothing
  stops a collecting site refusing to receive a ballot in the first place.
- **Authority by vote** only authorises the exact action voted on (its hash), never another.
- **Debates** are signed, so posts can't be forged or edited by a site; moderation hides posts but
  doesn't delete them from copies that already hold them.

## Conformance

`test/governance.test.mjs` covers motions, both ballot kinds, counting methods, recounts and
debates. There are no language-neutral vectors for this part yet (CVP-010, section 6).

## Changes

| Version | Date | SNIP | Change |
| --- | --- | --- | --- |
| 1 | 2026-11-12 | none | First version, in Secure Net 0.1.0 |
