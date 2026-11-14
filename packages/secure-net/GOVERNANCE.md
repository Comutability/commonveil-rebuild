# How Secure Net is governed

**Status: draft proposal. Not yet ratified.** It takes effect only when the authorised human
decision-maker's approval is recorded in Comutability's decision register. Merging this file, or
a comment on it, is not ratification by itself. Until then it describes how we intend to work.

It sits under the Founding Charter v1.1 and the proposals ORG-001 (community-led organisation,
human-controlled operations) and GOV-002 (independent protocol stewardship, product
architecture, human authority over AI). Where it disagrees with any of them, they win.

## What "independent" means here

Secure Net's technical direction isn't set by the needs of Commonveil, Veil Social or any other
single application, including Comutability's own. Proposals can come from anyone. Independent
implementations are welcome and none has privileged status for being Comutability's. Funding
doesn't buy technical authority. The specifications, tests and implementation guidance stay
public, so a compatible implementation never needs a private agreement with Comutability. The
protocol requires no particular hosting platform, database, operating system or commercial API.

Secure Net is a protocol other people build on, so changes to it follow their own process,
separate from any application's release process. Commonveil and Veil Social are users of the
protocol like anyone else: their teams can propose changes, and can be turned down.

## Changing the protocol: Secure Net Improvement Proposals (SNIPs)

Any change to what two implementations must agree on (a specification in `spec/`, a registry
entry, a wire format, an algorithm, a rule for accepting or refusing something) goes through a
numbered proposal in [`snips/`](snips/). [CVP-000](spec/CVP-000-framework.md) sets out how such a
change is classified (editorial, additive or breaking), versioned and, when the time comes,
retired.

1. **A public proposal** describes the problem and the intended solution
   ([template](snips/SNIP-TEMPLATE.md)). Anyone may write one.
2. **Maintainers and independent developers examine it** for security and for compatibility
   with existing sites and applications. Discussion happens in the open, on the pull request.
3. **A reference implementation and tests** demonstrate the change. A proposal without them
   can be discussed but not accepted.
4. **The Technical Steering Committee records a decision**: accepted or rejected, with reasons,
   in the proposal itself.
5. **It becomes part of a versioned specification only after the required review.** Until
   then, code for it is marked experimental and must not be the only option between sites.

A proposal moves through: **Draft → Public Review → Technical Review → Accepted or Rejected →
Implemented → Released**. Accepting a specification doesn't authorise anyone to deploy it:
each application decides, tests compatibility and releases on its own. A critical security
fix may be handled privately first and published afterwards with an advisory.

**Breaking changes** (anything an up-to-date site and a site one version behind would disagree
about) need a higher approval threshold and a **published migration plan**: who has to update,
by when, what happens to those who haven't, and how to go back.

Changes to security-sensitive parts (cryptography, key handling, signatures, federation
checks) also need review by a qualified human security reviewer, whatever else has approved
them.

## Who decides

- **The Technical Steering Committee (TSC)** decides on SNIPs. The aim is three to five
  qualified human maintainers, including independent contributors as suitable people come
  forward, chosen for their contributions, competence and willingness to be accountable. It can
  reject changes proposed by Comutability's own product teams.
- **For now** the founding steward coordinates a provisional maintainer group. Until a policy on
  appointment, terms, quorum, appeals and removal is adopted, that group doesn't claim the
  authority of a fully constituted independent committee, and its decisions say so.
- **Thresholds.** While the TSC has one member, that member decides, and says so in the record.
  Voting eligibility, quorum and the exact thresholds are for a separately approved governance
  policy to set, not this file. As a starting suggestion for that policy: from three members, a
  majority to accept; two thirds, and no unresolved objection from a security reviewer, for a
  breaking change.
- **Conflicts of interest.** A member with a material interest in a proposal says so, and
  doesn't decide it alone.
- **AI can prepare proposals, write implementations and tests, and review. It cannot be a
  voting member of the committee**, and its approval never stands in for a human's. An AI
  doesn't approve its own security-sensitive changes, merge protected changes or publish
  releases without the required human authorisation, or give itself more access. Work an AI
  prepared says so, and has a named human responsible for it.

## Accountability

Governance combines maintainer expertise with community representation. Contributors have
routes to:

- **challenge a decision**: open an appeal on the proposal; the TSC must answer in writing, and
  a rejected appeal can be taken to the Community Council once there is one;
- **remove ineffective representatives**: a recall can be proposed by contributors and is
  decided by the body that elected or appointed them;
- **propose leadership changes**, by the same proposal process as anything else.

Comutability starts with **founder stewardship** and moves towards **elections** as a genuine
contributor community emerges. The steps, and what counts as "emerged", are for the Founding
Charter and its supplementary decisions to set, not for this file.

## Licence and contributions

Secure Net is AGPL-3.0-only. Nothing here changes that. A licence change would need its own
proposal, legal review, the permission of the people who hold rights in the code, and recorded
human approval; rights already granted can't be withdrawn. Contributions keep clear attribution
and compatible licensing, without copyright assignment unless a need for it is shown.

## Releases

Versions follow semantic versioning. A release notes which SNIPs it contains and the status of
each. A new version of Secure Net never changes an application by itself: applications
pin the version they use and adopt a new one through their own review. Applications that keep a copy (Commonveil's `packages/secure-net`) check it against
`secure-net.manifest.json`.
