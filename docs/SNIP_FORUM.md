# The proposals forum

From 0.23.0 the community server can have a forum, `snip-proposals`, with one thread for every
Secure Net Improvement Proposal (SNIP) in the
[Secure Net repository](https://github.com/Comutability/secure-net/tree/main/snips) on GitHub.
Threads are opened and closed to follow GitHub, without anyone doing it by hand.

It is on for the hosted site, and off on self-hosted sites unless `SNIP_FORUM=on` is set.

## How it works

Posts in Commonveil are end-to-end encrypted with keys the server doesn't hold, so the server
can't write them. The work is split:

- **The site** (the `snips` function) reads the proposals from GitHub's public API, keeps a copy
  for 20 minutes (3 with a `GITHUB_TOKEN`), creates the empty forum channel when asked, and
  reports which proposals already have a thread and whether it is locked.
- **A community admin's app** does the posting. Whenever someone who can manage channels and
  threads in the community server has Commonveil open, their app asks the site where things
  stand, about every ten minutes, and makes whatever is missing. The posts are signed by that
  admin's device like anything else they post, and show as theirs.

So updates appear the next time an admin has the app open, not the instant GitHub changes.

## The rules

| On GitHub | In the forum |
| --- | --- |
| A SNIP file appears on the default branch, or in an open pull request | A thread is started: "SNIP-0003: its title", with its status and a link |
| The SNIP's Status line starts with Accepted, Rejected, Implemented, Released or Withdrawn | A closing note is added and the thread is locked |
| A pull request that introduced a SNIP is closed without merging | The thread is locked, with the note "Closed without merging" |
| A pull request is merged and the SNIP is still a Draft | Nothing: the thread stays open while the proposal is still being decided |

- Everyone in the server can read the forum and reply in open threads. Only people who manage
  threads can start one, so there is exactly one thread per proposal.
- Each proposal's thread has a fixed id made from its number, so two admins' apps can't both
  create one: the second is refused as a duplicate.
- A locked thread is never unlocked automatically, so a moderator's decision to lock one stands.
  If a proposal is reopened on GitHub, unlock its thread by hand.
- If GitHub can't be read, the last copy is used and nothing is opened or closed from it.
- At most eight things are done in one pass, so a long backlog arrives gradually.

## Privacy

- Only the site contacts GitHub, and only for the public list of proposals. Members' devices
  never do.
- Members who aren't community admins never trigger a read of GitHub.
- The site learns nothing new about posts: it stores them as ciphertext, like every other post.
  What it can see is what it always can: who posted in which channel, and when.

## Settings

| Where | Setting | Meaning |
| --- | --- | --- |
| Hosted site (Base44 secrets) | `SNIP_FORUM=off` | Turn the forum sync off |
| Self-hosted (`.env`) | `SNIP_FORUM=on` | Turn it on |
| Both | `GITHUB_TOKEN` | Optional. A read-only token for public repositories; GitHub is then checked every 3 minutes instead of every 20 |
| Both | `SNIP_REPO` | Optional. Another `owner/repository` to follow |

Turning it off stops the sync. The channel and its threads stay; delete the channel in server
settings if you don't want it.
