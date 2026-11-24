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
  stand, about every five minutes, and makes whatever is missing. The posts are signed by that
  admin's device like anything else they post, and show as theirs.

The signed-in administrator also sees a **Sync now** control to reconcile the forum using their own device keys. The admin app checks shortly after it opens and again when its tab regains focus or reconnects. It then checks about every five minutes while visible. Updates need an authorised admin device with the forum's encryption keys; simply checking GitHub on a server cannot create a valid encrypted post.

**A merged PR or SNIP file on main is not a human standards approval.** Closing the forum thread is a local discussion-workflow choice; the normative status remains in the SNIP itself on GitHub.

## The rules

| On GitHub | In the forum |
| --- | --- |
| A SNIP file appears on the default branch, or in an open pull request | A thread is started: "SNIP-0003: its title", with its status and a link |
| A SNIP reaches the GitHub default branch (including via a merged PR), even if still Draft | The admin device adds a **Merged** note with the source-linked PR author's stated purpose where available, explicitly **not** standards approval, then locks the thread |
| A SNIP's Status line reads Accepted, Rejected, Implemented, Released or Withdrawn inside an open PR | The admin device adds a closing note and locks the thread |
| A PR containing a SNIP closes without merging | The admin device adds a **Closed without merge** note, a source-linked maintainer reason if one is recorded, or explicitly says none was recorded, then locks the thread |

- Everyone in the server can read the forum and reply in open threads. Only people who manage
  threads can start one, so there is exactly one thread per proposal.
- Each proposal's thread has a fixed id made from its number, so two admins' apps can't both
  create one: the second is refused as a duplicate.
- A locked thread is never unlocked automatically, so a moderator's decision to lock one stands.
  If a proposal is reopened on GitHub, unlock its thread by hand.
- If GitHub can't be read, the last copy is used and nothing is opened or closed from it.
- **Only one proposal is reconciled per pass**, prioritising missing threads, including SNIP-0007 and SNIP-0008. A missing merged or declined proposal can still be posted, given its signed note and locked as one safe operation group.
- The device automatically resumes the next pending proposal after a pause while the browser remains unlocked and visible. It does not flood the service with a whole backlog at once.
- If Base44 reports `UPSTREAM_BUSY` (HTTP 429), the device pauses and retries with increasing delays instead of repeatedly hammering the shared backend. The button shows **Retry queued** during the pause. Already encrypted/signed posts are retained; stable message IDs make a partial operation resumable without duplicates.
- Only the browser device can encrypt, sign and post forum content. The backend cannot bypass the security of the forum to complete the backlog on its own.

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
