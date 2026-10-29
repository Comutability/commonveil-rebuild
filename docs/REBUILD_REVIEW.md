# Why Commonveil was rebuilt (October 2026)

A record of what was wrong with the previous app (Base44 app `6ab5d287eaa0525c979d8c3e`, left untouched) and the decisions
behind this one. Written for reviewers, including Comutability's intake review.

## What was broken

**Sign-up and sign-in could not work on Base44.** Registration created a platform account under a made-up internal email,
then called `asServiceRole.sso.getAccessToken(userId)` to issue that new member a session. That method only issues a token
for the calling user, so the session step always failed. The old app's own migration note (11 October) recorded a live 503.
Of 8 accounts, only the 2 admin accounts ever completed setup; 4 were stranded half-registrations from 8 October.

**The tests hid it.** All 243 security tests passed because the harness replaced `getAccessToken` with a stub that returned
a token for any user, certifying the exact call production refused.

**It couldn't be deployed reliably.** 125 backend functions against a documented limit of 50 per full deployment.

**Its scope made it unverifiable.** About 48,700 lines of frontend and 15,400 of backend, 85 tables and 1,797 commits, much of
it migration code for older key formats, three service-worker generations and legacy recovery paths, for data that didn't
exist. Several features couldn't deliver their stated guarantee on a single-operator platform: for example the onion relay
list was managed by the admin in the same database, so it offered no protection from the operator.

**There was little to lose.** 31 messages, all plaintext bot announcements of a daily AI-generated blog post; nothing
encrypted existed.

## Decisions

| Decision | Why |
|---|---|
| Base44's own email sign-in is the only session authority | It works and needs no workarounds. Members may use an alias; the email is never shown. A no-email identity provider can be added later through Base44 app SSO without touching encryption keys. |
| One account keyring shared by approved devices | Simpler than per-device wraps plus a separate vault, and history works on every device. Revocation is handled by rotation. |
| Standard BIP-39 phrase deriving a recovery key pair | Devices can re-seal backups after rotation without knowing the phrase. Standard wordlist, audited library. |
| New devices need approval (with a compared code) or the phrase | A signed-in session alone can never receive keys. |
| Device-signed requests for key changes, group additions, leaving and deleting | Stops someone with only a password from doing damage that matters. |
| Client-side "who's new" pause | The server controls membership; members see new people before their words reach them. |
| No member directory | Exact-username lookup only. |
| 6 backend functions | Each a small set of named actions over shared, tested modules. |
| Messaging core first | Public site plus encrypted DMs and small groups. Everything else waits until this is reviewed. |

## Content carried over

5 hand-written posts, 5 guides, 3 learning paths, 16 resources and 1 wiki page. The 29 auto-generated posts and the daily
generator were not carried over. Corrections made in transit:

- Brave was listed as not open source; the browser is open source, so it's now marked as such.
- DuckDuckGo is marked "partly" open source: its apps are, its search engine isn't.
- The wiki page on end-to-end encryption described sealed sender and onion routing, which this build doesn't have; that
  section was rewritten to describe the current protocol and its limits.

## Not carried over (for now)

Community servers, channels, roles and forums; social feed and stories; voice; polls, canvases and AMAs; gamification;
passkeys, backup codes and QR login (replaced by the platform's sign-in plus device approval); and the metadata features
(mixnet routing, onion relays, cover traffic, blind tokens, zero-knowledge proofs, mesh transport), dead man's switch, panic
wipe, wormholes and guest rooms. Any of these can return once the core has been reviewed, each with a threat model of its own.
