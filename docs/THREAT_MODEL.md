# Commonveil threat model

What Commonveil protects, against whom, and what it doesn't. Read with `PROTOCOL.md` (version 2).

## What we're protecting

1. The content of messages and group names.
2. The ability to speak as a member (signing) and to receive keys (devices).
3. Control of an account's encryption, and recoverability for its owner, without giving the server anything usable.

## Who might attack, and what happens

| Adversary | Can't | Can |
|---|---|---|
| **Server operator, hosting platform, or someone with the database** | Read messages or group names. Add a device that receives keys. Sign as a member. Swap any of a contact's keys, present or past, after the first contact without the app warning (pins and safety numbers cover the whole key history). Hand a new device a forged account (link codes cover the account's history; recovery needs a statement only the phrase can make). Silently add someone to a conversation (members are shown who's new before they send). | See metadata: who talks to whom, when, how much, profiles, device lists, which accounts each message was sealed to. Drop, delay or reorder messages. Deny service. Swap keys **before** two people first talk (trust on first use), unless they compare safety numbers. Push a reset through without the 7-day wait (it's enforced by the server), though contacts are still warned. Serve malicious app code (see below). |
| **Someone with a member's password or session** | Read messages. Approve a device. Sign messages. Start conversations, add people to groups, leave groups, delete messages or delete the account (these need a device signature). Take over the account's encryption quickly. | Ask for a reset. It waits 7 days, the account's devices show it and can cancel it, the phrase cancels it, and the sign-in email is told; if nobody acts, it completes (contacts are warned and old messages become unreadable to the new identity). Block or report people, edit the profile, see the conversation list and contacts' profiles, and fetch encrypted rows addressed to the account. |
| **A member of a conversation** | Forge other members' messages. Read conversations they aren't in, or see messages from before they joined. | Read and share everything sent while they're a member. Add people to a group they're in (others are shown who's new before they send). |
| **Thief of an unlocked device** | Keep reading new messages once the device is removed from another device (keys rotate). Have what it sends after removal shown as verified, unless it backdates it (see below). | Read everything already on it, and everything until it's removed. |
| **Someone who learns the recovery phrase** | Use it without also being able to sign in as the member. | With a session too: restore the keyring and read everything sent to the account's current and past key versions, and cancel resets. Change the phrase to stop this. |
| **Network attacker** | Anything beyond what TLS exposes. | Observe that a device talks to Commonveil. |
| **Malicious script on the page, browser extension or compromised browser** | Nothing is protected. | Everything the member can do or see. |
| **Future quantum computer** | | Possibly decrypt recorded traffic, since key agreement is P-256 only. |

## Properties not provided

- **Forward secrecy.** Message keys are sealed to a member's long-term account key for that version. Anyone who obtains
  that private key can read every message sent to it. Removing a device or changing the phrase rotates keys, which limits
  exposure from then on. A per-conversation ratchet would fix this and is the largest planned change.
- **Metadata privacy.** Membership, timing, sizes and recipient lists are visible to the server.
- **Cryptographic group membership.** The server holds member lists. Device-signed changes and the client-side member pins
  limit the damage, but a signed membership log checked by every client would be stronger.
- **Conversation integrity.** Each message is authenticated, but the server can withhold or reorder messages.
- **Deniability.** Messages are signed, so a recipient can prove who sent them.
- **Code integrity.** It's a web app: each visit trusts the code served. The Content Security Policy below limits what
  injected content can do, but not what the server itself serves. Installable builds with reproducible hashes would.

## Known limitations

- **Backdating by a removed device.** A device's messages are judged by the `sent_at` it signs itself. A removed device
  that the server still lets post can date a message to before its removal (or within the 10-minute grace after it) and
  have it shown as verified. A signed membership and device log with server-independent ordering would close this.
- **Showing a recovering device an earlier state.** A server can withhold the newest key statements from a device being
  recovered with the phrase, as long as an older statement with the same phrase's anchor exists. The device then works
  with older keys until it sees the rest of the history, which must follow by rotation.
- **Proof replay.** Device proofs aren't stored, so a captured request can be replayed for 5 minutes. Only starting a
  group isn't idempotent (a replay makes a second, empty group). Capturing one needs broken TLS or the server itself.
- **Sign-in links.** The Base44 sign-in library accepts a session token in the page address (`?access_token=`), so a
  crafted link can sign a visitor into someone else's account. It can't expose the visitor's own keys (they're stored
  per account), but someone who doesn't notice could set up keys or send messages in the wrong account. The app shows
  which @username is signed in, in the header on wider screens and in Settings. This is platform behaviour Commonveil
  can't change.
- **Display names aren't unique.** Anyone can call themselves anything. The app shows @usernames beside names in groups,
  in new-member and first-look notices, and in conversation details beside each safety number; check those.
- **Email notices are best effort.** If the email service fails, a reset request still shows on the account's devices.
- **Shared query allowance.** On Base44, everything the backend does as its service role shares one per-minute allowance
  for the whole app. Frequent reads use each member's own allowance instead, but a burst of activity across many members
  can still produce "the service is busy" errors; sends are retried as the same message, so nothing is sent twice.

## Assumptions

- The platform serves the code in this repository unmodified.
- The browser's WebCrypto implementation is correct and its random number generator is sound.
- People who need strong assurance compare safety numbers in person or over a call.

## Before a public launch

Done in October 2026:
- A Content Security Policy in every production build (`default-src 'none'`, scripts from the site only, Trusted Types
  required so no string reaches an HTML sink), checked by `npm run check:bundle` and by a browser test against a
  production build. `frame-ancestors` can't be set from a meta tag; Base44 sends `X-Frame-Options: DENY`. Subresource
  Integrity isn't needed: every script is served from the site itself.
- A security contact: `/.well-known/security.txt` and a private report form at `/security/report` that needs no account.
- Self-service account deletion, and a staff tool to erase what removed sign-ins left behind.
- Fixes for every finding of an independent review of the protocol and code (see `REBUILD_REVIEW.md`).

Still to do:
1. An independent review of version 2 by someone who hasn't worked on it, before anyone relies on it for their safety.
2. Repeat the Content Security Policy browser test on the published domain once the app is published.
3. Planned improvements, in rough order: forward secrecy (per-conversation ratchet), a signed membership and device log,
   group admin roles, a post-quantum hybrid (ML-KEM-768) for message keys, installable builds.

## Known platform behaviour worth noting

In the Base44 editor's preview (an iframe), the platform SDK mirrors API requests to the editor window for debugging.
Requests never contain private keys or the recovery phrase, only ciphertext, public keys and signatures. The published
site isn't framed, and iframe embedding of the published app is disabled. Production builds ignore a
`functions_version` in the page address, so a link can't point members at an older or unfinished backend.
