# Commonveil threat model

What Commonveil protects, against whom, and what it doesn't. Read with `PROTOCOL.md` (version 2).

## What we're protecting

1. The content of messages and group names.
2. The ability to speak as a member (signing) and to receive keys (devices).
3. Control of an account's encryption, and recoverability for its owner, without giving the server anything usable.

## Who might attack, and what happens

| Adversary | Can't | Can |
|---|---|---|
| **Server operator, hosting platform, or someone with the database** | Read messages or group names, or tell a reply, reaction or edit from any other message. Add a device that receives keys. Sign as a member. Swap any of a contact's keys, present or past, after the first contact without the app warning (pins and safety numbers cover the whole key history). Hand a new device a forged account (link codes cover the account's history; recovery needs a statement only the phrase can make). Silently add someone to a conversation (members are shown who's new before they send). Keep a disappearing message showing past its sender's timer (the timer is also inside the signed message). | See metadata: who talks to whom, when, how much, profiles, device lists, which accounts each message was sealed to, group admins, timers and who set them, when scheduled messages and check-ins are due and for whom (not what they say), when a conversation is set to self-destruct, and (only for members who turned auto-delete on) the day they last opened the app. Drop, delay or reorder messages. Keep the ciphertext of a disappearing message instead of deleting it. Hold back or never deliver a scheduled message or a missed check-in (so a check-in is a help, not a guarantee). Deny service. Swap keys **before** two people first talk (trust on first use), unless they compare safety numbers. Push a reset through without the 7-day wait (it's enforced by the server), though contacts are still warned. Serve malicious app code (see below). |
| **Someone with a member's password or session** | Read messages. Approve a device. Sign messages. Start conversations, add or remove people, choose admins, change timers, leave groups, delete messages, turn auto-delete on or off, or delete the account (these need a device signature). Take over the account's encryption quickly. | Ask for a reset. It waits 7 days, the account's devices show it and can cancel it, the phrase cancels it, and the sign-in email is told; if nobody acts, it completes (contacts are warned and old messages become unreadable to the new identity). Block or report people, edit the profile, see the conversation list and contacts' profiles, and fetch encrypted rows addressed to the account. |
| **A member of a conversation** | Forge other members' messages, edits or reactions. Edit anyone else's message. Read conversations they aren't in, or see messages from before they joined. Add or remove people, rename a group or change its timer, unless they're one of its admins. | Read and share everything sent while they're a member, including disappearing messages before they go. An admin can add people (others are shown who's new before they send) and remove them. |
| **Thief of an unlocked device** | Keep reading new messages once the device is removed from another device (keys rotate). Have what it sends after removal shown as verified, unless it backdates it (see below). Open the keys once a passcode lock has locked, without the passcode. | Read everything already on it, and everything until it's removed or locks. Copy the browser's files and try passcodes offline. |
| **Someone who learns the recovery phrase** | On commonveil.online: use it without also being able to sign in as the member. | With a session too: restore the keyring and read everything sent to the account's current and past key versions, and cancel resets. Change the phrase to stop this. **On a self-hosted site the phrase (or the private key, its other form) also gets back into the account** (`docs/IDENTITY.md`): whoever has it can set a new password, sign in, confirm their own browser and then read everything as above. Keep it as safe as the account itself. |
| **Someone with a member's password, on a self-hosted site** | Sign in on a browser the account hasn't used, without also a passkey, the phrase or private key, or approval from one of the member's signed-in devices. | Sign in on a browser already confirmed for the account. Try confirming a new one five times per attempt. Older accounts that still have an email: confirm a new browser with a code sent there. |
| **Another Commonveil site** (`docs/FEDERATION.md`) | Read anything (all it relays is ciphertext). Act for people from other sites, or for its own people where a device signature is needed. Make apps accept a forged message or key. | Relay, delay or drop what its own people send elsewhere, and what other sites' people do in conversations and servers it hosts. See the same metadata any host sees, for the rooms it hosts. Claim an id belonging to a third site's person before they first visit, so their requests there are refused (denial of service, not impersonation). Present its own key on first contact if it controls a site's DNS then (trust on first use; admins can compare keys). |
| **Phones carrying messages in a future mesh** (`docs/OFFLINE.md`) | Read or change a carried message. | Not built yet. In the design: see which site and room a message is for, its size, and when it passed by. |
| **Network attacker** | Anything beyond what TLS exposes. | Observe that a device talks to Commonveil. |
| **Malicious script on the page, browser extension or compromised browser** | Nothing is protected. | Everything the member can do or see. |
| **Future quantum computer** | Recorded messages, server items and calls, for recipients with post-quantum keys: keys are sealed with ML-KEM-768 + P-256, and call frames are sealed under server chain keys that travel the same way. | Forge P-256 signatures from then on (impersonating a device), and decrypt anything sealed to an older recipient who has no post-quantum key yet. |
| **The call relay (VoiceRoom actor) or whoever controls it** | Call audio; it can't connect as someone else, because each device checks the others' signed connection fingerprints. | See who is in which call and when, see participants' network candidates (IP addresses), drop or delay call set-up. |

## Properties not provided

- **Forward secrecy.** Message keys are sealed to a member's long-term account key for that version. Anyone who obtains
  that private key can read every message sent to it. Removing a device or changing the phrase rotates keys, which limits
  exposure from then on. A per-conversation ratchet would fix this and is the largest planned change.
- **Metadata privacy.** Membership, timing, sizes and recipient lists are visible to the server. In servers it also
  sees who is in which server, roles, channel structure (not names), who's waiting for keys, ticket membership, and who
  joined which call and when. A server listed in Discover publishes an unencrypted public card.
- **Network address privacy in calls.** Calls are peer to peer, so participants see each other's IP addresses, and the
  STUN server (Cloudflare) sees yours when you join. There's no TURN relay, so some networks can't connect.
- **Cryptographic group membership.** The server holds member lists. Device-signed changes and the client-side member pins
  limit the damage, but a signed membership log checked by every client would be stronger.
- **Conversation integrity.** Each message is authenticated, but the server can withhold or reorder messages.
- **Deniability.** Messages are signed, so a recipient can prove who sent them.
- **Code integrity.** It's a web app: each visit trusts the code served. The Content Security Policy below limits what
  injected content can do, but not what the server itself serves. Installable builds with reproducible hashes would.
- **Guaranteed deletion.** Disappearing messages and deletions remove what Commonveil stores and shows, but a member can
  copy a message first, and the hosting platform may keep backups or change history for a time.

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
- **Email notices are best effort.** If the email service fails, a reset request still shows on the account's devices,
  and new devices still show in Settings. An auto-delete warning that can't be sent is tried again daily; the account is
  deleted a week after its date even if no warning got through, because the member chose that.
- **The passcode lock covers the message keys, not the device's signing key.** That key is a browser-held key that can't
  be exported, so it can't be wrapped either; code running in the browser profile can use it while the app is locked (for
  example to remove the device). Someone who copies the browser's files can try passcodes offline at the speed of their
  hardware (600,000 PBKDF2 rounds each), so passcodes must be at least 8 characters and longer is better.
- **Notifications** are shown by the browser and operating system, which may keep a history. They never contain message
  text, and name the sender only if the member chooses (in an open tab only).
- **Push notifications** (off until turned on, per device) go through the browser's push service, encrypted to the
  browser. They say only "New message" or "New activity" and carry a one-time code; the app swaps it, signed in, for
  where to go. The push service learns that this device got something from this site at that moment, at most once
  every 20 seconds. Federated members aren't pushed to. See [NOTIFICATIONS.md](NOTIFICATIONS.md).
- **Edits and reactions are ordered by their sender's own signed time.** A member can make their own edit or reaction look
  older or newer than it is, but can't affect anyone else's, and an edit dated more than a day after the original is ignored.
- **The scheduled clean-up has a public address**, like every function. It takes no instructions beyond a task name and
  only does what's already due by the server's clock, so the worst a caller can do is use a little of the app's query
  allowance (repeat calls within a minute are skipped).
- **Shared query allowance.** On Base44, everything the backend does as its service role shares one per-minute allowance
  for the whole app. Frequent reads use each member's own allowance instead, but a burst of activity across many members
  can still produce "the service is busy" errors; sends are retried as the same message, so nothing is sent twice.

- **AutoMod is enforced by apps.** The service can't read messages, so a modified app can send something that breaks a
  server's AutoMod rules. Other members' apps hide it, but it has been delivered and stored (encrypted).
- **Files.** The service sees each file's size, part count and upload and download times. A download link works for five
  minutes for whoever holds it, though what it fetches is ciphertext.
- **Presence.** When someone turns it on, the presence room (and so the hosting platform) sees which servers and
  conversations they have open and when, and who is typing where. It's off by default.
- **Events.** The service knows that a server has events and which members answered them, though not the answers.
- **Stages.** Who may speak is decided by the relay on moderators' instructions; apps refuse to play anyone else. A relay
  run by an attacker could let someone speak, but couldn't add a device that isn't certified for its account.

- **Reports and escalation.** The service knows who reported whom and when, and how moderators
  closed it. Report content is end-to-end encrypted to the moderators; an escalation to the
  Commonveil team is, by design, a readable disclosure written by the moderator.
- **Automatic moderation acts on counts.** Warning steps, flood, raid and staff limits are enforced
  by the service using counts and times, never content.
- **Channel permissions.** Changing who can see a channel needs "Manage roles", only for roles
  below your own, with permissions you have there; a channel any role is denied becomes private
  (its own keys), so a deny really hides it.

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
3. Planned improvements, in rough order: forward secrecy (per-conversation ratchet), a signed membership and device log
   (which would also make admin changes verifiable by every member), post-quantum signatures (ML-DSA), installable
   builds. (Post-quantum hybrid key sealing, ML-KEM-768 + P-256, was added in November 2026: see
   `SERVERS_AND_VOICE.md`.)
4. Check on the published app that the scheduled clean-up (`maintenance`) runs on time: its workflows are listed, with their
   runs, in the app's workflow settings.
5. On the published app, test a call between two networks, in Chromium and in Firefox or Safari (the browser tests
   cover Chromium on one machine; Firefox and Safari use a worker for the frame encryption).

## Known platform behaviour worth noting

In the Base44 editor's preview (an iframe), the platform SDK mirrors API requests to the editor window for debugging.
Requests never contain private keys or the recovery phrase, only ciphertext, public keys and signatures. The published
site isn't framed, and iframe embedding of the published app is disabled. Production builds ignore a
`functions_version` in the page address, so a link can't point members at an older or unfinished backend.
