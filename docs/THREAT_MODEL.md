# Commonveil threat model

What Commonveil v1 protects, against whom, and what it doesn't. Read with `PROTOCOL.md`.

## What we're protecting

1. The content of messages and group names.
2. The ability to speak as a member (signing) and to receive keys (devices).
3. Recoverability for the member, without giving the server anything usable.

## Who might attack, and what happens

| Adversary | Can't | Can |
|---|---|---|
| **Server operator, hosting platform, or someone with the database** | Read messages or group names. Add a device that receives keys. Sign as a member. Silently swap a contact's keys after the first contact (the app warns). Silently add someone to a conversation (the app pauses senders until they've seen who's new). | See metadata: who talks to whom, when, how much, profiles, device lists. Drop, delay or reorder messages. Deny service. Swap keys **before** two people first talk (trust on first use), unless they compare safety numbers. Serve malicious app code (see below). |
| **Someone with a member's password or session** | Read messages. Approve a device. Sign messages. Add people to groups, leave groups or delete messages (these need a device signature). | Reset the account's encryption (contacts are warned, old messages become unreadable to the new identity), block or report people, edit the profile, see the member's conversation list and contacts' profiles. |
| **A member of a conversation** | Forge other members' messages. Read conversations they aren't in, or messages from before they joined. | Read and share everything sent while they're a member. Add people to a group they're in (others are shown who's new before they send). |
| **Thief of an unlocked device** | Keep reading new messages once the device is removed from another device (keys rotate). | Read everything already on it, and everything until it's removed. |
| **Someone who learns the recovery phrase** | Use it without also being able to sign in as the member. | With a session too: restore the keyring and read everything sent to the account's current and past key versions. Change the phrase to stop this. |
| **Network attacker** | Anything beyond what TLS exposes. | Observe that a device talks to Commonveil. |
| **Malicious script on the page, browser extension or compromised browser** | Nothing is protected. | Everything the member can do or see. |
| **Future quantum computer** | | Possibly decrypt recorded traffic, since key agreement is P-256 only. |

## Properties not provided

- **Forward secrecy.** Message keys are sealed to a member's long-term account key for that version. Anyone who obtains
  that private key can read every message sent to it. Removing a device or changing the phrase rotates keys, which limits
  exposure from then on. A per-conversation ratchet would fix this and is the largest planned change.
- **Metadata privacy.** Membership, timing and sizes are visible to the server.
- **Cryptographic group membership.** The server holds member lists. Device-signed changes and the client-side "who's new"
  pause limit the damage, but a signed membership log checked by every client would be stronger.
- **Conversation integrity.** Each message is authenticated, but the server can withhold or reorder messages.
- **Deniability.** Messages are signed, so a recipient can prove who sent them.
- **Code integrity.** It's a web app: each visit trusts the code served. A Content Security Policy, Subresource Integrity
  and installable builds with reproducible hashes would reduce this.

## Assumptions

- The platform serves the code in this repository unmodified.
- The browser's WebCrypto implementation is correct and its random number generator is sound.
- People who need strong assurance compare safety numbers in person or over a call.

## Before a public launch

1. An independent review of `PROTOCOL.md` and the code in `src/lib/crypto`, `src/lib/secure` and `base44/shared`.
2. A Content Security Policy and Subresource Integrity on the published domain, tested against Base44 hosting.
3. A published security contact and disclosure policy.
4. Self-service account deletion.
5. Planned improvements, in rough order: forward secrecy (per-conversation ratchet), a signed membership log, group admin
   roles, a post-quantum hybrid (ML-KEM-768) for message keys, installable builds.

## Known platform behaviour worth noting

In the Base44 editor's preview (an iframe), the platform SDK mirrors API requests to the editor window for debugging.
Requests never contain private keys or the recovery phrase, only ciphertext, public keys and signatures. The published
site isn't framed, and iframe embedding of the published app is disabled.
