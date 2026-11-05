# Servers, post-quantum keys and voice

Status: implemented and tested; **not independently audited**. This extends `PROTOCOL.md` (version 2) with what was added
in November 2026. If this and the code disagree, the code is wrong or this is out of date: please report it.

Code: `src/lib/crypto/kem.js` (post-quantum hybrid), `src/lib/crypto/serverKeys.js` (server key chains, grants, items),
`src/lib/secure/serverProtocol.js` and `ServerContext.jsx` (client flows), `src/lib/voice/*` (calls),
`base44/shared/servers/*` and `base44/shared/handlers/{servers,serverMessages,voice}.ts` (server checks),
`base44/actors/VoiceRoom/entry.ts` (call set-up relay).

## 1. Post-quantum hybrid encryption

Every place a key is sealed to an account or a device can use **MLKEM768-P256**: ML-KEM-768 combined with P-256 (the
CFRG concrete hybrid, `@noble/post-quantum`), so an attacker has to break both. A sealed value is `{ kct, iv, ct }`: the
KEM ciphertext, then AES-256-GCM under a key derived (HKDF-SHA-256, salt `commonveil/kem-seal/v1`) from the shared
secret and bound to its context.

- **Account keys.** A key version with a post-quantum key publishes it in the `account-key/v2` statement form (which adds
  `kem_pub` and, when the recovery phrase has one, `recovery_kem_pub`). Statements without one keep the `account-key/v1`
  form, so older histories still verify. Accounts made before November 2026 get a post-quantum key at their next
  rotation; the app rotates automatically once.
- **Devices.** A device certificate with a post-quantum key uses `device-cert/v2`. A device made earlier signs its new key
  itself (`device-kem/v1`) until its next certificate.
- **What uses it.** Message key wraps (envelope version 3), keyrings sent to a new device, the recovery backup, and server
  key grants (section 2). A recipient without a post-quantum key gets the P-256 form, and the app shows nothing different:
  the protection is only as strong as the weakest recipient's keys.
- **What doesn't.** Signatures are ECDSA P-256. A quantum computer could forge them, which would allow impersonation from
  then on, but not decrypting anything recorded earlier.

## 2. Servers

A server is a community with channels, roles and members, like a Discord server. The service stores ciphertext and
enforces permissions; members' devices hold the keys.

**Key chains.** Each server has:
- a history chain `<server>.h`, for channels set to full history;
- a live chain `<server>.l`, for channels where newcomers read only what's sent after they join. Its key moves on every
  hour (`STEP_MS`), one way only (HKDF), so a key for this hour can't be turned back into an earlier one;
- one chain per private channel, `<server>.c.<channel>`, given only to members who can see it.

A chain has numbered **generations**. A new generation is made on a device of a member with *Manage encryption*: a fresh
key, and a signed statement of its number, start time and a commitment (hash) to the key. Generations change when someone
loses access (leaving, a ban, a role or channel change), so they never get the new key.

**Grants.** Keys reach a member as grants: the key at a step, sealed to the member's current account key (post-quantum
hybrid where they have one) and signed by the granting device. The recipient's app opens it only if the grant's signer is
a device certified for a member who may hand out keys, and the key matches the generation's signed commitment. The service
tracks who's waiting for which keys and checks a grant's recipient may hold that chain; members' apps hand keys out in the
background. A server chooses who may hand keys out: any member's app (newcomers get keys quickly; members' apps learn the
account ids of people joining) or only staff with *Manage encryption* (ordinary members never learn who joins). The
community server uses staff only.

**Items.** Messages, forum posts and replies, reactions, edits, nicknames, channel and role names, rules and the server's
own name and description are encrypted with a chain's key at the current step and signed by the sending device, bound to
the server, channel and item. Reactions and edits are items too, so the service can't tell what they point at.

**Permissions** follow Discord's model (roles with permission bits, channel overwrites, a role hierarchy, an owner above
everyone) and are enforced by the service on every action. Actions that change something are signed by an active device
(`device-proof/v1`), so a signed-in session alone can't act.

**Invites** are a code plus a secret after `#`. Browsers never send the fragment, and the invite's preview (server name,
icon) is encrypted with a key derived from it, so the service's invite list can't rebuild links or read previews. An
invite can expire and have a use limit; the creator isn't shown to people who open it.

**Discovery** is off unless a server's admins turn it on. A listed server publishes a public card (name, description,
tags, icon, colour) that isn't encrypted; everything inside stays encrypted.

**Member lists.** Nobody is listed unless they choose to be, except staff (so members can see who runs a server). Servers
can also show only staff, or only a count. There's no online status. Moderators act on people through their messages or
profile; they don't get a list of everyone.

**Support tickets** are end-to-end encrypted group conversations (`PROTOCOL.md` section 7) between the member and up to 31
of the server's support team. The member sees exactly who's in it before sending.

**The community server.** Every new account joins it. Its admins are the sign-in addresses in the `DEFAULT_SERVER_ADMINS`
secret (comma separated; the first is the owner), never in the code. An admin gets the role when that account joins, and
their device makes the server's first key generations and hands out keys.

## 3. Voice calls

Up to 8 devices per voice channel call. Audio goes directly between devices; the service never receives it.

1. **Pass.** The `voice` function checks the member may view and connect to the voice channel and isn't timed out, then
   stores a single-use pass for `<server>.<channel>` that lasts one minute (`VoiceTicket`, readable only by the service).
2. **Relay.** The device connects to the `VoiceRoom` actor for that room (a realtime room on Base44). The platform tells
   the actor which signed-in account is connecting. The actor admits the connection only with a valid, unused pass for
   that account and room, deletes the pass, and from then on passes WebRTC offers, answers and network candidates between
   admitted devices, plus who's muted. A connection without a pass learns nothing about the call.
3. **Offer.** Each device makes a WebRTC certificate for the call and signs a `voice-hello/v1` statement: room, account,
   device, a random call id, the certificate's SHA-256 fingerprint and the time. Before connecting to someone, the app
   checks that statement against that device's certificate for their account (the same check messages get), and that the
   fingerprint their connection actually presents matches the signed one. Otherwise it doesn't connect and says so. This
   stops the relay, or anyone who controls it, from sitting in the middle.
4. **Media.** WebRTC encrypts the audio between each pair of devices (DTLS-SRTP). Every audio frame is also sealed with
   AES-256-GCM under a key derived from the channel's current chain key:
   `HKDF-SHA-256(chain key, salt "commonveil/voice-frame/v1", info "<room>|<chain>|<generation>|<step>")`.
   Frame layout: version (1 byte), generation (2 bytes), step (4 bytes), random 96-bit IV, ciphertext and tag; the first
   7 bytes are authenticated. Frames that don't open are dropped, never played. Since chain keys travel in post-quantum
   grants, recorded call traffic is protected against a future quantum computer too. Chromium does this on the page
   (`createEncodedStreams`); Firefox and Safari in a worker (`RTCRtpScriptTransform`).

Limits: the people in a call see each other's network addresses, as with any peer-to-peer call, and the STUN server
(`stun.cloudflare.com`) sees yours. There's no relay (TURN) server, so some strict networks can't connect. The service
knows who joined which call and when. Mute is enforced by each device, not cryptographically.

## 4. Platform notes for maintainers

- **Backend changes reach members only when the app is published.** Base44 serves the published version of every backend
  function and actor to everyone except the app's editors. A function or actor that has never been published is only
  reachable by editors (actors refuse others with "user worker not found"), so test accounts can't use it until a publish.
- **Revision lines.** Each `base44/functions/*/entry.ts` starts with a "Shared code revision" line. Bump it when files in
  `base44/shared` that the function imports change, so the platform redeploys it with them.
- **Content Security Policy.** Production builds allow connections to the site itself and to
  `wss://actors.base44-realtime.dev` (call set-up), workers from the site itself (the frame encryption worker), and one
  Trusted Types policy, `voice-worker`, which only returns that worker's own address. The editor preview doesn't apply
  the policy.

## 5. Tests

`tests/pq.test.mjs` (hybrid sealing, statement forms), `tests/servers.test.mjs` (chains, grants, permissions, invites,
member lists, tickets, the community server, call passes), `tests/voice.test.mjs` (signed offers, frame encryption) and
`tests/voiceRoom.test.mjs` (the actor's admission and relaying, against a stand-in runtime).
