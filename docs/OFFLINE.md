# Offline mode, local sites and the mesh

What Commonveil does when there's no internet: what's built and tested now, and the design for the
part a web app can't do (talking phone to phone over Bluetooth or Wi-Fi), for a future native app.

## What's built

### 1. Offline mode in the app

Messages to conversations and server channels can be written with no connection:

- The app **seals and signs the message straight away**, as it would online: encrypted to the
  members' devices as they are now, signed by this device, with a client-chosen message id and the
  time it was written.
- The finished request waits in the browser's IndexedDB (`src/lib/offline/outbox.js`). Nothing is
  kept in plain text: the app shows a waiting message by opening its own copy (every message is
  also sealed to its sender).
- When the connection is back, waiting messages are sent oldest first, marked `queued`. The server
  accepts a queued message's send time up to **a week** in the past (and never more than ten
  minutes ahead), keeps that time, and the app shows "written offline" on it.
- Each message's id makes sending idempotent: if it arrives twice, it's stored once.
- If something changed while you were away (someone joined or left, or a channel's keys moved on),
  the server refuses the old sealing, and the message is marked **Not sent**, with **Send again**
  (sealed afresh from the text this device can still open) or **Delete**.

**Offline mode** (Settings → Offline mode) does the same on purpose: after the app has loaded, it
stops checking for messages and holds everything you send, until you turn it off. A banner shows
whenever you're offline, by choice or not.

Limits: the app needs the server to start up (it doesn't run from a cache yet), so keep the tab
open. Attachments, edits of other people's things, and anything that isn't a message still need a
connection.

### 2. Sites hold messages for sites they can't reach

When your site can't reach the site hosting a conversation (`docs/FEDERATION.md`), it keeps your
sealed message and passes it on itself: after 30 seconds, then less and less often (at most every
30 minutes), for a week. The app shows "Your site is holding it until *other.site* can be reached",
and checks back now and then. Only message sends are held.

So a site whose internet link goes down keeps working for everyone on it, and catches up with
other sites when the link comes back.

### 3. Local sites: chat with no internet at all

A Commonveil site needs a network, not the internet. Run one on a Raspberry Pi with its own Wi-Fi
hotspot, and everyone in range can make an account on it and chat: end-to-end encrypted, nothing
leaving the room. Several local sites on one network can talk to each other with the Commonveil
Protocol, and to the wider internet when any link appears. `docs/SELF_HOSTING.md` has the
set-up, including the HTTPS certificate browsers need.

Tested in `tests/offline.test.mjs` (late sends, the week limit, holding and passing on, dedup) and
in a browser (the connection cut mid-conversation, offline mode on and off).

## What a web app can't do

Browsers can't make Bluetooth or Wi-Fi Direct connections between phones in the background, or
discover devices nearby on their own. (Web Bluetooth only connects to accessory devices, with a
prompt each time, and isn't in every browser.) So phone-to-phone mesh networking needs a native
app. What follows is the design for it, chosen so it can be added without changing anything about
how messages are sealed, signed or stored.

## The mesh design (for a native app)

### What travels

The unit is exactly what the outbox already holds: a **sealed, signed message request**. It's
already end-to-end encrypted to its recipients and signed by the sender's device, and carries its
own id and time. A phone carrying someone else's message can't read it, change it without breaking
the signature, or pass it off as its own. Wrapped for the mesh:

```json
{ "v": 1, "to_site": "chat.example.com", "room": "<conversation or channel id>", "id": "<message id>", "expires": "<time>", "hops": 0, "request": { /* the signed request, as sent to a site */ } }
```

`to_site` and `room` are what a carrier needs to know to deliver it; nothing else is visible.

### How it moves: store, carry, forward

- Phones nearby find each other over Bluetooth LE (and Wi-Fi Direct for bulk), and exchange
  **summaries** first: the ids of the messages they carry (a Bloom filter when there are many).
  Each sends only what the other lacks.
- Every phone keeps what it receives for its owner, and carries other people's messages, up to a
  size and age budget, oldest dropped first. The more phones around, the more paths a message has:
  it spreads like gossip, and gets through even when no single path is there all the time.
- When any phone reaches the internet, or a local site, it hands over everything addressed to it.
  The site checks each message as usual (device signature, membership, send time) and stores it
  once, by its id. Recipients get it from their site as normal.
- Messages for people nearby can be read straight away by them, if their phone has seen the room's
  members' keys before (apps keep them). Unknown senders show as unverified until their keys are
  fetched.

### Why not a blockchain

A blockchain makes strangers agree on one order of events without trusting each other. Chat
doesn't need that: each message is already signed by its sender's device and encrypted to its
readers, so nobody can forge or read it, and its id makes duplicates harmless. Order comes from the
host site (and each message's own send time). A chain would add a growing ledger every phone must
carry, and a public record of who sent what when, which is the opposite of what Commonveil is for.
What makes the mesh "secure itself" is the same thing that secures Commonveil now: signatures and
end-to-end encryption, checked by every app.

### Privacy in the mesh

- Carriers see `to_site`, `room` and sizes, never content or sender names. Room ids are random; a
  future version can encrypt `room` to the site's key, so only the site learns it.
- Phones advertise a rotating random identifier, not anything tied to the account.
- Nothing is relayed unless the owner turned the mesh on.
- Abuse limits: per-sender budgets, a cap on hops and age, and sites rejecting anything that fails
  their usual checks.

### What would be needed

A native app (sharing `src/lib/crypto` and `src/lib/secure` with the web app), the summary-and-swap
exchange over BLE and Wi-Fi Direct, a carry store with budgets, and a site endpoint to accept a
batch of carried requests for many people at once (today each is sent by its own sender's session).
None of it changes the message format.
