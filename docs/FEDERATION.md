# Commonveil legacy federation (application compatibility)

> This document describes Commonveil-specific federation between Commonveil
> sites. The Commonveil version 1 API is NOT Secure Net's independent
> CVP-019 outbox/deliver/mailbox transport. Secure Net is an open, separately
> governed protocol that any website or application can implement without
> Commonveil. Commonveil is its first adopting application.
> See SECURE_NET_INTEGRATION.md for the protocol integration model.
>
> Legacy routes, request signing labels and existing site keys are preserved
> for compatibility. A brand-neutral discovery path or signature-version
> change requires a separately reviewed Secure Net Improvement Proposal.


How Commonveil sites talk to each other: how people are found by their address, how a
conversation or a server on one site is used by people from others, and what each site learns.
This is the specification. The wire format (what's signed, digests, address rules) and all the end-to-end crypto live in **Secure Net** ([Comutability/secure-net](https://github.com/Comutability/secure-net), which other apps can use too): its Rust crates in the self-hosted server, and its JavaScript copy in `packages/secure-net` for the browser app and the Base44 site. The self-hosted implementation is the Rust server (`rust/commonveil-server/src/federation.rs` and `fed_net.rs`) and the Base44 site's is `base44/shared/federation/`. The Node.js `server/federation/` stays as the reference the Rust tests compare against: `tests/federation.test.mjs` runs two real Node.js sites against each other, and `rust/commonveil-server/tests/parity_federation.rs` runs the same exchange through both servers.

It's our own protocol, written for end-to-end encrypted chat. It borrows from three others:

| From | What we took | What we didn't |
| --- | --- | --- |
| **ActivityPub** | Sites as independent servers that sign their requests to each other (like HTTP Signatures), WebFinger for `acct:` lookups, NodeInfo. | Public, readable activities. In Commonveil every message is ciphertext; a site relays what it can't read. |
| **AT Protocol** | Identity is a domain name: `alice.chat.example.com` is both Alice's address and a web address that answers who she is. | A global relay that sees everything, and content stored as public repositories. |
| **Matrix** | Rooms that people from many servers join, found in a directory and joined by an address; each server serving its own users. | Copying every room's history to every participating server. A Commonveil conversation or server lives on one site only. |

## Words used here

- **Site:** one Commonveil installation, named by its domain (`chat.example.com`).
- **Home:** the site a person has their account on. People only ever talk to their home.
- **Host:** the site a conversation or a server lives on. It stores its (encrypted) messages.
- **Address** (or handle): a person's name across sites, `<username>.<handle domain>`. Underscores
  in usernames become hyphens: `ann_lee` on `chat.example.com` is `ann-lee.chat.example.com`, and is
  mentioned as `@ann-lee.chat.example.com`.
- **Shadow:** how a host knows a person from another site: an account with the same 24-hex id as on
  their home, holding a copy of their public keys and profile, and nothing else.

## The model

Every conversation and every server lives on exactly one site: whichever site the person who made
it is on. When someone on another site takes part, their home **relays** each call to the host,
signed with the home site's key, and the host runs it as that person. The host keeps a shadow of
them so its usual rules (membership, permissions, blocks, rate limits) apply unchanged.

End-to-end encryption doesn't change at all. People's apps make and check every key and signature,
as on one site: account key statements are each signed by the one before, devices are certified by
the account key, messages are signed by the sending device and sealed to each member's devices.
Sites carry ciphertext. A host can refuse to deliver, or delay, but it can't read a message or
forge one that apps accept (`docs/PROTOCOL.md`, `docs/THREAT_MODEL.md`).

## Finding a site

`GET https://<site>/.well-known/commonveil` answers the site's document:

```json
{
  "protocol": "commonveil/1",
  "host": "chat.example.com",
  "name": "Example chat",
  "software": { "name": "commonveil", "version": "0.19.0" },
  "handle_domain": "chat.example.com",
  "key": { "alg": "Ed25519", "public": "<32 bytes, base64url>" },
  "endpoints": {
    "act": "/cvp/v1/act",
    "directory": "/cvp/v1/directory",
    "inbox": "/cvp/v1/inbox",
    "actors": "/cvp/v1/actors/{name}/{room}",
    "discover": "/cvp/v1/discover"
  }
}
```

`host` must equal the name asked for. A site speaks only for addresses ending in
`.<handle_domain>`. The key is the site's identity: the first time one site sees another, it
**pins** this key (trust on first use). If it later changes, requests to and from that site are
refused (`SITE_KEY_CHANGED`) until an admin accepts the new key. Documents are cached for an hour.

Also served, for other software: `/.well-known/webfinger?resource=acct:<username>@<site>` (links to
the profile page and the address) and NodeInfo 2.1 at `/.well-known/nodeinfo`, with **no user
counts**: how many people use a site is nobody else's business.

## Finding a person

Given `ann-lee.chat.example.com`:

1. `GET https://ann-lee.chat.example.com/.well-known/commonveil/identity`. The address's own name
   answers first, as AT Protocol handles do.
2. If that fails, its parent: `GET https://chat.example.com/.well-known/commonveil/identity?handle=ann-lee.chat.example.com`.

Either answers:

```json
{ "handle": "ann-lee.chat.example.com", "user_id": "<24 hex>", "home": "chat.example.com", "profile_url": "https://chat.example.com/u/ann_lee" }
```

The answer counts only if `handle` matches exactly and the address ends in the home's
`handle_domain`. Opened in a browser, the address redirects to the profile page
(`/u/<username>`), which shows only what the person chose to share and a way to message them.

Then the asking site calls the home's **directory** (below) for the person's card, which also
checks they accept a conversation from the asker.

## Signed requests

Every site-to-site request (`POST /cvp/v1/...`, and the WebSocket upgrade) carries:

| Header | Value |
| --- | --- |
| `CV-From` | The sending site's host. |
| `CV-Date` | ISO 8601 time. Refused if more than 5 minutes off. |
| `CV-Nonce` | 16 random bytes, base64url. Each `(site, nonce)` is accepted once. |
| `CV-Digest` | `sha-256=<base64url SHA-256 of the body>` (of the empty string for a GET). |
| `CV-User` | The person the request is for, if any (their 24-hex id). |
| `CV-Signature` | Ed25519 signature, base64url, by the sending site's key, over the text below. |

The signed text is these lines, joined with `\n`:

```
commonveil-request/v1
<METHOD>
<receiving host>
<path, with query>
<sending host>
<CV-Date>
<CV-Nonce>
<CV-Digest>
<CV-User, or ->
```

The receiver fetches (or uses its pinned copy of) the sender's site document, checks the
signature, digest, time and nonce, and refuses blocked sites. Requests go over HTTPS only, and
never to private, loopback or link-local addresses (so a site can't be used to probe another's
network), unless both sites are on a private network and allow it.

## The person card

A home describes one of its people to other sites with a card:

```json
{
  "id": "<24 hex>",
  "handle": "ann-lee.chat.example.com",
  "profile": { "display_name": "", "bio": "", "pronouns": "", "accent_color": "", "avatar_emoji": "", "avatar_image": "", "profile_visibility": "shared", "dm_policy": "anyone" },
  "directory": { "statements": [ /* account key statements */ ], "devices": [ /* active and revoked devices */ ] }
}
```

Profile fields are blank when the person shows their profile to nobody. `directory` is exactly what
apps already check (`docs/PROTOCOL.md`): a host stores it for the shadow, and apps verify it the same
way whichever site served it.

A host accepts a card only from the site whose `handle_domain` the address is under, and only from
that same site afterwards (`WRONG_SITE`). An id that's already a local account can't become a
shadow (`ID_TAKEN`).

## Endpoints

### `POST /cvp/v1/act`: do something, as a person

```json
{ "user": { /* the person's card */ }, "function": "messages", "request": "<the app's request body, as sent>" }
```

`CV-User` must equal `user.id`. The host updates the shadow from the card, then runs the request
exactly as it would for one of its own people, and answers with the same status and body. Requests
that carry a device signature (most changes do) are checked against the person's devices, so a home
site can't act for someone without one of their devices. Not allowed: the `admin` function, and
`keys`, `profile` and `safety` except looking people up (`HOME_ONLY`): those are done on the
person's own home.

A home decides where a request goes from the ids in it: every conversation, server, channel and
message has a 24-hex id, and the home learns which site hosts each, for each of its people, from
the answers it relays, from membership notices, and from the person's own choices (see
[Routes](#routes)). A request naming things on two sites is refused (`MIXED_SITES`). An app can
also name a site explicitly with `_site` (browsing another site's servers, joining one by invite).

Requests with no conversation or server named mean "everything of mine": checking for new messages
(`messages.poll`), the conversation and server lists, scheduled messages. The home asks every site
the person has things on and merges the answers. Paging cursors become
`<this site's cursor>~<base64url JSON of { site: cursor }>`, so apps keep one cursor as before.

### `POST /cvp/v1/directory`: a person's card

```json
{ "handle": "ann-lee.chat.example.com", "user_id": "<24 hex>", "purpose": "conversation", "requester": { "id": "<24 hex>", "handle": "bo.other.example" } }
```

Answers `{ "user": <card> }`. For `purpose: "conversation"`, the person must accept new
conversations from **anyone** (people who only accept those they share a server with can't be
checked across sites, so the answer is no) and mustn't have blocked the requester, or the answer is
the same "nobody here" as for a name that doesn't exist.

### `POST /cvp/v1/inbox`: notices

| `type` | Sent by | Meaning |
| --- | --- | --- |
| `membership` | a host | `{ user_id, room: { kind, id }, joined }`: one of your people joined or left something here. For that person only, the home counts it as a claim that the id lives on the sending site (the weakest kind but one: see [Routes](#routes)), and knows where to look for their messages. |
| `keys` | a home | `{ user: <card> }`: this person's keys or devices changed; update the shadow. |
| `block` | a home | `{ user_id, blocked_id, blocked }`: one of our people blocked (or unblocked) someone; apply it on rooms you host. |

### `GET /cvp/v1/discover?tag=`: listed servers

Servers whose admins chose to list them, with only their public card: name, description, tags,
icon, colour and how to join. Not signed; readable by anyone, as on the site itself.

### WebSocket `/cvp/v1/actors/{name}/{room}?id=<connection>`

Realtime rooms (`VoiceRoom` for call set-up, `Presence` for status and typing). An app always
connects to its home; for a room on another site the home opens the connection to the host, signed
like any request, with the person's card in a `CV-Person` header (base64url JSON), and passes
messages both ways. Call audio itself goes peer to peer and is encrypted end to end.

### Files

Attachments are encrypted on the sender's device before upload, and live on the host. A host's
download links are short-lived and signed by it; apps fetch other sites' files through their home
(`/api/fed/files/<site>/<file>`), so an app only ever connects to its own site.

A file id alone doesn't say which site holds the file (the list of a message's files travels inside
its encryption), so an app asking for links (`files`, `download_links`) also names where the
message was posted: `conversation_id`, or `server_id` and `channel_id`. The home routes the request
by those, like any other, and never by file ids, which a message's sender chooses. The app keeps a
link only for an id it asked for, and only for the place it asked about, so a host can't hand out
links for files posted elsewhere and learn when they're opened. The Base44 site doesn't offer files
to other sites yet.

## Routes

A home has to know which site holds each conversation, server and channel its people use. Any
site can claim to hold any id, so since 0.24.25 a home treats each claim as evidence for one
person, weighed by how it was learned, never as a fact for everyone:

| Claim | Learned from | Weight |
| --- | --- | --- |
| Named | The person's app named the site (a non-empty `_site`) and the site answered. That covers what the request names, and, when it joins a server by invite (which names only the code), the server the site joined them to. If another site already holds the thing for that person by a named claim or an old route, it counts as heard instead (below). | 3 |
| From before 0.24.25 | Routes learned under the old rules (one table for everyone, first claim kept). Kept for everyone, so nothing stops working on upgrade. The old table itself is left as it was, so a rollback to 0.24.24 still finds it. | 2 |
| Heard | A site's answer to that person's request, or its membership notice naming them. At most 2000 ids from one answer (200 on the hosted site). | 1 |
| Chosen | An id in an answer under a key whose value an app picks: `thread_id` (a thread is named by its first message), `event_id`, `report_id` (named by their items). | 0 |

- **The heaviest claim decides.** A site naming itself in a notice can't outweigh the site the
  person joined through, or a route the home already had.
- **Naming a site never moves what someone joined from another site.** When the app names a site
  and it answers as the home of something another site already holds for that person, by a named
  claim or a route from before 0.24.25, the home can't tell which of the two is honest. So the answer counts
  only as heard, requests stay where they were, and the log names both sites (at most once an
  hour for each pair). Blocking the wrong one settles it.
- **A tie between two sites is a dispute.** Requests about that id go to neither: the app is told
  `DISPUTED_SITE`, and the home's log names the two sites (never what or whose, and at most once an
  hour for each pair). Claims from blocked sites don't count, so blocking the wrong one settles it.
- **Claims belong to the person they came with.** A notice naming Ann, or an answer to Ann's
  request, never changes where Ben's requests go.
- **Chosen ids only route a request that names nothing else, and only by chosen claims.** A
  thread id can't send a request that names a server anywhere but the server's own site, and a
  membership notice can't steer a request that names only a chosen id. Requests about a place,
  and realtime rooms, never route by chosen claims.
- **Only the top of a request names a place.** A named claim covers the conversation, server or
  channel ids at the top level of the request and of its signed payload, never ids nested deeper.
- **One site keeps at most 2000 claims for one person.** Past that, that site's own oldest claims
  the person's app didn't name go first, so a site sending endless notices only pushes out its
  own claims.
- **No claim counts for an id this site holds**, whatever kind of room the claim says it is. A
  request naming things held here, and otherwise only disputed ids, runs here. The hosted site
  also deletes any claim it finds about something it holds.
- **An old route outweighing a site is reported.** When a route from before 0.24.25 wins over what
  another site now says, the log names both sites, since the old route could be one a site took
  over before the update.

Realtime rooms are found the same way, for the person connecting. The hosted site keeps each
person's claims in `FedClaim` and reads `FedRoute` (from before 0.24.25) as the site-wide ones; it
never routes by chosen ids. Every implementation resolves claims as
`tests/vectors/route-claims.json` says.

What this can't do:

- **Routes taken over before 0.24.25 stay**, for everyone, until the admin blocks the site that
  took them (which makes them stop counting for everyone). Rejoining from the real site doesn't
  move them, because naming a site never moves what someone joined from another site. The log names such a
  site when the real one speaks up. To look yourself: on a self-hosted site, `SELECT host,
  COUNT(*) FROM fed_claims WHERE user_id = '*' GROUP BY host;` in its database lists the sites old
  routes point to; on the hosted site, the `FedRoute` table. Block any site there you don't trust.
  To remove one route by hand on a self-hosted site, delete it from both `fed_claims` and
  `fed_routes`: the old table is kept so a rollback to 0.24.24 still works, and its routes are
  copied in again at each start.
- **Joining from a site means trusting it about what you joined.** Its listing, or an invite link
  pointing at it, chooses the ids; if it lists a copy of another site's server, a person who joins
  from it gets its copy. That only works for someone who hasn't joined the server from another
  site and has no route to it from before 0.24.25: for anyone who has, the copy's answer counts as
  heard and the log names both sites.
- **While nothing else has been said about an id, the only claim decides.** A site can point
  someone's requests about a server elsewhere until they join it (and joining names its site), and
  a site whose people are already in a conversation, so know its id, can claim it before the real
  site's notice arrives (then it's a dispute).
- **A site that knows an id can make it unusable for someone** by disputing where it lives, until
  their admin blocks it. That covers a conversation it's in, and a channel or server whose id it
  has seen, whenever the home knows of it only by heard claims (for example, a conversation
  learned after the update, or a request that names only a channel).
- **Claims are kept until the account goes.** Which remote rooms someone uses, and on which
  sites, is kept with their claims (`fed_claims` and `fed_user_hosts`, or `FedClaim` and
  `FedUserHost` on the hosted site) and removed when their account is deleted. Nothing removes
  them sooner by age.
- **Rolling back loses what was learned since.** A rollback to 0.24.24 finds only the routes
  learned before the update: anything joined on 0.24.25 runs locally or fails until 0.24.24 learns
  it again, first claim kept. Updating again copies every old route in again as a site-wide claim
  (weight 2), including any a site took over while 0.24.24 ran, and those outweigh heard claims.
  The same holds on the hosted site until every function runs the new code: an older function
  can still write `FedRoute`.
- **Whoever answers for a server chooses its keys.** Apps check who signed a server's keys, not
  whether the signer may hand them out: that's the host's job (server membership isn't
  cryptographic yet: [THREAT_MODEL.md](THREAT_MODEL.md)). So a site that receives a person's
  requests about a server can show its own version of it, and read what they then post there.
  That is why where requests go matters.

## When a site can't be reached

A home that can't reach a host holds message sends (and only those: other requests fail with
`SITE_UNREACHABLE`). It answers the app `202 { "queued": true, "site": "<host>" }`, keeps the
sealed, signed request, and tries again after 30 seconds and then less often, up to every 30
minutes, for a week. Messages carry a client-chosen id, so a message delivered twice (by the home,
and by the app's own retry) is stored once. See `docs/OFFLINE.md`.

## What each site learns

| Who | Learns | Doesn't learn |
| --- | --- | --- |
| Your home | Everything it would about any of its people, plus which other sites you use and which conversations and servers there you're in (by id). | What you say (ciphertext), or anything about other sites' people beyond what you're in with them. |
| A host | Your address, public keys, devices and profile (as you share it), and what you do in the conversations and servers there: who sends when, sizes, reactions as encrypted items. | Your other conversations, your sign-in, your email (there isn't one), your recovery phrase. |
| Any other site | Nothing. Sites only contact each other because of people who use both. | |
| A network observer | That two sites talk, and roughly how much. | Content (HTTPS, and end-to-end encryption inside it). |

## Security notes

- **Trust on first use.** A site's key is pinned when first seen. Someone who controls a site's DNS
  before that first contact could present their own key. Admins can compare a site's key (shown in
  **Site admin → Other sites**) with what its admin publishes.
- **A home speaks for its people.** A malicious home can act for its own people (it signs their
  requests), but not forge their device signatures, so it can't send messages or make signed
  changes as them, or read anything. Apps also check people's key histories and warn of changes.
- **First claim on an id wins on each host.** A site could claim an id that belongs to someone on a
  third site before that person first visits the host; that person's requests there are then
  refused. It's a denial of service, not an impersonation: the address shown is the claiming site's.
- **Claims about where things live are weighed, per person.** Before 0.24.25 a home kept the first
  site to mention an id, for everyone, so a site could claim another site's server or channel and
  receive the requests about it. See [Routes](#routes) for what replaced that, and what it still
  can't prevent.
- **A host can withhold.** It can drop or delay messages and refuse service; it can't make apps
  accept a forged one. It does decide who is in the servers it hosts, and so whose keys members'
  apps use there (see [Routes](#routes) and [THREAT_MODEL.md](THREAT_MODEL.md)).
- **Blocking a site.** Admins can block any site; blocked sites' requests are refused both ways.
- **Rate limits** are the host's own, applied to people from other sites as to its own people.

## Versions

The protocol is named in every site document (`commonveil/1`) and in the signed text
(`commonveil-request/v1`). Changes that existing sites would misread get a new version; sites
then speak every version they know. New fields may be added to documents and cards at any time,
and must be ignored by sites that don't know them.

## Endpoints come from the site document

Only `/.well-known/commonveil` is at a fixed address. Everything else (`act`, `directory`,
`inbox`, `discover`, `actors`, `identity`, `files`) is wherever the site document's `endpoints`
says, and other sites use those addresses and sign for them. Each must be a plain path on the
same site; anything else is ignored in favour of the usual address. A site that can only be
reached under a path sets `FEDERATION_PATH_PREFIX` (for example `/functions/federation`). This is
what lets a site on a hosting platform, which can't serve `/cvp/v1/...`, take part.

## The hosted site

The hosted site (the Base44 build) speaks the same protocol, on what a hosted function has
(`base44/shared/federation/`):

- Its site document is a static file the build writes from `federation/site.ts`. Its endpoints
  are one function each: `/functions/fedact`, `feddirectory`, `fedinbox`, `fedidentity`,
  `feddiscover`.
- Its key is made on first use and kept in the backend-only `FedKey` table. What it knows about
  other sites is in `FedSite` (pinned keys; set `blocked` to stop talking to one, delete the row
  to accept a changed key), `FedClaim` (claims about where things live, per person: see
  [Routes](#routes)), `FedRoute` (the site-wide routes from before 0.24.25), `FedUserHost`, `FedShadow` and `FedNonce` (used requests).
- People from other sites have no account there, only what their own site shares: a profile row
  marked `remote`, their public keys, and a `FedShadow` row. They can never sign in there.
- Notices to other sites (someone was added to a conversation, keys changed, a block) are sent
  as part of the request that caused them.
- Every function call checks whether it names something on another site (one small read), and
  if working that out fails, the call carries on locally.

What it doesn't do with other sites: calls and presence, files and pictures in conversations
hosted elsewhere, and holding a message for a site that's down (the app is told instead). Its
site document says so under `limits`. It can't check the address a name resolves to at the
moment of connecting, as self-hosted sites do, so it only connects to public DNS names over
https and relies on the platform's network rules beyond that.

Turning it on: deploy, open `/functions/fedidentity?site=1`, copy the `public_key` it reports
into `federation/site.ts`, set `enabled: true`, and publish.

## The sealed relay (quantum-resistant)

What one site sends another is sealed for that site and signed twice
(`packages/secure-net/spec/CVP-015-quantum-resistance.md`; the code is Secure Net's `wire/sealed`,
`sealed.rs` in its Rust crate and `sealed.js` in the JavaScript copy):

- **Sealed**: the request body is encrypted from site to site with an ephemeral P-256 exchange
  and ML-KEM-768 together, then AES-256-GCM, and bound to the two sites and the endpoint. The
  answer comes back sealed under a one-time key from inside the request. Nothing in between (the
  network, a CDN, a hosting platform's proxy, or someone recording traffic to decrypt years
  later) learns who is writing to whom or what they asked for.
- **Signed twice**: Ed25519 and ML-DSA-65 over the same signature base. Both must verify.
- **No going back**: relay keys are published in the site document (`pq`) and pinned with the
  site's key. A site that has published them is refused if they change or vanish, and plain or
  singly-signed requests from it are refused.

Both kinds of site do this. On a self-hosted site the keys are made on first start and kept with
its data. On the hosted site they are in the `FedKey` table (purpose `relay`), and their public
halves are copied into `federation/site.ts` like the site key. Sites that don't publish relay
keys (older versions) are still talked to as before, until they do.

Message content was already quantum-resistant end to end between people (ML-KEM-768 with P-256).
Still classical: the signatures people's devices put on messages (forging one needs a quantum
computer at the time; a recording is no use), and private voting tokens.
