# The Commonveil Protocol (`commonveil/1`)

How Commonveil sites talk to each other: how people are found by their address, how a
conversation or a server on one site is used by people from others, and what each site learns.
This is the specification; `server/federation/` is the implementation, and
`tests/federation.test.mjs` runs two real sites against each other.

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
message has a 24-hex id, and the home learns which site hosts each from the answers it relays and
from membership notices. A request naming things on two sites is refused (`MIXED_SITES`). An app
can also name a site explicitly with `_site` (browsing another site's servers, joining one by
invite).

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
| `membership` | a host | `{ user_id, room: { kind, id }, joined }`: one of your people joined or left something here. The home then knows where that id lives, and where to look for that person's messages. |
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
- **A host can withhold.** It can drop or delay messages and refuse service; it can't make apps
  accept a forged one.
- **Blocking a site.** Admins can block any site; blocked sites' requests are refused both ways.
- **Rate limits** are the host's own, applied to people from other sites as to its own people.

## Versions

The protocol is named in every site document (`commonveil/1`) and in the signed text
(`commonveil-request/v1`). Changes that existing sites would misread get a new version; sites
then speak every version they know. New fields may be added to documents and cards at any time,
and must be ignored by sites that don't know them.
