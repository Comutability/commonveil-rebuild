# Commonveil

End-to-end encrypted messaging and communities that don't depend on trusting the server, and
that anyone can run themselves. Sites talk to each other, accounts are owned by a key rather than
an email, and messages keep flowing when the internet doesn't.

Hosted at [commonveil.online](https://commonveil.online) (on Base44), or on your own hardware with
Docker ([`docs/SELF_HOSTING.md`](docs/SELF_HOSTING.md)). Free software under the
[AGPL-3.0](LICENSE).

**Status: working and tested, not independently audited.** Don't rely on it where someone's safety
depends on it until a review is published.

## What's here

- **Encrypted messaging:** direct messages and groups of up to 32, device linking with a compared
  code, a 24-word recovery phrase, key rotation when a device is removed, safety numbers and
  key-change warnings over each person's whole key history, blocking, reporting, and self-service
  account deletion. Replies, reactions, edits, polls, disappearing messages, send later, safety
  check-ins and self-destructing conversations, all as encrypted items the server can't tell apart.
- **Servers, laid out like Discord:** channels (text, announcement, forum, ticket, voice), roles
  and permissions, invites, Discover, moderation and AutoMod. Everything inside is end-to-end
  encrypted with shared key chains.
- **Voice calls:** peer to peer for up to 8, every audio frame also encrypted.
- **Post-quantum hybrid encryption** (ML-KEM-768 + P-256) wherever a key is sealed to an account or device.
- **Offline mode:** messages written with no connection are sealed and signed at once, wait on the
  device, and go out when it's back. Sites hold messages for sites they can't reach. A site can run
  on a small computer with its own Wi-Fi, for chat with no internet ([`docs/OFFLINE.md`](docs/OFFLINE.md)).
- **Self-hosting:** one Docker Compose stack (the app, Caddy for HTTPS, and an updater), with an
  update notice, an update button and optional automatic updates.
- **The Commonveil Protocol:** self-hosted sites talk to each other. Everyone's address is their
  username under their site's domain (`@ann.chat.example.com`), which also opens their profile in a
  browser. Conversations and servers work across sites, still end-to-end encrypted
  ([`docs/FEDERATION.md`](docs/FEDERATION.md)).
- **Commonveil Identity** (self-hosted sites): a username and password, passkeys (on one device or
  in a password manager), new devices confirmed with a passkey, the recovery phrase, the private
  key or another device, and recovery only by those. No email ([`docs/IDENTITY.md`](docs/IDENTITY.md)).
- **Public site:** a Help Centre (`/help`) for every feature, release notes (`/releases`),
  resources, privacy and security pages, and a private security report form. No analytics or
  trackers, and a strict Content Security Policy.

## Documents

| Document | What it covers |
| --- | --- |
| [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) | Every feature, for the people using it. Built from the Help Centre's articles in `src/content/help/`. |
| [`docs/SELF_HOSTING.md`](docs/SELF_HOSTING.md) | Running your own site: install, settings, admins, updates, backups, other sites, no-internet sites. |
| [`docs/FEDERATION.md`](docs/FEDERATION.md) | The Commonveil Protocol (`commonveil/1`): addresses, signed site-to-site requests, endpoints, privacy. |
| [`docs/IDENTITY.md`](docs/IDENTITY.md) | Accounts on self-hosted sites: passkeys, the owner key, device checks, recovery. |
| [`docs/OFFLINE.md`](docs/OFFLINE.md) | Offline mode, holding messages, local sites, and the design for a phone-to-phone mesh. |
| [`docs/PROTOCOL.md`](docs/PROTOCOL.md) | The encryption protocol (version 2), exactly as implemented. |
| [`docs/SERVERS_AND_VOICE.md`](docs/SERVERS_AND_VOICE.md) | Post-quantum keys, servers and voice calls, and platform notes. |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | What is and isn't protected, against whom, and the known limitations. |
| [`docs/REBUILD_REVIEW.md`](docs/REBUILD_REVIEW.md) | Why the app was rebuilt in October 2026, and the review findings fixed before launch. |
| [`CHANGELOG.md`](CHANGELOG.md) | Every release since 0.1.0. |

## Layout

```
src/lib/crypto/      primitives, keyring, recovery, owner key, envelopes, identity (no network, no storage)
src/lib/secure/      client protocol flows, local storage, React state for keys, chat and servers
src/lib/identity/    sign-in on self-hosted sites: passkeys, devices, recovery
src/lib/offline/     offline mode and the outbox of sealed messages
src/pages/           public site, sign-in, the app, settings, admin
src/content/         Help Centre articles, and releases.json (the one place release notes are written)
base44/shared/       the backend: request handling, signature checks, data access, the handlers
base44/functions/    the backend on Base44: 15 functions over base44/shared
base44/actors/       realtime rooms: VoiceRoom (call set-up) and Presence (status and typing)
base44/entities/     the tables, with their access rules
server/              the backend self-hosted: the same handlers, SQLite, sign-in, files, rooms,
                     updates, and the Commonveil Protocol (server/federation/)
updater/             the updater container
deploy/              docker-compose.yml, Caddyfile, .env.example, install.sh
tests/               unit and integration tests (npm test), live browser tests (tests/e2e)
scripts/             release notes and tags, the user guide, the bundle check
```

## Checks

```bash
npm test               # crypto, the real backend handlers driven by the real client code, two real
                       # self-hosted sites talking to each other, sign-in, offline, site, tables
npm run lint
npm run build          # the Base44 site
npm run check:bundle   # after a build
npm run verify         # all of the above
VITE_COMMONVEIL_BACKEND=selfhost npx vite build --outDir dist-selfhost   # the self-hosted site
docker build -t commonveil:local .                                         # the image
```

The live browser suite in `tests/e2e/` runs the real app against the real backend, including a
production build under its Content Security Policy; see its README.

## Releases

Every update is a release, numbered from 0.1.0 (the rebuild) onwards:

1. Add the release to the top of `src/content/releases.json` and set `version` in `package.json`.
2. `npm run release` rewrites `CHANGELOG.md`; `npm test` fails if it's out of date.
3. Commit and push, then `node scripts/release.mjs --tag` and `git push origin --tags`.

Pushing a tag runs `.github/workflows/release.yml`: it makes the GitHub release from the notes and
publishes the Docker image (`ghcr.io/comutability/commonveil:<version>`, and `:latest`) that
self-hosted sites update to. The site shows the same notes at `/releases`.

## The hosted site

```bash
base44 login   # once per machine
base44 link    # once per clone
base44 dev     # local backend and frontend together
```

Publish from the Base44 dashboard, not with `base44 deploy`, so the deployed state matches the
repository. Base44 limits how many queries an app makes per minute; everyday reads use each member's
own allowance, but writes and lookups across members share one allowance for the whole app. The
scheduled tasks are workflows in `base44/workflows/`, each calling the `maintenance` function.
