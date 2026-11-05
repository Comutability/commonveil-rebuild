# Commonveil

Practical guides to owning your digital life, and end-to-end encrypted messaging that doesn't depend on trusting the server.
Built on Base44. Rebuilt from scratch in October 2026; see `docs/REBUILD_REVIEW.md` for why.

**Status: working and tested, not independently audited.** Don't rely on it where someone's safety depends on it until a
review is published.

## What's here

- **Public site:** blog, guides, learning paths, resources, wiki, privacy and security pages, and a private security
  report form (`/security/report`, no account needed). Search, saved pages and guide progress run in the browser and are
  kept there. No analytics or trackers. A Content Security Policy is built in.
- **Encrypted messaging:** direct messages and groups of up to 32, device linking with a compared code, a 24-word recovery
  phrase, key rotation when a device is removed, safety numbers and key-change warnings over each person's whole key
  history, a reset that waits a week so a stolen password can't take an account over, blocking, reporting, and
  self-service account deletion.
- **Also in messaging:** replies, reactions and edits (all encrypted messages the server can't tell apart), disappearing
  messages, group admins, notifications and message search on the device, a passcode lock per browser, security emails
  (new device, recovery phrase used, resets), a download of all your data built in the browser, and opt-in deletion after
  six months or a year without use. `docs/PROTOCOL.md` says exactly what each one stores.
- **Servers, laid out like Discord:** a server rail, channel categories, text, announcement, forum, ticket and voice
  channels, roles and permissions, invites, Discover, profiles and user settings. Everything inside a server is end-to-end
  encrypted with shared key chains; nobody is in a member list unless they choose to be (staff always are). Every new
  account joins the community server, whose admins come from the `DEFAULT_SERVER_ADMINS` secret.
- **Voice calls:** peer to peer for up to 8, with signed connection keys and every audio frame also encrypted under the
  channel's keys.
- **Post-quantum hybrid encryption** (ML-KEM-768 + P-256) wherever a key is sealed to an account or device.
- **Admin area** (`/admin`): reports, security reports, erasing what removed sign-ins left behind, and content editing. It
  needs the admin role, not encryption keys.

## Documents

- `docs/PROTOCOL.md`: the encryption protocol (version 2), exactly as implemented.
- `docs/SERVERS_AND_VOICE.md`: post-quantum keys, servers and voice calls, and platform notes for maintainers (backend
  changes reach members only after publishing; bump an entry file's revision line when its shared code changes).
- `docs/THREAT_MODEL.md`: what is and isn't protected, against whom, and the known limitations.
- `docs/REBUILD_REVIEW.md`: what was wrong with the previous app, the decisions behind this one, and the review findings
  fixed before launch.

## Layout

```
src/lib/crypto/      primitives, keyring, recovery, envelopes, identity (no network, no storage)
src/lib/secure/      client protocol flows, local storage, React state for keys and chat
src/pages/site/      public pages
src/pages/app/       sign-in gate, onboarding, messages, settings, admin
base44/functions/    8 backend functions: profile, keys, conversations, messages, safety, admin, disclose, and
                     maintenance (run on a schedule: disappearing messages, opt-in deletion of unused accounts)
base44/shared/       request handling, signature checks, data access, security emails, scheduled tasks, the handlers
base44/entities/     16 tables; nothing private can be written directly, and members can read only rows that name them
src/lib/site/        saved pages and search for the public site (in the browser only)
tests/               crypto, backend, conversation, site and schema tests (npm test), live browser tests (tests/e2e)
scripts/             check-bundle.mjs: the built site carries its policy and needs nothing it blocks
```

## Checks

```bash
npm test               # 88 tests: crypto; the real backend handlers driven by the real client code; conversations; site; tables
npm run lint
npm run build
npm run check:bundle   # after a build
npm run verify         # all four
```

The live browser suite in `tests/e2e/` runs the real app against the real backend, including a production build under its
Content Security Policy; see its README.

## Running locally

```bash
base44 login   # once per machine
base44 link    # once per clone
base44 dev     # local backend and frontend together
```

Publish from the Base44 dashboard, not with `base44 deploy`, so the deployed state matches the repository.

## Running it for a community

Base44 limits how many queries an app makes per minute. Everyday reads (polling for messages, loading the app) use each
member's own allowance, but writes and lookups across members share one allowance for the whole app, which is larger on
higher Base44 plans. If members see "the service is busy" often, that allowance is the place to look.

The scheduled clean-up (`base44/functions/maintenance/function.jsonc`) runs on the published app: disappearing messages
every 30 minutes and the opt-in deletion of unused accounts daily. Security emails use Base44's built-in email sending.
