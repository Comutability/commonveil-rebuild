# Commonveil

Practical guides to owning your digital life, and end-to-end encrypted messaging that doesn't depend on trusting the server.
Built on Base44. Rebuilt from scratch in October 2026; see `docs/REBUILD_REVIEW.md` for why.

**Status: working and tested, not independently audited.** Don't rely on it where someone's safety depends on it until a
review is published.

## What's here

- **Public site:** blog, guides, learning paths, resources, wiki, privacy and security pages. No analytics or trackers.
- **Encrypted messaging:** direct messages and groups of up to 32, device linking with a compared code, a 24-word recovery
  phrase, key rotation when a device is removed, safety numbers and key-change warnings, blocking and reporting.
- **Admin area** (`/admin`): reports and content editing. It needs the admin role, not encryption keys.

## Documents

- `docs/PROTOCOL.md`: the encryption protocol, exactly as implemented.
- `docs/THREAT_MODEL.md`: what is and isn't protected, against whom.
- `docs/REBUILD_REVIEW.md`: what was wrong with the previous app and the decisions behind this one.

## Layout

```
src/lib/crypto/      primitives, keyring, recovery, envelopes, identity (no network, no storage)
src/lib/secure/      client protocol flows, local storage, React state for keys and chat
src/pages/site/      public pages
src/pages/app/       sign-in gate, onboarding, messages, settings, admin
base44/functions/    6 backend functions: profile, keys, conversations, messages, safety, admin
base44/shared/       request handling, signature checks, data access, the action handlers
base44/entities/     13 tables; everything private is backend-only
tests/               crypto and backend tests (npm test), live browser tests (tests/e2e)
```

## Checks

```bash
npm test          # 40 tests: crypto, plus the real backend handlers driven by the real client code
npm run lint
npm run build
npm run verify    # all three
```

The live browser suite in `tests/e2e/` runs the real app against the real backend; see its README.

## Running locally

```bash
base44 login   # once per machine
base44 link    # once per clone
base44 dev     # local backend and frontend together
```

Publish from the Base44 dashboard, not with `base44 deploy`, so the deployed state matches the repository.
