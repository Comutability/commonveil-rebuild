# Secure Net

Secure Net is the Commonveil Protocol as a library: private, end-to-end encrypted, federated
communication that any app or website can use. Commonveil is built on it, and so can anything
else that wants to talk to Commonveil sites, or to build its own network the same way.

It's plain JavaScript (ES modules) with four small, audited dependencies (`@noble/curves`,
`@noble/hashes`, `@noble/post-quantum`, `@scure/bip39`). It runs in browsers, Node.js 20+ and
Deno, and needs no particular backend, database or host.

## What's in it

| Module | What it does | Spec |
| --- | --- | --- |
| `session/*` | **End-to-end messaging, post-quantum.** A handshake and double ratchet built on X25519 and ML-KEM-768 together, Ed25519 + ML-DSA-65 keys, several devices per person, groups, and moving history to a new device. Draft: awaiting human cryptographic review. | CVP-016 |
| `social/*` | **A federated social protocol, end to end encrypted.** ActivityPub's vocabulary (actors, Create, Follow, Like) and the AT Protocol's portability (key-based identity, moving between sites, signed repositories, lexicons), with followers-only posts, groups and direct messages sealed on devices and quantum-resistant throughout. Draft: awaiting human review. | CVP-017 to CVP-021 |
| `core/canonical`, `core/signed` | One byte-exact encoding for everything signed, and the signed-record envelope every other module uses. | CVP-002 |
| `crypto/*` | Account key chains, device certificates, end-to-end envelopes, post-quantum hybrid sealing, recovery phrases, community keys. The same code Commonveil runs. | CVP-001, CVP-003 |
| `wire/federation`, `wire/features` | How sites sign requests to each other, which addresses they may connect to, and how two sites agree on features. | CVP-005, CVP-008 |
| `commons/ledger` | A community's signed, hash-chained history that approved sites mirror, so a community keeps running when its home site goes down. | CVP-011 |
| `governance/vote`, `governance/debate` | Motions, structured debates, public and secret ballots, recountable results that can authorise changes in the ledger. No blockchain. | CVP-012 |
| `tokens/voprf` | Private one-use tokens (RFC 9497 VOPRF, P-256): secret ballots, anonymous rate limits and reports. | CVP-013 |
| `identity/portable` | Personas (a different face per community) and signed moves between sites. | CVP-001 |
| `consent/capsule` | Specific, time-limited, revocable permissions, honest about what revoking can't undo. | CVP-014 |
| `extensions/manifest` | Extension manifests (what runs where, with which permissions, pinned code) and theme packages (data only, contrast-checked). | CVP-008 |

The specs are in [`spec/`](spec/). [CVP-000](spec/CVP-000-framework.md) says how the standard is
written, versioned and changed; [`spec/registry.json`](spec/registry.json) lists every name two
implementations must agree on; [CVP-010](spec/CVP-010-conformance.md) says how another
implementation shows it conforms; and `npm run standards` checks that the code, registries and
documents agree. [`spec/INTEROPERABILITY.md`](spec/INTEROPERABILITY.md)
explains how sites run by different people stay private, end-to-end encrypted and able to talk.

## Using it

```js
import { ledger, vote, tokens } from "@comutability/secure-net";
// or just one module:
import { genesis, replay } from "@comutability/secure-net/commons/ledger";
```

A community, mirrored and failing over:

```js
const g = ledger.genesis({ name: "Allotment Society", keys: [{ kid: alice.kid, pub: alice.publicKey, caps: ["authority"] }],
  home: { site: "home.example", kid: siteKey.kid, pub: siteKey.publicKey },
  replicas: [{ site: "mirror.example", kid: mirrorKey.kid, pub: mirrorKey.publicKey }], succession: ["mirror.example"] }, alice);
const state = ledger.replay([g]);              // any copy checks every block itself
ledger.chooseHost(state, announcements, { unreachable: new Set(["home.example"]) }); // -> { site: "mirror.example", role: "acting" }
```

End-to-end messages between two devices (the full walk-through, with several devices, a group
and a new device, is [`examples/two-party.mjs`](examples/two-party.mjs): `npm run example`):

```js
import * as s from "@comutability/secure-net/session";
// Bob publishes prekeys; Alice fetches a bundle and checks it against Bob's account key.
let alice = s.initiate({ me: { device, deviceList }, bundle, accountKey: bobsAccountKey });
const { state, message } = await s.encrypt(alice, "Hello");   // send `message` through any relay
// On Bob's device:
const r = await s.respond({ me: { device, deviceList, prekeys }, message, accountKey: alicesAccountKey });
// r.plaintext; store r.state and r.prekeys (the one-time prekeys used are gone)
```

Show people `s.safetyNumber(theirs, yours)` to compare, and warn when an account key changes.

The social protocol, with two sites, follows, followers-only posts, a verifiable repository, a
new object type and a move between sites, is [`examples/social.mjs`](examples/social.mjs)
(`npm run example:social`).

## Working on it

```bash
npm install
npm test                          # node --test
npm run vectors                   # after changing session/primitives: rewrites spec/vectors
node scripts/manifest.mjs         # after any change: updates secure-net.manifest.json
```

Commonveil keeps a copy in `packages/secure-net` and checks it against `secure-net.manifest.json`
on every build, so the two can't drift apart unnoticed. Change Secure Net here, then update
Commonveil's copy with its `npm run secure-net:sync`.

## How it changes

Protocol changes go through public, numbered proposals decided by human maintainers: see
[GOVERNANCE.md](GOVERNANCE.md) and [`snips/`](snips/). (Draft, not yet ratified.)

## Licence

AGPL-3.0-only, the same as Commonveil.
