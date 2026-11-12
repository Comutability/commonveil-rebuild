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
| `core/canonical`, `core/signed` | One byte-exact encoding for everything signed, and the signed-record envelope every other module uses. | CVP-002 |
| `crypto/*` | Account key chains, device certificates, end-to-end envelopes, post-quantum hybrid sealing, recovery phrases, community keys. The same code Commonveil runs. | CVP-001, CVP-003 |
| `wire/federation`, `wire/features` | How sites sign requests to each other, which addresses they may connect to, and how two sites agree on features. | CVP-005, CVP-008 |
| `commons/ledger` | A community's signed, hash-chained history that approved sites mirror, so a community keeps running when its home site goes down. | CVP-011 |
| `governance/vote`, `governance/debate` | Motions, structured debates, public and secret ballots, recountable results that can authorise changes in the ledger. No blockchain. | CVP-012 |
| `tokens/voprf` | Private one-use tokens (RFC 9497 VOPRF, P-256): secret ballots, anonymous rate limits and reports. | CVP-013 |
| `identity/portable` | Personas (a different face per community) and signed moves between sites. | CVP-001 |
| `consent/capsule` | Specific, time-limited, revocable permissions, honest about what revoking can't undo. | CVP-014 |
| `extensions/manifest` | Extension manifests (what runs where, with which permissions, pinned code) and theme packages (data only, contrast-checked). | CVP-008 |

The specs are in [`spec/`](spec/). [`spec/INTEROPERABILITY.md`](spec/INTEROPERABILITY.md)
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

## Working on it

```bash
npm install
npm test                          # node --test
node scripts/manifest.mjs         # after any change: updates secure-net.manifest.json
```

Commonveil keeps a copy in `packages/secure-net` and checks it against `secure-net.manifest.json`
on every build, so the two can't drift apart unnoticed. Change Secure Net here, then update
Commonveil's copy with its `npm run secure-net:sync`.

## Licence

AGPL-3.0-only, the same as Commonveil.
