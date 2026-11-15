# Commonveil's server, in Rust

The self-hosted Commonveil server is moving from Node.js (`server/` and the backend in
`base44/shared`) to Rust, stage by stage, with the same HTTP API and the same data on disk. **The
Docker image keeps running the Node.js server until every part is here and matches it.** Then the
image switches, in a release made under [AGENTS.md](../AGENTS.md)'s rules.

## What's here

| Part | Status | Checked against the Node.js server |
| --- | --- | --- |
| Settings (`config`) | Done | Every variable in docs/SELF_HOSTING.md, read the same way |
| Data store (`store`) | Done | Same SQLite file and layout, so a site's existing data is read as it is. The same 1,000 random operations per run (creates, queries with every operator and mixed types, sorting, paging, bulk updates and deletes, and reads and writes as people under the real row rules) give identical answers, across four seeds |
| The site, its pages and their search tags (`http`, `seo`) | Done | ~40 addresses (pages, help articles, private and moved pages, assets, missing files, attempts to climb out of the site folder, the sitemap, HEAD, POST): the same status, security headers and bytes |
| `/api/health`, `/api/site` | Done | As above |
| Sign-in cryptography and sessions (`crypto`, `sessions`) | Done | Against the TypeScript it replaces (base44/shared/identity): password hashes made by either check on the other (with NFKC), access tokens are byte-identical, and bent tokens (extra parts, wrong prefix or signature, expiry boundaries, unparseable claims), unusable password hashes and odd Ed25519 signatures (non-canonical, all-zero key) are judged the same |
| Who's calling, and entity reads and writes (`/api/entities/*`) | Done | Both servers started from the same data: 110 requests (every operation, sorting, paging, odd arguments, refused tables) as nobody, three people of different roles and a bent token give the same status and answer |
| The action runner and its validators (`api`) | Done | Through the identity functions below |
| Sign-in and accounts: `/api/functions/identity`, passkeys (`webauthn`), proofs from encryption devices (through Secure Net's Rust core), first-run setup (`bootstrap`) | Done | The same script of 116 requests runs against each server on a fresh site (setup code, sign-up, passwords, confirming new browsers, refresh and sign-out, account changes, owner keys, a software passkey adding, signing in and recovering, device proofs good and bent, the password lock, malformed requests): every status and answer matches once random values are blanked |
| The other backend functions (`/api/functions/*`) | Next | Until then they answer 501 `NOT_YET` |
| Files, realtime rooms, scheduled tasks, updates, federation and the Commonveil Protocol | To do | |

Anything not yet moved answers `501 NOT_YET`, so a half-moved server can't be mistaken for a
working one.

Deliberate differences: an entity request body over 256 KB is a `413` (the Node.js server answers
`500`, because its size error isn't one it expects), and a body that isn't JSON says "The request
wasn't valid JSON." (Node.js passes on V8's own message, which changes between versions). Ed25519
signatures are checked strictly (canonical encodings, no small-order keys); the cases tested give
the same answer as Node.js's WebCrypto.

What the comparison found: a JSON array sent as a query is read as conditions on the fields
"0", "1", ... (JavaScript's `Object.entries`), so it matches nothing; Rust now does the same. A
`sort` of `null` sorts oldest first in the Node.js store, while a
missing one sorts newest first; Rust now does the same. And JavaScript's `<` isn't a consistent
ordering when a field mixes types, so the order of such a sort is up to the engine: Node.js 22 and
26 give different orders for the same rows. Real fields hold one type each (their schemas say
which), so the comparison sorts only on such fields. The store sorts with a TimSort (`timsort.rs`)
because, unlike the standard library's sort, it never panics on an inconsistent comparison.

## Working on it

```bash
cd rust
cargo test        # unit tests, then the comparison with the Node.js server (needs node and npm ci;
                  # the HTTP comparison also needs the self-hosted site built into dist-selfhost)
cargo clippy --all-targets -- -D warnings
ENTITIES_DIR=../base44/entities DIST_DIR=../dist-selfhost cargo run -p commonveil-server
```

`tests/node/store-ops.mjs` is the only JavaScript here: it drives the Node.js store for the
comparison, and goes when the Node.js server does.

Licence: AGPL-3.0-only.
