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
| Sign-in and accounts (passkeys, sessions, devices) | Next | |
| Backend functions (`/api/functions/*`), entity reads (`/api/entities/*`), files, realtime rooms, scheduled tasks, updates, federation and the Commonveil Protocol | To do | |

Anything not yet moved answers `501 NOT_YET`, so a half-moved server can't be mistaken for a
working one.

What the comparison found: a `sort` of `null` sorts oldest first in the Node.js store, while a
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
