# AGENTS.md

## Project Context

This is a Base44 app repository. Treat it as user-owned application code, keep changes focused on the user's request, and preserve existing project conventions.

Start with `README.md` for local setup, environment variables, and publish workflow.

## Base44 References

- CLI overview: https://docs.base44.com/developers/references/cli/get-started/overview.md
- Agent skills: https://docs.base44.com/developers/backend/overview/skills.md

If your agent supports Agent Skills, install or update Base44 skills before Base44-specific work:

```bash
npx skills add base44/skills
```

## Key Files

- `src/`: frontend application source.
- `src/api/base44Client.js`: frontend Base44 SDK client.
- `vite.config.js`: Vite config and Base44 Vite plugin setup.
- `.env.local`: local-only environment values; never commit secrets.

## Working Notes

- Use `base44 dev` as the default local development command when you need the local Base44 backend. It can run the backend and frontend together.
- When docs or code mention the frontend being started automatically, that usually means the Base44 project config includes `site.serveCommand`, for example `"serveCommand": "npm run dev"` in `base44/config.jsonc`.
- Use `npm run dev` only for frontend-only work against the hosted Base44 backend.
- Prefer the existing Base44 CLI workflow over adding new npm scripts for Base44-specific tasks.
- Reuse the existing SDK client and Vite plugin patterns before adding new Base44 integration paths.
- Run the relevant checks from `package.json` before finishing code changes.

## Releases and the Docker deployment

Every update to the project is a release. Never ship an update without one:

1. Add the release at the top of `src/content/releases.json` (version, date, title, plain-language notes for people who use Commonveil) and set the same `version` in `package.json`.
2. Run `npm run release` to rewrite `CHANGELOG.md`, then `npm run verify`.
3. Keep the Docker deployment in step with the release, every time: the `Dockerfile` builds the site (Node.js) and the Rust server, and its runtime stage must copy everything the server reads at run time (today `package.json`, `base44/entities` and the built site); `deploy/docker-compose.yml` and `deploy/.env.example` must offer any new setting, `deploy/install.sh` must still set up a working site, and `docs/SELF_HOSTING.md` must describe it. Set the same version in `rust/commonveil-server/Cargo.toml` and `rust/commonveil-updater/Cargo.toml`. Build both images (`docker build -t commonveil:test .` and `docker build -t commonveil-updater:test -f updater/Dockerfile .`) and run them before tagging (the `images` check does this for every pull request).
4. Commit, push, then `node scripts/release.mjs --tag` and `git push origin --tags`. The tag's workflow makes the GitHub release and publishes `ghcr.io/comutability/commonveil:<version>` (and `:latest`), which self-hosted sites are offered as an update.
5. Every tagged commit must build on its own: the workflow builds the image from the tag.

Both the Base44 site (`npm run build`) and the self-hosted site (`VITE_COMMONVEIL_BACKEND=selfhost npx vite build --outDir dist-selfhost`) are built from the same code. Features that only exist on self-hosted sites check `SELF_HOSTED` from `src/api/base44Client.js`.

Self-hosted sites run the Rust server (`rust/commonveil-server`) and updater (`rust/commonveil-updater`), from 0.24.0. The Node.js server (`server/`) and updater (`updater/updater.mjs`) stay only as the reference the Rust tests compare against (`cd rust && cargo test`), until they're retired: a backend change goes into the Rust server, and into `base44/shared/` (which the Base44 site runs) and the Node.js reference too, so the comparison keeps passing.

When shared backend code (`base44/shared/`) changes, bump the "Shared code revision" line in each `base44/functions/*/entry.ts`, so Base44 redeploys them.

## Keeping up with the protocol

Commonveil is built on Secure Net (https://github.com/Comutability/secure-net). From 0.23.0 on, Commonveil follows the protocol: whenever Secure Net changes, bring Commonveil up to it in the next release.

Secure Net is Rust only from 0.7.0. The Rust server uses its crates, pinned to one Secure Net commit in `rust/Cargo.toml` (the OpenMLS copies) and `rust/commonveil-server/Cargo.toml` (`secure-net-core`), always the same commit in both. `packages/secure-net` is the JavaScript copy of Secure Net 0.5.0, the last version with JavaScript, which the browser app and the Base44 functions use until they move to Rust; it can't be synced any more, and must never be edited directly (`npm run verify` checks it against its manifest).

1. When Secure Net's version changes, the Secure Net workflow opens a pull request moving the pin, with the Rust tests already run; to do it by hand, put the new commit in both files, then `cargo update -p secure-net-core -p openmls_traits -p openmls_rust_crypto` and `cargo test` in `rust/`.
2. Read what changed (Secure Net's `snips/`, `spec/registry.json` and each part's "Changes" table) and update what Commonveil builds on it, in the same pull request: the Rust server, `src/lib/secure/pq/`, `base44/shared/handlers/protocol.ts`, the federation code, and `docs/SECURE_NET_LAYER.md`. A change the browser app or the Base44 functions must follow has to be carried into their JavaScript by hand while they use the 0.5.0 copy.
3. A breaking protocol change needs a migration that keeps existing messages readable, written into the release notes.
4. Anything built on parts Secure Net marks Draft stays opt-in and labelled experimental in the app until that part has been reviewed and accepted.
5. Then release as above.
