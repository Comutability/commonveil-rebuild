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
3. Keep the Docker deployment in step with the release, every time: the `Dockerfile`'s runtime stage must copy everything the server now needs (and its runtime dependencies in the `deps` stage), `deploy/docker-compose.yml` and `deploy/.env.example` must offer any new setting, `deploy/install.sh` must still set up a working site, and `docs/SELF_HOSTING.md` must describe it. Build the image (`docker build -t commonveil:test .`) and run it before tagging.
4. Commit, push, then `node scripts/release.mjs --tag` and `git push origin --tags`. The tag's workflow makes the GitHub release and publishes `ghcr.io/comutability/commonveil:<version>` (and `:latest`), which self-hosted sites are offered as an update.
5. Every tagged commit must build on its own: the workflow builds the image from the tag.

Both the Base44 site (`npm run build`) and the self-hosted site (`VITE_COMMONVEIL_BACKEND=selfhost npx vite build --outDir dist-selfhost`) are built from the same code. Features that only exist on self-hosted sites check `SELF_HOSTED` from `src/api/base44Client.js`.

When shared backend code (`base44/shared/`) changes, bump the "Shared code revision" line in each `base44/functions/*/entry.ts`, so Base44 redeploys them.
