// Releases, from src/content/releases.json (the one place release notes are written).
//
//   node scripts/release.mjs            write CHANGELOG.md
//   node scripts/release.mjs --check    fail if CHANGELOG.md is out of date, or package.json's
//                                       version has no release notes (run by npm test)
//   node scripts/release.mjs --tag      tag every release (vX.Y.Z) that isn't tagged yet: at its
//                                       recorded commit, or at HEAD for package.json's version
//   node scripts/release.mjs --notes X  print one release's notes (used by the release workflow)
//
// Pushing the tags (git push origin --tags) starts .github/workflows/release.yml, which makes
// the GitHub release and publishes the Docker image for that version.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { changelog, checkReleases, releaseBody, releasedUpTo } from "../src/lib/site/releases.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const data = JSON.parse(readFileSync(join(root, "src/content/releases.json"), "utf8"));
export const releases = checkReleases(data);
export const packageVersion = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
export const changelogText = () => changelog(releasedUpTo(releases, packageVersion), { repository: data.repository });

const git = (...args) => execFileSync("git", args, { cwd: root, encoding: "utf8" }).trim();

function main(argv) {
  if (argv.includes("--notes")) {
    const v = argv[argv.indexOf("--notes") + 1]?.replace(/^v/, "");
    const r = releases.find((x) => x.version === v);
    if (!r) throw new Error(`No release notes for ${v}`);
    process.stdout.write(`## ${r.title}\n\n${releaseBody(r)}`);
    return;
  }
  if (!releases.some((r) => r.version === packageVersion)) {
    throw new Error(`package.json is at ${packageVersion}, which has no entry in src/content/releases.json`);
  }
  const file = join(root, "CHANGELOG.md");
  if (argv.includes("--check")) {
    if (readFileSync(file, "utf8") !== changelogText()) throw new Error("CHANGELOG.md is out of date. Run: npm run release");
    console.log("CHANGELOG.md is up to date.");
    return;
  }
  writeFileSync(file, changelogText());
  console.log("Wrote CHANGELOG.md");
  if (!argv.includes("--tag")) return;
  const existing = new Set(git("tag", "--list", "v*").split("\n").filter(Boolean));
  for (const r of [...releases].reverse()) {
    const tag = `v${r.version}`;
    if (existing.has(tag)) continue;
    let target = r.commit;
    if (!target) {
      if (r.version !== packageVersion) continue; // not released yet
      target = git("rev-parse", "HEAD");
    }
    git("tag", "-a", tag, target, "-m", `Commonveil ${r.version}: ${r.title}\n\n${releaseBody(r)}`);
    console.log(`Tagged ${tag} at ${target.slice(0, 7)}`);
  }
  console.log("Now push them: git push origin --tags");
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    main(process.argv.slice(2));
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}
