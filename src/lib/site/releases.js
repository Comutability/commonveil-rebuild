// Releases: version numbers, comparing them, and the release notes in src/content/releases.json.
// Pure functions, shared by the site's Releases page, the self-hosted update check and
// scripts/release.mjs (which writes CHANGELOG.md and tags each release on GitHub).

const SEMVER = /^(\d{1,4})\.(\d{1,4})\.(\d{1,6})$/;

export const isVersion = (v) => SEMVER.test(String(v || ""));

/** Negative if a is older than b, 0 if equal, positive if newer. Anything malformed sorts oldest. */
export function compareVersions(a, b) {
  const pa = SEMVER.exec(String(a || "").replace(/^v/, ""));
  const pb = SEMVER.exec(String(b || "").replace(/^v/, ""));
  if (!pa || !pb) return pa ? 1 : pb ? -1 : 0;
  for (let i = 1; i <= 3; i += 1) {
    const d = Number(pa[i]) - Number(pb[i]);
    if (d) return d;
  }
  return 0;
}

export const isNewer = (candidate, current) => compareVersions(candidate, current) > 0;

/** Releases newest first, checked: each has a version, a date and notes, and versions are unique. */
export function checkReleases(data) {
  const list = Array.isArray(data?.releases) ? data.releases : [];
  const seen = new Set();
  for (const r of list) {
    if (!isVersion(r.version)) throw new Error(`Bad version: ${r.version}`);
    if (seen.has(r.version)) throw new Error(`Version listed twice: ${r.version}`);
    seen.add(r.version);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(r.date || "")) throw new Error(`${r.version}: bad date`);
    if (!r.title || !Array.isArray(r.notes) || !r.notes.length) throw new Error(`${r.version}: needs a title and notes`);
    if (r.commit !== null && r.commit !== undefined && !/^[0-9a-f]{40}$/.test(r.commit)) throw new Error(`${r.version}: commit must be a full hash`);
  }
  return [...list].sort((x, y) => compareVersions(y.version, x.version));
}

/** The releases up to and including this version (the rest aren't out yet). */
export const releasedUpTo = (releases, version) => releases.filter((r) => compareVersions(r.version, version) <= 0);

/** CHANGELOG.md, from the release notes. */
export function changelog(releases, { repository = "" } = {}) {
  const out = [
    "# Changelog",
    "",
    "Every release of Commonveil. The newest is first. Versions follow [semantic versioning](https://semver.org): a new",
    "minor version (0.x.0) adds features; a patch (0.x.y) fixes things.",
    "",
    "> Generated from `src/content/releases.json` by `scripts/release.mjs`. Edit that file, not this one.",
    "",
  ];
  for (const r of releases) {
    const tag = repository ? `[${r.version}](https://github.com/${repository}/releases/tag/v${r.version})` : r.version;
    out.push(`## ${tag}: ${r.title}`, "", `_${r.date}_`, "");
    for (const n of r.notes) out.push(`- ${n}`);
    out.push("");
  }
  return `${out.join("\n").trim()}\n`;
}

/** The notes for one release as Markdown, for a GitHub release's description. */
export const releaseBody = (r) => `${r.notes.map((n) => `- ${n}`).join("\n")}\n`;
