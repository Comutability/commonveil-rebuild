// Release notes and version numbers: well formed, in order, and the changelog matches them.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { checkReleases, compareVersions, isNewer, releasedUpTo } from "../src/lib/site/releases.js";
import { changelogText, packageVersion, releases } from "../scripts/release.mjs";

test("versions compare as numbers, not text", () => {
  assert.ok(compareVersions("0.10.0", "0.9.0") > 0);
  assert.ok(compareVersions("1.0.0", "0.99.99") > 0);
  assert.equal(compareVersions("v0.4.1", "0.4.1"), 0);
  assert.ok(isNewer("0.16.0", "0.15.0"));
  assert.ok(!isNewer("0.15.0", "0.15.0"));
  assert.ok(!isNewer("not-a-version", "0.1.0"), "nothing malformed is ever offered as an update");
});

test("every release has a unique version, a date, notes, and a full commit hash once released", () => {
  assert.equal(releases.at(-1).version, "0.1.0", "the first release is 0.1.0");
  assert.ok(releases.some((r) => r.version === packageVersion), "package.json's version has release notes");
  for (let i = 1; i < releases.length; i += 1) assert.ok(compareVersions(releases[i - 1].version, releases[i].version) > 0);
  for (const r of releasedUpTo(releases, packageVersion)) {
    if (r.version !== packageVersion) assert.match(r.commit || "", /^[0-9a-f]{40}$/, `${r.version} records the commit it was released from`);
  }
  assert.throws(() => checkReleases({ releases: [{ version: "1.0", date: "2026-01-01", title: "x", notes: ["y"] }] }), /Bad version/);
  assert.throws(() => checkReleases({ releases: [{ version: "1.0.0", date: "2026-01-01", title: "x", notes: ["y"] }, { version: "1.0.0", date: "2026-01-01", title: "x", notes: ["y"] }] }), /twice/);
});

test("the site only lists releases up to its own version", () => {
  const shown = releasedUpTo(releases, "0.4.0");
  assert.equal(shown[0].version, "0.4.0");
  assert.ok(shown.every((r) => compareVersions(r.version, "0.4.0") <= 0));
});

test("CHANGELOG.md is up to date with the release notes", () => {
  assert.equal(readFileSync(new URL("../CHANGELOG.md", import.meta.url), "utf8"), changelogText(), "Run: npm run release");
});
