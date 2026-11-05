// Builds docs/USER_GUIDE.md from the Help Centre's articles (src/content/help), so the guide
// in the repository and the help pages on the website always say the same thing.
//   node scripts/build-user-guide.mjs          write docs/USER_GUIDE.md
//   node scripts/build-user-guide.mjs --check  fail if it's out of date (run by npm test)
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildGuide, parseArticle } from "../src/lib/site/help.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
export const SITE_URL = "https://commonveil-rebuild-71d823fd.base44.app";
const OUT = join(root, "docs", "USER_GUIDE.md");

export function loadArticles() {
  const dir = join(root, "src", "content", "help");
  return readdirSync(dir)
    .filter((f) => f.endsWith(".md"))
    .map((f) => parseArticle(f.replace(/\.md$/, ""), readFileSync(join(dir, f), "utf8")));
}

export function userGuide() {
  const intro = [
    "Everything Commonveil does, what each feature is for, how to use it, and exactly what it shares.",
    "",
    `The same guide is on the website, one topic per page, at [${SITE_URL}/help](${SITE_URL}/help).`,
    "",
    "> This file is generated from `src/content/help/*.md` by `scripts/build-user-guide.mjs`. Edit the articles, then run",
    "> `node scripts/build-user-guide.mjs`; `npm test` fails if this file is out of date. For the technical design, see",
    "> `PROTOCOL.md`, `SERVERS_AND_VOICE.md` and `THREAT_MODEL.md` in this folder.",
  ].join("\n");
  return buildGuide(loadArticles(), { links: "anchors", siteUrl: SITE_URL, intro });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const text = userGuide();
  if (process.argv.includes("--check")) {
    const current = readFileSync(OUT, "utf8");
    if (current !== text) {
      console.error("docs/USER_GUIDE.md is out of date. Run: node scripts/build-user-guide.mjs");
      process.exit(1);
    }
    console.log("docs/USER_GUIDE.md is up to date.");
  } else {
    writeFileSync(OUT, text);
    console.log(`Wrote docs/USER_GUIDE.md (${text.length} characters).`);
  }
}
