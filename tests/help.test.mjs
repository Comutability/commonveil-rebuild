// The Help Centre: every article is well formed, its links lead somewhere real, and the guide in
// the repository (docs/USER_GUIDE.md) matches the articles.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { HELP_SECTIONS, anchorFor, buildGuide, groupBySection, headingsOf, neighbours, parseArticle, searchHelp } from "../src/lib/site/help.js";
import { loadArticles, userGuide } from "../scripts/build-user-guide.mjs";

const articles = loadArticles();
const slugs = new Set(articles.map((a) => a.slug));
const appRoutes = readFileSync(new URL("../src/App.jsx", import.meta.url), "utf8");

test("every help article has a title, summary, known section and a body", () => {
  assert.ok(articles.length >= 20);
  for (const a of articles) {
    assert.ok(a.title && a.summary && a.body.length > 200, a.slug);
    assert.ok(HELP_SECTIONS.includes(a.section), a.slug);
    assert.ok(!/^# /m.test(a.body), `${a.slug}: articles start at "## " under their own title`);
  }
  assert.throws(() => parseArticle("x", "no header"), /no header/);
  assert.throws(() => parseArticle("x", "---\ntitle: A\nsummary: B\nsection: Nope\norder: 1\n---\nbody"), /unknown section/);
});

test("links between help articles, and to the rest of the site, all lead somewhere", () => {
  for (const a of articles) {
    for (const [, href] of a.body.matchAll(/\]\(([^)\s]+)\)/g)) {
      if (/^https?:\/\//.test(href)) continue;
      const help = /^\/help\/([a-z0-9-]+)$/.exec(href);
      if (help) {
        assert.ok(help[1] === "guide" || slugs.has(help[1]), `${a.slug} links to a missing article: ${href}`);
        continue;
      }
      const path = href.split("#")[0].replace(/^\//, "");
      assert.ok(href === "/help" || appRoutes.includes(`path="${path}"`), `${a.slug} links to an unknown page: ${href}`);
    }
  }
});

test("every article is in a section, in reading order, with neighbours", () => {
  const groups = groupBySection(articles);
  assert.deepEqual(groups.map((g) => g.section), HELP_SECTIONS.filter((s) => articles.some((a) => a.section === s)));
  assert.equal(groups.reduce((n, g) => n + g.articles.length, 0), articles.length);
  const first = groups[0].articles[0];
  assert.equal(first.slug, "welcome");
  assert.equal(neighbours(articles, "welcome").previous, null);
  assert.equal(neighbours(articles, "welcome").next.slug, groups[0].articles[1].slug);
});

test("headings get stable anchors, and the combined guide's links jump within it", () => {
  assert.equal(anchorFor("Devices, recovery and resets"), "devices-recovery-and-resets");
  assert.equal(anchorFor("Send later and safety check-ins"), "send-later-and-safety-check-ins");
  assert.deepEqual(headingsOf("## One\ntext\n### Sub\n## Two"), [{ text: "One", id: "one" }, { text: "Two", id: "two" }]);
  const guide = buildGuide(articles, { links: "anchors", siteUrl: "https://example.test" });
  const anchors = new Set([...guide.matchAll(/^#{1,6} (.+)$/gm)].map((m) => anchorFor(m[1])));
  for (const [, target] of guide.matchAll(/\]\(#([^)]+)\)/g)) assert.ok(anchors.has(target), `guide link to #${target} has no heading`);
  assert.ok(!/\]\(\/help\//.test(guide), "no site-relative help links left in the guide");
  assert.ok(guide.includes("](https://example.test/security/report)"), "other site links become full addresses");
});

test("help search finds articles by every word, titles first", () => {
  assert.equal(searchHelp(articles, "check-in")[0].slug, "send-later-and-check-ins");
  assert.equal(searchHelp(articles, "recovery phrase")[0].slug.length > 0, true);
  assert.deepEqual(searchHelp(articles, "x"), []);
  assert.deepEqual(searchHelp(articles, "zebracakesnothing"), []);
});

test("docs/USER_GUIDE.md is up to date with the help articles", () => {
  const current = readFileSync(new URL("../docs/USER_GUIDE.md", import.meta.url), "utf8");
  assert.equal(current, userGuide(), "Run: node scripts/build-user-guide.mjs");
});
