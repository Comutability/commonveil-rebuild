// What search engines and link previews are told (src/lib/site/seo.js), and how the self-hosted
// server sends it (server/http.mjs): public pages are described and findable; the app, sign-in,
// search, invites and people's profiles are never indexed; unknown pages are real 404s.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import { DEFAULT_SITE_URL, PAGES, headHtml, seoFor, sitemapXml } from "../src/lib/site/seo.js";
import { parseArticle } from "../src/lib/site/help.js";
import { serveStatic } from "../server/http.mjs";

const helpDir = new URL("../src/content/help/", import.meta.url);
const articles = readdirSync(helpDir).filter((f) => f.endsWith(".md")).map((f) => parseArticle(f.replace(/\.md$/, ""), readFileSync(new URL(f, helpDir), "utf8")));

test("every public page has its own title and a description of a useful length", () => {
  const titles = new Set();
  for (const path of [...PAGES.map((p) => p.path), ...articles.map((a) => `/help/${a.slug}`)]) {
    const m = seoFor(path, { articles });
    assert.equal(m.noindex, false, path);
    assert.ok(m.title.length <= 70, `${path} title is short enough to show in full: ${m.title}`);
    assert.ok(m.description.length >= 50 && m.description.length <= 170, `${path} description: ${m.description.length} characters`);
    assert.ok(!titles.has(m.title), `${path} has a title of its own`);
    titles.add(m.title);
    assert.ok(m.jsonLd.length >= 1, `${path} has structured data`);
    for (const d of m.jsonLd) assert.equal(d["@context"], "https://schema.org");
  }
  assert.equal(seoFor("/help/", { articles }).url, `${DEFAULT_SITE_URL}/help`, "one address per page");
  assert.equal(seoFor("/help/notifications", { articles }).jsonLd[0]["@type"], "TechArticle");
});

test("private places are never indexed, and unknown pages are not found", () => {
  for (const path of ["/app", "/app/c/123", "/app/settings/profile", "/admin", "/login", "/register", "/forgot-password", "/reset-password", "/search", "/invite/abc", "/u/ann"]) {
    const m = seoFor(path, { articles });
    assert.equal(m.noindex, true, path);
    assert.equal(m.notFound, false, path);
    assert.deepEqual(m.jsonLd, [], `${path} carries no structured data`);
  }
  for (const path of ["/nothing-here", "/help/no-such-article"]) assert.equal(seoFor(path, { articles }).notFound, true, path);
  assert.equal(seoFor("/wiki/old-page", { articles }).movedTo, "/help");
});

test("the sitemap lists every public page and article, and nothing private", () => {
  const xml = sitemapXml({ siteUrl: "https://chat.example.org", articles, lastmod: "2026-11-06" });
  for (const p of PAGES) assert.ok(xml.includes(`<loc>https://chat.example.org${p.path === "/" ? "/" : p.path}</loc>`), p.path);
  for (const a of articles) assert.ok(xml.includes(`<loc>https://chat.example.org/help/${a.slug}</loc>`), a.slug);
  for (const bad of ["/app", "/login", "/u/", "/search", "/invite"]) assert.ok(!xml.includes(`example.org${bad}`), bad);
  assert.equal((xml.match(/<url>/g) || []).length, PAGES.length + articles.length);
});

test("head tags are escaped, and structured data can't end its script early", () => {
  const html = headHtml({ ...seoFor("/", { articles }), title: `A "quoted" <b>title</b>`, jsonLd: [{ "@context": "https://schema.org", name: "</script><script>alert(1)</script>" }] });
  assert.ok(html.includes("A &quot;quoted&quot; &lt;b&gt;title&lt;/b&gt;"));
  assert.ok(!html.includes("</script><script>"), "no way out of the JSON");
  assert.ok(html.includes('<link rel="canonical"'));
  const hidden = headHtml(seoFor("/app", { articles }));
  assert.ok(hidden.includes('content="noindex, nofollow"'));
  assert.ok(!hidden.includes("og:") && !hidden.includes("canonical"), "nothing to preview or point at for a private page");
});

test("a self-hosted server sends each page with its own tags, real 404s and its own address", async () => {
  const dist = mkdtempSync(join(tmpdir(), "cv-seo-"));
  writeFileSync(join(dist, "index.html"), readFileSync(new URL("../index.html", import.meta.url), "utf8"));
  writeFileSync(join(dist, "help-index.json"), JSON.stringify(articles.map(({ slug, title, summary, section }) => ({ slug, title, summary, section }))));
  writeFileSync(join(dist, "sitemap.xml"), sitemapXml({ articles }));
  writeFileSync(join(dist, "robots.txt"), readFileSync(new URL("../public/robots.txt", import.meta.url), "utf8"));
  const server = http.createServer((req, res) => serveStatic(req, res, dist, "default-src 'none'", { siteUrl: "https://chat.example.org" }));
  await new Promise((r) => server.listen(0, r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const get = (p) => fetch(base + p, { redirect: "manual" });
    let r = await get("/security");
    assert.equal(r.status, 200);
    let html = await r.text();
    assert.match(html, /<title>How the encryption works, and where it stops \| Commonveil<\/title>/);
    assert.ok(html.includes('<link rel="canonical" href="https://chat.example.org/security" />'));
    assert.ok(html.includes('content="https://chat.example.org/og-image.png"'));
    assert.equal((html.match(/<title>/g) || []).length, 1, "one title");
    assert.equal((html.match(/name="description"/g) || []).length, 1, "one description");

    r = await get("/app/settings");
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("x-robots-tag"), "noindex, nofollow");
    assert.ok((await r.text()).includes("noindex"));

    r = await get("/no-such-page");
    assert.equal(r.status, 404, "an unknown address isn't a page of the site");
    assert.ok((await r.text()).includes('<div id="root">'), "but people still get the site's own not-found page");

    r = await get("/guides/old");
    assert.equal(r.status, 301);
    assert.equal(r.headers.get("location"), "/help");

    const sitemap = await (await get("/sitemap.xml")).text();
    assert.ok(sitemap.includes("<loc>https://chat.example.org/help</loc>") && !sitemap.includes(DEFAULT_SITE_URL), "this site's own address");
    const robots = await (await get("/robots.txt")).text();
    assert.ok(robots.includes("Sitemap: https://chat.example.org/sitemap.xml"));
  } finally {
    server.close();
  }
});
