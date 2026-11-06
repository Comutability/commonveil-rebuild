// The Help Centre: articles written as Markdown files in src/content/help, each with a small
// header (title, summary, section, order). Pure functions only, so the same code builds the
// website's help pages and docs/USER_GUIDE.md (scripts/build-user-guide.mjs).

/** The order sections appear in, everywhere. */
export const HELP_SECTIONS = Object.freeze([
  "Getting started",
  "Messages and calls",
  "Servers",
  "Running a server",
  "Privacy and safety",
  "Your account",
  "Running your own site",
  "Help",
]);

const FIELDS = ["title", "summary", "section", "order"];

/** One article from its file text. Throws if the header is missing or incomplete. */
export function parseArticle(slug, raw) {
  const text = String(raw || "").replace(/\r\n/g, "\n");
  const match = /^---\n([\s\S]*?)\n---\n?/.exec(text);
  if (!match) throw new Error(`Help article ${slug} has no header.`);
  const meta = {};
  for (const line of match[1].split("\n")) {
    const at = line.indexOf(":");
    if (at > 0) meta[line.slice(0, at).trim()] = line.slice(at + 1).trim();
  }
  for (const f of FIELDS) if (!meta[f]) throw new Error(`Help article ${slug} is missing "${f}".`);
  if (!HELP_SECTIONS.includes(meta.section)) throw new Error(`Help article ${slug} has an unknown section "${meta.section}".`);
  return {
    slug,
    title: meta.title,
    summary: meta.summary,
    section: meta.section,
    order: Number(meta.order) || 0,
    body: text.slice(match[0].length).trim(),
  };
}

/** Articles in reading order: by section, then by their order number. */
export function sortArticles(articles) {
  return [...articles].sort(
    (a, b) => HELP_SECTIONS.indexOf(a.section) - HELP_SECTIONS.indexOf(b.section) || a.order - b.order || a.title.localeCompare(b.title),
  );
}

/** [{ section, articles }] for each section that has any. */
export function groupBySection(articles) {
  const sorted = sortArticles(articles);
  return HELP_SECTIONS.map((section) => ({ section, articles: sorted.filter((a) => a.section === section) })).filter((g) => g.articles.length);
}

/** A heading's anchor: lower case, letters and digits joined by hyphens. */
export function anchorFor(text) {
  return String(text || "")
    .toLowerCase()
    .replace(/[*_`]/g, "")
    .replace(/&/g, " and ")
    .replace(/[^\p{L}\p{N}]+/gu, "-")
    .replace(/^-+|-+$/g, "");
}

/** The article's "## " headings, for an on-page contents list. */
export function headingsOf(body) {
  return String(body || "")
    .split("\n")
    .filter((l) => /^## /.test(l))
    .map((l) => {
      const text = l.slice(3).trim();
      return { text, id: anchorFor(text) };
    });
}

/** The article before and after this one, in reading order. */
export function neighbours(articles, slug) {
  const sorted = sortArticles(articles);
  const i = sorted.findIndex((a) => a.slug === slug);
  return { previous: i > 0 ? sorted[i - 1] : null, next: i >= 0 && i < sorted.length - 1 ? sorted[i + 1] : null };
}

/** Demote headings by one level, so an article's "## " sits under its own title in a combined guide. */
const demote = (body) => body.replace(/^(#{2,5}) /gm, (_, h) => `${h}# `);

/**
 * Every article as one Markdown document.
 * links: "site" keeps links as /help/… pages; "anchors" turns links between articles into
 * links within the document, and other site links into full addresses on siteUrl.
 */
export function buildGuide(articles, { links = "site", siteUrl = "", title = "Commonveil: the complete guide", intro = "" } = {}) {
  const groups = groupBySection(articles);
  // Each article's heading anchor, the way GitHub and the site's own pages both make it.
  const anchorOf = new Map(articles.map((a) => [a.slug, anchorFor(a.title)]));
  const fixLinks = (md) => {
    if (links !== "anchors") return md;
    return md.replace(/\]\((\/[^)\s]*)\)/g, (whole, href) => {
      const m = /^\/help\/([a-z0-9-]+)\/?(#.*)?$/.exec(href);
      if (m && anchorOf.has(m[1])) return `](#${anchorOf.get(m[1])})`;
      if (href === "/help/guide" || href === "/help") return "](#contents)";
      return siteUrl ? `](${siteUrl.replace(/\/$/, "")}${href})` : whole;
    });
  };
  const out = [`# ${title}`, ""];
  if (intro) out.push(intro.trim(), "");
  out.push("## Contents", "");
  for (const g of groups) {
    out.push(`**${g.section}**`, "");
    for (const a of g.articles) out.push(`- [${a.title}](${links === "anchors" ? `#${anchorOf.get(a.slug)}` : `/help/${a.slug}`}): ${a.summary}`);
    out.push("");
  }
  for (const g of groups) {
    out.push(`## ${g.section}`, "");
    for (const a of g.articles) {
      out.push(`### ${a.title}`, "", `_${a.summary}_`, "", fixLinks(demote(demote(a.body))), "");
    }
  }
  return `${out.filter((l, i, all) => !(l === "" && all[i - 1] === "")).join("\n").trim()}\n`;
}

/** Search help articles in the browser: every word must appear. Best matches first. */
export function searchHelp(articles, query) {
  const fold = (s) => String(s || "").normalize("NFKD").replace(/[̀-ͯ]/g, "").toLowerCase();
  const terms = [...new Set(fold(query).split(/\s+/).filter((t) => t.length >= 2))].slice(0, 8);
  if (!terms.length) return [];
  return sortArticles(articles)
    .map((a) => {
      const title = fold(a.title);
      const all = `${title} ${fold(a.summary)} ${fold(a.body)}`;
      if (!terms.every((t) => all.includes(t))) return null;
      const score = terms.reduce((s, t) => s + (title.includes(t) ? 10 : 0) + (fold(a.summary).includes(t) ? 4 : 0), 0);
      return { article: a, score };
    })
    .filter(Boolean)
    .sort((x, y) => y.score - x.score)
    .map((r) => r.article);
}
