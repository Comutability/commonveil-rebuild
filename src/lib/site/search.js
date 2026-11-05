// Searching the public site, entirely in the browser: the published pages are fetched as they
// are for browsing, and what you type is matched here. It's never sent anywhere, put in the
// address bar or kept.

const fold = (s) => String(s || "").normalize("NFKD").replace(/[̀-ͯ]/g, "").toLowerCase();

/** Markdown to plain text, roughly: enough for matching and snippets. */
export function plainText(markdown) {
  return String(markdown || "")
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/!\[[^\]]*\]\([^)]*\)/g, " ")
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/<[^>]+>/g, " ")
    .replace(/^\s*(?:[-*+]|\d+\.)\s+/gm, "")
    .replace(/^\s*-{3,}\s*$/gm, " ")
    .replace(/[#>*_`~|]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/** Everything searchable, as one list. */
export function toDocs({ resources = [], help = [] }) {
  const docs = [];
  for (const h of help) docs.push({ kind: "help", url: `/help/${h.slug}`, title: h.title, summary: h.summary, category: h.section, tags: [], body: h.body });
  for (const r of resources) docs.push({ kind: "resource", url: "/resources", external: r.website || null, title: r.name, summary: r.description, category: r.category, tags: [r.pricing_summary], body: "" });
  return docs.filter((d) => d.title);
}

function snippetOf(doc, terms) {
  const text = plainText(doc.body) || plainText(doc.summary);
  const folded = fold(text);
  let at = -1;
  for (const t of terms) {
    const i = folded.indexOf(t);
    if (i >= 0 && (at < 0 || i < at)) at = i;
  }
  if (at < 0) return plainText(doc.summary).slice(0, 180);
  const start = Math.max(0, at - 60);
  const end = Math.min(text.length, at + 140);
  return `${start > 0 ? "…" : ""}${text.slice(start, end).trim()}${end < text.length ? "…" : ""}`;
}

/** Pages that contain every word of the query, best matches first. */
export function searchContent(docs, query, { limit = 40 } = {}) {
  const terms = [...new Set(fold(query).split(/\s+/).filter((t) => t.length >= 2))].slice(0, 8);
  if (!terms.length) return [];
  const results = [];
  for (const doc of docs) {
    const title = fold(doc.title);
    const meta = fold([doc.summary, doc.category, ...(doc.tags || [])].filter(Boolean).join(" "));
    const body = fold(plainText(doc.body));
    let score = 0;
    let all = true;
    for (const t of terms) {
      const inTitle = title.includes(t);
      const inMeta = meta.includes(t);
      const inBody = body.includes(t);
      if (!inTitle && !inMeta && !inBody) {
        all = false;
        break;
      }
      score += (inTitle ? 10 : 0) + (inMeta ? 4 : 0) + (inBody ? 1 : 0);
    }
    if (all) results.push({ doc, score, snippet: snippetOf(doc, terms) });
  }
  results.sort((a, b) => b.score - a.score || a.doc.title.localeCompare(b.doc.title));
  return results.slice(0, limit);
}
