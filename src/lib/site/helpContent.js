// The Help Centre's articles, bundled into the site at build time (no requests to read them).
import { parseArticle, sortArticles } from "./help.js";

const files = import.meta.glob("../../content/help/*.md", { query: "?raw", import: "default", eager: true });

export const HELP_ARTICLES = sortArticles(
  Object.entries(files).map(([path, raw]) => parseArticle(path.split("/").pop().replace(/\.md$/, ""), raw)),
);

export const helpBySlug = (slug) => HELP_ARTICLES.find((a) => a.slug === slug) || null;
