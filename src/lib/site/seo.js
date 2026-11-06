// What search engines and link previews learn about each page of the public site
// (docs/SEO.md). Pure functions only: the browser (src/components/site/Seo.jsx), the build
// (sitemap.xml, in vite.config.js) and the self-hosted server (its HTML) all use this file, so
// they always agree.
//
// Only the public site is indexed. The app, sign-in pages, search results, invites and people's
// profiles never are: a profile is someone's, not ours to put in a search engine.

export const SITE_NAME = "Commonveil";
/** Where the site lives when nothing else says (the Base44 build). Self-hosted sites use their own. */
export const DEFAULT_SITE_URL = "https://commonveil-rebuild-71d823fd.base44.app";
export const DEFAULT_DESCRIPTION =
  "End-to-end encrypted messages, groups, communities and calls. Open source, free, and you can run it yourself.";
/** The picture shown when a link to the site is shared (1200 × 630). */
export const SHARE_IMAGE = "/og-image.png";
export const SHARE_IMAGE_ALT = "Commonveil: private messages and communities, end-to-end encrypted.";
export const SOURCE_URL = "https://github.com/Comutability/commonveil-rebuild";

/** The public pages, in sitemap order. */
export const PAGES = Object.freeze([
  {
    path: "/",
    title: "Commonveil: encrypted messages and communities you can trust",
    description:
      "Private messages, groups, communities and calls, end-to-end encrypted so not even we can read them. Open source, free, no phone number, and you can run it yourself.",
    priority: "1.0",
  },
  {
    path: "/help",
    title: "Help Centre",
    description: "How to use Commonveil: getting started, messages and calls, servers, privacy and safety, your account and running your own site.",
    priority: "0.9",
  },
  {
    path: "/help/guide",
    title: "The complete guide",
    description: "Every Commonveil feature on one page: what it's for, how to use it, and exactly what it shares.",
    priority: "0.7",
  },
  {
    path: "/security",
    title: "How the encryption works, and where it stops",
    description: "Commonveil's end-to-end encryption in plain language: what it protects, what the server can still see, and the limits we know about.",
    priority: "0.8",
  },
  {
    path: "/privacy",
    title: "Privacy: exactly what we hold, and what we can't see",
    description: "Every piece of information Commonveil stores, why, and for how long. Your messages, keys and searches never reach us in readable form.",
    priority: "0.8",
  },
  {
    path: "/terms",
    title: "Terms of Use",
    description: "The rules for using Commonveil, in plain language: who can join, what isn't allowed, and what happens to your account and data.",
    priority: "0.4",
  },
  {
    path: "/resources",
    title: "Privacy tools worth knowing about",
    description: "A short, opinionated list of privacy and self-hosting tools. Nobody pays to be here, and nothing is an affiliate link.",
    priority: "0.6",
  },
  {
    path: "/releases",
    title: "What's changed: release notes",
    description: "Every Commonveil release, newest first, in plain language.",
    priority: "0.5",
  },
  {
    path: "/security/report",
    title: "Report a security problem",
    description: "Found a security problem in Commonveil? How to tell us privately, and what happens next.",
    priority: "0.4",
  },
]);

/** Old addresses (guides, learning paths, the wiki and the blog, removed in 0.15.0), now the Help Centre. */
export const MOVED = /^\/(blog|guides|paths|wiki)(\/[^/]+)?$|^\/saved$/;

/** Paths that are never indexed: they're someone's, they're private, or they say nothing new. */
const PRIVATE = [/^\/app(\/|$)/, /^\/admin(\/|$)/, /^\/login\/?$/, /^\/register\/?$/, /^\/forgot-password\/?$/, /^\/reset-password\/?$/, /^\/search\/?$/, /^\/invite\//, /^\/u\//];

/** "/help/" and "/help" are the same page; only the first is kept as written. */
export function normalPath(pathname) {
  const p = String(pathname || "/").split(/[?#]/)[0] || "/";
  return p.length > 1 ? p.replace(/\/+$/, "") : "/";
}

const fullTitle = (title) => (title.includes(SITE_NAME) ? title : `${title} | ${SITE_NAME}`);

/**
 * What a page tells search engines. articles: the Help Centre's ({ slug, title, summary, section }).
 * Returns { path, title, description, noindex, notFound, ogType, jsonLd }.
 */
export function seoFor(pathname, { articles = [], siteUrl = DEFAULT_SITE_URL } = {}) {
  const path = normalPath(pathname);
  const base = String(siteUrl).replace(/\/+$/, "");
  const url = base + (path === "/" ? "/" : path);
  const page = PAGES.find((p) => p.path === path);
  if (page) {
    const jsonLd = [breadcrumbs(base, path, page.title)];
    if (path === "/") jsonLd.splice(0, 1, ...homeData(base));
    if (path === "/help") jsonLd.push(helpIndexData(base, articles));
    return { path, url, title: fullTitle(page.title), description: page.description, noindex: false, notFound: false, ogType: "website", jsonLd };
  }
  const article = /^\/help\/([a-z0-9-]+)$/.exec(path);
  const a = article && articles.find((x) => x.slug === article[1]);
  if (a) {
    return {
      path,
      url,
      title: fullTitle(a.title),
      description: a.summary,
      noindex: false,
      notFound: false,
      ogType: "article",
      section: a.section,
      jsonLd: [articleData(base, a), breadcrumbs(base, path, a.title, a.section)],
    };
  }
  if (MOVED.test(path)) return { path, url, title: fullTitle("Help Centre"), description: DEFAULT_DESCRIPTION, noindex: true, notFound: false, movedTo: "/help", ogType: "website", jsonLd: [] };
  if (PRIVATE.some((re) => re.test(path))) {
    const title = /^\/(login|register|forgot-password|reset-password)$/.test(path) ? `${{ login: "Sign in", register: "Create an account", "forgot-password": "Can't sign in?", "reset-password": "Choose a new password" }[path.slice(1)]} | ${SITE_NAME}` : SITE_NAME;
    return { path, url, title, description: DEFAULT_DESCRIPTION, noindex: true, notFound: false, ogType: "website", jsonLd: [] };
  }
  return { path, url, title: `Page not found | ${SITE_NAME}`, description: DEFAULT_DESCRIPTION, noindex: true, notFound: true, ogType: "website", jsonLd: [] };
}

function homeData(base) {
  const org = {
    "@context": "https://schema.org",
    "@type": "Organization",
    "@id": `${base}/#organization`,
    name: SITE_NAME,
    url: `${base}/`,
    logo: `${base}/icons/icon-512.png`,
    sameAs: [SOURCE_URL],
  };
  const site = {
    "@context": "https://schema.org",
    "@type": "WebSite",
    "@id": `${base}/#website`,
    name: SITE_NAME,
    url: `${base}/`,
    inLanguage: "en-GB",
    publisher: { "@id": `${base}/#organization` },
  };
  const app = {
    "@context": "https://schema.org",
    "@type": "WebApplication",
    name: SITE_NAME,
    url: `${base}/`,
    description: DEFAULT_DESCRIPTION,
    applicationCategory: "CommunicationApplication",
    operatingSystem: "Any (runs in a web browser; can be installed)",
    browserRequirements: "A current web browser",
    isAccessibleForFree: true,
    license: "https://www.gnu.org/licenses/agpl-3.0.html",
    codeRepository: SOURCE_URL,
    offers: { "@type": "Offer", price: "0", priceCurrency: "GBP" },
    publisher: { "@id": `${base}/#organization` },
  };
  return [org, site, app];
}

function articleData(base, a) {
  return {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    headline: a.title,
    description: a.summary,
    articleSection: a.section,
    inLanguage: "en-GB",
    url: `${base}/help/${a.slug}`,
    mainEntityOfPage: `${base}/help/${a.slug}`,
    isPartOf: { "@type": "WebSite", name: SITE_NAME, url: `${base}/` },
    publisher: { "@type": "Organization", name: SITE_NAME, url: `${base}/` },
  };
}

function helpIndexData(base, articles) {
  return {
    "@context": "https://schema.org",
    "@type": "ItemList",
    name: "Commonveil Help Centre",
    itemListElement: articles.map((a, i) => ({ "@type": "ListItem", position: i + 1, url: `${base}/help/${a.slug}`, name: a.title })),
  };
}

function breadcrumbs(base, path, title) {
  const items = [{ name: SITE_NAME, url: `${base}/` }];
  if (path.startsWith("/help/")) items.push({ name: "Help Centre", url: `${base}/help` });
  if (path === "/security/report") items.push({ name: "Security", url: `${base}/security` });
  items.push({ name: title.replace(/ \| Commonveil$/, ""), url: base + path });
  return {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    itemListElement: items.map((it, i) => ({ "@type": "ListItem", position: i + 1, name: it.name, item: it.url })),
  };
}

const escapeXml = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
export const escapeHtml = escapeXml;

/** Every page that should be found, for sitemap.xml. lastmod: the newest release date. */
export function sitemapXml({ siteUrl = DEFAULT_SITE_URL, articles = [], lastmod = "" } = {}) {
  const base = String(siteUrl).replace(/\/+$/, "");
  const urls = [
    ...PAGES.map((p) => ({ loc: base + (p.path === "/" ? "/" : p.path), priority: p.priority })),
    ...articles.map((a) => ({ loc: `${base}/help/${a.slug}`, priority: "0.7" })),
  ];
  const lines = urls.map((u) => `  <url><loc>${escapeXml(u.loc)}</loc>${lastmod ? `<lastmod>${lastmod}</lastmod>` : ""}<priority>${u.priority}</priority></url>`);
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${lines.join("\n")}\n</urlset>\n`;
}

/** JSON for a <script type="application/ld+json">, safe to put inside HTML. */
export const jsonLdText = (data) => JSON.stringify(data).replace(/</g, "\\u003c");

/**
 * The <head> tags for a page, as HTML: for servers that send each page ready-made (the
 * self-hosted server), so search engines and link previews needn't run any script.
 */
export function headHtml(meta, siteUrl = DEFAULT_SITE_URL) {
  const base = String(siteUrl).replace(/\/+$/, "");
  const e = escapeHtml;
  const tags = [
    `<title>${e(meta.title)}</title>`,
    `<meta name="description" content="${e(meta.description)}" />`,
    `<meta name="robots" content="${meta.noindex ? "noindex, nofollow" : "index, follow, max-image-preview:large"}" />`,
  ];
  if (!meta.noindex) {
    tags.push(
      `<link rel="canonical" href="${e(meta.url)}" />`,
      `<meta property="og:type" content="${meta.ogType}" />`,
      `<meta property="og:site_name" content="${SITE_NAME}" />`,
      `<meta property="og:locale" content="en_GB" />`,
      `<meta property="og:title" content="${e(meta.title)}" />`,
      `<meta property="og:description" content="${e(meta.description)}" />`,
      `<meta property="og:url" content="${e(meta.url)}" />`,
      `<meta property="og:image" content="${e(base + SHARE_IMAGE)}" />`,
      `<meta property="og:image:width" content="1200" />`,
      `<meta property="og:image:height" content="630" />`,
      `<meta property="og:image:alt" content="${e(SHARE_IMAGE_ALT)}" />`,
      `<meta name="twitter:card" content="summary_large_image" />`,
      `<meta name="twitter:title" content="${e(meta.title)}" />`,
      `<meta name="twitter:description" content="${e(meta.description)}" />`,
      `<meta name="twitter:image" content="${e(base + SHARE_IMAGE)}" />`,
      `<meta name="twitter:image:alt" content="${e(SHARE_IMAGE_ALT)}" />`,
    );
    for (const d of meta.jsonLd) tags.push(`<script type="application/ld+json" data-seo>${jsonLdText(d)}</script>`);
  }
  return tags.join("\n    ");
}
