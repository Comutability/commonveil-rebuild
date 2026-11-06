# Search engines and link previews

Every page that works without signing in is built to be found and to preview well when shared.
Nothing that needs a sign-in is ever indexed.

## What each page says

`src/lib/site/seo.js` is the one list. For every public page and Help Centre article it gives:

- its own title (under 70 characters) and description (50 to 170), and one canonical address;
- Open Graph and Twitter tags, with a shared picture (`public/og-image.png`, 1200 × 630);
- structured data (schema.org JSON-LD): Organization, WebSite and WebApplication on the home page,
  TechArticle for each help article, an ItemList of articles on the Help Centre, and breadcrumbs.

The rule: every page you can open without signing in is indexed (including sign-in, sign-up,
"Can't sign in?" and search); everything that needs a sign-in is not (`/app` and everything in it,
`/admin`). Three kinds of address need no sign-in but are still kept out, with no preview tags or
structured data, because each is private: invites (the code lets someone in), password-reset links
(a one-time key) and people's profiles (`/u/…`: there's deliberately no directory of people, and a
search engine would make one). Unknown addresses say "noindex" too.

`tests/seo.test.mjs` checks all of that, including that no two pages share a title.

## How it reaches search engines

- **In the browser**, `src/components/site/Seo.jsx` keeps the `<head>` right as you move around.
- **On Base44**, Base44 shows crawlers a snapshot of each page after it has run, so they see the
  same tags and content as a person does. Its own tags, structured data, robots file and sitemap
  are turned off, so it serves ours. The settings: `seo_disabled: false`,
  `platform_meta_injection_enabled: false`, `platform_jsonld_injection_enabled: false`,
  `robots_txt_enabled: false`, `sitemap_xml_enabled: false`, `llms_txt_enabled: false`,
  `canonical_url` set to the site's address.
- **On a self-hosted site**, the server writes each page's tags into the HTML it sends, so nothing
  needs to run first. Unknown addresses are real 404s, the old guide, wiki and blog addresses are
  permanent redirects to the Help Centre, and the sitemap and robots file use the site's own address.

## sitemap.xml and robots.txt

The build writes `sitemap.xml` (every public page and article). `public/robots.txt` points to it,
keeps crawlers out of `/app` and `/admin`, and lets them read invites, reset links and profiles
only so they see their "noindex" (a blocked page can still be listed by its address alone).
AI-training crawlers (GPTBot, ClaudeBot, Google-Extended, CCBot and others) are refused, as before;
that doesn't affect search results.

## When the address changes

The site's address is `DEFAULT_SITE_URL` in `src/lib/site/seo.js`, and appears in `public/robots.txt`
and the Base44 `canonical_url` setting. Moving to a new domain means changing all three, then telling
Google Search Console and Bing Webmaster Tools about the new address and its sitemap.

## Still to do by hand

- Add the site to Google Search Console and Bing Webmaster Tools, and submit the sitemap. That needs
  the site owner to prove they own the address.
- No one can promise a ranking. These pages are complete, fast and accessible (Lighthouse scores 100
  for SEO, accessibility and best practices on every public page); where they rank depends on what
  people search for and who links to them.
