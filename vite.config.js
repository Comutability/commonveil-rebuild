import base44 from "@base44/vite-plugin"
import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'
import { readFileSync, readdirSync } from 'node:fs'
import { defineConfig } from 'vite'

import { BASE44_CSP, SELF_HOSTED_CSP } from './csp.config.mjs'
import { parseArticle, sortArticles } from './src/lib/site/help.js'
import { DEFAULT_SITE_URL, sitemapXml } from './src/lib/site/seo.js'

// "selfhost" builds the site for a self-hosted server (server/), with no Base44 code in it.
const SELF_HOSTED = process.env.VITE_COMMONVEIL_BACKEND === 'selfhost'

/**
 * Content Security Policy, in a <meta> tag (see csp.config.mjs). It's added to production
 * builds only: the editor preview runs Vite's dev server, which needs inline scripts.
 * On Base44, frame-ancestors can't be set from a meta tag; Base44 sends X-Frame-Options: DENY.
 */
export const CONTENT_SECURITY_POLICY = SELF_HOSTED ? SELF_HOSTED_CSP : BASE44_CSP;

function contentSecurityPolicy() {
  return {
    name: "commonveil-content-security-policy",
    apply: "build",
    transformIndexHtml: {
      order: "pre",
      handler(html) {
        // Straight after the charset declaration and before any script, so it covers all of them.
        const tag = `<meta http-equiv="Content-Security-Policy" content="${CONTENT_SECURITY_POLICY}" />`;
        const charset = /<meta charset="UTF-8" \/>/i;
        return charset.test(html) ? html.replace(charset, (m) => `${m}\n    ${tag}`) : html.replace(/<head>/i, `<head>\n    ${tag}`);
      },
    },
  };
}

/**
 * sitemap.xml: every public page and Help Centre article (src/lib/site/seo.js). Written for the
 * site's usual address; a self-hosted server swaps in its own when it serves the file.
 */
function sitemap() {
  return {
    name: "commonveil-sitemap",
    apply: "build",
    generateBundle() {
      const dir = new URL("./src/content/help/", import.meta.url);
      const articles = sortArticles(
        readdirSync(dir).filter((f) => f.endsWith(".md")).map((f) => parseArticle(f.replace(/\.md$/, ""), readFileSync(new URL(f, dir), "utf8"))),
      );
      const { releases } = JSON.parse(readFileSync(new URL("./src/content/releases.json", import.meta.url), "utf8"));
      this.emitFile({ type: "asset", fileName: "sitemap.xml", source: sitemapXml({ siteUrl: DEFAULT_SITE_URL, articles, lastmod: releases[0]?.date || "" }) });
      // For a self-hosted server, which writes each page's tags itself (server/http.mjs).
      const index = articles.map(({ slug, title, summary, section }) => ({ slug, title, summary, section }));
      this.emitFile({ type: "asset", fileName: "help-index.json", source: JSON.stringify(index) });
    },
  };
}

const { version } = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8"));

// https://vite.dev/config/
export default defineConfig({
  define: {
    __APP_VERSION__: JSON.stringify(process.env.COMMONVEIL_VERSION || version),
  },
  plugins: [
    !SELF_HOSTED && base44({
      // Support for legacy code that imports the base44 SDK with @/integrations, @/entities, etc.
      // can be removed if the code has been updated to use the new SDK imports from @base44/sdk
      legacySDKImports: process.env.BASE44_LEGACY_SDK_IMPORTS === 'true',
      hmrNotifier: true,
      navigationNotifier: true,
      analyticsTracker: false,
      visualEditAgent: true
    }),
    react(),
    contentSecurityPolicy(),
    sitemap(),
  ],
  resolve: {
    alias: [
      // The Base44 plugin provides this alias; a self-hosted build sets it itself.
      ...(SELF_HOSTED
        ? [
            { find: /^@\//, replacement: fileURLToPath(new URL("./src/", import.meta.url)) },
            // No Base44 code in a self-hosted build.
            { find: /^@base44\/sdk$/, replacement: fileURLToPath(new URL("./src/api/sdkStub.js", import.meta.url)) },
          ]
        : []),
      // The browser build of this Markdown dependency decodes HTML entities through innerHTML,
      // which Trusted Types would block. Its default build uses a lookup table instead.
      {
        find: /^decode-named-character-reference$/,
        replacement: fileURLToPath(new URL("./node_modules/decode-named-character-reference/index.js", import.meta.url)),
      },
    ],
  },
});
