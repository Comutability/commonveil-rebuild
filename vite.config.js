import base44 from "@base44/vite-plugin"
import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'
import { readFileSync } from 'node:fs'
import { defineConfig } from 'vite'

/**
 * Content Security Policy for the published site.
 *
 * Base44 can't send a CSP header, so it goes in a <meta> tag. It's added to production
 * builds only: the editor preview runs Vite's dev server, which needs inline scripts.
 * frame-ancestors can't be set from a meta tag; Base44 sends X-Frame-Options: DENY instead.
 * Keep docs/THREAT_MODEL.md in step with any change here.
 */
export const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'self'",
  // Radix UI positions popovers with inline styles, and React style props are inline too.
  "style-src 'self' 'unsafe-inline'",
  // Images only from this site and Base44's media store: no third-party image requests.
  "img-src 'self' data: blob: https://media.base44.com",
  "font-src 'self' data:",
  // This site's own API, and Base44's realtime host for call set-up (the VoiceRoom actor).
  "connect-src 'self' wss://actors.base44-realtime.dev https://media.base44.com",
  "manifest-src 'self'",
  "form-action 'self'",
  "base-uri 'none'",
  "object-src 'none'",
  "frame-src 'none'",
  // Only the call audio encryption worker (see src/lib/voice/frameWorker.js).
  "worker-src 'self'",
  "media-src 'self' blob:",
  // DOM XSS protection (Chromium): no string may reach innerHTML or similar sinks.
  "require-trusted-types-for 'script'",
  // One policy, which only ever returns the call audio worker's own URL.
  "trusted-types voice-worker",
].join("; ");

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

const { version } = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8"));

// https://vite.dev/config/
export default defineConfig({
  define: { __APP_VERSION__: JSON.stringify(version) },
  plugins: [
    base44({
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
  ],
  resolve: {
    alias: [
      // The browser build of this Markdown dependency decodes HTML entities through innerHTML,
      // which Trusted Types would block. Its default build uses a lookup table instead.
      {
        find: /^decode-named-character-reference$/,
        replacement: fileURLToPath(new URL("./node_modules/decode-named-character-reference/index.js", import.meta.url)),
      },
    ],
  },
});
