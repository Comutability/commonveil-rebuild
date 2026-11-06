// The site's Content Security Policy, for both ways of running it. Keep docs/THREAT_MODEL.md in
// step with any change here.
//
// On Base44 the policy goes in a <meta> tag (Base44 can't send the header), and allows Base44's
// media store and realtime host. A self-hosted site needs nothing but itself, and also sends the
// policy as a header, which can forbid framing too.

const COMMON = [
  "default-src 'none'",
  "script-src 'self'",
  // Radix UI positions popovers with inline styles, and React style props are inline too.
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self' data:",
  "manifest-src 'self'",
  "form-action 'self'",
  "base-uri 'none'",
  "object-src 'none'",
  "frame-src 'none'",
  // Only the call encryption worker (see src/lib/voice/frameWorker.js).
  "worker-src 'self'",
  "media-src 'self' blob:",
  // DOM XSS protection (Chromium): no string may reach innerHTML or similar sinks.
  "require-trusted-types-for 'script'",
  // Two policies, each only ever returning one URL: the call worker and the service worker.
  "trusted-types voice-worker service-worker",
];

export const BASE44_CSP = [
  ...COMMON,
  // Images only from this site and Base44's media store: no third-party image requests.
  "img-src 'self' data: blob: https://media.base44.com",
  // This site's own API, and Base44's realtime host for calls and presence.
  "connect-src 'self' wss://actors.base44-realtime.dev https://media.base44.com",
].join("; ");

/** A self-hosted site talks only to itself; other sites are reached through its server. */
export const SELF_HOSTED_CSP = [...COMMON, "img-src 'self' data: blob:", "connect-src 'self'"].join("; ");

/** The header form adds what a <meta> tag can't carry. */
export const SELF_HOSTED_CSP_HEADER = `${SELF_HOSTED_CSP}; frame-ancestors 'none'`;
