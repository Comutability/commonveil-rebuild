// Base44's hosts and packages: nothing in a self-hosted build may mention them
// (scripts/check-independent.mjs), and that includes the release notes the site shows
// (tests/releases.test.mjs).
export const BASE44_NAMES = /base44\.(app|com|dev)|base44-realtime|@base44\/(sdk|vite-plugin)/;
