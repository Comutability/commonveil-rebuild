// Extensions and themes (CVP-008): what an extension declares before anyone runs it, and theme
// packages that can change how a client looks without running any code.
//
// Extension manifests say where the extension runs and exactly what it may touch. A client shows
// this before installing ("Privacy Lens"), and a site refuses manifests that ask for more than
// their execution model allows. The manifest pins the extension's code by hash, and is signed
// by its publisher, so an update can't quietly change either.
//
// Themes are data only: named design tokens (colours, a font from an approved list, radii,
// spacing) and images pinned by hash. No CSS, no scripts, no URLs. Colour pairs are checked for
// WCAG AA contrast, so a theme can't make text unreadable or hide a security warning.
import { sign, checkSignature, signingBytes } from "../core/signed.js";
import { sha256B64u } from "../core/bytes.js";

export const MANIFEST = "extension.manifest";
export const THEME = "theme.package";

/** Where an extension runs, and the most each model may ask for. */
export const EXECUTION = {
  "client-local": ["read.selected", "read.channel", "write.message", "ui.panel", "ui.command", "storage.local"],
  "server-side": ["read.metadata", "read.ciphertext", "write.ciphertext", "queue", "ratelimit"],
  external: ["send.selected", "ui.panel"],
  public: ["read.public", "publish.public"],
};
const ID = /^[a-z0-9]+(\.[a-z0-9-]+){2,}$/;
const SEMVER = /^\d{1,4}\.\d{1,4}\.\d{1,6}$/;
const HASH = /^[A-Za-z0-9_-]{43}$/;

const problem = (list, msg) => {
  list.push(msg);
  return list;
};

/** Problems with a manifest body, as a list of plain sentences (empty if fine). */
export function manifestProblems(m) {
  const out = [];
  if (!m || typeof m !== "object") return problem(out, "Not a manifest");
  if (!ID.test(m.id || "")) problem(out, "The id must be a reverse domain name, like org.example.debates");
  if (typeof m.name !== "string" || !m.name || m.name.length > 60) problem(out, "A name of up to 60 characters");
  if (!SEMVER.test(m.version || "")) problem(out, "A version like 1.2.3");
  const allowed = EXECUTION[m.execution];
  if (!allowed) problem(out, `Execution must be one of ${Object.keys(EXECUTION).join(", ")}`);
  if (!Array.isArray(m.permissions)) problem(out, "List the permissions it needs (an empty list is fine)");
  else for (const p of m.permissions) if (!allowed?.includes(p)) problem(out, `"${p}" isn't available to ${m.execution} extensions`);
  if (!HASH.test(m.code_hash || "")) problem(out, "The code must be pinned by its SHA-256 (base64url)");
  if (m.execution === "external" && !(typeof m.service === "string" && /^https:\/\/[^/]+/.test(m.service))) problem(out, "An external extension must name its service (https)");
  if (m.licence && typeof m.licence !== "string") problem(out, "The licence is an SPDX identifier");
  return out;
}

/** Sign a manifest as its publisher. */
export function publish(body, publisherKey) {
  const problems = manifestProblems(body);
  if (problems.length) throw new TypeError(problems.join(" "));
  return sign(MANIFEST, { ...body, publisher: publisherKey.kid }, publisherKey);
}

/** Check a signed manifest and the code it pins. Returns { ok, problems }. */
export function checkManifest(record, { publisherPub, code } = {}) {
  const problems = manifestProblems(record?.body);
  if (record?.kind !== MANIFEST || !checkSignature(record, record.sig, publisherPub) || record.body.publisher !== record.sig.kid) problems.push("Not signed by its publisher");
  if (code !== undefined && sha256B64u(code) !== record?.body?.code_hash) problems.push("The code doesn't match the hash in the manifest");
  return { ok: problems.length === 0, problems };
}

/** What a manifest means for someone's privacy, in plain words, for the install prompt. */
export function explainPermissions(m) {
  const say = {
    "read.selected": "read the message you choose to share with it",
    "read.channel": "read every message in the channels you enable it in",
    "write.message": "send messages as you, when you ask it to",
    "ui.panel": "show a panel",
    "ui.command": "add commands",
    "storage.local": "keep data on this device",
    "read.metadata": "see who's in a community and when messages are sent (not what they say)",
    "read.ciphertext": "store encrypted messages it can't read",
    "write.ciphertext": "deliver encrypted messages",
    queue: "hold messages until they can be delivered",
    ratelimit: "slow down floods of messages",
    "send.selected": "send what you choose to share to an outside service",
    "read.public": "read what's been published publicly",
    "publish.public": "publish things publicly",
  };
  const lines = m.permissions.map((p) => say[p] || p);
  if (m.execution === "external") lines.push(`Anything you share goes to ${m.service}, outside Commonveil's encryption`);
  return lines;
}

// ---- Themes ----

export const APPROVED_FONTS = ["system-ui", "serif", "sans-serif", "monospace", "Atkinson Hyperlegible", "Inter", "Source Serif 4", "IBM Plex Sans", "IBM Plex Mono", "Lexend", "OpenDyslexic"];
const COLOR = /^#[0-9a-fA-F]{6}$/;
const COLOR_TOKENS = ["background", "surface", "text", "muted", "accent", "accent-text", "danger", "danger-text", "border"];
/** Pairs that must stay readable: [text, background]. */
const CONTRAST_PAIRS = [["text", "background"], ["text", "surface"], ["muted", "background"], ["accent-text", "accent"], ["danger-text", "danger"]];

function luminance(hex) {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
/** WCAG contrast ratio between two colours, times 100 and rounded (so 450 means 4.5:1). */
export function contrast(a, b) {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p);
  return Math.round(((x + 0.05) / (y + 0.05)) * 100);
}

/** Problems with a theme body (empty if fine). */
export function themeProblems(t) {
  const out = [];
  if (!t || typeof t !== "object") return problem(out, "Not a theme");
  if (!ID.test(t.id || "")) problem(out, "The id must be a reverse domain name");
  if (!SEMVER.test(t.version || "")) problem(out, "A version like 1.2.3");
  const allowedKeys = new Set(["id", "name", "version", "colors", "dark", "fonts", "radius", "spacing", "images", "attribution", "licence", "publisher"]);
  for (const k of Object.keys(t)) if (!allowedKeys.has(k)) problem(out, `"${k}" isn't something a theme can set`);
  for (const scheme of ["colors", "dark"]) {
    const c = t[scheme];
    if (scheme === "dark" && c === undefined) continue;
    if (!c || typeof c !== "object") {
      problem(out, `${scheme} needs colours`);
      continue;
    }
    for (const [k, v] of Object.entries(c)) {
      if (!COLOR_TOKENS.includes(k)) problem(out, `"${k}" isn't a colour a theme can set`);
      else if (!COLOR.test(v)) problem(out, `${scheme}.${k} must be a colour like #1a2b3c`);
    }
    for (const tk of COLOR_TOKENS) if (!COLOR.test(c[tk] || "")) problem(out, `${scheme}.${tk} is missing`);
    for (const [fg, bg] of CONTRAST_PAIRS) {
      if (COLOR.test(c[fg] || "") && COLOR.test(c[bg] || "") && contrast(c[fg], c[bg]) < 450) problem(out, `${scheme}: ${fg} on ${bg} is too faint to read (needs 4.5:1)`);
    }
  }
  for (const [k, v] of Object.entries(t.fonts || {})) {
    if (!["body", "heading", "code"].includes(k)) problem(out, `"${k}" isn't a font a theme can set`);
    else if (!APPROVED_FONTS.includes(v)) problem(out, `${v} isn't one of the approved fonts`);
  }
  if (t.radius !== undefined && !(Number.isSafeInteger(t.radius) && t.radius >= 0 && t.radius <= 24)) problem(out, "Radius is 0 to 24 pixels");
  if (t.spacing !== undefined && !["compact", "normal", "relaxed"].includes(t.spacing)) problem(out, "Spacing is compact, normal or relaxed");
  for (const img of t.images || []) {
    if (!["background", "banner", "icon"].includes(img?.role) || !HASH.test(img?.hash || "") || !["image/png", "image/webp"].includes(img?.type)) problem(out, "Images are PNG or WebP, pinned by hash, with a role of background, banner or icon");
  }
  return out;
}

/** Sign a theme as its publisher. */
export function publishTheme(body, publisherKey) {
  const problems = themeProblems(body);
  if (problems.length) throw new TypeError(problems.join(" "));
  return sign(THEME, { ...body, publisher: publisherKey.kid }, publisherKey);
}

/** Check a signed theme. Returns { ok, problems }. */
export function checkTheme(record, publisherPub) {
  const problems = themeProblems(record?.body);
  if (record?.kind !== THEME || !checkSignature(record, record.sig, publisherPub) || record.body.publisher !== record.sig.kid) problems.push("Not signed by its publisher");
  return { ok: problems.length === 0, problems };
}

export const themeId = (record) => sha256B64u(signingBytes(record.kind, record.body));
