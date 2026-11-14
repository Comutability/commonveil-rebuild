// Site-to-site wire format (CVP-005): how one site signs a request to another, and the address
// rules every site applies before connecting anywhere. Transport (HTTP, WebSockets, DNS) is the
// host application's; this is the part two implementations must agree on byte for byte.
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { b64u, fromB64u, utf8 } from "../core/bytes.js";

/** The federation protocol this version of Secure Net speaks. */
export const PROTOCOL = "commonveil/1";

/** Where every site publishes its site document. This one path is fixed; the rest are in the document. */
export const SITE_DOCUMENT = "/.well-known/commonveil";

/**
 * Where a site's endpoints are unless its site document says otherwise. A site that can't serve
 * these paths (one on a hosting platform that only offers functions under its own prefix, say)
 * lists its own, and other sites use those.
 */
export const DEFAULT_ENDPOINTS = Object.freeze({
  act: "/cvp/v1/act",
  directory: "/cvp/v1/directory",
  inbox: "/cvp/v1/inbox",
  discover: "/cvp/v1/discover",
  actors: "/cvp/v1/actors/{name}/{room}",
  identity: "/.well-known/commonveil/identity",
  files: "/api/files",
});

/**
 * Where the social protocol's endpoints are by default (CVP-017 to CVP-021). Kept apart from
 * DEFAULT_ENDPOINTS, which sites publish as it stands: a site lists these in its site document
 * only once it serves them, alongside the features it announces.
 */
export const SOCIAL_ENDPOINTS = Object.freeze({
  actor: "/.well-known/commonveil/actor",
  prekeys: "/cvp/v2/prekeys/{actor}/{device}",
  deliver: "/cvp/v2/deliver",
  outbox: "/cvp/v2/outbox",
  mailbox: "/cvp/v2/mailbox",
  public: "/cvp/v2/public/{actor}",
  repo: "/cvp/v2/repo/{actor}",
  changes: "/cvp/v2/changes",
  lexicon: "/cvp/v2/lexicon/{id}",
});

const ENDPOINT_RE = /^\/[A-Za-z0-9._~{}\/-]{0,199}$/;

/**
 * A site's endpoints, from its site document. Each must be a plain path on that same site: no
 * scheme, host, query, "//" or "..", so a site document can never send requests anywhere else.
 * Anything missing or unsafe falls back to the default.
 */
export function endpointsOf(doc) {
  const out = { ...DEFAULT_ENDPOINTS };
  const given = doc && typeof doc.endpoints === "object" && doc.endpoints ? doc.endpoints : {};
  for (const name of Object.keys(DEFAULT_ENDPOINTS)) {
    const v = given[name];
    if (typeof v === "string" && ENDPOINT_RE.test(v) && !v.includes("//") && !v.split("/").includes("..")) out[name] = v;
  }
  return out;
}

/** How far apart two sites' clocks may be before a request is refused. */
export const SKEW_MS = 5 * 60_000;

/** A site address: a DNS name with an optional port, lower case. */
export const HOST_RE = /^(?=.{1,253}(:\d{1,5})?$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:\d{1,5})?$/;

/** A site address in its one accepted form, or null. */
export function normHost(h) {
  const v = String(h || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  return HOST_RE.test(v) ? v : null;
}

/** The body digest a signed request carries. */
export const digestOf = (body) => `sha-256=${b64u(sha256(typeof body === "string" ? utf8(body || "") : body || new Uint8Array()))}`;

/**
 * What a request's signature covers: method, both sites, path, time, a one-off nonce, the body
 * and the person it's for.
 */
export const signatureBase = ({ method, to, path, from, date, nonce, digest, user }) =>
  ["commonveil-request/v1", method.toUpperCase(), to, path, from, date, nonce, digest, user || "-"].join("\n");

/** Sign a request with a site's Ed25519 secret key (base64url). */
export const signRequest = (fields, secretKey) => b64u(ed25519.sign(utf8(signatureBase(fields)), fromB64u(secretKey)));

/** Check a request's signature against the sending site's published key (base64url). */
export function verifyRequest(fields, signature, publicKey) {
  try {
    return ed25519.verify(fromB64u(signature), utf8(signatureBase(fields)), fromB64u(publicKey));
  } catch {
    return false;
  }
}

/** Whether a request's date is close enough to now. */
export const freshEnough = (date, now = Date.now()) => {
  const t = Date.parse(date);
  return Number.isFinite(t) && Math.abs(now - t) <= SKEW_MS;
};

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

/**
 * Whether an address is one no site should be made to connect to on another's say-so: private,
 * loopback, link-local, carrier-grade NAT, multicast or reserved.
 */
export function isPrivate(ip) {
  const v = String(ip).toLowerCase().replace(/^\[|\]$/g, "");
  if (IPV4.test(v)) {
    const [a, b] = v.split(".").map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  if (v.startsWith("::ffff:")) return isPrivate(v.slice(7));
  return v === "::1" || v === "::" || v.startsWith("fc") || v.startsWith("fd") || v.startsWith("fe80") || v.startsWith("ff");
}
