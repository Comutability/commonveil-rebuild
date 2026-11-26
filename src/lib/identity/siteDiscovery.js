// Reading another Secure Net site's public site document (CVP-005), for a migration checklist.
//
// This is preparation only. It reads one public JSON document and reports what the site says it
// can do. Nothing is moved, deleted or switched over, and nothing here tells a site who you are.
//
// The document is read by this site's own server (protocol.check_site), not by the browser: the
// app's Content Security Policy only lets it talk to its own site. The server reads it over
// HTTPS with the same address rules federation uses, follows no redirects and pins nothing. The
// address is still checked here first, so a typing mistake is explained before anything is asked.
import { PROTOCOL, SITE_DOCUMENT, HOST_RE } from "../../../packages/secure-net/src/wire/federation.js";

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const RESERVED = /(^|\.)(localhost|local|localdomain|internal|intranet|lan|home\.arpa|corp|test|invalid|example|onion)$/;

export class DiscoveryError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "DiscoveryError";
    this.code = code;
  }
}

/** The host to check, in its one accepted form, or an explanation of why it can't be checked. */
export function destinationHost(input) {
  let raw = String(input ?? "").trim();
  if (!raw) throw new DiscoveryError("EMPTY", "Enter the other site's address, like friend.example.org.");
  if (/\s/.test(raw)) throw new DiscoveryError("BAD_HOST", "An address has no spaces in it.");
  if (raw.includes("://")) {
    let url;
    try {
      url = new URL(raw);
    } catch {
      throw new DiscoveryError("BAD_HOST", "That isn't an address this browser can read.");
    }
    if (url.protocol !== "https:") throw new DiscoveryError("NOT_HTTPS", "Only https addresses are checked: without it a site has no identity to compare.");
    if (url.username || url.password) throw new DiscoveryError("BAD_HOST", "An address never carries a name or password.");
    raw = url.host;
  } else {
    raw = raw.replace(/\/.*$/, "");
    if (raw.includes("@")) throw new DiscoveryError("BAD_HOST", "An address never carries a name or password.");
  }
  const host = raw.toLowerCase().replace(/\.$/, "");
  if (host.includes("[") || host.includes("]") || (host.match(/:/g) || []).length > 1) {
    throw new DiscoveryError("BAD_HOST", "Use a site's name, not a numeric IP address.");
  }
  if (!HOST_RE.test(host)) throw new DiscoveryError("BAD_HOST", "That doesn't look like a site address.");
  const name = host.split(":")[0];
  if (IPV4.test(name)) throw new DiscoveryError("BAD_HOST", "Use a site's name, not a numeric IP address.");
  if (!name.includes(".")) throw new DiscoveryError("PUBLIC_ONLY", "That's a local name, not a site others can reach.");
  if (RESERVED.test(name)) throw new DiscoveryError("PUBLIC_ONLY", "That's a private or reserved name, so it can't be another site.");
  return host;
}

const endpointNames = (doc) => (doc && typeof doc.endpoints === "object" && doc.endpoints ? doc.endpoints : {});

/**
 * What the destination says about itself, one line at a time. `ok` means every capability this
 * site's own account would need is advertised; a gap is something that would stop a move today.
 */
export function evaluateDestination(doc, { host }) {
  const items = [];
  const add = (id, label, state, detail) => items.push({ id, label, state, detail });
  const endpoints = endpointNames(doc);
  const software = doc?.software && typeof doc.software === "object" ? doc.software : {};

  add("https", "Answered over HTTPS", "ok", `This site's server read https://${host}${SITE_DOCUMENT}.`);

  const speaks = doc?.protocol === PROTOCOL;
  add("protocol", "Speaks the Commonveil protocol", speaks ? "ok" : "gap",
    speaks ? `It publishes protocol ${PROTOCOL}.` : `It publishes ${doc?.protocol ? `"${String(doc.protocol)}"` : "no protocol"}; this site speaks ${PROTOCOL}.`);

  const sameHost = doc?.host === host;
  add("host", "The document is for this address", sameHost ? "ok" : "gap",
    sameHost ? `It names itself ${host}.` : `It names itself ${doc?.host ? String(doc.host) : "nothing"}, not ${host}. Anyone could serve another site's document, so a move needs this to match.`);

  const key = typeof doc?.key?.public === "string" && doc.key.public.length > 0;
  add("key", "Publishes its site key", key ? "ok" : "gap",
    key ? "The key is trusted the first time it's seen and pinned after that; the document can't prove it on its own." : "Without a published key, other sites have nothing to pin, so requests can't be signed to it.");

  const handles = typeof doc?.handle_domain === "string" && doc.handle_domain.length > 0;
  add("handles", "Addresses use its own domain", handles ? "ok" : "gap",
    handles ? `People there are @name@${doc.handle_domain}.` : "It doesn't say which domain its addresses use.");

  const relay = ["directory", "inbox", "identity"].filter((n) => typeof endpoints[n] === "string" && endpoints[n].startsWith("/"));
  add("endpoints", "Publishes its relay endpoints", relay.length === 3 ? "ok" : "gap",
    relay.length === 3 ? `Directory, inbox and identity are at ${relay.map((n) => endpoints[n]).join(", ")}.` : `Only ${relay.length} of 3 relay endpoints are published (${relay.join(", ") || "none"}).`);

  const actors = doc?.limits?.actors !== false && typeof endpoints.actor === "string";
  add("actors", "Serves actor documents (CVP-017)", actors ? "ok" : "gap",
    actors ? "Identities can be looked up there, so an actor could be found at that site." : "It says it doesn't serve actor documents, so your protocol actor couldn't be looked up there.");

  const sealed = Boolean(doc?.pq && typeof doc.pq === "object" &&
    typeof doc.pq.kem === "string" && doc.pq.kem &&
    typeof doc.pq.sig === "string" && doc.pq.sig);
  add("sealed", "Relay has hybrid post-quantum encryption and signatures", sealed ? "ok" : "gap",
    sealed ? "The site publishes hybrid sealed relay keys." :
      "A future migration must not fall back to classical-only relay transport.");

  // Legacy Commonveil v1 inboxes are not the independent Secure Net v2 mailbox.
  // No deployed site should be marked ready until it advertises transfer explicitly.
  const features = doc?.features && typeof doc.features === "object" && !Array.isArray(doc.features) ? doc.features : {};
  const required = [
    ["cvp.actors", 1], ["cvp.sessions", 2], ["cvp.delivery", 2],
    ["cvp.sealed-relay", 1], ["cvp.pq-signatures", 1], ["cvp.transfer", 1],
  ];
  const missing = required.filter(([key, version]) =>
    !Number.isSafeInteger(features[key]) || features[key] < version);
  add("transfer", "Independent Secure Net transfer capabilities",
    missing.length === 0 ? "ok" : "gap",
    missing.length === 0
      ? "It advertises the required protocol versions. A signed challenge and import verification are still needed."
      : "Missing or outdated: " + missing.map(([key, version]) => key + " v" + version).join(", ") + ".");

  const requiredTransport = ["actor", "prekeys", "outbox", "mailbox", "deliver", "repo"];
  const absent = requiredTransport.filter((key) =>
    typeof endpoints[key] !== "string" || !endpoints[key].startsWith("/") ||
    endpoints[key].startsWith("//"));
  add("v2-transport", "Independent actor, mailbox and delivery endpoints",
    absent.length === 0 ? "ok" : "gap",
    absent.length === 0
      ? "It lists actor discovery, prekeys, outbox, mailbox, delivery and repository endpoints."
      : "Missing: " + absent.join(", ") + ". The older Commonveil inbox is not a Secure Net v2 transfer service.");

  add("software", "What it runs", "note",
    software.name || software.version ? `${String(software.name || "unknown")} ${String(software.version || "")}`.trim() : "It doesn't say what software or version it runs.");

  const gaps = items.filter((i) => i.state === "gap");
  return { items, ok: gaps.length === 0, gaps: gaps.length };
}

/**
 * Check an address end to end: guard it, have this site's server read the document (`read`,
 * given the host), and say what it can do.
 */
export async function checkDestination(input, { read } = {}) {
  const host = destinationHost(input);
  if (typeof read !== "function") throw new DiscoveryError("NO_READER", "This site can't read other sites' documents right now.");
  const doc = await read(host);
  if (!doc || typeof doc !== "object") throw new DiscoveryError("NOT_JSON", `${host} didn't answer with a site document. It may not be a Commonveil site.`);
  return { host, doc, ...evaluateDestination(doc, { host }) };
}