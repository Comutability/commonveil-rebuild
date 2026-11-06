// Talking to other Commonveil sites: the site's own signing key, signed requests (inspired by
// HTTP Message Signatures, as ActivityPub uses them), checking other sites' signatures against the
// keys they publish, and safe outbound connections. docs/FEDERATION.md describes the wire format.
import crypto from "node:crypto";
import dns from "node:dns/promises";
import net from "node:net";
import { WebSocket } from "ws";

export const PROTOCOL = "commonveil/1";
const SKEW_MS = 5 * 60_000;
const MAX_RESPONSE = 4 * 1024 * 1024;
const DOC_TTL_MS = 60 * 60_000;
export const HOST_RE = /^(?=.{1,253}(:\d{1,5})?$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:\d{1,5})?$/;

export class FederationError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export const normHost = (h) => {
  const v = String(h || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  if (!HOST_RE.test(v)) throw new FederationError(400, "BAD_SITE", "That isn't a site address.");
  return v;
};

const b64u = (buf) => Buffer.from(buf).toString("base64url");
const sha256 = (data) => crypto.createHash("sha256").update(data).digest();

/** The site's Ed25519 key, made once and kept with the data. */
export function siteKey(store) {
  let saved = store.getSetting("federation:site-key");
  if (!saved) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
    saved = {
      private: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
      public: b64u(publicKey.export({ format: "der", type: "spki" }).subarray(-32)),
      created: new Date().toISOString(),
    };
    store.setSetting("federation:site-key", saved);
  }
  const privateKey = crypto.createPrivateKey({ key: Buffer.from(saved.private, "base64"), format: "der", type: "pkcs8" });
  return { public: saved.public, sign: (data) => b64u(crypto.sign(null, Buffer.from(data), privateKey)) };
}

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
export function verifyEd25519(publicRaw, data, signature) {
  try {
    const key = crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicRaw, "base64url")]), format: "der", type: "spki" });
    return crypto.verify(null, Buffer.from(data), key, Buffer.from(signature, "base64url"));
  } catch {
    return false;
  }
}

/** What a request's signature covers: method, both sites, path, time, a one-off nonce, the body and the person it's for. */
export const signatureBase = ({ method, to, path, from, date, nonce, digest, user }) =>
  ["commonveil-request/v1", method.toUpperCase(), to, path, from, date, nonce, digest, user || "-"].join("\n");

export const digestOf = (body) => `sha-256=${b64u(sha256(body || ""))}`;

/**
 * Outbound connections to other sites. By default only https, and never to private, loopback or
 * link-local addresses (so another site can't make this one probe its own network). Tests and
 * private networks can allow those with FEDERATION_ALLOW_PRIVATE=true (then http works too).
 */
export class Transport {
  /** hostHeader: also say which site is meant in X-Forwarded-Host (tests, where every site is on 127.0.0.1). */
  constructor({ allowPrivate = false, fetchImpl = globalThis.fetch, wsImpl = WebSocket, urlFor = null, hostHeader = false } = {}) {
    this.hostHeader = hostHeader;
    this.allowPrivate = allowPrivate;
    this.fetch = fetchImpl;
    this.Ws = wsImpl;
    this.urlFor = urlFor;
  }

  async #check(host) {
    if (this.allowPrivate) return;
    const name = host.replace(/:\d+$/, "");
    const addrs = net.isIP(name) ? [{ address: name }] : await dns.lookup(name, { all: true, verbatim: true }).catch(() => []);
    if (!addrs.length) throw new FederationError(502, "SITE_UNREACHABLE", `Can't find ${host}.`);
    if (addrs.some((a) => isPrivate(a.address))) throw new FederationError(403, "PRIVATE_ADDRESS", `${host} points at a private address.`);
  }

  url(host, path, ws = false) {
    if (this.urlFor) return this.urlFor(host, path, ws);
    const scheme = this.allowPrivate && /^(localhost|127\.|\[::1\])|\.localhost(:|$)|\.test(:|$)/.test(host) ? "http" : "https";
    return `${ws ? scheme.replace("http", "ws") : scheme}://${host}${path}`;
  }

  async request(host, path, { method = "GET", headers = {}, body } = {}) {
    await this.#check(host);
    let res;
    try {
      res = await this.fetch(this.url(host, path), { method, headers: { "User-Agent": `Commonveil (${PROTOCOL})`, ...(this.hostHeader ? { "X-Forwarded-Host": host } : {}), ...headers }, body, redirect: "manual", signal: AbortSignal.timeout(15_000) });
    } catch (err) {
      throw new FederationError(502, "SITE_UNREACHABLE", `Can't reach ${host} right now.${err?.name === "TimeoutError" ? " It took too long to answer." : ""}`);
    }
    const len = Number(res.headers.get("content-length") || 0);
    if (len > MAX_RESPONSE) throw new FederationError(502, "TOO_LARGE", `${host} sent too much.`);
    const text = await res.text();
    if (text.length > MAX_RESPONSE) throw new FederationError(502, "TOO_LARGE", `${host} sent too much.`);
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = null;
    }
    return { status: res.status, data, text };
  }

  /** Fetch bytes (a file's encrypted parts) from another site. */
  async bytes(host, path) {
    await this.#check(host);
    const res = await this.fetch(this.url(host, path), { headers: this.hostHeader ? { "X-Forwarded-Host": host } : {}, redirect: "manual", signal: AbortSignal.timeout(30_000) });
    if (res.status !== 200) return null;
    const buf = Buffer.from(await res.arrayBuffer());
    return buf.length <= 2 * 1024 * 1024 ? buf : null;
  }

  async websocket(host, path, headers) {
    await this.#check(host);
    return new this.Ws(this.url(host, path, true), { headers: { ...(this.hostHeader ? { "X-Forwarded-Host": host } : {}), ...headers }, handshakeTimeout: 10_000, maxPayload: 64 * 1024 });
  }
}

export function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const v = ip.toLowerCase();
  if (v.startsWith("::ffff:")) return isPrivate(v.slice(7));
  return v === "::1" || v === "::" || v.startsWith("fc") || v.startsWith("fd") || v.startsWith("fe80") || v.startsWith("ff");
}

/** Signing outbound requests, and checking inbound ones. */
export class Signer {
  constructor({ host, store, transport, log = console }) {
    this.host = host;
    this.store = store;
    this.transport = transport;
    this.log = log;
    this.key = siteKey(store);
    this.nonces = new Map();
    this.docs = new Map();
    const db = store.db;
    db.exec(`CREATE TABLE IF NOT EXISTS fed_sites (host TEXT PRIMARY KEY, key TEXT NOT NULL, name TEXT, handle_domain TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, blocked INTEGER NOT NULL DEFAULT 0)`);
    this.q = {
      get: db.prepare("SELECT * FROM fed_sites WHERE host = ?"),
      put: db.prepare("INSERT INTO fed_sites (host, key, name, handle_domain, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(host) DO UPDATE SET name = excluded.name, handle_domain = excluded.handle_domain, last_seen = excluded.last_seen"),
      all: db.prepare("SELECT * FROM fed_sites ORDER BY last_seen DESC LIMIT 500"),
      block: db.prepare("UPDATE fed_sites SET blocked = ? WHERE host = ?"),
      forget: db.prepare("DELETE FROM fed_sites WHERE host = ?"),
    };
  }

  headers({ method, to, path, body, user }) {
    const date = new Date().toISOString();
    const nonce = b64u(crypto.randomBytes(16));
    const digest = digestOf(body);
    const signature = this.key.sign(signatureBase({ method, to, path, from: this.host, date, nonce, digest, user }));
    return { "CV-From": this.host, "CV-Date": date, "CV-Nonce": nonce, "CV-Digest": digest, "CV-Signature": signature, ...(user ? { "CV-User": user } : {}) };
  }

  /** POST JSON to another site, signed. Answers { status, data }. */
  async post(to, path, payload, { user } = {}) {
    this.#refuseBlocked(to);
    const body = JSON.stringify(payload);
    return this.transport.request(to, path, { method: "POST", body, headers: { "Content-Type": "application/json", ...this.headers({ method: "POST", to, path, body, user }) } });
  }

  #refuseBlocked(host) {
    if (this.q.get.get(host)?.blocked) throw new FederationError(403, "SITE_BLOCKED", `This site doesn't talk to ${host}.`);
  }

  /** Another site's public document, and its key pinned on first contact. */
  async siteDoc(host) {
    host = normHost(host);
    const cached = this.docs.get(host);
    if (cached && Date.now() - cached.at < DOC_TTL_MS) return cached.doc;
    const { status, data } = await this.transport.request(host, "/.well-known/commonveil");
    if (status !== 200 || data?.protocol !== PROTOCOL || data.host !== host || typeof data.key?.public !== "string") {
      throw new FederationError(502, "NOT_A_SITE", `${host} isn't a Commonveil site, or doesn't talk to other sites.`);
    }
    const pinned = this.q.get.get(host);
    if (pinned && pinned.key !== "-" && pinned.key !== data.key.public) {
      this.log.warn?.(`[federation] ${host} now presents a different key; refusing it until an admin accepts the change`);
      throw new FederationError(403, "SITE_KEY_CHANGED", `${host}'s key changed. An admin of this site has to accept the change first.`);
    }
    const now = new Date().toISOString();
    this.q.put.run(host, data.key.public, String(data.name || "").slice(0, 80), String(data.handle_domain || host), pinned?.first_seen || now, now);
    if (pinned?.key === "-") this.store.db.prepare("UPDATE fed_sites SET key = ? WHERE host = ?").run(data.key.public, host);
    this.docs.set(host, { doc: data, at: Date.now() });
    return data;
  }

  /** Check a signed request from another site. Answers { from, user } or throws. */
  async verify(req, body, path) {
    const h = (n) => String(req.headers[n] || "");
    const from = normHost(h("cv-from"));
    if (from === this.host) throw new FederationError(400, "SELF", "A site doesn't talk to itself.");
    this.#refuseBlocked(from);
    const date = h("cv-date");
    const t = Date.parse(date);
    if (!Number.isFinite(t) || Math.abs(Date.now() - t) > SKEW_MS) throw new FederationError(401, "STALE", "The request's time is off.");
    const nonce = h("cv-nonce");
    if (!/^[A-Za-z0-9_-]{16,64}$/.test(nonce)) throw new FederationError(401, "BAD_SIGNATURE", "Missing nonce.");
    const seenKey = `${from}:${nonce}`;
    if (this.nonces.has(seenKey)) throw new FederationError(401, "REPLAY", "That request was already used.");
    if (h("cv-digest") !== digestOf(body)) throw new FederationError(401, "BAD_DIGEST", "The body doesn't match its digest.");
    const doc = await this.siteDoc(from);
    const user = h("cv-user");
    const ok = verifyEd25519(doc.key.public, signatureBase({ method: req.method, to: this.host, path, from, date, nonce, digest: h("cv-digest"), user }), h("cv-signature"));
    if (!ok) throw new FederationError(401, "BAD_SIGNATURE", "The signature didn't verify.");
    this.nonces.set(seenKey, Date.now());
    if (this.nonces.size > 20_000) for (const [k, at] of this.nonces) if (Date.now() - at > 2 * SKEW_MS) this.nonces.delete(k);
    return { from, user, doc };
  }

  sites() {
    return this.q.all.all().map((r) => ({ host: r.host, name: r.name, handle_domain: r.handle_domain, first_seen: r.first_seen, last_seen: r.last_seen, blocked: Boolean(r.blocked) }));
  }

  setBlocked(host, blocked) {
    host = normHost(host);
    if (!this.q.get.get(host)) this.q.put.run(host, "-", "", host, new Date().toISOString(), new Date().toISOString());
    this.q.block.run(blocked ? 1 : 0, host);
    this.docs.delete(host);
  }

  /** Accept a site's new key (after an admin checked the change was expected). */
  forget(host) {
    this.q.forget.run(normHost(host));
    this.docs.delete(normHost(host));
  }
}
