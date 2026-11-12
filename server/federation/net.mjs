// Talking to other Commonveil sites: the site's own signing key, signed requests (inspired by
// HTTP Message Signatures, as ActivityPub uses them), checking other sites' signatures against the
// keys they publish, and safe outbound connections. docs/FEDERATION.md describes the wire format.
import crypto from "node:crypto";
import dns from "node:dns/promises";
import net from "node:net";
import https from "node:https";
import { lookup as dnsLookup } from "node:dns";
import { Readable } from "node:stream";
import { WebSocket } from "ws";
// The wire format itself (what's signed, digests, which addresses are off limits) is Secure Net's.
import { PROTOCOL, HOST_RE, SITE_DOCUMENT, signatureBase, digestOf, isPrivate, endpointsOf } from "../../packages/secure-net/src/wire/federation.js";

export { PROTOCOL, HOST_RE, signatureBase, digestOf, isPrivate, endpointsOf };
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { relaySuite, relayContext, relayKeysOf, relayKeysAcceptable, SUITE } from "../../packages/secure-net/src/wire/sealed.js";

/** The sealed relay (packages/secure-net/spec/CVP-015): requests between sites, sealed and signed post-quantum. */
export const relay = relaySuite({ ml_kem768, ml_dsa65 });
export { relayContext, relayKeysOf };

const SKEW_MS = 5 * 60_000;
const MAX_RESPONSE = 4 * 1024 * 1024;
const DOC_TTL_MS = 60 * 60_000;

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



/**
 * Outbound connections to other sites. By default only https, and never to private, loopback or
 * link-local addresses (so another site can't make this one probe its own network). Tests and
 * private networks can allow those with FEDERATION_ALLOW_PRIVATE=true (then http works too).
 */
export class Transport {
  /** hostHeader: also say which site is meant in X-Forwarded-Host (tests, where every site is on 127.0.0.1). */
  constructor({ allowPrivate = false, fetchImpl = null, wsImpl = WebSocket, urlFor = null, hostHeader = false } = {}) {
    this.hostHeader = hostHeader;
    this.allowPrivate = allowPrivate;
    // Connections check the address they actually connect to, not just an earlier lookup, so a
    // name that changes its answer in between (DNS rebinding) can't reach a private address.
    this.fetch = fetchImpl || (allowPrivate ? globalThis.fetch : pinnedFetch);
    this.lookup = allowPrivate ? undefined : publicLookup;
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

  async request(host, path, opts = {}) {
    return withSlot(() => this.#request(host, path, opts));
  }

  async #request(host, path, { method = "GET", headers = {}, body } = {}) {
    await this.#check(host);
    let res;
    try {
      res = await this.fetch(this.url(host, path), { method, headers: { "User-Agent": `Commonveil (${PROTOCOL})`, ...(this.hostHeader ? { "X-Forwarded-Host": host } : {}), ...headers }, body, redirect: "manual", signal: AbortSignal.timeout(15_000) });
    } catch (err) {
      throw new FederationError(502, "SITE_UNREACHABLE", `Can't reach ${host} right now.${err?.name === "TimeoutError" ? " It took too long to answer." : ""}`);
    }
    const len = Number(res.headers.get("content-length") || 0);
    if (len > MAX_RESPONSE) throw new FederationError(502, "TOO_LARGE", `${host} sent too much.`);
    // Counted as it arrives and cut off at the limit, whatever the length header said (CV-17).
    const raw = await readCapped(res, MAX_RESPONSE);
    if (!raw) throw new FederationError(502, "TOO_LARGE", `${host} sent too much.`);
    const text = new TextDecoder().decode(raw);
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
    return withSlot(() => this.#bytes(host, path));
  }

  async #bytes(host, path) {
    await this.#check(host);
    const res = await this.fetch(this.url(host, path), { headers: this.hostHeader ? { "X-Forwarded-Host": host } : {}, redirect: "manual", signal: AbortSignal.timeout(30_000) });
    if (res.status !== 200) {
      await res.body?.cancel?.().catch?.(() => {});
      return null;
    }
    const raw = await readCapped(res, MAX_FILE_PART);
    return raw ? Buffer.from(raw) : null;
  }

  async websocket(host, path, headers) {
    await this.#check(host);
    return new this.Ws(this.url(host, path, true), { headers: { ...(this.hostHeader ? { "X-Forwarded-Host": host } : {}), ...headers }, handshakeTimeout: 10_000, maxPayload: 64 * 1024, ...(this.lookup ? { lookup: this.lookup } : {}) });
  }
}

/** dns.lookup for outbound connections, refusing any private, loopback or link-local answer. */
export function publicLookup(hostname, options, callback) {
  const cb = typeof options === "function" ? options : callback;
  const opts = typeof options === "function" ? {} : options || {};
  dnsLookup(hostname, { ...opts, all: true, verbatim: true }, (err, addrs) => {
    if (err) return cb(err);
    const list = Array.isArray(addrs) ? addrs : [{ address: addrs, family: opts.family || 4 }];
    if (!list.length || list.some((a) => isPrivate(a.address))) {
      return cb(Object.assign(new Error(`${hostname} points at a private address`), { code: "PRIVATE_ADDRESS" }));
    }
    return opts.all ? cb(null, list) : cb(null, list[0].address, list[0].family);
  });
}

/** fetch() over https, connecting only to public addresses (checked at connect time). No redirects. */
export function pinnedFetch(url, { method = "GET", headers = {}, body, signal } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    if (u.protocol !== "https:") return reject(new Error("Only https is allowed"));
    if (net.isIP(u.hostname.replace(/^\[|\]$/g, "")) && isPrivate(u.hostname.replace(/^\[|\]$/g, ""))) return reject(new Error("Private address"));
    const req = https.request(u, { method, headers, lookup: publicLookup, signal }, (res) => {
      const out = new Headers();
      for (const [k, v] of Object.entries(res.headers)) if (v !== undefined) out.set(k, Array.isArray(v) ? v.join(", ") : String(v));
      const noBody = method === "HEAD" || res.statusCode === 204 || res.statusCode === 304;
      if (noBody) res.resume();
      resolve(new Response(noBody ? null : Readable.toWeb(res), { status: res.statusCode, headers: out }));
    });
    req.on("error", reject);
    req.end(body ?? undefined);
  });
}

const MAX_FILE_PART = 2 * 1024 * 1024;
const MAX_OUTBOUND = 16;
let outbound = 0;
const queue = [];

/** At most MAX_OUTBOUND reads from other sites at once; the rest wait their turn. */
async function withSlot(fn) {
  if (outbound >= MAX_OUTBOUND) await new Promise((resolve) => queue.push(resolve));
  outbound += 1;
  try {
    return await fn();
  } finally {
    outbound -= 1;
    queue.shift()?.();
  }
}

/** A response body, read chunk by chunk, or null as soon as it passes max bytes (reading stops there). */
export async function readCapped(res, max) {
  if (!res.body?.getReader) {
    const buf = new Uint8Array(await res.arrayBuffer());
    return buf.length <= max ? buf : null;
  }
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.byteLength;
  }
  return out;
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
    if (!db.prepare("PRAGMA table_info(fed_sites)").all().some((c) => c.name === "pq")) db.exec("ALTER TABLE fed_sites ADD COLUMN pq TEXT");
    this.q = {
      get: db.prepare("SELECT * FROM fed_sites WHERE host = ?"),
      put: db.prepare("INSERT INTO fed_sites (host, key, name, handle_domain, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(host) DO UPDATE SET name = excluded.name, handle_domain = excluded.handle_domain, last_seen = excluded.last_seen"),
      all: db.prepare("SELECT * FROM fed_sites ORDER BY last_seen DESC LIMIT 500"),
      block: db.prepare("UPDATE fed_sites SET blocked = ? WHERE host = ?"),
      forget: db.prepare("DELETE FROM fed_sites WHERE host = ?"),
    };
  }

  /** This site's relay keys, made once and kept with the data. */
  async relayKeys() {
    if (!this.relayKeysMade) {
      let saved = this.store.getSetting("federation:relay-keys");
      if (!saved) {
        saved = await relay.generateKeys();
        this.store.setSetting("federation:relay-keys", saved);
      }
      this.relayKeysMade = saved;
    }
    return this.relayKeysMade;
  }

  /** What the site document says about them. */
  async relayDoc() {
    const k = await this.relayKeys();
    return { suite: SUITE, kem: k.kem.public, sig: k.sig.public };
  }

  /** The headers of a signed request: Ed25519 and ML-DSA-65 over the same base. */
  async headers({ method, to, path, body, user }) {
    const date = new Date().toISOString();
    const nonce = b64u(crypto.randomBytes(16));
    const digest = digestOf(body);
    const base = signatureBase({ method, to, path, from: this.host, date, nonce, digest, user });
    return { "CV-From": this.host, "CV-Date": date, "CV-Nonce": nonce, "CV-Digest": digest, "CV-Signature": this.key.sign(base), "CV-PQ-Signature": relay.sign((await this.relayKeys()).sig.secret, base), ...(user ? { "CV-User": user } : {}) };
  }

  /** POST JSON to another site, signed, and sealed for it if it publishes relay keys. Answers { status, data }. */
  async post(to, path, payload, { user } = {}) {
    this.#refuseBlocked(to);
    let body = JSON.stringify(payload);
    const peer = relayKeysOf(await this.siteDoc(to));
    const context = relayContext({ from: this.host, to, path });
    let replyKey = null;
    if (peer) {
      const sealed = await relay.seal(peer.kem, body, context);
      body = JSON.stringify({ sealed: sealed.sealed });
      replyKey = sealed.replyKey;
    }
    const r = await this.transport.request(to, path, { method: "POST", body, headers: { "Content-Type": "application/json", ...(peer ? { "CV-Sealed": "1" } : {}), ...(await this.headers({ method: "POST", to, path, body, user })) } });
    if (!replyKey) return r;
    if (typeof r.data?.sealed === "string") {
      try {
        return { status: r.status, data: JSON.parse(await relay.openReply(replyKey, r.data.sealed, context)) };
      } catch {
        throw new FederationError(502, "SITE_ERROR", `${to}'s reply couldn't be opened.`);
      }
    }
    // A refusal before the request was opened comes back plain; an answer never does.
    if (r.status < 400) throw new FederationError(502, "SITE_ERROR", `${to} answered a sealed request in the clear.`);
    return r;
  }

  /** Where one of a site's endpoints is, from its site document (act, directory, inbox, ...). */
  async endpoint(host, name) {
    return endpointsOf(await this.siteDoc(host))[name];
  }

  /** POST to one of a site's endpoints by name, wherever that site keeps it. */
  async send(to, name, payload, options) {
    return this.post(to, await this.endpoint(to, name), payload, options);
  }

  #refuseBlocked(host) {
    if (this.q.get.get(host)?.blocked) throw new FederationError(403, "SITE_BLOCKED", `This site doesn't talk to ${host}.`);
  }

  /** Another site's public document, and its key pinned on first contact. */
  async siteDoc(host) {
    host = normHost(host);
    const cached = this.docs.get(host);
    if (cached && Date.now() - cached.at < DOC_TTL_MS) return cached.doc;
    const { status, data } = await this.transport.request(host, SITE_DOCUMENT);
    if (status !== 200 || data?.protocol !== PROTOCOL || data.host !== host || typeof data.key?.public !== "string") {
      throw new FederationError(502, "NOT_A_SITE", `${host} isn't a Commonveil site, or doesn't talk to other sites.`);
    }
    const pinned = this.q.get.get(host);
    const relayNow = relayKeysOf(data);
    const relayWas = pinned?.pq ? JSON.parse(pinned.pq) : null;
    if (pinned && pinned.key !== "-" && (pinned.key !== data.key.public || !relayKeysAcceptable(relayWas, relayNow))) {
      this.log.warn?.(`[federation] ${host} now presents a different key; refusing it until an admin accepts the change`);
      throw new FederationError(403, "SITE_KEY_CHANGED", `${host}'s key changed. An admin of this site has to accept the change first.`);
    }
    const now = new Date().toISOString();
    this.q.put.run(host, data.key.public, String(data.name || "").slice(0, 80), String(data.handle_domain || host), pinned?.first_seen || now, now);
    if (pinned?.key === "-") this.store.db.prepare("UPDATE fed_sites SET key = ? WHERE host = ?").run(data.key.public, host);
    // Relay keys are pinned with the site's key; a site may start sealing, never stop.
    if (relayNow && !relayWas) this.store.db.prepare("UPDATE fed_sites SET pq = ? WHERE host = ?").run(JSON.stringify(relayNow), host);
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
    // A site that publishes relay keys is held to them: both signatures, and sealed bodies.
    const peer = relayKeysOf(doc);
    const sealed = h("cv-sealed") === "1";
    if (peer) {
      const base = signatureBase({ method: req.method, to: this.host, path, from, date, nonce, digest: h("cv-digest"), user });
      if (!relay.verify(peer.sig, base, h("cv-pq-signature"))) throw new FederationError(401, "BAD_SIGNATURE", "The post-quantum signature didn't verify.");
      if (req.method === "POST" && !sealed) throw new FederationError(401, "UNSEALED", "This site only takes sealed requests from that site.");
    }
    this.nonces.set(seenKey, Date.now());
    if (this.nonces.size > 20_000) for (const [k, at] of this.nonces) if (Date.now() - at > 2 * SKEW_MS) this.nonces.delete(k);
    if (!sealed) return { from, user, doc, body, reply: null };
    // Opened only now that it's known who sent it. The reply goes back under the request's own key.
    const context = relayContext({ from, to: this.host, path });
    try {
      const opened = await relay.open((await this.relayKeys()).kem.secret, JSON.parse(body).sealed, context);
      return { from, user, doc, body: opened.text, reply: async (data) => ({ sealed: await relay.sealReply(opened.replyKey, JSON.stringify(data), context) }) };
    } catch {
      throw new FederationError(400, "CANNOT_OPEN", "That request wasn't sealed for this site.");
    }
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
