// The hosted site talking to other Commonveil sites (docs/FEDERATION.md, "The hosted site").
//
// The same protocol as a self-hosted site's (server/federation), on what a hosted function has:
// no long-lived process, no database hooks, tables instead of SQL. So:
//   - what it knows about other sites lives in the Fed* tables (backend only);
//   - notices to other sites (someone joined, keys changed, a block) are sent as part of the
//     request that caused them, not afterwards;
//   - people from other sites have no account row here (the platform assigns ids, and theirs must
//     stay their own): they exist as a profile, their public keys, and a FedShadow row.
// Not offered: calls and presence across sites, files from other sites, and holding messages
// for a site that's down (the app is told, and can try again).
import { peerDeviceOut, statementOut } from "../store.ts";
import { CURSOR_FIELDS, FAN_OUT, mergeResults, unb64u } from "./merge.ts";
import { SITE, siteDocument } from "./site.ts";
import * as W from "./wire.ts";

const ID24 = /^[a-f0-9]{24}$/;
const HANDLE_RE = /^[a-z0-9][a-z0-9-]{1,19}(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
const SHADOW_FIELDS = ["display_name", "bio", "pronouns", "accent_color", "avatar_emoji", "avatar_image"];
const MAX_REPLY = 10 * 1024 * 1024;
const DOC_TTL_MS = 5 * 60_000;
/** The things a request can be about that live on one site, and the table each is in here. */
const ROOM_KEYS: Record<string, string> = { conversation_id: "Conversation", server_id: "Server", channel_id: "Channel" };
const ROOM_LISTS: Record<string, string> = { conversations: "Conversation", servers: "Server", channels: "Channel", conversation: "Conversation", server: "Server", channel: "Channel" };
const ROOM_ID_LISTS: Record<string, string> = { conversation_ids: "Conversation", server_ids: "Server", channel_ids: "Channel" };
/** Functions that are only ever a person's own site's business. */
const LOCAL_ONLY = new Set(["identity", "admin", "notifications", "maintenance", "disclose", "invite", "voice", "files"]);
const KEY_READS = new Set(["status", "peer_keys", "device_sync", "get_recovery", "ack_envelopes"]);

export class FederationError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/** Short-lived memory inside one running function: saves repeated reads, never the only record. */
const memo = new Map<string, { at: number; value: any }>();
function remembered<T>(key: string, ttl: number, make: () => Promise<T>): Promise<T> {
  const hit = memo.get(key);
  if (hit && Date.now() - hit.at < ttl) return Promise.resolve(hit.value);
  return make().then((value) => {
    if (memo.size > 5000) memo.clear();
    memo.set(key, { at: Date.now(), value });
    return value;
  });
}
export const forgetMemo = () => memo.clear();

type Options = { sr: any; site?: typeof SITE; version?: string; fetchImpl?: typeof fetch; urlFor?: (host: string, path: string) => string; log?: any };

export class HostedFederation {
  sr: any;
  site: typeof SITE;
  host: string;
  version: string;
  fetch: typeof fetch;
  urlFor: (host: string, path: string) => string;
  open: boolean;
  log: any;

  constructor({ sr, site = SITE, version = "", fetchImpl, urlFor, log = console }: Options) {
    this.sr = sr;
    this.site = site;
    this.host = site.host;
    this.version = version;
    this.fetch = fetchImpl || ((...a: Parameters<typeof fetch>) => fetch(...a));
    // Tests reach their sites by port; a real site only ever uses https and public names.
    this.open = Boolean(urlFor);
    this.urlFor = urlFor || ((host, path) => `https://${host}${path}`);
    this.log = log;
  }

  get enabled() {
    return Boolean(this.site.enabled && this.site.public_key);
  }

  // ---------- this site's key ----------

  /** The site's key: the oldest FedKey row, made on first use. */
  async key(): Promise<{ public: string; secret: string }> {
    return remembered(`key:${this.host}`, 3600_000, async () => {
      const T = this.sr.entities.FedKey;
      let rows = await T.filter({}, "created_date", 5);
      if (!rows.length) {
        await T.create(await W.generateSiteKey());
        // Two first uses at once each make one: everyone then uses the older.
        rows = await T.filter({}, "created_date", 5);
      }
      return { public: rows[0].public, secret: rows[0].secret };
    });
  }

  // ---------- talking to other sites ----------

  async request(host: string, path: string, { method = "GET", body, headers = {} }: { method?: string; body?: string; headers?: Record<string, string> } = {}) {
    if (!W.HOST_RE.test(host) || (!this.open && !W.reachable(host))) throw new FederationError(400, "BAD_SITE", "That isn't a site this one can reach.");
    let res: Response;
    try {
      res = await this.fetch(this.urlFor(host, path), { method, body, headers: { Accept: "application/json", ...(this.open ? { "X-Forwarded-Host": host } : {}), ...headers }, redirect: "error", signal: AbortSignal.timeout(15_000) });
    } catch {
      throw new FederationError(502, "SITE_UNREACHABLE", `${host} can't be reached right now.`);
    }
    if (Number(res.headers.get("content-length") || 0) > MAX_REPLY) throw new FederationError(502, "SITE_ERROR", `${host} sent too much.`);
    const text = await res.text();
    if (text.length > MAX_REPLY) throw new FederationError(502, "SITE_ERROR", `${host} sent too much.`);
    let data: any = null;
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
    return { status: res.status, data };
  }

  /** Another site's document, with its key pinned the first time it's seen. */
  async siteDoc(hostRaw: string): Promise<any> {
    const host = W.normHost(hostRaw);
    if (!host || host === this.host) throw new FederationError(400, "BAD_SITE", "That isn't another site.");
    return remembered(`doc:${host}`, DOC_TTL_MS, async () => {
      const T = this.sr.entities.FedSite;
      const [pinned] = await T.filter({ host }, "created_date", 1);
      if (pinned?.blocked) throw new FederationError(403, "SITE_BLOCKED", `This site doesn't talk to ${host}.`);
      const { status, data } = await this.request(host, W.SITE_DOCUMENT);
      if (status !== 200 || data?.protocol !== W.PROTOCOL || data.host !== host || typeof data.key?.public !== "string") {
        throw new FederationError(502, "NOT_A_SITE", `${host} isn't a Commonveil site, or doesn't talk to other sites.`);
      }
      if (pinned && pinned.key !== data.key.public) {
        throw new FederationError(403, "SITE_KEY_CHANGED", `${host}'s key changed. An admin of this site has to accept the change first.`);
      }
      const now = new Date().toISOString();
      const row = { host, key: data.key.public, name: String(data.name || "").slice(0, 80), handle_domain: String(data.handle_domain || host), last_seen: now };
      if (!pinned) await T.create({ ...row, first_seen: now, blocked: false });
      else if (pinned.last_seen < new Date(Date.now() - 24 * 3600_000).toISOString()) await T.update(pinned.id, row);
      return data;
    });
  }

  async endpoint(host: string, name: string) {
    return W.endpointsOf(await this.siteDoc(host))[name];
  }

  /** POST to one of a site's endpoints, signed with this site's key. */
  async send(to: string, name: string, payload: unknown, user = "") {
    const path = await this.endpoint(to, name);
    const body = JSON.stringify(payload);
    const date = new Date().toISOString();
    const nonce = W.b64u(crypto.getRandomValues(new Uint8Array(16)));
    const digest = await W.digestOf(body);
    const signature = await W.signText((await this.key()).secret, W.signatureBase({ method: "POST", to, path, from: this.host, date, nonce, digest, user }));
    return this.request(to, path, { method: "POST", body, headers: { "Content-Type": "application/json", "CV-From": this.host, "CV-Date": date, "CV-Nonce": nonce, "CV-Digest": digest, "CV-Signature": signature, ...(user ? { "CV-User": user } : {}) } });
  }

  /** Check a signed request from another site. Answers { from, user } or throws. */
  async verify(req: Request, body: string) {
    const h = (n: string) => String(req.headers.get(n) || "");
    const url = new URL(req.url);
    const from = W.normHost(h("cv-from"));
    if (!from) throw new FederationError(401, "BAD_SIGNATURE", "The request doesn't say which site it's from.");
    if (from === this.host) throw new FederationError(400, "SELF", "A site doesn't talk to itself.");
    const date = h("cv-date");
    const t = Date.parse(date);
    if (!Number.isFinite(t) || Math.abs(Date.now() - t) > W.SKEW_MS) throw new FederationError(401, "STALE", "The request's time is off.");
    const nonce = h("cv-nonce");
    if (!/^[A-Za-z0-9_-]{16,64}$/.test(nonce)) throw new FederationError(401, "BAD_SIGNATURE", "Missing nonce.");
    if (h("cv-digest") !== (await W.digestOf(body))) throw new FederationError(401, "BAD_DIGEST", "The body doesn't match its digest.");
    const doc = await this.siteDoc(from);
    const user = h("cv-user");
    const base = W.signatureBase({ method: req.method, to: this.host, path: url.pathname + url.search, from, date, nonce, digest: h("cv-digest"), user });
    if (!(await W.verifyText(doc.key.public, base, h("cv-signature")))) throw new FederationError(401, "BAD_SIGNATURE", "The signature didn't verify.");
    // Each signed request works once. The row is written before anything is done with it.
    const N = this.sr.entities.FedNonce;
    const key = `${from}:${nonce}`;
    if ((await N.filter({ key }, "created_date", 1)).length) throw new FederationError(401, "REPLAY", "That request was already used.");
    await N.create({ key, expires_at: new Date(Date.now() + 2 * W.SKEW_MS).toISOString() });
    if ((await N.filter({ key }, "created_date", 2)).length > 1) throw new FederationError(401, "REPLAY", "That request was already used.");
    return { from, user };
  }

  // ---------- handles and people ----------

  handleFor(username: string) {
    return `${String(username).toLowerCase().replace(/_/g, "-")}.${this.host}`;
  }

  localUsername(handle: string): string | null {
    const suffix = `.${this.host}`;
    if (!handle.endsWith(suffix)) return null;
    const label = handle.slice(0, -suffix.length);
    return /^[a-z0-9-]{3,20}$/.test(label) ? label.replace(/-/g, "_") : null;
  }

  async localProfile(username: string) {
    const rows = await this.sr.entities.Profile.filter({ username_key: username.toLowerCase() }, "created_date", 1);
    return rows[0] && !rows[0].remote ? rows[0] : null;
  }

  async shadow(userId: string) {
    return remembered(`shadow:${userId}`, 60_000, async () => (await this.sr.entities.FedShadow.filter({ user_id: userId }, "created_date", 1))[0] || null);
  }

  /** What one of this site's people shares with other sites: public profile fields and public keys. */
  async card(userId: string): Promise<any> {
    return remembered(`card:${userId}`, 20_000, async () => {
      const E = this.sr.entities;
      const [profile] = await E.Profile.filter({ user_id: userId }, "created_date", 1);
      if (!profile || profile.remote) return null;
      const statements = (await E.AccountKey.filter({ user_id: userId }, "version", 500)).map(statementOut);
      const devices = (await E.Device.filter({ user_id: userId }, "created_date", 200)).filter((d: any) => d.status === "active" || d.status === "revoked").map(peerDeviceOut);
      const visibility = profile.profile_visibility || "shared";
      const shown: Record<string, string> = {};
      for (const f of SHADOW_FIELDS) shown[f] = visibility === "nobody" ? "" : profile[f] || "";
      return { id: userId, handle: this.handleFor(profile.username), profile: { ...shown, profile_visibility: visibility, dm_policy: profile.dm_policy || "anyone" }, directory: { statements, devices } };
    });
  }

  /** For the handlers (ctx.federation): find someone by handle, keep their public keys here, answer their id. */
  async resolveHandle(handleRaw: string, me: string): Promise<string | null> {
    if (!this.enabled) return null;
    const handle = String(handleRaw || "").toLowerCase();
    if (!HANDLE_RE.test(handle)) return null;
    const local = this.localUsername(handle);
    if (local) return (await this.localProfile(local))?.user_id || null;
    try {
      const [known] = await this.sr.entities.FedShadow.filter({ handle }, "created_date", 1);
      const ident = known ? { user_id: known.user_id, home: known.home } : await this.lookupHandle(handle);
      if (!ident) return null;
      const meCard = await this.card(me);
      const { status, data } = await this.send(ident.home, "directory", { user_id: ident.user_id, handle, requester: meCard ? { id: me, handle: meCard.handle } : null, purpose: "conversation" });
      if (status !== 200 || !data?.user) return null;
      await this.mirror(ident.home, data.user);
      return data.user.id;
    } catch (err) {
      if (err instanceof FederationError) return null;
      throw err;
    }
  }

  async lookupHandle(handle: string): Promise<{ user_id: string; home: string } | null> {
    const parent = handle.slice(handle.indexOf(".") + 1);
    const ways = [
      async () => [handle, W.DEFAULT_ENDPOINTS.identity],
      async () => [parent, `${await this.endpoint(parent, "identity").catch(() => W.DEFAULT_ENDPOINTS.identity)}?handle=${encodeURIComponent(handle)}`],
    ];
    for (const way of ways) {
      try {
        const [host, path] = await way();
        const { status, data } = await this.request(host, path);
        if (status !== 200 || data?.handle !== handle || !ID24.test(data.user_id || "")) continue;
        const home = W.normHost(data.home);
        if (!home) continue;
        const doc = await this.siteDoc(home);
        // A site can only speak for handles under its own handle domain.
        if (!handle.endsWith(`.${doc.handle_domain}`)) continue;
        return { user_id: data.user_id, home };
      } catch {
        // try the next way
      }
    }
    return null;
  }

  /** Whether an id is an account made on this site. */
  async localAccount(id: string) {
    const E = this.sr.entities;
    return Boolean((await E.Person.get(id).catch(() => null)) || (await E.User.get(id).catch(() => null)));
  }

  /** Keep a copy of another site's person here: profile, public keys and devices. */
  async mirror(home: string, card: any): Promise<string> {
    if (!card || !ID24.test(card.id || "") || !HANDLE_RE.test(card.handle || "")) throw new FederationError(400, "BAD_PERSON", "That person's details didn't make sense.");
    const doc = await this.siteDoc(home);
    if (!card.handle.endsWith(`.${doc.handle_domain}`)) throw new FederationError(403, "WRONG_SITE", "A site can only speak for its own people.");
    const E = this.sr.entities;
    const [existing] = await E.FedShadow.filter({ user_id: card.id }, "created_date", 1);
    if (existing && existing.home !== home) throw new FederationError(403, "WRONG_SITE", "That person belongs to another site.");
    if (!existing && (await this.localAccount(card.id))) throw new FederationError(409, "ID_TAKEN", "That id belongs to someone on this site.");
    const digest = W.b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify([card.handle, card.profile, card.directory])))));
    if (existing && existing.digest === digest) return card.id;
    const p = card.profile || {};
    const row: Record<string, unknown> = {
      user_id: card.id, username: card.handle, username_key: card.handle, remote: true, home,
      profile_visibility: ["shared", "conversations", "nobody"].includes(p.profile_visibility) ? p.profile_visibility : "shared",
      dm_policy: ["anyone", "servers", "nobody"].includes(p.dm_policy) ? p.dm_policy : "anyone",
      default_listed: false,
    };
    for (const f of SHADOW_FIELDS) row[f] = typeof p[f] === "string" ? p[f].slice(0, f === "avatar_image" ? 48_000 : 300) : "";
    const [prof] = await E.Profile.filter({ user_id: card.id }, "created_date", 1);
    if (prof && !prof.remote) throw new FederationError(409, "ID_TAKEN", "That id belongs to someone on this site.");
    if (prof) await E.Profile.update(prof.id, row);
    else await E.Profile.create(row);
    // Public keys and devices: replaced as a whole with the home site's current list.
    const statements = Array.isArray(card.directory?.statements) ? card.directory.statements.slice(0, 500) : [];
    const devices = Array.isArray(card.directory?.devices) ? card.directory.devices.slice(0, 200) : [];
    for (const k of await E.AccountKey.filter({ user_id: card.id }, "version", 500)) await E.AccountKey.delete(k.id);
    for (const s of statements) await E.AccountKey.create({ ...statementOut({ ...s, user_id: card.id }), user_id: card.id });
    const before = await E.Device.filter({ user_id: card.id }, "created_date", 200);
    for (const d of before) if (!devices.some((x: any) => x.device_id === d.device_id)) await E.Device.delete(d.id);
    for (const d of devices) {
      const dev = { ...peerDeviceOut(d), user_id: card.id, label: "" };
      const old = before.find((x: any) => x.device_id === d.device_id);
      if (old) await E.Device.update(old.id, dev);
      else await E.Device.create(dev);
    }
    const shadowRow = { user_id: card.id, home, handle: card.handle, digest };
    if (existing) await E.FedShadow.update(existing.id, shadowRow);
    else await E.FedShadow.create(shadowRow);
    memo.delete(`shadow:${card.id}`);
    return card.id;
  }

  // ---------- which site a thing is on ----------

  async userHosts(userId: string): Promise<string[]> {
    return remembered(`hosts:${userId}`, 60_000, async () => (await this.sr.entities.FedUserHost.filter({ user_id: userId }, "created_date", 50)).map((r: any) => r.host));
  }

  async addUserHost(userId: string, host: string) {
    if ((await this.userHosts(userId)).includes(host)) return;
    const T = this.sr.entities.FedUserHost;
    if (!(await T.filter({ user_id: userId, host }, "created_date", 1)).length) await T.create({ user_id: userId, host });
    memo.delete(`hosts:${userId}`);
  }

  async dropUserHost(userId: string, host: string) {
    for (const r of await this.sr.entities.FedUserHost.filter({ user_id: userId, host }, "created_date", 5)) await this.sr.entities.FedUserHost.delete(r.id);
    memo.delete(`hosts:${userId}`);
  }

  /** Which site hosts each of these ids, for the ones on another site. */
  async routes(ids: string[]): Promise<Map<string, string>> {
    const out = new Map<string, string>();
    const ask: string[] = [];
    for (const id of new Set(ids)) {
      const hit = memo.get(`route:${id}`);
      if (hit && Date.now() - hit.at < (hit.value ? 600_000 : 15_000)) {
        if (hit.value) out.set(id, hit.value);
      } else ask.push(id);
    }
    if (ask.length) {
      const rows = await this.sr.entities.FedRoute.filter({ ref_id: { $in: ask } }, "created_date", 500);
      for (const id of ask) {
        const host = rows.find((r: any) => r.ref_id === id)?.host || "";
        memo.set(`route:${id}`, { at: Date.now(), value: host });
        if (host) out.set(id, host);
      }
    }
    return out;
  }

  /** Remember that a room is on another site. Never for something that exists here. */
  async learnRoute(id: string, table: string, host: string): Promise<boolean> {
    if (!ID24.test(id) || (await this.routes([id])).has(id)) return false;
    if (await this.sr.entities[table].get(id).catch(() => null)) return false;
    await this.sr.entities.FedRoute.create({ ref_id: id, host, kind: table });
    memo.set(`route:${id}`, { at: Date.now(), value: host });
    return true;
  }

  #rooms(value: any, visit: (id: string, table: string) => void, depth = 0) {
    if (!value || typeof value !== "object" || depth > 6) return;
    if (Array.isArray(value)) return value.slice(0, 2000).forEach((v) => this.#rooms(v, visit, depth + 1));
    for (const [k, v] of Object.entries(value)) {
      if (typeof v === "string") {
        if (ROOM_KEYS[k] && ID24.test(v)) visit(v, ROOM_KEYS[k]);
      } else if (Array.isArray(v) && ROOM_ID_LISTS[k]) {
        for (const x of v.slice(0, 500)) if (typeof x === "string" && ID24.test(x)) visit(x, ROOM_ID_LISTS[k]);
      } else if (v && typeof v === "object") {
        if (ROOM_LISTS[k]) for (const x of Array.isArray(v) ? v.slice(0, 2000) : [v]) if (x && typeof (x as any).id === "string" && ID24.test((x as any).id)) visit((x as any).id, ROOM_LISTS[k]);
        this.#rooms(v, visit, depth + 1);
      }
    }
  }

  async learnRoutes(host: string, data: any, userId: string) {
    const found = new Map<string, string>();
    this.#rooms(data, (id, table) => found.set(id, table));
    if (!found.size) return;
    const known = await this.routes([...found.keys()]);
    for (const [id, table] of found) if (!known.has(id)) await this.learnRoute(id, table, host);
    await this.addUserHost(userId, host);
  }

  /** Which other site a request is about, if any: an explicit _site, or the site hosting what it names. */
  async targetOf(body: any): Promise<string | null> {
    if (typeof body._site === "string" && body._site) {
      const site = W.normHost(body._site);
      if (!site) throw new FederationError(400, "BAD_SITE", "That isn't a site.");
      return site === this.host ? null : site;
    }
    const ids = new Set<string>();
    this.#rooms(body, (id) => ids.add(id));
    if (typeof body.payload === "string") {
      try {
        this.#rooms(JSON.parse(body.payload), (id) => ids.add(id));
      } catch {
        // not JSON: nothing to route by
      }
    }
    if (!ids.size) return null;
    const routed = await this.routes([...ids]);
    const hosts = new Set(routed.values());
    if (hosts.size > 1) throw new FederationError(400, "MIXED_SITES", "That request names things on more than one site.");
    return [...hosts][0] || null;
  }

  // ---------- my people's calls, relayed ----------

  /** Run one call on another site, as this person. */
  async act(host: string, user: any, fn: string, body: any) {
    const card = await this.card(user.id);
    if (!card) throw new FederationError(409, "SETUP_REQUIRED", "Finish setting up your account first.");
    const { status, data } = await this.send(host, "act", { user: card, function: fn, request: JSON.stringify(body) }, user.id);
    if (status === 200) await this.learnRoutes(host, data, user.id);
    return { status, data: data ?? { error: `${host} didn't answer properly.`, code: "SITE_ERROR" } };
  }

  /**
   * For every function call (http.ts): relay a call about something on another site, or gather
   * "all of mine" from each site this person has things on. Answers { status, data }, or null
   * when it's only this site's business.
   */
  async relay(fn: string, body: any, user: any, runLocal: (body: any) => Promise<{ status: number; data: any }>) {
    if (!this.enabled || !user || LOCAL_ONLY.has(fn)) return null;
    let target: string | null;
    try {
      target = await this.targetOf(body);
    } catch (err: any) {
      if (err instanceof FederationError) return { status: err.status, data: { error: err.message, code: err.code } };
      // Trouble working out where something lives must never stop people using their own site.
      this.log.warn?.("[federation] routing", err?.name || "Error");
      return null;
    }
    delete body._site;
    if (target) {
      try {
        return await this.act(target, user, fn, body);
      } catch (err: any) {
        if (!(err instanceof FederationError)) throw err;
        return { status: err.status, data: { error: err.message, code: err.code } };
      }
    }
    const kind = FAN_OUT[`${fn}.${body.action}`];
    const hosts = kind ? await this.userHosts(user.id).catch(() => [] as string[]) : [];
    if (kind && hosts.length) return kind === "merge" ? this.#fanOutMerge(fn, body, user, hosts, runLocal) : this.#fanOutPeople(fn, body, user, hosts, runLocal);
    // Only this site's business: but other sites may need telling what came of it.
    if (fn !== "conversations" && fn !== "keys" && fn !== "safety") return null;
    const local = await runLocal(body);
    if (local.status === 200) await this.#tell(fn, body, user, local.data).catch((e) => this.log.warn?.("[federation] notice", e?.message));
    return local;
  }

  async #fanOutMerge(fn: string, body: any, user: any, hosts: string[], runLocal: (body: any) => Promise<{ status: number; data: any }>) {
    // Cursors are "<this site's>~<base64 JSON of each other site's>", so apps keep one cursor each.
    const remoteCursors: Record<string, Record<string, string>> = {};
    const localBody = { ...body };
    for (const field of Object.keys(CURSOR_FIELDS)) {
      if (typeof body[field] !== "string") continue;
      const [mine, rest] = body[field].split("~");
      localBody[field] = mine;
      if (rest) {
        try {
          for (const [h, c] of Object.entries(JSON.parse(unb64u(rest)))) (remoteCursors[h] ||= {})[field] = c as string;
        } catch {
          // a damaged cursor just starts that site afresh
        }
      }
    }
    const local = await runLocal(localBody);
    if (local.status !== 200) return local;
    const results: any[] = [{ host: this.host, data: local.data }];
    await Promise.all(hosts.map(async (h) => {
      const b = { ...localBody };
      for (const field of Object.keys(CURSOR_FIELDS)) {
        if (remoteCursors[h]?.[field] !== undefined) b[field] = remoteCursors[h][field];
        else delete b[field];
      }
      try {
        const r = await this.act(h, user, fn, b);
        if (r.status === 200) results.push({ host: h, data: r.data });
        else if (r.status === 401 || r.status === 403 || r.status === 404) await this.dropUserHost(user.id, h);
        else results.push({ host: h, data: null, keep: remoteCursors[h] });
      } catch {
        results.push({ host: h, data: null, keep: remoteCursors[h] });
      }
    }));
    return { status: 200, data: mergeResults(results) };
  }

  async #fanOutPeople(fn: string, body: any, user: any, hosts: string[], runLocal: (body: any) => Promise<{ status: number; data: any }>) {
    const ids: string[] = Array.isArray(body.user_ids) ? body.user_ids.filter((x: unknown) => typeof x === "string" && ID24.test(x as string)).slice(0, 500) : [];
    if (!ids.length) return null;
    const here = await this.sr.entities.Profile.filter({ user_id: { $in: ids } }, "created_date", 500);
    const remote = ids.filter((id) => !here.some((p: any) => p.user_id === id && !p.remote));
    if (!remote.length) return null;
    const local = await runLocal(body);
    const out: any = local.status === 200 ? local.data : fn === "keys" ? { keys: {} } : { profiles: [] };
    await Promise.all(hosts.map(async (h) => {
      try {
        const r = await this.act(h, user, fn, { ...body, user_ids: remote });
        if (r.status !== 200) return;
        if (r.data?.keys && out.keys) for (const [k, v] of Object.entries(r.data.keys)) out.keys[k] ||= v;
        if (Array.isArray(r.data?.profiles) && out.profiles) for (const p of r.data.profiles) if (!out.profiles.some((x: any) => x.user_id === p.user_id)) out.profiles.push(p);
      } catch {
        // that site is unreachable; its people stay unknown for now
      }
    }));
    return { status: 200, data: out };
  }

  /** After something changed here that other sites need to know: memberships, keys, blocks. */
  async #tell(fn: string, body: any, user: any, data: any) {
    const sends: Promise<unknown>[] = [];
    const post = (host: string, notice: unknown) => sends.push(this.send(host, "inbox", notice).catch(() => null));
    if (fn === "conversations") {
      const convo = data?.conversation;
      if (!convo?.id || !Array.isArray(convo.member_ids)) return;
      const others = convo.member_ids.filter((id: string) => id !== user.id);
      const shadows = others.length ? await this.sr.entities.FedShadow.filter({ user_id: { $in: others } }, "created_date", 200) : [];
      for (const s of shadows) post(s.home, { type: "membership", user_id: s.user_id, room: { kind: "conversation", id: convo.id }, joined: true });
    } else if (fn === "keys" && !KEY_READS.has(body.action)) {
      const hosts = await this.userHosts(user.id);
      if (!hosts.length) return;
      memo.delete(`card:${user.id}`);
      const card = await this.card(user.id);
      if (card) for (const host of hosts) post(host, { type: "keys", user: card });
    } else if (fn === "safety" && (body.action === "block" || body.action === "unblock")) {
      const blockedId = String(body.user_id || body.blocked_user_id || "");
      if (!ID24.test(blockedId)) return;
      const sites = new Set(await this.userHosts(user.id));
      const s = await this.shadow(blockedId);
      if (s) sites.add(s.home);
      for (const host of sites) post(host, { type: "block", user_id: user.id, blocked_id: blockedId, blocked: body.action === "block" });
    }
    await Promise.all(sends);
  }

  // ---------- other sites asking this one ----------

  async identity(handleRaw: string) {
    const handle = String(handleRaw || "").toLowerCase();
    const username = this.localUsername(handle);
    const profile = username ? await this.localProfile(username) : null;
    if (!profile) throw new FederationError(404, "NOT_FOUND", "Nobody here by that name.");
    return { handle: this.handleFor(profile.username), user_id: profile.user_id, home: this.host, profile_url: `https://${this.host}/u/${profile.username}` };
  }

  async inboundDirectory(from: string, payload: any) {
    const handle = String(payload?.handle || "").toLowerCase();
    const username = this.localUsername(handle);
    const profile = username ? await this.localProfile(username) : null;
    if (!profile || profile.user_id !== payload.user_id) throw new FederationError(404, "NOT_FOUND", "Nobody here by that name.");
    if (payload.purpose === "conversation") {
      // "Only people I share a server with" can't be checked for people on other sites, so it means no.
      if ((profile.dm_policy || "anyone") !== "anyone") throw new FederationError(403, "NOT_ACCEPTING", `${handle} isn't accepting new conversations from other sites.`);
      const requester = String(payload.requester?.id || "");
      if (ID24.test(requester)) {
        const B = this.sr.entities.Block;
        const blocked = [...(await B.filter({ user_id: profile.user_id, blocked_user_id: requester }, "created_date", 1)), ...(await B.filter({ user_id: requester, blocked_user_id: profile.user_id }, "created_date", 1))];
        if (blocked.length) throw new FederationError(404, "NOT_FOUND", "Nobody here by that name.");
      }
    }
    await this.addUserHost(profile.user_id, from);
    return { user: await this.card(profile.user_id) };
  }

  async inboundInbox(from: string, payload: any) {
    if (payload?.type === "membership") {
      const uid = String(payload.user_id || "");
      if (!ID24.test(uid) || !(await this.localAccount(uid))) return { ok: false };
      const id = String(payload.room?.id || "");
      const table = payload.room?.kind === "server" ? "Server" : "Conversation";
      if (ID24.test(id)) await this.learnRoute(id, table, from);
      if (payload.joined) await this.addUserHost(uid, from);
      return { ok: true };
    }
    if (payload?.type === "keys") {
      const s = ID24.test(payload.user?.id || "") ? await this.shadow(payload.user.id) : null;
      if (s && s.home === from) await this.mirror(from, payload.user);
      return { ok: true };
    }
    if (payload?.type === "block") {
      const s = ID24.test(payload.user_id || "") ? await this.shadow(payload.user_id) : null;
      if (s?.home !== from || !ID24.test(payload.blocked_id || "")) return { ok: false };
      const B = this.sr.entities.Block;
      const exists = await B.filter({ user_id: payload.user_id, blocked_user_id: payload.blocked_id }, "created_date", 5);
      if (payload.blocked && !exists.length) await B.create({ user_id: payload.user_id, blocked_user_id: payload.blocked_id });
      if (!payload.blocked) for (const b of exists) await B.delete(b.id);
      return { ok: true };
    }
    throw new FederationError(400, "UNKNOWN_TYPE", "Unknown notice.");
  }

  async discover(tagRaw: string) {
    const tag = String(tagRaw || "").slice(0, 40);
    const rows = await this.sr.entities.Server.filter(tag ? { discoverable: true, public_tags: tag } : { discoverable: true }, "-member_count", 100).catch(() => []);
    const servers = rows
      .filter((s: any) => s.status !== "deleting" && s.public_name)
      .map((s: any) => ({ id: s.id, site: this.host, name: s.public_name, description: s.public_description || "", tags: s.public_tags || [], icon: s.public_icon || "", color: s.public_color || "", join_mode: s.join_mode }));
    return { site: this.host, servers };
  }

  document() {
    return siteDocument(this.site, this.version);
  }

  get handlers() {
    return { resolveHandle: (h: string, me: string) => this.resolveHandle(h, me) };
  }
}
