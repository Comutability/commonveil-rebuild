// The Commonveil Protocol: how self-hosted Commonveil sites talk to each other. docs/FEDERATION.md
// is the specification; this is the implementation.
//
// The model, in short:
// - Identity is an address. Alice on chat.example.com is @alice.chat.example.com; that name
//   answers who she is (/.well-known/commonveil/identity) and, in a browser, leads to her profile.
// - Every conversation and every server lives on one site, its host. People always talk to their
//   own site (their home). When they open something hosted elsewhere, their home relays the call,
//   signed with the home site's key, and the host runs it as that person.
// - On the host, a person from another site is a "shadow" account with the same id, whose public
//   keys and devices are copied from their home with every call. Their keys sign themselves (each
//   key statement is signed by the one before, and devices are certified by the account), and
//   everyone's app checks them as it does today, so nothing about end-to-end encryption changes:
//   the host stores ciphertext it can't read, like any Commonveil site.
import crypto from "node:crypto";
import { WebSocketServer } from "ws";
import { HANDLE_RE } from "../../base44/shared/http.ts";
import { peerDeviceOut, statementOut } from "../../base44/shared/store.ts";
import { userRecord } from "../../base44/shared/identity/sessions.ts";
import { json, readBody, bearer } from "../http.mjs";
import { FederationError, PROTOCOL, Signer, Transport, normHost } from "./net.mjs";
import { CURSOR_FIELDS, FAN_OUT, mergeResults } from "../../base44/shared/federation/merge.ts";
import { DEFAULT_ENDPOINTS } from "../../packages/secure-net/src/wire/federation.js";
import {sitePolicy,siteVerdict,publicSiteRules} from "../sitePolicy.mjs";

const ID24 = /^[0-9a-f]{24}$/;
// Where something lives (docs/FEDERATION.md, "Routes"). Ids a site gives its own records: where one
// appears, it says which site holds it.
const ID_KEYS = new Set(["conversation_id", "server_id", "channel_id", "case_id", "message_id", "ticket_id", "invite_id", "role_id", "id", "parent_id"]);
// Not file ids: a message's list of file parts is chosen by its sender, so a request routed by them
// could be steered to the sender's site. A file is found by where it was posted (docs/FEDERATION.md).
const ID_LIST_KEYS = new Set(["conversation_ids", "server_ids", "channel_ids", "message_ids"]);
// Ids a person's app chooses (a thread is named by its first message, an event and a server report
// by their items): anyone can write any value there, so they only route a request that names
// nothing else, and never outweigh what a site says about its own records.
const CHOSEN_KEYS = new Set(["thread_id", "event_id", "report_id"]);
// What an app names when it picks the site itself (_site): the place the request is about.
const PLACE_KEYS = new Set(["conversation_id", "server_id", "channel_id", "conversation_ids", "server_ids", "channel_ids"]);
// How much a claim about where something lives counts. Claims are kept per person: what one site
// says to one person never moves anyone else's requests. The highest claim wins; two sites with the
// same highest claim are a dispute, and the request goes to neither.
export const CLAIM = {
  chosen: 0, // a chosen id (above) in an answer
  implicit: 1, // a site's answer to this person's request, or its notice that they joined something there
  legacy: 2, // learned before 0.24.25, for everyone here (routes then weren't kept per person)
  explicit: 3, // the person's app named the site (_site), and the site answered
};

/** The claims for one thing, as [{ host, strength }], blocked sites already left out. */
export function resolveRoute(claims) {
  if (!claims.length) return { route: null, disputed: [] };
  const top = Math.max(...claims.map((c) => c.strength));
  const hosts = [...new Set(claims.filter((c) => c.strength === top).map((c) => c.host))].sort();
  return hosts.length === 1 ? { route: hosts[0], disputed: [] } : { route: null, disputed: hosts };
}

/**
 * How much a claim from a site the person's app named counts: named (3), unless another site
 * already holds the thing for them by an old route or a named claim. Then only heard (1): a site
 * can't take over what someone already has by answering a join. Answers { strength, other }.
 */
export function namedClaimStrength(claims, host) {
  const others = claims.filter((c) => c.host !== host && c.strength >= CLAIM.legacy).sort((a, b) => b.strength - a.strength || a.host.localeCompare(b.host));
  return others.length ? { strength: CLAIM.implicit, other: others[0].host } : { strength: CLAIM.explicit, other: null };
}

/** The ids a request or an answer names: [id, chosen] pairs (chosen: under a key an app picks). */
function idsNamed(v, key, depth, maxDepth, perList, out) {
  if (depth > maxDepth || v === null || v === undefined) return out;
  if (typeof v === "string") {
    if ((ID_KEYS.has(key) || ID_LIST_KEYS.has(key)) && ID24.test(v)) out.push([v, false]);
    else if (CHOSEN_KEYS.has(key) && ID24.test(v)) out.push([v, true]);
  } else if (Array.isArray(v)) {
    for (const x of v.slice(0, perList)) idsNamed(x, key, depth + 1, maxDepth, perList, out);
  } else if (typeof v === "object") {
    for (const [k, x] of Object.entries(v)) idsNamed(x, k, depth + 1, maxDepth, perList, out);
  }
  return out;
}

/** The places a request names (PLACE_KEYS), in its body and in its signed payload. */
function placesNamed(body) {
  const out = new Set();
  const go = (v, key, depth) => {
    if (depth > 6 || v === null || v === undefined) return;
    if (typeof v === "string") {
      if (PLACE_KEYS.has(key) && ID24.test(v)) out.add(v);
    } else if (Array.isArray(v)) {
      for (const x of v.slice(0, 500)) go(x, key, depth + 1);
    } else if (typeof v === "object") {
      for (const [k, x] of Object.entries(v)) go(x, k, depth + 1);
    }
  };
  go(body, "", 0);
  if (typeof body.payload === "string") {
    try {
      go(JSON.parse(body.payload), "", 0);
    } catch {
      // not JSON: nothing named in it
    }
  }
  return [...out].sort();
}

/**
 * Routes from before 0.24.25 (one table for everyone, first claim kept) become site-wide claims. The
 * old table stays, untouched: if the updater rolls back to 0.24.24, that version still finds its
 * routes. Copying again changes nothing.
 */
export function migrateRoutes(db) {
  if (!db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'fed_routes'").get()) return;
  db.exec(`INSERT OR IGNORE INTO fed_claims (user_id, id, host, strength, seen) SELECT '*', id, host, ${CLAIM.legacy}, seen FROM fed_routes`);
}

/** At most this many ids are learned from one answer: what a site says can't grow the claims table, or the work per answer, without bound. */
const MAX_LEARNED = 2000;

/** Say something about two sites at most once an hour: a site can't flood the log. */
const warned = new Map();
/** For tests: say everything again. */
export function forgetWarnings() {
  warned.clear();
}
function warnOnce(log, kind, a, b, line) {
  const key = `${kind} ${[a, b].sort().join(" ")}`;
  const now = Date.now();
  if (warned.size > 10_000) warned.clear();
  if (now - (warned.get(key) || 0) < 3_600_000) return;
  warned.set(key, now);
  log.warn?.(line());
}
const MAX_ACT_BODY = 9 * 1024 * 1024;
// Held messages (docs/OFFLINE.md): tried again after 30 seconds, then less and less often (at
// most every 30 minutes), for up to a week; the same week a message written offline may wait.
const HELD_EVERY_MS = 30_000;
const HELD_FIRST_RETRY_MS = 30_000;
const HELD_MAX_WAIT_MS = 30 * 60_000;
const HELD_MAX_AGE_MS = 7 * 24 * 3600_000;
const SHADOW_FIELDS = ["display_name", "bio", "pronouns", "accent_color", "avatar_emoji", "avatar_image"];
const ACTOR_NAMES = new Set(["VoiceRoom", "Presence"]);


const b64 = (s) => Buffer.from(s).toString("base64url");
const unb64 = (s) => Buffer.from(String(s), "base64url").toString();

export class Federation {
  constructor({ config, store, serviceClient, clientFor, auth, log = console, transport }) {
    this.config = config;
    this.store = store;
    this.sr = serviceClient;
    this.clientFor = clientFor;
    this.auth = auth;
    this.log = log;
    this.enabled = Boolean(config.federation);
    this.host = config.host + (new URL(config.siteUrl).port ? `:${new URL(config.siteUrl).port}` : "");
    this.transport = transport || new Transport({ allowPrivate: config.allowPrivateFederation });
    this.signer = new Signer({ host: this.host, store, transport: this.transport, log });
    this.wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });
    const db = store.db;
    db.exec(`CREATE TABLE IF NOT EXISTS fed_claims (user_id TEXT NOT NULL, id TEXT NOT NULL, host TEXT NOT NULL, strength INTEGER NOT NULL, seen INTEGER NOT NULL, PRIMARY KEY (user_id, id, host))`);
    db.exec(`CREATE INDEX IF NOT EXISTS fed_claims_by_id ON fed_claims (id)`);
    migrateRoutes(db);
    db.exec(`CREATE TABLE IF NOT EXISTS fed_user_hosts (user_id TEXT NOT NULL, host TEXT NOT NULL, seen INTEGER NOT NULL, PRIMARY KEY (user_id, host))`);
    db.exec(`CREATE TABLE IF NOT EXISTS fed_shadows (user_id TEXT PRIMARY KEY, home TEXT NOT NULL, handle TEXT NOT NULL, digest TEXT NOT NULL DEFAULT '', updated INTEGER NOT NULL)`);
    db.exec(`CREATE TABLE IF NOT EXISTS fed_notified (user_id TEXT NOT NULL, room TEXT NOT NULL, PRIMARY KEY (user_id, room))`);
    // Messages held for a site that can't be reached right now (docs/OFFLINE.md): each is the
    // sender's own sealed, signed request, delivered as it is once the site answers again.
    db.exec(`CREATE TABLE IF NOT EXISTS fed_outbox (host TEXT NOT NULL, msg_id TEXT NOT NULL, user_id TEXT NOT NULL, fn TEXT NOT NULL, body TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_at INTEGER NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (host, msg_id))`);
    this.q = {
      claims: db.prepare("SELECT c.host AS host, MAX(c.strength) AS strength FROM fed_claims c LEFT JOIN fed_sites s ON s.host = c.host WHERE c.id = ? AND c.user_id IN (?, '*') AND COALESCE(s.blocked, 0) = 0 GROUP BY c.host"),
      sameClaim: db.prepare("UPDATE fed_claims SET seen = ? WHERE user_id = ? AND id = ? AND host = ? AND strength >= ?"),
      putClaim: db.prepare("INSERT INTO fed_claims (user_id, id, host, strength, seen) VALUES (?, ?, ?, ?, ?) ON CONFLICT(user_id, id, host) DO UPDATE SET strength = MAX(strength, excluded.strength), seen = excluded.seen"),
      hostsOf: db.prepare("SELECT host FROM fed_user_hosts WHERE user_id = ?"),
      putHost: db.prepare("INSERT INTO fed_user_hosts (user_id, host, seen) VALUES (?, ?, ?) ON CONFLICT(user_id, host) DO UPDATE SET seen = excluded.seen"),
      dropHost: db.prepare("DELETE FROM fed_user_hosts WHERE user_id = ? AND host = ?"),
      shadow: db.prepare("SELECT * FROM fed_shadows WHERE user_id = ?"),
      shadowByHandle: db.prepare("SELECT * FROM fed_shadows WHERE handle = ?"),
      putShadow: db.prepare("INSERT INTO fed_shadows (user_id, home, handle, digest, updated) VALUES (?, ?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET handle = excluded.handle, digest = excluded.digest, updated = excluded.updated"),
      shadowsOfHome: db.prepare("SELECT user_id FROM fed_shadows WHERE home = ?"),
      notified: db.prepare("SELECT 1 FROM fed_notified WHERE user_id = ? AND room = ?"),
      putNotified: db.prepare("INSERT OR IGNORE INTO fed_notified (user_id, room) VALUES (?, ?)"),
      dropNotified: db.prepare("DELETE FROM fed_notified WHERE user_id = ? AND room = ?"),
    };
    this.pollCache = new Map();
    // Tell other sites when one of their people joins or leaves something hosted here.
    const prevWrite = store.onWrite;
    store.onWrite = (entity, row, old) => {
      prevWrite?.(entity, row, old);
      if (!this.enabled) return;
      this.#watchMembership(entity, row, old);
      if ((entity === "AccountKey" || entity === "Device") && !this.q.shadow.get(row.user_id)) this.#soon(`keys:${row.user_id}`, () => this.keysChanged(row.user_id));
      if (entity === "Block" && !old && !this.q.shadow.get(row.user_id)) this.blockChanged(row.user_id, row.blocked_user_id, true);
    };
    const prevRemove = store.onRemove;
    store.onRemove = (entity, id, row) => {
      prevRemove?.(entity, id, row);
      if (this.enabled && entity === "Block" && row && !this.q.shadow.get(row.user_id)) this.blockChanged(row.user_id, row.blocked_user_id, false);
    };
    this.timers = new Map();
  }

  start() {
    if (!this.enabled) return;
    this.heldTimer = setInterval(() => this.deliverHeld().catch((e) => this.log.warn?.("[federation] held messages", e?.message)), HELD_EVERY_MS);
    this.heldTimer.unref?.();
  }
  stop() {
    for (const t of this.timers.values()) clearTimeout(t);
    clearInterval(this.heldTimer);
  }

  // ---------- holding messages for sites that can't be reached ----------

  #holdable(fn, body) {
    return (fn === "messages" || fn === "channels") && body.action === "send" && typeof body.msg_id === "string" && /^[A-Za-z0-9_-]{8,64}$/.test(body.msg_id);
  }

  #hold(host, user, fn, body) {
    const now = Date.now();
    this.store.db
      .prepare("INSERT INTO fed_outbox (host, msg_id, user_id, fn, body, attempts, next_at, created) VALUES (?, ?, ?, ?, ?, 0, ?, ?) ON CONFLICT(host, msg_id) DO NOTHING")
      .run(host, body.msg_id, user.id, fn, JSON.stringify({ ...body, queued: true }), now + HELD_FIRST_RETRY_MS, now);
    return { status: 202, data: { queued: true, held_by: this.host, site: host, msg_id: body.msg_id } };
  }

  /** Try held messages that are due. Answers how many went out. */
  async deliverHeld(now = Date.now()) {
    const db = this.store.db;
    db.prepare("DELETE FROM fed_outbox WHERE created < ?").run(now - HELD_MAX_AGE_MS);
    const due = db.prepare("SELECT * FROM fed_outbox WHERE next_at <= ? ORDER BY created LIMIT 100").all(now);
    let sent = 0;
    const down = new Set();
    for (const row of due) {
      const drop = () => db.prepare("DELETE FROM fed_outbox WHERE host = ? AND msg_id = ?").run(row.host, row.msg_id);
      const later = () =>
        db.prepare("UPDATE fed_outbox SET attempts = attempts + 1, next_at = ? WHERE host = ? AND msg_id = ?").run(now + Math.min(HELD_MAX_WAIT_MS, HELD_FIRST_RETRY_MS * 2 ** (row.attempts + 1)), row.host, row.msg_id);
      if (down.has(row.host)) {
        later();
        continue;
      }
      const user = await userRecord(this.sr, row.user_id);
      if (!user) {
        drop();
        continue;
      }
      try {
        const r = await this.act(row.host, user, row.fn, JSON.parse(row.body));
        if (r.status === 200) sent += 1;
        if (r.status >= 500 || r.status === 429) {
          later();
          continue;
        }
        // Delivered, or turned down for good (the sender's device sees why when it next tries).
        drop();
      } catch (err) {
        down.add(row.host);
        later();
      }
    }
    return sent;
  }

  #soon(key, fn) {
    clearTimeout(this.timers.get(key));
    this.timers.set(key, setTimeout(() => {
      this.timers.delete(key);
      Promise.resolve(fn()).catch(() => {});
    }, 1500));
  }

  // ---------- handles ----------

  /** A local person's handle: their username (underscores become hyphens), then the handle domain. */
  handleFor(username) {
    return `${String(username).toLowerCase().replace(/_/g, "-")}.${this.config.handleDomain}`;
  }

  /** The local username a handle names, if it's one of ours. */
  #localUsername(handle) {
    const suffix = `.${this.config.handleDomain}`;
    if (!handle.endsWith(suffix)) return null;
    const label = handle.slice(0, -suffix.length);
    return /^[a-z0-9-]{3,20}$/.test(label) ? label.replace(/-/g, "_") : null;
  }

  async #localProfile(username) {
    const rows = await this.sr.entities.Profile.filter({ username_key: username.toLowerCase() }, "created_date", 1);
    return rows[0] && !rows[0].remote ? rows[0] : null;
  }

  /** This site's own people, as other sites see them: handle, id, and what their profile shares. */
  async #identity(profile) {
    return { handle: this.handleFor(profile.username), user_id: profile.user_id, home: this.host, profile_url: `${this.config.siteUrl}/u/${profile.username}` };
  }

  /** What one of our people shares with other sites: public profile fields and public keys. */
  async #card(userId) {
    const [profile] = await this.sr.entities.Profile.filter({ user_id: userId }, "created_date", 1);
    if (!profile || profile.remote) return null;
    const statements = (await this.sr.entities.AccountKey.filter({ user_id: userId }, "version", 500)).map(statementOut);
    const devices = (await this.sr.entities.Device.filter({ user_id: userId }, "created_date", 200)).filter((d) => d.status === "active" || d.status === "revoked").map(peerDeviceOut);
    const visibility = profile.profile_visibility || "shared";
    const shown = {};
    for (const f of SHADOW_FIELDS) shown[f] = visibility === "nobody" ? "" : profile[f] || "";
    return {
      id: userId,
      handle: this.handleFor(profile.username),
      profile: { ...shown, profile_visibility: visibility, dm_policy: profile.dm_policy || "anyone" },
      directory: { statements, devices },
    };
  }

  /**
   * For the handlers (ctx.federation): find someone by handle, check they accept a conversation
   * from `me`, keep a copy of their public keys here, and answer their id.
   */
  async resolveHandle(handle, me) {
    if (!this.enabled) return null;
    handle = String(handle || "").toLowerCase();
    if (!HANDLE_RE.test(handle)) return null;
    const local = this.#localUsername(handle);
    if (local) {
      const p = await this.#localProfile(local);
      return p ? p.user_id : null;
    }
    const known = this.q.shadowByHandle.get(handle);
    const ident = known ? { user_id: known.user_id, home: known.home } : await this.#lookupHandle(handle);
    if (!ident) return null;
    const meCard = await this.#card(me);
    const { status, data } = await this.signer.send(ident.home, "directory", { user_id: ident.user_id, handle, requester: meCard ? { id: me, handle: meCard.handle } : null, purpose: "conversation" });
    if (status !== 200 || !data?.user) return null;
    await this.#mirror(ident.home, data.user);
    return data.user.id;
  }

  async #lookupHandle(handle) {
    // The handle's own name answers first (like the AT Protocol's handles); its parent domain second.
    const parent = handle.slice(handle.indexOf(".") + 1);
    const ways = [
      async () => [handle, DEFAULT_ENDPOINTS.identity],
      // A site that can't answer at the usual address says where it does in its site document.
      async () => [parent, `${await this.signer.endpoint(parent, "identity").catch(() => DEFAULT_ENDPOINTS.identity)}?handle=${encodeURIComponent(handle)}`],
    ];
    for (const way of ways) {
      try {
        const [host, path] = await way();
        const { status, data } = await this.transport.request(host, path);
        if (status !== 200 || data?.handle !== handle || !ID24.test(data.user_id || "")) continue;
        const home = normHost(data.home);
        const doc = await this.signer.siteDoc(home);
        // A site can only speak for handles under its own handle domain.
        if (!handle.endsWith(`.${doc.handle_domain}`)) continue;
        return { user_id: data.user_id, home };
      } catch {
        // try the next way
      }
    }
    return null;
  }

  // ---------- shadows: people from other sites, as this site knows them ----------

  /** Keep a copy of another site's person here: account, profile, public keys and devices. */
  async #mirror(home, card) {
    if (!card || !ID24.test(card.id || "") || !HANDLE_RE.test(card.handle || "")) throw new FederationError(400, "BAD_PERSON", "That person's details didn't make sense.");
    const doc = await this.signer.siteDoc(home);
    if (!card.handle.endsWith(`.${doc.handle_domain}`)) throw new FederationError(403, "WRONG_SITE", "A site can only speak for its own people.");
    const existing = this.q.shadow.get(card.id);
    if (existing && existing.home !== home) throw new FederationError(403, "WRONG_SITE", "That person belongs to another site.");
    if (!existing && ["User", "Person"].includes(this.store.tableOf(card.id))) throw new FederationError(409, "ID_TAKEN", "That id belongs to someone on this site.");
    const digest = crypto.createHash("sha256").update(JSON.stringify([card.handle, card.profile, card.directory])).digest("hex");
    if (existing && existing.digest === digest) return card.id;
    const U = this.sr.entities;
    if (!existing) await U.User.create({ email: "", role: "user", full_name: "", remote: true, home }, card.id);
    const p = card.profile || {};
    const profileRow = {
      user_id: card.id, username: card.handle, username_key: card.handle, remote: true, home,
      profile_visibility: ["shared", "conversations", "nobody"].includes(p.profile_visibility) ? p.profile_visibility : "shared",
      dm_policy: ["anyone", "servers", "nobody"].includes(p.dm_policy) ? p.dm_policy : "anyone",
      default_listed: false,
    };
    for (const f of SHADOW_FIELDS) profileRow[f] = typeof p[f] === "string" ? p[f].slice(0, f === "avatar_image" ? 48_000 : 300) : "";
    const [prof] = await U.Profile.filter({ user_id: card.id }, "created_date", 1);
    if (prof) await U.Profile.update(prof.id, profileRow);
    else await U.Profile.create(profileRow);
    // Public keys and devices: replaced as a whole with the home site's current list.
    const statements = Array.isArray(card.directory?.statements) ? card.directory.statements.slice(0, 500) : [];
    const devices = Array.isArray(card.directory?.devices) ? card.directory.devices.slice(0, 200) : [];
    for (const k of await U.AccountKey.filter({ user_id: card.id }, "version", 500)) await U.AccountKey.delete(k.id);
    for (const s of statements) await U.AccountKey.create({ ...statementOut({ ...s, user_id: card.id }), user_id: card.id });
    const before = await U.Device.filter({ user_id: card.id }, "created_date", 200);
    for (const d of before) if (!devices.some((x) => x.device_id === d.device_id)) await U.Device.delete(d.id);
    for (const d of devices) {
      const row = { ...peerDeviceOut(d), user_id: card.id, label: "" };
      const old = before.find((x) => x.device_id === d.device_id);
      if (old) await U.Device.update(old.id, row);
      else await U.Device.create(row);
    }
    this.q.putShadow.run(card.id, home, card.handle, digest, Date.now());
    return card.id;
  }

  // ---------- notices about membership ----------

  #watchMembership(entity, row, old) {
    let room = null;
    let added = [];
    let removed = [];
    if (entity === "Conversation") {
      room = `c:${row.id}`;
      const now = new Set(row.member_ids || []);
      const was = new Set(old?.member_ids || []);
      added = [...now].filter((u) => !was.has(u));
      removed = [...was].filter((u) => !now.has(u));
    } else if (entity === "ServerMember") {
      room = `s:${row.server_id}`;
      if (!old) added = [row.user_id];
    } else {
      return;
    }
    for (const [list, joined] of [[added, true], [removed, false]]) {
      for (const uid of list) {
        const s = this.q.shadow.get(uid);
        if (!s) continue;
        if (joined && this.q.notified.get(uid, room)) continue;
        if (joined) this.q.putNotified.run(uid, room);
        else this.q.dropNotified.run(uid, room);
        this.signer.send(s.home, "inbox", { type: "membership", user_id: uid, room: { kind: room[0] === "c" ? "conversation" : "server", id: room.slice(2) }, joined })
          .catch((e) => this.log.warn?.(`[federation] couldn't tell ${s.home} about a membership: ${e.message}`));
      }
    }
  }

  /** After a local person's keys or devices change, the sites hosting their rooms get the new list. */
  async keysChanged(userId) {
    const card = await this.#card(userId);
    if (!card) return;
    for (const { host } of this.q.hostsOf.all(userId)) {
      this.signer.send(host, "inbox", { type: "keys", user: card }).catch(() => {});
    }
  }

  // ---------- home side: relaying my people's calls ----------

  /**
   * Where something on another site lives, for this person: their own claims and the site-wide
   * ones from before 0.24.25, leaving out blocked sites. Answers { route, disputed }.
   */
  routeOf(userId, id) {
    return resolveRoute(this.#claimsOf(userId, id));
  }

  #claimsOf(userId, id) {
    return this.q.claims.all(id, userId).map((r) => ({ host: r.host, strength: Number(r.strength) }));
  }

  /** Record a site's claim that it holds something, for one person. Never for something that's here. */
  #claim(userId, id, host, strength, now = Date.now()) {
    if (!ID24.test(id) || host === this.host || this.store.has(id)) return;
    // Heard before, as strongly: nothing changes but when.
    if (this.q.sameClaim.run(now, userId, id, host, strength).changes > 0) return;
    const before = this.routeOf(userId, id);
    this.q.putClaim.run(userId, id, host, strength, now);
    // Which sites, never what or whose: the admin can block the one that's wrong.
    const claims = this.#claimsOf(userId, id);
    const after = resolveRoute(claims);
    if (!before.disputed.length && after.disputed.length) {
      const [a, b] = after.disputed.length === 2 ? after.disputed : [after.disputed[0], host];
      warnOnce(this.log, "dispute", a, b, () => `[federation] ${after.disputed.join(after.disputed.length === 2 ? " and " : ", ")} each claim to hold the same thing; requests about it go to neither. Block whichever is wrong.`);
    } else if (after.route && after.route !== host && strength < CLAIM.legacy && claims.some((c) => c.host === after.route && c.strength === CLAIM.legacy)) {
      // A route from before 0.24.25 outweighs what this site says: it could be one a site took over then, so say so.
      warnOnce(this.log, "older", after.route, host, () => `[federation] ${after.route} (a route from before 0.24.25) and ${host} each claim to hold the same thing; the older route is used. Block whichever is wrong.`);
    }
  }

  /** A claim from a site the person's app named: see namedClaimStrength. */
  #claimNamed(userId, id, host, now) {
    if (!ID24.test(id) || host === this.host || this.store.has(id)) return;
    const { strength, other } = namedClaimStrength(this.#claimsOf(userId, id), host);
    if (other) warnOnce(this.log, "named", host, other, () => `[federation] ${host} answered as the home of something ${other} already holds for someone here; it stays with ${other}. Block whichever is wrong.`);
    this.#claim(userId, id, host, strength, now);
  }

  /** What a site's answer to this person says it holds: claims for this person only. */
  #learnRoutes(host, data, user) {
    const now = Date.now();
    let learned = false;
    const seen = new Set();
    const found = idsNamed(data, "", 0, 8, 5000, []).filter(([id, chosen]) => !seen.has(`${id} ${chosen}`) && seen.add(`${id} ${chosen}`));
    for (const [id, chosen] of found.slice(0, MAX_LEARNED)) {
      if (this.store.has(id)) continue;
      this.#claim(user.id, id, host, chosen ? CLAIM.chosen : CLAIM.implicit, now);
      learned = true;
    }
    if (learned) this.q.putHost.run(user.id, host, now);
  }

  /**
   * Which site a request is about, for this person: an explicit _site, or the site holding the ids
   * it names. Ids an app chooses (CHOSEN_KEYS) count only when nothing else is named.
   */
  #targetOf(body, user) {
    if (typeof body._site === "string" && body._site) {
      const site = normHost(body._site);
      return site === this.host ? null : site;
    }
    const named = idsNamed(body, "", 0, 6, 500, []);
    if (typeof body.payload === "string") {
      try {
        idsNamed(JSON.parse(body.payload), "", 0, 6, 500, named);
      } catch {
        // not JSON: nothing to route by
      }
    }
    // Calls rooms: "<server>.<channel>" and "dm.<conversation>.<call>" carry their ids too.
    for (const k of ["room", "room_id"]) if (typeof body[k] === "string") for (const part of body[k].split(".")) idsNamed(part, "id", 1, 6, 500, named);
    for (const chosen of [false, true]) {
      const hosts = new Set();
      let here = false;
      let disputed = false;
      for (const [id] of named.filter(([, c]) => c === chosen)) {
        if (this.store.has(id)) {
          here = true;
          continue;
        }
        const r = this.routeOf(user.id, id);
        if (r.route) hosts.add(r.route);
        else if (r.disputed.length) {
          disputed = true;
          warnOnce(this.log, "dispute", r.disputed[0], r.disputed[1], () => `[federation] ${r.disputed.join(r.disputed.length === 2 ? " and " : ", ")} each claim to hold the same thing; requests about it go to neither. Block whichever is wrong.`);
        }
      }
      hosts.delete(this.host);
      if (hosts.size > 1) throw new FederationError(400, "MIXED_SITES", "That request names things on more than one site.");
      if (hosts.size) return [...hosts][0];
      if (here) return null;
      if (disputed) throw new FederationError(409, "DISPUTED_SITE", "More than one site claims to hold this, so it isn't being sent to either. Your site's admin can see which sites in its log, and block the wrong one.");
    }
    return null;
  }

  /** Run one call on another site, as this person. Answers { status, data }. */
  async act(host, user, fn, body) {
    const card = await this.#card(user.id);
    if (!card) throw new FederationError(409, "SETUP_REQUIRED", "Finish setting up your account first.");
    const { status, data } = await this.signer.send(host, "act", { user: card, function: fn, request: JSON.stringify(body) }, { user: user.id });
    if (status === 200) this.#learnRoutes(host, data, user);
    if (fn === "files" && data) this.#rewriteFileLinks(host, data);
    return { status, data: data ?? { error: `${host} didn't answer properly.`, code: "SITE_ERROR" } };
  }

  #rewriteFileLinks(host, data) {
    const visit = (o) => {
      if (!o || typeof o !== "object") return;
      for (const [k, v] of Object.entries(o)) {
        if (typeof v === "string" && /\/api\/files\/[a-f0-9]{48}\?exp=\d+&sig=[A-Za-z0-9_-]+$/.test(v)) {
          const tail = v.slice(v.indexOf("/api/files/") + "/api/files/".length);
          o[k] = `/api/fed/files/${encodeURIComponent(host)}/${tail}`;
        } else if (typeof v === "object") visit(v);
      }
    };
    visit(data);
  }

  /**
   * For /api/functions: relay a call that's about something on another site, or gather "all of
   * mine" from every site this person has things on. Answers { status, data } or null (local only).
   */
  async relayFunction(fn, raw, user, runLocal) {
    // Signing in is always your own site's business.
    if (!this.enabled || !user || fn === "identity") return null;
    let body;
    try {
      body = JSON.parse(raw || "{}");
    } catch {
      return null;
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) return null;
    let target;
    try {
      target = this.#targetOf(body, user);
    } catch (err) {
      return { status: err.status || 400, data: { error: err.message, code: err.code } };
    }
    // Only a site the app actually named counts as its choice: an empty _site routed by claims.
    const namedSite = typeof body._site === "string" && body._site !== "";
    const hadSite = "_site" in body;
    delete body._site;
    if (target) {
      try {
        const r = await this.act(target, user, fn, body);
        // The site answered, but isn't well: hold the message rather than lose it.
        if ((r.status === 502 || r.status === 503 || r.status === 504) && this.#holdable(fn, body)) return this.#hold(target, user, fn, body);
        // The person's app named the site, and it answered: what the request is about lives there,
        // for this person, whatever another site said before.
        if (r.status === 200 && namedSite) {
          const now = Date.now();
          const places = placesNamed(body);
          // Joining by invite names only the code: the server is the one the site joined them to
          // (as trusted as the ids in its listing, which it chooses too). Never what someone already
          // has from another site: namedClaimStrength.
          if (!places.length && fn === "servers" && body.action === "join_server" && ID24.test(String(r.data?.server_id || ""))) places.push(r.data.server_id);
          for (const id of places) this.#claimNamed(user.id, id, target, now);
        }
        return r;
      } catch (err) {
        if (err?.code === "SITE_UNREACHABLE" && this.#holdable(fn, body)) return this.#hold(target, user, fn, body);
        return { status: err.status || 502, data: { error: err.message, code: err.code || "SITE_ERROR" } };
      }
    }
    const kind = FAN_OUT[`${fn}.${body.action}`];
    const hosts = this.q.hostsOf.all(user.id).map((r) => r.host);
    if (!kind || !hosts.length) return hadSite ? runLocal(JSON.stringify(body)) : null;
    return kind === "merge" ? this.#fanOutMerge(fn, body, user, hosts, runLocal) : this.#fanOutPeople(fn, body, user, hosts, runLocal);
  }

  async #fanOutMerge(fn, body, user, hosts, runLocal) {
    // Cursors become "<this site's>~<base64 JSON of each other site's>", so apps keep one cursor each.
    const remoteCursors = {};
    const localBody = { ...body };
    for (const field of Object.keys(CURSOR_FIELDS)) {
      if (typeof body[field] !== "string") continue;
      const [mine, rest] = body[field].split("~");
      localBody[field] = mine;
      if (rest) {
        try {
          for (const [h, c] of Object.entries(JSON.parse(unb64(rest)))) (remoteCursors[h] ||= {})[field] = c;
        } catch {
          // a damaged cursor just starts that site afresh
        }
      }
    }
    const local = await runLocal(JSON.stringify(localBody));
    if (local.status !== 200) return local;
    const results = [{ host: this.host, data: local.data }];
    await Promise.all(hosts.map(async (h) => {
      const b = { ...localBody };
      for (const field of Object.keys(CURSOR_FIELDS)) {
        if (remoteCursors[h]?.[field] !== undefined) b[field] = remoteCursors[h][field];
        else delete b[field];
      }
      try {
        const r = await this.act(h, user, fn, b);
        if (r.status === 200) results.push({ host: h, data: r.data });
        else if (r.status === 401 || r.status === 403 || r.status === 404) this.q.dropHost.run(user.id, h);
        else results.push({ host: h, data: null, keep: remoteCursors[h] });
      } catch {
        results.push({ host: h, data: null, keep: remoteCursors[h] });
      }
    }));
    return { status: 200, data: mergeResults(results) };
  }

  async #fanOutPeople(fn, body, user, hosts, runLocal) {
    const ids = Array.isArray(body.user_ids) ? body.user_ids.filter((x) => typeof x === "string") : [];
    const remote = ids.filter((id) => this.q.shadow.get(id) || !this.store.has(id));
    if (!remote.length) return null;
    const local = await runLocal(JSON.stringify(body));
    const out = local.status === 200 ? local.data : fn === "keys" ? { keys: {} } : { profiles: [] };
    await Promise.all(hosts.map(async (h) => {
      try {
        const r = await this.act(h, user, fn, { ...body, user_ids: remote });
        if (r.status !== 200) return;
        if (r.data?.keys) for (const [k, v] of Object.entries(r.data.keys)) out.keys[k] ||= v;
        if (Array.isArray(r.data?.profiles)) for (const p of r.data.profiles) if (!out.profiles.some((x) => x.user_id === p.user_id)) out.profiles.push(p);
      } catch {
        // that site is unreachable; its people stay unknown for now
      }
    }));
    return { status: 200, data: out };
  }

  // ---------- host side: other sites' people acting here ----------

  async #inboundAct(from, payload, signedUser) {
    const card = payload?.user;
    if (!card || card.id !== signedUser) throw new FederationError(400, "BAD_PERSON", "The request's person doesn't match its signature.");
    const fn = String(payload.function || "");
    const { functionTable } = await import("../functions.mjs");
    const table = this.functions ||= functionTable({ defaultAdmins: this.config.defaultServerAdmins });
    if (!Object.hasOwn(table, fn) || fn === "admin") throw new FederationError(404, "NOT_FOUND", "Unknown function.");
    await this.#mirror(from, card);
    const user = await this.sr.entities.User.get(card.id);
    const [actions, options = {}] = table[fn];
    const { runAction } = await import("../functions.mjs");
    const raw = String(payload.request || "{}");
    let parsed = {};
    try {
      parsed = JSON.parse(raw);
    } catch {
      parsed = {};
    }
    // A Mastodon-style limit prevents unsolicited new interactions from a
    // remote site but preserves already established encrypted conversations.
    if (siteVerdict(this.store,from)==="limit" &&
        ((fn==="conversations" && ["create_dm","create_group","add_members"].includes(parsed.action)) ||
         (fn==="servers" && ["join_server"].includes(parsed.action)))) {
      throw new FederationError(403,"SITE_LIMITED","New interactions from this remote site are limited by local moderation.");
    }
    // Things that only make sense on a person's own site.
    if (["keys", "profile", "safety"].includes(fn) && !["peer_keys", "get_many", "find"].includes(parsed.action)) {
      throw new FederationError(403, "HOME_ONLY", "That's done on the person's own site.");
    }
    const res = await runAction(this.clientFor(user), raw, actions, { ...options, federation: this.handlers, trustPlatformUser: true });
    let data = null;
    try {
      data = JSON.parse(await res.text());
    } catch {
      data = null;
    }
    // A host keeps a person's membership notices current even if the membership came from elsewhere.
    return { status: res.status, data };
  }

  get handlers() {
    return { host: this.host, resolveHandle: (h, me) => this.resolveHandle(h, me), siteDocument: (h) => this.signer.peekSiteDoc(h) };
  }

  async #inboundDirectory(from, payload) {
    if (sitePolicy(this.store).allow_remote_discovery===false || siteVerdict(this.store,from)==="limit") {
      throw new FederationError(403,"SITE_LIMITED","This site's policy restricts remote discovery.");
    }
    const handle = String(payload?.handle || "").toLowerCase();
    const username = this.#localUsername(handle);
    const profile = username ? await this.#localProfile(username) : null;
    if (!profile || profile.user_id !== payload.user_id) throw new FederationError(404, "NOT_FOUND", "Nobody here by that name.");
    const requester = payload.requester;
    if (payload.purpose === "conversation") {
      const policy = profile.dm_policy || "anyone";
      // "Only people I share a server with" can't be checked for people on other sites, so it means no.
      if (policy !== "anyone") throw new FederationError(403, "NOT_ACCEPTING", `${handle} isn't accepting new conversations from other sites.`);
      if (requester?.id) {
        const blocked = await this.sr.entities.Block.filter({ $or: [{ user_id: profile.user_id, blocked_user_id: requester.id }, { user_id: requester.id, blocked_user_id: profile.user_id }] }, "created_date", 1).catch(() => []);
        if (blocked.length) throw new FederationError(404, "NOT_FOUND", "Nobody here by that name.");
      }
    }
    const card = await this.#card(profile.user_id);
    // The person now has someone to talk to on that site.
    this.q.putHost.run(profile.user_id, from, Date.now());
    return { user: card };
  }

  async #inboundInbox(from, payload) {
    if (payload?.type === "membership") {
      const uid = String(payload.user_id || "");
      if (!ID24.test(uid) || !["User", "Person"].includes(this.store.tableOf(uid)) || this.q.shadow.get(uid)) return { ok: false };
      // Only a claim for that person, and a weak one: any site can send this notice.
      const id = String(payload.room?.id || "");
      if (ID24.test(id)) this.#claim(uid, id, from, CLAIM.implicit);
      if (payload.joined) this.q.putHost.run(uid, from, Date.now());
      return { ok: true };
    }
    if (payload?.type === "keys") {
      const s = this.q.shadow.get(payload.user?.id);
      if (s && s.home === from) await this.#mirror(from, payload.user);
      return { ok: true };
    }
    if (payload?.type === "block") {
      const s = this.q.shadow.get(payload.user_id);
      if (s?.home !== from || !ID24.test(payload.blocked_id || "")) return { ok: false };
      const exists = await this.sr.entities.Block.filter({ user_id: payload.user_id, blocked_user_id: payload.blocked_id }, "created_date", 1);
      if (payload.blocked && !exists.length) await this.sr.entities.Block.create({ user_id: payload.user_id, blocked_user_id: payload.blocked_id });
      if (!payload.blocked) for (const b of exists) await this.sr.entities.Block.delete(b.id);
      return { ok: true };
    }
    throw new FederationError(400, "UNKNOWN_TYPE", "Unknown notice.");
  }

  /** After a local block or unblock: tell the other person's site, and sites hosting our rooms. */
  async blockChanged(userId, blockedId, blocked) {
    const sites = new Set(this.q.hostsOf.all(userId).map((r) => r.host));
    const s = this.q.shadow.get(blockedId);
    if (s) sites.add(s.home);
    for (const host of sites) this.signer.send(host, "inbox", { type: "block", user_id: userId, blocked_id: blockedId, blocked }).catch(() => {});
  }

  // ---------- HTTP ----------

  siteDocument() {
    return {
      protocol: PROTOCOL,
      host: this.host,
      name: this.config.siteName,
      software: { name: "commonveil", version: this.config.version },
      handle_domain: this.config.handleDomain,
      key: { alg: "Ed25519", public: this.signer.key.public },
      // The site document itself and file links stay where they are; the rest can move under a prefix.
      endpoints: Object.fromEntries(Object.entries(DEFAULT_ENDPOINTS).map(([k, v]) => [k, k === "files" ? v : `${this.config.federationPrefix || ""}${v}`])),
    };
  }

  #requestHost(req) {
    const raw = (this.config.trustProxy && req.headers["x-forwarded-host"]) || req.headers.host || "";
    return String(raw).split(",")[0].trim().toLowerCase();
  }

  /** Handle anything the protocol owns. Answers true if it did. */
  async route(req, res, url) {
    const prefix = this.config.federationPrefix || "";
    const moved = prefix && url.pathname.startsWith(`${prefix}/`) ? url.pathname.slice(prefix.length) : "";
    const p = moved.startsWith("/cvp/v1/") || moved === DEFAULT_ENDPOINTS.identity ? moved : url.pathname;
    const reqHost = this.#requestHost(req);

    // TLS for handles: Caddy asks before getting a certificate for a name.
    if (p === "/api/tls-check") {
      const d = String(url.searchParams.get("domain") || "").toLowerCase();
      if (d === this.config.host) return json(res, 200, { ok: true }), true;
      const u = this.enabled ? this.#localUsername(d) : null;
      return json(res, u && (await this.#localProfile(u)) ? 200 : 404, {}), true;
    }

    // A handle's own address (alice.example.com): who she is, or her profile in a browser.
    const hostOnly = reqHost.replace(/:\d+$/, "");
    if (this.enabled && hostOnly !== this.config.host && hostOnly.endsWith(`.${this.config.handleDomain}`)) {
      const username = this.#localUsername(hostOnly);
      const profile = username ? await this.#localProfile(username) : null;
      if (p === "/.well-known/commonveil/identity") {
        return (profile ? json(res, 200, await this.#identity(profile), { "Access-Control-Allow-Origin": "*" }) : json(res, 404, { error: "Nobody here by that name." })), true;
      }
      res.writeHead(302, { Location: profile ? `${this.config.siteUrl}/u/${profile.username}` : this.config.siteUrl });
      res.end();
      return true;
    }

    if (p === "/.well-known/commonveil") {
      if (!this.enabled) return json(res, 404, { error: "This site doesn't talk to other sites." }), true;
      return json(res, 200, { ...this.siteDocument(), pq: await this.signer.relayDoc() }, { "Access-Control-Allow-Origin": "*", "Cache-Control": "public, max-age=300" }), true;
    }
    if (p === "/.well-known/commonveil/identity") {
      const handle = String(url.searchParams.get("handle") || "").toLowerCase();
      const username = this.enabled ? this.#localUsername(handle) : null;
      const profile = username ? await this.#localProfile(username) : null;
      return (profile ? json(res, 200, await this.#identity(profile), { "Access-Control-Allow-Origin": "*" }) : json(res, 404, { error: "Nobody here by that name." })), true;
    }
    // WebFinger, so fediverse tools can at least find a Commonveil address and its profile page.
    if (p === "/.well-known/webfinger") {
      const m = /^acct:([a-z0-9_-]{3,20})@(.+)$/i.exec(String(url.searchParams.get("resource") || ""));
      const profile = m && this.enabled && m[2].toLowerCase() === this.config.host ? await this.#localProfile(m[1]) : null;
      if (!profile) return json(res, 404, {}), true;
      return json(res, 200, {
        subject: `acct:${profile.username}@${this.config.host}`,
        aliases: [`${this.config.siteUrl}/u/${profile.username}`, `https://${this.handleFor(profile.username)}`],
        links: [{ rel: "http://webfinger.net/rel/profile-page", type: "text/html", href: `${this.config.siteUrl}/u/${profile.username}` }],
      }, { "Content-Type": "application/jrd+json", "Access-Control-Allow-Origin": "*" }), true;
    }
    if (p === "/.well-known/nodeinfo") {
      return json(res, 200, { links: [{ rel: "http://nodeinfo.diaspora.software/ns/schema/2.1", href: `${this.config.siteUrl}/nodeinfo/2.1` }] }), true;
    }
    if (p === "/nodeinfo/2.1") {
      // Deliberately no user counts: how many people use a site is nobody else's business.
      return json(res, 200, { version: "2.1", software: { name: "commonveil", version: this.config.version, repository: "https://github.com/Comutability/commonveil-rebuild" }, protocols: [], services: { inbound: [], outbound: [] }, openRegistrations: this.config.openRegistration && sitePolicy(this.store).registration_open, usage: { users: {} }, metadata: { nodeName: this.config.siteName, federation: this.enabled ? PROTOCOL : "off" } }), true;
    }

    // Where someone lives, from their handle or their site's address (for "join from your own site").
    if (p === "/api/fed/resolve" && this.enabled) {
      const q = String(url.searchParams.get("q") || "").trim().toLowerCase().replace(/^@/, "").replace(/^https?:\/\//, "").replace(/\/.*$/, "");
      let home = null;
      if (HANDLE_RE.test(q)) home = (await this.#lookupHandle(q).catch(() => null))?.home || null;
      if (!home) home = await this.signer.siteDoc(q).then((d) => d.host).catch(() => null);
      return json(res, home ? 200 : 404, home ? { home, home_url: this.transport.url(home, "") } : { error: "Not found" }), true;
    }

    // Public profile pages are part of the app (/u/name); this answers what they may show.
    if (p.startsWith("/api/fed/profile/")) {
      const username = decodeURIComponent(p.slice("/api/fed/profile/".length));
      const profile = /^[A-Za-z0-9_]{3,20}$/.test(username) ? await this.#localProfile(username) : null;
      if (!profile) return json(res, 404, { error: "Nobody here by that name." }), true;
      const visible = (profile.profile_visibility || "shared") === "shared";
      return json(res, 200, {
        username: profile.username,
        handle: this.enabled ? this.handleFor(profile.username) : null,
        display_name: visible ? profile.display_name || "" : "",
        avatar_image: visible ? profile.avatar_image || "" : "",
        avatar_emoji: visible ? profile.avatar_emoji || "" : "",
        accent_color: profile.accent_color || "",
        accepts_new: (profile.dm_policy || "anyone") === "anyone",
      }), true;
    }

    // Files from other sites, fetched by this site so apps only ever talk to their own.
    if (p.startsWith("/api/fed/files/")) {
      // The link itself is the permission (the host signed it, and it expires in minutes), as on the
      // host. This site only fetches from sites its people have things on.
      const [, , , , hostEnc, name] = p.split("/");
      const host = (() => { try { return normHost(decodeURIComponent(hostEnc || "")); } catch { return null; } })();
      if (host && ["suspend","reject_media"].includes(siteVerdict(this.store,host))) {
        return json(res,403,{error:"Media from that site is restricted by this site's policy.",code:"SITE_MEDIA_BLOCKED"}),true;
      }
      if (!host || !/^[a-f0-9]{48}$/.test(name || "") || !this.store.db.prepare("SELECT 1 FROM fed_user_hosts WHERE host = ? LIMIT 1").get(host)) return json(res, 404, { error: "Not found" }), true;
      const bytes = await this.signer.endpoint(host, "files").then((base) => this.transport.bytes(host, `${base}/${name}?${url.searchParams.toString()}`)).catch(() => null);
      if (!bytes) return json(res, 404, { error: "That link has expired." }), true;
      res.writeHead(200, { "Content-Type": "application/octet-stream", "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff", "Content-Length": bytes.length });
      res.end(bytes);
      return true;
    }

    if (p === "/api/site/rules" && req.method==="GET") {
      return json(res,200,publicSiteRules(this.store),{"Cache-Control":"public, max-age=120"}),true;
    }
    if (p === "/api/admin/federation") {
      const user = await this.auth.userFor(bearer(req));
      if (!user || user.role !== "admin") return json(res, 403, { error: "Admins only." }), true;
      if (req.method === "GET") return json(res, 200, { enabled: this.enabled, host: this.host, handle_domain: this.config.handleDomain, key: this.signer.key.public, sites: this.signer.sites() }), true;
      try {
        const b = JSON.parse((await readBody(req, 4096)) || "{}");
        if (b.action === "block" || b.action === "unblock") this.signer.setBlocked(b.host, b.action === "block");
        else if (b.action === "accept_new_key") this.signer.forget(b.host);
        else return json(res, 400, { error: "Unknown action." }), true;
        return json(res, 200, { ok: true, sites: this.signer.sites() }), true;
      } catch (err) {
        return json(res, err.status || 400, { error: err.message }), true;
      }
    }

    if (p.startsWith("/cvp/v1/")) {
      if (!this.enabled) return json(res, 404, { error: "This site doesn't talk to other sites.", code: "FEDERATION_OFF" }), true;
      if (req.method === "GET" && p === "/cvp/v1/discover") {
        if (!sitePolicy(this.store).allow_remote_discovery) return json(res,403,{error:"Remote directory listings are disabled by this site's policy.",code:"DISCOVERY_DISABLED"}),true;
        return this.#discover(res, url), true;
      }
      if (req.method !== "POST") return json(res, 405, { error: "Use POST." }), true;
      try {
        const body = await readBody(req, MAX_ACT_BODY);
        const checked = await this.signer.verify(req, body, url.pathname + url.search);
        const { from, user } = checked;
        const payload = JSON.parse(checked.body || "{}");
        // A sealed request gets a sealed answer.
        const answer = async (status, data) => json(res, status, checked.reply ? await checked.reply(data) : data);
        if (p === "/cvp/v1/act") {
          const r = await this.#inboundAct(from, payload, user);
          return await answer(r.status, r.data ?? {}), true;
        }
        if (p === "/cvp/v1/directory") return await answer(200, await this.#inboundDirectory(from, payload)), true;
        if (p === "/cvp/v1/inbox") return await answer(200, await this.#inboundInbox(from, payload)), true;
        return json(res, 404, { error: "Not found" }), true;
      } catch (err) {
        if (!(err instanceof FederationError)) this.log.error?.("[federation]", err);
        return json(res, err.status || 500, { error: err instanceof FederationError ? err.message : "Something went wrong.", code: err.code || "INTERNAL" }), true;
      }
    }
    return false;
  }

  async #discover(res, url) {
    const tag = String(url.searchParams.get("tag") || "").slice(0, 40);
    const rows = await this.sr.entities.Server.filter(tag ? { discoverable: true, public_tags: tag } : { discoverable: true }, "-member_count", 100).catch(() => []);
    const servers = rows
      .filter((s) => s.status !== "deleting" && s.public_name)
      .map((s) => ({ id: s.id, site: this.host, name: s.public_name, description: s.public_description || "", tags: s.public_tags || [], icon: s.public_icon || "", color: s.public_color || "", join_mode: s.join_mode }));
    json(res, 200, { site: this.host, servers }, { "Access-Control-Allow-Origin": "*", "Cache-Control": "public, max-age=120" });
  }

  // ---------- realtime rooms across sites ----------

  /** Which site hosts a realtime room, for this person, from the ids in its name. A disputed id carries the connection nowhere. */
  roomHost(roomId, userId) {
    if (!this.enabled) return null;
    for (const part of String(roomId).split(".")) {
      if (!ID24.test(part)) continue;
      if (this.store.has(part)) return null;
      const r = this.routeOf(userId, part);
      if (r.route) return r.route;
      if (r.disputed.length) return null;
    }
    return null;
  }

  /** A person here connects to a room on another site: this site carries their connection there. */
  async proxyActor(clientWs, { host, name, room, connId, user }) {
    let template;
    try {
      template = await this.signer.endpoint(host, "actors");
    } catch {
      clientWs.close(1011, "Can't reach that site");
      return;
    }
    const path = `${template.replace("{name}", encodeURIComponent(name)).replace("{room}", encodeURIComponent(room))}?id=${encodeURIComponent(connId)}`;
    const card = await this.#card(user.id);
    const headers = { ...(await this.signer.headers({ method: "GET", to: host, path, body: "", user: user.id })), "CV-Person": b64(JSON.stringify(card)) };
    let upstream;
    try {
      upstream = await this.transport.websocket(host, path, headers);
    } catch {
      clientWs.close(1011, "Can't reach that site");
      return;
    }
    const queue = [];
    upstream.on("open", () => { for (const m of queue.splice(0)) upstream.send(m); });
    clientWs.on("message", (d) => (upstream.readyState === upstream.OPEN ? upstream.send(String(d)) : queue.length < 100 && queue.push(String(d))));
    upstream.on("message", (d) => clientWs.readyState === clientWs.OPEN && clientWs.send(String(d)));
    upstream.on("close", (code, reason) => clientWs.close(code === 1005 ? 1000 : code, String(reason || "")));
    upstream.on("error", () => clientWs.close(1011, "That site went away"));
    clientWs.on("close", () => upstream.close());
  }

  /** Another site carries one of its people into a room here. */
  async acceptActor(req, socket, head, actorHost) {
    const url = new URL(req.url, "http://local");
    const [name, roomEnc] = url.pathname.slice(url.pathname.indexOf("/cvp/v1/actors/") + "/cvp/v1/actors/".length).split("/");
    try {
      if (!this.enabled || !ACTOR_NAMES.has(name)) throw new FederationError(404, "NOT_FOUND", "Not found");
      const { from, user } = await this.signer.verify(req, "", url.pathname + url.search);
      const card = JSON.parse(unb64(req.headers["cv-person"] || ""));
      if (card?.id !== user) throw new FederationError(400, "BAD_PERSON", "Person mismatch");
      await this.#mirror(from, card);
      const room = decodeURIComponent(roomEnc || "");
      const connId = url.searchParams.get("id") || "";
      this.wss.handleUpgrade(req, socket, head, (ws) => actorHost.attach(ws, name, room, connId, { id: user }));
    } catch (err) {
      socket.write(`HTTP/1.1 ${err.status || 403} Forbidden\r\n\r\n`);
      socket.destroy();
    }
  }
}

export { mergeResults };
