// Who's here right now, and who's typing: for people who chose to share it. One room per server
// ("s.<serverId>") or conversation ("c.<conversationId>"); only its members get in.
//
// Nothing here is written down: not to the database, not to this room's storage. It lives in
// memory while people are connected and is gone when they leave. Apps only connect when their
// person has turned sharing on, and they only see others while they share their own.
import { Actor } from "base44:runtime/actors";
import { verifyAccess } from "../../shared/identity/sessions.ts";

const MAX_PEOPLE = 400;
const ROOM_RE = /^(s|c)\.([A-Za-z0-9_-]{8,64})$/;
const ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
const STATUSES = new Set(["online", "idle"]);
const RECHECK_MS = 5 * 60_000; // membership is checked again this often
const TYPING_EVERY_MS = 2500;
const MAX_MESSAGES_PER_10S = 30;

export default class Presence extends Actor {
  // conn.id -> { userId, status, checkedAt, typedAt }
  people = new Map();
  counts = new Map();

  async handleStart() {
    // A wake from hibernation keeps sockets but not this memory. Apps say hello again every
    // 20 seconds, so they're re-admitted (and re-checked) as they do.
    this.people = new Map();
  }

  room() {
    const m = ROOM_RE.exec(this.instanceId || "");
    return m ? { kind: m[1], id: m[2] } : null;
  }

  async isMember(userId) {
    const room = this.room();
    if (!room) return false;
    const sr = this.client.asServiceRole;
    try {
      if (room.kind === "s") {
        const rows = await sr.entities.ServerMember.filter({ server_id: room.id, user_id: userId }, "created_date", 1);
        return rows.length > 0;
      }
      const conv = await sr.entities.Conversation.get(room.id);
      return Boolean(conv && (conv.member_ids || []).includes(userId));
    } catch {
      return false;
    }
  }

  async admit(conn) {
    if (!conn.identity || conn.identity.type !== "authenticated") return null;
    const known = this.people.get(conn.id);
    if (known && known.userId === conn.identity.userId && Date.now() - known.checkedAt < RECHECK_MS) return known;
    if (!(await this.isMember(conn.identity.userId))) {
      this.people.delete(conn.id);
      conn.reject(4003, "Not a member.");
      return null;
    }
    const entry = known && known.userId === conn.identity.userId ? { ...known, checkedAt: Date.now() } : { userId: conn.identity.userId, status: "online", checkedAt: Date.now(), typedAt: 0 };
    if (!known && this.people.size >= MAX_PEOPLE) {
      conn.reject(4001, "Too many people here to show presence.");
      return null;
    }
    this.people.set(conn.id, entry);
    return entry;
  }

  // ---------- Commonveil sign-in (docs/IDENTITY.md) ----------
  // A connection without a platform identity signs in with a message carrying its access token:
  // { type: "__auth", token }. The room asks for it ("sign-in-needed") whenever one connects.

  withIdentity(conn) {
    if (conn.identity && conn.identity.type === "authenticated") return conn;
    const userId = this.signedIn?.get(conn.id);
    if (!userId) return conn;
    return new Proxy(conn, {
      get: (t, k) => (k === "identity" ? { type: "authenticated", userId } : typeof t[k] === "function" ? t[k].bind(t) : t[k]),
    });
  }

  async signIn(conn, msg) {
    if (conn.identity && conn.identity.type === "authenticated") return true;
    const s = await verifyAccess(this.client.asServiceRole, msg.token).catch(() => null);
    if (!s) {
      conn.reject(4003, "Please sign in again.");
      return false;
    }
    this.signedIn ||= new Map();
    this.signedIn.set(conn.id, s.userId);
    return true;
  }

  async handleConnect(conn) {
    conn = this.withIdentity(conn);
    if (!conn.identity || conn.identity.type !== "authenticated") {
      conn.send({ type: "sign-in-needed" });
      return;
    }
    const me = await this.admit(conn);
    if (!me) return;
    conn.send({ type: "here", people: this.list() });
    this.broadcastPeople();
  }

  async handleMessage(conn, msg) {
    if (!msg || typeof msg !== "object" || typeof msg.type !== "string") return;
    if (this.flooding(conn.id)) return;
    if (msg.type === "__auth") {
      if (await this.signIn(conn, msg)) await this.handleConnect(conn);
      return;
    }
    conn = this.withIdentity(conn);
    const fresh = !this.people.has(conn.id);
    const me = await this.admit(conn);
    if (!me) return;
    if (msg.type === "hello") {
      const status = STATUSES.has(msg.status) ? msg.status : "online";
      const changed = fresh || status !== me.status;
      me.status = status;
      if (fresh) conn.send({ type: "here", people: this.list() });
      if (changed) this.broadcastPeople();
    } else if (msg.type === "typing") {
      // Where: a channel id in a server, nothing in a conversation. Throttled, and passed on
      // to the others straight away. Apps don't send it for private channels.
      const channelId = this.room()?.kind === "s" ? (typeof msg.channel_id === "string" && ID_RE.test(msg.channel_id) ? msg.channel_id : null) : "";
      if (channelId === null || Date.now() - me.typedAt < TYPING_EVERY_MS) return;
      me.typedAt = Date.now();
      const thread = typeof msg.thread_id === "string" && ID_RE.test(msg.thread_id) ? msg.thread_id : "";
      for (const c of this.getConnections()) if (c.id !== conn.id && this.people.has(c.id)) c.send({ type: "typing", user_id: me.userId, channel_id: channelId, thread_id: thread });
    }
  }

  async handleClose(conn) {
    this.counts.delete(conn.id);
    this.signedIn?.delete(conn.id);
    if (this.people.delete(conn.id)) this.broadcastPeople();
  }

  flooding(connId) {
    const now = Date.now();
    const entry = this.counts.get(connId) || { start: now, n: 0 };
    if (now - entry.start > 10_000) {
      entry.start = now;
      entry.n = 0;
    }
    entry.n += 1;
    this.counts.set(connId, entry);
    return entry.n > MAX_MESSAGES_PER_10S;
  }

  /** One entry per person (they may be here on several devices): online beats idle. */
  list() {
    const by = new Map();
    for (const p of this.people.values()) {
      if (!by.has(p.userId) || p.status === "online") by.set(p.userId, p.status);
    }
    return [...by].map(([user_id, status]) => ({ user_id, status }));
  }

  broadcastPeople() {
    const people = this.list();
    for (const c of this.getConnections()) if (this.people.has(c.id)) c.send({ type: "here", people });
  }
}
