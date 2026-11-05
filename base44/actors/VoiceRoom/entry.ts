// One voice channel's call. This room only passes connection set-up (WebRTC offers, answers
// and network candidates) between the devices in the call, plus who's muted. Audio never comes
// here: it goes directly between devices, encrypted twice, and each device checks that the
// others' connection keys were signed by a device certified for that member's account.
//
// Admission: a signed-in connection must present a single-use pass from the voice function,
// which checked membership and permissions a moment ago. Until then it gets nothing.
import { Actor } from "base44:runtime/actors";

const MAX_PEOPLE = 8;
// A dropped socket usually comes straight back (the SDK reconnects with the same id), and the
// audio between devices carries on meanwhile. Keep a place this long before telling the others.
const GRACE_MS = 20_000;
const MAX_SIGNAL_CHARS = 24000; // an offer with its candidates is a few KB
const MAX_MESSAGES_PER_10S = 200;
const ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
const B64_RE = /^[A-Za-z0-9+/=_-]{1,400}$/;
const FINGERPRINT_RE = /^[0-9A-F]{2}(:[0-9A-F]{2}){31}$/;

function cleanHello(h) {
  if (!h || typeof h !== "object") return null;
  const out = {
    call_id: typeof h.call_id === "string" && ID_RE.test(h.call_id) ? h.call_id : null,
    fingerprint: typeof h.fingerprint === "string" && FINGERPRINT_RE.test(h.fingerprint) ? h.fingerprint : null,
    issued_at: typeof h.issued_at === "string" && h.issued_at.length <= 40 ? h.issued_at : null,
    signature: typeof h.signature === "string" && B64_RE.test(h.signature) ? h.signature : null,
  };
  return out.call_id && out.fingerprint && out.issued_at && out.signature ? out : null;
}

export default class VoiceRoom extends Actor {
  // conn.id -> { seat, userId, deviceId, hello, muted, deafened, canSpeak }
  people = new Map();
  nextSeat = 1;
  counts = new Map();

  async handleStart() {
    // Any wake (including hibernation, which keeps sockets attached): reload who's in the call,
    // then drop anyone whose connection is gone.
    const saved = await this.storage.get("people");
    if (saved) this.people = new Map(saved);
    const live = new Set(this.getConnections().map((c) => c.id));
    let changed = false;
    for (const [id, p] of [...this.people]) {
      if (live.has(id)) continue;
      if (!p.goneAt) {
        // Its socket went while the room slept: start the grace period now.
        p.goneAt = Date.now();
        await this.schedule(`drop:${id}`, p.goneAt + GRACE_MS);
        changed = true;
      } else if (Date.now() - p.goneAt > GRACE_MS) {
        this.people.delete(id);
        changed = true;
      }
    }
    this.nextSeat = Math.max(0, ...[...this.people.values()].map((p) => p.seat)) + 1;
    if (changed) await this.save();
  }

  async handleConnect(conn) {
    if (!conn.identity || conn.identity.type !== "authenticated") {
      conn.reject(4003, "Sign in to join calls.");
      return;
    }
    const me = this.people.get(conn.id);
    if (me && me.userId === conn.identity.userId) {
      // A reconnect of someone already in: they're still in, in the same place.
      if (me.goneAt) {
        delete me.goneAt;
        await this.cancelSchedule(`drop:${conn.id}`);
        await this.save();
      }
      this.welcome(conn, me);
      return;
    }
    conn.send({ type: "pass-needed" });
  }

  async handleMessage(conn, msg) {
    if (!msg || typeof msg !== "object" || typeof msg.type !== "string") return;
    if (this.flooding(conn.id)) return;
    if (msg.type === "join") {
      await this.join(conn, msg);
      return;
    }
    const me = this.people.get(conn.id);
    if (!me) return;
    if (msg.type === "signal") {
      const target = this.connOfSeat(Number(msg.to));
      if (!target || target.id === conn.id) return;
      let size = 0;
      try {
        size = JSON.stringify(msg.data ?? null).length;
      } catch {
        return;
      }
      if (size > MAX_SIGNAL_CHARS) return;
      target.send({ type: "signal", from: me.seat, data: msg.data });
    } else if (msg.type === "state") {
      me.muted = Boolean(msg.muted) || !me.canSpeak;
      me.deafened = Boolean(msg.deafened);
      await this.save();
      this.sendToMembers({ type: "peer-state", seat: me.seat, muted: me.muted, deafened: me.deafened });
    } else if (msg.type === "leave") {
      await this.remove(conn.id);
    }
  }

  async handleClose(conn) {
    this.counts.delete(conn.id);
    const p = this.people.get(conn.id);
    if (!p || p.left) {
      await this.remove(conn.id);
      return;
    }
    p.goneAt = Date.now();
    await this.save();
    await this.schedule(`drop:${conn.id}`, p.goneAt + GRACE_MS);
  }

  async handleWake(key) {
    if (typeof key !== "string" || !key.startsWith("drop:")) return;
    const id = key.slice(5);
    const p = this.people.get(id);
    if (!p || !p.goneAt) return;
    if (this.getConnections().some((c) => c.id === id)) {
      delete p.goneAt;
      await this.save();
      return;
    }
    await this.remove(id);
  }

  handleTick() {}

  // ---------- helpers ----------

  async join(conn, msg) {
    const userId = conn.identity && conn.identity.type === "authenticated" ? conn.identity.userId : null;
    if (!userId) {
      conn.reject(4003, "Sign in to join calls.");
      return;
    }
    const existing = this.people.get(conn.id);
    if (existing) {
      this.welcome(conn, existing);
      return;
    }
    const ticketId = typeof msg.ticket === "string" && ID_RE.test(msg.ticket) ? msg.ticket : null;
    const hello = cleanHello(msg.hello);
    if (!ticketId || !hello) {
      conn.send({ type: "error", code: "BAD_JOIN", message: "That join request isn't valid." });
      return;
    }
    let ticket = null;
    try {
      ticket = await this.client.asServiceRole.entities.VoiceTicket.get(ticketId);
    } catch {
      ticket = null;
    }
    const valid = ticket && ticket.room === this.instanceId && ticket.user_id === userId && Date.parse(ticket.expires_at) > Date.now();
    if (ticket) {
      // Single use, valid or not.
      try {
        await this.client.asServiceRole.entities.VoiceTicket.delete(ticketId);
      } catch {
        // Already gone: someone else used it first.
        conn.send({ type: "error", code: "PASS_USED", message: "That pass was already used. Try joining again." });
        return;
      }
    }
    if (!valid) {
      conn.send({ type: "error", code: "PASS_INVALID", message: "Your pass for this call has expired. Try joining again." });
      return;
    }
    // The same device joining again (a reload, say) replaces its old place, connected or not.
    for (const [id, p] of [...this.people]) {
      if (id === conn.id || p.userId !== userId || p.deviceId !== ticket.device_id) continue;
      await this.remove(id);
      await this.cancelSchedule(`drop:${id}`);
      const old = this.getConnections().find((c) => c.id === id);
      if (old) old.reject(4005, "You joined this call from somewhere else.");
    }
    if (this.people.size >= MAX_PEOPLE) {
      conn.send({ type: "error", code: "CALL_FULL", message: `This call is full: up to ${MAX_PEOPLE} people can be in it.` });
      return;
    }
    const me = {
      seat: this.nextSeat++,
      userId,
      deviceId: ticket.device_id,
      hello,
      canSpeak: ticket.can_speak !== false,
      muted: Boolean(msg.muted) || ticket.can_speak === false,
      deafened: Boolean(msg.deafened),
    };
    this.people.set(conn.id, me);
    await this.save();
    this.welcome(conn, me);
    this.sendToMembers({ type: "peer-joined", peer: this.publicOf(me) }, conn.id);
  }

  welcome(conn, me) {
    const peers = [];
    for (const [id, p] of this.people) if (id !== conn.id) peers.push(this.publicOf(p));
    conn.send({ type: "welcome", seat: me.seat, can_speak: me.canSpeak, peers, max_people: MAX_PEOPLE });
  }

  async remove(connId) {
    const p = this.people.get(connId);
    if (!p) return;
    this.people.delete(connId);
    await this.save();
    this.sendToMembers({ type: "peer-left", seat: p.seat });
  }

  // An explicit public shape: never the connection id, which the client holds.
  publicOf(p) {
    return { seat: p.seat, user_id: p.userId, device_id: p.deviceId, hello: p.hello, muted: p.muted, deafened: p.deafened };
  }

  // Only people admitted to the call hear about it: a connection that hasn't shown a pass gets nothing.
  sendToMembers(data, exceptId = null) {
    for (const c of this.getConnections()) {
      if (c.id !== exceptId && this.people.has(c.id)) c.send(data);
    }
  }

  connOfSeat(seat) {
    for (const c of this.getConnections()) {
      const p = this.people.get(c.id);
      if (p && p.seat === seat) return c;
    }
    return null;
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

  save() {
    return this.storage.put("people", [...this.people.entries()]);
  }
}
