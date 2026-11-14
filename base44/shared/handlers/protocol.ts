// The experimental protocol layer (docs/SECURE_NET_LAYER.md): Secure Net actors, prekeys and a mailbox
// for sealed envelopes (CVP-016, CVP-017, CVP-019).
//
// The server's part is deliberately small. It stores each account's signed actor document and
// its devices' prekeys, hands them out, and holds sealed envelopes until the device they are for
// collects them. It checks shapes, sizes, who may write what and how often. It does not check
// the post-quantum signatures and cannot open anything: people's devices verify every document
// and prekey themselves, against keys they have pinned. So nothing here needs post-quantum code
// on the server, and a server that lied could only stop this layer working, which leaves a
// conversation exactly as protected as it is without it.
import { ApiError, id, int, str, type Actions } from "../http.ts";
import { signedByActiveDevice } from "../deviceAuth.ts";
import { blockedEitherWay, contactsOf, profileOf, rateLimited } from "../store.ts";

export const PROTO_LIMITS = Object.freeze({
  documentChars: 96 * 1024,
  sealedChars: 16 * 1024,
  prekeyChars: 12 * 1024,
  oneTimePerKind: 20, // one-time prekeys kept per device, per kind
  envelopeChars: 80 * 1024,
  sendItems: 40,
  mailPerDevice: 500, // waiting envelopes; more are refused until the device collects
  sendsPerMinute: 60,
  bundlesPerMinute: 60,
  collect: 100,
  mailDays: 30,
});

const KID = /^[A-Za-z0-9_-]{22}$/;
const kid = (v: unknown, name: string) => {
  if (typeof v !== "string" || !KID.test(v)) throw new ApiError(400, "BAD_FIELD", `Invalid ${name}.`);
  return v;
};

function parse(text: unknown, name: string, max: number): any {
  const s = str(text, name, max, 2);
  try {
    const v = JSON.parse(s);
    if (v && typeof v === "object" && !Array.isArray(v)) return v;
  } catch { /* fall through */ }
  throw new ApiError(400, "BAD_FIELD", `Invalid ${name}.`);
}

/** A signed record of the given kind, by shape only (devices check the signatures). */
function recordOf(text: unknown, kind: string, name: string, max: number) {
  const r = parse(text, name, max);
  if (r.kind !== kind || !r.body || typeof r.body !== "object" || !r.sig || !KID.test(r.sig.kid || "") || typeof r.sig.value !== "string" || typeof r.sig.pq !== "string") {
    throw new ApiError(400, "BAD_FIELD", `Invalid ${name}.`);
  }
  return r;
}

const actorOf = async (sr: any, userId: string) => (await sr.entities.ProtoActor.filter({ user_id: userId }, "-seq", 1))[0] || null;
const devicesIn = (doc: any): string[] => (doc?.body?.devices?.body?.devices || []).map((d: any) => d?.kid).filter((k: unknown) => typeof k === "string");

async function removeAll(sr: any, entity: string, query: any) {
  for (;;) {
    const rows = await sr.entities[entity].filter(query, "created_date", 100);
    if (!rows.length) return;
    await Promise.all(rows.map((r: any) => sr.entities[entity].delete(r.id).catch(() => null)));
  }
}

/** Sends and bundle requests are counted in memory per server instance: a brake, not an exact limit. */
const recent = new Map<string, number[]>();
function brake(key: string, perMinute: number, now: Date, what: string) {
  const t = now.getTime();
  const list = (recent.get(key) || []).filter((x) => t - x < 60_000);
  if (list.length >= perMinute) throw rateLimited(what);
  list.push(t);
  recent.set(key, list);
  if (recent.size > 5000) for (const [k, v] of recent) if (!v.some((x) => t - x < 60_000)) recent.delete(k);
}

export const protocolActions: Actions = {
  /** This account's own protocol identity, for a device that is turning the layer on. */
  async mine({ sr, user }: any) {
    const row = await actorOf(sr, user.id);
    return { actor: row ? { document: row.document, sealed_account: row.sealed_account, sealed_version: row.sealed_version, seq: row.seq } : null };
  },

  /** Publish (or update) the actor document. Signed by one of the account's devices. */
  async proto_publish(ctx: any) {
    const { sr, user } = ctx;
    const { data } = await signedByActiveDevice(ctx, "proto_publish");
    const doc = recordOf(data.document, "actor.document", "actor document", PROTO_LIMITS.documentChars);
    const b = doc.body;
    const profile = await profileOf(sr, user.id);
    if (!profile?.username) throw new ApiError(409, "NO_PROFILE", "Choose a username first.");
    const name = String(b.handle || "").split("@")[0];
    if (name !== String(profile.username).toLowerCase() || String(b.handle).split("@").length !== 2) throw new ApiError(400, "BAD_HANDLE", "The handle must be your username at this site.");
    if (!KID.test(b.id || "") || doc.sig.kid !== b.id || typeof b.account !== "string" || !b.account.includes(".")) throw new ApiError(400, "BAD_FIELD", "Invalid actor document.");
    const seq = int(b.seq, "seq", 1, 1_000_000_000);
    if (!devicesIn(doc).length || devicesIn(doc).length > 10) throw new ApiError(400, "BAD_FIELD", "Invalid device list.");
    const sealed = str(data.sealed_account, "sealed account key", PROTO_LIMITS.sealedChars, 16);
    const sealedVersion = int(data.sealed_version, "key version", 1, 100_000);
    const prev = await actorOf(sr, user.id);
    if (prev && prev.actor_id !== b.id) throw new ApiError(409, "ACTOR_EXISTS", "This account already has a protocol identity. Turn it off first to start again.");
    if (prev && seq <= prev.seq) throw new ApiError(409, "STALE", "A newer version is already published.");
    const row = { user_id: user.id, actor_id: b.id, handle: b.handle, seq, document: JSON.stringify(doc), sealed_account: sealed, sealed_version: sealedVersion };
    if (prev) await sr.entities.ProtoActor.update(prev.id, row);
    else await sr.entities.ProtoActor.create(row);
    // Prekeys and mail of devices no longer on the list go with them.
    const keep = new Set(devicesIn(doc));
    const stale = (await sr.entities.ProtoPrekey.filter({ user_id: user.id, slot: "signed" }, "created_date", 50)).map((r: any) => r.device).filter((d: string) => !keep.has(d));
    for (const d of new Set<string>(stale)) {
      await removeAll(sr, "ProtoPrekey", { user_id: user.id, device: d });
      await removeAll(sr, "ProtoMail", { to_user_id: user.id, to_device: d });
    }
    return { ok: true, seq };
  },

  /** Publish one device's prekeys. Replaces its signed and last-resort prekeys; tops up one-time ones. */
  async proto_prekeys(ctx: any) {
    const { sr, user } = ctx;
    const { data } = await signedByActiveDevice(ctx, "proto_prekeys");
    const device = kid(data.device, "device");
    const actor = await actorOf(sr, user.id);
    if (!actor || !devicesIn(JSON.parse(actor.document)).includes(device)) throw new ApiError(409, "NOT_LISTED", "Publish the actor document with this device first.");
    const one = (text: unknown, slot: string) => {
      const r = recordOf(text, "session.prekey", "prekey", PROTO_LIMITS.prekeyChars);
      if (r.body.device !== device || r.sig.kid !== device || typeof r.body.id !== "string" || r.body.id.length > 40) throw new ApiError(400, "BAD_FIELD", "Invalid prekey.");
      return { user_id: user.id, device, slot, prekey_id: r.body.id, record: JSON.stringify(r) };
    };
    const list = (v: unknown) => (Array.isArray(v) ? v.slice(0, PROTO_LIMITS.oneTimePerKind) : []);
    const rows: any[] = [];
    if (data.signed !== undefined || data.lastResort !== undefined) {
      rows.push(one(data.signed, "signed"), one(data.lastResort, "last"));
      await removeAll(sr, "ProtoPrekey", { user_id: user.id, device, slot: "signed" });
      await removeAll(sr, "ProtoPrekey", { user_id: user.id, device, slot: "last" });
    }
    for (const [slot, items] of [["otk", list(data.oneTime)], ["pq", list(data.pqOneTime)]] as const) {
      const have = (await sr.entities.ProtoPrekey.filter({ user_id: user.id, device, slot }, "created_date", PROTO_LIMITS.oneTimePerKind + 1)).length;
      for (const text of items.slice(0, Math.max(0, PROTO_LIMITS.oneTimePerKind - have))) rows.push(one(text, slot));
    }
    for (const r of rows) await sr.entities.ProtoPrekey.create(r);
    return { ok: true, stored: rows.length };
  },

  /** The actor documents of people you share a conversation with (and your own). */
  async actors({ sr, user, body }: any) {
    const ids: string[] = Array.isArray(body.user_ids) ? [...new Set<string>(body.user_ids.slice(0, 40).map((v: unknown) => id(v, "user")))] : [];
    const contacts = await contactsOf(sr, user.id);
    const out = [];
    for (const uid of ids.filter((u) => contacts.has(u))) {
      const row = await actorOf(sr, uid);
      if (row) out.push({ user_id: uid, document: row.document });
    }
    return { actors: out };
  },

  /** One prekey bundle for one device of a contact (or of your own account). Uses up one-time prekeys. */
  async bundle({ sr, user, body, now }: any) {
    const uid = id(body.user_id, "user");
    const device = kid(body.device, "device");
    brake(`b:${user.id}`, PROTO_LIMITS.bundlesPerMinute, now, "starting sessions");
    if (!(await contactsOf(sr, user.id)).has(uid)) throw new ApiError(404, "NOT_FOUND", "No such device.");
    const actor = await actorOf(sr, uid);
    const doc = actor && JSON.parse(actor.document);
    if (!doc || !devicesIn(doc).includes(device)) throw new ApiError(404, "NOT_FOUND", "No such device.");
    const first = async (slot: string) => (await sr.entities.ProtoPrekey.filter({ user_id: uid, device, slot }, "created_date", 1))[0] || null;
    /** A one-time prekey is handed out only by whoever manages to delete it. */
    const take = async (slot: string) => {
      for (let i = 0; i < 3; i += 1) {
        const row = await first(slot);
        if (!row) return null;
        try {
          await sr.entities[`ProtoPrekey`].delete(row.id);
          return row;
        } catch { /* someone else took it: try the next */ }
      }
      return null;
    };
    const signed = await first("signed");
    const last = await first("last");
    if (!signed || !last) throw new ApiError(404, "NO_PREKEYS", "That device has no prekeys published.");
    const pq = (await take("pq")) || last;
    const otk = await take("otk");
    return { bundle: { deviceList: doc.body.devices, device, signed: JSON.parse(signed.record), pq: JSON.parse(pq.record), oneTime: otk ? JSON.parse(otk.record) : null } };
  },

  /** Put sealed envelopes in the mailboxes of contacts' devices (or your own other devices). */
  async send({ sr, user, body, now }: any) {
    const items: any[] = Array.isArray(body.items) ? body.items : [];
    if (!items.length || items.length > PROTO_LIMITS.sendItems) throw new ApiError(400, "BAD_FIELD", "Invalid items.");
    brake(`s:${user.id}`, PROTO_LIMITS.sendsPerMinute, now, "sending");
    const contacts = await contactsOf(sr, user.id);
    const allowed = new Map<string, Set<string> | null>();
    const rows = [];
    for (const it of items) {
      const to = id(it?.to, "recipient");
      const env = parse(it?.envelope, "envelope", PROTO_LIMITS.envelopeChars);
      // Only direct envelopes travel here, and nothing rides along on them (CVP-019, section 1).
      const extra = Object.keys(env).some((k) => !["v", "mode", "device", "session", "message"].includes(k));
      if (env.v !== 1 || env.mode !== "direct" || extra || !KID.test(env.device || "") || !KID.test(env.session || "") || env.message?.v !== 1 || typeof env.message?.c !== "string") {
        throw new ApiError(400, "BAD_ENVELOPE", "Only direct envelopes can be sent.");
      }
      if (!allowed.has(to)) {
        let devices: Set<string> | null = null;
        if (contacts.has(to) && (to === user.id || !(await blockedEitherWay(sr, user.id, to)))) {
          const actor = await actorOf(sr, to);
          devices = actor ? new Set(devicesIn(JSON.parse(actor.document))) : null;
        }
        allowed.set(to, devices);
      }
      // Someone who can't be reached is skipped without saying why, like a blocked message.
      if (!allowed.get(to)?.has(env.device)) continue;
      rows.push({ to_user_id: to, to_device: env.device, from_user_id: user.id, envelope: JSON.stringify(env), expires_at: new Date(now.getTime() + PROTO_LIMITS.mailDays * 86_400_000).toISOString() });
    }
    let stored = 0;
    for (const r of rows) {
      const waiting = await sr.entities.ProtoMail.filter({ to_user_id: r.to_user_id, to_device: r.to_device }, "-created_date", PROTO_LIMITS.mailPerDevice);
      if (waiting.length >= PROTO_LIMITS.mailPerDevice) continue;
      await sr.entities.ProtoMail.create(r);
      stored += 1;
    }
    return { ok: true, stored };
  },

  /** Collect what is waiting for one of your devices. Acknowledge with the ids to delete them. */
  async collect({ sr, user, body }: any) {
    const device = kid(body.device, "device");
    const ack: string[] = Array.isArray(body.ack) ? body.ack.slice(0, PROTO_LIMITS.collect).map((v: unknown) => id(v, "id")) : [];
    for (const mailId of ack) {
      const [row] = await sr.entities.ProtoMail.filter({ id: mailId, to_user_id: user.id, to_device: device }, "created_date", 1);
      if (row) await sr.entities.ProtoMail.delete(row.id).catch(() => null);
    }
    const rows = await sr.entities.ProtoMail.filter({ to_user_id: user.id, to_device: device }, "created_date", PROTO_LIMITS.collect);
    const count = async (slot: string) => (await sr.entities.ProtoPrekey.filter({ user_id: user.id, device, slot }, "created_date", PROTO_LIMITS.oneTimePerKind + 1)).length;
    return { mail: rows.map((r: any) => ({ id: r.id, from: r.from_user_id, envelope: r.envelope })), prekeys: { otk: await count("otk"), pq: await count("pq") } };
  },

  /** Turn the layer off for this account: its identity, prekeys and waiting mail are deleted. */
  async proto_disable(ctx: any) {
    const { sr, user } = ctx;
    await signedByActiveDevice(ctx, "proto_disable");
    await removeAll(sr, "ProtoActor", { user_id: user.id });
    await removeAll(sr, "ProtoPrekey", { user_id: user.id });
    await removeAll(sr, "ProtoMail", { to_user_id: user.id });
    return { ok: true };
  },
};
