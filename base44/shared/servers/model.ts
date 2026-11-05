// Servers: shared data access, permission checks, members' access lists, and key bookkeeping.
//
// The service never holds a server key. It decides who's a member (as it does for groups) and
// enforces permissions, and it keeps track of which members still need which keys, so members'
// apps know whom to hand keys to. Members read server rows with their own access: row rules
// let them read rows whose audience_id is in their User record's cv_access list, which only
// the backend can change (checked against the live platform).
import { ApiError, LIMITS, isoTime, platformTime, randomIdField, str } from "../http.ts";
import { verifyServerItemSignature } from "../verify.ts";
import { P, basePermissions, channelIsPrivate, channelPermissions, has, isStaff, topPosition } from "../permissions.ts";
import { byAge, createdAt, requireActiveDevice } from "../store.ts";

export const SERVER_LIMITS = Object.freeze({
  serversPerUser: 100,
  serversCreatedPerDay: 10,
  joinsPerHour: 30,
  membersPerServer: 10_000,
  channelsPerServer: 200,
  rolesPerServer: 100,
  invitesPerServer: 500,
  grantsPerRequest: 60,
  pendingBatch: 25,
  messagesPerMinute: 30,
  pageSize: 50,
  maxItemEnvelopeChars: 16 * 1024,
  /** Emoji and sticker sets carry small images, so their items can be bigger. */
  maxImageSetEnvelopeChars: 180 * 1024,
  maxMessageEnvelopeChars: 24 * 1024,
  maxPreviewChars: 4096,
  auditRetentionChoices: [30, 90, 180],
  slowmodeChoices: [0, 5, 10, 30, 60, 300, 900, 3600],
  timeoutMaxDays: 28,
  ticketsOpenPerMember: 3,
  staffPerTicket: 31,
});

/** Disappearing messages in a channel: off, an hour, a day, a week, four weeks. */
export const CHANNEL_EXPIRY_CHOICES = Object.freeze([0, 3600, 86_400, 604_800, 2_419_200]);

export const CHANNEL_KINDS = new Set(["category", "text", "announcement", "rules", "forum", "voice", "tickets"]);
/** Channels people post messages in. */
export const MESSAGE_KINDS = new Set(["text", "announcement", "rules", "forum"]);

export const TAGS = Object.freeze([
  "privacy", "security", "open-source", "learning", "support", "community", "friends", "study", "gaming", "creative",
  "technology", "local", "activism", "health", "music", "books",
]);

const CHAIN_RE = /^([A-Za-z0-9_-]{1,64})\.(h|l|c\.[A-Za-z0-9_-]{1,64})$/;
export const historyChainId = (serverId: string) => `${serverId}.h`;
export const liveChainId = (serverId: string) => `${serverId}.l`;
export const channelChainId = (serverId: string, channelId: string) => `${serverId}.c.${channelId}`;

export function parseChainId(chainId: unknown) {
  const m = typeof chainId === "string" ? CHAIN_RE.exec(chainId) : null;
  if (!m) return null;
  if (m[2] === "h" || m[2] === "l") return { serverId: m[1], kind: m[2], channelId: "" };
  return { serverId: m[1], kind: "c", channelId: m[2].slice(2) };
}

export const STEP_MS = 3600_000;
export function stepAt(chainId: string, startedAt: string, atMs: number) {
  if (parseChainId(chainId)?.kind !== "l") return 0;
  return Math.max(0, Math.floor((atMs - Date.parse(startedAt)) / STEP_MS));
}

// ---------- outputs ----------

export const itemOut = (row: any, prefix: string) =>
  row?.[`${prefix}_envelope`]
    ? {
        envelope: row[`${prefix}_envelope`],
        item_id: row[`${prefix}_item_id`],
        sender_id: row[`${prefix}_sender_id`],
        device_id: row[`${prefix}_device_id`],
        sent_at: row[`${prefix}_sent_at`],
        signature: row[`${prefix}_signature`],
      }
    : null;

export const serverOut = (s: any) => ({
  id: s.id,
  owner_id: s.owner_id || "",
  is_default: Boolean(s.is_default),
  template: s.template || "",
  join_mode: s.join_mode || "invite",
  discoverable: Boolean(s.discoverable),
  public: s.discoverable || s.is_default ? { name: s.public_name || "", description: s.public_description || "", tags: s.public_tags || [], icon: s.public_icon || "", color: s.public_color || "" } : null,
  profile: itemOut(s, "profile"),
  rules: itemOut(s, "rules"),
  emoji: itemOut(s, "emoji"),
  stickers: itemOut(s, "stickers"),
  automod: itemOut(s, "automod"),
  settings: {
    rules_required: Boolean(s.rules_required),
    min_account_minutes: Number(s.min_account_minutes) || 0,
    min_member_minutes: Number(s.min_member_minutes) || 0,
    invites_paused: Boolean(s.invites_paused),
    joins_paused: Boolean(s.joins_paused),
    member_list: s.member_list || "opt_in",
    audit_retention_days: Number(s.audit_retention_days) || 90,
    default_history: s.default_history || "joined",
    allow_member_dms: s.allow_member_dms !== false,
    key_handout: s.key_handout === "staff" ? "staff" : "members",
  },
  member_count: Number(s.member_count) || 0,
  keys_pending_at: s.keys_pending_at || null,
  changed_at: s.changed_at || s.updated_date,
  created_date: s.created_date,
  updated_date: s.updated_date,
});

export const channelOut = (c: any) => ({
  id: c.id,
  server_id: c.server_id,
  kind: c.kind,
  parent_id: c.parent_id || "",
  position: Number(c.position) || 0,
  template_key: c.template_key || "",
  name: itemOut(c, "name"),
  history: c.history || "joined",
  private: Boolean(c.private),
  overwrites: Array.isArray(c.overwrites) ? c.overwrites.map((o: any) => ({ role_id: o.role_id, allow: Number(o.allow) || 0, deny: Number(o.deny) || 0 })) : [],
  slowmode_seconds: Number(c.slowmode_seconds) || 0,
  expire_seconds: Number(c.expire_seconds) || 0,
  sensitive: Boolean(c.sensitive),
  last_message_at: c.last_message_at || null,
});

export const roleOut = (r: any) => ({
  id: r.id,
  server_id: r.server_id,
  position: Number(r.position) || 0,
  permissions: Number(r.permissions) || 0,
  is_everyone: Boolean(r.is_everyone),
  template_key: r.template_key || "",
  hoist: Boolean(r.hoist),
  mentionable: Boolean(r.mentionable),
  name: itemOut(r, "name"),
});

/** A member as other members see them. joined_at only to the month: nobody needs the minute. */
export const memberOut = (m: any, { self = false } = {}) => ({
  user_id: m.user_id,
  server_id: m.server_id,
  role_ids: m.role_ids || [],
  joined_at: self ? m.joined_at : String(m.joined_at || "").slice(0, 7),
  listed: Boolean(m.listed),
  timeout_until: m.timeout_until && Date.parse(m.timeout_until) > Date.now() ? m.timeout_until : null,
  nick: itemOut(m, "nick"),
  ...(self ? { rules_accepted_at: m.rules_accepted_at || null, key_status: m.key_status || "pending" } : {}),
});

export const chainOut = (k: any) => ({
  chain_id: k.chain_id,
  kind: k.kind,
  channel_id: k.channel_id || "",
  rotation_needed: Boolean(k.rotation_needed),
});

export const generationOut = (g: any) => ({
  server_id: g.server_id,
  chain_id: g.chain_id,
  generation: Number(g.generation),
  started_at: g.started_at,
  commit: g.commit,
  creator_id: g.creator_id,
  device_id: g.device_id,
  signature: g.signature,
});

export const grantOut = (g: any) => ({
  id: g.id,
  server_id: g.server_id,
  chain_id: g.chain_id,
  generation: Number(g.generation),
  step: Number(g.step),
  recipient_id: g.user_id,
  recipient_key_version: Number(g.recipient_key_version),
  sealed: g.sealed,
  grantor_id: g.grantor_id,
  grantor_device_id: g.grantor_device_id,
  granted_at: g.granted_at,
  signature: g.signature,
});

export const serverMessageOut = (m: any) => ({
  id: m.id,
  server_id: m.server_id,
  channel_id: m.channel_id,
  msg_id: m.msg_id,
  kind: m.kind,
  thread_id: m.thread_id || "",
  sender_id: m.sender_id,
  device_id: m.device_id,
  envelope: m.deleted ? null : m.envelope,
  signature: m.deleted ? null : m.signature,
  sent_at: m.sent_at,
  created_date: m.created_date,
  updated_date: m.updated_date,
  expires_at: m.expires_at || null,
  deleted: Boolean(m.deleted),
  deleted_by: m.deleted ? m.deleted_by || m.sender_id : null,
  pinned: Boolean(m.pinned),
  last_reply_at: m.last_reply_at || null,
  reply_count: Number(m.reply_count) || 0,
  thread_locked: Boolean(m.thread_locked),
});

export const BLANK_SERVER_MESSAGE = {
  envelope: "", signature: "", deleted: true, msg_id: "", sender_id: "", device_id: "", sent_at: "", thread_id: "", pinned: false,
};

// ---------- reading a server ----------

export async function serverById(db: any, serverId: string) {
  const rows = await db.entities.Server.filter({ audience_id: serverId }, "created_date", 1);
  const s = rows[0];
  if (!s || s.status === "deleting") throw new ApiError(404, "SERVER_NOT_FOUND", "Server not found.");
  return s;
}

export async function memberRow(db: any, serverId: string, userId: string) {
  const rows = await db.entities.ServerMember.filter({ server_id: serverId, user_id: userId }, "created_date", 5);
  return rows.sort(byAge)[0] || null;
}

/** The caller's membership, read with their own access. Not a member: the same 404 as no server. */
export async function requireMember(own: any, serverId: string, userId: string) {
  const member = await memberRow(own, serverId, userId);
  if (!member) throw new ApiError(404, "SERVER_NOT_FOUND", "Server not found.");
  return member;
}

/** Everything about a server that permissions depend on. */
export async function serverParts(db: any, serverId: string) {
  const server = await serverById(db, serverId);
  const [roles, channels] = await Promise.all([
    db.entities.Role.filter({ server_id: serverId }, "position", SERVER_LIMITS.rolesPerServer + 5),
    db.entities.Channel.filter({ server_id: serverId }, "position", SERVER_LIMITS.channelsPerServer + 5),
  ]);
  return { server, roles, channels };
}

export function permsOf(parts: { server: any; roles: any[] }, member: any, channel: any = null) {
  return channel ? channelPermissions(parts.server, parts.roles, member, channel) : basePermissions(parts.server, parts.roles, member);
}

/**
 * Whether this member's app hands keys to people waiting for them (and so may learn who's
 * waiting). Servers choose: any member, or only staff with MANAGE_KEYS.
 */
export function canHandOutKeys(parts: { server: any; roles: any[] }, member: any) {
  return parts.server.key_handout !== "staff" || has(basePermissions(parts.server, parts.roles, member), P.MANAGE_KEYS);
}

export function requirePerm(perms: number, bit: number, what: string) {
  if (!has(perms, bit)) throw new ApiError(403, "MISSING_PERMISSION", `You don't have permission to ${what}.`);
}

/** Acting on another member needs a higher role than theirs (the owner is above everyone; nobody acts on the owner). */
export function requireAbove(parts: { server: any; roles: any[] }, actor: any, target: any, what: string) {
  if (target.user_id === parts.server.owner_id) throw new ApiError(403, "HIERARCHY", `You can't ${what} the server's owner.`);
  if (actor.user_id === parts.server.owner_id) return;
  if (topPosition(parts.server, parts.roles, actor) <= topPosition(parts.server, parts.roles, target)) {
    throw new ApiError(403, "HIERARCHY", `You can only ${what} members whose highest role is below yours.`);
  }
}

export function channelIn(parts: { channels: any[] }, channelId: string) {
  const ch = parts.channels.find((c: any) => c.id === channelId);
  if (!ch) throw new ApiError(404, "CHANNEL_NOT_FOUND", "Channel not found.");
  return ch;
}

/** The key chain a channel's messages are encrypted with. */
export function chainForChannel(serverId: string, channel: any) {
  if (channel.private) return channelChainId(serverId, channel.id);
  return channel.history === "full" ? historyChainId(serverId) : liveChainId(serverId);
}

/** Mark that something about the server's layout or settings changed, so members' apps reload it. */
export async function touchServer(sr: any, serverId: string, now: Date, extra: any = {}) {
  const [s] = await sr.entities.Server.filter({ audience_id: serverId }, "created_date", 1);
  if (s) await sr.entities.Server.update(s.id, { changed_at: now.toISOString(), ...extra });
}

// ---------- access lists ----------

/**
 * Work out, and store, which servers and private channels a person can read: what row rules
 * on server tables go by. Called whenever that could have changed for them.
 */
export async function refreshAccess(sr: any, userId: string) {
  const memberships = (await sr.entities.ServerMember.filter({ user_id: userId }, "created_date", SERVER_LIMITS.serversPerUser + 10)).sort(byAge);
  const serverIds = [...new Set(memberships.map((m: any) => m.server_id))];
  const access = new Set<string>(serverIds);
  if (serverIds.length) {
    const privateChannels = await sr.entities.Channel.filter({ server_id: { $in: serverIds }, private: true }, "position", 2000);
    const withPrivate = [...new Set(privateChannels.map((c: any) => c.server_id))];
    if (withPrivate.length) {
      const [servers, roles] = await Promise.all([
        sr.entities.Server.filter({ audience_id: { $in: withPrivate } }, "created_date", withPrivate.length + 5),
        sr.entities.Role.filter({ server_id: { $in: withPrivate } }, "position", 5000),
      ]);
      for (const ch of privateChannels) {
        const server = servers.find((s: any) => s.id === ch.server_id);
        const member = memberships.find((m: any) => m.server_id === ch.server_id);
        if (!server || !member) continue;
        const serverRoles = roles.filter((r: any) => r.server_id === ch.server_id);
        if (has(channelPermissions(server, serverRoles, member, ch), P.VIEW_CHANNEL)) access.add(ch.id);
      }
    }
  }
  const list = [...access];
  await sr.entities.User.update(userId, { cv_access: list });
  return list;
}

/** Which of a server's private channels each of these members can see. */
export function visiblePrivate(parts: { server: any; roles: any[]; channels: any[] }, member: any) {
  return parts.channels.filter((c: any) => c.private && has(channelPermissions(parts.server, parts.roles, member, c), P.VIEW_CHANNEL)).map((c: any) => c.id);
}

// ---------- keys ----------

export async function generationsOf(db: any, serverId: string, chainIds?: string[]) {
  const q: any = { server_id: serverId };
  if (chainIds) q.chain_id = { $in: chainIds };
  const rows = await db.entities.KeyGeneration.filter(q, "created_date", 2000);
  // One statement per (chain, generation): the oldest wins a race.
  const seen = new Set<string>();
  const out: any[] = [];
  for (const g of rows.sort(byAge)) {
    const k = `${g.chain_id}|${g.generation}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(g);
  }
  return out.sort((a, b) => a.chain_id.localeCompare(b.chain_id) || a.generation - b.generation);
}

export function latestGeneration(gens: any[], chainId: string) {
  let best: any = null;
  for (const g of gens) if (g.chain_id === chainId && (!best || g.generation > best.generation)) best = g;
  return best;
}

/** Chains a member can read: the server's two, and the private channels they can see. */
export function chainsFor(parts: { server: any; roles: any[]; channels: any[] }, member: any) {
  const ids = [historyChainId(parts.server.id), liveChainId(parts.server.id)];
  for (const chId of visiblePrivate(parts, member)) ids.push(channelChainId(parts.server.id, chId));
  return ids;
}

/**
 * The grants a member should have: every generation of the history chain and of the private
 * channels they can see; and of the live chain, the hour they joined in the generation running
 * then, and every later generation from its start.
 */
export function expectedGrants(parts: any, member: any, gens: any[]) {
  const out: { chain_id: string; generation: number; step: number }[] = [];
  const joined = Date.parse(member.joined_at);
  for (const chainId of chainsFor(parts, member)) {
    const mine = gens.filter((g) => g.chain_id === chainId).sort((a, b) => a.generation - b.generation);
    if (parseChainId(chainId)?.kind !== "l") {
      for (const g of mine) out.push({ chain_id: chainId, generation: Number(g.generation), step: 0 });
      continue;
    }
    for (let i = 0; i < mine.length; i += 1) {
      const g = mine[i];
      const next = mine[i + 1];
      const start = Date.parse(g.started_at);
      if (next && Date.parse(next.started_at) <= joined) continue; // superseded before they joined
      out.push({ chain_id: chainId, generation: Number(g.generation), step: joined > start ? stepAt(chainId, g.started_at, joined) : 0 });
    }
  }
  return out;
}

export const grantKey = (g: any) => `${g.chain_id}|${Number(g.generation)}`;

/** What a member is still missing, given their grants. */
export function missingGrants(parts: any, member: any, gens: any[], grants: any[]) {
  const have = new Set(grants.filter((g: any) => g.user_id === member.user_id).map(grantKey));
  return expectedGrants(parts, member, gens).filter((e) => !have.has(grantKey(e)));
}

/** Recheck members' key status after grants or changes. Marks the server when someone's waiting. */
export async function refreshKeyStatus(sr: any, parts: any, members: any[], now: Date) {
  if (!members.length) return 0;
  const gens = await generationsOf(sr, parts.server.id);
  const grants = await sr.entities.KeyGrant.filter({ server_id: parts.server.id, user_id: { $in: members.map((m: any) => m.user_id) } }, "created_date", 5000);
  let pending = 0;
  for (const m of members) {
    const status = missingGrants(parts, m, gens, grants).length ? "pending" : "ok";
    if (status === "pending") pending += 1;
    if ((m.key_status || "pending") !== status) await sr.entities.ServerMember.update(m.id, { key_status: status });
  }
  if (pending && !parts.server.keys_pending_at) {
    await sr.entities.Server.update(parts.server.id, { keys_pending_at: now.toISOString() });
    parts.server.keys_pending_at = now.toISOString();
  }
  return pending;
}

/** Mark that a chain needs a new generation (someone who held it lost access). */
export async function needRotation(sr: any, serverId: string, chainIds: string[], reason: string) {
  if (!chainIds.length) return;
  const rows = await sr.entities.KeyChain.filter({ server_id: serverId, chain_id: { $in: chainIds } }, "created_date", 500);
  for (const k of rows) if (!k.rotation_needed) await sr.entities.KeyChain.update(k.id, { rotation_needed: true, rotation_reason: reason });
}

// ---------- encrypted items ----------

/**
 * An encrypted item sent with a request (a server name, nickname, role name, rules, a ban
 * reason): its envelope's shape, the sending device, the clock, and the device's signature.
 * The envelope must be encrypted with the server's history chain, current generation.
 */
export async function acceptItem(ctx: any, { kind, serverId, channelId = "", item, gens, chainId, maxChars = SERVER_LIMITS.maxItemEnvelopeChars }: any) {
  const { own, user, now } = ctx;
  if (!item || typeof item !== "object") throw new ApiError(400, "BAD_FIELD", "Missing encrypted item.");
  const envelope = str(item.envelope, "encrypted item", maxChars);
  const itemId = randomIdField(item.item_id, "item id");
  const sentAt = isoTime(item.sent_at, "sent time");
  if (Math.abs(now.getTime() - Date.parse(sentAt)) > LIMITS.sentAtSkewMs) {
    throw new ApiError(400, "CLOCK_SKEW", "Your device clock looks wrong. Check it and try again.");
  }
  const device = await requireActiveDevice(own, user.id, randomIdField(item.device_id, "device id"));
  const env = parseItemEnvelope(envelope);
  const chain = chainId || historyChainId(serverId);
  const latest = latestGeneration(gens, chain);
  if (!latest) throw new ApiError(409, "NO_KEYS_YET", "This server's encryption isn't set up yet.");
  if (env.chain !== chain || env.gen !== Number(latest.generation) || env.step !== stepAt(chain, latest.started_at, Date.parse(sentAt))) {
    throw new ApiError(409, "STALE_SERVER_KEYS", "This server's keys changed. Refreshing and trying again.");
  }
  const ok = await verifyServerItemSignature({
    kind, server_id: serverId, channel_id: channelId, item_id: itemId, sender_id: user.id, device_id: device.device_id,
    envelope, sent_at: sentAt, signature: item.signature, signPub: device.sign_pub,
  });
  if (!ok) throw new ApiError(403, "SIGNATURE_INVALID", "The signature didn't verify.");
  return { envelope, item_id: itemId, sender_id: user.id, device_id: device.device_id, sent_at: sentAt, signature: item.signature };
}

export function itemFields(prefix: string, accepted: any) {
  return {
    [`${prefix}_envelope`]: accepted.envelope,
    [`${prefix}_item_id`]: accepted.item_id,
    [`${prefix}_sender_id`]: accepted.sender_id,
    [`${prefix}_device_id`]: accepted.device_id,
    [`${prefix}_sent_at`]: accepted.sent_at,
    [`${prefix}_signature`]: accepted.signature,
  };
}

export const clearedItem = (prefix: string) => itemFields(prefix, { envelope: "", item_id: "", sender_id: "", device_id: "", sent_at: "", signature: "" });

/** A server envelope's shape: { v: 1, chain, gen, step, iv, ct, kc }. */
export function parseItemEnvelope(envelope: string) {
  let env: any;
  try {
    env = JSON.parse(envelope);
  } catch {
    throw new ApiError(400, "BAD_ENVELOPE", "The encrypted item is malformed.");
  }
  const B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
  const len = (v: unknown) => (typeof v === "string" && B64.test(v) ? atob(v).length : -1);
  const ok =
    env && env.v === 1 && parseChainId(env.chain) && Number.isInteger(env.gen) && env.gen >= 0 && Number.isInteger(env.step) && env.step >= 0 &&
    len(env.iv) === 12 && len(env.ct) >= 17 && len(env.kc) === 32;
  if (!ok) throw new ApiError(400, "BAD_ENVELOPE", "The encrypted item is malformed.");
  return env as { v: number; chain: string; gen: number; step: number };
}

// ---------- audit log ----------

/** A line in the server's audit log: who did what to which thing. Never any message content. */
export async function audit(sr: any, server: any, actorId: string, action: string, targetKind = "", targetId = "", detail = "", now = new Date()) {
  const days = SERVER_LIMITS.auditRetentionChoices.includes(Number(server.audit_retention_days)) ? Number(server.audit_retention_days) : 90;
  await sr.entities.AuditEntry.create({
    server_id: server.id,
    actor_id: actorId,
    action,
    target_kind: targetKind,
    target_id: targetId,
    detail: String(detail || "").slice(0, 200),
    expires_at: new Date(now.getTime() + days * 86_400_000).toISOString(),
  });
}

export { platformTime, createdAt, isStaff, channelIsPrivate, has, P };
