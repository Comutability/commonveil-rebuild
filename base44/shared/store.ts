// Common data access, always through the service role and always scoped by the
// caller's own user id. Entities are backend-only, so this is the only way in.
import { ApiError, LIMITS, parsePlatformTime } from "./http.ts";

/**
 * When a record was created, in milliseconds. A record just created comes back as
 * "2026-10-29T11:37:14.587123Z" and the same record read later as "2026-10-29T11:37:14.587000",
 * so times are compared as numbers, never as text.
 */
export const createdAt = (r: any) => parsePlatformTime(String(r?.created_date || ""));

/** Oldest first; ties broken by id, so every request agrees on the order. */
export const byAge = (a: any, b: any) => createdAt(a) - createdAt(b) || String(a.id).localeCompare(String(b.id));

/**
 * A query made straight after a write may not include the new row yet. Put it in (once) and
 * sort oldest first, so "oldest wins" checks and rate limits see what was actually written.
 */
export function withRow(rows: any[], created: any) {
  return [...rows.filter((r: any) => r.id !== created.id), created].sort(byAge);
}

export async function profileOf(sr: any, userId: string) {
  const rows = await sr.entities.Profile.filter({ user_id: userId }, "created_date", 5);
  return rows[0] || null;
}

export const publicProfile = (p: any) => ({
  user_id: p.user_id,
  username: p.username,
  display_name: p.display_name || "",
  bio: p.bio || "",
  pronouns: p.pronouns || "",
  accent_color: p.accent_color || "",
  avatar_emoji: p.avatar_emoji || "",
});

/** A profile with only what the person chose to show this viewer: the username always, the rest if they allow it. */
export function profileFor(p: any, { contact }: { contact: boolean }) {
  const visibility = p.profile_visibility || "shared";
  const full = visibility === "shared" || (visibility === "conversations" && contact);
  if (full) return publicProfile(p);
  return { user_id: p.user_id, username: p.username, display_name: "", bio: "", pronouns: "", accent_color: p.accent_color || "", avatar_emoji: "" };
}

/**
 * Which of these people share a server with userId (servers set to count members for direct
 * messages only). One query with the member's own access, one with the service role.
 */
export async function serverPeersOf(sr: any, own: any, userId: string, ids: string[]) {
  const out = new Set<string>();
  if (!ids.length) return out;
  const mine = await own.entities.ServerMember.filter({ user_id: userId }, "created_date", 200);
  const serverIds = [...new Set(mine.map((m: any) => m.server_id))];
  if (!serverIds.length) return out;
  const theirs = await sr.entities.ServerMember.filter({ server_id: { $in: serverIds }, user_id: { $in: ids } }, "created_date", 5000);
  for (const m of theirs) out.add(m.user_id);
  return out;
}

export async function accountKeysOf(sr: any, userId: string) {
  const rows = await sr.entities.AccountKey.filter({ user_id: userId }, "version", 300);
  return rows.sort((a: any, b: any) => a.version - b.version || String(a.created_date).localeCompare(String(b.created_date)));
}

/** One statement per version: a lost publishing race can leave a duplicate for a moment, and the oldest wins. */
export function uniqueVersions(rows: any[]) {
  const seen = new Set<number>();
  const out: any[] = [];
  for (const k of [...rows].sort(byAge)) {
    if (seen.has(k.version)) continue;
    seen.add(k.version);
    out.push(k);
  }
  return out.sort((a, b) => a.version - b.version);
}

export function latestKeyOf(keys: any[]) {
  return keys.length ? keys[keys.length - 1] : null;
}

export const statementOut = (k: any) => ({
  user_id: k.user_id,
  version: k.version,
  ecdh_pub: k.ecdh_pub,
  sign_pub: k.sign_pub,
  recovery_pub: k.recovery_pub,
  signed_by_version: k.signed_by_version,
  issued_at: k.issued_at,
  signature: k.signature,
  is_reset: Boolean(k.is_reset),
  // Post-quantum keys, on statements made from November 2026 (account-key/v2).
  ...(k.kem_pub ? { kem_pub: k.kem_pub, recovery_kem_pub: k.recovery_kem_pub || "" } : {}),
});

/** The account's own view also carries the recovery anchors (useless to anyone without the phrase). */
export const ownStatementOut = (k: any) => ({ ...statementOut(k), recovery_mac: k.recovery_mac || "" });

/** Latest key version for each user. Throws if any user has no keys yet. */
export async function latestVersionsFor(sr: any, userIds: string[]) {
  return new Map([...(await latestKeysFor(sr, userIds))].map(([u, k]) => [u, k.version]));
}

/** Each user's latest key statement (oldest row wins a duplicate version). */
export async function latestKeysFor(sr: any, userIds: string[]) {
  const rows = await sr.entities.AccountKey.filter({ user_id: { $in: userIds } }, "version", 5000);
  const latest = new Map<string, any>();
  for (const r of [...rows].sort(byAge)) {
    const seen = latest.get(r.user_id);
    if (!seen || r.version > seen.version) latest.set(r.user_id, r);
  }
  return latest;
}

/**
 * Every live device (active or pending) and the most recent removed ones. Live devices are
 * fetched on their own, so however many requests pile up, a real device is never left off.
 */
export async function devicesOf(sr: any, userId: string) {
  const [live, past] = await Promise.all([
    sr.entities.Device.filter({ user_id: userId, status: { $in: ["active", "pending"] } }, "created_date", 100),
    sr.entities.Device.filter({ user_id: userId, status: "revoked" }, "-created_date", 100),
  ]);
  return [...live, ...past];
}

export async function deviceOf(sr: any, userId: string, deviceId: string) {
  const rows = await sr.entities.Device.filter({ user_id: userId, device_id: deviceId }, "created_date", 5);
  return rows[0] || null;
}

export function pendingExpired(device: any, now: Date) {
  return device.status === "pending" && device.pending_expires_at && Date.parse(device.pending_expires_at) < now.getTime();
}

export const deviceOut = (d: any, now: Date) => ({
  device_id: d.device_id,
  label: d.label || "Device",
  sign_pub: d.sign_pub,
  box_pub: d.box_pub,
  status: pendingExpired(d, now) ? "expired" : d.status,
  cert_key_version: d.cert_key_version ?? null,
  cert_issued_at: d.cert_issued_at || null,
  cert_signature: d.cert_signature || null,
  approved_via: d.approved_via || null,
  approved_at: d.approved_at || null,
  pending_expires_at: d.pending_expires_at || null,
  revoked_at: d.revoked_at || null,
  revoked_reason: d.revoked_reason || null,
  synced_key_version: d.synced_key_version ?? null,
  last_seen_at: d.last_seen_at || null,
  created_date: d.created_date,
  ...devicePqOut(d),
});

/** A device's post-quantum key, its own signature over it, and whether its certificate covers it. */
const devicePqOut = (d: any) => (d.kem_pub ? { kem_pub: d.kem_pub, kem_sig: d.kem_sig || "", cert_has_kem: Boolean(d.cert_has_kem) } : {});

/** What other members see about your devices: keys and certificate, no labels or timings. */
export const peerDeviceOut = (d: any) => ({
  device_id: d.device_id,
  sign_pub: d.sign_pub,
  box_pub: d.box_pub,
  status: d.status,
  cert_key_version: d.cert_key_version,
  cert_issued_at: d.cert_issued_at,
  cert_signature: d.cert_signature,
  ...devicePqOut(d),
});

/** Active device owned by this user, or a 403. */
export async function requireActiveDevice(sr: any, userId: string, deviceId: string) {
  const device = await deviceOf(sr, userId, deviceId);
  if (!device) throw new ApiError(403, "DEVICE_UNKNOWN", "This device isn't registered to your account.");
  if (device.status !== "active") throw new ApiError(403, "DEVICE_NOT_ACTIVE", "This device hasn't been approved, or was removed.");
  return device;
}

export async function blockedEitherWay(sr: any, a: string, b: string) {
  const rows = await sr.entities.Block.filter(
    { $or: [{ user_id: a, blocked_user_id: b }, { user_id: b, blocked_user_id: a }] },
    "created_date",
    2,
  );
  return rows.length > 0;
}

export async function myConversations(sr: any, userId: string, limit = 500) {
  return sr.entities.Conversation.filter({ member_ids: userId }, "-updated_date", limit);
}

export async function conversationForMember(sr: any, userId: string, conversationId: string) {
  let conv: any = null;
  try {
    conv = await sr.entities.Conversation.get(conversationId);
  } catch {
    conv = null;
  }
  if (!conv || !Array.isArray(conv.member_ids) || !conv.member_ids.includes(userId)) {
    // Same answer whether it doesn't exist or you aren't in it.
    throw new ApiError(404, "CONVERSATION_NOT_FOUND", "Conversation not found.");
  }
  return conv;
}

/** User ids that share at least one conversation with userId (plus userId). */
export async function contactsOf(sr: any, userId: string) {
  const convs = await myConversations(sr, userId);
  const ids = new Set<string>([userId]);
  for (const c of convs) for (const m of c.member_ids || []) ids.add(m);
  return ids;
}

export async function countSince(sr: any, entity: string, query: any, since: Date, cap: number) {
  const rows = await sr.entities[entity].filter(
    { ...query, created_date: { $gte: since.toISOString().replace("Z", "") } },
    "-created_date",
    cap + 1,
  );
  return rows.filter((r: any) => parsePlatformTime(r.created_date) >= since.getTime()).length;
}

export function rateLimited(what: string) {
  return new ApiError(429, "RATE_LIMITED", `You're ${what} too quickly. Please wait a moment.`);
}

export async function enforceRate(sr: any, entity: string, query: any, windowMs: number, cap: number, now: Date, what: string) {
  const n = await countSince(sr, entity, query, new Date(now.getTime() - windowMs), cap);
  if (n >= cap) throw rateLimited(what);
}

/**
 * Checked again after inserting: requests arriving together all pass the first count, so
 * each one looks for its own row among the oldest `cap` in the window. False means undo it.
 */
export async function withinRate(sr: any, entity: string, query: any, windowMs: number, cap: number, now: Date, created: any) {
  const since = new Date(now.getTime() - windowMs - 60_000);
  const rows = await sr.entities[entity].filter(
    { ...query, created_date: { $gte: since.toISOString().replace("Z", "") } },
    "created_date",
    cap * 2 + 20,
  );
  const windowStart = now.getTime() - windowMs;
  const ordered = withRow(rows.filter((r: any) => createdAt(r) >= windowStart), created);
  return ordered.findIndex((r: any) => r.id === created.id) < cap;
}

/**
 * Messages a member may list: only those whose key was sealed to them, so someone added
 * to a group isn't even shown that earlier messages exist. (Messages from before this
 * was recorded have no recipient list and stay visible to every member.)
 */
export const addressedTo = (userId: string) => ({ $or: [{ recipient_ids: userId }, { recipient_ids: null }] });

/** Disappearing-message timers a conversation can have, in seconds: off, a day, a week, four weeks. */
export const EXPIRY_CHOICES = Object.freeze([0, 86_400, 604_800, 2_419_200]);

/** False once a disappearing message's time is up, even before the scheduled clean-up deletes it. */
export const isLive = (m: any, now: Date) => !m.expires_at || Date.parse(m.expires_at) > now.getTime();

/** Delete an account after this many days without use: off, about six months, a year. */
export const AUTO_DELETE_DAYS = Object.freeze([0, 183, 365]);

/** A day, "2026-10-30": all that's kept of when an account was last used, and only while auto-delete is on. */
export const dayOf = (d: Date) => d.toISOString().slice(0, 10);

/**
 * A group's admins. A group whose listed admins have all gone (or that predates admins) is
 * managed by its creator if they're still in it, otherwise by its longest-standing member.
 */
export function adminsOf(conv: any): string[] {
  if (conv.kind !== "group") return [];
  const members: string[] = conv.member_ids || [];
  const listed = (conv.admin_ids || []).filter((m: string) => members.includes(m));
  if (listed.length) return listed;
  if (conv.creator_id && members.includes(conv.creator_id)) return [conv.creator_id];
  return members.length ? [members[0]] : [];
}

/** Group admins; in a direct message both people manage their own conversation. */
export function isAdmin(conv: any, userId: string) {
  return conv.kind !== "group" || adminsOf(conv).includes(userId);
}

export function requireGroupAdmin(conv: any, userId: string, what: string) {
  if (!isAdmin(conv, userId)) throw new ApiError(403, "NOT_ADMIN", `Only the group's admins can ${what}.`);
}

/**
 * Who's left, and who manages, once someone leaves or is removed. A group is never left
 * without an admin: if the last one goes, the longest-standing member takes over.
 */
export function withoutMember(conv: any, userId: string) {
  const member_ids = (conv.member_ids || []).filter((m: string) => m !== userId);
  let admin_ids = adminsOf(conv).filter((m: string) => m !== userId && member_ids.includes(m));
  if (!admin_ids.length && member_ids.length) admin_ids = [member_ids[0]];
  return { member_ids, admin_ids };
}

export const conversationOut = (c: any) => ({
  id: c.id,
  kind: c.kind,
  member_ids: c.member_ids || [],
  admin_ids: adminsOf(c),
  creator_id: c.creator_id || "",
  created_date: c.created_date,
  updated_date: c.updated_date,
  last_message_at: c.last_message_at || null,
  expire_seconds: Number(c.expire_seconds) || 0,
  expiry_set_by: c.expiry_set_by || null,
  expiry_set_at: c.expiry_set_at || null,
  ...(c.server_id ? { server_id: c.server_id, ticket: { number: Number(c.ticket_number) || 0, status: c.ticket_status || "open", opened_by: c.ticket_opened_by || "", channel_id: c.ticket_channel_id || "" } } : {}),
  title: c.title_envelope
    ? {
        envelope: c.title_envelope,
        item_id: c.title_item_id,
        sender_id: c.title_sender_id,
        device_id: c.title_device_id,
        sent_at: c.title_sent_at,
        signature: c.title_signature,
      }
    : null,
});

export const messageOut = (m: any) => ({
  id: m.id,
  conversation_id: m.conversation_id,
  msg_id: m.msg_id,
  sender_id: m.sender_id,
  device_id: m.device_id,
  envelope: m.deleted ? null : m.envelope,
  signature: m.deleted ? null : m.signature,
  sent_at: m.sent_at,
  created_date: m.created_date,
  expires_at: m.expires_at || null,
  deleted: Boolean(m.deleted),
});

/**
 * Every member must be covered exactly once, each at their current key version, and with a
 * post-quantum wrap whenever that key has a post-quantum half.
 */
export async function assertWrapsMatchMembers(sr: any, wraps: { u: string; kv: number; kem?: boolean }[], memberIds: string[]) {
  const latest = await latestKeysFor(sr, memberIds);
  const wrapUsers = new Set(wraps.map((w) => w.u));
  const exact = wrapUsers.size === memberIds.length && memberIds.every((m) => wrapUsers.has(m));
  if (!exact) throw new ApiError(409, "RECIPIENTS_CHANGED", "The people in this conversation changed. Refreshing and trying again.");
  for (const w of wraps) {
    const current = latest.get(w.u);
    if (!current) throw new ApiError(409, "MEMBER_NOT_READY", "Someone here hasn't finished setting up encryption.");
    if (w.kv !== current.version) throw new ApiError(409, "STALE_KEYS", "Someone's keys changed. Refreshing and trying again.");
    if (current.kem_pub && !w.kem) throw new ApiError(409, "STALE_KEYS", "Someone's keys changed. Refreshing and trying again.");
  }
}

export { LIMITS };
