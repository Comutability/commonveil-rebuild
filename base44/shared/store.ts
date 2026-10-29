// Common data access, always through the service role and always scoped by the
// caller's own user id. Entities are backend-only, so this is the only way in.
import { ApiError, LIMITS, parsePlatformTime } from "./http.ts";

export async function profileOf(sr: any, userId: string) {
  const rows = await sr.entities.Profile.filter({ user_id: userId }, "created_date", 5);
  return rows[0] || null;
}

export const publicProfile = (p: any) => ({
  user_id: p.user_id,
  username: p.username,
  display_name: p.display_name || "",
  bio: p.bio || "",
});

export async function accountKeysOf(sr: any, userId: string) {
  const rows = await sr.entities.AccountKey.filter({ user_id: userId }, "version", 300);
  return rows.sort((a: any, b: any) => a.version - b.version || String(a.created_date).localeCompare(String(b.created_date)));
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
});

/** Latest key version for each user. Throws if any user has no keys yet. */
export async function latestVersionsFor(sr: any, userIds: string[]) {
  const rows = await sr.entities.AccountKey.filter({ user_id: { $in: userIds } }, "version", 5000);
  const latest = new Map<string, number>();
  for (const r of rows) latest.set(r.user_id, Math.max(latest.get(r.user_id) || 0, r.version));
  return latest;
}

export async function devicesOf(sr: any, userId: string) {
  return sr.entities.Device.filter({ user_id: userId }, "created_date", 200);
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
});

/** What other members see about your devices: keys and certificate, no labels or timings. */
export const peerDeviceOut = (d: any) => ({
  device_id: d.device_id,
  sign_pub: d.sign_pub,
  box_pub: d.box_pub,
  status: d.status,
  cert_key_version: d.cert_key_version,
  cert_issued_at: d.cert_issued_at,
  cert_signature: d.cert_signature,
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

export async function enforceRate(sr: any, entity: string, query: any, windowMs: number, cap: number, now: Date, what: string) {
  const n = await countSince(sr, entity, query, new Date(now.getTime() - windowMs), cap);
  if (n >= cap) throw new ApiError(429, "RATE_LIMITED", `You're ${what} too quickly. Please wait a moment.`);
}

export const conversationOut = (c: any) => ({
  id: c.id,
  kind: c.kind,
  member_ids: c.member_ids || [],
  created_by: c.created_by,
  created_date: c.created_date,
  updated_date: c.updated_date,
  last_message_at: c.last_message_at || null,
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
  deleted: Boolean(m.deleted),
});

/** Every member must be covered exactly once, each at their current key version. */
export async function assertWrapsMatchMembers(sr: any, wraps: { u: string; kv: number }[], memberIds: string[]) {
  const latest = await latestVersionsFor(sr, memberIds);
  const wrapUsers = new Set(wraps.map((w) => w.u));
  const exact = wrapUsers.size === memberIds.length && memberIds.every((m) => wrapUsers.has(m));
  if (!exact) throw new ApiError(409, "RECIPIENTS_CHANGED", "The people in this conversation changed. Refreshing and trying again.");
  for (const w of wraps) {
    const current = latest.get(w.u);
    if (!current) throw new ApiError(409, "MEMBER_NOT_READY", "Someone here hasn't finished setting up encryption.");
    if (w.kv !== current) throw new ApiError(409, "STALE_KEYS", "Someone's keys changed. Refreshing and trying again.");
  }
}

export { LIMITS };
