// Moderation the service can do without reading anything: counts, rates and who did what. A
// server's owner chooses how each part behaves (its "policy"); reasons and notes stay encrypted.
//
// - Warnings add up: at the counts the server sets, a timeout, kick or ban follows automatically.
// - Flood protection: too many messages too fast, and the sender is timed out for a while.
// - Raid protection: too many people joining in a minute, and joining pauses itself.
// - Staff limits ("anti-nuke"): a staff member doing too many bans, kicks or deletions in ten
//   minutes is stopped and loses their roles until the owner looks.
import { ApiError } from "../http.ts";
import { P } from "../permissions.ts";
import { audit } from "./model.ts";
import { countSince } from "../store.ts";

/** Permissions that make someone a moderator for reports and cases. */
export const MOD_PERMS = P.MANAGE_MESSAGES | P.KICK_MEMBERS | P.BAN_MEMBERS | P.TIMEOUT_MEMBERS | P.ADMINISTRATOR;

export const CASE_ACTIONS = ["warn", "note", "timeout", "kick", "ban", "unban", "purge", "quarantine"] as const;

export const DEFAULT_POLICY = Object.freeze({
  warn_window_days: 30,
  thresholds: [
    { count: 3, action: "timeout", minutes: 60 },
    { count: 5, action: "kick", minutes: 0 },
  ],
  flood: { enabled: false, messages: 8, seconds: 10, timeout_minutes: 10 },
  raid: { enabled: false, joins_per_minute: 10 },
  nuke: { enabled: true, limit: 10 },
});

const pick = <T,>(v: unknown, options: readonly T[], fallback: T): T => (options.includes(v as T) ? (v as T) : fallback);

/** The server's policy, with anything missing or out of range set to its default. */
export function policyOf(server: any) {
  return cleanPolicy(server?.mod_policy || {});
}

export function cleanPolicy(raw: any) {
  const d = DEFAULT_POLICY;
  const thresholds = Array.isArray(raw?.thresholds)
    ? raw.thresholds
        .filter((t: any) => t && Number.isInteger(t.count) && t.count >= 1 && t.count <= 20 && ["timeout", "kick", "ban"].includes(t.action))
        .slice(0, 5)
        .map((t: any) => ({ count: t.count, action: t.action, minutes: t.action === "kick" ? 0 : pick(t.minutes, [0, 10, 60, 360, 1440, 10080, 40320], t.action === "timeout" ? 60 : 0) }))
        .filter((t: any) => !(t.action === "timeout" && t.minutes === 0))
        .sort((a: any, b: any) => a.count - b.count)
    : d.thresholds;
  const f = raw?.flood || {};
  const r = raw?.raid || {};
  const n = raw?.nuke || {};
  return {
    warn_window_days: pick(raw?.warn_window_days, [7, 30, 90, 365], d.warn_window_days),
    thresholds: thresholds.filter((t: any, i: number, all: any[]) => all.findIndex((x) => x.count === t.count) === i),
    flood: {
      enabled: f.enabled === true,
      messages: pick(f.messages, [5, 8, 12, 20], d.flood.messages),
      seconds: pick(f.seconds, [5, 10, 30], d.flood.seconds),
      timeout_minutes: pick(f.timeout_minutes, [1, 5, 10, 60], d.flood.timeout_minutes),
    },
    raid: { enabled: r.enabled === true, joins_per_minute: pick(r.joins_per_minute, [5, 10, 20, 50], d.raid.joins_per_minute) },
    nuke: { enabled: n.enabled !== false, limit: pick(n.limit, [3, 5, 10, 20], d.nuke.limit) },
  };
}

/** Write a case. reason: accepted item fields (or {}). Returns the row. */
export async function logCase(sr: any, server: any, { action, targetId, actorId, minutes = 0, reason = {}, reportId = "", now }: any) {
  const [last] = await sr.entities.ModCase.filter({ server_id: server.id }, "-case_number", 1);
  return sr.entities.ModCase.create({
    server_id: server.id,
    case_number: (Number(last?.case_number) || 0) + 1,
    action,
    target_id: targetId,
    actor_id: actorId,
    minutes,
    report_id: reportId,
    active: action === "warn",
    ...reason,
    created_at: now.toISOString(),
  });
}

/**
 * After a warning: the number of active warnings in the window, and the punishment the policy
 * sets for exactly that many, if any. The caller applies it (it needs the member helpers).
 */
export async function thresholdFor(sr: any, server: any, targetId: string, now: Date) {
  const policy = policyOf(server);
  const since = new Date(now.getTime() - policy.warn_window_days * 86_400_000);
  const warns = (await sr.entities.ModCase.filter({ server_id: server.id, target_id: targetId, action: "warn", active: true }, "-created_date", 100))
    .filter((c: any) => Date.parse(c.created_at || c.created_date) >= since.getTime()).length;
  const step = policy.thresholds.find((t: any) => t.count === warns) || null;
  return { warns, step };
}

const DESTRUCTIVE = ["member_ban", "member_kick", "member_timeout", "channel_delete", "role_delete", "messages_purge"];

/**
 * Staff limits. Before a destructive action by anyone but the owner: if they've done the limit
 * already in ten minutes, refuse, take away their roles and tell the owner (through the audit log).
 * removeRoles is the caller's way to strip them.
 */
export async function guardNuke(sr: any, parts: any, member: any, now: Date, removeRoles: () => Promise<void>) {
  if (member.user_id === parts.server.owner_id) return;
  const policy = policyOf(parts.server);
  if (!policy.nuke.enabled) return;
  const since = new Date(now.getTime() - 600_000);
  const recent = (await sr.entities.AuditEntry.filter({ server_id: parts.server.id, actor_id: member.user_id, created_date: { $gte: since.toISOString().replace("Z", "") } }, "-created_date", 100))
    .filter((a: any) => DESTRUCTIVE.includes(a.action)).length;
  if (recent < policy.nuke.limit) return;
  await removeRoles();
  await logCase(sr, parts.server, { action: "quarantine", targetId: member.user_id, actorId: "system", now });
  await audit(sr, parts.server, "system", "staff_quarantine", "member", member.user_id, `${recent} actions in 10 min`, now);
  throw new ApiError(403, "STAFF_LIMIT", "That's more than this server allows in ten minutes, so your roles have been taken away until the owner checks.");
}

/** Raid protection, after someone joins: too many joins in a minute pauses joining. */
export async function checkRaid(sr: any, server: any, now: Date) {
  const policy = policyOf(server);
  if (!policy.raid.enabled || server.joins_paused) return false;
  const joins = await countSince(sr, "ServerMember", { server_id: server.id }, new Date(now.getTime() - 60_000), policy.raid.joins_per_minute + 1);
  if (joins <= policy.raid.joins_per_minute) return false;
  await sr.entities.Server.update(server.id, { joins_paused: true, raid_detected_at: now.toISOString() });
  await audit(sr, server, "system", "raid_lockdown", "server", server.id, `${joins} joins in a minute`, now);
  return true;
}

/** Flood protection, before a message: true if this member just went over the server's rate. */
export async function floodedBy(sr: any, server: any, userId: string, now: Date) {
  const policy = policyOf(server);
  if (!policy.flood.enabled) return null;
  const n = await countSince(sr, "ServerMessage", { server_id: server.id, sender_id: userId, kind: { $in: ["message", "post"] } }, new Date(now.getTime() - policy.flood.seconds * 1000), policy.flood.messages + 1);
  return n >= policy.flood.messages ? policy.flood : null;
}
