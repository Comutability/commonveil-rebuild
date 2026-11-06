// Server moderation: reports to a server's moderators, cases (warnings, notes, and a record of
// every timeout, kick and ban), the server's moderation policy, purging a member's messages, and
// escalating a report to the Commonveil team.
//
// Reports are end-to-end encrypted to the server's moderators (and the reporter) with their
// account keys, like a group message: the service sees who reported whom and when, never what
// was said. Reasons on cases are encrypted with the server's key. Escalating to Commonveil is
// the one place a moderator chooses to share something readable, and the app says so first.
import { ApiError, cleanText, id, isoTime, LIMITS, randomIdField, str, type Actions, type Ctx } from "../http.ts";
import { signedByActiveDevice } from "../deviceAuth.ts";
import { P, has, topPosition } from "../permissions.ts";
import {
  acceptItem, audit, generationsOf, itemFields, itemOut, memberRow, permsOf, requireAbove, requireMember, serverParts, SERVER_LIMITS,
} from "../servers/model.ts";
import { removeMember } from "../servers/build.ts";
import { CASE_ACTIONS, MOD_PERMS, cleanPolicy, logCase, policyOf, thresholdFor } from "../servers/moderation.ts";
import { assertWrapsMatchMembers, countSince, latestKeysFor, rateLimited, requireActiveDevice } from "../store.ts";
import { parseEnvelopeShape, verifyItemSignature } from "../verify.ts";

export const MOD_LIMITS = Object.freeze({ moderatorsPerReport: 31, reportsPerDay: 10, reportEnvelopeChars: 64 * 1024, escalationsPerDay: 20 });
const STATUSES = ["open", "resolved", "dismissed", "escalated"];
const REASONS = ["spam", "harassment", "hate", "sexual", "violence", "self_harm", "scam", "illegal", "under_16", "other"];

async function signedMember(ctx: Ctx, action: string) {
  const { data, device } = await signedByActiveDevice(ctx, action);
  const serverId = id(data.server_id, "server");
  const member = await requireMember(ctx.own, serverId, ctx.user.id);
  const parts = await serverParts(ctx.sr, serverId);
  return { data, device, serverId, member, parts, perms: permsOf(parts, member) };
}

const isMod = (perms: number) => (perms & MOD_PERMS) !== 0;
function requireMod(perms: number) {
  if (!isMod(perms)) throw new ApiError(403, "MISSING_PERMISSION", "Only moderators can do that.");
}

/**
 * Who a report about targetId goes to: moderators (by permission, highest roles first) who have
 * finished setting up encryption, never the person reported, at most 31.
 */
async function moderatorsOf(sr: any, parts: any, { exclude = [] as string[] } = {}) {
  const modRoles = parts.roles.filter((r: any) => !r.is_everyone && (Number(r.permissions) & MOD_PERMS)).map((r: any) => r.id);
  const rows = modRoles.length ? await sr.entities.ServerMember.filter({ server_id: parts.server.id, role_ids: { $in: modRoles } }, "joined_at", 300) : [];
  if (parts.server.owner_id && !rows.some((m: any) => m.user_id === parts.server.owner_id)) {
    const owner = await memberRow(sr, parts.server.id, parts.server.owner_id);
    if (owner) rows.push(owner);
  }
  const ready = new Set((await latestKeysFor(sr, rows.map((m: any) => m.user_id))).keys());
  return rows
    .filter((m: any) => !exclude.includes(m.user_id) && ready.has(m.user_id) && isMod(permsOf(parts, m)))
    .sort((a: any, b: any) => topPosition(parts.server, parts.roles, b) - topPosition(parts.server, parts.roles, a))
    .slice(0, MOD_LIMITS.moderatorsPerReport)
    .map((m: any) => m.user_id);
}

const reportOut = (r: any, { full }: { full: boolean }) => ({
  report_id: r.report_id, server_id: r.server_id, reporter_id: r.reporter_id, target_id: r.target_id, status: r.status,
  created_date: r.created_date, handled_by: r.handled_by || "", handled_at: r.handled_at || "", recipient_ids: r.recipient_ids || [],
  ...(full ? { envelope: r.envelope, signature: r.signature, device_id: r.device_id, sent_at: r.sent_at, sender_id: r.reporter_id } : {}),
});

const caseOut = (c: any, { withReason = true } = {}) => ({
  case_id: c.id, case_number: c.case_number, action: c.action, target_id: c.target_id, actor_id: c.actor_id, minutes: Number(c.minutes) || 0,
  active: Boolean(c.active), report_id: c.report_id || "", created_at: c.created_at || c.created_date, ...(withReason ? { reason: itemOut(c, "reason") } : {}),
});

async function reasonOf(ctx: Ctx, serverId: string, item: any) {
  if (!item) return {};
  return itemFields("reason", await acceptItem(ctx, { kind: "case", serverId, item, gens: await generationsOf(ctx.sr, serverId) }));
}

/** Apply a timeout, kick or ban to a member (used by warnings' automatic steps). */
async function punish(sr: any, parts: any, target: any, action: string, minutes: number, now: Date) {
  const serverId = parts.server.id;
  if (action === "timeout") {
    await sr.entities.ServerMember.update(target.id, { timeout_until: new Date(now.getTime() + minutes * 60_000).toISOString() });
  } else if (action === "kick") {
    await removeMember(sr, serverId, target.user_id, { reason: "kicked", now });
  } else if (action === "ban") {
    const [existing] = await sr.entities.ServerBan.filter({ server_id: serverId, user_id: target.user_id }, "created_date", 1);
    const expires = minutes ? new Date(now.getTime() + minutes * 60_000).toISOString() : "";
    if (!existing) await sr.entities.ServerBan.create({ server_id: serverId, user_id: target.user_id, banned_by: "system", expires_at: expires });
    await removeMember(sr, serverId, target.user_id, { reason: "banned", now });
  }
}

export const moderationActions: Actions = {
  // ---------- reports ----------

  /** Who a report would go to, so the reporter's app can encrypt it to exactly them. */
  async report_recipients(ctx: Ctx) {
    const { sr, own, user, body } = ctx;
    const serverId = id(body.server_id, "server");
    await requireMember(own, serverId, user.id);
    const targetId = body.target_id ? id(body.target_id, "member") : "";
    const parts = await serverParts(sr, serverId);
    const mods = await moderatorsOf(sr, parts, { exclude: [user.id, targetId].filter(Boolean) });
    return { recipients: [user.id, ...mods], moderators: mods.length };
  },

  /** Send a report: an encrypted item for the moderators and you. */
  async report(ctx: Ctx) {
    const { sr, user, now } = ctx;
    const { data, serverId, parts } = await signedMember(ctx, "report");
    const targetId = id(data.target_id, "member");
    if (targetId === user.id) throw new ApiError(400, "BAD_FIELD", "You can't report yourself.");
    if ((await countSince(sr, "ServerReport", { server_id: serverId, reporter_id: user.id }, new Date(now.getTime() - 86_400_000), MOD_LIMITS.reportsPerDay)) >= MOD_LIMITS.reportsPerDay) {
      throw rateLimited("sending reports");
    }
    const mods = await moderatorsOf(sr, parts, { exclude: [user.id, targetId] });
    if (!mods.length) throw new ApiError(409, "NO_MODERATORS", "This server has no moderators who can take reports. You can report to the Commonveil team instead.");
    const recipients = [user.id, ...mods];
    const item = data.item || {};
    const reportId = randomIdField(item.item_id, "report id");
    const device = await requireActiveDevice(ctx.own, user.id, randomIdField(item.device_id, "device id"));
    const sentAt = isoTime(item.sent_at, "sent time");
    if (Math.abs(now.getTime() - Date.parse(sentAt)) > LIMITS.sentAtSkewMs) throw new ApiError(400, "CLOCK_SKEW", "Your device clock looks wrong. Check it and try again.");
    const envelope = str(item.envelope, "report", MOD_LIMITS.reportEnvelopeChars);
    const wraps = parseEnvelopeShape(envelope, MOD_LIMITS.reportEnvelopeChars);
    await assertWrapsMatchMembers(sr, wraps, recipients);
    const ok = await verifyItemSignature({
      kind: "report", conversation_id: serverId, item_id: reportId, sender_id: user.id, device_id: device.device_id, envelope, sent_at: sentAt, signature: item.signature, signPub: device.sign_pub,
    });
    if (!ok) throw new ApiError(403, "SIGNATURE_INVALID", "The report's signature didn't verify.");
    const [dup] = await sr.entities.ServerReport.filter({ server_id: serverId, report_id: reportId }, "created_date", 1);
    if (dup) return { report: reportOut(dup, { full: false }) };
    const row = await sr.entities.ServerReport.create({
      server_id: serverId, report_id: reportId, reporter_id: user.id, target_id: targetId, recipient_ids: recipients,
      envelope, signature: item.signature, device_id: device.device_id, sent_at: sentAt, status: "open", handled_by: "", handled_at: "",
    });
    await audit(sr, parts.server, user.id, "report_sent", "member", targetId, "", now);
    return { report: reportOut(row, { full: false }), moderators: mods.length };
  },

  /** Reports you can read: as a moderator, those sent to you; otherwise your own. */
  async reports(ctx: Ctx) {
    const { sr, own, user, body } = ctx;
    const serverId = id(body.server_id, "server");
    const member = await requireMember(own, serverId, user.id);
    const parts = await serverParts(sr, serverId);
    const mod = isMod(permsOf(parts, member));
    const status = body.status && STATUSES.includes(body.status) ? body.status : null;
    const rows = await sr.entities.ServerReport.filter({ server_id: serverId, ...(status ? { status } : {}) }, "-created_date", 200);
    const mine = rows.filter((r: any) => (r.recipient_ids || []).includes(user.id) && (mod || r.reporter_id === user.id));
    return { reports: mine.map((r: any) => reportOut(r, { full: true })), moderator: mod };
  },

  async set_report_status(ctx: Ctx) {
    const { sr, user, now } = ctx;
    const { data, serverId, parts, perms } = await signedMember(ctx, "set_report_status");
    requireMod(perms);
    const status = STATUSES.includes(data.status) && data.status !== "escalated" ? data.status : null;
    if (!status) throw new ApiError(400, "BAD_FIELD", "Invalid status.");
    const [row] = await sr.entities.ServerReport.filter({ server_id: serverId, report_id: randomIdField(data.report_id, "report") }, "created_date", 1);
    if (!row || !(row.recipient_ids || []).includes(user.id)) throw new ApiError(404, "NOT_FOUND", "Report not found.");
    await sr.entities.ServerReport.update(row.id, { status, handled_by: user.id, handled_at: now.toISOString() });
    await audit(sr, parts.server, user.id, `report_${status}`, "member", row.target_id, "", now);
    return { ok: true };
  },

  /**
   * Escalate to the Commonveil team. The moderator writes what to share (and may paste in what
   * was reported): that text is readable by the Commonveil team, which is the point.
   */
  async escalate(ctx: Ctx) {
    const { sr, user, now } = ctx;
    const { data, serverId, parts, perms } = await signedMember(ctx, "escalate");
    requireMod(perms);
    const [row] = data.report_id ? await sr.entities.ServerReport.filter({ server_id: serverId, report_id: randomIdField(data.report_id, "report") }, "created_date", 1) : [null];
    if (data.report_id && (!row || !(row.recipient_ids || []).includes(user.id))) throw new ApiError(404, "NOT_FOUND", "Report not found.");
    const targetId = row ? row.target_id : id(data.target_id, "member");
    const reason = REASONS.includes(data.reason) ? data.reason : null;
    if (!reason) throw new ApiError(400, "BAD_FIELD", "Choose a reason.");
    const details = cleanText(data.details, 4000);
    if (!details.trim()) throw new ApiError(400, "BAD_FIELD", "Say what happened, so the Commonveil team can act.");
    if ((await countSince(sr, "Report", { escalated_by: user.id }, new Date(now.getTime() - 86_400_000), MOD_LIMITS.escalationsPerDay)) >= MOD_LIMITS.escalationsPerDay) throw rateLimited("escalating reports");
    await sr.entities.Report.create({
      reporter_id: user.id, reported_user_id: targetId, conversation_id: "", reason: ["spam", "harassment", "illegal", "under_16"].includes(reason) ? reason : "other",
      details, status: "open", source: "server", server_id: serverId, server_report_id: row?.report_id || "", escalated_by: user.id, category: reason,
      server_name: typeof data.server_name === "string" ? data.server_name.slice(0, 100) : "",
    });
    if (row) await sr.entities.ServerReport.update(row.id, { status: "escalated", handled_by: user.id, handled_at: now.toISOString() });
    await audit(sr, parts.server, user.id, "report_escalated", "member", targetId, "", now);
    return { ok: true };
  },

  // ---------- cases ----------

  /** Warn a member, with an encrypted reason. The server's policy may then time out, kick or ban. */
  async warn(ctx: Ctx) {
    const { sr, user, now } = ctx;
    const { data, serverId, member, parts, perms } = await signedMember(ctx, "warn");
    if (!has(perms, P.TIMEOUT_MEMBERS) && !has(perms, P.KICK_MEMBERS) && !has(perms, P.BAN_MEMBERS)) throw new ApiError(403, "MISSING_PERMISSION", "You can't warn members here.");
    const targetId = id(data.user_id, "member");
    const target = await memberRow(sr, serverId, targetId);
    if (!target) throw new ApiError(404, "NOT_MEMBER", "That person isn't in this server.");
    requireAbove(parts, member, target, "warn");
    const reason = await reasonOf(ctx, serverId, data.reason);
    const c = await logCase(sr, parts.server, { action: "warn", targetId, actorId: user.id, reason, reportId: data.report_id ? randomIdField(data.report_id, "report") : "", now });
    await audit(sr, parts.server, user.id, "member_warn", "member", targetId, `case ${c.case_number}`, now);
    const { warns, step } = await thresholdFor(sr, parts.server, targetId, now);
    let applied = null;
    if (step) {
      await punish(sr, parts, target, step.action, step.minutes, now);
      const auto = await logCase(sr, parts.server, { action: step.action, targetId, actorId: "system", minutes: step.minutes, now });
      await audit(sr, parts.server, "system", `member_${step.action}`, "member", targetId, `${warns} warnings (case ${auto.case_number})`, now);
      applied = { action: step.action, minutes: step.minutes };
    }
    return { case: caseOut(c), warnings: warns, applied };
  },

  /** A private note on a member, for moderators only. */
  async note(ctx: Ctx) {
    const { sr, user, now } = ctx;
    const { data, serverId, parts, perms } = await signedMember(ctx, "note");
    requireMod(perms);
    const targetId = id(data.user_id, "member");
    if (!data.reason) throw new ApiError(400, "BAD_FIELD", "Write the note.");
    const c = await logCase(sr, parts.server, { action: "note", targetId, actorId: user.id, reason: await reasonOf(ctx, serverId, data.reason), now });
    return { case: caseOut(c) };
  },

  /** Cases: all of them (or one member's) for moderators; your own warnings for anyone. */
  async cases(ctx: Ctx) {
    const { sr, own, user, body } = ctx;
    const serverId = id(body.server_id, "server");
    const member = await requireMember(own, serverId, user.id);
    const parts = await serverParts(sr, serverId);
    if (!isMod(permsOf(parts, member))) {
      const rows = await sr.entities.ModCase.filter({ server_id: serverId, target_id: user.id, action: "warn" }, "-created_date", 100);
      return { cases: rows.map((c: any) => caseOut(c)), moderator: false };
    }
    const q: any = { server_id: serverId };
    if (body.user_id) q.target_id = id(body.user_id, "member");
    const rows = await sr.entities.ModCase.filter(q, "-created_date", 200);
    return { cases: rows.map((c: any) => caseOut(c)), moderator: true };
  },

  /** Take back a warning (it stops counting) or a note. */
  async pardon(ctx: Ctx) {
    const { sr, user, now } = ctx;
    const { data, serverId, parts, perms } = await signedMember(ctx, "pardon");
    requireMod(perms);
    const c = await sr.entities.ModCase.get(id(data.case_id, "case")).catch(() => null);
    if (!c || c.server_id !== serverId || !["warn", "note"].includes(c.action)) throw new ApiError(404, "NOT_FOUND", "Case not found.");
    await sr.entities.ModCase.update(c.id, { active: false, ...(c.action === "note" ? itemFields("reason", { envelope: "", item_id: "", sender_id: "", device_id: "", sent_at: "", signature: "" }) : {}) });
    await audit(sr, parts.server, user.id, "case_pardon", "member", c.target_id, `case ${c.case_number}`, now);
    return { ok: true };
  },

  /** Delete a member's recent messages across the server (or one channel). Nothing is read. */
  async purge(ctx: Ctx) {
    const { sr, user, now } = ctx;
    const { data, serverId, member, parts, perms } = await signedMember(ctx, "purge");
    requirePermMod(perms, P.MANAGE_MESSAGES);
    const targetId = id(data.user_id, "member");
    const target = await memberRow(sr, serverId, targetId);
    if (target) requireAbove(parts, member, target, "delete messages from");
    const seconds = [3600, 21_600, 86_400, 604_800].includes(data.seconds) ? data.seconds : null;
    if (!seconds) throw new ApiError(400, "BAD_FIELD", "Choose how far back.");
    const since = new Date(now.getTime() - seconds * 1000).toISOString().replace("Z", "");
    const q: any = { server_id: serverId, sender_id: targetId, created_date: { $gte: since } };
    if (data.channel_id) q.channel_id = id(data.channel_id, "channel");
    const rows = await sr.entities.ServerMessage.filter(q, "created_date", 1000);
    let n = 0;
    for (const m of rows) {
      if (m.deleted) continue;
      await sr.entities.ServerMessage.update(m.id, { envelope: "", signature: "", deleted: true, deleted_by: user.id, deleted_at: now.toISOString() });
      n += 1;
    }
    await logCase(sr, parts.server, { action: "purge", targetId, actorId: user.id, minutes: Math.round(seconds / 60), now });
    await audit(sr, parts.server, user.id, "messages_purge", "member", targetId, `${n} messages`, now);
    return { deleted: n };
  },

  // ---------- policy ----------

  async policy(ctx: Ctx) {
    const { sr, own, user, body } = ctx;
    const serverId = id(body.server_id, "server");
    await requireMember(own, serverId, user.id);
    const parts = await serverParts(sr, serverId);
    return { policy: policyOf(parts.server), raid_detected_at: parts.server.raid_detected_at || "" };
  },

  async set_policy(ctx: Ctx) {
    const { sr, user, now } = ctx;
    const { data, parts, perms } = await signedMember(ctx, "set_policy");
    if (!has(perms, P.MANAGE_SERVER)) throw new ApiError(403, "MISSING_PERMISSION", "You can't change moderation settings.");
    const policy = cleanPolicy(data.policy || {});
    // Only the owner can turn staff limits off, since they're what stops a rogue admin.
    if (!policy.nuke.enabled && user.id !== parts.server.owner_id) throw new ApiError(403, "OWNER_ONLY", "Only the owner can turn off staff limits.");
    await sr.entities.Server.update(parts.server.id, { mod_policy: policy, ...(data.clear_raid ? { raid_detected_at: "" } : {}) });
    await audit(sr, parts.server, user.id, "mod_policy", "server", parts.server.id, "", now);
    return { policy };
  },
};

function requirePermMod(perms: number, bit: number) {
  if (!has(perms, bit)) throw new ApiError(403, "MISSING_PERMISSION", "You don't have permission to do that.");
}

export { CASE_ACTIONS, SERVER_LIMITS };
