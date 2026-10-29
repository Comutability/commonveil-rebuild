// Blocking and reporting, plus the staff side of reports.
import { ApiError, LIMITS, cleanText, id, type Actions } from "../http.ts";
import { conversationForMember, enforceRate, profileOf, publicProfile } from "../store.ts";

const REASONS = new Set(["spam", "harassment", "impersonation", "illegal", "other"]);
const STATUSES = new Set(["open", "reviewing", "resolved", "dismissed"]);

export const safetyActions: Actions = {
  async block({ sr, user, body }) {
    const target = id(body.user_id, "member");
    if (target === user.id) throw new ApiError(400, "BAD_FIELD", "You can't block yourself.");
    if (!(await profileOf(sr, target))) throw new ApiError(404, "NOT_FOUND", "Member not found.");
    const existing = await sr.entities.Block.filter({ user_id: user.id, blocked_user_id: target }, "created_date", 1);
    if (!existing.length) await sr.entities.Block.create({ user_id: user.id, blocked_user_id: target });
    return { ok: true };
  },

  async unblock({ sr, user, body }) {
    const target = id(body.user_id, "member");
    const rows = await sr.entities.Block.filter({ user_id: user.id, blocked_user_id: target }, "created_date", 10);
    for (const r of rows) await sr.entities.Block.delete(r.id);
    return { ok: true };
  },

  async list_blocks({ sr, user }) {
    const rows = await sr.entities.Block.filter({ user_id: user.id }, "-created_date", 500);
    const ids = rows.map((r: any) => r.blocked_user_id);
    const profiles = ids.length ? await sr.entities.Profile.filter({ user_id: { $in: ids } }, "created_date", 500) : [];
    return { blocked: profiles.map(publicProfile) };
  },

  /** Reports carry only what the reporter chooses to share; staff can't read your messages. */
  async report({ sr, user, body, now }) {
    const target = id(body.user_id, "member");
    if (target === user.id) throw new ApiError(400, "BAD_FIELD", "You can't report yourself.");
    if (!(await profileOf(sr, target))) throw new ApiError(404, "NOT_FOUND", "Member not found.");
    const reason = typeof body.reason === "string" && REASONS.has(body.reason) ? body.reason : null;
    if (!reason) throw new ApiError(400, "BAD_FIELD", "Choose a reason.");
    let conversationId = "";
    if (body.conversation_id !== undefined && body.conversation_id !== null && body.conversation_id !== "") {
      const conv = await conversationForMember(sr, user.id, id(body.conversation_id, "conversation"));
      if (!conv.member_ids.includes(target)) throw new ApiError(400, "BAD_FIELD", "That member isn't in this conversation.");
      conversationId = conv.id;
    }
    const details = cleanText(body.details, 2000);
    await enforceRate(sr, "Report", { reporter_id: user.id }, 24 * 3600_000, LIMITS.reportsPerDay, now, "sending reports");
    await sr.entities.Report.create({
      reporter_id: user.id,
      reported_user_id: target,
      conversation_id: conversationId,
      reason,
      details,
      status: "open",
    });
    return { ok: true };
  },
};

function requireAdmin(user: any) {
  if (user.role !== "admin") throw new ApiError(403, "FORBIDDEN", "Staff only.");
}

export const adminActions: Actions = {
  async list_reports({ sr, user, body }) {
    requireAdmin(user);
    const query: any = {};
    if (typeof body.status === "string" && STATUSES.has(body.status)) query.status = body.status;
    const rows = await sr.entities.Report.filter(query, "-created_date", 200);
    const ids = [...new Set(rows.flatMap((r: any) => [r.reporter_id, r.reported_user_id]))];
    const profiles = ids.length ? await sr.entities.Profile.filter({ user_id: { $in: ids } }, "created_date", 500) : [];
    const name = (uid: string) => profiles.find((p: any) => p.user_id === uid)?.username || "(no username)";
    return {
      reports: rows.map((r: any) => ({
        id: r.id,
        reporter: name(r.reporter_id),
        reported_user_id: r.reported_user_id,
        reported: name(r.reported_user_id),
        reason: r.reason,
        details: r.details || "",
        status: r.status,
        resolution_note: r.resolution_note || "",
        created_date: r.created_date,
      })),
    };
  },

  async update_report({ sr, user, body }) {
    requireAdmin(user);
    const report = await sr.entities.Report.get(id(body.report_id, "report")).catch(() => null);
    if (!report) throw new ApiError(404, "NOT_FOUND", "Report not found.");
    const status = typeof body.status === "string" && STATUSES.has(body.status) ? body.status : report.status;
    const updated = await sr.entities.Report.update(report.id, {
      status,
      resolution_note: cleanText(body.resolution_note, 1000),
      handled_by: user.id,
    });
    return { report: { id: report.id, status: updated.status ?? status } };
  },
};
