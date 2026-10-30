// Blocking and reporting, plus the staff side: reports, and erasing what removed sign-ins left behind.
import { ApiError, LIMITS, cleanText, id, type Actions } from "../http.ts";
import { conversationForMember, enforceRate, profileOf, publicProfile, rateLimited, withinRate } from "../store.ts";
import { purgeAccount } from "../accountDeletion.ts";

const REASONS = new Set(["spam", "harassment", "impersonation", "illegal", "other"]);
const STATUSES = new Set(["open", "reviewing", "resolved", "dismissed"]);
const SECURITY_STATUSES = new Set(["new", "triaged", "fixed", "closed"]);

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
    const created = await sr.entities.Report.create({
      reporter_id: user.id,
      reported_user_id: target,
      conversation_id: conversationId,
      reason,
      details,
      status: "open",
    });
    if (!(await withinRate(sr, "Report", { reporter_id: user.id }, 24 * 3600_000, LIMITS.reportsPerDay, now, created))) {
      await sr.entities.Report.delete(created.id);
      throw rateLimited("sending reports");
    }
    return { ok: true };
  },
};

function requireAdmin(user: any) {
  if (user.role !== "admin") throw new ApiError(403, "FORBIDDEN", "Staff only.");
}

/** How long one erase call may run before it returns and asks to be called again. */
const ERASE_BUDGET_MS = 45_000;
const SCAN_PAGE = 200;
const SCAN_LIMIT = 5000;

const checkFailed = () =>
  new ApiError(503, "CHECK_FAILED", "Couldn't check which sign-ins still exist, so nothing was changed. Please try again later.");

/**
 * Which of these user ids still have a Base44 sign-in. The staff member's own id is always asked
 * about too: if the platform can't find them, its answers mean nothing, and nothing may be erased.
 */
async function signInsAmong(sr: any, staffId: string, ids: string[]): Promise<Set<string>> {
  const wanted = [...new Set([staffId, ...ids])];
  let rows: any[];
  try {
    rows = await sr.entities.User.filter({ id: { $in: wanted } }, "created_date", wanted.length);
  } catch {
    throw checkFailed();
  }
  const found = new Set<string>((rows || []).map((r: any) => r?.id).filter((v: unknown): v is string => typeof v === "string"));
  if (!found.has(staffId)) throw checkFailed();
  return found;
}

/** A second, separate check for one id. Only a clear "not found" counts as gone. */
async function signInGone(sr: any, userId: string): Promise<boolean> {
  try {
    return !(await sr.entities.User.get(userId));
  } catch (err: any) {
    if (err?.status === 404) return false === true || true;
    throw checkFailed();
  }
}

export const adminActions: Actions = {
  async list_reports({ sr, user, body }) {
    requireAdmin(user);
    const query: any = {};
    if (typeof body.status === "string" && STATUSES.has(body.status)) query.status = body.status;
    const rows = await sr.entities.Report.filter(query, "-created_date", 200);
    const ids = [...new Set(rows.flatMap((r: any) => [r.reporter_id, r.reported_user_id]))];
    const profiles = ids.length ? await sr.entities.Profile.filter({ user_id: { $in: ids } }, "created_date", 500) : [];
    const name = (uid: string) => profiles.find((p: any) => p.user_id === uid)?.username || "(deleted account)";
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

  async list_security_reports({ sr, user, body }) {
    requireAdmin(user);
    const query: any = {};
    if (typeof body.status === "string" && SECURITY_STATUSES.has(body.status)) query.status = body.status;
    const rows = await sr.entities.SecurityReport.filter(query, "-created_date", 200);
    const ids = [...new Set(rows.map((r: any) => r.reporter_user_id).filter(Boolean))];
    const profiles = ids.length ? await sr.entities.Profile.filter({ user_id: { $in: ids } }, "created_date", 500) : [];
    return {
      reports: rows.map((r: any) => ({
        id: r.id,
        summary: r.summary,
        details: r.details,
        contact: r.contact || "",
        reporter: r.reporter_user_id ? profiles.find((p: any) => p.user_id === r.reporter_user_id)?.username || "(member)" : "",
        status: r.status,
        staff_note: r.staff_note || "",
        created_date: r.created_date,
      })),
    };
  },

  async update_security_report({ sr, user, body }) {
    requireAdmin(user);
    const report = await sr.entities.SecurityReport.get(id(body.report_id, "report")).catch(() => null);
    if (!report) throw new ApiError(404, "NOT_FOUND", "Report not found.");
    const status = typeof body.status === "string" && SECURITY_STATUSES.has(body.status) ? body.status : report.status;
    await sr.entities.SecurityReport.update(report.id, { status, staff_note: cleanText(body.staff_note, 2000) });
    return { report: { id: report.id, status } };
  },

  /**
   * Members whose Base44 sign-in was removed outside Commonveil (in the Base44 dashboard), so
   * their profile, keys and messages were left behind.
   */
  async list_removed_accounts({ sr, user }) {
    requireAdmin(user);
    const accounts: any[] = [];
    const seen = new Set<string>();
    let after = "";
    let scanned = 0;
    while (scanned < SCAN_LIMIT) {
      const page = await sr.entities.Profile.filter(after ? { created_date: { $gte: after } } : {}, "created_date", SCAN_PAGE);
      const fresh = page.filter((p: any) => !seen.has(p.id));
      if (!fresh.length) break;
      for (const p of fresh) seen.add(p.id);
      scanned += fresh.length;
      const present = await signInsAmong(sr, user.id, fresh.map((p: any) => p.user_id).filter(Boolean));
      for (const p of fresh) {
        if (p.user_id && !present.has(p.user_id)) {
          accounts.push({ user_id: p.user_id, username: p.username, display_name: p.display_name || "", created_date: p.created_date });
        }
      }
      after = page[page.length - 1].created_date;
      if (page.length < SCAN_PAGE) break;
    }
    return { accounts, complete: scanned < SCAN_LIMIT };
  },

  /**
   * Erase what a removed sign-in left behind, exactly as if the member had deleted their own
   * account. Refused while the sign-in exists: members delete their own accounts.
   */
  async erase_removed_account({ sr, user, body }) {
    requireAdmin(user);
    const target = id(body.user_id, "account");
    if (body.confirm !== "ERASE") throw new ApiError(400, "CONFIRM_REQUIRED", "Type ERASE to confirm.");
    const present = await signInsAmong(sr, user.id, [target]);
    if (present.has(target) || !(await signInGone(sr, target))) {
      throw new ApiError(
        409,
        "SIGN_IN_EXISTS",
        "That account can still sign in. Members delete their own accounts in Settings; to remove someone, remove their sign-in in Base44 first.",
      );
    }
    return { done: await purgeAccount(sr, target, Date.now() + ERASE_BUDGET_MS) };
  },
};
