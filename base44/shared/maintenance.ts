// Scheduled clean-up, run by the app's automations (base44/functions/maintenance):
// - expire: delete disappearing messages whose time is up. Until then the app already hides
//   them; this removes them from the database too, blanked first like any deletion. Also
//   unused call passes and server audit entries past their retention.
// - inactive: accounts whose owners chose to have them deleted after a stretch without use.
//   The sign-in address is emailed a week before; signing in keeps the account.
//
// Like every function, this one has a public address, so it takes no instructions beyond which
// task to run. Each task only acts on what is already due by the server's clock, so a call
// that comes early, late or twice does nothing extra.
import { userRecord } from "./identity/sessions.ts";
import { json } from "./http.ts";
import { BLANK, OutOfTime, blankAndDeleteAll, eraseConversation, purgeAccount, removePlatformUser } from "./accountDeletion.ts";
import { AUTO_DELETE_DAYS, dayOf } from "./store.ts";
import { emailNotice, inactiveWarningEmail } from "./notify.ts";
import { forgetOrphanedFiles } from "./handlers/files.ts";
import { deliverDue } from "./handlers/scheduled.ts";

const DAY = 24 * 3600_000;

/** The warning goes out at least this long before an account is deleted. */
export const WARN_DAYS = 7;

/** Functions are stopped after five minutes; leave time to answer. Unfinished work waits for the next run. */
const BUDGET_MS = 4 * 60_000;

/** However often the address is called, a task starts at most this often on one server. */
const MIN_GAP_MS: Record<string, number> = { expire: 60_000, inactive: 15 * 60_000, deliver: 60_000 };
const lastStarted = new Map<string, number>();

const startOfDay = (day: string) => Date.parse(`${day}T00:00:00Z`);

const BLANK_SERVER_MESSAGE = { envelope: "", signature: "", deleted: true, msg_id: "", sender_id: "", device_id: "", sent_at: "", expires_at: "", pinned: false };

/**
 * Delete disappearing messages whose time is up, in conversations and in server channels, and
 * server audit log entries past their server's retention period.
 */
export async function expireMessages(sr: any, now: Date, deadline: number) {
  // Blanking clears expires_at, so a message whose delete failed isn't picked up again.
  const due = { expires_at: { $gt: "", $lte: now.toISOString() } };
  try {
    const removed = await blankAndDeleteAll(sr, "Message", due, BLANK.Message, deadline);
    const serverRemoved = await blankAndDeleteAll(sr, "ServerMessage", due, BLANK_SERVER_MESSAGE, deadline);
    const audit = await blankAndDeleteAll(sr, "AuditEntry", due, { expires_at: "", actor_id: "", target_id: "", detail: "" }, deadline);
    // Call passes nobody used: they last a minute, and nothing about a call is kept after it.
    const passes = await blankAndDeleteAll(sr, "VoiceTicket", due, { expires_at: "", user_id: "", device_id: "", room: "" }, deadline);
    // Files whose message has gone.
    const files = await forgetOrphanedFiles(sr, now, deadline);
    // Temporary server bans that have run out.
    let bansLifted = 0;
    for (const b of await sr.entities.ServerBan.filter({ expires_at: { $gt: "", $lte: now.toISOString() } }, "created_date", 200)) {
      if (Date.now() > deadline) break;
      await sr.entities.ServerBan.delete(b.id).catch(() => null);
      bansLifted += 1;
    }
    return { removed, server_removed: serverRemoved, audit_removed: audit, passes_removed: passes, files_removed: files, bans_lifted: bansLifted, done: true };
  } catch (error) {
    if (error instanceof OutOfTime) return { removed: null, done: false };
    throw error;
  }
}

/**
 * Accounts set to delete themselves after a stretch without use. Each is warned by email first;
 * it's deleted once its time is up and a week has passed since the warning. If the email can't
 * be sent, it's tried again each run, and the account is deleted anyway a week after its time is
 * up: the member's own setting stands.
 */
export async function deleteInactiveAccounts(sr: any, now: Date, deadline: number) {
  const out = { warned: 0, deleted: 0, skipped: 0, done: true };
  const at = now.getTime();
  for (const days of AUTO_DELETE_DAYS.filter((d) => d > 0)) {
    // Everyone on this setting whose warning is due: last used at least (days - WARN_DAYS) days ago.
    const warnFrom = dayOf(new Date(at - (days - WARN_DAYS) * DAY));
    const rows = await sr.entities.Profile.filter({ delete_after_days: days, last_active_at: { $gt: "", $lte: warnFrom } }, "last_active_at", 200);
    for (const p of rows) {
      if (Date.now() > deadline) return { ...out, done: false };
      const dueAt = startOfDay(p.last_active_at) + days * DAY;
      const warnedAt = p.inactive_warned_at ? Date.parse(p.inactive_warned_at) : NaN;
      let account: any = null;
      account = await userRecord(sr, p.user_id);
      // Without the sign-in record there's no one to warn, and no telling staff apart: leave it.
      if (!account || account.role === "admin") {
        out.skipped += 1;
        continue;
      }
      if (Number.isNaN(warnedAt)) {
        const deleteOn = new Date(Math.max(dueAt, at + WARN_DAYS * DAY));
        const email = inactiveWarningEmail(deleteOn, days);
        if (await emailNotice(sr, account.email, email.subject, email.lines)) {
          await sr.entities.Profile.update(p.id, { inactive_warned_at: now.toISOString() });
          out.warned += 1;
          continue;
        }
        if (at < dueAt + WARN_DAYS * DAY) continue;
      } else if (at < Math.max(dueAt, warnedAt + WARN_DAYS * DAY)) {
        continue;
      }
      // Due. Look again first, in case they signed in or changed the setting since the query.
      let fresh: any = null;
      try {
        fresh = await sr.entities.Profile.get(p.id);
      } catch {
        fresh = null;
      }
      if (!fresh || fresh.user_id !== p.user_id || fresh.last_active_at !== p.last_active_at || Number(fresh.delete_after_days) !== days) continue;
      if (!(await purgeAccount(sr, p.user_id, deadline))) return { ...out, done: false };
      await removePlatformUser(sr, p.user_id);
      out.deleted += 1;
    }
  }
  return out;
}

const TASKS: Record<string, (sr: any, now: Date, deadline: number) => Promise<unknown>> = {
  expire: expireMessages,
  inactive: deleteInactiveAccounts,
  deliver: deliverAndDestroy,
};

/** Run one task by name. Answers with counts only: nothing about any member. */
export async function runMaintenance(sr: any, task: unknown, now: Date): Promise<Response> {
  if (typeof task !== "string" || !Object.prototype.hasOwnProperty.call(TASKS, task)) {
    return json(400, { error: "Unknown task.", code: "UNKNOWN_TASK" });
  }
  const started = Date.now();
  if (started - (lastStarted.get(task) ?? -Infinity) < MIN_GAP_MS[task]) return json(200, { task, skipped: "ran recently" });
  lastStarted.set(task, started);
  try {
    const result = await TASKS[task](sr, now, started + BUDGET_MS);
    return json(200, { task, ...(result as object) });
  } catch (error) {
    const message = String((error as any)?.message || "");
    if (/rate limit|too many requests|429/i.test(message)) {
      console.warn("commonveil maintenance busy", { task });
      return json(429, { error: "Busy. The next run picks this up.", code: "UPSTREAM_BUSY" });
    }
    console.error("commonveil maintenance failure", { task, name: (error as any)?.name || "Error" });
    return json(500, { error: "Something went wrong. The next run picks this up.", code: "INTERNAL" });
  }
}

/**
 * deliver: scheduled messages and missed check-ins that are due, and self-destructing
 * conversations whose time is up (everything in them, blanked first).
 */
export async function deliverAndDestroy(sr: any, now: Date, deadline: number) {
  const delivered = await deliverDue(sr, now, deadline);
  let destroyed = 0;
  for (const c of await sr.entities.Conversation.filter({ destroy_at: { $gt: "", $lte: now.toISOString() } }, "destroy_at", 50)) {
    if (Date.now() > deadline) break;
    await eraseConversation(sr, c.id, deadline);
    destroyed += 1;
  }
  return { delivered, destroyed, done: true };
}

/** For tests: forget when tasks last started. */
export function resetMaintenanceThrottle() {
  lastStarted.clear();
}
