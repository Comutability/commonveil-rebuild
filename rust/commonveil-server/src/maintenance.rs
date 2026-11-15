//! Scheduled clean-up (base44/shared/maintenance.ts). On Base44 these run as workflows; a
//! self-hosted server runs them on timers (`start`), as the Node.js server does:
//! - expire: delete disappearing messages whose time is up, unused call passes, audit entries
//!   past their retention, files whose message has gone, temporary bans that have run out, and
//!   sign-in leftovers past their time.
//! - inactive: accounts whose owners chose to have them deleted after a stretch without use.
//! - deliver: scheduled messages and missed check-ins that are due, and self-destructing
//!   conversations whose time is up.
//!
//! Each task only acts on what is already due by the server's clock, so a run that comes early,
//! late or twice does nothing extra.
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use serde_json::{json, Value};

use crate::api::Result;
use crate::db::{id_of, Db};
use crate::deletion::{blank, blank_and_delete_until, erase_conversation_until, purge_account, remove_platform_user};
use crate::js::{to_js_string, to_number, truthy};
use crate::shared::{day_of, iso, AUTO_DELETE_DAYS};
use crate::App;

const DAY: i64 = 24 * 3_600_000;
/// The warning goes out at least this long before an account is deleted.
pub const WARN_DAYS: i64 = 7;
/// Leave time to answer; unfinished work waits for the next run.
const BUDGET_MS: i64 = 4 * 60_000;
pub const TASKS: [&str; 3] = ["expire", "inactive", "deliver"];

fn min_gap(task: &str) -> i64 {
    if task == "inactive" { 15 * 60_000 } else { 60_000 }
}

fn wall() -> i64 {
    crate::sessions::now_ms()
}

/// Delete disappearing messages whose time is up, and the other leftovers past their time.
pub fn expire_messages(app: &App, now: i64, deadline: i64) -> Result<Value> {
    let sr = Db::service(&app.store);
    // Blanking clears expires_at, so a record whose delete failed isn't picked up again.
    let due = || json!({ "expires_at": { "$gt": "", "$lte": iso(now) } });
    let server_blank = json!({ "envelope": "", "signature": "", "deleted": true, "msg_id": "", "sender_id": "", "device_id": "", "sent_at": "", "expires_at": "", "pinned": false });
    let steps: [(&str, Value); 4] = [
        ("Message", blank("Message")),
        ("ServerMessage", server_blank),
        ("AuditEntry", json!({ "expires_at": "", "actor_id": "", "target_id": "", "detail": "" })),
        // Call passes nobody used: they last a minute, and nothing about a call is kept after it.
        ("VoiceTicket", json!({ "expires_at": "", "user_id": "", "device_id": "", "room": "" })),
    ];
    let mut counts = Vec::new();
    for (entity, b) in steps {
        match blank_and_delete_until(&sr, entity, due(), b, deadline)? {
            Some(n) => counts.push(n),
            None => return Ok(json!({ "removed": null, "done": false })),
        }
    }
    // Files whose message has gone.
    let files = crate::files::forget_orphaned_files(&sr, now, deadline)?;
    // Temporary server bans that have run out.
    let mut bans_lifted = 0;
    for b in sr.filter("ServerBan", due(), "created_date", 200)? {
        if wall() > deadline {
            break;
        }
        let _ = sr.delete("ServerBan", id_of(&b));
        bans_lifted += 1;
    }
    // Sign-in leftovers past their time: challenges, refresh tokens, notification codes, and so on.
    let mut sign_in_removed = 0;
    for entity in ["CvChallenge", "CvRefresh", "PushCode", "FedNonce", "ProtoMail"] {
        loop {
            if wall() > deadline {
                return Ok(json!({ "removed": null, "done": false }));
            }
            let rows = sr.filter(entity, due(), "created_date", 200).unwrap_or_default();
            for r in &rows {
                let _ = sr.delete(entity, id_of(r));
                sign_in_removed += 1;
            }
            if rows.len() < 200 {
                break;
            }
        }
    }
    Ok(json!({
        "removed": counts[0], "server_removed": counts[1], "audit_removed": counts[2], "passes_removed": counts[3],
        "files_removed": files, "bans_lifted": bans_lifted, "sign_in_removed": sign_in_removed, "done": true,
    }))
}

/// Accounts set to delete themselves after a stretch without use. A self-hosted site has no email
/// service, so no warning can be sent: the account is deleted a week after its time is up, as the
/// member's own setting asks.
pub fn delete_inactive_accounts(app: &App, now: i64, deadline: i64) -> Result<Value> {
    let sr = Db::service(&app.store);
    let (warned, mut deleted, mut skipped) = (0, 0, 0);
    let out = |warned: i32, deleted: i32, skipped: i32, done: bool| json!({ "warned": warned, "deleted": deleted, "skipped": skipped, "done": done });
    for days in AUTO_DELETE_DAYS.into_iter().filter(|d| *d > 0) {
        // Everyone on this setting whose warning is due: last used at least (days - WARN_DAYS) days ago.
        let warn_from = day_of(now - (days - WARN_DAYS) * DAY);
        let rows = sr.filter("Profile", json!({ "delete_after_days": days, "last_active_at": { "$gt": "", "$lte": warn_from } }), "last_active_at", 200)?;
        for p in rows {
            if wall() > deadline {
                return Ok(out(warned, deleted, skipped, false));
            }
            let start = crate::dates::parse(&format!("{}T00:00:00Z", to_js_string(p.get("last_active_at")))).unwrap_or(f64::NAN);
            let due_at = start + (days * DAY) as f64;
            let warned_at = if truthy(p.get("inactive_warned_at")) { crate::dates::parse(&to_js_string(p.get("inactive_warned_at"))).unwrap_or(f64::NAN) } else { f64::NAN };
            let user_id = to_js_string(p.get("user_id"));
            let account = crate::sessions::user_record(&app.store, &user_id);
            // Without the sign-in record there's no one to warn, and no telling staff apart: leave it.
            if account.as_ref().is_none_or(|a| a["role"] == "admin") {
                skipped += 1;
                continue;
            }
            let at = now as f64;
            if warned_at.is_nan() {
                // Email isn't available on a self-hosted site (the Node.js server has none either).
                if at < due_at + (WARN_DAYS * DAY) as f64 {
                    continue;
                }
            } else if at < due_at.max(warned_at + (WARN_DAYS * DAY) as f64) {
                continue;
            }
            // Due. Look again first, in case they signed in or changed the setting since the query.
            let fresh = sr.get("Profile", id_of(&p));
            let same = fresh.as_ref().is_some_and(|f| f["user_id"] == p["user_id"] && f["last_active_at"] == p["last_active_at"] && to_number(f.get("delete_after_days")) == days as f64);
            if !same {
                continue;
            }
            if !purge_account(&sr, &app.store, &user_id, deadline)? {
                return Ok(out(warned, deleted, skipped, false));
            }
            remove_platform_user(&sr, &app.store, &user_id);
            deleted += 1;
        }
    }
    Ok(out(warned, deleted, skipped, true))
}

/// Scheduled messages and missed check-ins that are due, and self-destructing conversations.
pub fn deliver_and_destroy(app: &App, now: i64, deadline: i64) -> Result<Value> {
    let sr = Db::service(&app.store);
    let delivered = crate::messages::deliver_due(&sr, &app.config.site_url, now, deadline, json!({}))?;
    let mut destroyed = 0;
    for c in sr.filter("Conversation", json!({ "destroy_at": { "$gt": "", "$lte": iso(now) } }), "destroy_at", 50)? {
        if wall() > deadline {
            break;
        }
        erase_conversation_until(&sr, id_of(&c), deadline)?;
        destroyed += 1;
    }
    Ok(json!({ "delivered": delivered, "destroyed": destroyed, "done": true }))
}

fn last_started() -> &'static Mutex<HashMap<String, i64>> {
    static L: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
    L.get_or_init(Default::default)
}

/// Run one task by name: `(status, answer)`. Answers with counts only, nothing about any member.
pub fn run(app: &App, task: &str, now: i64) -> (u16, Value) {
    if !TASKS.contains(&task) {
        return (400, json!({ "error": "Unknown task.", "code": "UNKNOWN_TASK" }));
    }
    let started = wall();
    {
        let mut last = last_started().lock().unwrap_or_else(|e| e.into_inner());
        if last.get(task).is_some_and(|t| started - t < min_gap(task)) {
            return (200, json!({ "task": task, "skipped": "ran recently" }));
        }
        last.insert(task.to_string(), started);
    }
    let deadline = started + BUDGET_MS;
    let result = match task {
        "expire" => expire_messages(app, now, deadline),
        "inactive" => delete_inactive_accounts(app, now, deadline),
        _ => deliver_and_destroy(app, now, deadline),
    };
    match result {
        Ok(v) => {
            let mut out = json!({ "task": task });
            for (k, val) in v.as_object().into_iter().flatten() {
                out[k] = val.clone();
            }
            (200, out)
        }
        Err(_) => {
            eprintln!("commonveil maintenance failure: {task}");
            (500, json!({ "error": "Something went wrong. The next run picks this up.", "code": "INTERNAL" }))
        }
    }
}

/// For tests: forget when tasks last started.
pub fn reset_throttle() {
    last_started().lock().unwrap_or_else(|e| e.into_inner()).clear();
}

/// Start the timers: deliver every minute, expire every half hour, inactive every six hours, each
/// first run 30 to 60 seconds after start.
pub fn start(app: &Arc<App>) {
    for (task, every) in [("deliver", 60_000u64), ("expire", 30 * 60_000), ("inactive", 6 * 3_600_000)] {
        let app = app.clone();
        let first = 30_000 + (crate::crypto::random_bytes(2).iter().fold(0u64, |a, b| a * 256 + *b as u64) % 30_000);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(first)).await;
            let mut tick = tokio::time::interval(Duration::from_millis(every));
            loop {
                tick.tick().await;
                let a = app.clone();
                let _ = tokio::task::spawn_blocking(move || run(&a, task, wall())).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn unknown_tasks_are_refused() {
        assert!(!super::TASKS.contains(&"everything"));
    }
}
