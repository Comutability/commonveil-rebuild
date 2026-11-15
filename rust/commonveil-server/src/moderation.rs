//! Server moderation (base44/shared/handlers/moderation.ts): reports to a server's moderators,
//! cases (warnings, notes, and a record of every timeout, kick and ban), the moderation policy,
//! purging a member's messages, and escalating a report to the Commonveil team.
//!
//! Reports are end-to-end encrypted to the server's moderators (and the reporter) with their
//! account keys: the service sees who reported whom and when, never what was said. Reasons on
//! cases are encrypted with the server's key. Escalating is the one place a moderator chooses to
//! share something readable, and the app says so first.
use serde_json::{json, Value};

use crate::api::{clean_text, id, random_id_field, str_field, Actions, ApiError, Ctx, Result};
use crate::db::{id_of, Db};
use crate::js::{number_value, to_js_string, to_number, truthy};
use crate::permissions::{has, p, top_position};
use crate::servers::{case_reason, signed_member, Signed};
use crate::servers_build::{clean_policy, log_case, policy_of, threshold_for, MOD_PERMS};
use crate::servers_core::*;
use crate::shared::{assert_wraps_match_members, count_since, ids_of, iso, latest_keys_for, or, rate_limited, require_active_device};
use crate::verify::{check_clock, iso_time, parse_envelope_shape, verify_item_signature};

pub const MODERATORS_PER_REPORT: usize = 31;
pub const REPORTS_PER_DAY: usize = 10;
pub const REPORT_ENVELOPE_CHARS: usize = 64 * 1024;
pub const ESCALATIONS_PER_DAY: usize = 20;
const STATUSES: [&str; 4] = ["open", "resolved", "dismissed", "escalated"];
const REASONS: [&str; 10] = ["spam", "harassment", "hate", "sexual", "violence", "self_harm", "scam", "illegal", "under_16", "other"];

fn deny(status: u16, code: &str, message: &str) -> ApiError {
    ApiError::new(status, code, message)
}

fn is_mod(perms: i64) -> bool {
    perms & MOD_PERMS != 0
}

fn require_mod(perms: i64) -> Result<()> {
    if is_mod(perms) {
        Ok(())
    } else {
        Err(deny(403, "MISSING_PERMISSION", "Only moderators can do that."))
    }
}

fn require_perm_mod(perms: i64, bit: i64) -> Result<()> {
    if has(perms, bit) {
        Ok(())
    } else {
        Err(deny(403, "MISSING_PERMISSION", "You don't have permission to do that."))
    }
}

/// A string `includes` check, as JavaScript's (only strings match).
fn one_of<'a>(v: &Value, list: &[&'a str]) -> Option<&'a str> {
    let s = v.as_str()?;
    list.iter().find(|x| **x == s).copied()
}

/// Who a report goes to: moderators (by permission, highest roles first) who have finished
/// setting up encryption, never the excluded people, at most 31.
fn moderators_of(sr: &Db, parts: &Parts, exclude: &[String]) -> Result<Vec<String>> {
    let mod_roles: Vec<Value> = parts.roles.iter().filter(|r| !truthy(r.get("is_everyone")) && (to_number(r.get("permissions")) as i64 & MOD_PERMS) != 0).map(|r| r["id"].clone()).collect();
    let mut rows = if mod_roles.is_empty() { vec![] } else { sr.filter("ServerMember", json!({ "server_id": parts.server["id"], "role_ids": { "$in": mod_roles } }), "joined_at", 300)? };
    let owner = to_js_string(parts.server.get("owner_id"));
    if truthy(parts.server.get("owner_id")) && !rows.iter().any(|m| m["user_id"] == owner.as_str()) {
        if let Some(o) = member_row(sr, &to_js_string(parts.server.get("id")), &owner)? {
            rows.push(o);
        }
    }
    let ids: Vec<String> = rows.iter().map(|m| to_js_string(m.get("user_id"))).collect();
    let ready = latest_keys_for(sr, &ids)?;
    let mut mods: Vec<&Value> = rows
        .iter()
        .filter(|m| {
            let uid = to_js_string(m.get("user_id"));
            !exclude.contains(&uid) && ready.contains_key(&uid) && is_mod(perms_of(parts, m, None))
        })
        .collect();
    let top = |m: &Value| top_position(&parts.server, &parts.roles, Some(m));
    mods.sort_by(|a, b| top(b).partial_cmp(&top(a)).unwrap_or(std::cmp::Ordering::Equal));
    Ok(mods.into_iter().take(MODERATORS_PER_REPORT).map(|m| to_js_string(m.get("user_id"))).collect())
}

fn copy(o: &mut Value, key: &str, row: &Value, src: &str) {
    if let Some(v) = row.get(src) {
        o[key] = v.clone();
    }
}

fn report_out(r: &Value, full: bool) -> Value {
    let mut o = json!({});
    for k in ["report_id", "server_id", "reporter_id", "target_id", "status", "created_date"] {
        copy(&mut o, k, r, k);
    }
    o["handled_by"] = or(&r["handled_by"], json!(""));
    o["handled_at"] = or(&r["handled_at"], json!(""));
    o["recipient_ids"] = or(&r["recipient_ids"], json!([]));
    if full {
        for k in ["envelope", "signature", "device_id", "sent_at"] {
            copy(&mut o, k, r, k);
        }
        copy(&mut o, "sender_id", r, "reporter_id");
    }
    o
}

fn case_out(c: &Value) -> Value {
    let mut o = json!({});
    copy(&mut o, "case_id", c, "id");
    for k in ["case_number", "action", "target_id", "actor_id"] {
        copy(&mut o, k, c, k);
    }
    o["minutes"] = num0(c.get("minutes"));
    o["active"] = json!(truthy(c.get("active")));
    o["report_id"] = or(&c["report_id"], json!(""));
    let at = or(&c["created_at"], c.get("created_date").cloned().unwrap_or(Value::Null));
    if !(at.is_null() && c.get("created_date").is_none()) {
        o["created_at"] = at;
    }
    o["reason"] = item_out(c, "reason");
    o
}

/// Apply a timeout, kick or ban to a member (warnings' automatic steps).
fn punish(ctx: &Ctx, parts: &Parts, target: &Value, action: &str, minutes: f64) -> Result<()> {
    let (sr, now) = (ctx.sr(), ctx.now);
    let server_id = to_js_string(parts.server.get("id"));
    let user_id = to_js_string(target.get("user_id"));
    match action {
        "timeout" => {
            sr.update("ServerMember", id_of(target), json!({ "timeout_until": iso(now + (minutes * 60_000.0) as i64) }))?;
        }
        "kick" => {
            remove_member(&sr, ctx.store(), &server_id, &user_id, "kicked")?;
        }
        "ban" => {
            let existing = sr.first("ServerBan", json!({ "server_id": server_id, "user_id": user_id }), "created_date")?;
            let expires = if minutes != 0.0 { iso(now + (minutes * 60_000.0) as i64) } else { String::new() };
            if existing.is_none() {
                sr.create("ServerBan", json!({ "server_id": server_id, "user_id": user_id, "banned_by": "system", "expires_at": expires }))?;
            }
            remove_member(&sr, ctx.store(), &server_id, &user_id, "banned")?;
        }
        _ => {}
    }
    Ok(())
}

// ---------- reports ----------

fn report_recipients(ctx: &mut Ctx) -> Result<Value> {
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    let server_id = id(&ctx.body["server_id"], "server")?;
    require_member(&ctx.own(), &server_id, &uid)?;
    let target = if truthy(ctx.body.get("target_id")) { id(&ctx.body["target_id"], "member")? } else { String::new() };
    let parts = server_parts(&sr, &server_id)?;
    let exclude: Vec<String> = [uid.clone(), target].into_iter().filter(|s| !s.is_empty()).collect();
    let mods = moderators_of(&sr, &parts, &exclude)?;
    let mut recipients = vec![uid];
    recipients.extend(mods.iter().cloned());
    Ok(json!({ "recipients": recipients, "moderators": mods.len() }))
}

fn report(ctx: &mut Ctx) -> Result<Value> {
    let Signed { data, server_id, parts, .. } = signed_member(ctx, "report")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    let target_id = id(&data["target_id"], "member")?;
    if target_id == uid {
        return Err(deny(400, "BAD_FIELD", "You can't report yourself."));
    }
    if count_since(&sr, "ServerReport", json!({ "server_id": server_id, "reporter_id": uid }), now - 86_400_000, REPORTS_PER_DAY)? >= REPORTS_PER_DAY {
        return Err(rate_limited("sending reports"));
    }
    let mods = moderators_of(&sr, &parts, &[uid.clone(), target_id.clone()])?;
    if mods.is_empty() {
        return Err(deny(409, "NO_MODERATORS", "This server has no moderators who can take reports. You can report to the Commonveil team instead."));
    }
    let mut recipients = vec![uid.clone()];
    recipients.extend(mods.iter().cloned());
    let item = if truthy(data.get("item")) { data["item"].clone() } else { json!({}) };
    let report_id = random_id_field(&item["item_id"], "report id")?;
    let device = require_active_device(&ctx.own(), &uid, &random_id_field(&item["device_id"], "device id")?)?;
    let sent_at = iso_time(&item["sent_at"], "sent time")?;
    check_clock(&sent_at, now)?;
    let envelope = str_field(&item["envelope"], "report", REPORT_ENVELOPE_CHARS, 1)?;
    let wraps = parse_envelope_shape(&envelope, REPORT_ENVELOPE_CHARS)?;
    assert_wraps_match_members(&sr, &wraps, &recipients)?;
    let signature = item.get("signature").cloned().unwrap_or(Value::Null);
    if !verify_item_signature("report", &server_id, &report_id, &uid, device["device_id"].as_str().unwrap_or(""), &envelope, &sent_at, &signature, device["sign_pub"].as_str().unwrap_or(""))? {
        return Err(deny(403, "SIGNATURE_INVALID", "The report's signature didn't verify."));
    }
    if let Some(dup) = sr.first("ServerReport", json!({ "server_id": server_id, "report_id": report_id }), "created_date")? {
        return Ok(json!({ "report": report_out(&dup, false) }));
    }
    let mut row = json!({
        "server_id": server_id, "report_id": report_id, "reporter_id": uid, "target_id": target_id, "recipient_ids": recipients,
        "envelope": envelope, "signature": signature, "device_id": device["device_id"], "sent_at": sent_at, "status": "open", "handled_by": "", "handled_at": "",
    });
    if item.get("signature").is_none() {
        row.as_object_mut().unwrap().remove("signature");
    }
    let row = sr.create("ServerReport", row)?;
    audit(&sr, &parts.server, &uid, "report_sent", "member", &target_id, "", now)?;
    Ok(json!({ "report": report_out(&row, false), "moderators": mods.len() }))
}

fn reports(ctx: &mut Ctx) -> Result<Value> {
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    let server_id = id(&ctx.body["server_id"], "server")?;
    let member = require_member(&ctx.own(), &server_id, &uid)?;
    let parts = server_parts(&sr, &server_id)?;
    let moderator = is_mod(perms_of(&parts, &member, None));
    let mut q = json!({ "server_id": server_id });
    if truthy(ctx.body.get("status")) {
        if let Some(s) = one_of(&ctx.body["status"], &STATUSES) {
            q["status"] = json!(s);
        }
    }
    let rows = sr.filter("ServerReport", q, "-created_date", 200)?;
    let mine: Vec<Value> = rows.iter().filter(|r| ids_of(&r["recipient_ids"]).contains(&uid) && (moderator || r["reporter_id"] == uid.as_str())).map(|r| report_out(r, true)).collect();
    Ok(json!({ "reports": mine, "moderator": moderator }))
}

fn set_report_status(ctx: &mut Ctx) -> Result<Value> {
    let Signed { data, server_id, parts, perms, .. } = signed_member(ctx, "set_report_status")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_mod(perms)?;
    let status = one_of(&data["status"], &STATUSES).filter(|s| *s != "escalated").ok_or_else(|| deny(400, "BAD_FIELD", "Invalid status."))?;
    let row = sr.first("ServerReport", json!({ "server_id": server_id, "report_id": random_id_field(&data["report_id"], "report")? }), "created_date")?;
    let row = row.filter(|r| ids_of(&r["recipient_ids"]).contains(&uid)).ok_or_else(|| deny(404, "NOT_FOUND", "Report not found."))?;
    sr.update("ServerReport", id_of(&row), json!({ "status": status, "handled_by": uid, "handled_at": iso(now) }))?;
    audit(&sr, &parts.server, &uid, &format!("report_{status}"), "member", &to_js_string(row.get("target_id")), "", now)?;
    Ok(json!({ "ok": true }))
}

/// The first `n` UTF-16 units of a string, as JavaScript's `slice`.
fn js_slice(s: &str, n: usize) -> String {
    let units: Vec<u16> = s.encode_utf16().take(n).collect();
    String::from_utf16_lossy(&units)
}

fn escalate(ctx: &mut Ctx) -> Result<Value> {
    let Signed { data, server_id, parts, perms, .. } = signed_member(ctx, "escalate")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_mod(perms)?;
    let has_report = truthy(data.get("report_id"));
    let row = if has_report { sr.first("ServerReport", json!({ "server_id": server_id, "report_id": random_id_field(&data["report_id"], "report")? }), "created_date")? } else { None };
    if has_report && !row.as_ref().is_some_and(|r| ids_of(&r["recipient_ids"]).contains(&uid)) {
        return Err(deny(404, "NOT_FOUND", "Report not found."));
    }
    let target_id = match &row {
        Some(r) => to_js_string(r.get("target_id")),
        None => id(&data["target_id"], "member")?,
    };
    let reason = one_of(&data["reason"], &REASONS).ok_or_else(|| deny(400, "BAD_FIELD", "Choose a reason."))?;
    let details = clean_text(&data["details"], 4000)?;
    if details.trim().is_empty() {
        return Err(deny(400, "BAD_FIELD", "Say what happened, so the Commonveil team can act."));
    }
    if count_since(&sr, "Report", json!({ "escalated_by": uid }), now - 86_400_000, ESCALATIONS_PER_DAY)? >= ESCALATIONS_PER_DAY {
        return Err(rate_limited("escalating reports"));
    }
    sr.create(
        "Report",
        json!({
            "reporter_id": uid, "reported_user_id": target_id, "conversation_id": "",
            "reason": if ["spam", "harassment", "illegal", "under_16"].contains(&reason) { reason } else { "other" },
            "details": details, "status": "open", "source": "server", "server_id": server_id,
            "server_report_id": row.as_ref().map_or(json!(""), |r| r.get("report_id").cloned().unwrap_or(json!(""))),
            "escalated_by": uid, "category": reason,
            "server_name": data["server_name"].as_str().map_or(String::new(), |s| js_slice(s, 100)),
        }),
    )?;
    if let Some(r) = &row {
        sr.update("ServerReport", id_of(r), json!({ "status": "escalated", "handled_by": uid, "handled_at": iso(now) }))?;
    }
    audit(&sr, &parts.server, &uid, "report_escalated", "member", &target_id, "", now)?;
    Ok(json!({ "ok": true }))
}

// ---------- cases ----------

fn warn(ctx: &mut Ctx) -> Result<Value> {
    let Signed { data, server_id, member, parts, perms, .. } = signed_member(ctx, "warn")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    if !has(perms, p::TIMEOUT_MEMBERS) && !has(perms, p::KICK_MEMBERS) && !has(perms, p::BAN_MEMBERS) {
        return Err(deny(403, "MISSING_PERMISSION", "You can't warn members here."));
    }
    let target_id = id(&data["user_id"], "member")?;
    let target = member_row(&sr, &server_id, &target_id)?.ok_or_else(|| deny(404, "NOT_MEMBER", "That person isn't in this server."))?;
    require_above(&parts, &member, &target, "warn")?;
    let reason = case_reason(ctx, &server_id, &data["reason"])?;
    let report_id = if truthy(data.get("report_id")) { random_id_field(&data["report_id"], "report")? } else { String::new() };
    let c = log_case(&sr, &parts.server, "warn", &target_id, &uid, json!(0), &reason, &report_id, now)?;
    audit(&sr, &parts.server, &uid, "member_warn", "member", &target_id, &format!("case {}", to_js_string(c.get("case_number"))), now)?;
    let (warns, step) = threshold_for(&sr, &parts.server, &target_id, now)?;
    let mut applied = Value::Null;
    if let Some(step) = step {
        let action = to_js_string(step.get("action"));
        let minutes = to_number(step.get("minutes"));
        punish(ctx, &parts, &target, &action, minutes)?;
        let auto = log_case(&sr, &parts.server, &action, &target_id, "system", step.get("minutes").cloned().unwrap_or(json!(0)), &json!({}), "", now)?;
        audit(&sr, &parts.server, "system", &format!("member_{action}"), "member", &target_id, &format!("{warns} warnings (case {})", to_js_string(auto.get("case_number"))), now)?;
        applied = json!({ "action": step["action"], "minutes": step["minutes"] });
    }
    Ok(json!({ "case": case_out(&c), "warnings": warns, "applied": applied }))
}

fn note(ctx: &mut Ctx) -> Result<Value> {
    let Signed { data, server_id, parts, perms, .. } = signed_member(ctx, "note")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_mod(perms)?;
    let target_id = id(&data["user_id"], "member")?;
    if !truthy(data.get("reason")) {
        return Err(deny(400, "BAD_FIELD", "Write the note."));
    }
    let reason = case_reason(ctx, &server_id, &data["reason"])?;
    let c = log_case(&sr, &parts.server, "note", &target_id, &uid, json!(0), &reason, "", now)?;
    Ok(json!({ "case": case_out(&c) }))
}

fn cases(ctx: &mut Ctx) -> Result<Value> {
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    let server_id = id(&ctx.body["server_id"], "server")?;
    let member = require_member(&ctx.own(), &server_id, &uid)?;
    let parts = server_parts(&sr, &server_id)?;
    if !is_mod(perms_of(&parts, &member, None)) {
        let rows = sr.filter("ModCase", json!({ "server_id": server_id, "target_id": uid, "action": "warn" }), "-created_date", 100)?;
        return Ok(json!({ "cases": rows.iter().map(case_out).collect::<Vec<_>>(), "moderator": false }));
    }
    let mut q = json!({ "server_id": server_id });
    if truthy(ctx.body.get("user_id")) {
        q["target_id"] = json!(id(&ctx.body["user_id"], "member")?);
    }
    let rows = sr.filter("ModCase", q, "-created_date", 200)?;
    Ok(json!({ "cases": rows.iter().map(case_out).collect::<Vec<_>>(), "moderator": true }))
}

fn pardon(ctx: &mut Ctx) -> Result<Value> {
    let Signed { data, server_id, parts, perms, .. } = signed_member(ctx, "pardon")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_mod(perms)?;
    let c = sr.get("ModCase", &id(&data["case_id"], "case")?);
    let c = c.filter(|c| c["server_id"] == server_id.as_str() && (c["action"] == "warn" || c["action"] == "note")).ok_or_else(|| deny(404, "NOT_FOUND", "Case not found."))?;
    let mut change = json!({ "active": false });
    if c["action"] == "note" {
        for (k, v) in cleared_item("reason").as_object().into_iter().flatten() {
            change[k] = v.clone();
        }
    }
    sr.update("ModCase", id_of(&c), change)?;
    audit(&sr, &parts.server, &uid, "case_pardon", "member", &to_js_string(c.get("target_id")), &format!("case {}", to_js_string(c.get("case_number"))), now)?;
    Ok(json!({ "ok": true }))
}

fn purge(ctx: &mut Ctx) -> Result<Value> {
    let Signed { data, server_id, member, parts, perms, .. } = signed_member(ctx, "purge")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_perm_mod(perms, p::MANAGE_MESSAGES)?;
    let target_id = id(&data["user_id"], "member")?;
    if let Some(target) = member_row(&sr, &server_id, &target_id)? {
        require_above(&parts, &member, &target, "delete messages from")?;
    }
    let seconds = data["seconds"].as_f64().filter(|s| [3600.0, 21_600.0, 86_400.0, 604_800.0].contains(s)).ok_or_else(|| deny(400, "BAD_FIELD", "Choose how far back."))?;
    let since = iso(now - (seconds * 1000.0) as i64).trim_end_matches('Z').to_string();
    // Only channels this moderator can see and manage messages in, as for an ordinary delete
    // (CV-12): a server-wide permission doesn't reach into channels hidden from them.
    let manageable: Vec<Value> = parts
        .channels
        .iter()
        .filter(|c| {
            let pm = perms_of(&parts, &member, Some(c));
            has(pm, p::VIEW_CHANNEL) && has(pm, p::MANAGE_MESSAGES)
        })
        .map(|c| c["id"].clone())
        .collect();
    let mut q = json!({ "server_id": server_id, "sender_id": target_id, "created_date": { "$gte": since } });
    if truthy(data.get("channel_id")) {
        let cid = id(&data["channel_id"], "channel")?;
        if !manageable.contains(&json!(cid)) {
            return Err(deny(404, "CHANNEL_NOT_FOUND", "Channel not found."));
        }
        q["channel_id"] = json!(cid);
    }
    let rows = sr.filter("ServerMessage", q, "created_date", 1000)?;
    let mut n = 0;
    for m in rows.iter().filter(|m| manageable.contains(&m["channel_id"])) {
        if truthy(m.get("deleted")) {
            continue;
        }
        sr.update("ServerMessage", id_of(m), json!({ "envelope": "", "signature": "", "deleted": true, "deleted_by": uid, "deleted_at": iso(now) }))?;
        n += 1;
    }
    log_case(&sr, &parts.server, "purge", &target_id, &uid, number_value((seconds / 60.0).round()), &json!({}), "", now)?;
    audit(&sr, &parts.server, &uid, "messages_purge", "member", &target_id, &format!("{n} messages"), now)?;
    Ok(json!({ "deleted": n }))
}

// ---------- policy ----------

fn policy(ctx: &mut Ctx) -> Result<Value> {
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    let server_id = id(&ctx.body["server_id"], "server")?;
    require_member(&ctx.own(), &server_id, &uid)?;
    let parts = server_parts(&sr, &server_id)?;
    Ok(json!({ "policy": policy_of(&parts.server), "raid_detected_at": or(&parts.server["raid_detected_at"], json!("")) }))
}

fn set_policy(ctx: &mut Ctx) -> Result<Value> {
    let Signed { data, parts, perms, .. } = signed_member(ctx, "set_policy")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    if !has(perms, p::MANAGE_SERVER) {
        return Err(deny(403, "MISSING_PERMISSION", "You can't change moderation settings."));
    }
    let raw = if truthy(data.get("policy")) { data["policy"].clone() } else { json!({}) };
    let policy = clean_policy(&raw);
    // Only the owner can turn staff limits off, since they're what stops a rogue admin.
    if !truthy(policy["nuke"].get("enabled")) && parts.server["owner_id"] != uid.as_str() {
        return Err(deny(403, "OWNER_ONLY", "Only the owner can turn off staff limits."));
    }
    let mut change = json!({ "mod_policy": policy });
    if truthy(data.get("clear_raid")) {
        change["raid_detected_at"] = json!("");
    }
    let server_row = to_js_string(parts.server.get("id"));
    sr.update("Server", &server_row, change)?;
    audit(&sr, &parts.server, &uid, "mod_policy", "server", &server_row, "", now)?;
    Ok(json!({ "policy": policy }))
}

pub fn actions() -> Actions {
    let mut a = Actions::new();
    for (name, f) in [
        ("report_recipients", report_recipients as crate::api::Action),
        ("report", report),
        ("reports", reports),
        ("set_report_status", set_report_status),
        ("escalate", escalate),
        ("warn", warn),
        ("note", note),
        ("cases", cases),
        ("pardon", pardon),
        ("purge", purge),
        ("policy", policy),
        ("set_policy", set_policy),
    ] {
        a.insert(name, f);
    }
    a
}
