//! Servers (communities): membership, keys, roles, channels, settings, moderation, invites,
//! discovery and support tickets (base44/shared/handlers/servers.ts). Content is end-to-end
//! encrypted on members' devices; this code stores ciphertext, enforces permissions and keeps
//! track of who still needs which keys.
use std::collections::HashSet;

use serde_json::{json, Value};

use crate::api::{clean_text, id, id_list, int, str_field, Actions, ApiError, Ctx, Limits, Result};
use crate::db::{id_of, merged, Db};
use crate::js::{to_js_string, to_number, truthy};
use crate::permissions::{channel_is_private, has, is_staff, p, top_position, ALL_PERMISSIONS, STAFF_PERMISSIONS};
use crate::servers_build::{add_member, check_raid, clean_admin_list, create_from_template, ensure_default_server, guard_nuke, log_case, members_who_can_see, undo_join};
use crate::servers_core::*;
use crate::shared::{account_keys_of, by_age, count_since, iso, latest_keys_for, or, platform_ms, profile_of, rate_limited, with_row};
use crate::verify::{is_kem_sealed, iso_time, signed_by_active_device, valid_sealed, verify_sig};

const DAY: i64 = 86_400_000;
const INVITE_AGES: [f64; 7] = [1800.0, 3600.0, 21_600.0, 43_200.0, 86_400.0, 604_800.0, 0.0];
const INVITE_USES: [f64; 7] = [0.0, 1.0, 5.0, 10.0, 25.0, 50.0, 100.0];
const ACCOUNT_AGE_CHOICES: [f64; 5] = [0.0, 5.0, 10.0, 60.0, 1440.0];
const MEMBER_AGE_CHOICES: [f64; 3] = [0.0, 10.0, 60.0];
const DELETE_HISTORY_CHOICES: [f64; 4] = [0.0, 3600.0, 86_400.0, 604_800.0];

pub(crate) fn deny(status: u16, code: &str, message: &str) -> ApiError {
    ApiError::new(status, code, message)
}
fn plural(n: f64, one: &str, many: &str) -> String {
    format!("{} {}", to_js_string(Some(&crate::js::number_value(n))), if n == 1.0 { one } else { many })
}

/// How an invite reads in the audit log, e.g. "expires after 7 days, unlimited uses".
pub fn invite_summary(age: f64, uses: f64) -> String {
    let a = if age != 0.0 && age % 86_400.0 == 0.0 {
        format!("expires after {}", plural(age / 86_400.0, "day", "days"))
    } else if age != 0.0 && age % 3600.0 == 0.0 {
        format!("expires after {}", plural(age / 3600.0, "hour", "hours"))
    } else if age != 0.0 {
        format!("expires after {}", plural((age / 60.0).round(), "minute", "minutes"))
    } else {
        "no expiry".into()
    };
    format!("{a}, {}", if uses != 0.0 { plural(uses, "use", "uses") } else { "unlimited uses".into() })
}

/// `options.includes(value)`, or a 400.
fn choice(v: &Value, options: &[f64], name: &str) -> Result<f64> {
    v.as_f64().filter(|x| options.contains(x)).ok_or_else(|| deny(400, "BAD_FIELD", &format!("Invalid {name}.")))
}
fn choice_str<'a>(v: &Value, options: &[&'a str], name: &str) -> Result<&'a str> {
    v.as_str().and_then(|s| options.iter().find(|o| **o == s).copied()).ok_or_else(|| deny(400, "BAD_FIELD", &format!("Invalid {name}.")))
}
fn boolean(v: &Value, name: &str) -> Result<bool> {
    v.as_bool().ok_or_else(|| deny(400, "BAD_FIELD", &format!("Invalid {name}.")))
}
fn given(data: &Value, k: &str) -> bool {
    data.get(k).is_some()
}
fn nv(f: f64) -> Value {
    crate::js::number_value(f)
}
fn n0(v: Option<&Value>) -> f64 {
    let x = to_number(v);
    if x.is_nan() { 0.0 } else { x }
}

fn require_ready(sr: &Db, user_id: &str) -> Result<()> {
    if profile_of(sr, user_id)?.is_none() {
        return Err(deny(409, "PROFILE_REQUIRED", "Choose a username first."));
    }
    if account_keys_of(sr, user_id)?.is_empty() {
        return Err(deny(409, "SETUP_REQUIRED", "Finish setting up encryption first."));
    }
    Ok(())
}

/// A device-signed request about one server from one of its members.
pub(crate) struct Signed {
    pub device: Value,
    pub data: Value,
    pub server_id: String,
    pub member: Value,
    pub parts: Parts,
    pub perms: i64,
}

pub(crate) fn signed_member(ctx: &Ctx, action: &str) -> Result<Signed> {
    let (device, data) = signed_by_active_device(ctx, action, Limits::MAX_BODY_BYTES)?;
    let server_id = id(&data["server_id"], "server")?;
    let member = require_member(&ctx.own(), &server_id, ctx.user_id())?;
    let parts = server_parts(&ctx.sr(), &server_id)?;
    let perms = perms_of(&parts, &member, None);
    Ok(Signed { device, data, server_id, member, parts, perms })
}

/// A member's profile as others in the server see it, respecting their visibility choice.
pub(crate) fn card_of(profile: Option<&Value>) -> Value {
    let Some(p) = profile else { return Value::Null };
    let hidden = p["profile_visibility"] == "nobody" || p["profile_visibility"] == "conversations";
    let shown = |k: &str| if hidden { json!("") } else { or(&p[k], json!("")) };
    Obj::new()
        .copy("user_id", p, "user_id")
        .copy("username", p, "username")
        .set("display_name", shown("display_name"))
        .set("pronouns", shown("pronouns"))
        .set("bio", shown("bio"))
        .set("accent_color", or(&p["accent_color"], json!("")))
        .set("avatar_emoji", shown("avatar_emoji"))
        .set("avatar_image", shown("avatar_image"))
        .done()
}

pub(crate) fn profiles_for(sr: &Db, user_ids: &[Value]) -> Result<Vec<Value>> {
    if user_ids.is_empty() {
        return Ok(vec![]);
    }
    sr.filter("Profile", json!({ "user_id": { "$in": user_ids } }), "created_date", user_ids.len() + 10)
}

/// `${chain_id}|${Number(generation)}` for a grant as sent.
fn grant_key_of(g: &Value) -> String {
    format!("{}|{}", to_js_string(g.get("chain_id")), to_js_string(Some(&crate::servers_core::num(g.get("generation")))).replace("null", "NaN"))
}

pub(crate) struct Checked {
    pub accepted: Vec<Value>,
    pub skipped: usize,
    pub members: Vec<Value>,
}

/// Validate grants sent by a member, against what each recipient should have. `creating`: the
/// "chain|generation" the caller is making right now.
pub(crate) fn check_grants(ctx: &Ctx, parts: &Parts, device: &Value, raw: &Value, gens: &[Value], allow_chain: &dyn Fn(&str) -> bool, creating: Option<&str>) -> Result<Checked> {
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    let Some(list) = raw.as_array().filter(|a| a.len() <= GRANTS_PER_REQUEST) else { return Err(deny(400, "BAD_FIELD", "Too many keys in one go.")) };
    let sid = id_of(&parts.server).to_string();
    let mut recipients: Vec<String> = Vec::new();
    for g in list {
        if let Some(r) = g.get("recipient_id").and_then(Value::as_str) {
            if !recipients.iter().any(|x| x == r) {
                recipients.push(r.to_string());
            }
        }
    }
    let members = if recipients.is_empty() { vec![] } else { sr.filter("ServerMember", json!({ "server_id": sid, "user_id": { "$in": recipients } }), "created_date", recipients.len() + 5)? };
    let existing = if recipients.is_empty() {
        vec![]
    } else {
        let mut with_me = recipients.clone();
        with_me.push(uid.clone());
        sr.filter("KeyGrant", json!({ "server_id": sid, "user_id": { "$in": with_me } }), "created_date", 5000)?
    };
    let latest = if recipients.is_empty() { Default::default() } else { latest_keys_for(&sr, &recipients)? };
    let mine: Vec<&Value> = existing.iter().filter(|g| g["user_id"] == uid.as_str()).collect();
    let mut accepted = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut skipped = 0;
    let bad = || deny(400, "BAD_GRANT", "Invalid key.");
    for g in list {
        if !truthy(Some(g)) || !(g.is_object() || g.is_array()) {
            return Err(bad());
        }
        let chain = parse_chain_id(&g["chain_id"]);
        let chain_text = to_js_string(g.get("chain_id"));
        if chain.as_ref().is_none_or(|c| c.server_id != sid) || !allow_chain(&chain_text) {
            return Err(deny(400, "BAD_GRANT", "That key isn't for this server."));
        }
        let generation = int(&g["generation"], "generation", 0, 1_000_000)?;
        let step = int(&g["step"], "step", 0, 200_000)?;
        let recipient = id(&g["recipient_id"], "member")?;
        let key = grant_key_of(g);
        if !gens.iter().any(|x| x["chain_id"] == g["chain_id"] && to_number(x.get("generation")) == generation as f64) {
            return Err(deny(409, "STALE_SERVER_KEYS", "This server's keys changed. Refreshing and trying again."));
        }
        let held_step = match mine.iter().find(|x| grant_key_of(x) == key) {
            Some(x) => Some(to_number(x.get("step"))),
            None => creating.filter(|c| *c == key).map(|_| 0.0),
        };
        if held_step.is_none_or(|s| s > step as f64) {
            return Err(deny(403, "NOT_HELD", "You can only pass on keys you have."));
        }
        let target = members.iter().find(|m| m["user_id"] == recipient.as_str());
        let refused = |t: &Value| t["refused_grantors"].as_array().is_some_and(|r| r.iter().any(|x| x == uid.as_str()));
        let Some(target) = target.filter(|t| !refused(t)) else {
            skipped += 1;
            continue;
        };
        let want = expected_grants(parts, target, gens).into_iter().find(|(c, gn, _)| grant_key(c, *gn) == key);
        let already = existing.iter().any(|x| x["user_id"] == recipient.as_str() && grant_key_of(x) == key) || seen.contains(&format!("{recipient}|{key}"));
        if want.as_ref().is_none_or(|w| w.2 != step) || already {
            skipped += 1;
            continue;
        }
        let stale = || deny(409, "STALE_KEYS", "Someone's keys changed. Refreshing and trying again.");
        let current = latest.get(&recipient).ok_or_else(stale)?;
        if to_number(g.get("recipient_key_version")) != to_number(current.get("version")) {
            return Err(stale());
        }
        let sealed_text = str_field(&g["sealed"], "sealed key", 4096, 1)?;
        let sealed: Value = serde_json::from_str(&sealed_text).unwrap_or(Value::Null);
        if !valid_sealed(&sealed) {
            return Err(deny(400, "BAD_GRANT", "Invalid sealed key."));
        }
        if truthy(current.get("kem_pub")) && !is_kem_sealed(&sealed) {
            return Err(stale());
        }
        if g["grantor_id"] != uid.as_str() || g["grantor_device_id"] != device["device_id"] {
            return Err(bad());
        }
        let granted_at = iso_time(&g["granted_at"], "time")?;
        if (now as f64 - crate::dates::parse(&granted_at).unwrap_or(f64::NAN)).abs() > crate::verify::SENT_AT_SKEW_MS as f64 {
            return Err(deny(400, "CLOCK_SKEW", "Your device clock looks wrong. Check it and try again."));
        }
        let version = num(current.get("version"));
        let text = secure_net_core::cv::canonical::key_grant_text(&json!({
            "server_id": sid, "chain_id": chain_text, "generation": generation, "step": step, "recipient_id": recipient, "recipient_key_version": version,
            "sealed_hash": secure_net_core::cv::encoding::sha256_b64(&sealed_text), "grantor_id": uid, "grantor_device_id": device["device_id"], "granted_at": granted_at,
        }))
        .map_err(|e| ApiError { status: 500, code: "INTERNAL".into(), message: e.message })?;
        if !verify_sig(device["sign_pub"].as_str().unwrap_or(""), &g["signature"], &text) {
            return Err(deny(403, "SIGNATURE_INVALID", "A key's signature didn't verify."));
        }
        seen.insert(format!("{recipient}|{key}"));
        let mut row = json!({
            "server_id": sid, "chain_id": chain_text, "generation": generation, "step": step, "recipient_key_version": version,
            "sealed": sealed_text, "grantor_id": uid, "grantor_device_id": device["device_id"], "granted_at": granted_at, "signature": g["signature"],
        });
        if g.get("signature").is_none() {
            row.as_object_mut().unwrap().remove("signature");
        }
        row["user_id"] = json!(recipient);
        accepted.push(row);
    }
    Ok(Checked { accepted, skipped, members })
}

/// What a member's app needs to show a server. Read with their own access.
pub(crate) fn state_for(own: &Db, server_id: &str, user_id: &str, now: i64) -> Result<Value> {
    let member = require_member(own, server_id, user_id)?;
    let servers = own.filter("Server", json!({ "audience_id": server_id }), "created_date", 1)?;
    let roles = own.filter("Role", json!({ "server_id": server_id }), "position", ROLES_PER_SERVER + 5)?;
    let channels = own.filter("Channel", json!({ "server_id": server_id }), "position", CHANNELS_PER_SERVER + 5)?;
    let chains = own.filter("KeyChain", json!({ "server_id": server_id }), "created_date", CHANNELS_PER_SERVER + 5)?;
    let mut gens = own.filter("KeyGeneration", json!({ "server_id": server_id }), "created_date", 2000)?;
    let grants = own.filter("KeyGrant", json!({ "server_id": server_id, "user_id": user_id }), "created_date", 2000)?;
    let Some(server) = servers.into_iter().next().filter(|s| s["status"] != "deleting") else { return Err(deny(404, "SERVER_NOT_FOUND", "Server not found.")) };
    gens.sort_by(by_age);
    let mut seen: HashSet<String> = HashSet::new();
    let generations: Vec<Value> = gens.iter().filter(|g| seen.insert(format!("{}|{}", to_js_string(g.get("chain_id")), to_js_string(g.get("generation"))))).map(generation_out).collect();
    Ok(json!({
        "server": server_out(&server, true),
        "member": member_out(&member, true, now),
        "roles": roles.iter().map(role_out).collect::<Vec<_>>(),
        "channels": channels.iter().map(channel_out).collect::<Vec<_>>(),
        "chains": chains.iter().map(chain_out).collect::<Vec<_>>(),
        "generations": generations,
        "grants": grants.iter().map(grant_out).collect::<Vec<_>>(),
    }))
}

/// Everyone in a server whose access to private channels may have changed: refresh it and their keys.
pub(crate) fn after_access_change(sr: &Db, store: &crate::store::Store, server_id: &str, user_ids: &[String], now: i64) -> Result<()> {
    let mut parts = server_parts(sr, server_id)?;
    let mut before: Vec<(String, Vec<String>)> = Vec::new();
    let mut members: Vec<Value> = Vec::new();
    let mut unique: Vec<&String> = Vec::new();
    for u in user_ids {
        if !unique.contains(&u) {
            unique.push(u);
        }
    }
    for uid in unique {
        let Some(m) = member_row(sr, server_id, uid)? else { continue };
        members.push(m);
        let record = crate::sessions::user_record(store, uid);
        let access: Vec<String> = record.as_ref().map(|u| crate::shared::ids_of(&u["cv_access"])).unwrap_or_default().into_iter().filter(|x| parts.channels.iter().any(|c| c["id"] == x.as_str())).collect();
        before.push((uid.clone(), access));
    }
    let mut lost: Vec<String> = Vec::new();
    for m in &members {
        let after: HashSet<String> = visible_private(&parts, m).into_iter().collect();
        let uid = to_js_string(m.get("user_id"));
        for had in before.iter().find(|(u, _)| *u == uid).map(|(_, a)| a.clone()).unwrap_or_default() {
            let chain = channel_chain_id(server_id, &had);
            if !after.contains(&had) && !lost.contains(&chain) {
                lost.push(chain);
            }
        }
        refresh_access(sr, store, &uid)?;
    }
    if !lost.is_empty() {
        need_rotation(sr, server_id, &lost, "access")?;
    }
    refresh_key_status(sr, &mut parts, &members, now)?;
    Ok(())
}

/// Staff limits hit: take away every role this member has (the owner can give them back).
fn strip_roles(sr: &Db, store: &crate::store::Store, server_id: &str, member: &Value, now: i64) -> Result<()> {
    sr.update("ServerMember", id_of(member), json!({ "role_ids": [] }))?;
    after_access_change(sr, store, server_id, &[to_js_string(member.get("user_id"))], now)
}

/// An optional encrypted reason for a moderation case.
pub(crate) fn case_reason(ctx: &Ctx, server_id: &str, item: &Value) -> Result<Value> {
    if !truthy(Some(item)) {
        return Ok(json!({}));
    }
    let gens = generations_of(&ctx.sr(), server_id, None)?;
    let accepted = accept_item(&ctx.own(), ctx.user_id(), ctx.now, "case", server_id, "", item, &gens, None, MAX_ITEM_ENVELOPE_CHARS)?;
    Ok(item_fields("reason", &accepted))
}

/// Checks for a role's settings that apply whether it's new or changed.
fn role_changes(parts: &Parts, actor: &Value, data: &Value) -> Result<Value> {
    let mut changes = json!({});
    if given(data, "permissions") {
        let perms = int(&data["permissions"], "permissions", 0, ALL_PERMISSIONS)? & ALL_PERMISSIONS;
        let mine = perms_of(parts, actor, None);
        if perms & !mine != 0 {
            return Err(deny(403, "MISSING_PERMISSION", "You can't give a role permissions you don't have."));
        }
        changes["permissions"] = json!(perms);
    }
    if given(data, "hoist") {
        changes["hoist"] = json!(boolean(&data["hoist"], "hoist")?);
    }
    if given(data, "mentionable") {
        changes["mentionable"] = json!(boolean(&data["mentionable"], "mentionable")?);
    }
    Ok(changes)
}

/// Who may set a channel's permission overwrites, and to what (CV-11).
fn check_overwrites(parts: &Parts, member: &Value, channel: Option<&Value>, next: &[Value]) -> Result<()> {
    let before: Vec<Value> = channel.and_then(|c| c["overwrites"].as_array().cloned()).unwrap_or_default();
    let find = |list: &[Value], rid: &Value| list.iter().find(|o| o["role_id"] == *rid).cloned();
    // A Map of the old entries keeps the last one for a repeated role.
    let last_before = |rid: &Value| before.iter().rev().find(|o| o["role_id"] == *rid).cloned();
    let mut changed_ids: Vec<Value> = Vec::new();
    for o in next {
        let changed = match last_before(&o["role_id"]) {
            None => true,
            Some(b) => to_number(b.get("allow")) != to_number(o.get("allow")) || to_number(b.get("deny")) != to_number(o.get("deny")),
        };
        if changed && !changed_ids.contains(&o["role_id"]) {
            changed_ids.push(o["role_id"].clone());
        }
    }
    let mut seen_before: Vec<Value> = Vec::new();
    for b in &before {
        // A Map keeps the last entry for a repeated role; its keys are each role once.
        if seen_before.contains(&b["role_id"]) {
            continue;
        }
        seen_before.push(b["role_id"].clone());
        if !next.iter().any(|o| o["role_id"] == b["role_id"]) && !changed_ids.contains(&b["role_id"]) {
            changed_ids.push(b["role_id"].clone());
        }
    }
    if changed_ids.is_empty() {
        return Ok(());
    }
    if !has(perms_of(parts, member, None), p::MANAGE_ROLES) {
        return Err(deny(403, "MISSING_PERMISSION", "You need permission to manage roles to change who can do what in a channel."));
    }
    let mine = perms_of(parts, member, channel);
    let top = top_position(&parts.server, &parts.roles, Some(member));
    for rid in &changed_ids {
        if let Some(role) = parts.roles.iter().find(|r| r["id"] == *rid) {
            if !truthy(role.get("is_everyone")) && n0(role.get("position")) >= top {
                return Err(deny(403, "HIERARCHY", "You can only change permissions for roles below your own."));
            }
        }
        let was = last_before(rid).unwrap_or(json!({ "allow": 0, "deny": 0 }));
        let now = find(next, rid).unwrap_or(json!({ "allow": 0, "deny": 0 }));
        let bits = |v: &Value, k: &str| n0(v.get(k)) as i64;
        let changed = (bits(&was, "allow") ^ bits(&now, "allow")) | (bits(&was, "deny") ^ bits(&now, "deny"));
        if changed & !mine != 0 {
            return Err(deny(403, "MISSING_PERMISSION", "You can't allow or deny permissions you don't have here."));
        }
    }
    Ok(())
}

fn require_channel_manager(parts: &Parts, member: &Value, channel: &Value) -> Result<()> {
    let pm = perms_of(parts, member, Some(channel));
    if !has(pm, p::VIEW_CHANNEL) || !has(pm, p::MANAGE_CHANNELS) {
        return Err(deny(403, "MISSING_PERMISSION", "You don't have permission to manage this channel."));
    }
    Ok(())
}

fn overwrites_from(parts: &Parts, raw: &Value) -> Result<Vec<Value>> {
    let Some(list) = raw.as_array().filter(|a| a.len() <= 50) else { return Err(deny(400, "BAD_FIELD", "Invalid permissions.")) };
    let mut out: Vec<Value> = Vec::new();
    for o in list {
        let role_id = id(&o["role_id"], "role")?;
        if !parts.roles.iter().any(|r| r["id"] == role_id.as_str()) {
            return Err(deny(404, "ROLE_NOT_FOUND", "Role not found."));
        }
        if out.iter().any(|x| x["role_id"] == role_id.as_str()) {
            continue;
        }
        let nz = |v: &Value| if v.is_null() { json!(0) } else { v.clone() };
        let allow = int(&nz(&o["allow"]), "allow", 0, ALL_PERMISSIONS)? & ALL_PERMISSIONS;
        let deny_bits = int(&nz(&o["deny"]), "deny", 0, ALL_PERMISSIONS)? & ALL_PERMISSIONS;
        out.push(json!({ "role_id": role_id, "allow": allow, "deny": deny_bits }));
    }
    Ok(out)
}

/// Move a channel between public and private: its rows' audience, its key chain and who can read it.
fn apply_privacy(ctx: &Ctx, parts: &Parts, channel: &mut Value, now_private: bool, before: &[Value]) -> Result<()> {
    let (sr, store, now) = (ctx.sr(), ctx.store(), ctx.now);
    let sid = id_of(&parts.server).to_string();
    let cid = id_of(channel).to_string();
    let audience = if now_private { cid.clone() } else { sid.clone() };
    if truthy(channel.get("private")) != now_private || channel["audience_id"] != audience.as_str() {
        sr.update("Channel", &cid, json!({ "private": now_private, "audience_id": audience }))?;
        store.update_many("ServerMessage", &json!({ "channel_id": cid }), &json!({ "$set": { "audience_id": audience } }))?;
        channel["private"] = json!(now_private);
        channel["audience_id"] = json!(audience);
    }
    if now_private {
        let chain_id = channel_chain_id(&sid, &cid);
        if sr.first("KeyChain", json!({ "server_id": sid, "chain_id": chain_id }), "created_date")?.is_none() {
            sr.create("KeyChain", json!({ "server_id": sid, "audience_id": cid, "chain_id": chain_id, "kind": "c", "channel_id": cid, "rotation_needed": false }))?;
        }
    }
    let fresh = server_parts(&sr, &sid)?;
    let ch = fresh.channels.iter().find(|c| c["id"] == cid.as_str()).cloned().unwrap_or_else(|| channel.clone());
    let after = if now_private { members_who_can_see(&sr, &fresh, &ch)? } else { vec![] };
    let mut affected: Vec<String> = Vec::new();
    for m in before.iter().chain(after.iter()) {
        let u = to_js_string(m.get("user_id"));
        if !affected.contains(&u) {
            affected.push(u);
        }
    }
    after_access_change(&sr, store, &sid, &affected, now)
}

// ---------- the actions ----------

fn admin_emails(ctx: &Ctx) -> Vec<String> {
    clean_admin_list(&ctx.app.config.default_server_admins)
}

/// Everyone joins the community server once, the first time they open the app after setup.
fn join_default_once(ctx: &Ctx) -> Result<()> {
    let (sr, own, uid, now) = (ctx.sr(), ctx.own(), ctx.user_id().to_string(), ctx.now);
    let Some(profile) = own.first("Profile", json!({ "user_id": uid }), "created_date")? else { return Ok(()) };
    if truthy(profile.get("default_server_done")) {
        return Ok(());
    }
    if own.filter("AccountKey", json!({ "user_id": uid }), "version", 1)?.is_empty() {
        return Ok(());
    }
    let server = ensure_default_server(&sr, now)?;
    let user = ctx.user.clone().unwrap_or(Value::Null);
    if let Err(e) = add_member(&sr, ctx.store(), &server, &user, profile["default_listed"] == true, &admin_emails(ctx), now, "") {
        // Paused or full: try again next time. Banned: that's that.
        if e.code != "BANNED" {
            return Ok(());
        }
    }
    sr.update("Profile", id_of(&profile), json!({ "default_server_done": true }))?;
    Ok(())
}

fn list(ctx: &mut Ctx) -> Result<Value> {
    join_default_once(ctx)?;
    let (own, uid, now) = (ctx.own(), ctx.user_id().to_string(), ctx.now);
    let members = own.filter("ServerMember", json!({ "user_id": uid }), "created_date", SERVERS_PER_USER + 10)?;
    let mut ids: Vec<Value> = Vec::new();
    for m in &members {
        if !ids.contains(&m["server_id"]) {
            ids.push(m["server_id"].clone());
        }
    }
    let servers = if ids.is_empty() { vec![] } else { own.filter("Server", json!({ "audience_id": { "$in": ids } }), "created_date", ids.len() + 5)? };
    Ok(json!({
        "servers": servers.iter().filter(|s| s["status"] != "deleting").map(|s| server_out(s, false)).collect::<Vec<_>>(),
        "members": members.iter().map(|m| member_out(m, true, now)).collect::<Vec<_>>(),
    }))
}

fn state(ctx: &mut Ctx) -> Result<Value> {
    state_for(&ctx.own(), &id(&ctx.body["server_id"], "server")?, ctx.user_id(), ctx.now)
}

fn create_server(ctx: &mut Ctx) -> Result<Value> {
    let (_, data) = signed_by_active_device(ctx, "create_server", Limits::MAX_BODY_BYTES)?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_ready(&sr, &uid)?;
    let key = if data["template"].is_null() { json!("blank") } else { data["template"].clone() };
    let name = choice_str(&key, &["blank", "friends", "study", "community"], "template")?;
    let template = crate::servers_template::starter(name).ok_or_else(|| deny(400, "BAD_FIELD", "Invalid template."))?;
    if sr.filter("ServerMember", json!({ "user_id": uid }), "created_date", SERVERS_PER_USER + 1)?.len() >= SERVERS_PER_USER {
        return Err(deny(409, "TOO_MANY_SERVERS", &format!("You can be in up to {SERVERS_PER_USER} servers.")));
    }
    if count_since(&sr, "Server", json!({ "owner_id": uid }), now - DAY, SERVERS_CREATED_PER_DAY)? >= SERVERS_CREATED_PER_DAY {
        return Err(rate_limited("creating servers"));
    }
    let server = create_from_template(&sr, &template, &uid, false, now)?;
    let sid = id_of(&server).to_string();
    sr.create("ServerMember", json!({ "server_id": sid, "user_id": uid, "role_ids": [], "joined_at": iso(now), "listed": true, "rules_accepted_at": iso(now), "timeout_until": "", "key_status": "pending" }))?;
    sr.update("Server", &sid, json!({ "member_count": 1, "keys_pending_at": iso(now) }))?;
    refresh_access(&sr, ctx.store(), &uid)?;
    audit(&sr, &server, &uid, "server_create", "server", &sid, name, now)?;
    Ok(json!({ "server_id": sid }))
}

// ---------- keys ----------

fn create_generation(ctx: &mut Ctx) -> Result<Value> {
    let Signed { device, data, server_id, member, mut parts, perms } = signed_member(ctx, "create_generation")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    let g = &data["generation"];
    if !truthy(Some(g)) || !(g.is_object() || g.is_array()) {
        return Err(deny(400, "BAD_FIELD", "Missing key generation."));
    }
    let chain_id = str_field(&g["chain_id"], "key chain", 140, 1)?;
    let chain = parse_chain_id(&json!(chain_id)).filter(|c| c.server_id == server_id).ok_or_else(|| deny(400, "BAD_FIELD", "That key chain isn't this server's."))?;
    if !chains_for(&parts, &member).contains(&chain_id) {
        return Err(deny(403, "MISSING_PERMISSION", "You can't read that channel."));
    }
    let chain_row = sr.first("KeyChain", json!({ "server_id": server_id, "chain_id": chain_id }), "created_date")?.ok_or_else(|| deny(404, "NOT_FOUND", "That key chain doesn't exist."))?;
    let gens = generations_of(&sr, &server_id, None)?;
    let latest = latest_generation(&gens, &chain_id).cloned();
    let generation = int(&g["generation"], "generation", 0, 1_000_000)?;
    let expected = latest.as_ref().map_or(0.0, |l| to_number(l.get("generation")) + 1.0);
    if generation as f64 != expected {
        return Err(deny(409, "GENERATION_TAKEN", "Someone else just renewed these keys. Refreshing."));
    }
    if generation > 0 {
        require_perm(perms, p::MANAGE_KEYS, "renew this server's keys")?;
    } else if !can_hand_out_keys(&parts, &member) {
        require_perm(perms, p::MANAGE_KEYS, "set up this server's keys")?;
    }
    let started_at = iso_time(&g["started_at"], "start time")?;
    let started = crate::dates::parse(&started_at).unwrap_or(f64::NAN);
    if (now as f64 - started).abs() > crate::verify::SENT_AT_SKEW_MS as f64 {
        return Err(deny(400, "CLOCK_SKEW", "Your device clock looks wrong. Check it and try again."));
    }
    if let Some(l) = &latest {
        if started <= crate::dates::parse(&to_js_string(l.get("started_at"))).unwrap_or(f64::NAN) {
            return Err(deny(400, "BAD_FIELD", "Invalid start time."));
        }
    }
    let commit = g["commit"].as_str().filter(|c| crate::verify::b64_bytes(&json!(c)).is_some_and(|b| b.len() == 32)).ok_or_else(|| deny(400, "BAD_FIELD", "Invalid key commitment."))?.to_string();
    let mut statement = json!({ "server_id": server_id, "chain_id": chain_id, "generation": generation, "started_at": started_at, "commit": commit, "creator_id": uid, "device_id": device["device_id"], "signature": g["signature"] });
    if g.get("signature").is_none() {
        statement.as_object_mut().unwrap().remove("signature");
    }
    let text = secure_net_core::cv::canonical::chain_generation_text(&statement).map_err(|e| ApiError { status: 500, code: "INTERNAL".into(), message: e.message })?;
    if g["creator_id"] != uid.as_str() || g["device_id"] != device["device_id"] || !verify_sig(device["sign_pub"].as_str().unwrap_or(""), &g["signature"], &text) {
        return Err(deny(403, "SIGNATURE_INVALID", "The key generation's signature didn't verify."));
    }
    let audience = if chain.kind == "c" { chain.channel_id.clone() } else { server_id.clone() };
    let row = sr.create("KeyGeneration", merged(&statement, &json!({ "audience_id": audience })))?;
    let same = with_row(sr.filter("KeyGeneration", json!({ "server_id": server_id, "chain_id": chain_id, "generation": generation }), "created_date", 5)?, &row);
    if same[0]["id"] != row["id"] {
        sr.delete("KeyGeneration", id_of(&row))?;
        return Err(deny(409, "GENERATION_TAKEN", "Someone else just renewed these keys. Refreshing."));
    }
    let mut all = gens.clone();
    all.push(row.clone());
    let creating = grant_key(&chain_id, generation as f64);
    let checked = match check_grants(ctx, &parts, &device, &data["grants"], &all, &|c| c == chain_id, Some(&creating)) {
        Ok(c) => c,
        Err(e) => {
            sr.delete("KeyGeneration", id_of(&row))?;
            return Err(e);
        }
    };
    if !checked.accepted.iter().any(|x| x["user_id"] == uid.as_str() && x["generation"] == generation) {
        sr.delete("KeyGeneration", id_of(&row))?;
        return Err(deny(400, "BAD_FIELD", "Keep a copy of the new key for yourself."));
    }
    for a in &checked.accepted {
        sr.create("KeyGrant", a.clone())?;
    }
    if truthy(chain_row.get("rotation_needed")) {
        sr.update("KeyChain", id_of(&chain_row), json!({ "rotation_needed": false, "rotation_reason": "" }))?;
    }
    ctx.store().update_many("ServerMember", &json!({ "server_id": server_id }), &json!({ "$set": { "key_status": "pending" } }))?;
    sr.update("Server", id_of(&parts.server), json!({ "keys_pending_at": iso(now) }))?;
    // As read before every member was marked pending, as the JavaScript passes them.
    let mut members = checked.members.clone();
    members.push(member.clone());
    refresh_key_status(&sr, &mut parts, &members, now)?;
    if generation > 0 {
        audit(&sr, &parts.server, &uid, "keys_renewed", "chain", &chain_id, &format!("generation {generation}"), now)?;
    }
    Ok(json!({ "generation": generation_out(&row), "granted": checked.accepted.len() }))
}

fn pending_grants(ctx: &mut Ctx) -> Result<Value> {
    let (sr, own, uid) = (ctx.sr(), ctx.own(), ctx.user_id().to_string());
    let server_id = id(&ctx.body["server_id"], "server")?;
    let me = require_member(&own, &server_id, &uid)?;
    let parts = server_parts(&sr, &server_id)?;
    if !can_hand_out_keys(&parts, &me) {
        return Ok(json!({ "items": [], "recipients": {}, "staff_only": true }));
    }
    if !truthy(parts.server.get("keys_pending_at")) {
        return Ok(json!({ "items": [], "recipients": {} }));
    }
    let pending = sr.filter("ServerMember", json!({ "server_id": server_id, "key_status": "pending" }), "joined_at", 60)?;
    if pending.is_empty() {
        sr.update("Server", id_of(&parts.server), json!({ "keys_pending_at": "" }))?;
        return Ok(json!({ "items": [], "recipients": {} }));
    }
    let gens = generations_of(&sr, &server_id, None)?;
    let mut ids: Vec<Value> = pending.iter().map(|m| m["user_id"].clone()).collect();
    ids.push(json!(uid));
    let grants = sr.filter("KeyGrant", json!({ "server_id": server_id, "user_id": { "$in": ids } }), "created_date", 5000)?;
    let mut held: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
    for g in &grants {
        if g["user_id"] == uid.as_str() {
            held.insert(grant_key(&to_js_string(g.get("chain_id")), to_number(g.get("generation"))), to_number(g.get("step")));
        }
    }
    let mut items: Vec<Value> = Vec::new();
    let mut people: Vec<String> = Vec::new();
    let mut still_waiting = 0;
    for m in &pending {
        let missing = missing_grants(&parts, m, &gens, &grants);
        if missing.is_empty() {
            sr.update("ServerMember", id_of(m), json!({ "key_status": "ok" }))?;
            continue;
        }
        still_waiting += 1;
        let mu = to_js_string(m.get("user_id"));
        if mu == uid {
            continue;
        }
        let doable: Vec<&Expected> = missing.iter().filter(|(c, g, s)| held.get(&grant_key(c, *g)).is_some_and(|h| *h <= *s as f64)).collect();
        if doable.is_empty() || people.len() >= PENDING_BATCH {
            continue;
        }
        if !people.contains(&mu) {
            people.push(mu.clone());
        }
        for (c, g, s) in doable {
            items.push(json!({ "user_id": mu, "chain_id": c, "generation": nv(*g), "step": s }));
        }
    }
    if still_waiting == 0 {
        sr.update("Server", id_of(&parts.server), json!({ "keys_pending_at": "" }))?;
    }
    let latest = if people.is_empty() { Default::default() } else { latest_keys_for(&sr, &people)? };
    let mut recipients = serde_json::Map::new();
    for u in &people {
        if let Some(k) = latest.get(u) {
            let v = to_number(k.get("version"));
            if v != 0.0 && !v.is_nan() {
                recipients.insert(u.clone(), nv(v));
            } else {
                recipients.insert(u.clone(), num(k.get("version")));
            }
        }
    }
    let items: Vec<Value> = items.into_iter().filter(|i| recipients.get(i["user_id"].as_str().unwrap_or("")).is_some_and(|v| truthy(Some(v)))).collect();
    Ok(json!({ "items": items, "recipients": recipients }))
}

fn grant_keys(ctx: &mut Ctx) -> Result<Value> {
    let Signed { device, data, server_id, member, mut parts, perms } = signed_member(ctx, "grant_keys")?;
    let (sr, now) = (ctx.sr(), ctx.now);
    if !can_hand_out_keys(&parts, &member) {
        require_perm(perms, p::MANAGE_KEYS, "hand out this server's keys")?;
    }
    let gens = generations_of(&sr, &server_id, None)?;
    let chains: HashSet<String> = chains_for(&parts, &member).into_iter().collect();
    let checked = check_grants(ctx, &parts, &device, &data["grants"], &gens, &|c| chains.contains(c), None)?;
    for a in &checked.accepted {
        sr.create("KeyGrant", a.clone())?;
    }
    refresh_key_status(&sr, &mut parts, &checked.members, now)?;
    Ok(json!({ "accepted": checked.accepted.len(), "skipped": checked.skipped }))
}

fn request_keys(ctx: &mut Ctx) -> Result<Value> {
    let Signed { data, server_id, member, mut parts, .. } = signed_member(ctx, "request_keys")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    let ids = id_list(&data["grant_ids"], "keys", 2000)?;
    let bad = if given(&data, "bad_grant_ids") { id_list(&data["bad_grant_ids"], "keys", 2000)? } else { vec![] };
    let mut refused: Vec<String> = Vec::new();
    for r in member["refused_grantors"].as_array().into_iter().flatten() {
        let r = to_js_string(Some(r));
        if !refused.contains(&r) {
            refused.push(r);
        }
    }
    for g in sr.filter("KeyGrant", json!({ "server_id": server_id, "user_id": uid }), "created_date", 2000)? {
        let gid = id_of(&g).to_string();
        if ids.contains(&gid) || bad.contains(&gid) {
            sr.delete("KeyGrant", &gid)?;
        }
        let grantor = to_js_string(g.get("grantor_id"));
        if bad.contains(&gid) && truthy(g.get("grantor_id")) && grantor != uid && !refused.contains(&grantor) {
            refused.push(grantor);
        }
    }
    let had = member["refused_grantors"].as_array().map_or(0, |a| a.len());
    if refused.len() != had {
        let keep: Vec<String> = refused[refused.len().saturating_sub(50)..].to_vec();
        sr.update("ServerMember", id_of(&member), json!({ "refused_grantors": keep }))?;
    }
    refresh_key_status(&sr, &mut parts, std::slice::from_ref(&member), now)?;
    Ok(json!({ "ok": true }))
}

// ---------- joining and leaving ----------

fn code_ok(v: &Value) -> Option<String> {
    v.as_str().filter(|c| (8..=16).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_alphanumeric())).map(String::from)
}

fn join_server(ctx: &mut Ctx) -> Result<Value> {
    let (_, data) = signed_by_active_device(ctx, "join_server", Limits::MAX_BODY_BYTES)?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_ready(&sr, &uid)?;
    if count_since(&sr, "ServerMember", json!({ "user_id": uid }), now - 3_600_000, JOINS_PER_HOUR)? >= JOINS_PER_HOUR {
        return Err(rate_limited("joining servers"));
    }
    let mut invite: Option<Value> = None;
    let server = if given(&data, "invite_code") {
        let Some(code) = code_ok(&data["invite_code"]) else { return Err(deny(404, "INVITE_INVALID", "That invite isn't valid.")) };
        let inv = sr.first("Invite", json!({ "code": code }), "created_date")?;
        let expired = inv.as_ref().is_some_and(|i| truthy(i.get("expires_at")) && platform_ms(&i["expires_at"]) <= now as f64);
        let used = inv.as_ref().is_some_and(|i| to_number(i.get("max_uses")) > 0.0 && to_number(i.get("uses")) >= to_number(i.get("max_uses")));
        let Some(inv) = inv.filter(|i| !truthy(i.get("revoked")) && !expired && !used) else { return Err(deny(404, "INVITE_INVALID", "That invite has expired or isn't valid.")) };
        let server = server_by_id(&sr, &to_js_string(inv.get("server_id")))?;
        if truthy(server.get("invites_paused")) {
            return Err(deny(403, "INVITES_PAUSED", "This server's invites are paused."));
        }
        invite = Some(inv);
        server
    } else {
        let server = server_by_id(&sr, &id(&data["server_id"], "server")?)?;
        if server["join_mode"] != "open" || !(truthy(server.get("discoverable")) || truthy(server.get("is_default"))) {
            return Err(deny(403, "INVITE_REQUIRED", "You need an invite to join this server."));
        }
        server
    };
    let profile = profile_of(&sr, &uid)?;
    let user = ctx.user.clone().unwrap_or(Value::Null);
    let via = invite.as_ref().map(|i| to_js_string(i.get("id"))).unwrap_or_default();
    let joined = add_member(&sr, ctx.store(), &server, &user, profile.as_ref().is_some_and(|p| p["default_listed"] == true), &admin_emails(ctx), now, &via)?;
    let sid = id_of(&server).to_string();
    if let (true, Some(inv)) = (joined.joined, &invite) {
        let mut used = sr.filter("ServerMember", json!({ "server_id": sid, "via_invite": inv["id"] }), "created_date", 5000)?;
        used.sort_by(by_age);
        let all = with_row(used, &joined.member);
        let mine = all.iter().position(|m| m["id"] == joined.member["id"]).map_or(-1, |i| i as i64);
        let max = n0(inv.get("max_uses"));
        if max > 0.0 && mine as f64 >= max {
            undo_join(&sr, ctx.store(), &server, &joined.member)?;
            return Err(deny(404, "INVITE_INVALID", "That invite has expired or isn't valid."));
        }
        let uses = if max > 0.0 { max.min(all.len() as f64) } else { all.len() as f64 };
        sr.update("Invite", id_of(inv), json!({ "uses": nv(uses) }))?;
    }
    if joined.joined {
        check_raid(&sr, &server, now)?;
    }
    if let Some(p) = &profile {
        if truthy(server.get("is_default")) && !truthy(p.get("default_server_done")) {
            sr.update("Profile", id_of(p), json!({ "default_server_done": true }))?;
        }
    }
    Ok(json!({ "server_id": sid, "member": member_out(&joined.member, true, now), "joined": joined.joined }))
}

fn leave_server(ctx: &mut Ctx) -> Result<Value> {
    let Signed { server_id, parts, .. } = signed_member(ctx, "leave_server")?;
    if parts.server["owner_id"] == ctx.user_id() {
        return Err(deny(409, "OWNER_CANNOT_LEAVE", "Transfer ownership first, or delete the server."));
    }
    remove_member(&ctx.sr(), ctx.store(), &server_id, ctx.user_id(), "left")?;
    Ok(json!({ "ok": true }))
}

fn accept_rules(ctx: &mut Ctx) -> Result<Value> {
    let Signed { member, .. } = signed_member(ctx, "accept_rules")?;
    ctx.sr().update("ServerMember", id_of(&member), json!({ "rules_accepted_at": iso(ctx.now) }))?;
    Ok(json!({ "ok": true }))
}

fn set_listed(ctx: &mut Ctx) -> Result<Value> {
    let Signed { data, member, .. } = signed_member(ctx, "set_listed")?;
    ctx.sr().update("ServerMember", id_of(&member), json!({ "listed": boolean(&data["listed"], "choice")? }))?;
    Ok(json!({ "ok": true }))
}

fn gens_now(ctx: &Ctx, server_id: &str) -> Result<Vec<Value>> {
    generations_of(&ctx.sr(), server_id, None)
}
fn accept(ctx: &Ctx, kind: &str, server_id: &str, item: &Value, max: usize) -> Result<Value> {
    let gens = gens_now(ctx, server_id)?;
    accept_item(&ctx.own(), ctx.user_id(), ctx.now, kind, server_id, "", item, &gens, None, max)
}

fn set_nickname(ctx: &mut Ctx) -> Result<Value> {
    let Signed { data, server_id, member, parts, perms, .. } = signed_member(ctx, "set_nickname")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    let target_id = if given(&data, "user_id") { id(&data["user_id"], "member")? } else { uid.clone() };
    let target = if target_id == uid { Some(member.clone()) } else { member_row(&sr, &server_id, &target_id)? };
    let target = target.ok_or_else(|| deny(404, "NOT_MEMBER", "That person isn't in this server."))?;
    if target_id == uid {
        require_perm(perms, p::CHANGE_NICKNAME, "change your nickname")?;
    } else {
        require_perm(perms, p::MANAGE_NICKNAMES, "change nicknames")?;
        require_above(&parts, &member, &target, "change the nickname of")?;
    }
    let fields = if data.get("item") == Some(&Value::Null) { cleared_item("nick") } else { item_fields("nick", &accept(ctx, "nick", &server_id, &data["item"], MAX_ITEM_ENVELOPE_CHARS)?) };
    sr.update("ServerMember", id_of(&target), fields)?;
    if target_id != uid {
        audit(&sr, &parts.server, &uid, "nickname_change", "member", &target_id, "", now)?;
    }
    Ok(json!({ "ok": true }))
}

// ---------- members ----------

fn members(ctx: &mut Ctx) -> Result<Value> {
    let (sr, own, uid, now) = (ctx.sr(), ctx.own(), ctx.user_id().to_string(), ctx.now);
    let server_id = id(&ctx.body["server_id"], "server")?;
    require_member(&own, &server_id, &uid)?;
    let parts = server_parts(&sr, &server_id)?;
    let mode = or(&parts.server["member_list"], json!("opt_in"));
    let count = num0(parts.server.get("member_count"));
    if mode == "count_only" {
        return Ok(json!({ "members": [], "profiles": [], "count": count }));
    }
    let staff_roles: Vec<Value> = parts.roles.iter().filter(|r| !truthy(r.get("is_everyone")) && (n0(r.get("permissions")) as i64 & STAFF_PERMISSIONS) != 0).map(|r| r["id"].clone()).collect();
    let mut found: Vec<Value> = Vec::new();
    let mut add = |rows: Vec<Value>| {
        for m in rows {
            if !found.iter().any(|f| f["user_id"] == m["user_id"]) {
                found.push(m);
            }
        }
    };
    if !staff_roles.is_empty() {
        add(sr.filter("ServerMember", json!({ "server_id": server_id, "role_ids": { "$in": staff_roles } }), "joined_at", 500)?);
    }
    if mode == "opt_in" {
        add(sr.filter("ServerMember", json!({ "server_id": server_id, "listed": true }), "joined_at", 1000)?);
    }
    if truthy(parts.server.get("owner_id")) {
        add(sr.filter("ServerMember", json!({ "server_id": server_id, "user_id": parts.server["owner_id"] }), "joined_at", 1)?);
    }
    let list: Vec<Value> = found.into_iter().filter(|m| is_staff(&parts.server, &parts.roles, Some(m)) || (mode == "opt_in" && truthy(m.get("listed")))).collect();
    let profiles = profiles_for(&sr, &list.iter().map(|m| m["user_id"].clone()).collect::<Vec<_>>())?;
    Ok(json!({ "members": list.iter().map(|m| member_out(m, false, now)).collect::<Vec<_>>(), "profiles": profiles.iter().map(|p| card_of(Some(p))).collect::<Vec<_>>(), "count": count }))
}

fn member(ctx: &mut Ctx) -> Result<Value> {
    let (sr, own, uid, now) = (ctx.sr(), ctx.own(), ctx.user_id().to_string(), ctx.now);
    let server_id = id(&ctx.body["server_id"], "server")?;
    require_member(&own, &server_id, &uid)?;
    let target_id = id(&ctx.body["user_id"], "member")?;
    let target = member_row(&sr, &server_id, &target_id)?.ok_or_else(|| deny(404, "NOT_MEMBER", "That person isn't in this server."))?;
    let profiles = profiles_for(&sr, &[json!(target_id)])?;
    Ok(json!({ "member": member_out(&target, false, now), "profile": card_of(profiles.first()) }))
}

fn nuke_guard(ctx: &Ctx, s: &Signed) -> Result<()> {
    let (sr, store, now) = (ctx.sr(), ctx.store(), ctx.now);
    guard_nuke(&sr, &s.parts, &s.member, now, &|| strip_roles(&ctx.sr(), store, &s.server_id, &s.member, now))
}

fn kick_member(ctx: &mut Ctx) -> Result<Value> {
    let s = signed_member(ctx, "kick_member")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_perm(s.perms, p::KICK_MEMBERS, "kick members")?;
    let target_id = id(&s.data["user_id"], "member")?;
    if target_id == uid {
        return Err(deny(400, "BAD_FIELD", "To leave yourself, use Leave server."));
    }
    let target = member_row(&sr, &s.server_id, &target_id)?.ok_or_else(|| deny(404, "NOT_MEMBER", "That person isn't in this server."))?;
    require_above(&s.parts, &s.member, &target, "kick")?;
    nuke_guard(ctx, &s)?;
    let reason = case_reason(ctx, &s.server_id, &s.data["reason"])?;
    remove_member(&sr, ctx.store(), &s.server_id, &target_id, "kicked")?;
    log_case(&sr, &s.parts.server, "kick", &target_id, &uid, json!(0), &reason, "", now)?;
    audit(&sr, &s.parts.server, &uid, "member_kick", "member", &target_id, "", now)?;
    Ok(json!({ "ok": true }))
}

fn ban_member(ctx: &mut Ctx) -> Result<Value> {
    let s = signed_member(ctx, "ban_member")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_perm(s.perms, p::BAN_MEMBERS, "ban members")?;
    let target_id = id(&s.data["user_id"], "member")?;
    if target_id == uid {
        return Err(deny(400, "BAD_FIELD", "You can't ban yourself."));
    }
    let target = member_row(&sr, &s.server_id, &target_id)?;
    match &target {
        Some(t) => require_above(&s.parts, &s.member, t, "ban")?,
        None if s.parts.server["owner_id"] == target_id.as_str() => return Err(deny(403, "HIERARCHY", "You can't ban the server's owner.")),
        None => {}
    }
    let nz = |v: &Value| if v.is_null() { json!(0) } else { v.clone() };
    let delete_seconds = choice(&nz(&s.data["delete_seconds"]), &DELETE_HISTORY_CHOICES, "message history")?;
    let ban_minutes = choice(&nz(&s.data["minutes"]), &[0.0, 60.0, 1440.0, 10080.0, 43200.0], "ban length")?;
    nuke_guard(ctx, &s)?;
    let reason = if truthy(s.data.get("reason")) { item_fields("reason", &accept(ctx, "ban", &s.server_id, &s.data["reason"], MAX_ITEM_ENVELOPE_CHARS)?) } else { json!({}) };
    let existing = sr.first("ServerBan", json!({ "server_id": s.server_id, "user_id": target_id }), "created_date")?;
    let expires = if ban_minutes != 0.0 { iso(now + (ban_minutes * 60_000.0) as i64) } else { String::new() };
    match existing {
        None => {
            sr.create("ServerBan", merged(&json!({ "server_id": s.server_id, "user_id": target_id, "banned_by": uid, "expires_at": expires }), &reason))?;
        }
        Some(e) => {
            sr.update("ServerBan", id_of(&e), json!({ "expires_at": expires }))?;
        }
    }
    log_case(&sr, &s.parts.server, "ban", &target_id, &uid, nv(ban_minutes), &json!({}), "", now)?;
    if target.is_some() {
        remove_member(&sr, ctx.store(), &s.server_id, &target_id, "banned")?;
    } else {
        need_rotation(&sr, &s.server_id, &[history_chain_id(&s.server_id), live_chain_id(&s.server_id)], "banned")?;
    }
    if delete_seconds != 0.0 {
        let since = iso(now - (delete_seconds * 1000.0) as i64);
        for m in sr.filter("ServerMessage", json!({ "server_id": s.server_id, "sender_id": target_id, "created_date": { "$gte": since.trim_end_matches('Z') } }), "created_date", 1000)? {
            if !truthy(m.get("deleted")) {
                sr.update("ServerMessage", id_of(&m), json!({ "envelope": "", "signature": "", "deleted": true, "deleted_by": uid, "deleted_at": iso(now) }))?;
            }
        }
    }
    let detail = if delete_seconds != 0.0 { format!("messages from the last {} h deleted", to_js_string(Some(&nv(delete_seconds / 3600.0)))) } else { String::new() };
    audit(&sr, &s.parts.server, &uid, "member_ban", "member", &target_id, &detail, now)?;
    Ok(json!({ "ok": true }))
}

fn unban_member(ctx: &mut Ctx) -> Result<Value> {
    let s = signed_member(ctx, "unban_member")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_perm(s.perms, p::BAN_MEMBERS, "unban members")?;
    let target_id = id(&s.data["user_id"], "member")?;
    for b in sr.filter("ServerBan", json!({ "server_id": s.server_id, "user_id": target_id }), "created_date", 5)? {
        sr.delete("ServerBan", id_of(&b))?;
    }
    log_case(&sr, &s.parts.server, "unban", &target_id, &uid, json!(0), &json!({}), "", now)?;
    audit(&sr, &s.parts.server, &uid, "member_unban", "member", &target_id, "", now)?;
    Ok(json!({ "ok": true }))
}

fn bans(ctx: &mut Ctx) -> Result<Value> {
    let (sr, own, uid) = (ctx.sr(), ctx.own(), ctx.user_id().to_string());
    let server_id = id(&ctx.body["server_id"], "server")?;
    let member = require_member(&own, &server_id, &uid)?;
    let parts = server_parts(&sr, &server_id)?;
    require_perm(perms_of(&parts, &member, None), p::BAN_MEMBERS, "see bans")?;
    let rows = sr.filter("ServerBan", json!({ "server_id": server_id }), "-created_date", 500)?;
    let profiles = profiles_for(&sr, &rows.iter().map(|b| b["user_id"].clone()).collect::<Vec<_>>())?;
    let bans: Vec<Value> = rows.iter().map(|b| {
        let reason = if truthy(b.get("reason_envelope")) { item_out(b, "reason") } else { Value::Null };
        Obj::new().copy("user_id", b, "user_id").copy("banned_by", b, "banned_by").copy("created_date", b, "created_date").set("expires_at", or(&b["expires_at"], json!(""))).set("reason", reason).done()
    }).collect();
    Ok(json!({ "bans": bans, "profiles": profiles.iter().map(|p| Obj::new().copy("user_id", p, "user_id").copy("username", p, "username").done()).collect::<Vec<_>>() }))
}

fn timeout_member(ctx: &mut Ctx) -> Result<Value> {
    let s = signed_member(ctx, "timeout_member")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_perm(s.perms, p::TIMEOUT_MEMBERS, "time out members")?;
    let target_id = id(&s.data["user_id"], "member")?;
    let target = member_row(&sr, &s.server_id, &target_id)?.ok_or_else(|| deny(404, "NOT_MEMBER", "That person isn't in this server."))?;
    require_above(&s.parts, &s.member, &target, "time out")?;
    let minutes = int(&s.data["minutes"], "length", 0, TIMEOUT_MAX_DAYS * 1440)?;
    if minutes != 0 {
        nuke_guard(ctx, &s)?;
    }
    let until = if minutes != 0 { iso(now + minutes * 60_000) } else { String::new() };
    sr.update("ServerMember", id_of(&target), json!({ "timeout_until": until }))?;
    if minutes != 0 {
        let reason = case_reason(ctx, &s.server_id, &s.data["reason"])?;
        log_case(&sr, &s.parts.server, "timeout", &target_id, &uid, json!(minutes), &reason, "", now)?;
    }
    audit(&sr, &s.parts.server, &uid, if minutes != 0 { "member_timeout" } else { "member_timeout_end" }, "member", &target_id, &if minutes != 0 { format!("{minutes} min") } else { String::new() }, now)?;
    Ok(json!({ "ok": true, "timeout_until": if until.is_empty() { Value::Null } else { json!(until) } }))
}

fn set_member_roles(ctx: &mut Ctx) -> Result<Value> {
    let s = signed_member(ctx, "set_member_roles")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_perm(s.perms, p::MANAGE_ROLES, "manage roles")?;
    let target_id = id(&s.data["user_id"], "member")?;
    let target = member_row(&sr, &s.server_id, &target_id)?.ok_or_else(|| deny(404, "NOT_MEMBER", "That person isn't in this server."))?;
    if target_id != uid {
        require_above(&s.parts, &s.member, &target, "change the roles of")?;
    }
    let wanted = id_list(&s.data["role_ids"], "roles", 50)?;
    let top = top_position(&s.parts.server, &s.parts.roles, Some(&s.member));
    let current = crate::shared::ids_of(&target["role_ids"]);
    let mut all: Vec<String> = Vec::new();
    for r in wanted.iter().chain(current.iter()) {
        if !all.contains(r) {
            all.push(r.clone());
        }
    }
    for rid in &all {
        let role = s.parts.roles.iter().find(|r| r["id"] == rid.as_str());
        let Some(role) = role.filter(|r| !truthy(r.get("is_everyone"))) else {
            if wanted.contains(rid) {
                return Err(deny(404, "ROLE_NOT_FOUND", "Role not found."));
            }
            continue;
        };
        let changing = wanted.contains(rid) != current.contains(rid);
        if changing && n0(role.get("position")) >= top {
            return Err(deny(403, "HIERARCHY", "You can only give or take roles below your own."));
        }
    }
    let role_ids: Vec<String> = wanted.into_iter().filter(|rid| s.parts.roles.iter().any(|r| r["id"] == rid.as_str() && !truthy(r.get("is_everyone")))).collect();
    sr.update("ServerMember", id_of(&target), json!({ "role_ids": role_ids }))?;
    after_access_change(&sr, ctx.store(), &s.server_id, std::slice::from_ref(&target_id), now)?;
    touch_server(&sr, &s.server_id, now, json!({}))?;
    audit(&sr, &s.parts.server, &uid, "member_roles", "member", &target_id, "", now)?;
    Ok(json!({ "ok": true }))
}

// ---------- roles ----------

fn create_role(ctx: &mut Ctx) -> Result<Value> {
    let s = signed_member(ctx, "create_role")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_perm(s.perms, p::MANAGE_ROLES, "manage roles")?;
    if s.parts.roles.len() >= ROLES_PER_SERVER {
        return Err(deny(409, "TOO_MANY", &format!("A server can have up to {ROLES_PER_SERVER} roles.")));
    }
    let changes = role_changes(&s.parts, &s.member, &s.data)?;
    let top = top_position(&s.parts.server, &s.parts.roles, Some(&s.member));
    let highest = s.parts.roles.iter().filter(|r| !truthy(r.get("is_everyone"))).map(|r| n0(r.get("position"))).fold(0.0_f64, f64::max);
    let position = if top == 9_007_199_254_740_991.0 { highest + 1.0 } else { (top - 1.0).max(1.0) };
    let name = if truthy(s.data.get("item")) { item_fields("name", &accept(ctx, "role", &s.server_id, &s.data["item"], MAX_ITEM_ENVELOPE_CHARS)?) } else { json!({}) };
    let pick = |k: &str, d: Value| changes.get(k).cloned().filter(|v| !v.is_null()).unwrap_or(d);
    let row = sr.create("Role", merged(&json!({
        "server_id": s.server_id, "audience_id": s.server_id, "position": nv(position), "permissions": pick("permissions", json!(0)), "is_everyone": false, "template_key": "",
        "hoist": pick("hoist", json!(false)), "mentionable": pick("mentionable", json!(false)),
    }), &name))?;
    touch_server(&sr, &s.server_id, now, json!({}))?;
    audit(&sr, &s.parts.server, &uid, "role_create", "role", id_of(&row), "", now)?;
    Ok(json!({ "role": role_out(&row) }))
}

fn update_role(ctx: &mut Ctx) -> Result<Value> {
    let s = signed_member(ctx, "update_role")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_perm(s.perms, p::MANAGE_ROLES, "manage roles")?;
    let rid = id(&s.data["role_id"], "role")?;
    let role = s.parts.roles.iter().find(|r| r["id"] == rid.as_str()).cloned().ok_or_else(|| deny(404, "ROLE_NOT_FOUND", "Role not found."))?;
    let top = top_position(&s.parts.server, &s.parts.roles, Some(&s.member));
    let everyone = truthy(role.get("is_everyone"));
    if !everyone && n0(role.get("position")) >= top {
        return Err(deny(403, "HIERARCHY", "You can only edit roles below your own."));
    }
    let mut changes = role_changes(&s.parts, &s.member, &s.data)?;
    if given(&s.data, "item") && !everyone {
        let more = if s.data["item"].is_null() { cleared_item("name") } else { item_fields("name", &accept(ctx, "role", &s.server_id, &s.data["item"], MAX_ITEM_ENVELOPE_CHARS)?) };
        changes = merged(&changes, &more);
    }
    sr.update("Role", id_of(&role), changes.clone())?;
    if let Some(perms) = changes.get("permissions") {
        if perms.as_f64() != Some(to_number(role.get("permissions"))) {
            let q = if everyone { json!({ "server_id": s.server_id }) } else { json!({ "server_id": s.server_id, "role_ids": role["id"] }) };
            let affected: Vec<String> = sr.filter("ServerMember", q, "joined_at", 10_000)?.iter().map(|m| to_js_string(m.get("user_id"))).collect();
            if !affected.is_empty() && s.parts.channels.iter().any(|c| truthy(c.get("private"))) {
                after_access_change(&sr, ctx.store(), &s.server_id, &affected, now)?;
            }
        }
    }
    touch_server(&sr, &s.server_id, now, json!({}))?;
    let detail = changes.as_object().map(|o| o.keys().filter(|k| !k.starts_with("name_")).cloned().collect::<Vec<_>>().join(", ")).unwrap_or_default();
    audit(&sr, &s.parts.server, &uid, "role_update", "role", id_of(&role), &detail, now)?;
    Ok(json!({ "ok": true }))
}

fn delete_role(ctx: &mut Ctx) -> Result<Value> {
    let s = signed_member(ctx, "delete_role")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_perm(s.perms, p::MANAGE_ROLES, "manage roles")?;
    let rid = id(&s.data["role_id"], "role")?;
    let role = s.parts.roles.iter().find(|r| r["id"] == rid.as_str() && !truthy(r.get("is_everyone"))).cloned().ok_or_else(|| deny(404, "ROLE_NOT_FOUND", "Role not found."))?;
    if n0(role.get("position")) >= top_position(&s.parts.server, &s.parts.roles, Some(&s.member)) {
        return Err(deny(403, "HIERARCHY", "You can only delete roles below your own."));
    }
    nuke_guard(ctx, &s)?;
    let holders = sr.filter("ServerMember", json!({ "server_id": s.server_id, "role_ids": role["id"] }), "joined_at", 5000)?;
    for m in &holders {
        let kept: Vec<Value> = m["role_ids"].as_array().into_iter().flatten().filter(|r| **r != role["id"]).cloned().collect();
        sr.update("ServerMember", id_of(m), json!({ "role_ids": kept }))?;
    }
    for ch in &s.parts.channels {
        let all: Vec<Value> = ch["overwrites"].as_array().cloned().unwrap_or_default();
        let kept: Vec<Value> = all.iter().filter(|o| o["role_id"] != role["id"]).cloned().collect();
        if kept.len() != all.len() {
            sr.update("Channel", id_of(ch), json!({ "overwrites": kept }))?;
        }
    }
    sr.delete("Role", id_of(&role))?;
    if !holders.is_empty() {
        let ids: Vec<String> = holders.iter().map(|m| to_js_string(m.get("user_id"))).collect();
        after_access_change(&sr, ctx.store(), &s.server_id, &ids, now)?;
    }
    touch_server(&sr, &s.server_id, now, json!({}))?;
    audit(&sr, &s.parts.server, &uid, "role_delete", "role", id_of(&role), "", now)?;
    Ok(json!({ "ok": true }))
}

fn reorder_roles(ctx: &mut Ctx) -> Result<Value> {
    let s = signed_member(ctx, "reorder_roles")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_perm(s.perms, p::MANAGE_ROLES, "manage roles")?;
    let Some(order) = s.data["order"].as_array().filter(|o| o.len() <= ROLES_PER_SERVER) else { return Err(deny(400, "BAD_FIELD", "Invalid order.")) };
    let top = top_position(&s.parts.server, &s.parts.roles, Some(&s.member));
    for o in order {
        let rid = id(&o["id"], "role")?;
        let role = s.parts.roles.iter().find(|r| r["id"] == rid.as_str());
        let position = int(&o["position"], "position", 1, 10_000)?;
        let Some(role) = role.filter(|r| !truthy(r.get("is_everyone"))) else { return Err(deny(404, "ROLE_NOT_FOUND", "Role not found.")) };
        if n0(role.get("position")) >= top || position as f64 >= top {
            return Err(deny(403, "HIERARCHY", "You can only move roles below your own."));
        }
        if to_number(role.get("position")) != position as f64 {
            sr.update("Role", id_of(role), json!({ "position": position }))?;
        }
    }
    touch_server(&sr, &s.server_id, now, json!({}))?;
    audit(&sr, &s.parts.server, &uid, "roles_reorder", "server", &s.server_id, "", now)?;
    Ok(json!({ "ok": true }))
}

// ---------- channels ----------

fn parent_from(parts: &Parts, v: &Value) -> Result<String> {
    let pid = if truthy(Some(v)) { id(v, "category")? } else { String::new() };
    if !pid.is_empty() && !parts.channels.iter().any(|c| c["id"] == pid.as_str() && c["kind"] == "category") {
        return Err(deny(404, "CHANNEL_NOT_FOUND", "Category not found."));
    }
    Ok(pid)
}

fn create_channel(ctx: &mut Ctx) -> Result<Value> {
    let s = signed_member(ctx, "create_channel")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_perm(s.perms, p::MANAGE_CHANNELS, "manage channels")?;
    if s.parts.channels.len() >= CHANNELS_PER_SERVER {
        return Err(deny(409, "TOO_MANY", &format!("A server can have up to {CHANNELS_PER_SERVER} channels.")));
    }
    let kind = choice_str(&s.data["kind"], &CHANNEL_KINDS, "channel type")?;
    let parent_id = parent_from(&s.parts, &s.data["parent_id"])?;
    if kind == "category" && !parent_id.is_empty() {
        return Err(deny(400, "BAD_FIELD", "Categories can't go inside categories."));
    }
    let overwrites = if truthy(s.data.get("overwrites")) { overwrites_from(&s.parts, &s.data["overwrites"])? } else { vec![] };
    if let Some(parent) = s.parts.channels.iter().find(|c| !parent_id.is_empty() && c["id"] == parent_id.as_str()) {
        require_channel_manager(&s.parts, &s.member, parent)?;
    }
    check_overwrites(&s.parts, &s.member, None, &overwrites)?;
    let private = channel_is_private(&s.parts.roles, &json!({ "kind": kind, "overwrites": overwrites }));
    let history = if truthy(s.data.get("history")) { json!(choice_str(&s.data["history"], &["full", "joined"], "history setting")?) } else { or(&s.parts.server["default_history"], json!("joined")) };
    let name = if truthy(s.data.get("item")) { item_fields("name", &accept(ctx, "channel", &s.server_id, &s.data["item"], MAX_ITEM_ENVELOPE_CHARS)?) } else { json!({}) };
    let position = s.parts.channels.iter().map(|c| n0(c.get("position"))).fold(0.0_f64, f64::max) + 1.0;
    let mut row = sr.create("Channel", merged(&json!({
        "server_id": s.server_id, "audience_id": s.server_id, "kind": kind, "parent_id": parent_id, "position": nv(position), "template_key": "",
        "history": if private { json!("full") } else { history }, "private": false, "overwrites": overwrites, "slowmode_seconds": 0, "expire_seconds": 0,
        "sensitive": false, "creator_id": uid,
    }), &name))?;
    if private {
        apply_privacy(ctx, &s.parts, &mut row, true, &[])?;
    }
    touch_server(&sr, &s.server_id, now, json!({}))?;
    audit(&sr, &s.parts.server, &uid, "channel_create", "channel", id_of(&row), kind, now)?;
    row["private"] = json!(private);
    Ok(json!({ "channel": channel_out(&row) }))
}

fn update_channel(ctx: &mut Ctx) -> Result<Value> {
    let s = signed_member(ctx, "update_channel")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_perm(s.perms, p::MANAGE_CHANNELS, "manage channels")?;
    let channel = channel_in(&s.parts, &id(&s.data["channel_id"], "channel")?)?.clone();
    require_channel_manager(&s.parts, &s.member, &channel)?;
    let mut changes = json!({});
    let mut changed: Vec<&str> = Vec::new();
    let d = &s.data;
    if given(d, "item") {
        let more = if d["item"].is_null() { cleared_item("name") } else { item_fields("name", &accept(ctx, "channel", &s.server_id, &d["item"], MAX_ITEM_ENVELOPE_CHARS)?) };
        changes = merged(&changes, &more);
        changed.push("name");
    }
    if given(d, "parent_id") && channel["kind"] != "category" {
        let pid = parent_from(&s.parts, &d["parent_id"])?;
        if let Some(parent) = s.parts.channels.iter().find(|c| !pid.is_empty() && c["id"] == pid.as_str()) {
            require_channel_manager(&s.parts, &s.member, parent)?;
        }
        changes["parent_id"] = json!(pid);
        changed.push("category");
    }
    if given(d, "history") {
        changes["history"] = json!(choice_str(&d["history"], &["full", "joined"], "history setting")?);
        changed.push("history");
    }
    if given(d, "slowmode_seconds") {
        changes["slowmode_seconds"] = nv(choice(&d["slowmode_seconds"], &SLOWMODE_CHOICES, "slow mode")?);
        changed.push("slow mode");
    }
    if given(d, "expire_seconds") {
        changes["expire_seconds"] = nv(choice(&d["expire_seconds"], &CHANNEL_EXPIRY_CHOICES, "disappearing messages")?);
        changed.push("disappearing messages");
    }
    if given(d, "sensitive") {
        changes["sensitive"] = json!(boolean(&d["sensitive"], "content warning")?);
        changed.push("content warning");
    }
    let mut privacy: Option<bool> = None;
    let mut before: Vec<Value> = Vec::new();
    if given(d, "overwrites") {
        let overwrites = overwrites_from(&s.parts, &d["overwrites"])?;
        check_overwrites(&s.parts, &s.member, Some(&channel), &overwrites)?;
        let now_private = channel_is_private(&s.parts.roles, &json!({ "kind": channel["kind"], "overwrites": overwrites }));
        changes["overwrites"] = json!(overwrites);
        changed.push("permissions");
        if truthy(channel.get("private")) {
            before = members_who_can_see(&sr, &s.parts, &channel)?;
        }
        privacy = Some(now_private);
        if now_private {
            changes["history"] = json!("full");
        }
    }
    sr.update("Channel", id_of(&channel), changes.clone())?;
    if let Some(pv) = privacy {
        if pv || truthy(channel.get("private")) {
            let mut c = merged(&channel, &changes);
            apply_privacy(ctx, &s.parts, &mut c, pv, &before)?;
        }
    }
    touch_server(&sr, &s.server_id, now, json!({}))?;
    audit(&sr, &s.parts.server, &uid, "channel_update", "channel", id_of(&channel), &changed.join(", "), now)?;
    Ok(json!({ "ok": true }))
}

fn delete_channel(ctx: &mut Ctx) -> Result<Value> {
    let s = signed_member(ctx, "delete_channel")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_perm(s.perms, p::MANAGE_CHANNELS, "manage channels")?;
    let channel = channel_in(&s.parts, &id(&s.data["channel_id"], "channel")?)?.clone();
    require_channel_manager(&s.parts, &s.member, &channel)?;
    nuke_guard(ctx, &s)?;
    let cid = id_of(&channel).to_string();
    if channel["kind"] == "category" {
        for c in s.parts.channels.iter().filter(|x| x["parent_id"] == cid.as_str()) {
            sr.update("Channel", id_of(c), json!({ "parent_id": "" }))?;
        }
    }
    for m in sr.filter("ServerMessage", json!({ "channel_id": cid }), "created_date", 5000)? {
        sr.update("ServerMessage", id_of(&m), json!({ "envelope": "", "signature": "", "deleted": true }))?;
        sr.delete("ServerMessage", id_of(&m))?;
    }
    let private = truthy(channel.get("private"));
    let before = if private { members_who_can_see(&sr, &s.parts, &channel)? } else { vec![] };
    if private {
        let chain_id = channel_chain_id(&s.server_id, &cid);
        for t in ["KeyGrant", "KeyGeneration", "KeyChain"] {
            sr.delete_many(t, json!({ "server_id": s.server_id, "chain_id": chain_id }))?;
        }
    }
    sr.delete("Channel", &cid)?;
    for m in &before {
        refresh_access(&sr, ctx.store(), &to_js_string(m.get("user_id")))?;
    }
    touch_server(&sr, &s.server_id, now, json!({}))?;
    audit(&sr, &s.parts.server, &uid, "channel_delete", "channel", &cid, &to_js_string(channel.get("kind")), now)?;
    Ok(json!({ "ok": true }))
}

fn reorder_channels(ctx: &mut Ctx) -> Result<Value> {
    let s = signed_member(ctx, "reorder_channels")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_perm(s.perms, p::MANAGE_CHANNELS, "manage channels")?;
    let Some(order) = s.data["order"].as_array().filter(|o| o.len() <= CHANNELS_PER_SERVER) else { return Err(deny(400, "BAD_FIELD", "Invalid order.")) };
    for o in order {
        let ch = channel_in(&s.parts, &id(&o["id"], "channel")?)?;
        let position = int(&o["position"], "position", 0, 10_000)?;
        let parent_id = if truthy(o.get("parent_id")) { id(&o["parent_id"], "category")? } else { String::new() };
        if !parent_id.is_empty() && (ch["kind"] == "category" || !s.parts.channels.iter().any(|c| c["id"] == parent_id.as_str() && c["kind"] == "category")) {
            return Err(deny(400, "BAD_FIELD", "Invalid category."));
        }
        if to_number(ch.get("position")) != position as f64 || to_js_string(Some(&or(&ch["parent_id"], json!("")))) != parent_id {
            sr.update("Channel", id_of(ch), json!({ "position": position, "parent_id": parent_id }))?;
        }
    }
    touch_server(&sr, &s.server_id, now, json!({}))?;
    audit(&sr, &s.parts.server, &uid, "channels_reorder", "server", &s.server_id, "", now)?;
    Ok(json!({ "ok": true }))
}

// ---------- the server itself ----------

fn set_server_profile(ctx: &mut Ctx) -> Result<Value> {
    let s = signed_member(ctx, "set_server_profile")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_perm(s.perms, p::MANAGE_SERVER, "change the server's profile")?;
    let accepted = accept(ctx, "server", &s.server_id, &s.data["item"], MAX_ITEM_ENVELOPE_CHARS)?;
    sr.update("Server", id_of(&s.parts.server), merged(&item_fields("profile", &accepted), &json!({ "changed_at": iso(now) })))?;
    audit(&sr, &s.parts.server, &uid, "server_profile", "server", &s.server_id, "", now)?;
    Ok(json!({ "ok": true }))
}

fn set_server_set(ctx: &mut Ctx) -> Result<Value> {
    let s = signed_member(ctx, "set_server_set")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    let slot = choice_str(&s.data["slot"], &["emoji", "stickers", "automod", "onboarding", "icon", "banner"], "set")?;
    let picture = slot == "icon" || slot == "banner";
    let with_server = slot == "automod" || slot == "onboarding" || picture;
    let what = if picture { "change the server's pictures" } else if slot == "automod" { "change AutoMod" } else if slot == "onboarding" { "change the welcome" } else { "manage emoji and stickers" };
    require_perm(s.perms, if with_server { p::MANAGE_SERVER } else { p::MANAGE_EXPRESSIONS }, what)?;
    let max = if picture { MAX_PICTURE_ENVELOPE_CHARS } else if slot == "automod" { MAX_ITEM_ENVELOPE_CHARS } else { MAX_IMAGE_SET_ENVELOPE_CHARS };
    let fields = if s.data.get("item") == Some(&Value::Null) { cleared_item(slot) } else { item_fields(slot, &accept(ctx, slot, &s.server_id, &s.data["item"], max)?) };
    sr.update("Server", id_of(&s.parts.server), merged(&fields, &json!({ "changed_at": iso(now) })))?;
    audit(&sr, &s.parts.server, &uid, &format!("server_{slot}"), "server", &s.server_id, "", now)?;
    Ok(json!({ "ok": true }))
}

fn set_server_rules(ctx: &mut Ctx) -> Result<Value> {
    let s = signed_member(ctx, "set_server_rules")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_perm(s.perms, p::MANAGE_SERVER, "change the rules")?;
    let fields = if s.data.get("item") == Some(&Value::Null) { cleared_item("rules") } else { item_fields("rules", &accept(ctx, "rules", &s.server_id, &s.data["item"], MAX_ITEM_ENVELOPE_CHARS)?) };
    sr.update("Server", id_of(&s.parts.server), merged(&fields, &json!({ "changed_at": iso(now) })))?;
    audit(&sr, &s.parts.server, &uid, "server_rules", "server", &s.server_id, "", now)?;
    Ok(json!({ "ok": true }))
}

fn update_server_settings(ctx: &mut Ctx) -> Result<Value> {
    let sg = signed_member(ctx, "update_server_settings")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_perm(sg.perms, p::MANAGE_SERVER, "change the server's settings")?;
    let (s, d) = (&sg.parts.server, &sg.data);
    let mut changes = serde_json::Map::new();
    let is_default = truthy(s.get("is_default"));
    if given(d, "join_mode") && !is_default {
        changes.insert("join_mode".into(), json!(choice_str(&d["join_mode"], &["invite", "open"], "joining")?));
    }
    if given(d, "discoverable") && !is_default {
        changes.insert("discoverable".into(), json!(boolean(&d["discoverable"], "listing")?));
    }
    // changes.discoverable ?? s.discoverable ?? s.is_default
    let listed = match changes.get("discoverable") {
        Some(v) => truthy(Some(v)),
        None => match s.get("discoverable") {
            Some(v) if !v.is_null() => truthy(Some(v)),
            _ => is_default,
        },
    };
    if given(d, "public") {
        let pb = if truthy(d.get("public")) { d["public"].clone() } else { json!({}) };
        let name = clean_text(&pb["name"], 60)?;
        if listed && name.is_empty() {
            return Err(deny(400, "BAD_FIELD", "A listed server needs a public name."));
        }
        let mut tags: Vec<String> = Vec::new();
        if let Some(list) = pb["tags"].as_array() {
            for t in list {
                let tag = choice_str(t, &TAGS, "tag")?.to_string();
                if !tags.contains(&tag) {
                    tags.push(tag);
                }
            }
        }
        if tags.len() > 5 {
            return Err(deny(400, "BAD_FIELD", "Choose up to 5 tags."));
        }
        let icon = clean_text(&pb["icon"], 8)?;
        let color = if truthy(pb.get("color")) {
            let ok = pb["color"].as_str().is_some_and(|c| c.len() == 7 && c.starts_with('#') && c[1..].bytes().all(|b| b.is_ascii_hexdigit()));
            if !ok {
                return Err(deny(400, "BAD_FIELD", "Invalid colour."));
            }
            pb["color"].clone()
        } else {
            json!("")
        };
        changes.insert("public_name".into(), json!(name));
        changes.insert("public_description".into(), json!(clean_text(&pb["description"], 300)?));
        changes.insert("public_tags".into(), json!(tags));
        changes.insert("public_icon".into(), json!(icon));
        changes.insert("public_color".into(), color);
    }
    if changes.get("discoverable") == Some(&json!(false)) {
        for (k, v) in [("public_name", json!("")), ("public_description", json!("")), ("public_tags", json!([])), ("public_icon", json!("")), ("public_color", json!(""))] {
            changes.insert(k.into(), v);
        }
    }
    if changes.get("discoverable") == Some(&json!(true)) {
        let name = match changes.get("public_name") {
            Some(v) if !v.is_null() => v.clone(),
            _ => s["public_name"].clone(),
        };
        if !truthy(Some(&name)) {
            return Err(deny(400, "BAD_FIELD", "A listed server needs a public name."));
        }
    }
    let mut set = |k: &str, v: Value| {
        changes.insert(k.into(), v);
    };
    if given(d, "rules_required") {
        set("rules_required", json!(boolean(&d["rules_required"], "rules screening")?));
    }
    if given(d, "min_account_minutes") {
        set("min_account_minutes", nv(choice(&d["min_account_minutes"], &ACCOUNT_AGE_CHOICES, "account age")?));
    }
    if given(d, "min_member_minutes") {
        set("min_member_minutes", nv(choice(&d["min_member_minutes"], &MEMBER_AGE_CHOICES, "membership age")?));
    }
    if given(d, "invites_paused") {
        set("invites_paused", json!(boolean(&d["invites_paused"], "invites")?));
    }
    if given(d, "joins_paused") {
        set("joins_paused", json!(boolean(&d["joins_paused"], "joining")?));
    }
    if given(d, "member_list") {
        set("member_list", json!(choice_str(&d["member_list"], &["opt_in", "staff_only", "count_only"], "member list")?));
    }
    if given(d, "audit_retention_days") {
        set("audit_retention_days", nv(choice(&d["audit_retention_days"], &AUDIT_RETENTION_CHOICES, "audit log retention")?));
    }
    if given(d, "default_history") {
        set("default_history", json!(choice_str(&d["default_history"], &["full", "joined"], "history setting")?));
    }
    if given(d, "allow_member_dms") {
        set("allow_member_dms", json!(boolean(&d["allow_member_dms"], "direct messages")?));
    }
    if given(d, "key_handout") {
        set("key_handout", json!(choice_str(&d["key_handout"], &["members", "staff"], "who hands out keys")?));
    }
    if changes.is_empty() {
        return Ok(json!({ "server": server_out(s, true) }));
    }
    let changes = Value::Object(changes);
    let updated = sr.update("Server", id_of(s), merged(&changes, &json!({ "changed_at": iso(now) })))?;
    let mut keys: Vec<String> = changes.as_object().unwrap().keys().filter(|k| !k.starts_with("public_")).cloned().collect();
    if given(d, "public") {
        keys.push("listing".into());
    }
    audit(&sr, s, &uid, "server_settings", "server", id_of(s), &keys.join(", "), now)?;
    Ok(json!({ "server": server_out(&merged(&merged(s, &updated), &changes), true) }))
}

fn transfer_ownership(ctx: &mut Ctx) -> Result<Value> {
    let s = signed_member(ctx, "transfer_ownership")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    if s.parts.server["owner_id"] != uid.as_str() {
        return Err(deny(403, "NOT_OWNER", "Only the owner can hand the server on."));
    }
    let target_id = id(&s.data["user_id"], "member")?;
    if member_row(&sr, &s.server_id, &target_id)?.is_none() {
        return Err(deny(404, "NOT_MEMBER", "That person isn't in this server."));
    }
    sr.update("Server", id_of(&s.parts.server), json!({ "owner_id": target_id, "changed_at": iso(now) }))?;
    audit(&sr, &s.parts.server, &uid, "ownership_transfer", "member", &target_id, "", now)?;
    Ok(json!({ "ok": true }))
}

fn delete_server(ctx: &mut Ctx) -> Result<Value> {
    let s = signed_member(ctx, "delete_server")?;
    if s.parts.server["owner_id"] != ctx.user_id() {
        return Err(deny(403, "NOT_OWNER", "Only the owner can delete the server."));
    }
    if truthy(s.parts.server.get("is_default")) {
        return Err(deny(403, "DEFAULT_SERVER", "The community server can't be deleted."));
    }
    if s.data["confirm"] != "DELETE" {
        return Err(deny(400, "CONFIRM_REQUIRED", "Type DELETE to confirm."));
    }
    let done = erase_server(&ctx.sr(), ctx.store(), &s.parts.server, crate::sessions::now_ms() + 45_000)?;
    Ok(json!({ "done": done }))
}

// ---------- invites ----------

pub fn invite_out(i: &Value) -> Value {
    Obj::new()
        .copy("code", i, "code")
        .copy("server_id", i, "server_id")
        .copy("creator_id", i, "creator_id")
        .set("channel_id", or(&i["channel_id"], json!("")))
        .set("expires_at", or(&i["expires_at"], Value::Null))
        .set("max_uses", num0(i.get("max_uses")))
        .set("uses", num0(i.get("uses")))
        .copy("created_date", i, "created_date")
        .done()
}

/// Rough numbers: exact member counts of small servers say too much.
pub fn round_count(n: f64) -> Value {
    nv(if n < 10.0 {
        n
    } else if n < 100.0 {
        (n / 5.0).round() * 5.0
    } else if n < 1000.0 {
        (n / 10.0).round() * 10.0
    } else {
        (n / 100.0).round() * 100.0
    })
}

fn create_invite(ctx: &mut Ctx) -> Result<Value> {
    let s = signed_member(ctx, "create_invite")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    require_perm(s.perms, p::CREATE_INVITES, "create invites")?;
    if truthy(s.parts.server.get("invites_paused")) {
        return Err(deny(403, "INVITES_PAUSED", "Invites are paused in this server."));
    }
    let code = code_ok(&s.data["code"]).ok_or_else(|| deny(400, "BAD_FIELD", "Invalid invite code."))?;
    let or_null = |v: &Value, d: Value| if v.is_null() { d } else { v.clone() };
    let age = choice(&or_null(&s.data["max_age_seconds"], json!(604_800)), &INVITE_AGES, "expiry")?;
    let uses = choice(&or_null(&s.data["max_uses"], json!(0)), &INVITE_USES, "number of uses")?;
    let preview = if truthy(s.data.get("preview")) { str_field(&s.data["preview"], "preview", MAX_PREVIEW_CHARS, 1)? } else { String::new() };
    if sr.filter("Invite", json!({ "server_id": s.server_id, "revoked": false }), "created_date", INVITES_PER_SERVER + 1)?.len() >= INVITES_PER_SERVER {
        return Err(deny(409, "TOO_MANY", "This server has too many invites. Revoke some first."));
    }
    if sr.first("Invite", json!({ "code": code }), "created_date")?.is_some() {
        return Err(deny(409, "CODE_TAKEN", "Try again."));
    }
    let channel_id = if truthy(s.data.get("channel_id")) { id(&s.data["channel_id"], "channel")? } else { String::new() };
    let row = sr.create("Invite", json!({
        "server_id": s.server_id, "code": code, "creator_id": uid, "channel_id": channel_id,
        "expires_at": if age != 0.0 { iso(now + (age * 1000.0) as i64) } else { String::new() }, "max_uses": nv(uses), "uses": 0, "revoked": false, "preview": preview,
    }))?;
    audit(&sr, &s.parts.server, &uid, "invite_create", "invite", id_of(&row), &invite_summary(age, uses), now)?;
    Ok(json!({ "invite": invite_out(&row) }))
}

fn invites(ctx: &mut Ctx) -> Result<Value> {
    let (sr, own, uid, now) = (ctx.sr(), ctx.own(), ctx.user_id().to_string(), ctx.now);
    let server_id = id(&ctx.body["server_id"], "server")?;
    let member = require_member(&own, &server_id, &uid)?;
    let parts = server_parts(&sr, &server_id)?;
    let all = has(perms_of(&parts, &member, None), p::MANAGE_INVITES);
    let q = if all { json!({ "server_id": server_id, "revoked": false }) } else { json!({ "server_id": server_id, "revoked": false, "creator_id": uid }) };
    let rows = sr.filter("Invite", q, "-created_date", 500)?;
    Ok(json!({ "invites": rows.iter().filter(|i| !truthy(i.get("expires_at")) || platform_ms(&i["expires_at"]) > now as f64).map(invite_out).collect::<Vec<_>>() }))
}

fn revoke_invite(ctx: &mut Ctx) -> Result<Value> {
    let s = signed_member(ctx, "revoke_invite")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    let code = str_field(&s.data["code"], "code", 16, 1)?;
    let invite = sr.first("Invite", json!({ "server_id": s.server_id, "code": code }), "created_date")?.ok_or_else(|| deny(404, "NOT_FOUND", "Invite not found."))?;
    if invite["creator_id"] != uid.as_str() {
        require_perm(s.perms, p::MANAGE_INVITES, "revoke other people's invites")?;
    }
    sr.update("Invite", id_of(&invite), json!({ "revoked": true, "preview": "" }))?;
    audit(&sr, &s.parts.server, &uid, "invite_revoke", "invite", id_of(&invite), "", now)?;
    Ok(json!({ "ok": true }))
}

// ---------- discovery and the audit log ----------

fn discover(ctx: &mut Ctx) -> Result<Value> {
    let sr = ctx.sr();
    let tag = if truthy(ctx.body.get("tag")) { Some(choice_str(&ctx.body["tag"], &TAGS, "tag")?) } else { None };
    let q = match tag {
        Some(t) => json!({ "discoverable": true, "public_tags": t }),
        None => json!({ "discoverable": true }),
    };
    let rows = sr.filter("Server", q, "-member_count", 100)?;
    let servers: Vec<Value> = rows.iter().filter(|s| s["status"] != "deleting" && truthy(s.get("public_name"))).map(|s| {
        Obj::new()
            .copy("id", s, "id")
            .set("is_default", json!(truthy(s.get("is_default"))))
            .copy("join_mode", s, "join_mode")
            .copy("name", s, "public_name")
            .set("description", or(&s["public_description"], json!("")))
            .set("tags", or(&s["public_tags"], json!([])))
            .set("icon", or(&s["public_icon"], json!("")))
            .set("color", or(&s["public_color"], json!("")))
            .set("member_count", round_count(n0(s.get("member_count"))))
            .done()
    }).collect();
    Ok(json!({ "servers": servers, "tags": TAGS }))
}

fn audit_log(ctx: &mut Ctx) -> Result<Value> {
    let (sr, own, uid, now) = (ctx.sr(), ctx.own(), ctx.user_id().to_string(), ctx.now);
    let server_id = id(&ctx.body["server_id"], "server")?;
    let member = require_member(&own, &server_id, &uid)?;
    let parts = server_parts(&sr, &server_id)?;
    require_perm(perms_of(&parts, &member, None), p::VIEW_AUDIT_LOG, "see the audit log")?;
    let rows = sr.filter("AuditEntry", json!({ "server_id": server_id }), "-created_date", 200)?;
    let live: Vec<&Value> = rows.iter().filter(|a| crate::dates::parse(&to_js_string(a.get("expires_at"))).unwrap_or(f64::NAN) > now as f64).collect();
    let mut people: Vec<Value> = Vec::new();
    for a in &live {
        for v in [a["actor_id"].clone(), if a["target_kind"] == "member" { a["target_id"].clone() } else { json!("") }] {
            if truthy(Some(&v)) && !people.contains(&v) {
                people.push(v);
            }
        }
    }
    let profiles = profiles_for(&sr, &people)?;
    let retention = n0(parts.server.get("audit_retention_days"));
    Ok(json!({
        "entries": live.iter().map(|a| Obj::new().copy("id", a, "id").copy("actor_id", a, "actor_id").copy("action", a, "action").copy("target_kind", a, "target_kind").copy("target_id", a, "target_id").set("detail", or(&a["detail"], json!(""))).copy("at", a, "created_date").done()).collect::<Vec<_>>(),
        "profiles": profiles.iter().map(|p| Obj::new().copy("user_id", p, "user_id").copy("username", p, "username").done()).collect::<Vec<_>>(),
        "retention_days": nv(if retention == 0.0 { 90.0 } else { retention }),
    }))
}

// ---------- support tickets ----------

fn open_ticket(ctx: &mut Ctx) -> Result<Value> {
    let s = signed_member(ctx, "open_ticket")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    let channel = channel_in(&s.parts, &id(&s.data["channel_id"], "channel")?)?.clone();
    if channel["kind"] != "tickets" {
        return Err(deny(400, "BAD_FIELD", "Tickets are opened from a tickets channel."));
    }
    require_perm(perms_of(&s.parts, &s.member, Some(&channel)), p::VIEW_CHANNEL, "open tickets here")?;
    if truthy(s.member.get("timeout_until")) && platform_ms(&s.member["timeout_until"]) > now as f64 {
        return Err(deny(403, "TIMED_OUT", "You're timed out in this server."));
    }
    if sr.filter("Conversation", json!({ "server_id": s.server_id, "ticket_opened_by": uid, "ticket_status": "open" }), "created_date", 10)?.len() >= TICKETS_OPEN_PER_MEMBER {
        return Err(deny(429, "TOO_MANY_TICKETS", "You have the most open tickets you can have here. Close one first."));
    }
    let ticket_roles: Vec<Value> = s.parts.roles.iter().filter(|r| !truthy(r.get("is_everyone")) && (n0(r.get("permissions")) as i64 & (p::MANAGE_TICKETS | p::ADMINISTRATOR)) != 0).map(|r| r["id"].clone()).collect();
    let mut staff_rows = if ticket_roles.is_empty() { vec![] } else { sr.filter("ServerMember", json!({ "server_id": s.server_id, "role_ids": { "$in": ticket_roles } }), "joined_at", 200)? };
    let owner = to_js_string(s.parts.server.get("owner_id"));
    if truthy(s.parts.server.get("owner_id")) && !staff_rows.iter().any(|m| m["user_id"] == owner.as_str()) {
        if let Some(o) = member_row(&sr, &s.server_id, &owner)? {
            staff_rows.push(o);
        }
    }
    let ids: Vec<String> = staff_rows.iter().map(|m| to_js_string(m.get("user_id"))).collect();
    let ready = latest_keys_for(&sr, &ids)?;
    let mut staff: Vec<&Value> = staff_rows.iter().filter(|m| m["user_id"] != uid.as_str() && ready.contains_key(&to_js_string(m.get("user_id"))) && has(perms_of(&s.parts, m, None), p::MANAGE_TICKETS)).collect();
    let top = |m: &Value| top_position(&s.parts.server, &s.parts.roles, Some(m));
    staff.sort_by(|a, b| top(a).partial_cmp(&top(b)).unwrap_or(std::cmp::Ordering::Equal));
    let staff: Vec<String> = staff.into_iter().take(STAFF_PER_TICKET).map(|m| to_js_string(m.get("user_id"))).collect();
    if staff.is_empty() {
        return Err(deny(409, "NO_SUPPORT_TEAM", "This server doesn't have a support team yet."));
    }
    let last = sr.first("Conversation", json!({ "server_id": s.server_id }), "-ticket_number")?;
    let number = last.map_or(0.0, |c| n0(c.get("ticket_number"))) + 1.0;
    let mut members = vec![uid.clone()];
    members.extend(staff.iter().cloned());
    let conv = sr.create("Conversation", json!({
        "kind": "group", "member_ids": members, "admin_ids": members, "creator_id": uid, "server_id": s.server_id, "ticket_channel_id": channel["id"],
        "ticket_number": nv(number), "ticket_status": "open", "ticket_opened_by": uid,
    }))?;
    Ok(json!({ "conversation_id": conv["id"], "ticket_number": nv(number), "staff": staff }))
}

fn tickets(ctx: &mut Ctx) -> Result<Value> {
    let (own, uid) = (ctx.own(), ctx.user_id().to_string());
    let server_id = id(&ctx.body["server_id"], "server")?;
    require_member(&own, &server_id, &uid)?;
    let rows = own.filter("Conversation", json!({ "server_id": server_id, "member_ids": uid }), "-created_date", 200)?;
    let out: Vec<Value> = rows.iter().map(|c| {
        Obj::new().copy("conversation_id", c, "id").set("number", num0(c.get("ticket_number"))).set("status", or(&c["ticket_status"], json!("open"))).copy("opened_by", c, "ticket_opened_by")
            .set("channel_id", or(&c["ticket_channel_id"], json!(""))).copy("created_date", c, "created_date").set("last_message_at", or(&c["last_message_at"], Value::Null)).done()
    }).collect();
    Ok(json!({ "tickets": out }))
}

fn set_ticket_status(ctx: &mut Ctx) -> Result<Value> {
    let s = signed_member(ctx, "set_ticket_status")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    let conv = sr.get("Conversation", &id(&s.data["conversation_id"], "ticket")?);
    let Some(conv) = conv.filter(|c| c["server_id"] == s.server_id.as_str() && crate::shared::ids_of(&c["member_ids"]).contains(&uid)) else {
        return Err(deny(404, "NOT_FOUND", "Ticket not found."));
    };
    if conv["ticket_opened_by"] != uid.as_str() {
        require_perm(perms_of(&s.parts, &s.member, None), p::MANAGE_TICKETS, "close other people's tickets")?;
    }
    let status = choice_str(&s.data["status"], &["open", "closed"], "status")?;
    sr.update("Conversation", id_of(&conv), json!({ "ticket_status": status }))?;
    audit(&sr, &s.parts.server, &uid, if status == "closed" { "ticket_close" } else { "ticket_reopen" }, "ticket", id_of(&conv), &format!("#{}", to_js_string(conv.get("ticket_number"))), now)?;
    Ok(json!({ "ok": true }))
}

pub fn actions() -> Actions {
    let mut a = Actions::new();
    for (name, f) in [
        ("list", list as crate::api::Action),
        ("state", state),
        ("create_server", create_server),
        ("create_generation", create_generation),
        ("pending_grants", pending_grants),
        ("grant_keys", grant_keys),
        ("request_keys", request_keys),
        ("join_server", join_server),
        ("leave_server", leave_server),
        ("accept_rules", accept_rules),
        ("set_listed", set_listed),
        ("set_nickname", set_nickname),
        ("members", members),
        ("member", member),
        ("kick_member", kick_member),
        ("ban_member", ban_member),
        ("unban_member", unban_member),
        ("bans", bans),
        ("timeout_member", timeout_member),
        ("set_member_roles", set_member_roles),
        ("create_role", create_role),
        ("update_role", update_role),
        ("delete_role", delete_role),
        ("reorder_roles", reorder_roles),
        ("create_channel", create_channel),
        ("update_channel", update_channel),
        ("delete_channel", delete_channel),
        ("reorder_channels", reorder_channels),
        ("set_server_profile", set_server_profile),
        ("set_server_set", set_server_set),
        ("set_server_rules", set_server_rules),
        ("update_server_settings", update_server_settings),
        ("transfer_ownership", transfer_ownership),
        ("delete_server", delete_server),
        ("create_invite", create_invite),
        ("invites", invites),
        ("revoke_invite", revoke_invite),
        ("discover", discover),
        ("audit_log", audit_log),
        ("open_ticket", open_ticket),
        ("tickets", tickets),
        ("set_ticket_status", set_ticket_status),
    ] {
        a.insert(name, f);
    }
    a
}

// ---------- what someone opening an invite link sees, signed in or not ----------

fn invite_info(ctx: &mut Ctx) -> Result<Value> {
    let (sr, now) = (ctx.sr(), ctx.now);
    let Some(code) = code_ok(&ctx.body["code"]) else { return Err(deny(404, "INVITE_INVALID", "That invite isn't valid.")) };
    let invite = sr.first("Invite", json!({ "code": code }), "created_date")?;
    let expired = invite.as_ref().is_some_and(|i| truthy(i.get("expires_at")) && platform_ms(&i["expires_at"]) <= now as f64);
    let used = invite.as_ref().is_some_and(|i| to_number(i.get("max_uses")) > 0.0 && to_number(i.get("uses")) >= to_number(i.get("max_uses")));
    let Some(invite) = invite.filter(|i| !truthy(i.get("revoked")) && !expired && !used) else { return Err(deny(404, "INVITE_INVALID", "That invite has expired or isn't valid.")) };
    let server = sr.first("Server", json!({ "audience_id": invite["server_id"] }), "created_date")?;
    let Some(server) = server.filter(|s| s["status"] != "deleting") else { return Err(deny(404, "INVITE_INVALID", "That invite isn't valid.")) };
    let public = if truthy(server.get("discoverable")) || truthy(server.get("is_default")) {
        json!({ "name": or(&server["public_name"], json!("")), "description": or(&server["public_description"], json!("")), "icon": or(&server["public_icon"], json!("")), "color": or(&server["public_color"], json!("")) })
    } else {
        Value::Null
    };
    Ok(Obj::new()
        .copy("server_id", &server, "id")
        .set("preview", or(&invite["preview"], json!("")))
        .set("public", public)
        .set("member_count", round_count(n0(server.get("member_count"))))
        .set("expires_at", or(&invite["expires_at"], Value::Null))
        .done())
}

pub fn invite_actions() -> Actions {
    let mut a = Actions::new();
    a.insert("invite_info", invite_info as crate::api::Action);
    a
}
