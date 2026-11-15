//! Direct messages and small groups (base44/shared/handlers/conversations.ts). Membership is
//! server-side metadata; names and messages are end-to-end encrypted.
use serde_json::{json, Value};

use crate::api::{id, random_id_field, str_field, Actions, ApiError, Ctx, Limits, Result};
use crate::db::{id_of, merged, Db};
use crate::js::{to_js_string, to_number, truthy};
use crate::shared::{
    account_keys_of, admins_of, assert_wraps_match_members, blocked_either_way, by_age, conversation_for_member, conversation_out, enforce_rate, ids_of, iso, my_conversations, profile_of, rate_limited, require_active_device, require_group_admin, with_row, within_rate, without_member,
    EXPIRY_CHOICES,
};
use crate::verify::{check_clock, parse_envelope_shape, signed_by_active_device, verify_item_signature, MAX_ENVELOPE_CHARS, MAX_GROUP_MEMBERS};

const CONVERSATIONS_PER_HOUR: usize = 30;
const HOUR_MS: i64 = 3_600_000;

fn deny(status: u16, code: &str, message: &str) -> ApiError {
    ApiError::new(status, code, message)
}
fn title_cleared() -> Value {
    json!({ "title_envelope": "", "title_item_id": "", "title_sender_id": "", "title_device_id": "", "title_sent_at": "", "title_signature": "" })
}
fn username_ok(s: &str) -> bool {
    (3..=20).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

/// Whether someone accepts a new conversation from me.
fn accepts_from(sr: &Db, own: &Db, me: &str, profile: &Value) -> Result<bool> {
    let policy = crate::shared::or(&profile["dm_policy"], json!("anyone"));
    if policy == "anyone" {
        return Ok(true);
    }
    if policy == "nobody" {
        return Ok(false);
    }
    let mut server_ids: Vec<Value> = Vec::new();
    for m in own.filter("ServerMember", json!({ "user_id": me }), "created_date", 200)? {
        if !server_ids.contains(&m["server_id"]) {
            server_ids.push(m["server_id"].clone());
        }
    }
    if server_ids.is_empty() {
        return Ok(false);
    }
    let theirs = sr.filter("ServerMember", json!({ "server_id": { "$in": server_ids }, "user_id": profile["user_id"] }), "created_date", 200)?;
    if theirs.is_empty() {
        return Ok(false);
    }
    let ids: Vec<Value> = theirs.iter().map(|m| m["server_id"].clone()).collect();
    let servers = sr.filter("Server", json!({ "audience_id": { "$in": ids } }), "created_date", 200)?;
    Ok(servers.iter().any(|s| s["allow_member_dms"] != false && s["status"] != "deleting"))
}

fn require_accepts(sr: &Db, own: &Db, me: &str, user_ids: &[String]) -> Result<()> {
    if user_ids.is_empty() {
        return Ok(());
    }
    for p in sr.filter("Profile", json!({ "user_id": { "$in": user_ids } }), "created_date", user_ids.len() + 5)? {
        if truthy(p.get("remote")) {
            continue;
        }
        if !accepts_from(sr, own, me, &p)? {
            return Err(deny(403, "NOT_ACCEPTING", &format!("{} isn't accepting new conversations.", to_js_string(p.get("username")))));
        }
    }
    Ok(())
}

fn require_self_ready(sr: &Db, user_id: &str) -> Result<()> {
    if profile_of(sr, user_id)?.is_none() {
        return Err(deny(409, "PROFILE_REQUIRED", "Choose a username first."));
    }
    if account_keys_of(sr, user_id)?.is_empty() {
        return Err(deny(409, "SETUP_REQUIRED", "Finish setting up encryption first."));
    }
    Ok(())
}

/// Exact usernames to user ids. Missing and blocked look the same. (People on other sites are
/// reached through federation, which this server doesn't run yet: their addresses are refused.)
fn resolve_usernames(sr: &Db, me: &str, usernames: &Value, max: usize) -> Result<Vec<String>> {
    let Some(list) = usernames.as_array().filter(|a| !a.is_empty() && a.len() <= max) else {
        return Err(deny(400, "BAD_FIELD", &format!("Add between 1 and {max} people.")));
    };
    let mut keys: Vec<String> = Vec::new();
    for u in list {
        let v = u.as_str().map(crate::js::trim).unwrap_or_default();
        let v = v.strip_prefix('@').unwrap_or(&v).to_lowercase();
        if !username_ok(&v) {
            return Err(deny(400, "BAD_USERNAME", "One of those usernames isn't valid."));
        }
        if !keys.contains(&v) {
            keys.push(v);
        }
    }
    let rows = sr.filter("Profile", json!({ "username_key": { "$in": keys } }), "created_date", 200)?;
    let mut ids = Vec::new();
    for key in &keys {
        let p = rows.iter().find(|r| r["username_key"] == key.as_str());
        let blocked = match p {
            Some(p) if p["user_id"] != me => blocked_either_way(sr, me, &to_js_string(p.get("user_id")))?,
            _ => false,
        };
        let Some(p) = p.filter(|_| !blocked) else { return Err(deny(404, "NOT_FOUND", &format!("No member has the username \"{key}\"."))) };
        let uid = to_js_string(p.get("user_id"));
        if account_keys_of(sr, &uid)?.is_empty() {
            return Err(deny(409, "MEMBER_NOT_READY", &format!("{} hasn't finished setting up encryption yet.", to_js_string(p.get("username")))));
        }
        if uid != me {
            ids.push(uid);
        }
    }
    Ok(ids)
}

fn list(ctx: &mut Ctx) -> Result<Value> {
    let rows = my_conversations(&ctx.own(), ctx.user_id(), 500)?;
    Ok(json!({ "conversations": rows.iter().map(conversation_out).collect::<Vec<_>>() }))
}

fn get(ctx: &mut Ctx) -> Result<Value> {
    let conv = conversation_for_member(&ctx.own(), ctx.user_id(), &id(&ctx.body["conversation_id"], "conversation")?)?;
    Ok(json!({ "conversation": conversation_out(&conv) }))
}

fn create_dm(ctx: &mut Ctx) -> Result<Value> {
    let (_, data) = signed_by_active_device(ctx, "create_dm", Limits::MAX_BODY_BYTES)?;
    let (sr, own, uid, now) = (ctx.sr(), ctx.own(), ctx.user_id().to_string(), ctx.now);
    require_self_ready(&sr, &uid)?;
    let found = resolve_usernames(&sr, &uid, &json!([data.get("username").cloned().unwrap_or(Value::Null)]), 1)?;
    let Some(other) = found.first().cloned() else { return Err(deny(400, "BAD_FIELD", "That's your own username.")) };
    let mut pair = [uid.clone(), other.clone()];
    pair.sort();
    let dm_key = pair.join(":");
    let mut existing = sr.filter("Conversation", json!({ "dm_key": dm_key }), "created_date", 5)?;
    existing.sort_by(by_age);
    if let Some(e) = existing.first() {
        return Ok(json!({ "conversation": conversation_out(e), "created": false }));
    }
    require_accepts(&sr, &own, &uid, std::slice::from_ref(&other))?;
    enforce_rate(&sr, "Conversation", json!({ "creator_id": uid }), HOUR_MS, CONVERSATIONS_PER_HOUR, now, "starting conversations")?;
    let created = sr.create("Conversation", json!({ "kind": "dm", "member_ids": [uid, other], "dm_key": dm_key, "creator_id": uid }))?;
    if !within_rate(&sr, "Conversation", json!({ "creator_id": uid }), HOUR_MS, CONVERSATIONS_PER_HOUR, now, &created)? {
        sr.delete("Conversation", id_of(&created))?;
        return Err(rate_limited("starting conversations"));
    }
    let all = with_row(sr.filter("Conversation", json!({ "dm_key": dm_key }), "created_date", 5)?, &created);
    if all[0]["id"] != created["id"] {
        sr.delete("Conversation", id_of(&created))?;
        return Ok(json!({ "conversation": conversation_out(&all[0]), "created": false }));
    }
    Ok(json!({ "conversation": conversation_out(&created), "created": true }))
}

fn create_group(ctx: &mut Ctx) -> Result<Value> {
    let (_, data) = signed_by_active_device(ctx, "create_group", Limits::MAX_BODY_BYTES)?;
    let (sr, own, uid, now) = (ctx.sr(), ctx.own(), ctx.user_id().to_string(), ctx.now);
    require_self_ready(&sr, &uid)?;
    let others = resolve_usernames(&sr, &uid, &data["usernames"], MAX_GROUP_MEMBERS - 1)?;
    if others.is_empty() {
        return Err(deny(400, "BAD_FIELD", "Add at least one other person."));
    }
    require_accepts(&sr, &own, &uid, &others)?;
    enforce_rate(&sr, "Conversation", json!({ "creator_id": uid }), HOUR_MS, CONVERSATIONS_PER_HOUR, now, "starting conversations")?;
    let mut members = vec![uid.clone()];
    members.extend(others);
    let created = sr.create("Conversation", json!({ "kind": "group", "member_ids": members, "admin_ids": [uid], "creator_id": uid }))?;
    if !within_rate(&sr, "Conversation", json!({ "creator_id": uid }), HOUR_MS, CONVERSATIONS_PER_HOUR, now, &created)? {
        sr.delete("Conversation", id_of(&created))?;
        return Err(rate_limited("starting conversations"));
    }
    Ok(json!({ "conversation": conversation_out(&created) }))
}

fn add_members(ctx: &mut Ctx) -> Result<Value> {
    let (_, data) = signed_by_active_device(ctx, "add_members", Limits::MAX_BODY_BYTES)?;
    let (sr, own, uid) = (ctx.sr(), ctx.own(), ctx.user_id().to_string());
    let conv = conversation_for_member(&sr, &uid, &id(&data["conversation_id"], "conversation")?)?;
    if conv["kind"] != "group" {
        return Err(deny(400, "NOT_GROUP", "You can only add people to a group."));
    }
    require_group_admin(&conv, &uid, "add people")?;
    let ids = resolve_usernames(&sr, &uid, &data["usernames"], MAX_GROUP_MEMBERS)?;
    let members = ids_of(&conv["member_ids"]);
    let new: Vec<String> = ids.iter().filter(|i| !members.contains(i)).cloned().collect();
    require_accepts(&sr, &own, &uid, &new)?;
    let mut next: Vec<String> = Vec::new();
    for m in members.into_iter().chain(ids) {
        if !next.contains(&m) {
            next.push(m);
        }
    }
    if next.len() > MAX_GROUP_MEMBERS {
        return Err(deny(409, "GROUP_FULL", &format!("Groups can have up to {MAX_GROUP_MEMBERS} people.")));
    }
    let updated = sr.update("Conversation", id_of(&conv), json!({ "member_ids": next }))?;
    Ok(json!({ "conversation": conversation_out(&merged(&merged(&conv, &updated), &json!({ "member_ids": next }))) }))
}

fn leave(ctx: &mut Ctx) -> Result<Value> {
    let (_, data) = signed_by_active_device(ctx, "leave", Limits::MAX_BODY_BYTES)?;
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    let conv = conversation_for_member(&sr, &uid, &id(&data["conversation_id"], "conversation")?)?;
    if conv["kind"] != "group" {
        return Err(deny(400, "DM_LEAVE", "You can't leave a direct message. Block the member if you need to stop contact."));
    }
    let (members, admins) = without_member(&conv, &uid);
    if members.is_empty() {
        if !crate::deletion::erase_conversation_until(&sr, id_of(&conv), crate::sessions::now_ms() + 45_000)? {
            return Err(deny(503, "TRY_AGAIN", "Still removing this group's messages. Try again to finish."));
        }
    } else {
        let mut changes = json!({ "member_ids": members, "admin_ids": admins });
        if conv["title_sender_id"] == uid.as_str() {
            changes = merged(&changes, &title_cleared());
        }
        sr.update("Conversation", id_of(&conv), changes)?;
    }
    Ok(json!({ "ok": true }))
}

fn remove_member(ctx: &mut Ctx) -> Result<Value> {
    let (_, data) = signed_by_active_device(ctx, "remove_member", Limits::MAX_BODY_BYTES)?;
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    let conv = conversation_for_member(&sr, &uid, &id(&data["conversation_id"], "conversation")?)?;
    if conv["kind"] != "group" {
        return Err(deny(400, "NOT_GROUP", "Only groups have members to remove."));
    }
    require_group_admin(&conv, &uid, "remove people")?;
    let target = id(&data["user_id"], "member")?;
    if target == uid {
        return Err(deny(400, "BAD_FIELD", "To leave the group yourself, use Leave group."));
    }
    if !ids_of(&conv["member_ids"]).contains(&target) {
        return Err(deny(404, "NOT_MEMBER", "That person isn't in this group."));
    }
    let (members, admins) = without_member(&conv, &target);
    let next = json!({ "member_ids": members, "admin_ids": admins });
    let changes = if conv["title_sender_id"] == target.as_str() { merged(&next, &title_cleared()) } else { next.clone() };
    let updated = sr.update("Conversation", id_of(&conv), changes)?;
    Ok(json!({ "conversation": conversation_out(&merged(&merged(&conv, &updated), &next)) }))
}

fn set_admin(ctx: &mut Ctx) -> Result<Value> {
    let (_, data) = signed_by_active_device(ctx, "set_admin", Limits::MAX_BODY_BYTES)?;
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    let conv = conversation_for_member(&sr, &uid, &id(&data["conversation_id"], "conversation")?)?;
    if conv["kind"] != "group" {
        return Err(deny(400, "NOT_GROUP", "Only groups have admins."));
    }
    require_group_admin(&conv, &uid, "choose admins")?;
    let target = id(&data["user_id"], "member")?;
    if !ids_of(&conv["member_ids"]).contains(&target) {
        return Err(deny(404, "NOT_MEMBER", "That person isn't in this group."));
    }
    let Some(admin) = data["admin"].as_bool() else { return Err(deny(400, "BAD_FIELD", "Say whether they should be an admin.")) };
    let current = admins_of(&conv);
    let admin_ids: Vec<String> = if admin {
        let mut a = current.clone();
        if !a.contains(&target) {
            a.push(target.clone());
        }
        a
    } else {
        current.into_iter().filter(|a| *a != target).collect()
    };
    if admin_ids.is_empty() {
        return Err(deny(409, "LAST_ADMIN", "A group needs at least one admin. Make someone else an admin first."));
    }
    let updated = sr.update("Conversation", id_of(&conv), json!({ "admin_ids": admin_ids }))?;
    Ok(json!({ "conversation": conversation_out(&merged(&merged(&conv, &updated), &json!({ "admin_ids": admin_ids }))) }))
}

fn set_expiry(ctx: &mut Ctx) -> Result<Value> {
    let (_, data) = signed_by_active_device(ctx, "set_expiry", Limits::MAX_BODY_BYTES)?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    let conv = conversation_for_member(&sr, &uid, &id(&data["conversation_id"], "conversation")?)?;
    require_group_admin(&conv, &uid, "change disappearing messages")?;
    let seconds = to_number(data.get("seconds"));
    if !EXPIRY_CHOICES.iter().any(|c| *c as f64 == seconds) {
        return Err(deny(400, "BAD_FIELD", "Choose off, a day, a week or four weeks."));
    }
    let changes = json!({ "expire_seconds": seconds as i64, "expiry_set_by": uid, "expiry_set_at": iso(now) });
    let updated = sr.update("Conversation", id_of(&conv), changes.clone())?;
    Ok(json!({ "conversation": conversation_out(&merged(&merged(&conv, &updated), &changes)) }))
}

fn set_self_destruct(ctx: &mut Ctx) -> Result<Value> {
    let (_, data) = signed_by_active_device(ctx, "set_self_destruct", Limits::MAX_BODY_BYTES)?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    let conv = conversation_for_member(&sr, &uid, &id(&data["conversation_id"], "conversation")?)?;
    if truthy(conv.get("server_id")) {
        return Err(deny(400, "BAD_FIELD", "Support tickets can't self-destruct."));
    }
    require_group_admin(&conv, &uid, "set a self-destruct time")?;
    let hours = to_number(data.get("hours"));
    if ![0.0, 1.0, 6.0, 24.0, 72.0, 168.0, 720.0].contains(&hours) {
        return Err(deny(400, "BAD_FIELD", "Choose off, or a time from an hour to 30 days."));
    }
    let on = hours != 0.0;
    let changes = json!({ "destroy_at": if on { iso(now + hours as i64 * HOUR_MS) } else { String::new() }, "destroy_set_by": if on { uid.clone() } else { String::new() } });
    let updated = sr.update("Conversation", id_of(&conv), changes.clone())?;
    Ok(json!({ "conversation": conversation_out(&merged(&merged(&conv, &updated), &changes)) }))
}

fn set_title(ctx: &mut Ctx) -> Result<Value> {
    let (sr, own, uid, now, body) = (ctx.sr(), ctx.own(), ctx.user_id().to_string(), ctx.now, &ctx.body);
    let conv = conversation_for_member(&own, &uid, &id(&body["conversation_id"], "conversation")?)?;
    if conv["kind"] != "group" {
        return Err(deny(400, "NOT_GROUP", "Only groups have names."));
    }
    require_group_admin(&conv, &uid, "rename the group")?;
    let device = require_active_device(&own, &uid, &random_id_field(&body["device_id"], "device id")?)?;
    let item_id = random_id_field(&body["item_id"], "item id")?;
    let sent_at = crate::verify::iso_time(&body["sent_at"], "sent time")?;
    check_clock(&sent_at, now)?;
    let envelope = str_field(&body["envelope"], "group name", MAX_ENVELOPE_CHARS, 1)?;
    let wraps = parse_envelope_shape(&envelope, MAX_ENVELOPE_CHARS)?;
    assert_wraps_match_members(&sr, &wraps, &ids_of(&conv["member_ids"]))?;
    let ok = verify_item_signature("title", id_of(&conv), &item_id, &uid, &to_js_string(device.get("device_id")), &envelope, &sent_at, &body["signature"], device["sign_pub"].as_str().unwrap_or(""))?;
    if !ok {
        return Err(deny(403, "SIGNATURE_INVALID", "The group name's signature didn't verify."));
    }
    let updated = sr.update("Conversation", id_of(&conv), json!({ "title_envelope": envelope, "title_item_id": item_id, "title_sender_id": uid, "title_device_id": device["device_id"], "title_sent_at": sent_at, "title_signature": body["signature"] }))?;
    Ok(json!({ "conversation": conversation_out(&merged(&conv, &updated)) }))
}

pub fn actions() -> Actions {
    let mut a = Actions::new();
    for (name, f) in [
        ("list", list as crate::api::Action),
        ("get", get),
        ("create_dm", create_dm),
        ("create_group", create_group),
        ("add_members", add_members),
        ("leave", leave),
        ("remove_member", remove_member),
        ("set_admin", set_admin),
        ("set_expiry", set_expiry),
        ("set_self_destruct", set_self_destruct),
        ("set_title", set_title),
    ] {
        a.insert(name, f);
    }
    a
}
