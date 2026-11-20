//! Messages in server channels (base44/shared/handlers/serverMessages.ts). Like direct messages,
//! the service checks who's sending, the device and its signature, and stores ciphertext it can't
//! read. Every member of a channel reads with the channel's shared key, so a message is one row.
use serde_json::{json, Value};

use crate::api::{id, int, random_id_field, str_field, Actions, ApiError, Ctx, Limits, Result};
use crate::db::{id_of, Db};
use crate::js::{to_js_string, to_number, truthy};
use crate::notifications::{notify_people, subject};
use crate::permissions::{channel_permissions, has, p};
use crate::servers_build::{flooded_by, log_case};
use crate::servers_core::*;
use crate::shared::{count_since, iso, platform_ms, profile_of, rate_limited, require_active_device};
use crate::verify::{check_sent_at, iso_time, signed_by_active_device};

/// A member's view of a channel: (membership, channel, permissions), or None if they can't see it.
type Seen = Option<(Value, Value, i64)>;

const KINDS: [&str; 4] = ["message", "reaction", "edit", "post"];
const CHANNEL_PUSH_BATCH: usize = 200;

fn deny(status: u16, code: &str, message: &str) -> ApiError {
    ApiError::new(status, code, message)
}

struct View {
    member: Value,
    server: Value,
    channel: Value,
    roles: Vec<Value>,
    perms: i64,
}

/// The caller's view of one channel, read with their own access.
fn channel_view(own: &Db, server_id: &str, channel_id: &str, user_id: &str) -> Result<View> {
    let member = require_member(own, server_id, user_id)?;
    let servers = own.filter("Server", json!({ "audience_id": server_id }), "created_date", 1)?;
    let roles = own.filter("Role", json!({ "server_id": server_id }), "position", ROLES_PER_SERVER + 5)?;
    let channels = own.filter("Channel", json!({ "server_id": server_id }), "position", CHANNELS_PER_SERVER + 5)?;
    let not_found = || deny(404, "CHANNEL_NOT_FOUND", "Channel not found.");
    let server = servers.into_iter().next().filter(|s| s["status"] != "deleting").ok_or_else(not_found)?;
    let channel = channels.into_iter().find(|c| c["id"] == channel_id).ok_or_else(not_found)?;
    let perms = channel_permissions(&server, &roles, Some(&member), &channel);
    if !has(perms, p::VIEW_CHANNEL) {
        return Err(not_found());
    }
    Ok(View { member, server, channel, roles, perms })
}

/// Bounded push fanout. Only readable members are eligible; no message text or encrypted
/// content leaves the server. Mention-routing hints are ephemeral metadata from the sender.
fn notify_channel(sr: &Db, push_subject: &str, server: &Value, roles: &[Value], channel: &Value, sender_id: &str, sender_perms: i64, body: &Value) -> Result<()> {
    let members = sr.filter("ServerMember", json!({ "server_id": server["id"] }), "joined_at", CHANNEL_PUSH_BATCH + 1)?;
    if members.len() > CHANNEL_PUSH_BATCH { eprintln!("commonveil push: channel_fanout_limited count={CHANNEL_PUSH_BATCH}"); }
    let hint = &body["notification_hint"];
    let users: Vec<&str> = hint["users"].as_array().into_iter().flatten().filter_map(Value::as_str).take(50).collect();
    let mentioned_roles: Vec<&str> = hint["roles"].as_array().into_iter().flatten().filter_map(Value::as_str)
        .filter(|role| roles.iter().any(|r| r["id"] == *role && truthy(r.get("mentionable")) && !truthy(r.get("is_everyone"))))
        .take(20).collect();
    let everyone = hint["everyone"] == true && has(sender_perms, p::MENTION_EVERYONE);
    let mut mention_targets = Vec::new();
    let mut activity_targets = Vec::new();
    for member in members.iter().take(CHANNEL_PUSH_BATCH) {
        let uid = member["user_id"].as_str().unwrap_or("");
        if uid.is_empty() || uid == sender_id || member["key_status"] != "ok" || !has(channel_permissions(server, roles, Some(member), channel), p::VIEW_CHANNEL) { continue; }
        let matched = everyone || users.contains(&uid) || member["role_ids"].as_array().is_some_and(|rs| rs.iter().any(|r| r.as_str().is_some_and(|v| mentioned_roles.contains(&v))));
        if matched { mention_targets.push(uid.to_string()); } else { activity_targets.push(uid.to_string()); }
    }
    let path = format!("/app/s/{}/{}", id_of(server), id_of(channel));
    let place_id = id_of(channel);
    if !mention_targets.is_empty() { notify_people(sr, push_subject, &mention_targets, "mention", &path, place_id); }
    if !activity_targets.is_empty() { notify_people(sr, push_subject, &activity_targets, "activity", &path, place_id); }
    Ok(())
}

fn is_live(m: &Value, now: i64) -> bool {
    !truthy(m.get("expires_at")) || crate::dates::parse(&to_js_string(m.get("expires_at"))).unwrap_or(f64::NAN) > now as f64
}

/// Messages before someone joined, in a channel that only shows newcomers what came after. A
/// message stored in the millisecond they joined counts as before (hidden).
fn hidden_from_newcomer(channel: &Value, perms: i64, member: &Value, m: &Value) -> bool {
    let joined_only = channel["history"] == "joined" || !has(perms, p::READ_HISTORY);
    joined_only && platform_ms(&json!(to_js_string(m.get("created_date")))) <= crate::dates::parse(&to_js_string(member.get("joined_at"))).unwrap_or(f64::NAN)
}

/// Of these messages, the ones this member may read right now, worked out from the server's
/// current roles, overwrites and their membership (CV-05), with the same history rule (CV-06).
fn readable_now(own: &Db, user_id: &str, rows: Vec<Value>) -> Result<Vec<Value>> {
    if rows.is_empty() {
        return Ok(rows);
    }
    let mut server_ids: Vec<Value> = Vec::new();
    let mut channel_ids: Vec<Value> = Vec::new();
    for m in &rows {
        if truthy(m.get("server_id")) && !server_ids.contains(&m["server_id"]) {
            server_ids.push(m["server_id"].clone());
        }
        if truthy(m.get("channel_id")) && !channel_ids.contains(&m["channel_id"]) {
            channel_ids.push(m["channel_id"].clone());
        }
    }
    let members = own.filter("ServerMember", json!({ "user_id": user_id, "server_id": { "$in": server_ids } }), "created_date", server_ids.len() + 5)?;
    let servers = own.filter("Server", json!({ "audience_id": { "$in": server_ids } }), "created_date", server_ids.len() + 5)?;
    let roles = own.filter("Role", json!({ "server_id": { "$in": server_ids } }), "position", (ROLES_PER_SERVER + 5) * server_ids.len())?;
    let channels = own.filter("Channel", json!({ "id": { "$in": channel_ids } }), "position", channel_ids.len() + 5)?;
    let mut views: Vec<(String, Seen)> = Vec::new();
    let mut out = Vec::new();
    for m in rows {
        let key = format!("{}|{}", to_js_string(m.get("server_id")), to_js_string(m.get("channel_id")));
        let view = match views.iter().find(|(k, _)| *k == key) {
            Some((_, v)) => v.clone(),
            None => {
                let member = members.iter().find(|x| x["server_id"] == m["server_id"]);
                let server = servers.iter().find(|s| s["audience_id"] == m["server_id"] || s["id"] == m["server_id"]);
                let channel = channels.iter().find(|c| c["id"] == m["channel_id"] && c["server_id"] == m["server_id"]);
                let v = match (member, server, channel) {
                    (Some(mb), Some(s), Some(c)) if s["status"] != "deleting" => {
                        let server_roles: Vec<Value> = roles.iter().filter(|r| r["server_id"] == m["server_id"]).cloned().collect();
                        let perms = channel_permissions(s, &server_roles, Some(mb), c);
                        has(perms, p::VIEW_CHANNEL).then(|| (mb.clone(), c.clone(), perms))
                    }
                    _ => None,
                };
                views.push((key, v.clone()));
                v
            }
        };
        if let Some((mb, c, perms)) = view {
            if !hidden_from_newcomer(&c, perms, &mb, &m) {
                out.push(m);
            }
        }
    }
    Ok(out)
}

fn send(ctx: &mut Ctx) -> Result<Value> {
    let (sr, own, uid, now, body) = (ctx.sr(), ctx.own(), ctx.user_id().to_string(), ctx.now, &ctx.body);
    let server_id = id(&body["server_id"], "server")?;
    let View { member, server, channel, roles, perms } = channel_view(&own, &server_id, &id(&body["channel_id"], "channel")?, &uid)?;
    if !channel["kind"].as_str().is_some_and(|k| MESSAGE_KINDS.contains(&k)) {
        return Err(deny(400, "BAD_FIELD", "You can't post in this kind of channel."));
    }
    let kind = body["kind"].as_str().filter(|k| KINDS.contains(k)).ok_or_else(|| deny(400, "BAD_FIELD", "Invalid message kind."))?.to_string();
    let thread_id = if truthy(body.get("thread_id")) { random_id_field(&body["thread_id"], "post")? } else { String::new() };
    let forum = channel["kind"] == "forum";
    match kind.as_str() {
        "post" => {
            if !forum || !thread_id.is_empty() {
                return Err(deny(400, "BAD_FIELD", "Posts start in forum channels."));
            }
            require_perm(perms, p::CREATE_POSTS, "start posts here")?;
        }
        "reaction" => require_perm(perms, p::ADD_REACTIONS, "react here")?,
        _ => {
            require_perm(perms, p::SEND_MESSAGES, "post here")?;
            if forum && thread_id.is_empty() {
                return Err(deny(400, "BAD_FIELD", "In a forum, reply to a post or start one."));
            }
        }
    }
    if truthy(member.get("timeout_until")) && crate::dates::parse(&to_js_string(member.get("timeout_until"))).unwrap_or(f64::NAN) > now as f64 {
        return Err(deny(403, "TIMED_OUT", "You're timed out in this server for now."));
    }
    let staff = has(perms, p::MANAGE_MESSAGES) || has(perms, p::MANAGE_SERVER);
    if !staff {
        if truthy(server.get("rules_required")) && !truthy(member.get("rules_accepted_at")) {
            return Err(deny(403, "RULES_REQUIRED", "Read and accept the server's rules first."));
        }
        let member_minutes = { let x = to_number(server.get("min_member_minutes")); if x.is_nan() { 0.0 } else { x } };
        if member_minutes != 0.0 && (now as f64 - crate::dates::parse(&to_js_string(member.get("joined_at"))).unwrap_or(f64::NAN)) < member_minutes * 60_000.0 {
            return Err(deny(403, "TOO_NEW", &format!("New members can post {} minutes after joining.", to_js_string(Some(&crate::js::number_value(member_minutes))))));
        }
        let account_minutes = { let x = to_number(server.get("min_account_minutes")); if x.is_nan() { 0.0 } else { x } };
        if account_minutes != 0.0 {
            let profile = profile_of(&own, &uid)?;
            let young = match &profile {
                None => true,
                Some(pr) => (now as f64 - platform_ms(&pr["created_date"])) < account_minutes * 60_000.0,
            };
            if young {
                return Err(deny(403, "ACCOUNT_TOO_NEW", "Your account is too new to post here yet."));
            }
        }
    }
    let mut root: Option<Value> = None;
    if !thread_id.is_empty() {
        let r = own.first("ServerMessage", json!({ "channel_id": channel["id"], "msg_id": thread_id }), "created_date")?;
        let fits = r.as_ref().is_some_and(|r| !truthy(r.get("deleted")) && if forum { r["kind"] == "post" } else { r["kind"] == "message" && !truthy(r.get("thread_id")) });
        if !fits {
            return Err(deny(404, "NOT_FOUND", if forum { "That post isn't here any more." } else { "That thread isn't here any more." }));
        }
        let r = r.unwrap();
        if truthy(r.get("thread_locked")) && !has(perms, p::MANAGE_THREADS) && kind != "reaction" {
            return Err(deny(403, "THREAD_LOCKED", "This thread is locked."));
        }
        root = Some(r);
    }
    let device = require_active_device(&own, &uid, &random_id_field(&body["device_id"], "device id")?)?;
    let msg_id = random_id_field(&body["msg_id"], "message id")?;
    let sent_at = iso_time(&body["sent_at"], "sent time")?;
    check_sent_at(&sent_at, now, &body["queued"])?;
    let envelope = str_field(&body["envelope"], "message", MAX_MESSAGE_ENVELOPE_CHARS, 1)?;
    let env = parse_item_envelope(&envelope)?;
    let chain_id = chain_for_channel(&server_id, &channel);
    let gens = own.filter("KeyGeneration", json!({ "server_id": server_id, "chain_id": chain_id }), "created_date", 500)?;
    let chain_rows = own.filter("KeyChain", json!({ "server_id": server_id, "chain_id": chain_id }), "created_date", 1)?;
    let latest = latest_generation(&gens, &chain_id);
    if chain_rows.first().is_some_and(|c| truthy(c.get("rotation_needed"))) {
        return Err(deny(409, "KEYS_RENEWING", "This channel's keys are being renewed after someone lost access. You can post again as soon as a moderator's app has renewed them, usually within moments."));
    }
    let latest = latest.ok_or_else(|| deny(409, "NO_KEYS_YET", "This channel's encryption is still being set up. Try again in a moment."))?;
    let sent_ms = crate::dates::parse(&sent_at).unwrap_or(f64::NAN);
    if env.chain != chain_id || env.gen != to_number(latest.get("generation")) || env.step != step_at(&chain_id, &to_js_string(latest.get("started_at")), sent_ms) as f64 {
        return Err(deny(409, "STALE_SERVER_KEYS", "This channel's keys changed. Refreshing and trying again."));
    }
    let item = json!({ "item_id": msg_id, "sender_id": uid, "device_id": device["device_id"], "envelope": envelope, "sent_at": sent_at, "signature": body.get("signature").cloned().unwrap_or(Value::Null) });
    if !verify_server_item_signature("message", &server_id, id_of(&channel), &item, device["sign_pub"].as_str().unwrap_or(""))? {
        return Err(deny(403, "SIGNATURE_INVALID", "The message signature didn't verify, so it wasn't sent."));
    }
    if let Some(dup) = own.first("ServerMessage", json!({ "channel_id": channel["id"], "msg_id": msg_id }), "created_date")? {
        if dup["sender_id"] != uid.as_str() {
            return Err(deny(409, "DUPLICATE_ID", "That message id is already taken. Please try again."));
        }
        return Ok(json!({ "message": server_message_out(&dup), "duplicate": true }));
    }
    let posting = kind == "message" || kind == "post";
    let slow = to_number(channel.get("slowmode_seconds"));
    if !staff && posting && slow > 0.0 {
        if let Some(last) = own.first("ServerMessage", json!({ "channel_id": channel["id"], "sender_id": uid, "kind": { "$in": ["message", "post"] } }), "-created_date")? {
            let wait = platform_ms(&json!(to_js_string(last.get("created_date")))) + slow * 1000.0 - now as f64;
            if wait > 0.0 {
                return Err(deny(429, "SLOWMODE", &format!("Slow mode is on here: you can post again in {} seconds.", (wait / 1000.0).ceil() as i64)));
            }
        }
    }
    if count_since(&own, "ServerMessage", json!({ "sender_id": uid }), now - 60_000, SERVER_MESSAGES_PER_MINUTE)? >= SERVER_MESSAGES_PER_MINUTE {
        return Err(rate_limited("sending messages"));
    }
    if !staff && posting {
        if let Some(flood) = flooded_by(&sr, &server, &uid, now)? {
            let minutes = flood["timeout_minutes"].as_f64().unwrap_or(10.0);
            sr.update("ServerMember", id_of(&member), json!({ "timeout_until": iso(now + (minutes * 60_000.0) as i64) }))?;
            log_case(&sr, &server, "timeout", &uid, "system", crate::js::number_value(minutes), &json!({}), "", now)?;
            let m = to_js_string(Some(&crate::js::number_value(minutes)));
            audit(&sr, &server, "system", "member_timeout", "member", &uid, &format!("flood protection, {m} min"), now)?;
            return Err(deny(429, "FLOOD", &format!("That's too many messages too quickly for this server, so you're timed out for {m} minute{}.", if minutes == 1.0 { "" } else { "s" })));
        }
    }
    let lifetime = { let x = to_number(channel.get("expire_seconds")); if x.is_nan() { 0.0 } else { x } };
    let private = truthy(channel.get("private"));
    let mut row = json!({
        "server_id": server_id, "channel_id": channel["id"], "audience_id": if private { channel["id"].clone() } else { json!(server_id) },
        "msg_id": msg_id, "kind": kind, "thread_id": thread_id, "sender_id": uid, "device_id": device["device_id"],
        "envelope": envelope, "signature": body["signature"], "sent_at": sent_at, "deleted": false, "pinned": false,
    });
    if body.get("signature").is_none() {
        row.as_object_mut().unwrap().remove("signature");
    }
    if kind == "post" {
        row["last_reply_at"] = json!(crate::api::platform_time(now));
        row["reply_count"] = json!(0);
    }
    if lifetime > 0.0 {
        row["expires_at"] = json!(iso(now + (lifetime * 1000.0) as i64));
    }
    let message = sr.create("ServerMessage", row)?;
    let at = if truthy(message.get("created_date")) { message["created_date"].clone() } else { json!(crate::api::platform_time(now)) };
    if posting {
        sr.update("Channel", id_of(&channel), json!({ "last_message_at": at }))?;
    }
    if let (Some(r), "message") = (&root, kind.as_str()) {
        let count = { let x = to_number(r.get("reply_count")); if x.is_nan() { 0.0 } else { x } };
        sr.update("ServerMessage", id_of(r), json!({ "last_reply_at": at, "reply_count": crate::js::number_value(count + 1.0) }))?;
    }
    if posting && notify_channel(&sr, &subject(ctx), &server, &roles, &channel, &uid, perms, body).is_err() {
        eprintln!("commonveil push: channel_preparation_failed");
    }
    Ok(json!({ "message": server_message_out(&message) }))
}

fn list(ctx: &mut Ctx) -> Result<Value> {
    let (own, uid, now, body) = (ctx.own(), ctx.user_id().to_string(), ctx.now, &ctx.body);
    let server_id = id(&body["server_id"], "server")?;
    let view = channel_view(&own, &server_id, &id(&body["channel_id"], "channel")?, &uid)?;
    let limit = if body.get("limit").is_none() { SERVER_PAGE_SIZE } else { int(&body["limit"], "limit", 1, SERVER_PAGE_SIZE)? } as usize;
    let posts = truthy(body.get("posts"));
    let (mut query, sort) = if posts {
        (json!({ "channel_id": view.channel["id"], "kind": "post" }), "-last_reply_at")
    } else {
        let thread = if truthy(body.get("thread_id")) { random_id_field(&body["thread_id"], "post")? } else { String::new() };
        (json!({ "channel_id": view.channel["id"], "thread_id": thread }), "-created_date")
    };
    if body.get("before").is_some() {
        let field = if posts { "last_reply_at" } else { "created_date" };
        query[field] = json!({ "$lt": str_field(&body["before"], "cursor", 40, 1)? });
    }
    let rows = own.filter("ServerMessage", query, sort, limit + 1)?;
    let page: Vec<&Value> = rows.iter().take(limit).collect();
    let mut extra: Vec<Value> = Vec::new();
    if truthy(body.get("thread_id")) && body.get("before").is_none() {
        extra = own.filter("ServerMessage", json!({ "channel_id": view.channel["id"], "msg_id": body["thread_id"] }), "created_date", 1)?;
    }
    let cursor_field = if posts { "last_reply_at" } else { "created_date" };
    let mut all: Vec<Value> = extra;
    all.extend(page.iter().rev().map(|m| (*m).clone()));
    let messages: Vec<Value> = all.iter().filter(|m| is_live(m, now) && !hidden_from_newcomer(&view.channel, view.perms, &view.member, m)).map(server_message_out).collect();
    let before = page.last().map_or(Value::Null, |m| m.get(cursor_field).cloned().unwrap_or(Value::Null));
    let mut out = json!({ "messages": messages, "has_more": rows.len() > limit });
    if page.last().is_some_and(|m| m.get(cursor_field).is_none()) {
        // `page[i][field]` undefined: JSON leaves the key out.
    } else {
        out["before"] = before;
    }
    Ok(out)
}

fn pins(ctx: &mut Ctx) -> Result<Value> {
    let (own, uid, now) = (ctx.own(), ctx.user_id().to_string(), ctx.now);
    let server_id = id(&ctx.body["server_id"], "server")?;
    let view = channel_view(&own, &server_id, &id(&ctx.body["channel_id"], "channel")?, &uid)?;
    let rows = own.filter("ServerMessage", json!({ "channel_id": view.channel["id"], "pinned": true }), "-created_date", 50)?;
    Ok(json!({ "messages": rows.iter().filter(|m| is_live(m, now) && !truthy(m.get("deleted")) && !hidden_from_newcomer(&view.channel, view.perms, &view.member, m)).map(server_message_out).collect::<Vec<_>>() }))
}

fn delete_server_message(ctx: &mut Ctx) -> Result<Value> {
    let (_, data) = signed_by_active_device(ctx, "delete_server_message", Limits::MAX_BODY_BYTES)?;
    let (sr, own, uid, now) = (ctx.sr(), ctx.own(), ctx.user_id().to_string(), ctx.now);
    let server_id = id(&data["server_id"], "server")?;
    let message = own.first("ServerMessage", json!({ "server_id": server_id, "channel_id": id(&data["channel_id"], "channel")?, "msg_id": random_id_field(&data["msg_id"], "message")? }), "created_date")?;
    let message = message.ok_or_else(|| deny(404, "NOT_FOUND", "Message not found."))?;
    if message["sender_id"] != uid.as_str() {
        let view = channel_view(&own, &server_id, &to_js_string(message.get("channel_id")), &uid)?;
        require_perm(view.perms, p::MANAGE_MESSAGES, "delete other people's messages")?;
        let parts = server_parts(&sr, &server_id)?;
        audit(&sr, &parts.server, &uid, "message_delete", "member", &to_js_string(message.get("sender_id")), "", now)?;
    }
    if !truthy(message.get("deleted")) {
        sr.update("ServerMessage", id_of(&message), json!({ "envelope": "", "signature": "", "deleted": true, "deleted_by": uid, "deleted_at": iso(now), "pinned": false }))?;
    }
    Ok(json!({ "ok": true }))
}

fn pin_server_message(ctx: &mut Ctx) -> Result<Value> {
    let (_, data) = signed_by_active_device(ctx, "pin_server_message", Limits::MAX_BODY_BYTES)?;
    let (sr, own, uid, now) = (ctx.sr(), ctx.own(), ctx.user_id().to_string(), ctx.now);
    let server_id = id(&data["server_id"], "server")?;
    let view = channel_view(&own, &server_id, &id(&data["channel_id"], "channel")?, &uid)?;
    require_perm(view.perms, p::MANAGE_MESSAGES, "pin messages")?;
    let message = own.first("ServerMessage", json!({ "channel_id": view.channel["id"], "msg_id": random_id_field(&data["msg_id"], "message")? }), "created_date")?;
    let message = message.filter(|m| !truthy(m.get("deleted"))).ok_or_else(|| deny(404, "NOT_FOUND", "Message not found."))?;
    let pinned = data["pinned"] != false;
    sr.update("ServerMessage", id_of(&message), json!({ "pinned": pinned }))?;
    let parts = server_parts(&sr, &server_id)?;
    audit(&sr, &parts.server, &uid, if pinned { "message_pin" } else { "message_unpin" }, "channel", id_of(&view.channel), "", now)?;
    Ok(json!({ "ok": true }))
}

fn lock_thread(ctx: &mut Ctx) -> Result<Value> {
    let (_, data) = signed_by_active_device(ctx, "lock_thread", Limits::MAX_BODY_BYTES)?;
    let (sr, own, uid, now) = (ctx.sr(), ctx.own(), ctx.user_id().to_string(), ctx.now);
    let server_id = id(&data["server_id"], "server")?;
    let view = channel_view(&own, &server_id, &id(&data["channel_id"], "channel")?, &uid)?;
    require_perm(view.perms, p::MANAGE_THREADS, "lock threads")?;
    let root = own.first("ServerMessage", json!({ "channel_id": view.channel["id"], "msg_id": random_id_field(&data["msg_id"], "message")? }), "created_date")?;
    let root = root.filter(|r| !truthy(r.get("deleted")) && !truthy(r.get("thread_id")) && (r["kind"] == "post" || r["kind"] == "message")).ok_or_else(|| deny(404, "NOT_FOUND", "Thread not found."))?;
    let locked = data["locked"] != false;
    sr.update("ServerMessage", id_of(&root), json!({ "thread_locked": locked }))?;
    let parts = server_parts(&sr, &server_id)?;
    audit(&sr, &parts.server, &uid, if locked { "thread_lock" } else { "thread_unlock" }, "channel", id_of(&view.channel), "", now)?;
    Ok(json!({ "ok": true }))
}

pub fn actions() -> Actions {
    let mut a = Actions::new();
    for (name, f) in [("send", send as crate::api::Action), ("list", list), ("pins", pins), ("delete_server_message", delete_server_message), ("pin_server_message", pin_server_message), ("lock_thread", lock_thread)] {
        a.insert(name, f);
    }
    a
}

/// Server changes for a member's poll (messages.poll), with the member's own access.
pub fn poll_servers(own: &Db, user_id: &str, since: &str, changes_since: Option<&str>, settled: &str, limit: usize, now: i64) -> Result<Value> {
    let rows = own.filter("ServerMessage", json!({ "updated_date": { "$gte": since } }), "updated_date", limit + 1)?;
    let page: Vec<Value> = rows.iter().take(limit).cloned().collect();
    let has_more = rows.len() > limit;
    let mut cursor = since.to_string();
    for m in &page {
        let u = to_js_string(m.get("updated_date"));
        if u > cursor {
            cursor = u;
        }
    }
    if !has_more && cursor.as_str() > settled {
        cursor = if settled > since { settled.to_string() } else { since.to_string() };
    }
    let visible = readable_now(own, user_id, page.into_iter().filter(|m| is_live(m, now)).collect())?;
    let mut out = json!({ "server_messages": visible.iter().map(server_message_out).collect::<Vec<_>>(), "servers_cursor": cursor, "servers_more": has_more });
    if let Some(cs) = changes_since {
        let servers = own.filter("Server", json!({ "updated_date": { "$gte": cs } }), "updated_date", 100)?;
        let memberships = own.filter("ServerMember", json!({ "user_id": user_id }), "created_date", SERVERS_PER_USER + 10)?;
        let mut cc = cs.to_string();
        for s in &servers {
            let u = to_js_string(s.get("updated_date"));
            if u > cc {
                cc = u;
            }
        }
        if cc.as_str() > settled {
            cc = if settled > cs { settled.to_string() } else { cs.to_string() };
        }
        let mut ids: Vec<Value> = Vec::new();
        for m in &memberships {
            if !ids.contains(&m["server_id"]) {
                ids.push(m["server_id"].clone());
            }
        }
        out["servers"] = json!(servers.iter().filter(|s| s["status"] != "deleting").map(|s| server_out(s, false)).collect::<Vec<_>>());
        out["server_ids"] = json!(ids);
        out["server_changes_cursor"] = json!(cc);
    }
    Ok(out)
}
