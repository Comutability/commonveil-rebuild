//! Encrypted messages (base44/shared/handlers/messages.ts), and messages that wait: "send later"
//! and safety check-ins (scheduled.ts). The server checks membership, the sending device, the
//! signature and that every current member got a copy of the key, then stores ciphertext it
//! cannot read.
use serde_json::{json, Value};

use crate::api::{id, int, random_id_field, str_field, Actions, ApiError, Ctx, Limits, Result};
use crate::db::{id_of, Db};
use crate::js::{to_js_string, to_number, truthy};
use crate::notifications::{conversation_path, notify_people, subject};
use crate::shared::{
    addressed_to, assert_wraps_match_members, blocked_either_way, conversation_for_member, conversation_out, enforce_rate, ids_of, is_live, iso, message_out, my_conversations, platform_ms, rate_limited, require_active_device, within_rate,
};
use crate::verify::{check_clock, check_sent_at, iso_time, parse_envelope_shape, signed_by_active_device, verify_item_signature, MAX_ENVELOPE_CHARS};

/// How far behind "now" a poll cursor stays, so rows that show up late in queries aren't skipped.
const SETTLE_MS: i64 = 5_000;
const MESSAGES_PER_MINUTE: usize = 30;
const PAGE_SIZE: i64 = 50;
const POLL_LIMIT: usize = 200;

const PENDING_PER_USER: usize = 50;
const MAX_DAYS: i64 = 366;
const MIN_SECONDS: i64 = 60;
const PER_DELIVERY: usize = 200;
const CHECKIN_HOURS: [f64; 9] = [1.0, 2.0, 4.0, 8.0, 12.0, 24.0, 48.0, 72.0, 168.0];

fn deny(status: u16, code: &str, message: &str) -> ApiError {
    ApiError::new(status, code, message)
}
fn blank_message() -> Value {
    json!({ "conversation_id": "", "msg_id": "", "sender_id": "", "device_id": "", "envelope": "", "signature": "", "sent_at": "", "recipient_ids": [], "deleted": true })
}
fn blank_scheduled() -> Value {
    json!({ "envelope": "", "signature": "", "msg_id": "", "recipient_ids": [], "deliver_at": "" })
}
fn platform_time(ms: i64) -> String {
    crate::api::platform_time(ms)
}
fn lifetime_of(conv: &Value) -> f64 {
    let n = to_number(conv.get("expire_seconds"));
    if n.is_nan() { 0.0 } else { n }
}

fn send(ctx: &mut Ctx) -> Result<Value> {
    let (sr, own, uid, now, body) = (ctx.sr(), ctx.own(), ctx.user_id().to_string(), ctx.now, &ctx.body);
    let conv = conversation_for_member(&own, &uid, &id(&body["conversation_id"], "conversation")?)?;
    let members = ids_of(&conv["member_ids"]);
    if conv["kind"] == "dm" {
        if let Some(other) = members.iter().find(|m| **m != uid) {
            if blocked_either_way(&sr, &uid, other)? {
                return Err(deny(403, "BLOCKED", "You can't message this member."));
            }
        }
    }
    let device = require_active_device(&own, &uid, &random_id_field(&body["device_id"], "device id")?)?;
    let msg_id = random_id_field(&body["msg_id"], "message id")?;
    let sent_at = iso_time(&body["sent_at"], "sent time")?;
    check_sent_at(&sent_at, now, &body["queued"])?;
    let envelope = body["envelope"].as_str().unwrap_or("").to_string();
    let wraps = parse_envelope_shape(&envelope, MAX_ENVELOPE_CHARS)?;
    assert_wraps_match_members(&sr, &wraps, &members)?;
    let device_id = to_js_string(device.get("device_id"));
    if !verify_item_signature("message", id_of(&conv), &msg_id, &uid, &device_id, &envelope, &sent_at, &body["signature"], device["sign_pub"].as_str().unwrap_or(""))? {
        return Err(deny(403, "SIGNATURE_INVALID", "The message signature didn't verify, so it wasn't sent."));
    }
    // A message that's waiting (send later, or a check-in) is reserved (CV-09).
    let mine = own.first("Profile", json!({ "user_id": uid }), "created_date")?;
    if mine.as_ref().is_some_and(|p| to_number(p.get("scheduled_waiting")) > 0.0) {
        let waiting = sr.filter("ScheduledMessage", json!({ "conversation_id": conv["id"], "msg_id": msg_id }), "created_date", 1)?;
        if waiting.iter().any(|w| truthy(w.get("deliver_at"))) {
            return Err(deny(409, "SCHEDULED_ITEM", "That message is waiting to be sent at its time."));
        }
    }
    // A retry of a send that was stored but whose answer got lost.
    if let Some(dup) = own.first("Message", json!({ "conversation_id": conv["id"], "msg_id": msg_id }), "created_date")? {
        if dup["sender_id"] != uid.as_str() {
            return Err(deny(409, "DUPLICATE_ID", "That message id is already taken. Please try again."));
        }
        let last = if truthy(conv.get("last_message_at")) { to_js_string(conv.get("last_message_at")) } else { String::new() };
        if last < to_js_string(dup.get("created_date")) {
            sr.update("Conversation", id_of(&conv), json!({ "last_message_at": dup["created_date"] }))?;
        }
        return Ok(json!({ "message": message_out(&dup), "duplicate": true }));
    }
    enforce_rate(&own, "Message", json!({ "sender_id": uid }), 60_000, MESSAGES_PER_MINUTE, now, "sending messages")?;
    let lifetime = lifetime_of(&conv);
    let mut row = json!({
        "conversation_id": conv["id"], "msg_id": msg_id, "sender_id": uid, "device_id": device_id, "envelope": envelope,
        "signature": body["signature"], "sent_at": sent_at, "recipient_ids": wraps.iter().map(|w| w.u.clone()).collect::<Vec<_>>(), "deleted": false,
    });
    if body.get("signature").is_none() {
        row.as_object_mut().unwrap().remove("signature");
    }
    if lifetime > 0.0 {
        row["expires_at"] = json!(iso(now + (lifetime * 1000.0) as i64));
    }
    let message = sr.create("Message", row)?;
    if !within_rate(&own, "Message", json!({ "sender_id": uid }), 60_000, MESSAGES_PER_MINUTE, now, &message)? {
        sr.update("Message", id_of(&message), blank_message())?;
        sr.delete("Message", id_of(&message))?;
        return Err(rate_limited("sending messages"));
    }
    let at = if truthy(message.get("created_date")) { message["created_date"].clone() } else { json!(platform_time(now)) };
    sr.update("Conversation", id_of(&conv), json!({ "last_message_at": at }))?;
    let others: Vec<String> = members.into_iter().filter(|m| *m != uid).collect();
    notify_people(&sr, &subject(ctx), &others, "message", &conversation_path(id_of(&conv)), id_of(&conv));
    Ok(json!({ "message": message_out(&message) }))
}

fn list(ctx: &mut Ctx) -> Result<Value> {
    let (own, uid, now, body) = (ctx.own(), ctx.user_id().to_string(), ctx.now, &ctx.body);
    let conv = conversation_for_member(&own, &uid, &id(&body["conversation_id"], "conversation")?)?;
    let limit = if body.get("limit").is_none() { PAGE_SIZE } else { int(&body["limit"], "limit", 1, PAGE_SIZE)? } as usize;
    let mut query = json!({ "conversation_id": conv["id"], "$or": addressed_to(&uid) });
    if body.get("before").is_some() {
        query["created_date"] = json!({ "$lt": str_field(&body["before"], "cursor", 40, 1)? });
    }
    let rows = own.filter("Message", query, "-created_date", limit + 1)?;
    let page: Vec<&Value> = rows.iter().take(limit).collect();
    let mut messages: Vec<Value> = page.iter().filter(|m| is_live(m, now)).map(|m| message_out(m)).collect();
    messages.reverse();
    Ok(json!({ "messages": messages, "has_more": rows.len() > limit, "before": page.last().map_or(Value::Null, |m| m["created_date"].clone()) }))
}

/// Move a cursor on to the newest of these, but never past "a few seconds ago".
fn advance(since: &str, times: impl Iterator<Item = String>, settled: &str, keep_back: bool) -> String {
    let mut cursor = since.to_string();
    for t in times {
        if t > cursor {
            cursor = t;
        }
    }
    if keep_back && cursor.as_str() > settled {
        cursor = if settled > since { settled.to_string() } else { since.to_string() };
    }
    cursor
}

fn poll(ctx: &mut Ctx) -> Result<Value> {
    let (own, uid, now, body) = (ctx.own(), ctx.user_id().to_string(), ctx.now, &ctx.body);
    if body.get("since").is_none() {
        let start = platform_time(now - 5_000);
        return Ok(json!({ "cursor": start, "conversations_cursor": start, "servers_cursor": start, "server_changes_cursor": start, "messages": [], "conversations": [], "conversation_ids": [] }));
    }
    let since = str_field(&body["since"], "cursor", 40, 1)?;
    let settled = platform_time(now - SETTLE_MS);
    let rows = own.filter("Message", json!({ "recipient_ids": uid, "updated_date": { "$gte": since } }), "updated_date", POLL_LIMIT + 1)?;
    let page: Vec<&Value> = rows.iter().take(POLL_LIMIT).collect();
    let has_more = rows.len() > POLL_LIMIT;
    let cursor = advance(&since, page.iter().map(|m| to_js_string(m.get("updated_date"))), &settled, !has_more);
    let mut out = json!({ "cursor": cursor, "messages": page.iter().filter(|m| is_live(m, now)).map(|m| message_out(m)).collect::<Vec<_>>(), "has_more": has_more });
    if body.get("conversations_since").is_some() {
        let conv_since = str_field(&body["conversations_since"], "cursor", 40, 1)?;
        let convs = my_conversations(&own, &uid, 500)?;
        let changed: Vec<&Value> = convs.iter().filter(|c| to_js_string(c.get("updated_date")) >= conv_since).collect();
        let conv_cursor = advance(&conv_since, changed.iter().map(|c| to_js_string(c.get("updated_date"))), &settled, true);
        out["conversations"] = json!(changed.iter().map(|c| conversation_out(c)).collect::<Vec<_>>());
        out["conversation_ids"] = json!(convs.iter().map(|c| c["id"].clone()).collect::<Vec<_>>());
        out["conversations_cursor"] = json!(conv_cursor);
    }
    if body.get("servers_since").is_some() {
        // Server messages move to Rust with the servers themselves.
        return Err(ApiError::new(501, "NOT_YET", "This part of the server hasn't moved to Rust yet."));
    }
    Ok(out)
}

fn delete(ctx: &mut Ctx) -> Result<Value> {
    let (_, data) = signed_by_active_device(ctx, "delete", Limits::MAX_BODY_BYTES)?;
    let (sr, own, uid, now) = (ctx.sr(), ctx.own(), ctx.user_id().to_string(), ctx.now);
    let message = own.get("Message", &id(&data["message_id"], "message")?);
    let Some(message) = message.filter(|m| m["sender_id"] == uid.as_str()) else { return Err(deny(404, "NOT_FOUND", "Message not found.")) };
    if !truthy(message.get("deleted")) {
        sr.update("Message", id_of(&message), json!({ "deleted": true, "envelope": "", "signature": "", "deleted_at": iso(now) }))?;
    }
    Ok(json!({ "ok": true }))
}

// ---------- messages that wait (scheduled.ts) ----------

fn scheduled_out(r: &Value) -> Value {
    let hours = to_number(r.get("checkin_hours"));
    let mut o = json!({
        "id": r["id"], "conversation_id": r["conversation_id"], "kind": r["kind"], "deliver_at": r["deliver_at"], "checkin_hours": crate::js::number_value(if hours.is_nan() { 0.0 } else { hours }),
        "msg_id": r["msg_id"], "sender_id": r["sender_id"], "device_id": r["device_id"], "envelope": r["envelope"], "signature": r["signature"], "sent_at": r["sent_at"],
        "created_date": r["created_date"],
    });
    if let Some(m) = o.as_object_mut() {
        m.retain(|k, v| !(v.is_null() && r.get(k).is_none()) || k == "checkin_hours");
    }
    o
}

fn mine(ctx: &Ctx, row_id: &Value) -> Result<Value> {
    let row = ctx.sr().get("ScheduledMessage", &id(row_id, "scheduled message")?);
    match row {
        Some(r) if r["sender_id"] == ctx.user_id() && truthy(r.get("deliver_at")) => Ok(r),
        _ => Err(deny(404, "NOT_FOUND", "That scheduled message isn't waiting any more.")),
    }
}

/// How many of a sender's messages are waiting, kept on their own profile (CV-09).
pub fn recount_waiting(sr: &Db, sender_id: &str) -> Result<()> {
    let rows = sr.filter("ScheduledMessage", json!({ "sender_id": sender_id }), "created_date", PENDING_PER_USER + 5)?;
    let count = rows.iter().filter(|r| truthy(r.get("deliver_at"))).count();
    if let Some(p) = sr.first("Profile", json!({ "user_id": sender_id }), "created_date")? {
        let n = to_number(p.get("scheduled_waiting"));
        if (if n.is_nan() { 0.0 } else { n }) != count as f64 {
            sr.update("Profile", id_of(&p), json!({ "scheduled_waiting": count }))?;
        }
    }
    Ok(())
}

/// Deliver what's due: into the conversation, for whoever is still in it.
pub fn deliver_due(sr: &Db, subject: &str, now: i64, deadline: i64, only: Value) -> Result<usize> {
    let mut q = only;
    q["deliver_at"] = json!({ "$gt": "", "$lte": iso(now) });
    let due = sr.filter("ScheduledMessage", q, "deliver_at", PER_DELIVERY)?;
    let mut delivered = 0;
    for row in &due {
        if crate::sessions::now_ms() > deadline {
            break;
        }
        let sender = to_js_string(row.get("sender_id"));
        let conv = sr.get("Conversation", &to_js_string(row.get("conversation_id")));
        let members = conv.as_ref().map(|c| ids_of(&c["member_ids"])).unwrap_or_default();
        let mut ok = conv.is_some() && members.contains(&sender);
        if let (true, Some(c)) = (ok, &conv) {
            if c["kind"] == "dm" {
                if let Some(other) = members.iter().find(|m| **m != sender) {
                    if blocked_either_way(sr, &sender, other)? {
                        ok = false;
                    }
                }
            }
        }
        let recipients: Vec<String> = ids_of(&row["recipient_ids"]).into_iter().filter(|u| members.contains(u)).collect();
        if let (true, false, Some(c)) = (ok, recipients.is_empty(), &conv) {
            if sr.first("Message", json!({ "conversation_id": c["id"], "msg_id": row["msg_id"] }), "created_date")?.is_none() {
                let lifetime = lifetime_of(c);
                let mut m = json!({
                    "conversation_id": c["id"], "msg_id": row["msg_id"], "sender_id": row["sender_id"], "device_id": row["device_id"], "envelope": row["envelope"],
                    "signature": row["signature"], "sent_at": row["sent_at"], "recipient_ids": recipients, "deleted": false, "scheduled": true,
                });
                if lifetime > 0.0 {
                    m["expires_at"] = json!(iso(now + (lifetime * 1000.0) as i64));
                }
                let m = sr.create("Message", m)?;
                let at = if truthy(m.get("created_date")) { m["created_date"].clone() } else { json!(platform_time(now)) };
                sr.update("Conversation", id_of(c), json!({ "last_message_at": at }))?;
                let to: Vec<String> = recipients.iter().filter(|u| **u != sender).cloned().collect();
                notify_people(sr, subject, &to, "message", &conversation_path(id_of(c)), id_of(c));
                delivered += 1;
            }
        }
        let _ = sr.update("ScheduledMessage", id_of(row), blank_scheduled());
        let _ = sr.delete("ScheduledMessage", id_of(row));
        let _ = recount_waiting(sr, &sender);
    }
    Ok(delivered)
}

fn schedule(ctx: &mut Ctx) -> Result<Value> {
    let (sr, own, uid, now, body) = (ctx.sr(), ctx.own(), ctx.user_id().to_string(), ctx.now, &ctx.body);
    let conv = conversation_for_member(&own, &uid, &id(&body["conversation_id"], "conversation")?)?;
    let kind = if body["kind"] == "checkin" { "checkin" } else { "later" };
    let mut hours = 0.0;
    let deliver_at = if kind == "checkin" {
        hours = to_number(body.get("checkin_hours"));
        if !CHECKIN_HOURS.contains(&hours) {
            return Err(deny(400, "BAD_FIELD", "Choose how long until you check in."));
        }
        now + (hours * 3_600_000.0) as i64
    } else {
        let at = crate::dates::parse(&iso_time(&body["deliver_at"], "delivery time")?).unwrap_or(f64::NAN) as i64;
        let ahead = at - now;
        if !(MIN_SECONDS * 1000..=MAX_DAYS * 86_400_000).contains(&ahead) {
            return Err(deny(400, "BAD_FIELD", "Choose a time from a minute to a year from now."));
        }
        at
    };
    let pending = sr.filter("ScheduledMessage", json!({ "sender_id": uid }), "created_date", PENDING_PER_USER + 1)?;
    if pending.iter().filter(|r| truthy(r.get("deliver_at"))).count() >= PENDING_PER_USER {
        return Err(rate_limited("scheduling messages (you have the most waiting you can)"));
    }
    let device = require_active_device(&own, &uid, &random_id_field(&body["device_id"], "device id")?)?;
    let msg_id = random_id_field(&body["msg_id"], "message id")?;
    let sent_at = iso_time(&body["sent_at"], "sent time")?;
    check_clock(&sent_at, now)?;
    let envelope = body["envelope"].as_str().unwrap_or("").to_string();
    let wraps = parse_envelope_shape(&envelope, MAX_ENVELOPE_CHARS)?;
    assert_wraps_match_members(&sr, &wraps, &ids_of(&conv["member_ids"]))?;
    let device_id = to_js_string(device.get("device_id"));
    if !verify_item_signature("message", id_of(&conv), &msg_id, &uid, &device_id, &envelope, &sent_at, &body["signature"], device["sign_pub"].as_str().unwrap_or(""))? {
        return Err(deny(403, "SIGNATURE_INVALID", "The message signature didn't verify."));
    }
    let row = sr.create("ScheduledMessage", json!({
        "conversation_id": conv["id"], "sender_id": uid, "device_id": device_id, "msg_id": msg_id, "envelope": envelope, "signature": body["signature"], "sent_at": sent_at,
        "recipient_ids": wraps.iter().map(|w| w.u.clone()).collect::<Vec<_>>(), "deliver_at": iso(deliver_at), "kind": kind, "checkin_hours": crate::js::number_value(hours),
    }))?;
    recount_waiting(&sr, &uid)?;
    Ok(json!({ "scheduled": scheduled_out(&row) }))
}

fn scheduled(ctx: &mut Ctx) -> Result<Value> {
    let (sr, uid, body) = (ctx.sr(), ctx.user_id().to_string(), &ctx.body);
    let mut q = json!({ "sender_id": uid });
    if truthy(body.get("conversation_id")) {
        q["conversation_id"] = json!(id(&body["conversation_id"], "conversation")?);
    }
    let rows: Vec<Value> = sr.filter("ScheduledMessage", q, "deliver_at", 100)?.into_iter().filter(|r| truthy(r.get("deliver_at"))).collect();
    Ok(json!({ "scheduled": rows.iter().map(scheduled_out).collect::<Vec<_>>() }))
}

fn cancel_scheduled(ctx: &mut Ctx) -> Result<Value> {
    let (_, data) = signed_by_active_device(ctx, "cancel_scheduled", Limits::MAX_BODY_BYTES)?;
    let row = mine(ctx, &data["id"])?;
    let sr = ctx.sr();
    sr.update("ScheduledMessage", id_of(&row), blank_scheduled())?;
    sr.delete("ScheduledMessage", id_of(&row))?;
    recount_waiting(&sr, ctx.user_id())?;
    Ok(json!({ "ok": true }))
}

fn check_in(ctx: &mut Ctx) -> Result<Value> {
    let (_, data) = signed_by_active_device(ctx, "check_in", Limits::MAX_BODY_BYTES)?;
    let row = mine(ctx, &data["id"])?;
    if row["kind"] != "checkin" {
        return Err(deny(400, "BAD_FIELD", "That isn't a check-in."));
    }
    let h = to_number(row.get("checkin_hours"));
    let h = if h.is_nan() || h == 0.0 { 24.0 } else { h };
    let at = iso(ctx.now + (h * 3_600_000.0) as i64);
    ctx.sr().update("ScheduledMessage", id_of(&row), json!({ "deliver_at": at }))?;
    Ok(json!({ "deliver_at": at }))
}

fn deliver_mine(ctx: &mut Ctx) -> Result<Value> {
    let n = deliver_due(&ctx.sr(), &subject(ctx), ctx.now, crate::sessions::now_ms() + 20_000, json!({ "sender_id": ctx.user_id() }))?;
    Ok(json!({ "delivered": n }))
}

pub fn actions() -> Actions {
    let mut a = Actions::new();
    for (name, f) in [
        ("schedule", schedule as crate::api::Action),
        ("scheduled", scheduled),
        ("cancel_scheduled", cancel_scheduled),
        ("check_in", check_in),
        ("deliver_mine", deliver_mine),
        ("send", send),
        ("list", list),
        ("poll", poll),
        ("delete", delete),
    ] {
        a.insert(name, f);
    }
    a
}

/// A waiting message's time (used by tests).
pub fn due_at(r: &Value) -> f64 {
    platform_ms(&r["deliver_at"])
}
