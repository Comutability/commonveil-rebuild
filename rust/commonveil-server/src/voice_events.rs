//! Voice-call passes (base44/shared/handlers/voice.ts) and scheduled events
//! (base44/shared/handlers/events.ts).
//!
//! Voice: this only hands out a one-minute, single-use pass to join one call. The call runs in
//! the VoiceRoom actor, which passes connection set-up between devices and nothing else: audio
//! and video go directly between devices, encrypted end to end.
//!
//! Events: an event's details are one encrypted item, and so is each answer. The service stores
//! both without reading them; it knows a server has an event, and which members answered.
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha1::Sha1;

use crate::api::{id, random_id_field, Actions, ApiError, Ctx, Limits, Result};
use crate::db::{id_of, Db};
use crate::js::{to_js_string, truthy};
use crate::permissions::{has, p};
use crate::servers::{signed_member, Signed};
use crate::servers_core::*;
use crate::shared::{ids_of, iso, platform_ms, rate_limited};
use crate::verify::signed_by_active_device;

pub const VOICE_PER_CALL: usize = 8;
pub const VOICE_PER_STAGE: usize = 16;
pub const VOICE_TICKET_SECONDS: i64 = 60;
pub const VOICE_TICKETS_PER_MINUTE: usize = 6;
pub const EVENTS_PER_SERVER: usize = 50;
pub const RSVPS_LISTED: usize = 2000;

/// coturn REST API credentials for configured relay servers. The user ID
/// contains no name, email or IP; the long operator secret never reaches a
/// client. Disabled when the operator has not provided a valid configuration.
fn turn_ice_servers(user_id: &str) -> Value {
    let secret = std::env::var("VOICE_TURN_SECRET")
        .unwrap_or_default()
        .trim()
        .to_string();
    let urls_raw = std::env::var("VOICE_TURN_URLS").unwrap_or_default();
    let urls: Vec<&str> = urls_raw
        .split(',')
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .collect();
    if secret.len() < 32 || urls.is_empty() {
        return json!([]);
    }
    let url_pattern =
        regex::Regex::new(r"^turns?:[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:\?transport=(?:udp|tcp))?$")
            .expect("static TURN URL pattern");
    if urls.iter().any(|url| !url_pattern.is_match(url)) {
        return json!([]);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let username = format!("{}:{user_id}", now + 6 * 60 * 60);
    let mut mac =
        Hmac::<Sha1>::new_from_slice(secret.as_bytes()).expect("HMAC accepts a shared secret");
    mac.update(username.as_bytes());
    let credential = STANDARD.encode(mac.finalize().into_bytes());
    json!([{ "urls": urls, "username": username, "credential": credential }])
}

/// The actor room for a voice or stage channel's call.
pub fn voice_room_id(server_id: &str, channel_id: &str) -> String {
    format!("{server_id}.{channel_id}")
}

/// The actor room for one call in a conversation.
pub fn call_room_id(conversation_id: &str, call_id: &str) -> String {
    format!("dm.{conversation_id}.{call_id}")
}

fn call_id_ok(v: &Value) -> Option<String> {
    let s = v.as_str()?;
    ((8..=32).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
    .then(|| s.to_string())
}

fn deny(status: u16, code: &str, message: &str) -> ApiError {
    ApiError::new(status, code, message)
}

fn parse_ms(v: Option<&Value>) -> f64 {
    crate::dates::parse(&to_js_string(v)).unwrap_or(f64::NAN)
}

fn issue(
    ctx: &Ctx,
    device: &Value,
    room: &str,
    can_speak: bool,
    can_moderate: bool,
    stage: bool,
) -> Result<Value> {
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now as f64);
    // Old passes are useless after a minute: clear this account's, and slow down floods.
    let mine = sr.filter(
        "VoiceTicket",
        json!({ "user_id": uid }),
        "-created_date",
        50,
    )?;
    let recent = mine
        .iter()
        .filter(|t| {
            let at = if truthy(t.get("created_date")) {
                platform_ms(&t["created_date"])
            } else {
                parse_ms(t.get("expires_at"))
            };
            now - at < 60_000.0
        })
        .count();
    if recent >= VOICE_TICKETS_PER_MINUTE {
        return Err(rate_limited("joining calls"));
    }
    for t in mine.iter().filter(|t| parse_ms(t.get("expires_at")) < now) {
        let _ = sr.delete("VoiceTicket", id_of(t));
    }
    let row = sr.create(
        "VoiceTicket",
        json!({
            "room": room, "user_id": uid, "device_id": device["device_id"], "can_speak": can_speak, "can_moderate": can_moderate,
            "stage": stage, "expires_at": iso(ctx.now + VOICE_TICKET_SECONDS * 1000),
        }),
    )?;
    Ok(json!({
        "ticket": row["id"], "room": room, "can_speak": can_speak, "can_moderate": can_moderate, "stage": stage,
        "max_people": if stage { VOICE_PER_STAGE } else { VOICE_PER_CALL },
        "turn_servers": turn_ice_servers(&uid),
    }))
}

fn voice_ticket(ctx: &mut Ctx) -> Result<Value> {
    let (device, data) = signed_by_active_device(ctx, "voice_ticket", Limits::MAX_BODY_BYTES)?;
    let server_id = id(&data["server_id"], "server")?;
    let member = require_member(&ctx.own(), &server_id, ctx.user_id())?;
    let parts = server_parts(&ctx.sr(), &server_id)?;
    let channel = channel_in(&parts, &id(&data["channel_id"], "channel")?)?;
    if channel["kind"] != "voice" && channel["kind"] != "stage" {
        return Err(deny(400, "BAD_FIELD", "That isn't a voice channel."));
    }
    let perms = perms_of(&parts, &member, Some(channel));
    if !has(perms, p::VIEW_CHANNEL) || !has(perms, p::CONNECT) {
        return Err(deny(
            403,
            "MISSING_PERMISSION",
            "You don't have permission to join this call.",
        ));
    }
    if truthy(member.get("timeout_until")) && parse_ms(member.get("timeout_until")) > ctx.now as f64
    {
        return Err(deny(
            403,
            "TIMED_OUT",
            "You're timed out in this server, so you can't join calls for now.",
        ));
    }
    let stage = channel["kind"] == "stage";
    // On a stage, moderators speak; everyone else listens until a moderator brings them up.
    let can_moderate = has(perms, p::MUTE_MEMBERS);
    let can_speak = if stage {
        can_moderate
    } else {
        has(perms, p::SPEAK)
    };
    issue(
        ctx,
        &device,
        &voice_room_id(&server_id, id_of(channel)),
        can_speak,
        can_moderate,
        stage,
    )
}

fn call_ticket(ctx: &mut Ctx) -> Result<Value> {
    let (device, data) = signed_by_active_device(ctx, "call_ticket", Limits::MAX_BODY_BYTES)?;
    let conv = ctx.sr().get(
        "Conversation",
        &id(&data["conversation_id"], "conversation")?,
    );
    let Some(conv) = conv.filter(|c| ids_of(&c["member_ids"]).iter().any(|m| m == ctx.user_id()))
    else {
        return Err(deny(404, "NOT_FOUND", "Conversation not found."));
    };
    let call_id =
        call_id_ok(&data["call_id"]).ok_or_else(|| deny(400, "BAD_FIELD", "Invalid call."))?;
    issue(
        ctx,
        &device,
        &call_room_id(id_of(&conv), &call_id),
        true,
        false,
        false,
    )
}

pub fn voice_actions() -> Actions {
    let mut a = Actions::new();
    a.insert("voice_ticket", voice_ticket as crate::api::Action);
    a.insert("call_ticket", call_ticket);
    a
}

// ---------- events ----------

fn event_out(e: &Value) -> Value {
    let mut o = json!({});
    for (k, src) in [
        ("event_id", "event_id"),
        ("creator_id", "creator_id"),
        ("created_date", "created_date"),
    ] {
        if let Some(v) = e.get(src) {
            o[k] = v.clone();
        }
    }
    o["item"] = item_out(e, "event");
    o
}

fn rsvp_out(r: &Value) -> Value {
    let mut o = json!({});
    for k in ["event_id", "user_id"] {
        if let Some(v) = r.get(k) {
            o[k] = v.clone();
        }
    }
    o["item"] = item_out(r, "rsvp");
    o
}

fn event_row(sr: &Db, server_id: &str, event_id: &str) -> Result<Value> {
    sr.first(
        "ServerEvent",
        json!({ "server_id": server_id, "event_id": event_id }),
        "created_date",
    )?
    .ok_or_else(|| deny(404, "NOT_FOUND", "That event isn't here any more."))
}

fn accept_event_item(ctx: &Ctx, kind: &str, server_id: &str, item: &Value) -> Result<Value> {
    let gens = generations_of(&ctx.sr(), server_id, None)?;
    accept_item(
        &ctx.own(),
        ctx.user_id(),
        ctx.now,
        kind,
        server_id,
        "",
        item,
        &gens,
        None,
        MAX_ITEM_ENVELOPE_CHARS,
    )
}

fn merge(mut a: Value, b: &Value) -> Value {
    for (k, v) in b.as_object().into_iter().flatten() {
        a[k] = v.clone();
    }
    a
}

fn list(ctx: &mut Ctx) -> Result<Value> {
    let own = ctx.own();
    let server_id = id(&ctx.body["server_id"], "server")?;
    require_member(&own, &server_id, ctx.user_id())?;
    let events = own.filter(
        "ServerEvent",
        json!({ "audience_id": server_id }),
        "created_date",
        EVENTS_PER_SERVER,
    )?;
    let rsvps = if events.is_empty() {
        vec![]
    } else {
        own.filter(
            "EventRsvp",
            json!({ "audience_id": server_id }),
            "created_date",
            RSVPS_LISTED,
        )?
    };
    Ok(
        json!({ "events": events.iter().map(event_out).collect::<Vec<_>>(), "rsvps": rsvps.iter().map(rsvp_out).collect::<Vec<_>>() }),
    )
}

fn shared_event(ctx: &mut Ctx) -> Result<Value> {
    let event_id = random_id_field(&ctx.body["event_id"], "event")?;
    let row = ctx.own().first(
        "ServerEvent",
        json!({ "event_id": event_id }),
        "created_date",
    )?;
    let row = row.ok_or_else(|| {
        deny(
            404,
            "NOT_FOUND",
            "That event isn't here any more, or it's in a server you're not in.",
        )
    })?;
    Ok(
        json!({ "server_id": row.get("server_id").cloned().unwrap_or(Value::Null), "event": event_out(&row) }),
    )
}

fn create_event(ctx: &mut Ctx) -> Result<Value> {
    let Signed {
        data,
        server_id,
        parts,
        perms,
        ..
    } = signed_member(ctx, "create_event")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    if !has(perms, p::MANAGE_EVENTS) {
        return Err(deny(
            403,
            "MISSING_PERMISSION",
            "You can't schedule events here.",
        ));
    }
    if sr
        .filter(
            "ServerEvent",
            json!({ "server_id": server_id }),
            "created_date",
            EVENTS_PER_SERVER + 1,
        )?
        .len()
        >= EVENTS_PER_SERVER
    {
        return Err(deny(
            409,
            "LIMIT_REACHED",
            &format!(
                "A server can have up to {EVENTS_PER_SERVER} events. Cancel an old one first."
            ),
        ));
    }
    let accepted = accept_event_item(ctx, "event", &server_id, &data["item"])?;
    let fields = item_fields("event", &accepted);
    let row = sr.create("ServerEvent", merge(json!({ "server_id": server_id, "audience_id": server_id, "event_id": accepted["item_id"], "creator_id": uid }), &fields))?;
    audit(
        &sr,
        &parts.server,
        &uid,
        "event_create",
        "server",
        &server_id,
        "",
        now,
    )?;
    Ok(json!({ "event": event_out(&row) }))
}

fn update_event(ctx: &mut Ctx) -> Result<Value> {
    let Signed {
        data,
        server_id,
        parts,
        perms,
        ..
    } = signed_member(ctx, "update_event")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    if !has(perms, p::MANAGE_EVENTS) {
        return Err(deny(
            403,
            "MISSING_PERMISSION",
            "You can't change events here.",
        ));
    }
    let row = event_row(
        &sr,
        &server_id,
        &random_id_field(&data["event_id"], "event")?,
    )?;
    let accepted = accept_event_item(ctx, "event", &server_id, &data["item"])?;
    // The event keeps its id; the new item's own id is only for its signature.
    let fields = item_fields("event", &accepted);
    sr.update("ServerEvent", id_of(&row), fields.clone())?;
    audit(
        &sr,
        &parts.server,
        &uid,
        "event_update",
        "server",
        &server_id,
        "",
        now,
    )?;
    Ok(json!({ "event": event_out(&merge(row, &fields)) }))
}

fn cancel_event(ctx: &mut Ctx) -> Result<Value> {
    let Signed {
        data,
        server_id,
        parts,
        perms,
        ..
    } = signed_member(ctx, "cancel_event")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    if !has(perms, p::MANAGE_EVENTS) {
        return Err(deny(
            403,
            "MISSING_PERMISSION",
            "You can't cancel events here.",
        ));
    }
    let row = event_row(
        &sr,
        &server_id,
        &random_id_field(&data["event_id"], "event")?,
    )?;
    sr.delete_many(
        "EventRsvp",
        json!({ "server_id": server_id, "event_id": row["event_id"] }),
    )?;
    sr.update("ServerEvent", id_of(&row), cleared_item("event"))?;
    sr.delete("ServerEvent", id_of(&row))?;
    audit(
        &sr,
        &parts.server,
        &uid,
        "event_cancel",
        "server",
        &server_id,
        "",
        now,
    )?;
    Ok(json!({ "ok": true }))
}

fn rsvp(ctx: &mut Ctx) -> Result<Value> {
    let Signed {
        data,
        server_id,
        perms,
        ..
    } = signed_member(ctx, "rsvp")?;
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    if !has(perms, p::VIEW_CHANNEL) {
        return Err(deny(
            403,
            "MISSING_PERMISSION",
            "You can't answer events here.",
        ));
    }
    let row = event_row(
        &sr,
        &server_id,
        &random_id_field(&data["event_id"], "event")?,
    )?;
    for r in sr.filter(
        "EventRsvp",
        json!({ "server_id": server_id, "event_id": row["event_id"], "user_id": uid }),
        "created_date",
        5,
    )? {
        sr.delete("EventRsvp", id_of(&r))?;
    }
    if data.get("item") == Some(&Value::Null) {
        return Ok(json!({ "ok": true }));
    }
    let accepted = accept_event_item(ctx, "rsvp", &server_id, &data["item"])?;
    sr.create("EventRsvp", merge(json!({ "server_id": server_id, "audience_id": server_id, "event_id": row["event_id"], "user_id": uid }), &item_fields("rsvp", &accepted)))?;
    Ok(json!({ "ok": true }))
}

pub fn event_actions() -> Actions {
    let mut a = Actions::new();
    for (name, f) in [
        ("list", list as crate::api::Action),
        ("shared_event", shared_event),
        ("create_event", create_event),
        ("update_event", update_event),
        ("cancel_event", cancel_event),
        ("rsvp", rsvp),
    ] {
        a.insert(name, f);
    }
    a
}
