//! Attachments (base44/shared/handlers/files.ts). Files are encrypted on the sender's device, in
//! parts, before they reach this function: it stores ciphertext it can't read, as private files,
//! and hands out short-lived links only to people who can see where the file was sent. The file's
//! key, name and type travel inside the end-to-end encrypted message, never here.
use std::collections::HashMap;

use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine;
use serde_json::{json, Value};

use crate::api::{id, random_id_field, Actions, ApiError, Ctx, Result};
use crate::db::{id_of, Db};
use crate::js::{to_js_string, to_number, truthy};
use crate::permissions::{has, p};
use crate::servers_core::{channel_in, perms_of, require_member, server_parts};
use crate::shared::{count_since, ids_of, iso, rate_limited};
use crate::verify::signed_by_active_device;

/// Bytes of ciphertext in one part (the last part can be smaller).
pub const PART_BYTES: usize = 768 * 1024;
/// Parts in one file: up to about 10 MB.
pub const MAX_PARTS: f64 = 14.0;
/// Parts one account can upload in ten minutes.
pub const PARTS_PER_10_MIN: usize = 150;
/// How long a download link works.
pub const LINK_SECONDS: f64 = 300.0;
/// Links handed out in one request.
pub const MAX_LINKS: usize = 60;
/// Body size the files function accepts: one part, base64, plus the signed request around it.
pub const FILES_MAX_BODY: usize = (PART_BYTES * 4).div_ceil(3) + 16 * 1024;

/// `atob`: standard alphabet, and it doesn't mind stray bits at the end.
const ATOB: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

fn bad(message: &str) -> ApiError {
    ApiError::new(400, "BAD_FIELD", message)
}

fn decode_part(data: &Value) -> Result<Vec<u8>> {
    let Some(s) = data.as_str() else {
        return Err(bad("Invalid file part."));
    };
    let body = s.trim_end_matches('=');
    let shape = !s.is_empty()
        && s.len() % 4 == 0
        && s.len() - body.len() <= 2
        && !body.is_empty()
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/');
    if !shape {
        return Err(bad("Invalid file part."));
    }
    let bytes = ATOB.decode(s).map_err(|_| bad("Invalid file part."))?;
    if bytes.len() > PART_BYTES || bytes.len() < 29 {
        return Err(ApiError::new(
            413,
            "TOO_LARGE",
            "That file part is too large.",
        ));
    }
    Ok(bytes)
}

/// May this person see things posted at this place? Returns where, for the row.
fn place_for(ctx: &Ctx, data: &Value, sending: bool) -> Result<Value> {
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    let not_found = || ApiError::new(404, "NOT_FOUND", "Not found.");
    match data["scope"].as_str() {
        Some("server") => {
            let server_id = id(&data["server_id"], "server")?;
            let member = require_member(&ctx.own(), &server_id, &uid)?;
            let parts = server_parts(&sr, &server_id)?;
            let channel = channel_in(&parts, &id(&data["channel_id"], "channel")?)?;
            let perms = perms_of(&parts, &member, Some(channel));
            if !has(perms, p::VIEW_CHANNEL) {
                return Err(not_found());
            }
            if sending {
                if !has(perms, p::SEND_MESSAGES) && !has(perms, p::CREATE_POSTS) {
                    return Err(ApiError::new(
                        403,
                        "MISSING_PERMISSION",
                        "You can't post files here.",
                    ));
                }
                if truthy(member.get("timeout_until"))
                    && crate::dates::parse(&to_js_string(member.get("timeout_until")))
                        .unwrap_or(f64::NAN)
                        > ctx.now as f64
                {
                    return Err(ApiError::new(
                        403,
                        "TIMED_OUT",
                        "You're timed out in this server.",
                    ));
                }
            }
            Ok(json!({ "scope": "server", "scope_id": server_id, "channel_id": channel["id"] }))
        }
        Some("conversation") => {
            let conv = sr.get(
                "Conversation",
                &id(&data["conversation_id"], "conversation")?,
            );
            let conv = conv
                .filter(|c| ids_of(&c["member_ids"]).contains(&uid))
                .ok_or_else(not_found)?;
            Ok(json!({ "scope": "conversation", "scope_id": conv["id"], "channel_id": "" }))
        }
        _ => Err(bad("Invalid place.")),
    }
}

fn message_row(sr: &Db, row: &Value) -> Result<Option<Value>> {
    if row["scope"] == "server" {
        sr.first(
            "ServerMessage",
            json!({ "msg_id": row["msg_id"], "server_id": row["scope_id"] }),
            "created_date",
        )
    } else {
        sr.first(
            "Message",
            json!({ "msg_id": row["msg_id"], "conversation_id": row["scope_id"] }),
            "created_date",
        )
    }
}

/// The file's message exists, wasn't deleted, and was sent by whoever uploaded the file.
fn message_exists(sr: &Db, row: &Value) -> Result<bool> {
    let Some(m) = message_row(sr, row)? else {
        return Ok(false);
    };
    let expired = truthy(m.get("expires_at"))
        && crate::dates::parse(&to_js_string(m.get("expires_at"))).unwrap_or(f64::NAN)
            <= crate::sessions::now_ms() as f64;
    Ok(!truthy(m.get("deleted")) && !expired && m["sender_id"] == row["owner_id"])
}

fn whole_number(v: &Value) -> Option<f64> {
    let n = to_number(Some(v));
    (n.is_finite() && n.fract() == 0.0).then_some(n)
}

fn upload_part(ctx: &mut Ctx) -> Result<Value> {
    let (_, data) = signed_by_active_device(ctx, "upload_part", FILES_MAX_BODY)?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    let place = place_for(ctx, &data, true)?;
    let msg_id = random_id_field(&data["msg_id"], "message id")?;
    let (part, parts) = (whole_number(&data["part"]), whole_number(&data["parts"]));
    let (Some(part), Some(parts)) = (part, parts) else {
        return Err(bad("That file is too large: files can be up to 10 MB."));
    };
    if !(1.0..=MAX_PARTS).contains(&parts) || part < 0.0 || part >= parts {
        return Err(bad("That file is too large: files can be up to 10 MB."));
    }
    let bytes = decode_part(&data["data"])?;
    // Parts are uploaded before their message is sent. A message id that's already in use (anyone's)
    // can't have parts added to it, so nobody can hang files on someone else's message.
    let mut probe = place.clone();
    probe["msg_id"] = json!(msg_id);
    if message_row(&sr, &probe)?.is_some() {
        return Err(ApiError::new(
            409,
            "DUPLICATE_ID",
            "That message has already been sent.",
        ));
    }
    if count_since(
        &sr,
        "Attachment",
        json!({ "owner_id": uid }),
        now - 600_000,
        PARTS_PER_10_MIN,
    )? >= PARTS_PER_10_MIN
    {
        return Err(rate_limited("uploading files"));
    }
    let file_uri = ctx.app.files.upload(&bytes).map_err(|_| {
        ApiError::new(
            502,
            "UPLOAD_FAILED",
            "The file couldn't be stored. Try again.",
        )
    })?;
    let mut row = place;
    for (k, v) in [
        ("owner_id", json!(uid)),
        ("msg_id", json!(msg_id)),
        ("part", crate::js::number_value(part)),
        ("parts", crate::js::number_value(parts)),
        ("size", json!(bytes.len())),
        ("file_uri", json!(file_uri)),
        ("swept_at", json!("")),
    ] {
        row[k] = v;
    }
    let row = sr.create("Attachment", row)?;
    Ok(json!({ "file_id": row["id"] }))
}

fn file_id_ok(v: &Value) -> Option<String> {
    let s = v.as_str()?;
    ((1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
    .then(|| s.to_string())
}

fn download_links(ctx: &mut Ctx) -> Result<Value> {
    let sr = ctx.sr();
    let mut ids: Vec<String> = Vec::new();
    for v in ctx.body["file_ids"].as_array().into_iter().flatten() {
        if let Some(s) = file_id_ok(v) {
            if !ids.contains(&s) {
                ids.push(s);
            }
        }
    }
    ids.truncate(MAX_LINKS);
    if ids.is_empty() {
        return Ok(json!({ "links": {} }));
    }
    let rows = sr.filter(
        "Attachment",
        json!({ "id": { "$in": ids } }),
        "created_date",
        ids.len(),
    )?;
    let mut allowed: Vec<(String, bool)> = Vec::new();
    let mut live: HashMap<String, bool> = HashMap::new();
    let mut links = serde_json::Map::new();
    for row in &rows {
        let key = format!(
            "{}:{}:{}",
            to_js_string(row.get("scope")),
            to_js_string(row.get("scope_id")),
            to_js_string(row.get("channel_id"))
        );
        let known = allowed.iter().find(|(k, _)| *k == key).map(|(_, ok)| *ok);
        // A message's files are all in one place: a request spanning many places is refused there.
        let ok = match known {
            Some(ok) => ok,
            None if allowed.len() >= 5 => continue,
            None => {
                let place = if row["scope"] == "server" {
                    json!({ "scope": "server", "server_id": row["scope_id"], "channel_id": row["channel_id"] })
                } else {
                    json!({ "scope": "conversation", "conversation_id": row["scope_id"] })
                };
                let ok = place_for(ctx, &place, false).is_ok();
                allowed.push((key, ok));
                ok
            }
        };
        if !ok {
            continue;
        }
        // A file goes with its message: once that's deleted or has disappeared, so has the file.
        let msg_key = format!(
            "{}:{}:{}",
            to_js_string(row.get("scope")),
            to_js_string(row.get("msg_id")),
            to_js_string(row.get("owner_id"))
        );
        let exists = match live.get(&msg_key) {
            Some(e) => *e,
            None => {
                let e = message_exists(&sr, row)?;
                live.insert(msg_key, e);
                e
            }
        };
        if !exists {
            continue;
        }
        if let Some(url) = ctx.app.files.signed_url(
            &to_js_string(row.get("file_uri")),
            LINK_SECONDS,
            crate::sessions::now_ms(),
        ) {
            links.insert(id_of(row).to_string(), json!(url));
        }
    }
    Ok(json!({ "links": links }))
}

pub fn actions() -> Actions {
    let mut a = Actions::new();
    a.insert("upload_part", upload_part as crate::api::Action);
    a.insert("download_links", download_links);
    a
}

/// Scheduled clean-up: forget parts whose message no longer exists (deleted, disappeared, or never
/// sent; an hour's grace covers one still being sent). Rows still in use are checked again a day
/// later. Links already stop working the moment a message goes (see download_links).
pub fn forget_orphaned_files(sr: &Db, now: i64, deadline: i64) -> Result<usize> {
    let hour_ago = iso(now - 3_600_000).trim_end_matches('Z').to_string();
    let day_ago = iso(now - 86_400_000);
    let mut rows = sr.filter(
        "Attachment",
        json!({ "swept_at": "", "created_date": { "$lte": hour_ago } }),
        "created_date",
        100,
    )?;
    rows.extend(sr.filter(
        "Attachment",
        json!({ "swept_at": { "$gt": "", "$lte": day_ago } }),
        "swept_at",
        100,
    )?);
    let mut seen: HashMap<String, bool> = HashMap::new();
    let mut removed = 0;
    for row in &rows {
        if crate::sessions::now_ms() > deadline {
            break;
        }
        let key = format!(
            "{}:{}:{}",
            to_js_string(row.get("scope")),
            to_js_string(row.get("msg_id")),
            to_js_string(row.get("owner_id"))
        );
        let exists = match seen.get(&key) {
            Some(e) => *e,
            None => {
                let e = message_exists(sr, row)?;
                seen.insert(key, e);
                e
            }
        };
        if exists {
            let _ = sr.update("Attachment", id_of(row), json!({ "swept_at": iso(now) }));
        } else {
            let _ = sr.delete("Attachment", id_of(row));
            removed += 1;
        }
    }
    Ok(removed)
}
