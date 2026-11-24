//! Common data access for the backend functions (base44/shared/store.ts).
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use serde_json::{json, Value};

use crate::api::{ApiError, Result};
use crate::db::{id_of, Db};
use crate::js::{to_js_string, to_number, truthy};

pub const DAY_MS: i64 = 24 * 3_600_000;
/// Delete an account after this many days without use: off, about six months, a year.
pub const AUTO_DELETE_DAYS: [i64; 3] = [0, 183, 365];
/// Disappearing-message timers a conversation can have, in seconds.
pub const EXPIRY_CHOICES: [i64; 4] = [0, 86_400, 604_800, 2_419_200];

/// `v || fallback`.
pub fn or(v: &Value, fallback: Value) -> Value {
    if truthy(Some(v)) {
        v.clone()
    } else {
        fallback
    }
}
/// `v ?? fallback`.
pub fn or_null(v: &Value) -> Value {
    v.clone()
}

/// `parsePlatformTime`: a time with or without its zone (no zone means UTC); NaN if unreadable.
pub fn platform_ms(v: &Value) -> f64 {
    crate::dates::parse(&to_js_string(Some(v))).unwrap_or(f64::NAN)
}
/// When a record was created, in milliseconds.
pub fn created_at(r: &Value) -> f64 {
    if truthy(r.get("created_date")) {
        platform_ms(&r["created_date"])
    } else {
        f64::NAN
    }
}
/// Oldest first; ties broken by id. (Ids are lower-case hex, where `localeCompare` is byte order.)
pub fn by_age(a: &Value, b: &Value) -> Ordering {
    let d = created_at(a) - created_at(b);
    if d.is_nan() || d == 0.0 {
        to_js_string(a.get("id")).cmp(&to_js_string(b.get("id")))
    } else if d < 0.0 {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}
/// Put a row just written in (once), oldest first.
pub fn with_row(rows: Vec<Value>, created: &Value) -> Vec<Value> {
    let mut v: Vec<Value> = rows
        .into_iter()
        .filter(|r| r["id"] != created["id"])
        .collect();
    v.push(created.clone());
    v.sort_by(by_age);
    v
}

/// A day, "2026-10-30".
pub fn day_of(ms: i64) -> String {
    crate::store::iso(ms)[..10].to_string()
}
pub fn iso(ms: i64) -> String {
    crate::store::iso(ms)
}

// ---------- profiles ----------

pub fn profile_of(db: &Db, user_id: &str) -> Result<Option<Value>> {
    Ok(db
        .filter("Profile", json!({ "user_id": user_id }), "created_date", 5)?
        .into_iter()
        .next())
}

pub fn public_profile(p: &Value) -> Value {
    json!({
        "user_id": p["user_id"],
        "username": p["username"],
        "display_name": or(&p["display_name"], json!("")),
        "bio": or(&p["bio"], json!("")),
        "pronouns": or(&p["pronouns"], json!("")),
        "accent_color": or(&p["accent_color"], json!("")),
        "avatar_emoji": or(&p["avatar_emoji"], json!("")),
        "avatar_image": or(&p["avatar_image"], json!("")),
    })
}

/// Only what the person chose to show this viewer.
pub fn profile_for(p: &Value, contact: bool) -> Value {
    let visibility = or(&p["profile_visibility"], json!("shared"));
    if visibility == "shared" || (visibility == "conversations" && contact) {
        return public_profile(p);
    }
    json!({ "user_id": p["user_id"], "username": p["username"], "display_name": "", "bio": "", "pronouns": "", "accent_color": or(&p["accent_color"], json!("")), "avatar_emoji": "", "avatar_image": "" })
}

/// Which of these people share a server with `user_id`.
pub fn server_peers_of(
    sr: &Db,
    own: &Db,
    user_id: &str,
    ids: &[String],
) -> Result<HashSet<String>> {
    let mut out = HashSet::new();
    if ids.is_empty() {
        return Ok(out);
    }
    let mine = own.filter(
        "ServerMember",
        json!({ "user_id": user_id }),
        "created_date",
        200,
    )?;
    let mut server_ids: Vec<Value> = Vec::new();
    for m in &mine {
        if !server_ids.contains(&m["server_id"]) {
            server_ids.push(m["server_id"].clone());
        }
    }
    if server_ids.is_empty() {
        return Ok(out);
    }
    for m in sr.filter(
        "ServerMember",
        json!({ "server_id": { "$in": server_ids }, "user_id": { "$in": ids } }),
        "created_date",
        5000,
    )? {
        out.insert(to_js_string(m.get("user_id")));
    }
    Ok(out)
}

/// User ids that share at least one conversation with `user_id` (plus `user_id`).
pub fn contacts_of(db: &Db, user_id: &str) -> Result<HashSet<String>> {
    let mut ids = HashSet::from([user_id.to_string()]);
    for c in my_conversations(db, user_id, 500)? {
        for m in c["member_ids"].as_array().into_iter().flatten() {
            ids.insert(to_js_string(Some(m)));
        }
    }
    Ok(ids)
}

pub fn blocked_either_way(sr: &Db, a: &str, b: &str) -> Result<bool> {
    Ok(!sr.filter("Block", json!({ "$or": [{ "user_id": a, "blocked_user_id": b }, { "user_id": b, "blocked_user_id": a }] }), "created_date", 2)?.is_empty())
}

// ---------- keys ----------

fn num_cmp(a: &Value, b: &Value) -> Ordering {
    let d = to_number(Some(a)) - to_number(Some(b));
    if d < 0.0 {
        Ordering::Less
    } else if d > 0.0 {
        Ordering::Greater
    } else {
        Ordering::Equal
    }
}

pub fn account_keys_of(db: &Db, user_id: &str) -> Result<Vec<Value>> {
    let mut rows = db.filter("AccountKey", json!({ "user_id": user_id }), "version", 300)?;
    rows.sort_by(|a, b| {
        num_cmp(&a["version"], &b["version"]).then_with(|| {
            to_js_string(a.get("created_date")).cmp(&to_js_string(b.get("created_date")))
        })
    });
    Ok(rows)
}

/// One statement per version (the oldest wins a duplicate).
pub fn unique_versions(rows: &[Value]) -> Vec<Value> {
    let mut sorted = rows.to_vec();
    sorted.sort_by(by_age);
    let mut seen: Vec<Value> = Vec::new();
    let mut out = Vec::new();
    for k in sorted {
        if seen.contains(&k["version"]) {
            continue;
        }
        seen.push(k["version"].clone());
        out.push(k);
    }
    out.sort_by(|a, b| num_cmp(&a["version"], &b["version"]));
    out
}

pub fn latest_key_of(keys: &[Value]) -> Option<Value> {
    keys.last().cloned()
}

pub fn statement_out(k: &Value) -> Value {
    let mut o = json!({
        "user_id": k["user_id"], "version": k["version"], "ecdh_pub": k["ecdh_pub"], "sign_pub": k["sign_pub"],
        "recovery_pub": k["recovery_pub"], "signed_by_version": k["signed_by_version"], "issued_at": k["issued_at"],
        "signature": k["signature"], "is_reset": truthy(k.get("is_reset")),
    });
    strip_missing(&mut o, k);
    if truthy(k.get("kem_pub")) {
        o["kem_pub"] = k["kem_pub"].clone();
        o["recovery_kem_pub"] = or(&k["recovery_kem_pub"], json!(""));
    }
    o
}
/// `JSON.stringify` leaves out fields that were undefined.
fn strip_missing(o: &mut Value, from: &Value) {
    if let Some(m) = o.as_object_mut() {
        m.retain(|key, v| !(v.is_null() && from.get(key).is_none()));
    }
}
pub fn own_statement_out(k: &Value) -> Value {
    let mut o = statement_out(k);
    o["recovery_mac"] = or(&k["recovery_mac"], json!(""));
    o
}

/// Each user's latest key statement (the oldest row wins a duplicate version).
pub fn latest_keys_for(sr: &Db, user_ids: &[String]) -> Result<HashMap<String, Value>> {
    let mut rows = sr.filter(
        "AccountKey",
        json!({ "user_id": { "$in": user_ids } }),
        "version",
        5000,
    )?;
    rows.sort_by(by_age);
    let mut latest: HashMap<String, Value> = HashMap::new();
    for r in rows {
        let u = to_js_string(r.get("user_id"));
        if latest
            .get(&u)
            .is_none_or(|seen| crate::js::gt(r.get("version"), seen.get("version")))
        {
            latest.insert(u, r);
        }
    }
    Ok(latest)
}

// ---------- devices ----------

/// Every live device (active or pending) and the most recent removed ones.
pub fn devices_of(db: &Db, user_id: &str) -> Result<Vec<Value>> {
    let mut live = db.filter(
        "Device",
        json!({ "user_id": user_id, "status": { "$in": ["active", "pending"] } }),
        "created_date",
        100,
    )?;
    live.extend(db.filter(
        "Device",
        json!({ "user_id": user_id, "status": "revoked" }),
        "-created_date",
        100,
    )?);
    Ok(live)
}

pub fn device_of(db: &Db, user_id: &str, device_id: &str) -> Result<Option<Value>> {
    Ok(db
        .filter(
            "Device",
            json!({ "user_id": user_id, "device_id": device_id }),
            "created_date",
            5,
        )?
        .into_iter()
        .next())
}

pub fn pending_expired(d: &Value, now: i64) -> bool {
    d["status"] == "pending"
        && truthy(d.get("pending_expires_at"))
        && platform_ms(&d["pending_expires_at"]) < now as f64
}

fn device_pq_out(d: &Value, o: &mut Value) {
    if truthy(d.get("kem_pub")) {
        o["kem_pub"] = d["kem_pub"].clone();
        o["kem_sig"] = or(&d["kem_sig"], json!(""));
        o["cert_has_kem"] = json!(truthy(d.get("cert_has_kem")));
    }
}

pub fn device_out(d: &Value, now: i64) -> Value {
    let nul = |k: &str| or(&d[k], Value::Null);
    let mut o = json!({
        "device_id": d["device_id"],
        "label": or(&d["label"], json!("Device")),
        "sign_pub": d["sign_pub"],
        "box_pub": d["box_pub"],
        "status": if pending_expired(d, now) { json!("expired") } else { d["status"].clone() },
        "cert_key_version": or_null(&d["cert_key_version"]),
        "cert_issued_at": nul("cert_issued_at"),
        "cert_signature": nul("cert_signature"),
        "approved_via": nul("approved_via"),
        "approved_at": nul("approved_at"),
        "pending_expires_at": nul("pending_expires_at"),
        "revoked_at": nul("revoked_at"),
        "revoked_reason": nul("revoked_reason"),
        "synced_key_version": or_null(&d["synced_key_version"]),
        "last_seen_at": nul("last_seen_at"),
        "created_date": d["created_date"],
    });
    for k in ["device_id", "sign_pub", "box_pub", "status", "created_date"] {
        if d.get(k).is_none() && o[k].is_null() {
            o.as_object_mut().unwrap().remove(k);
        }
    }
    device_pq_out(d, &mut o);
    o
}

/// What other members see about your devices: keys and certificate, no labels or timings.
pub fn peer_device_out(d: &Value) -> Value {
    let mut o = json!({
        "device_id": d["device_id"], "sign_pub": d["sign_pub"], "box_pub": d["box_pub"], "status": d["status"],
        "cert_key_version": d["cert_key_version"], "cert_issued_at": d["cert_issued_at"], "cert_signature": d["cert_signature"],
    });
    strip_missing(&mut o, d);
    device_pq_out(d, &mut o);
    o
}

/// Active device owned by this user, or a 403.
pub fn require_active_device(db: &Db, user_id: &str, device_id: &str) -> Result<Value> {
    let Some(d) = device_of(db, user_id, device_id)? else {
        return Err(ApiError::new(
            403,
            "DEVICE_UNKNOWN",
            "This device isn't registered to your account.",
        ));
    };
    if d["status"] != "active" {
        return Err(ApiError::new(
            403,
            "DEVICE_NOT_ACTIVE",
            "This device hasn't been approved, or was removed.",
        ));
    }
    Ok(d)
}

// ---------- conversations ----------

pub fn my_conversations(db: &Db, user_id: &str, limit: usize) -> Result<Vec<Value>> {
    db.filter(
        "Conversation",
        json!({ "member_ids": user_id }),
        "-updated_date",
        limit,
    )
}

fn str_list(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().map(|x| to_js_string(Some(x))).collect())
        .unwrap_or_default()
}

/// A group's admins (see store.ts adminsOf).
pub fn admins_of(conv: &Value) -> Vec<String> {
    if conv["kind"] != "group" {
        return vec![];
    }
    let members = str_list(&conv["member_ids"]);
    let listed: Vec<String> = str_list(&conv["admin_ids"])
        .into_iter()
        .filter(|m| members.contains(m))
        .collect();
    if !listed.is_empty() {
        return listed;
    }
    let creator = to_js_string(conv.get("creator_id"));
    if truthy(conv.get("creator_id")) && members.contains(&creator) {
        return vec![creator];
    }
    members.into_iter().take(1).collect()
}

/// Who's left, and who manages, once someone leaves or is removed.
pub fn without_member(conv: &Value, user_id: &str) -> (Vec<String>, Vec<String>) {
    let members: Vec<String> = str_list(&conv["member_ids"])
        .into_iter()
        .filter(|m| m != user_id)
        .collect();
    let mut admins: Vec<String> = admins_of(conv)
        .into_iter()
        .filter(|m| m != user_id && members.contains(m))
        .collect();
    if admins.is_empty() && !members.is_empty() {
        admins = vec![members[0].clone()];
    }
    (members, admins)
}

// ---------- rates ----------

pub fn count_since(sr: &Db, entity: &str, query: Value, since: i64, cap: usize) -> Result<usize> {
    let mut q = query;
    q["created_date"] = json!({ "$gte": iso(since).trim_end_matches('Z') });
    Ok(sr
        .filter(entity, q, "-created_date", cap + 1)?
        .iter()
        .filter(|r| platform_ms(&r["created_date"]) >= since as f64)
        .count())
}

pub fn rate_limited(what: &str) -> ApiError {
    ApiError::new(
        429,
        "RATE_LIMITED",
        &format!("You're {what} too quickly. Please wait a moment."),
    )
}

pub fn enforce_rate(
    sr: &Db,
    entity: &str,
    query: Value,
    window_ms: i64,
    cap: usize,
    now: i64,
    what: &str,
) -> Result<()> {
    if count_since(sr, entity, query, now - window_ms, cap)? >= cap {
        return Err(rate_limited(what));
    }
    Ok(())
}

/// Checked again after inserting. False means undo it.
pub fn within_rate(
    sr: &Db,
    entity: &str,
    query: Value,
    window_ms: i64,
    cap: usize,
    now: i64,
    created: &Value,
) -> Result<bool> {
    let since = now - window_ms - 60_000;
    let mut q = query;
    q["created_date"] = json!({ "$gte": iso(since).trim_end_matches('Z') });
    let start = (now - window_ms) as f64;
    let rows: Vec<Value> = sr
        .filter(entity, q, "created_date", cap * 2 + 20)?
        .into_iter()
        .filter(|r| created_at(r) >= start)
        .collect();
    let ordered = with_row(rows, created);
    Ok(ordered
        .iter()
        .position(|r| id_of(r) == id_of(created))
        .is_some_and(|i| i < cap))
}

/// The conversation, if this person is in it; the same 404 whether it doesn't exist or they aren't.
pub fn conversation_for_member(db: &Db, user_id: &str, conversation_id: &str) -> Result<Value> {
    match db.get("Conversation", conversation_id) {
        Some(c)
            if c["member_ids"]
                .as_array()
                .is_some_and(|m| m.iter().any(|x| x == user_id)) =>
        {
            Ok(c)
        }
        _ => Err(ApiError::new(
            404,
            "CONVERSATION_NOT_FOUND",
            "Conversation not found.",
        )),
    }
}

/// Group admins; in a direct message both people manage their own conversation.
pub fn is_admin(conv: &Value, user_id: &str) -> bool {
    conv["kind"] != "group" || admins_of(conv).iter().any(|a| a == user_id)
}

pub fn require_group_admin(conv: &Value, user_id: &str, what: &str) -> Result<()> {
    if !is_admin(conv, user_id) {
        return Err(ApiError::new(
            403,
            "NOT_ADMIN",
            &format!("Only the group's admins can {what}."),
        ));
    }
    Ok(())
}

pub fn conversation_out(c: &Value) -> Value {
    let expire = {
        let n = to_number(c.get("expire_seconds"));
        crate::js::number_value(if n.is_nan() { 0.0 } else { n })
    };
    let mut o = json!({
        "id": c["id"],
        "kind": c["kind"],
        "member_ids": or(&c["member_ids"], json!([])),
        "admin_ids": admins_of(c),
        "creator_id": or(&c["creator_id"], json!("")),
        "created_date": c["created_date"],
        "updated_date": c["updated_date"],
        "last_message_at": or(&c["last_message_at"], Value::Null),
        "expire_seconds": expire,
        "expiry_set_by": or(&c["expiry_set_by"], Value::Null),
        "expiry_set_at": or(&c["expiry_set_at"], Value::Null),
        "destroy_at": or(&c["destroy_at"], Value::Null),
        "destroy_set_by": or(&c["destroy_set_by"], Value::Null),
    });
    for k in ["id", "kind", "created_date", "updated_date"] {
        if c.get(k).is_none() {
            o.as_object_mut().unwrap().remove(k);
        }
    }
    if truthy(c.get("server_id")) {
        let n = to_number(c.get("ticket_number"));
        o["server_id"] = c["server_id"].clone();
        o["ticket"] = json!({
            "number": crate::js::number_value(if n.is_nan() { 0.0 } else { n }),
            "status": or(&c["ticket_status"], json!("open")),
            "opened_by": or(&c["ticket_opened_by"], json!("")),
            "channel_id": or(&c["ticket_channel_id"], json!("")),
        });
    }
    o["title"] = if truthy(c.get("title_envelope")) {
        let mut t = json!({ "envelope": c["title_envelope"], "item_id": c["title_item_id"], "sender_id": c["title_sender_id"], "device_id": c["title_device_id"], "sent_at": c["title_sent_at"], "signature": c["title_signature"] });
        let keys = [
            ("item_id", "title_item_id"),
            ("sender_id", "title_sender_id"),
            ("device_id", "title_device_id"),
            ("sent_at", "title_sent_at"),
            ("signature", "title_signature"),
        ];
        for (k, src) in keys {
            if c.get(src).is_none() {
                t.as_object_mut().unwrap().remove(k);
            }
        }
        t
    } else {
        Value::Null
    };
    o
}

pub fn message_out(m: &Value) -> Value {
    let deleted = truthy(m.get("deleted"));
    let mut o = json!({
        "id": m["id"], "conversation_id": m["conversation_id"], "msg_id": m["msg_id"], "sender_id": m["sender_id"], "device_id": m["device_id"],
        "envelope": if deleted { Value::Null } else { m["envelope"].clone() },
        "signature": if deleted { Value::Null } else { m["signature"].clone() },
        "sent_at": m["sent_at"], "created_date": m["created_date"],
        "expires_at": or(&m["expires_at"], Value::Null),
        "deleted": deleted, "scheduled": truthy(m.get("scheduled")),
    });
    for k in [
        "id",
        "conversation_id",
        "msg_id",
        "sender_id",
        "device_id",
        "sent_at",
        "created_date",
    ] {
        if m.get(k).is_none() {
            o.as_object_mut().unwrap().remove(k);
        }
    }
    for k in ["envelope", "signature"] {
        if !deleted && m.get(k).is_none() {
            o.as_object_mut().unwrap().remove(k);
        }
    }
    o
}

/// False once a disappearing message's time is up.
pub fn is_live(m: &Value, now: i64) -> bool {
    !truthy(m.get("expires_at")) || platform_ms(&m["expires_at"]) > now as f64
}

/// Messages a member may list: only those whose key was sealed to them (or from before that was recorded).
pub fn addressed_to(user_id: &str) -> Value {
    json!([{ "recipient_ids": user_id }, { "recipient_ids": null }])
}

/// Every member covered exactly once, each at their current key version, post-quantum where theirs is.
pub fn assert_wraps_match_members(
    sr: &Db,
    wraps: &[crate::verify::Wrap],
    member_ids: &[String],
) -> Result<()> {
    let latest = latest_keys_for(sr, member_ids)?;
    let users: HashSet<&str> = wraps.iter().map(|w| w.u.as_str()).collect();
    let exact =
        users.len() == member_ids.len() && member_ids.iter().all(|m| users.contains(m.as_str()));
    if !exact {
        return Err(ApiError::new(
            409,
            "RECIPIENTS_CHANGED",
            "The people in this conversation changed. Refreshing and trying again.",
        ));
    }
    let stale = || {
        ApiError::new(
            409,
            "STALE_KEYS",
            "Someone's keys changed. Refreshing and trying again.",
        )
    };
    for w in wraps {
        let Some(current) = latest.get(&w.u) else {
            return Err(ApiError::new(
                409,
                "MEMBER_NOT_READY",
                "Someone here hasn't finished setting up encryption.",
            ));
        };
        if !crate::js::strict_eq(Some(&json!(w.kv)), current.get("version")) {
            return Err(stale());
        }
        if truthy(current.get("kem_pub")) && !w.kem {
            return Err(stale());
        }
    }
    Ok(())
}

/// A list field as strings (`member_ids` and the like).
pub fn ids_of(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().map(|x| to_js_string(Some(x))).collect())
        .unwrap_or_default()
}
