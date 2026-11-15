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
    if truthy(Some(v)) { v.clone() } else { fallback }
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
    if truthy(r.get("created_date")) { platform_ms(&r["created_date"]) } else { f64::NAN }
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
    let mut v: Vec<Value> = rows.into_iter().filter(|r| r["id"] != created["id"]).collect();
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
    Ok(db.filter("Profile", json!({ "user_id": user_id }), "created_date", 5)?.into_iter().next())
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
pub fn server_peers_of(sr: &Db, own: &Db, user_id: &str, ids: &[String]) -> Result<HashSet<String>> {
    let mut out = HashSet::new();
    if ids.is_empty() {
        return Ok(out);
    }
    let mine = own.filter("ServerMember", json!({ "user_id": user_id }), "created_date", 200)?;
    let mut server_ids: Vec<Value> = Vec::new();
    for m in &mine {
        if !server_ids.contains(&m["server_id"]) {
            server_ids.push(m["server_id"].clone());
        }
    }
    if server_ids.is_empty() {
        return Ok(out);
    }
    for m in sr.filter("ServerMember", json!({ "server_id": { "$in": server_ids }, "user_id": { "$in": ids } }), "created_date", 5000)? {
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
    if d < 0.0 { Ordering::Less } else if d > 0.0 { Ordering::Greater } else { Ordering::Equal }
}

pub fn account_keys_of(db: &Db, user_id: &str) -> Result<Vec<Value>> {
    let mut rows = db.filter("AccountKey", json!({ "user_id": user_id }), "version", 300)?;
    rows.sort_by(|a, b| num_cmp(&a["version"], &b["version"]).then_with(|| to_js_string(a.get("created_date")).cmp(&to_js_string(b.get("created_date")))));
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
    let mut rows = sr.filter("AccountKey", json!({ "user_id": { "$in": user_ids } }), "version", 5000)?;
    rows.sort_by(by_age);
    let mut latest: HashMap<String, Value> = HashMap::new();
    for r in rows {
        let u = to_js_string(r.get("user_id"));
        if latest.get(&u).is_none_or(|seen| crate::js::gt(r.get("version"), seen.get("version"))) {
            latest.insert(u, r);
        }
    }
    Ok(latest)
}

// ---------- devices ----------

/// Every live device (active or pending) and the most recent removed ones.
pub fn devices_of(db: &Db, user_id: &str) -> Result<Vec<Value>> {
    let mut live = db.filter("Device", json!({ "user_id": user_id, "status": { "$in": ["active", "pending"] } }), "created_date", 100)?;
    live.extend(db.filter("Device", json!({ "user_id": user_id, "status": "revoked" }), "-created_date", 100)?);
    Ok(live)
}

pub fn device_of(db: &Db, user_id: &str, device_id: &str) -> Result<Option<Value>> {
    Ok(db.filter("Device", json!({ "user_id": user_id, "device_id": device_id }), "created_date", 5)?.into_iter().next())
}

pub fn pending_expired(d: &Value, now: i64) -> bool {
    d["status"] == "pending" && truthy(d.get("pending_expires_at")) && platform_ms(&d["pending_expires_at"]) < now as f64
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
    let Some(d) = device_of(db, user_id, device_id)? else { return Err(ApiError::new(403, "DEVICE_UNKNOWN", "This device isn't registered to your account.")) };
    if d["status"] != "active" {
        return Err(ApiError::new(403, "DEVICE_NOT_ACTIVE", "This device hasn't been approved, or was removed."));
    }
    Ok(d)
}

// ---------- conversations ----------

pub fn my_conversations(db: &Db, user_id: &str, limit: usize) -> Result<Vec<Value>> {
    db.filter("Conversation", json!({ "member_ids": user_id }), "-updated_date", limit)
}

fn str_list(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().map(|x| to_js_string(Some(x))).collect()).unwrap_or_default()
}

/// A group's admins (see store.ts adminsOf).
pub fn admins_of(conv: &Value) -> Vec<String> {
    if conv["kind"] != "group" {
        return vec![];
    }
    let members = str_list(&conv["member_ids"]);
    let listed: Vec<String> = str_list(&conv["admin_ids"]).into_iter().filter(|m| members.contains(m)).collect();
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
    let members: Vec<String> = str_list(&conv["member_ids"]).into_iter().filter(|m| m != user_id).collect();
    let mut admins: Vec<String> = admins_of(conv).into_iter().filter(|m| m != user_id && members.contains(m)).collect();
    if admins.is_empty() && !members.is_empty() {
        admins = vec![members[0].clone()];
    }
    (members, admins)
}

// ---------- rates ----------

pub fn count_since(sr: &Db, entity: &str, query: Value, since: i64, cap: usize) -> Result<usize> {
    let mut q = query;
    q["created_date"] = json!({ "$gte": iso(since).trim_end_matches('Z') });
    Ok(sr.filter(entity, q, "-created_date", cap + 1)?.iter().filter(|r| platform_ms(&r["created_date"]) >= since as f64).count())
}

pub fn rate_limited(what: &str) -> ApiError {
    ApiError::new(429, "RATE_LIMITED", &format!("You're {what} too quickly. Please wait a moment."))
}

pub fn enforce_rate(sr: &Db, entity: &str, query: Value, window_ms: i64, cap: usize, now: i64, what: &str) -> Result<()> {
    if count_since(sr, entity, query, now - window_ms, cap)? >= cap {
        return Err(rate_limited(what));
    }
    Ok(())
}

/// Checked again after inserting. False means undo it.
pub fn within_rate(sr: &Db, entity: &str, query: Value, window_ms: i64, cap: usize, now: i64, created: &Value) -> Result<bool> {
    let since = now - window_ms - 60_000;
    let mut q = query;
    q["created_date"] = json!({ "$gte": iso(since).trim_end_matches('Z') });
    let start = (now - window_ms) as f64;
    let rows: Vec<Value> = sr.filter(entity, q, "created_date", cap * 2 + 20)?.into_iter().filter(|r| created_at(r) >= start).collect();
    let ordered = with_row(rows, created);
    Ok(ordered.iter().position(|r| id_of(r) == id_of(created)).is_some_and(|i| i < cap))
}
