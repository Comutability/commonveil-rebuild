//! Account keys and devices (base44/shared/handlers/keys.ts).
//!
//! The server can't read keys, but it can refuse: the first statement is self-signed and every
//! later one signed by the previous key (except a reset); a device becomes active only with a
//! certificate signed by the account's current key; a reset waits, and any device or the phrase
//! can stop it; sensitive actions carry a proof signed by an active device's own key.
use serde_json::{json, Value};

use crate::api::{id, id_list, int, random_id_field, Actions, ApiError, Ctx, Limits, Result};
use crate::db::{id_of, merged, Db};
use crate::js::{strict_eq, to_js_string, truthy};
use crate::shared::{
    account_keys_of, contacts_of, created_at, device_of, device_out, devices_of, enforce_rate, iso,
    latest_key_of, own_statement_out, peer_device_out, pending_expired, profile_of, rate_limited,
    server_peers_of, statement_out, unique_versions, with_row, within_rate, DAY_MS,
};
use crate::verify::{
    parse_device, parse_statement, payload_of, require_kem_key, require_recovery_anchor,
    require_sealed, signed_by_active_device, verify_cert, verify_device_kem_sig, verify_proof,
    verify_statement,
};

const QUERY_CAP: usize = 5000;
const MAX_KEY_VERSIONS: i64 = 250;
const MAX_BODY: usize = Limits::MAX_BODY_BYTES;

fn deny(status: u16, code: &str, message: &str) -> ApiError {
    ApiError::new(status, code, message)
}
/// Where the JavaScript would fail on a missing value (a TypeError): an unexpected error.
fn broken() -> ApiError {
    ApiError {
        status: 500,
        code: "INTERNAL".into(),
        message: "missing value".into(),
    }
}
fn version(k: &Value) -> i64 {
    k["version"].as_f64().unwrap_or(f64::NAN) as i64
}
fn not_initialised() -> ApiError {
    deny(
        409,
        "NOT_INITIALISED",
        "Encryption isn't set up for this account yet.",
    )
}

/// Rows for several people in one query, or person by person if it comes back full.
fn for_everyone(
    sr: &Db,
    entity: &str,
    query: Value,
    sort: &str,
    per_person: usize,
    user_ids: &[String],
) -> Result<Vec<Value>> {
    let mut q = query.clone();
    q["user_id"] = json!({ "$in": user_ids });
    let rows = sr.filter(entity, q, sort, QUERY_CAP)?;
    if rows.len() < QUERY_CAP {
        return Ok(rows);
    }
    let mut out = Vec::new();
    for uid in user_ids {
        let mut q = query.clone();
        q["user_id"] = json!(uid);
        out.extend(sr.filter(entity, q, sort, per_person)?);
    }
    Ok(out)
}

/// The request is signed by the new device it describes.
fn signed_by_new_device(ctx: &Ctx, action: &str) -> Result<(Value, Value)> {
    let (text, data) = payload_of(&ctx.body, MAX_BODY)?;
    let device = parse_device(&data["device"])?;
    let proof_device = verify_proof(
        ctx.user_id(),
        action,
        &text,
        &ctx.body["proof"],
        device["sign_pub"].as_str().unwrap_or(""),
        ctx.now,
    )?;
    if device["device_id"] != proof_device.as_str() {
        return Err(deny(
            403,
            "PROOF_INVALID",
            "This device couldn't prove it's yours.",
        ));
    }
    Ok((device, data))
}

fn expire_stale_pending(sr: &Db, devices: &mut [Value], now: i64) -> Result<()> {
    for d in devices.iter_mut() {
        if pending_expired(d, now) {
            sr.update(
                "Device",
                id_of(d),
                json!({ "status": "revoked", "revoked_reason": "expired", "revoked_at": iso(now) }),
            )?;
            d["status"] = json!("revoked");
            d["revoked_reason"] = json!("expired");
        }
    }
    Ok(())
}

fn live_devices(devices: &[Value], now: i64) -> Vec<Value> {
    devices
        .iter()
        .filter(|d| {
            d["status"] == "active" || (d["status"] == "pending" && !pending_expired(d, now))
        })
        .cloned()
        .collect()
}

fn require_keyring_envelope(
    raw: &Value,
    version: i64,
    sign_pub: &Value,
    name: &str,
) -> Result<String> {
    let ok = truthy(Some(raw))
        && (raw.is_object() || raw.is_array())
        && strict_eq(raw.get("keyring_version"), Some(&json!(version)))
        && strict_eq(raw.get("key_sign_pub"), Some(sign_pub));
    if !ok {
        return Err(deny(
            409,
            "STALE_KEYS",
            "Your keys changed on another device. Refresh and try again.",
        ));
    }
    require_sealed(&raw["sealed"], name)
}

fn publish_key(sr: &Db, user_id: &str, statement: &Value, is_reset: bool) -> Result<Option<Value>> {
    let key = sr.create(
        "AccountKey",
        merged(statement, &json!({ "is_reset": is_reset })),
    )?;
    let same = with_row(
        sr.filter(
            "AccountKey",
            json!({ "user_id": user_id, "version": statement["version"] }),
            "created_date",
            10,
        )?,
        &key,
    );
    if same[0]["id"] != key["id"] {
        sr.delete("AccountKey", id_of(&key))?;
        return Ok(None);
    }
    Ok(Some(key))
}

// ---------- resets ----------

fn reset_out(r: &Value) -> Value {
    json!({
        "id": r["id"], "device_id": r["device_id"], "device_label": crate::shared::or(&r["device_label"], json!("A browser")),
        "requested_at": r["created_date"], "effective_at": r["effective_at"], "status": r["status"], "ended_by": crate::shared::or(&r["ended_by"], json!("")),
    })
}

fn waiting_resets(sr: &Db, user_id: &str) -> Result<Vec<Value>> {
    sr.filter(
        "ResetRequest",
        json!({ "user_id": user_id, "status": "waiting" }),
        "created_date",
        20,
    )
}

fn end_resets(sr: &Db, rows: &[Value], status: &str, by: &str, now: i64) -> Result<()> {
    for r in rows {
        sr.update(
            "ResetRequest",
            id_of(r),
            json!({ "status": status, "ended_by": by, "ended_at": iso(now) }),
        )?;
    }
    Ok(())
}

/// The request is signed by the browser a reset request came from.
fn signed_by_reset_device(ctx: &Ctx, action: &str) -> Result<Value> {
    let (text, data) = payload_of(&ctx.body, MAX_BODY)?;
    let request = ctx
        .sr()
        .get("ResetRequest", &id(&data["request_id"], "request")?);
    let Some(request) = request.filter(|r| r["user_id"] == ctx.user_id()) else {
        return Err(deny(404, "NOT_FOUND", "That reset request wasn't found."));
    };
    let proof_device = verify_proof(
        ctx.user_id(),
        action,
        &text,
        &ctx.body["proof"],
        request["device_sign_pub"].as_str().unwrap_or(""),
        ctx.now,
    )?;
    if request["device_id"] != proof_device.as_str() {
        return Err(deny(
            403,
            "PROOF_INVALID",
            "This browser couldn't prove it made the request.",
        ));
    }
    Ok(request)
}

// ---------- the actions ----------

fn status(ctx: &mut Ctx) -> Result<Value> {
    let (sr, own, uid, now) = (ctx.sr(), ctx.own(), ctx.user_id().to_string(), ctx.now);
    let key_rows = account_keys_of(&own, &uid)?;
    let mut devices = devices_of(&own, &uid)?;
    let envelopes = own.filter(
        "KeyEnvelope",
        json!({ "user_id": uid }),
        "-created_date",
        300,
    )?;
    let resets = own.filter(
        "ResetRequest",
        json!({ "user_id": uid }),
        "-created_date",
        5,
    )?;
    expire_stale_pending(&sr, &mut devices, now)?;
    let keys = unique_versions(&key_rows);
    let latest = latest_key_of(&keys);
    let current = |e: &Value| {
        latest.as_ref().is_some_and(|l| {
            strict_eq(e.get("keyring_version"), l.get("version"))
                && strict_eq(e.get("key_sign_pub"), l.get("sign_pub"))
        })
    };
    let recovery = envelopes
        .iter()
        .find(|e| e["kind"] == "recovery" && current(e));
    let waiting: Vec<&Value> = envelopes
        .iter()
        .filter(|e| e["kind"] == "device" && current(e))
        .map(|e| &e["device_id"])
        .collect();
    Ok(json!({
        "statements": keys.iter().map(own_statement_out).collect::<Vec<_>>(),
        "devices": devices.iter().map(|d| { let mut o = device_out(d, now); o["keys_waiting"] = json!(waiting.contains(&&d["device_id"])); o }).collect::<Vec<_>>(),
        "recovery": recovery.map(|r| json!({ "keyring_version": r["keyring_version"], "recovery_pub": r["recovery_pub"] })),
        "resets": resets.iter().map(reset_out).collect::<Vec<_>>(),
    }))
}

fn init_account(ctx: &mut Ctx) -> Result<Value> {
    let (device, data) = signed_by_new_device(ctx, "init_account")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    if profile_of(&sr, &uid)?.is_none() {
        return Err(deny(409, "PROFILE_REQUIRED", "Choose a username first."));
    }
    if !account_keys_of(&sr, &uid)?.is_empty() {
        return Err(deny(
            409,
            "ALREADY_INITIALISED",
            "Encryption is already set up for this account. Link this device instead.",
        ));
    }
    let statement = parse_statement(&data["statement"], &uid)?;
    if statement["version"] != 1 || statement["signed_by_version"] != 1 {
        return Err(deny(
            400,
            "BAD_STATEMENT",
            "The first key must be version 1.",
        ));
    }
    let sign_pub = statement["sign_pub"].as_str().unwrap_or("").to_string();
    if !verify_statement(&statement, &sign_pub)? {
        return Err(deny(
            403,
            "STATEMENT_INVALID",
            "The key statement failed its signature check.",
        ));
    }
    require_recovery_anchor(&statement)?;
    let cert = verify_cert(&data["cert"], &uid, &device, 1, &sign_pub)?;
    let recovery_sealed = require_keyring_envelope(
        &data["recovery"],
        1,
        &statement["sign_pub"],
        "recovery backup",
    )?;
    if publish_key(&sr, &uid, &statement, false)?.is_none() {
        return Err(deny(
            409,
            "ALREADY_INITIALISED",
            "Encryption was just set up from another device. Link this device instead.",
        ));
    }
    let at = iso(now);
    let row = merged(
        &merged(&json!({ "user_id": uid }), &device),
        &json!({
            "status": "active", "cert_key_version": 1, "cert_issued_at": cert["issued_at"], "cert_signature": cert["signature"], "cert_has_kem": cert["has_kem"],
            "approved_via": "first_device", "approved_at": at, "synced_key_version": 1, "last_seen_at": at,
        }),
    );
    sr.create("Device", row)?;
    sr.create("KeyEnvelope", json!({ "user_id": uid, "kind": "recovery", "keyring_version": 1, "recovery_pub": statement["recovery_pub"], "key_sign_pub": sign_pub, "sealed": recovery_sealed, "created_by_device_id": device["device_id"] }))?;
    Ok(json!({ "ok": true, "version": 1 }))
}

fn register_device(ctx: &mut Ctx) -> Result<Value> {
    let (device, _) = signed_by_new_device(ctx, "register_device")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    if account_keys_of(&sr, &uid)?.is_empty() {
        return Err(not_initialised());
    }
    let mut devices = devices_of(&sr, &uid)?;
    expire_stale_pending(&sr, &mut devices, now)?;
    if device_of(&sr, &uid, device["device_id"].as_str().unwrap_or(""))?.is_some() {
        return Err(deny(
            409,
            "DEVICE_EXISTS",
            "This device is already registered.",
        ));
    }
    let live = live_devices(&devices, now);
    if live.len() >= Limits::MAX_DEVICES {
        return Err(deny(
            409,
            "TOO_MANY_DEVICES",
            &format!(
                "You can have up to {} devices. Remove one first.",
                Limits::MAX_DEVICES
            ),
        ));
    }
    if live.iter().filter(|d| d["status"] == "pending").count() >= Limits::MAX_PENDING_DEVICES {
        return Err(deny(
            429,
            "TOO_MANY_PENDING",
            "Too many devices are waiting for approval. Approve or deny them first.",
        ));
    }
    enforce_rate(
        &sr,
        "Device",
        json!({ "user_id": uid }),
        DAY_MS,
        Limits::REGISTRATIONS_PER_DAY,
        now,
        "adding devices",
    )?;
    let row = sr.create("Device", merged(&merged(&json!({ "user_id": uid }), &device), &json!({ "status": "pending", "pending_expires_at": iso(now + Limits::PENDING_DEVICE_MINUTES * 60_000) })))?;
    if !within_rate(
        &sr,
        "Device",
        json!({ "user_id": uid }),
        DAY_MS,
        Limits::REGISTRATIONS_PER_DAY,
        now,
        &row,
    )? {
        sr.delete("Device", id_of(&row))?;
        return Err(rate_limited("adding devices"));
    }
    Ok(json!({ "device": device_out(&row, now) }))
}

fn approve_device(ctx: &mut Ctx) -> Result<Value> {
    let (approver, data) = signed_by_active_device(ctx, "approve_device", MAX_BODY)?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    let target_id = random_id_field(&data["target_device_id"], "device id")?;
    let target = device_of(&sr, &uid, &target_id)?;
    let Some(target) =
        target.filter(|t| t["status"] == "pending" && t["device_id"] != approver["device_id"])
    else {
        return Err(deny(
            409,
            "NOT_PENDING",
            "That device isn't waiting for approval.",
        ));
    };
    if pending_expired(&target, now) {
        return Err(deny(
            410,
            "REQUEST_EXPIRED",
            "That request expired. Start linking again on the new device.",
        ));
    }
    let latest = latest_key_of(&account_keys_of(&sr, &uid)?).ok_or_else(broken)?;
    let cert = verify_cert(
        &data["cert"],
        &uid,
        &target,
        version(&latest),
        latest["sign_pub"].as_str().unwrap_or(""),
    )?;
    let sealed = require_keyring_envelope(
        &data["envelope"],
        version(&latest),
        &latest["sign_pub"],
        "keys for the new device",
    )?;
    sr.create("KeyEnvelope", json!({ "user_id": uid, "kind": "device", "device_id": target["device_id"], "keyring_version": latest["version"], "key_sign_pub": latest["sign_pub"], "sealed": sealed, "created_by_device_id": approver["device_id"] }))?;
    let updated = sr.update("Device", id_of(&target), json!({
        "status": "active", "cert_key_version": latest["version"], "cert_issued_at": cert["issued_at"], "cert_signature": cert["signature"], "cert_has_kem": cert["has_kem"],
        "approved_by_device_id": approver["device_id"], "approved_via": "device_approval", "approved_at": iso(now),
    }))?;
    Ok(json!({ "device": device_out(&merged(&target, &updated), now), "emailed": false }))
}

fn deny_device(ctx: &mut Ctx) -> Result<Value> {
    let (_, data) = signed_by_active_device(ctx, "deny_device", MAX_BODY)?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    let target = device_of(
        &sr,
        &uid,
        &random_id_field(&data["target_device_id"], "device id")?,
    )?;
    let Some(target) = target.filter(|t| t["status"] == "pending") else {
        return Err(deny(
            409,
            "NOT_PENDING",
            "That device isn't waiting for approval.",
        ));
    };
    sr.update(
        "Device",
        id_of(&target),
        json!({ "status": "revoked", "revoked_reason": "denied", "revoked_at": iso(now) }),
    )?;
    Ok(json!({ "ok": true }))
}

fn device_sync(ctx: &mut Ctx) -> Result<Value> {
    let (sr, own, uid, now) = (ctx.sr(), ctx.own(), ctx.user_id().to_string(), ctx.now);
    let device_id = random_id_field(&ctx.body["device_id"], "device id")?;
    let device = device_of(&own, &uid, &device_id)?.ok_or_else(|| {
        deny(
            404,
            "DEVICE_UNKNOWN",
            "This device isn't registered to your account.",
        )
    })?;
    let latest = latest_key_of(&account_keys_of(&own, &uid)?);
    let mut envelope = Value::Null;
    if let (true, Some(l)) = (device["status"] == "active", &latest) {
        let rows = own.filter("KeyEnvelope", json!({ "user_id": uid, "kind": "device", "device_id": device_id, "keyring_version": l["version"], "key_sign_pub": l["sign_pub"] }), "-created_date", 1)?;
        if let Some(r) = rows.first() {
            let sealed: Value =
                serde_json::from_str(r["sealed"].as_str().unwrap_or("")).map_err(|_| broken())?;
            envelope = json!({ "keyring_version": r["keyring_version"], "key_sign_pub": r["key_sign_pub"], "sealed": sealed });
        }
    }
    if device["status"] == "active"
        && (!truthy(device.get("last_seen_at"))
            || now as f64 - crate::shared::platform_ms(&device["last_seen_at"]) > 600_000.0)
    {
        sr.update(
            "Device",
            id_of(&device),
            json!({ "last_seen_at": iso(now) }),
        )?;
    }
    Ok(
        json!({ "device": device_out(&device, now), "latest_version": latest.map_or(Value::Null, |l| l["version"].clone()), "envelope": envelope }),
    )
}

fn ack_envelopes(ctx: &mut Ctx) -> Result<Value> {
    let (device, data) = signed_by_active_device(ctx, "ack_envelopes", MAX_BODY)?;
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    let v = int(&data["keyring_version"], "keyring version", 1, 1_000_000)?;
    let latest = latest_key_of(&account_keys_of(&sr, &uid)?);
    if latest
        .as_ref()
        .is_none_or(|l| crate::js::gt(Some(&json!(v)), l.get("version")))
    {
        return Err(deny(400, "BAD_FIELD", "Unknown keyring version."));
    }
    for r in sr.filter(
        "KeyEnvelope",
        json!({ "user_id": uid, "kind": "device", "device_id": device["device_id"] }),
        "created_date",
        100,
    )? {
        if crate::js::le(r.get("keyring_version"), Some(&json!(v))) {
            sr.delete("KeyEnvelope", id_of(&r))?;
        }
    }
    if !truthy(device.get("synced_key_version"))
        || crate::js::lt(device.get("synced_key_version"), Some(&json!(v)))
    {
        sr.update("Device", id_of(&device), json!({ "synced_key_version": v }))?;
    }
    Ok(json!({ "ok": true }))
}

fn send_keyring(ctx: &mut Ctx) -> Result<Value> {
    let (sender, data) = signed_by_active_device(ctx, "send_keyring", MAX_BODY)?;
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    let target = device_of(
        &sr,
        &uid,
        &random_id_field(&data["target_device_id"], "device id")?,
    )?;
    let Some(target) =
        target.filter(|t| t["status"] == "active" && t["device_id"] != sender["device_id"])
    else {
        return Err(deny(409, "NOT_ACTIVE", "That device isn't active."));
    };
    let latest = latest_key_of(&account_keys_of(&sr, &uid)?).ok_or_else(broken)?;
    let sealed = require_keyring_envelope(
        &data["envelope"],
        version(&latest),
        &latest["sign_pub"],
        "device keys",
    )?;
    let old = sr.filter(
        "KeyEnvelope",
        json!({ "user_id": uid, "kind": "device", "device_id": target["device_id"] }),
        "created_date",
        100,
    )?;
    sr.create("KeyEnvelope", json!({ "user_id": uid, "kind": "device", "device_id": target["device_id"], "keyring_version": latest["version"], "key_sign_pub": latest["sign_pub"], "sealed": sealed, "created_by_device_id": sender["device_id"] }))?;
    for r in old {
        sr.delete("KeyEnvelope", id_of(&r))?;
    }
    Ok(json!({ "ok": true }))
}

fn get_recovery(ctx: &mut Ctx) -> Result<Value> {
    let (own, uid) = (ctx.own(), ctx.user_id().to_string());
    let keys = unique_versions(&account_keys_of(&own, &uid)?);
    let latest = latest_key_of(&keys).ok_or_else(not_initialised)?;
    let rows = own.filter("KeyEnvelope", json!({ "user_id": uid, "kind": "recovery", "keyring_version": latest["version"], "key_sign_pub": latest["sign_pub"] }), "-created_date", 1)?;
    let r = rows.first().ok_or_else(|| {
        deny(
            404,
            "NO_BACKUP",
            "No recovery backup was found for your current keys.",
        )
    })?;
    let sealed: Value =
        serde_json::from_str(r["sealed"].as_str().unwrap_or("")).map_err(|_| broken())?;
    Ok(
        json!({ "statements": keys.iter().map(own_statement_out).collect::<Vec<_>>(), "recovery": { "keyring_version": r["keyring_version"], "recovery_pub": r["recovery_pub"], "sealed": sealed } }),
    )
}

fn recover_device(ctx: &mut Ctx) -> Result<Value> {
    let (device, data) = signed_by_new_device(ctx, "recover_device")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    let latest = latest_key_of(&account_keys_of(&sr, &uid)?).ok_or_else(not_initialised)?;
    let cert = verify_cert(
        &data["cert"],
        &uid,
        &device,
        version(&latest),
        latest["sign_pub"].as_str().unwrap_or(""),
    )?;
    let mut devices = devices_of(&sr, &uid)?;
    expire_stale_pending(&sr, &mut devices, now)?;
    let at = iso(now);
    let fields = json!({
        "status": "active", "cert_key_version": latest["version"], "cert_issued_at": cert["issued_at"], "cert_signature": cert["signature"], "cert_has_kem": cert["has_kem"],
        "approved_via": "recovery_phrase", "approved_at": at, "synced_key_version": latest["version"], "last_seen_at": at,
    });
    let row = match device_of(&sr, &uid, device["device_id"].as_str().unwrap_or(""))? {
        Some(existing) => {
            let kem = |d: &Value| {
                if truthy(d.get("kem_pub")) {
                    d["kem_pub"].clone()
                } else {
                    json!("")
                }
            };
            let same = existing["sign_pub"] == device["sign_pub"]
                && existing["box_pub"] == device["box_pub"]
                && kem(&existing) == kem(&device);
            if existing["status"] != "pending" || !same {
                return Err(deny(
                    409,
                    "DEVICE_EXISTS",
                    "This device is already registered.",
                ));
            }
            let updated = sr.update("Device", id_of(&existing), fields)?;
            merged(&existing, &updated)
        }
        None => {
            if live_devices(&devices, now).len() >= Limits::MAX_DEVICES {
                return Err(deny(
                    409,
                    "TOO_MANY_DEVICES",
                    &format!(
                        "You can have up to {} devices. Remove one first.",
                        Limits::MAX_DEVICES
                    ),
                ));
            }
            sr.create(
                "Device",
                merged(&merged(&json!({ "user_id": uid }), &device), &fields),
            )?
        }
    };
    end_resets(
        &sr,
        &waiting_resets(&sr, &uid)?,
        "cancelled",
        "recovery",
        now,
    )?;
    Ok(json!({ "device": device_out(&row, now), "emailed": false }))
}

fn revoke_device(ctx: &mut Ctx) -> Result<Value> {
    let (actor, data) = signed_by_active_device(ctx, "revoke_device", MAX_BODY)?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    let target = device_of(
        &sr,
        &uid,
        &random_id_field(&data["target_device_id"], "device id")?,
    )?
    .ok_or_else(|| {
        deny(
            404,
            "DEVICE_UNKNOWN",
            "That device isn't registered to your account.",
        )
    })?;
    if target["status"] != "revoked" {
        sr.update(
            "Device",
            id_of(&target),
            json!({ "status": "revoked", "revoked_reason": "removed", "revoked_at": iso(now) }),
        )?;
    }
    for e in sr.filter(
        "KeyEnvelope",
        json!({ "user_id": uid, "kind": "device", "device_id": target["device_id"] }),
        "created_date",
        100,
    )? {
        sr.delete("KeyEnvelope", id_of(&e))?;
    }
    let remaining: Vec<Value> = devices_of(&sr, &uid)?
        .into_iter()
        .filter(|d| d["status"] == "active")
        .collect();
    let revoked_self = target["device_id"] == actor["device_id"];
    if !revoked_self {
        // Every server key this account holds is one the device may have copied: each is renewed.
        let mut by_server: Vec<(String, Vec<String>)> = Vec::new();
        for g in sr.filter("KeyGrant", json!({ "user_id": uid }), "created_date", 5000)? {
            let (s, c) = (
                to_js_string(g.get("server_id")),
                to_js_string(g.get("chain_id")),
            );
            match by_server.iter_mut().find(|(x, _)| *x == s) {
                Some((_, chains)) if !chains.contains(&c) => chains.push(c),
                Some(_) => {}
                None => by_server.push((s, vec![c])),
            }
        }
        for (server_id, chains) in by_server {
            crate::servers_core::need_rotation(&sr, &server_id, &chains, "device")?;
        }
        crate::sessions::bump_epoch(ctx.store(), &uid);
    }
    Ok(
        json!({ "remaining": remaining.iter().map(|d| device_out(d, now)).collect::<Vec<_>>(), "revoked_self": revoked_self }),
    )
}

fn rotate_keys(ctx: &mut Ctx) -> Result<Value> {
    let (actor, data) = signed_by_active_device(ctx, "rotate_keys", MAX_BODY)?;
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    let latest = latest_key_of(&account_keys_of(&sr, &uid)?).ok_or_else(not_initialised)?;
    if version(&latest) >= MAX_KEY_VERSIONS {
        return Err(deny(
            409,
            "TOO_MANY_VERSIONS",
            "This account's keys have changed too many times. Contact support.",
        ));
    }
    let mut statement = parse_statement(&data["statement"], &uid)?;
    if version(&statement) != version(&latest) + 1
        || statement["signed_by_version"].as_i64() != Some(version(&latest))
    {
        return Err(deny(
            409,
            "STALE_KEYS",
            "Your keys changed on another device. Refresh and try again.",
        ));
    }
    if !verify_statement(&statement, latest["sign_pub"].as_str().unwrap_or(""))? {
        return Err(deny(
            403,
            "STATEMENT_INVALID",
            "The new key wasn't signed by your current key.",
        ));
    }
    if statement["recovery_pub"] != latest["recovery_pub"] {
        require_recovery_anchor(&statement)?;
    } else {
        statement["recovery_mac"] = json!("");
        let latest_rkem = crate::shared::or(&latest["recovery_kem_pub"], json!(""));
        if truthy(statement.get("kem_pub")) && statement["recovery_kem_pub"] != latest_rkem {
            return Err(deny(
                400,
                "BAD_STATEMENT",
                "A recovery key can only change with a new recovery phrase.",
            ));
        }
    }
    if truthy(latest.get("kem_pub")) && !truthy(statement.get("kem_pub")) {
        return Err(deny(
            400,
            "BAD_STATEMENT",
            "New keys must include a post-quantum key.",
        ));
    }
    let new_version = version(&statement);
    let new_sign = statement["sign_pub"].as_str().unwrap_or("").to_string();
    let active: Vec<Value> = devices_of(&sr, &uid)?
        .into_iter()
        .filter(|d| d["status"] == "active")
        .collect();
    let certs: Vec<Value> = data["certs"].as_array().cloned().unwrap_or_default();
    let envelopes: Vec<Value> = data["envelopes"].as_array().cloned().unwrap_or_default();
    let changed = || {
        deny(
            409,
            "DEVICES_CHANGED",
            "Your device list changed. Refresh and try again.",
        )
    };
    if certs.len() != active.len() {
        return Err(changed());
    }
    let mut verified: Vec<(Value, Value)> = Vec::new();
    for d in &active {
        let raw = certs
            .iter()
            .find(|c| truthy(Some(c)) && c["device_id"] == d["device_id"])
            .ok_or_else(changed)?;
        verified.push((
            d.clone(),
            verify_cert(raw, &uid, d, new_version, &new_sign)?,
        ));
    }
    let others: Vec<&Value> = active
        .iter()
        .filter(|d| d["device_id"] != actor["device_id"])
        .collect();
    if envelopes.len() != others.len() {
        return Err(changed());
    }
    let mut sealed_for: Vec<(Value, String)> = Vec::new();
    for d in &others {
        let e = envelopes
            .iter()
            .find(|x| truthy(Some(x)) && x["device_id"] == d["device_id"])
            .ok_or_else(changed)?;
        sealed_for.push((
            d["device_id"].clone(),
            require_keyring_envelope(e, new_version, &statement["sign_pub"], "device keys")?,
        ));
    }
    let recovery_sealed = require_keyring_envelope(
        &data["recovery"],
        new_version,
        &statement["sign_pub"],
        "recovery backup",
    )?;
    let mut created = Vec::new();
    for (device_id, sealed) in &sealed_for {
        created.push(sr.create("KeyEnvelope", json!({ "user_id": uid, "kind": "device", "device_id": device_id, "keyring_version": new_version, "key_sign_pub": new_sign, "sealed": sealed, "created_by_device_id": actor["device_id"] }))?);
    }
    created.push(sr.create("KeyEnvelope", json!({ "user_id": uid, "kind": "recovery", "keyring_version": new_version, "recovery_pub": statement["recovery_pub"], "key_sign_pub": new_sign, "sealed": recovery_sealed, "created_by_device_id": actor["device_id"] }))?);
    if publish_key(&sr, &uid, &statement, false)?.is_none() {
        for row in &created {
            sr.delete("KeyEnvelope", id_of(row))?;
        }
        return Err(deny(
            409,
            "STALE_KEYS",
            "Another device changed your keys at the same moment. Refresh and try again.",
        ));
    }
    for (d, c) in &verified {
        let mut fields = json!({ "cert_key_version": new_version, "cert_issued_at": c["issued_at"], "cert_signature": c["signature"], "cert_has_kem": c["has_kem"] });
        if d["device_id"] == actor["device_id"] {
            fields["synced_key_version"] = json!(new_version);
        }
        sr.update("Device", id_of(d), fields)?;
    }
    for e in sr.filter(
        "KeyEnvelope",
        json!({ "user_id": uid }),
        "created_date",
        500,
    )? {
        let older = crate::js::lt(e.get("keyring_version"), Some(&json!(new_version)));
        let stale_device = e["kind"] == "device" && older;
        let old_phrase = e["kind"] == "recovery" && e["recovery_pub"] != statement["recovery_pub"];
        let older_backup = e["kind"] == "recovery" && older;
        if stale_device || old_phrase || older_backup {
            sr.delete("KeyEnvelope", id_of(&e))?;
        }
    }
    Ok(json!({ "ok": true, "version": new_version }))
}

fn request_reset(ctx: &mut Ctx) -> Result<Value> {
    let (device, data) = signed_by_new_device(ctx, "request_reset")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    if data["confirm"] != "RESET" {
        return Err(deny(400, "CONFIRM_REQUIRED", "Type RESET to confirm."));
    }
    let latest = latest_key_of(&account_keys_of(&sr, &uid)?).ok_or_else(|| {
        deny(
            409,
            "NOT_INITIALISED",
            "Encryption isn't set up yet, so there's nothing to reset.",
        )
    })?;
    let statement = parse_statement(&data["statement"], &uid)?;
    if version(&statement) != version(&latest) + 1
        || statement["signed_by_version"] != statement["version"]
    {
        return Err(deny(
            409,
            "STALE_KEYS",
            "Your keys changed. Refresh and try again.",
        ));
    }
    let sign_pub = statement["sign_pub"].as_str().unwrap_or("").to_string();
    if !verify_statement(&statement, &sign_pub)? {
        return Err(deny(
            403,
            "STATEMENT_INVALID",
            "The key statement failed its signature check.",
        ));
    }
    require_recovery_anchor(&statement)?;
    let cert = verify_cert(&data["cert"], &uid, &device, version(&statement), &sign_pub)?;
    let recovery_sealed = require_keyring_envelope(
        &data["recovery"],
        version(&statement),
        &statement["sign_pub"],
        "recovery backup",
    )?;
    if device_of(&sr, &uid, device["device_id"].as_str().unwrap_or(""))?
        .is_some_and(|e| e["status"] == "active")
    {
        return Err(deny(
            409,
            "DEVICE_EXISTS",
            "This browser is already set up, so there's nothing to reset.",
        ));
    }
    let waiting = waiting_resets(&sr, &uid)?;
    if waiting
        .iter()
        .any(|r| r["device_id"] != device["device_id"])
    {
        return Err(deny(409, "RESET_PENDING", "A reset was already requested from another browser. It can be cancelled from one of your devices."));
    }
    enforce_rate(
        &sr,
        "ResetRequest",
        json!({ "user_id": uid }),
        DAY_MS,
        Limits::RESETS_PER_DAY,
        now,
        "requesting resets",
    )?;
    end_resets(&sr, &waiting, "withdrawn", "requester", now)?;
    let effective = now + Limits::RESET_DELAY_HOURS * 3_600_000;
    let row = sr.create("ResetRequest", json!({
        "user_id": uid, "device_id": device["device_id"], "device_label": device["label"], "device_sign_pub": device["sign_pub"], "device_box_pub": device["box_pub"],
        "device_kem_pub": crate::shared::or(&device["kem_pub"], json!("")), "statement": statement.to_string(), "cert": cert.to_string(),
        "recovery_sealed": recovery_sealed, "recovery_pub": statement["recovery_pub"], "key_sign_pub": sign_pub, "effective_at": iso(effective),
        "status": "waiting", "ended_by": "", "ended_at": "",
    }))?;
    if !within_rate(
        &sr,
        "ResetRequest",
        json!({ "user_id": uid }),
        DAY_MS,
        Limits::RESETS_PER_DAY,
        now,
        &row,
    )? {
        sr.delete("ResetRequest", id_of(&row))?;
        return Err(rate_limited("requesting resets"));
    }
    Ok(json!({ "request": reset_out(&row), "emailed": false }))
}

fn finish_reset(ctx: &mut Ctx) -> Result<Value> {
    let request = signed_by_reset_device(ctx, "finish_reset")?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    if request["status"] != "waiting" {
        return Err(deny(
            409,
            "RESET_ENDED",
            if request["status"] == "done" {
                "This reset is already complete."
            } else {
                "This reset was cancelled, so nothing changed."
            },
        ));
    }
    if (now as f64) < crate::shared::platform_ms(&request["effective_at"]) {
        return Err(deny(
            409,
            "RESET_WAITING",
            "The waiting period isn't over yet.",
        ));
    }
    let statement: Value =
        serde_json::from_str(request["statement"].as_str().unwrap_or("")).map_err(|_| broken())?;
    let cert: Value =
        serde_json::from_str(request["cert"].as_str().unwrap_or("")).map_err(|_| broken())?;
    let latest = latest_key_of(&account_keys_of(&sr, &uid)?);
    let sign_pub = statement["sign_pub"].as_str().unwrap_or("").to_string();
    let fresh = latest
        .as_ref()
        .is_some_and(|l| version(&statement) == version(l) + 1)
        && verify_statement(&statement, &sign_pub)?;
    if !fresh {
        end_resets(
            &sr,
            std::slice::from_ref(&request),
            "stale",
            "keys_changed",
            now,
        )?;
        return Err(deny(
            409,
            "RESET_STALE",
            "Your account's keys changed while the reset was waiting, so it was cancelled.",
        ));
    }
    let keys = account_keys_of(&sr, &uid)?;
    let recent = keys
        .iter()
        .filter(|k| truthy(k.get("is_reset")) && (now as f64) - created_at(k) < DAY_MS as f64)
        .count();
    if recent >= Limits::RESETS_PER_DAY {
        return Err(deny(
            429,
            "RATE_LIMITED",
            "Too many resets today. Please try again tomorrow.",
        ));
    }
    if publish_key(&sr, &uid, &statement, true)?.is_none() {
        return Err(deny(
            409,
            "STALE_KEYS",
            "Your keys changed at the same moment. Refresh and try again.",
        ));
    }
    let at = iso(now);
    for d in devices_of(&sr, &uid)? {
        if d["status"] != "revoked" && d["device_id"] != request["device_id"] {
            sr.update(
                "Device",
                id_of(&d),
                json!({ "status": "revoked", "revoked_reason": "account_reset", "revoked_at": at }),
            )?;
        }
    }
    for e in sr.filter(
        "KeyEnvelope",
        json!({ "user_id": uid }),
        "created_date",
        500,
    )? {
        sr.delete("KeyEnvelope", id_of(&e))?;
    }
    let fields = json!({
        "status": "active", "cert_key_version": statement["version"], "cert_issued_at": cert["issued_at"], "cert_signature": cert["signature"], "cert_has_kem": truthy(cert.get("kem_pub")),
        "approved_via": "account_reset", "approved_at": at, "synced_key_version": statement["version"], "last_seen_at": at, "pending_expires_at": "",
    });
    let keys_of_request = json!({ "sign_pub": request["device_sign_pub"], "box_pub": request["device_box_pub"], "kem_pub": crate::shared::or(&request["device_kem_pub"], json!("")), "kem_sig": "" });
    match device_of(&sr, &uid, request["device_id"].as_str().unwrap_or(""))? {
        Some(existing) => {
            sr.update(
                "Device",
                id_of(&existing),
                merged(&fields, &keys_of_request),
            )?;
        }
        None => {
            let base = json!({ "user_id": uid, "device_id": request["device_id"], "label": crate::shared::or(&request["device_label"], json!("Device")) });
            sr.create("Device", merged(&merged(&base, &keys_of_request), &fields))?;
        }
    }
    sr.create("KeyEnvelope", json!({ "user_id": uid, "kind": "recovery", "keyring_version": statement["version"], "recovery_pub": request["recovery_pub"], "key_sign_pub": request["key_sign_pub"], "sealed": request["recovery_sealed"], "created_by_device_id": request["device_id"] }))?;
    end_resets(
        &sr,
        std::slice::from_ref(&request),
        "done",
        "requester",
        now,
    )?;
    Ok(json!({ "ok": true, "version": statement["version"], "emailed": false }))
}

fn withdraw_reset(ctx: &mut Ctx) -> Result<Value> {
    let request = signed_by_reset_device(ctx, "withdraw_reset")?;
    if request["status"] == "waiting" {
        end_resets(
            &ctx.sr(),
            std::slice::from_ref(&request),
            "withdrawn",
            "requester",
            ctx.now,
        )?;
    }
    Ok(json!({ "ok": true }))
}

fn set_device_kem(ctx: &mut Ctx) -> Result<Value> {
    let (device, data) = signed_by_active_device(ctx, "set_device_kem", MAX_BODY)?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    let kem_pub = require_kem_key(&data["kem_pub"], "post-quantum key")?;
    if truthy(device.get("kem_pub")) {
        if device["kem_pub"] == kem_pub.as_str() {
            return Ok(json!({ "device": device_out(&device, now) }));
        }
        return Err(deny(
            409,
            "ALREADY_SET",
            "This device already has a post-quantum key.",
        ));
    }
    if !verify_device_kem_sig(&uid, &device, &kem_pub, &data["kem_sig"])? {
        return Err(deny(
            403,
            "SIGNATURE_INVALID",
            "The post-quantum key's signature didn't verify.",
        ));
    }
    let updated = sr.update(
        "Device",
        id_of(&device),
        json!({ "kem_pub": kem_pub, "kem_sig": data["kem_sig"], "cert_has_kem": false }),
    )?;
    Ok(json!({ "device": device_out(&merged(&device, &updated), now) }))
}

fn cancel_reset(ctx: &mut Ctx) -> Result<Value> {
    signed_by_active_device(ctx, "cancel_reset", MAX_BODY)?;
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    let waiting = waiting_resets(&sr, &uid)?;
    end_resets(&sr, &waiting, "cancelled", "device", ctx.now)?;
    Ok(json!({ "ok": true, "cancelled": waiting.len() }))
}

fn peer_keys(ctx: &mut Ctx) -> Result<Value> {
    let (sr, own, uid) = (ctx.sr(), ctx.own(), ctx.user_id().to_string());
    let ids = id_list(&ctx.body["user_ids"], "user ids", 50)?;
    let mut allowed = contacts_of(&own, &uid)?;
    let others: Vec<String> = ids
        .iter()
        .filter(|i| !allowed.contains(*i))
        .cloned()
        .collect();
    allowed.extend(server_peers_of(&sr, &own, &uid, &others)?);
    let wanted: Vec<String> = ids.into_iter().filter(|i| allowed.contains(i)).collect();
    let mut out = serde_json::Map::new();
    if wanted.is_empty() {
        return Ok(json!({ "keys": out }));
    }
    let key_rows = for_everyone(&sr, "AccountKey", json!({}), "version", 300, &wanted)?;
    let mut devices = for_everyone(
        &sr,
        "Device",
        json!({ "status": "active" }),
        "created_date",
        50,
        &wanted,
    )?;
    devices.extend(for_everyone(
        &sr,
        "Device",
        json!({ "status": "revoked", "revoked_reason": { "$in": ["removed", "account_reset"] } }),
        "-created_date",
        100,
        &wanted,
    )?);
    for u in &wanted {
        let mine: Vec<Value> = key_rows
            .iter()
            .filter(|k| k["user_id"] == u.as_str())
            .cloned()
            .collect();
        out.insert(u.clone(), json!({
            "statements": unique_versions(&mine).iter().map(statement_out).collect::<Vec<_>>(),
            "devices": devices.iter().filter(|d| d["user_id"] == u.as_str() && truthy(d.get("cert_signature"))).map(peer_device_out).collect::<Vec<_>>(),
        }));
    }
    Ok(json!({ "keys": out }))
}

pub fn actions() -> Actions {
    let mut a = Actions::new();
    for (name, f) in [
        ("status", status as crate::api::Action),
        ("init_account", init_account),
        ("register_device", register_device),
        ("approve_device", approve_device),
        ("deny_device", deny_device),
        ("device_sync", device_sync),
        ("ack_envelopes", ack_envelopes),
        ("send_keyring", send_keyring),
        ("get_recovery", get_recovery),
        ("recover_device", recover_device),
        ("revoke_device", revoke_device),
        ("rotate_keys", rotate_keys),
        ("request_reset", request_reset),
        ("finish_reset", finish_reset),
        ("withdraw_reset", withdraw_reset),
        ("set_device_kem", set_device_kem),
        ("cancel_reset", cancel_reset),
        ("peer_keys", peer_keys),
    ] {
        a.insert(name, f);
    }
    a
}
