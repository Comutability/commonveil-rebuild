//! The experimental protocol layer (base44/shared/handlers/protocol.ts, docs/SECURE_NET_LAYER.md):
//! Secure Net actors, prekeys and a mailbox for sealed envelopes (CVP-016, CVP-017, CVP-019).
//!
//! The server's part is deliberately small. It stores each account's signed actor document and its
//! devices' prekeys, hands them out, and holds sealed envelopes until the device they are for
//! collects them. It checks shapes, sizes, who may write what and how often. It does not check the
//! post-quantum signatures and cannot open anything: people's devices verify every document and
//! prekey themselves, against keys they have pinned.
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};

use crate::api::{id, int, str_field, Actions, ApiError, Ctx, Result};
use crate::db::{id_of, Db};
use crate::js::{number_value, to_js_string, to_number, truthy};
use crate::shared::{blocked_either_way, contacts_of, iso, profile_of, rate_limited};
use crate::verify::signed_by_active_device;

pub const DOCUMENT_CHARS: usize = 96 * 1024;
pub const SEALED_CHARS: usize = 16 * 1024;
pub const PREKEY_CHARS: usize = 12 * 1024;
/// One-time prekeys kept per device, per kind.
pub const ONE_TIME_PER_KIND: usize = 20;
pub const ENVELOPE_CHARS: usize = 80 * 1024;
pub const SEND_ITEMS: usize = 40;
/// Waiting envelopes per device; more are refused until the device collects.
pub const MAIL_PER_DEVICE: usize = 500;
pub const SENDS_PER_MINUTE: usize = 60;
pub const BUNDLES_PER_MINUTE: usize = 60;
pub const COLLECT: usize = 100;
pub const MAIL_DAYS: i64 = 30;

fn bad(name: &str) -> ApiError {
    ApiError::new(400, "BAD_FIELD", &format!("Invalid {name}."))
}

fn kid_ok(s: &str) -> bool {
    s.len() == 22
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `KID.test(v || "")`: the test coerces what it's given to a string.
fn kid_test(v: Option<&Value>) -> bool {
    kid_ok(&if truthy(v) {
        to_js_string(v)
    } else {
        String::new()
    })
}

fn kid(v: &Value, name: &str) -> Result<String> {
    v.as_str()
        .filter(|s| kid_ok(s))
        .map(String::from)
        .ok_or_else(|| bad(name))
}

/// `JSON.stringify`, with whole numbers written as JavaScript writes them.
pub fn js_stringify(v: &Value) -> String {
    fn norm(v: &Value) -> Value {
        match v {
            Value::Number(n) => n.as_f64().map_or(v.clone(), number_value),
            Value::Array(a) => Value::Array(a.iter().map(norm).collect()),
            Value::Object(o) => {
                Value::Object(o.iter().map(|(k, v)| (k.clone(), norm(v))).collect())
            }
            _ => v.clone(),
        }
    }
    norm(v).to_string()
}

fn parse(text: &Value, name: &str, max: usize) -> Result<Value> {
    let s = str_field(text, name, max, 2)?;
    match serde_json::from_str::<Value>(&s) {
        Ok(v) if v.is_object() => Ok(v),
        _ => Err(bad(name)),
    }
}

/// A signed record of the given kind, by shape only (devices check the signatures).
fn record_of(text: &Value, kind: &str, name: &str, max: usize) -> Result<Value> {
    let r = parse(text, name, max)?;
    let body_ok = truthy(r.get("body")) && (r["body"].is_object() || r["body"].is_array());
    let sig = &r["sig"];
    if r["kind"] != kind
        || !body_ok
        || !truthy(r.get("sig"))
        || !kid_test(sig.get("kid"))
        || !sig["value"].is_string()
        || !sig["pq"].is_string()
    {
        return Err(bad(name));
    }
    Ok(r)
}

fn actor_of(sr: &Db, user_id: &str) -> Result<Option<Value>> {
    sr.first("ProtoActor", json!({ "user_id": user_id }), "-seq")
}

fn devices_in(doc: &Value) -> Vec<String> {
    doc["body"]["devices"]["body"]["devices"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|d| d["kid"].as_str().map(String::from))
        .collect()
}

fn document_of(actor: &Value) -> Value {
    serde_json::from_str(actor["document"].as_str().unwrap_or("null")).unwrap_or(Value::Null)
}

fn remove_all(sr: &Db, entity: &str, query: Value) -> Result<()> {
    loop {
        let rows = sr.filter(entity, query.clone(), "created_date", 100)?;
        if rows.is_empty() {
            return Ok(());
        }
        let mut gone = 0;
        for r in &rows {
            if sr.delete(entity, id_of(r)).is_ok() {
                gone += 1;
            }
        }
        if gone == 0 {
            return Ok(());
        }
    }
}

/// Sends and bundle requests are counted in memory: a brake, not an exact limit.
fn brake(key: &str, per_minute: usize, now: i64, what: &str) -> Result<()> {
    static RECENT: OnceLock<Mutex<HashMap<String, Vec<i64>>>> = OnceLock::new();
    let mut recent = RECENT
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut list: Vec<i64> = recent
        .get(key)
        .map(|l| l.iter().copied().filter(|x| now - x < 60_000).collect())
        .unwrap_or_default();
    if list.len() >= per_minute {
        return Err(rate_limited(what));
    }
    list.push(now);
    recent.insert(key.to_string(), list);
    if recent.len() > 5000 {
        recent.retain(|_, v| v.iter().any(|x| now - x < 60_000));
    }
    Ok(())
}

fn mine(ctx: &mut Ctx) -> Result<Value> {
    let row = actor_of(&ctx.sr(), ctx.user_id())?;
    Ok(json!({ "actor": row.map(|r| {
        let mut o = json!({});
        for k in ["document", "sealed_account", "sealed_version", "seq"] {
            if let Some(v) = r.get(k) {
                o[k] = v.clone();
            }
        }
        o
    }) }))
}

fn proto_publish(ctx: &mut Ctx) -> Result<Value> {
    let (_, data) =
        signed_by_active_device(ctx, "proto_publish", crate::api::Limits::MAX_BODY_BYTES)?;
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    let doc = record_of(
        &data["document"],
        "actor.document",
        "actor document",
        DOCUMENT_CHARS,
    )?;
    let b = &doc["body"];
    let profile = profile_of(&sr, &uid)?;
    let Some(profile) = profile.filter(|p| truthy(p.get("username"))) else {
        return Err(ApiError::new(409, "NO_PROFILE", "Choose a username first."));
    };
    let handle = if truthy(b.get("handle")) {
        to_js_string(b.get("handle"))
    } else {
        String::new()
    };
    let name = handle.split('@').next().unwrap_or("");
    if name != to_js_string(profile.get("username")).to_lowercase()
        || to_js_string(b.get("handle")).split('@').count() != 2
    {
        return Err(ApiError::new(
            400,
            "BAD_HANDLE",
            "The handle must be your username at this site.",
        ));
    }
    if !kid_test(b.get("id"))
        || doc["sig"]["kid"] != b["id"]
        || !b["account"].as_str().is_some_and(|a| a.contains('.'))
    {
        return Err(ApiError::new(400, "BAD_FIELD", "Invalid actor document."));
    }
    let seq = int(&b["seq"], "seq", 1, 1_000_000_000)?;
    let devices = devices_in(&doc);
    if devices.is_empty() || devices.len() > 10 {
        return Err(ApiError::new(400, "BAD_FIELD", "Invalid device list."));
    }
    let sealed = str_field(
        &data["sealed_account"],
        "sealed account key",
        SEALED_CHARS,
        16,
    )?;
    let sealed_version = int(&data["sealed_version"], "key version", 1, 100_000)?;
    let prev = actor_of(&sr, &uid)?;
    if let Some(p) = &prev {
        if p["actor_id"] != b["id"] {
            return Err(ApiError::new(
                409,
                "ACTOR_EXISTS",
                "This account already has a protocol identity. Turn it off first to start again.",
            ));
        }
        if seq as f64 <= to_number(p.get("seq")) {
            return Err(ApiError::new(
                409,
                "STALE",
                "A newer version is already published.",
            ));
        }
    }
    let row = json!({ "user_id": uid, "actor_id": b["id"], "handle": b["handle"], "seq": seq, "document": js_stringify(&doc), "sealed_account": sealed, "sealed_version": sealed_version });
    match &prev {
        Some(p) => sr.update("ProtoActor", id_of(p), row)?,
        None => sr.create("ProtoActor", row)?,
    };
    // Prekeys and mail of devices no longer on the list go with them.
    let keep: HashSet<&String> = devices.iter().collect();
    let mut stale: Vec<String> = Vec::new();
    for r in sr.filter(
        "ProtoPrekey",
        json!({ "user_id": uid, "slot": "signed" }),
        "created_date",
        50,
    )? {
        let d = to_js_string(r.get("device"));
        if !keep.contains(&d) && !stale.contains(&d) {
            stale.push(d);
        }
    }
    for d in stale {
        remove_all(&sr, "ProtoPrekey", json!({ "user_id": uid, "device": d }))?;
        remove_all(
            &sr,
            "ProtoMail",
            json!({ "to_user_id": uid, "to_device": d }),
        )?;
    }
    Ok(json!({ "ok": true, "seq": seq }))
}

fn proto_prekeys(ctx: &mut Ctx) -> Result<Value> {
    let (_, data) =
        signed_by_active_device(ctx, "proto_prekeys", crate::api::Limits::MAX_BODY_BYTES)?;
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    let device = kid(&data["device"], "device")?;
    let actor = actor_of(&sr, &uid)?;
    if !actor
        .as_ref()
        .is_some_and(|a| devices_in(&document_of(a)).contains(&device))
    {
        return Err(ApiError::new(
            409,
            "NOT_LISTED",
            "Publish the actor document with this device first.",
        ));
    }
    let one = |text: &Value, slot: &str| -> Result<Value> {
        let r = record_of(text, "session.prekey", "prekey", PREKEY_CHARS)?;
        let body_id_ok = r["body"]["id"]
            .as_str()
            .is_some_and(|s| s.encode_utf16().count() <= 40);
        if r["body"]["device"] != device.as_str()
            || r["sig"]["kid"] != device.as_str()
            || !body_id_ok
        {
            return Err(ApiError::new(400, "BAD_FIELD", "Invalid prekey."));
        }
        Ok(
            json!({ "user_id": uid, "device": device, "slot": slot, "prekey_id": r["body"]["id"], "record": js_stringify(&r) }),
        )
    };
    let list = |v: &Value| -> Vec<Value> {
        v.as_array()
            .map(|a| a.iter().take(ONE_TIME_PER_KIND).cloned().collect())
            .unwrap_or_default()
    };
    let mut rows: Vec<Value> = Vec::new();
    if data.get("signed").is_some() || data.get("lastResort").is_some() {
        rows.push(one(&data["signed"], "signed")?);
        rows.push(one(&data["lastResort"], "last")?);
        remove_all(
            &sr,
            "ProtoPrekey",
            json!({ "user_id": uid, "device": device, "slot": "signed" }),
        )?;
        remove_all(
            &sr,
            "ProtoPrekey",
            json!({ "user_id": uid, "device": device, "slot": "last" }),
        )?;
    }
    for (slot, items) in [
        ("otk", list(&data["oneTime"])),
        ("pq", list(&data["pqOneTime"])),
    ] {
        let have = sr
            .filter(
                "ProtoPrekey",
                json!({ "user_id": uid, "device": device, "slot": slot }),
                "created_date",
                ONE_TIME_PER_KIND + 1,
            )?
            .len();
        for text in items.iter().take(ONE_TIME_PER_KIND.saturating_sub(have)) {
            rows.push(one(text, slot)?);
        }
    }
    for r in &rows {
        sr.create("ProtoPrekey", r.clone())?;
    }
    Ok(json!({ "ok": true, "stored": rows.len() }))
}

fn actors(ctx: &mut Ctx) -> Result<Value> {
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    let mut ids: Vec<String> = Vec::new();
    if let Some(a) = ctx.body["user_ids"].as_array() {
        for v in a.iter().take(40) {
            let u = id(v, "user")?;
            if !ids.contains(&u) {
                ids.push(u);
            }
        }
    }
    let contacts = contacts_of(&sr, &uid)?;
    let mut out = Vec::new();
    for u in ids.iter().filter(|u| contacts.contains(*u)) {
        if let Some(row) = actor_of(&sr, u)? {
            out.push(json!({ "user_id": u, "document": row.get("document").cloned().unwrap_or(Value::Null) }));
        }
    }
    Ok(json!({ "actors": out }))
}

fn parse_record(row: &Value) -> Value {
    serde_json::from_str(row["record"].as_str().unwrap_or("null")).unwrap_or(Value::Null)
}

fn bundle(ctx: &mut Ctx) -> Result<Value> {
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    let target = id(&ctx.body["user_id"], "user")?;
    let device = kid(&ctx.body["device"], "device")?;
    brake(
        &format!("b:{uid}"),
        BUNDLES_PER_MINUTE,
        now,
        "starting sessions",
    )?;
    let no_device = || ApiError::new(404, "NOT_FOUND", "No such device.");
    if !contacts_of(&sr, &uid)?.contains(&target) {
        return Err(no_device());
    }
    let doc = actor_of(&sr, &target)?.map(|a| document_of(&a));
    let Some(doc) = doc.filter(|d| devices_in(d).contains(&device)) else {
        return Err(no_device());
    };
    let first = |slot: &str| {
        sr.first(
            "ProtoPrekey",
            json!({ "user_id": target, "device": device, "slot": slot }),
            "created_date",
        )
    };
    // A one-time prekey is handed out only by whoever manages to delete it.
    let take = |slot: &str| -> Result<Option<Value>> {
        for _ in 0..3 {
            let Some(row) = first(slot)? else {
                return Ok(None);
            };
            if sr.delete("ProtoPrekey", id_of(&row)).is_ok() {
                return Ok(Some(row));
            }
        }
        Ok(None)
    };
    let (signed, last) = (first("signed")?, first("last")?);
    let (Some(signed), Some(last)) = (signed, last) else {
        return Err(ApiError::new(
            404,
            "NO_PREKEYS",
            "That device has no prekeys published.",
        ));
    };
    let pq = take("pq")?.unwrap_or(last);
    let otk = take("otk")?;
    let mut b = json!({});
    if let Some(d) = doc["body"].get("devices") {
        b["deviceList"] = d.clone();
    }
    b["device"] = json!(device);
    b["signed"] = parse_record(&signed);
    b["pq"] = parse_record(&pq);
    b["oneTime"] = otk.map_or(Value::Null, |o| parse_record(&o));
    Ok(json!({ "bundle": b }))
}

const ENVELOPE_KEYS: [&str; 5] = ["v", "mode", "device", "session", "message"];

fn send(ctx: &mut Ctx) -> Result<Value> {
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    let items: Vec<Value> = ctx.body["items"].as_array().cloned().unwrap_or_default();
    if items.is_empty() || items.len() > SEND_ITEMS {
        return Err(bad("items"));
    }
    brake(&format!("s:{uid}"), SENDS_PER_MINUTE, now, "sending")?;
    let contacts = contacts_of(&sr, &uid)?;
    let mut allowed: HashMap<String, Option<Vec<String>>> = HashMap::new();
    let mut rows = Vec::new();
    for it in &items {
        let to = id(&it["to"], "recipient")?;
        let env = parse(&it["envelope"], "envelope", ENVELOPE_CHARS)?;
        // Only direct envelopes travel here, and nothing rides along on them (CVP-019, section 1).
        let extra = env
            .as_object()
            .is_some_and(|o| o.keys().any(|k| !ENVELOPE_KEYS.contains(&k.as_str())));
        let ok = env["v"].as_f64() == Some(1.0)
            && env["mode"] == "direct"
            && !extra
            && kid_test(env.get("device"))
            && kid_test(env.get("session"))
            && env["message"]["v"].as_f64() == Some(1.0)
            && env["message"]["c"].is_string();
        if !ok {
            return Err(ApiError::new(
                400,
                "BAD_ENVELOPE",
                "Only direct envelopes can be sent.",
            ));
        }
        if !allowed.contains_key(&to) {
            let mut devices = None;
            if contacts.contains(&to) && (to == uid || !blocked_either_way(&sr, &uid, &to)?) {
                devices = actor_of(&sr, &to)?.map(|a| devices_in(&document_of(&a)));
            }
            allowed.insert(to.clone(), devices);
        }
        // Someone who can't be reached is skipped without saying why, like a blocked message.
        let device = to_js_string(env.get("device"));
        if !allowed[&to].as_ref().is_some_and(|d| d.contains(&device)) {
            continue;
        }
        rows.push(json!({ "to_user_id": to, "to_device": env["device"], "from_user_id": uid, "envelope": js_stringify(&env), "expires_at": iso(now + MAIL_DAYS * 86_400_000) }));
    }
    let mut stored = 0;
    for r in rows {
        if sr
            .filter(
                "ProtoMail",
                json!({ "to_user_id": r["to_user_id"], "to_device": r["to_device"] }),
                "-created_date",
                MAIL_PER_DEVICE,
            )?
            .len()
            >= MAIL_PER_DEVICE
        {
            continue;
        }
        sr.create("ProtoMail", r)?;
        stored += 1;
    }
    Ok(json!({ "ok": true, "stored": stored }))
}

fn collect(ctx: &mut Ctx) -> Result<Value> {
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    let device = kid(&ctx.body["device"], "device")?;
    let mut ack = Vec::new();
    if let Some(a) = ctx.body["ack"].as_array() {
        for v in a.iter().take(COLLECT) {
            ack.push(id(v, "id")?);
        }
    }
    for mail_id in &ack {
        if let Some(row) = sr.first(
            "ProtoMail",
            json!({ "id": mail_id, "to_user_id": uid, "to_device": device }),
            "created_date",
        )? {
            let _ = sr.delete("ProtoMail", id_of(&row));
        }
    }
    let rows = sr.filter(
        "ProtoMail",
        json!({ "to_user_id": uid, "to_device": device }),
        "created_date",
        COLLECT,
    )?;
    let count = |slot: &str| {
        sr.filter(
            "ProtoPrekey",
            json!({ "user_id": uid, "device": device, "slot": slot }),
            "created_date",
            ONE_TIME_PER_KIND + 1,
        )
        .map(|r| r.len())
    };
    let mail: Vec<Value> = rows
        .iter()
        .map(|r| {
            let mut o = json!({});
            for (k, src) in [
                ("id", "id"),
                ("from", "from_user_id"),
                ("envelope", "envelope"),
            ] {
                if let Some(v) = r.get(src) {
                    o[k] = v.clone();
                }
            }
            o
        })
        .collect();
    Ok(json!({ "mail": mail, "prekeys": { "otk": count("otk")?, "pq": count("pq")? } }))
}

fn proto_disable(ctx: &mut Ctx) -> Result<Value> {
    signed_by_active_device(ctx, "proto_disable", crate::api::Limits::MAX_BODY_BYTES)?;
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    remove_all(&sr, "ProtoActor", json!({ "user_id": uid }))?;
    remove_all(&sr, "ProtoPrekey", json!({ "user_id": uid }))?;
    remove_all(&sr, "ProtoMail", json!({ "to_user_id": uid }))?;
    Ok(json!({ "ok": true }))
}

/// Site checks: at most this many per person in the window, per server.
const SITE_CHECKS_PER_WINDOW: usize = 10;
const SITE_CHECK_WINDOW_MS: i64 = 10 * 60_000;
fn site_checks() -> &'static Mutex<HashMap<String, Vec<i64>>> {
    static CHECKS: OnceLock<Mutex<HashMap<String, Vec<i64>>>> = OnceLock::new();
    CHECKS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Another site's public document, for the pre-move checklist (Settings, Protocol identity)
/// (base44/shared/handlers/protocol.ts, checkSite). It goes through this server because the app's
/// security policy only lets the browser talk to its own site. Nothing is pinned or remembered.
fn check_site(ctx: &mut Ctx) -> Result<Value> {
    let host = ctx.body["host"]
        .as_str()
        .filter(|h| h.encode_utf16().count() <= 300)
        .and_then(secure_net_core::wire::federation::norm_host)
        .ok_or_else(|| ApiError::new(400, "BAD_SITE", "That isn't a site address."))?;
    let fed = &ctx.app.federation;
    if !fed.enabled {
        return Err(ApiError::new(
            503,
            "FEDERATION_OFF",
            "This site doesn't talk to other sites.",
        ));
    }
    if host == fed.host {
        return Err(ApiError::new(400, "BAD_SITE", "That's this site."));
    }
    {
        let mut checks = site_checks().lock().unwrap_or_else(|e| e.into_inner());
        let now = ctx.now;
        let recent: Vec<i64> = checks
            .get(ctx.user_id())
            .map(|v| {
                v.iter()
                    .copied()
                    .filter(|at| now - at < SITE_CHECK_WINDOW_MS)
                    .collect()
            })
            .unwrap_or_default();
        if recent.len() >= SITE_CHECKS_PER_WINDOW {
            return Err(rate_limited("checking sites"));
        }
        let mut recent = recent;
        recent.push(now);
        checks.insert(ctx.user_id().to_string(), recent);
    }
    let document = fed
        .signer
        .peek_site_doc(&ctx.app.store, &host)
        .map_err(|e| {
            if e.status == 403 {
                ApiError::new(403, "SITE_BLOCKED", "This site doesn't talk to that site.")
            } else {
                ApiError::new(
                    502,
                    "SITE_UNREACHABLE",
                    "That site couldn't be read. It may be down, or not be a Commonveil site.",
                )
            }
        })?;
    Ok(json!({ "host": host, "document": document }))
}

pub fn actions() -> Actions {
    let mut a = Actions::new();
    for (name, f) in [
        ("mine", mine as crate::api::Action),
        ("proto_publish", proto_publish),
        ("proto_prekeys", proto_prekeys),
        ("actors", actors),
        ("bundle", bundle),
        ("send", send),
        ("collect", collect),
        ("proto_disable", proto_disable),
        ("check_site", check_site),
    ] {
        a.insert(name, f);
    }
    a
}
