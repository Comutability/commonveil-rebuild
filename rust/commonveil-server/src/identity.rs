//! Commonveil sign-in (docs/IDENTITY.md), matching base44/shared/handlers/identity.ts as a
//! self-hosted site runs it: usernames and passwords, owner keys (the recovery phrase), passkeys,
//! confirming new browsers, and devices.
use serde_json::{json, Value};

use crate::api::{clean_text, Actions, ApiError, Ctx, Result};
use crate::crypto::{b64url, check_password, from_b64url, hash_password, hmac, random_bytes, random_token, same_string, sha256_hex, verify_ed25519};
use crate::js::{to_js_string, truthy};
use crate::sessions::{bump_epoch, issue_access, live_session, refresh_row, signed_in, user_record};
use crate::store::{iso, Store};
use crate::webauthn::{authentication_options, registration_options, rp_id_for, verify_assertion, verify_registration};

const MIN_PASSWORD: usize = 10;
const CHECK_MINUTES: i64 = 10;
const MAX_PASSKEYS: usize = 20;
const MAX_DEVICES: usize = 50;
const LOCK_AFTER: usize = 10;
const LOCK_MINUTES: i64 = 15;
const REGISTRATIONS_PER_HOUR: usize = 60;
const OPEN_CHALLENGE_MINUTES: i64 = 5;
pub const TERMS_VERSION: &str = "2026-11-06";
const RESERVED: [&str; 26] = ["admin", "administrator", "root", "system", "support", "help", "staff", "moderator", "mod", "mods", "commonveil", "security", "official", "team", "null", "undefined", "anonymous", "everyone", "here", "abuse", "postmaster", "webmaster", "info", "noreply", "no_reply", ""];

/// What an owner-key signature covers. The app builds the same text (src/lib/crypto/owner.js).
pub fn owner_text(realm: &str, purpose: &str, challenge: &str) -> String {
    format!("commonveil-owner/v1\n{realm}\n{purpose}\n{challenge}")
}

fn deny(status: u16, code: &str, message: &str) -> ApiError {
    ApiError::new(status, code, message)
}
fn expired() -> ApiError {
    deny(400, "EXPIRED", "That took too long. Start again.")
}
fn now_iso() -> String {
    iso(crate::sessions::now_ms())
}
fn now() -> i64 {
    crate::sessions::now_ms()
}
fn username_ok(s: &str) -> bool {
    (3..=20).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}
/// The first `n` UTF-16 code units of a string (`String.prototype.slice(0, n)`).
fn slice16(s: &str, n: usize) -> String {
    String::from_utf16_lossy(&s.encode_utf16().take(n).collect::<Vec<u16>>())
}
fn device_name(v: &Value) -> String {
    let s = v.as_str().map(|s| slice16(s, 60)).unwrap_or_default();
    clean_text(&json!(s), 60).ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "A browser".into())
}
/// `String(v || "")`.
fn text_or_empty(v: &Value) -> String {
    if truthy(Some(v)) { to_js_string(Some(v)) } else { String::new() }
}
fn check_new_password(v: &Value) -> Result<()> {
    match v.as_str() {
        Some(p) if (MIN_PASSWORD..=512).contains(&p.encode_utf16().count()) => Ok(()),
        _ => Err(deny(400, "WEAK_PASSWORD", &format!("Use at least {MIN_PASSWORD} characters."))),
    }
}
fn date(v: &Value) -> f64 {
    v.as_str().and_then(crate::dates::parse).unwrap_or(f64::NAN)
}
fn first(s: &Store, table: &str, q: Value, sort: &str, limit: f64) -> Result<Vec<Value>> {
    Ok(s.filter(table, &q, Some(&json!(sort)), Some(limit), None)?)
}
fn put(obj: &mut Value, k: &str, v: Value) {
    obj.as_object_mut().unwrap().insert(k.into(), v);
}

// ---------- storage helpers ----------

fn account_of(s: &Store, user_id: &str) -> Result<Option<Value>> {
    Ok(first(s, "CvAccount", json!({ "user_id": user_id }), "created_date", 1.0)?.into_iter().next())
}

/// A local person by username (not someone from another site).
fn user_id_for_name(s: &Store, name: &Value) -> Result<Option<String>> {
    let n = crate::js::trim(&text_or_empty(name));
    let n = n.strip_prefix('@').unwrap_or(&n).to_string();
    if !username_ok(&n) {
        return Ok(None);
    }
    let rows = first(s, "Profile", json!({ "username_key": n.to_lowercase() }), "created_date", 2.0)?;
    Ok(rows.iter().find(|r| !truthy(r.get("remote"))).and_then(|p| p["user_id"].as_str().filter(|u| !u.is_empty()).map(String::from)))
}

fn put_challenge(s: &Store, user_id: &str, purpose: &str, data: Value, minutes: i64) -> Result<String> {
    let id = random_token(32);
    s.create("CvChallenge", &json!({ "user_id": user_id, "purpose": purpose, "token_hash": sha256_hex(&id), "data": data.to_string(), "expires_at": iso(now() + minutes * 60_000) }), None)?;
    Ok(id)
}

fn parse_data(row: &Value) -> Result<Value> {
    let text = if truthy(row.get("data")) { to_js_string(row.get("data")) } else { "{}".into() };
    serde_json::from_str(&text).map_err(|_| ApiError { status: 500, code: "INTERNAL".into(), message: "bad challenge data".into() })
}

fn get_challenge(s: &Store, id: &Value, purpose: &str) -> Result<(Value, Value)> {
    let Some(id) = id.as_str().filter(|i| i.encode_utf16().count() <= 100) else { return Err(expired()) };
    let row = first(s, "CvChallenge", json!({ "token_hash": sha256_hex(id) }), "created_date", 1.0)?.into_iter().next().ok_or_else(expired)?;
    if row["purpose"] != purpose || date(&row["expires_at"]) < now() as f64 {
        return Err(expired());
    }
    let data = parse_data(&row)?;
    Ok((row, data))
}

fn save_challenge(s: &Store, row: &Value, data: &Value) -> Result<()> {
    s.update("CvChallenge", row["id"].as_str().unwrap_or(""), &json!({ "data": data.to_string() }))?;
    Ok(())
}
fn drop_challenge(s: &Store, row: &Value) {
    let _ = s.delete("CvChallenge", row["id"].as_str().unwrap_or(""));
}

fn new_device(s: &Store, user_id: &str, name: &Value, how: &str) -> Result<Value> {
    let existing = first(s, "CvDevice", json!({ "user_id": user_id }), "last_seen", (MAX_DEVICES + 5) as f64)?;
    let drop = (existing.len() + 1).saturating_sub(MAX_DEVICES);
    for old in existing.iter().take(drop) {
        forget_device(s, old["id"].as_str().unwrap_or(""))?;
    }
    let secret = random_token(32);
    let row = s.create("CvDevice", &json!({ "user_id": user_id, "secret_hash": sha256_hex(&secret), "name": device_name(name), "confirmed_by": how, "last_seen": now_iso() }), None)?;
    Ok(json!({ "id": row["id"], "secret": secret }))
}

fn known_device(s: &Store, user_id: &str, device: &Value) -> Option<Value> {
    let (id, secret) = (device.get("id")?.as_str()?, device.get("secret")?.as_str()?);
    if secret.encode_utf16().count() > 100 {
        return None;
    }
    let row = s.get("CvDevice", id).ok()?;
    if row["user_id"] != user_id || !same_string(row["secret_hash"].as_str().unwrap_or(""), &sha256_hex(secret)) {
        return None;
    }
    let _ = s.update("CvDevice", id, &json!({ "last_seen": now_iso() }));
    Some(row)
}

fn forget_device(s: &Store, device_id: &str) -> Result<()> {
    for r in first(s, "CvRefresh", json!({ "device_id": device_id }), "created_date", 100.0)? {
        let _ = s.delete("CvRefresh", r["id"].as_str().unwrap_or(""));
    }
    let _ = s.delete("CvDevice", device_id);
    Ok(())
}

fn passkeys_of(s: &Store, user_id: &str) -> Result<Vec<Value>> {
    first(s, "CvPasskey", json!({ "user_id": user_id }), "created_date", (MAX_PASSKEYS + 5) as f64)
}

fn methods_for(s: &Store, acct: &Value) -> Result<Vec<&'static str>> {
    let uid = acct["user_id"].as_str().unwrap_or("");
    let mut m = Vec::new();
    if !passkeys_of(s, uid)?.is_empty() {
        m.push("passkey");
    }
    if truthy(acct.get("owner_pub")) {
        m.push("key");
    }
    if !first(s, "CvDevice", json!({ "user_id": uid }), "created_date", 1.0)?.is_empty() {
        m.push("device");
    }
    Ok(m)
}

/// Sign in this browser: straight in if it's known, a check if it's new and there's something to check with.
fn arrive(ctx: &Ctx, acct: &Value, device: &Value, name: &Value, how: &str) -> Result<Value> {
    let (s, keys) = (ctx.store(), &ctx.app.keys);
    let uid = acct["user_id"].as_str().unwrap_or("");
    if let Some(known) = known_device(s, uid, device) {
        return Ok(signed_in(keys, s, uid, known["id"].as_str().unwrap_or(""), json!({})));
    }
    let methods = methods_for(s, acct)?;
    if methods.is_empty() {
        let fresh = new_device(s, uid, name, how)?;
        return Ok(signed_in(keys, s, uid, fresh["id"].as_str().unwrap_or(""), json!({ "device": fresh })));
    }
    let n = u32::from_le_bytes(random_bytes(4).try_into().unwrap());
    let code = format!("{:06}", n % 1_000_000);
    let challenge = random_token(32);
    let id = put_challenge(s, uid, "login", json!({ "device_name": device_name(name), "code": code, "challenge": challenge, "attempts": 0, "state": "waiting", "created_at": now_iso() }), CHECK_MINUTES)?;
    Ok(json!({ "verify": { "id": id, "methods": methods, "code": code, "challenge": challenge, "realm": ctx.app.config.host } }))
}

fn passkey_host<'a>(ctx: &'a Ctx<'_>) -> impl Fn(&str) -> bool + 'a {
    move |h: &str| h == ctx.app.config.host
}

fn origin_host(ctx: &Ctx, origin: &Value) -> Result<String> {
    rp_id_for(&text_or_empty(origin), &passkey_host(ctx)).map_err(|e| deny(400, "PASSKEY_ORIGIN", &e.message))
}

fn passkey_check(s: &Store, response: &Value, challenge: &str, rp_id: &str, user_id: Option<&str>) -> Result<Value> {
    let cid = response["id"].as_str().unwrap_or("");
    let row = if cid.is_empty() { None } else { first(s, "CvPasskey", json!({ "credential_id": cid }), "created_date", 1.0)?.into_iter().next() };
    let Some(row) = row.filter(|r| user_id.is_none_or(|u| r["user_id"] == u) && r["rp_id"] == rp_id) else {
        return Err(deny(401, "BAD_PASSKEY", "That passkey isn't one this account uses here."));
    };
    let counter = crate::js::to_number(row.get("counter"));
    let counter = if counter.is_nan() || counter <= 0.0 { 0 } else { counter as u32 };
    match verify_assertion(response, challenge, rp_id, row["public_key"].as_str().unwrap_or(""), counter) {
        Ok((counter, synced)) => {
            let _ = s.update("CvPasskey", row["id"].as_str().unwrap_or(""), &json!({ "counter": counter, "synced": synced || truthy(row.get("synced")), "last_used": now_iso() }));
            Ok(row)
        }
        Err(e) => Err(deny(401, "BAD_PASSKEY", if e.known { &e.message } else { "That passkey didn't work. Try again." })),
    }
}

fn require_session(ctx: &Ctx) -> Result<()> {
    if ctx.user.is_none() || ctx.session.as_ref().is_none_or(|s| s.device_id.is_empty()) {
        return Err(deny(401, "SIGN_IN_REQUIRED", "Please sign in again."));
    }
    Ok(())
}

/// A new access token for this session after it moved the epoch on itself (absent if its device has gone).
fn renewed(ctx: &Ctx) -> Option<Value> {
    let dev = &ctx.session.as_ref()?.device_id;
    ctx.store().get("CvDevice", dev).ok()?;
    let (token, expires) = issue_access(&ctx.app.keys, ctx.store(), ctx.user_id(), dev, now());
    Some(json!({ "access_token": token, "access_expires_at": expires }))
}

fn require_live_session(ctx: &Ctx) -> Result<()> {
    require_session(ctx)?;
    if !live_session(ctx.store(), ctx.user_id(), ctx.session.as_ref()) {
        return Err(deny(401, "SIGN_IN_REQUIRED", "Please sign in again."));
    }
    Ok(())
}

// ----- signed-out challenges, as signed tokens -----

fn open_challenge(ctx: &Ctx, purpose: &str, data: Value) -> String {
    let mut claims = data;
    put(&mut claims, "p", json!(purpose));
    put(&mut claims, "x", json!(now() + OPEN_CHALLENGE_MINUTES * 60_000));
    put(&mut claims, "n", json!(random_token(12)));
    let c = b64url(claims.to_string().as_bytes());
    format!("{c}.{}", hmac(&ctx.app.keys.token_secret(ctx.store()), &format!("cv-open.{c}")))
}

fn read_open_challenge(ctx: &Ctx, id: &Value, purpose: &str) -> Result<Value> {
    let Some(id) = id.as_str().filter(|i| i.encode_utf16().count() <= 800) else { return Err(expired()) };
    let mut parts = id.split('.');
    let (claims, sig) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if claims.is_empty() || sig.is_empty() || !same_string(&hmac(&ctx.app.keys.token_secret(ctx.store()), &format!("cv-open.{claims}")), sig) {
        return Err(expired());
    }
    let data: Value = from_b64url(claims).and_then(|b| serde_json::from_slice(&b).ok()).ok_or_else(expired)?;
    if data.get("p").is_none_or(|p| p != purpose) || crate::js::to_number(data.get("x")).partial_cmp(&(now() as f64)) != Some(std::cmp::Ordering::Greater) {
        return Err(expired());
    }
    Ok(data)
}

fn spend_challenge(s: &Store, id: &str) -> Result<()> {
    let hash = sha256_hex(id);
    if !first(s, "CvChallenge", json!({ "token_hash": hash }), "created_date", 1.0)?.is_empty() {
        return Err(deny(400, "EXPIRED", "That was already used. Start again."));
    }
    s.create("CvChallenge", &json!({ "user_id": "", "purpose": "spent", "token_hash": hash, "data": "{}", "expires_at": iso(now() + OPEN_CHALLENGE_MINUTES * 60_000) }), None)?;
    Ok(())
}

// ----- password attempts -----

/// Each attempt is written down before the slow password check, and the count read after.
fn start_password_attempt(s: &Store, user_id: &str) -> Result<bool> {
    let since = now() - LOCK_MINUTES * 60_000;
    s.create("CvChallenge", &json!({ "user_id": user_id, "purpose": "pw-attempt", "token_hash": random_token(16), "data": "{}", "expires_at": iso(now() + LOCK_MINUTES * 60_000) }), None)?;
    let recent = first(s, "CvChallenge", json!({ "user_id": user_id, "purpose": "pw-attempt" }), "-created_date", (LOCK_AFTER + 5) as f64)?;
    let counted = recent.iter().filter(|r| date(&r["expires_at"]) - (LOCK_MINUTES * 60_000) as f64 >= (since - 1000) as f64).count();
    Ok(counted > LOCK_AFTER)
}

fn clear_password_attempts(s: &Store, user_id: &str) -> Result<()> {
    for r in first(s, "CvChallenge", json!({ "user_id": user_id, "purpose": "pw-attempt" }), "created_date", 100.0)? {
        let _ = s.delete("CvChallenge", r["id"].as_str().unwrap_or(""));
    }
    Ok(())
}

// ----- proving it's really you -----

fn has_encryption_device(s: &Store, user_id: &str) -> bool {
    first(s, "Device", json!({ "user_id": user_id, "status": "active" }), "created_date", 1.0).is_ok_and(|r| !r.is_empty())
}

/// A change that adds or removes a way into the account: a live session, plus a proof from an
/// encryption device or the current password. Returns the request's fields.
fn proven_change(ctx: &Ctx, action: &str) -> Result<Value> {
    require_live_session(ctx)?;
    let (s, uid, body) = (ctx.store(), ctx.user_id(), &ctx.body);
    if truthy(body.get("proof")) {
        if let Some(payload) = body["payload"].as_str() {
            let fields: Value = serde_json::from_str(payload).map_err(|_| deny(400, "BAD_PAYLOAD", "Invalid request."))?;
            if !(fields.is_object() || fields.is_array()) || fields["action"] != action || fields["user_id"] != uid {
                return Err(deny(400, "BAD_PAYLOAD", "Invalid request."));
            }
            let device = crate::shared::require_active_device(&crate::db::Db::service(s), uid, &text_or_empty(&body["proof"]["device_id"]))?;
            crate::verify::verify_proof(uid, &format!("identity.{action}"), payload, &body["proof"], device["sign_pub"].as_str().unwrap_or(""), now())?;
            let mut out = if fields.is_object() { fields } else { json!({}) };
            put(&mut out, "proven_by", json!("device"));
            return Ok(out);
        }
    }
    let acct = account_of(s, uid)?;
    if let (Some(pw), Some(a)) = (body["password"].as_str(), acct.as_ref().filter(|a| truthy(a.get("password")))) {
        if start_password_attempt(s, uid)? {
            return Err(deny(429, "RATE_LIMITED", "Too many wrong passwords. Try again in a few minutes."));
        }
        if check_password(pw, a["password"].as_str().unwrap_or("")) {
            clear_password_attempts(s, uid)?;
            let mut out = body.clone();
            put(&mut out, "proven_by", json!("password"));
            return Ok(out);
        }
        return Err(deny(401, "BAD_LOGIN", "That isn't your current password."));
    }
    Err(deny(403, "PROOF_REQUIRED", "Confirm it's you: unlock this device's encryption, or enter your password."))
}

// ----- usernames (profile.ts claim_username) -----

fn by_age(a: &Value, b: &Value) -> std::cmp::Ordering {
    let t = |r: &Value| r["created_date"].as_str().and_then(crate::dates::parse).unwrap_or(f64::NAN);
    match t(a).partial_cmp(&t(b)) {
        Some(std::cmp::Ordering::Equal) | None => to_js_string(a.get("id")).cmp(&to_js_string(b.get("id"))),
        Some(o) => o,
    }
}
fn with_row(rows: Vec<Value>, created: &Value) -> Vec<Value> {
    let mut v: Vec<Value> = rows.into_iter().filter(|r| r["id"] != created["id"]).collect();
    v.push(created.clone());
    v.sort_by(by_age);
    v
}

fn claim_username(s: &Store, user_id: &str, username: &str) -> Result<()> {
    let username = crate::js::trim(username);
    if !username_ok(&username) {
        return Err(deny(400, "BAD_USERNAME", "Usernames are 3-20 characters: letters, numbers and underscores."));
    }
    let key = username.to_lowercase();
    let retired = !first(s, "RetiredUsername", json!({ "username_key": key }), "created_date", 1.0)?.is_empty();
    if RESERVED.contains(&key.as_str()) || retired {
        return Err(deny(409, "USERNAME_TAKEN", "That username isn't available."));
    }
    if !first(s, "Profile", json!({ "user_id": user_id }), "created_date", 5.0)?.is_empty() {
        return Err(deny(409, "ALREADY_CLAIMED", "You already have a username."));
    }
    if !first(s, "Profile", json!({ "username_key": key }), "created_date", 1.0)?.is_empty() {
        return Err(deny(409, "USERNAME_TAKEN", "That username is taken."));
    }
    let created = s.create("Profile", &json!({ "user_id": user_id, "username": username, "username_key": key, "display_name": username, "bio": "" }), None)?;
    // Two people (or two tabs) can race for the same name. Oldest claim wins.
    let same_name = with_row(first(s, "Profile", json!({ "username_key": key }), "created_date", 10.0)?, &created);
    let mine = with_row(first(s, "Profile", json!({ "user_id": user_id }), "created_date", 10.0)?, &created);
    if same_name[0]["id"] != created["id"] || mine[0]["id"] != created["id"] {
        let _ = s.delete("Profile", created["id"].as_str().unwrap_or(""));
        if mine[0]["id"] != created["id"] {
            return Err(deny(409, "ALREADY_CLAIMED", "You already have a username."));
        }
        return Err(deny(409, "USERNAME_TAKEN", "That username is taken."));
    }
    Ok(())
}

// ---------- the actions ----------

fn register(ctx: &mut Ctx) -> Result<Value> {
    let (s, body) = (ctx.store(), &ctx.body);
    let username = crate::js::trim(&text_or_empty(&body["username"]));
    let username = username.strip_prefix('@').unwrap_or(&username).to_string();
    if !username_ok(&username) {
        return Err(deny(400, "BAD_USERNAME", "Usernames are 3 to 20 letters, numbers or underscores."));
    }
    check_new_password(&body["password"])?;
    if body["age_confirmed"] != true {
        return Err(deny(400, "AGE_REQUIRED", "Commonveil is for people 16 and over. Confirm you're 16 or older to create an account."));
    }
    // A new self-hosted site: only its operator, with the setup code, can make the first account.
    let mut role = "user";
    if ctx.app.bootstrap.needed(s) {
        if body.get("setup_code").is_none() || body["setup_code"] == "" {
            return Err(deny(403, "SETUP_CODE_REQUIRED", "This site isn't set up yet. Its operator creates the first account with the setup code shown when the server started."));
        }
        if user_id_for_name(s, &json!(username))?.is_some() {
            return Err(deny(409, "USERNAME_TAKEN", "That username is taken."));
        }
        if !ctx.app.bootstrap.consume(&body["setup_code"]) {
            return Err(deny(403, "BAD_SETUP_CODE", "That setup code isn't right, or has already been used."));
        }
        role = "admin";
    } else if !ctx.app.config.open_registration {
        return Err(deny(403, "REGISTRATION_CLOSED", "This site isn't taking new accounts. Ask its operator."));
    }
    if user_id_for_name(s, &json!(username))?.is_some() {
        return Err(deny(409, "USERNAME_TAKEN", "That username is taken."));
    }
    let hour_ago = iso(now() - 3_600_000).trim_end_matches('Z').to_string();
    if first(s, "Person", json!({ "created_date": { "$gte": hour_ago } }), "-created_date", REGISTRATIONS_PER_HOUR as f64)?.len() >= REGISTRATIONS_PER_HOUR {
        return Err(deny(429, "RATE_LIMITED", "A lot of accounts are being made right now. Try again in a while."));
    }
    let person = s.create("Person", &json!({ "role": role, "email": "", "full_name": "" }), None)?;
    let pid = person["id"].as_str().unwrap_or("").to_string();
    if let Err(e) = claim_username(s, &pid, &username) {
        let _ = s.delete("Person", &pid);
        return Err(e);
    }
    let rounds = ctx.app.config.password_rounds;
    s.create("CvAccount", &json!({ "user_id": pid, "kind": "person", "password": hash_password(body["password"].as_str().unwrap_or(""), rounds), "owner_pub": "", "failed": 0, "security_epoch": 0, "age_confirmed_at": now_iso(), "terms_version": TERMS_VERSION }), None)?;
    let device = new_device(s, &pid, &body["device_name"], "registration")?;
    Ok(signed_in(&ctx.app.keys, s, &pid, device["id"].as_str().unwrap_or(""), json!({ "device": device, "user": { "id": pid, "role": role } })))
}

/// Base44 accounts made with an email only; a self-hosted site has none.
fn link_platform(_ctx: &mut Ctx) -> Result<Value> {
    Err(deny(401, "SIGN_IN_REQUIRED", "Sign in with your email first."))
}

fn login(ctx: &mut Ctx) -> Result<Value> {
    let s = ctx.store();
    let user_id = user_id_for_name(s, &ctx.body["username"])?;
    let acct = match &user_id {
        Some(u) => account_of(s, u)?,
        None => None,
    };
    if let Some(a) = &acct {
        if start_password_attempt(s, a["user_id"].as_str().unwrap_or(""))? {
            return Err(deny(429, "RATE_LIMITED", "Too many wrong passwords. Try again in a few minutes, or get back in with your recovery phrase."));
        }
    }
    let stored = acct.as_ref().map(|a| text_or_empty(&a["password"])).unwrap_or_default();
    if !check_password(&text_or_empty(&ctx.body["password"]), &stored) {
        let no_pw = acct.as_ref().is_some_and(|a| !truthy(a.get("password")));
        return Err(deny(401, "BAD_LOGIN", if no_pw { "This account doesn't have a password for its username yet. Sign in with your email, then set one." } else { "That username and password don't match." }));
    }
    let acct = acct.unwrap();
    clear_password_attempts(s, acct["user_id"].as_str().unwrap_or(""))?;
    let (device, name) = (ctx.body["device"].clone(), ctx.body["device_name"].clone());
    arrive(ctx, &acct, &device, &name, "password")
}

fn allow_list(rows: &[Value], rp_id: &str) -> Vec<(String, Value)> {
    rows.iter().filter(|p| p["rp_id"] == rp_id).map(|p| (p["credential_id"].as_str().unwrap_or("").to_string(), p["transports"].clone())).collect()
}

fn check_options(ctx: &mut Ctx) -> Result<Value> {
    let s = ctx.store();
    let (row, mut data) = get_challenge(s, &ctx.body["id"], "login")?;
    let rp_id = origin_host(ctx, &ctx.body["origin"])?;
    let challenge = random_token(32);
    let allow = allow_list(&passkeys_of(s, row["user_id"].as_str().unwrap_or(""))?, &rp_id);
    put(&mut data, "webauthn", json!(challenge));
    put(&mut data, "rp_id", json!(rp_id));
    save_challenge(s, &row, &data)?;
    Ok(json!({ "options": authentication_options(&rp_id, &challenge, &allow) }))
}

fn check(ctx: &mut Ctx) -> Result<Value> {
    let s = ctx.store();
    let (row, mut data) = get_challenge(s, &ctx.body["id"], "login")?;
    let uid = row["user_id"].as_str().unwrap_or("").to_string();
    let acct = account_of(s, &uid)?.ok_or_else(expired)?;
    let fail = |data: &mut Value, message: &str| -> ApiError {
        let n = crate::js::to_number(data.get("attempts"));
        put(data, "attempts", json!(if n.is_nan() || n == 0.0 { 0.0 } else { n } as i64 + 1));
        if data["attempts"].as_i64().unwrap_or(0) >= 5 {
            drop_challenge(s, &row);
        } else if let Err(e) = save_challenge(s, &row, data) {
            return e;
        }
        deny(401, "CHECK_FAILED", message)
    };
    let method = ctx.body["method"].as_str().unwrap_or("");
    match method {
        "passkey" => {
            if !truthy(data.get("webauthn")) {
                return Err(fail(&mut data, "Start again."));
            }
            let (w, r) = (text_or_empty(&data["webauthn"]), text_or_empty(&data["rp_id"]));
            if let Err(e) = passkey_check(s, &ctx.body["response"], &w, &r, Some(&uid)) {
                return Err(fail(&mut data, &e.message));
            }
        }
        "key" => {
            let ok = truthy(acct.get("owner_pub")) && ctx.body["signature"].as_str().is_some_and(|sig| verify_ed25519(acct["owner_pub"].as_str().unwrap_or(""), &owner_text(&ctx.app.config.host, "verify-device", &text_or_empty(&data["challenge"])), sig));
            if !ok {
                return Err(fail(&mut data, "That recovery phrase or private key isn't this account's."));
            }
        }
        "device" => {
            if data["state"] == "denied" {
                drop_challenge(s, &row);
                return Err(deny(403, "DENIED", "That sign-in was turned down on your other device."));
            }
            if data["state"] != "approved" {
                return Ok(json!({ "waiting": true }));
            }
        }
        _ => return Err(deny(400, "BAD_METHOD", "Choose how to confirm this device.")),
    }
    drop_challenge(s, &row);
    let device = new_device(s, &uid, &data["device_name"], method)?;
    Ok(signed_in(&ctx.app.keys, s, &uid, device["id"].as_str().unwrap_or(""), json!({ "device": device })))
}

fn passkey_login_options(ctx: &mut Ctx) -> Result<Value> {
    let rp_id = origin_host(ctx, &ctx.body["origin"])?;
    let challenge = random_token(32);
    let id = open_challenge(ctx, "passkey-login", json!({ "c": challenge, "r": rp_id }));
    Ok(json!({ "id": id, "options": authentication_options(&rp_id, &challenge, &[]) }))
}

fn passkey_login(ctx: &mut Ctx) -> Result<Value> {
    let s = ctx.store();
    let data = read_open_challenge(ctx, &ctx.body["id"], "passkey-login")?;
    let pk = passkey_check(s, &ctx.body["response"], &text_or_empty(&data["c"]), &text_or_empty(&data["r"]), None)?;
    spend_challenge(s, &to_js_string(ctx.body.get("id")))?;
    let uid = pk["user_id"].as_str().unwrap_or("").to_string();
    if account_of(s, &uid)?.is_none() {
        return Err(deny(401, "BAD_PASSKEY", "That passkey isn't one this site knows."));
    }
    if let Some(known) = known_device(s, &uid, &ctx.body["device"]) {
        return Ok(signed_in(&ctx.app.keys, s, &uid, known["id"].as_str().unwrap_or(""), json!({})));
    }
    let fresh = new_device(s, &uid, &ctx.body["device_name"], "passkey")?;
    Ok(signed_in(&ctx.app.keys, s, &uid, fresh["id"].as_str().unwrap_or(""), json!({ "device": fresh })))
}

fn recover_options(ctx: &mut Ctx) -> Result<Value> {
    let username = crate::js::trim(&text_or_empty(&ctx.body["username"]));
    let username = username.strip_prefix('@').unwrap_or(&username).to_lowercase();
    let rp_id = rp_id_for(&text_or_empty(&ctx.body["origin"]), &passkey_host(ctx)).unwrap_or_default();
    let (challenge, webauthn) = (random_token(32), random_token(32));
    let id = open_challenge(ctx, "recover", json!({ "u": username, "c": challenge, "w": webauthn, "r": rp_id }));
    Ok(json!({ "id": id, "challenge": challenge, "realm": ctx.app.config.host, "options": if rp_id.is_empty() { Value::Null } else { authentication_options(&rp_id, &webauthn, &[]) } }))
}

fn recover(ctx: &mut Ctx) -> Result<Value> {
    let s = ctx.store();
    check_new_password(&ctx.body["new_password"])?;
    let data = read_open_challenge(ctx, &ctx.body["id"], "recover")?;
    let user_id = if truthy(data.get("u")) { user_id_for_name(s, &data["u"])? } else { None };
    let acct = match &user_id {
        Some(u) => account_of(s, u)?,
        None => None,
    };
    let nope = || deny(401, "RECOVER_FAILED", "That didn't match this account. Check the username and try again.");
    let Some(acct) = acct else { return Err(nope()) };
    let uid = acct["user_id"].as_str().unwrap_or("").to_string();
    match ctx.body["method"].as_str() {
        Some("key") => {
            let ok = truthy(acct.get("owner_pub")) && ctx.body["signature"].as_str().is_some_and(|sig| verify_ed25519(acct["owner_pub"].as_str().unwrap_or(""), &owner_text(&ctx.app.config.host, "recover", &text_or_empty(&data["c"])), sig));
            if !ok {
                return Err(nope());
            }
        }
        Some("passkey") => {
            if passkey_check(s, &ctx.body["response"], &text_or_empty(&data["w"]), &text_or_empty(&data["r"]), Some(&uid)).is_err() {
                return Err(nope());
            }
        }
        _ => return Err(nope()),
    }
    spend_challenge(s, &to_js_string(ctx.body.get("id")))?;
    s.update("CvAccount", acct["id"].as_str().unwrap_or(""), &json!({ "password": hash_password(ctx.body["new_password"].as_str().unwrap_or(""), ctx.app.config.password_rounds), "failed": 0 }))?;
    clear_password_attempts(s, &uid)?;
    // Every session made before this can no longer change how the account is protected,
    bump_epoch(s, &uid);
    // and every session is signed out; devices stay connected.
    for r in first(s, "CvRefresh", json!({ "user_id": uid }), "created_date", 500.0)? {
        let _ = s.delete("CvRefresh", r["id"].as_str().unwrap_or(""));
    }
    if let Some(known) = known_device(s, &uid, &ctx.body["device"]) {
        return Ok(signed_in(&ctx.app.keys, s, &uid, known["id"].as_str().unwrap_or(""), json!({})));
    }
    let method = ctx.body["method"].as_str().unwrap_or("").to_string();
    let fresh = new_device(s, &uid, &ctx.body["device_name"], &method)?;
    Ok(signed_in(&ctx.app.keys, s, &uid, fresh["id"].as_str().unwrap_or(""), json!({ "device": fresh })))
}

fn refresh(ctx: &mut Ctx) -> Result<Value> {
    let s = ctx.store();
    let Some((row, device)) = refresh_row(s, ctx.body.get("refresh_token"), now()) else { return Err(deny(401, "SIGN_IN_REQUIRED", "Please sign in again.")) };
    let did = device["id"].as_str().unwrap_or("");
    let _ = s.update("CvDevice", did, &json!({ "last_seen": now_iso() }));
    let (token, expires) = issue_access(&ctx.app.keys, s, row["user_id"].as_str().unwrap_or(""), did, now());
    Ok(json!({ "access_token": token, "access_expires_at": expires, "user_id": row["user_id"], "device_id": did }))
}

fn logout(ctx: &mut Ctx) -> Result<Value> {
    if let Some((row, _)) = refresh_row(ctx.store(), ctx.body.get("refresh_token"), now()) {
        let _ = ctx.store().delete("CvRefresh", row["id"].as_str().unwrap_or(""));
    }
    Ok(json!({ "ok": true }))
}

fn me(ctx: &mut Ctx) -> Result<Value> {
    require_session(ctx)?;
    let rec = user_record(ctx.store(), ctx.user_id()).ok_or_else(|| deny(401, "SIGN_IN_REQUIRED", "Please sign in again."))?;
    let or = |k: &str, d: &str| if truthy(rec.get(k)) { rec[k].clone() } else { json!(d) };
    Ok(json!({ "user": { "id": rec["id"], "role": or("role", "user"), "email": or("email", ""), "full_name": or("full_name", ""), "site_owner": truthy(rec.get("site_owner")), "created_date": rec["created_date"] } }))
}

fn status(ctx: &mut Ctx) -> Result<Value> {
    require_session(ctx)?;
    let (s, uid) = (ctx.store(), ctx.user_id());
    let current = ctx.session.as_ref().map(|x| x.device_id.clone()).unwrap_or_default();
    let acct = account_of(s, uid)?;
    let a = |k: &str| acct.as_ref().and_then(|a| a.get(k).cloned());
    let platform = a("kind").is_some_and(|k| k == "platform");
    let passkeys: Vec<Value> = passkeys_of(s, uid)?.iter().map(|p| json!({ "id": p["id"], "name": p["name"], "synced": truthy(p.get("synced")), "created_at": p["created_date"], "last_used": if truthy(p.get("last_used")) { p["last_used"].clone() } else { Value::Null }, "here": true })).collect();
    let devices: Vec<Value> = first(s, "CvDevice", json!({ "user_id": uid }), "-last_seen", MAX_DEVICES as f64)?.iter().map(|d| json!({ "id": d["id"], "name": d["name"], "created_at": d["created_date"], "last_seen": d["last_seen"], "confirmed_by": d["confirmed_by"], "current": d["id"] == current.as_str() })).collect();
    Ok(json!({
        "kind": a("kind").filter(|k| truthy(Some(k))).unwrap_or(json!("person")),
        "has_password": truthy(a("password").as_ref()),
        "age_confirmed": truthy(a("age_confirmed_at").as_ref()),
        "email": if platform { a("email").filter(|e| truthy(Some(e))).unwrap_or(json!("")) } else { json!("") },
        "email_retiring": platform && truthy(a("email").as_ref()),
        "owner": truthy(a("owner_pub").as_ref()),
        "owner_set_at": a("owner_set_at").filter(|v| truthy(Some(v))).unwrap_or(Value::Null),
        "passkeys": passkeys,
        "devices": devices,
    }))
}

fn account(ctx: &mut Ctx) -> Result<Value> {
    require_session(ctx)?;
    let s = ctx.store();
    let uid = ctx.user_id().to_string();
    let current = ctx.session.as_ref().map(|x| x.device_id.clone()).unwrap_or_default();
    let acct = account_of(s, &uid)?.ok_or_else(|| deny(404, "NOT_FOUND", "No sign-in for this account."))?;
    let change = match ctx.body["payload"].as_str() {
        Some(p) => serde_json::from_str::<Value>(p).ok().map_or(json!(""), |v| v.get("change").cloned().unwrap_or(Value::Null)),
        None => ctx.body.get("change").cloned().unwrap_or(Value::Null),
    };
    let change = change.as_str().unwrap_or("").to_string();
    let mut body = ctx.body.clone();
    match change.as_str() {
        "remove_passkey" | "remove_email" => body = proven_change(ctx, &format!("account.{change}"))?,
        "set_password" => {
            body = if has_encryption_device(s, &uid) {
                proven_change(ctx, "account.set_password")?
            } else {
                require_live_session(ctx)?;
                body
            }
        }
        "disconnect_device" | "change_password" => require_live_session(ctx)?,
        _ => {}
    }
    let aid = acct["id"].as_str().unwrap_or("");
    let rounds = ctx.app.config.password_rounds;
    match change.as_str() {
        "remove_passkey" => {
            if let Ok(pk) = s.get("CvPasskey", &text_or_empty(&body["id"])) {
                if pk["user_id"] == uid.as_str() {
                    s.delete("CvPasskey", pk["id"].as_str().unwrap_or(""))?;
                    bump_epoch(s, &uid);
                    let mut out = json!({ "ok": true });
                    if let Some(r) = renewed(ctx) {
                        put(&mut out, "renewed_access", r);
                    }
                    return Ok(out);
                }
            }
            Ok(json!({ "ok": true }))
        }
        "disconnect_device" => {
            let d = s.get("CvDevice", &text_or_empty(&body["id"])).ok().filter(|d| d["user_id"] == uid.as_str()).ok_or_else(|| deny(404, "NOT_FOUND", "That device isn't connected."))?;
            let did = d["id"].as_str().unwrap_or("").to_string();
            forget_device(s, &did)?;
            // Its last access token can't be used to change anything about the account either.
            bump_epoch(s, &uid);
            let mut out = json!({ "ok": true, "signed_out": did == current });
            if did != current {
                if let Some(r) = renewed(ctx) {
                    put(&mut out, "renewed_access", r);
                }
            }
            Ok(out)
        }
        "confirm_age" => {
            if body["age_confirmed"] != true {
                return Err(deny(400, "AGE_REQUIRED", "Commonveil is for people 16 and over."));
            }
            s.update("CvAccount", aid, &json!({ "age_confirmed_at": now_iso(), "terms_version": TERMS_VERSION }))?;
            Ok(json!({ "ok": true }))
        }
        "set_password" => {
            if truthy(acct.get("password")) {
                return Err(deny(409, "HAS_PASSWORD", "You already have a password. Change it instead."));
            }
            check_new_password(&body["new_password"])?;
            s.update("CvAccount", aid, &json!({ "password": hash_password(body["new_password"].as_str().unwrap_or(""), rounds) }))?;
            Ok(json!({ "ok": true }))
        }
        "change_password" => {
            if !check_password(&text_or_empty(&body["password"]), &text_or_empty(&acct["password"])) {
                return Err(deny(401, "BAD_LOGIN", "That isn't your current password."));
            }
            check_new_password(&body["new_password"])?;
            s.update("CvAccount", aid, &json!({ "password": hash_password(body["new_password"].as_str().unwrap_or(""), rounds) }))?;
            bump_epoch(s, &uid);
            let mut out = json!({ "ok": true });
            if let Some(r) = renewed(ctx) {
                put(&mut out, "renewed_access", r);
            }
            Ok(out)
        }
        "remove_email" => {
            if acct["kind"] != "platform" {
                return Ok(json!({ "ok": true }));
            }
            if !truthy(acct.get("password")) {
                return Err(deny(409, "NEEDS_PASSWORD", "Set a password for your username first."));
            }
            if !truthy(acct.get("owner_pub")) {
                return Err(deny(409, "NEEDS_OWNER", "Confirm your recovery phrase first, so you can always get back in."));
            }
            s.update("CvAccount", aid, &json!({ "email": "" }))?;
            Ok(json!({ "ok": true }))
        }
        _ => Err(deny(400, "BAD_ACTION", "Unknown change.")),
    }
}

fn approvals(ctx: &mut Ctx) -> Result<Value> {
    require_session(ctx)?;
    let mut out = Vec::new();
    for r in first(ctx.store(), "CvChallenge", json!({ "user_id": ctx.user_id(), "purpose": "login" }), "-created_date", 10.0)? {
        if date(&r["expires_at"]) < now() as f64 {
            continue;
        }
        let d = parse_data(&r)?;
        if d["state"] == "waiting" {
            out.push(json!({ "id": r["id"], "device_name": d["device_name"], "code": d["code"], "created_at": d["created_at"] }));
        }
    }
    Ok(json!({ "approvals": out }))
}

fn approve(ctx: &mut Ctx) -> Result<Value> {
    require_session(ctx)?;
    let s = ctx.store();
    // Saying no is always allowed; letting another browser in must be proven.
    let asked = ctx.body.clone();
    let body = if asked["approve"] == true || asked["payload"].is_string() {
        proven_change(ctx, "approve")?
    } else {
        require_live_session(ctx)?;
        asked
    };
    let r = s.get("CvChallenge", &text_or_empty(&body["id"])).ok();
    let Some(r) = r.filter(|r| r["user_id"] == ctx.user_id() && r["purpose"] == "login" && date(&r["expires_at"]).partial_cmp(&(now() as f64)) != Some(std::cmp::Ordering::Less)) else {
        return Err(deny(404, "NOT_FOUND", "That sign-in has gone."));
    };
    let mut d = parse_data(&r)?;
    put(&mut d, "state", json!(if body["approve"] == true { "approved" } else { "denied" }));
    put(&mut d, "approved_by", json!(ctx.session.as_ref().map(|x| x.device_id.clone()).unwrap_or_default()));
    s.update("CvChallenge", r["id"].as_str().unwrap_or(""), &json!({ "data": d.to_string() }))?;
    Ok(json!({ "ok": true }))
}

fn passkey_options(ctx: &mut Ctx) -> Result<Value> {
    require_live_session(ctx)?;
    let (s, uid) = (ctx.store(), ctx.user_id().to_string());
    let rp_id = origin_host(ctx, &ctx.body["origin"])?;
    let existing = passkeys_of(s, &uid)?;
    if existing.len() >= MAX_PASSKEYS {
        return Err(deny(409, "TOO_MANY", &format!("You can have up to {MAX_PASSKEYS} passkeys. Remove one first.")));
    }
    let profile = first(s, "Profile", json!({ "user_id": uid }), "created_date", 1.0)?.into_iter().next();
    let kind = if ctx.body["kind"] == "device" { "device" } else { "synced" };
    let challenge = random_token(32);
    let id = put_challenge(s, &uid, "passkey-reg", json!({ "challenge": challenge, "kind": kind, "rp_id": rp_id }), 5)?;
    let name = profile.as_ref().map(|p| text_or_empty(&p["username"])).filter(|n| !n.is_empty()).unwrap_or_else(|| "commonveil".into());
    let options = registration_options(&rp_id, &ctx.app.config.site_name, &uid, &name, &challenge, &allow_list(&existing, &rp_id), kind);
    Ok(json!({ "id": id, "options": options }))
}

fn passkey_add(ctx: &mut Ctx) -> Result<Value> {
    let s = ctx.store();
    let body = proven_change(ctx, "passkey_add")?;
    let (row, data) = get_challenge(s, &body["id"], "passkey-reg")?;
    if row["user_id"] != ctx.user_id() {
        return Err(deny(400, "EXPIRED", "Start again."));
    }
    let info = verify_registration(&body["response"], &text_or_empty(&data["challenge"]), &text_or_empty(&data["rp_id"])).map_err(|e| deny(400, "BAD_PASSKEY", if e.known { &e.message } else { "That passkey couldn't be added. Try again." }))?;
    drop_challenge(s, &row);
    if !first(s, "CvPasskey", json!({ "credential_id": info.credential_id }), "created_date", 1.0)?.is_empty() {
        return Err(deny(409, "EXISTS", "That passkey is already set up."));
    }
    let name = clean_text(&json!(body["name"].as_str().map(|n| slice16(n, 60)).unwrap_or_default()), 60).ok().filter(|n| !n.is_empty()).unwrap_or_else(|| (if info.synced { "Synced passkey" } else { "Passkey on this device" }).into());
    let pk = s.create("CvPasskey", &json!({ "user_id": ctx.user_id(), "credential_id": info.credential_id, "public_key": info.public_key, "alg": info.alg, "counter": info.counter, "transports": info.transports, "synced": info.synced, "rp_id": data["rp_id"], "name": name, "last_used": "" }), None)?;
    Ok(json!({ "ok": true, "passkey": { "id": pk["id"], "synced": info.synced } }))
}

fn owner_challenge(ctx: &mut Ctx) -> Result<Value> {
    require_live_session(ctx)?;
    let challenge = random_token(32);
    let id = put_challenge(ctx.store(), ctx.user_id(), "owner-set", json!({ "challenge": challenge }), 5)?;
    Ok(json!({ "id": id, "challenge": challenge, "realm": ctx.app.config.host }))
}

fn owner(ctx: &mut Ctx) -> Result<Value> {
    require_live_session(ctx)?;
    let (s, uid) = (ctx.store(), ctx.user_id().to_string());
    let realm = ctx.app.config.host.clone();
    let acct = account_of(s, &uid)?.ok_or_else(|| deny(404, "NOT_FOUND", "No sign-in for this account."))?;
    let mut body = ctx.body.clone();
    let mut authorised = false;
    if truthy(body.get("proof")) && body["payload"].is_string() {
        body = proven_change(ctx, "owner")?;
        authorised = body["proven_by"] == "device";
    }
    let (row, data) = get_challenge(s, &body["id"], "owner-set")?;
    if row["user_id"] != uid.as_str() {
        return Err(deny(400, "EXPIRED", "Start again."));
    }
    let new_pub = body["owner_pub"].as_str().filter(|k| k.len() == 43 && k.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')).ok_or_else(|| deny(400, "BAD_KEY", "That key isn't valid."))?.to_string();
    let challenge = text_or_empty(&data["challenge"]);
    if !body["signature"].as_str().is_some_and(|sig| verify_ed25519(&new_pub, &owner_text(&realm, "set-owner", &challenge), sig)) {
        return Err(deny(400, "BAD_KEY", "That key couldn't be confirmed."));
    }
    let old = text_or_empty(&acct["owner_pub"]);
    if !authorised && !old.is_empty() {
        if let Some(old_sig) = body["old_signature"].as_str() {
            authorised = verify_ed25519(&old, &owner_text(&realm, &format!("replace-owner:{new_pub}"), &challenge), old_sig);
        }
    }
    if !authorised && old.is_empty() && !has_encryption_device(s, &uid) && ctx.body["password"].is_string() {
        authorised = proven_change(ctx, "owner")?["proven_by"] == "password";
    }
    if !authorised {
        return Err(deny(403, "PROOF_REQUIRED", "Confirm it's you: do this from a device with your encryption unlocked."));
    }
    drop_challenge(s, &row);
    if old == new_pub {
        return Ok(json!({ "ok": true }));
    }
    s.update("CvAccount", acct["id"].as_str().unwrap_or(""), &json!({ "owner_pub": new_pub, "owner_set_at": now_iso() }))?;
    if !old.is_empty() {
        bump_epoch(s, &uid);
        let mut out = json!({ "ok": true });
        if let Some(r) = renewed(ctx) {
            put(&mut out, "renewed_access", r);
        }
        return Ok(out);
    }
    Ok(json!({ "ok": true }))
}

/// The identity function's actions.
pub fn actions() -> Actions {
    let mut a: Actions = Actions::new();
    for (name, f) in [
        ("register", register as crate::api::Action),
        ("link_platform", link_platform),
        ("login", login),
        ("check_options", check_options),
        ("check", check),
        ("passkey_login_options", passkey_login_options),
        ("passkey_login", passkey_login),
        ("recover_options", recover_options),
        ("recover", recover),
        ("refresh", refresh),
        ("logout", logout),
        ("me", me),
        ("status", status),
        ("account", account),
        ("approvals", approvals),
        ("approve", approve),
        ("passkey_options", passkey_options),
        ("passkey_add", passkey_add),
        ("owner_challenge", owner_challenge),
        ("owner", owner),
    ] {
        a.insert(name, f);
    }
    a
}

/// Remove everything an account signs in with (account deletion).
pub fn remove_sign_in(s: &Store, user_id: &str) {
    for name in ["CvRefresh", "CvDevice", "CvPasskey", "CvChallenge", "CvAccount"] {
        loop {
            let rows = first(s, name, json!({ "user_id": user_id }), "created_date", 100.0).unwrap_or_default();
            if rows.is_empty() {
                break;
            }
            for r in &rows {
                let _ = s.delete(name, r["id"].as_str().unwrap_or(""));
            }
            if rows.len() < 100 {
                break;
            }
        }
    }
}
