//! Sessions for Commonveil sign-in, matching base44/shared/identity/sessions.ts (docs/IDENTITY.md).
//!
//! An access token (15 minutes) is "cv1.<claims>.<HMAC>", checked with no database lookup; a
//! refresh token (30 days) is stored hashed and tied to one device.
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::crypto::{b64url, from_b64url, hmac, random_token, same_string, sha256_hex};
use crate::store::{iso, Store};

pub const ACCESS_SECONDS: i64 = 15 * 60;
pub const REFRESH_DAYS: i64 = 30;

/// Who a valid access token is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub user_id: String,
    pub device_id: String,
    pub epoch: i64,
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn first(store: &Store, table: &str, query: Value) -> Option<Value> {
    store
        .filter(table, &query, Some(&json!("created_date")), Some(1.0), None)
        .ok()
        .and_then(|r| r.into_iter().next())
}

/// The site's token key, made the first time and then kept (CvSecret).
pub struct Keys {
    cached: Mutex<Option<String>>,
}
impl Default for Keys {
    fn default() -> Self {
        Self {
            cached: Mutex::new(None),
        }
    }
}
impl Keys {
    pub fn token_secret(&self, store: &Store) -> String {
        let mut c = self.cached.lock().unwrap();
        if let Some(s) = c.as_ref() {
            return s.clone();
        }
        let found = first(store, "CvSecret", json!({ "name": "access-tokens" })).and_then(|r| {
            r["value"]
                .as_str()
                .filter(|v| !v.is_empty())
                .map(String::from)
        });
        let secret = match found {
            Some(v) => v,
            None => {
                let _ = store.create(
                    "CvSecret",
                    &json!({ "name": "access-tokens", "value": random_token(32) }),
                    None,
                );
                // Two first requests at once: the oldest key wins, for everyone.
                first(store, "CvSecret", json!({ "name": "access-tokens" }))
                    .and_then(|r| r["value"].as_str().map(String::from))
                    .unwrap_or_default()
            }
        };
        *c = Some(secret.clone());
        secret
    }
}

/// The account's security epoch: goes up whenever a way into it is removed or reset.
pub fn security_epoch(store: &Store, user_id: &str) -> i64 {
    first(store, "CvAccount", json!({ "user_id": user_id })).map_or(0, |a| {
        let n = crate::js::to_number(a.get("security_epoch"));
        if n.is_nan() {
            0
        } else {
            n as i64
        }
    })
}

pub fn bump_epoch(store: &Store, user_id: &str) {
    if let Some(a) = first(store, "CvAccount", json!({ "user_id": user_id })) {
        let n = crate::js::to_number(a.get("security_epoch"));
        let _ = store.update(
            "CvAccount",
            a["id"].as_str().unwrap_or(""),
            &json!({ "security_epoch": if n.is_nan() { 0 } else { n as i64 } + 1 }),
        );
    }
}

pub fn issue_access(
    keys: &Keys,
    store: &Store,
    user_id: &str,
    device_id: &str,
    now: i64,
) -> (String, String) {
    let e = security_epoch(store, user_id);
    let claims = b64url(
        json!({ "u": user_id, "d": device_id, "x": now.div_euclid(1000) + ACCESS_SECONDS, "e": e })
            .to_string()
            .as_bytes(),
    );
    let sig = hmac(&keys.token_secret(store), &format!("cv1.{claims}"));
    (
        format!("cv1.{claims}.{sig}"),
        iso(now + ACCESS_SECONDS * 1000),
    )
}

/// Who a valid access token is for, or nothing.
pub fn verify_access(
    keys: &Keys,
    store: &Store,
    token: Option<&Value>,
    now: i64,
) -> Option<Session> {
    let token = token?.as_str()?;
    if token.encode_utf16().count() > 600 {
        return None;
    }
    // `const [v, claims, sig] = token.split(".")`: anything after a third dot is ignored.
    let mut parts = token.split('.');
    let (v, claims, sig) = (
        parts.next()?,
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
    );
    if v != "cv1" || claims.is_empty() || sig.is_empty() {
        return None;
    }
    if !same_string(
        &hmac(&keys.token_secret(store), &format!("cv1.{claims}")),
        sig,
    ) {
        return None;
    }
    let c: Value = serde_json::from_slice(&from_b64url(claims)?).ok()?;
    let (u, d) = (c["u"].as_str()?, c["d"].as_str()?);
    let x = crate::js::to_number(c.get("x"));
    // `!(c.x * 1000 > now)`: a missing or bad expiry (NaN) fails too.
    if (x * 1000.0).partial_cmp(&(now as f64)) != Some(std::cmp::Ordering::Greater) {
        return None;
    }
    let e = crate::js::to_number(c.get("e"));
    Some(Session {
        user_id: u.into(),
        device_id: d.into(),
        epoch: if e.is_nan() || e == 0.0 { 0 } else { e as i64 },
    })
}

pub fn issue_refresh(store: &Store, user_id: &str, device_id: &str, now: i64) -> String {
    let token = format!("cvr1.{}", random_token(32));
    let _ = store.create("CvRefresh", &json!({ "user_id": user_id, "device_id": device_id, "token_hash": sha256_hex(&token), "expires_at": iso(now + REFRESH_DAYS * 86_400_000) }), None);
    token
}

/// Everything the app keeps after signing in, plus `extra` fields.
pub fn signed_in(
    keys: &Keys,
    store: &Store,
    user_id: &str,
    device_id: &str,
    extra: Value,
) -> Value {
    let now = now_ms();
    let (token, expires) = issue_access(keys, store, user_id, device_id, now);
    let mut out = json!({ "session": { "access_token": token, "access_expires_at": expires, "refresh_token": issue_refresh(store, user_id, device_id, now), "user_id": user_id, "device_id": device_id } });
    for (k, v) in extra.as_object().into_iter().flatten() {
        out[k] = v.clone();
    }
    out
}

/// Whether a session may still change how the account is protected.
pub fn live_session(store: &Store, user_id: &str, session: Option<&Session>) -> bool {
    let Some(s) = session.filter(|s| !s.device_id.is_empty()) else {
        return false;
    };
    match store.get("CvDevice", &s.device_id) {
        Ok(d) if d["user_id"] == user_id => s.epoch == security_epoch(store, user_id),
        _ => false,
    }
}

/// The refresh token's row and device, if it's valid and its device is still connected.
pub fn refresh_row(store: &Store, token: Option<&Value>, now: i64) -> Option<(Value, Value)> {
    let t = token?.as_str()?;
    if !t.starts_with("cvr1.") || t.encode_utf16().count() > 100 {
        return None;
    }
    let row = first(store, "CvRefresh", json!({ "token_hash": sha256_hex(t) }))?;
    let expires = crate::dates::parse(row["expires_at"].as_str().unwrap_or(""));
    if expires.is_some_and(|e| (e as i64) < now) {
        return None;
    }
    let device = store
        .get("CvDevice", row["device_id"].as_str().unwrap_or(""))
        .ok()?;
    (device["user_id"] == row["user_id"]).then_some((row, device))
}

// ---------- people ----------

/// A person's own record: a Person (made with a username) or a User.
pub fn user_record(store: &Store, id: &str) -> Option<Value> {
    if id.is_empty() {
        return None;
    }
    store
        .get("Person", id)
        .ok()
        .or_else(|| store.get("User", id).ok())
}

pub fn update_user_record(store: &Store, id: &str, changes: &Value) -> Option<Value> {
    if store.get("Person", id).is_ok() {
        store.update("Person", id, changes).ok()
    } else {
        store.update("User", id, changes).ok()
    }
}

pub fn user_exists(store: &Store, id: &str) -> bool {
    user_record(store, id).is_some()
}
