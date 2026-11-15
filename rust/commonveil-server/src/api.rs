//! Request handling shared by every backend function, matching base44/shared/http.ts as the
//! self-hosted server runs it: the server has already worked out who is calling.
use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::sessions::Session;

pub struct Limits;
impl Limits {
    pub const MAX_BODY_BYTES: usize = 256 * 1024;
    pub const MAX_DEVICES: usize = 10;
    pub const MAX_PENDING_DEVICES: usize = 3;
    pub const PENDING_DEVICE_MINUTES: i64 = 15;
    pub const PROOF_SKEW_MS: i64 = 5 * 60 * 1000;
    pub const RESETS_PER_DAY: usize = 3;
    pub const RESET_DELAY_HOURS: i64 = 168;
    pub const REGISTRATIONS_PER_DAY: usize = 10;
}

/// An error with the status and code the app shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
}
impl ApiError {
    pub fn new(status: u16, code: &str, message: &str) -> Self {
        Self { status, code: code.into(), message: if message.is_empty() { code.into() } else { message.into() } }
    }
}
impl From<crate::store::StoreError> for ApiError {
    fn from(e: crate::store::StoreError) -> Self {
        // A store failure inside an action is an unexpected one, as in the JavaScript.
        ApiError { status: 500, code: "INTERNAL".into(), message: format!("store: {}", e.message) }
    }
}
pub type Result<T> = std::result::Result<T, ApiError>;

pub fn bad_field(name: &str) -> ApiError {
    ApiError::new(400, "BAD_FIELD", &format!("Invalid {name}."))
}

/// What an action sees.
pub struct Ctx<'a> {
    pub app: &'a crate::App,
    pub user: Option<Value>,
    pub session: Option<Session>,
    pub body: Value,
    pub now: i64,
}
impl Ctx<'_> {
    pub fn store(&self) -> &crate::store::Store {
        &self.app.store
    }
    /// The service role: every row.
    pub fn sr(&self) -> crate::db::Db<'_> {
        crate::db::Db::service(&self.app.store)
    }
    /// The caller's own access, under the entities' row rules.
    pub fn own(&self) -> crate::db::Db<'_> {
        let user = self.user.clone().unwrap_or_else(|| json!({ "id": "", "email": "" }));
        crate::db::Db::person(&self.app.store, crate::person_of(&user))
    }
    /// The caller's id (actions that need a signed-in caller only run with one).
    pub fn user_id(&self) -> &str {
        self.user.as_ref().and_then(|u| u["id"].as_str()).unwrap_or("")
    }
}

pub type Action = fn(&mut Ctx) -> Result<Value>;
pub type Actions = BTreeMap<&'static str, Action>;

pub struct RunOptions {
    pub allow_anonymous: bool,
    pub max_body_bytes: usize,
}
impl Default for RunOptions {
    fn default() -> Self {
        Self { allow_anonymous: false, max_body_bytes: Limits::MAX_BODY_BYTES }
    }
}

/// Run one named action: (status, JSON reply).
pub fn run_action(app: &crate::App, user: Option<Value>, session: Option<Session>, raw: &str, actions: &Actions, options: &RunOptions) -> (u16, Value) {
    let fail = |e: ApiError| (e.status, json!({ "error": e.message, "code": e.code }));
    if raw.encode_utf16().count() > options.max_body_bytes {
        return fail(ApiError::new(413, "TOO_LARGE", "That request is too large."));
    }
    let mut body = json!({});
    if !raw.is_empty() {
        match serde_json::from_str::<Value>(raw) {
            Ok(v) => body = v,
            Err(_) => return fail(ApiError::new(400, "BAD_JSON", "The request wasn't valid JSON.")),
        }
    }
    if !body.is_object() {
        return fail(ApiError::new(400, "BAD_REQUEST", "Invalid request."));
    }
    // A sign-in token in the body isn't how self-hosted callers are known; it's dropped.
    body.as_object_mut().unwrap().remove("_session");
    if user.is_none() && !options.allow_anonymous {
        return fail(ApiError::new(401, "SIGN_IN_REQUIRED", "Please sign in again."));
    }
    let action = body["action"].as_str().unwrap_or("").to_string();
    let Some(f) = actions.get(action.as_str()) else { return fail(ApiError::new(400, "UNKNOWN_ACTION", "Unknown action.")) };
    let mut ctx = Ctx { app, user, session, body, now: crate::sessions::now_ms() };
    match f(&mut ctx) {
        Ok(Value::Null) => (200, json!({ "ok": true })),
        Ok(v) => (200, v),
        Err(e) if e.status == 500 && e.code == "INTERNAL" => {
            // Log a category only: no request bodies, keys or user data.
            eprintln!("commonveil function failure");
            (500, json!({ "error": "Something went wrong. Nothing was changed.", "code": "INTERNAL" }))
        }
        Err(e) => fail(e),
    }
}

// ---------- small validators ----------

fn id_like(s: &str, min: usize) -> bool {
    (min..=64).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

pub fn str_field(v: &Value, name: &str, max: usize, min: usize) -> Result<String> {
    match v.as_str() {
        Some(s) if (min..=max).contains(&s.encode_utf16().count()) => Ok(s.into()),
        _ => Err(bad_field(name)),
    }
}
pub fn id(v: &Value, name: &str) -> Result<String> {
    v.as_str().filter(|s| id_like(s, 1)).map(String::from).ok_or_else(|| bad_field(name))
}
pub fn random_id_field(v: &Value, name: &str) -> Result<String> {
    v.as_str().filter(|s| id_like(s, 16)).map(String::from).ok_or_else(|| bad_field(name))
}
pub fn int(v: &Value, name: &str, min: i64, max: i64) -> Result<i64> {
    let f = v.as_f64().filter(|f| f.fract() == 0.0 && f.is_finite()).ok_or_else(|| bad_field(name))?;
    if f < min as f64 || f > max as f64 { Err(bad_field(name)) } else { Ok(f as i64) }
}

/// Strip control and direction characters, then trim.
pub fn clean_text(v: &Value, max: usize) -> Result<String> {
    let s = match v {
        Value::Null => return Ok(String::new()),
        Value::String(s) => s,
        _ => return Err(ApiError::new(400, "BAD_FIELD", "Invalid text.")),
    };
    let bad = |c: char| matches!(c, '\u{0}'..='\u{8}' | '\u{B}' | '\u{C}' | '\u{E}'..='\u{1F}' | '\u{7F}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}');
    let cleaned: String = s.chars().filter(|c| !bad(*c)).collect();
    let cleaned = crate::js::trim(&cleaned);
    if cleaned.encode_utf16().count() > max {
        return Err(ApiError::new(400, "TOO_LONG", &format!("Please keep it under {max} characters.")));
    }
    Ok(cleaned)
}

/// Platform timestamps look like 2026-10-29T11:37:14.587000 (UTC, no zone)... as `toISOString()`
/// without the Z.
pub fn platform_time(ms: i64) -> String {
    crate::store::iso(ms).trim_end_matches('Z').to_string()
}

/// A list of ids, each checked, duplicates dropped (first kept).
pub fn id_list(v: &Value, name: &str, max: usize) -> Result<Vec<String>> {
    let Some(a) = v.as_array().filter(|a| a.len() <= max) else { return Err(bad_field(name)) };
    let mut out: Vec<String> = Vec::new();
    for x in a {
        let i = id(x, name)?;
        if !out.contains(&i) {
            out.push(i);
        }
    }
    Ok(out)
}

/// `atob`: forgiving base64 (WHATWG), `None` where it would throw.
pub fn atob(s: &str) -> Option<Vec<u8>> {
    let mut t: Vec<u8> = s.bytes().filter(|c| !matches!(c, b' ' | b'\t' | b'\n' | b'\x0c' | b'\r')).collect();
    if t.len().is_multiple_of(4) {
        for _ in 0..2 {
            if t.last() == Some(&b'=') {
                t.pop();
            }
        }
    }
    if t.len() % 4 == 1 {
        return None;
    }
    let mut bits: u32 = 0;
    let (mut n, mut out) = (0, Vec::new());
    for c in t {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;
        bits = (bits << 6) | v;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
            bits &= (1 << n) - 1;
        }
    }
    Some(out)
}
