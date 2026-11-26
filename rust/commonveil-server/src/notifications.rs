//! Push notifications that give nothing away (base44/shared/handlers/notifications.ts).
//!
//! A push says only that there's something new: its kind, and a random one-time code that the
//! app, signed in as the same person, swaps for where to go. A mute key lets a device stay
//! silent for conversations muted on it, without the push naming the conversation.
//!
//! Server channels: each browser says which servers it wants pushes from (`alerts`), per server
//! and never per channel, so a busy server only pushes to the browsers that asked for it. The
//! browser still applies its own channel settings to what arrives.
use serde_json::{json, Value};

use crate::api::{id, Actions, ApiError, Ctx, Result};
use crate::crypto::{hmac, random_token, sha256_hex};
use crate::db::{id_of, Db};
use crate::js::{to_js_string, truthy};
use crate::shared::{iso, platform_ms};

const MAX_SUBSCRIPTIONS: usize = 10;
const CODE_DAYS: i64 = 7;
const QUIET_MS: f64 = 20_000.0;
const MAX_PER_SEND: usize = 200;
/// Both alert lists together: more servers than anyone can be in (serversPerUser).
const MAX_ALERT_SERVERS: usize = 200;

fn b64url_ok(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// The site's push key: made the first time, then kept.
pub fn push_keys(sr: &Db) -> Result<Value> {
    let parse =
        |row: &Value| serde_json::from_str::<Value>(row["value"].as_str().unwrap_or("")).ok();
    if let Some(v) = sr
        .first("CvSecret", json!({ "name": "push-vapid" }), "created_date")?
        .as_ref()
        .filter(|r| truthy(r.get("value")))
        .and_then(parse)
    {
        return Ok(v);
    }
    sr.create(
        "CvSecret",
        json!({ "name": "push-vapid", "value": crate::webpush::make_vapid_keys().to_string() }),
    )?;
    let first = sr.first("CvSecret", json!({ "name": "push-vapid" }), "created_date")?;
    first.as_ref().and_then(parse).ok_or_else(|| ApiError {
        status: 500,
        code: "INTERNAL".into(),
        message: "push key".into(),
    })
}

/// What a device needs to stay quiet about a place it's muted, without being told the place.
pub fn mute_key(secret: &str, place_id: &str) -> String {
    hmac(secret, &format!("mute:{place_id}"))
        .chars()
        .take(16)
        .collect()
}

pub fn conversation_path(conversation_id: &str) -> String {
    format!("/app/c/{conversation_id}")
}

/// Tell these people's devices there's something new. Never fails: notifications are a nicety.
pub fn notify_people(
    sr: &Db,
    subject: &str,
    user_ids: &[String],
    kind: &str,
    path: &str,
    place_id: &str,
) {
    send_quietly(sr, subject, user_ids, kind, path, place_id, None);
}

/// The same for a server channel ("activity" or "mention"): only to browsers that asked for this
/// server's pushes of that kind (`alerts`). `server`: its id, and whether it's the default one.
pub fn notify_server_people(
    sr: &Db,
    subject: &str,
    user_ids: &[String],
    kind: &str,
    path: &str,
    place_id: &str,
    server: (&str, bool),
) {
    send_quietly(sr, subject, user_ids, kind, path, place_id, Some(server));
}

fn send_quietly(
    sr: &Db,
    subject: &str,
    user_ids: &[String],
    kind: &str,
    path: &str,
    place_id: &str,
    server: Option<(&str, bool)>,
) {
    if notify(
        sr,
        subject,
        user_ids,
        NotifyRequest {
            kind,
            path,
            place_id,
            only_endpoint: None,
            bypass_quiet: false,
            server,
        },
    )
    .is_err()
    {
        eprintln!("commonveil push: preparation_failed kind={kind}");
    }
}

/// Whether this browser asked for this server's pushes of this kind (`alerts`). A browser that
/// hasn't said yet (an app from before 0.24.23) gets mentions, and other activity only from servers
/// other than the site's default one: the app's own defaults.
pub fn wants_server_push(sub: &Value, kind: &str, server_id: &str, is_default: bool) -> bool {
    if sub["alerts_set"] != true {
        return kind == "mention" || !is_default;
    }
    let listed = |field: &str| {
        sub[field]
            .as_array()
            .is_some_and(|ids| ids.iter().any(|v| v == server_id))
    };
    listed("alert_all") || (kind == "mention" && listed("alert_mentions"))
}

/// Return only safe aggregate outcomes: no endpoints, identifiers, keys or payloads in diagnostics.
struct NotifyRequest<'a> {
    kind: &'a str,
    path: &'a str,
    place_id: &'a str,
    only_endpoint: Option<&'a str>,
    bypass_quiet: bool,
    server: Option<(&'a str, bool)>,
}

fn notify(sr: &Db, subject: &str, user_ids: &[String], req: NotifyRequest<'_>) -> Result<Value> {
    let NotifyRequest {
        kind,
        path,
        place_id,
        only_endpoint,
        bypass_quiet,
        server,
    } = req;
    let mut tally =
        json!({ "attempted": 0, "sent": 0, "rejected": 0, "failed": 0, "gone": 0, "skipped": 0 });
    let mut people: Vec<String> = Vec::new();
    for u in user_ids {
        if !people.contains(u) {
            people.push(u.clone());
        }
    }
    people.truncate(MAX_PER_SEND);
    if people.is_empty() {
        return Ok(tally);
    }
    let subs = sr.filter(
        "PushSubscription",
        json!({ "user_id": { "$in": people } }),
        "created_date",
        MAX_PER_SEND * 2,
    )?;
    let now = crate::sessions::now_ms();
    let scoped: Vec<Value> = subs
        .into_iter()
        .filter(|s| server.is_none_or(|(sid, default)| wants_server_push(s, kind, sid, default)))
        .filter(|s| only_endpoint.is_none_or(|e| s["endpoint"] == e))
        .collect();
    if only_endpoint.is_some() && scoped.is_empty() {
        tally["failure_reason"] = json!("no_subscription");
    }
    let due: Vec<Value> = scoped
        .iter()
        .filter(|s| {
            bypass_quiet
                || !truthy(s.get("last_push_at"))
                || now as f64 - platform_ms(&s["last_push_at"]) > QUIET_MS
        })
        .cloned()
        .collect();
    tally["skipped"] = json!(scoped.len() - due.len());
    if scoped.len() != due.len() {
        eprintln!(
            "commonveil push: rate_limited kind={kind} count={}",
            scoped.len() - due.len()
        );
    }
    if due.is_empty() {
        return Ok(tally);
    }
    let keys = push_keys(sr)?;
    let mut codes: Vec<(String, String)> = Vec::new();
    for s in &due {
        let user = to_js_string(s.get("user_id"));
        if codes.iter().any(|(u, _)| *u == user) {
            continue;
        }
        let code = random_token(18);
        sr.create("PushCode", json!({ "user_id": user, "code_hash": sha256_hex(&code), "path": path, "expires_at": iso(now + CODE_DAYS * 86_400_000) }))?;
        codes.push((user, code));
    }
    let urgency = if kind == "message" || kind == "conversation" || kind == "mention" {
        "high"
    } else {
        "normal"
    };
    for s in &due {
        tally["attempted"] = json!(tally["attempted"].as_u64().unwrap_or(0) + 1);
        let user = to_js_string(s.get("user_id"));
        let code = codes
            .iter()
            .find(|(u, _)| *u == user)
            .map(|(_, c)| c.clone());
        let mute = if truthy(s.get("mute_secret")) {
            mute_key(&to_js_string(s.get("mute_secret")), place_id)
        } else {
            String::new()
        };
        let payload = json!({ "v": 1, "k": kind, "c": code, "m": mute });
        let text = |k: &str| to_js_string(s.get(k));
        let result = crate::webpush::send_push(
            &text("endpoint"),
            &text("p256dh"),
            &text("auth"),
            &payload,
            &keys,
            subject,
            urgency,
        );
        let increment = |tally: &mut Value, field: &str| {
            tally[field] = json!(tally[field].as_u64().unwrap_or(0) + 1);
        };
        match result {
            crate::webpush::Sent::Unsendable => {
                increment(&mut tally, "failed");
                if only_endpoint.is_some() {
                    tally["failure_reason"] = json!("keys");
                }
                eprintln!("commonveil push: delivery kind={kind} outcome=failed reason=keys");
            }
            crate::webpush::Sent::Gone(code) => {
                increment(&mut tally, "gone");
                if only_endpoint.is_some() {
                    tally["failure_reason"] = json!("expired");
                }
                if code > 0 && only_endpoint.is_some() {
                    tally["status_code"] = json!(code);
                }
                eprintln!("commonveil push: delivery kind={kind} outcome=gone status={code}");
                let _ = sr.delete("PushSubscription", id_of(s));
            }
            crate::webpush::Sent::Sent(code) => {
                increment(&mut tally, "sent");
                if only_endpoint.is_some() {
                    tally["status_code"] = json!(code);
                }
                eprintln!("commonveil push: delivery kind={kind} outcome=sent status={code}");
                let _ = sr.update(
                    "PushSubscription",
                    id_of(s),
                    json!({ "last_push_at": iso(crate::sessions::now_ms()) }),
                );
            }
            crate::webpush::Sent::Rejected(code) => {
                increment(&mut tally, "rejected");
                if only_endpoint.is_some() {
                    tally["failure_reason"] = json!("http_rejected");
                }
                if only_endpoint.is_some() {
                    tally["status_code"] = json!(code);
                }
                eprintln!("commonveil push: delivery kind={kind} outcome=rejected status={code}");
            }
            crate::webpush::Sent::Failed => {
                increment(&mut tally, "failed");
                if only_endpoint.is_some() {
                    tally["failure_reason"] = json!("network");
                }
                eprintln!("commonveil push: delivery kind={kind} outcome=failed reason=network");
            }
        }
    }
    Ok(tally)
}

/// The subject pushes are sent under: this site.
pub fn subject(ctx: &Ctx) -> String {
    ctx.app.config.site_url.clone()
}

fn key(ctx: &mut Ctx) -> Result<Value> {
    Ok(json!({ "public_key": push_keys(&ctx.sr())?["publicKey"] }))
}

fn subscribe(ctx: &mut Ctx) -> Result<Value> {
    let (sr, uid, body) = (ctx.sr(), ctx.user_id().to_string(), &ctx.body);
    if !crate::webpush::endpoint_ok(&body["endpoint"]) {
        return Err(ApiError::new(
            400,
            "BAD_ENDPOINT",
            "That isn't a browser push address.",
        ));
    }
    for k in ["p256dh", "auth", "mute_secret"] {
        if !body[k]
            .as_str()
            .is_some_and(|v| b64url_ok(v) && v.len() <= 200)
        {
            return Err(ApiError::new(
                400,
                "BAD_KEYS",
                "That subscription is incomplete.",
            ));
        }
    }
    // An address belongs to one browser: drop any older claim to it. The app says it again when the
    // settings are opened (a turn-on can be interrupted), so an identical record is left as it is.
    let claimed = sr.filter(
        "PushSubscription",
        json!({ "endpoint": body["endpoint"] }),
        "created_date",
        20,
    )?;
    let mine_now = |s: &Value| s["user_id"] == uid.as_str();
    if claimed.iter().any(|s| {
        mine_now(s)
            && s["p256dh"] == body["p256dh"]
            && s["auth"] == body["auth"]
            && s["mute_secret"] == body["mute_secret"]
    }) {
        return Ok(json!({ "ok": true }));
    }
    // New keys for the same browser and person keep the servers it asked for.
    let choice = claimed
        .iter()
        .find(|s| mine_now(s) && s["alerts_set"] == true)
        .map(|s| {
            let list = |k: &str| s[k].as_array().cloned().unwrap_or_default();
            json!({ "alerts_set": true, "alert_all": list("alert_all"), "alert_mentions": list("alert_mentions") })
        });
    for old in &claimed {
        let _ = sr.delete("PushSubscription", id_of(old));
    }
    let mine = sr.filter(
        "PushSubscription",
        json!({ "user_id": uid }),
        "created_date",
        MAX_SUBSCRIPTIONS + 5,
    )?;
    for old in mine
        .iter()
        .take((mine.len() + 1).saturating_sub(MAX_SUBSCRIPTIONS))
    {
        let _ = sr.delete("PushSubscription", id_of(old));
    }
    let device = ctx
        .session
        .as_ref()
        .map(|s| s.device_id.clone())
        .unwrap_or_default();
    let mut row = json!({ "user_id": uid, "device_id": device, "endpoint": body["endpoint"], "p256dh": body["p256dh"], "auth": body["auth"], "mute_secret": body["mute_secret"], "last_push_at": "" });
    if let (Some(row), Some(Value::Object(choice))) = (row.as_object_mut(), choice) {
        row.extend(choice);
    }
    sr.create("PushSubscription", row)?;
    Ok(json!({ "ok": true }))
}

/// Which servers this browser wants pushes from: `all`, every new message or post; `mentions`,
/// only when it's mentioned; a server in neither list pushes it nothing. Per server, never per
/// channel: the app works the lists out from its own settings, and the browser still applies its
/// channel settings to what arrives.
fn alerts(ctx: &mut Ctx) -> Result<Value> {
    let (sr, uid, body) = (ctx.sr(), ctx.user_id().to_string(), &ctx.body);
    if !crate::webpush::endpoint_ok(&body["endpoint"]) {
        return Err(ApiError::new(
            400,
            "BAD_ENDPOINT",
            "This browser has no valid push subscription.",
        ));
    }
    let bad_list = || ApiError::new(400, "BAD_FIELD", "Invalid server list.");
    let list = |v: &Value| -> Result<Vec<String>> {
        let items = v
            .as_array()
            .filter(|a| a.len() <= MAX_ALERT_SERVERS)
            .ok_or_else(bad_list)?;
        let mut out: Vec<String> = Vec::new();
        for item in items {
            let sid = id(item, "server")?;
            if !out.contains(&sid) {
                out.push(sid);
            }
        }
        Ok(out)
    };
    let all = list(&body["all"])?;
    let mentions: Vec<String> = list(&body["mentions"])?
        .into_iter()
        .filter(|s| !all.contains(s))
        .collect();
    if all.len() + mentions.len() > MAX_ALERT_SERVERS {
        return Err(bad_list());
    }
    let Some(sub) = sr.first(
        "PushSubscription",
        json!({ "endpoint": body["endpoint"], "user_id": uid }),
        "created_date",
    )?
    else {
        return Err(ApiError::new(
            409,
            "PUSH_NOT_REGISTERED",
            "This browser's subscription isn't registered. Turn push off and on here.",
        ));
    };
    sr.update(
        "PushSubscription",
        id_of(&sub),
        json!({ "alerts_set": true, "alert_all": all, "alert_mentions": mentions }),
    )?;
    Ok(json!({ "ok": true }))
}

fn unsubscribe(ctx: &mut Ctx) -> Result<Value> {
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    for s in sr.filter(
        "PushSubscription",
        json!({ "user_id": uid }),
        "created_date",
        50,
    )? {
        if !truthy(ctx.body.get("endpoint")) || s["endpoint"] == ctx.body["endpoint"] {
            let _ = sr.delete("PushSubscription", id_of(&s));
        }
    }
    Ok(json!({ "ok": true }))
}

fn open(ctx: &mut Ctx) -> Result<Value> {
    let Some(code) = ctx.body["code"]
        .as_str()
        .filter(|c| b64url_ok(c) && c.len() <= 60)
    else {
        return Err(ApiError::new(
            400,
            "BAD_CODE",
            "That notification has expired.",
        ));
    };
    let sr = ctx.sr();
    let row = sr.first(
        "PushCode",
        json!({ "code_hash": sha256_hex(code) }),
        "created_date",
    )?;
    let Some(row) = row.filter(|r| {
        r["user_id"] == ctx.user_id()
            && platform_ms(&r["expires_at"]).partial_cmp(&(crate::sessions::now_ms() as f64))
                != Some(std::cmp::Ordering::Less)
    }) else {
        return Ok(json!({ "path": "/app" }));
    };
    let _ = sr.delete("PushCode", id_of(&row));
    Ok(json!({ "path": row["path"].as_str().filter(|p| p.starts_with("/app")).unwrap_or("/app") }))
}

fn test(ctx: &mut Ctx) -> Result<Value> {
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    let endpoint = ctx.body["endpoint"]
        .as_str()
        .filter(|e| crate::webpush::endpoint_ok(&json!(e)))
        .ok_or_else(|| {
            ApiError::new(
                400,
                "BAD_ENDPOINT",
                "This browser has no valid push subscription.",
            )
        })?;
    let subs = sr.filter(
        "PushSubscription",
        json!({ "user_id": uid }),
        "created_date",
        MAX_SUBSCRIPTIONS + 5,
    )?;
    if !subs.iter().any(|s| s["endpoint"] == endpoint) {
        return Err(ApiError::new(
            409,
            "PUSH_NOT_REGISTERED",
            "This browser's subscription isn't registered. Turn push off and on here.",
        ));
    }
    let tally = notify(
        &sr,
        &subject(ctx),
        &[uid],
        NotifyRequest {
            kind: "test",
            path: "/app/settings/notifications",
            place_id: "test",
            only_endpoint: Some(endpoint),
            bypass_quiet: true,
            server: None,
        },
    )?;
    let mut response = tally;
    response["ok"] = json!(true);
    Ok(response)
}

pub fn actions() -> Actions {
    let mut a = Actions::new();
    for (name, f) in [
        ("key", key as crate::api::Action),
        ("subscribe", subscribe),
        ("alerts", alerts),
        ("unsubscribe", unsubscribe),
        ("open", open),
        ("test", test),
    ] {
        a.insert(name, f);
    }
    a
}

/// `id(...)` checked, for paths built from ids.
pub fn checked_path(conversation_id: &Value) -> Result<String> {
    Ok(conversation_path(&id(conversation_id, "conversation")?))
}

#[cfg(test)]
mod tests {
    use super::wants_server_push;
    use serde_json::json;

    #[test]
    fn a_browser_gets_only_the_server_pushes_it_asked_for() {
        let chose =
            json!({ "alerts_set": true, "alert_all": ["busy"], "alert_mentions": ["quiet"] });
        assert!(wants_server_push(&chose, "activity", "busy", false));
        assert!(wants_server_push(&chose, "mention", "busy", false));
        assert!(!wants_server_push(&chose, "activity", "quiet", false));
        assert!(wants_server_push(&chose, "mention", "quiet", false));
        assert!(!wants_server_push(&chose, "mention", "muted", false));
        assert!(!wants_server_push(&chose, "activity", "muted", true));
        // Not said yet: mentions everywhere, other activity except from the default server.
        let older = json!({});
        assert!(wants_server_push(&older, "mention", "agora", true));
        assert!(!wants_server_push(&older, "activity", "agora", true));
        assert!(wants_server_push(&older, "activity", "club", false));
        // Said, with nothing chosen: nothing at all.
        let none = json!({ "alerts_set": true, "alert_all": [], "alert_mentions": [] });
        assert!(!wants_server_push(&none, "mention", "club", false));
    }
}
