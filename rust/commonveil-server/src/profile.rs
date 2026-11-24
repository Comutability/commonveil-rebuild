//! Usernames and profiles (base44/shared/handlers/profile.ts). There is no member directory: you
//! can look someone up only by their exact username, and see profiles of people you share a
//! conversation or a server with, as far as each person chose to show them.
use std::collections::HashSet;

use serde_json::{json, Value};

use crate::api::{atob, clean_text, id_list, Actions, ApiError, Ctx, Limits, Result};
use crate::db::{id_of, merged, Db};
use crate::js::{to_js_string, to_number, truthy};
use crate::shared::{
    account_keys_of, blocked_either_way, contacts_of, day_of, profile_for, profile_of,
    public_profile, server_peers_of, with_row, AUTO_DELETE_DAYS,
};

/// How long one call may spend deleting before it returns and asks to be called again.
const DELETION_BUDGET_MS: i64 = 45_000;
pub const ACCENT_COLORS: [&str; 9] = [
    "", "teal", "sky", "indigo", "violet", "rose", "amber", "lime", "slate",
];
const RESERVED: [&str; 25] = [
    "admin",
    "administrator",
    "root",
    "system",
    "support",
    "help",
    "staff",
    "moderator",
    "mod",
    "mods",
    "commonveil",
    "security",
    "official",
    "team",
    "null",
    "undefined",
    "anonymous",
    "everyone",
    "here",
    "abuse",
    "postmaster",
    "webmaster",
    "info",
    "noreply",
    "no_reply",
];
const AVATAR_MAX_CHARS: usize = 18_000;

fn deny(status: u16, code: &str, message: &str) -> ApiError {
    ApiError::new(status, code, message)
}
fn len16(s: &str) -> usize {
    s.encode_utf16().count()
}
fn days_of(p: &Value) -> f64 {
    let n = to_number(p.get("delete_after_days"));
    if n.is_nan() {
        0.0
    } else {
        n
    }
}

fn auto_delete_out(p: &Value) -> Value {
    let days = days_of(p);
    let on = days != 0.0;
    json!({
        "days": crate::js::number_value(days),
        "last_active_on": if on && truthy(p.get("last_active_at")) { p["last_active_at"].clone() } else { Value::Null },
        "warned": on && truthy(p.get("inactive_warned_at")),
    })
}

/// Your own privacy choices, as you set them.
fn privacy_out(p: &Value) -> Value {
    json!({
        "profile_visibility": crate::shared::or(&p["profile_visibility"], json!("shared")),
        "dm_policy": crate::shared::or(&p["dm_policy"], json!("anyone")),
        "default_listed": truthy(p.get("default_listed")),
    })
}

fn normalise_username(v: &Value) -> Result<(String, String)> {
    let ok = |s: &str| {
        (3..=20).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
    };
    match v.as_str().map(crate::js::trim) {
        Some(u) if ok(&u) => {
            let key = u.to_lowercase();
            Ok((u, key))
        }
        _ => Err(deny(
            400,
            "BAD_USERNAME",
            "Usernames are 3-20 characters: letters, numbers and underscores.",
        )),
    }
}

/// Count rows up to a cap.
fn count_up_to(db: &Db, entity: &str, query: Value, cap: usize) -> Result<Value> {
    let rows = db.filter(entity, query, "-created_date", cap + 1)?;
    let n = rows.len().min(cap);
    Ok(
        json!({ "count": n, "more": rows.len() > cap, "oldest": if rows.is_empty() { Value::Null } else { rows[n - 1]["created_date"].clone() } }),
    )
}

fn avatar_image(v: &Value) -> Result<String> {
    if v.is_null() || *v == "" {
        return Ok(String::new());
    }
    let too_big = || {
        deny(
            400,
            "BAD_FIELD",
            "That picture is too large or isn't an image. Try a smaller one.",
        )
    };
    let unreadable = || deny(400, "BAD_FIELD", "That picture couldn't be read.");
    let s = v
        .as_str()
        .filter(|s| len16(s) <= AVATAR_MAX_CHARS)
        .ok_or_else(too_big)?;
    let re =
        regex::Regex::new(r"^data:image/(webp|png|jpeg);base64,([A-Za-z0-9+/]+={0,2})$").unwrap();
    let m = re.captures(s).ok_or_else(too_big)?;
    let data = &m[2];
    let b = atob(&data[..data.len().min(32)]).ok_or_else(unreadable)?;
    let at = |i: usize| b.get(i).copied();
    let ok = match &m[1] {
        "webp" => {
            [0x52, 0x49, 0x46, 0x46]
                .iter()
                .enumerate()
                .all(|(i, x)| at(i) == Some(*x))
                && [0x57, 0x45, 0x42, 0x50]
                    .iter()
                    .enumerate()
                    .all(|(i, x)| at(8 + i) == Some(*x))
        }
        "png" => [0x89, 0x50, 0x4e, 0x47]
            .iter()
            .enumerate()
            .all(|(i, x)| at(i) == Some(*x)),
        _ => [0xff, 0xd8, 0xff]
            .iter()
            .enumerate()
            .all(|(i, x)| at(i) == Some(*x)),
    };
    if !ok {
        return Err(unreadable());
    }
    Ok(s.to_string())
}

fn day_of_value(v: &Value) -> Value {
    if truthy(Some(v)) {
        json!(to_js_string(Some(v)).chars().take(10).collect::<String>())
    } else {
        Value::Null
    }
}

fn privacy_report(ctx: &mut Ctx) -> Result<Value> {
    let (sr, own, uid) = (ctx.sr(), ctx.own(), ctx.user_id().to_string());
    let user = ctx.user.clone().unwrap_or(Value::Null);
    let profile = profile_of(&own, &uid)?;
    let devices = own.filter("Device", json!({ "user_id": uid }), "created_date", 50)?;
    let convs = own.filter(
        "Conversation",
        json!({ "member_ids": uid }),
        "created_date",
        500,
    )?;
    let memberships = own.filter(
        "ServerMember",
        json!({ "user_id": uid }),
        "created_date",
        200,
    )?;
    let sent = count_up_to(&own, "Message", json!({ "sender_id": uid }), 1000)?;
    let files = count_up_to(&sr, "Attachment", json!({ "owner_id": uid }), 1000)?;
    let scheduled = count_up_to(&sr, "ScheduledMessage", json!({ "sender_id": uid }), 100)?;
    let server_reports = count_up_to(&sr, "ServerReport", json!({ "reporter_id": uid }), 200)?;
    let team_reports = count_up_to(&sr, "Report", json!({ "reporter_id": uid }), 200)?;
    let blocks = count_up_to(&sr, "Block", json!({ "user_id": uid }), 500)?;
    let email: Vec<u16> = if truthy(user.get("email")) {
        to_js_string(user.get("email")).encode_utf16().collect()
    } else {
        vec![]
    };
    let at = email.iter().position(|&c| c == b'@' as u16);
    let hint = match at {
        Some(at) if at > 1 => format!(
            "{}{}{}",
            String::from_utf16_lossy(&email[..1]),
            "•".repeat((at - 1).min(6)),
            String::from_utf16_lossy(&email[at..])
        ),
        _ => String::new(),
    };
    let p = profile.clone().unwrap_or(Value::Null);
    let mut people: HashSet<String> = HashSet::new();
    for c in &convs {
        for m in c["member_ids"].as_array().into_iter().flatten() {
            if *m != uid.as_str() {
                people.insert(m.to_string());
            }
        }
    }
    let count = |f: &dyn Fn(&Value) -> bool| convs.iter().filter(|c| f(c)).count();
    Ok(json!({
        "account": {
            "created": crate::shared::or(&user["created_date"], Value::Null),
            "email_hint": hint,
            "username": crate::shared::or(&p["username"], json!("")),
            "shared_profile": { "display_name": truthy(p.get("display_name")), "bio": truthy(p.get("bio")), "pronouns": truthy(p.get("pronouns")), "avatar": truthy(p.get("avatar_emoji")), "picture": truthy(p.get("avatar_image")) },
            "profile_visibility": crate::shared::or(&p["profile_visibility"], json!("shared")),
            "dm_policy": crate::shared::or(&p["dm_policy"], json!("anyone")),
            "auto_delete_days": crate::js::number_value(days_of(&p)),
            "last_active_day": day_of_value(&p["last_active_at"]),
        },
        "devices": devices.iter().map(|d| json!({
            "label": crate::shared::or(&d["label"], json!("")),
            "status": d["status"],
            "added": crate::shared::or(&d["approved_at"], d["created_date"].clone()),
            "last_seen_day": day_of_value(&d["last_seen_at"]),
        })).collect::<Vec<_>>(),
        "conversations": {
            "direct": count(&|c| c["kind"] == "dm"),
            "groups": count(&|c| c["kind"] == "group" && !truthy(c.get("server_id"))),
            "tickets": count(&|c| truthy(c.get("server_id"))),
            "people": people.len(),
            "disappearing": count(&|c| to_number(c.get("expire_seconds")) > 0.0),
            "self_destructing": count(&|c| truthy(c.get("destroy_at"))),
        },
        "servers": { "count": memberships.len(), "listed": memberships.iter().filter(|m| truthy(m.get("listed"))).count() },
        "stored": { "messages_sent": sent, "files_uploaded": files, "scheduled": scheduled, "reports_to_moderators": server_reports, "reports_to_commonveil": team_reports, "blocks": blocks },
    }))
}

fn me(ctx: &mut Ctx) -> Result<Value> {
    let (sr, own, uid) = (ctx.sr(), ctx.own(), ctx.user_id().to_string());
    let mut profile = profile_of(&own, &uid)?;
    let keys = account_keys_of(&own, &uid)?;
    let today = day_of(ctx.now);
    if let Some(p) = profile.as_mut() {
        if days_of(p) > 0.0
            && (p["last_active_at"] != today.as_str() || truthy(p.get("inactive_warned_at")))
        {
            sr.update(
                "Profile",
                id_of(p),
                json!({ "last_active_at": today, "inactive_warned_at": "" }),
            )?;
            p["last_active_at"] = json!(today);
            p["inactive_warned_at"] = json!("");
        }
    }
    let role = ctx
        .user
        .as_ref()
        .map(|u| u["role"].clone())
        .unwrap_or(Value::Null);
    Ok(json!({
        "user": { "id": uid, "role": if role == "admin" { "admin" } else { "user" } },
        "profile": profile.as_ref().map(public_profile),
        "privacy": profile.as_ref().map(privacy_out),
        "encryption_ready": !keys.is_empty(),
        "auto_delete": profile.as_ref().map(auto_delete_out),
    }))
}

fn is_staff(ctx: &Ctx) -> bool {
    ctx.user.as_ref().is_some_and(|u| u["role"] == "admin")
}

fn set_auto_delete(ctx: &mut Ctx) -> Result<Value> {
    if is_staff(ctx) {
        return Err(deny(
            403,
            "STAFF_ACCOUNT",
            "Staff accounts can't be set to delete themselves.",
        ));
    }
    let (_, data) =
        crate::verify::signed_by_active_device(ctx, "set_auto_delete", Limits::MAX_BODY_BYTES)?;
    let days = data
        .get("days")
        .and_then(Value::as_f64)
        .filter(|d| AUTO_DELETE_DAYS.iter().any(|x| *x as f64 == *d));
    let Some(days) = days else {
        return Err(deny(400, "BAD_FIELD", "Choose one of the offered periods."));
    };
    let (sr, own, uid) = (ctx.sr(), ctx.own(), ctx.user_id().to_string());
    let profile = profile_of(&own, &uid)?
        .ok_or_else(|| deny(409, "PROFILE_REQUIRED", "Choose a username first."))?;
    let fields = if days != 0.0 {
        json!({ "delete_after_days": days as i64, "last_active_at": day_of(ctx.now), "inactive_warned_at": "" })
    } else {
        json!({ "delete_after_days": 0, "last_active_at": "", "inactive_warned_at": "" })
    };
    let updated = sr.update("Profile", id_of(&profile), fields.clone())?;
    Ok(json!({ "auto_delete": auto_delete_out(&merged(&merged(&profile, &fields), &updated)) }))
}

fn claim_username(ctx: &mut Ctx) -> Result<Value> {
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    let (username, key) = normalise_username(&ctx.body["username"])?;
    if RESERVED.contains(&key.as_str()) || crate::deletion::is_retired_username(&sr, &key)? {
        return Err(deny(
            409,
            "USERNAME_TAKEN",
            "That username isn't available.",
        ));
    }
    let display = clean_text(&ctx.body["display_name"], 50)?;
    let display_name = if display.is_empty() {
        username.clone()
    } else {
        display
    };
    if profile_of(&sr, &uid)?.is_some() {
        return Err(deny(409, "ALREADY_CLAIMED", "You already have a username."));
    }
    if !sr
        .filter("Profile", json!({ "username_key": key }), "created_date", 1)?
        .is_empty()
    {
        return Err(deny(409, "USERNAME_TAKEN", "That username is taken."));
    }
    let created = sr.create("Profile", json!({ "user_id": uid, "username": username, "username_key": key, "display_name": display_name, "bio": "" }))?;
    let same_name = with_row(
        sr.filter(
            "Profile",
            json!({ "username_key": key }),
            "created_date",
            10,
        )?,
        &created,
    );
    let mine = with_row(
        sr.filter("Profile", json!({ "user_id": uid }), "created_date", 10)?,
        &created,
    );
    if same_name[0]["id"] != created["id"] || mine[0]["id"] != created["id"] {
        sr.delete("Profile", id_of(&created))?;
        if mine[0]["id"] != created["id"] {
            return Err(deny(409, "ALREADY_CLAIMED", "You already have a username."));
        }
        return Err(deny(409, "USERNAME_TAKEN", "That username is taken."));
    }
    Ok(json!({ "profile": public_profile(&created) }))
}

fn update(ctx: &mut Ctx) -> Result<Value> {
    let (sr, uid, body) = (ctx.sr(), ctx.user_id().to_string(), &ctx.body);
    let profile = profile_of(&sr, &uid)?
        .ok_or_else(|| deny(409, "PROFILE_REQUIRED", "Choose a username first."))?;
    let mut changes = serde_json::Map::new();
    let given = |k: &str| body.get(k).is_some();
    let invalid = || deny(400, "BAD_FIELD", "Invalid choice.");
    if given("display_name") {
        let d = clean_text(&body["display_name"], 50)?;
        changes.insert(
            "display_name".into(),
            if d.is_empty() {
                profile["username"].clone()
            } else {
                json!(d)
            },
        );
    }
    if given("bio") {
        changes.insert("bio".into(), json!(clean_text(&body["bio"], 280)?));
    }
    if given("pronouns") {
        changes.insert("pronouns".into(), json!(clean_text(&body["pronouns"], 30)?));
    }
    if given("accent_color") {
        if !body["accent_color"]
            .as_str()
            .is_some_and(|c| ACCENT_COLORS.contains(&c))
        {
            return Err(deny(400, "BAD_FIELD", "Choose one of the offered colours."));
        }
        changes.insert("accent_color".into(), body["accent_color"].clone());
    }
    if given("avatar_emoji") {
        let emoji = body["avatar_emoji"]
            .as_str()
            .map(crate::js::trim)
            .unwrap_or_default();
        let re = regex::Regex::new(r"^\p{Extended_Pictographic}(\x{200d}\p{Extended_Pictographic}|\x{fe0f}|[\x{1f3fb}-\x{1f3ff}])*$").unwrap();
        if !emoji.is_empty() && (len16(&emoji) > 16 || !re.is_match(&emoji)) {
            return Err(deny(400, "BAD_FIELD", "Choose a single emoji."));
        }
        changes.insert("avatar_emoji".into(), json!(emoji));
    }
    if given("avatar_image") {
        changes.insert(
            "avatar_image".into(),
            json!(avatar_image(&body["avatar_image"])?),
        );
    }
    if given("profile_visibility") {
        if !body["profile_visibility"]
            .as_str()
            .is_some_and(|v| ["shared", "conversations", "nobody"].contains(&v))
        {
            return Err(invalid());
        }
        changes.insert(
            "profile_visibility".into(),
            body["profile_visibility"].clone(),
        );
    }
    if given("dm_policy") {
        if !body["dm_policy"]
            .as_str()
            .is_some_and(|v| ["anyone", "servers", "nobody"].contains(&v))
        {
            return Err(invalid());
        }
        changes.insert("dm_policy".into(), body["dm_policy"].clone());
    }
    if given("default_listed") {
        if !body["default_listed"].is_boolean() {
            return Err(invalid());
        }
        changes.insert("default_listed".into(), body["default_listed"].clone());
    }
    let changes = Value::Object(changes);
    let updated = if changes.as_object().is_some_and(|c| !c.is_empty()) {
        sr.update("Profile", id_of(&profile), changes.clone())?
    } else {
        profile.clone()
    };
    let m = merged(&merged(&profile, &updated), &changes);
    Ok(json!({ "profile": public_profile(&m), "privacy": privacy_out(&m) }))
}

fn find(ctx: &mut Ctx) -> Result<Value> {
    let (sr, own, uid) = (ctx.sr(), ctx.own(), ctx.user_id().to_string());
    let raw = ctx.body["username"]
        .as_str()
        .map(crate::js::trim)
        .unwrap_or_default();
    let raw = raw.strip_prefix('@').unwrap_or(&raw).to_lowercase();
    let fed = crate::conversations::federation_of(ctx);
    let key = match fed {
        // Someone on another site, found through their site (which checks they accept contact).
        Some(fed) if crate::federation::handle_ok(&raw) => {
            if fed.resolve_for_handler(&raw, &uid)?.is_none() {
                return Err(deny(
                    404,
                    "NOT_FOUND",
                    "Nobody can be reached at that address.",
                ));
            }
            raw
        }
        _ => normalise_username(&ctx.body["username"])?.1,
    };
    let target = sr.first("Profile", json!({ "username_key": key }), "created_date")?;
    let blocked = match &target {
        Some(t) if t["user_id"] != uid.as_str() => {
            blocked_either_way(&sr, &uid, &to_js_string(t.get("user_id")))?
        }
        _ => false,
    };
    let Some(target) = target.filter(|_| !blocked) else {
        return Err(deny(404, "NOT_FOUND", "No member has that username."));
    };
    let tid = to_js_string(target.get("user_id"));
    let keys = account_keys_of(&sr, &tid)?;
    let profile = if tid == uid {
        public_profile(&target)
    } else {
        profile_for(&target, contacts_of(&own, &uid)?.contains(&tid))
    };
    Ok(json!({ "profile": profile, "encryption_ready": !keys.is_empty() }))
}

fn delete_account(ctx: &mut Ctx) -> Result<Value> {
    if is_staff(ctx) {
        return Err(deny(
            403,
            "STAFF_ACCOUNT",
            "Staff accounts can't be deleted here. The app owner removes staff access in Base44.",
        ));
    }
    let uid = ctx.user_id().to_string();
    let has_keys = !ctx
        .sr()
        .filter("AccountKey", json!({ "user_id": uid }), "created_date", 1)?
        .is_empty();
    let confirm = if has_keys {
        crate::verify::signed_by_active_device(ctx, "delete_account", Limits::MAX_BODY_BYTES)?
            .1
            .get("confirm")
            .cloned()
    } else if let Some(p) = ctx.body["payload"].as_str() {
        serde_json::from_str::<Value>(p)
            .ok()
            .and_then(|v| v.as_object().and_then(|o| o.get("confirm").cloned()))
    } else {
        ctx.body.get("confirm").cloned()
    };
    if confirm.is_none_or(|c| c != "DELETE") {
        return Err(deny(400, "CONFIRM_REQUIRED", "Type DELETE to confirm."));
    }
    let (sr, store) = (ctx.sr(), ctx.store());
    if !crate::deletion::purge_account(
        &sr,
        store,
        &uid,
        crate::sessions::now_ms() + DELETION_BUDGET_MS,
    )? {
        return Ok(json!({ "done": false }));
    }
    Ok(
        json!({ "done": true, "sign_in_removed": crate::deletion::remove_platform_user(&sr, store, &uid) }),
    )
}

fn get_many(ctx: &mut Ctx) -> Result<Value> {
    let (sr, own, uid) = (ctx.sr(), ctx.own(), ctx.user_id().to_string());
    let ids = id_list(&ctx.body["user_ids"], "user ids", 100)?;
    let contacts = contacts_of(&own, &uid)?;
    let others: Vec<String> = ids
        .iter()
        .filter(|i| !contacts.contains(*i))
        .cloned()
        .collect();
    let peers = server_peers_of(&sr, &own, &uid, &others)?;
    let wanted: Vec<String> = ids
        .into_iter()
        .filter(|i| contacts.contains(i) || peers.contains(i))
        .collect();
    if wanted.is_empty() {
        return Ok(json!({ "profiles": [] }));
    }
    let rows = sr.filter(
        "Profile",
        json!({ "user_id": { "$in": wanted } }),
        "created_date",
        200,
    )?;
    let profiles: Vec<Value> = rows
        .iter()
        .map(|p| {
            if p["user_id"] == uid.as_str() {
                public_profile(p)
            } else {
                profile_for(p, contacts.contains(&to_js_string(p.get("user_id"))))
            }
        })
        .collect();
    Ok(json!({ "profiles": profiles }))
}

pub fn actions() -> Actions {
    let mut a = Actions::new();
    for (name, f) in [
        ("privacy_report", privacy_report as crate::api::Action),
        ("me", me),
        ("set_auto_delete", set_auto_delete),
        ("claim_username", claim_username),
        ("update", update),
        ("find", find),
        ("delete_account", delete_account),
        ("get_many", get_many),
    ] {
        a.insert(name, f);
    }
    a
}
