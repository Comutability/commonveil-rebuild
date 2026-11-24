//! The parts of the server model that other features need (base44/shared/servers/model.ts,
//! build.ts and erase.ts): reading a server, access lists, key rotation flags, removing a member
//! and erasing a server or an account's traces in servers.
use serde_json::{json, Value};

use crate::api::{ApiError, Result};
use crate::db::{id_of, Db};
use crate::js::{to_js_string, to_number, truthy};
use crate::permissions::{channel_permissions, has, p};
use crate::shared::by_age;

pub const SERVERS_PER_USER: usize = 100;
pub const ROLES_PER_SERVER: usize = 100;
pub const CHANNELS_PER_SERVER: usize = 200;

pub fn history_chain_id(server_id: &str) -> String {
    format!("{server_id}.h")
}
pub fn live_chain_id(server_id: &str) -> String {
    format!("{server_id}.l")
}
pub fn channel_chain_id(server_id: &str, channel_id: &str) -> String {
    format!("{server_id}.c.{channel_id}")
}

pub fn blank_server_message() -> Value {
    json!({ "envelope": "", "signature": "", "deleted": true, "msg_id": "", "sender_id": "", "device_id": "", "sent_at": "", "thread_id": "", "pinned": false })
}

pub fn server_by_id(db: &Db, server_id: &str) -> Result<Value> {
    match db.first(
        "Server",
        json!({ "audience_id": server_id }),
        "created_date",
    )? {
        Some(s) if s["status"] != "deleting" => Ok(s),
        _ => Err(ApiError::new(404, "SERVER_NOT_FOUND", "Server not found.")),
    }
}

pub fn member_row(db: &Db, server_id: &str, user_id: &str) -> Result<Option<Value>> {
    let mut rows = db.filter(
        "ServerMember",
        json!({ "server_id": server_id, "user_id": user_id }),
        "created_date",
        5,
    )?;
    rows.sort_by(by_age);
    Ok(rows.into_iter().next())
}

pub struct Parts {
    pub server: Value,
    pub roles: Vec<Value>,
    pub channels: Vec<Value>,
}

/// Everything about a server that permissions depend on.
pub fn server_parts(db: &Db, server_id: &str) -> Result<Parts> {
    let server = server_by_id(db, server_id)?;
    let roles = db.filter(
        "Role",
        json!({ "server_id": server_id }),
        "position",
        ROLES_PER_SERVER + 5,
    )?;
    let channels = db.filter(
        "Channel",
        json!({ "server_id": server_id }),
        "position",
        CHANNELS_PER_SERVER + 5,
    )?;
    Ok(Parts {
        server,
        roles,
        channels,
    })
}

/// The private channels this member can see.
pub fn visible_private(parts: &Parts, member: &Value) -> Vec<String> {
    parts
        .channels
        .iter()
        .filter(|c| {
            truthy(c.get("private"))
                && has(
                    channel_permissions(&parts.server, &parts.roles, Some(member), c),
                    p::VIEW_CHANNEL,
                )
        })
        .map(|c| to_js_string(c.get("id")))
        .collect()
}

pub fn need_rotation(sr: &Db, server_id: &str, chain_ids: &[String], reason: &str) -> Result<()> {
    if chain_ids.is_empty() {
        return Ok(());
    }
    for k in sr.filter(
        "KeyChain",
        json!({ "server_id": server_id, "chain_id": { "$in": chain_ids } }),
        "created_date",
        500,
    )? {
        if !truthy(k.get("rotation_needed")) {
            sr.update(
                "KeyChain",
                id_of(&k),
                json!({ "rotation_needed": true, "rotation_reason": reason }),
            )?;
        }
    }
    Ok(())
}

/// Work out, and store, which servers and private channels a person can read.
pub fn refresh_access(sr: &Db, store: &crate::store::Store, user_id: &str) -> Result<Vec<String>> {
    let mut memberships = sr.filter(
        "ServerMember",
        json!({ "user_id": user_id }),
        "created_date",
        SERVERS_PER_USER + 10,
    )?;
    memberships.sort_by(by_age);
    let mut access: Vec<String> = Vec::new();
    for m in &memberships {
        let s = to_js_string(m.get("server_id"));
        if !access.contains(&s) {
            access.push(s);
        }
    }
    let server_ids = access.clone();
    if !server_ids.is_empty() {
        let private = sr.filter(
            "Channel",
            json!({ "server_id": { "$in": server_ids }, "private": true }),
            "position",
            2000,
        )?;
        let mut with_private: Vec<Value> = Vec::new();
        for c in &private {
            if !with_private.contains(&c["server_id"]) {
                with_private.push(c["server_id"].clone());
            }
        }
        if !with_private.is_empty() {
            let servers = sr.filter(
                "Server",
                json!({ "audience_id": { "$in": with_private } }),
                "created_date",
                with_private.len() + 5,
            )?;
            let roles = sr.filter(
                "Role",
                json!({ "server_id": { "$in": with_private } }),
                "position",
                5000,
            )?;
            for ch in &private {
                let server = servers.iter().find(|s| s["id"] == ch["server_id"]);
                let member = memberships
                    .iter()
                    .find(|m| m["server_id"] == ch["server_id"]);
                let (Some(server), Some(member)) = (server, member) else {
                    continue;
                };
                let server_roles: Vec<Value> = roles
                    .iter()
                    .filter(|r| r["server_id"] == ch["server_id"])
                    .cloned()
                    .collect();
                if has(
                    channel_permissions(server, &server_roles, Some(member), ch),
                    p::VIEW_CHANNEL,
                ) {
                    let id = to_js_string(ch.get("id"));
                    if !access.contains(&id) {
                        access.push(id);
                    }
                }
            }
        }
    }
    crate::sessions::update_user_record(store, user_id, &json!({ "cv_access": access }));
    Ok(access)
}

/// Take someone out of a server (build.ts removeMember).
pub fn remove_member(
    sr: &Db,
    store: &crate::store::Store,
    server_id: &str,
    user_id: &str,
    reason: &str,
) -> Result<bool> {
    let parts = server_parts(sr, server_id)?;
    let Some(member) = member_row(sr, server_id, user_id)? else {
        return Ok(false);
    };
    let mut held = vec![history_chain_id(server_id), live_chain_id(server_id)];
    held.extend(
        visible_private(&parts, &member)
            .iter()
            .map(|c| channel_chain_id(server_id, c)),
    );
    for row in sr.filter(
        "ServerMember",
        json!({ "server_id": server_id, "user_id": user_id }),
        "created_date",
        5,
    )? {
        sr.delete("ServerMember", id_of(&row))?;
    }
    sr.delete_many(
        "KeyGrant",
        json!({ "server_id": server_id, "user_id": user_id }),
    )?;
    sr.delete_many(
        "EventRsvp",
        json!({ "server_id": server_id, "user_id": user_id }),
    )?;
    let count = to_number(parts.server.get("member_count"));
    let count = if count.is_nan() || count == 0.0 {
        1.0
    } else {
        count
    };
    sr.update(
        "Server",
        id_of(&parts.server),
        json!({ "member_count": crate::js::number_value((count - 1.0).max(0.0)) }),
    )?;
    if reason == "banned" || parts.server["join_mode"] != "open" {
        need_rotation(sr, server_id, &held, reason)?;
    }
    refresh_access(sr, store, user_id)?;
    Ok(true)
}

/// Delete a server and everything in it. True when finished; false means call again.
pub fn erase_server(
    sr: &Db,
    store: &crate::store::Store,
    server: &Value,
    deadline: i64,
) -> Result<bool> {
    let sid = id_of(server).to_string();
    if server["status"] != "deleting" {
        sr.update("Server", &sid, json!({ "status": "deleting" }))?;
    }
    loop {
        if crate::sessions::now_ms() > deadline {
            return Ok(false);
        }
        let rows = sr.filter(
            "ServerMessage",
            json!({ "server_id": sid }),
            "created_date",
            200,
        )?;
        if rows.is_empty() {
            break;
        }
        for m in rows {
            sr.update("ServerMessage", id_of(&m), blank_server_message())?;
            sr.delete("ServerMessage", id_of(&m))?;
        }
    }
    for m in sr.filter(
        "ServerMember",
        json!({ "server_id": sid }),
        "created_date",
        10_000,
    )? {
        if crate::sessions::now_ms() > deadline {
            return Ok(false);
        }
        sr.update(
            "ServerMember",
            id_of(&m),
            json!({ "nick_envelope": "", "role_ids": [] }),
        )?;
        sr.delete("ServerMember", id_of(&m))?;
        refresh_access(sr, store, &to_js_string(m.get("user_id")))?;
    }
    for entity in [
        "KeyGrant",
        "KeyGeneration",
        "KeyChain",
        "Invite",
        "ServerBan",
        "AuditEntry",
        "EventRsvp",
        "ServerEvent",
        "ServerReport",
        "ModCase",
        "Channel",
        "Role",
    ] {
        if crate::sessions::now_ms() > deadline {
            return Ok(false);
        }
        sr.delete_many(entity, json!({ "server_id": sid }))?;
    }
    for c in sr.filter(
        "Conversation",
        json!({ "server_id": sid }),
        "created_date",
        1000,
    )? {
        sr.update(
            "Conversation",
            id_of(&c),
            json!({ "server_id": "", "ticket_channel_id": "" }),
        )?;
    }
    sr.update("Server", &sid, json!({ "profile_envelope": "", "rules_envelope": "", "emoji_envelope": "", "stickers_envelope": "", "automod_envelope": "", "onboarding_envelope": "", "public_name": "", "public_description": "", "public_tags": [] }))?;
    sr.delete("Server", &sid)?;
    Ok(true)
}

/// An account being deleted: out of every server, its messages blanked, servers it owned handed on.
pub fn erase_server_traces(
    sr: &Db,
    store: &crate::store::Store,
    user_id: &str,
    deadline: i64,
) -> Result<bool> {
    let mut memberships = sr.filter(
        "ServerMember",
        json!({ "user_id": user_id }),
        "created_date",
        500,
    )?;
    memberships.sort_by(by_age);
    for m in &memberships {
        if crate::sessions::now_ms() > deadline {
            return Ok(false);
        }
        let sid = to_js_string(m.get("server_id"));
        if let Some(server) = sr.first("Server", json!({ "audience_id": sid }), "created_date")? {
            if server["owner_id"] == user_id {
                let others: Vec<Value> = sr
                    .filter(
                        "ServerMember",
                        json!({ "server_id": server["id"] }),
                        "joined_at",
                        2,
                    )?
                    .into_iter()
                    .filter(|x| x["user_id"] != user_id)
                    .collect();
                if others.is_empty() && !truthy(server.get("is_default")) {
                    if !erase_server(sr, store, &server, deadline)? {
                        return Ok(false);
                    }
                    continue;
                }
                let next = others
                    .first()
                    .map(|o| o["user_id"].clone())
                    .filter(|u| truthy(Some(u)))
                    .unwrap_or(json!(""));
                sr.update("Server", id_of(&server), json!({ "owner_id": next }))?;
            }
        }
        remove_member(sr, store, &sid, user_id, "deleted")?;
    }
    loop {
        if crate::sessions::now_ms() > deadline {
            return Ok(false);
        }
        let rows: Vec<Value> = sr
            .filter(
                "ServerMessage",
                json!({ "sender_id": user_id }),
                "created_date",
                200,
            )?
            .into_iter()
            .filter(|x| !truthy(x.get("deleted")) || truthy(x.get("envelope")))
            .collect();
        if rows.is_empty() {
            break;
        }
        for m in rows {
            sr.update("ServerMessage", id_of(&m), blank_server_message())?;
            sr.delete("ServerMessage", id_of(&m))?;
        }
    }
    sr.delete_many("KeyGrant", json!({ "user_id": user_id }))?;
    sr.delete_many("EventRsvp", json!({ "user_id": user_id }))?;
    sr.delete_many("ServerReport", json!({ "reporter_id": user_id }))?;
    sr.delete_many("ModCase", json!({ "target_id": user_id }))?;
    Ok(true)
}

// ---------- limits and kinds (model.ts) ----------

pub const SERVERS_CREATED_PER_DAY: usize = 10;
pub const JOINS_PER_HOUR: usize = 30;
pub const MEMBERS_PER_SERVER: f64 = 10_000.0;
pub const INVITES_PER_SERVER: usize = 500;
pub const GRANTS_PER_REQUEST: usize = 60;
pub const PENDING_BATCH: usize = 25;
pub const SERVER_MESSAGES_PER_MINUTE: usize = 30;
pub const SERVER_PAGE_SIZE: i64 = 50;
pub const MAX_ITEM_ENVELOPE_CHARS: usize = 16 * 1024;
pub const MAX_IMAGE_SET_ENVELOPE_CHARS: usize = 180 * 1024;
pub const MAX_PICTURE_ENVELOPE_CHARS: usize = 19 * 1024;
pub const MAX_MESSAGE_ENVELOPE_CHARS: usize = 24 * 1024;
pub const MAX_PREVIEW_CHARS: usize = 4096;
pub const AUDIT_RETENTION_CHOICES: [f64; 3] = [30.0, 90.0, 180.0];
pub const SLOWMODE_CHOICES: [f64; 8] = [0.0, 5.0, 10.0, 30.0, 60.0, 300.0, 900.0, 3600.0];
pub const TIMEOUT_MAX_DAYS: i64 = 28;
pub const TICKETS_OPEN_PER_MEMBER: usize = 3;
pub const STAFF_PER_TICKET: usize = 31;
pub const CHANNEL_EXPIRY_CHOICES: [f64; 5] = [0.0, 3600.0, 86_400.0, 604_800.0, 2_419_200.0];
pub const CHANNEL_KINDS: [&str; 8] = [
    "category",
    "text",
    "announcement",
    "rules",
    "forum",
    "voice",
    "stage",
    "tickets",
];
pub const MESSAGE_KINDS: [&str; 4] = ["text", "announcement", "rules", "forum"];
pub const TAGS: [&str; 16] = [
    "privacy",
    "security",
    "open-source",
    "learning",
    "support",
    "community",
    "friends",
    "study",
    "gaming",
    "creative",
    "technology",
    "local",
    "activism",
    "health",
    "music",
    "books",
];
pub const STEP_MS: i64 = 3_600_000;

pub struct ChainId {
    pub server_id: String,
    pub kind: &'static str,
    pub channel_id: String,
}

fn id_part(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

pub fn parse_chain_id(v: &Value) -> Option<ChainId> {
    let s = v.as_str()?;
    let (server, rest) = s.split_once('.')?;
    if !id_part(server) {
        return None;
    }
    match rest {
        "h" => Some(ChainId {
            server_id: server.into(),
            kind: "h",
            channel_id: String::new(),
        }),
        "l" => Some(ChainId {
            server_id: server.into(),
            kind: "l",
            channel_id: String::new(),
        }),
        _ => {
            let ch = rest.strip_prefix("c.")?;
            id_part(ch).then(|| ChainId {
                server_id: server.into(),
                kind: "c",
                channel_id: ch.into(),
            })
        }
    }
}

pub fn step_at(chain_id: &str, started_at: &str, at_ms: f64) -> i64 {
    if parse_chain_id(&json!(chain_id)).is_none_or(|c| c.kind != "l") {
        return 0;
    }
    let started = crate::dates::parse(started_at).unwrap_or(f64::NAN);
    let v = ((at_ms - started) / STEP_MS as f64).floor();
    // Math.max(0, NaN) is NaN in JavaScript; that never reaches here with stored times.
    if v.is_nan() {
        0
    } else {
        v.max(0.0) as i64
    }
}

// ---------- outputs ----------

/// `Number(v) || 0`.
pub fn num0(v: Option<&Value>) -> Value {
    let n = to_number(v);
    crate::js::number_value(if n.is_nan() { 0.0 } else { n })
}
fn n0(v: Option<&Value>) -> f64 {
    let n = to_number(v);
    if n.is_nan() {
        0.0
    } else {
        n
    }
}
/// `Number(v)` as JSON (NaN becomes null, as JSON.stringify writes it).
pub fn num(v: Option<&Value>) -> Value {
    crate::js::number_value(to_number(v))
}
use crate::shared::or;

/// Build an object as a JavaScript literal does: a field read from a row that the row doesn't
/// have is undefined, and JSON leaves it out.
pub struct Obj(serde_json::Map<String, Value>);
impl Obj {
    pub fn new() -> Self {
        Obj(serde_json::Map::new())
    }
    /// `key: row.src` (left out when the row has no such field).
    pub fn copy(mut self, key: &str, row: &Value, src: &str) -> Self {
        if let Some(v) = row.get(src) {
            self.0.insert(key.into(), v.clone());
        }
        self
    }
    pub fn set(mut self, key: &str, v: Value) -> Self {
        self.0.insert(key.into(), v);
        self
    }
    pub fn done(self) -> Value {
        Value::Object(self.0)
    }
}
impl Default for Obj {
    fn default() -> Self {
        Self::new()
    }
}

pub fn item_out(row: &Value, prefix: &str) -> Value {
    if !truthy(row.get(format!("{prefix}_envelope").as_str())) {
        return Value::Null;
    }
    let mut o = Obj::new();
    for k in [
        "envelope",
        "item_id",
        "sender_id",
        "device_id",
        "sent_at",
        "signature",
    ] {
        o = o.copy(k, row, &format!("{prefix}_{k}"));
    }
    o.done()
}

pub fn server_out(s: &Value, sets: bool) -> Value {
    let public = if truthy(s.get("discoverable")) || truthy(s.get("is_default")) {
        json!({ "name": or(&s["public_name"], json!("")), "description": or(&s["public_description"], json!("")), "tags": or(&s["public_tags"], json!([])), "icon": or(&s["public_icon"], json!("")), "color": or(&s["public_color"], json!("")) })
    } else {
        Value::Null
    };
    let retention = n0(s.get("audit_retention_days"));
    let mut o = Obj::new()
        .copy("id", s, "id")
        .set("owner_id", or(&s["owner_id"], json!("")))
        .set("is_default", json!(truthy(s.get("is_default"))))
        .set("template", or(&s["template"], json!("")))
        .set("join_mode", or(&s["join_mode"], json!("invite")))
        .set("discoverable", json!(truthy(s.get("discoverable"))))
        .set("public", public)
        .set("profile", item_out(s, "profile"))
        .set("rules", item_out(s, "rules"));
    o = if sets {
        o.set("emoji", item_out(s, "emoji"))
            .set("stickers", item_out(s, "stickers"))
            .set("icon", item_out(s, "icon"))
            .set("banner", item_out(s, "banner"))
    } else {
        o.set("sets_omitted", json!(true))
    };
    let changed = if truthy(s.get("changed_at")) {
        Some(s["changed_at"].clone())
    } else {
        s.get("updated_date").cloned()
    };
    let mut o = o
        .set("automod", item_out(s, "automod"))
        .set("onboarding", item_out(s, "onboarding"))
        .set("settings", json!({
            "rules_required": truthy(s.get("rules_required")),
            "min_account_minutes": num0(s.get("min_account_minutes")),
            "min_member_minutes": num0(s.get("min_member_minutes")),
            "invites_paused": truthy(s.get("invites_paused")),
            "joins_paused": truthy(s.get("joins_paused")),
            "member_list": or(&s["member_list"], json!("opt_in")),
            "audit_retention_days": crate::js::number_value(if retention == 0.0 { 90.0 } else { retention }),
            "default_history": or(&s["default_history"], json!("joined")),
            "allow_member_dms": s["allow_member_dms"] != false,
            "key_handout": if s["key_handout"] == "staff" { "staff" } else { "members" },
        }))
        .set("member_count", num0(s.get("member_count")))
        .set("keys_pending_at", or(&s["keys_pending_at"], Value::Null));
    if let Some(c) = changed {
        o = o.set("changed_at", c);
    }
    o.copy("created_date", s, "created_date")
        .copy("updated_date", s, "updated_date")
        .done()
}

pub fn channel_out(c: &Value) -> Value {
    let overwrites: Value = match c["overwrites"].as_array() {
        Some(list) => list
            .iter()
            .map(|o| {
                Obj::new()
                    .copy("role_id", o, "role_id")
                    .set("allow", num0(o.get("allow")))
                    .set("deny", num0(o.get("deny")))
                    .done()
            })
            .collect(),
        None => json!([]),
    };
    Obj::new()
        .copy("id", c, "id")
        .copy("server_id", c, "server_id")
        .copy("kind", c, "kind")
        .set("parent_id", or(&c["parent_id"], json!("")))
        .set("position", num0(c.get("position")))
        .set("template_key", or(&c["template_key"], json!("")))
        .set("name", item_out(c, "name"))
        .set("history", or(&c["history"], json!("joined")))
        .set("private", json!(truthy(c.get("private"))))
        .set("overwrites", overwrites)
        .set("slowmode_seconds", num0(c.get("slowmode_seconds")))
        .set("expire_seconds", num0(c.get("expire_seconds")))
        .set("sensitive", json!(truthy(c.get("sensitive"))))
        .set("last_message_at", or(&c["last_message_at"], Value::Null))
        .done()
}

pub fn role_out(r: &Value) -> Value {
    Obj::new()
        .copy("id", r, "id")
        .copy("server_id", r, "server_id")
        .set("position", num0(r.get("position")))
        .set("permissions", num0(r.get("permissions")))
        .set("is_everyone", json!(truthy(r.get("is_everyone"))))
        .set("template_key", or(&r["template_key"], json!("")))
        .set("hoist", json!(truthy(r.get("hoist"))))
        .set("mentionable", json!(truthy(r.get("mentionable"))))
        .set("name", item_out(r, "name"))
        .done()
}

pub fn member_out(m: &Value, me: bool, now: i64) -> Value {
    let joined = if me {
        m.get("joined_at").cloned()
    } else {
        Some(json!(to_js_string(Some(&or(&m["joined_at"], json!(""))))
            .chars()
            .take(7)
            .collect::<String>()))
    };
    let timeout = if truthy(m.get("timeout_until"))
        && crate::shared::platform_ms(&m["timeout_until"]) > now as f64
        && crate::dates::parse(&to_js_string(m.get("timeout_until"))).is_some()
    {
        m["timeout_until"].clone()
    } else {
        Value::Null
    };
    let mut o = Obj::new()
        .copy("user_id", m, "user_id")
        .copy("server_id", m, "server_id")
        .set("role_ids", or(&m["role_ids"], json!([])));
    if let Some(j) = joined {
        o = o.set("joined_at", j);
    }
    o = o
        .set("listed", json!(truthy(m.get("listed"))))
        .set("timeout_until", timeout)
        .set("nick", item_out(m, "nick"));
    if me {
        o = o
            .set(
                "rules_accepted_at",
                or(&m["rules_accepted_at"], Value::Null),
            )
            .set("key_status", or(&m["key_status"], json!("pending")));
    }
    o.done()
}

pub fn chain_out(k: &Value) -> Value {
    Obj::new()
        .copy("chain_id", k, "chain_id")
        .copy("kind", k, "kind")
        .set("channel_id", or(&k["channel_id"], json!("")))
        .set("rotation_needed", json!(truthy(k.get("rotation_needed"))))
        .done()
}

pub fn generation_out(g: &Value) -> Value {
    Obj::new()
        .copy("server_id", g, "server_id")
        .copy("chain_id", g, "chain_id")
        .set("generation", num(g.get("generation")))
        .copy("started_at", g, "started_at")
        .copy("commit", g, "commit")
        .copy("creator_id", g, "creator_id")
        .copy("device_id", g, "device_id")
        .copy("signature", g, "signature")
        .done()
}

pub fn grant_out(g: &Value) -> Value {
    Obj::new()
        .copy("id", g, "id")
        .copy("server_id", g, "server_id")
        .copy("chain_id", g, "chain_id")
        .set("generation", num(g.get("generation")))
        .set("step", num(g.get("step")))
        .copy("recipient_id", g, "user_id")
        .set("recipient_key_version", num(g.get("recipient_key_version")))
        .copy("sealed", g, "sealed")
        .copy("grantor_id", g, "grantor_id")
        .copy("grantor_device_id", g, "grantor_device_id")
        .copy("granted_at", g, "granted_at")
        .copy("signature", g, "signature")
        .done()
}

pub fn server_message_out(m: &Value) -> Value {
    let deleted = truthy(m.get("deleted"));
    let mut o = Obj::new()
        .copy("id", m, "id")
        .copy("server_id", m, "server_id")
        .copy("channel_id", m, "channel_id")
        .copy("msg_id", m, "msg_id")
        .copy("kind", m, "kind")
        .set("thread_id", or(&m["thread_id"], json!("")))
        .copy("sender_id", m, "sender_id")
        .copy("device_id", m, "device_id");
    o = if deleted {
        o.set("envelope", Value::Null).set("signature", Value::Null)
    } else {
        o.copy("envelope", m, "envelope")
            .copy("signature", m, "signature")
    };
    let mut o = o
        .copy("sent_at", m, "sent_at")
        .copy("created_date", m, "created_date")
        .copy("updated_date", m, "updated_date")
        .set("expires_at", or(&m["expires_at"], Value::Null))
        .set("deleted", json!(deleted));
    o = if deleted {
        if truthy(m.get("deleted_by")) {
            o.set("deleted_by", m["deleted_by"].clone())
        } else {
            o.copy("deleted_by", m, "sender_id")
        }
    } else {
        o.set("deleted_by", Value::Null)
    };
    o.set("pinned", json!(truthy(m.get("pinned"))))
        .set("last_reply_at", or(&m["last_reply_at"], Value::Null))
        .set("reply_count", num0(m.get("reply_count")))
        .set("thread_locked", json!(truthy(m.get("thread_locked"))))
        .done()
}

// ---------- reading a server ----------

/// The caller's membership, read with their own access. Not a member: the same 404 as no server.
pub fn require_member(own: &Db, server_id: &str, user_id: &str) -> Result<Value> {
    member_row(own, server_id, user_id)?
        .ok_or_else(|| ApiError::new(404, "SERVER_NOT_FOUND", "Server not found."))
}

pub fn perms_of(parts: &Parts, member: &Value, channel: Option<&Value>) -> i64 {
    match channel {
        Some(c) => channel_permissions(&parts.server, &parts.roles, Some(member), c),
        None => crate::permissions::base_permissions(&parts.server, &parts.roles, Some(member)),
    }
}

pub fn can_hand_out_keys(parts: &Parts, member: &Value) -> bool {
    parts.server["key_handout"] != "staff"
        || has(
            crate::permissions::base_permissions(&parts.server, &parts.roles, Some(member)),
            p::MANAGE_KEYS,
        )
}

pub fn require_perm(perms: i64, bit: i64, what: &str) -> Result<()> {
    if !has(perms, bit) {
        return Err(ApiError::new(
            403,
            "MISSING_PERMISSION",
            &format!("You don't have permission to {what}."),
        ));
    }
    Ok(())
}

pub fn require_above(parts: &Parts, actor: &Value, target: &Value, what: &str) -> Result<()> {
    if target["user_id"] == parts.server["owner_id"] {
        return Err(ApiError::new(
            403,
            "HIERARCHY",
            &format!("You can't {what} the server's owner."),
        ));
    }
    if actor["user_id"] == parts.server["owner_id"] {
        return Ok(());
    }
    let top = |m: &Value| crate::permissions::top_position(&parts.server, &parts.roles, Some(m));
    if top(actor) <= top(target) {
        return Err(ApiError::new(
            403,
            "HIERARCHY",
            &format!("You can only {what} members whose highest role is below yours."),
        ));
    }
    Ok(())
}

pub fn channel_in<'a>(parts: &'a Parts, channel_id: &str) -> Result<&'a Value> {
    parts
        .channels
        .iter()
        .find(|c| c["id"] == channel_id)
        .ok_or_else(|| ApiError::new(404, "CHANNEL_NOT_FOUND", "Channel not found."))
}

pub fn chain_for_channel(server_id: &str, channel: &Value) -> String {
    if truthy(channel.get("private")) {
        return channel_chain_id(server_id, id_of(channel));
    }
    if channel["history"] == "full" {
        history_chain_id(server_id)
    } else {
        live_chain_id(server_id)
    }
}

pub fn touch_server(sr: &Db, server_id: &str, now: i64, extra: Value) -> Result<()> {
    if let Some(s) = sr.first(
        "Server",
        json!({ "audience_id": server_id }),
        "created_date",
    )? {
        sr.update(
            "Server",
            id_of(&s),
            crate::db::merged(&json!({ "changed_at": crate::shared::iso(now) }), &extra),
        )?;
    }
    Ok(())
}

// ---------- keys ----------

fn gen_n(g: &Value) -> f64 {
    to_number(g.get("generation"))
}

pub fn generations_of(
    db: &Db,
    server_id: &str,
    chain_ids: Option<&[String]>,
) -> Result<Vec<Value>> {
    let mut q = json!({ "server_id": server_id });
    if let Some(c) = chain_ids {
        q["chain_id"] = json!({ "$in": c });
    }
    let mut rows = db.filter("KeyGeneration", q, "created_date", 2000)?;
    rows.sort_by(by_age);
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = Vec::new();
    for g in rows {
        let k = format!(
            "{}|{}",
            to_js_string(g.get("chain_id")),
            to_js_string(g.get("generation"))
        );
        if seen.insert(k) {
            out.push(g);
        }
    }
    out.sort_by(|a, b| {
        to_js_string(a.get("chain_id"))
            .cmp(&to_js_string(b.get("chain_id")))
            .then_with(|| {
                gen_n(a)
                    .partial_cmp(&gen_n(b))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });
    Ok(out)
}

pub fn latest_generation<'a>(gens: &'a [Value], chain_id: &str) -> Option<&'a Value> {
    let mut best: Option<&Value> = None;
    for g in gens {
        if g["chain_id"] == chain_id
            && best.is_none_or(|b| crate::js::gt(g.get("generation"), b.get("generation")))
        {
            best = Some(g);
        }
    }
    best
}

pub fn chains_for(parts: &Parts, member: &Value) -> Vec<String> {
    let sid = id_of(&parts.server);
    let mut ids = vec![history_chain_id(sid), live_chain_id(sid)];
    for ch in visible_private(parts, member) {
        ids.push(channel_chain_id(sid, &ch));
    }
    ids
}

/// (chain, generation, step)
pub type Expected = (String, f64, i64);

pub fn expected_grants(parts: &Parts, member: &Value, gens: &[Value]) -> Vec<Expected> {
    let mut out = Vec::new();
    let joined = crate::dates::parse(&to_js_string(member.get("joined_at"))).unwrap_or(f64::NAN);
    for chain in chains_for(parts, member) {
        let mut mine: Vec<&Value> = gens
            .iter()
            .filter(|g| g["chain_id"] == chain.as_str())
            .collect();
        mine.sort_by(|a, b| {
            (gen_n(a) - gen_n(b))
                .partial_cmp(&0.0)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        if parse_chain_id(&json!(chain)).is_none_or(|c| c.kind != "l") {
            for g in &mine {
                out.push((chain.clone(), gen_n(g), 0));
            }
            continue;
        }
        for (i, g) in mine.iter().enumerate() {
            let start = crate::dates::parse(&to_js_string(g.get("started_at"))).unwrap_or(f64::NAN);
            if let Some(next) = mine.get(i + 1) {
                if crate::dates::parse(&to_js_string(next.get("started_at"))).unwrap_or(f64::NAN)
                    <= joined
                {
                    continue;
                }
            }
            let step = if joined > start {
                step_at(&chain, &to_js_string(g.get("started_at")), joined)
            } else {
                0
            };
            out.push((chain.clone(), gen_n(g), step));
        }
    }
    out
}

pub fn grant_key(chain: &str, generation: f64) -> String {
    format!(
        "{chain}|{}",
        to_js_string(Some(&crate::js::number_value(generation)))
    )
}

pub fn missing_grants(
    parts: &Parts,
    member: &Value,
    gens: &[Value],
    grants: &[Value],
) -> Vec<Expected> {
    let have: std::collections::HashSet<String> = grants
        .iter()
        .filter(|g| g["user_id"] == member["user_id"])
        .map(|g| {
            grant_key(
                &to_js_string(g.get("chain_id")),
                to_number(g.get("generation")),
            )
        })
        .collect();
    expected_grants(parts, member, gens)
        .into_iter()
        .filter(|(c, g, _)| !have.contains(&grant_key(c, *g)))
        .collect()
}

pub fn refresh_key_status(
    sr: &Db,
    parts: &mut Parts,
    members: &[Value],
    now: i64,
) -> Result<usize> {
    if members.is_empty() {
        return Ok(0);
    }
    let sid = id_of(&parts.server).to_string();
    let gens = generations_of(sr, &sid, None)?;
    let ids: Vec<Value> = members.iter().map(|m| m["user_id"].clone()).collect();
    let grants = sr.filter(
        "KeyGrant",
        json!({ "server_id": sid, "user_id": { "$in": ids } }),
        "created_date",
        5000,
    )?;
    let mut pending = 0;
    for m in members {
        let status = if missing_grants(parts, m, &gens, &grants).is_empty() {
            "ok"
        } else {
            "pending"
        };
        if status == "pending" {
            pending += 1;
        }
        if or(&m["key_status"], json!("pending")) != status {
            sr.update("ServerMember", id_of(m), json!({ "key_status": status }))?;
        }
    }
    if pending > 0 && !truthy(parts.server.get("keys_pending_at")) {
        let at = crate::shared::iso(now);
        sr.update("Server", &sid, json!({ "keys_pending_at": at }))?;
        parts.server["keys_pending_at"] = json!(at);
    }
    Ok(pending)
}

// ---------- encrypted items ----------

pub struct ItemEnvelope {
    pub chain: String,
    pub gen: f64,
    pub step: f64,
}

/// A server envelope's shape: { v: 1, chain, gen, step, iv, ct, kc }.
pub fn parse_item_envelope(envelope: &str) -> Result<ItemEnvelope> {
    let bad = || ApiError::new(400, "BAD_ENVELOPE", "The encrypted item is malformed.");
    let env: Value = serde_json::from_str(envelope).map_err(|_| bad())?;
    let len = |v: &Value| -> i64 {
        match v.as_str() {
            Some("") => 0,
            Some(_) => crate::verify::b64_bytes(v).map_or(-1, |b| b.len() as i64),
            None => -1,
        }
    };
    let int_ok = |v: &Value| {
        v.as_f64()
            .is_some_and(|f| f.is_finite() && f.fract() == 0.0 && f >= 0.0)
    };
    let ok = truthy(Some(&env))
        && env["v"].as_f64() == Some(1.0)
        && parse_chain_id(&env["chain"]).is_some()
        && int_ok(&env["gen"])
        && int_ok(&env["step"])
        && len(&env["iv"]) == 12
        && len(&env["ct"]) >= 17
        && len(&env["kc"]) == 32;
    if !ok {
        return Err(bad());
    }
    Ok(ItemEnvelope {
        chain: to_js_string(env.get("chain")),
        gen: env["gen"].as_f64().unwrap_or(0.0),
        step: env["step"].as_f64().unwrap_or(0.0),
    })
}

pub fn verify_server_item_signature(
    kind: &str,
    server_id: &str,
    channel_id: &str,
    item: &Value,
    sign_pub: &str,
) -> Result<bool> {
    let text = secure_net_core::cv::canonical::server_item_text(&json!({
        "kind": kind, "server_id": server_id, "channel_id": channel_id, "item_id": item["item_id"], "sender_id": item["sender_id"], "device_id": item["device_id"],
        "envelope_hash": secure_net_core::cv::encoding::sha256_b64(item["envelope"].as_str().unwrap_or("")), "sent_at": item["sent_at"],
    }))
    .map_err(|e| ApiError { status: 500, code: "INTERNAL".into(), message: e.message })?;
    Ok(crate::verify::verify_sig(
        sign_pub,
        &item["signature"],
        &text,
    ))
}

/// An encrypted item sent with a request: its envelope's shape, the sending device, the clock,
/// and the device's signature. Encrypted with the given chain (default: history), current generation.
#[allow(clippy::too_many_arguments)]
pub fn accept_item(
    own: &Db,
    user_id: &str,
    now: i64,
    kind: &str,
    server_id: &str,
    channel_id: &str,
    item: &Value,
    gens: &[Value],
    chain_id: Option<&str>,
    max_chars: usize,
) -> Result<Value> {
    if !truthy(Some(item)) || !(item.is_object() || item.is_array()) {
        return Err(ApiError::new(400, "BAD_FIELD", "Missing encrypted item."));
    }
    let envelope = crate::api::str_field(&item["envelope"], "encrypted item", max_chars, 1)?;
    let item_id = crate::api::random_id_field(&item["item_id"], "item id")?;
    let sent_at = crate::verify::iso_time(&item["sent_at"], "sent time")?;
    crate::verify::check_clock(&sent_at, now)?;
    let device = crate::shared::require_active_device(
        own,
        user_id,
        &crate::api::random_id_field(&item["device_id"], "device id")?,
    )?;
    let env = parse_item_envelope(&envelope)?;
    let chain = chain_id
        .map(String::from)
        .unwrap_or_else(|| history_chain_id(server_id));
    let latest = latest_generation(gens, &chain).ok_or_else(|| {
        ApiError::new(
            409,
            "NO_KEYS_YET",
            "This server's encryption isn't set up yet.",
        )
    })?;
    let sent_ms = crate::dates::parse(&sent_at).unwrap_or(f64::NAN);
    if env.chain != chain
        || env.gen != gen_n(latest)
        || env.step != step_at(&chain, &to_js_string(latest.get("started_at")), sent_ms) as f64
    {
        return Err(ApiError::new(
            409,
            "STALE_SERVER_KEYS",
            "This server's keys changed. Refreshing and trying again.",
        ));
    }
    let accepted = json!({ "envelope": envelope, "item_id": item_id, "sender_id": user_id, "device_id": device["device_id"], "sent_at": sent_at, "signature": item.get("signature").cloned().unwrap_or(Value::Null) });
    if !verify_server_item_signature(
        kind,
        server_id,
        channel_id,
        &accepted,
        device["sign_pub"].as_str().unwrap_or(""),
    )? {
        return Err(ApiError::new(
            403,
            "SIGNATURE_INVALID",
            "The signature didn't verify.",
        ));
    }
    let mut out = accepted;
    if item.get("signature").is_none() {
        out.as_object_mut().unwrap().remove("signature");
    }
    Ok(out)
}

pub fn item_fields(prefix: &str, accepted: &Value) -> Value {
    let mut o = serde_json::Map::new();
    for k in [
        "envelope",
        "item_id",
        "sender_id",
        "device_id",
        "sent_at",
        "signature",
    ] {
        if let Some(v) = accepted.get(k) {
            o.insert(format!("{prefix}_{k}"), v.clone());
        }
    }
    Value::Object(o)
}

pub fn cleared_item(prefix: &str) -> Value {
    item_fields(
        prefix,
        &json!({ "envelope": "", "item_id": "", "sender_id": "", "device_id": "", "sent_at": "", "signature": "" }),
    )
}

// ---------- audit log ----------

#[allow(clippy::too_many_arguments)]
pub fn audit(
    sr: &Db,
    server: &Value,
    actor_id: &str,
    action: &str,
    target_kind: &str,
    target_id: &str,
    detail: &str,
    now: i64,
) -> Result<()> {
    let r = to_number(server.get("audit_retention_days"));
    let days = if AUDIT_RETENTION_CHOICES.contains(&r) {
        r
    } else {
        90.0
    };
    let detail = slice16(detail, 200);
    sr.create("AuditEntry", json!({
        "server_id": server["id"], "actor_id": actor_id, "action": action, "target_kind": target_kind, "target_id": target_id,
        "detail": detail, "expires_at": crate::shared::iso(now + (days * 86_400_000.0) as i64),
    }))?;
    Ok(())
}

/// `String.prototype.slice(0, n)`: the first n UTF-16 code units.
pub fn slice16(s: &str, n: usize) -> String {
    String::from_utf16_lossy(&s.encode_utf16().take(n).collect::<Vec<u16>>())
}
