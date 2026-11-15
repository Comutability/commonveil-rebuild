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
    match db.first("Server", json!({ "audience_id": server_id }), "created_date")? {
        Some(s) if s["status"] != "deleting" => Ok(s),
        _ => Err(ApiError::new(404, "SERVER_NOT_FOUND", "Server not found.")),
    }
}

pub fn member_row(db: &Db, server_id: &str, user_id: &str) -> Result<Option<Value>> {
    let mut rows = db.filter("ServerMember", json!({ "server_id": server_id, "user_id": user_id }), "created_date", 5)?;
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
    let roles = db.filter("Role", json!({ "server_id": server_id }), "position", ROLES_PER_SERVER + 5)?;
    let channels = db.filter("Channel", json!({ "server_id": server_id }), "position", CHANNELS_PER_SERVER + 5)?;
    Ok(Parts { server, roles, channels })
}

/// The private channels this member can see.
pub fn visible_private(parts: &Parts, member: &Value) -> Vec<String> {
    parts.channels.iter().filter(|c| truthy(c.get("private")) && has(channel_permissions(&parts.server, &parts.roles, Some(member), c), p::VIEW_CHANNEL)).map(|c| to_js_string(c.get("id"))).collect()
}

pub fn need_rotation(sr: &Db, server_id: &str, chain_ids: &[String], reason: &str) -> Result<()> {
    if chain_ids.is_empty() {
        return Ok(());
    }
    for k in sr.filter("KeyChain", json!({ "server_id": server_id, "chain_id": { "$in": chain_ids } }), "created_date", 500)? {
        if !truthy(k.get("rotation_needed")) {
            sr.update("KeyChain", id_of(&k), json!({ "rotation_needed": true, "rotation_reason": reason }))?;
        }
    }
    Ok(())
}

/// Work out, and store, which servers and private channels a person can read.
pub fn refresh_access(sr: &Db, store: &crate::store::Store, user_id: &str) -> Result<Vec<String>> {
    let mut memberships = sr.filter("ServerMember", json!({ "user_id": user_id }), "created_date", SERVERS_PER_USER + 10)?;
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
        let private = sr.filter("Channel", json!({ "server_id": { "$in": server_ids }, "private": true }), "position", 2000)?;
        let mut with_private: Vec<Value> = Vec::new();
        for c in &private {
            if !with_private.contains(&c["server_id"]) {
                with_private.push(c["server_id"].clone());
            }
        }
        if !with_private.is_empty() {
            let servers = sr.filter("Server", json!({ "audience_id": { "$in": with_private } }), "created_date", with_private.len() + 5)?;
            let roles = sr.filter("Role", json!({ "server_id": { "$in": with_private } }), "position", 5000)?;
            for ch in &private {
                let server = servers.iter().find(|s| s["id"] == ch["server_id"]);
                let member = memberships.iter().find(|m| m["server_id"] == ch["server_id"]);
                let (Some(server), Some(member)) = (server, member) else { continue };
                let server_roles: Vec<Value> = roles.iter().filter(|r| r["server_id"] == ch["server_id"]).cloned().collect();
                if has(channel_permissions(server, &server_roles, Some(member), ch), p::VIEW_CHANNEL) {
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
pub fn remove_member(sr: &Db, store: &crate::store::Store, server_id: &str, user_id: &str, reason: &str) -> Result<bool> {
    let parts = server_parts(sr, server_id)?;
    let Some(member) = member_row(sr, server_id, user_id)? else { return Ok(false) };
    let mut held = vec![history_chain_id(server_id), live_chain_id(server_id)];
    held.extend(visible_private(&parts, &member).iter().map(|c| channel_chain_id(server_id, c)));
    for row in sr.filter("ServerMember", json!({ "server_id": server_id, "user_id": user_id }), "created_date", 5)? {
        sr.delete("ServerMember", id_of(&row))?;
    }
    sr.delete_many("KeyGrant", json!({ "server_id": server_id, "user_id": user_id }))?;
    sr.delete_many("EventRsvp", json!({ "server_id": server_id, "user_id": user_id }))?;
    let count = to_number(parts.server.get("member_count"));
    let count = if count.is_nan() || count == 0.0 { 1.0 } else { count };
    sr.update("Server", id_of(&parts.server), json!({ "member_count": crate::js::number_value((count - 1.0).max(0.0)) }))?;
    if reason == "banned" || parts.server["join_mode"] != "open" {
        need_rotation(sr, server_id, &held, reason)?;
    }
    refresh_access(sr, store, user_id)?;
    Ok(true)
}

/// Delete a server and everything in it. True when finished; false means call again.
pub fn erase_server(sr: &Db, store: &crate::store::Store, server: &Value, deadline: i64) -> Result<bool> {
    let sid = id_of(server).to_string();
    if server["status"] != "deleting" {
        sr.update("Server", &sid, json!({ "status": "deleting" }))?;
    }
    loop {
        if crate::sessions::now_ms() > deadline {
            return Ok(false);
        }
        let rows = sr.filter("ServerMessage", json!({ "server_id": sid }), "created_date", 200)?;
        if rows.is_empty() {
            break;
        }
        for m in rows {
            sr.update("ServerMessage", id_of(&m), blank_server_message())?;
            sr.delete("ServerMessage", id_of(&m))?;
        }
    }
    for m in sr.filter("ServerMember", json!({ "server_id": sid }), "created_date", 10_000)? {
        if crate::sessions::now_ms() > deadline {
            return Ok(false);
        }
        sr.update("ServerMember", id_of(&m), json!({ "nick_envelope": "", "role_ids": [] }))?;
        sr.delete("ServerMember", id_of(&m))?;
        refresh_access(sr, store, &to_js_string(m.get("user_id")))?;
    }
    for entity in ["KeyGrant", "KeyGeneration", "KeyChain", "Invite", "ServerBan", "AuditEntry", "EventRsvp", "ServerEvent", "ServerReport", "ModCase", "Channel", "Role"] {
        if crate::sessions::now_ms() > deadline {
            return Ok(false);
        }
        sr.delete_many(entity, json!({ "server_id": sid }))?;
    }
    for c in sr.filter("Conversation", json!({ "server_id": sid }), "created_date", 1000)? {
        sr.update("Conversation", id_of(&c), json!({ "server_id": "", "ticket_channel_id": "" }))?;
    }
    sr.update("Server", &sid, json!({ "profile_envelope": "", "rules_envelope": "", "emoji_envelope": "", "stickers_envelope": "", "automod_envelope": "", "onboarding_envelope": "", "public_name": "", "public_description": "", "public_tags": [] }))?;
    sr.delete("Server", &sid)?;
    Ok(true)
}

/// An account being deleted: out of every server, its messages blanked, servers it owned handed on.
pub fn erase_server_traces(sr: &Db, store: &crate::store::Store, user_id: &str, deadline: i64) -> Result<bool> {
    let mut memberships = sr.filter("ServerMember", json!({ "user_id": user_id }), "created_date", 500)?;
    memberships.sort_by(by_age);
    for m in &memberships {
        if crate::sessions::now_ms() > deadline {
            return Ok(false);
        }
        let sid = to_js_string(m.get("server_id"));
        if let Some(server) = sr.first("Server", json!({ "audience_id": sid }), "created_date")? {
            if server["owner_id"] == user_id {
                let others: Vec<Value> = sr.filter("ServerMember", json!({ "server_id": server["id"] }), "joined_at", 2)?.into_iter().filter(|x| x["user_id"] != user_id).collect();
                if others.is_empty() && !truthy(server.get("is_default")) {
                    if !erase_server(sr, store, &server, deadline)? {
                        return Ok(false);
                    }
                    continue;
                }
                let next = others.first().map(|o| o["user_id"].clone()).filter(|u| truthy(Some(u))).unwrap_or(json!(""));
                sr.update("Server", id_of(&server), json!({ "owner_id": next }))?;
            }
        }
        remove_member(sr, store, &sid, user_id, "deleted")?;
    }
    loop {
        if crate::sessions::now_ms() > deadline {
            return Ok(false);
        }
        let rows: Vec<Value> = sr.filter("ServerMessage", json!({ "sender_id": user_id }), "created_date", 200)?.into_iter().filter(|x| !truthy(x.get("deleted")) || truthy(x.get("envelope"))).collect();
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
