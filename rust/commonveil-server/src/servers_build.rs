//! Making a server from a template, joining one (base44/shared/servers/build.ts), and the
//! moderation the service can do without reading anything (servers/moderation.ts).
use serde_json::{json, Value};

use crate::api::{ApiError, Result};
use crate::db::{id_of, merged, Db};
use crate::js::{to_js_string, to_number, truthy};
use crate::permissions::{channel_is_private, channel_permissions, has, p, to_int};
use crate::servers_core::{audit, channel_chain_id, history_chain_id, live_chain_id, member_row, refresh_access, Parts, MEMBERS_PER_SERVER, SERVERS_PER_USER};
use crate::shared::{by_age, count_since, iso, or, platform_ms, with_row};
use crate::store::Store;

/// The community server's public card (it's listed in Discover).
fn community_public() -> Value {
    json!({
        "public_name": "Commonveil Community",
        "public_description": "Help, guides, ideas and good company from the people behind Commonveil and everyone using it. Everything here is end-to-end encrypted.",
        "public_tags": ["privacy", "security", "support", "community", "learning"],
        "public_icon": "CV",
        "public_color": "#0f766e",
    })
}

fn n(v: Option<&Value>) -> f64 {
    let x = to_number(v);
    if x.is_nan() { 0.0 } else { x }
}

/// Create a server with a template's roles, categories and channels.
pub fn create_from_template(sr: &Db, template: &Value, owner_id: &str, is_default: bool, now: i64) -> Result<Value> {
    let mut fields = json!({
        "owner_id": owner_id, "audience_id": "pending", "is_default": is_default, "template": template["key"],
        "join_mode": if is_default { "open" } else { "invite" }, "discoverable": is_default,
    });
    if is_default {
        fields = merged(&fields, &community_public());
    }
    fields = merged(&fields, &json!({
        "rules_required": is_default, "min_account_minutes": 0, "min_member_minutes": 0, "invites_paused": false, "joins_paused": false,
        "member_list": "opt_in", "audit_retention_days": 90, "default_history": "joined", "allow_member_dms": true,
        // In the community server only staff hand out keys, so ordinary members never learn who joins.
        "key_handout": if is_default { "staff" } else { "members" },
        "member_count": 0, "status": "active", "changed_at": iso(now),
    }));
    let mut server = sr.create("Server", fields)?;
    let sid = id_of(&server).to_string();
    sr.update("Server", &sid, json!({ "audience_id": sid }))?;
    server["audience_id"] = json!(sid);
    let mut role_ids: Vec<(String, String)> = Vec::new();
    let mut roles: Vec<Value> = Vec::new();
    let everyone = sr.create("Role", json!({ "server_id": sid, "audience_id": sid, "position": 0, "permissions": template["everyone"], "is_everyone": true, "template_key": "everyone", "hoist": false, "mentionable": false }))?;
    role_ids.push(("everyone".into(), id_of(&everyone).into()));
    roles.push(everyone);
    for r in template["roles"].as_array().into_iter().flatten() {
        let row = sr.create("Role", json!({ "server_id": sid, "audience_id": sid, "position": r["position"], "permissions": r["permissions"], "is_everyone": false, "template_key": r["key"], "hoist": r["hoist"], "mentionable": r["mentionable"] }))?;
        role_ids.push((to_js_string(r.get("key")), id_of(&row).into()));
        roles.push(row);
    }
    let role_id = |k: &str| role_ids.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
    let mut channel_ids: Vec<(String, String)> = Vec::new();
    let mut chains = vec![
        json!({ "server_id": sid, "audience_id": sid, "chain_id": history_chain_id(&sid), "kind": "h", "channel_id": "", "rotation_needed": false }),
        json!({ "server_id": sid, "audience_id": sid, "chain_id": live_chain_id(&sid), "kind": "l", "channel_id": "", "rotation_needed": false }),
    ];
    for (position, c) in template["channels"].as_array().into_iter().flatten().enumerate() {
        let overwrites: Vec<Value> = c["overwrites"].as_array().into_iter().flatten().filter_map(|o| {
            let rid = role_id(o["role"].as_str().unwrap_or(""))?;
            Some(json!({ "role_id": rid, "allow": or(&o["allow"], json!(0)), "deny": or(&o["deny"], json!(0)) }))
        }).collect();
        let private = channel_is_private(&roles, &json!({ "kind": c["kind"], "overwrites": overwrites }));
        let parent = c["parent"].as_str().and_then(|p| channel_ids.iter().find(|(k, _)| k == p).map(|(_, v)| v.clone())).unwrap_or_default();
        let row = sr.create("Channel", json!({
            "server_id": sid, "audience_id": sid, "kind": c["kind"], "parent_id": parent, "position": position, "template_key": c["key"],
            "history": or(&c["history"], json!("joined")), "private": private, "overwrites": overwrites, "slowmode_seconds": or(&c["slowmode"], json!(0)),
            "expire_seconds": 0, "sensitive": false, "creator_id": owner_id,
        }))?;
        let cid = id_of(&row).to_string();
        channel_ids.push((to_js_string(c.get("key")), cid.clone()));
        if private {
            sr.update("Channel", &cid, json!({ "audience_id": cid }))?;
            chains.push(json!({ "server_id": sid, "audience_id": cid, "chain_id": channel_chain_id(&sid, &cid), "kind": "c", "channel_id": cid, "rotation_needed": false }));
        }
    }
    for c in chains {
        sr.create("KeyChain", c)?;
    }
    Ok(server)
}

fn live_defaults(sr: &Db) -> Result<Vec<Value>> {
    Ok(sr.filter("Server", json!({ "is_default": true }), "created_date", 5)?.into_iter().filter(|s| s["status"] != "deleting").collect())
}

/// The community server: made the first time anyone needs it. Two at once: the older one stays.
pub fn ensure_default_server(sr: &Db, now: i64) -> Result<Value> {
    let mut existing = live_defaults(sr)?;
    existing.sort_by(by_age);
    if let Some(s) = existing.into_iter().next() {
        return Ok(s);
    }
    let made = create_from_template(sr, &crate::servers_template::community(), "", true, now)?;
    let all = with_row(live_defaults(sr)?, &made);
    if all[0]["id"] != made["id"] {
        sr.update("Server", id_of(&made), json!({ "status": "deleting", "is_default": false }))?;
        return Ok(all[0].clone());
    }
    Ok(made)
}

/// The addresses (or, self-hosted, usernames) that become the community server's admins.
pub fn clean_admin_list(list: &[String]) -> Vec<String> {
    let re = regex::Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").unwrap();
    list.iter().map(|e| crate::js::trim(e).to_lowercase()).filter(|e| re.is_match(e)).take(10).collect()
}

pub struct Joined {
    pub member: Value,
    pub joined: bool,
}

/// Add someone to a server. Checks bans, pauses and limits; the caller has checked the way in.
#[allow(clippy::too_many_arguments)]
pub fn add_member(sr: &Db, store: &Store, server: &Value, user: &Value, listed: bool, admin_emails: &[String], now: i64, via_invite: &str) -> Result<Joined> {
    if server["status"] == "deleting" {
        return Err(ApiError::new(404, "SERVER_NOT_FOUND", "Server not found."));
    }
    let sid = id_of(server).to_string();
    let uid = to_js_string(user.get("id"));
    if let Some(existing) = member_row(sr, &sid, &uid)? {
        return Ok(Joined { member: existing, joined: false });
    }
    if truthy(server.get("joins_paused")) {
        return Err(ApiError::new(403, "JOINS_PAUSED", "This server isn't taking new members at the moment."));
    }
    let banned = sr.filter("ServerBan", json!({ "server_id": sid, "user_id": uid }), "created_date", 5)?;
    let live: Vec<&Value> = banned.iter().filter(|b| !truthy(b.get("expires_at")) || platform_ms(&b["expires_at"]) > now as f64).collect();
    if !live.is_empty() {
        return Err(ApiError::new(403, "BANNED", "You can't join this server."));
    }
    for b in &banned {
        let _ = sr.delete("ServerBan", id_of(b));
    }
    if n(server.get("member_count")) >= MEMBERS_PER_SERVER {
        return Err(ApiError::new(409, "SERVER_FULL", "This server is full."));
    }
    if sr.filter("ServerMember", json!({ "user_id": uid }), "created_date", SERVERS_PER_USER + 1)?.len() >= SERVERS_PER_USER {
        return Err(ApiError::new(409, "TOO_MANY_SERVERS", &format!("You can be in up to {SERVERS_PER_USER} servers. Leave one first.")));
    }
    let mut role_ids: Vec<Value> = Vec::new();
    let mut make_owner = false;
    if truthy(server.get("is_default")) && !admin_emails.is_empty() {
        let mut names: Vec<String> = Vec::new();
        if truthy(user.get("email")) {
            names.push(to_js_string(user.get("email")).to_lowercase());
        }
        if user["role"] == "admin" {
            if let Some(p) = sr.first("Profile", json!({ "user_id": uid }), "created_date")? {
                if truthy(p.get("username_key")) {
                    names.push(to_js_string(p.get("username_key")).to_lowercase());
                }
            }
        }
        if let Some(m) = admin_emails.iter().find(|e| names.contains(e)) {
            if let Some(admin) = sr.first("Role", json!({ "server_id": sid, "template_key": "admin" }), "created_date")? {
                role_ids.push(admin["id"].clone());
            }
            if !truthy(server.get("owner_id")) && *m == admin_emails[0] {
                make_owner = true;
            }
        }
    }
    let created = sr.create("ServerMember", json!({
        "server_id": sid, "user_id": uid, "role_ids": role_ids, "joined_at": iso(now), "listed": listed || !role_ids.is_empty(),
        "rules_accepted_at": "", "timeout_until": "", "key_status": "pending", "via_invite": via_invite,
    }))?;
    let rows = with_row(sr.filter("ServerMember", json!({ "server_id": sid, "user_id": uid }), "created_date", 5)?, &created);
    if rows[0]["id"] != created["id"] {
        sr.delete("ServerMember", id_of(&created))?;
        return Ok(Joined { member: rows[0].clone(), joined: false });
    }
    let mut update = json!({ "member_count": crate::js::number_value(n(server.get("member_count")) + 1.0), "keys_pending_at": iso(now) });
    if make_owner {
        update["owner_id"] = json!(uid);
        update["changed_at"] = json!(iso(now));
    }
    sr.update("Server", &sid, update)?;
    refresh_access(sr, store, &uid)?;
    Ok(Joined { member: created, joined: true })
}

/// Undo a join that turned out not to be allowed (an invite used up a moment earlier, CV-13).
pub fn undo_join(sr: &Db, store: &Store, server: &Value, member: &Value) -> Result<()> {
    let _ = sr.delete("ServerMember", id_of(member));
    let fresh = sr.get("Server", id_of(server)).unwrap_or_else(|| server.clone());
    let c = n(fresh.get("member_count"));
    let c = if c == 0.0 { 1.0 } else { c };
    sr.update("Server", id_of(server), json!({ "member_count": crate::js::number_value((c - 1.0).max(0.0)) }))?;
    refresh_access(sr, store, &to_js_string(member.get("user_id")))?;
    Ok(())
}

/// Members who can see a private channel, worked out from their effective permissions there.
pub fn members_who_can_see(sr: &Db, parts: &Parts, channel: &Value) -> Result<Vec<Value>> {
    let sid = id_of(&parts.server).to_string();
    let everyone = parts.roles.iter().find(|r| truthy(r.get("is_everyone")));
    let ev = everyone.and_then(|e| channel["overwrites"].as_array().and_then(|o| o.iter().find(|o| o["role_id"] == e["id"])));
    let num = |v: Option<&Value>| n(v) as i64;
    let everyone_sees = everyone.is_some_and(|e| ((num(e.get("permissions")) & !ev.map_or(0, |x| num(x.get("deny")))) | ev.map_or(0, |x| num(x.get("allow")))) & p::VIEW_CHANNEL != 0);
    let mut found: Vec<Value> = Vec::new();
    if everyone_sees {
        found.extend(sr.filter("ServerMember", json!({ "server_id": sid }), "joined_at", 10_000)?);
    } else {
        let role_ids: Vec<Value> = parts.roles.iter().filter(|r| !truthy(r.get("is_everyone"))).map(|r| r["id"].clone()).collect();
        if !role_ids.is_empty() {
            found.extend(sr.filter("ServerMember", json!({ "server_id": sid, "role_ids": { "$in": role_ids } }), "joined_at", 10_000)?);
        }
    }
    let owner = to_js_string(parts.server.get("owner_id"));
    if truthy(parts.server.get("owner_id")) && !found.iter().any(|m| m["user_id"] == owner.as_str()) {
        if let Some(o) = member_row(sr, &sid, &owner)? {
            found.push(o);
        }
    }
    Ok(found.into_iter().filter(|m| has(channel_permissions(&parts.server, &parts.roles, Some(m), channel), p::VIEW_CHANNEL)).collect())
}

// ---------- moderation (servers/moderation.ts) ----------

pub const MOD_PERMS: i64 = p::MANAGE_MESSAGES | p::KICK_MEMBERS | p::BAN_MEMBERS | p::TIMEOUT_MEMBERS | p::ADMINISTRATOR;
pub const CASE_ACTIONS: [&str; 8] = ["warn", "note", "timeout", "kick", "ban", "unban", "purge", "quarantine"];

/// `options.includes(v) ? v : fallback`.
fn pick(v: &Value, options: &[f64], fallback: f64) -> Value {
    match v.as_f64() {
        Some(x) if options.contains(&x) => crate::js::number_value(x),
        _ => crate::js::number_value(fallback),
    }
}

pub fn policy_of(server: &Value) -> Value {
    let raw = if truthy(server.get("mod_policy")) { server["mod_policy"].clone() } else { json!({}) };
    clean_policy(&raw)
}

pub fn clean_policy(raw: &Value) -> Value {
    let thresholds: Vec<Value> = match raw["thresholds"].as_array() {
        Some(list) => {
            let mut t: Vec<Value> = list
                .iter()
                .filter(|t| truthy(Some(t)) && t["count"].as_f64().is_some_and(|c| c.fract() == 0.0 && (1.0..=20.0).contains(&c)) && t["action"].as_str().is_some_and(|a| ["timeout", "kick", "ban"].contains(&a)))
                .take(5)
                .map(|t| {
                    let action = t["action"].as_str().unwrap_or("");
                    let minutes = if action == "kick" { json!(0) } else { pick(&t["minutes"], &[0.0, 10.0, 60.0, 360.0, 1440.0, 10080.0, 40320.0], if action == "timeout" { 60.0 } else { 0.0 }) };
                    json!({ "count": crate::js::number_value(t["count"].as_f64().unwrap_or(0.0)), "action": action, "minutes": minutes })
                })
                .filter(|t| !(t["action"] == "timeout" && t["minutes"] == 0))
                .collect();
            t.sort_by(|a, b| a["count"].as_f64().partial_cmp(&b["count"].as_f64()).unwrap_or(std::cmp::Ordering::Equal));
            t
        }
        None => vec![json!({ "count": 3, "action": "timeout", "minutes": 60 }), json!({ "count": 5, "action": "kick", "minutes": 0 })],
    };
    let mut unique: Vec<Value> = Vec::new();
    for t in thresholds {
        if !unique.iter().any(|x| x["count"] == t["count"]) {
            unique.push(t);
        }
    }
    let obj = |v: &Value| if truthy(Some(v)) { v.clone() } else { json!({}) };
    let (f, r, nk) = (obj(&raw["flood"]), obj(&raw["raid"]), obj(&raw["nuke"]));
    json!({
        "warn_window_days": pick(&raw["warn_window_days"], &[7.0, 30.0, 90.0, 365.0], 30.0),
        "thresholds": unique,
        "flood": { "enabled": f["enabled"] == true, "messages": pick(&f["messages"], &[5.0, 8.0, 12.0, 20.0], 8.0), "seconds": pick(&f["seconds"], &[5.0, 10.0, 30.0], 10.0), "timeout_minutes": pick(&f["timeout_minutes"], &[1.0, 5.0, 10.0, 60.0], 10.0) },
        "raid": { "enabled": r["enabled"] == true, "joins_per_minute": pick(&r["joins_per_minute"], &[5.0, 10.0, 20.0, 50.0], 10.0) },
        "nuke": { "enabled": nk["enabled"] != false, "limit": pick(&nk["limit"], &[3.0, 5.0, 10.0, 20.0], 10.0) },
    })
}

/// Write a case. `reason`: accepted item fields (or {}).
#[allow(clippy::too_many_arguments)]
pub fn log_case(sr: &Db, server: &Value, action: &str, target_id: &str, actor_id: &str, minutes: Value, reason: &Value, report_id: &str, now: i64) -> Result<Value> {
    let last = sr.first("ModCase", json!({ "server_id": server["id"] }), "-case_number")?;
    let number = last.map_or(0.0, |l| n(l.get("case_number"))) + 1.0;
    let row = merged(
        &json!({ "server_id": server["id"], "case_number": crate::js::number_value(number), "action": action, "target_id": target_id, "actor_id": actor_id, "minutes": minutes, "report_id": report_id, "active": action == "warn" }),
        reason,
    );
    sr.create("ModCase", merged(&row, &json!({ "created_at": iso(now) })))
}

/// After a warning: active warnings in the window, and the punishment set for exactly that many.
pub fn threshold_for(sr: &Db, server: &Value, target_id: &str, now: i64) -> Result<(usize, Option<Value>)> {
    let policy = policy_of(server);
    let since = now as f64 - policy["warn_window_days"].as_f64().unwrap_or(30.0) * 86_400_000.0;
    let warns = sr
        .filter("ModCase", json!({ "server_id": server["id"], "target_id": target_id, "action": "warn", "active": true }), "-created_date", 100)?
        .iter()
        .filter(|c| crate::dates::parse(&to_js_string(Some(&or(&c["created_at"], c["created_date"].clone())))).unwrap_or(f64::NAN) >= since)
        .count();
    let step = policy["thresholds"].as_array().and_then(|t| t.iter().find(|t| t["count"].as_f64() == Some(warns as f64)).cloned());
    Ok((warns, step))
}

const DESTRUCTIVE: [&str; 6] = ["member_ban", "member_kick", "member_timeout", "channel_delete", "role_delete", "messages_purge"];

/// Staff limits, before a destructive action by anyone but the owner.
pub fn guard_nuke(sr: &Db, parts: &Parts, member: &Value, now: i64, remove_roles: &dyn Fn() -> Result<()>) -> Result<()> {
    if member["user_id"] == parts.server["owner_id"] {
        return Ok(());
    }
    let policy = policy_of(&parts.server);
    if policy["nuke"]["enabled"] != true {
        return Ok(());
    }
    let since = iso(now - 600_000);
    let recent = sr
        .filter("AuditEntry", json!({ "server_id": parts.server["id"], "actor_id": member["user_id"], "created_date": { "$gte": since.trim_end_matches('Z') } }), "-created_date", 100)?
        .iter()
        .filter(|a| a["action"].as_str().is_some_and(|x| DESTRUCTIVE.contains(&x)))
        .count();
    if (recent as f64) < policy["nuke"]["limit"].as_f64().unwrap_or(10.0) {
        return Ok(());
    }
    remove_roles()?;
    let target = to_js_string(member.get("user_id"));
    log_case(sr, &parts.server, "quarantine", &target, "system", json!(0), &json!({}), "", now)?;
    audit(sr, &parts.server, "system", "staff_quarantine", "member", &target, &format!("{recent} actions in 10 min"), now)?;
    Err(ApiError::new(403, "STAFF_LIMIT", "That's more than this server allows in ten minutes, so your roles have been taken away until the owner checks."))
}

/// Raid protection, after someone joins.
pub fn check_raid(sr: &Db, server: &Value, now: i64) -> Result<bool> {
    let policy = policy_of(server);
    if policy["raid"]["enabled"] != true || truthy(server.get("joins_paused")) {
        return Ok(false);
    }
    let limit = policy["raid"]["joins_per_minute"].as_f64().unwrap_or(10.0) as usize;
    let joins = count_since(sr, "ServerMember", json!({ "server_id": server["id"] }), now - 60_000, limit + 1)?;
    if joins <= limit {
        return Ok(false);
    }
    sr.update("Server", id_of(server), json!({ "joins_paused": true, "raid_detected_at": iso(now) }))?;
    audit(sr, server, "system", "raid_lockdown", "server", id_of(server), &format!("{joins} joins in a minute"), now)?;
    Ok(true)
}

/// Flood protection, before a message: the policy's flood settings if this member just went over.
pub fn flooded_by(sr: &Db, server: &Value, user_id: &str, now: i64) -> Result<Option<Value>> {
    let policy = policy_of(server);
    if policy["flood"]["enabled"] != true {
        return Ok(None);
    }
    let msgs = policy["flood"]["messages"].as_f64().unwrap_or(8.0) as usize;
    let secs = policy["flood"]["seconds"].as_f64().unwrap_or(10.0) as i64;
    let count = count_since(sr, "ServerMessage", json!({ "server_id": server["id"], "sender_id": user_id, "kind": { "$in": ["message", "post"] } }), now - secs * 1000, msgs + 1)?;
    Ok((count >= msgs).then(|| policy["flood"].clone()))
}

/// `to_int` re-exported for callers that check permission numbers.
pub fn perm_int(v: &Value) -> i64 {
    to_int(v)
}
