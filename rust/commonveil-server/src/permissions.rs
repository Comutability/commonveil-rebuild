//! Server permissions (base44/shared/permissions.ts): bit flags, roles and channel overwrites.
use serde_json::Value;

pub mod p {
    pub const VIEW_CHANNEL: i64 = 1 << 0;
    pub const SEND_MESSAGES: i64 = 1 << 1;
    pub const ADD_REACTIONS: i64 = 1 << 2;
    pub const CREATE_POSTS: i64 = 1 << 3;
    pub const CONNECT: i64 = 1 << 4;
    pub const SPEAK: i64 = 1 << 5;
    pub const MENTION_EVERYONE: i64 = 1 << 6;
    pub const MANAGE_MESSAGES: i64 = 1 << 7;
    pub const MANAGE_CHANNELS: i64 = 1 << 8;
    pub const MANAGE_ROLES: i64 = 1 << 9;
    pub const MANAGE_SERVER: i64 = 1 << 10;
    pub const CREATE_INVITES: i64 = 1 << 11;
    pub const MANAGE_INVITES: i64 = 1 << 12;
    pub const KICK_MEMBERS: i64 = 1 << 13;
    pub const BAN_MEMBERS: i64 = 1 << 14;
    pub const TIMEOUT_MEMBERS: i64 = 1 << 15;
    pub const VIEW_AUDIT_LOG: i64 = 1 << 16;
    pub const MANAGE_TICKETS: i64 = 1 << 17;
    pub const MANAGE_NICKNAMES: i64 = 1 << 18;
    pub const CHANGE_NICKNAME: i64 = 1 << 19;
    pub const MANAGE_KEYS: i64 = 1 << 20;
    pub const READ_HISTORY: i64 = 1 << 21;
    pub const MANAGE_EXPRESSIONS: i64 = 1 << 22;
    pub const MANAGE_EVENTS: i64 = 1 << 23;
    pub const MUTE_MEMBERS: i64 = 1 << 24;
    pub const MANAGE_THREADS: i64 = 1 << 25;
    pub const ADMINISTRATOR: i64 = 1 << 30;
}
use p::*;

pub const ALL_PERMISSIONS: i64 = ((1 << 26) - 1) | ADMINISTRATOR;
pub const DEFAULT_EVERYONE: i64 = VIEW_CHANNEL | SEND_MESSAGES | ADD_REACTIONS | CREATE_POSTS | CONNECT | SPEAK | CREATE_INVITES | CHANGE_NICKNAME | READ_HISTORY;
pub const STAFF_PERMISSIONS: i64 = ADMINISTRATOR | MANAGE_SERVER | MANAGE_ROLES | MANAGE_CHANNELS | MANAGE_MESSAGES | KICK_MEMBERS | BAN_MEMBERS | TIMEOUT_MEMBERS | MANAGE_TICKETS;
pub const SERVER_ONLY: i64 = ADMINISTRATOR | MANAGE_SERVER | MANAGE_ROLES | KICK_MEMBERS | BAN_MEMBERS | TIMEOUT_MEMBERS | VIEW_AUDIT_LOG | MANAGE_NICKNAMES | CHANGE_NICKNAME | MANAGE_KEYS | MANAGE_INVITES | MANAGE_EXPRESSIONS | MANAGE_EVENTS;

/// `Number.isInteger(v) ? v & ALL_PERMISSIONS : 0` (with JavaScript's 32-bit `&`).
pub fn to_int(v: &Value) -> i64 {
    match v.as_f64() {
        Some(f) if f.is_finite() && f.fract() == 0.0 => {
            let m = f.rem_euclid(4_294_967_296.0) as u32 as i32 as i64;
            m & ALL_PERMISSIONS
        }
        _ => 0,
    }
}

fn position(r: &Value) -> f64 {
    let n = crate::js::to_number(r.get("position"));
    if n.is_nan() || n == 0.0 { 0.0 } else { n }
}

fn roles_of<'a>(roles: &'a [Value], member: &Value) -> (Option<&'a Value>, Vec<&'a Value>) {
    let everyone = roles.iter().find(|r| crate::js::truthy(r.get("is_everyone")));
    let ids: Vec<&Value> = member["role_ids"].as_array().map(|a| a.iter().collect()).unwrap_or_default();
    let mut mine: Vec<&Value> = roles.iter().filter(|r| !crate::js::truthy(r.get("is_everyone")) && ids.contains(&&r["id"])).collect();
    mine.sort_by(|a, b| position(b).partial_cmp(&position(a)).unwrap_or(std::cmp::Ordering::Equal));
    (everyone, mine)
}

fn is_owner(server: &Value, member: &Value) -> bool {
    crate::js::truthy(server.get("owner_id")) && member["user_id"] == server["owner_id"]
}

pub fn base_permissions(server: &Value, roles: &[Value], member: Option<&Value>) -> i64 {
    let Some(member) = member else { return 0 };
    if is_owner(server, member) {
        return ALL_PERMISSIONS;
    }
    let (everyone, mine) = roles_of(roles, member);
    let mut perms = everyone.map_or(0, |e| to_int(&e["permissions"]));
    for r in mine {
        perms |= to_int(&r["permissions"]);
    }
    if perms & ADMINISTRATOR != 0 { ALL_PERMISSIONS } else { perms }
}

pub fn channel_permissions(server: &Value, roles: &[Value], member: Option<&Value>, channel: &Value) -> i64 {
    let base = base_permissions(server, roles, member);
    let Some(member) = member else { return base };
    if base == ALL_PERMISSIONS {
        return base;
    }
    let (everyone, mine) = roles_of(roles, member);
    let overwrites: Vec<&Value> = channel["overwrites"].as_array().map(|a| a.iter().collect()).unwrap_or_default();
    let channel_bits = ALL_PERMISSIONS & !SERVER_ONLY;
    let mut perms = base;
    if let Some(ev) = everyone.and_then(|e| overwrites.iter().find(|o| o["role_id"] == e["id"])) {
        perms = (perms & !(to_int(&ev["deny"]) & channel_bits)) | (to_int(&ev["allow"]) & channel_bits);
    }
    let (mut allow, mut deny) = (0, 0);
    let my_ids: Vec<&Value> = mine.iter().map(|r| &r["id"]).collect();
    for o in &overwrites {
        if !my_ids.contains(&&o["role_id"]) {
            continue;
        }
        allow |= to_int(&o["allow"]);
        deny |= to_int(&o["deny"]);
    }
    perms = (perms & !(deny & channel_bits)) | (allow & channel_bits);
    if perms & VIEW_CHANNEL == 0 { 0 } else { perms }
}

pub fn has(perms: i64, bit: i64) -> bool {
    perms & bit == bit
}

pub fn top_position(server: &Value, roles: &[Value], member: Option<&Value>) -> f64 {
    let Some(member) = member else { return -1.0 };
    if is_owner(server, member) {
        return 9_007_199_254_740_991.0;
    }
    roles_of(roles, member).1.first().map_or(0.0, |r| position(r))
}

pub fn is_staff(server: &Value, roles: &[Value], member: Option<&Value>) -> bool {
    base_permissions(server, roles, member) & STAFF_PERMISSIONS != 0
}

pub fn channel_is_private(roles: &[Value], channel: &Value) -> bool {
    if channel["kind"] == "category" {
        return false;
    }
    let Some(everyone) = roles.iter().find(|r| crate::js::truthy(r.get("is_everyone"))) else { return true };
    let mut perms = to_int(&everyone["permissions"]);
    if perms & ADMINISTRATOR != 0 {
        return false;
    }
    let overwrites: Vec<&Value> = channel["overwrites"].as_array().map(|a| a.iter().collect()).unwrap_or_default();
    if let Some(ev) = overwrites.iter().find(|o| o["role_id"] == everyone["id"]) {
        perms = (perms & !to_int(&ev["deny"])) | to_int(&ev["allow"]);
    }
    if perms & VIEW_CHANNEL == 0 {
        return true;
    }
    overwrites.iter().any(|o| o["role_id"] != everyone["id"] && to_int(&o["deny"]) & VIEW_CHANNEL != 0)
}
