//! Server templates (base44/shared/servers/template.ts): the roles and channels a server starts with.
use serde_json::{json, Value};

use crate::permissions::{p, DEFAULT_EVERYONE};

fn read_only() -> Value {
    json!({ "role": "everyone", "deny": p::SEND_MESSAGES | p::CREATE_POSTS })
}
fn staff_only() -> Value {
    json!([{ "role": "everyone", "deny": p::VIEW_CHANNEL }, { "role": "moderator", "allow": p::VIEW_CHANNEL }, { "role": "support", "allow": p::VIEW_CHANNEL }])
}
fn moderator() -> i64 {
    p::MANAGE_MESSAGES | p::KICK_MEMBERS | p::BAN_MEMBERS | p::TIMEOUT_MEMBERS | p::VIEW_AUDIT_LOG | p::MANAGE_NICKNAMES | p::MANAGE_TICKETS | p::MANAGE_KEYS | p::MENTION_EVERYONE | p::MANAGE_INVITES
}

/// The Commonveil community server everyone joins.
pub fn community() -> Value {
    json!({
        "key": "commonveil-community",
        "everyone": DEFAULT_EVERYONE,
        "roles": [
            { "key": "admin", "position": 30, "permissions": p::ADMINISTRATOR, "hoist": true, "mentionable": true },
            { "key": "moderator", "position": 20, "permissions": moderator(), "hoist": true, "mentionable": true },
            { "key": "support", "position": 10, "permissions": p::MANAGE_TICKETS | p::MANAGE_MESSAGES, "hoist": true, "mentionable": true },
        ],
        "channels": [
            { "key": "start", "kind": "category" },
            { "key": "welcome", "kind": "announcement", "parent": "start", "history": "full", "overwrites": [read_only()] },
            { "key": "rules", "kind": "rules", "parent": "start", "history": "full", "overwrites": [read_only()] },
            { "key": "announcements", "kind": "announcement", "parent": "start", "history": "full", "overwrites": [read_only()] },
            { "key": "community", "kind": "category" },
            { "key": "general", "kind": "text", "parent": "community", "history": "joined" },
            { "key": "introductions", "kind": "text", "parent": "community", "history": "full", "slowmode": 60 },
            { "key": "privacy-news", "kind": "text", "parent": "community", "history": "full" },
            { "key": "off-topic", "kind": "text", "parent": "community", "history": "joined" },
            { "key": "learn", "kind": "category" },
            { "key": "guides", "kind": "forum", "parent": "learn", "history": "full" },
            { "key": "show-and-tell", "kind": "forum", "parent": "learn", "history": "full" },
            { "key": "ideas", "kind": "forum", "parent": "learn", "history": "full" },
            { "key": "support", "kind": "category" },
            { "key": "help", "kind": "forum", "parent": "support", "history": "full" },
            { "key": "support-tickets", "kind": "tickets", "parent": "support", "history": "full" },
            { "key": "bug-reports", "kind": "forum", "parent": "support", "history": "full" },
            { "key": "voice", "kind": "category" },
            { "key": "lounge", "kind": "voice", "parent": "voice" },
            { "key": "co-working", "kind": "voice", "parent": "voice" },
            { "key": "help-desk", "kind": "voice", "parent": "voice" },
            { "key": "staff", "kind": "category" },
            { "key": "staff-chat", "kind": "text", "parent": "staff", "history": "full", "overwrites": staff_only() },
            { "key": "mod-notes", "kind": "text", "parent": "staff", "history": "full", "overwrites": staff_only() },
            { "key": "staff-voice", "kind": "voice", "parent": "staff", "overwrites": staff_only() },
        ],
    })
}

pub fn starter_blank() -> Value {
    json!({
        "key": "blank",
        "everyone": DEFAULT_EVERYONE,
        "roles": [

        ],
        "channels": [
            { "key": "text", "kind": "category" },
            { "key": "general", "kind": "text", "parent": "text", "history": "joined" },
            { "key": "voice-channels", "kind": "category" },
            { "key": "general-voice", "kind": "voice", "parent": "voice-channels" },
        ],
    })
}

pub fn starter_friends() -> Value {
    json!({
        "key": "friends",
        "everyone": DEFAULT_EVERYONE,
        "roles": [

        ],
        "channels": [
            { "key": "text", "kind": "category" },
            { "key": "general", "kind": "text", "parent": "text", "history": "joined" },
            { "key": "plans", "kind": "text", "parent": "text", "history": "full" },
            { "key": "voice-channels", "kind": "category" },
            { "key": "hangout", "kind": "voice", "parent": "voice-channels" },
        ],
    })
}

pub fn starter_study() -> Value {
    json!({
        "key": "study",
        "everyone": DEFAULT_EVERYONE,
        "roles": [

        ],
        "channels": [
            { "key": "info", "kind": "category" },
            { "key": "welcome", "kind": "announcement", "parent": "info", "history": "full", "overwrites": [read_only()] },
            { "key": "study", "kind": "category" },
            { "key": "general", "kind": "text", "parent": "study", "history": "joined" },
            { "key": "notes", "kind": "forum", "parent": "study", "history": "full" },
            { "key": "homework-help", "kind": "forum", "parent": "study", "history": "full" },
            { "key": "voice-channels", "kind": "category" },
            { "key": "study-room", "kind": "voice", "parent": "voice-channels" },
        ],
    })
}

pub fn starter_community() -> Value {
    json!({
        "key": "community",
        "everyone": DEFAULT_EVERYONE,
        "roles": [
            { "key": "moderator", "position": 20, "permissions": moderator(), "hoist": true, "mentionable": true },
            { "key": "support", "position": 10, "permissions": p::MANAGE_TICKETS | p::MANAGE_MESSAGES, "hoist": true, "mentionable": true },
        ],
        "channels": [
            { "key": "start", "kind": "category" },
            { "key": "welcome", "kind": "announcement", "parent": "start", "history": "full", "overwrites": [read_only()] },
            { "key": "rules", "kind": "rules", "parent": "start", "history": "full", "overwrites": [read_only()] },
            { "key": "announcements", "kind": "announcement", "parent": "start", "history": "full", "overwrites": [read_only()] },
            { "key": "community", "kind": "category" },
            { "key": "general", "kind": "text", "parent": "community", "history": "joined" },
            { "key": "introductions", "kind": "text", "parent": "community", "history": "full" },
            { "key": "support", "kind": "category" },
            { "key": "help", "kind": "forum", "parent": "support", "history": "full" },
            { "key": "support-tickets", "kind": "tickets", "parent": "support", "history": "full" },
            { "key": "voice", "kind": "category" },
            { "key": "lounge", "kind": "voice", "parent": "voice" },
            { "key": "staff", "kind": "category" },
            { "key": "staff-chat", "kind": "text", "parent": "staff", "history": "full", "overwrites": staff_only() },
        ],
    })
}

/// A template people can start their own server from.
pub fn starter(key: &str) -> Option<Value> {
    Some(match key {
        "blank" => starter_blank(),
        "friends" => starter_friends(),
        "study" => starter_study(),
        "community" => starter_community(),
        _ => return None,
    })
}
