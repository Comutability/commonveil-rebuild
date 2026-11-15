//! Servers, invites and channel messages over HTTP against the Node.js server: the same script
//! (real key generations, sealed grants, encrypted items and signatures from Secure Net's Rust
//! client code) runs against both, each on its own fresh site, and every reply must match once
//! random values are blanked.
use std::collections::HashMap;
use std::path::Path;

use secure_net_core::cv::server_keys;
use serde_json::{json, Value};

mod common;
use common::{compare, iso_at, now, ready, start, succeeded, Flow, Kit};

struct Who<'a> {
    token: String,
    id: String,
    kit: &'a Kit,
}

/// The chain keys a member's app holds: chain id -> (generation, key).
type Keys = HashMap<String, (i64, Vec<u8>)>;

fn rid(n: u32) -> String {
    format!("item-{n:04}-aaaaaaaaaaaa")
}

impl Who<'_> {
    fn signed(&self, action: &str, payload: Value) -> Value {
        self.kit.signed(&self.id, action, 0, payload)
    }
    fn recipient(&self) -> Value {
        self.kit.recipient(&self.id)
    }
    /// A new generation of a chain, with copies for these members.
    fn generation(&self, server_id: &str, chain_id: &str, generation: i64, to: &[&Who], keys: &mut Keys) -> Value {
        // A chain from another server is signed as that server's, then sent here.
        let owner = chain_id.split('.').next().unwrap_or(server_id);
        let (st, key) = server_keys::make_generation(owner, chain_id, generation, &self.id, &self.kit.d[0], &iso_at(now())).unwrap();
        let grants: Vec<Value> = to.iter().map(|w| self.grant(server_id, chain_id, generation, &key[..], w)).collect();
        keys.insert(chain_id.to_string(), (generation, key.to_vec()));
        self.signed("create_generation", json!({ "server_id": server_id, "generation": st, "grants": grants }))
    }
    fn grant(&self, server_id: &str, chain_id: &str, generation: i64, key: &[u8], to: &Who) -> Value {
        server_keys::make_grant(server_keys::GrantArgs { server_id, chain_id, generation, step: 0, key, recipient: &to.recipient(), user_id: &self.id, device: &self.kit.d[0], now: now() }).unwrap()
    }
    /// An encrypted, signed item for `accept_item` (and the signature kind it's checked under).
    fn item(&self, kind: &str, server_id: &str, channel_id: &str, item_id: &str, chain_id: &str, keys: &Keys) -> Value {
        let (generation, key) = keys.get(chain_id).cloned().unwrap_or((0, vec![0; 32]));
        let device_id = self.kit.d[0]["device_id"].as_str().unwrap();
        let scope = json!({ "kind": if kind == "message" { "message" } else { kind }, "server_id": server_id, "channel_id": channel_id, "item_id": item_id, "sender_id": self.id, "device_id": device_id, "chain_id": chain_id, "generation": generation, "step": 0 });
        let env = server_keys::encrypt_server_item(&scope, &key, &json!({ "text": "hello" })).unwrap().to_string();
        let at = iso_at(now());
        let sig = server_keys::sign_server_item(self.kit.d[0]["sign_priv"].as_str().unwrap(), &json!({ "kind": kind, "serverId": server_id, "channelId": channel_id, "itemId": item_id, "senderId": self.id, "deviceId": device_id, "envelopeJson": env, "sentAt": at })).unwrap();
        json!({ "envelope": env, "item_id": item_id, "device_id": device_id, "sent_at": at, "signature": sig })
    }
    #[allow(clippy::too_many_arguments)]
    fn message(&self, server_id: &str, channel_id: &str, msg_id: &str, chain_id: &str, keys: &Keys, kind: &str, thread: &str) -> Value {
        let mut it = self.item("message", server_id, channel_id, msg_id, chain_id, keys);
        let o = it.as_object_mut().unwrap();
        o.remove("item_id");
        let mut body = json!({ "action": "send", "server_id": server_id, "channel_id": channel_id, "msg_id": msg_id, "kind": kind });
        for (k, v) in o.iter() {
            body[k] = v.clone();
        }
        if !thread.is_empty() {
            body["thread_id"] = json!(thread);
        }
        body
    }
}

fn channel(state: &Value, key: &str) -> Value {
    state["channels"].as_array().and_then(|c| c.iter().find(|c| c["template_key"] == key).cloned()).unwrap_or(Value::Null)
}
fn role(state: &Value, key: &str) -> Value {
    state["roles"].as_array().and_then(|c| c.iter().find(|c| c["template_key"] == key).cloned()).unwrap_or(Value::Null)
}
fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

fn script(port: u16, data: &Path, kits: &[Kit]) -> Vec<Value> {
    let mut f = Flow::new(port);
    let setup = std::fs::read_to_string(data.join("setup-code")).unwrap().trim().to_string();
    let mut people: Vec<Who> = Vec::new();
    for (i, name) in ["alice", "bob", "carol", "dave", "erin"].iter().enumerate() {
        let mut reg = json!({ "action": "register", "username": name, "password": "a long enough password", "age_confirmed": true });
        if i == 0 {
            reg["setup_code"] = json!(setup);
        }
        let r = f.call("identity", &format!("register {name}"), "", reg);
        people.push(Who { token: s(&r["session"]["access_token"]), id: s(&r["session"]["user_id"]), kit: &kits[i] });
        f.call("keys", &format!("{name} sets up encryption"), &people[i].token, kits[i].init(&people[i].id));
    }
    let (alice, bob, carol, dave, erin) = (&people[0], &people[1], &people[2], &people[3], &people[4]);
    let sv = |f: &mut Flow, step: &str, w: &Who, body: Value| f.call("servers", step, &w.token, body);
    let ch = |f: &mut Flow, step: &str, w: &Who, body: Value| f.call("channels", step, &w.token, body);

    // ----- the community server, and making a server -----
    sv(&mut f, "list: joins the community server", alice, json!({ "action": "list" }));
    sv(&mut f, "list again", alice, json!({ "action": "list" }));
    sv(&mut f, "create: unsigned", bob, json!({ "action": "create_server" }));
    sv(&mut f, "create: bad template", bob, bob.signed("create_server", json!({ "template": "castle" })));
    let made = sv(&mut f, "create", bob, bob.signed("create_server", json!({ "template": "community" })));
    let sid = s(&made["server_id"]);
    let st = sv(&mut f, "state", bob, json!({ "action": "state", "server_id": sid }));
    sv(&mut f, "state: not a member", carol, json!({ "action": "state", "server_id": sid }));
    let (h, l) = (format!("{sid}.h"), format!("{sid}.l"));
    let staff_chat = channel(&st, "staff-chat");
    let private_chain = format!("{sid}.c.{}", s(&staff_chat["id"]));

    // ----- keys -----
    let mut bob_keys: Keys = HashMap::new();
    let mut gen = bob.generation(&sid, &h, 0, &[bob], &mut bob_keys);
    gen["payload"] = json!(gen["payload"].as_str().unwrap().replace("\"generation\":0,", "\"generation\":1,"));
    sv(&mut f, "generation: bent payload", bob, gen);
    sv(&mut f, "generation: none for me", bob, bob.generation(&sid, &h, 0, &[], &mut bob_keys));
    sv(&mut f, "generation: skips one", bob, bob.generation(&sid, &h, 1, &[bob], &mut bob_keys));
    sv(&mut f, "generation: another server's chain", bob, bob.generation(&sid, "otherserver0001.h", 0, &[bob], &mut bob_keys));
    sv(&mut f, "generation: history", bob, bob.generation(&sid, &h, 0, &[bob], &mut bob_keys));
    sv(&mut f, "generation: taken", bob, bob.generation(&sid, &h, 0, &[bob], &mut bob_keys));
    sv(&mut f, "generation: live", bob, bob.generation(&sid, &l, 0, &[bob], &mut bob_keys));
    sv(&mut f, "generation: staff chat", bob, bob.generation(&sid, &private_chain, 0, &[bob], &mut bob_keys));
    sv(&mut f, "profile", bob, bob.signed("set_server_profile", json!({ "server_id": sid, "item": bob.item("server", &sid, "", &rid(1), &h, &bob_keys) })));
    sv(&mut f, "profile: wrong chain", bob, bob.signed("set_server_profile", json!({ "server_id": sid, "item": bob.item("server", &sid, "", &rid(2), &l, &bob_keys) })));
    sv(&mut f, "rules", bob, bob.signed("set_server_rules", json!({ "server_id": sid, "item": bob.item("rules", &sid, "", &rid(3), &h, &bob_keys) })));
    sv(&mut f, "emoji", bob, bob.signed("set_server_set", json!({ "server_id": sid, "slot": "emoji", "item": bob.item("emoji", &sid, "", &rid(4), &h, &bob_keys) })));
    sv(&mut f, "emoji: cleared", bob, bob.signed("set_server_set", json!({ "server_id": sid, "slot": "emoji", "item": null })));
    sv(&mut f, "set: bad slot", bob, bob.signed("set_server_set", json!({ "server_id": sid, "slot": "music", "item": null })));

    // ----- invites and joining -----
    sv(&mut f, "invite: bad code", bob, bob.signed("create_invite", json!({ "server_id": sid, "code": "short" })));
    sv(&mut f, "invite: bad expiry", bob, bob.signed("create_invite", json!({ "server_id": sid, "code": "abcdefgh12", "max_age_seconds": 5 })));
    sv(&mut f, "invite", bob, bob.signed("create_invite", json!({ "server_id": sid, "code": "abcdefgh12", "max_age_seconds": 3600, "max_uses": 1, "preview": "sealed" })));
    sv(&mut f, "invite: code taken", bob, bob.signed("create_invite", json!({ "server_id": sid, "code": "abcdefgh12" })));
    sv(&mut f, "invite 2", bob, bob.signed("create_invite", json!({ "server_id": sid, "code": "abcdefgh34", "max_uses": 0 })));
    f.call("invite", "invite info (signed out)", "", json!({ "action": "invite_info", "code": "abcdefgh12" }));
    f.call("invite", "invite info: unknown", "", json!({ "action": "invite_info", "code": "zzzzzzzz99" }));
    sv(&mut f, "invites", bob, json!({ "action": "invites", "server_id": sid }));
    sv(&mut f, "join: no invite", carol, carol.signed("join_server", json!({ "server_id": sid })));
    sv(&mut f, "join: bad invite", carol, carol.signed("join_server", json!({ "invite_code": "nope" })));
    sv(&mut f, "carol joins", carol, carol.signed("join_server", json!({ "invite_code": "abcdefgh12" })));
    sv(&mut f, "carol joins again", carol, carol.signed("join_server", json!({ "invite_code": "abcdefgh34" })));
    sv(&mut f, "dave: used up", dave, dave.signed("join_server", json!({ "invite_code": "abcdefgh12" })));
    sv(&mut f, "dave joins", dave, dave.signed("join_server", json!({ "invite_code": "abcdefgh34" })));
    sv(&mut f, "erin joins", erin, erin.signed("join_server", json!({ "invite_code": "abcdefgh34" })));
    f.call("invite", "invite info after", "", json!({ "action": "invite_info", "code": "abcdefgh34" }));
    sv(&mut f, "pending grants", bob, json!({ "action": "pending_grants", "server_id": sid }));
    let grants: Vec<Value> = [carol, dave, erin].iter().flat_map(|w| [&h, &l].map(|c| bob.grant(&sid, c, 0, &bob_keys[c].1, w))).collect();
    sv(&mut f, "grant: not held", carol, carol.signed("grant_keys", json!({ "server_id": sid, "grants": [bob.grant(&sid, &h, 0, &bob_keys[&h].1, dave)] })));
    sv(&mut f, "grant", bob, bob.signed("grant_keys", json!({ "server_id": sid, "grants": grants })));
    sv(&mut f, "grant again (skipped)", bob, bob.signed("grant_keys", json!({ "server_id": sid, "grants": grants[..2] })));
    sv(&mut f, "grant: private chain to someone who can't see it", bob, bob.signed("grant_keys", json!({ "server_id": sid, "grants": [bob.grant(&sid, &private_chain, 0, &bob_keys[&private_chain].1, carol)] })));
    sv(&mut f, "pending grants: none", bob, json!({ "action": "pending_grants", "server_id": sid }));
    let cst = sv(&mut f, "carol's state", carol, json!({ "action": "state", "server_id": sid }));
    let keys_of = |_w: &Who| bob_keys.iter().filter(|(c, _)| **c != private_chain).map(|(c, k)| (c.clone(), k.clone())).collect::<Keys>();
    let carol_keys = keys_of(carol);
    let dave_keys = keys_of(dave);
    sv(&mut f, "accept rules", carol, carol.signed("accept_rules", json!({ "server_id": sid })));
    sv(&mut f, "listed", carol, carol.signed("set_listed", json!({ "server_id": sid, "listed": true })));
    sv(&mut f, "listed: not a yes or no", carol, carol.signed("set_listed", json!({ "server_id": sid, "listed": 1 })));
    sv(&mut f, "nickname", carol, carol.signed("set_nickname", json!({ "server_id": sid, "item": carol.item("nick", &sid, "", &rid(5), &h, &carol_keys) })));
    sv(&mut f, "nickname for someone else", carol, carol.signed("set_nickname", json!({ "server_id": sid, "user_id": dave.id, "item": null })));
    sv(&mut f, "nickname cleared", carol, carol.signed("set_nickname", json!({ "server_id": sid, "item": null })));
    sv(&mut f, "members", dave, json!({ "action": "members", "server_id": sid }));
    sv(&mut f, "member", dave, json!({ "action": "member", "server_id": sid, "user_id": carol.id }));
    sv(&mut f, "member: not in it", dave, json!({ "action": "member", "server_id": sid, "user_id": alice.id }));

    // ----- channel messages -----
    let general = s(&channel(&cst, "general")["id"]);
    let intro = s(&channel(&cst, "introductions")["id"]);
    let help = s(&channel(&cst, "help")["id"]);
    let welcome = s(&channel(&cst, "welcome")["id"]);
    let first = f.call("messages", "poll: start", &dave.token, json!({ "action": "poll" }));
    ch(&mut f, "send", carol, carol.message(&sid, &general, &rid(10), &l, &carol_keys, "message", ""));
    ch(&mut f, "send: retried", carol, carol.message(&sid, &general, &rid(10), &l, &carol_keys, "message", ""));
    ch(&mut f, "send: wrong chain", carol, carol.message(&sid, &general, &rid(11), &h, &carol_keys, "message", ""));
    ch(&mut f, "send: read-only channel", carol, carol.message(&sid, &welcome, &rid(12), &h, &carol_keys, "message", ""));
    ch(&mut f, "react in the read-only channel", carol, carol.message(&sid, &welcome, &rid(13), &h, &carol_keys, "reaction", ""));
    ch(&mut f, "send: rules not accepted", dave, dave.message(&sid, &general, &rid(14), &l, &dave_keys, "message", ""));
    ch(&mut f, "send: bad kind", carol, carol.message(&sid, &general, &rid(15), &l, &carol_keys, "shout", ""));
    ch(&mut f, "send: private channel unseen", carol, carol.message(&sid, &s(&staff_chat["id"]), &rid(16), &private_chain, &carol_keys, "message", ""));
    ch(&mut f, "slow mode", carol, carol.message(&sid, &intro, &rid(17), &h, &carol_keys, "message", ""));
    ch(&mut f, "slow mode: too soon", carol, carol.message(&sid, &intro, &rid(18), &h, &carol_keys, "message", ""));
    ch(&mut f, "forum: reply without a post", carol, carol.message(&sid, &help, &rid(19), &h, &carol_keys, "message", ""));
    ch(&mut f, "forum: post", carol, carol.message(&sid, &help, &rid(20), &h, &carol_keys, "post", ""));
    ch(&mut f, "forum: reply", carol, carol.message(&sid, &help, &rid(21), &h, &carol_keys, "message", &rid(20)));
    ch(&mut f, "thread on a message", carol, carol.message(&sid, &general, &rid(22), &l, &carol_keys, "message", &rid(10)));
    ch(&mut f, "list", dave, json!({ "action": "list", "server_id": sid, "channel_id": general }));
    ch(&mut f, "list: a thread", dave, json!({ "action": "list", "server_id": sid, "channel_id": general, "thread_id": rid(10) }));
    ch(&mut f, "list: posts", dave, json!({ "action": "list", "server_id": sid, "channel_id": help, "posts": true }));
    ch(&mut f, "list: bad limit", dave, json!({ "action": "list", "server_id": sid, "channel_id": general, "limit": 0 }));
    ch(&mut f, "list: not a member", alice, json!({ "action": "list", "server_id": sid, "channel_id": general }));
    ch(&mut f, "pin: not a moderator", carol, carol.signed("pin_server_message", json!({ "server_id": sid, "channel_id": general, "msg_id": rid(10) })));
    ch(&mut f, "pin", bob, bob.signed("pin_server_message", json!({ "server_id": sid, "channel_id": general, "msg_id": rid(10) })));
    ch(&mut f, "pins", dave, json!({ "action": "pins", "server_id": sid, "channel_id": general }));
    ch(&mut f, "lock a thread", bob, bob.signed("lock_thread", json!({ "server_id": sid, "channel_id": help, "msg_id": rid(20) })));
    ch(&mut f, "locked: reply refused", carol, carol.message(&sid, &help, &rid(23), &h, &carol_keys, "message", &rid(20)));
    ch(&mut f, "delete someone else's", dave, dave.signed("delete_server_message", json!({ "server_id": sid, "channel_id": general, "msg_id": rid(10) })));
    ch(&mut f, "delete as a moderator", bob, bob.signed("delete_server_message", json!({ "server_id": sid, "channel_id": general, "msg_id": rid(22) })));
    ch(&mut f, "delete my own", carol, carol.signed("delete_server_message", json!({ "server_id": sid, "channel_id": intro, "msg_id": rid(17) })));
    f.call("messages", "poll servers", &dave.token, json!({ "action": "poll", "since": first["cursor"], "servers_since": "2000-01-01T00:00:00", "server_changes_since": first["server_changes_cursor"] }));
    f.call("messages", "poll servers: bad cursor", &dave.token, json!({ "action": "poll", "since": first["cursor"], "servers_since": 5 }));

    // ----- roles and channels -----
    let moderator = role(&st, "moderator");
    sv(&mut f, "role: not allowed", carol, carol.signed("create_role", json!({ "server_id": sid })));
    let made_role = sv(&mut f, "role", bob, bob.signed("create_role", json!({ "server_id": sid, "permissions": 2048, "hoist": true, "item": bob.item("role", &sid, "", &rid(30), &h, &bob_keys) })));
    sv(&mut f, "role: bad permissions", bob, bob.signed("create_role", json!({ "server_id": sid, "permissions": -1 })));
    sv(&mut f, "update role", bob, bob.signed("update_role", json!({ "server_id": sid, "role_id": made_role["role"]["id"], "mentionable": true, "item": null })));
    sv(&mut f, "reorder roles", bob, bob.signed("reorder_roles", json!({ "server_id": sid, "order": [{ "id": made_role["role"]["id"], "position": 5 }] })));
    sv(&mut f, "give carol moderator", bob, bob.signed("set_member_roles", json!({ "server_id": sid, "user_id": carol.id, "role_ids": [moderator["id"]] })));
    sv(&mut f, "carol can't give a role above hers", carol, carol.signed("set_member_roles", json!({ "server_id": sid, "user_id": dave.id, "role_ids": [moderator["id"]] })));
    sv(&mut f, "carol's new view", carol, json!({ "action": "state", "server_id": sid }));
    sv(&mut f, "pending grants: carol now sees staff chat", bob, json!({ "action": "pending_grants", "server_id": sid }));
    sv(&mut f, "channel: bad kind", bob, bob.signed("create_channel", json!({ "server_id": sid, "kind": "garden" })));
    let made_channel = sv(&mut f, "channel", bob, bob.signed("create_channel", json!({ "server_id": sid, "kind": "text", "history": "full", "item": bob.item("channel", &sid, "", &rid(31), &h, &bob_keys) })));
    let new_ch = made_channel["channel"]["id"].clone();
    sv(&mut f, "channel: slow mode", bob, bob.signed("update_channel", json!({ "server_id": sid, "channel_id": new_ch, "slowmode_seconds": 30, "sensitive": true })));
    sv(&mut f, "channel: bad slow mode", bob, bob.signed("update_channel", json!({ "server_id": sid, "channel_id": new_ch, "slowmode_seconds": 7 })));
    let everyone = role(&st, "everyone");
    sv(&mut f, "channel: made private", bob, bob.signed("update_channel", json!({ "server_id": sid, "channel_id": new_ch, "overwrites": [{ "role_id": everyone["id"], "deny": 1 }, { "role_id": moderator["id"], "allow": 1 }] })));
    sv(&mut f, "channel: carol can't lift a deny she can't give", carol, carol.signed("update_channel", json!({ "server_id": sid, "channel_id": new_ch, "overwrites": [] })));
    sv(&mut f, "reorder channels", bob, bob.signed("reorder_channels", json!({ "server_id": sid, "order": [{ "id": new_ch, "position": 0 }] })));
    sv(&mut f, "delete the channel", bob, bob.signed("delete_channel", json!({ "server_id": sid, "channel_id": new_ch })));
    sv(&mut f, "delete the role", bob, bob.signed("delete_role", json!({ "server_id": sid, "role_id": made_role["role"]["id"] })));

    // ----- moderation -----
    sv(&mut f, "timeout dave", carol, carol.signed("timeout_member", json!({ "server_id": sid, "user_id": dave.id, "minutes": 10 })));
    ch(&mut f, "timed out: can't post", dave, dave.message(&sid, &general, &rid(40), &l, &dave_keys, "message", ""));
    sv(&mut f, "end the timeout", carol, carol.signed("timeout_member", json!({ "server_id": sid, "user_id": dave.id, "minutes": 0 })));
    sv(&mut f, "kick: the owner", carol, carol.signed("kick_member", json!({ "server_id": sid, "user_id": bob.id })));
    sv(&mut f, "kick erin", carol, carol.signed("kick_member", json!({ "server_id": sid, "user_id": erin.id })));
    sv(&mut f, "ban dave", carol, carol.signed("ban_member", json!({ "server_id": sid, "user_id": dave.id, "delete_seconds": 3600, "reason": carol.item("ban", &sid, "", &rid(41), &h, &carol_keys) })));
    sv(&mut f, "ban: bad length", carol, carol.signed("ban_member", json!({ "server_id": sid, "user_id": erin.id, "minutes": 5 })));
    sv(&mut f, "bans", carol, json!({ "action": "bans", "server_id": sid }));
    sv(&mut f, "dave can't come back", dave, dave.signed("join_server", json!({ "invite_code": "abcdefgh34" })));
    sv(&mut f, "unban", carol, carol.signed("unban_member", json!({ "server_id": sid, "user_id": dave.id })));
    sv(&mut f, "state: keys due for renewal", bob, json!({ "action": "state", "server_id": sid }));
    sv(&mut f, "audit log", bob, json!({ "action": "audit_log", "server_id": sid }));
    sv(&mut f, "audit log: not allowed", erin, json!({ "action": "audit_log", "server_id": sid }));

    // ----- settings and discovery -----
    sv(&mut f, "settings: nothing", bob, bob.signed("update_server_settings", json!({ "server_id": sid })));
    sv(&mut f, "settings: listed without a name", bob, bob.signed("update_server_settings", json!({ "server_id": sid, "discoverable": true })));
    sv(&mut f, "settings: listed", bob, bob.signed("update_server_settings", json!({ "server_id": sid, "discoverable": true, "join_mode": "open", "public": { "name": " Tea Club ", "description": "Tea", "tags": ["friends", "friends", "local"], "icon": "T", "color": "#aabbcc" }, "member_list": "staff_only", "audit_retention_days": 30 })));
    sv(&mut f, "settings: bad colour", bob, bob.signed("update_server_settings", json!({ "server_id": sid, "public": { "name": "x", "color": "red" } })));
    sv(&mut f, "discover", erin, json!({ "action": "discover" }));
    sv(&mut f, "discover: a tag", erin, json!({ "action": "discover", "tag": "local" }));
    sv(&mut f, "erin joins an open server", erin, erin.signed("join_server", json!({ "server_id": sid })));
    sv(&mut f, "members: staff only", erin, json!({ "action": "members", "server_id": sid }));

    // ----- tickets -----
    let tickets = s(&channel(&cst, "support-tickets")["id"]);
    sv(&mut f, "ticket: not a tickets channel", erin, erin.signed("open_ticket", json!({ "server_id": sid, "channel_id": general })));
    let t = sv(&mut f, "ticket", erin, erin.signed("open_ticket", json!({ "server_id": sid, "channel_id": tickets })));
    sv(&mut f, "tickets", erin, json!({ "action": "tickets", "server_id": sid }));
    sv(&mut f, "close the ticket", erin, erin.signed("set_ticket_status", json!({ "server_id": sid, "conversation_id": t["conversation_id"], "status": "closed" })));
    sv(&mut f, "ticket: bad status", erin, erin.signed("set_ticket_status", json!({ "server_id": sid, "conversation_id": t["conversation_id"], "status": "gone" })));

    // ----- keys that don't open, leaving, handing on, deleting -----
    let mine = sv(&mut f, "erin's state", erin, json!({ "action": "state", "server_id": sid }));
    let ids: Vec<Value> = mine["grants"].as_array().map(|g| g.iter().map(|x| x["id"].clone()).collect()).unwrap_or_default();
    sv(&mut f, "request keys", erin, erin.signed("request_keys", json!({ "server_id": sid, "grant_ids": [], "bad_grant_ids": ids })));
    sv(&mut f, "revoke an invite", bob, bob.signed("revoke_invite", json!({ "server_id": sid, "code": "abcdefgh34" })));
    sv(&mut f, "owner can't leave", bob, bob.signed("leave_server", json!({ "server_id": sid })));
    sv(&mut f, "hand on: not the owner", carol, carol.signed("transfer_ownership", json!({ "server_id": sid, "user_id": carol.id })));
    sv(&mut f, "hand on", bob, bob.signed("transfer_ownership", json!({ "server_id": sid, "user_id": carol.id })));
    sv(&mut f, "bob leaves", bob, bob.signed("leave_server", json!({ "server_id": sid })));
    sv(&mut f, "delete: not confirmed", carol, carol.signed("delete_server", json!({ "server_id": sid })));
    sv(&mut f, "delete", carol, carol.signed("delete_server", json!({ "server_id": sid, "confirm": "DELETE" })));
    sv(&mut f, "gone", carol, json!({ "action": "state", "server_id": sid }));
    sv(&mut f, "list after", erin, json!({ "action": "list" }));
    f.log
}

#[test]
fn servers_and_channels_answer_as_the_node_server_does() {
    if !ready() {
        eprintln!("skipped: node, the npm packages or dist-selfhost aren't there");
        return;
    }
    let kits: Vec<Kit> = (0..5).map(|_| Kit::new()).collect();
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (node, rust) = (start(true, d1.path()), start(false, d2.path()));
    let (a, b) = (script(node.1, d1.path(), &kits), script(rust.1, d2.path(), &kits));
    let ok = compare(&a, &b);
    assert!(ok > 60, "only {ok} steps succeeded");
    succeeded(&a, &["create", "generation: history", "generation: live", "carol joins", "dave joins", "grant", "send", "forum: post", "forum: reply", "pin", "role", "give carol moderator", "channel", "channel: made private", "ban dave", "unban", "settings: listed", "ticket", "hand on", "delete", "poll servers"]);
}
