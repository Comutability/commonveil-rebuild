//! Helpers for the scripts that exercise servers: people with keys, chain generations, grants,
//! encrypted items and channel messages made by Secure Net's Rust client code.
use std::collections::HashMap;

use secure_net_core::cv::server_keys;
use serde_json::{json, Value};

use super::{iso_at, now, Flow, Kit};

pub struct Who<'a> {
    pub token: String,
    pub id: String,
    pub kit: &'a Kit,
}

/// The chain keys a member's app holds: chain id -> (generation, key).
pub type Keys = HashMap<String, (i64, Vec<u8>)>;

pub fn rid(n: u32) -> String {
    format!("item-{n:04}-aaaaaaaaaaaa")
}

impl Who<'_> {
    pub fn signed(&self, action: &str, payload: Value) -> Value {
        self.kit.signed(&self.id, action, 0, payload)
    }
    pub fn recipient(&self) -> Value {
        self.kit.recipient(&self.id)
    }
    /// A new generation of a chain, with copies for these members.
    pub fn generation(&self, server_id: &str, chain_id: &str, generation: i64, to: &[&Who], keys: &mut Keys) -> Value {
        // A chain from another server is signed as that server's, then sent here.
        let owner = chain_id.split('.').next().unwrap_or(server_id);
        let (st, key) = server_keys::make_generation(owner, chain_id, generation, &self.id, &self.kit.d[0], &iso_at(now())).unwrap();
        let grants: Vec<Value> = to.iter().map(|w| self.grant(server_id, chain_id, generation, &key[..], w)).collect();
        keys.insert(chain_id.to_string(), (generation, key.to_vec()));
        self.signed("create_generation", json!({ "server_id": server_id, "generation": st, "grants": grants }))
    }
    pub fn grant(&self, server_id: &str, chain_id: &str, generation: i64, key: &[u8], to: &Who) -> Value {
        server_keys::make_grant(server_keys::GrantArgs { server_id, chain_id, generation, step: 0, key, recipient: &to.recipient(), user_id: &self.id, device: &self.kit.d[0], now: now() }).unwrap()
    }
    /// An encrypted, signed item for `accept_item` (and the signature kind it's checked under).
    pub fn item(&self, kind: &str, server_id: &str, channel_id: &str, item_id: &str, chain_id: &str, keys: &Keys) -> Value {
        let (generation, key) = keys.get(chain_id).cloned().unwrap_or((0, vec![0; 32]));
        let device_id = self.kit.d[0]["device_id"].as_str().unwrap();
        let scope = json!({ "kind": if kind == "message" { "message" } else { kind }, "server_id": server_id, "channel_id": channel_id, "item_id": item_id, "sender_id": self.id, "device_id": device_id, "chain_id": chain_id, "generation": generation, "step": 0 });
        let env = server_keys::encrypt_server_item(&scope, &key, &json!({ "text": "hello" })).unwrap().to_string();
        let at = iso_at(now());
        let sig = server_keys::sign_server_item(self.kit.d[0]["sign_priv"].as_str().unwrap(), &json!({ "kind": kind, "serverId": server_id, "channelId": channel_id, "itemId": item_id, "senderId": self.id, "deviceId": device_id, "envelopeJson": env, "sentAt": at })).unwrap();
        json!({ "envelope": env, "item_id": item_id, "device_id": device_id, "sent_at": at, "signature": sig })
    }
    #[allow(clippy::too_many_arguments)]
    pub fn message(&self, server_id: &str, channel_id: &str, msg_id: &str, chain_id: &str, keys: &Keys, kind: &str, thread: &str) -> Value {
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

pub fn channel(state: &Value, key: &str) -> Value {
    state["channels"].as_array().and_then(|c| c.iter().find(|c| c["template_key"] == key).cloned()).unwrap_or(Value::Null)
}
pub fn role(state: &Value, key: &str) -> Value {
    state["roles"].as_array().and_then(|c| c.iter().find(|c| c["template_key"] == key).cloned()).unwrap_or(Value::Null)
}
pub fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}


/// Register people (the first with the site's setup code) and set up their encryption.
pub fn people<'a>(f: &mut Flow, data: &std::path::Path, names: &[&str], kits: &'a [Kit]) -> Vec<Who<'a>> {
    let setup = std::fs::read_to_string(data.join("setup-code")).unwrap().trim().to_string();
    let mut out = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let mut reg = json!({ "action": "register", "username": name, "password": "a long enough password", "age_confirmed": true });
        if i == 0 {
            reg["setup_code"] = json!(setup);
        }
        let r = f.call("identity", &format!("register {name}"), "", reg);
        let who = Who { token: s(&r["session"]["access_token"]), id: s(&r["session"]["user_id"]), kit: &kits[i] };
        f.call("keys", &format!("{name} sets up encryption"), &who.token, kits[i].init(&who.id));
        out.push(who);
    }
    out
}
