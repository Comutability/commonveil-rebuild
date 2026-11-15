//! Profiles and account keys over HTTP against the Node.js server: the same script (real keys,
//! statements, certificates and proofs made with Secure Net's Rust client code) runs against both,
//! each on its own fresh site, and every reply must match once random values are blanked.
use std::path::Path;

use secure_net_core::cv::{device, identity, keyring, recovery};
use serde_json::{json, Value};

mod common;
use common::{compare, ready, start, succeeded, Flow};

/// Key material made once and used on both sites (only the account ids differ).
struct Kit {
    rk: recovery::RecoveryKeys,
    v: Vec<Value>,
    d: Vec<Value>,
}

fn now() -> i64 {
    commonveil_server::sessions::now_ms()
}

impl Kit {
    fn new() -> Self {
        let rk = recovery::derive_recovery_key(&recovery::generate_recovery_phrase()).unwrap();
        let v = (1..=3).map(|n| keyring::create_key_version(n, now()).unwrap()).collect();
        let d = (1..=5).map(|n| device::create_device_keys(&format!("Device {n}"), now()).unwrap()).collect();
        Self { rk, v, d }
    }
    fn statement(&self, uid: &str, v: usize, signer: usize, anchor: bool) -> Value {
        let mut st = identity::make_account_statement(uid, &self.v[v], &self.rk.public_key, &self.rk.kem_public_key, &self.v[signer], now()).unwrap();
        if anchor {
            st["recovery_mac"] = json!(recovery::recovery_anchor_mac(&self.rk.anchor_key[..], &st).unwrap());
        }
        st
    }
    fn cert(&self, uid: &str, d: usize, v: usize) -> Value {
        identity::make_device_cert(uid, &self.d[d], &self.v[v], self.d[d]["kem_pub"].as_str().unwrap(), now()).unwrap()
    }
    fn keyring(&self, uid: &str, versions: &[usize]) -> Value {
        let mut k = keyring::new_keyring(uid, self.v[versions[0]].clone()).unwrap();
        for v in &versions[1..] {
            k = keyring::with_version(&k, self.v[*v].clone()).unwrap();
        }
        k
    }
    fn recovery_env(&self, k: &Value, v: usize) -> Value {
        let mut e = keyring::seal_keyring_for_recovery(k, &self.rk.public_key, Some(&self.rk.kem_public_key)).unwrap();
        e["key_sign_pub"] = self.v[v]["sign_pub"].clone();
        e
    }
    fn device_env(&self, k: &Value, d: usize, v: usize) -> Value {
        let dev = &self.d[d];
        let mut e = keyring::seal_keyring_to_device(k, dev["device_id"].as_str().unwrap(), dev["box_pub"].as_str().unwrap(), dev["kem_pub"].as_str()).unwrap();
        e["key_sign_pub"] = self.v[v]["sign_pub"].clone();
        e["device_id"] = dev["device_id"].clone();
        e
    }
    fn public(&self, d: usize) -> Value {
        device::public_device(&self.d[d])
    }
    fn id(&self, d: usize) -> Value {
        self.d[d]["device_id"].clone()
    }
    /// A request signed by device `d`.
    fn signed(&self, uid: &str, action: &str, d: usize, payload: Value) -> Value {
        let text = payload.to_string();
        json!({ "action": action, "payload": text, "proof": identity::make_device_proof(uid, &self.d[d], action, &text, now()).unwrap() })
    }
}

fn script(port: u16, data: &Path, kit: &Kit) -> Vec<Value> {
    let mut f = Flow::new(port);
    let setup = std::fs::read_to_string(data.join("setup-code")).unwrap().trim().to_string();
    let reg = |name: &str| json!({ "action": "register", "username": name, "password": "a long enough password", "age_confirmed": true });
    let mut first = reg("alice");
    first["setup_code"] = json!(setup);
    let token = |r: &Value| r["session"]["access_token"].as_str().unwrap_or("").to_string();
    let alice = token(&f.call("identity", "register alice", "", first));
    let bob = token(&f.call("identity", "register bob", "", reg("bob")));
    let carol = token(&f.call("identity", "register carol", "", reg("carol")));
    let me = f.call("profile", "me", &bob, json!({ "action": "me" }));
    let uid = me["user"]["id"].as_str().unwrap_or("").to_string();
    let alice_id = f.call("profile", "me: alice", &alice, json!({ "action": "me" }))["user"]["id"].clone();
    let p = |f: &mut Flow, step: &str, t: &str, body: Value| f.call("profile", step, t, body);

    // ----- profiles -----
    p(&mut f, "nobody", "", json!({ "action": "me" }));
    p(&mut f, "claim again", &bob, json!({ "action": "claim_username", "username": "bobby" }));
    p(&mut f, "claim bad", &bob, json!({ "action": "claim_username", "username": "b" }));
    p(&mut f, "claim reserved", &bob, json!({ "action": "claim_username", "username": "Support" }));
    p(&mut f, "update: nothing", &bob, json!({ "action": "update" }));
    p(&mut f, "update: fields", &bob, json!({ "action": "update", "display_name": "  Bob \u{200b}B ", "bio": "Hello", "pronouns": "he/him", "accent_color": "teal", "avatar_emoji": "👍🏽", "profile_visibility": "conversations", "dm_policy": "servers", "default_listed": true }));
    p(&mut f, "update: blank name", &bob, json!({ "action": "update", "display_name": "" }));
    p(&mut f, "update: long bio", &bob, json!({ "action": "update", "bio": "x".repeat(281) }));
    p(&mut f, "update: bad colour", &bob, json!({ "action": "update", "accent_color": "red" }));
    p(&mut f, "update: two emoji", &bob, json!({ "action": "update", "avatar_emoji": "ab" }));
    p(&mut f, "update: emoji family", &bob, json!({ "action": "update", "avatar_emoji": "👨\u{200d}👩\u{200d}👧" }));
    p(&mut f, "update: picture", &bob, json!({ "action": "update", "avatar_image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB" }));
    p(&mut f, "update: not a picture", &bob, json!({ "action": "update", "avatar_image": "data:image/png;base64,AAAAAAAAAAAA" }));
    p(&mut f, "update: wrong type", &bob, json!({ "action": "update", "avatar_image": "data:image/gif;base64,R0lGODlh" }));
    p(&mut f, "update: picture removed", &bob, json!({ "action": "update", "avatar_image": null }));
    p(&mut f, "update: bad visibility", &bob, json!({ "action": "update", "profile_visibility": "all" }));
    p(&mut f, "update: bad listed", &bob, json!({ "action": "update", "default_listed": "yes" }));
    p(&mut f, "update: text not a string", &bob, json!({ "action": "update", "bio": 5 }));
    p(&mut f, "find bob as alice", &alice, json!({ "action": "find", "username": "@BOB" }));
    p(&mut f, "find self", &bob, json!({ "action": "find", "username": "bob" }));
    p(&mut f, "find nobody", &bob, json!({ "action": "find", "username": "nobody_x" }));
    p(&mut f, "find bad", &bob, json!({ "action": "find", "username": "x" }));
    p(&mut f, "get many", &bob, json!({ "action": "get_many", "user_ids": [uid, alice_id, uid, "nope"] }));
    p(&mut f, "get many: bad", &bob, json!({ "action": "get_many", "user_ids": "x" }));
    p(&mut f, "privacy report", &bob, json!({ "action": "privacy_report" }));
    p(&mut f, "auto delete: staff", &alice, json!({ "action": "set_auto_delete" }));
    p(&mut f, "auto delete: no proof", &bob, json!({ "action": "set_auto_delete", "payload": "{}" }));
    p(&mut f, "delete: staff", &alice, json!({ "action": "delete_account" }));

    // ----- keys: the first device -----
    let k = |f: &mut Flow, step: &str, body: Value| f.call("keys", step, &bob, body);
    k(&mut f, "status: empty", json!({ "action": "status" }));
    let kr1 = kit.keyring(&uid, &[0]);
    let init = |st: Value, cert: Value| json!({ "device": kit.public(0), "statement": st, "cert": cert, "recovery": kit.recovery_env(&kr1, 0) });
    k(&mut f, "init: no anchor", kit.signed(&uid, "init_account", 0, init(kit.statement(&uid, 0, 0, false), kit.cert(&uid, 0, 0))));
    k(&mut f, "init: proof by another device", kit.signed(&uid, "init_account", 1, init(kit.statement(&uid, 0, 0, true), kit.cert(&uid, 0, 0))));
    k(&mut f, "init: wrong action", kit.signed(&uid, "register_device", 0, init(kit.statement(&uid, 0, 0, true), kit.cert(&uid, 0, 0))));
    k(&mut f, "init: cert for another device", kit.signed(&uid, "init_account", 0, init(kit.statement(&uid, 0, 0, true), kit.cert(&uid, 1, 0))));
    let mut bent = kit.statement(&uid, 0, 0, true);
    bent["issued_at"] = json!("2026-01-01T00:00:00.000Z");
    k(&mut f, "init: statement altered", kit.signed(&uid, "init_account", 0, init(bent, kit.cert(&uid, 0, 0))));
    let mut stale = init(kit.statement(&uid, 0, 0, true), kit.cert(&uid, 0, 0));
    stale["recovery"]["keyring_version"] = json!(2);
    k(&mut f, "init: stale backup", kit.signed(&uid, "init_account", 0, stale));
    let mut bad_ct = init(kit.statement(&uid, 0, 0, true), kit.cert(&uid, 0, 0));
    bad_ct["recovery"]["sealed"]["iv"] = json!("AAAA");
    k(&mut f, "init: bad ciphertext", kit.signed(&uid, "init_account", 0, bad_ct));
    k(&mut f, "init", kit.signed(&uid, "init_account", 0, init(kit.statement(&uid, 0, 0, true), kit.cert(&uid, 0, 0))));
    k(&mut f, "init again", kit.signed(&uid, "init_account", 0, init(kit.statement(&uid, 0, 0, true), kit.cert(&uid, 0, 0))));
    k(&mut f, "status", json!({ "action": "status" }));
    p(&mut f, "me with keys", &bob, json!({ "action": "me" }));

    // ----- linking a second device -----
    k(&mut f, "register D2", kit.signed(&uid, "register_device", 1, json!({ "device": kit.public(1) })));
    k(&mut f, "register D2 again", kit.signed(&uid, "register_device", 1, json!({ "device": kit.public(1) })));
    k(&mut f, "sync D2: pending", json!({ "action": "device_sync", "device_id": kit.id(1) }));
    k(&mut f, "sync unknown", json!({ "action": "device_sync", "device_id": "unknown-device-00001" }));
    k(&mut f, "approve: from a pending device", kit.signed(&uid, "approve_device", 1, json!({ "target_device_id": kit.id(1) })));
    k(&mut f, "approve: wrong key version", kit.signed(&uid, "approve_device", 0, json!({ "target_device_id": kit.id(1), "cert": kit.cert(&uid, 1, 1), "envelope": kit.device_env(&kr1, 1, 0) })));
    k(&mut f, "approve D2", kit.signed(&uid, "approve_device", 0, json!({ "target_device_id": kit.id(1), "cert": kit.cert(&uid, 1, 0), "envelope": kit.device_env(&kr1, 1, 0) })));
    k(&mut f, "approve D2 again", kit.signed(&uid, "approve_device", 0, json!({ "target_device_id": kit.id(1), "cert": kit.cert(&uid, 1, 0), "envelope": kit.device_env(&kr1, 1, 0) })));
    k(&mut f, "sync D2: keys", json!({ "action": "device_sync", "device_id": kit.id(1) }));
    k(&mut f, "ack: unknown version", kit.signed(&uid, "ack_envelopes", 1, json!({ "keyring_version": 5 })));
    k(&mut f, "ack", kit.signed(&uid, "ack_envelopes", 1, json!({ "keyring_version": 1 })));
    k(&mut f, "send keyring to self", kit.signed(&uid, "send_keyring", 0, json!({ "target_device_id": kit.id(0) })));
    k(&mut f, "send keyring", kit.signed(&uid, "send_keyring", 0, json!({ "target_device_id": kit.id(1), "envelope": kit.device_env(&kr1, 1, 0) })));
    k(&mut f, "recovery backup", json!({ "action": "get_recovery" }));
    k(&mut f, "device kem: the same", kit.signed(&uid, "set_device_kem", 0, json!({ "kem_pub": kit.d[0]["kem_pub"] })));
    k(&mut f, "device kem: another", kit.signed(&uid, "set_device_kem", 0, json!({ "kem_pub": kit.d[1]["kem_pub"] })));
    k(&mut f, "device kem: not a key", kit.signed(&uid, "set_device_kem", 0, json!({ "kem_pub": "AAAA" })));

    // ----- a new key version -----
    let kr2 = kit.keyring(&uid, &[0, 1]);
    let rotate = |certs: Value, envs: Value| json!({ "statement": kit.statement(&uid, 1, 0, false), "certs": certs, "envelopes": envs, "recovery": kit.recovery_env(&kr2, 1) });
    k(&mut f, "rotate: a device missing", kit.signed(&uid, "rotate_keys", 0, rotate(json!([kit.cert(&uid, 0, 1)]), json!([kit.device_env(&kr2, 1, 1)]))));
    k(&mut f, "rotate: signed by itself", kit.signed(&uid, "rotate_keys", 0, json!({ "statement": kit.statement(&uid, 1, 1, false), "certs": [], "envelopes": [], "recovery": {} })));
    k(&mut f, "rotate", kit.signed(&uid, "rotate_keys", 0, rotate(json!([kit.cert(&uid, 0, 1), kit.cert(&uid, 1, 1)]), json!([kit.device_env(&kr2, 1, 1)]))));
    k(&mut f, "rotate again", kit.signed(&uid, "rotate_keys", 0, rotate(json!([kit.cert(&uid, 0, 1), kit.cert(&uid, 1, 1)]), json!([kit.device_env(&kr2, 1, 1)]))));
    k(&mut f, "status: version 2", json!({ "action": "status" }));

    // ----- denying, removing, recovering -----
    k(&mut f, "register D3", kit.signed(&uid, "register_device", 2, json!({ "device": kit.public(2) })));
    k(&mut f, "deny D3", kit.signed(&uid, "deny_device", 0, json!({ "target_device_id": kit.id(2) })));
    k(&mut f, "deny D3 again", kit.signed(&uid, "deny_device", 0, json!({ "target_device_id": kit.id(2) })));
    k(&mut f, "revoke unknown", kit.signed(&uid, "revoke_device", 0, json!({ "target_device_id": "unknown-device-00001" })));
    k(&mut f, "revoke D2", kit.signed(&uid, "revoke_device", 0, json!({ "target_device_id": kit.id(1) })));
    k(&mut f, "D2 can't act now", kit.signed(&uid, "ack_envelopes", 1, json!({ "keyring_version": 2 })));
    k(&mut f, "recover D4: old key", kit.signed(&uid, "recover_device", 3, json!({ "device": kit.public(3), "cert": kit.cert(&uid, 3, 0) })));
    k(&mut f, "recover D4", kit.signed(&uid, "recover_device", 3, json!({ "device": kit.public(3), "cert": kit.cert(&uid, 3, 1) })));
    k(&mut f, "recover D4 again", kit.signed(&uid, "recover_device", 3, json!({ "device": kit.public(3), "cert": kit.cert(&uid, 3, 1) })));

    // ----- resets -----
    let kr3 = kit.keyring(&uid, &[2]);
    let reset = |confirm: &str| json!({ "device": kit.public(4), "statement": kit.statement(&uid, 2, 2, true), "cert": kit.cert(&uid, 4, 2), "recovery": kit.recovery_env(&kr3, 2), "confirm": confirm });
    k(&mut f, "reset: not confirmed", kit.signed(&uid, "request_reset", 4, reset("reset")));
    k(&mut f, "reset: from an active device", kit.signed(&uid, "request_reset", 0, json!({ "device": kit.public(0), "statement": kit.statement(&uid, 2, 2, true), "cert": identity::make_device_cert(&uid, &kit.d[0], &kit.v[2], kit.d[0]["kem_pub"].as_str().unwrap(), now()).unwrap(), "recovery": kit.recovery_env(&kr3, 2), "confirm": "RESET" })));
    let req = k(&mut f, "reset", kit.signed(&uid, "request_reset", 4, reset("RESET")));
    let rid = req["request"]["id"].clone();
    k(&mut f, "status: a reset waiting", json!({ "action": "status" }));
    k(&mut f, "finish: too soon", kit.signed(&uid, "finish_reset", 4, json!({ "request_id": rid })));
    k(&mut f, "finish: another browser", kit.signed(&uid, "finish_reset", 3, json!({ "request_id": rid })));
    k(&mut f, "withdraw", kit.signed(&uid, "withdraw_reset", 4, json!({ "request_id": rid })));
    k(&mut f, "finish: withdrawn", kit.signed(&uid, "finish_reset", 4, json!({ "request_id": rid })));
    k(&mut f, "reset again", kit.signed(&uid, "request_reset", 4, reset("RESET")));
    k(&mut f, "cancel from a device", kit.signed(&uid, "cancel_reset", 0, json!({})));
    k(&mut f, "finish: unknown request", kit.signed(&uid, "finish_reset", 4, json!({ "request_id": "nope" })));

    // ----- what others see -----
    k(&mut f, "peer keys", json!({ "action": "peer_keys", "user_ids": [uid, alice_id] }));
    f.call("keys", "peer keys as alice", &alice, json!({ "action": "peer_keys", "user_ids": [uid] }));
    k(&mut f, "peer keys: too many", json!({ "action": "peer_keys", "user_ids": (0..51).map(|i| format!("u{i}")).collect::<Vec<_>>() }));

    // ----- auto-delete and deleting accounts -----
    p(&mut f, "auto delete: bad period", &bob, kit.signed(&uid, "set_auto_delete", 0, json!({ "days": 7 })));
    p(&mut f, "auto delete: on", &bob, kit.signed(&uid, "set_auto_delete", 0, json!({ "days": 183 })));
    p(&mut f, "me: auto delete", &bob, json!({ "action": "me" }));
    p(&mut f, "auto delete: off", &bob, kit.signed(&uid, "set_auto_delete", 0, json!({ "days": 0 })));
    p(&mut f, "delete carol: not confirmed", &carol, json!({ "action": "delete_account" }));
    p(&mut f, "delete carol: payload", &carol, json!({ "action": "delete_account", "payload": "{\"confirm\":\"no\"}" }));
    p(&mut f, "delete carol", &carol, json!({ "action": "delete_account", "confirm": "DELETE" }));
    p(&mut f, "carol is gone", &carol, json!({ "action": "me" }));
    p(&mut f, "carol's name is retired", &bob, json!({ "action": "find", "username": "carol" }));
    f.call("identity", "carol's name can't be taken", "", reg("carol"));
    p(&mut f, "delete bob: needs a device", &bob, json!({ "action": "delete_account", "confirm": "DELETE" }));
    p(&mut f, "delete bob", &bob, kit.signed(&uid, "delete_account", 0, json!({ "confirm": "DELETE" })));
    p(&mut f, "bob is gone", &bob, json!({ "action": "me" }));
    f.call("keys", "alice can't see bob's keys", &alice, json!({ "action": "peer_keys", "user_ids": [uid] }));
    f.log
}

#[test]
fn profiles_and_keys_answer_as_the_node_server_does() {
    if !ready() {
        eprintln!("skipped: node, the npm packages or dist-selfhost aren't there");
        return;
    }
    let kit = Kit::new();
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (node, rust) = (start(true, d1.path()), start(false, d2.path()));
    let (a, b) = (script(node.1, d1.path(), &kit), script(rust.1, d2.path(), &kit));
    let ok = compare(&a, &b);
    assert!(ok > 40, "only {ok} steps succeeded");
    succeeded(&a, &["init", "register D2", "approve D2", "sync D2: keys", "ack", "send keyring", "rotate", "deny D3", "revoke D2", "recover D4", "reset", "withdraw", "cancel from a device", "auto delete: on", "delete carol", "delete bob", "update: fields", "update: picture"]);
}
