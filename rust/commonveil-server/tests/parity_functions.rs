//! The backend functions over HTTP against the Node.js server: the same script of requests runs
//! against both, each on its own fresh site, and every reply must match once random values
//! (tokens, ids, codes, times) are blanked. Skipped when node, the npm packages or dist-selfhost
//! aren't there.
use std::path::Path;

use commonveil_server::crypto::{b64url, hash_password, sha256};
use commonveil_server::identity::owner_text;
use commonveil_server::store::{load_schemas, Store};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

mod common;
use common::{blank, post, ready, repo, start};

// ---------- a software passkey ----------

fn cbor_head(major: u8, n: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=255 => out.extend([m | 24, n as u8]),
        _ => {
            out.push(m | 25);
            out.extend((n as u16).to_be_bytes());
        }
    }
}
fn cbor_int(i: i64, out: &mut Vec<u8>) {
    if i >= 0 {
        cbor_head(0, i as u64, out)
    } else {
        cbor_head(1, (-1 - i) as u64, out)
    }
}
fn cbor_bytes(b: &[u8], out: &mut Vec<u8>) {
    cbor_head(2, b.len() as u64, out);
    out.extend_from_slice(b);
}
fn cbor_text(t: &str, out: &mut Vec<u8>) {
    cbor_head(3, t.len() as u64, out);
    out.extend_from_slice(t.as_bytes());
}

struct Passkey {
    key: p256::ecdsa::SigningKey,
    id: Vec<u8>,
    counter: u32,
}

impl Passkey {
    fn new(seed: u8) -> Self {
        Self {
            key: p256::ecdsa::SigningKey::from_bytes(&[seed; 32].into()).unwrap(),
            id: vec![seed; 20],
            counter: 0,
        }
    }
    fn client_data(typ: &str, challenge: &str) -> Vec<u8> {
        json!({ "type": typ, "challenge": challenge, "origin": "https://cv.example", "crossOrigin": false }).to_string().into_bytes()
    }
    fn create(&self, options: &Value) -> Value {
        let point = {
            use p256::elliptic_curve::sec1::ToSec1Point;
            self.key.verifying_key().as_affine().to_sec1_point(false)
        };
        let mut cose = Vec::new();
        cbor_head(5, 5, &mut cose);
        for (k, v) in [(1, 2), (3, -7), (-1, 1)] {
            cbor_int(k, &mut cose);
            cbor_int(v, &mut cose);
        }
        cbor_int(-2, &mut cose);
        cbor_bytes(point.x().unwrap(), &mut cose);
        cbor_int(-3, &mut cose);
        cbor_bytes(point.y().unwrap(), &mut cose);
        let mut auth = sha256(options["rp"]["id"].as_str().unwrap_or("").as_bytes()).to_vec();
        auth.push(0x01 | 0x04 | 0x08 | 0x40);
        auth.extend(0u32.to_be_bytes());
        auth.extend([0u8; 16]);
        auth.extend((self.id.len() as u16).to_be_bytes());
        auth.extend(&self.id);
        auth.extend(cose);
        let mut att = Vec::new();
        cbor_head(5, 3, &mut att);
        cbor_text("fmt", &mut att);
        cbor_text("none", &mut att);
        cbor_text("attStmt", &mut att);
        cbor_head(5, 0, &mut att);
        cbor_text("authData", &mut att);
        cbor_bytes(&auth, &mut att);
        let id = b64url(&self.id);
        json!({ "id": id, "rawId": id, "type": "public-key", "clientExtensionResults": {}, "response": {
            "clientDataJSON": b64url(&Self::client_data("webauthn.create", options["challenge"].as_str().unwrap_or(""))),
            "attestationObject": b64url(&att), "transports": ["internal", 7] } })
    }
    fn get(&mut self, options: &Value) -> Value {
        use p256::ecdsa::signature::Signer;
        self.counter += 1;
        let mut auth = sha256(options["rpId"].as_str().unwrap_or("").as_bytes()).to_vec();
        auth.push(0x01 | 0x04);
        auth.extend(self.counter.to_be_bytes());
        let cd = Self::client_data("webauthn.get", options["challenge"].as_str().unwrap_or(""));
        let mut signed = auth.clone();
        signed.extend(sha256(&cd));
        let sig: p256::ecdsa::Signature = self.key.sign(&signed);
        let id = b64url(&self.id);
        json!({ "id": id, "rawId": id, "type": "public-key", "clientExtensionResults": {}, "response": {
            "clientDataJSON": b64url(&cd), "authenticatorData": b64url(&auth), "signature": b64url(sig.to_der().as_bytes()), "userHandle": null } })
    }
}

// ---------- the script ----------

const CAROL: &str = "carolcarol000000";
const CAROL_DEVICE: &str = "carol-device-000001";

/// Carol is already on both sites, with an encryption device (so she can prove changes with it).
fn seed(data: &Path, device_pub: &str) {
    let s = Store::open(
        data.join("commonveil.db").to_str().unwrap(),
        load_schemas(&repo().join("base44/entities")),
    )
    .unwrap();
    s.create(
        "Person",
        &json!({ "role": "user", "email": "", "full_name": "" }),
        Some(CAROL),
    )
    .unwrap();
    s.create("Profile", &json!({ "user_id": CAROL, "username": "carol", "username_key": "carol", "display_name": "carol", "bio": "" }), None).unwrap();
    s.create("CvAccount", &json!({ "user_id": CAROL, "kind": "person", "password": hash_password("carols password", 1000), "owner_pub": "", "failed": 0, "security_epoch": 0 }), None).unwrap();
    s.create("Device", &json!({ "user_id": CAROL, "device_id": CAROL_DEVICE, "status": "active", "sign_pub": device_pub }), None).unwrap();
}

struct Flow {
    port: u16,
    log: Vec<Value>,
}

impl Flow {
    fn call(&mut self, step: &str, token: &str, body: Value) -> Value {
        let (status, reply) = post(
            self.port,
            "POST",
            "/api/functions/identity",
            token,
            &body.to_string(),
        );
        self.log
            .push(json!({ "step": step, "status": status, "reply": blank(&reply) }));
        reply
    }
    fn raw(&mut self, step: &str, method: &str, path: &str, body: &str) {
        let (status, reply) = post(self.port, method, path, "", body);
        self.log
            .push(json!({ "step": step, "status": status, "reply": blank(&reply) }));
    }
}

fn sig(key: &SigningKey, text: &str) -> String {
    b64url(&key.sign(text.as_bytes()).to_bytes())
}

fn proof(pkcs8: &str, action: &str, payload: &str, issued_at: &str) -> Value {
    use secure_net_core::cv;
    let nonce = cv::encoding::random_id(16);
    let text = cv::canonical::device_proof_text(&json!({ "user_id": CAROL, "device_id": CAROL_DEVICE, "action": action, "payload_hash": cv::encoding::sha256_b64(payload), "issued_at": issued_at, "nonce": nonce })).unwrap();
    json!({ "device_id": CAROL_DEVICE, "issued_at": issued_at, "nonce": nonce, "signature": cv::primitives::sign_with_pkcs8(pkcs8, text.as_bytes()).unwrap() })
}

fn now_iso() -> String {
    commonveil_server::store::iso(commonveil_server::sessions::now_ms())
}

fn script(port: u16, data: &Path, pkcs8: &str) -> Vec<Value> {
    let mut f = Flow {
        port,
        log: Vec::new(),
    };
    let setup = std::fs::read_to_string(data.join("setup-code"))
        .expect("the setup code is written")
        .trim()
        .to_lowercase();
    let reg = |name: &str, pw: &str| json!({ "action": "register", "username": name, "password": pw, "age_confirmed": true, "device_name": "Firefox on Linux" });

    // ----- the first account needs the setup code -----
    f.call("no action", "", json!({}));
    f.call("unknown action", "", json!({ "action": "nope" }));
    f.call(
        "register: no setup code",
        "",
        reg("alice", "long enough password"),
    );
    let mut wrong = reg("alice", "long enough password");
    wrong["setup_code"] = json!("AAAAA-BBBBB-CCCCC-DDDDD");
    f.call("register: wrong setup code", "", wrong);
    let mut taken = reg("carol", "long enough password");
    taken["setup_code"] = json!(setup);
    f.call("register: setup with a taken name", "", taken);
    f.call("register: weak password", "", reg("alice", "short"));
    f.call(
        "register: bad username",
        "",
        reg("a!", "long enough password"),
    );
    f.call(
        "register: no age",
        "",
        json!({ "action": "register", "username": "alice", "password": "long enough password" }),
    );
    let mut first = reg("@alice", "long enough password");
    first["setup_code"] = json!(setup);
    let alice = f.call("register: with the setup code", "", first.clone());
    f.call("register: the code again", "", first);
    let a_token = alice["session"]["access_token"]
        .as_str()
        .unwrap_or("")
        .to_string();
    f.call("me: alice", &a_token, json!({ "action": "me" }));
    f.call("me: nobody", "", json!({ "action": "me" }));

    // ----- open registration -----
    let bob = f.call("register: bob", "", reg("Bob_1", "bobs long password"));
    f.call("register: bob again", "", reg("bob_1", "another password"));
    f.call("register: reserved", "", reg("Admin", "another password"));
    let b_token = bob["session"]["access_token"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let b_device = bob["device"].clone();

    // ----- passwords -----
    f.call(
        "login: wrong password",
        "",
        json!({ "action": "login", "username": "bob_1", "password": "nope nope nope" }),
    );
    f.call(
        "login: nobody",
        "",
        json!({ "action": "login", "username": "nobody_here", "password": "nope nope nope" }),
    );
    f.call("login: known browser", "", json!({ "action": "login", "username": "@BOB_1", "password": "bobs long password", "device": b_device }));
    let v = f.call("login: new browser", "", json!({ "action": "login", "username": "bob_1", "password": "bobs long password", "device_name": "Phone" }));
    let vid = v["verify"]["id"].clone();
    f.call(
        "check: waiting",
        "",
        json!({ "action": "check", "id": vid, "method": "device" }),
    );
    f.call(
        "check: bad method",
        "",
        json!({ "action": "check", "id": vid, "method": "smoke" }),
    );
    let ap = f.call("approvals", &b_token, json!({ "action": "approvals" }));
    let ap_id = ap["approvals"][0]["id"].clone();
    f.call(
        "approve: unproven",
        &b_token,
        json!({ "action": "approve", "id": ap_id, "approve": true }),
    );
    f.call(
        "approve: wrong password",
        &b_token,
        json!({ "action": "approve", "id": ap_id, "approve": true, "password": "wrong wrong" }),
    );
    f.call("approve: with password", &b_token, json!({ "action": "approve", "id": ap_id, "approve": true, "password": "bobs long password" }));
    let phone = f.call(
        "check: approved",
        "",
        json!({ "action": "check", "id": vid, "method": "device" }),
    );
    f.call(
        "check: spent",
        "",
        json!({ "action": "check", "id": vid, "method": "device" }),
    );
    let v = f.call(
        "login: another browser",
        "",
        json!({ "action": "login", "username": "bob_1", "password": "bobs long password" }),
    );
    let vid2 = v["verify"]["id"].clone();
    let ap = f.call(
        "approvals: again",
        &b_token,
        json!({ "action": "approvals" }),
    );
    f.call(
        "approve: no",
        &b_token,
        json!({ "action": "approve", "id": ap["approvals"][0]["id"], "approve": false }),
    );
    f.call(
        "check: denied",
        "",
        json!({ "action": "check", "id": vid2, "method": "device" }),
    );
    f.call(
        "check: key without one",
        "",
        json!({ "action": "check", "id": vid2, "method": "key", "signature": "x" }),
    );

    // ----- tokens -----
    let refresh = phone["session"]["refresh_token"].clone();
    f.call(
        "refresh",
        "",
        json!({ "action": "refresh", "refresh_token": refresh }),
    );
    f.call(
        "refresh: bent",
        "",
        json!({ "action": "refresh", "refresh_token": "nope" }),
    );
    f.call(
        "logout",
        "",
        json!({ "action": "logout", "refresh_token": refresh }),
    );
    f.call(
        "refresh: after logout",
        "",
        json!({ "action": "refresh", "refresh_token": refresh }),
    );
    f.call("status: bob", &b_token, json!({ "action": "status" }));

    // ----- account changes -----
    f.call(
        "account: unknown",
        &b_token,
        json!({ "action": "account", "change": "nope" }),
    );
    f.call("account: set password (has one)", &b_token, json!({ "action": "account", "change": "set_password", "new_password": "a new long password" }));
    f.call(
        "account: confirm age (no)",
        &b_token,
        json!({ "action": "account", "change": "confirm_age" }),
    );
    f.call(
        "account: confirm age",
        &b_token,
        json!({ "action": "account", "change": "confirm_age", "age_confirmed": true }),
    );
    f.call("account: change password (wrong)", &b_token, json!({ "action": "account", "change": "change_password", "password": "nope", "new_password": "a new long password" }));
    f.call("account: change password (weak)", &b_token, json!({ "action": "account", "change": "change_password", "password": "bobs long password", "new_password": "short" }));
    let changed = f.call("account: change password", &b_token, json!({ "action": "account", "change": "change_password", "password": "bobs long password", "new_password": "bobs newer password" }));
    f.call(
        "account: old token after the epoch moved",
        &b_token,
        json!({ "action": "account", "change": "confirm_age", "age_confirmed": true }),
    );
    let b_token = changed["renewed_access"]["access_token"]
        .as_str()
        .unwrap_or("")
        .to_string();
    f.call(
        "account: remove email (no proof)",
        &b_token,
        json!({ "action": "account", "change": "remove_email" }),
    );
    f.call(
        "account: remove email (password)",
        &b_token,
        json!({ "action": "account", "change": "remove_email", "password": "bobs newer password" }),
    );
    f.call(
        "account: disconnect nothing",
        &b_token,
        json!({ "action": "account", "change": "disconnect_device", "id": "nope" }),
    );

    // ----- the owner key -----
    let owner = SigningKey::from_bytes(&[7; 32]);
    let owner_pub = b64url(owner.verifying_key().as_bytes());
    let oc = f.call(
        "owner challenge",
        &b_token,
        json!({ "action": "owner_challenge" }),
    );
    let ch = oc["challenge"].as_str().unwrap_or("").to_string();
    f.call(
        "owner: bad key",
        &b_token,
        json!({ "action": "owner", "id": oc["id"], "owner_pub": "short", "signature": "x" }),
    );
    f.call("owner: bad signature", &b_token, json!({ "action": "owner", "id": oc["id"], "owner_pub": owner_pub, "signature": sig(&owner, "other") }));
    f.call("owner: unproven", &b_token, json!({ "action": "owner", "id": oc["id"], "owner_pub": owner_pub, "signature": sig(&owner, &owner_text("cv.example", "set-owner", &ch)) }));
    let oc = f.call(
        "owner challenge 2",
        &b_token,
        json!({ "action": "owner_challenge" }),
    );
    let ch = oc["challenge"].as_str().unwrap_or("").to_string();
    f.call("owner: with password", &b_token, json!({ "action": "owner", "id": oc["id"], "owner_pub": owner_pub, "signature": sig(&owner, &owner_text("cv.example", "set-owner", &ch)), "password": "bobs newer password" }));
    let v = f.call(
        "login: new browser with a key",
        "",
        json!({ "action": "login", "username": "bob_1", "password": "bobs newer password" }),
    );
    let ch = v["verify"]["challenge"].as_str().unwrap_or("").to_string();
    f.call("check: wrong key", "", json!({ "action": "check", "id": v["verify"]["id"], "method": "key", "signature": sig(&SigningKey::from_bytes(&[8; 32]), &owner_text("cv.example", "verify-device", &ch)) }));
    f.call("check: key", "", json!({ "action": "check", "id": v["verify"]["id"], "method": "key", "signature": sig(&owner, &owner_text("cv.example", "verify-device", &ch)) }));

    // ----- passkeys -----
    let mut pk = Passkey::new(3);
    f.call(
        "passkey options: wrong origin",
        &b_token,
        json!({ "action": "passkey_options", "origin": "https://evil.example" }),
    );
    let po = f.call(
        "passkey options",
        &b_token,
        json!({ "action": "passkey_options", "origin": "https://cv.example", "kind": "device" }),
    );
    f.call(
        "passkey add: unproven",
        &b_token,
        json!({ "action": "passkey_add", "id": po["id"], "response": pk.create(&po["options"]) }),
    );
    f.call("passkey add", &b_token, json!({ "action": "passkey_add", "id": po["id"], "response": pk.create(&po["options"]), "password": "bobs newer password", "name": "My laptop" }));
    let po = f.call(
        "passkey options 2",
        &b_token,
        json!({ "action": "passkey_options", "origin": "https://cv.example" }),
    );
    f.call("passkey add: again", &b_token, json!({ "action": "passkey_add", "id": po["id"], "response": pk.create(&po["options"]), "password": "bobs newer password" }));
    let lo = f.call(
        "passkey login options",
        "",
        json!({ "action": "passkey_login_options", "origin": "https://cv.example" }),
    );
    let answer = pk.get(&lo["options"]);
    f.call("passkey login", "", json!({ "action": "passkey_login", "id": lo["id"], "response": answer, "device_name": "Tablet" }));
    f.call(
        "passkey login: replayed",
        "",
        json!({ "action": "passkey_login", "id": lo["id"], "response": answer }),
    );
    let lo = f.call(
        "passkey login options 2",
        "",
        json!({ "action": "passkey_login_options", "origin": "https://cv.example" }),
    );
    f.call("passkey login: stranger", "", json!({ "action": "passkey_login", "id": lo["id"], "response": Passkey::new(4).get(&lo["options"]) }));
    f.call(
        "passkey login: bent id",
        "",
        json!({ "action": "passkey_login", "id": "abc.def", "response": {} }),
    );
    let v = f.call(
        "login: passkey check",
        "",
        json!({ "action": "login", "username": "bob_1", "password": "bobs newer password" }),
    );
    let co = f.call("check options", "", json!({ "action": "check_options", "id": v["verify"]["id"], "origin": "https://cv.example" }));
    f.call("check: passkey", "", json!({ "action": "check", "id": v["verify"]["id"], "method": "passkey", "response": pk.get(&co["options"]) }));
    let st = f.call(
        "status: with a passkey",
        &b_token,
        json!({ "action": "status" }),
    );

    // ----- recovery -----
    let ro = f.call("recover options", "", json!({ "action": "recover_options", "username": "@Bob_1", "origin": "https://cv.example" }));
    let ch = ro["challenge"].as_str().unwrap_or("").to_string();
    f.call(
        "recover: weak",
        "",
        json!({ "action": "recover", "id": ro["id"], "method": "key", "new_password": "x" }),
    );
    f.call("recover: wrong key", "", json!({ "action": "recover", "id": ro["id"], "method": "key", "signature": "AAAA", "new_password": "recovered password" }));
    f.call("recover: key", "", json!({ "action": "recover", "id": ro["id"], "method": "key", "signature": sig(&owner, &owner_text("cv.example", "recover", &ch)), "new_password": "recovered password", "device": b_device }));
    f.call("recover: again", "", json!({ "action": "recover", "id": ro["id"], "method": "key", "signature": sig(&owner, &owner_text("cv.example", "recover", &ch)), "new_password": "recovered password" }));
    f.call(
        "old token after recovery",
        &b_token,
        json!({ "action": "approvals" }),
    );
    f.call(
        "old token: live check",
        &b_token,
        json!({ "action": "owner_challenge" }),
    );
    let ro = f.call(
        "recover options: passkey",
        "",
        json!({ "action": "recover_options", "username": "bob_1", "origin": "https://cv.example" }),
    );
    let back = f.call("recover: passkey", "", json!({ "action": "recover", "id": ro["id"], "method": "passkey", "response": pk.get(&ro["options"]), "new_password": "recovered again" }));
    let b_token = back["session"]["access_token"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let pid = st["passkeys"][0]["id"].clone();
    f.call(
        "remove passkey: unproven",
        &b_token,
        json!({ "action": "account", "change": "remove_passkey", "id": pid }),
    );
    let removed = f.call("remove passkey", &b_token, json!({ "action": "account", "change": "remove_passkey", "id": pid, "password": "recovered again" }));
    let b_token = removed["renewed_access"]["access_token"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let did = st["devices"]
        .as_array()
        .and_then(|d| d.iter().find(|d| d["current"] != true))
        .map(|d| d["id"].clone())
        .unwrap_or(Value::Null);
    f.call(
        "disconnect a device",
        &b_token,
        json!({ "action": "account", "change": "disconnect_device", "id": did }),
    );
    f.call("status: after", &b_token, json!({ "action": "status" }));

    // ----- proofs from an encryption device (carol) -----
    let c = f.call(
        "login: carol",
        "",
        json!({ "action": "login", "username": "carol", "password": "carols password" }),
    );
    let c_token = c["session"]["access_token"]
        .as_str()
        .unwrap_or("")
        .to_string();
    f.call(
        "carol: set password needs a proof",
        &c_token,
        json!({ "action": "account", "change": "set_password", "new_password": "x" }),
    );
    let payload =
        json!({ "action": "account.remove_email", "user_id": CAROL, "change": "remove_email" })
            .to_string();
    f.call("carol: proof", &c_token, json!({ "action": "account", "payload": payload, "proof": proof(pkcs8, "identity.account.remove_email", &payload, &now_iso()) }));
    f.call("carol: proof for another action", &c_token, json!({ "action": "account", "payload": payload, "proof": proof(pkcs8, "identity.account.remove_passkey", &payload, &now_iso()) }));
    f.call("carol: old proof", &c_token, json!({ "action": "account", "payload": payload, "proof": proof(pkcs8, "identity.account.remove_email", &payload, "2020-01-01T00:00:00.000Z") }));
    let bad = json!({ "action": "account.remove_email", "user_id": "someone-else", "change": "remove_email" }).to_string();
    f.call("carol: payload for someone else", &c_token, json!({ "action": "account", "payload": bad, "proof": proof(pkcs8, "identity.account.remove_email", &bad, &now_iso()) }));
    let mut p = proof(pkcs8, "identity.account.remove_email", &payload, &now_iso());
    p["device_id"] = json!("unknown-device-0001");
    f.call(
        "carol: unknown device",
        &c_token,
        json!({ "action": "account", "payload": payload, "proof": p }),
    );
    let mut p = proof(pkcs8, "identity.account.remove_email", &payload, &now_iso());
    p["nonce"] = json!("short");
    f.call(
        "carol: short nonce",
        &c_token,
        json!({ "action": "account", "payload": payload, "proof": p }),
    );
    f.call(
        "carol: not json",
        &c_token,
        json!({ "action": "account", "payload": "{", "proof": {} }),
    );

    // ----- too many wrong passwords -----
    for i in 0..11 {
        f.call(
            &format!("wrong password {i}"),
            "",
            json!({ "action": "login", "username": "carol", "password": "wrong" }),
        );
    }
    f.call(
        "locked even with the right one",
        "",
        json!({ "action": "login", "username": "carol", "password": "carols password" }),
    );

    // ----- the endpoint itself -----
    f.raw(
        "GET is not a function call",
        "GET",
        "/api/functions/identity",
        "",
    );
    f.raw("not JSON", "POST", "/api/functions/identity", "{");
    f.raw("an array", "POST", "/api/functions/identity", "[]");
    f.raw("empty body", "POST", "/api/functions/identity", "");
    f.log
}

#[test]
fn identity_answers_every_step_as_the_node_server_does() {
    if !ready() {
        eprintln!("skipped: node, the npm packages or dist-selfhost aren't there");
        return;
    }
    let (pkcs8, device_pub) = secure_net_core::cv::primitives::generate_pair().unwrap();
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    seed(d1.path(), &device_pub);
    seed(d2.path(), &device_pub);
    let (node, rust) = (start(true, d1.path()), start(false, d2.path()));
    let (a, b) = (
        script(node.1, d1.path(), &pkcs8),
        script(rust.1, d2.path(), &pkcs8),
    );
    if std::env::var("CV_DUMP").is_ok() {
        for (x, y) in a.iter().zip(&b) {
            println!(
                "{}\n  node: {} {}\n  rust: {} {}",
                x["step"], x["status"], x["reply"], y["status"], y["reply"]
            );
        }
    }
    assert_eq!(a.len(), b.len());
    let mut ok = 0;
    for (x, y) in a.iter().zip(&b) {
        assert_eq!(x, y, "\nnode: {x}\nrust: {y}");
        if x["status"] == 200 {
            ok += 1;
        }
    }
    // Controls: the script really signs in, adds a passkey and so on.
    assert!(ok > 40, "only {ok} steps succeeded");
    for step in [
        "register: with the setup code",
        "check: approved",
        "passkey add",
        "passkey login",
        "check: passkey",
        "recover: key",
        "recover: passkey",
        "carol: proof",
        "check: key",
        "disconnect a device",
        "remove passkey",
    ] {
        let s = a.iter().find(|s| s["step"] == step).unwrap();
        assert_eq!(s["status"], 200, "control {step}: {s}");
    }
    assert!(
        !d2.path().join("setup-code").exists() && !d1.path().join("setup-code").exists(),
        "the setup code is gone once used"
    );
}
