//! Helpers shared by the tests that compare the two servers over HTTP.
#![allow(dead_code)]
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use secure_net_core::cv::{device, identity, keyring, recovery};
use serde_json::{json, Value};

pub mod servers;

pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

pub fn ready() -> bool {
    let node = Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    node && repo().join("node_modules").exists() && repo().join("dist-selfhost/index.html").exists()
}

pub struct Server(pub std::process::Child, pub u16);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub fn start(node: bool, data: &Path) -> Server {
    start_with(node, data, &[])
}

/// Start a server with extra settings.
pub fn start_with(node: bool, data: &Path, extra: &[(&str, String)]) -> Server {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut cmd = if node {
        let mut c = Command::new("node");
        c.arg(repo().join("server/index.mjs"));
        c
    } else {
        Command::new(env!("CARGO_BIN_EXE_commonveil-server"))
    };
    cmd.env("PORT", port.to_string())
        .env("BIND", "127.0.0.1")
        .env("DATA_DIR", data)
        .env("DIST_DIR", repo().join("dist-selfhost"))
        .env("SITE_URL", "https://cv.example")
        .env("UPDATE_CHECK_HOURS", "1000")
        .env("FEDERATION", "off")
        .env("COMMONVEIL_VERSION", "9.9.9")
        .env("PASSWORD_ROUNDS", "1000")
        .env("ENTITIES_DIR", repo().join("base44/entities"));
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let server = Server(
        cmd.stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        port,
    );
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return server;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    drop(server);
    panic!("{} server didn't start", if node { "Node" } else { "Rust" });
}

pub fn post(port: u16, method: &str, path: &str, token: &str, body: &str) -> (u16, Value) {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    let auth = if token.is_empty() {
        String::new()
    } else {
        format!("Authorization: Bearer {token}\r\n")
    };
    write!(s, "{method} {path} HTTP/1.1\r\nHost: cv.example\r\nConnection: close\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status: u16 = head.split(' ').nth(1).unwrap().parse().unwrap();
    let mut body = raw[split + 4..].to_vec();
    if head.to_lowercase().contains("transfer-encoding: chunked") {
        let (mut out, mut i) = (Vec::new(), 0);
        while let Some(end) = body[i..].windows(2).position(|w| w == b"\r\n") {
            let size = usize::from_str_radix(String::from_utf8_lossy(&body[i..i + end]).trim(), 16)
                .unwrap_or(0);
            if size == 0 {
                break;
            }
            out.extend_from_slice(&body[i + end + 2..i + end + 2 + size]);
            i += end + 2 + size + 2;
        }
        body = out;
    }
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// Blank what's random or time-bound, so two sites' answers can be compared.
pub fn blank(v: &Value) -> Value {
    let iso = regex::Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?$").unwrap();
    match v {
        Value::String(s) if iso.is_match(s) => json!("<time>"),
        Value::String(s) if s.starts_with("https://cv.example/api/files/") => json!("<file link>"),
        Value::String(s) if s.len() == 6 && s.bytes().all(|c| c.is_ascii_digit()) => {
            json!("<code>")
        }
        Value::String(s)
            if s.len() >= 12
                && s.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_-.".contains(&c))
                && s.bytes().any(|c| c.is_ascii_digit()) =>
        {
            json!("<random>")
        }
        Value::String(s)
            if s.len() >= 16
                && s.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"+/=_-.".contains(&c))
                && s.bytes().any(|c| c.is_ascii_digit() || b"+/=".contains(&c)) =>
        {
            json!("<random>")
        }
        // Tokens and secrets: long runs of base64 characters (even ones that happen to hold no digit).
        Value::String(s)
            if s.len() >= 24
                && s.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"+/=_-.".contains(&c))
                && !s.bytes().all(|c| c.is_ascii_uppercase() || c == b'_') =>
        {
            json!("<random>")
        }
        Value::Number(n) if n.as_f64().is_some_and(|f| f > 1e12) => json!("<time>"),
        Value::Array(a) => Value::Array(a.iter().map(blank).collect()),
        // Ciphertext parts are random whatever characters they happen to use.
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, v)| {
                    let key = if blank(&json!(k)) != json!(k) {
                        "<key>".to_string()
                    } else {
                        k.clone()
                    };
                    let value = if [
                        "iv",
                        "ct",
                        "kct",
                        "epk",
                        "wk",
                        "envelope",
                        "signature",
                        "kc",
                        "sealed",
                    ]
                    .contains(&k.as_str())
                        && v.is_string()
                    {
                        json!("<random>")
                    } else {
                        blank(v)
                    };
                    (key, value)
                })
                .collect(),
        ),
        _ => v.clone(),
    }
}

/// A script of function calls against one server, with every reply logged (blanked).
pub struct Flow {
    pub port: u16,
    pub log: Vec<Value>,
}

impl Flow {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            log: Vec::new(),
        }
    }
    pub fn call(&mut self, function: &str, step: &str, token: &str, body: Value) -> Value {
        let (status, reply) = post(
            self.port,
            "POST",
            &format!("/api/functions/{function}"),
            token,
            &body.to_string(),
        );
        self.log
            .push(json!({ "step": step, "status": status, "reply": blank(&reply) }));
        reply
    }
}

/// Compare two scripts' logs step by step (CV_DUMP=1 prints both). Returns how many steps succeeded.
pub fn compare(a: &[Value], b: &[Value]) -> usize {
    if std::env::var("CV_DUMP").is_ok() {
        for (x, y) in a.iter().zip(b) {
            println!(
                "{}\n  node: {} {}\n  rust: {} {}",
                x["step"], x["status"], x["reply"], y["status"], y["reply"]
            );
        }
    }
    assert_eq!(a.len(), b.len());
    let mut ok = 0;
    for (x, y) in a.iter().zip(b) {
        assert_eq!(x, y, "\nnode: {x}\nrust: {y}");
        if x["status"] == 200 {
            ok += 1;
        }
    }
    ok
}

/// The control steps really succeeded.
pub fn succeeded(log: &[Value], steps: &[&str]) {
    for step in steps {
        let s = log
            .iter()
            .find(|s| s["step"] == *step)
            .unwrap_or_else(|| panic!("no step {step}"));
        assert_eq!(s["status"], 200, "control {step}: {s}");
    }
}

/// Key material made once and used on both sites (only the account ids differ).
pub struct Kit {
    pub rk: recovery::RecoveryKeys,
    pub v: Vec<Value>,
    pub d: Vec<Value>,
}

pub fn now() -> i64 {
    commonveil_server::sessions::now_ms()
}

impl Kit {
    pub fn new() -> Self {
        let rk = recovery::derive_recovery_key(&recovery::generate_recovery_phrase()).unwrap();
        let v = (1..=3)
            .map(|n| keyring::create_key_version(n, now()).unwrap())
            .collect();
        let d = (1..=5)
            .map(|n| device::create_device_keys(&format!("Device {n}"), now()).unwrap())
            .collect();
        Self { rk, v, d }
    }
    pub fn statement(&self, uid: &str, v: usize, signer: usize, anchor: bool) -> Value {
        let mut st = identity::make_account_statement(
            uid,
            &self.v[v],
            &self.rk.public_key,
            &self.rk.kem_public_key,
            &self.v[signer],
            now(),
        )
        .unwrap();
        if anchor {
            st["recovery_mac"] =
                json!(recovery::recovery_anchor_mac(&self.rk.anchor_key[..], &st).unwrap());
        }
        st
    }
    pub fn cert(&self, uid: &str, d: usize, v: usize) -> Value {
        identity::make_device_cert(
            uid,
            &self.d[d],
            &self.v[v],
            self.d[d]["kem_pub"].as_str().unwrap(),
            now(),
        )
        .unwrap()
    }
    pub fn keyring(&self, uid: &str, versions: &[usize]) -> Value {
        let mut k = keyring::new_keyring(uid, self.v[versions[0]].clone()).unwrap();
        for v in &versions[1..] {
            k = keyring::with_version(&k, self.v[*v].clone()).unwrap();
        }
        k
    }
    pub fn recovery_env(&self, k: &Value, v: usize) -> Value {
        let mut e = keyring::seal_keyring_for_recovery(
            k,
            &self.rk.public_key,
            Some(&self.rk.kem_public_key),
        )
        .unwrap();
        e["key_sign_pub"] = self.v[v]["sign_pub"].clone();
        e
    }
    pub fn device_env(&self, k: &Value, d: usize, v: usize) -> Value {
        let dev = &self.d[d];
        let mut e = keyring::seal_keyring_to_device(
            k,
            dev["device_id"].as_str().unwrap(),
            dev["box_pub"].as_str().unwrap(),
            dev["kem_pub"].as_str(),
        )
        .unwrap();
        e["key_sign_pub"] = self.v[v]["sign_pub"].clone();
        e["device_id"] = dev["device_id"].clone();
        e
    }
    pub fn public(&self, d: usize) -> Value {
        device::public_device(&self.d[d])
    }
    pub fn id(&self, d: usize) -> Value {
        self.d[d]["device_id"].clone()
    }
    /// A request signed by device `d`.
    pub fn signed(&self, uid: &str, action: &str, d: usize, payload: Value) -> Value {
        let text = payload.to_string();
        json!({ "action": action, "payload": text, "proof": identity::make_device_proof(uid, &self.d[d], action, &text, now()).unwrap() })
    }
}

impl Kit {
    /// The request that sets up encryption with key version 1 and device 0.
    pub fn init(&self, uid: &str) -> Value {
        let k = self.keyring(uid, &[0]);
        self.signed(uid, "init_account", 0, json!({ "device": self.public(0), "statement": self.statement(uid, 0, 0, true), "cert": self.cert(uid, 0, 0), "recovery": self.recovery_env(&k, 0) }))
    }
    /// This account as a recipient of an envelope (key version 1).
    pub fn recipient(&self, uid: &str) -> Value {
        json!({ "user_id": uid, "key_version": 1, "ecdh_pub": self.v[0]["ecdh_pub"], "kem_pub": self.v[0]["kem_pub"] })
    }
}

/// An encrypted, signed item from device 0 of `sender`: (envelope JSON, signature).
pub fn sealed_item(
    kind: &str,
    conversation_id: &str,
    item_id: &str,
    sender: (&str, &Kit),
    recipients: &[Value],
    sent_at: &str,
) -> (String, String) {
    let device_id = sender.1.d[0]["device_id"].as_str().unwrap();
    let scope = json!({ "kind": kind, "conversation_id": conversation_id, "item_id": item_id, "sender_id": sender.0, "device_id": device_id });
    let env = secure_net_core::cv::envelope::encrypt_envelope(
        &scope,
        recipients,
        &json!({ "text": "hello" }),
    )
    .unwrap()
    .to_string();
    let sig = identity::sign_item(sender.1.d[0]["sign_priv"].as_str().unwrap(), &json!({ "kind": kind, "conversationId": conversation_id, "itemId": item_id, "senderId": sender.0, "deviceId": device_id, "envelopeJson": env, "sentAt": sent_at })).unwrap();
    (env, sig)
}

pub fn random_id() -> String {
    secure_net_core::cv::encoding::random_id(16)
}

pub fn iso_at(ms: i64) -> String {
    commonveil_server::store::iso(ms)
}

/// A plain GET, for file links: (status, body bytes).
pub fn get_raw(port: u16, path: &str) -> (u16, Vec<u8>) {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: cv.example\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    (
        head.split(' ').nth(1).unwrap().parse().unwrap(),
        raw[split + 4..].to_vec(),
    )
}
