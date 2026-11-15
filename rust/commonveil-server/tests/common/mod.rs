//! Helpers shared by the tests that compare the two servers over HTTP.
#![allow(dead_code)]
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

pub fn ready() -> bool {
    let node = Command::new("node").arg("--version").output().is_ok_and(|o| o.status.success());
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
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let mut cmd = if node {
        let mut c = Command::new("node");
        c.arg(repo().join("server/index.mjs"));
        c
    } else {
        Command::new(env!("CARGO_BIN_EXE_commonveil-server"))
    };
    cmd.env("PORT", port.to_string()).env("BIND", "127.0.0.1").env("DATA_DIR", data).env("DIST_DIR", repo().join("dist-selfhost")).env("SITE_URL", "https://cv.example").env("UPDATE_CHECK_HOURS", "1000").env("FEDERATION", "off").env("COMMONVEIL_VERSION", "9.9.9").env("PASSWORD_ROUNDS", "1000").env("ENTITIES_DIR", repo().join("base44/entities"));
    let server = Server(cmd.stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap(), port);
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
    let auth = if token.is_empty() { String::new() } else { format!("Authorization: Bearer {token}\r\n") };
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
            let size = usize::from_str_radix(String::from_utf8_lossy(&body[i..i + end]).trim(), 16).unwrap_or(0);
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
        Value::String(s) if s.len() == 6 && s.bytes().all(|c| c.is_ascii_digit()) => json!("<code>"),
        Value::String(s) if s.len() >= 12 && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"_-.".contains(&c)) && s.bytes().any(|c| c.is_ascii_digit()) => json!("<random>"),
        Value::String(s) if s.len() >= 16 && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"+/=_-.".contains(&c)) && s.bytes().any(|c| c.is_ascii_digit() || b"+/=".contains(&c)) => json!("<random>"),
        // Tokens and secrets: long runs of base64 characters (even ones that happen to hold no digit).
        Value::String(s) if s.len() >= 24 && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"+/=_-.".contains(&c)) && !s.bytes().all(|c| c.is_ascii_uppercase() || c == b'_') => json!("<random>"),
        Value::Number(n) if n.as_f64().is_some_and(|f| f > 1e12) => json!("<time>"),
        Value::Array(a) => Value::Array(a.iter().map(blank).collect()),
        // Ciphertext parts are random whatever characters they happen to use.
        Value::Object(o) => Value::Object(o.iter().map(|(k, v)| {
            let key = if blank(&json!(k)) != json!(k) { "<key>".to_string() } else { k.clone() };
            let value = if ["iv", "ct", "kct", "epk", "wk"].contains(&k.as_str()) && v.is_string() { json!("<random>") } else { blank(v) };
            (key, value)
        }).collect()),
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
        Self { port, log: Vec::new() }
    }
    pub fn call(&mut self, function: &str, step: &str, token: &str, body: Value) -> Value {
        let (status, reply) = post(self.port, "POST", &format!("/api/functions/{function}"), token, &body.to_string());
        self.log.push(json!({ "step": step, "status": status, "reply": blank(&reply) }));
        reply
    }
}

/// Compare two scripts' logs step by step (CV_DUMP=1 prints both). Returns how many steps succeeded.
pub fn compare(a: &[Value], b: &[Value]) -> usize {
    if std::env::var("CV_DUMP").is_ok() {
        for (x, y) in a.iter().zip(b) {
            println!("{}\n  node: {} {}\n  rust: {} {}", x["step"], x["status"], x["reply"], y["status"], y["reply"]);
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
        let s = log.iter().find(|s| s["step"] == *step).unwrap_or_else(|| panic!("no step {step}"));
        assert_eq!(s["status"], 200, "control {step}: {s}");
    }
}
