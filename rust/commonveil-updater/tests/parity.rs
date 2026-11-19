//! The updater over HTTP against the Node.js one (updater/updater.mjs): the same requests go to
//! both, each with its own deployment folder, a stand-in for `docker` (it logs each command, fails
//! when told to, and plays the app restarting on the version .env names) and a stand-in for the
//! app's health answer. Every answer, every docker command and the .env each leaves behind must
//! match.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

const TOKEN: &str = "an updater token, long enough to count";

const FAKE_DOCKER: &str = r#"#!/bin/sh
# Stands in for docker in the updater's tests.
echo "$*" >> "$FAKE_DIR/docker.log"
case " $* " in
  *" pull "*)
    if [ -f "$FAKE_DIR/fail-pull" ]; then echo "pull access denied" >&2; exit 1; fi
    sleep 1 ;;
  *" up "*)
    if [ -f "$FAKE_DIR/fail-up" ]; then echo "no space left on device" >&2; exit 1; fi
    sed -n 's/^COMMONVEIL_VERSION=//p' .env | head -n 1 | tr -d '\r' > "$FAKE_DIR/running" ;;
esac
"#;

fn node_ready() -> bool {
    let reference = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../updater/updater.mjs");
    reference.exists() && Command::new("node").arg("--version").output().is_ok_and(|o| o.status.success())
}

/// The app's health answer: the version the stand-in for docker last started.
fn fake_app(root: PathBuf) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(&stream);
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                line.clear();
            }
            let version = std::fs::read_to_string(root.join("running")).unwrap_or_default().trim().to_string();
            let body = json!({ "status": "ok", "version": version }).to_string();
            let _ = write!(&stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        }
    });
    port
}

struct Updater {
    child: Child,
    port: u16,
}

impl Drop for Updater {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn command(node: bool) -> Command {
    if node {
        let mut c = Command::new("node");
        c.arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/updater-node.mjs"));
        c
    } else {
        Command::new(env!("CARGO_BIN_EXE_commonveil-updater"))
    }
}

fn configured(node: bool, root: &Path, app_port: u16, token: &str, extra: &[(&str, &str)]) -> (Command, u16) {
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let mut cmd = command(node);
    cmd.env("UPDATER_TEST_PORT", port.to_string())
        .env("UPDATER_PORT", port.to_string())
        .env("UPDATER_TOKEN", token)
        .env("PROJECT_DIR", root.join("project"))
        .env("APP_HEALTH_URL", format!("http://127.0.0.1:{app_port}/api/health"))
        .env("PATH", format!("{}:{}", root.join("bin").display(), std::env::var("PATH").unwrap_or_default()))
        .env("FAKE_DIR", root)
        .env_remove("UPDATER_ALLOW_DOWNGRADE")
        .env_remove("APP_SERVICE");
    for (k, v) in extra {
        cmd.env(k, v);
    }
    (cmd, port)
}

fn start(node: bool, root: &Path, app_port: u16, extra: &[(&str, &str)]) -> Updater {
    let (mut cmd, port) = configured(node, root, app_port, TOKEN, extra);
    let updater = Updater { child: cmd.stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap(), port };
    let until = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < until, "the updater didn't start");
        std::thread::sleep(Duration::from_millis(50));
    }
    updater
}

fn call(port: u16, method: &str, path: &str, auth: Option<&str>, body: &str) -> (u16, Value) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let auth = auth.map(|a| format!("Authorization: {a}\r\n")).unwrap_or_default();
    write!(s, "{method} {path} HTTP/1.1\r\nHost: updater\r\nConnection: close\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return (0, Value::Null);
    };
    let head = String::from_utf8_lossy(&raw[..split]).to_lowercase();
    let status = head.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let mut body = raw[split + 4..].to_vec();
    if head.contains("transfer-encoding: chunked") {
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

/// The folder's own path reads as <dir>, and times as <time>, so two runs can be compared.
fn blank(v: &Value, root: &str) -> Value {
    match v {
        Value::String(s) => json!(s.replace(root, "<dir>")),
        Value::Array(a) => Value::Array(a.iter().map(|x| blank(x, root)).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), if k == "at" && x.is_string() { json!("<time>") } else { blank(x, root) })).collect()),
        _ => v.clone(),
    }
}

/// A deployment folder with a stand-in for docker, a site on 0.23.1 and its app answering.
fn deployment() -> (tempfile::TempDir, u16) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("project")).unwrap();
    std::fs::create_dir_all(root.join("bin")).unwrap();
    std::fs::write(root.join("bin/docker"), FAKE_DOCKER).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.join("bin/docker"), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    // Windows line ends, which must survive the update.
    std::fs::write(root.join("project/.env"), "SITE_DOMAIN=chat.example\r\nCOMMONVEIL_VERSION=0.23.1\r\nUPDATER_TOKEN=x\r\n").unwrap();
    std::fs::write(root.join("running"), "0.23.1").unwrap();
    let app = fake_app(root.to_path_buf());
    (dir, app)
}

fn script(node: bool) -> Vec<Value> {
    let (dir, app) = deployment();
    let root = dir.path().to_path_buf();
    let root_text = root.display().to_string();
    let mut log: Vec<Value> = Vec::new();
    let note = |log: &mut Vec<Value>, step: &str, (status, reply): (u16, Value)| log.push(json!({ "step": step, "status": status, "reply": blank(&reply, &root_text) }));
    let bearer = format!("Bearer {TOKEN}");
    let settle = |port: u16| {
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            let got = call(port, "GET", "/status", Some(&bearer), "");
            if got.1["busy"] == json!(false) || Instant::now() > until {
                return got;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    };
    {
        let u = start(node, &root, app, &[]);
        let get = |path: &str, auth: Option<&str>| call(u.port, "GET", path, auth, "");
        let post = |path: &str, body: &str| call(u.port, "POST", path, Some(&bearer), body);
        note(&mut log, "status: no token", get("/status", None));
        note(&mut log, "status: wrong token", get("/status", Some("Bearer nope")));
        note(&mut log, "status: token and more", get("/status", Some(&format!("{bearer}x"))));
        note(&mut log, "status: lowercase", get("/status", Some(&format!("bearer {TOKEN}"))));
        note(&mut log, "update: no token", call(u.port, "POST", "/update", None, r#"{"version":"0.24.0"}"#));
        note(&mut log, "status", get("/status", Some(&bearer)));
        note(&mut log, "update: GET", get("/update", Some(&bearer)));
        note(&mut log, "status: POST", post("/status", ""));
        note(&mut log, "status: with a query", get("/status?x=1", Some(&bearer)));
        note(&mut log, "nothing there", get("/", Some(&bearer)));
        for body in ["", "not json", "null", "[]", "{}", r#"{"version":"0.24"}"#, r#"{"version":"v0.24.0"}"#, r#"{"version":"0.24.0 "}"#, r#"{"version":"0.24.0\n"}"#, r#"{"version":1}"#, r#"{"version":true}"#, r#"{"version":{}}"#, r#"{"version":["0","24"]}"#, r#"{"version":"12345.0.0"}"#] {
            note(&mut log, &format!("update: {body}"), post("/update", body));
        }
        note(&mut log, "update: what runs now", post("/update", r#"{"version":"0.23.1"}"#));
        note(&mut log, "update: older", post("/update", r#"{"version":"0.23.0"}"#));
        note(&mut log, "update", post("/update", r#"{"version":"0.24.0"}"#));
        note(&mut log, "update: while busy", post("/update", r#"{"version":"0.24.1"}"#));
        note(&mut log, "status: busy", get("/status", Some(&bearer)));
        note(&mut log, "status: updated", settle(u.port));
        note(&mut log, "update: not newer than what runs now", post("/update", r#"{"version":"0.24.0"}"#));

        std::fs::write(root.join("fail-pull"), "").unwrap();
        note(&mut log, "update: the pull fails", post("/update", r#"{"version":"0.25.0"}"#));
        note(&mut log, "status: went back", settle(u.port));
        std::fs::remove_file(root.join("fail-pull")).unwrap();

        std::fs::write(root.join("fail-up"), "").unwrap();
        note(&mut log, "update: starting fails", post("/update", r#"{"version":"0.25.0"}"#));
        note(&mut log, "status: couldn't go back", settle(u.port));
        std::fs::remove_file(root.join("fail-up")).unwrap();

        std::fs::write(root.join("project/.env"), "SITE_DOMAIN=chat.example\nUPDATER_TOKEN=x").unwrap();
        note(&mut log, "update: .env doesn't name a version", post("/update", r#"{"version":"0.26.0"}"#));
        note(&mut log, "status: named now", settle(u.port));
    }
    {
        // The operator allows going back.
        let u = start(node, &root, app, &[("UPDATER_ALLOW_DOWNGRADE", "true")]);
        note(&mut log, "update: back to an older version", call(u.port, "POST", "/update", Some(&bearer), r#"{"version":"0.23.0"}"#));
        note(&mut log, "status: older", settle(u.port));
    }
    let read = |p: &str| std::fs::read_to_string(root.join(p)).unwrap_or_default().replace(&root_text, "<dir>");
    log.push(json!({ "step": "docker commands", "lines": read("docker.log").lines().collect::<Vec<_>>() }));
    log.push(json!({ "step": ".env", "text": read("project/.env") }));
    log.push(json!({ "step": "running", "text": read("running") }));
    // A token too short to be safe: it won't start.
    let (mut cmd, _) = configured(node, &root, app, "short", &[]);
    let out = cmd.output().unwrap();
    log.push(json!({ "step": "short token", "code": out.status.code(), "stderr": String::from_utf8_lossy(&out.stderr).trim() }));
    log
}

#[test]
fn the_updater_answers_as_the_node_one_did() {
    if !node_ready() {
        eprintln!("skipped: needs Node.js and updater/updater.mjs");
        return;
    }
    let (node, rust) = (script(true), script(false));
    if std::env::var("CV_DUMP").is_ok() {
        for (a, b) in node.iter().zip(&rust) {
            println!("{}\n  node: {a}\n  rust: {b}", a["step"]);
        }
    }
    assert_eq!(node.len(), rust.len());
    for (a, b) in node.iter().zip(&rust) {
        assert_eq!(a, b, "\nnode: {a}\nrust: {b}");
    }
    // The script did reach what it means to test.
    let step = |name: &str| rust.iter().find(|s| s["step"] == name).unwrap_or_else(|| panic!("no step {name}")).clone();
    assert_eq!(step("update")["status"], 202);
    assert_eq!(step("update: while busy")["status"], 409);
    assert_eq!(step("status: updated")["reply"]["last"]["ok"], true);
    assert_eq!(step("status: went back")["reply"]["last"]["rolled_back"], true);
    assert_eq!(step("status: couldn't go back")["reply"]["last"]["rolled_back"], false);
    assert_eq!(step("status: older")["reply"]["last"]["version"], "0.23.0");
    assert_eq!(step(".env")["text"], "SITE_DOMAIN=chat.example\nUPDATER_TOKEN=x\nCOMMONVEIL_VERSION=0.23.0\n");
    assert_eq!(step("short token")["code"], 1);
}

#[test]
fn a_long_request_starts_nothing() {
    let (dir, app) = deployment();
    let u = start(false, dir.path(), app, &[]);
    let bearer = format!("Bearer {TOKEN}");
    let body = format!(r#"{{"version":"0.24.0","padding":"{}"}}"#, "x".repeat(2000));
    let (status, _) = call(u.port, "POST", "/update", Some(&bearer), &body);
    assert_ne!(status, 202);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(call(u.port, "GET", "/status", Some(&bearer), ""), (200, json!({ "busy": false, "last": null })));
    assert!(!dir.path().join("docker.log").exists());
}
