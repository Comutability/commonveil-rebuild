//! The Commonveil updater (it replaces updater/updater.mjs and answers exactly as it did): a tiny
//! service, reachable only from the app container, that installs a new release when the site's
//! admin (or automatic updates) asks. It sets COMMONVEIL_VERSION in the deployment's .env, pulls
//! that image and restarts the app with it. If the new version doesn't come up healthy, it goes
//! back to the previous one.
//!
//! It needs the Docker socket, which is powerful: that's why it's a separate container that does
//! this one thing, answers only requests carrying UPDATER_TOKEN, and only accepts version numbers.
//! It only ever moves forward: going back to an older version needs the operator to allow it here,
//! on the server (UPDATER_ALLOW_DOWNGRADE=true), not just someone holding the token.
//!
//! Settings (environment variables):
//!   UPDATER_TOKEN            the secret the app sends, at least 24 characters (required)
//!   PROJECT_DIR              the deployment's folder, with docker-compose.yml and .env (/project)
//!   UPDATER_ALLOW_DOWNGRADE  true allows going back to an older version
//!   APP_SERVICE              the app's Compose service (app)
//!   APP_HEALTH_URL           where the app says which version it runs (http://app:8080/api/health)
//!   UPDATER_PORT             the port to listen on (8090)
//!
//! API (every request needs `Authorization: Bearer <UPDATER_TOKEN>`):
//!   GET  /status   {"busy": bool, "last": the last update's outcome or null}
//!   POST /update   {"version": "x.y.z"}: 202 when it starts, 409 when busy or not newer
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::{header, Method, StatusCode};
use axum::response::Response;
use serde_json::{json, Value};

/// How long `docker compose` may take, and how much it may print on each of its outputs.
const COMPOSE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const MAX_OUTPUT: usize = 8 * 1024 * 1024;
/// A request is a version number: a longer body is refused.
const MAX_BODY: usize = 1024;
/// Errors kept in the status are cut to this many characters.
const MAX_ERROR: usize = 300;

struct Settings {
    project: String,
    token: String,
    service: String,
    health_url: String,
    allow_downgrade: bool,
    /// How long a new (or the old) version has to come up healthy, and how often to look.
    health_wait: Duration,
    health_every: Duration,
}

impl Settings {
    fn from_env() -> Self {
        let get = |k: &str, default: &str| std::env::var(k).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_string());
        let service = get("APP_SERVICE", "app");
        Self {
            project: get("PROJECT_DIR", "/project"),
            token: std::env::var("UPDATER_TOKEN").unwrap_or_default(),
            health_url: get("APP_HEALTH_URL", &format!("http://{service}:8080/api/health")),
            service,
            allow_downgrade: std::env::var("UPDATER_ALLOW_DOWNGRADE").is_ok_and(|v| v == "true"),
            health_wait: Duration::from_secs(120),
            health_every: Duration::from_secs(3),
        }
    }

    fn env_file(&self) -> PathBuf {
        PathBuf::from(format!("{}/.env", self.project))
    }
}

#[derive(Default)]
struct Job {
    busy: bool,
    last: Value,
}

struct Updater {
    settings: Settings,
    state: Mutex<Job>,
}

impl Updater {
    fn job(&self) -> std::sync::MutexGuard<'_, Job> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

// ---------- versions ----------

/// x.y.z, as /^\d{1,4}\.\d{1,4}\.\d{1,6}$/ (ASCII digits only, nothing after).
fn is_version(v: &str) -> bool {
    let p: Vec<&str> = v.split('.').collect();
    p.len() == 3 && p.iter().zip([4, 4, 6]).all(|(x, max)| !x.is_empty() && x.len() <= max && x.bytes().all(|b| b.is_ascii_digit()))
}

/// a > b, for versions that passed `is_version`.
fn newer(a: &str, b: &str) -> bool {
    let parts = |v: &str| v.split('.').map(|x| x.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    parts(a) > parts(b)
}

/// JavaScript's String(value || ""): what Node made of whatever was sent as a version.
fn js_text(v: Option<&Value>) -> String {
    fn text(v: &Value) -> String {
        match v {
            Value::Null => "null".into(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => match n.as_f64() {
                Some(f) if f.fract() == 0.0 && f.abs() < 1e21 => format!("{f:.0}"),
                _ => n.to_string(),
            },
            Value::String(s) => s.clone(),
            // Arrays join their items (null as nothing); objects say so.
            Value::Array(a) => a.iter().map(|x| if x.is_null() { String::new() } else { text(x) }).collect::<Vec<_>>().join(","),
            Value::Object(_) => "[object Object]".into(),
        }
    }
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => String::new(),
        Some(Value::Number(n)) if n.as_f64().is_some_and(|f| f == 0.0) => String::new(),
        Some(Value::String(s)) if s.is_empty() => String::new(),
        Some(v) => text(v),
    }
}

/// The first `count` UTF-16 units of `s`, as JavaScript's slice(0, count).
fn js_slice(s: &str, count: usize) -> String {
    let mut out = String::new();
    let mut used = 0;
    for c in s.chars() {
        used += c.len_utf16();
        if used > count {
            break;
        }
        out.push(c);
    }
    out
}

// ---------- .env ----------

/// Where the first line setting COMMONVEIL_VERSION is: (start of the line, end of its value).
/// Lines end at \n, \r, U+2028 or U+2029, as in the regular expression /^COMMONVEIL_VERSION=.*$/m.
fn version_line(text: &str) -> Option<(usize, usize)> {
    const KEY: &str = "COMMONVEIL_VERSION=";
    let ends = |c: char| matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}');
    let mut start = 0;
    loop {
        let rest = &text[start..];
        let line_len = rest.find(ends).unwrap_or(rest.len());
        if rest[..line_len].starts_with(KEY) {
            return Some((start, start + line_len));
        }
        if line_len == rest.len() {
            return None;
        }
        start += line_len + rest[line_len..].chars().next().map_or(1, char::len_utf8);
    }
}

fn set_version(text: &str, version: &str) -> String {
    let line = format!("COMMONVEIL_VERSION={version}");
    match version_line(text) {
        Some((start, end)) => format!("{}{line}{}", &text[..start], &text[end..]),
        None => {
            let mut out = text.to_string();
            if !out.ends_with('\n') {
                out.push('\n');
            }
            format!("{out}{line}\n")
        }
    }
}

fn read_env(s: &Settings) -> std::io::Result<String> {
    let file = s.env_file();
    if !file.exists() {
        return Ok(String::new());
    }
    std::fs::read_to_string(file)
}

/// Replace .env whole, readable only by its owner: never a half-written file (written, then moved).
fn write_env(s: &Settings, text: &str) -> std::io::Result<()> {
    let file = s.env_file();
    let tmp = PathBuf::from(format!("{}.{}.tmp", file.display(), std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(&tmp)?.write_all(text.as_bytes())?;
    std::fs::rename(&tmp, &file)
}

// ---------- the app and Docker ----------

/// The app's health answer: (status, body).
fn health(url: &str) -> Result<(u16, Value), String> {
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(4)).build();
    let (status, response) = match agent.get(url).call() {
        Ok(r) => (r.status(), r),
        Err(ureq::Error::Status(code, r)) => (code, r),
        Err(e) => return Err(e.to_string()),
    };
    let text = response.into_string().map_err(|e| e.to_string())?;
    Ok((status, serde_json::from_str(&text).map_err(|e| e.to_string())?))
}

/// The version the site runs now, as it says itself ("" if it can't be asked).
fn running_version(url: &str) -> String {
    match health(url) {
        Ok((_, Value::Object(o))) => js_text(o.get("version")),
        _ => String::new(),
    }
}

fn healthy(s: &Settings, version: &str) -> bool {
    let until = Instant::now() + s.health_wait;
    while Instant::now() < until {
        if let Ok((status, body)) = health(&s.health_url) {
            if (200..300).contains(&status) && body.get("version").and_then(Value::as_str) == Some(version) {
                return true;
            }
        }
        std::thread::sleep(s.health_every);
    }
    false
}

/// Read one of a command's outputs, up to MAX_OUTPUT; `over` says it went past that.
fn collect(mut from: impl Read + Send + 'static, over: Arc<AtomicBool>) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let (mut out, mut buf) = (Vec::new(), [0u8; 8192]);
        loop {
            match from.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) if out.len() + n > MAX_OUTPUT => {
                    over.store(true, Ordering::Relaxed);
                    break;
                }
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
        out
    })
}

/// `docker compose --project-directory PROJECT <args>`, in that folder. Errors read as Node's did.
fn compose(s: &Settings, args: &[&str]) -> Result<(), String> {
    let mut all = vec!["compose", "--project-directory", s.project.as_str()];
    all.extend_from_slice(args);
    let mut child = Command::new("docker")
        .args(&all)
        .current_dir(&s.project)
        .env("PWD", &s.project)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| if e.kind() == std::io::ErrorKind::NotFound { "spawn docker ENOENT".to_string() } else { format!("spawn docker {e}") })?;
    let (out_over, err_over) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
    let stdout = collect(child.stdout.take().expect("piped"), out_over.clone());
    let stderr = collect(child.stderr.take().expect("piped"), err_over.clone());
    let started = Instant::now();
    let status = loop {
        if let Ok(Some(status)) = child.try_wait() {
            break Some(status);
        }
        if started.elapsed() > COMPOSE_TIMEOUT || out_over.load(Ordering::Relaxed) || err_over.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let (_, err_text) = (stdout.join().unwrap_or_default(), String::from_utf8_lossy(&stderr.join().unwrap_or_default()).to_string());
    if out_over.load(Ordering::Relaxed) {
        return Err("stdout maxBuffer length exceeded".into());
    }
    if err_over.load(Ordering::Relaxed) {
        return Err("stderr maxBuffer length exceeded".into());
    }
    match status {
        Some(status) if status.success() => Ok(()),
        _ => Err(format!("Command failed: docker {}\n{err_text}", all.join(" "))),
    }
}

fn now_iso() -> String {
    iso(SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64))
}

/// Milliseconds since 1970 as 2026-01-02T03:04:05.678Z (JavaScript's toISOString).
fn iso(ms: i64) -> String {
    let (secs, milli) = (ms.div_euclid(1000), ms.rem_euclid(1000));
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Days to a date (Howard Hinnant's civil_from_days).
    let z = days + 719_468;
    let (era, doe) = (z.div_euclid(146_097), z.rem_euclid(146_097));
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{milli:03}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

// ---------- updating ----------

/// Install `version`, or go back to what ran before: the outcome, for /status.
fn update(s: &Settings, version: &str) -> Value {
    let service = s.service.as_str();
    // Node stopped here (unhandled) when .env couldn't be read or written: nothing had changed,
    // so it counts as a failed update that's already back where it was.
    let unchanged = |e: std::io::Error| {
        eprintln!("Update to {version} failed: {e}. Nothing was changed.");
        json!({ "ok": false, "version": version, "error": js_slice(&e.to_string(), MAX_ERROR), "rolled_back": true, "rollback_error": "", "at": now_iso() })
    };
    let before = match read_env(s) {
        Ok(text) => text,
        Err(e) => return unchanged(e),
    };
    let previous = version_line(&before).map(|(a, b)| &before[a + "COMMONVEIL_VERSION=".len()..b]).filter(|v| !v.is_empty()).unwrap_or("latest").to_string();
    let was = running_version(&s.health_url);
    if let Err(e) = write_env(s, &set_version(&before, version)) {
        return unchanged(e);
    }
    let attempt = compose(s, &["pull", service]).and_then(|()| compose(s, &["up", "-d", "--no-deps", service])).and_then(|()| if healthy(s, version) { Ok(()) } else { Err(format!("{version} didn't start properly")) });
    match attempt {
        Ok(()) => {
            println!("Updated to {version}");
            json!({ "ok": true, "version": version, "at": now_iso() })
        }
        Err(error) => {
            eprintln!("Update to {version} failed: {error}. Going back to {previous}.");
            let (mut rolled_back, mut rollback_error) = (false, String::new());
            match write_env(s, &before).map_err(|e| e.to_string()).and_then(|()| compose(s, &["up", "-d", "--no-deps", service])) {
                // Back only counts if the old version really is running again.
                Ok(()) => {
                    rolled_back = was.is_empty() || healthy(s, &was);
                    if !rolled_back {
                        rollback_error = format!("{was} didn't come back up");
                    }
                }
                Err(e) => rollback_error = e,
            }
            if !rolled_back {
                eprintln!("Going back failed too: {rollback_error}. The site needs attention.");
            }
            json!({ "ok": false, "version": version, "error": js_slice(&error, MAX_ERROR), "rolled_back": rolled_back, "rollback_error": js_slice(&rollback_error, MAX_ERROR), "at": now_iso() })
        }
    }
}

// ---------- HTTP ----------

fn reply(status: u16, body: Value) -> Response {
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.to_string().into())
        .expect("a valid response")
}

/// The Authorization header is exactly "Bearer <token>", compared in constant time.
fn authorised(got: &[u8], token: &str) -> bool {
    let want = format!("Bearer {token}");
    got.len() == want.len() && std::hint::black_box(got.iter().zip(want.as_bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b))) == 0
}

async fn handle(State(u): State<Arc<Updater>>, req: Request) -> Response {
    let auth = req.headers().get(header::AUTHORIZATION).map_or(&b""[..], |v| v.as_bytes());
    if !authorised(auth, &u.settings.token) {
        return reply(401, json!({ "error": "Not allowed" }));
    }
    let target = req.uri().path_and_query().map_or("", |p| p.as_str()).to_string();
    if req.method() == Method::GET && target == "/status" {
        let job = u.job();
        return reply(200, json!({ "busy": job.busy, "last": job.last }));
    }
    if req.method() != Method::POST || target != "/update" {
        return reply(404, json!({ "error": "Not found" }));
    }
    let Ok(body) = to_bytes(req.into_body(), MAX_BODY).await else {
        return reply(413, json!({ "error": "Too large" }));
    };
    let version = match serde_json::from_slice::<Value>(&body) {
        Ok(Value::Object(o)) => js_text(o.get("version")),
        _ => String::new(),
    };
    if !is_version(&version) {
        return reply(400, json!({ "error": "Not a version number" }));
    }
    {
        let mut job = u.job();
        if job.busy {
            return reply(409, json!({ "error": "An update is already running" }));
        }
        job.busy = true;
    }
    let url = u.settings.health_url.clone();
    let current = tokio::task::spawn_blocking(move || running_version(&url)).await.unwrap_or_default();
    if is_version(&current) && !newer(&version, &current) && !u.settings.allow_downgrade {
        u.job().busy = false;
        return reply(409, json!({ "error": format!("{version} isn't newer than {current}. Going back needs UPDATER_ALLOW_DOWNGRADE=true on the server.") }));
    }
    let (worker, v) = (u.clone(), version.clone());
    std::thread::spawn(move || {
        let outcome = update(&worker.settings, &v);
        let mut job = worker.job();
        job.last = outcome;
        job.busy = false;
    });
    reply(202, json!({ "ok": true, "version": version }))
}

fn main() {
    let settings = Settings::from_env();
    if settings.token.encode_utf16().count() < 24 {
        eprintln!("UPDATER_TOKEN must be set (at least 24 characters). See docs/SELF_HOSTING.md.");
        std::process::exit(1);
    }
    let port: u16 = std::env::var("UPDATER_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8090);
    let updater = Arc::new(Updater { settings, state: Mutex::new(Job { busy: false, last: Value::Null }) });
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("a runtime");
    let served: std::io::Result<()> = runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
        println!("Commonveil updater ready");
        let app = axum::Router::new().fallback(handle).with_state(updater);
        // It runs as the container's first process, which gets no default signal handling: stop
        // on the signals `docker stop` and Ctrl-C send.
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                #[cfg(unix)]
                {
                    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("a signal handler");
                    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
                }
                #[cfg(not(unix))]
                let _ = tokio::signal::ctrl_c().await;
            })
            .await
    });
    if let Err(e) = served {
        eprintln!("The updater couldn't start: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_numbers() {
        for v in ["0.24.0", "1.2.3", "9999.9999.999999", "01.2.3"] {
            assert!(is_version(v), "{v}");
        }
        for v in ["", "0.24", "v0.24.0", "0.24.0 ", "0.24.0\n", "1.2.3.4", "12345.0.0", "0.0.1234567", "1.2.x", "١.٢.٣", "+1.2.3"] {
            assert!(!is_version(v), "{v}");
        }
        assert!(newer("0.24.0", "0.23.1") && newer("1.0.0", "0.99.99") && newer("0.10.0", "0.9.0"));
        assert!(!newer("0.23.1", "0.23.1") && !newer("0.23.0", "0.23.1") && !newer("0.9.0", "0.10.0"));
    }

    #[test]
    fn what_javascript_makes_of_a_version() {
        let t = |v: Value| js_text(Some(&v));
        assert_eq!(js_text(None), "");
        for (v, want) in [(json!(null), ""), (json!(false), ""), (json!(0), ""), (json!(""), ""), (json!("0.24.0"), "0.24.0"), (json!(true), "true"), (json!(12), "12"), (json!(1.5), "1.5"), (json!({}), "[object Object]"), (json!([]), ""), (json!(["0.24.0"]), "0.24.0"), (json!([[1, null], "a"]), "1,,a")] {
            assert_eq!(t(v.clone()), want, "{v}");
        }
        assert_eq!(js_slice("abcdef", 3), "abc");
        assert_eq!(js_slice("a😀b", 2), "a");
        assert_eq!(js_slice("a😀b", 3), "a😀");
    }

    #[test]
    fn setting_the_version_in_env() {
        assert_eq!(set_version("A=1\nCOMMONVEIL_VERSION=0.23.1\nB=2\n", "0.24.0"), "A=1\nCOMMONVEIL_VERSION=0.24.0\nB=2\n");
        // Only the first line that sets it, and nothing that merely mentions it.
        assert_eq!(set_version("X_COMMONVEIL_VERSION=1\nCOMMONVEIL_VERSION=a\nCOMMONVEIL_VERSION=b", "0.24.0"), "X_COMMONVEIL_VERSION=1\nCOMMONVEIL_VERSION=0.24.0\nCOMMONVEIL_VERSION=b");
        // Windows line ends stay as they were.
        assert_eq!(set_version("A=1\r\nCOMMONVEIL_VERSION=latest\r\n", "0.24.0"), "A=1\r\nCOMMONVEIL_VERSION=0.24.0\r\n");
        assert_eq!(set_version("A=1\rCOMMONVEIL_VERSION=latest", "1.0.0"), "A=1\rCOMMONVEIL_VERSION=1.0.0");
        // Added when it isn't there, on a line of its own.
        assert_eq!(set_version("A=1", "0.24.0"), "A=1\nCOMMONVEIL_VERSION=0.24.0\n");
        assert_eq!(set_version("A=1\n", "0.24.0"), "A=1\nCOMMONVEIL_VERSION=0.24.0\n");
        assert_eq!(set_version("", "0.24.0"), "\nCOMMONVEIL_VERSION=0.24.0\n");
        assert_eq!(set_version("# COMMONVEIL_VERSION=1\n", "2.0.0"), "# COMMONVEIL_VERSION=1\nCOMMONVEIL_VERSION=2.0.0\n");
        let text = "A=1\nCOMMONVEIL_VERSION=0.23.1\n";
        assert_eq!(version_line(text).map(|(a, b)| &text[a..b]), Some("COMMONVEIL_VERSION=0.23.1"));
    }

    #[test]
    fn times_read_as_javascript_writes_them() {
        assert_eq!(iso(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso(1_700_000_000_123), "2023-11-14T22:13:20.123Z");
        assert_eq!(iso(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(iso(4_102_444_799_999), "2099-12-31T23:59:59.999Z");
        assert_eq!(now_iso().len(), 24);
    }

    #[test]
    fn only_the_exact_token() {
        let token = "t".repeat(32);
        assert!(authorised(format!("Bearer {token}").as_bytes(), &token));
        for got in [String::new(), token.clone(), format!("bearer {token}"), format!("Bearer {token}x"), format!("Bearer {}", "t".repeat(31))] {
            assert!(!authorised(got.as_bytes(), &token), "{got}");
        }
    }

    fn settings(project: &str, health_url: &str) -> Settings {
        Settings { project: project.into(), token: "t".repeat(32), service: "app".into(), health_url: health_url.into(), allow_downgrade: false, health_wait: Duration::from_millis(300), health_every: Duration::from_millis(50) }
    }

    #[test]
    fn a_version_that_never_answers_counts_as_failed() {
        // Nothing listens there, so the app never comes up healthy.
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let s = settings("/nonexistent", &format!("http://127.0.0.1:{port}/api/health"));
        let started = Instant::now();
        assert!(!healthy(&s, "0.24.0"));
        assert!(started.elapsed() >= Duration::from_millis(300));
        assert_eq!(running_version(&s.health_url), "");
    }

    #[test]
    fn docker_that_cant_run_reads_as_node_said_it() {
        let dir = tempfile::tempdir().unwrap();
        let s = settings(&format!("{}/missing", dir.path().display()), "http://127.0.0.1:9/");
        assert_eq!(compose(&s, &["pull", "app"]), Err("spawn docker ENOENT".to_string()));
        // .env can't be written there either: nothing changed, and that's what the status says.
        let outcome = update(&s, "0.24.0");
        assert_eq!((outcome["ok"].clone(), outcome["rolled_back"].clone(), outcome["version"].clone()), (json!(false), json!(true), json!("0.24.0")));
    }
}
