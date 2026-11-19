//! Updates for a self-hosted site (server/updates.mjs): checks for new releases, tells admins,
//! and asks the updater container (updater/) to install one, now or automatically. Before an
//! update the database is copied to DATA_DIR/backups, so an update can always be undone.
//!
//! The check reads the project's public release list (UPDATE_FEED). It sends nothing about this
//! site: GitHub sees an ordinary request from this server's address, a few times a day.
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use crate::js::{to_js_string, truthy};
use crate::App;

const SETTINGS_KEY: &str = "updates:settings";
const STATUS_KEY: &str = "updates:status";
const KEEP_BACKUPS: usize = 5;
/// An update that hasn't come back on its new version by then didn't work.
const APPLY_DEADLINE_MS: f64 = 20.0 * 60_000.0;

// ---------- versions (src/lib/site/releases.js) ----------

fn parts(v: &str) -> Option<[u64; 3]> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let p: Vec<&str> = v.split('.').collect();
    let lens = [4, 4, 6];
    if p.len() != 3 || p.iter().zip(lens).any(|(x, l)| x.is_empty() || x.len() > l || !x.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    Some([p[0].parse().ok()?, p[1].parse().ok()?, p[2].parse().ok()?])
}

pub fn is_version(v: &str) -> bool {
    !v.starts_with('v') && parts(v).is_some()
}

/// Older is less; anything malformed sorts oldest.
pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    match (parts(a), parts(b)) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => std::cmp::Ordering::Greater,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

pub fn is_newer(candidate: &str, current: &str) -> bool {
    compare_versions(candidate, current) == std::cmp::Ordering::Greater
}

fn js_slice(s: &str, n: usize) -> String {
    let units: Vec<u16> = s.encode_utf16().take(n).collect();
    String::from_utf16_lossy(&units)
}

fn wall_iso() -> String {
    crate::shared::iso(crate::sessions::now_ms())
}

// ---------- the updater ----------

fn settings(app: &App) -> Value {
    let mut s = json!({ "auto": false });
    if let Some(Value::Object(o)) = app.store.get_setting(SETTINGS_KEY) {
        for (k, v) in o {
            s[k] = v;
        }
    }
    s
}

fn status(app: &App) -> Value {
    app.store.get_setting(STATUS_KEY).unwrap_or_else(|| json!({ "checked_at": null, "latest": null, "error": null, "applying": null }))
}

fn set_status(app: &App, changes: Value) {
    let mut s = status(app);
    if !s.is_object() {
        s = json!({});
    }
    for (k, v) in changes.as_object().into_iter().flatten() {
        s[k] = v.clone();
    }
    app.store.set_setting(STATUS_KEY, Some(&s));
}

fn can_apply(app: &App) -> bool {
    !app.config.updater_url.is_empty() && !app.config.updater_token.is_empty()
}

fn updater_base(app: &App) -> String {
    app.config.updater_url.trim_end_matches('/').to_string()
}

fn agent(secs: u64) -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(Duration::from_secs(secs)).build()
}

fn version_of(r: &Value) -> String {
    let t = to_js_string(Some(&r["tag_name"]));
    t.strip_prefix('v').unwrap_or(&t).to_string()
}

/// Look for a newer release. Installs it straight away if automatic updates are on.
pub fn check(app: &App) -> Result<Value, String> {
    let result = (|| -> Result<Value, String> {
        let res = agent(15).get(&app.config.update_feed).set("Accept", "application/vnd.github+json").set("User-Agent", "Commonveil-update-check").call();
        let body = match res {
            Ok(r) => r.into_string().map_err(|e| e.to_string())?,
            Err(ureq::Error::Status(code, _)) => return Err(format!("The release list answered {code}")),
            Err(e) => return Err(e.to_string()),
        };
        let list: Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
        let mut releases: Vec<Value> = list
            .as_array()
            .into_iter()
            .flatten()
            .filter(|r| truthy(Some(r)) && !truthy(r.get("draft")) && !truthy(r.get("prerelease")) && is_version(&version_of(r)))
            .map(|r| {
                let url = r["html_url"].as_str().filter(|u| u.starts_with("https://")).map_or(Value::Null, |u| json!(u));
                json!({
                    "version": version_of(r),
                    "title": js_slice(&if truthy(r.get("name")) { to_js_string(r.get("name")) } else { String::new() }, 200),
                    "notes": js_slice(&if truthy(r.get("body")) { to_js_string(r.get("body")) } else { String::new() }, 20_000),
                    "url": url,
                    "published_at": if truthy(r.get("published_at")) { r["published_at"].clone() } else { Value::Null },
                })
            })
            .collect();
        releases.sort_by(|a, b| compare_versions(b["version"].as_str().unwrap_or(""), a["version"].as_str().unwrap_or("")));
        let latest = releases.first().cloned().unwrap_or(Value::Null);
        let newer: Vec<Value> = releases.iter().filter(|r| is_newer(r["version"].as_str().unwrap_or(""), &app.config.version)).cloned().collect();
        set_status(app, json!({ "checked_at": wall_iso(), "latest": latest, "newer": newer, "error": null }));
        let latest_version = latest["version"].as_str().unwrap_or("").to_string();
        if !latest.is_null() && is_newer(&latest_version, &app.config.version) && settings(app)["auto"] == true && can_apply(app) {
            println!("[updates] installing {latest_version} automatically");
            if let Err(e) = apply(app, &latest_version) {
                eprintln!("[updates] automatic update failed: {e}");
            }
        }
        Ok(status(app))
    })();
    if let Err(e) = &result {
        set_status(app, json!({ "checked_at": wall_iso(), "error": e }));
    }
    result
}

/// Copy the database with SQLite's own snapshot, keeping the last few.
pub fn backup(app: &App, label: &str) -> Result<std::path::PathBuf, String> {
    let dir = app.config.data_dir.join("backups");
    let _ = std::fs::create_dir_all(&dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    let stamp = wall_iso().replace([':', '.'], "-");
    let file = dir.join(format!("commonveil-{}-to-{label}-{stamp}.db", app.config.version));
    let _ = app.store.vacuum_into(&file);
    // The copy has to be there before anything else happens.
    if std::fs::metadata(&file).map_or(true, |m| m.len() == 0) {
        return Err("The backup couldn't be made, so nothing was changed.".into());
    }
    // Keep the newest few by when they were made, never by name, and never the one just made (CV-21).
    let mut old: Vec<(std::path::PathBuf, std::time::SystemTime)> = std::fs::read_dir(&dir)
        .map_err(|e| e.to_string())?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "db") && *p != file)
        .filter_map(|p| std::fs::metadata(&p).and_then(|m| m.modified()).ok().map(|t| (p, t)))
        .collect();
    old.sort_by_key(|o| std::cmp::Reverse(o.1));
    for (p, _) in old.iter().skip(KEEP_BACKUPS - 1) {
        let _ = std::fs::remove_file(p);
    }
    Ok(file)
}

fn base_name(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

pub fn apply(app: &App, version: &str) -> Result<Value, String> {
    if !is_version(version) {
        return Err("Not a version".into());
    }
    if !can_apply(app) {
        return Err("This site has no updater. See docs/SELF_HOSTING.md to add one.".into());
    }
    if !is_newer(version, &app.config.version) {
        return Err("That isn't newer than this site.".into());
    }
    let backup = backup(app, version)?;
    set_status(app, json!({ "applying": { "version": version, "at": wall_iso(), "backup": base_name(&backup) }, "error": null }));
    let res = agent(20).post(&format!("{}/update", updater_base(app))).set("Content-Type", "application/json").set("Authorization", &format!("Bearer {}", app.config.updater_token)).send_string(&json!({ "version": version }).to_string());
    match res {
        Ok(_) => Ok(json!({ "ok": true, "version": version, "backup": base_name(&backup) })),
        Err(ureq::Error::Status(code, r)) => {
            let out: Value = r.into_string().ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(json!({}));
            let msg = out["error"].as_str().filter(|e| !e.is_empty()).map(String::from);
            set_status(app, json!({ "applying": null, "error": msg.clone().unwrap_or_else(|| format!("The updater answered {code}")) }));
            Err(msg.unwrap_or_else(|| "The updater refused".into()))
        }
        Err(e) => {
            // Couldn't even ask: nothing is updating (CV-19).
            set_status(app, json!({ "applying": null, "error": format!("Couldn't reach the updater: {e}") }));
            Err("Couldn't reach the updater. Nothing was changed.".into())
        }
    }
}

/// Follow an update the updater accepted: report a failure or a rollback, and treat one that
/// hasn't finished in time as failed, so the admin can try again (CV-19).
pub fn reconcile(app: &App) {
    let a = status(app)["applying"].clone();
    let version = a["version"].as_str().unwrap_or("").to_string();
    if !a.is_object() || !is_newer(&version, &app.config.version) {
        return;
    }
    let job: Option<Value> = agent(5).get(&format!("{}/status", updater_base(app))).set("Authorization", &format!("Bearer {}", app.config.updater_token)).call().ok().and_then(|r| r.into_string().ok()).and_then(|t| serde_json::from_str(&t).ok());
    let at = crate::dates::parse(&to_js_string(a.get("at"))).unwrap_or(f64::NAN);
    if let Some(last) = job.as_ref().map(|j| &j["last"]).filter(|l| l.is_object()) {
        if last["version"] == version.as_str() && last["ok"] == false && crate::dates::parse(&to_js_string(last.get("at"))).unwrap_or(f64::NAN) >= at {
            let how = if last["rolled_back"] == false { " and going back failed too: check the server" } else { ", so the site went back to the version it had" };
            let extra = if truthy(last.get("error")) { to_js_string(last.get("error")) } else { String::new() };
            set_status(app, json!({ "applying": null, "error": format!("The update to {version} didn't work{how}. {extra}").trim().to_string() }));
            return;
        }
    }
    let busy = job.as_ref().is_some_and(|j| truthy(j.get("busy")));
    if !busy && crate::sessions::now_ms() as f64 - at > APPLY_DEADLINE_MS {
        set_status(app, json!({ "applying": null, "error": format!("The update to {version} didn't finish. You can try again.") }));
    }
}

pub fn view(app: &App) -> Value {
    let s = status(app);
    let current = &app.config.version;
    let newer_than = |r: &Value| r["version"].as_str().is_some_and(|v| is_newer(v, current));
    let latest = if truthy(s.get("latest")) && newer_than(&s["latest"]) { s["latest"].clone() } else { Value::Null };
    let applying = if truthy(s.get("applying")) && newer_than(&s["applying"]) { s["applying"].clone() } else { Value::Null };
    let mut out = json!({ "current": current, "available": latest });
    out["newer"] = json!(s["newer"].as_array().map(|n| n.iter().filter(|r| newer_than(r)).cloned().collect::<Vec<_>>()).unwrap_or_default());
    for k in ["checked_at", "error"] {
        if let Some(v) = s.get(k) {
            out[k] = v.clone();
        }
    }
    out["applying"] = applying;
    out["auto"] = settings(app)["auto"].clone();
    out["can_apply"] = json!(can_apply(app));
    out
}

/// `/api/admin/updates`: GET the status; POST `{ action: "check" | "apply" | "set_auto", auto }`.
/// Admins only. Runs on a blocking thread.
pub fn route(app: &App, method: &str, user: Option<&Value>, body: &[u8]) -> (u16, Value) {
    if !user.is_some_and(|u| u["role"] == "admin") {
        return (403, json!({ "error": "Admins only.", "code": "FORBIDDEN" }));
    }
    let failed = |e: String| (400, json!({ "error": e, "code": "UPDATE_FAILED" }));
    if method == "GET" {
        reconcile(app);
        return (200, view(app));
    }
    if method != "POST" {
        return (405, json!({ "error": "Use GET or POST.", "code": "METHOD" }));
    }
    let text = String::from_utf8_lossy(body);
    let body: Value = match serde_json::from_str(if text.is_empty() { "{}" } else { &text }) {
        Ok(v) => v,
        Err(e) => return failed(e.to_string()),
    };
    match body["action"].as_str() {
        Some("check") => {
            let _ = check(app);
            (200, view(app))
        }
        Some("set_auto") => {
            let mut s = settings(app);
            s["auto"] = json!(body["auto"] == true);
            app.store.set_setting(SETTINGS_KEY, Some(&s));
            (200, view(app))
        }
        Some("apply") => {
            let target = if truthy(body.get("version")) { to_js_string(body.get("version")) } else { view(app)["available"]["version"].as_str().unwrap_or("").to_string() };
            match apply(app, &target) {
                Ok(_) => (200, view(app)),
                Err(e) => failed(e),
            }
        }
        _ => (400, json!({ "error": "Unknown action.", "code": "UNKNOWN_ACTION" })),
    }
}

/// Check a minute after start, then every UPDATE_CHECK_HOURS.
pub fn start(app: &Arc<App>) {
    let app = app.clone();
    let every = Duration::from_millis((app.config.update_check_hours * 3_600_000.0).min(2f64.powi(31) - 1.0) as u64);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        loop {
            let a = app.clone();
            let _ = tokio::task::spawn_blocking(move || check(&a)).await;
            tokio::time::sleep(every).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_as_the_site_does() {
        assert!(is_newer("0.10.0", "0.9.9"));
        assert!(is_newer("1.0.0", "v0.99.99"));
        assert!(!is_newer("0.9.0", "0.9.0"));
        assert!(is_newer("0.0.1", "nonsense"));
        assert!(!is_version("v1.2.3") && !is_version("1.2") && !is_version("12345.0.0") && is_version("1234.5678.123456"));
    }
}
