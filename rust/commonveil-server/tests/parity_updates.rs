//! The update checker and installer (/api/admin/updates) against the Node.js server, with a
//! stand-in release list and updater served by the test: the same script runs against both, and
//! every answer must match once times and backup names are blanked.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;

use serde_json::{json, Value};

mod common;
use common::servers::{people, Who};
use common::{blank, compare, post, ready, start_with, Flow, Kit};

/// Answers the release list at /releases and an updater at /update and /status.
fn stand_in() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut s = stream;
            let mut buf = [0u8; 8192];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let path = req.split(' ').nth(1).unwrap_or("").to_string();
            let (status, body) = if path.starts_with("/releases") {
                (200, json!([
                    { "tag_name": "v9.9.8", "name": "Older", "body": "old", "html_url": "https://example.org/9.9.8", "published_at": "2026-01-01T00:00:00Z" },
                    { "tag_name": "v10.0.0", "name": "Ten", "body": "big", "html_url": "https://example.org/10", "published_at": "2026-03-01T00:00:00Z" },
                    { "tag_name": "v9.9.10", "name": "Patch", "body": "fix", "html_url": "http://insecure.example", "published_at": "2026-02-01T00:00:00Z" },
                    { "tag_name": "v11.0.0", "name": "Draft", "draft": true },
                    { "tag_name": "v12.0.0", "name": "Pre", "prerelease": true },
                    { "tag_name": "banana", "name": "Bad" },
                ]))
            } else if path.starts_with("/missing") {
                (404, json!({ "message": "Not Found" }))
            } else if path.starts_with("/update") {
                (202, json!({ "ok": true }))
            } else if path.starts_with("/status") {
                (200, json!({ "busy": true, "last": null }))
            } else {
                (404, json!({}))
            };
            let text = body.to_string();
            let _ = write!(s, "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}", text.len());
        }
    });
    port
}

fn updates(f: &mut Flow, step: &str, w: &Who, method: &str, body: Value) {
    let (status, reply) = post(f.port, method, "/api/admin/updates", &w.token, &body.to_string());
    if let Some(name) = reply["applying"]["backup"].as_str() {
        assert!(name.starts_with("commonveil-9.9.9-to-10.0.0-") && name.ends_with(".db"), "{name}");
    }
    let reply = blank(&reply);
    f.log.push(json!({ "step": step, "status": status, "reply": reply }));
}

fn script(port: u16, data: &Path, kits: &[Kit]) -> Vec<Value> {
    let mut f = Flow::new(port);
    let people = people(&mut f, data, &["alice", "bob"], kits);
    let (alice, bob) = (&people[0], &people[1]);
    updates(&mut f, "not an admin", bob, "GET", json!(null));
    updates(&mut f, "status before a check", alice, "GET", json!(null));
    updates(&mut f, "check", alice, "POST", json!({ "action": "check" }));
    updates(&mut f, "unknown action", alice, "POST", json!({ "action": "dance" }));
    updates(&mut f, "apply: not a version", alice, "POST", json!({ "action": "apply", "version": "ten" }));
    updates(&mut f, "apply: older", alice, "POST", json!({ "action": "apply", "version": "9.9.8" }));
    updates(&mut f, "automatic updates on", alice, "POST", json!({ "action": "set_auto", "auto": true }));
    updates(&mut f, "automatic updates off", alice, "POST", json!({ "action": "set_auto", "auto": "yes" }));
    updates(&mut f, "apply the newest", alice, "POST", json!({ "action": "apply" }));
    updates(&mut f, "status while applying", alice, "GET", json!(null));
    let backups = std::fs::read_dir(data.join("backups")).map(|d| d.count()).unwrap_or(0);
    f.log.push(json!({ "step": "a backup was made", "status": 200, "reply": backups }));
    updates(&mut f, "PUT", alice, "PUT", json!({}));
    f.log
}

fn script_without_updater(port: u16, data: &Path, kits: &[Kit]) -> Vec<Value> {
    let mut f = Flow::new(port);
    let people = people(&mut f, data, &["alice"], kits);
    updates(&mut f, "check: the list isn't there", &people[0], "POST", json!({ "action": "check" }));
    updates(&mut f, "apply: no updater", &people[0], "POST", json!({ "action": "apply", "version": "10.0.0" }));
    f.log
}

#[test]
fn updates_answer_as_the_node_server_does() {
    if !ready() {
        eprintln!("skipped: node, the npm packages or dist-selfhost aren't there");
        return;
    }
    let feed = stand_in();
    let extra = [("UPDATE_FEED", format!("http://127.0.0.1:{feed}/releases")), ("UPDATER_URL", format!("http://127.0.0.1:{feed}/")), ("UPDATER_TOKEN", "updater-token".to_string())];
    let kits: Vec<Kit> = (0..2).map(|_| Kit::new()).collect();
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (node, rust) = (start_with(true, d1.path(), &extra), start_with(false, d2.path(), &extra));
    let (a, b) = (script(node.1, d1.path(), &kits), script(rust.1, d2.path(), &kits));
    compare(&a, &b);
    let applied = a.iter().find(|s| s["step"] == "status while applying").unwrap();
    assert_eq!(applied["reply"]["applying"]["version"], "10.0.0", "{applied}");

    let extra = [("UPDATE_FEED", format!("http://127.0.0.1:{feed}/missing"))];
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (node, rust) = (start_with(true, d1.path(), &extra), start_with(false, d2.path(), &extra));
    compare(&script_without_updater(node.1, d1.path(), &kits), &script_without_updater(rust.1, d2.path(), &kits));
}
