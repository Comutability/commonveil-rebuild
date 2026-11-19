//! The scheduled tasks, run directly against a fresh site's store.
use std::collections::HashMap;

use commonveil_server::config::Config;
use commonveil_server::db::Db;
use commonveil_server::{maintenance, App};
use serde_json::json;

fn app(dir: &std::path::Path) -> std::sync::Arc<App> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let env: HashMap<String, String> = [("DATA_DIR", dir.to_str().unwrap()), ("SITE_URL", "https://cv.example")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    App::new(Config::load(&env, &root).unwrap(), &root.join("base44/entities")).unwrap()
}

#[test]
fn tasks_remove_only_what_is_due() {
    let dir = tempfile::tempdir().unwrap();
    let app = app(dir.path());
    let sr = Db::service(&app.store);
    let now = commonveil_server::sessions::now_ms();
    let past = commonveil_server::store::iso(now - 60_000);
    let later = commonveil_server::store::iso(now + 3_600_000);
    sr.create("Message", json!({ "conversation_id": "c1", "msg_id": "m1", "envelope": "x", "expires_at": past })).unwrap();
    sr.create("Message", json!({ "conversation_id": "c1", "msg_id": "m2", "envelope": "x", "expires_at": later })).unwrap();
    sr.create("Message", json!({ "conversation_id": "c1", "msg_id": "m3", "envelope": "x", "expires_at": "" })).unwrap();
    sr.create("ServerBan", json!({ "server_id": "s1", "user_id": "u1", "expires_at": past })).unwrap();
    sr.create("ServerBan", json!({ "server_id": "s1", "user_id": "u2", "expires_at": "" })).unwrap();
    sr.create("VoiceTicket", json!({ "room": "r", "user_id": "u1", "expires_at": past })).unwrap();
    sr.create("CvRefresh", json!({ "user_id": "u1", "expires_at": past })).unwrap();
    let doomed = sr.create("Conversation", json!({ "kind": "group", "member_ids": ["u1"], "destroy_at": past })).unwrap();
    sr.create("Message", json!({ "conversation_id": doomed["id"], "msg_id": "m4", "envelope": "x" })).unwrap();

    maintenance::reset_throttle();
    let (status, out) = maintenance::run(&app, "expire", now);
    assert_eq!(status, 200, "{out}");
    assert_eq!(out["removed"], 1);
    assert_eq!(out["bans_lifted"], 1);
    assert_eq!(out["passes_removed"], 1);
    assert_eq!(out["sign_in_removed"], 1);
    assert_eq!(out["done"], true);
    assert_eq!(sr.filter("Message", json!({ "conversation_id": "c1" }), "created_date", 10).unwrap().len(), 2);
    assert_eq!(sr.filter("ServerBan", json!({}), "created_date", 10).unwrap().len(), 1);

    let (status, again) = maintenance::run(&app, "expire", now);
    assert_eq!((status, again["skipped"].as_str()), (200, Some("ran recently")));

    let (status, out) = maintenance::run(&app, "deliver", now);
    assert_eq!(status, 200, "{out}");
    assert_eq!(out["destroyed"], 1);
    assert!(sr.get("Conversation", doomed["id"].as_str().unwrap()).is_none());
    assert!(sr.filter("Message", json!({ "msg_id": "m4" }), "created_date", 1).unwrap().is_empty());

    let (status, out) = maintenance::run(&app, "inactive", now);
    assert_eq!((status, out["deleted"].clone()), (200, json!(0)), "{out}");
    assert_eq!(maintenance::run(&app, "everything", now).0, 400);
}
