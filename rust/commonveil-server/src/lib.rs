//! The self-hosted Commonveil server, in Rust.
//!
//! It replaces `server/` (Node.js) and the backend in `base44/shared` (TypeScript) stage by
//! stage, keeping the same HTTP API and the same data on disk. Until every part is here, the
//! Docker image keeps running the Node.js server: see rust/README.md for what is done.
pub mod api;
pub mod bootstrap;
pub mod config;
pub mod conversations;
pub mod crypto;
pub mod db;
pub mod deletion;
pub mod dates;
pub mod http;
pub mod identity;
pub mod js;
pub mod keys;
pub mod messages;
pub mod notifications;
pub mod permissions;
pub mod profile;
pub mod safety;
pub mod seo;
pub mod server_messages;
pub mod file_store;
pub mod actors;
pub mod rooms;
pub mod cli;
pub mod files;
pub mod updates;
pub mod maintenance;
pub mod moderation;
pub mod protocol;
pub mod snips;
pub mod voice_events;
pub mod servers;
pub mod servers_build;
pub mod servers_core;
pub mod servers_template;
pub mod shared;
pub mod sessions;
pub mod store;
pub mod timsort;
pub mod verify;
pub mod webpush;
pub mod webauthn;

use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{Method, Response};
use axum::Router;
use serde_json::json;

use crate::config::Config;
use crate::store::Store;

/// What the Node.js server answers that this one doesn't do yet (so a half-ported server can't be
/// mistaken for a working one).
const ENTITY_OPS: [&str; 6] = ["filter", "list", "get", "create", "update", "delete"];
/// Tables the app only ever reads through the backend functions (CV-06): direct reads are refused.
const FUNCTIONS_ONLY: [&str; 1] = ["ServerMessage"];
const MAX_JSON: usize = 256 * 1024;

pub struct App {
    pub config: Config,
    pub store: Store,
    pub keys: sessions::Keys,
    pub bootstrap: bootstrap::Bootstrap,
    pub files: file_store::FileStore,
    pub actors: Arc<actors::Host>,
    functions: std::collections::BTreeMap<&'static str, api::Actions>,
}

impl App {
    pub fn new(config: Config, entities_dir: &Path) -> rusqlite::Result<Arc<Self>> {
        let mut store = Store::open(config.db_file.to_str().unwrap_or(":memory:"), store::load_schemas(entities_dir))?;
        let files = file_store::FileStore::new(&config.files_dir, &config.secret, &config.site_url);
        // Deleting a file's row removes the file.
        let on_files = files.clone();
        store.on_remove = Some(Box::new(move |entity: &str, _id: &str, row: &serde_json::Value| {
            if entity == "Attachment" && crate::js::truthy(row.get("file_uri")) {
                on_files.remove(row["file_uri"].as_str().unwrap_or(""));
            }
        }));
        let bootstrap = bootstrap::Bootstrap::new(&config.data_dir);
        bootstrap.prepare(&store);
        Ok(Arc::new_cyclic(|me| Self { config, store, keys: sessions::Keys::default(), bootstrap, files, actors: actors::Host::new(me.clone()), functions: [("identity", identity::actions()), ("profile", profile::actions()), ("keys", keys::actions()), ("conversations", conversations::actions()), ("messages", messages::actions()), ("notifications", notifications::actions()), ("safety", safety::safety_actions()), ("admin", safety::admin_actions()), ("disclose", safety::disclosure_actions()), ("invite", servers::invite_actions()), ("servers", servers::actions()), ("channels", server_messages::actions()), ("voice", voice_events::voice_actions()), ("events", voice_events::event_actions()), ("files", files::actions()), ("moderation", moderation::actions()), ("protocol", protocol::actions()), ("snips", snips::actions())].into_iter().collect() }))
    }

    /// Who's calling: Commonveil sign-in's access token, sent as the bearer token. The user is
    /// their record with id, email and role filled in, as the Node.js server makes it.
    pub fn session_for(&self, token: &str) -> Option<(serde_json::Value, sessions::Session)> {
        let session = sessions::verify_access(&self.keys, &self.store, Some(&serde_json::Value::String(token.into())), sessions::now_ms())?;
        let record = sessions::user_record(&self.store, &session.user_id)?;
        let mut user = record.clone();
        user["id"] = record["id"].clone();
        user["email"] = if crate::js::truthy(record.get("email")) { record["email"].clone() } else { json!("") };
        user["role"] = if crate::js::truthy(record.get("role")) { record["role"].clone() } else { json!("user") };
        Some((user, session))
    }

    pub fn router(self: &Arc<Self>) -> Router {
        Router::new().fallback(handle).with_state(self.clone())
    }
}

fn bearer(req: &Request) -> String {
    let h = req.headers().get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    h.strip_prefix("Bearer ").map(|t| t.trim().to_string()).unwrap_or_default()
}

/// The rules' view of a signed-in person.
pub fn person_of(user: &serde_json::Value) -> store::Person {
    store::Person { id: user["id"].as_str().unwrap_or("").into(), email: user["email"].as_str().unwrap_or("").into(), record: user.as_object().cloned().unwrap_or_default() }
}

/// `/api/entities/<table>/<op>`: reads (and the few allowed writes) as the caller, under the
/// table's row rules.
async fn entities(app: Arc<App>, req: Request, path: &str) -> Response<Body> {
    let mut parts = path["/api/entities/".len()..].splitn(2, '/');
    let (name, op) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("").to_string());
    if req.method() != Method::POST || !ENTITY_OPS.contains(&op.as_str()) || !app.store.schemas.contains_key(&name) || FUNCTIONS_ONLY.contains(&name.as_str()) {
        return http::json(404, &json!({ "error": "Not found", "code": "NOT_FOUND" }));
    }
    let token = bearer(&req);
    let Ok(bytes) = axum::body::to_bytes(req.into_body(), MAX_JSON).await else {
        // The Node.js server answers 500 here (its size error isn't one it expects); 413 is what it means.
        return http::json(413, &json!({ "error": "That request is too large.", "code": "TOO_LARGE" }));
    };
    let text = String::from_utf8_lossy(&bytes);
    let b: serde_json::Value = match serde_json::from_str(if text.is_empty() { "{}" } else { &text }) {
        Ok(v) => v,
        Err(_) => return http::json(400, &json!({ "error": "The request wasn't valid JSON.", "code": "ERROR" })),
    };
    let user = app.session_for(&token).map(|(u, _)| person_of(&u));
    let u = user.as_ref();
    let s = &app.store;
    let num = |k: &str| crate::js::to_number(b.get(k));
    let limit = { let l = num("limit"); (if l.is_nan() || l == 0.0 { 200.0 } else { l }).min(500.0) };
    let skip = { let k = num("skip"); if k.is_nan() { 0.0 } else { k } };
    let sort = b.get("sort").filter(|v| v.is_string());
    let sid = || crate::js::to_js_string(b.get("id"));
    let data = || if crate::js::truthy(b.get("data")) { b["data"].clone() } else { json!({}) };
    // `b.query && typeof b.query === "object" ? b.query : {}`
    let query = if b["query"].is_object() || b["query"].is_array() { b["query"].clone() } else { json!({}) };
    let result = match op.as_str() {
        "filter" => s.person_filter(u, &name, &query, sort, Some(limit), Some(skip)).map(serde_json::Value::from),
        "list" => s.person_filter(u, &name, &json!({}), sort, Some(limit), Some(skip)).map(serde_json::Value::from),
        "get" => s.person_get(u, &name, &sid()),
        "create" => s.person_create(u, &name, &data()),
        "update" => s.person_update(u, &name, &sid(), &data()),
        _ => s.person_delete(u, &name, &sid()),
    };
    match result {
        Ok(v) => http::json(200, &v),
        Err(e) if [400, 403, 404].contains(&e.status) => http::json(e.status, &json!({ "error": e.message, "code": "ERROR" })),
        Err(_) => http::json(500, &json!({ "error": "Something went wrong.", "code": "ERROR" })),
    }
}

/// `/api/functions/<name>`: one backend function's action, as the caller.
async fn function(app: Arc<App>, req: Request, name: &str) -> Response<Body> {
    if req.method() != Method::POST || !app.functions.contains_key(name) {
        return http::json(404, &json!({ "error": "Unknown function.", "code": "NOT_FOUND" }));
    }
    let options = api::RunOptions {
        allow_anonymous: name == "identity" || name == "disclose" || name == "invite",
        max_body_bytes: if name == "files" { files::FILES_MAX_BODY } else { api::Limits::MAX_BODY_BYTES },
    };
    let token = bearer(&req);
    let Ok(bytes) = axum::body::to_bytes(req.into_body(), options.max_body_bytes + 1024).await else {
        return http::json(413, &json!({ "error": "That request is too large.", "code": "TOO_LARGE" }));
    };
    let raw = String::from_utf8_lossy(&bytes).into_owned();
    let name = name.to_string();
    let out = tokio::task::spawn_blocking(move || {
        let who = app.session_for(&token);
        let (user, session) = match who {
            Some((u, s)) => (Some(u), Some(s)),
            None => (None, None),
        };
        let Some(actions) = app.functions.get(name.as_str()) else { return (404, json!({ "error": "Unknown function.", "code": "NOT_FOUND" })) };
        api::run_action(&app, user, session, &raw, actions, &options)
    })
    .await;
    match out {
        Ok((status, v)) => http::json(status, &v),
        Err(_) => http::json(500, &json!({ "error": "Something went wrong. Nothing was changed.", "code": "INTERNAL" })),
    }
}

/// `/api/files/<name>?exp=&sig=`: a file behind a signed, short-lived link.
fn file_link(app: &App, head: bool, name: &str, query: &str) -> Response<Body> {
    let get = |k: &str| url::form_urlencoded::parse(query.as_bytes()).find(|(n, _)| n == k).map(|(_, v)| v.into_owned()).unwrap_or_default();
    let Some(file) = app.files.open(name, &get("exp"), &get("sig"), sessions::now_ms()) else {
        return http::json(404, &json!({ "error": "That link has expired.", "code": "NOT_FOUND" }));
    };
    let Ok(bytes) = std::fs::read(&file) else {
        return http::json(404, &json!({ "error": "That link has expired.", "code": "NOT_FOUND" }));
    };
    let headers = [
        ("Content-Type", "application/octet-stream".to_string()),
        ("Cache-Control", "private, no-store".to_string()),
        ("X-Content-Type-Options", "nosniff".to_string()),
        ("Referrer-Policy", "no-referrer".to_string()),
        ("Content-Length", bytes.len().to_string()),
    ];
    http::response(200, if head { Vec::new() } else { bytes }, &headers)
}

async fn handle(State(app): State<Arc<App>>, req: Request) -> Response<Body> {
    let path = req.uri().path().to_string();
    let pq = req.uri().path_and_query().map_or(path.clone(), |p| p.as_str().to_string());
    let c = &app.config;
    if path == "/api/health" {
        return http::json(200, &json!({ "ok": true, "version": c.version }));
    }
    if path == "/api/site" {
        return http::json(200, &json!({
            "id": "self-hosted",
            "public_settings": { "auth_config": { "enable_username_password": true, "mfa_policy": "off" } },
            "site": { "name": c.site_name, "version": c.version, "federation": c.federation, "handle_domain": c.handle_domain, "email": false },
        }));
    }
    if path.starts_with("/api/actors/") && req.headers().get("upgrade").and_then(|v| v.to_str().ok()).is_some_and(|v| v.eq_ignore_ascii_case("websocket")) {
        return actors::upgrade(app.clone(), req).await;
    }
    if path.starts_with("/api/entities/") {
        return entities(app.clone(), req, &path).await;
    }
    if let Some(name) = path.strip_prefix("/api/functions/") {
        let name = name.to_string();
        return function(app.clone(), req, &name).await;
    }
    if let Some(name) = path.strip_prefix("/api/files/").filter(|_| req.method() == Method::GET || req.method() == Method::HEAD) {
        return file_link(&app, req.method() == Method::HEAD, name, req.uri().query().unwrap_or(""));
    }
    if path.starts_with("/api/admin/updates") {
        let method = req.method().as_str().to_string();
        let token = bearer(&req);
        let body = axum::body::to_bytes(req.into_body(), 4096).await.unwrap_or_default();
        let app = app.clone();
        let out = tokio::task::spawn_blocking(move || {
            let user = app.session_for(&token).map(|(u, _)| u);
            updates::route(&app, &method, user.as_ref(), &body)
        })
        .await;
        return match out {
            Ok((status, v)) => http::json(status, &v),
            Err(_) => http::json(500, &json!({ "error": "Something went wrong.", "code": "INTERNAL" })),
        };
    }
    if path.starts_with("/api/") {
        return http::json(404, &json!({ "error": "Not found", "code": "NOT_FOUND" }));
    }
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return http::send(405, "Method not allowed", &[]);
    }
    let method = req.method().clone();
    let dist = c.dist_dir.clone();
    let site = c.site_url.clone();
    tokio::task::spawn_blocking(move || http::serve_static(&method, &pq, &dist, &site)).await.unwrap_or_else(|_| http::json(500, &json!({ "error": "Something went wrong.", "code": "INTERNAL" })))
}
