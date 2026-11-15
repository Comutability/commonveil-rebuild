//! The self-hosted Commonveil server, in Rust.
//!
//! It replaces `server/` (Node.js) and the backend in `base44/shared` (TypeScript) stage by
//! stage, keeping the same HTTP API and the same data on disk. Until every part is here, the
//! Docker image keeps running the Node.js server: see rust/README.md for what is done.
pub mod config;
pub mod http;
pub mod js;
pub mod seo;
pub mod store;
pub mod timsort;

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
const NOT_YET: [&str; 4] = ["/api/functions/", "/api/entities/", "/api/files/", "/api/admin/updates"];

pub struct App {
    pub config: Config,
    pub store: Store,
}

impl App {
    pub fn new(config: Config, entities_dir: &Path) -> rusqlite::Result<Arc<Self>> {
        let store = Store::open(config.db_file.to_str().unwrap_or(":memory:"), store::load_schemas(entities_dir))?;
        Ok(Arc::new(Self { config, store }))
    }

    pub fn router(self: &Arc<Self>) -> Router {
        Router::new().fallback(handle).with_state(self.clone())
    }
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
    if NOT_YET.iter().any(|p| path.starts_with(p)) {
        return http::json(501, &json!({ "error": "This part of the server hasn't moved to Rust yet.", "code": "NOT_YET" }));
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
