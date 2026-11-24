//! HTTP helpers and the built site, matching `server/http.mjs`.
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use axum::body::Body;
use axum::http::{HeaderValue, Method, Response, StatusCode};
use serde_json::Value;

use crate::seo;

pub const SECURITY_HEADERS: [(&str, &str); 5] = [
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Permissions-Policy", "camera=(self), microphone=(self), display-capture=(self), geolocation=(), payment=(), usb=(), interest-cohort=()"),
];

/// The self-hosted site's Content Security Policy header (csp.config.mjs, SELF_HOSTED_CSP_HEADER).
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; manifest-src 'self'; form-action 'self'; base-uri 'none'; object-src 'none'; frame-src 'none'; worker-src 'self'; media-src 'self' blob:; require-trusted-types-for 'script'; trusted-types voice-worker service-worker json-ld; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'";

pub fn response(status: u16, body: impl Into<Body>, headers: &[(&str, String)]) -> Response<Body> {
    let mut r = Response::new(body.into());
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let h = r.headers_mut();
    for (k, v) in SECURITY_HEADERS {
        h.insert(k, HeaderValue::from_static(v));
    }
    for (k, v) in headers {
        if let Ok(v) = HeaderValue::from_str(v) {
            h.insert(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v);
        }
    }
    r
}

/// `send`: text, no caching.
pub fn send(status: u16, body: &str, headers: &[(&str, String)]) -> Response<Body> {
    let mut all = vec![("Cache-Control", "no-store".to_string())];
    all.extend_from_slice(headers);
    response(status, body.to_string(), &all)
}

/// `json`: a JSON reply, no caching.
pub fn json(status: u16, body: &Value) -> Response<Body> {
    response(
        status,
        body.to_string(),
        &[
            ("Cache-Control", "no-store".into()),
            ("Content-Type", "application/json; charset=utf-8".into()),
        ],
    )
}

fn content_type(ext: &str) -> &'static str {
    match ext {
        ".html" => "text/html; charset=utf-8",
        ".js" | ".mjs" => "text/javascript; charset=utf-8",
        ".css" => "text/css; charset=utf-8",
        ".json" => "application/json; charset=utf-8",
        ".svg" => "image/svg+xml",
        ".png" => "image/png",
        ".jpg" | ".jpeg" => "image/jpeg",
        ".webp" => "image/webp",
        ".ico" => "image/x-icon",
        ".woff2" => "font/woff2",
        ".woff" => "font/woff",
        ".txt" => "text/plain; charset=utf-8",
        ".xml" => "application/xml; charset=utf-8",
        ".webmanifest" => "application/manifest+json",
        ".wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

fn ext_of(p: &str) -> String {
    let name = p.rsplit('/').next().unwrap_or("");
    match name.rfind('.') {
        Some(i) if i > 0 => name[i..].to_lowercase(),
        _ => String::new(),
    }
}

struct SeoAssets {
    html: String,
    articles: Vec<Value>,
}
type SeoCache = Mutex<Vec<(PathBuf, std::sync::Arc<SeoAssets>)>>;
fn seo_assets(dist: &Path) -> std::sync::Arc<SeoAssets> {
    static CACHE: OnceLock<SeoCache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(Vec::new()));
    let mut c = cache.lock().unwrap();
    if let Some((_, a)) = c.iter().find(|(p, _)| p == dist) {
        return a.clone();
    }
    let articles = std::fs::read_to_string(dist.join("help-index.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let a = std::sync::Arc::new(SeoAssets {
        html: std::fs::read_to_string(dist.join("index.html")).unwrap_or_default(),
        articles,
    });
    c.push((dist.to_path_buf(), a.clone()));
    a
}

/// The page for a path, with its own tags.
pub fn page_for(dist: &Path, pathname: &str, site_url: &str) -> (String, seo::Meta) {
    let assets = seo_assets(dist);
    let meta = seo::seo_for(pathname, &assets.articles, site_url);
    let block = regex::Regex::new(r"<!-- seo:[^>]*-->[\s\S]*?<!-- /seo -->").unwrap();
    let head = seo::head_html(&meta, site_url);
    let body = if block.is_match(&assets.html) {
        block
            .replacen(&assets.html, 1, regex::NoExpand(&head))
            .into_owned()
    } else {
        assets.html.clone()
    };
    (body, meta)
}

/// `path.posix.normalize("/" + rel)`, then refuse anything that climbs out.
fn safe_join(root: &Path, rel: &str) -> Option<PathBuf> {
    let mut out = root.to_path_buf();
    for c in Path::new(&format!("/{rel}")).components() {
        match c {
            Component::Normal(p) => out.push(p),
            Component::ParentDir => {
                if out == root {
                    continue;
                }
                out.pop();
            }
            _ => {}
        }
    }
    out.starts_with(root).then_some(out)
}

/// Serve the built site, falling back to index.html for the app's own routes.
pub fn serve_static(
    method: &Method,
    path_and_query: &str,
    dist: &Path,
    site_url: &str,
) -> Response<Body> {
    let raw = path_and_query.split('?').next().unwrap_or("/");
    let Ok(rel) = percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .map(|s| s.into_owned())
    else {
        return send(400, "Bad path", &[]);
    };
    if rel.contains('\0') {
        return send(400, "Bad path", &[]);
    }
    let root = std::path::absolute(dist).unwrap_or_else(|_| dist.to_path_buf());
    let Some(mut file) = safe_join(&root, &rel) else {
        return send(404, "Not found", &[]);
    };
    let mut is_index = false;
    if !file.is_file() {
        // A missing asset is a 404; anything else is a page of the app.
        if rel.starts_with("/assets/") || !ext_of(&rel).is_empty() {
            return send(404, "Not found", &[("Content-Type", "text/plain".into())]);
        }
        file = root.join("index.html");
        is_index = true;
    }
    let fname = file.to_string_lossy().replace('\\', "/");
    let ext = ext_of(&fname);
    let cache = if is_index
        || ext == ".html"
        || fname.ends_with("/sw.js")
        || fname.ends_with("/manifest.webmanifest")
    {
        "no-cache"
    } else if fname.contains("/assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "public, max-age=3600"
    };
    let mut headers = vec![
        ("Content-Type", content_type(&ext).to_string()),
        ("Cache-Control", cache.to_string()),
    ];
    if ext == ".html" {
        headers.push(("Content-Security-Policy", CSP.into()));
        headers.push(("X-Frame-Options", "DENY".into()));
    }
    let head = method == Method::HEAD;
    if is_index && !site_url.is_empty() {
        let (body, meta) = page_for(&root, &rel, site_url);
        if !meta.moved_to.is_empty() {
            return response(
                301,
                Body::empty(),
                &[
                    ("Location", meta.moved_to),
                    ("Cache-Control", "public, max-age=86400".into()),
                ],
            );
        }
        if meta.noindex {
            headers.push(("X-Robots-Tag", "noindex, nofollow".into()));
        }
        return response(
            if meta.not_found { 404 } else { 200 },
            if head {
                Body::empty()
            } else {
                Body::from(body)
            },
            &headers,
        );
    }
    // The sitemap and robots file are written for the usual address; this site's own goes in.
    if !site_url.is_empty() && (fname.ends_with("/sitemap.xml") || fname.ends_with("/robots.txt")) {
        let text = std::fs::read_to_string(&file)
            .unwrap_or_default()
            .replace(seo::SITE_PLACEHOLDER, site_url.trim_end_matches('/'));
        if fname.ends_with(".xml") {
            headers[0].1 = "application/xml; charset=utf-8".into();
        }
        return response(
            200,
            if head {
                Body::empty()
            } else {
                Body::from(text)
            },
            &headers,
        );
    }
    if head {
        return response(200, Body::empty(), &headers);
    }
    match std::fs::read(&file) {
        Ok(bytes) => response(200, bytes, &headers),
        Err(_) => send(404, "Not found", &[]),
    }
}
