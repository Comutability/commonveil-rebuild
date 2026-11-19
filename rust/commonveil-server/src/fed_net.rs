//! Talking to other Commonveil sites (server/federation/net.mjs): the site's own signing key,
//! signed requests (inspired by HTTP Message Signatures, as ActivityPub uses them), checking other
//! sites' signatures against the keys they publish, sealed requests (CVP-015), and safe outbound
//! connections. The wire format itself (what's signed, digests, which addresses are off limits,
//! the sealed relay) is Secure Net's, from `secure_net_core::wire`.
use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD, URL_SAFE_NO_PAD};
use base64::engine::DecodePaddingMode;
use base64::Engine;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier, VerifyingKey};
use rusqlite::{params, OptionalExtension};
use secure_net_core::wire::federation::{self as wire, RequestFields, PROTOCOL, SITE_DOCUMENT, SKEW_MS};
use secure_net_core::wire::sealed;
use serde_json::{json, Value};

use crate::api::ApiError;
use crate::js::{to_js_string, truthy};
use crate::protocol::js_stringify;
use crate::store::Store;

const MAX_RESPONSE: usize = 4 * 1024 * 1024;
const MAX_FILE_PART: usize = 2 * 1024 * 1024;
const DOC_TTL_MS: i64 = 60 * 60_000;
/// At most this many reads from other sites at once; the rest wait their turn.
const MAX_OUTBOUND: usize = 16;
/// The DER header of an Ed25519 private key in PKCS #8, as the Node.js server stores it.
const ED25519_PKCS8_PREFIX: [u8; 16] = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
/// Node.js's `Buffer.from(s, "base64url")`: padding or not, stray bits allowed.
const B64U_LOOSE: GeneralPurpose = GeneralPurpose::new(&base64::alphabet::URL_SAFE, GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true).with_decode_padding_mode(DecodePaddingMode::Indifferent));

pub type FedResult<T> = std::result::Result<T, ApiError>;

/// A FederationError: a status, a code and a message people can read.
pub fn fed_err(status: u16, code: &str, message: impl AsRef<str>) -> ApiError {
    ApiError::new(status, code, message.as_ref())
}

pub fn b64u(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn unb64u(s: &str) -> Option<Vec<u8>> {
    B64U_LOOSE.decode(s.trim_end_matches('=')).ok()
}

/// The first `n` UTF-16 units of a string, as JavaScript's `slice`.
pub fn js_slice(s: &str, n: usize) -> String {
    let units: Vec<u16> = s.encode_utf16().take(n).collect();
    String::from_utf16_lossy(&units)
}

fn now_ms() -> i64 {
    crate::sessions::now_ms()
}

/// A site address in its one accepted form.
pub fn norm_host(h: &str) -> FedResult<String> {
    wire::norm_host(h).ok_or_else(|| fed_err(400, "BAD_SITE", "That isn't a site address."))
}

/// `host` without a trailing `:port`.
pub fn strip_port(host: &str) -> &str {
    match host.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    }
}

// ---------- the site's own key ----------

pub struct SiteKey {
    pub public: String,
    signing: SigningKey,
}

impl SiteKey {
    pub fn sign(&self, data: &str) -> String {
        b64u(&self.signing.sign(data.as_bytes()).to_bytes())
    }
}

/// The site's Ed25519 key, made once and kept with the data, in the form the Node.js server keeps
/// it: `{ private: base64 PKCS #8, public: base64url raw, created }`.
pub fn site_key(store: &Store) -> Result<SiteKey, String> {
    if let Some(saved) = store.get_setting("federation:site-key").filter(|v| truthy(Some(v))) {
        let der = saved["private"].as_str().and_then(|p| STANDARD.decode(p).ok()).filter(|d| d.len() == 48 && d[..16] == ED25519_PKCS8_PREFIX).ok_or("The site's federation key is damaged, so the server can't start.")?;
        let seed: [u8; 32] = der[16..].try_into().expect("32 bytes");
        return Ok(SiteKey { public: to_js_string(saved.get("public")), signing: SigningKey::from_bytes(&seed) });
    }
    let random = crate::crypto::random_bytes(32);
    let seed: [u8; 32] = random[..32].try_into().expect("32 bytes");
    let signing = SigningKey::from_bytes(&seed);
    let public = b64u(signing.verifying_key().as_bytes());
    let der = [&ED25519_PKCS8_PREFIX[..], &seed].concat();
    store.set_setting("federation:site-key", Some(&json!({ "private": STANDARD.encode(der), "public": public, "created": crate::shared::iso(now_ms()) })));
    Ok(SiteKey { public, signing })
}

pub fn verify_ed25519(public_raw: &str, data: &str, signature: &str) -> bool {
    let (Some(pk), Some(sig)) = (unb64u(public_raw), unb64u(signature)) else { return false };
    let Ok(pk) = <[u8; 32]>::try_from(pk.as_slice()) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else { return false };
    let Ok(sig) = Signature::from_slice(&sig) else { return false };
    vk.verify(data.as_bytes(), &sig).is_ok()
}

// ---------- outbound connections ----------

/// Where a site is, by name: (host, path, websocket?) to a URL. Tests map every site to a port
/// on this machine; the real world uses https (wss) to the name itself.
pub type UrlFor = Arc<dyn Fn(&str, &str, bool) -> String + Send + Sync>;

pub struct Reply {
    pub status: u16,
    pub data: Value,
}

/// Outbound connections to other sites. By default only https, and never to private, loopback or
/// link-local addresses (so another site can't make this one probe its own network). Private
/// networks can allow those with FEDERATION_ALLOW_PRIVATE=true (then http works for local names).
pub struct Transport {
    pub allow_private: bool,
    host_header: bool,
    url_for: Option<UrlFor>,
    agent: ureq::Agent,
    bytes_agent: ureq::Agent,
    busy: Mutex<usize>,
    freed: Condvar,
}

struct Slot<'a>(&'a Transport);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        *self.0.busy.lock().unwrap_or_else(|e| e.into_inner()) -= 1;
        self.0.freed.notify_one();
    }
}

/// Addresses for an outbound connection, refusing any private, loopback or link-local answer.
/// Used when connecting, so a name that changes its answer in between (DNS rebinding) can't
/// reach a private address.
fn public_addrs(netloc: &str, allow_private: bool) -> std::io::Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = netloc.to_socket_addrs()?.collect();
    if !allow_private && (addrs.is_empty() || addrs.iter().any(|a| wire::is_private(&a.ip().to_string()))) {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("{netloc} points at a private address")));
    }
    Ok(addrs)
}

/// The JavaScript's test for names that get plain http when private addresses are allowed.
fn local_name(host: &str) -> bool {
    let tail = |suffix: &str| {
        host.match_indices(suffix).any(|(i, _)| {
            let rest = &host[i + suffix.len()..];
            rest.is_empty() || rest.starts_with(':')
        })
    };
    host.starts_with("localhost") || host.starts_with("127.") || host.starts_with("[::1]") || tail(".localhost") || tail(".test")
}

pub trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}
pub type Upstream = tokio_tungstenite::WebSocketStream<Box<dyn Io>>;

impl Transport {
    pub fn new(allow_private: bool) -> Self {
        Self::build(allow_private, false, None)
    }

    /// For tests: every site reachable by name through `url_for`, which says which site is meant
    /// in X-Forwarded-Host (every test site is on 127.0.0.1).
    pub fn mapped(url_for: UrlFor) -> Self {
        Self::build(true, true, Some(url_for))
    }

    fn build(allow_private: bool, host_header: bool, url_for: Option<UrlFor>) -> Self {
        let agent = |secs: u64| ureq::AgentBuilder::new().redirects(0).timeout(Duration::from_secs(secs)).resolver(move |netloc: &str| public_addrs(netloc, allow_private)).build();
        Self { allow_private, host_header, url_for, agent: agent(15), bytes_agent: agent(30), busy: Mutex::new(0), freed: Condvar::new() }
    }

    fn slot(&self) -> Slot<'_> {
        let mut n = self.busy.lock().unwrap_or_else(|e| e.into_inner());
        while *n >= MAX_OUTBOUND {
            n = self.freed.wait(n).unwrap_or_else(|e| e.into_inner());
        }
        *n += 1;
        Slot(self)
    }

    /// The name's addresses, all public (unless private addresses are allowed).
    fn check(&self, host: &str) -> FedResult<()> {
        if self.allow_private {
            return Ok(());
        }
        let name = strip_port(host);
        let ips: Vec<IpAddr> = match name.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => (name, 0u16).to_socket_addrs().map(|a| a.map(|s| s.ip()).collect()).unwrap_or_default(),
        };
        if ips.is_empty() {
            return Err(fed_err(502, "SITE_UNREACHABLE", format!("Can't find {host}.")));
        }
        if ips.iter().any(|ip| wire::is_private(&ip.to_string())) {
            return Err(fed_err(403, "PRIVATE_ADDRESS", format!("{host} points at a private address.")));
        }
        Ok(())
    }

    pub fn url(&self, host: &str, path: &str, ws: bool) -> String {
        if let Some(f) = &self.url_for {
            return f(host, path, ws);
        }
        let plain = self.allow_private && local_name(host);
        let scheme = match (plain, ws) {
            (true, false) => "http",
            (true, true) => "ws",
            (false, false) => "https",
            (false, true) => "wss",
        };
        format!("{scheme}://{host}{path}")
    }

    /// One request to another site: `{ status, data }`, data being the JSON reply or null.
    pub fn request(&self, host: &str, path: &str, method: &str, headers: &[(String, String)], body: Option<&str>) -> FedResult<Reply> {
        let _slot = self.slot();
        self.check(host)?;
        let mut req = self.agent.request(method, &self.url(host, path, false)).set("User-Agent", &format!("Commonveil ({PROTOCOL})"));
        if self.host_header {
            req = req.set("X-Forwarded-Host", host);
        }
        for (k, v) in headers {
            req = req.set(k, v);
        }
        let res = match body {
            Some(b) => req.send_string(b),
            None => req.call(),
        };
        let res = match res {
            Ok(r) | Err(ureq::Error::Status(_, r)) => r,
            Err(ureq::Error::Transport(t)) => {
                let slow = t.to_string().to_lowercase().contains("timed out");
                return Err(fed_err(502, "SITE_UNREACHABLE", format!("Can't reach {host} right now.{}", if slow { " It took too long to answer." } else { "" })));
            }
        };
        let status = res.status();
        let too_large = || fed_err(502, "TOO_LARGE", format!("{host} sent too much."));
        if res.header("content-length").and_then(|v| v.trim().parse::<f64>().ok()).is_some_and(|n| n > MAX_RESPONSE as f64) {
            return Err(too_large());
        }
        // Counted as it arrives and cut off at the limit, whatever the length header said (CV-17).
        let mut raw = Vec::new();
        res.into_reader().take(MAX_RESPONSE as u64 + 1).read_to_end(&mut raw).map_err(|_| fed_err(502, "SITE_UNREACHABLE", format!("Can't reach {host} right now.")))?;
        if raw.len() > MAX_RESPONSE {
            return Err(too_large());
        }
        let text = String::from_utf8_lossy(&raw);
        let data = if text.is_empty() { Value::Null } else { serde_json::from_str(&text).unwrap_or(Value::Null) };
        Ok(Reply { status, data })
    }

    /// Bytes from another site (a file's encrypted parts), or None.
    pub fn bytes(&self, host: &str, path: &str) -> Option<Vec<u8>> {
        let _slot = self.slot();
        self.check(host).ok()?;
        let mut req = self.bytes_agent.get(&self.url(host, path, false));
        if self.host_header {
            req = req.set("X-Forwarded-Host", host);
        }
        let res = req.call().ok()?;
        if res.status() != 200 {
            return None;
        }
        let mut raw = Vec::new();
        res.into_reader().take(MAX_FILE_PART as u64 + 1).read_to_end(&mut raw).ok()?;
        (raw.len() <= MAX_FILE_PART).then_some(raw)
    }

    /// A WebSocket to a room on another site, with these headers (signed by the caller).
    pub async fn websocket(&self, host: &str, path: &str, headers: &[(String, String)]) -> FedResult<Upstream> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let unreachable = || fed_err(502, "SITE_UNREACHABLE", format!("Can't reach {host} right now."));
        let url = self.url(host, path, true);
        let parsed = url::Url::parse(&url).map_err(|_| unreachable())?;
        let secure = parsed.scheme() == "wss";
        let name = parsed.host_str().ok_or_else(unreachable)?.to_string();
        let port = parsed.port_or_known_default().ok_or_else(unreachable)?;
        let (allow, host_owned, netloc) = (self.allow_private, host.to_string(), format!("{name}:{port}"));
        let me_check = Transport::new(allow);
        let addrs = tokio::task::spawn_blocking(move || -> FedResult<Vec<SocketAddr>> {
            me_check.check(&host_owned)?;
            public_addrs(&netloc, allow).map_err(|_| fed_err(403, "PRIVATE_ADDRESS", format!("{host_owned} points at a private address.")))
        })
        .await
        .map_err(|_| unreachable())??;
        let mut tcp = None;
        for addr in addrs {
            if let Ok(Ok(s)) = tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(addr)).await {
                tcp = Some(s);
                break;
            }
        }
        let tcp = tcp.ok_or_else(unreachable)?;
        let stream: Box<dyn Io> = if secure {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_safe_default_protocol_versions().map_err(|_| unreachable())?.with_root_certificates(roots).with_no_client_auth();
            let server = rustls::pki_types::ServerName::try_from(name.clone()).map_err(|_| unreachable())?;
            let tls = tokio::time::timeout(Duration::from_secs(10), tokio_rustls::TlsConnector::from(Arc::new(config)).connect(server, tcp)).await.map_err(|_| unreachable())?.map_err(|_| unreachable())?;
            Box::new(tls)
        } else {
            Box::new(tcp)
        };
        let mut request = url.as_str().into_client_request().map_err(|_| unreachable())?;
        let h = request.headers_mut();
        let mut all: Vec<(String, String)> = Vec::new();
        if self.host_header {
            all.push(("X-Forwarded-Host".into(), host.into()));
        }
        all.extend_from_slice(headers);
        for (k, v) in all {
            if let (Ok(k), Ok(v)) = (axum::http::HeaderName::from_bytes(k.as_bytes()), axum::http::HeaderValue::from_str(&v)) {
                h.insert(k, v);
            }
        }
        let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default().max_message_size(Some(64 * 1024)).max_frame_size(Some(64 * 1024));
        let (ws, _) = tokio::time::timeout(Duration::from_secs(10), tokio_tungstenite::client_async_with_config(request, stream, Some(config))).await.map_err(|_| unreachable())?.map_err(|_| unreachable())?;
        Ok(ws)
    }
}

// ---------- signing and checking ----------

struct SiteRow {
    key: String,
    first_seen: String,
    blocked: bool,
    pq: Option<String>,
}

/// A checked request from another site: who sent it, as whom, its (opened) body, and how to
/// answer it (sealed under the request's own key, when it came sealed).
pub struct Checked {
    pub from: String,
    pub user: String,
    pub body: String,
    reply: Option<(Vec<u8>, String)>,
}

impl Checked {
    /// The answer as it goes back: sealed for a sealed request, as it is otherwise.
    pub fn answer(&self, data: &Value) -> FedResult<Value> {
        match &self.reply {
            None => Ok(data.clone()),
            Some((key, context)) => {
                let sealed = sealed::seal_reply(key, &js_stringify(data), context).map_err(|_| fed_err(500, "INTERNAL", "Something went wrong."))?;
                Ok(json!({ "sealed": sealed }))
            }
        }
    }
}

/// Signing outbound requests, and checking inbound ones.
pub struct Signer {
    pub host: String,
    pub key: SiteKey,
    pub transport: Transport,
    relay: Mutex<Option<Value>>,
    nonces: Mutex<HashMap<String, i64>>,
    docs: Mutex<HashMap<String, (Value, i64)>>,
}

impl Signer {
    pub fn new(host: &str, store: &Store, transport: Transport) -> Result<Self, String> {
        store.with_db(|db| -> rusqlite::Result<()> {
            db.execute_batch("CREATE TABLE IF NOT EXISTS fed_sites (host TEXT PRIMARY KEY, key TEXT NOT NULL, name TEXT, handle_domain TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, blocked INTEGER NOT NULL DEFAULT 0)")?;
            let has_pq = db.prepare("PRAGMA table_info(fed_sites)")?.query_map([], |r| r.get::<_, String>(1))?.flatten().any(|c| c == "pq");
            if !has_pq {
                db.execute_batch("ALTER TABLE fed_sites ADD COLUMN pq TEXT")?;
            }
            Ok(())
        })
        .map_err(|e| e.to_string())?;
        Ok(Self { host: host.into(), key: site_key(store)?, transport, relay: Mutex::new(None), nonces: Mutex::new(HashMap::new()), docs: Mutex::new(HashMap::new()) })
    }

    fn site_row(&self, store: &Store, host: &str) -> Option<SiteRow> {
        store.with_db(|db| {
            db.query_row("SELECT key, first_seen, blocked, pq FROM fed_sites WHERE host = ?", [host], |r| Ok(SiteRow { key: r.get(0)?, first_seen: r.get(1)?, blocked: r.get::<_, i64>(2)? != 0, pq: r.get(3)? })).optional().ok().flatten()
        })
    }

    /// This site's relay keys, made once and kept with the data.
    pub fn relay_keys(&self, store: &Store) -> FedResult<Value> {
        let mut made = self.relay.lock().unwrap_or_else(|e| e.into_inner());
        if made.is_none() {
            let saved = match store.get_setting("federation:relay-keys").filter(|v| truthy(Some(v))) {
                Some(s) => s,
                None => {
                    let k = sealed::generate_keys().map_err(|_| fed_err(500, "INTERNAL", "Something went wrong."))?;
                    store.set_setting("federation:relay-keys", Some(&k));
                    k
                }
            };
            *made = Some(saved);
        }
        Ok(made.clone().expect("made"))
    }

    /// What the site document says about them.
    pub fn relay_doc(&self, store: &Store) -> FedResult<Value> {
        let k = self.relay_keys(store)?;
        Ok(json!({ "suite": sealed::SUITE, "kem": k["kem"]["public"], "sig": k["sig"]["public"] }))
    }

    /// The headers of a signed request: Ed25519 and ML-DSA-65 over the same base.
    pub fn headers(&self, store: &Store, method: &str, to: &str, path: &str, body: &str, user: Option<&str>) -> FedResult<Vec<(String, String)>> {
        let date = crate::shared::iso(now_ms());
        let nonce = b64u(&crate::crypto::random_bytes(16));
        let digest = wire::digest_of(body.as_bytes());
        let user = user.unwrap_or("");
        let base = wire::signature_base(&RequestFields { method, to, path, from: &self.host, date: &date, nonce: &nonce, digest: &digest, user });
        let relay = self.relay_keys(store)?;
        let pq = sealed::sign(relay["sig"]["secret"].as_str().unwrap_or(""), &base).map_err(|_| fed_err(500, "INTERNAL", "Something went wrong."))?;
        let mut out = vec![
            ("CV-From".to_string(), self.host.clone()),
            ("CV-Date".into(), date),
            ("CV-Nonce".into(), nonce),
            ("CV-Digest".into(), digest),
            ("CV-Signature".into(), self.key.sign(&base)),
            ("CV-PQ-Signature".into(), pq),
        ];
        if !user.is_empty() {
            out.push(("CV-User".into(), user.into()));
        }
        Ok(out)
    }

    /// POST JSON to another site, signed, and sealed for it if it publishes relay keys.
    pub fn post(&self, store: &Store, to: &str, path: &str, payload: &Value, user: Option<&str>) -> FedResult<Reply> {
        self.refuse_blocked(store, to)?;
        let mut body = js_stringify(payload);
        let peer = sealed::relay_keys_of(&self.site_doc(store, to)?);
        let context = sealed::relay_context(&self.host, to, path);
        let mut reply_key = None;
        if let Some(p) = &peer {
            let (s, key) = sealed::seal(p["kem"].as_str().unwrap_or(""), &body, &context).map_err(|_| fed_err(502, "SITE_ERROR", format!("{to}'s relay key isn't usable.")))?;
            body = json!({ "sealed": s }).to_string();
            reply_key = Some(key);
        }
        let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];
        if peer.is_some() {
            headers.push(("CV-Sealed".into(), "1".into()));
        }
        headers.extend(self.headers(store, "POST", to, path, &body, user)?);
        let r = self.transport.request(to, path, "POST", &headers, Some(&body))?;
        let Some(key) = reply_key else { return Ok(r) };
        if let Some(s) = r.data.get("sealed").and_then(Value::as_str) {
            let opened = sealed::open_reply(&key, s, &context).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok());
            return match opened {
                Some(data) => Ok(Reply { status: r.status, data }),
                None => Err(fed_err(502, "SITE_ERROR", format!("{to}'s reply couldn't be opened."))),
            };
        }
        // A refusal before the request was opened comes back plain; an answer never does.
        if r.status < 400 {
            return Err(fed_err(502, "SITE_ERROR", format!("{to} answered a sealed request in the clear.")));
        }
        Ok(r)
    }

    /// Where one of a site's endpoints is, from its site document (act, directory, inbox, ...).
    pub fn endpoint(&self, store: &Store, host: &str, name: &str) -> FedResult<String> {
        Ok(wire::endpoints_of(&self.site_doc(store, host)?)[name].as_str().unwrap_or("").to_string())
    }

    /// POST to one of a site's endpoints by name, wherever that site keeps it.
    pub fn send(&self, store: &Store, to: &str, name: &str, payload: &Value, user: Option<&str>) -> FedResult<Reply> {
        let path = self.endpoint(store, to, name)?;
        self.post(store, to, &path, payload, user)
    }

    fn refuse_blocked(&self, store: &Store, host: &str) -> FedResult<()> {
        if self.site_row(store, host).is_some_and(|r| r.blocked) {
            return Err(fed_err(403, "SITE_BLOCKED", format!("This site doesn't talk to {host}.")));
        }
        Ok(())
    }

    /// Another site's public document, and its key pinned on first contact.
    pub fn site_doc(&self, store: &Store, host: &str) -> FedResult<Value> {
        let host = norm_host(host)?;
        let now = now_ms();
        if let Some((doc, at)) = self.docs.lock().unwrap_or_else(|e| e.into_inner()).get(&host) {
            if now - at < DOC_TTL_MS {
                return Ok(doc.clone());
            }
        }
        let r = self.transport.request(&host, SITE_DOCUMENT, "GET", &[], None)?;
        let d = &r.data;
        if r.status != 200 || d["protocol"] != PROTOCOL || d["host"] != host.as_str() || !d["key"]["public"].is_string() {
            return Err(fed_err(502, "NOT_A_SITE", format!("{host} isn't a Commonveil site, or doesn't talk to other sites.")));
        }
        let pinned = self.site_row(store, &host);
        let relay_now = sealed::relay_keys_of(d).unwrap_or(Value::Null);
        let relay_was: Value = pinned.as_ref().and_then(|p| p.pq.as_deref()).and_then(|t| serde_json::from_str(t).ok()).unwrap_or(Value::Null);
        let public = d["key"]["public"].as_str().unwrap_or("").to_string();
        if let Some(p) = &pinned {
            if p.key != "-" && (p.key != public || !sealed::relay_keys_acceptable(&relay_was, &relay_now)) {
                eprintln!("[federation] {host} now presents a different key; refusing it until an admin accepts the change");
                return Err(fed_err(403, "SITE_KEY_CHANGED", format!("{host}'s key changed. An admin of this site has to accept the change first.")));
            }
        }
        let at = crate::shared::iso(now);
        let name = js_slice(&if truthy(d.get("name")) { to_js_string(d.get("name")) } else { String::new() }, 80);
        let handle_domain = if truthy(d.get("handle_domain")) { to_js_string(d.get("handle_domain")) } else { host.clone() };
        let first_seen = pinned.as_ref().map_or(at.clone(), |p| p.first_seen.clone());
        store.with_db(|db| -> rusqlite::Result<()> {
            db.execute("INSERT INTO fed_sites (host, key, name, handle_domain, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(host) DO UPDATE SET name = excluded.name, handle_domain = excluded.handle_domain, last_seen = excluded.last_seen", params![host, public, name, handle_domain, first_seen, at])?;
            if pinned.as_ref().is_some_and(|p| p.key == "-") {
                db.execute("UPDATE fed_sites SET key = ? WHERE host = ?", params![public, host])?;
            }
            // Relay keys are pinned with the site's key; a site may start sealing, never stop.
            if truthy(Some(&relay_now)) && relay_was.is_null() {
                db.execute("UPDATE fed_sites SET pq = ? WHERE host = ?", params![js_stringify(&relay_now), host])?;
            }
            Ok(())
        })
        .map_err(|_| fed_err(500, "INTERNAL", "Something went wrong."))?;
        self.docs.lock().unwrap_or_else(|e| e.into_inner()).insert(host, (r.data.clone(), now));
        Ok(r.data)
    }

    /// Check a signed request from another site. `h` reads a request header (lower-case name).
    pub fn verify(&self, store: &Store, method: &str, h: &dyn Fn(&str) -> String, body: &str, path: &str) -> FedResult<Checked> {
        let from = norm_host(&h("cv-from"))?;
        if from == self.host {
            return Err(fed_err(400, "SELF", "A site doesn't talk to itself."));
        }
        self.refuse_blocked(store, &from)?;
        let date = h("cv-date");
        let now = now_ms();
        let t = crate::dates::parse(&date).unwrap_or(f64::NAN);
        if !t.is_finite() || (now as f64 - t).abs() > SKEW_MS as f64 {
            return Err(fed_err(401, "STALE", "The request's time is off."));
        }
        let nonce = h("cv-nonce");
        if !(16..=64).contains(&nonce.len()) || !nonce.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
            return Err(fed_err(401, "BAD_SIGNATURE", "Missing nonce."));
        }
        let seen = format!("{from}:{nonce}");
        if self.nonces.lock().unwrap_or_else(|e| e.into_inner()).contains_key(&seen) {
            return Err(fed_err(401, "REPLAY", "That request was already used."));
        }
        let digest = h("cv-digest");
        if digest != wire::digest_of(body.as_bytes()) {
            return Err(fed_err(401, "BAD_DIGEST", "The body doesn't match its digest."));
        }
        let doc = self.site_doc(store, &from)?;
        let user = h("cv-user");
        let base = wire::signature_base(&RequestFields { method, to: &self.host, path, from: &from, date: &date, nonce: &nonce, digest: &digest, user: &user });
        if !verify_ed25519(doc["key"]["public"].as_str().unwrap_or(""), &base, &h("cv-signature")) {
            return Err(fed_err(401, "BAD_SIGNATURE", "The signature didn't verify."));
        }
        // A site that publishes relay keys is held to them: both signatures, and sealed bodies.
        let peer = sealed::relay_keys_of(&doc);
        let is_sealed = h("cv-sealed") == "1";
        if let Some(p) = &peer {
            if !sealed::verify(p["sig"].as_str().unwrap_or(""), &base, &h("cv-pq-signature")) {
                return Err(fed_err(401, "BAD_SIGNATURE", "The post-quantum signature didn't verify."));
            }
            if method == "POST" && !is_sealed {
                return Err(fed_err(401, "UNSEALED", "This site only takes sealed requests from that site."));
            }
        }
        {
            let mut nonces = self.nonces.lock().unwrap_or_else(|e| e.into_inner());
            nonces.insert(seen, now);
            if nonces.len() > 20_000 {
                nonces.retain(|_, at| now - *at <= 2 * SKEW_MS);
            }
        }
        if !is_sealed {
            return Ok(Checked { from, user, body: body.into(), reply: None });
        }
        // Opened only now that it's known who sent it. The reply goes back under the request's own key.
        let context = sealed::relay_context(&from, &self.host, path);
        let relay = self.relay_keys(store)?;
        let opened = serde_json::from_str::<Value>(body).ok().and_then(|outer| outer["sealed"].as_str().map(String::from)).and_then(|s| sealed::open(relay["kem"]["secret"].as_str().unwrap_or(""), &s, &context).ok());
        match opened {
            Some((text, key)) => Ok(Checked { from, user, body: text, reply: Some((key, context)) }),
            None => Err(fed_err(400, "CANNOT_OPEN", "That request wasn't sealed for this site.")),
        }
    }

    pub fn sites(&self, store: &Store) -> Value {
        store.with_db(|db| {
            let rows = db.prepare("SELECT host, name, handle_domain, first_seen, last_seen, blocked FROM fed_sites ORDER BY last_seen DESC LIMIT 500").and_then(|mut st| {
                st.query_map([], |r| {
                    Ok(json!({
                        "host": r.get::<_, String>(0)?, "name": r.get::<_, Option<String>>(1)?, "handle_domain": r.get::<_, Option<String>>(2)?,
                        "first_seen": r.get::<_, String>(3)?, "last_seen": r.get::<_, String>(4)?, "blocked": r.get::<_, i64>(5)? != 0,
                    }))
                })
                .map(|it| it.flatten().collect::<Vec<_>>())
            });
            Value::Array(rows.unwrap_or_default())
        })
    }

    pub fn set_blocked(&self, store: &Store, host: &str, blocked: bool) -> FedResult<()> {
        let host = norm_host(host)?;
        let at = crate::shared::iso(now_ms());
        store.with_db(|db| -> rusqlite::Result<()> {
            if db.query_row("SELECT 1 FROM fed_sites WHERE host = ?", [&host], |_| Ok(())).optional()?.is_none() {
                db.execute("INSERT INTO fed_sites (host, key, name, handle_domain, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(host) DO UPDATE SET name = excluded.name, handle_domain = excluded.handle_domain, last_seen = excluded.last_seen", params![host, "-", "", host, at, at])?;
            }
            db.execute("UPDATE fed_sites SET blocked = ? WHERE host = ?", params![i64::from(blocked), host])?;
            Ok(())
        })
        .map_err(|_| fed_err(500, "INTERNAL", "Something went wrong."))?;
        self.docs.lock().unwrap_or_else(|e| e.into_inner()).remove(&host);
        Ok(())
    }

    /// Accept a site's new key (after an admin checked the change was expected).
    pub fn forget(&self, store: &Store, host: &str) -> FedResult<()> {
        let host = norm_host(host)?;
        store.with_db(|db| db.execute("DELETE FROM fed_sites WHERE host = ?", [&host]).map(|_| ())).map_err(|_| fed_err(500, "INTERNAL", "Something went wrong."))?;
        self.docs.lock().unwrap_or_else(|e| e.into_inner()).remove(&host);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_names_get_plain_http_only_when_private_addresses_are_allowed() {
        for (host, local) in [("localhost:3000", true), ("127.0.0.1", true), ("a.test", true), ("a.test:80", true), ("a.testing", false), ("x.localhost", true), ("example.org", false)] {
            assert_eq!(local_name(host), local, "{host}");
        }
        let open = Transport::new(true);
        assert_eq!(open.url("a.test:8080", "/x", true), "ws://a.test:8080/x");
        assert_eq!(Transport::new(false).url("a.test", "/x", false), "https://a.test/x");
    }

    #[test]
    fn private_addresses_are_refused() {
        let t = Transport::new(false);
        assert_eq!(t.check("127.0.0.1").unwrap_err().code, "PRIVATE_ADDRESS");
        assert_eq!(t.check("10.1.2.3:443").unwrap_err().code, "PRIVATE_ADDRESS");
        assert!(public_addrs("127.0.0.1:443", false).is_err());
        assert!(public_addrs("127.0.0.1:443", true).is_ok());
    }

    #[test]
    fn signatures_check_out() {
        let seed = [7u8; 32];
        let key = SiteKey { public: b64u(SigningKey::from_bytes(&seed).verifying_key().as_bytes()), signing: SigningKey::from_bytes(&seed) };
        let sig = key.sign("hello");
        assert!(verify_ed25519(&key.public, "hello", &sig));
        assert!(!verify_ed25519(&key.public, "hellO", &sig));
        assert!(!verify_ed25519("short", "hello", &sig));
    }
}
