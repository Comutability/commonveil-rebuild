//! The Commonveil Protocol between two sites, alpha.test and beta.test, run four ways: both
//! Node.js, both Rust, and each mixed pair. The same script (handles and documents, a conversation
//! across sites, a server on one site joined from the other with encrypted channels, files and a
//! realtime room carried across, people's choices, refusals and an admin's block) runs against
//! each pair, and every answer must match the Node.js pair's once random values are blanked. So the
//! Rust server both behaves as the Node.js one does and talks to it.
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use commonveil_server::config::Config;
use commonveil_server::fed_net::{Transport, UrlFor};
use commonveil_server::App;
use serde_json::{json, Value};
use tungstenite::client::IntoClientRequest;
use tungstenite::Message;

mod common;
use common::servers::{channel, people, rid, s, Keys, Who};
use common::{blank, compare, iso_at, now, ready, repo, sealed_item, succeeded, Flow, Kit};

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Node,
    Rust,
}

struct Site {
    name: String,
    port: u16,
    data: tempfile::TempDir,
    child: Option<Child>,
}

impl Drop for Site {
    fn drop(&mut self) {
        if let Some(c) = &mut self.child {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Running sites, and everything the script saw, in order.
struct Net {
    sites: Vec<Site>,
    log: Vec<Value>,
    _rt: tokio::runtime::Runtime,
}

fn site_env(name: &str, port: u16, data: &Path, extra: &[(&str, &str)]) -> HashMap<String, String> {
    let mut env: HashMap<String, String> = [
        ("DATA_DIR", data.to_string_lossy().into_owned()),
        ("SITE_URL", format!("http://{name}")),
        ("PORT", port.to_string()),
        ("BIND", "127.0.0.1".into()),
        ("TRUST_PROXY", "true".into()),
        ("FEDERATION_ALLOW_PRIVATE", "true".into()),
        ("UPDATE_CHECK_HOURS", "1000".into()),
        ("COMMONVEIL_VERSION", "9.9.9".into()),
        ("PASSWORD_ROUNDS", "1000".into()),
        (
            "DIST_DIR",
            repo().join("dist-selfhost").to_string_lossy().into_owned(),
        ),
        (
            "ENTITIES_DIR",
            repo()
                .join("base44/entities")
                .to_string_lossy()
                .into_owned(),
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    for (k, v) in extra {
        env.insert(k.to_string(), v.to_string());
    }
    env
}

fn start(plan: &[(&str, Kind)], extra: &[(&str, &str)]) -> Net {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let ports: Arc<Mutex<HashMap<String, u16>>> = Arc::default();
    let mut listeners = Vec::new();
    for (name, _) in plan {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        ports
            .lock()
            .unwrap()
            .insert(name.to_string(), l.local_addr().unwrap().port());
        listeners.push(l);
    }
    let map = serde_json::to_string(&*ports.lock().unwrap()).unwrap();
    let mut sites = Vec::new();
    for ((name, kind), listener) in plan.iter().zip(listeners) {
        let port = listener.local_addr().unwrap().port();
        let data = tempfile::tempdir().unwrap();
        let env = site_env(name, port, data.path(), extra);
        let child = match kind {
            Kind::Node => {
                drop(listener);
                let mut cmd = Command::new("node");
                cmd.arg(repo().join("rust/commonveil-server/tests/support/fed-site.mjs"))
                    .envs(&env)
                    .env("CV_SITE_PORTS", &map);
                Some(
                    cmd.stdout(Stdio::null())
                        .stderr(Stdio::inherit())
                        .spawn()
                        .unwrap(),
                )
            }
            Kind::Rust => {
                let p = ports.clone();
                let url_for: UrlFor = Arc::new(move |host: &str, path: &str, ws: bool| {
                    let h = commonveil_server::fed_net::strip_port(host);
                    let map = p.lock().unwrap();
                    let site = map
                        .keys()
                        .find(|n| h == n.as_str() || h.ends_with(&format!(".{n}")));
                    let port = site.map_or(1, |s| map[s]);
                    format!(
                        "{}://127.0.0.1:{port}{path}",
                        if ws { "ws" } else { "http" }
                    )
                });
                let config = Config::load(&env, &repo()).unwrap();
                let app = App::with_transport(
                    config,
                    &repo().join("base44/entities"),
                    Some(Transport::mapped(url_for)),
                )
                .unwrap();
                let _inside = rt.enter();
                app.federation.start();
                listener.set_nonblocking(true).unwrap();
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                rt.spawn(async move { axum::serve(listener, app.router()).await });
                None
            }
        };
        sites.push(Site {
            name: name.to_string(),
            port,
            data,
            child,
        });
    }
    for site in &sites {
        let up = (0..150).any(|_| {
            let ok = TcpStream::connect(("127.0.0.1", site.port)).is_ok();
            if !ok {
                std::thread::sleep(Duration::from_millis(100));
            }
            ok
        });
        assert!(up, "{} didn't start", site.name);
    }
    Net {
        sites,
        log: Vec::new(),
        _rt: rt,
    }
}

struct Raw {
    status: u16,
    location: String,
    body: Vec<u8>,
}

/// One HTTP request to a site, addressed to `host` (a site or one of its handles).
fn http(
    port: u16,
    method: &str,
    path: &str,
    host: &str,
    token: &str,
    body: &str,
    extra: &[(&str, String)],
) -> Raw {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nX-Forwarded-Host: {host}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n", body.len());
    if !token.is_empty() {
        head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    for (k, v) in extra {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    write!(s, "{head}\r\n{body}").unwrap();
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(raw.len());
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|x| x.parse().ok())
        .unwrap_or(0);
    let location = head
        .lines()
        .find_map(|l| {
            l.to_lowercase()
                .starts_with("location:")
                .then(|| l[9..].trim().to_string())
        })
        .unwrap_or_default();
    let mut body = raw.get(split + 4..).unwrap_or(&[]).to_vec();
    if head.to_lowercase().contains("transfer-encoding: chunked") {
        let (mut out, mut i) = (Vec::new(), 0);
        while let Some(end) = body[i..].windows(2).position(|w| w == b"\r\n") {
            let size = usize::from_str_radix(String::from_utf8_lossy(&body[i..i + end]).trim(), 16)
                .unwrap_or(0);
            if size == 0 {
                break;
            }
            out.extend_from_slice(&body[i + end + 2..i + end + 2 + size]);
            i += end + 2 + size + 2;
        }
        body = out;
    }
    Raw {
        status,
        location,
        body,
    }
}

impl Net {
    fn port(&self, site: &str) -> u16 {
        self.sites.iter().find(|s| s.name == site).unwrap().port
    }
    fn data(&self, site: &str) -> &Path {
        self.sites
            .iter()
            .find(|s| s.name == site)
            .unwrap()
            .data
            .path()
    }
    /// Blank what's random, with each site's port standing for its name.
    fn blank(&self, v: &Value) -> Value {
        let mut text = v.to_string();
        for s in &self.sites {
            text = text.replace(&format!("127.0.0.1:{}", s.port), &format!("<{}>", s.name));
        }
        fn walk(v: &Value) -> Value {
            match v {
                Value::String(s) if s.contains("/api/fed/files/") => {
                    json!("<link through this site>")
                }
                Value::String(s) if s.contains("/api/files/") => json!("<file link>"),
                Value::String(s) if s.contains('~') => json!("<cursor for several sites>"),
                Value::Array(a) => Value::Array(a.iter().map(walk).collect()),
                Value::Object(o) => {
                    Value::Object(o.iter().map(|(k, x)| (k.clone(), walk(x))).collect())
                }
                _ => v.clone(),
            }
        }
        blank(&walk(&serde_json::from_str(&text).unwrap()))
    }
    fn record(&mut self, step: String, status: u16, reply: &Value) {
        let reply = self.blank(reply);
        self.log
            .push(json!({ "step": step, "status": status, "reply": reply }));
    }
    fn get(&mut self, site: &str, step: &str, path: &str, host: &str) -> Value {
        let r = http(self.port(site), "GET", path, host, "", "", &[]);
        let data: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        let mut shown = json!({ "body": data });
        if !r.location.is_empty() {
            shown["location"] = json!(r.location);
        }
        self.record(format!("{site}: {step}"), r.status, &shown);
        data
    }
    fn call(&mut self, site: &str, function: &str, step: &str, who: &Who, body: Value) -> Value {
        let r = http(
            self.port(site),
            "POST",
            &format!("/api/functions/{function}"),
            site,
            &who.token,
            &body.to_string(),
            &[],
        );
        let data: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        self.record(format!("{site}: {step}"), r.status, &data);
        data
    }
    fn raw_post(
        &mut self,
        site: &str,
        step: &str,
        path: &str,
        token: &str,
        body: &str,
        headers: &[(&str, String)],
    ) -> Value {
        let r = http(self.port(site), "POST", path, site, token, body, headers);
        let data: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        self.record(format!("{site}: {step}"), r.status, &data);
        data
    }
    fn register<'a>(&mut self, site: &str, names: &[&str], kits: &'a [Kit]) -> Vec<Who<'a>> {
        let mut f = Flow::new(self.port(site));
        let data = self.data(site).to_path_buf();
        let out = people(&mut f, &data, names, kits);
        for mut entry in f.log {
            entry["step"] = json!(format!("{site}: {}", entry["step"].as_str().unwrap_or("")));
            self.log.push(entry);
        }
        out
    }
}

/// A WebSocket to a site, as a browser on it would open one.
struct Socket {
    ws: Option<tungstenite::WebSocket<TcpStream>>,
}

impl Socket {
    fn open(net: &mut Net, site: &str, step: &str, path: &str) -> Socket {
        let stream = TcpStream::connect(("127.0.0.1", net.port(site))).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(1500)))
            .unwrap();
        let mut req = format!("ws://{site}{path}").into_client_request().unwrap();
        req.headers_mut()
            .insert("X-Forwarded-Host", site.parse().unwrap());
        let (ws, status) = match tungstenite::client(req, stream) {
            Ok((ws, _)) => (Some(ws), 101),
            Err(tungstenite::HandshakeError::Failure(tungstenite::Error::Http(r))) => {
                (None, r.status().as_u16())
            }
            Err(e) => panic!("{step}: {e}"),
        };
        net.record(format!("{site}: {step}"), status, &json!(null));
        Socket { ws }
    }
    fn send(&mut self, msg: Value) {
        if let Some(ws) = &mut self.ws {
            let _ = ws.send(Message::Text(msg.to_string().into()));
        }
    }
    fn read(&mut self, net: &mut Net, step: &str) {
        let mut got = Vec::new();
        if let Some(ws) = &mut self.ws {
            loop {
                match ws.read() {
                    Ok(Message::Text(t)) => {
                        got.push(serde_json::from_str(&t).unwrap_or(Value::Null))
                    }
                    Ok(Message::Close(f)) => {
                        got.push(json!({ "closed": f.as_ref().map(|c| u16::from(c.code)) }))
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
        net.record(step.to_string(), 200, &json!(got));
    }
    fn close(&mut self) {
        if let Some(ws) = &mut self.ws {
            let _ = ws.close(None);
            let _ = ws.read();
        }
        self.ws = None;
    }
}

fn script(net: &mut Net, kits: &[Kit]) -> Vec<Value> {
    let (a, b) = ("alpha.test", "beta.test");
    let alpha_people = net.register(a, &["alice", "carol"], &kits[0..2]);
    let beta_people = net.register(b, &["bob", "dave"], &kits[2..4]);
    let (alice, carol) = (&alpha_people[0], &alpha_people[1]);
    let (bob, dave) = (&beta_people[0], &beta_people[1]);

    // ----- documents and addresses -----
    net.get(a, "site document", "/.well-known/commonveil", a);
    net.get(
        a,
        "identity by handle host",
        "/.well-known/commonveil/identity",
        "alice.alpha.test",
    );
    net.get(
        a,
        "identity by query",
        "/.well-known/commonveil/identity?handle=alice.alpha.test",
        a,
    );
    net.get(
        a,
        "identity: nobody",
        "/.well-known/commonveil/identity",
        "nobody.alpha.test",
    );
    net.get(a, "a handle in a browser", "/", "alice.alpha.test");
    net.get(
        a,
        "an unknown handle in a browser",
        "/x",
        "nobody.alpha.test",
    );
    net.get(
        a,
        "tls check: a person",
        "/api/tls-check?domain=alice.alpha.test",
        a,
    );
    net.get(
        a,
        "tls check: nobody",
        "/api/tls-check?domain=nobody.alpha.test",
        a,
    );
    net.get(
        a,
        "tls check: the site",
        "/api/tls-check?domain=alpha.test",
        a,
    );
    net.get(
        a,
        "webfinger",
        "/.well-known/webfinger?resource=acct:alice@alpha.test",
        a,
    );
    net.get(
        a,
        "webfinger: another site",
        "/.well-known/webfinger?resource=acct:alice@beta.test",
        a,
    );
    net.get(a, "nodeinfo links", "/.well-known/nodeinfo", a);
    net.get(a, "nodeinfo", "/nodeinfo/2.1", a);
    net.get(a, "public profile", "/api/fed/profile/alice", a);
    net.get(a, "public profile: nobody", "/api/fed/profile/nobody", a);
    net.get(
        a,
        "where someone lives",
        "/api/fed/resolve?q=%40bob.beta.test",
        a,
    );
    net.get(
        a,
        "where a site is",
        "/api/fed/resolve?q=https://beta.test/x",
        a,
    );
    net.get(
        a,
        "where: nowhere",
        "/api/fed/resolve?q=nobody.nowhere.test",
        a,
    );
    net.get(a, "discover", "/cvp/v1/discover", a);

    // ----- checking another site before a move (protocol.check_site) -----
    net.call(
        a,
        "protocol",
        "check another site",
        alice,
        json!({ "action": "check_site", "host": "https://Beta.test/x" }),
    );
    net.call(
        a,
        "protocol",
        "check: this site",
        alice,
        json!({ "action": "check_site", "host": a }),
    );
    net.call(
        a,
        "protocol",
        "check: not a site",
        alice,
        json!({ "action": "check_site", "host": "not a site" }),
    );
    net.call(
        a,
        "protocol",
        "check: nowhere",
        alice,
        json!({ "action": "check_site", "host": "nowhere.test" }),
    );

    // ----- a conversation across sites -----
    let dm = net.call(
        a,
        "conversations",
        "alice writes to bob.beta.test",
        alice,
        alice.signed("create_dm", json!({ "username": "bob.beta.test" })),
    );
    let dm_id = s(&dm["conversation"]["id"]);
    net.call(
        a,
        "conversations",
        "alice writes to a handle nobody has",
        alice,
        alice.signed("create_dm", json!({ "username": "nobody.beta.test" })),
    );
    let send = |net: &mut Net, site: &str, step: &str, who: &Who, n: u32, recipients: &[&Who]| {
        let at = iso_at(now());
        let recips: Vec<Value> = recipients.iter().map(|w| w.recipient()).collect();
        let (env, sig) = sealed_item("message", &dm_id, &rid(n), (&who.id, who.kit), &recips, &at);
        net.call(site, "messages", step, who, json!({ "action": "send", "conversation_id": dm_id, "device_id": who.kit.id(0), "msg_id": rid(n), "sent_at": at, "envelope": env, "signature": sig }))
    };
    send(net, a, "alice sends", alice, 1, &[alice, bob]);
    let start = net.call(
        b,
        "messages",
        "bob's site polls (first)",
        bob,
        json!({ "action": "poll" }),
    );
    std::thread::sleep(Duration::from_millis(50));
    // Changes since the start of time, not since the first poll's cursor: which rows changed in the
    // seconds before that poll depends on how fast the run is, and the comparison mustn't.
    net.call(b, "messages", "bob's site polls (since)", bob, json!({ "action": "poll", "since": start["cursor"], "conversations_since": "2000-01-01T00:00:00" }));
    net.call(
        b,
        "conversations",
        "bob's site lists his conversations",
        bob,
        json!({ "action": "list" }),
    );
    net.call(
        b,
        "messages",
        "bob reads through his site",
        bob,
        json!({ "action": "list", "conversation_id": dm_id }),
    );
    send(
        net,
        b,
        "bob answers through his site",
        bob,
        2,
        &[alice, bob],
    );
    net.call(
        a,
        "messages",
        "alice reads both",
        alice,
        json!({ "action": "list", "conversation_id": dm_id }),
    );
    // A file in the conversation, posted on alpha: bob asks for it through beta by naming the
    // conversation, as the app does, and beta finds the site that holds it.
    let dm_bytes: Vec<u8> = (0..200u32).map(|i| (i * 7 % 251) as u8).collect();
    let dm_up = json!({ "scope": "conversation", "conversation_id": dm_id, "msg_id": rid(3), "part": 0, "parts": 1, "data": STANDARD.encode(&dm_bytes) });
    let dm_file = net.call(
        a,
        "files",
        "alice attaches a file to the conversation",
        alice,
        alice.signed("upload_part", dm_up),
    );
    send(
        net,
        a,
        "and sends the message it's in",
        alice,
        3,
        &[alice, bob],
    );
    let dm_links = net.call(b, "files", "bob's links, naming the conversation", bob, json!({ "action": "download_links", "file_ids": [dm_file["file_id"]], "conversation_id": dm_id }));
    assert_eq!(
        dm_links["links"].as_object().map_or(0, |m| m.len()),
        1,
        "naming the conversation finds the file's site: {dm_links}"
    );
    net.call(
        a,
        "keys",
        "alice's site has bob's keys",
        alice,
        json!({ "action": "peer_keys", "user_ids": [bob.id] }),
    );
    net.call(
        b,
        "profile",
        "bob's site gets alice's profile",
        bob,
        json!({ "action": "get_many", "user_ids": [alice.id] }),
    );

    // ----- a server on beta, joined from alpha -----
    let made = net.call(
        b,
        "servers",
        "bob makes a server",
        bob,
        bob.signed("create_server", json!({ "template": "community" })),
    );
    let sid = s(&made["server_id"]);
    let st = net.call(
        b,
        "servers",
        "its state",
        bob,
        json!({ "action": "state", "server_id": sid }),
    );
    let (h, l) = (format!("{sid}.h"), format!("{sid}.l"));
    let mut keys: Keys = HashMap::new();
    net.call(
        b,
        "servers",
        "history keys",
        bob,
        bob.generation(&sid, &h, 0, &[bob], &mut keys),
    );
    net.call(
        b,
        "servers",
        "live keys",
        bob,
        bob.generation(&sid, &l, 0, &[bob], &mut keys),
    );
    net.call(b, "servers", "listed and open", bob, bob.signed("update_server_settings", json!({ "server_id": sid, "discoverable": true, "join_mode": "open", "public": { "name": "Beta garden", "description": "Plants", "tags": ["friends"] } })));
    net.get(b, "beta's listing", "/cvp/v1/discover", b);
    net.call(
        a,
        "servers",
        "alice browses beta from alpha",
        alice,
        json!({ "action": "discover", "_site": b }),
    );
    net.call(
        a,
        "servers",
        "alpha's own listing",
        alice,
        json!({ "action": "discover" }),
    );
    let mut join = alice.signed("join_server", json!({ "server_id": sid }));
    join["_site"] = json!(b);
    net.call(a, "servers", "alice joins from alpha", alice, join);
    net.call(
        a,
        "servers",
        "the server is in alice's list",
        alice,
        json!({ "action": "list" }),
    );
    net.call(
        b,
        "servers",
        "bob's app sees who needs keys",
        bob,
        json!({ "action": "pending_grants", "server_id": sid }),
    );
    let grants: Vec<Value> = [&h, &l]
        .iter()
        .map(|c| bob.grant(&sid, c, 0, &keys[*c].1, alice))
        .collect();
    net.call(
        b,
        "servers",
        "bob's app hands alice the keys",
        bob,
        bob.signed("grant_keys", json!({ "server_id": sid, "grants": grants })),
    );
    let general = s(&channel(&st, "general")["id"]);
    net.call(
        b,
        "channels",
        "bob writes in general",
        bob,
        bob.message(&sid, &general, &rid(10), &l, &keys, "message", ""),
    );
    net.call(
        a,
        "servers",
        "alice's state, through alpha",
        alice,
        json!({ "action": "state", "server_id": sid }),
    );
    net.call(
        a,
        "channels",
        "alice writes in general, through alpha",
        alice,
        alice.message(&sid, &general, &rid(11), &l, &keys, "message", ""),
    );
    net.call(
        a,
        "channels",
        "alice reads general",
        alice,
        json!({ "action": "list", "server_id": sid, "channel_id": general }),
    );
    let first = net.call(
        a,
        "messages",
        "alice's site polls",
        alice,
        json!({ "action": "poll" }),
    );
    net.call(a, "messages", "alice's site polls servers too", alice, json!({ "action": "poll", "since": first["cursor"], "servers_since": "2000-01-01T00:00:00", "server_changes_since": "2000-01-01T00:00:00" }));
    net.call(
        a,
        "servers",
        "mixed sites in one request",
        alice,
        json!({ "action": "state", "server_id": sid, "conversation_id": dm_id }),
    );

    // ----- a file in beta's channel, from alpha -----
    let bytes: Vec<u8> = (0..300u32).map(|i| (i * 13 % 251) as u8).collect();
    let up = json!({ "scope": "server", "server_id": sid, "channel_id": general, "msg_id": rid(12), "part": 0, "parts": 1, "data": STANDARD.encode(&bytes) });
    let file = net.call(
        a,
        "files",
        "alice uploads to beta, through alpha",
        alice,
        alice.signed("upload_part", up),
    );
    net.call(
        a,
        "channels",
        "and sends its message",
        alice,
        alice.message(&sid, &general, &rid(12), &l, &keys, "message", ""),
    );
    let alone = net.call(
        a,
        "files",
        "links by id alone (the route isn't known)",
        alice,
        json!({ "action": "download_links", "file_ids": [file["file_id"]] }),
    );
    assert_eq!(
        alone["links"].as_object().map_or(1, |m| m.len()),
        0,
        "a file id alone doesn't route: {alone}"
    );
    let links = net.call(
        a,
        "files",
        "links, naming beta",
        alice,
        json!({ "action": "download_links", "file_ids": [file["file_id"]], "_site": b }),
    );
    // What the app sends: the place the file was posted, whose site alpha already knows.
    let by_place = net.call(a, "files", "links, naming the channel", alice, json!({ "action": "download_links", "file_ids": [file["file_id"]], "server_id": sid, "channel_id": general }));
    assert_eq!(
        by_place["links"].as_object().map_or(0, |m| m.len()),
        1,
        "naming the channel finds the file's site: {by_place}"
    );
    // A sender can't steer a request by listing another site's id among a file's parts: alpha's own
    // conversation is named, so it stays on alpha, whatever else the part ids say.
    let steer = net.call(a, "files", "links, with another site's id among the parts", alice, json!({ "action": "download_links", "file_ids": [sid, dm_file["file_id"]], "conversation_id": dm_id }));
    assert_eq!(
        steer["links"]
            .as_object()
            .map(|m| m.contains_key(s(&dm_file["file_id"]).as_str())),
        Some(true),
        "the request stayed on alpha: {steer}"
    );
    let link = links["links"]
        .as_object()
        .and_then(|m| m.values().next())
        .and_then(Value::as_str)
        .unwrap_or("/api/fed/files/none/x")
        .to_string();
    let got = http(net.port(a), "GET", &link, a, "", "", &[]);
    net.record(
        format!("{a}: the file, through alpha"),
        got.status,
        &json!({ "same": got.body == bytes }),
    );
    let bent = http(net.port(a), "GET", &format!("{link}x"), a, "", "", &[]);
    net.record(format!("{a}: a bent link"), bent.status, &json!(null));
    let local = net.call(
        b,
        "files",
        "bob's links on beta",
        bob,
        json!({ "action": "download_links", "file_ids": [file["file_id"]] }),
    );
    let local_link = local["links"]
        .as_object()
        .and_then(|m| m.values().next())
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let local_path = local_link
        .find("/api/files/")
        .map_or("/api/files/none".to_string(), |i| {
            local_link[i..].to_string()
        });
    let got = http(net.port(b), "GET", &local_path, b, "", "", &[]);
    net.record(
        format!("{b}: the file on beta"),
        got.status,
        &json!({ "same": got.body == bytes }),
    );

    // ----- a realtime room on beta, joined through alpha -----
    let room = format!("/api/actors/Presence/s.{sid}");
    let mut bp = Socket::open(
        net,
        b,
        "bob opens the room",
        &format!("{room}?id=conn-bob-001&token={}", bob.token),
    );
    bp.read(net, "bob is there");
    let mut ap = Socket::open(
        net,
        a,
        "alice opens the room through alpha",
        &format!("{room}?id=conn-alice-001&token={}", alice.token),
    );
    ap.read(net, "alice sees who's there");
    bp.read(net, "bob sees alice arrive");
    ap.send(json!({ "type": "typing", "channel_id": general }));
    bp.read(net, "bob sees alice typing");
    ap.send(json!({ "type": "__ping" }));
    ap.read(net, "alice's ping, answered by beta");
    ap.close();
    bp.read(net, "bob sees alice leave");
    bp.close();

    // ----- people's choices -----
    net.call(
        b,
        "profile",
        "dave only takes people from his servers",
        dave,
        json!({ "action": "update", "dm_policy": "servers" }),
    );
    net.call(
        a,
        "conversations",
        "carol can't reach dave",
        carol,
        carol.signed("create_dm", json!({ "username": "dave.beta.test" })),
    );
    net.call(
        b,
        "profile",
        "dave takes anyone again",
        dave,
        json!({ "action": "update", "dm_policy": "anyone" }),
    );
    net.call(
        a,
        "profile",
        "carol finds dave",
        carol,
        json!({ "action": "find", "username": "@dave.beta.test" }),
    );
    net.call(
        a,
        "conversations",
        "carol writes to dave and bob",
        carol,
        carol.signed(
            "create_group",
            json!({ "usernames": ["dave.beta.test", "bob.beta.test"] }),
        ),
    );

    // ----- refusals -----
    net.raw_post(
        a,
        "act, unsigned",
        "/cvp/v1/act",
        "",
        &json!({ "user": { "id": "0".repeat(24) } }).to_string(),
        &[],
    );
    net.raw_post(
        a,
        "act, from beta, no date",
        "/cvp/v1/act",
        "",
        "{}",
        &[("CV-From", b.into())],
    );
    let fresh = commonveil_server::shared::iso(commonveil_server::sessions::now_ms());
    let sig_headers = |nonce: &str, digest: &str| {
        vec![
            ("CV-From", b.to_string()),
            ("CV-Date", fresh.clone()),
            ("CV-Nonce", nonce.to_string()),
            ("CV-Digest", digest.to_string()),
            ("CV-Signature", "bm90IGEgc2lnbmF0dXJl".to_string()),
        ]
    };
    net.raw_post(
        a,
        "act, no nonce",
        "/cvp/v1/act",
        "",
        "{}",
        &sig_headers("x", ""),
    );
    net.raw_post(
        a,
        "act, a body that isn't its digest",
        "/cvp/v1/act",
        "",
        "{}",
        &sig_headers("abcdefghijklmnop1", "sha-256=nope"),
    );
    let digest = secure_net_core::wire::federation::digest_of(b"{}");
    net.raw_post(
        a,
        "act, a signature that isn't beta's",
        "/cvp/v1/act",
        "",
        "{}",
        &sig_headers("abcdefghijklmnop2", &digest),
    );
    net.raw_post(
        a,
        "act, from itself",
        "/cvp/v1/act",
        "",
        "{}",
        &[("CV-From", a.into())],
    );
    net.get(a, "act by GET", "/cvp/v1/act", a);
    net.raw_post(
        a,
        "an unknown endpoint, unsigned",
        "/cvp/v1/elsewhere",
        "",
        "{}",
        &[],
    );

    // ----- an admin stops talking to a site -----
    let admin = |net: &mut Net, step: &str, who: &Who, body: Value| {
        let r = http(
            net.port(a),
            "POST",
            "/api/admin/federation",
            a,
            &who.token,
            &body.to_string(),
            &[],
        );
        let data: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        net.record(format!("{a}: {step}"), r.status, &data);
    };
    let r = http(
        net.port(a),
        "GET",
        "/api/admin/federation",
        a,
        &alice.token,
        "",
        &[],
    );
    net.record(
        format!("{a}: the admin's view"),
        r.status,
        &serde_json::from_slice(&r.body).unwrap_or(Value::Null),
    );
    let r = http(
        net.port(a),
        "GET",
        "/api/admin/federation",
        a,
        &carol.token,
        "",
        &[],
    );
    net.record(
        format!("{a}: not an admin"),
        r.status,
        &serde_json::from_slice(&r.body).unwrap_or(Value::Null),
    );
    admin(
        net,
        "block beta",
        alice,
        json!({ "action": "block", "host": b }),
    );
    net.call(
        b,
        "conversations",
        "bob can't reach carol now",
        bob,
        bob.signed("create_dm", json!({ "username": "carol.alpha.test" })),
    );
    net.call(
        a,
        "messages",
        "alice can't reach beta either",
        alice,
        json!({ "action": "list", "conversation_id": dm_id }),
    );
    admin(
        net,
        "unblock beta",
        alice,
        json!({ "action": "unblock", "host": b }),
    );
    net.call(
        b,
        "conversations",
        "bob reaches carol",
        bob,
        bob.signed("create_dm", json!({ "username": "carol.alpha.test" })),
    );
    admin(
        net,
        "an unknown action",
        alice,
        json!({ "action": "dance", "host": b }),
    );
    admin(
        net,
        "block: not a site",
        alice,
        json!({ "action": "block", "host": "not a site" }),
    );
    admin(
        net,
        "accept a new key",
        alice,
        json!({ "action": "accept_new_key", "host": "gamma.test" }),
    );
    std::mem::take(&mut net.log)
}

#[test]
fn sites_talk_to_each_other_as_the_node_servers_do() {
    if !ready() {
        eprintln!("skipped: node, the npm packages or dist-selfhost aren't there");
        return;
    }
    let kits: Vec<Kit> = (0..4).map(|_| Kit::new()).collect();
    let run = |pair: (Kind, Kind)| {
        let mut net = start(&[("alpha.test", pair.0), ("beta.test", pair.1)], &[]);
        let log = script(&mut net, &kits);
        drop(net);
        log
    };
    let node = run((Kind::Node, Kind::Node));
    let ok = compare(&node, &run((Kind::Rust, Kind::Rust)));
    assert!(ok > 60, "only {ok} steps succeeded");
    compare(&node, &run((Kind::Rust, Kind::Node)));
    compare(&node, &run((Kind::Node, Kind::Rust)));
    succeeded(
        &node,
        &[
            "alpha.test: alice writes to bob.beta.test",
            "beta.test: bob reads through his site",
            "beta.test: bob answers through his site",
            "alpha.test: alice joins from alpha",
            "alpha.test: alice writes in general, through alpha",
            "alpha.test: alice reads general",
            "alpha.test: links, naming beta",
            "alpha.test: the file, through alpha",
            "beta.test: bob reaches carol",
        ],
    );
    let file = node
        .iter()
        .find(|s| s["step"] == "alpha.test: the file, through alpha")
        .unwrap();
    assert_eq!(file["reply"]["same"], true, "{file}");
}

/// With federation off, a site's protocol addresses answer as the Node.js server's do.
#[test]
fn a_site_that_doesnt_federate_answers_as_the_node_server_does() {
    if !ready() {
        eprintln!("skipped: node, the npm packages or dist-selfhost aren't there");
        return;
    }
    let kits: Vec<Kit> = (0..1).map(|_| Kit::new()).collect();
    let run = |kind: Kind| {
        let mut net = start(&[("solo.test", kind)], &[("FEDERATION", "off")]);
        let me = net.register("solo.test", &["alice"], &kits[0..1]);
        for (step, path) in [
            ("site document", "/.well-known/commonveil"),
            (
                "identity",
                "/.well-known/commonveil/identity?handle=alice.solo.test",
            ),
            ("tls check", "/api/tls-check?domain=alice.solo.test"),
            (
                "webfinger",
                "/.well-known/webfinger?resource=acct:alice@solo.test",
            ),
            ("nodeinfo", "/nodeinfo/2.1"),
            ("public profile", "/api/fed/profile/alice"),
            ("resolve", "/api/fed/resolve?q=bob.beta.test"),
            ("protocol", "/cvp/v1/discover"),
        ] {
            net.get("solo.test", step, path, "solo.test");
        }
        net.get("solo.test", "a handle host", "/", "alice.solo.test");
        net.raw_post("solo.test", "act", "/cvp/v1/act", "", "{}", &[]);
        let r = http(
            net.port("solo.test"),
            "GET",
            "/api/admin/federation",
            "solo.test",
            &me[0].token,
            "",
            &[],
        );
        net.record(
            "solo.test: the admin's view".into(),
            r.status,
            &serde_json::from_slice(&r.body).unwrap_or(Value::Null),
        );
        net.call(
            "solo.test",
            "profile",
            "find by handle",
            &me[0],
            json!({ "action": "find", "username": "bob.beta.test" }),
        );
        net.call(
            "solo.test",
            "conversations",
            "write to a handle",
            &me[0],
            me[0].signed("create_dm", json!({ "username": "bob.beta.test" })),
        );
        std::mem::take(&mut net.log)
    };
    compare(&run(Kind::Node), &run(Kind::Rust));
}
