//! The realtime rooms over WebSockets (server/actors.mjs and server/actorRuntime.mjs):
//! `/api/actors/<Name>/<instance>?id=<connection>&token=<session>`. Each room is one instance of
//! its kind, made on first connection and dropped once it's empty and has no timers waiting.
//!
//! The rooms themselves are in `rooms` (VoiceRoom and Presence). This is the small part of
//! Base44's actor runtime they use: one instance per room, connections with the signed-in
//! person's identity, a little storage, and wake-up timers.
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use axum::body::Body;
use axum::extract::ws::{CloseFrame, Message, WebSocket};
use axum::http::Response;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

use crate::App;

const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// What a room sends down one connection.
#[derive(Debug)]
pub enum Out {
    Text(String),
    Close(u16, String),
    Terminate,
}

/// One WebSocket in a room.
pub struct Conn {
    pub id: String,
    /// The signed-in person the platform let in, if any.
    pub user_id: Option<String>,
    serial: u64,
    tx: UnboundedSender<Out>,
}

impl Conn {
    pub fn send(&self, msg: &Value) {
        let _ = self.tx.send(Out::Text(msg.to_string()));
    }
    pub fn reject(&self, code: u16, reason: &str) {
        let units: Vec<u16> = reason.encode_utf16().take(120).collect();
        let _ = self.tx.send(Out::Close(code, String::from_utf16_lossy(&units)));
    }
    fn terminate(&self) {
        let _ = self.tx.send(Out::Terminate);
    }
}

/// What a room's code can reach while it handles something.
pub struct Cx<'a> {
    pub app: &'a App,
    pub instance_id: &'a str,
    pub conns: &'a [Conn],
    storage_key: &'a str,
    timers: &'a mut HashMap<String, (u64, tokio::task::AbortHandle)>,
    me: &'a Weak<Mutex<Instance>>,
    host: &'a Arc<Host>,
    next_timer: &'a mut u64,
}

impl Cx<'_> {
    pub fn conn(&self, id: &str) -> Option<&Conn> {
        self.conns.iter().find(|c| c.id == id)
    }
    pub fn storage_get(&self, name: &str) -> Option<Value> {
        self.app.store.get_setting(&format!("actor:{}:{name}", self.storage_key)).filter(|v| !v.is_null())
    }
    pub fn storage_put(&self, name: &str, value: &Value) {
        self.app.store.set_setting(&format!("actor:{}:{name}", self.storage_key), Some(value));
    }
    /// Call the room's `wake(key)` at `at` (milliseconds), replacing any timer with that key.
    pub fn schedule(&mut self, key: &str, at: i64) {
        self.cancel(key);
        *self.next_timer += 1;
        let token = *self.next_timer;
        let (me, host, key_owned) = (self.me.clone(), self.host.clone(), key.to_string());
        let delay = (at - crate::sessions::now_ms()).max(0) as u64;
        let task = tokio::runtime::Handle::current().spawn(async move {
            tokio::time::sleep(Duration::from_millis(delay)).await;
            let Some(inst) = me.upgrade() else { return };
            let _ = tokio::task::spawn_blocking(move || {
                let mut guard = inst.lock().unwrap_or_else(|e| e.into_inner());
                if guard.timers.get(&key_owned).map(|t| t.0) != Some(token) {
                    return;
                }
                guard.timers.remove(&key_owned);
                guard.with(&host, &Arc::downgrade(&inst), |room, cx| room.wake(cx, &key_owned));
                let empty = guard.is_empty();
                let name = guard.key.clone();
                drop(guard);
                if empty {
                    host.maybe_drop(&name);
                }
            })
            .await;
        });
        self.timers.insert(key.to_string(), (token, task.abort_handle()));
    }
    pub fn cancel(&mut self, key: &str) {
        if let Some((_, t)) = self.timers.remove(key) {
            t.abort();
        }
    }
}

/// A room kind: VoiceRoom or Presence.
pub trait Room: Send {
    fn start(&mut self, cx: &mut Cx);
    fn connect(&mut self, cx: &mut Cx, conn_id: &str);
    fn message(&mut self, cx: &mut Cx, conn_id: &str, msg: &Value);
    fn close(&mut self, cx: &mut Cx, conn_id: &str);
    fn wake(&mut self, cx: &mut Cx, key: &str);
}

pub struct Instance {
    key: String,
    instance_id: String,
    room: Box<dyn Room>,
    conns: Vec<Conn>,
    timers: HashMap<String, (u64, tokio::task::AbortHandle)>,
    next_timer: u64,
}

impl Instance {
    fn with<R>(&mut self, host: &Arc<Host>, me: &Weak<Mutex<Instance>>, f: impl FnOnce(&mut Box<dyn Room>, &mut Cx) -> R) -> R {
        let app = host.app();
        let Instance { key, instance_id, room, conns, timers, next_timer } = self;
        let mut cx = Cx { app: &app, instance_id, conns, storage_key: key, timers, me, host, next_timer };
        f(room, &mut cx)
    }
    fn is_empty(&self) -> bool {
        self.conns.is_empty() && self.timers.is_empty()
    }
}

pub struct Host {
    app: Weak<App>,
    instances: Mutex<HashMap<String, Arc<Mutex<Instance>>>>,
    serial: Mutex<u64>,
}

impl Host {
    pub fn new(app: Weak<App>) -> Arc<Self> {
        Arc::new(Self { app, instances: Mutex::new(HashMap::new()), serial: Mutex::new(0) })
    }

    fn app(&self) -> Arc<App> {
        self.app.upgrade().expect("the app outlives its rooms")
    }

    fn make(name: &str) -> Option<Box<dyn Room>> {
        match name {
            "VoiceRoom" => Some(Box::new(crate::rooms::VoiceRoom::default())),
            "Presence" => Some(Box::new(crate::rooms::Presence::default())),
            _ => None,
        }
    }

    fn instance(self: &Arc<Self>, name: &str, instance_id: &str) -> Option<Arc<Mutex<Instance>>> {
        let key = format!("{name}:{instance_id}");
        let mut all = self.instances.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(i) = all.get(&key) {
            return Some(i.clone());
        }
        let inst = Arc::new(Mutex::new(Instance { key: key.clone(), instance_id: instance_id.into(), room: Self::make(name)?, conns: Vec::new(), timers: HashMap::new(), next_timer: 0 }));
        {
            let mut guard = inst.lock().unwrap_or_else(|e| e.into_inner());
            guard.with(self, &Arc::downgrade(&inst), |room, cx| room.start(cx));
        }
        all.insert(key, inst.clone());
        Some(inst)
    }

    fn maybe_drop(&self, key: &str) {
        let mut all = self.instances.lock().unwrap_or_else(|e| e.into_inner());
        if all.get(key).is_some_and(|i| i.lock().unwrap_or_else(|e| e.into_inner()).is_empty()) {
            all.remove(key);
        }
    }

    /// Join a WebSocket to a room, as this person (None: not signed in).
    pub async fn attach(self: Arc<Self>, socket: WebSocket, name: String, instance_id: String, conn_id: String, user_id: Option<String>) {
        let host = self.clone();
        let (n, i) = (name.clone(), instance_id.clone());
        let Ok(Some(inst)) = tokio::task::spawn_blocking(move || host.instance(&n, &i)).await else {
            let (mut sink, _) = socket.split();
            let _ = sink.send(Message::Close(Some(CloseFrame { code: 1008, reason: "Unknown room".into() }))).await;
            return;
        };
        let (mut sink, mut stream) = socket.split();
        let (tx, mut rx) = unbounded_channel::<Out>();
        let serial = {
            let mut s = self.serial.lock().unwrap_or_else(|e| e.into_inner());
            *s += 1;
            *s
        };
        // Writer: what the room sends goes out in order; a close or terminate ends it.
        let writer = tokio::spawn(async move {
            while let Some(out) = rx.recv().await {
                match out {
                    Out::Text(t) => {
                        if sink.send(Message::Text(t.into())).await.is_err() {
                            break;
                        }
                    }
                    Out::Close(code, reason) => {
                        let _ = sink.send(Message::Close(Some(CloseFrame { code, reason: reason.into() }))).await;
                        break;
                    }
                    Out::Terminate => break,
                }
            }
            let _ = sink.close().await;
        });
        let me = Arc::downgrade(&inst);
        // Connect, as one step (a same-id connection already here is cut off).
        {
            let (inst, host, me, conn_id, tx) = (inst.clone(), self.clone(), me.clone(), conn_id.clone(), tx.clone());
            let _ = tokio::task::spawn_blocking(move || {
                let mut g = inst.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(pos) = g.conns.iter().position(|c| c.id == conn_id) {
                    g.conns.remove(pos).terminate();
                }
                g.conns.push(Conn { id: conn_id.clone(), user_id, serial, tx });
                g.with(&host, &me, |room, cx| room.connect(cx, &conn_id));
            })
            .await;
        }
        // Reader: one message at a time, in order.
        while let Some(Ok(frame)) = stream.next().await {
            let text = match frame {
                Message::Text(t) => t.to_string(),
                Message::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
                Message::Close(_) => break,
                _ => continue,
            };
            let Ok(msg) = serde_json::from_str::<Value>(&text) else { continue };
            if msg.is_object() && msg["type"] == "__ping" {
                let _ = tx.send(Out::Text(json!({ "type": "__pong" }).to_string()));
                continue;
            }
            let (inst, host, me, conn_id) = (inst.clone(), self.clone(), me.clone(), conn_id.clone());
            let _ = tokio::task::spawn_blocking(move || {
                let mut g = inst.lock().unwrap_or_else(|e| e.into_inner());
                // A newer connection with this id took over: this one says nothing more.
                if !g.conns.iter().any(|c| c.id == conn_id && c.serial == serial) {
                    return;
                }
                g.with(&host, &me, |room, cx| room.message(cx, &conn_id, &msg));
            })
            .await;
        }
        // Closed: out of the room, then the room hears about it.
        let host = self.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let mut g = inst.lock().unwrap_or_else(|e| e.into_inner());
            let Some(pos) = g.conns.iter().position(|c| c.id == conn_id && c.serial == serial) else { return };
            g.conns.remove(pos);
            g.with(&host, &me, |room, cx| room.close(cx, &conn_id));
            let (empty, key) = (g.is_empty(), g.key.clone());
            drop(g);
            if empty {
                host.maybe_drop(&key);
            }
        })
        .await;
        drop(tx);
        let _ = writer.await;
    }
}

fn name_ok(s: &str) -> bool {
    (1..=40).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphabetic())
}
fn instance_ok(s: &str) -> bool {
    (1..=160).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn conn_ok(s: &str) -> bool {
    (8..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}

/// An upgrade request under /api/actors/: check it, then hand the socket to its room.
pub async fn upgrade(app: Arc<App>, req: axum::extract::Request) -> Response<Body> {
    use axum::extract::FromRequestParts;
    let not_found = || Response::builder().status(404).body(Body::empty()).expect("valid response");
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let get = |k: &str| url::form_urlencoded::parse(query.as_bytes()).find(|(n, _)| n == k).map(|(_, v)| v.into_owned()).unwrap_or_default();
    let segs: Vec<&str> = path.split('/').collect();
    let name = segs.get(3).copied().unwrap_or("").to_string();
    let instance = url::form_urlencoded::parse(format!("x={}", segs.get(4).copied().unwrap_or("").replace('+', "%2B")).as_bytes()).next().map(|(_, v)| v.into_owned()).unwrap_or_default();
    let conn_id = get("id");
    if !name_ok(&name) || Host::make(&name).is_none() || !instance_ok(&instance) || !conn_ok(&conn_id) {
        return not_found();
    }
    let (mut parts, _) = req.into_parts();
    let Ok(ws) = axum::extract::ws::WebSocketUpgrade::from_request_parts(&mut parts, &()).await else { return not_found() };
    let token = get("token");
    let host = app.actors.clone();
    ws.max_message_size(MAX_MESSAGE_BYTES).on_upgrade(move |socket| async move {
        let (a, room) = (app.clone(), instance.clone());
        let found = tokio::task::spawn_blocking(move || {
            let user = a.session_for(&token).map(|(u, _)| crate::js::to_js_string(u.get("id")));
            // A room on another site: this site carries the connection there.
            let remote = user.as_ref().and_then(|_| a.federation.room_host(&room));
            (user, remote)
        })
        .await;
        let (user, remote) = found.unwrap_or((None, None));
        match (user, remote) {
            (Some(user), Some(site)) => app.federation.clone().proxy_actor(socket, site, name, instance, conn_id, user).await,
            (user, _) => host.attach(socket, name, instance, conn_id, user).await,
        }
    })
}
