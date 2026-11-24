//! The realtime rooms (Presence and VoiceRoom) over WebSockets against the Node.js server: the
//! same script runs against both, each on its own fresh site, and every message each connection
//! receives, and how each one is closed, must match once random values are blanked.
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};
use tungstenite::{Message, WebSocket};

mod common;
use common::servers::{channel, people, s, Who};
use common::{blank, compare, ready, start, succeeded, Flow, Kit};

struct Socket {
    name: String,
    ws: Option<WebSocket<TcpStream>>,
}

/// Open a room connection, or log why it was refused.
fn open(f: &mut Flow, name: &str, path: &str) -> Socket {
    let stream = TcpStream::connect(("127.0.0.1", f.port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    match tungstenite::client(format!("ws://cv.example{path}"), stream) {
        Ok((ws, _)) => {
            f.log
                .push(json!({ "step": format!("{name}: open"), "status": 101 }));
            Socket {
                name: name.into(),
                ws: Some(ws),
            }
        }
        Err(tungstenite::HandshakeError::Failure(tungstenite::Error::Http(r))) => {
            f.log
                .push(json!({ "step": format!("{name}: open"), "status": r.status().as_u16() }));
            Socket {
                name: name.into(),
                ws: None,
            }
        }
        Err(e) => panic!("{name}: {e}"),
    }
}

impl Socket {
    fn send(&mut self, msg: Value) {
        if let Some(ws) = &mut self.ws {
            let _ = ws.send(Message::Text(msg.to_string().into()));
        }
    }
    /// Everything that arrives in the next moment, in order, logged under `step`.
    fn read(&mut self, f: &mut Flow, step: &str) -> Vec<Value> {
        let mut got = Vec::new();
        if let Some(ws) = &mut self.ws {
            loop {
                match ws.read() {
                    Ok(Message::Text(t)) => {
                        got.push(serde_json::from_str(&t).unwrap_or(Value::Null))
                    }
                    Ok(Message::Close(frame)) => {
                        got.push(json!({ "closed": frame.as_ref().map(|c| u16::from(c.code)), "reason": frame.as_ref().map(|c| c.reason.to_string()) }));
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
        f.log.push(json!({ "step": format!("{}: {step}", self.name), "status": 200, "reply": blank(&json!(got)) }));
        got
    }
    fn close(&mut self) {
        if let Some(ws) = &mut self.ws {
            let _ = ws.close(None);
            let _ = ws.read();
        }
        self.ws = None;
    }
}

fn script(port: u16, data: &Path, kits: &[Kit]) -> Vec<Value> {
    let mut f = Flow::new(port);
    let people = people(&mut f, data, &["alice", "bob", "carol"], kits);
    let (alice, bob, carol) = (&people[0], &people[1], &people[2]);
    let call = |f: &mut Flow, func: &str, step: &str, w: &Who, body: Value| {
        f.call(func, step, &w.token, body)
    };
    let made = call(
        &mut f,
        "servers",
        "create",
        bob,
        bob.signed("create_server", json!({ "template": "community" })),
    );
    let sid = s(&made["server_id"]);
    let st = call(
        &mut f,
        "servers",
        "state",
        bob,
        json!({ "action": "state", "server_id": sid }),
    );
    call(
        &mut f,
        "servers",
        "invite",
        bob,
        bob.signed(
            "create_invite",
            json!({ "server_id": sid, "code": "abcdefgh34" }),
        ),
    );
    call(
        &mut f,
        "servers",
        "carol joins",
        carol,
        carol.signed("join_server", json!({ "invite_code": "abcdefgh34" })),
    );
    let general = s(&channel(&st, "general")["id"]);
    let lounge = s(&channel(&st, "lounge")["id"]);

    // ----- addresses that aren't rooms -----
    open(
        &mut f,
        "unknown room kind",
        "/api/actors/Lobby/abc?id=conn-0001",
    );
    open(
        &mut f,
        "bad connection id",
        &format!("/api/actors/Presence/s.{sid}?id=x"),
    );
    open(
        &mut f,
        "bad room name",
        "/api/actors/Presence/a%20b?id=conn-0001",
    );

    // ----- presence -----
    let room = format!("/api/actors/Presence/s.{sid}");
    let mut b1 = open(
        &mut f,
        "bob presence",
        &format!("{room}?id=conn-bob-01&token={}", bob.token),
    );
    b1.read(&mut f, "joined");
    let mut c1 = open(
        &mut f,
        "carol presence",
        &format!("{room}?id=conn-carol-01"),
    );
    c1.read(&mut f, "joined without signing in");
    c1.send(json!({ "type": "hello" }));
    c1.read(&mut f, "hello before signing in");
    c1.send(json!({ "type": "__auth", "token": "nonsense" }));
    c1.read(&mut f, "bad token");
    let mut c1 = open(
        &mut f,
        "carol presence again",
        &format!("{room}?id=conn-carol-01"),
    );
    c1.read(&mut f, "joined without signing in");
    c1.send(json!({ "type": "__auth", "token": carol.token }));
    c1.read(&mut f, "signed in");
    b1.read(&mut f, "carol arrives");
    let mut a1 = open(
        &mut f,
        "alice presence",
        &format!("{room}?id=conn-alice-01&token={}", alice.token),
    );
    a1.read(&mut f, "not a member");
    c1.send(json!({ "type": "hello", "status": "idle" }));
    c1.read(&mut f, "went idle");
    b1.read(&mut f, "carol went idle");
    b1.send(json!({ "type": "typing", "channel_id": general, "thread_id": "nope" }));
    b1.send(json!({ "type": "typing", "channel_id": general }));
    c1.read(&mut f, "bob typing (once, throttled)");
    b1.send(json!({ "type": "typing" }));
    c1.read(&mut f, "typing without a channel");
    b1.send(json!({ "type": "__ping" }));
    b1.read(&mut f, "ping");
    b1.send(json!("not an object"));
    b1.read(&mut f, "nonsense");
    c1.close();
    b1.read(&mut f, "carol leaves");
    let dm = call(
        &mut f,
        "conversations",
        "dm",
        bob,
        bob.signed("create_dm", json!({ "username": "carol" })),
    );
    let dm_id = s(&dm["conversation"]["id"]);
    let mut d1 = open(
        &mut f,
        "bob in the conversation",
        &format!(
            "/api/actors/Presence/c.{dm_id}?id=conn-bob-02&token={}",
            bob.token
        ),
    );
    d1.read(&mut f, "joined");
    let mut d2 = open(
        &mut f,
        "alice in the conversation",
        &format!(
            "/api/actors/Presence/c.{dm_id}?id=conn-alice-02&token={}",
            alice.token
        ),
    );
    d2.read(&mut f, "not in it");
    d1.close();
    b1.close();

    // ----- a voice call -----
    let vroom = format!("/api/actors/VoiceRoom/{sid}.{lounge}");
    let fp = vec!["AB"; 32].join(":");
    let hello = json!({ "call_id": "call-0001aa", "fingerprint": fp, "issued_at": "2026-11-15T10:00:00Z", "signature": "c2lnbmF0dXJl" });
    let bt = call(
        &mut f,
        "voice",
        "bob's pass",
        bob,
        bob.signed(
            "voice_ticket",
            json!({ "server_id": sid, "channel_id": lounge }),
        ),
    );
    let ct = call(
        &mut f,
        "voice",
        "carol's pass",
        carol,
        carol.signed(
            "voice_ticket",
            json!({ "server_id": sid, "channel_id": lounge }),
        ),
    );
    let mut bv = open(
        &mut f,
        "bob voice",
        &format!("{vroom}?id=conn-bob-03&token={}", bob.token),
    );
    bv.read(&mut f, "connected");
    bv.send(json!({ "type": "join", "ticket": "short", "hello": hello }));
    bv.read(&mut f, "bad join");
    bv.send(json!({ "type": "signal", "to": 1, "data": {} }));
    bv.read(&mut f, "signal before joining");
    bv.send(json!({ "type": "join", "ticket": bt["ticket"], "hello": hello }));
    bv.read(&mut f, "joined");
    let mut cv = open(&mut f, "carol voice", &format!("{vroom}?id=conn-carol-03"));
    cv.read(&mut f, "connected without signing in");
    cv.send(json!({ "type": "join", "ticket": ct["ticket"], "hello": hello }));
    cv.read(&mut f, "join without signing in");
    let mut cv = open(
        &mut f,
        "carol voice again",
        &format!("{vroom}?id=conn-carol-03"),
    );
    cv.read(&mut f, "connected without signing in");
    cv.send(json!({ "type": "__auth", "token": carol.token }));
    cv.read(&mut f, "signed in");
    cv.send(json!({ "type": "join", "ticket": bt["ticket"], "hello": hello }));
    cv.read(&mut f, "someone else's pass (used)");
    let ct2 = call(
        &mut f,
        "voice",
        "carol's pass again",
        carol,
        carol.signed(
            "voice_ticket",
            json!({ "server_id": sid, "channel_id": lounge }),
        ),
    );
    cv.send(json!({ "type": "join", "ticket": ct2["ticket"], "hello": hello, "muted": true }));
    cv.read(&mut f, "joined");
    bv.read(&mut f, "carol joined");
    bv.send(json!({ "type": "signal", "to": 2, "data": { "sdp": "offer" } }));
    cv.read(&mut f, "signal from bob");
    bv.send(json!({ "type": "signal", "to": 1, "data": {} }));
    bv.read(&mut f, "signal to myself");
    cv.send(json!({ "type": "state", "muted": false, "deafened": true }));
    cv.read(&mut f, "state");
    bv.read(&mut f, "carol's state");
    bv.send(json!({ "type": "mute-peer", "seat": 2 }));
    bv.read(&mut f, "bob mutes carol");
    cv.read(&mut f, "muted by bob");
    cv.send(json!({ "type": "mute-peer", "seat": 1 }));
    cv.read(&mut f, "carol can't mute bob");
    cv.send(json!({ "type": "leave" }));
    cv.read(&mut f, "left");
    bv.read(&mut f, "carol left");
    cv.close();
    bv.send(json!({ "type": "__ping" }));
    bv.read(&mut f, "ping");
    bv.close();
    f.log
}

#[test]
fn the_realtime_rooms_behave_as_the_node_server_does() {
    if !ready() {
        eprintln!("skipped: node, the npm packages or dist-selfhost aren't there");
        return;
    }
    let kits: Vec<Kit> = (0..3).map(|_| Kit::new()).collect();
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (node, rust) = (start(true, d1.path()), start(false, d2.path()));
    let (a, b) = (
        script(node.1, d1.path(), &kits),
        script(rust.1, d2.path(), &kits),
    );
    compare(&a, &b);
    succeeded(&a, &["create", "carol joins", "bob's pass", "carol's pass"]);
    let joined = a
        .iter()
        .find(|s| s["step"] == "carol voice again: joined")
        .unwrap();
    assert_eq!(joined["reply"][0]["type"], "welcome", "{joined}");
}
