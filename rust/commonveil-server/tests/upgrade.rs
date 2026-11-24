//! A site the Node.js server made keeps working on the Rust server: in 0.24.0 the Docker image
//! switched servers on the same data volume. The Node.js server makes a site and fills it
//! (accounts and their encryption, a conversation and a group with messages, a server with
//! channel messages, a file, the site's federation keys). Then the same site, copied, is served by
//! the Node.js server and by the Rust server, and the same script (reading what was there, then
//! carrying on with old sessions, passwords and new messages) must get the same answers from both.
use std::collections::HashMap;
use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};

mod common;
use common::servers::{channel, people, rid, s, Keys, Who};
use common::{
    blank, get_raw, iso_at, now, post, ready, sealed_item, start_with, Flow, Kit, Server,
};

/// What the Node.js server's site holds, for carrying on with it.
struct Site {
    people: Vec<(String, String)>,
    dm: String,
    group: String,
    server: String,
    general: String,
    file: String,
    keys: Keys,
}

fn federating(node: bool, data: &Path) -> Server {
    start_with(node, data, &[("FEDERATION", "true".to_string())])
}

fn file_bytes() -> Vec<u8> {
    (0..300u32).map(|i| (i * 13 % 251) as u8).collect()
}

/// The Node.js server makes the site.
fn make(port: u16, data: &Path, kits: &[Kit]) -> Site {
    let mut f = Flow::new(port);
    let people = people(&mut f, data, &["alice", "bob", "carol", "dave"], kits);
    let (bob, carol, dave) = (&people[1], &people[2], &people[3]);
    let call = |f: &mut Flow, func: &str, step: &str, w: &Who, body: Value| {
        f.call(func, step, &w.token, body)
    };

    // A server, with both chains and everyone holding their keys.
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
    let (h, l) = (format!("{sid}.h"), format!("{sid}.l"));
    let mut keys: Keys = HashMap::new();
    call(
        &mut f,
        "servers",
        "history keys",
        bob,
        bob.generation(&sid, &h, 0, &[bob], &mut keys),
    );
    call(
        &mut f,
        "servers",
        "live keys",
        bob,
        bob.generation(&sid, &l, 0, &[bob], &mut keys),
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
    for w in [carol, dave] {
        call(
            &mut f,
            "servers",
            "join",
            w,
            w.signed("join_server", json!({ "invite_code": "abcdefgh34" })),
        );
    }
    let grants: Vec<Value> = [carol, dave]
        .iter()
        .flat_map(|w| [&h, &l].map(|c| bob.grant(&sid, c, 0, &keys[c].1, w)))
        .collect();
    call(
        &mut f,
        "servers",
        "grant",
        bob,
        bob.signed("grant_keys", json!({ "server_id": sid, "grants": grants })),
    );
    let general = s(&channel(&st, "general")["id"]);
    for (n, w) in [(1, bob), (2, carol)] {
        call(
            &mut f,
            "channels",
            "channel message",
            w,
            w.message(&sid, &general, &rid(n), &l, &keys, "message", ""),
        );
    }

    // A conversation with a file, and a group.
    let dm = s(&call(
        &mut f,
        "conversations",
        "dm",
        carol,
        carol.signed("create_dm", json!({ "username": "dave" })),
    )["conversation"]["id"]);
    let pair = [carol.recipient(), dave.recipient()];
    let send = |f: &mut Flow, step: &str, w: &Who, conv: &str, id: &str, to: &[Value]| {
        let at = iso_at(now());
        let (env, sig) = sealed_item("message", conv, id, (&w.id, w.kit), to, &at);
        f.call("messages", step, &w.token, json!({ "action": "send", "conversation_id": conv, "device_id": w.kit.id(0), "msg_id": id, "sent_at": at, "envelope": env, "signature": sig }));
    };
    send(&mut f, "dm message", carol, &dm, &rid(10), &pair);
    let upload = carol.signed("upload_part", json!({ "scope": "conversation", "conversation_id": dm, "msg_id": rid(11), "part": 0, "parts": 1, "data": STANDARD.encode(file_bytes()) }));
    let file = s(&call(&mut f, "files", "upload", carol, upload)["file_id"]);
    send(
        &mut f,
        "dm message with the file",
        carol,
        &dm,
        &rid(11),
        &pair,
    );
    send(&mut f, "dm answer", dave, &dm, &rid(12), &pair);
    let group = s(&call(
        &mut f,
        "conversations",
        "group",
        bob,
        bob.signed("create_group", json!({ "usernames": ["carol", "dave"] })),
    )["conversation"]["id"]);
    send(
        &mut f,
        "group message",
        bob,
        &group,
        &rid(20),
        &[bob.recipient(), carol.recipient(), dave.recipient()],
    );
    call(
        &mut f,
        "profile",
        "dave: only from servers",
        dave,
        json!({ "action": "update", "dm_policy": "servers" }),
    );

    // The site's federation keys.
    let (status, _) = get_raw(port, "/.well-known/commonveil");
    assert_eq!(status, 200);
    for step in &f.log {
        assert_eq!(step["status"], 200, "making the site: {step}");
    }
    Site {
        people: people
            .iter()
            .map(|w| (w.token.clone(), w.id.clone()))
            .collect(),
        dm,
        group,
        server: sid,
        general,
        file,
        keys,
    }
}

/// What each server makes of the same site.
fn carry_on(port: u16, site: &Site, kits: &[Kit]) -> Vec<Value> {
    let mut f = Flow::new(port);
    let who: Vec<Who> = site
        .people
        .iter()
        .zip(kits)
        .map(|((token, id), kit)| Who {
            token: token.clone(),
            id: id.clone(),
            kit,
        })
        .collect();
    let (alice, bob, carol, dave) = (&who[0], &who[1], &who[2], &who[3]);
    let call = |f: &mut Flow, func: &str, step: &str, w: &Who, body: Value| {
        f.call(func, step, &w.token, body)
    };
    // Read-only answers come from the same data, so they must match exactly, not just in shape.
    let raw = |f: &mut Flow, step: &str, path: &str| {
        let (status, body) = post(port, "GET", path, "", "");
        f.log
            .push(json!({ "step": step, "status": status, "raw": body }));
    };
    raw(
        &mut f,
        "the site's federation document",
        "/.well-known/commonveil",
    );
    raw(
        &mut f,
        "webfinger",
        "/.well-known/webfinger?resource=acct:bob@cv.example",
    );
    raw(&mut f, "nodeinfo", "/.well-known/nodeinfo");

    // Sessions made by the Node.js server.
    for w in [alice, bob, carol, dave] {
        call(
            &mut f,
            "profile",
            "me, still signed in",
            w,
            json!({ "action": "me" }),
        );
    }
    call(
        &mut f,
        "conversations",
        "conversations",
        carol,
        json!({ "action": "list" }),
    );
    call(
        &mut f,
        "conversations",
        "the group",
        dave,
        json!({ "action": "get", "conversation_id": site.group }),
    );
    call(
        &mut f,
        "messages",
        "the conversation",
        dave,
        json!({ "action": "list", "conversation_id": site.dm }),
    );
    call(
        &mut f,
        "messages",
        "the group's messages",
        carol,
        json!({ "action": "list", "conversation_id": site.group }),
    );
    call(
        &mut f,
        "messages",
        "everything new",
        dave,
        json!({ "action": "poll" }),
    );
    call(
        &mut f,
        "servers",
        "servers",
        dave,
        json!({ "action": "list" }),
    );
    call(
        &mut f,
        "servers",
        "the server",
        dave,
        json!({ "action": "state", "server_id": site.server }),
    );
    call(
        &mut f,
        "channels",
        "the channel",
        dave,
        json!({ "action": "list", "server_id": site.server, "channel_id": site.general }),
    );
    call(
        &mut f,
        "keys",
        "everyone's keys",
        carol,
        json!({ "action": "peer_keys", "user_ids": [alice.id, bob.id, dave.id] }),
    );

    // The file is still there, byte for byte.
    let links = call(
        &mut f,
        "files",
        "links",
        dave,
        json!({ "action": "download_links", "file_ids": [site.file] }),
    );
    let url = links["links"][site.file.as_str()]
        .as_str()
        .unwrap_or("")
        .to_string();
    let (status, body) = get_raw(
        port,
        url.strip_prefix("https://cv.example")
            .unwrap_or("/api/files/none"),
    );
    f.log.push(json!({ "step": "download the file", "status": status, "reply": { "same": body == file_bytes() } }));

    // Passwords set on the Node.js server.
    let wrong = post(
        port,
        "POST",
        "/api/functions/identity",
        "",
        &json!({ "action": "login", "username": "bob", "password": "not the password" })
            .to_string(),
    );
    f.log.push(
        json!({ "step": "sign in: wrong password", "status": wrong.0, "reply": blank(&wrong.1) }),
    );
    // The right one gets as far as confirming the new device from one of bob's others.
    f.call(
        "identity",
        "sign in",
        "",
        json!({ "action": "login", "username": "bob", "password": "a long enough password" }),
    );

    // Carrying on.
    let pair = [carol.recipient(), dave.recipient()];
    let at = iso_at(now());
    let (env, sig) = sealed_item(
        "message",
        &site.dm,
        &rid(30),
        (&dave.id, dave.kit),
        &pair,
        &at,
    );
    call(
        &mut f,
        "messages",
        "a new message",
        dave,
        json!({ "action": "send", "conversation_id": site.dm, "device_id": dave.kit.id(0), "msg_id": rid(30), "sent_at": at, "envelope": env, "signature": sig }),
    );
    call(
        &mut f,
        "messages",
        "the conversation now",
        carol,
        json!({ "action": "list", "conversation_id": site.dm }),
    );
    call(
        &mut f,
        "channels",
        "a new channel message",
        dave,
        dave.message(
            &site.server,
            &site.general,
            &rid(31),
            &format!("{}.l", site.server),
            &site.keys,
            "message",
            "",
        ),
    );
    call(
        &mut f,
        "channels",
        "the channel now",
        carol,
        json!({ "action": "list", "server_id": site.server, "channel_id": site.general }),
    );
    call(
        &mut f,
        "conversations",
        "a new conversation",
        bob,
        bob.signed("create_dm", json!({ "username": "carol" })),
    );
    call(
        &mut f,
        "conversations",
        "dave still only takes them from servers",
        alice,
        alice.signed("create_dm", json!({ "username": "dave" })),
    );
    call(
        &mut f,
        "conversations",
        "conversations now",
        bob,
        json!({ "action": "list" }),
    );
    f.log
}

#[test]
fn a_site_the_node_server_made_carries_on_with_the_rust_server() {
    if !ready() {
        eprintln!("skipped: needs Node.js, node_modules and dist-selfhost");
        return;
    }
    let kits: Vec<Kit> = (0..4).map(|_| Kit::new()).collect();
    let node_data = tempfile::tempdir().unwrap();
    let site = {
        let node = federating(true, node_data.path());
        make(node.1, node_data.path(), &kits)
    };
    // The Node.js server has stopped. The Rust server gets a copy of its data, as the new image
    // gets the volume.
    let rust_data = tempfile::tempdir().unwrap();
    copy(node_data.path(), rust_data.path());
    let (node_log, rust_log) = {
        let (node, rust) = (
            federating(true, node_data.path()),
            federating(false, rust_data.path()),
        );
        (
            carry_on(node.1, &site, &kits),
            carry_on(rust.1, &site, &kits),
        )
    };
    if std::env::var("CV_DUMP").is_ok() {
        for (a, b) in node_log.iter().zip(&rust_log) {
            println!("{}\n  node: {a}\n  rust: {b}", a["step"]);
        }
    }
    assert_eq!(node_log.len(), rust_log.len());
    for (a, b) in node_log.iter().zip(&rust_log) {
        assert_eq!(a, b, "\nnode: {a}\nrust: {b}");
    }
    // It really did carry on.
    let failed: Vec<&Value> = rust_log
        .iter()
        .filter(|s| {
            s["status"] != 200
                && s["step"] != "sign in: wrong password"
                && s["step"] != "dave still only takes them from servers"
        })
        .collect();
    assert!(failed.is_empty(), "{failed:?}");
    let step = |name: &str| {
        rust_log
            .iter()
            .find(|s| s["step"] == name)
            .cloned()
            .unwrap_or_default()
    };
    assert_eq!(step("download the file")["reply"]["same"], true);
    assert_eq!(step("sign in: wrong password")["status"], 401);
    assert_eq!(
        step("sign in")["reply"]["verify"]["methods"],
        json!(["device"])
    );
    assert_eq!(
        step("the site's federation document")["raw"]["key"]["alg"],
        "Ed25519"
    );
}

fn copy(from: &Path, to: &Path) {
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            std::fs::create_dir_all(&target).unwrap();
            copy(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}
