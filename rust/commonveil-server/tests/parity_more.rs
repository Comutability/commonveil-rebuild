//! Voice passes, events, files (and their download links), server moderation, the protocol layer
//! and the proposals forum, over HTTP against the Node.js server: the same script runs against
//! both, each on its own fresh site, and every reply must match once random values are blanked.
use std::collections::HashMap;
use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};

mod common;
use common::servers::{channel, people, rid, role, s, Keys, Who};
use common::{compare, get_raw, iso_at, now, ready, sealed_item, start, succeeded, Flow, Kit};

/// A 22-character protocol key id.
fn kid(name: &str) -> String {
    format!("{name:_<21}1")
}

fn actor_doc(who: &str, seq: u32, devices: &[&str]) -> String {
    let id = kid(&format!("{who}actor"));
    json!({
        "kind": "actor.document",
        "body": { "id": id, "handle": format!("{who}@cv.example"), "account": "acct.example", "seq": seq, "devices": { "body": { "devices": devices.iter().map(|d| json!({ "kid": d })).collect::<Vec<_>>() } } },
        "sig": { "kid": id, "value": "sig", "pq": "pq" },
    })
    .to_string()
}

fn prekey(device: &str, id: &str) -> String {
    json!({ "kind": "session.prekey", "body": { "device": device, "id": id }, "sig": { "kid": device, "value": "sig", "pq": "pq" } }).to_string()
}

fn envelope(device: &str) -> String {
    json!({ "v": 1, "mode": "direct", "device": device, "session": kid("session"), "message": { "v": 1, "c": "sealed" } }).to_string()
}

fn script(port: u16, data: &Path, kits: &[Kit]) -> Vec<Value> {
    let mut f = Flow::new(port);
    let people = people(
        &mut f,
        data,
        &["alice", "bob", "carol", "dave", "erin"],
        kits,
    );
    let (alice, bob, carol, dave, erin) =
        (&people[0], &people[1], &people[2], &people[3], &people[4]);
    let call = |f: &mut Flow, func: &str, step: &str, w: &Who, body: Value| {
        f.call(func, step, &w.token, body)
    };

    // ----- a server to work in -----
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
    let mut bob_keys: Keys = HashMap::new();
    call(
        &mut f,
        "servers",
        "history keys",
        bob,
        bob.generation(&sid, &h, 0, &[bob], &mut bob_keys),
    );
    call(
        &mut f,
        "servers",
        "live keys",
        bob,
        bob.generation(&sid, &l, 0, &[bob], &mut bob_keys),
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
    for w in [carol, dave, erin] {
        call(
            &mut f,
            "servers",
            "join",
            w,
            w.signed("join_server", json!({ "invite_code": "abcdefgh34" })),
        );
    }
    let grants: Vec<Value> = [carol, dave, erin]
        .iter()
        .flat_map(|w| [&h, &l].map(|c| bob.grant(&sid, c, 0, &bob_keys[c].1, w)))
        .collect();
    call(
        &mut f,
        "servers",
        "grant",
        bob,
        bob.signed("grant_keys", json!({ "server_id": sid, "grants": grants })),
    );
    let keys = bob_keys.clone();
    call(&mut f, "servers", "carol moderates", bob, bob.signed("set_member_roles", json!({ "server_id": sid, "user_id": carol.id, "role_ids": [role(&st, "moderator")["id"]] })));
    let general = s(&channel(&st, "general")["id"]);
    let lounge = s(&channel(&st, "lounge")["id"]);
    let dm = call(
        &mut f,
        "conversations",
        "dm",
        carol,
        carol.signed("create_dm", json!({ "username": "dave" })),
    );
    let dm_id = s(&dm["conversation"]["id"]);

    // ----- voice -----
    call(
        &mut f,
        "voice",
        "voice: unsigned",
        dave,
        json!({ "action": "voice_ticket" }),
    );
    call(
        &mut f,
        "voice",
        "voice: not a voice channel",
        dave,
        dave.signed(
            "voice_ticket",
            json!({ "server_id": sid, "channel_id": general }),
        ),
    );
    call(
        &mut f,
        "voice",
        "voice",
        dave,
        dave.signed(
            "voice_ticket",
            json!({ "server_id": sid, "channel_id": lounge }),
        ),
    );
    call(
        &mut f,
        "voice",
        "voice: not a member",
        alice,
        alice.signed(
            "voice_ticket",
            json!({ "server_id": sid, "channel_id": lounge }),
        ),
    );
    call(
        &mut f,
        "voice",
        "call",
        dave,
        dave.signed(
            "call_ticket",
            json!({ "conversation_id": dm_id, "call_id": "abcdefgh12" }),
        ),
    );
    call(
        &mut f,
        "voice",
        "call: bad id",
        dave,
        dave.signed(
            "call_ticket",
            json!({ "conversation_id": dm_id, "call_id": "a b" }),
        ),
    );
    call(
        &mut f,
        "voice",
        "call: not in it",
        erin,
        erin.signed(
            "call_ticket",
            json!({ "conversation_id": dm_id, "call_id": "abcdefgh12" }),
        ),
    );
    for i in 0..5 {
        call(
            &mut f,
            "voice",
            &format!("voice again {i}"),
            dave,
            dave.signed(
                "voice_ticket",
                json!({ "server_id": sid, "channel_id": lounge }),
            ),
        );
    }

    // ----- events -----
    call(
        &mut f,
        "events",
        "events: none",
        dave,
        json!({ "action": "list", "server_id": sid }),
    );
    call(
        &mut f,
        "events",
        "event: not allowed",
        dave,
        dave.signed(
            "create_event",
            json!({ "server_id": sid, "item": dave.item("event", &sid, "", &rid(50), &h, &keys) }),
        ),
    );
    let ev = call(&mut f, "events", "event", bob, bob.signed("create_event", json!({ "server_id": sid, "item": bob.item("event", &sid, "", &rid(51), &h, &bob_keys) })));
    call(&mut f, "events", "event: wrong chain", bob, bob.signed("create_event", json!({ "server_id": sid, "item": bob.item("event", &sid, "", &rid(52), &l, &bob_keys) })));
    let eid = s(&ev["event"]["event_id"]);
    call(&mut f, "events", "rsvp", dave, dave.signed("rsvp", json!({ "server_id": sid, "event_id": eid, "item": dave.item("rsvp", &sid, "", &rid(53), &h, &keys) })));
    call(&mut f, "events", "rsvp again", dave, dave.signed("rsvp", json!({ "server_id": sid, "event_id": eid, "item": dave.item("rsvp", &sid, "", &rid(54), &h, &keys) })));
    call(
        &mut f,
        "events",
        "rsvp: unknown event",
        dave,
        dave.signed(
            "rsvp",
            json!({ "server_id": sid, "event_id": rid(99), "item": null }),
        ),
    );
    call(
        &mut f,
        "events",
        "events",
        carol,
        json!({ "action": "list", "server_id": sid }),
    );
    call(
        &mut f,
        "events",
        "shared event",
        carol,
        json!({ "action": "shared_event", "event_id": eid }),
    );
    call(
        &mut f,
        "events",
        "shared event: outsider",
        alice,
        json!({ "action": "shared_event", "event_id": eid }),
    );
    call(&mut f, "events", "update", bob, bob.signed("update_event", json!({ "server_id": sid, "event_id": eid, "item": bob.item("event", &sid, "", &rid(55), &h, &bob_keys) })));
    call(
        &mut f,
        "events",
        "take back rsvp",
        dave,
        dave.signed(
            "rsvp",
            json!({ "server_id": sid, "event_id": eid, "item": null }),
        ),
    );
    call(
        &mut f,
        "events",
        "cancel",
        bob,
        bob.signed("cancel_event", json!({ "server_id": sid, "event_id": eid })),
    );
    call(
        &mut f,
        "events",
        "events after",
        carol,
        json!({ "action": "list", "server_id": sid }),
    );

    // ----- files -----
    let bytes: Vec<u8> = (0..200u32).map(|i| (i * 7 % 251) as u8).collect();
    let part = STANDARD.encode(&bytes);
    let up = |w: &Who, place: Value, msg: &str, extra: Value| {
        let mut p = place;
        p["msg_id"] = json!(msg);
        p["part"] = json!(0);
        p["parts"] = json!(1);
        p["data"] = json!(part);
        for (k, v) in extra.as_object().into_iter().flatten() {
            p[k] = v.clone();
        }
        w.signed("upload_part", p)
    };
    let in_dm = json!({ "scope": "conversation", "conversation_id": dm_id });
    let in_general = json!({ "scope": "server", "server_id": sid, "channel_id": general });
    call(
        &mut f,
        "files",
        "upload: bad place",
        carol,
        up(carol, json!({ "scope": "moon" }), &rid(60), json!({})),
    );
    call(
        &mut f,
        "files",
        "upload: too many parts",
        carol,
        up(carol, in_dm.clone(), &rid(60), json!({ "parts": 15 })),
    );
    call(
        &mut f,
        "files",
        "upload: bad part",
        carol,
        up(
            carol,
            in_dm.clone(),
            &rid(60),
            json!({ "data": "not base64!" }),
        ),
    );
    call(
        &mut f,
        "files",
        "upload: too small",
        carol,
        up(carol, in_dm.clone(), &rid(60), json!({ "data": "AAAA" })),
    );
    call(
        &mut f,
        "files",
        "upload: not in it",
        erin,
        up(erin, in_dm.clone(), &rid(60), json!({})),
    );
    let dm_file = call(
        &mut f,
        "files",
        "upload to a conversation",
        carol,
        up(carol, in_dm.clone(), &rid(60), json!({})),
    );
    let ch_file = call(
        &mut f,
        "files",
        "upload to a channel",
        carol,
        up(carol, in_general.clone(), &rid(61), json!({})),
    );
    call(
        &mut f,
        "files",
        "upload: read-only channel",
        carol,
        up(
            carol,
            json!({ "scope": "server", "server_id": sid, "channel_id": channel(&st, "welcome")["id"] }),
            &rid(62),
            json!({}),
        ),
    );
    call(
        &mut f,
        "files",
        "links before the messages are sent",
        dave,
        json!({ "action": "download_links", "file_ids": [dm_file["file_id"], ch_file["file_id"]] }),
    );
    let recips = [carol.recipient(), dave.recipient()];
    let at = iso_at(now());
    let (env, sig) = sealed_item(
        "message",
        &dm_id,
        &rid(60),
        (&carol.id, carol.kit),
        &recips,
        &at,
    );
    call(
        &mut f,
        "messages",
        "send the conversation message",
        carol,
        json!({ "action": "send", "conversation_id": dm_id, "device_id": carol.kit.id(0), "msg_id": rid(60), "sent_at": at, "envelope": env, "signature": sig }),
    );
    call(
        &mut f,
        "channels",
        "send the channel message",
        carol,
        carol.message(&sid, &general, &rid(61), &l, &keys, "message", ""),
    );
    call(
        &mut f,
        "files",
        "upload: message already sent",
        carol,
        up(carol, in_dm.clone(), &rid(60), json!({})),
    );
    let links = call(
        &mut f,
        "files",
        "links",
        dave,
        json!({ "action": "download_links", "file_ids": [dm_file["file_id"], ch_file["file_id"], "nope", 5] }),
    );
    call(
        &mut f,
        "files",
        "links: outsider",
        erin,
        json!({ "action": "download_links", "file_ids": [dm_file["file_id"]] }),
    );
    call(
        &mut f,
        "files",
        "links: none asked for",
        erin,
        json!({ "action": "download_links" }),
    );
    for (step, key) in [
        ("download the conversation file", &dm_file["file_id"]),
        ("download the channel file", &ch_file["file_id"]),
    ] {
        let url = links["links"][key.as_str().unwrap_or("")]
            .as_str()
            .unwrap_or("")
            .to_string();
        let path = url
            .strip_prefix("https://cv.example")
            .unwrap_or("/api/files/none")
            .to_string();
        let (status, body) = get_raw(port, &path);
        f.log
            .push(json!({ "step": step, "status": status, "reply": { "same": body == bytes } }));
        let (status, _) = get_raw(port, &format!("{}x", path));
        f.log
            .push(json!({ "step": format!("{step}: bent link"), "status": status }));
    }

    // ----- moderation -----
    let m =
        |f: &mut Flow, step: &str, w: &Who, body: Value| f.call("moderation", step, &w.token, body);
    let r = m(
        &mut f,
        "report recipients",
        dave,
        json!({ "action": "report_recipients", "server_id": sid, "target_id": erin.id }),
    );
    let by_id: HashMap<String, &Who> = people.iter().map(|w| (w.id.clone(), w)).collect();
    let recips: Vec<Value> = r["recipients"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|i| by_id.get(i.as_str().unwrap_or("")))
        .map(|w| w.recipient())
        .collect();
    let report_item = |id: &str, recips: &[Value]| {
        let at = iso_at(now());
        let (env, sig) = sealed_item("report", &sid, id, (&dave.id, dave.kit), recips, &at);
        json!({ "item_id": id, "device_id": dave.kit.id(0), "sent_at": at, "envelope": env, "signature": sig })
    };
    m(&mut f, "report: myself", dave, dave.signed("report", json!({ "server_id": sid, "target_id": dave.id, "item": report_item(&rid(70), &recips) })));
    m(&mut f, "report: wrong recipients", dave, dave.signed("report", json!({ "server_id": sid, "target_id": erin.id, "item": report_item(&rid(70), &recips[..1]) })));
    let rep = m(&mut f, "report", dave, dave.signed("report", json!({ "server_id": sid, "target_id": erin.id, "item": report_item(&rid(70), &recips) })));
    m(&mut f, "report: retried", dave, dave.signed("report", json!({ "server_id": sid, "target_id": erin.id, "item": report_item(&rid(70), &recips) })));
    m(
        &mut f,
        "reports: mine",
        dave,
        json!({ "action": "reports", "server_id": sid }),
    );
    m(
        &mut f,
        "reports: moderator",
        carol,
        json!({ "action": "reports", "server_id": sid, "status": "open" }),
    );
    m(
        &mut f,
        "reports: someone else",
        erin,
        json!({ "action": "reports", "server_id": sid }),
    );
    let report_id = rep["report"]["report_id"].clone();
    m(
        &mut f,
        "report status: not a moderator",
        dave,
        dave.signed(
            "set_report_status",
            json!({ "server_id": sid, "report_id": report_id, "status": "resolved" }),
        ),
    );
    m(
        &mut f,
        "report status: bad",
        carol,
        carol.signed(
            "set_report_status",
            json!({ "server_id": sid, "report_id": report_id, "status": "escalated" }),
        ),
    );
    m(
        &mut f,
        "report status",
        carol,
        carol.signed(
            "set_report_status",
            json!({ "server_id": sid, "report_id": report_id, "status": "resolved" }),
        ),
    );
    m(
        &mut f,
        "escalate: no reason",
        carol,
        carol.signed(
            "escalate",
            json!({ "server_id": sid, "report_id": report_id }),
        ),
    );
    m(
        &mut f,
        "escalate: no details",
        carol,
        carol.signed(
            "escalate",
            json!({ "server_id": sid, "report_id": report_id, "reason": "scam", "details": "  " }),
        ),
    );
    m(&mut f, "escalate", carol, carol.signed("escalate", json!({ "server_id": sid, "report_id": report_id, "reason": "hate", "details": "What was said.", "server_name": "Tea Club" })));
    m(
        &mut f,
        "escalate without a report",
        carol,
        carol.signed(
            "escalate",
            json!({ "server_id": sid, "target_id": erin.id, "reason": "spam", "details": "Spam." }),
        ),
    );
    m(
        &mut f,
        "policy",
        dave,
        json!({ "action": "policy", "server_id": sid }),
    );
    m(
        &mut f,
        "policy: not allowed",
        carol,
        carol.signed("set_policy", json!({ "server_id": sid, "policy": {} })),
    );
    m(
        &mut f,
        "policy: only the owner turns staff limits off",
        bob,
        bob.signed(
            "set_policy",
            json!({ "server_id": sid, "policy": { "nuke": { "enabled": false } } }),
        ),
    );
    m(&mut f, "set policy", bob, bob.signed("set_policy", json!({ "server_id": sid, "policy": { "warn_window_days": 7, "thresholds": [{ "count": 2, "action": "timeout", "minutes": 10 }, { "count": 9, "action": "ban" }, { "count": 2, "action": "kick" }, { "count": 30, "action": "ban" }], "flood": { "enabled": true, "messages": 5 } }, "clear_raid": true })));
    m(
        &mut f,
        "warn: not allowed",
        dave,
        dave.signed("warn", json!({ "server_id": sid, "user_id": erin.id })),
    );
    m(
        &mut f,
        "warn: the owner",
        carol,
        carol.signed("warn", json!({ "server_id": sid, "user_id": bob.id })),
    );
    m(&mut f, "warn", carol, carol.signed("warn", json!({ "server_id": sid, "user_id": erin.id, "report_id": report_id, "reason": carol.item("case", &sid, "", &rid(71), &h, &keys) })));
    m(
        &mut f,
        "warn again: timed out",
        carol,
        carol.signed("warn", json!({ "server_id": sid, "user_id": erin.id })),
    );
    let note = m(&mut f, "note", carol, carol.signed("note", json!({ "server_id": sid, "user_id": erin.id, "reason": carol.item("case", &sid, "", &rid(72), &h, &keys) })));
    m(
        &mut f,
        "note: empty",
        carol,
        carol.signed("note", json!({ "server_id": sid, "user_id": erin.id })),
    );
    m(
        &mut f,
        "cases: mine",
        erin,
        json!({ "action": "cases", "server_id": sid }),
    );
    m(
        &mut f,
        "cases",
        carol,
        json!({ "action": "cases", "server_id": sid }),
    );
    m(
        &mut f,
        "cases: one member",
        carol,
        json!({ "action": "cases", "server_id": sid, "user_id": erin.id }),
    );
    m(
        &mut f,
        "pardon",
        carol,
        carol.signed(
            "pardon",
            json!({ "server_id": sid, "case_id": note["case"]["case_id"] }),
        ),
    );
    m(
        &mut f,
        "pardon: unknown",
        carol,
        carol.signed(
            "pardon",
            json!({ "server_id": sid, "case_id": "nope00000000" }),
        ),
    );
    m(
        &mut f,
        "purge: bad length",
        carol,
        carol.signed(
            "purge",
            json!({ "server_id": sid, "user_id": carol.id, "seconds": 60 }),
        ),
    );
    m(
        &mut f,
        "purge",
        bob,
        bob.signed(
            "purge",
            json!({ "server_id": sid, "user_id": carol.id, "seconds": 3600 }),
        ),
    );
    m(&mut f, "purge: a channel", bob, bob.signed("purge", json!({ "server_id": sid, "user_id": carol.id, "seconds": 86400, "channel_id": general })));

    // ----- the protocol layer -----
    let pr =
        |f: &mut Flow, step: &str, w: &Who, body: Value| f.call("protocol", step, &w.token, body);
    let (cd, dd) = (kid("caroldevice"), kid("davedevice"));
    pr(
        &mut f,
        "proto: mine, none",
        carol,
        json!({ "action": "mine" }),
    );
    pr(&mut f, "proto: bad handle", carol, carol.signed("proto_publish", json!({ "document": actor_doc("dave", 1, &[&cd]), "sealed_account": "sealed-account-key-0001", "sealed_version": 1 })));
    pr(&mut f, "proto: no devices", carol, carol.signed("proto_publish", json!({ "document": actor_doc("carol", 1, &[]), "sealed_account": "sealed-account-key-0001", "sealed_version": 1 })));
    pr(&mut f, "proto: publish", carol, carol.signed("proto_publish", json!({ "document": actor_doc("carol", 1, &[&cd]), "sealed_account": "sealed-account-key-0001", "sealed_version": 1 })));
    pr(&mut f, "proto: stale", carol, carol.signed("proto_publish", json!({ "document": actor_doc("carol", 1, &[&cd]), "sealed_account": "sealed-account-key-0001", "sealed_version": 1 })));
    pr(&mut f, "dave publishes", dave, dave.signed("proto_publish", json!({ "document": actor_doc("dave", 1, &[&dd]), "sealed_account": "sealed-account-key-0002", "sealed_version": 1 })));
    pr(
        &mut f,
        "proto: prekeys for a device not listed",
        carol,
        carol.signed(
            "proto_prekeys",
            json!({ "device": dd, "signed": prekey(&dd, "s1"), "lastResort": prekey(&dd, "l1") }),
        ),
    );
    pr(&mut f, "proto: prekeys", carol, carol.signed("proto_prekeys", json!({ "device": cd, "signed": prekey(&cd, "s1"), "lastResort": prekey(&cd, "l1"), "oneTime": [prekey(&cd, "o1"), prekey(&cd, "o2")], "pqOneTime": [prekey(&cd, "q1")] })));
    pr(
        &mut f,
        "proto: bad prekey",
        carol,
        carol.signed(
            "proto_prekeys",
            json!({ "device": cd, "oneTime": [prekey(&dd, "o3")] }),
        ),
    );
    pr(&mut f, "proto: mine", carol, json!({ "action": "mine" }));
    pr(
        &mut f,
        "proto: actors",
        dave,
        json!({ "action": "actors", "user_ids": [carol.id, erin.id, dave.id, carol.id] }),
    );
    pr(
        &mut f,
        "proto: actors from a stranger",
        erin,
        json!({ "action": "actors", "user_ids": [carol.id] }),
    );
    pr(
        &mut f,
        "proto: bundle",
        dave,
        json!({ "action": "bundle", "user_id": carol.id, "device": cd }),
    );
    pr(
        &mut f,
        "proto: bundle 2",
        dave,
        json!({ "action": "bundle", "user_id": carol.id, "device": cd }),
    );
    pr(
        &mut f,
        "proto: bundle 3 (one-time keys used up)",
        dave,
        json!({ "action": "bundle", "user_id": carol.id, "device": cd }),
    );
    pr(
        &mut f,
        "proto: bundle, no prekeys",
        carol,
        json!({ "action": "bundle", "user_id": dave.id, "device": dd }),
    );
    pr(
        &mut f,
        "proto: bundle from a stranger",
        erin,
        json!({ "action": "bundle", "user_id": carol.id, "device": cd }),
    );
    pr(
        &mut f,
        "proto: send",
        dave,
        json!({ "action": "send", "items": [{ "to": carol.id, "envelope": envelope(&cd) }, { "to": carol.id, "envelope": envelope(&dd) }, { "to": erin.id, "envelope": envelope(&cd) }] }),
    );
    pr(
        &mut f,
        "proto: send, extra fields",
        dave,
        json!({ "action": "send", "items": [{ "to": carol.id, "envelope": json!({ "v": 1, "mode": "direct", "device": cd, "session": kid("session"), "message": { "v": 1, "c": "x" }, "from": "me" }).to_string() }] }),
    );
    pr(
        &mut f,
        "proto: send nothing",
        dave,
        json!({ "action": "send", "items": [] }),
    );
    let mail = pr(
        &mut f,
        "proto: collect",
        carol,
        json!({ "action": "collect", "device": cd }),
    );
    let ids: Vec<Value> = mail["mail"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|m| m["id"].clone())
        .collect();
    pr(
        &mut f,
        "proto: collect and acknowledge",
        carol,
        json!({ "action": "collect", "device": cd, "ack": ids }),
    );
    pr(
        &mut f,
        "proto: collect, bad device",
        carol,
        json!({ "action": "collect", "device": "short" }),
    );
    pr(&mut f, "proto: publish without the device", carol, carol.signed("proto_publish", json!({ "document": actor_doc("carol", 2, &[&kid("carolnew")]), "sealed_account": "sealed-account-key-0001", "sealed_version": 2 })));
    pr(
        &mut f,
        "proto: mine after",
        carol,
        json!({ "action": "mine" }),
    );
    pr(
        &mut f,
        "proto: disable",
        carol,
        carol.signed("proto_disable", json!({})),
    );
    pr(
        &mut f,
        "proto: mine, gone",
        carol,
        json!({ "action": "mine" }),
    );

    // ----- the proposals forum (off here) -----
    f.call(
        "snips",
        "snips: status",
        &bob.token,
        json!({ "action": "status" }),
    );
    f.call(
        "snips",
        "snips: ensure forum",
        &bob.token,
        bob.signed("ensure_forum", json!({})),
    );
    f.call(
        "fedinbox",
        "a function this site doesn't run",
        &bob.token,
        json!({ "action": "anything" }),
    );
    f.call("nope", "no such function", "", json!({}));
    f.log
}

#[test]
fn the_rest_of_the_functions_answer_as_the_node_server_does() {
    if !ready() {
        eprintln!("skipped: node, the npm packages or dist-selfhost aren't there");
        return;
    }
    let kits: Vec<Kit> = (0..5).map(|_| Kit::new()).collect();
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (node, rust) = (start(true, d1.path()), start(false, d2.path()));
    let (a, b) = (
        script(node.1, d1.path(), &kits),
        script(rust.1, d2.path(), &kits),
    );
    let ok = compare(&a, &b);
    assert!(ok > 40, "only {ok} steps succeeded");
    succeeded(
        &a,
        &[
            "voice",
            "call",
            "event",
            "rsvp",
            "update",
            "cancel",
            "upload to a conversation",
            "upload to a channel",
            "links",
            "download the conversation file",
            "download the channel file",
            "report",
            "report status",
            "escalate",
            "set policy",
            "warn",
            "note",
            "pardon",
            "purge",
            "proto: publish",
            "proto: prekeys",
            "proto: bundle",
            "proto: send",
            "proto: collect",
            "proto: disable",
            "snips: status",
        ],
    );
}
