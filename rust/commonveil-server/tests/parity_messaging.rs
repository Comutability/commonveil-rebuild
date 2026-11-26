//! Conversations, messages, messages that wait, and push subscriptions over HTTP against the
//! Node.js server: the same script (real envelopes and signatures from Secure Net's Rust client
//! code) runs against both, each on its own fresh site, and every reply must match once random
//! values are blanked.
use std::path::Path;

use serde_json::{json, Value};

mod common;
use common::{compare, iso_at, now, ready, sealed_item, start, succeeded, Flow, Kit};

fn mid(n: u32) -> String {
    format!("msg-{n:04}-aaaaaaaaaaaa")
}

struct Who<'a> {
    token: String,
    id: String,
    kit: &'a Kit,
}

fn script(port: u16, data: &Path, kits: &[Kit]) -> Vec<Value> {
    let mut f = Flow::new(port);
    let setup = std::fs::read_to_string(data.join("setup-code"))
        .unwrap()
        .trim()
        .to_string();
    let mut people: Vec<Who> = Vec::new();
    for (i, name) in ["alice", "bob", "carol", "dave", "erin"].iter().enumerate() {
        let mut reg = json!({ "action": "register", "username": name, "password": "a long enough password", "age_confirmed": true });
        if i == 0 {
            reg["setup_code"] = json!(setup);
        }
        let r = f.call("identity", &format!("register {name}"), "", reg);
        people.push(Who {
            token: r["session"]["access_token"].as_str().unwrap_or("").into(),
            id: r["session"]["user_id"].as_str().unwrap_or("").into(),
            kit: &kits[i],
        });
    }
    // Bob, Carol and Dave set up encryption; Alice and Erin don't.
    for p in &people[1..4] {
        f.call("keys", "init", &p.token, p.kit.init(&p.id));
    }
    let (bob, carol, dave, erin) = (&people[1], &people[2], &people[3], &people[4]);
    let c = |f: &mut Flow, step: &str, who: &Who, body: Value| {
        f.call("conversations", step, &who.token, body)
    };
    let m = |f: &mut Flow, step: &str, who: &Who, body: Value| {
        f.call("messages", step, &who.token, body)
    };
    let signed =
        |who: &Who, action: &str, payload: Value| who.kit.signed(&who.id, action, 0, payload);

    // ----- starting conversations -----
    c(&mut f, "list: none", bob, json!({ "action": "list" }));
    c(
        &mut f,
        "dm: unsigned",
        bob,
        json!({ "action": "create_dm", "username": "carol" }),
    );
    c(
        &mut f,
        "dm: without keys",
        erin,
        json!({ "action": "create_dm", "payload": "{}", "proof": {} }),
    );
    c(
        &mut f,
        "dm: self",
        bob,
        signed(bob, "create_dm", json!({ "username": "bob" })),
    );
    c(
        &mut f,
        "dm: not ready",
        bob,
        signed(bob, "create_dm", json!({ "username": "erin" })),
    );
    c(
        &mut f,
        "dm: nobody",
        bob,
        signed(bob, "create_dm", json!({ "username": "nobody_x" })),
    );
    c(
        &mut f,
        "dm: bad name",
        bob,
        signed(bob, "create_dm", json!({ "username": "a b" })),
    );
    c(
        &mut f,
        "dm: missing name",
        bob,
        signed(bob, "create_dm", json!({})),
    );
    let dm = c(
        &mut f,
        "dm",
        bob,
        signed(bob, "create_dm", json!({ "username": "@Carol" })),
    );
    let dm_id = dm["conversation"]["id"].as_str().unwrap_or("").to_string();
    c(
        &mut f,
        "dm again (the other way)",
        carol,
        signed(carol, "create_dm", json!({ "username": "bob" })),
    );
    f.call(
        "profile",
        "carol: nobody new",
        &carol.token,
        json!({ "action": "update", "dm_policy": "nobody" }),
    );
    c(
        &mut f,
        "dm: not accepting",
        dave,
        signed(dave, "create_dm", json!({ "username": "carol" })),
    );
    f.call(
        "profile",
        "carol: servers only",
        &carol.token,
        json!({ "action": "update", "dm_policy": "servers" }),
    );
    c(
        &mut f,
        "dm: servers only",
        dave,
        signed(dave, "create_dm", json!({ "username": "carol" })),
    );
    c(
        &mut f,
        "group: not accepting",
        bob,
        signed(
            bob,
            "create_group",
            json!({ "usernames": ["carol", "dave"] }),
        ),
    );
    f.call(
        "profile",
        "carol: anyone",
        &carol.token,
        json!({ "action": "update", "dm_policy": "anyone" }),
    );
    c(
        &mut f,
        "group: only me",
        bob,
        signed(bob, "create_group", json!({ "usernames": ["bob"] })),
    );
    c(
        &mut f,
        "group: nobody",
        bob,
        signed(bob, "create_group", json!({ "usernames": [] })),
    );
    let g = c(
        &mut f,
        "group",
        bob,
        signed(
            bob,
            "create_group",
            json!({ "usernames": ["carol", "dave", "carol"] }),
        ),
    );
    let g_id = g["conversation"]["id"].as_str().unwrap_or("").to_string();
    c(&mut f, "list", bob, json!({ "action": "list" }));
    c(
        &mut f,
        "get",
        carol,
        json!({ "action": "get", "conversation_id": g_id }),
    );
    c(
        &mut f,
        "get: not a member",
        erin,
        json!({ "action": "get", "conversation_id": g_id }),
    );
    c(
        &mut f,
        "get: bad id",
        bob,
        json!({ "action": "get", "conversation_id": "a b" }),
    );

    // ----- the group's name -----
    let all3 = [
        bob.kit.recipient(&bob.id),
        carol.kit.recipient(&carol.id),
        dave.kit.recipient(&dave.id),
    ];
    let title = |who: &Who, item: &str, recipients: &[Value], at: &str| {
        let (env, sig) = sealed_item("title", &g_id, item, (&who.id, who.kit), recipients, at);
        json!({ "action": "set_title", "conversation_id": g_id, "device_id": who.kit.id(0), "item_id": item, "sent_at": at, "envelope": env, "signature": sig })
    };
    let at = iso_at(now());
    c(
        &mut f,
        "title: not an admin",
        carol,
        title(carol, &mid(1), &all3, &at),
    );
    c(
        &mut f,
        "title: someone left out",
        bob,
        title(bob, &mid(2), &all3[..2], &at),
    );
    c(
        &mut f,
        "title: old clock",
        bob,
        title(bob, &mid(3), &all3, &iso_at(now() - 3_600_000)),
    );
    let mut bent = title(bob, &mid(4), &all3, &at);
    bent["sent_at"] = json!(iso_at(now() - 1000));
    c(&mut f, "title: signature doesn't cover it", bob, bent);
    c(&mut f, "title", bob, title(bob, &mid(5), &all3, &at));

    // ----- messages -----
    let dm_people = [bob.kit.recipient(&bob.id), carol.kit.recipient(&carol.id)];
    let msg = |who: &Who, conv: &str, item: &str, recipients: &[Value], at: &str| {
        let (env, sig) = sealed_item("message", conv, item, (&who.id, who.kit), recipients, at);
        json!({ "action": "send", "conversation_id": conv, "device_id": who.kit.id(0), "msg_id": item, "sent_at": at, "envelope": env, "signature": sig })
    };
    let first = m(&mut f, "poll: start", carol, json!({ "action": "poll" }));
    m(
        &mut f,
        "send",
        bob,
        msg(bob, &dm_id, &mid(10), &dm_people, &iso_at(now())),
    );
    m(
        &mut f,
        "send: retried",
        bob,
        msg(bob, &dm_id, &mid(10), &dm_people, &iso_at(now())),
    );
    m(
        &mut f,
        "send: id taken by someone else",
        carol,
        msg(carol, &dm_id, &mid(10), &dm_people, &iso_at(now())),
    );
    m(
        &mut f,
        "send: not a member",
        dave,
        msg(dave, &dm_id, &mid(11), &dm_people, &iso_at(now())),
    );
    m(
        &mut f,
        "send: someone left out",
        bob,
        msg(bob, &dm_id, &mid(12), &dm_people[..1], &iso_at(now())),
    );
    m(
        &mut f,
        "send: a stranger added",
        bob,
        msg(bob, &dm_id, &mid(13), &all3, &iso_at(now())),
    );
    let mut wrong_kv = dm_people.clone();
    wrong_kv[1]["key_version"] = json!(2);
    m(
        &mut f,
        "send: old keys",
        bob,
        msg(bob, &dm_id, &mid(14), &wrong_kv, &iso_at(now())),
    );
    let mut classical = dm_people.clone();
    classical[1]["kem_pub"] = json!("");
    m(
        &mut f,
        "send: not post-quantum",
        bob,
        msg(bob, &dm_id, &mid(15), &classical, &iso_at(now())),
    );
    m(
        &mut f,
        "send: clock ahead",
        bob,
        msg(
            bob,
            &dm_id,
            &mid(16),
            &dm_people,
            &iso_at(now() + 3_600_000),
        ),
    );
    let mut queued = msg(
        bob,
        &dm_id,
        &mid(17),
        &dm_people,
        &iso_at(now() - 3_600_000),
    );
    queued["queued"] = json!(true);
    m(&mut f, "send: queued an hour ago", bob, queued);
    let mut stale = msg(
        bob,
        &dm_id,
        &mid(18),
        &dm_people,
        &iso_at(now() - 8 * 86_400_000),
    );
    stale["queued"] = json!(true);
    m(&mut f, "send: queued too long ago", bob, stale);
    let mut bad_sig = msg(bob, &dm_id, &mid(19), &dm_people, &iso_at(now()));
    bad_sig["signature"] = json!("AAAA");
    m(&mut f, "send: bad signature", bob, bad_sig);
    let mut bad_env = msg(bob, &dm_id, &mid(20), &dm_people, &iso_at(now()));
    bad_env["envelope"] = json!("{\"v\":1}");
    m(&mut f, "send: malformed", bob, bad_env);
    m(
        &mut f,
        "send: no envelope",
        bob,
        json!({ "action": "send", "conversation_id": dm_id, "device_id": bob.kit.id(0), "msg_id": mid(21), "sent_at": iso_at(now()) }),
    );
    m(
        &mut f,
        "send: another's device",
        bob,
        json!({ "action": "send", "conversation_id": dm_id, "device_id": carol.kit.id(0), "msg_id": mid(22), "sent_at": iso_at(now()) }),
    );
    m(
        &mut f,
        "send to the group",
        carol,
        msg(carol, &g_id, &mid(23), &all3, &iso_at(now())),
    );
    m(
        &mut f,
        "list",
        carol,
        json!({ "action": "list", "conversation_id": dm_id }),
    );
    m(
        &mut f,
        "list: one",
        carol,
        json!({ "action": "list", "conversation_id": dm_id, "limit": 1 }),
    );
    m(
        &mut f,
        "list: bad limit",
        carol,
        json!({ "action": "list", "conversation_id": dm_id, "limit": 51 }),
    );
    m(
        &mut f,
        "list: before",
        carol,
        json!({ "action": "list", "conversation_id": dm_id, "before": "2000-01-01T00:00:00" }),
    );
    m(
        &mut f,
        "list: not a member",
        dave,
        json!({ "action": "list", "conversation_id": dm_id }),
    );
    // Changes since the start of time, not since the first poll's cursor: which rows changed in the
    // seconds before that poll depends on how fast the run is, and the comparison mustn't.
    m(
        &mut f,
        "poll",
        carol,
        json!({ "action": "poll", "since": first["cursor"], "conversations_since": "2000-01-01T00:00:00" }),
    );
    m(
        &mut f,
        "poll: bad cursor",
        carol,
        json!({ "action": "poll", "since": 5 }),
    );

    // ----- disappearing and self-destructing -----
    c(
        &mut f,
        "expiry: bad",
        carol,
        signed(
            carol,
            "set_expiry",
            json!({ "conversation_id": dm_id, "seconds": 60 }),
        ),
    );
    c(
        &mut f,
        "expiry: a day",
        carol,
        signed(
            carol,
            "set_expiry",
            json!({ "conversation_id": dm_id, "seconds": "86400" }),
        ),
    );
    m(
        &mut f,
        "send: disappearing",
        bob,
        msg(bob, &dm_id, &mid(30), &dm_people, &iso_at(now())),
    );
    c(
        &mut f,
        "expiry: in the group, not an admin",
        dave,
        signed(
            dave,
            "set_expiry",
            json!({ "conversation_id": g_id, "seconds": 0 }),
        ),
    );
    c(
        &mut f,
        "self-destruct: bad",
        bob,
        signed(
            bob,
            "set_self_destruct",
            json!({ "conversation_id": dm_id, "hours": 2 }),
        ),
    );
    c(
        &mut f,
        "self-destruct: a day",
        bob,
        signed(
            bob,
            "set_self_destruct",
            json!({ "conversation_id": dm_id, "hours": 24 }),
        ),
    );
    c(
        &mut f,
        "self-destruct: off",
        bob,
        signed(
            bob,
            "set_self_destruct",
            json!({ "conversation_id": dm_id, "hours": 0 }),
        ),
    );

    // ----- deleting messages -----
    let listed = m(
        &mut f,
        "list again",
        bob,
        json!({ "action": "list", "conversation_id": dm_id }),
    );
    let first_id = listed["messages"][0]["id"].clone();
    m(
        &mut f,
        "delete: someone else's",
        carol,
        signed(carol, "delete", json!({ "message_id": first_id })),
    );
    m(
        &mut f,
        "delete",
        bob,
        signed(bob, "delete", json!({ "message_id": first_id })),
    );
    m(
        &mut f,
        "delete again",
        bob,
        signed(bob, "delete", json!({ "message_id": first_id })),
    );
    m(
        &mut f,
        "list: deleted shows",
        carol,
        json!({ "action": "list", "conversation_id": dm_id }),
    );

    // ----- messages that wait -----
    let later = |who: &Who, item: &str, extra: Value| {
        let mut b = msg(who, &dm_id, item, &dm_people, &iso_at(now()));
        b["action"] = json!("schedule");
        for (k, v) in extra.as_object().unwrap() {
            b[k] = v.clone();
        }
        b
    };
    m(
        &mut f,
        "schedule: too soon",
        bob,
        later(
            bob,
            &mid(40),
            json!({ "deliver_at": iso_at(now() + 10_000) }),
        ),
    );
    m(
        &mut f,
        "schedule: too far",
        bob,
        later(
            bob,
            &mid(40),
            json!({ "deliver_at": iso_at(now() + 400 * 86_400_000) }),
        ),
    );
    let s = m(
        &mut f,
        "schedule",
        bob,
        later(
            bob,
            &mid(40),
            json!({ "deliver_at": iso_at(now() + 30 * 86_400_000) }),
        ),
    );
    let s2 = m(
        &mut f,
        "schedule: in two hours",
        bob,
        later(
            bob,
            &mid(41),
            json!({ "deliver_at": iso_at(now() + 7_200_000) }),
        ),
    );
    m(
        &mut f,
        "schedule: check-in, bad interval",
        bob,
        later(
            bob,
            &mid(42),
            json!({ "kind": "checkin", "checkin_hours": 3 }),
        ),
    );
    let ci = m(
        &mut f,
        "schedule: check-in",
        bob,
        later(
            bob,
            &mid(42),
            json!({ "kind": "checkin", "checkin_hours": 1 }),
        ),
    );
    m(&mut f, "scheduled", bob, json!({ "action": "scheduled" }));
    m(
        &mut f,
        "scheduled: one conversation",
        bob,
        json!({ "action": "scheduled", "conversation_id": g_id }),
    );
    m(
        &mut f,
        "send a waiting one early",
        bob,
        msg(bob, &dm_id, &mid(41), &dm_people, &iso_at(now())),
    );
    m(
        &mut f,
        "check in: not a check-in",
        bob,
        signed(bob, "check_in", json!({ "id": s2["scheduled"]["id"] })),
    );
    m(
        &mut f,
        "check in",
        bob,
        signed(bob, "check_in", json!({ "id": ci["scheduled"]["id"] })),
    );
    m(
        &mut f,
        "check in: someone else's",
        carol,
        signed(carol, "check_in", json!({ "id": ci["scheduled"]["id"] })),
    );
    m(
        &mut f,
        "cancel",
        bob,
        signed(
            bob,
            "cancel_scheduled",
            json!({ "id": s["scheduled"]["id"] }),
        ),
    );
    m(
        &mut f,
        "cancel again",
        bob,
        signed(
            bob,
            "cancel_scheduled",
            json!({ "id": s["scheduled"]["id"] }),
        ),
    );
    m(
        &mut f,
        "deliver mine: nothing due",
        bob,
        json!({ "action": "deliver_mine" }),
    );
    f.call(
        "profile",
        "privacy report counts them",
        &bob.token,
        json!({ "action": "privacy_report" }),
    );

    // ----- group membership -----
    c(
        &mut f,
        "set admin: not one",
        carol,
        signed(
            carol,
            "set_admin",
            json!({ "conversation_id": g_id, "user_id": dave.id, "admin": true }),
        ),
    );
    c(
        &mut f,
        "set admin: not a yes or no",
        bob,
        signed(
            bob,
            "set_admin",
            json!({ "conversation_id": g_id, "user_id": carol.id, "admin": "yes" }),
        ),
    );
    c(
        &mut f,
        "set admin",
        bob,
        signed(
            bob,
            "set_admin",
            json!({ "conversation_id": g_id, "user_id": carol.id, "admin": true }),
        ),
    );
    c(
        &mut f,
        "remove: self",
        carol,
        signed(
            carol,
            "remove_member",
            json!({ "conversation_id": g_id, "user_id": carol.id }),
        ),
    );
    c(
        &mut f,
        "remove: not in it",
        carol,
        signed(
            carol,
            "remove_member",
            json!({ "conversation_id": g_id, "user_id": erin.id }),
        ),
    );
    c(
        &mut f,
        "remove dave",
        carol,
        signed(
            carol,
            "remove_member",
            json!({ "conversation_id": g_id, "user_id": dave.id }),
        ),
    );
    m(
        &mut f,
        "dave can't read now",
        dave,
        json!({ "action": "list", "conversation_id": g_id }),
    );
    c(
        &mut f,
        "add: a direct message",
        bob,
        signed(
            bob,
            "add_members",
            json!({ "conversation_id": dm_id, "usernames": ["dave"] }),
        ),
    );
    c(
        &mut f,
        "add dave back",
        bob,
        signed(
            bob,
            "add_members",
            json!({ "conversation_id": g_id, "usernames": ["dave", "carol"] }),
        ),
    );
    c(
        &mut f,
        "drop an admin",
        carol,
        signed(
            carol,
            "set_admin",
            json!({ "conversation_id": g_id, "user_id": bob.id, "admin": false }),
        ),
    );
    c(
        &mut f,
        "last admin can't step down",
        carol,
        signed(
            carol,
            "set_admin",
            json!({ "conversation_id": g_id, "user_id": carol.id, "admin": false }),
        ),
    );
    c(
        &mut f,
        "leave: a direct message",
        bob,
        signed(bob, "leave", json!({ "conversation_id": dm_id })),
    );
    c(
        &mut f,
        "bob leaves (he set the name)",
        bob,
        signed(bob, "leave", json!({ "conversation_id": g_id })),
    );
    c(
        &mut f,
        "the name went with him",
        carol,
        json!({ "action": "get", "conversation_id": g_id }),
    );
    c(
        &mut f,
        "carol leaves (dave takes over)",
        carol,
        signed(carol, "leave", json!({ "conversation_id": g_id })),
    );
    c(
        &mut f,
        "dave is in charge",
        dave,
        json!({ "action": "get", "conversation_id": g_id }),
    );
    c(
        &mut f,
        "dave leaves last",
        dave,
        signed(dave, "leave", json!({ "conversation_id": g_id })),
    );
    c(
        &mut f,
        "the group is gone",
        dave,
        json!({ "action": "get", "conversation_id": g_id }),
    );

    // ----- push subscriptions (none left subscribed, so nothing is sent anywhere) -----
    let n = |f: &mut Flow, step: &str, who: &Who, body: Value| {
        f.call("notifications", step, &who.token, body)
    };
    n(&mut f, "push key", bob, json!({ "action": "key" }));
    n(
        &mut f,
        "subscribe: not a push service",
        bob,
        json!({ "action": "subscribe", "endpoint": "https://evil.example/x", "p256dh": "a", "auth": "b", "mute_secret": "c" }),
    );
    n(
        &mut f,
        "subscribe: missing keys",
        bob,
        json!({ "action": "subscribe", "endpoint": "https://fcm.googleapis.com/fcm/send/abc", "p256dh": "a" }),
    );
    n(
        &mut f,
        "subscribe",
        bob,
        json!({ "action": "subscribe", "endpoint": "https://fcm.googleapis.com/fcm/send/abc", "p256dh": "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4", "auth": "BTBZMqHH6r4Tts7J_aSIgg", "mute_secret": "c2VjcmV0" }),
    );
    let endpoint = "https://fcm.googleapis.com/fcm/send/abc";
    n(
        &mut f,
        "alerts: not a list",
        bob,
        json!({ "action": "alerts", "endpoint": endpoint, "all": "everything", "mentions": [] }),
    );
    n(
        &mut f,
        "alerts: not a server id",
        bob,
        json!({ "action": "alerts", "endpoint": endpoint, "all": ["no such thing!"], "mentions": [] }),
    );
    let many: Vec<String> = (0..201).map(|i| format!("server{i}")).collect();
    n(
        &mut f,
        "alerts: too many servers",
        bob,
        json!({ "action": "alerts", "endpoint": endpoint, "all": many, "mentions": [] }),
    );
    n(
        &mut f,
        "alerts: someone else's browser",
        carol,
        json!({ "action": "alerts", "endpoint": endpoint, "all": [], "mentions": [] }),
    );
    n(
        &mut f,
        "alerts: not a push address",
        bob,
        json!({ "action": "alerts", "endpoint": "https://evil.example/x", "all": [], "mentions": [] }),
    );
    n(
        &mut f,
        "alerts",
        bob,
        json!({ "action": "alerts", "endpoint": endpoint, "all": ["server1", "server1"], "mentions": ["server2", "server1"] }),
    );
    n(
        &mut f,
        "subscribe again: the same browser",
        bob,
        json!({ "action": "subscribe", "endpoint": endpoint, "p256dh": "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4", "auth": "BTBZMqHH6r4Tts7J_aSIgg", "mute_secret": "c2VjcmV0" }),
    );
    n(
        &mut f,
        "alerts: still registered",
        bob,
        json!({ "action": "alerts", "endpoint": endpoint, "all": [], "mentions": ["server2"] }),
    );
    n(
        &mut f,
        "unsubscribe",
        bob,
        json!({ "action": "unsubscribe" }),
    );
    n(
        &mut f,
        "alerts: after unsubscribing",
        bob,
        json!({ "action": "alerts", "endpoint": endpoint, "all": [], "mentions": [] }),
    );
    n(
        &mut f,
        "open: bad code",
        bob,
        json!({ "action": "open", "code": "a b" }),
    );
    n(
        &mut f,
        "open: unknown code",
        bob,
        json!({ "action": "open", "code": "abc" }),
    );
    n(&mut f, "test", bob, json!({ "action": "test" }));
    f.log
}

#[test]
fn conversations_and_messages_answer_as_the_node_server_does() {
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
    assert!(ok > 45, "only {ok} steps succeeded");
    succeeded(
        &a,
        &[
            "dm",
            "group",
            "title",
            "send",
            "send: retried",
            "send: queued an hour ago",
            "send to the group",
            "poll",
            "expiry: a day",
            "send: disappearing",
            "delete",
            "schedule",
            "schedule: check-in",
            "check in",
            "cancel",
            "set admin",
            "remove dave",
            "add dave back",
            "dave leaves last",
            "subscribe",
            "alerts",
            "subscribe again: the same browser",
            "alerts: still registered",
            "push key",
        ],
    );
}
