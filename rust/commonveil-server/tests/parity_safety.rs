//! Blocking, reporting, the staff tools and security reports over HTTP against the Node.js
//! server: the same script runs against both, each on its own fresh site (with one member whose
//! sign-in was removed outside the app), and every reply must match once random values are blanked.
use std::path::Path;

use commonveil_server::store::{load_schemas, Store};
use serde_json::{json, Value};

mod common;
use common::{compare, iso_at, now, ready, repo, sealed_item, start, succeeded, Flow, Kit};

const GHOST: &str = "ghostghost000000";

/// A member whose sign-in was removed outside the app: their profile and keys stay behind.
fn seed(data: &Path) {
    let s = Store::open(
        data.join("commonveil.db").to_str().unwrap(),
        load_schemas(&repo().join("base44/entities")),
    )
    .unwrap();
    s.create("Profile", &json!({ "user_id": GHOST, "username": "ghost", "username_key": "ghost", "display_name": "Ghost", "bio": "" }), None).unwrap();
    s.create(
        "AccountKey",
        &json!({ "user_id": GHOST, "version": 1, "sign_pub": "x" }),
        None,
    )
    .unwrap();
}

fn script(port: u16, data: &Path, kits: &[Kit]) -> Vec<Value> {
    let mut f = Flow::new(port);
    let setup = std::fs::read_to_string(data.join("setup-code"))
        .unwrap()
        .trim()
        .to_string();
    let mut who: Vec<(String, String)> = Vec::new();
    for (i, name) in ["alice", "bob", "carol"].iter().enumerate() {
        let mut reg = json!({ "action": "register", "username": name, "password": "a long enough password", "age_confirmed": true });
        if i == 0 {
            reg["setup_code"] = json!(setup);
        }
        let r = f.call("identity", &format!("register {name}"), "", reg);
        who.push((
            r["session"]["access_token"].as_str().unwrap_or("").into(),
            r["session"]["user_id"].as_str().unwrap_or("").into(),
        ));
    }
    let [(alice, _), (bob, bob_id), (carol, carol_id)] =
        [who[0].clone(), who[1].clone(), who[2].clone()];
    f.call("keys", "bob init", &bob, kits[1].init(&bob_id));
    f.call("keys", "carol init", &carol, kits[2].init(&carol_id));
    let dm = f.call(
        "conversations",
        "dm",
        &bob,
        kits[1].signed(&bob_id, "create_dm", 0, json!({ "username": "carol" })),
    );
    let dm_id = dm["conversation"]["id"].as_str().unwrap_or("").to_string();
    let recipients = [kits[1].recipient(&bob_id), kits[2].recipient(&carol_id)];
    let send = |n: u32| {
        let item = format!("msg-{n:04}-aaaaaaaaaaaa");
        let at = iso_at(now());
        let (env, sig) = sealed_item(
            "message",
            &dm_id,
            &item,
            (&bob_id, &kits[1]),
            &recipients,
            &at,
        );
        json!({ "action": "send", "conversation_id": dm_id, "device_id": kits[1].id(0), "msg_id": item, "sent_at": at, "envelope": env, "signature": sig })
    };
    let s = |f: &mut Flow, step: &str, t: &str, body: Value| f.call("safety", step, t, body);
    let a = |f: &mut Flow, step: &str, t: &str, body: Value| f.call("admin", step, t, body);

    // ----- blocking -----
    s(
        &mut f,
        "block: self",
        &bob,
        json!({ "action": "block", "user_id": bob_id }),
    );
    s(
        &mut f,
        "block: nobody",
        &bob,
        json!({ "action": "block", "user_id": "nobody" }),
    );
    s(
        &mut f,
        "block: bad id",
        &bob,
        json!({ "action": "block", "user_id": "a b" }),
    );
    s(
        &mut f,
        "carol blocks bob",
        &carol,
        json!({ "action": "block", "user_id": bob_id }),
    );
    s(
        &mut f,
        "block again",
        &carol,
        json!({ "action": "block", "user_id": bob_id }),
    );
    s(
        &mut f,
        "list blocks",
        &carol,
        json!({ "action": "list_blocks" }),
    );
    f.call("messages", "bob can't message carol", &bob, send(1));
    f.call(
        "profile",
        "bob can't find carol",
        &bob,
        json!({ "action": "find", "username": "carol" }),
    );
    f.call(
        "profile",
        "carol can't find bob",
        &carol,
        json!({ "action": "find", "username": "bob" }),
    );
    f.call(
        "conversations",
        "bob can't start another",
        &bob,
        kits[1].signed(
            &bob_id,
            "create_group",
            0,
            json!({ "usernames": ["carol"] }),
        ),
    );
    s(
        &mut f,
        "unblock",
        &carol,
        json!({ "action": "unblock", "user_id": bob_id }),
    );
    s(
        &mut f,
        "list blocks: none",
        &carol,
        json!({ "action": "list_blocks" }),
    );
    f.call("messages", "bob can message again", &bob, send(2));

    // ----- reports -----
    s(
        &mut f,
        "report: self",
        &bob,
        json!({ "action": "report", "user_id": bob_id, "reason": "spam" }),
    );
    s(
        &mut f,
        "report: nobody",
        &bob,
        json!({ "action": "report", "user_id": "nobody", "reason": "spam" }),
    );
    s(
        &mut f,
        "report: no reason",
        &bob,
        json!({ "action": "report", "user_id": carol_id }),
    );
    s(
        &mut f,
        "report: not a reason",
        &bob,
        json!({ "action": "report", "user_id": carol_id, "reason": "rude" }),
    );
    s(
        &mut f,
        "report: someone else's conversation",
        &alice,
        json!({ "action": "report", "user_id": carol_id, "reason": "spam", "conversation_id": dm_id }),
    );
    s(
        &mut f,
        "report: too long",
        &bob,
        json!({ "action": "report", "user_id": carol_id, "reason": "spam", "details": "x".repeat(2001) }),
    );
    s(
        &mut f,
        "report",
        &bob,
        json!({ "action": "report", "user_id": carol_id, "reason": "harassment", "conversation_id": dm_id, "details": " Said \u{202e}things " }),
    );
    s(
        &mut f,
        "report: no conversation",
        &carol,
        json!({ "action": "report", "user_id": bob_id, "reason": "under_16", "conversation_id": "" }),
    );
    s(
        &mut f,
        "my reports",
        &bob,
        json!({ "action": "my_reports" }),
    );

    // ----- staff -----
    a(
        &mut f,
        "not staff",
        &bob,
        json!({ "action": "list_reports" }),
    );
    a(
        &mut f,
        "reports",
        &alice,
        json!({ "action": "list_reports" }),
    );
    let open = a(
        &mut f,
        "reports: open",
        &alice,
        json!({ "action": "list_reports", "status": "open" }),
    );
    a(
        &mut f,
        "reports: unknown status means all",
        &alice,
        json!({ "action": "list_reports", "status": "x" }),
    );
    a(
        &mut f,
        "update report: none",
        &alice,
        json!({ "action": "update_report", "report_id": "nope" }),
    );
    a(
        &mut f,
        "update report",
        &alice,
        json!({ "action": "update_report", "report_id": open["reports"][0]["id"], "status": "resolved", "resolution_note": "Handled" }),
    );
    a(
        &mut f,
        "update report: bad status keeps it",
        &alice,
        json!({ "action": "update_report", "report_id": open["reports"][0]["id"], "status": "gone" }),
    );
    a(
        &mut f,
        "reports: resolved",
        &alice,
        json!({ "action": "list_reports", "status": "resolved" }),
    );

    // ----- security reports -----
    let d = |f: &mut Flow, step: &str, t: &str, body: Value| f.call("disclose", step, t, body);
    let good = json!({ "action": "submit", "summary": "Something is wrong", "details": "When I do this, that happens, every time.", "contact": "me at example" });
    d(
        &mut f,
        "disclose: short title",
        "",
        json!({ "action": "submit", "summary": "Bad", "details": "x".repeat(30) }),
    );
    d(
        &mut f,
        "disclose: short details",
        "",
        json!({ "action": "submit", "summary": "Long enough", "details": "too short" }),
    );
    d(
        &mut f,
        "disclose: text not a string",
        "",
        json!({ "action": "submit", "summary": 5 }),
    );
    for i in 0..11 {
        d(
            &mut f,
            &format!("disclose anonymously {i}"),
            "",
            good.clone(),
        );
    }
    for i in 0..6 {
        d(&mut f, &format!("disclose as bob {i}"), &bob, good.clone());
    }
    let sec = a(
        &mut f,
        "security reports",
        &alice,
        json!({ "action": "list_security_reports" }),
    );
    a(
        &mut f,
        "security reports: new",
        &alice,
        json!({ "action": "list_security_reports", "status": "new" }),
    );
    a(
        &mut f,
        "update security report",
        &alice,
        json!({ "action": "update_security_report", "report_id": sec["reports"][0]["id"], "status": "triaged", "staff_note": "Looking" }),
    );
    a(
        &mut f,
        "update security report: none",
        &alice,
        json!({ "action": "update_security_report", "report_id": "nope" }),
    );
    a(
        &mut f,
        "security reports: triaged",
        &alice,
        json!({ "action": "list_security_reports", "status": "triaged" }),
    );

    // ----- site content -----
    a(
        &mut f,
        "content: not content",
        &alice,
        json!({ "action": "content_list", "type": "Profile" }),
    );
    a(
        &mut f,
        "content: none",
        &alice,
        json!({ "action": "content_list", "type": "Resource" }),
    );
    a(
        &mut f,
        "content: nothing to save",
        &alice,
        json!({ "action": "content_save", "type": "Resource", "data": [] }),
    );
    let item = a(
        &mut f,
        "content: add",
        &alice,
        json!({ "action": "content_save", "type": "Resource", "data": { "name": "Tool", "website": "https://x.example", "status": "published", "secret": "dropped" } }),
    );
    a(
        &mut f,
        "content: edit",
        &alice,
        json!({ "action": "content_save", "type": "Resource", "id": item["item"]["id"], "data": { "description": "Good" } }),
    );
    a(
        &mut f,
        "content: edit a missing one",
        &alice,
        json!({ "action": "content_save", "type": "Resource", "id": "missing0000", "data": { "name": "x" } }),
    );
    a(
        &mut f,
        "content: list",
        &alice,
        json!({ "action": "content_list", "type": "Resource" }),
    );
    a(
        &mut f,
        "content: delete",
        &alice,
        json!({ "action": "content_delete", "type": "Resource", "id": item["item"]["id"] }),
    );
    a(
        &mut f,
        "content: delete a missing one",
        &alice,
        json!({ "action": "content_delete", "type": "Resource", "id": "missing0000" }),
    );
    a(
        &mut f,
        "content: as a member",
        &bob,
        json!({ "action": "content_list", "type": "Resource" }),
    );

    // ----- what removed sign-ins left behind -----
    a(
        &mut f,
        "removed accounts",
        &alice,
        json!({ "action": "list_removed_accounts" }),
    );
    a(
        &mut f,
        "erase: not confirmed",
        &alice,
        json!({ "action": "erase_removed_account", "user_id": GHOST }),
    );
    a(
        &mut f,
        "erase: still signs in",
        &alice,
        json!({ "action": "erase_removed_account", "user_id": bob_id, "confirm": "ERASE" }),
    );
    a(
        &mut f,
        "erase",
        &alice,
        json!({ "action": "erase_removed_account", "user_id": GHOST, "confirm": "ERASE" }),
    );
    a(
        &mut f,
        "removed accounts: none",
        &alice,
        json!({ "action": "list_removed_accounts" }),
    );
    f.call("identity", "the name is retired", "", json!({ "action": "register", "username": "ghost", "password": "a long enough password", "age_confirmed": true }));
    f.log
}

#[test]
fn safety_and_staff_tools_answer_as_the_node_server_does() {
    if !ready() {
        eprintln!("skipped: node, the npm packages or dist-selfhost aren't there");
        return;
    }
    let kits: Vec<Kit> = (0..3).map(|_| Kit::new()).collect();
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    seed(d1.path());
    seed(d2.path());
    let (node, rust) = (start(true, d1.path()), start(false, d2.path()));
    let (x, y) = (
        script(node.1, d1.path(), &kits),
        script(rust.1, d2.path(), &kits),
    );
    let ok = compare(&x, &y);
    assert!(ok > 30, "only {ok} steps succeeded");
    succeeded(
        &x,
        &[
            "carol blocks bob",
            "unblock",
            "bob can message again",
            "report",
            "update report",
            "disclose anonymously 0",
            "disclose as bob 4",
            "update security report",
            "content: add",
            "content: delete",
            "erase",
        ],
    );
    for (step, code) in [
        ("bob can't message carol", 403),
        ("disclose anonymously 10", 429),
        ("disclose as bob 5", 429),
        ("erase: still signs in", 409),
    ] {
        assert_eq!(
            x.iter().find(|s| s["step"] == step).unwrap()["status"],
            code,
            "control {step}"
        );
    }
}
