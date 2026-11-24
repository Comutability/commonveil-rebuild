//! Transport HTTP tests. A standard Commonveil install keeps every new
//! CVP-019 reference endpoint absent; an isolated opt-in test site can
//! use independent actor credentials without Commonveil login.
mod common;
use common::{post, start_with};
use secure_net_core::social::{
    client::SocialClient,
    site::{MemoryNetwork, ReferenceSite},
};
use serde_json::json;
use tempfile::tempdir;

const ADMIN: &str = "test-only-admin-credential-0123456789";
const NOW: i64 = 1_800_000_000_000;
fn actor() -> SocialClient {
    let mut net = MemoryNetwork::new();
    net.add(ReferenceSite::new("cv.example").unwrap());
    let mut c = SocialClient::new("anotherapp@cv.example", "Person", None, 2, true, NOW).unwrap();
    c.register(&mut net).unwrap();
    c
}
#[test]
fn normal_sites_have_no_generic_relay_endpoints_or_side_effects() {
    let dir = tempdir().unwrap();
    let server = start_with(false, dir.path(), &[]);
    for (method, path) in [
        ("GET", "/cvp/v2/relay/site"),
        ("POST", "/cvp/v2/relay/admin/actors"),
        ("POST", "/cvp/v2/outbox"),
        ("GET", "/cvp/v2/mailbox?device=fake"),
        ("POST", "/cvp/v2/deliver"),
        ("POST", "/cvp/v2/outbox/flush"),
    ] {
        let (status, body) = post(server.1, method, path, ADMIN, "{}");
        assert_eq!(status, 404, "{path} {body}");
    }
    assert!(!dir
        .path()
        .join("secure-net-relay-experimental.sqlite")
        .exists());
}

#[test]
fn independent_actor_uses_experimental_http_inbox_outbox_and_survives_restart() {
    let dir = tempdir().unwrap();
    let client = actor();
    let token = {
        let server = start_with(
            false,
            dir.path(),
            &[
                ("EXPERIMENTAL_SECURE_NET_RELAY", "true".to_string()),
                ("SECURE_NET_RELAY_ADMIN", ADMIN.to_string()),
            ],
        );
        let (code, site) = post(server.1, "GET", "/cvp/v2/relay/site", "", "");
        assert_eq!(code, 200, "{site}");
        assert_eq!(site["protocol"], "secure-net");
        assert_eq!(site["profile"], "experimental-direct-only");
        assert_eq!(site["production_conformance"], false);
        assert_eq!(site["features_advertised"], json!([]));
        let (code, denied) = post(server.1, "POST", "/cvp/v2/relay/admin/actors", "bad", "{}");
        assert_eq!(code, 401, "{denied}");
        let (code, created) = post(
            server.1,
            "POST",
            "/cvp/v2/relay/admin/actors",
            ADMIN,
            &json!({"document":client.actor_record}).to_string(),
        );
        assert_eq!(code, 200, "{created}");
        assert_eq!(created["actor"], client.id);
        assert_eq!(created["commonveil_account_required"], false);
        let auth = created["credential"].as_str().unwrap().to_owned();
        let env = json!({"v":2,"mode":"direct","device":client.device.kid,
        "message":{"v":2,"h":"someHeader","c":"opaqueCiphertext"}});
        let data = json!({"items":[{"host":"cv.example","to":client.id,"envelope":env}]});
        let (code, denied) = post(
            server.1,
            "POST",
            "/cvp/v2/outbox",
            "untrusted",
            &data.to_string(),
        );
        assert_eq!(code, 401, "{denied}");
        let (code, stored) = post(server.1, "POST", "/cvp/v2/outbox", &auth, &data.to_string());
        assert_eq!(code, 200, "{stored}");
        assert_eq!(stored["local_stored"], 1);
        let (code, received) = post(
            server.1,
            "GET",
            &format!("/cvp/v2/mailbox?device={}", client.device.kid),
            &auth,
            "",
        );
        assert_eq!(code, 200, "{received}");
        assert_eq!(received["items"].as_array().unwrap().len(), 1);
        assert_eq!(received["items"][0]["envelope"], env);
        auth
    };
    let server = start_with(
        false,
        dir.path(),
        &[
            ("EXPERIMENTAL_SECURE_NET_RELAY", "true".to_string()),
            ("SECURE_NET_RELAY_ADMIN", ADMIN.to_string()),
        ],
    );
    let (code, received) = post(
        server.1,
        "GET",
        &format!("/cvp/v2/mailbox?device={}", client.device.kid),
        &token,
        "",
    );
    assert_eq!(code, 200, "{received}");
    let id = received["items"][0]["id"].as_str().unwrap();
    let (code, ack) = post(
        server.1,
        "POST",
        "/cvp/v2/mailbox/ack",
        &token,
        &json!({"device":client.device.kid,"ids":[id]}).to_string(),
    );
    assert_eq!(code, 200, "{ack}");
    assert_eq!(ack["acknowledged"], 1);
    let (code, after) = post(
        server.1,
        "GET",
        &format!("/cvp/v2/mailbox?device={}", client.device.kid),
        &token,
        "",
    );
    assert_eq!(code, 200);
    assert_eq!(after["items"].as_array().unwrap().len(), 0);
}
