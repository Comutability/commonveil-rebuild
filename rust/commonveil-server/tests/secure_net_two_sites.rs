mod common;
use common::{post, Server};
use secure_net_core::social::{
    client::SocialClient,
    site::{MemoryNetwork, ReferenceSite},
};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::tempdir;

const ADMIN: &str = "temporary-operator-test-secret-0123456789";
fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn launch(dir: &Path, port: u16) -> Server {
    let mut command = Command::new(env!("CARGO_BIN_EXE_commonveil-server"));
    command
        .env("PORT", port.to_string())
        .env("BIND", "127.0.0.1")
        .env("SITE_URL", format!("http://127.0.0.1:{port}"))
        .env("DATA_DIR", dir)
        .env("DIST_DIR", common::repo().join("dist-selfhost"))
        .env("ENTITIES_DIR", common::repo().join("base44/entities"))
        .env("FEDERATION", "off")
        .env("FEDERATION_ALLOW_PRIVATE", "true")
        .env("EXPERIMENTAL_SECURE_NET_RELAY", "true")
        .env("SECURE_NET_RELAY_ADMIN", ADMIN)
        .env("UPDATE_CHECK_HOURS", "1000")
        .env("PASSWORD_ROUNDS", "1000")
        .env("COMMONVEIL_VERSION", "9.9.9")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let server = Server(command.spawn().unwrap(), port);
    for _ in 0..110 {
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return server;
            }
        }
        std::thread::sleep(Duration::from_millis(80));
    }
    panic!("server not ready");
}
fn client_for(host: &str) -> SocialClient {
    let mut net = MemoryNetwork::new();
    net.add(ReferenceSite::new(host).unwrap());
    let mut client = SocialClient::new(
        &format!("person@{host}"),
        "Person",
        None,
        2,
        true,
        1_800_000_000_000,
    )
    .unwrap();
    client.register(&mut net).unwrap();
    client
}
fn check(code: u16, reply: &Value, expect: u16) {
    assert_eq!(code, expect, "{reply}");
}

#[test]
fn two_independent_rust_sites_exchange_ciphertext_with_pinned_signed_sealed_transport() {
    let src = tempdir().unwrap();
    let dst = tempdir().unwrap();
    let p1 = port();
    let p2 = port();
    assert_ne!(p1, p2);
    let _source = launch(src.path(), p1);
    let _dest = launch(dst.path(), p2);
    let a = format!("127.0.0.1:{p1}");
    let b = format!("127.0.0.1:{p2}");
    let sender = client_for(&a);
    let recipient = client_for(&b);
    let mut sites = Vec::new();
    for p in [p1, p2] {
        let (code, doc) = post(p, "GET", "/cvp/v2/relay/site", "", "");
        check(code, &doc, 200);
        assert_eq!(doc["production_conformance"], false);
        sites.push(doc);
    }
    for (from, other) in [(p1, &sites[1]), (p2, &sites[0])] {
        let body = json!({"host":other["site"],"key":other["key"]["public"],"pq":other["pq"]});
        let (code, response) = post(
            from,
            "POST",
            "/cvp/v2/relay/admin/trust",
            ADMIN,
            &body.to_string(),
        );
        check(code, &response, 200);
    }
    let mut credentials = Vec::new();
    for (p, client) in [(p1, &sender), (p2, &recipient)] {
        let (code, created) = post(
            p,
            "POST",
            "/cvp/v2/relay/admin/actors",
            ADMIN,
            &json!({"document":client.actor_record}).to_string(),
        );
        check(code, &created, 200);
        credentials.push(created["credential"].as_str().unwrap().to_owned());
    }
    // E2E ciphertext is opaque here. The Secure Net reference client suites
    // independently test real device-side encryption and decryption.
    let encrypted = json!({"v":2,"mode":"direct","device":recipient.device.kid,
        "message":{"v":2,"h":"dGhpcy1pcy1vbmx5LW1ldGFkYXRh",
                           "c":"YWVzLWdjbS1jaXBoZXJ0ZXh0"}});
    let (code, queued) = post(
        p1,
        "POST",
        "/cvp/v2/outbox",
        &credentials[0],
        &json!({"items":[{"host":b,"to":recipient.id,"envelope":encrypted}]}).to_string(),
    );
    check(code, &queued, 200);
    assert_eq!(queued["remote_queued"], 1);
    let (code, delivered) = post(p1, "POST", "/cvp/v2/outbox/flush", ADMIN, "{}");
    check(code, &delivered, 200);
    assert_eq!(delivered["delivered"], 1, "{delivered}");
    let (code, inbox) = post(
        p2,
        "GET",
        &format!("/cvp/v2/mailbox?device={}", recipient.device.kid),
        &credentials[1],
        "",
    );
    check(code, &inbox, 200);
    assert_eq!(inbox["items"].as_array().unwrap().len(), 1);
    assert_eq!(inbox["items"][0]["envelope"], encrypted);
    let (code, no_duplicate) = post(p1, "POST", "/cvp/v2/outbox/flush", ADMIN, "{}");
    check(code, &no_duplicate, 200);
    assert_eq!(no_duplicate["delivered"], 0);
    assert_eq!(inbox["items"][0]["from"], a);
    let id = inbox["items"][0]["id"].as_str().unwrap();
    let (code, ack) = post(
        p2,
        "POST",
        "/cvp/v2/mailbox/ack",
        &credentials[1],
        &json!({"device":recipient.device.kid,"ids":[id]}).to_string(),
    );
    check(code, &ack, 200);
    assert_eq!(ack["acknowledged"], 1);
}
