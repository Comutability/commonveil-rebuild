use commonveil_server::secure_net_relay::Relay;
use secure_net_core::bytes::{b64u, random_b64u};
use secure_net_core::social::client::SocialClient;
use secure_net_core::social::site::{MemoryNetwork, ReferenceSite};
use secure_net_core::wire::{
    federation::{self as wire, RequestFields},
    sealed,
};
use serde_json::{json, Value};
use tempfile::tempdir;

const NOW: i64 = 1_800_000_000_000;
const ADMIN: &str = "test-only-admin-credential-0123456789";
fn actor(host: &str) -> SocialClient {
    let mut net = MemoryNetwork::new();
    net.add(ReferenceSite::new(host).unwrap());
    let mut client =
        SocialClient::new(&format!("alice@{host}"), "Person", None, 2, true, NOW).unwrap();
    client.register(&mut net).unwrap();
    client
}
fn enrol(relay: &mut Relay, actor: &SocialClient) -> String {
    relay
        .register_actor(ADMIN, ADMIN, &json!({"document":actor.actor_record}))
        .unwrap()["credential"]
        .as_str()
        .unwrap()
        .to_string()
}
fn sealed_direct(device: &str) -> Value {
    json!({"v":2,"mode":"direct","device":device,
       "message":{"v":2,"h":"aabbcc","c":"ABCD1234"}})
}
fn status<T>(result: Result<T, commonveil_server::secure_net_relay::RelayError>) -> u16 {
    result.err().unwrap().status
}

#[test]
fn private_site_local_inbox_outbox_credentials_are_independent_of_commonveil_accounts() {
    let dir = tempdir().unwrap();
    let alice = actor("relay.example");
    let mut db = Relay::open(dir.path(), "relay.example").unwrap();
    assert_eq!(
        status(db.register_actor(
            "not-authorised",
            ADMIN,
            &json!({"document":alice.actor_record})
        )),
        401
    );
    let token = enrol(&mut db, &alice);
    let local = json!({"items":[{"host":"relay.example","to":alice.id,
        "envelope":sealed_direct(&alice.device.kid)}]});
    assert_eq!(status(db.outbox("wrong credential", &local, NOW)), 401);
    let sent = db.outbox(&token, &local, NOW).unwrap();
    assert_eq!(sent["local_stored"], 1);
    assert_eq!(sent["remote_queued"], 0);
    let bad_device = random_b64u(16);
    assert_eq!(status(db.mailbox(&token, &bad_device, NOW)), 403);
    assert_eq!(
        status(db.mailbox("not the account", &alice.device.kid, NOW)),
        401
    );
    let result = db.mailbox(&token, &alice.device.kid, NOW).unwrap();
    assert_eq!(result["items"].as_array().unwrap().len(), 1);
    let id = result["items"][0]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        result["items"][0]["envelope"],
        sealed_direct(&alice.device.kid)
    );
    assert_eq!(result["items"][0]["from"], "relay.example");
    drop(db);
    // A server restart does not lose the independent encrypted mailbox.
    let mut db = Relay::open(dir.path(), "relay.example").unwrap();
    assert_eq!(
        db.mailbox(&token, &alice.device.kid, NOW).unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        status(db.acknowledge("wrong", &json!({"device":alice.device.kid,"ids":[id]}))),
        401
    );
    assert_eq!(
        db.acknowledge(&token, &json!({"device":alice.device.kid,"ids":[id]}))
            .unwrap()["acknowledged"],
        1
    );
    assert_eq!(
        db.mailbox(&token, &alice.device.kid, NOW).unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn untrusted_sites_are_refused_and_malformed_messages_never_enter_any_mailbox() {
    let dir = tempdir().unwrap();
    let alice = actor("relay.example");
    let mut db = Relay::open(dir.path(), "relay.example").unwrap();
    let token = enrol(&mut db, &alice);
    let remote = json!({"items":[{"host":"peer.example","to":alice.id,
       "envelope":sealed_direct(&alice.device.kid)}]});
    assert_eq!(status(db.outbox(&token, &remote, NOW)), 403);
    let malformed = json!({"items":[{"host":"relay.example","to":alice.id,
       "envelope":{"v":2,"mode":"direct","device":alice.device.kid,
       "message":{"v":2,"h":"abc","c":"def"},"plaintext":"hello"}}]});
    assert_eq!(status(db.outbox(&token, &malformed, NOW)), 400);
    assert_eq!(
        db.mailbox(&token, &alice.device.kid, NOW).unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(status(db.outbox(&token, &json!({"items":[]}), NOW)), 400);
}

#[test]
fn encrypted_site_delivery_authenticates_both_signatures_seals_and_consumes_nonces_durably() {
    let a = tempdir().unwrap();
    let b = tempdir().unwrap();
    let mut source = Relay::open(a.path(), "sender.example").unwrap();
    let mut dest = Relay::open(b.path(), "recipient.example").unwrap();
    let recipient = actor("recipient.example");
    let dest_token = enrol(&mut dest, &recipient);
    let sender = actor("sender.example");
    let sender_token = enrol(&mut source, &sender);
    let seed = [7_u8; 32];
    let ed_public = b64u(
        &ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes(),
    );
    let secret = b64u(&seed);
    let src_pq = sealed::generate_keys().unwrap();
    let dst_pq = sealed::generate_keys().unwrap();
    let dst_key = b64u(
        &ed25519_dalek::SigningKey::from_bytes(&[8u8; 32])
            .verifying_key()
            .to_bytes(),
    );
    source
        .trust_site(
            ADMIN,
            ADMIN,
            &json!({"host":"recipient.example","key":dst_key,
      "pq":{"suite":sealed::SUITE,"kem":dst_pq["kem"]["public"],"sig":dst_pq["sig"]["public"]}}),
        )
        .unwrap();
    dest.trust_site(
        ADMIN,
        ADMIN,
        &json!({"host":"sender.example","key":ed_public,
      "pq":{"suite":sealed::SUITE,"kem":src_pq["kem"]["public"],"sig":src_pq["sig"]["public"]}}),
    )
    .unwrap();
    let envelope = sealed_direct(&recipient.device.kid);
    let queued = source
        .outbox(
            &sender_token,
            &json!({"items":[{"host":"recipient.example",
       "to":recipient.id,"envelope":envelope}]}),
            NOW,
        )
        .unwrap();
    assert_eq!(queued["remote_queued"], 1);
    assert_eq!(source.pending(ADMIN, ADMIN, NOW).unwrap().len(), 1);
    let body = json!({"v":1,"items":[{"to":recipient.id,"envelope":envelope}]}).to_string();
    let context = sealed::relay_context("sender.example", "recipient.example", "/cvp/v2/deliver");
    let (sealed_text, reply_key) =
        sealed::seal(dst_pq["kem"]["public"].as_str().unwrap(), &body, &context).unwrap();
    let raw = json!({"sealed":sealed_text}).to_string();
    let date = secure_net_core::cv::encoding::iso_from_ms(NOW).unwrap();
    let nonce = random_b64u(18);
    let digest = wire::digest_of(raw.as_bytes());
    let fields = RequestFields {
        method: "POST",
        to: "recipient.example",
        path: "/cvp/v2/deliver",
        from: "sender.example",
        date: &date,
        nonce: &nonce,
        digest: &digest,
        user: "",
    };
    let transcript = wire::signature_base(&fields);
    let ed_sig = wire::sign_request(&fields, &secret).unwrap();
    let pq_sig = sealed::sign(src_pq["sig"]["secret"].as_str().unwrap(), &transcript).unwrap();
    let mut headers = std::collections::HashMap::new();
    for (k, v) in [
        ("cv-from", "sender.example"),
        ("cv-date", &date),
        ("cv-nonce", &nonce),
        ("cv-digest", &digest),
        ("cv-signature", &ed_sig),
        ("cv-pq-signature", &pq_sig),
        ("cv-sealed", "1"),
    ] {
        headers.insert(k.to_string(), v.to_string());
    }
    let response = dest
        .deliver(
            &headers,
            raw.as_bytes(),
            NOW,
            dst_pq["kem"]["secret"].as_str().unwrap(),
        )
        .unwrap();
    let receipt =
        sealed::open_reply(&reply_key, response["sealed"].as_str().unwrap(), &context).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&receipt).unwrap()["stored"],
        1
    );
    assert_eq!(
        dest.mailbox(&dest_token, &recipient.device.kid, NOW)
            .unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        status(dest.deliver(
            &headers,
            raw.as_bytes(),
            NOW,
            dst_pq["kem"]["secret"].as_str().unwrap()
        )),
        409
    );
    drop(dest);
    let mut dest = Relay::open(b.path(), "recipient.example").unwrap();
    assert_eq!(
        status(dest.deliver(
            &headers,
            raw.as_bytes(),
            NOW,
            dst_pq["kem"]["secret"].as_str().unwrap()
        )),
        409
    );
    let mut damaged = raw.as_bytes().to_vec();
    damaged[7] ^= 1;
    assert_eq!(
        status(dest.deliver(
            &headers,
            &damaged,
            NOW,
            dst_pq["kem"]["secret"].as_str().unwrap()
        )),
        401
    );
    let mut no_pq = headers.clone();
    no_pq.remove("cv-pq-signature");
    assert_eq!(
        status(dest.deliver(
            &no_pq,
            raw.as_bytes(),
            NOW,
            dst_pq["kem"]["secret"].as_str().unwrap()
        )),
        401
    );
    let mut no_seal = headers.clone();
    no_seal.remove("cv-sealed");
    assert_eq!(
        status(dest.deliver(
            &no_seal,
            raw.as_bytes(),
            NOW,
            dst_pq["kem"]["secret"].as_str().unwrap()
        )),
        401
    );
    // No second mailbox item was inserted by tampering or replay.
    assert_eq!(
        dest.mailbox(&dest_token, &recipient.device.kid, NOW)
            .unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn signed_public_prekeys_are_verified_then_one_time_keys_are_consumed_across_restarts() {
    use secure_net_core::session::keys::verify_bundle;
    let dir = tempdir().unwrap();
    let mut net = MemoryNetwork::new();
    net.add(ReferenceSite::new("relay.example").unwrap());
    let mut c = SocialClient::new("owner@relay.example", "Person", None, 2, true, NOW).unwrap();
    c.register(&mut net).unwrap();
    let pubkeys = net
        .site("relay.example")
        .unwrap()
        .prekeys
        .get(&format!("{}/{}", c.id, c.device.kid))
        .unwrap()
        .clone();
    let mut relay = Relay::open(dir.path(), "relay.example").unwrap();
    let token = enrol(&mut relay, &c);
    let actor = relay.public_actor(&c.id).unwrap();
    assert_eq!(actor["body"]["id"], c.id);
    assert_eq!(
        status(relay.take_prekey_bundle(&c.id, &c.device.kid, NOW)),
        404
    );
    let added = relay
        .publish_prekeys(
            &token,
            &json!({
                "device":c.device.kid,"published":pubkeys
            }),
            NOW,
        )
        .unwrap();
    assert_eq!(added["published"], true);
    assert_eq!(added["private_keys_stored"], false);
    assert_eq!(
        status(relay.publish_prekeys(
            &token,
            &json!({
                "device":c.device.kid,"published":pubkeys
            }),
            NOW
        )),
        409
    );
    let first = relay.take_prekey_bundle(&c.id, &c.device.kid, NOW).unwrap();
    assert!(first["oneTime"].is_object());
    verify_bundle(&first, &c.account.public_key, 0, NOW).unwrap();
    drop(relay);
    let mut restarted = Relay::open(dir.path(), "relay.example").unwrap();
    let second = restarted
        .take_prekey_bundle(&c.id, &c.device.kid, NOW)
        .unwrap();
    assert_ne!(
        first["oneTime"]["body"]["id"],
        second["oneTime"]["body"]["id"]
    );
    assert_ne!(first["pq"]["body"]["id"], second["pq"]["body"]["id"]);
    verify_bundle(&second, &c.account.public_key, 0, NOW).unwrap();
}
