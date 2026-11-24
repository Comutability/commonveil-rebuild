//! HTTP tests of the experimental destination. The public deployment and all ordinary
//! self-hosted sites keep these routes disabled by default.
mod common;

use common::{post, start_with};
use secure_net_core::bytes::{random_b64u, sha256_b64u};
use secure_net_core::canonical::canonical_bytes;
use secure_net_core::signed::{sign, SigningKey};
use serde_json::{json, Value};
use tempfile::tempdir;

fn manifest(parts: &[&str]) -> (Vec<Value>, String, usize) {
    let chunks: Vec<Value> = parts
        .iter()
        .enumerate()
        .map(
            |(i, part)| json!({ "i":i, "sha256":sha256_b64u(part.as_bytes()), "bytes":part.len() }),
        )
        .collect();
    let total = parts.iter().map(|p| p.len()).sum();
    let root = sha256_b64u(&canonical_bytes(&json!({"v":1,"chunks":chunks})).unwrap());
    (chunks, root, total)
}
fn prepare(port: u16, owner: &SigningKey, parts: &[&str], seq: u64) -> Value {
    let path = "/cvp/v2/experimental-transfer";
    let (st, issued) = post(
        port,
        "POST",
        &format!("{path}/challenge"),
        "",
        &json!({ "owner_public":owner.public_key }).to_string(),
    );
    assert_eq!(st, 200, "challenge: {issued}");
    assert_eq!(issued["destination"], "cv.example");
    let nonce = issued["challenge"].as_str().unwrap();
    let (manifest, root, bytes) = manifest(parts);
    let now = commonveil_server::sessions::now_ms();
    let record = sign(
        "transfer.intent",
        &json!({
            "v":1, "actor":owner.kid, "from":"old.example", "to":"cv.example",
            "seq":seq,"challenge":nonce,"ciphertext_root":root,
            "chunks":parts.len(), "bytes":bytes, "issued_ms":now, "expires_ms":now+120_000
        }),
        owner,
    )
    .unwrap();
    let (status, ticket) = post(
        port,
        "POST",
        &format!("{path}/prepare"),
        "",
        &json!({"owner_public":owner.public_key,"intent":record,"manifest":manifest}).to_string(),
    );
    assert_eq!(status, 200, "prepare: {ticket}");
    ticket
}

#[test]
fn transfer_endpoint_is_not_accessible_with_default_configuration() {
    let dir = tempdir().unwrap();
    let server = start_with(false, dir.path(), &[]);
    let owner = SigningKey::generate(true);
    let (code, body) = post(
        server.1,
        "POST",
        "/cvp/v2/experimental-transfer/challenge",
        "",
        &json!({"owner_public":owner.public_key}).to_string(),
    );
    assert_eq!(code, 404);
    assert_eq!(body["code"], "NOT_FOUND");
    assert!(!dir.path().join("migration-stage-experimental.db").exists());
}

#[test]
fn opt_in_endpoint_stages_ciphertext_and_recovers_from_process_restart() {
    let dir = tempdir().unwrap();
    let owner = SigningKey::generate(true);
    let (id, token) = {
        let server = start_with(
            false,
            dir.path(),
            &[("EXPERIMENTAL_TRANSFER_STAGING", "true".into())],
        );
        let ticket = prepare(
            server.1,
            &owner,
            &[
                "first opaque encrypted chunk",
                "second opaque encrypted chunk",
            ],
            1,
        );
        assert_eq!(ticket["imported"], false);
        assert_eq!(ticket["cutover"], false);
        let id = ticket["stage_id"].as_str().unwrap().to_owned();
        let token = ticket["stage_token"].as_str().unwrap().to_owned();
        let path = format!("/cvp/v2/experimental-transfer/stages/{id}/chunks/1");
        let (code, body) = post(
            server.1,
            "POST",
            &path,
            &token,
            "second opaque encrypted chunk",
        );
        assert_eq!(code, 200, "first chunk: {body}");
        assert_eq!(body["ciphertext_complete"], false);
        let (code, status) = post(
            server.1,
            "POST",
            &format!("/cvp/v2/experimental-transfer/stages/{id}/status"),
            &token,
            &json!({"cursor":0,"limit":10}).to_string(),
        );
        assert_eq!(code, 200, "status: {status}");
        assert_eq!(status["missing"], json!([0]));
        let (bad, reply) = post(
            server.1,
            "POST",
            &format!("/cvp/v2/experimental-transfer/stages/{id}/chunks/0"),
            &token,
            "unrecognised plaintext/chunk",
        );
        assert_eq!(bad, 400);
        assert_eq!(reply["code"], "CORRUPT_CHUNK");
        let (unauthorised, _) = post(
            server.1,
            "POST",
            &format!("/cvp/v2/experimental-transfer/stages/{id}/status"),
            &random_b64u(32),
            "{}",
        );
        assert_eq!(unauthorised, 404);
        (id, token)
    };
    // Rust process has been stopped. The next instance reopens the same staging database.
    let server = start_with(
        false,
        dir.path(),
        &[("EXPERIMENTAL_TRANSFER_STAGING", "true".into())],
    );
    let prefix = format!("/cvp/v2/experimental-transfer/stages/{id}");
    let (code, status) = post(server.1, "POST", &format!("{prefix}/status"), &token, "{}");
    assert_eq!(code, 200, "restarted status: {status}");
    assert_eq!(status["received"], 1);
    let (code, reply) = post(
        server.1,
        "POST",
        &format!("{prefix}/chunks/0"),
        &token,
        "first opaque encrypted chunk",
    );
    assert_eq!(code, 200, "last chunk: {reply}");
    assert_eq!(reply["ciphertext_complete"], true);
    assert_eq!(reply["imported"], false);
    assert_eq!(reply["cutover"], false);
    let (code, retrieved) = post(server.1, "GET", &format!("{prefix}/chunks/0"), &token, "");
    assert_eq!(code, 200);
    assert!(retrieved["ciphertext"]
        .as_str()
        .is_some_and(|v| !v.is_empty()));
    let (code, ended) = post(server.1, "POST", &format!("{prefix}/abort"), &token, "");
    assert_eq!(code, 200, "abort: {ended}");
    assert_eq!(ended["source_unchanged"], true);
    let (code, _) = post(server.1, "POST", &format!("{prefix}/status"), &token, "{}");
    assert_eq!(code, 404);
}

#[test]
fn owner_signed_reconciliation_over_http_survives_restart_without_cutover() {
    let dir = tempdir().unwrap();
    let owner = SigningKey::generate(true);
    let impostor = SigningKey::generate(true);
    let ciphertext = "opaque encrypted report archive";
    // Test-only opaque data. Real devices must AEAD-encrypt this before upload.
    let report = format!("CVRPT{}{}", char::from(1), "A".repeat(64));
    let prefix = "/cvp/v2/experimental-transfer";
    let (id, token, statement) = {
        let server = start_with(
            false,
            dir.path(),
            &[("EXPERIMENTAL_TRANSFER_STAGING", "true".into())],
        );
        let ticket = prepare(server.1, &owner, &[ciphertext], 7);
        let id = ticket["stage_id"].as_str().unwrap().to_owned();
        let token = ticket["stage_token"].as_str().unwrap().to_owned();
        let (_, root, _) = manifest(&[ciphertext]);
        let now = commonveil_server::sessions::now_ms();
        let statement = sign(
            "transfer.reconcile",
            &json!({
                "v": 1, "actor": owner.kid,
                "stage_id": id, "to": "cv.example",
                "ciphertext_root": root,
                "challenge": ticket["reconcile_challenge"],
                "encrypted_report_sha256": sha256_b64u(report.as_bytes()),
                "client_checked": true, "issued_ms": now, "expires_ms": now + 120_000
            }),
            &owner,
        )
        .unwrap();
        let endpoint = format!("{prefix}/stages/{id}/reconcile");
        let request = json!({"owner_public": owner.public_key, "statement": statement}).to_string();
        let (status, body) = post(server.1, "POST", &endpoint, &token, &request);
        assert_eq!(status, 409, "{body}");
        assert_eq!(body["code"], "INCOMPLETE_CIPHERTEXT");
        let (code, chunk) = post(
            server.1,
            "POST",
            &format!("{prefix}/stages/{id}/chunks/0"),
            &token,
            ciphertext,
        );
        assert_eq!(code, 200, "{chunk}");

        let forbidden_request =
            json!({"owner_public": impostor.public_key, "statement": statement}).to_string();
        let (code, denied) = post(server.1, "POST", &endpoint, &token, &forbidden_request);
        assert_eq!(code, 403, "{denied}");
        assert_eq!(denied["code"], "WRONG_ACTOR");
        let (code, missing_report) = post(server.1, "POST", &endpoint, &token, &request);
        assert_eq!(code, 409, "{missing_report}");
        assert_eq!(missing_report["code"], "MISSING_ENCRYPTED_REPORT");
        let report_path = format!("{prefix}/stages/{id}/report");
        let (code, accepted) = post(server.1, "POST", &report_path, &token, &report);
        assert_eq!(code, 200, "{accepted}");
        assert_eq!(accepted["sha256"], sha256_b64u(report.as_bytes()));
        assert_eq!(accepted["imported"], false);
        let (code, retry) = post(server.1, "POST", &report_path, &token, &report);
        assert_eq!(code, 200, "{retry}");
        assert_eq!(retry["duplicate"], true);
        let (code, conflict) = post(
            server.1,
            "POST",
            &report_path,
            &token,
            &format!("CVRPT{}{}", char::from(1), "B".repeat(64)),
        );
        assert_eq!(code, 409, "{conflict}");
        assert_eq!(conflict["code"], "REPORT_CONFLICT");
        let (code, denied) = post(server.1, "GET", &report_path, &random_b64u(32), "");
        assert_eq!(code, 404, "{denied}");

        let (code, denied) = post(server.1, "POST", &endpoint, &random_b64u(32), &request);
        assert_eq!(code, 404, "{denied}");

        let (code, confirmed) = post(server.1, "POST", &endpoint, &token, &request);
        assert_eq!(code, 200, "{confirmed}");
        assert_eq!(confirmed["client_attested"], true);
        assert_eq!(confirmed["imported"], false);
        assert_eq!(confirmed["cutover"], false);
        (id, token, statement)
    };

    // A fresh process must recover the signed statement and keep all
    // account routing unchanged.
    let restarted = start_with(
        false,
        dir.path(),
        &[("EXPERIMENTAL_TRANSFER_STAGING", "true".into())],
    );
    let endpoint = format!("{prefix}/stages/{id}");
    let (code, status) = post(
        restarted.1,
        "POST",
        &format!("{endpoint}/status"),
        &token,
        "{}",
    );
    assert_eq!(code, 200, "{status}");
    assert_eq!(status["client_attested"], true);
    assert_eq!(status["encrypted_report_staged"], true);
    let (code, report_copy) = post(
        restarted.1,
        "GET",
        &format!("{endpoint}/report"),
        &token,
        "",
    );
    assert_eq!(code, 200, "{report_copy}");
    assert_eq!(report_copy["sha256"], sha256_b64u(report.as_bytes()));

    assert_eq!(status["imported"], false);
    assert_eq!(status["cutover"], false);
    let (code, result) = post(
        restarted.1,
        "GET",
        &format!("{endpoint}/reconcile"),
        &token,
        "",
    );
    assert_eq!(code, 200, "{result}");
    assert_eq!(result["client_signed_statement"], statement);
    let (code, cancelled) = post(
        restarted.1,
        "POST",
        &format!("{endpoint}/abort"),
        &token,
        "",
    );
    assert_eq!(code, 200, "{cancelled}");
    assert_eq!(cancelled["source_unchanged"], true);
    let (code, missing) = post(
        restarted.1,
        "GET",
        &format!("{endpoint}/reconcile"),
        &token,
        "",
    );
    assert_eq!(code, 404, "{missing}");
}

// A->B->C here tests *independent identity and ciphertext staging only*.
// It does NOT test live account migration, actor redirect or mailbox transfer.
#[test]
fn independently_owned_actor_can_stage_on_two_distinct_hosts_without_a_source_host() {
    let original_actor = SigningKey::generate(true);
    let classical_only = SigningKey::generate(false);
    let host_b_dir = tempdir().unwrap();
    let host_c_dir = tempdir().unwrap();
    let enabled = "true".to_string();
    let host_b = start_with(
        false,
        host_b_dir.path(),
        &[
            ("EXPERIMENTAL_TRANSFER_STAGING", enabled.clone()),
            ("SITE_URL", "https://b.example".to_string()),
        ],
    );
    let host_c = start_with(
        false,
        host_c_dir.path(),
        &[
            ("EXPERIMENTAL_TRANSFER_STAGING", enabled),
            ("SITE_URL", "https://c.example".to_string()),
        ],
    );
    let endpoint = "/cvp/v2/experimental-transfer";
    let (bad, downgrade) = post(
        host_c.1,
        "POST",
        &format!("{endpoint}/challenge"),
        "",
        &json!({"owner_public":classical_only.public_key}).to_string(),
    );
    assert_eq!(bad, 400, "{downgrade}");
    assert_eq!(downgrade["code"], "HYBRID_KEY_REQUIRED");

    // Host A is deliberately offline. Only the user-held independent actor
    // key and ciphertext are available. We make no claim to transfer A's
    // unavailable messages or to verify A's past actor document sequence.
    let mut stage_tokens = Vec::new();
    for (server, from, destination, seq, payload) in [
        (
            &host_b,
            "a.example",
            "b.example",
            1_u64,
            "opaque-stage-for-b",
        ),
        (
            &host_c,
            "b.example",
            "c.example",
            2_u64,
            "opaque-stage-for-c",
        ),
    ] {
        let (status, issued) = post(
            server.1,
            "POST",
            &format!("{endpoint}/challenge"),
            "",
            &json!({"owner_public":original_actor.public_key}).to_string(),
        );
        assert_eq!(status, 200, "{issued}");
        assert_eq!(issued["actor"], original_actor.kid);
        assert_eq!(issued["destination"], destination);
        let nonce = issued["challenge"].as_str().unwrap();
        let (manifest, root, bytes) = manifest(&[payload]);
        let now = commonveil_server::sessions::now_ms();
        // First try a properly signed but wrong-destination statement. A
        // separate host must not accept a valid signature addressed to B.
        let bad_to = if destination == "b.example" {
            "c.example"
        } else {
            "b.example"
        };
        let make_intent = |to: &str| {
            sign(
                "transfer.intent",
                &json!({
                    "v": 1, "actor": original_actor.kid, "from": from, "to": to,
                    "seq": seq, "challenge": nonce, "ciphertext_root": root,
                    "chunks": 1, "bytes": bytes, "issued_ms": now, "expires_ms": now + 120_000,
                }),
                &original_actor,
            )
            .unwrap()
        };
        let forged_destination = make_intent(bad_to);
        let (code, rejected) = post(
            server.1,
            "POST",
            &format!("{endpoint}/prepare"),
            "",
            &json!({
                "owner_public": original_actor.public_key,
                "intent": forged_destination, "manifest": manifest,
            })
            .to_string(),
        );
        assert_eq!(code, 400, "{rejected}");
        assert_eq!(rejected["code"], "BAD_INTENT");

        let signed = make_intent(destination);
        let (code, prepared) = post(
            server.1,
            "POST",
            &format!("{endpoint}/prepare"),
            "",
            &json!({
                "owner_public": original_actor.public_key,
                "intent": signed, "manifest": manifest,
            })
            .to_string(),
        );
        assert_eq!(code, 200, "{prepared}");
        assert_eq!(prepared["cutover"], false);
        let stage = prepared["stage_id"].as_str().unwrap();
        let token = prepared["stage_token"].as_str().unwrap();
        let (code, response) = post(
            server.1,
            "POST",
            &format!("{endpoint}/stages/{stage}/chunks/0"),
            token,
            payload,
        );
        assert_eq!(code, 200, "{response}");
        assert_eq!(response["ciphertext_complete"], true);
        assert_eq!(response["cutover"], false);
        stage_tokens.push((server.1, stage.to_string(), token.to_string()));
    }
    // The two staging databases and bearer credentials are independent.
    let (b_port, b_id, b_token) = &stage_tokens[0];
    let (c_port, c_id, c_token) = &stage_tokens[1];
    let (bad, denied) = post(
        *c_port,
        "POST",
        &format!("{endpoint}/stages/{c_id}/status"),
        b_token,
        "{}",
    );
    assert_eq!(bad, 404, "{denied}");
    let (bad, denied) = post(
        *b_port,
        "POST",
        &format!("{endpoint}/stages/{b_id}/status"),
        c_token,
        "{}",
    );
    assert_eq!(bad, 404, "{denied}");
    for (port, id, token) in stage_tokens {
        let (code, status) = post(
            port,
            "POST",
            &format!("{endpoint}/stages/{id}/status"),
            &token,
            "{}",
        );
        assert_eq!(code, 200, "{status}");
        assert_eq!(status["ciphertext_complete"], true);
        assert_eq!(status["client_attested"], false);
        assert_eq!(status["imported"], false);
        assert_eq!(status["cutover"], false);
    }
}
