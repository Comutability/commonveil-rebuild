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
        let statement = sign("transfer.reconcile", &json!({
            "v": 1, "actor": owner.kid,
            "stage_id": id, "to": "cv.example",
            "ciphertext_root": root,
            "challenge": ticket["reconcile_challenge"],
            "encrypted_report_sha256": sha256_b64u(b"encrypted client-private reconciliation report"),
            "client_checked": true, "issued_ms": now, "expires_ms": now + 120_000
        }), &owner).unwrap();
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
