//! Sign-in against the TypeScript it replaces (base44/shared/identity): passwords hashed by either
//! check on the other, access tokens are byte-identical, and every bent token, password hash and
//! signature is judged the same. Skipped when node isn't found.
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use commonveil_server::crypto::{b64url, check_password, hash_password, hmac, verify_ed25519};
use commonveil_server::sessions::{issue_access, verify_access, Keys};
use commonveil_server::store::{load_schemas, Store};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn node(ops: &[Value]) -> Option<Vec<Value>> {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/node/identity-ops.mjs");
    let mut child = Command::new("node").arg(script).arg(repo().join("base44/entities")).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().ok()?;
    child.stdin.take().unwrap().write_all(Value::from(ops.to_vec()).to_string().as_bytes()).unwrap();
    let out = child.wait_with_output().ok()?;
    assert!(out.status.success(), "the TypeScript sign-in code failed");
    Some(serde_json::from_slice(&out.stdout).unwrap())
}

const T: i64 = 1_800_000_000_000;

fn seeded() -> (Store, Value) {
    let store = Store::open(":memory:", load_schemas(&repo().join("base44/entities"))).unwrap();
    let tables = json!({ "CvSecret": [{ "name": "access-tokens", "value": "the-site-secret" }], "CvAccount": [{ "user_id": "u1", "security_epoch": 3 }] });
    for (t, rows) in tables.as_object().unwrap() {
        for r in rows.as_array().unwrap() {
            store.create(t, r, None).unwrap();
        }
    }
    (store, json!({ "op": "seed", "tables": tables }))
}

#[test]
fn passwords_tokens_and_signatures_match_the_typescript() {
    if Command::new("node").arg("--version").output().is_err() {
        eprintln!("skipped: node not found");
        return;
    }
    let (store, seed) = seeded();
    let keys = Keys::default();
    let mut ops = vec![seed];
    let mut want: Vec<Option<Value>> = vec![None]; // what Rust says, where it can say it up front

    // HMAC
    for (secret, text) in [("k", "cv1.abc"), ("ключ", "ünïcødé ✓"), ("k", "")] {
        ops.push(json!({ "op": "hmac", "secret": secret, "text": text }));
        want.push(Some(json!(hmac(secret, text))));
    }
    // Passwords made in Rust, checked by the TypeScript
    let passwords = ["correct horse battery staple", "", "ﬁne", "naïve café", "x".repeat(200).as_str().to_owned().leak()];
    for p in passwords {
        let h = hash_password(p, 1000);
        ops.push(json!({ "op": "checkPassword", "password": p, "hash": h }));
        want.push(Some(json!(true)));
        ops.push(json!({ "op": "checkPassword", "password": format!("{p}!"), "hash": h }));
        want.push(Some(json!(false)));
    }
    for (p, h) in [("x", ""), ("x", "pbkdf2-sha256$0$AAAA$AAAA$2"), ("x", "pbkdf2-sha256$1000$!!$AAAA$2"), ("x", "argon2$1$a$b"), ("x", "pbkdf2-sha256$-5$AAAAAAAAAAAAAAAAAAAAAA$AAAA$2")] {
        ops.push(json!({ "op": "checkPassword", "password": p, "hash": h }));
        want.push(Some(json!(check_password(p, h))));
    }
    // Passwords made by the TypeScript (checked in Rust below)
    let made_at = ops.len();
    for p in passwords {
        ops.push(json!({ "op": "hashPassword", "password": p, "rounds": 1000 }));
        want.push(None);
    }
    // Access tokens: the same token from the same claims and key
    let (rust_token, rust_expiry) = issue_access(&keys, &store, "u1", "d1", T);
    let issued_at = ops.len();
    ops.push(json!({ "op": "issueAccess", "user": "u1", "device": "d1", "now": T }));
    want.push(Some(json!({ "token": rust_token, "expires_at": rust_expiry })));
    let bent = |t: &str| -> Vec<Value> {
        let mut v = vec![json!(t), json!(format!("{t}.extra")), json!(t.replacen("cv1.", "cv2.", 1)), json!(format!("{}x", &t[..t.len() - 1])), json!(t.split('.').take(2).collect::<Vec<_>>().join(".")), json!(""), json!(42), json!(null), json!(format!("cv1.{}.{}", b64url(b"{\"u\":1}"), "sig")), json!("x".repeat(601))];
        let claims = b64url(json!({ "d": "d1", "x": T / 1000 + 900, "e": 0 }).to_string().as_bytes());
        v.push(json!(format!("cv1.{claims}.{}", hmac("the-site-secret", &format!("cv1.{claims}")))));
        let claims = b64url(b"not json");
        v.push(json!(format!("cv1.{claims}.{}", hmac("the-site-secret", &format!("cv1.{claims}")))));
        v
    };
    for token in bent(&rust_token) {
        for now in [T, T + 899_000, T + 900_000] {
            let s = verify_access(&keys, &store, Some(&token), now);
            ops.push(json!({ "op": "verifyAccess", "token": token, "now": now }));
            want.push(Some(s.map_or(Value::Null, |s| json!({ "userId": s.user_id, "deviceId": s.device_id, "epoch": s.epoch }))));
        }
    }
    // Ed25519
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let pk = b64url(sk.verifying_key().as_bytes());
    let sig = b64url(&sk.sign(b"proof text").to_bytes());
    let mut bad_sig = commonveil_server::crypto::from_b64url(&sig).unwrap();
    bad_sig[63] |= 0x80; // S no longer canonical
    for (k, t, s) in [(pk.clone(), "proof text", sig.clone()), (pk.clone(), "proof texT", sig.clone()), (pk.clone(), "proof text", b64url(&bad_sig)), (b64url(&[0u8; 32]), "proof text", sig.clone()), ("!!".into(), "proof text", sig.clone()), (pk.clone(), "proof text", "AAAA".into())] {
        ops.push(json!({ "op": "verifyEd25519", "key": k, "text": t, "sig": s }));
        want.push(Some(json!(verify_ed25519(&k, t, &s))));
    }

    let Some(got) = node(&ops) else {
        eprintln!("skipped: node not found");
        return;
    };
    for (i, w) in want.iter().enumerate() {
        if let Some(w) = w {
            assert_eq!(&got[i], w, "operation {i}: {}", ops[i]);
        }
    }
    // Hashes the TypeScript made check out in Rust, and the right way round.
    for (j, p) in passwords.iter().enumerate() {
        let h = got[made_at + j].as_str().unwrap();
        assert!(check_password(p, h) && !check_password(&format!("{p}?"), h), "{p:?}");
    }
    assert_eq!(got[issued_at]["token"], rust_token, "the same token, byte for byte");
}
