//! What the server checks about keys, certificates, proofs and ciphertexts (base44/shared/verify.ts
//! and deviceAuth.ts). It can't read anything encrypted, but it can refuse what's malformed or
//! not signed by the right key. The texts signed are Secure Net's (secure_net_core::cv::canonical).
use p256::ecdsa::signature::Verifier;
use serde_json::{json, Value};

use crate::api::{random_id_field, ApiError, Ctx, Limits, Result};
use crate::js::{strict_eq, truthy};

pub const KEM_PUBLIC_BYTES: usize = 1249;
pub const KEM_CIPHERTEXT_BYTES: usize = 1153;
pub const MAX_SEALED_CHARS: usize = 96 * 1024;

fn deny(status: u16, code: &str, message: &str) -> ApiError {
    ApiError::new(status, code, message)
}
fn internal(e: secure_net_core::error::Error) -> ApiError {
    ApiError { status: 500, code: "INTERNAL".into(), message: e.message }
}

/// Standard base64 as `B64_RE` accepts it, decoded as `atob` does. `None` for anything else.
pub fn b64_bytes(v: &Value) -> Option<Vec<u8>> {
    let s = v.as_str()?;
    if s.is_empty() || s.len() > 200_000 || s.len() % 4 != 0 {
        return None;
    }
    let b = s.as_bytes();
    let pad = b.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return None;
    }
    let body = &b[..b.len() - pad];
    let sym = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    for chunk in body.chunks(4) {
        let vals: Vec<u32> = chunk.iter().map(|&c| sym(c)).collect::<Option<_>>()?;
        let n = vals.iter().fold(0u32, |a, v| (a << 6) | v) << (6 * (4 - vals.len()));
        let bytes = n.to_be_bytes();
        out.extend_from_slice(&bytes[1..vals.len()]);
    }
    Some(out)
}

pub fn to_b64(bytes: &[u8]) -> String {
    secure_net_core::cv::encoding::to_b64(bytes)
}

/// A real, on-curve, uncompressed P-256 public key.
pub fn is_p256_key(v: &Value) -> bool {
    match b64_bytes(v) {
        Some(raw) if raw.len() == 65 && raw[0] == 4 => p256::PublicKey::from_sec1_bytes(&raw).is_ok(),
        _ => false,
    }
}
pub fn require_p256_key(v: &Value, name: &str) -> Result<String> {
    if !is_p256_key(v) {
        return Err(deny(400, "BAD_KEY", &format!("Invalid {name}.")));
    }
    Ok(v.as_str().unwrap_or("").into())
}

/// A hybrid public key: ML-KEM-768's 1184 bytes, then an uncompressed P-256 point.
pub fn is_kem_key(v: &Value) -> bool {
    match b64_bytes(v) {
        Some(raw) if raw.len() == KEM_PUBLIC_BYTES => is_p256_key(&json!(to_b64(&raw[KEM_PUBLIC_BYTES - 65..]))),
        _ => false,
    }
}
pub fn require_kem_key(v: &Value, name: &str) -> Result<String> {
    if !is_kem_key(v) {
        return Err(deny(400, "BAD_KEY", &format!("Invalid {name}.")));
    }
    Ok(v.as_str().unwrap_or("").into())
}
/// "" when absent, else a valid hybrid key.
fn optional_kem_key(v: Option<&Value>, name: &str) -> Result<String> {
    match v {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) if s.is_empty() => Ok(String::new()),
        Some(v) => require_kem_key(v, name),
    }
}

/// ECDSA P-256 / SHA-256 over the text, a raw 64-byte signature, as WebCrypto checks it.
pub fn verify_sig(public_key: &str, signature: &Value, text: &str) -> bool {
    let (Some(raw), Some(sig)) = (b64_bytes(&json!(public_key)), b64_bytes(signature)) else { return false };
    if raw.len() != 65 || sig.len() != 64 {
        return false;
    }
    let (Ok(key), Ok(sig)) = (p256::ecdsa::VerifyingKey::from_sec1_bytes(&raw), p256::ecdsa::Signature::from_slice(&sig)) else { return false };
    key.verify(text.as_bytes(), &sig).is_ok()
}

// ---------- account key statements ----------

fn is_int(v: &Value) -> bool {
    v.as_f64().is_some_and(|f| f.is_finite() && f.fract() == 0.0)
}

pub fn iso_time(v: &Value, name: &str) -> Result<String> {
    let re = regex::Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$").unwrap();
    match v.as_str() {
        Some(s) if s.len() <= 40 && re.is_match(s) && crate::dates::parse(s).is_some() => Ok(s.into()),
        _ => Err(crate::api::bad_field(name)),
    }
}

pub fn parse_statement(raw: &Value, user_id: &str) -> Result<Value> {
    if !truthy(Some(raw)) || !(raw.is_object() || raw.is_array()) {
        return Err(deny(400, "BAD_STATEMENT", "Missing key statement."));
    }
    if raw["user_id"] != user_id {
        return Err(deny(403, "WRONG_ACCOUNT", "That key statement is for a different account."));
    }
    if !is_int(&raw["version"]) || raw["version"].as_f64().unwrap_or(0.0) < 1.0 {
        return Err(deny(400, "BAD_STATEMENT", "Invalid key version."));
    }
    if !is_int(&raw["signed_by_version"]) || raw["signed_by_version"].as_f64().unwrap_or(0.0) < 1.0 {
        return Err(deny(400, "BAD_STATEMENT", "Invalid signer."));
    }
    let mut st = json!({
        "user_id": user_id,
        "version": raw["version"].as_f64().unwrap_or(0.0) as i64,
        "ecdh_pub": require_p256_key(&raw["ecdh_pub"], "encryption key")?,
        "sign_pub": require_p256_key(&raw["sign_pub"], "signing key")?,
        "recovery_pub": require_p256_key(&raw["recovery_pub"], "recovery key")?,
        "signed_by_version": raw["signed_by_version"].as_f64().unwrap_or(0.0) as i64,
        "issued_at": iso_time(&raw["issued_at"], "issued_at")?,
        "signature": raw["signature"].as_str().unwrap_or(""),
        "recovery_mac": "",
        "kem_pub": optional_kem_key(raw.get("kem_pub"), "post-quantum key")?,
        "recovery_kem_pub": "",
    });
    if st["kem_pub"] != "" {
        st["recovery_kem_pub"] = json!(optional_kem_key(raw.get("recovery_kem_pub"), "post-quantum recovery key")?);
    } else if truthy(raw.get("recovery_kem_pub")) {
        return Err(deny(400, "BAD_STATEMENT", "A post-quantum recovery key needs a post-quantum account key."));
    }
    match raw.get("recovery_mac") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) if s.is_empty() => {}
        Some(mac) => {
            if b64_bytes(mac).is_none_or(|m| m.len() != 32) {
                return Err(deny(400, "BAD_STATEMENT", "Invalid recovery anchor."));
            }
            st["recovery_mac"] = mac.clone();
        }
    }
    Ok(st)
}

/// Statements made with the phrase to hand (setup, reset, a new phrase) must carry its anchor.
pub fn require_recovery_anchor(st: &Value) -> Result<()> {
    if !truthy(st.get("recovery_mac")) {
        return Err(deny(400, "BAD_STATEMENT", "This key statement is missing its recovery anchor."));
    }
    Ok(())
}

pub fn verify_statement(st: &Value, signer_pub: &str) -> Result<bool> {
    let text = secure_net_core::cv::canonical::statement_text(st).map_err(internal)?;
    Ok(verify_sig(signer_pub, &st["signature"], &text))
}

// ---------- devices ----------

pub fn parse_device(raw: &Value) -> Result<Value> {
    if !truthy(Some(raw)) || !(raw.is_object() || raw.is_array()) {
        return Err(deny(400, "BAD_DEVICE", "Missing device."));
    }
    let label = match raw["label"].as_str() {
        Some(l) => {
            let cleaned: String = l.chars().filter(|c| !matches!(c, '\u{0}'..='\u{1F}' | '\u{7F}')).collect();
            let t = crate::js::trim(&cleaned);
            let t = String::from_utf16_lossy(&t.encode_utf16().take(60).collect::<Vec<u16>>());
            if t.is_empty() { "Device".to_string() } else { t }
        }
        None => "Device".into(),
    };
    let mut d = json!({
        "device_id": random_id_field(&raw["device_id"], "device id")?,
        "label": label,
        "sign_pub": require_p256_key(&raw["sign_pub"], "device signing key")?,
        "box_pub": require_p256_key(&raw["box_pub"], "device box key")?,
    });
    let kem = optional_kem_key(raw.get("kem_pub"), "device post-quantum key")?;
    if !kem.is_empty() {
        d["kem_pub"] = json!(kem);
    }
    Ok(d)
}

/// The certificate must name exactly these device keys and be signed by the given account key.
/// Returns it with `has_kem`.
pub fn verify_cert(raw: &Value, user_id: &str, device: &Value, key_version: i64, account_sign_pub: &str) -> Result<Value> {
    if !truthy(Some(raw)) || !(raw.is_object() || raw.is_array()) {
        return Err(deny(400, "BAD_CERT", "Missing device certificate."));
    }
    let mut cert = serde_json::Map::new();
    for k in ["user_id", "device_id", "sign_pub", "box_pub", "key_version"] {
        if let Some(v) = raw.get(k) {
            cert.insert(k.into(), v.clone());
        }
    }
    cert.insert("issued_at".into(), json!(iso_time(&raw["issued_at"], "certificate time")?));
    if let Some(v) = raw.get("signature") {
        cert.insert("signature".into(), v.clone());
    }
    let kem = raw.get("kem_pub").filter(|k| *k != "");
    if let Some(k) = kem {
        cert.insert("kem_pub".into(), k.clone());
    }
    let c = Value::Object(cert);
    let s = |v: &str| Some(json!(v));
    let matches = strict_eq(c.get("user_id"), s(user_id).as_ref())
        && strict_eq(c.get("device_id"), device.get("device_id"))
        && strict_eq(c.get("sign_pub"), device.get("sign_pub"))
        && strict_eq(c.get("box_pub"), device.get("box_pub"))
        && strict_eq(c.get("key_version"), Some(&json!(key_version)))
        && kem.is_none_or(|k| strict_eq(Some(k), device.get("kem_pub")));
    if !matches {
        return Err(deny(400, "CERT_MISMATCH", "The device certificate doesn't match the device."));
    }
    let text = secure_net_core::cv::canonical::cert_text(&c).map_err(internal)?;
    if !verify_sig(account_sign_pub, &c["signature"], &text) {
        return Err(deny(403, "CERT_INVALID", "The device certificate failed its signature check."));
    }
    let mut out = c;
    out["has_kem"] = json!(kem.is_some());
    Ok(out)
}

/// A device's own signature over its post-quantum key (device-kem/v1).
pub fn verify_device_kem_sig(user_id: &str, device: &Value, kem_pub: &str, signature: &Value) -> Result<bool> {
    let text = secure_net_core::cv::canonical::device_kem_text(user_id, device["device_id"].as_str().unwrap_or(""), kem_pub).map_err(internal)?;
    Ok(verify_sig(device["sign_pub"].as_str().unwrap_or(""), signature, &text))
}

/// Proof that a request was signed by the device holding `sign_pub`. Returns its device id.
pub fn verify_proof(user_id: &str, action: &str, payload_json: &str, proof: &Value, sign_pub: &str, now: i64) -> Result<String> {
    if !truthy(Some(proof)) || !(proof.is_object() || proof.is_array()) {
        return Err(deny(401, "PROOF_REQUIRED", "This action must come from one of your devices."));
    }
    let device_id = random_id_field(&proof["device_id"], "device id")?;
    let issued_at = iso_time(&proof["issued_at"], "proof time")?;
    let nonce = random_id_field(&proof["nonce"], "nonce")?;
    if (now as f64 - crate::dates::parse(&issued_at).unwrap_or(f64::NAN)).abs() > Limits::PROOF_SKEW_MS as f64 {
        return Err(deny(401, "PROOF_EXPIRED", "That request is too old. Check your device clock and try again."));
    }
    let hash = secure_net_core::cv::encoding::sha256_b64(payload_json);
    let text = secure_net_core::cv::canonical::device_proof_text(&json!({ "user_id": user_id, "device_id": device_id, "action": action, "payload_hash": hash, "issued_at": issued_at, "nonce": nonce })).map_err(internal)?;
    if !verify_sig(sign_pub, &proof["signature"], &text) {
        return Err(deny(403, "PROOF_INVALID", "This device couldn't prove it's yours."));
    }
    Ok(device_id)
}

// ---------- sealed values ----------

/// A sealed value: classical {epk, iv, ct} or post-quantum {kct, iv, ct}.
pub fn valid_sealed(v: &Value) -> bool {
    if !truthy(Some(v)) || !(v.is_object() || v.is_array()) {
        return false;
    }
    let (iv, ct) = (b64_bytes(&v["iv"]), b64_bytes(&v["ct"]));
    if iv.is_none_or(|i| i.len() != 12) || ct.is_none_or(|c| c.len() < 17) {
        return false;
    }
    if v.get("kct").is_some() {
        return v.get("epk").is_none() && b64_bytes(&v["kct"]).is_some_and(|k| k.len() == KEM_CIPHERTEXT_BYTES);
    }
    b64_bytes(&v["epk"]).is_some_and(|e| e.len() == 65 && e[0] == 4)
}

pub fn is_kem_sealed(v: &Value) -> bool {
    v["kct"].is_string()
}

pub fn require_sealed(v: &Value, name: &str) -> Result<String> {
    if !valid_sealed(v) {
        return Err(deny(400, "BAD_CIPHERTEXT", &format!("Invalid {name}.")));
    }
    let out = if is_kem_sealed(v) { json!({ "kct": v["kct"], "iv": v["iv"], "ct": v["ct"] }) } else { json!({ "epk": v["epk"], "iv": v["iv"], "ct": v["ct"] }) }.to_string();
    if out.encode_utf16().count() > MAX_SEALED_CHARS {
        return Err(deny(413, "TOO_LARGE", &format!("{name} is too large.")));
    }
    Ok(out)
}

// ---------- requests signed by a device (deviceAuth.ts) ----------

/// The request's payload: an exact JSON string, and what it says.
pub fn payload_of(body: &Value, max_bytes: usize) -> Result<(String, Value)> {
    let Some(text) = body["payload"].as_str().filter(|p| !p.is_empty() && p.encode_utf16().count() <= max_bytes) else {
        return Err(deny(400, "BAD_PAYLOAD", "Missing payload."));
    };
    let data: Value = serde_json::from_str(text).map_err(|_| deny(400, "BAD_PAYLOAD", "Invalid payload."))?;
    if !data.is_object() {
        return Err(deny(400, "BAD_PAYLOAD", "Invalid payload."));
    }
    Ok((text.to_string(), data))
}

/// The request is signed by one of this account's active devices: (that device, the payload).
pub fn signed_by_active_device(ctx: &Ctx, action: &str, max_bytes: usize) -> Result<(Value, Value)> {
    let proof = &ctx.body["proof"];
    if !truthy(Some(proof)) || !(proof.is_object() || proof.is_array()) {
        return Err(deny(401, "PROOF_REQUIRED", "This action must come from one of your devices."));
    }
    let (text, data) = payload_of(&ctx.body, max_bytes)?;
    let device_id = random_id_field(&proof["device_id"], "device id")?;
    // The member's own device row: read with their own access.
    let device = crate::shared::require_active_device(&ctx.own(), ctx.user_id(), &device_id)?;
    verify_proof(ctx.user_id(), action, &text, proof, device["sign_pub"].as_str().unwrap_or(""), ctx.now)?;
    Ok((device, data))
}

// ---------- encrypted messages and items ----------

pub const MAX_ENVELOPE_CHARS: usize = 96 * 1024;
pub const MAX_GROUP_MEMBERS: usize = 32;
pub const SENT_AT_SKEW_MS: i64 = 10 * 60 * 1000;
pub const QUEUED_MAX_AGE_MS: i64 = 7 * 24 * 3600 * 1000;

/// One member's copy of a message key: who, at which key version, post-quantum or not.
pub struct Wrap {
    pub u: String,
    pub kv: i64,
    pub kem: bool,
}

/// A message or title envelope's shape, and its wraps. The server can't read it, but it can insist
/// it's well-formed.
pub fn parse_envelope_shape(text: &str, max_chars: usize) -> Result<Vec<Wrap>> {
    let n = text.encode_utf16().count();
    if n == 0 || n > max_chars {
        return Err(deny(413, "TOO_LARGE", "That message is too large."));
    }
    let bad = || deny(400, "BAD_ENVELOPE", "The encrypted message is malformed.");
    let env: Value = serde_json::from_str(text).map_err(|_| bad())?;
    let v = &env["v"];
    if !(v.as_f64() == Some(2.0) || v.as_f64() == Some(3.0)) {
        return Err(bad());
    }
    let v3 = v.as_f64() == Some(3.0);
    let (iv, ct, kc) = (b64_bytes(&env["iv"]), b64_bytes(&env["ct"]), b64_bytes(&env["kc"]));
    if iv.is_none_or(|x| x.len() != 12) || ct.is_none_or(|x| x.len() < 17) || kc.is_none_or(|x| x.len() != 32) {
        return Err(bad());
    }
    let wraps = env["wraps"].as_array().filter(|w| !w.is_empty() && w.len() <= MAX_GROUP_MEMBERS).ok_or_else(bad)?;
    let mut out: Vec<Wrap> = Vec::new();
    for w in wraps {
        let Some(u) = w["u"].as_str() else { return Err(bad()) };
        let kv_ok = w["kv"].as_f64().is_some_and(|k| k.is_finite() && k.fract() == 0.0 && k >= 1.0);
        if !truthy(Some(w)) || out.iter().any(|x| x.u == u) || !kv_ok {
            return Err(bad());
        }
        if b64_bytes(&w["iv"]).is_none_or(|x| x.len() != 12) || b64_bytes(&w["wk"]).is_none_or(|x| x.len() != 48) {
            return Err(bad());
        }
        let kem = w.get("kct").is_some();
        if kem {
            if !v3 || w.get("epk").is_some() || b64_bytes(&w["kct"]).is_none_or(|x| x.len() != KEM_CIPHERTEXT_BYTES) {
                return Err(bad());
            }
        } else if b64_bytes(&w["epk"]).is_none_or(|x| x.len() != 65) {
            return Err(bad());
        }
        out.push(Wrap { u: u.to_string(), kv: w["kv"].as_f64().unwrap_or(0.0) as i64, kem });
    }
    Ok(out)
}

/// A message's own send time: never more than a few minutes ahead; at most a few minutes behind,
/// unless it was written offline and queued (then up to a week).
pub fn check_sent_at(sent_at: &str, now: i64, queued: &Value) -> Result<()> {
    let age = now as f64 - crate::dates::parse(sent_at).unwrap_or(f64::NAN);
    let q = *queued == true;
    let max = if q { QUEUED_MAX_AGE_MS } else { SENT_AT_SKEW_MS } as f64;
    if age < -(SENT_AT_SKEW_MS as f64) || age > max {
        if q && age > 0.0 {
            return Err(deny(400, "TOO_OLD", "This message waited too long to be sent. Copy it and send it again."));
        }
        return Err(deny(400, "CLOCK_SKEW", "Your device clock looks wrong. Check it and try again."));
    }
    Ok(())
}

/// The plain clock check items other than messages use.
pub fn check_clock(sent_at: &str, now: i64) -> Result<()> {
    if (now as f64 - crate::dates::parse(sent_at).unwrap_or(f64::NAN)).abs() > SENT_AT_SKEW_MS as f64 {
        return Err(deny(400, "CLOCK_SKEW", "Your device clock looks wrong. Check it and try again."));
    }
    Ok(())
}

/// A signature over an encrypted conversation item (item/v1): a message or a group name.
#[allow(clippy::too_many_arguments)]
pub fn verify_item_signature(kind: &str, conversation_id: &str, item_id: &str, sender_id: &str, device_id: &str, envelope: &str, sent_at: &str, signature: &Value, sign_pub: &str) -> Result<bool> {
    let text = secure_net_core::cv::canonical::item_text(&json!({
        "kind": kind, "conversation_id": conversation_id, "item_id": item_id, "sender_id": sender_id, "device_id": device_id,
        "envelope_hash": secure_net_core::cv::encoding::sha256_b64(envelope), "sent_at": sent_at,
    }))
    .map_err(internal)?;
    Ok(verify_sig(sign_pub, signature, &text))
}
