//! Web Push (base44/shared/push/webpush.ts):
//!   - RFC 8291: the payload is encrypted to the browser's own key, so the push service in between
//!     can't read it;
//!   - RFC 8292 (VAPID): each push is signed with this site's key, so only this site can push to its
//!     subscribers.
use aes_gcm::aead::{Aead, KeyInit as _};
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::Signer;
use serde_json::{json, Value};
use sha2::Sha256;

use crate::crypto::{b64url, from_b64url, random_bytes};

/// Browser push services. A subscription must point at one of these.
fn push_host_ok(host: &str) -> bool {
    let labels = |suffix: &str| {
        host.strip_suffix(suffix).is_some_and(|p| {
            p.is_empty()
                || (p.ends_with('.')
                    && p[..p.len() - 1].split('.').all(|l| {
                        !l.is_empty()
                            && l.bytes()
                                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                    }))
        })
    };
    let one_label = |suffix: &str| {
        host.strip_suffix(suffix).is_some_and(|p| {
            p.is_empty()
                || (p.ends_with('.') && {
                    let l = &p[..p.len() - 1];
                    !l.is_empty()
                        && !l.contains('.')
                        && l.bytes()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                })
        })
    };
    matches!(
        host,
        "fcm.googleapis.com"
            | "android.googleapis.com"
            | "updates.push.services.mozilla.com"
            | "web.push.apple.com"
    ) || one_label("push.services.mozilla.com")
        || labels("notify.windows.com")
        || labels("push.apple.com")
}

pub fn endpoint_ok(endpoint: &Value) -> bool {
    let Some(e) = endpoint
        .as_str()
        .filter(|e| e.encode_utf16().count() <= 1000)
    else {
        return false;
    };
    match url::Url::parse(e) {
        Ok(u) => {
            u.scheme() == "https"
                && u.port().is_none()
                && u.username().is_empty()
                && u.host_str().is_some_and(push_host_ok)
        }
        Err(_) => false,
    }
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// HKDF-SHA-256 for outputs of up to 32 bytes.
fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let prk = hmac(salt, ikm);
    let mut i = info.to_vec();
    i.push(1);
    hmac(&prk, &i)[..len].to_vec()
}

/// Encrypt a payload for one subscription (RFC 8291, aes128gcm). `fixed`: the sender's secret key
/// and the salt, for the RFC's test vector only.
pub fn encrypt_payload(
    payload: &[u8],
    p256dh: &str,
    auth: &str,
    fixed: Option<(&[u8], &[u8])>,
) -> Option<Vec<u8>> {
    let ua_public = from_b64url(p256dh)?;
    let auth_secret = from_b64url(auth)?;
    if ua_public.len() != 65 || ua_public[0] != 4 || auth_secret.len() != 16 {
        return None;
    }
    let ua_key = p256::PublicKey::from_sec1_bytes(&ua_public).ok()?;
    let secret = match fixed {
        Some((sk, _)) => p256::SecretKey::from_slice(sk).ok()?,
        None => p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng),
    };
    let sender_public =
        p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&secret.public_key(), false)
            .as_bytes()
            .to_vec();
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), ua_key.as_affine());
    let mut info = b"WebPush: info\0".to_vec();
    info.extend(&ua_public);
    info.extend(&sender_public);
    let ikm = hkdf(&auth_secret, shared.raw_secret_bytes(), &info, 32);
    let salt = match fixed {
        Some((_, s)) => s.to_vec(),
        None => random_bytes(16),
    };
    let cek = hkdf(&salt, &ikm, b"Content-Encoding: aes128gcm\0", 16);
    let nonce = hkdf(&salt, &ikm, b"Content-Encoding: nonce\0", 12);
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(&cek).ok()?;
    let mut plain = payload.to_vec();
    plain.push(2);
    let sealed = cipher
        .encrypt(aes_gcm::Nonce::from_slice(&nonce), plain.as_slice())
        .ok()?;
    let mut out = salt;
    out.extend(4096u32.to_be_bytes());
    out.push(65);
    out.extend(&sender_public);
    out.extend(sealed);
    Some(out)
}

// ---------- VAPID ----------

/// The site's push key, stored as the Node.js server stores it: `{ publicKey, privateJwk }`.
pub fn make_vapid_keys() -> Value {
    let sk = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let point =
        p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&sk.public_key(), false);
    json!({
        "publicKey": b64url(point.as_bytes()),
        "privateJwk": { "key_ops": ["sign"], "ext": true, "kty": "EC", "x": b64url(point.x().unwrap()), "y": b64url(point.y().unwrap()), "crv": "P-256", "d": b64url(&sk.to_bytes()) },
    })
}

fn vapid_header(endpoint: &str, keys: &Value, subject: &str, now_ms: i64) -> Option<String> {
    let u = url::Url::parse(endpoint).ok()?;
    let aud = u.origin().ascii_serialization();
    let enc = |v: Value| b64url(v.to_string().as_bytes());
    let unsigned = format!(
        "{}.{}",
        enc(json!({ "typ": "JWT", "alg": "ES256" })),
        enc(json!({ "aud": aud, "exp": now_ms / 1000 + 12 * 3600, "sub": subject }))
    );
    let d = from_b64url(keys["privateJwk"]["d"].as_str()?)?;
    let key = p256::ecdsa::SigningKey::from_slice(&d).ok()?;
    let sig: p256::ecdsa::Signature = key.sign(unsigned.as_bytes());
    Some(format!(
        "vapid t={unsigned}.{}, k={}",
        b64url(&sig.to_bytes()),
        keys["publicKey"].as_str()?
    ))
}

pub enum Sent {
    /// The subscription's keys are unusable (nothing was sent).
    Unsendable,
    Sent(u16),
    Gone(u16),
    Rejected(u16),
    Failed,
}

/// Send one push.
pub fn send_push(
    endpoint: &str,
    p256dh: &str,
    auth: &str,
    payload: &Value,
    keys: &Value,
    subject: &str,
    urgency: &str,
) -> Sent {
    if !endpoint_ok(&json!(endpoint)) {
        return Sent::Gone(0);
    }
    // A subscription with bad keys throws in the JavaScript, and the whole notification stops.
    let Some(body) = encrypt_payload(payload.to_string().as_bytes(), p256dh, auth, None) else {
        return Sent::Unsendable;
    };
    let Some(authz) = vapid_header(endpoint, keys, subject, crate::sessions::now_ms()) else {
        return Sent::Unsendable;
    };
    let agent = crate::tls::agent()
        .redirects(0)
        .timeout(std::time::Duration::from_secs(5))
        .build();
    let res = agent
        .post(endpoint)
        .set("Authorization", &authz)
        .set("Content-Encoding", "aes128gcm")
        .set("Content-Type", "application/octet-stream")
        .set("TTL", "86400")
        .set("Urgency", urgency)
        .set("Topic", "commonveil")
        .send_bytes(&body);
    match res {
        Ok(r) if (200..300).contains(&r.status()) => Sent::Sent(r.status()),
        Err(ureq::Error::Status(code @ (404 | 410), _)) => Sent::Gone(code),
        Err(ureq::Error::Status(code, _)) => Sent::Rejected(code),
        Ok(r) => Sent::Rejected(r.status()),
        _ => Sent::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8291 section 5's worked example.
    #[test]
    fn the_rfc_8291_example_encrypts_to_its_published_bytes() {
        let sk = from_b64url("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw").unwrap();
        let salt = from_b64url("DGv6ra1nlYgDCS1FRnbzlw").unwrap();
        let out = encrypt_payload(b"When I grow up, I want to be a watermelon", "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4", "BTBZMqHH6r4Tts7J_aSIgg", Some((&sk, &salt))).unwrap();
        assert_eq!(b64url(&out), "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN");
    }

    #[test]
    fn vapid_headers_verify_under_the_site_key() {
        use p256::ecdsa::signature::Verifier;
        let keys = make_vapid_keys();
        let h = vapid_header(
            "https://fcm.googleapis.com/fcm/send/x",
            &keys,
            "https://cv.example",
            1_800_000_000_000,
        )
        .unwrap();
        let t = h
            .strip_prefix("vapid t=")
            .unwrap()
            .split(", k=")
            .next()
            .unwrap();
        let (unsigned, sig) = t.rsplit_once('.').unwrap();
        let claims: Value =
            serde_json::from_slice(&from_b64url(unsigned.split('.').nth(1).unwrap()).unwrap())
                .unwrap();
        assert_eq!(
            claims,
            json!({ "aud": "https://fcm.googleapis.com", "exp": 1_800_043_200, "sub": "https://cv.example" })
        );
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(
            &from_b64url(keys["publicKey"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let sig = p256::ecdsa::Signature::from_slice(&from_b64url(sig).unwrap()).unwrap();
        assert!(key.verify(unsigned.as_bytes(), &sig).is_ok());
    }

    #[test]
    fn only_browser_push_services_are_accepted() {
        for ok in [
            "https://fcm.googleapis.com/fcm/send/abc",
            "https://updates.push.services.mozilla.com/wpush/v2/x",
            "https://web.push.apple.com/x",
            "https://wns2-db5p.notify.windows.com/w/?token=x",
            "https://a.push.services.mozilla.com/x",
        ] {
            assert!(endpoint_ok(&json!(ok)), "{ok}");
        }
        for bad in [
            "http://fcm.googleapis.com/x",
            "https://fcm.googleapis.com:8443/x",
            "https://evil.example/x",
            "https://user@fcm.googleapis.com/x",
            "https://a.b.push.services.mozilla.com/x",
            "https://notify.windows.com.evil.example/x",
            "nope",
        ] {
            assert!(!endpoint_ok(&json!(bad)), "{bad}");
        }
    }
}
