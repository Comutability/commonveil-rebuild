//! Passkeys (WebAuthn), matching base44/shared/identity/webauthn.ts. No attestation is asked for, so
//! registering reads the new key out of the authenticator data, and signing in checks a signature
//! with it. Keys: ES256 (P-256), EdDSA (Ed25519) and RS256.
use serde_json::{json, Value};

use crate::crypto::{b64url, from_b64url, sha256};

pub const ALGS: [i64; 3] = [-8, -7, -257];

/// A passkey problem. `known`: one of the module's own (a `PasskeyError` in the JavaScript), whose
/// message the app shows; otherwise something failed underneath (bad base64url, a value of the
/// wrong shape, a key the crypto library refuses), and callers show their own generic message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyError {
    pub known: bool,
    pub message: String,
}
fn pk_err(m: &str) -> PasskeyError {
    PasskeyError {
        known: true,
        message: m.into(),
    }
}
fn other(m: &str) -> PasskeyError {
    PasskeyError {
        known: false,
        message: m.into(),
    }
}

/// `String(v || "")`.
fn text_or_empty(v: &Value) -> String {
    if crate::js::truthy(Some(v)) {
        crate::js::to_js_string(Some(v))
    } else {
        String::new()
    }
}
type R<T> = Result<T, PasskeyError>;

// ---------- just enough CBOR ----------

#[derive(Debug, Clone, PartialEq)]
pub enum Cbor {
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Bool(bool),
    Null,
}
impl Cbor {
    /// `Map.get` by key (an integer or a string, compared as JavaScript's Map compares them).
    pub fn get(&self, key: &Cbor) -> Option<&Cbor> {
        match self {
            Cbor::Map(m) => m.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    fn bytes(&self) -> Option<&[u8]> {
        if let Cbor::Bytes(b) = self {
            Some(b)
        } else {
            None
        }
    }
}

/// Read one CBOR item at `start`: (value, end).
pub fn cbor(bytes: &[u8], start: usize) -> R<(Cbor, usize)> {
    struct P<'a> {
        b: &'a [u8],
        i: usize,
    }
    impl P<'_> {
        // Reading past the end gives `undefined` in JavaScript, which becomes 0 or NaN in its
        // arithmetic; reading on would only produce rubbish, so it's refused here.
        fn byte(&mut self) -> R<u8> {
            let v = *self.b.get(self.i).ok_or_else(|| pk_err("Bad CBOR"))?;
            self.i += 1;
            Ok(v)
        }
        fn head(&mut self) -> R<(u8, u8, u64)> {
            let b = self.byte()?;
            let (major, info) = (b >> 5, b & 31);
            let n = match info {
                0..=23 => u64::from(info),
                24 => u64::from(self.byte()?),
                25 => (u64::from(self.byte()?) << 8) | u64::from(self.byte()?),
                26 => (0..4).try_fold(0u64, |n, _| {
                    Ok::<_, PasskeyError>((n << 8) | u64::from(self.byte()?))
                })?,
                27 => (0..8).try_fold(0u64, |n, _| {
                    Ok::<_, PasskeyError>(n.wrapping_mul(256) + u64::from(self.byte()?))
                })?,
                _ => return Err(pk_err("Unsupported CBOR")),
            };
            Ok((major, info, n))
        }
        fn read(&mut self, depth: u32) -> R<Cbor> {
            if depth > 16 || self.i >= self.b.len() {
                return Err(pk_err("Bad CBOR"));
            }
            let (major, info, n) = self.head()?;
            Ok(match major {
                0 => Cbor::Int(i128::from(n)),
                1 => Cbor::Int(-1 - i128::from(n)),
                2 | 3 => {
                    let end = self.i.saturating_add(n as usize);
                    if end > self.b.len() {
                        if major == 2 {
                            return Err(pk_err("Bad CBOR"));
                        }
                        // A text string that runs off the end decodes what there is.
                        let t = String::from_utf8_lossy(&self.b[self.i..]).into_owned();
                        self.i = end;
                        return Ok(Cbor::Text(t));
                    }
                    let v = self.b[self.i..end].to_vec();
                    self.i = end;
                    if major == 2 {
                        Cbor::Bytes(v)
                    } else {
                        Cbor::Text(String::from_utf8_lossy(&v).into_owned())
                    }
                }
                4 => Cbor::Array((0..n).map(|_| self.read(depth + 1)).collect::<R<_>>()?),
                5 => {
                    let mut m = Vec::new();
                    for _ in 0..n {
                        let k = self.read(depth + 1)?;
                        let v = self.read(depth + 1)?;
                        m.push((k, v));
                    }
                    Cbor::Map(m)
                }
                7 => match info {
                    20 => Cbor::Bool(false),
                    21 => Cbor::Bool(true),
                    _ => Cbor::Null,
                },
                _ => return Err(pk_err("Unsupported CBOR")),
            })
        }
    }
    let mut p = P { b: bytes, i: start };
    let v = p.read(0)?;
    Ok((v, p.i))
}

// ---------- authenticator data ----------

struct AuthData {
    rp_id_hash: Vec<u8>,
    flags: u8,
    counter: u32,
    credential_id: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
}

fn parse_auth_data(d: &[u8]) -> R<AuthData> {
    if d.len() < 37 {
        return Err(pk_err("Short authenticator data"));
    }
    let mut out = AuthData {
        rp_id_hash: d[..32].to_vec(),
        flags: d[32],
        counter: u32::from_be_bytes([d[33], d[34], d[35], d[36]]),
        credential_id: None,
        public_key: None,
    };
    if out.flags & 0x40 != 0 {
        let i = 37 + 16;
        let at = |k: usize| d.get(k).copied().unwrap_or(0) as usize;
        let len = (at(i) << 8) | at(i + 1);
        let start = (i + 2).min(d.len());
        let end = (start + len).min(d.len());
        out.credential_id = Some(d[start..end].to_vec());
        let (_, kend) = cbor(d, start + len)?;
        out.public_key = Some(d[start + len..kend.min(d.len())].to_vec());
    }
    Ok(out)
}

const UP: u8 = 0x01;
const BE: u8 = 0x08;
const BS: u8 = 0x10;

// ---------- keys ----------

enum Key {
    Es256(p256::ecdsa::VerifyingKey),
    EdDsa(ed25519_dalek::VerifyingKey),
    Rs256(rsa::RsaPublicKey),
}

fn import_cose(cose: &[u8]) -> R<(Key, i64)> {
    // The right shape but refused by the crypto library: WebCrypto throws its own error there.
    let unsupported = || other("key import failed");
    let (m, _) = cbor(cose, 0)?;
    if !matches!(m, Cbor::Map(_)) {
        return Err(other("not a map"));
    }
    let int = |k: i128| m.get(&Cbor::Int(k)).cloned();
    let (kty, alg) = (int(1), int(3));
    match (kty, alg) {
        (Some(Cbor::Int(2)), Some(Cbor::Int(-7))) if int(-1) == Some(Cbor::Int(1)) => {
            let (x, y) = (
                int(-2)
                    .and_then(|v| v.bytes().map(<[u8]>::to_vec))
                    .ok_or_else(unsupported)?,
                int(-3)
                    .and_then(|v| v.bytes().map(<[u8]>::to_vec))
                    .ok_or_else(unsupported)?,
            );
            if x.len() != 32 || y.len() != 32 {
                return Err(unsupported());
            }
            let mut raw = vec![4u8];
            raw.extend(x);
            raw.extend(y);
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&raw)
                .map(|k| (Key::Es256(k), -7))
                .map_err(|_| unsupported())
        }
        (Some(Cbor::Int(1)), Some(Cbor::Int(-8))) if int(-1) == Some(Cbor::Int(6)) => {
            let x = int(-2)
                .and_then(|v| v.bytes().map(<[u8]>::to_vec))
                .ok_or_else(unsupported)?;
            let x: [u8; 32] = x.try_into().map_err(|_| unsupported())?;
            ed25519_dalek::VerifyingKey::from_bytes(&x)
                .map(|k| (Key::EdDsa(k), -8))
                .map_err(|_| unsupported())
        }
        (Some(Cbor::Int(3)), Some(Cbor::Int(-257))) => {
            let (n, e) = (
                int(-1)
                    .and_then(|v| v.bytes().map(<[u8]>::to_vec))
                    .ok_or_else(unsupported)?,
                int(-2)
                    .and_then(|v| v.bytes().map(<[u8]>::to_vec))
                    .ok_or_else(unsupported)?,
            );
            rsa::RsaPublicKey::new(
                rsa::BigUint::from_bytes_be(&n),
                rsa::BigUint::from_bytes_be(&e),
            )
            .map(|k| (Key::Rs256(k), -257))
            .map_err(|_| unsupported())
        }
        _ => Err(pk_err("That kind of passkey isn't supported.")),
    }
}

/// ECDSA signatures come DER-encoded; r and s, 32 bytes each, are wanted.
fn der_to_raw(der: &[u8]) -> R<[u8; 64]> {
    let bad = || pk_err("Bad signature");
    if der.first() != Some(&0x30) {
        return Err(bad());
    }
    let mut i = 2;
    let mut part = || -> R<[u8; 32]> {
        if der.get(i) != Some(&0x02) {
            return Err(bad());
        }
        let len = *der.get(i + 1).ok_or_else(bad)? as usize;
        i += 2;
        let mut v = &der[i.min(der.len())..(i + len).min(der.len())];
        i += len;
        while v.len() > 32 && v[0] == 0 {
            v = &v[1..];
        }
        if v.len() > 32 {
            return Err(bad());
        }
        let mut out = [0u8; 32];
        out[32 - v.len()..].copy_from_slice(v);
        Ok(out)
    };
    let (r, s) = (part()?, part()?);
    let mut raw = [0u8; 64];
    raw[..32].copy_from_slice(&r);
    raw[32..].copy_from_slice(&s);
    Ok(raw)
}

fn verify_signature(cose: &[u8], sig: &[u8], data: &[u8]) -> R<bool> {
    use p256::ecdsa::signature::Verifier;
    let (key, _) = import_cose(cose)?;
    Ok(match key {
        Key::Es256(k) => p256::ecdsa::Signature::from_slice(&der_to_raw(sig)?)
            .is_ok_and(|s| k.verify(data, &s).is_ok()),
        Key::EdDsa(k) => <[u8; 64]>::try_from(sig).is_ok_and(|s| {
            k.verify_strict(data, &ed25519_dalek::Signature::from_bytes(&s))
                .is_ok()
        }),
        Key::Rs256(k) => {
            let v = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(k);
            rsa::pkcs1v15::Signature::try_from(sig).is_ok_and(|s| v.verify(data, &s).is_ok())
        }
    })
}

// ---------- the browser's side ----------

fn host_of(origin: &str) -> Option<(String, String)> {
    let u = url::Url::parse(origin).ok()?;
    Some((
        u.scheme().to_string(),
        u.host_str()
            .unwrap_or("")
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_lowercase(),
    ))
}

/// Is this an origin a passkey for rp_id may come from?
pub fn origin_fits(origin: &str, rp_id: &str) -> bool {
    let Some((scheme, host)) = host_of(origin) else {
        return false;
    };
    let secure = scheme == "https" || host == "localhost" || host.ends_with(".localhost");
    secure && (host == rp_id || host.ends_with(&format!(".{rp_id}")))
}

/// A safe passkey site name: what the app's page is on, if allowed.
pub fn rp_id_for(origin: &str, allowed: &dyn Fn(&str) -> bool) -> Result<String, PasskeyError> {
    let host = host_of(origin).map(|h| h.1).unwrap_or_default();
    if host.is_empty() || !allowed(&host) {
        return Err(pk_err("Passkeys can't be used from this address."));
    }
    Ok(host)
}

fn client_data(response: &Value, typ: &str, challenge: &str, rp_id: &str) -> R<Vec<u8>> {
    let raw = from_b64url(&text_or_empty(&response["response"]["clientDataJSON"]))
        .ok_or_else(|| other("bad base64url"))?;
    let parsed: Value = serde_json::from_str(&String::from_utf8_lossy(&raw))
        .map_err(|_| pk_err("That passkey's answer couldn't be read."))?;
    let origin = text_or_empty(&parsed["origin"]);
    if parsed["type"] != typ
        || parsed["challenge"] != challenge
        || !origin_fits(&origin, rp_id)
        || parsed["crossOrigin"] == true
    {
        return Err(pk_err("That passkey's answer wasn't for this sign-in."));
    }
    Ok(raw)
}

fn creds(list: &[(String, Value)]) -> Value {
    Value::Array(list.iter().map(|(id, t)| json!({ "type": "public-key", "id": id, "transports": if crate::js::truthy(Some(t)) { t.clone() } else { json!([]) } })).collect())
}

pub fn registration_options(
    rp_id: &str,
    rp_name: &str,
    user_id: &str,
    user_name: &str,
    challenge: &str,
    exclude: &[(String, Value)],
    kind: &str,
) -> Value {
    let mut sel = json!({ "residentKey": "required", "requireResidentKey": true, "userVerification": "preferred" });
    if kind == "device" {
        sel["authenticatorAttachment"] = json!("platform");
    }
    let mut o = json!({
        "challenge": challenge,
        "rp": { "id": rp_id, "name": rp_name },
        "user": { "id": b64url(user_id.as_bytes()), "name": user_name, "displayName": user_name },
        "pubKeyCredParams": ALGS.iter().map(|a| json!({ "type": "public-key", "alg": a })).collect::<Vec<_>>(),
        "timeout": 300_000,
        "attestation": "none",
        "excludeCredentials": creds(exclude),
        "authenticatorSelection": sel,
    });
    if kind == "device" {
        o["hints"] = json!(["client-device"]);
    }
    o["extensions"] = json!({ "credProps": true });
    o
}

pub fn authentication_options(rp_id: &str, challenge: &str, allow: &[(String, Value)]) -> Value {
    json!({ "challenge": challenge, "rpId": rp_id, "timeout": 300_000, "userVerification": "preferred", "allowCredentials": creds(allow) })
}

/// What to store about a new passkey.
pub struct Registered {
    pub credential_id: String,
    pub public_key: String,
    pub alg: i64,
    pub counter: u32,
    pub synced: bool,
    pub transports: Value,
}

pub fn verify_registration(response: &Value, challenge: &str, rp_id: &str) -> R<Registered> {
    client_data(response, "webauthn.create", challenge, rp_id)?;
    let unreadable = || pk_err("That passkey couldn't be read.");
    let att_bytes = from_b64url(&text_or_empty(&response["response"]["attestationObject"]))
        .ok_or_else(unreadable)?;
    let (att, _) = cbor(&att_bytes, 0).map_err(|_| unreadable())?;
    if !matches!(att, Cbor::Map(_)) {
        return Err(other("not a map"));
    }
    let auth_data = att
        .get(&Cbor::Text("authData".into()))
        .and_then(Cbor::bytes)
        .ok_or_else(|| other("no authenticator data"))?;
    let auth = parse_auth_data(auth_data)?;
    if auth.rp_id_hash != sha256(rp_id.as_bytes()) {
        return Err(pk_err("That passkey is for another site."));
    }
    let (Some(cid), Some(pk)) = (auth.credential_id, auth.public_key) else {
        return Err(pk_err("That passkey couldn't be added."));
    };
    if auth.flags & UP == 0 {
        return Err(pk_err("That passkey couldn't be added."));
    }
    let id = b64url(&cid);
    if response["id"] != id.as_str() {
        return Err(pk_err("That passkey's answer didn't match."));
    }
    let (_, alg) = import_cose(&pk)?;
    let transports = match &response["response"]["transports"] {
        Value::Array(a) => Value::Array(
            a.iter()
                .filter(|t| t.is_string())
                .take(6)
                .cloned()
                .collect(),
        ),
        _ => json!([]),
    };
    Ok(Registered {
        credential_id: id,
        public_key: b64url(&pk),
        alg,
        counter: auth.counter,
        synced: auth.flags & BE != 0,
        transports,
    })
}

/// A passkey's answer when signing in: (its new counter, whether it's synced).
pub fn verify_assertion(
    response: &Value,
    challenge: &str,
    rp_id: &str,
    public_key: &str,
    counter: u32,
) -> R<(u32, bool)> {
    let raw = client_data(response, "webauthn.get", challenge, rp_id)?;
    let data = from_b64url(&text_or_empty(&response["response"]["authenticatorData"]))
        .ok_or_else(|| other("bad base64url"))?;
    let auth = parse_auth_data(&data)?;
    if auth.rp_id_hash != sha256(rp_id.as_bytes()) {
        return Err(pk_err("That passkey is for another site."));
    }
    if auth.flags & UP == 0 {
        return Err(pk_err("The passkey prompt wasn't answered."));
    }
    let mut signed = data.clone();
    signed.extend_from_slice(&sha256(&raw));
    // Bad base64url here throws in the JavaScript before the signature check: an underlying error.
    let key = from_b64url(public_key).ok_or_else(|| other("bad base64url"))?;
    let sig = from_b64url(&text_or_empty(&response["response"]["signature"]))
        .ok_or_else(|| other("bad base64url"))?;
    let ok = verify_signature(&key, &sig, &signed).unwrap_or(false);
    if !ok {
        return Err(pk_err("That passkey didn't work. Try again."));
    }
    // A counter that goes backwards means the passkey may have been copied.
    if auth.counter > 0 && counter > 0 && auth.counter <= counter {
        return Err(pk_err(
            "That passkey looks like a copy. Remove it and add it again.",
        ));
    }
    Ok((auth.counter, auth.flags & BS != 0 || auth.flags & BE != 0))
}
