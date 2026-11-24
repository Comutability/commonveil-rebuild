//! Small cryptographic helpers for Commonveil sign-in, matching base44/shared/identity/crypto.ts.
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Like the JavaScript: only `[A-Za-z0-9_-]`, padding optional; a length that leaves one spare
/// character is refused (as `atob` refuses it).
pub fn from_b64url(s: &str) -> Option<Vec<u8>> {
    if !s
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        || s.len() % 4 == 1
    {
        return None;
    }
    // atob ignores stray low bits in the last character; the strict decoder doesn't. Clear them.
    let mut t = s.to_string();
    let rem = s.len() % 4;
    if rem != 0 {
        const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let last = t.pop().unwrap();
        let v = ALPHA.iter().position(|&c| c == last as u8).unwrap();
        let keep = if rem == 2 { v & 0b110000 } else { v & 0b111100 };
        t.push(ALPHA[keep] as char);
    }
    base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    )
    .decode(t)
    .ok()
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).expect("system randomness");
    b
}

pub fn random_token(bytes: usize) -> String {
    b64url(&random_bytes(bytes))
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn sha256_hex(text: &str) -> String {
    sha256(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Constant-time comparison of two strings (by UTF-16 code unit, as the JavaScript compares).
pub fn same_string(a: &str, b: &str) -> bool {
    let (x, y): (Vec<u16>, Vec<u16>) = (a.encode_utf16().collect(), b.encode_utf16().collect());
    if x.len() != y.len() {
        return false;
    }
    x.iter().zip(&y).fold(0u16, |d, (p, q)| d | (p ^ q)) == 0
}

pub fn hmac(secret: &str, text: &str) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("any key length");
    m.update(text.as_bytes());
    b64url(&m.finalize().into_bytes())
}

// ---------- passwords ----------

/// PBKDF2-SHA256, 600,000 rounds, 16-byte salt, 32-byte key.
pub const PASSWORD_ROUNDS: u32 = 600_000;
/// The JavaScript spreads the rounds over calls of at most 100,000, each feeding the next; a hash
/// made that way ends in "$2". The same chain is computed here, so hashes move between the two.
const ROUNDS_PER_CALL: u32 = 100_000;

fn derive(material: &[u8], salt: &[u8], rounds: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(material, salt, rounds, &mut out);
    out
}

fn pbkdf2_chain(password: &str, salt: &[u8], rounds: u32) -> [u8; 32] {
    let runs = rounds.div_ceil(ROUNDS_PER_CALL).max(1);
    let each = rounds.div_ceil(runs);
    let mut material: Vec<u8> = password.nfkc().collect::<String>().into_bytes();
    let mut out = [0u8; 32];
    for _ in 0..runs {
        out = derive(&material, salt, each);
        material = out.to_vec();
    }
    out
}

pub fn hash_password(password: &str, rounds: u32) -> String {
    let salt = random_bytes(16);
    format!(
        "pbkdf2-sha256${rounds}${}${}$2",
        b64url(&salt),
        b64url(&pbkdf2_chain(password, &salt, rounds))
    )
}

pub fn check_password(password: &str, stored: &str) -> bool {
    let parts: Vec<&str> = stored.split('$').collect();
    let get = |i: usize| parts.get(i).copied().unwrap_or("");
    let count = crate::js::string_to_number(get(1));
    if get(0) != "pbkdf2-sha256" || !(count.is_finite() && count != 0.0 && !count.is_nan()) {
        // Spend the same time on a missing or unusable hash.
        let _ = pbkdf2_chain(password, &[0u8; 16], PASSWORD_ROUNDS);
        return false;
    }
    // A negative or fractional count can't be derived (WebCrypto refuses it too).
    if count < 1.0 || count.fract() != 0.0 || count > f64::from(u32::MAX) {
        return false;
    }
    let Some(salt) = from_b64url(get(2)) else {
        return false;
    };
    let got = if get(4) == "2" {
        b64url(&pbkdf2_chain(password, &salt, count as u32))
    } else {
        // An older single-call hash: the server runs on Node.js, which allows any round count.
        b64url(&derive(
            password.nfkc().collect::<String>().as_bytes(),
            &salt,
            count as u32,
        ))
    };
    same_string(&got, get(3))
}

// ---------- signatures ----------

/// Ed25519: a 32-byte public key and a 64-byte signature, both base64url.
pub fn verify_ed25519(public_key: &str, text: &str, signature: &str) -> bool {
    let (Some(k), Some(s)) = (from_b64url(public_key), from_b64url(signature)) else {
        return false;
    };
    let (Ok(k), Ok(s)) = (<[u8; 32]>::try_from(k), <[u8; 64]>::try_from(s)) else {
        return false;
    };
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&k) else {
        return false;
    };
    key.verify_strict(text.as_bytes(), &ed25519_dalek::Signature::from_bytes(&s))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_round_trip_and_refuse() {
        let h = hash_password("correct horse", 1000);
        assert!(h.starts_with("pbkdf2-sha256$1000$") && h.ends_with("$2"));
        assert!(check_password("correct horse", &h));
        assert!(!check_password("correct horsf", &h));
        assert!(!check_password("x", "") && !check_password("x", "bcrypt$1$a$b"));
        assert!(
            check_password("ﬁ", &hash_password("fi", 1000)),
            "NFKC: the ligature is the two letters"
        );
    }

    #[test]
    fn base64url_reads_like_atob() {
        assert_eq!(from_b64url("AQID").unwrap(), vec![1, 2, 3]);
        assert_eq!(from_b64url("AQI").unwrap(), vec![1, 2]);
        assert!(from_b64url("A").is_none() && from_b64url("AQ+D").is_none());
        assert_eq!(
            from_b64url("AR").unwrap(),
            vec![1],
            "stray low bits are ignored, as atob ignores them"
        );
        assert!(
            same_string("abc", "abc") && !same_string("abc", "abd") && !same_string("ab", "abc")
        );
    }
}
