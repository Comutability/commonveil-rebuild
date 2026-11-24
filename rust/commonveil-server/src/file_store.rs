//! Private file storage for a self-hosted site (server/files.mjs). Files are already end-to-end
//! encrypted parts when they arrive; this keeps them on disk and hands out short-lived signed
//! links, like Base44's UploadPrivateFile and CreateFileSignedUrl.
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

#[derive(Clone)]
pub struct FileStore {
    dir: PathBuf,
    secret: String,
    site_url: String,
}

fn hex_name(s: &str) -> bool {
    s.len() == 48 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The name inside `private://<48 hex>`.
fn name_of(uri: &str) -> Option<&str> {
    uri.strip_prefix("private://").filter(|n| hex_name(n))
}

impl FileStore {
    pub fn new(dir: &Path, secret: &str, site_url: &str) -> Self {
        let _ = std::fs::create_dir_all(dir);
        set_mode(dir, 0o700);
        Self {
            dir: dir.to_path_buf(),
            secret: secret.to_string(),
            site_url: site_url.to_string(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(&name[..2]).join(name)
    }

    fn sign(&self, name: &str, exp: &str) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.secret.as_bytes()).expect("any key length");
        mac.update(format!("file:{name}:{exp}").as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    /// Store a file; returns its `private://` uri.
    pub fn upload(&self, bytes: &[u8]) -> std::io::Result<String> {
        let name: String = crate::crypto::random_bytes(24)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let p = self.path(&name);
        let parent = p.parent().expect("has a folder");
        std::fs::create_dir_all(parent)?;
        set_mode(parent, 0o700);
        std::fs::write(&p, bytes)?;
        set_mode(&p, 0o600);
        Ok(format!("private://{name}"))
    }

    /// A link that works for `expires_in` seconds (10 to 3600, 300 if not given).
    pub fn signed_url(&self, uri: &str, expires_in: f64, now_ms: i64) -> Option<String> {
        let name = name_of(uri)?;
        let wanted = if expires_in.is_nan() || expires_in == 0.0 {
            300.0
        } else {
            expires_in
        };
        let exp = (now_ms as f64 / 1000.0).floor() as i64 + wanted.clamp(10.0, 3600.0) as i64;
        let exp = exp.to_string();
        Some(format!(
            "{}/api/files/{name}?exp={exp}&sig={}",
            self.site_url,
            self.sign(name, &exp)
        ))
    }

    /// The file for a signed link, or None if the link is wrong or has run out.
    pub fn open(&self, name: &str, exp: &str, sig: &str, now_ms: i64) -> Option<PathBuf> {
        if !hex_name(name)
            || exp.is_empty()
            || exp.len() > 12
            || !exp.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        if (exp.parse::<i64>().ok()? as f64) < now_ms as f64 / 1000.0 {
            return None;
        }
        let want = self.sign(name, exp);
        if want.len() != sig.len() || !subtle_eq(want.as_bytes(), sig.as_bytes()) {
            return None;
        }
        let p = self.path(name);
        p.exists().then_some(p)
    }

    pub fn remove(&self, uri: &str) {
        if let Some(name) = name_of(uri) {
            let _ = std::fs::remove_file(self.path(name));
        }
    }
}

/// Constant-time comparison of two equal-length byte strings.
fn subtle_eq(a: &[u8], b: &[u8]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(unix)]
fn set_mode(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode));
}
#[cfg(not(unix))]
fn set_mode(_: &Path, _: u32) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_open_only_while_valid() {
        let dir = tempfile::tempdir().unwrap();
        let fs = FileStore::new(dir.path(), "secret", "https://example.org");
        let uri = fs.upload(b"ciphertext").unwrap();
        let now = 1_700_000_000_000;
        let url = fs.signed_url(&uri, 60.0, now).unwrap();
        let q = url.split("/api/files/").nth(1).unwrap();
        let (name, rest) = q.split_once('?').unwrap();
        let exp = rest.split('&').next().unwrap().trim_start_matches("exp=");
        let sig = rest.split("&sig=").nth(1).unwrap();
        assert!(fs.open(name, exp, sig, now).is_some());
        assert!(fs.open(name, exp, sig, now + 61_000).is_none());
        assert!(fs.open(name, exp, "x", now).is_none());
        assert!(fs
            .open(
                name,
                &(exp.parse::<i64>().unwrap() + 1).to_string(),
                sig,
                now
            )
            .is_none());
        fs.remove(&uri);
        assert!(fs.open(name, exp, sig, now).is_none());
        assert!(fs.signed_url("private://nope", 60.0, now).is_none());
    }
}
