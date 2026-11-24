//! Settings for a self-hosted site, from environment variables, matching `server/config.mjs`.
//! docs/SELF_HOSTING.md lists them all.
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

#[derive(Clone, Debug)]
pub struct SnipForum {
    pub enabled: bool,
    pub repo: String,
    pub token: String,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub port: u16,
    pub bind: String,
    pub site_url: String,
    pub host: String,
    pub secure: bool,
    pub data_dir: PathBuf,
    pub db_file: PathBuf,
    pub files_dir: PathBuf,
    pub dist_dir: PathBuf,
    pub secret: String,
    pub site_name: String,
    pub password_rounds: u32,
    pub default_server_admins: Vec<String>,
    pub snip_forum: SnipForum,
    pub open_registration: bool,
    pub trust_proxy: bool,
    pub update_feed: String,
    pub update_check_hours: f64,
    pub updater_url: String,
    pub updater_token: String,
    /// Experimental opaque transfer staging. Default off. No account imports or cutovers.
    pub experimental_transfer_staging: bool,
    pub federation: bool,
    pub federation_prefix: String,
    pub handle_domain: String,
    pub allow_private_federation: bool,
    pub version: String,
}

fn list(v: Option<&String>) -> Vec<String> {
    v.map(|s| {
        s.split(',')
            .map(|x| x.trim().to_lowercase())
            .filter(|x| !x.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

fn boolean(v: Option<&String>, fallback: bool) -> bool {
    match v.map(String::as_str) {
        None | Some("") => fallback,
        Some(s) => matches!(s.to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
    }
}

fn number(v: Option<&String>) -> Option<f64> {
    v.filter(|s| !s.is_empty())
        .map(|s| crate::js::string_to_number(s))
}

/// The hostname of a URL, lower case (enough of `new URL(...).hostname` for site addresses).
fn hostname(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if authority.starts_with('[') {
        authority
            .split(']')
            .next()
            .map(|h| format!("{h}]"))
            .unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or("").to_string()
    };
    host.to_lowercase()
}

fn valid_prefix(s: &str) -> bool {
    let segs: Vec<&str> = s.split('/').collect();
    s.starts_with('/')
        && (2..=5).contains(&segs.len())
        && segs[1..].iter().all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._~-".contains(&c))
        })
}

/// Where the server's own files are (package.json, and base44/entities when ENTITIES_DIR isn't
/// set): APP_ROOT if given, else the working directory if it holds package.json (as in the Docker
/// image, /app), else the repository this was built from.
pub fn app_root() -> PathBuf {
    if let Some(root) = std::env::var_os("APP_ROOT").filter(|r| !r.is_empty()) {
        return PathBuf::from(root);
    }
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("package.json").is_file() {
            return cwd;
        }
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

impl Config {
    pub fn from_env() -> std::io::Result<Self> {
        Self::load(&std::env::vars().collect(), &app_root())
    }

    /// `env`: the variables; `app_root`: where package.json and dist/ are when not configured.
    pub fn load(env: &HashMap<String, String>, app_root: &Path) -> std::io::Result<Self> {
        let get = |k: &str| env.get(k);
        let data_dir = std::path::absolute(get("DATA_DIR").map_or("./data", String::as_str))?;
        std::fs::create_dir_all(&data_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700));
        }
        // A secret for signing file links and site-to-site requests. Made once and kept with the data.
        let secret_file = data_dir.join("secret");
        let mut secret = get("SECRET").cloned().unwrap_or_default();
        if secret.is_empty() {
            if !secret_file.exists() {
                let mut b = [0u8; 32];
                getrandom::fill(&mut b).expect("system randomness");
                std::fs::write(&secret_file, URL_SAFE_NO_PAD.encode(b))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o600))?;
                }
            }
            secret = std::fs::read_to_string(&secret_file)?.trim().to_string();
        }
        let port_text = get("PORT").cloned().unwrap_or_else(|| "8080".into());
        let site_url = get("SITE_URL")
            .filter(|s| !s.is_empty())
            .cloned()
            .unwrap_or_else(|| format!("http://localhost:{port_text}"))
            .trim_end_matches('/')
            .to_string();
        let host = hostname(&site_url);
        let version = match get("COMMONVEIL_VERSION").filter(|s| !s.is_empty()) {
            Some(v) => v.clone(),
            None => std::fs::read_to_string(app_root.join("package.json"))
                .ok()
                .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
                .and_then(|p| p["version"].as_str().map(String::from))
                .unwrap_or_default(),
        };
        let prefix = get("FEDERATION_PATH_PREFIX").cloned().unwrap_or_default();
        Ok(Self {
            port: number(get("PORT")).unwrap_or(8080.0) as u16,
            bind: get("BIND").filter(|s| !s.is_empty()).cloned().unwrap_or_else(|| "0.0.0.0".into()),
            secure: site_url.starts_with("https://"),
            db_file: data_dir.join("commonveil.db"),
            files_dir: data_dir.join("files"),
            dist_dir: std::path::absolute(get("DIST_DIR").map_or_else(|| app_root.join("dist"), PathBuf::from))?,
            secret,
            site_name: get("SITE_NAME").filter(|s| !s.is_empty()).cloned().unwrap_or_else(|| "Commonveil".into()),
            // PBKDF2 rounds for passwords. Only tests lower it.
            password_rounds: number(get("PASSWORD_ROUNDS")).unwrap_or(600_000.0).max(1000.0) as u32,
            default_server_admins: list(get("DEFAULT_SERVER_ADMINS")),
            snip_forum: SnipForum { enabled: get("SNIP_FORUM").is_some_and(|v| v.to_lowercase() == "on"), repo: get("SNIP_REPO").cloned().unwrap_or_default(), token: get("GITHUB_TOKEN").cloned().unwrap_or_default() },
            open_registration: boolean(get("OPEN_REGISTRATION"), true),
            trust_proxy: boolean(get("TRUST_PROXY"), false),
            update_feed: get("UPDATE_FEED").filter(|s| !s.is_empty()).cloned().unwrap_or_else(|| "https://api.github.com/repos/Comutability/commonveil-rebuild/releases?per_page=20".into()),
            update_check_hours: number(get("UPDATE_CHECK_HOURS")).unwrap_or(6.0).max(1.0),
            updater_url: get("UPDATER_URL").cloned().unwrap_or_default(),
            updater_token: get("UPDATER_TOKEN").cloned().unwrap_or_default(),
            experimental_transfer_staging: boolean(get("EXPERIMENTAL_TRANSFER_STAGING"), false),
            federation: boolean(get("FEDERATION"), true),
            federation_prefix: if valid_prefix(&prefix) { prefix } else { String::new() },
            handle_domain: get("HANDLE_DOMAIN").filter(|s| !s.is_empty()).map_or_else(|| host.clone(), |h| h.to_lowercase()),
            allow_private_federation: boolean(get("FEDERATION_ALLOW_PRIVATE"), false),
            version,
            site_url,
            host,
            data_dir,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = HashMap::new();
        env.insert("DATA_DIR".to_string(), dir.path().display().to_string());
        env.insert(
            "SITE_URL".to_string(),
            "https://Chat.Example.org/".to_string(),
        );
        env.insert(
            "DEFAULT_SERVER_ADMINS".to_string(),
            " Alice, ,bob ".to_string(),
        );
        env.insert("PASSWORD_ROUNDS".to_string(), "10".to_string());
        env.insert("FEDERATION_PATH_PREFIX".to_string(), "/a/b".to_string());
        env.insert("TRUST_PROXY".to_string(), "Yes".to_string());
        env.insert("COMMONVEIL_VERSION".to_string(), "9.9.9".to_string());
        let c = Config::load(&env, dir.path()).unwrap();
        assert_eq!(
            (c.site_url.as_str(), c.host.as_str(), c.secure),
            ("https://Chat.Example.org", "chat.example.org", true)
        );
        assert_eq!(c.default_server_admins, vec!["alice", "bob"]);
        assert_eq!(
            (
                c.password_rounds,
                c.port,
                c.federation_prefix.as_str(),
                c.trust_proxy
            ),
            (1000, 8080, "/a/b", true)
        );
        assert_eq!(
            (
                c.handle_domain.as_str(),
                c.version.as_str(),
                c.open_registration,
                c.federation
            ),
            ("chat.example.org", "9.9.9", true, true)
        );
        let secret = std::fs::read_to_string(dir.path().join("secret")).unwrap();
        assert_eq!(secret.len(), 43);
        assert_eq!(
            Config::load(&env, dir.path()).unwrap().secret,
            secret,
            "made once and kept"
        );
        for bad in ["/a b", "a/b", "/a//b", "/1/2/3/4/5", "/"] {
            env.insert("FEDERATION_PATH_PREFIX".to_string(), bad.to_string());
            assert_eq!(
                Config::load(&env, dir.path()).unwrap().federation_prefix,
                "",
                "{bad}"
            );
        }
    }
}
