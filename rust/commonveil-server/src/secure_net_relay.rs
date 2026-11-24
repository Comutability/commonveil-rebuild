//! Independent actor inbox/outbox reference service for Secure Net CVP-019.
//! This service does not use Commonveil account ids, conversations or rooms.
//! It is a self-hosted, operator-opt-in experimental transport. Do not
//! advertise it as an independently audited general CVP-019 implementation.
use std::path::Path;
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use secure_net_core::bytes::{random_b64u, sha256_b64u};
use secure_net_core::social::actor::verify_actor_document;
use secure_net_core::social::delivery::{envelope_problems, read_delivery_body};
use secure_net_core::social::vocabulary::is_actor_id;
use secure_net_core::wire::federation::{self as wire, RequestFields};
use secure_net_core::wire::sealed;
use serde_json::{json, Value};

pub const MAX_REQUEST: usize = 4 * 1024 * 1024;
const MAX_ITEMS: usize = 100;
const MAX_MAIL_PER_DEVICE: i64 = 500;
const MAX_OUTBOX_PER_ACTOR: i64 = 1000;
const MAIL_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000;
const REPLAY_TTL_MS: i64 = 10 * 60 * 1000;
const MAX_TRUSTED_SITES: i64 = 100;

pub struct RelayError {
    pub status: u16,
    pub code: &'static str,
}
type RelayResult<T> = Result<T, RelayError>;
fn error<T>(status: u16, code: &'static str) -> RelayResult<T> {
    Err(RelayError { status, code })
}
fn internal() -> RelayError {
    RelayError {
        status: 500,
        code: "RELAY_UNAVAILABLE",
    }
}
fn valid_actor_id(v: &Value) -> bool {
    is_actor_id(Some(v))
}
fn strong_token(s: &str) -> bool {
    s.len() >= 32
        && s.len() <= 256
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}
fn valid_device(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        s.len() == 22
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    })
}
fn strict(v: &Value, keys: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|o| o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k)))
}
fn parse_json(raw: &[u8], max: usize) -> RelayResult<Value> {
    if raw.len() > max {
        return error(413, "TOO_LARGE");
    }
    serde_json::from_slice(raw).map_err(|_| RelayError {
        status: 400,
        code: "BAD_JSON",
    })
}
fn from_db<T>(r: rusqlite::Result<T>) -> RelayResult<T> {
    r.map_err(|_| internal())
}

pub struct Relay {
    db: Connection,
    host: String,
}
impl Relay {
    pub fn open(dir: &Path, host: &str) -> RelayResult<Self> {
        if wire::norm_host(host).as_deref() != Some(host) {
            return error(500, "BAD_SITE");
        }
        std::fs::create_dir_all(dir).map_err(|_| internal())?;
        let path = dir.join("secure-net-relay-experimental.sqlite");
        let db = from_db(Connection::open(path))?;
        from_db(db.busy_timeout(Duration::from_secs(6)))?;
        from_db(db.execute_batch(
            "PRAGMA journal_mode=WAL;
           PRAGMA synchronous=FULL;
           PRAGMA foreign_keys=ON;
           CREATE TABLE IF NOT EXISTS actors(
             id TEXT PRIMARY KEY, handle TEXT UNIQUE NOT NULL, seq INTEGER NOT NULL,
             document TEXT NOT NULL, token_hash TEXT UNIQUE NOT NULL
           );
           CREATE TABLE IF NOT EXISTS trusted_sites(
             host TEXT PRIMARY KEY, public_key TEXT NOT NULL,
             relay_kem TEXT NOT NULL, relay_sig TEXT NOT NULL
           );
           CREATE TABLE IF NOT EXISTS mail(
             id TEXT PRIMARY KEY, actor TEXT NOT NULL, device TEXT NOT NULL,
             source_host TEXT NOT NULL, envelope TEXT NOT NULL, created INTEGER NOT NULL,
             expires INTEGER NOT NULL,
             UNIQUE(actor,device,source_host,envelope)
           );
           CREATE INDEX IF NOT EXISTS mail_for_device ON mail(actor,device,created);
           CREATE TABLE IF NOT EXISTS outbox(
             id TEXT PRIMARY KEY, actor TEXT NOT NULL, site TEXT NOT NULL,
             destination TEXT NOT NULL, envelope TEXT NOT NULL, created INTEGER NOT NULL,
             attempts INTEGER NOT NULL DEFAULT 0, next_at INTEGER NOT NULL
           );
           CREATE INDEX IF NOT EXISTS outbox_for_site ON outbox(site,next_at);
           CREATE TABLE IF NOT EXISTS seen_site_nonces(
             host TEXT NOT NULL, nonce TEXT NOT NULL, seen INTEGER NOT NULL,
             PRIMARY KEY(host,nonce)
           );",
        ))?;
        Ok(Self {
            db,
            host: host.to_owned(),
        })
    }
    fn purge(&mut self, now: i64) -> RelayResult<()> {
        from_db(
            self.db
                .execute("DELETE FROM mail WHERE expires < ?1", params![now]),
        )?;
        from_db(self.db.execute(
            "DELETE FROM seen_site_nonces WHERE seen < ?1",
            params![now - REPLAY_TTL_MS],
        ))?;
        Ok(())
    }
    fn admin(&self, token: &str, configured: &str) -> RelayResult<()> {
        if !strong_token(configured) {
            return error(503, "ADMIN_NOT_CONFIGURED");
        }
        if !strong_token(token) {
            return error(401, "UNAUTHORISED");
        }
        let first = secure_net_core::bytes::sha256(token.as_bytes());
        let second = secure_net_core::bytes::sha256(configured.as_bytes());
        if !secure_net_core::bytes::equal_bytes(&first, &second) {
            return error(403, "FORBIDDEN");
        }
        Ok(())
    }
    fn actor_for_token(&self, token: &str) -> RelayResult<String> {
        if !strong_token(token) {
            return error(401, "UNAUTHORISED");
        }
        let digest = sha256_b64u(token.as_bytes());
        let actor = from_db(
            self.db
                .query_row(
                    "SELECT id FROM actors WHERE token_hash=?1",
                    params![digest],
                    |row| row.get::<_, String>(0),
                )
                .optional(),
        )?;
        actor.ok_or(RelayError {
            status: 403,
            code: "FORBIDDEN",
        })
    }
    fn actor_document(&self, id: &str) -> RelayResult<Option<Value>> {
        let stored: Option<String> = from_db(
            self.db
                .query_row(
                    "SELECT document FROM actors WHERE id=?1",
                    params![id],
                    |row| row.get(0),
                )
                .optional(),
        )?;
        Ok(stored.and_then(|text| serde_json::from_str(&text).ok()))
    }
    fn listed_device(&self, actor: &str, device: &str) -> RelayResult<bool> {
        let Some(record) = self.actor_document(actor)? else {
            return Ok(false);
        };
        Ok(record["body"]["devices"]["body"]["devices"]
            .as_array()
            .is_some_and(|list| list.iter().any(|entry| entry["kid"] == device)))
    }
    /// Operator approves a signed independent actor document and issues an
    /// app-specific high-entropy credential. This is *site-local* auth, not
    /// a Secure Net-issued identity or a Commonveil account requirement.
    pub fn register_actor(&mut self, token: &str, admin: &str, body: &Value) -> RelayResult<Value> {
        self.admin(token, admin)?;
        if !strict(body, &["document"]) {
            return error(400, "BAD_REQUEST");
        }
        let record = &body["document"];
        let verified = verify_actor_document(record, None, None, 0).map_err(|_| RelayError {
            status: 400,
            code: "BAD_ACTOR",
        })?;
        let id = verified["id"].as_str().ok_or(RelayError {
            status: 400,
            code: "BAD_ACTOR",
        })?;
        let handle = verified["handle"].as_str().ok_or(RelayError {
            status: 400,
            code: "BAD_ACTOR",
        })?;
        let host = secure_net_core::social::actor::parse_handle(handle).map(|v| v.1);
        if host.as_deref() != Some(self.host.as_str()) {
            return error(400, "WRONG_SITE");
        }
        let seq = verified["seq"].as_i64().ok_or(RelayError {
            status: 400,
            code: "BAD_ACTOR",
        })?;
        let existing: Option<(String, i64)> = from_db(
            self.db
                .query_row(
                    "SELECT id,seq FROM actors WHERE handle=?1",
                    params![handle],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional(),
        )?;
        if let Some((old_id, old_seq)) = existing {
            if old_id != id {
                return error(409, "ACTOR_KEY_CHANGED");
            }
            if seq <= old_seq {
                return error(409, "STALE_ACTOR");
            }
        }
        let bearer = random_b64u(32);
        let digest = sha256_b64u(bearer.as_bytes());
        from_db(self.db.execute(
            "INSERT INTO actors(id,handle,seq,document,token_hash)
             VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(id) DO UPDATE SET seq=excluded.seq,
             document=excluded.document,token_hash=excluded.token_hash",
            params![id, handle, seq, record.to_string(), digest],
        ))?;
        Ok(json!({"actor":id,"handle":handle,"credential":bearer,
             "warning":"Store this site-local credential securely. It is shown only once.",
             "commonveil_account_required":false,"cvp_profile":"experimental"}))
    }
    /// Explicitly pin a trusted peer site and its compulsory hybrid relay
    /// public keys. Unknown and changed sites never receive authorisation.
    pub fn trust_site(&mut self, token: &str, admin: &str, v: &Value) -> RelayResult<Value> {
        self.admin(token, admin)?;
        if !strict(v, &["host", "key", "pq"]) {
            return error(400, "BAD_REQUEST");
        }
        let host = v["host"].as_str().unwrap_or("");
        if host == self.host || wire::norm_host(host).as_deref() != Some(host) {
            return error(400, "BAD_SITE");
        }
        let site_key = v["key"].as_str().unwrap_or("");
        if secure_net_core::bytes::from_b64u(site_key)
            .ok()
            .is_none_or(|raw| raw.len() != 32)
        {
            return error(400, "BAD_SITE_KEY");
        }
        let pq = sealed::relay_keys_of(&json!({"pq":v["pq"]})).ok_or(RelayError {
            status: 400,
            code: "BAD_RELAY_KEY",
        })?;
        let count: i64 = from_db(self.db.query_row(
            "SELECT COUNT(*) FROM trusted_sites",
            [],
            |r| r.get(0),
        ))?;
        if count >= MAX_TRUSTED_SITES {
            return error(409, "SITE_LIMIT");
        }
        let previous: Option<(String, String, String)> = from_db(
            self.db
                .query_row(
                    "SELECT public_key,relay_kem,relay_sig FROM trusted_sites WHERE host=?1",
                    params![host],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional(),
        )?;
        let kem = pq["kem"].as_str().unwrap_or("");
        let sig = pq["sig"].as_str().unwrap_or("");
        if let Some((a, b, c)) = previous {
            if a != site_key || b != kem || c != sig {
                return error(409, "SITE_KEY_CHANGED");
            }
            return Ok(json!({"trusted":true,"duplicate":true,"host":host}));
        }
        from_db(self.db.execute(
            "INSERT INTO trusted_sites(host,public_key,relay_kem,relay_sig) VALUES(?1,?2,?3,?4)",
            params![host, site_key, kem, sig],
        ))?;
        Ok(json!({"trusted":true,"host":host,"duplicate":false}))
    }
    fn trusted(&self, host: &str) -> RelayResult<Option<(String, String, String)>> {
        from_db(
            self.db
                .query_row(
                    "SELECT public_key,relay_kem,relay_sig FROM trusted_sites WHERE host=?1",
                    params![host],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional(),
        )
    }
}
