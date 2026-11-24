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

#[derive(Debug)]
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
           CREATE TABLE IF NOT EXISTS prekeys(
             actor TEXT NOT NULL, device TEXT NOT NULL, published TEXT NOT NULL,
             PRIMARY KEY(actor,device)
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

impl Relay {
    fn canonical_recipient(&self, to: &Value, envelope: &Value) -> RelayResult<(String, String)> {
        if !valid_actor_id(to) {
            return error(400, "BAD_RECIPIENT");
        }
        if !envelope_problems(envelope)
            .map_err(|_| RelayError {
                status: 400,
                code: "BAD_ENVELOPE",
            })?
            .is_empty()
            || envelope["mode"] != "direct"
            || !valid_device(&envelope["device"])
        {
            // Audience, group and public records need separate membership and
            // author verification. Fail closed until supported.
            return error(400, "UNSUPPORTED_ENVELOPE");
        }
        Ok((
            to.as_str().unwrap_or("").to_owned(),
            envelope["device"].as_str().unwrap_or("").to_owned(),
        ))
    }

    /// Outbox is scoped to a *site-local* independent actor token. It never
    /// takes Commonveil login state, legacy federation ids or raw plaintext.
    pub fn outbox(&mut self, token: &str, body: &Value, now: i64) -> RelayResult<Value> {
        let actor = self.actor_for_token(token)?;
        if !strict(body, &["items"]) {
            return error(400, "BAD_REQUEST");
        }
        let items = body["items"].as_array().ok_or(RelayError {
            status: 400,
            code: "BAD_ITEMS",
        })?;
        if items.is_empty() || items.len() > MAX_ITEMS {
            return error(400, "BAD_ITEMS");
        }
        let mut work = Vec::new();
        for item in items {
            if !strict(item, &["host", "to", "envelope"]) {
                return error(400, "BAD_ITEMS");
            }
            let host = item["host"].as_str().unwrap_or("");
            if wire::norm_host(host).as_deref() != Some(host) {
                return error(400, "BAD_SITE");
            }
            let (to, device) = self.canonical_recipient(&item["to"], &item["envelope"])?;
            let local = host == self.host;
            if local {
                if !self.listed_device(&to, &device)? {
                    return error(404, "RECIPIENT_UNAVAILABLE");
                }
            } else if self.trusted(host)?.is_none() {
                return error(403, "UNTRUSTED_SITE");
            }
            work.push((
                host.to_string(),
                to,
                device,
                item["envelope"].to_string(),
                local,
            ));
        }
        self.purge(now)?;
        let tx = from_db(
            self.db
                .transaction_with_behavior(TransactionBehavior::Immediate),
        )?;
        let mut local_count = 0u64;
        let mut remote_count = 0u64;
        for (host, to, device, envelope, local) in work {
            if local {
                let count: i64 = from_db(tx.query_row(
                    "SELECT COUNT(*) FROM mail WHERE actor=?1 AND device=?2",
                    params![to, device],
                    |r| r.get(0),
                ))?;
                if count >= MAX_MAIL_PER_DEVICE {
                    return error(429, "MAILBOX_FULL");
                }
                let id = random_b64u(24);
                let inserted = from_db(tx.execute(
                    "INSERT INTO mail(id,actor,device,source_host,envelope,created,expires)
                     VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT DO NOTHING",
                    params![id, to, device, self.host, envelope, now, now + MAIL_TTL_MS],
                ))?;
                local_count += inserted as u64;
            } else {
                let count: i64 = from_db(tx.query_row(
                    "SELECT COUNT(*) FROM outbox WHERE actor=?1",
                    params![actor],
                    |r| r.get(0),
                ))?;
                if count >= MAX_OUTBOX_PER_ACTOR {
                    return error(429, "OUTBOX_FULL");
                }
                from_db(tx.execute(
                    "INSERT INTO outbox(id,actor,site,destination,envelope,created,next_at)
                     VALUES(?1,?2,?3,?4,?5,?6,?6)",
                    params![random_b64u(24), actor, host, to, envelope, now],
                ))?;
                remote_count += 1;
            }
        }
        from_db(tx.commit())?;
        Ok(
            json!({"accepted":local_count+remote_count,"local_stored":local_count,
          "remote_queued":remote_count,"pending_delivery":remote_count>0,
          "cvp_profile":"experimental","commonveil_account_required":false}),
        )
    }

    pub fn mailbox(&mut self, token: &str, device: &str, now: i64) -> RelayResult<Value> {
        let actor = self.actor_for_token(token)?;
        if !valid_device(&json!(device)) || !self.listed_device(&actor, device)? {
            return error(403, "FORBIDDEN");
        }
        self.purge(now)?;
        let mut statement = from_db(self.db.prepare(
            "SELECT id,source_host,envelope FROM mail
             WHERE actor=?1 AND device=?2 AND expires>=?3
             ORDER BY created,id LIMIT 100",
        ))?;
        let items = from_db(statement.query_map(params![actor, device, now], |r| {
            let id: String = r.get(0)?;
            let source: String = r.get(1)?;
            let body: String = r.get(2)?;
            Ok((id, source, body))
        }))?;
        let mut out = Vec::new();
        for entry in items {
            let (id, from, envelope) = entry.map_err(|_| internal())?;
            let parsed: Value = serde_json::from_str(&envelope).map_err(|_| internal())?;
            out.push(json!({"id":id,"from":from,"envelope":parsed}));
        }
        Ok(json!({"actor":actor,"device":device,"items":out,"cvp_profile":"experimental"}))
    }

    pub fn acknowledge(&mut self, token: &str, body: &Value) -> RelayResult<Value> {
        let actor = self.actor_for_token(token)?;
        if !strict(body, &["device", "ids"]) || !valid_device(&body["device"]) {
            return error(400, "BAD_REQUEST");
        }
        let device = body["device"].as_str().unwrap_or("");
        if !self.listed_device(&actor, device)? {
            return error(403, "FORBIDDEN");
        }
        let ids = body["ids"].as_array().ok_or(RelayError {
            status: 400,
            code: "BAD_IDS",
        })?;
        if ids.len() > 100
            || ids.iter().any(|v| {
                v.as_str().is_none_or(|s| {
                    !(16..=64).contains(&s.len())
                        || !s
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
                })
            })
        {
            return error(400, "BAD_IDS");
        }
        let tx = from_db(
            self.db
                .transaction_with_behavior(TransactionBehavior::Immediate),
        )?;
        let mut deleted = 0usize;
        for id in ids {
            deleted += from_db(tx.execute(
                "DELETE FROM mail WHERE id=?1 AND actor=?2 AND device=?3",
                params![id.as_str().unwrap_or(""), actor, device],
            ))?;
        }
        from_db(tx.commit())?;
        Ok(json!({"acknowledged":deleted}))
    }

    fn authenticate_delivery(
        &mut self,
        headers: &std::collections::HashMap<String, String>,
        raw: &[u8],
        now: i64,
        relay_secret: &str,
    ) -> RelayResult<(String, Vec<Value>, Vec<u8>, String)> {
        let get = |key: &str| headers.get(key).map(String::as_str).unwrap_or("");
        let from = get("cv-from");
        if from == self.host || wire::norm_host(from).as_deref() != Some(from) {
            return error(403, "UNTRUSTED_SITE");
        }
        let (key, pq_kem, pq_sig) = self.trusted(from)?.ok_or(RelayError {
            status: 403,
            code: "UNTRUSTED_SITE",
        })?;
        let nonce = get("cv-nonce");
        if nonce.len() < 16
            || nonce.len() > 64
            || !nonce
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            return error(401, "BAD_NONCE");
        }
        if !wire::fresh_enough(get("cv-date"), now) {
            return error(401, "STALE");
        }
        if get("cv-digest") != wire::digest_of(raw) {
            return error(401, "BAD_DIGEST");
        }
        let transcript = wire::signature_base(&RequestFields {
            method: "POST",
            to: &self.host,
            path: "/cvp/v2/deliver",
            from,
            date: get("cv-date"),
            nonce,
            digest: get("cv-digest"),
            user: "",
        });
        if !wire::verify_request(
            &RequestFields {
                method: "POST",
                to: &self.host,
                path: "/cvp/v2/deliver",
                from,
                date: get("cv-date"),
                nonce,
                digest: get("cv-digest"),
                user: "",
            },
            get("cv-signature"),
            &key,
        ) || !sealed::verify(&pq_sig, &transcript, get("cv-pq-signature"))
        {
            return error(401, "BAD_SIGNATURE");
        }
        if get("cv-sealed") != "1" {
            return error(401, "UNSEALED");
        }
        let outer: Value = serde_json::from_slice(raw).map_err(|_| RelayError {
            status: 400,
            code: "BAD_BODY",
        })?;
        if !strict(&outer, &["sealed"]) || pq_kem.is_empty() {
            return error(400, "BAD_BODY");
        }
        let context = sealed::relay_context(from, &self.host, "/cvp/v2/deliver");
        let (clear, reply_key) = sealed::open(
            relay_secret,
            outer["sealed"].as_str().unwrap_or(""),
            &context,
        )
        .map_err(|_| RelayError {
            status: 400,
            code: "CANNOT_OPEN",
        })?;
        let inner: Value = serde_json::from_str(&clear).map_err(|_| RelayError {
            status: 400,
            code: "BAD_BODY",
        })?;
        if !strict(&inner, &["v", "items"]) {
            return error(400, "BAD_BODY");
        }
        let items = read_delivery_body(&inner).map_err(|_| RelayError {
            status: 400,
            code: "BAD_DELIVERY",
        })?;
        Ok((from.to_string(), items, reply_key, context))
    }

    /// All-or-nothing verified site delivery and persisted nonce consumption.
    pub fn deliver(
        &mut self,
        headers: &std::collections::HashMap<String, String>,
        raw: &[u8],
        now: i64,
        relay_secret: &str,
    ) -> RelayResult<Value> {
        if raw.len() > MAX_REQUEST {
            return error(413, "TOO_LARGE");
        }
        let (from, items, reply_key, context) =
            self.authenticate_delivery(headers, raw, now, relay_secret)?;
        self.purge(now)?;
        let nonce = headers.get("cv-nonce").ok_or(RelayError {
            status: 401,
            code: "BAD_NONCE",
        })?;
        // Validate the *entire* delivery before writing anything.
        let mut destinations = Vec::new();
        for item in items {
            let (to, device) = self.canonical_recipient(&item["to"], &item["envelope"])?;
            if self.listed_device(&to, &device)? {
                destinations.push((to, device, item["envelope"].to_string()));
            }
        }
        let tx = from_db(
            self.db
                .transaction_with_behavior(TransactionBehavior::Immediate),
        )?;
        let seen: Option<i64> = from_db(
            tx.query_row(
                "SELECT seen FROM seen_site_nonces WHERE host=?1 AND nonce=?2",
                params![from, nonce],
                |r| r.get(0),
            )
            .optional(),
        )?;
        if seen.is_some() {
            return error(409, "REPLAY");
        }
        let mut stored = 0usize;
        for (to, device, envelope) in destinations {
            let count: i64 = from_db(tx.query_row(
                "SELECT COUNT(*) FROM mail WHERE actor=?1 AND device=?2",
                params![to, device],
                |r| r.get(0),
            ))?;
            if count >= MAX_MAIL_PER_DEVICE {
                return error(429, "MAILBOX_FULL");
            }
            stored += from_db(tx.execute(
                "INSERT INTO mail(id,actor,device,source_host,envelope,created,expires)
                 VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT DO NOTHING",
                params![
                    random_b64u(24),
                    to,
                    device,
                    from,
                    envelope,
                    now,
                    now + MAIL_TTL_MS
                ],
            ))?;
        }
        from_db(tx.execute(
            "INSERT INTO seen_site_nonces(host,nonce,seen) VALUES(?1,?2,?3)",
            params![from, nonce, now],
        ))?;
        from_db(tx.commit())?;
        let reply = sealed::seal_reply(
            &reply_key,
            &json!({"ok":true,"stored":stored}).to_string(),
            &context,
        )
        .map_err(|_| internal())?;
        Ok(json!({"sealed":reply}))
    }

    /// The sending site explicitly drains its durable remote outbox. A failed
    /// remote reply leaves the queued delivery untouched for a later retry.
    pub fn pending(
        &self,
        token: &str,
        admin: &str,
        now: i64,
    ) -> RelayResult<Vec<(String, String, String, String)>> {
        self.admin(token, admin)?;
        let mut stmt = from_db(self.db.prepare(
            "SELECT id,site,destination,envelope FROM outbox WHERE next_at<=?1
             ORDER BY created,id LIMIT 20",
        ))?;
        let rows = from_db(stmt.query_map(params![now], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        }))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|_| internal())?)
        }
        Ok(out)
    }
    pub fn mark_sent(&mut self, token: &str, admin: &str, id: &str) -> RelayResult<()> {
        self.admin(token, admin)?;
        from_db(
            self.db
                .execute("DELETE FROM outbox WHERE id=?1", params![id]),
        )?;
        Ok(())
    }
    pub fn delay(&mut self, token: &str, admin: &str, id: &str, now: i64) -> RelayResult<()> {
        self.admin(token, admin)?;
        from_db(self.db.execute(
            "UPDATE outbox SET attempts=attempts+1,next_at=?2 WHERE id=?1",
            params![id, now + 60_000],
        ))?;
        Ok(())
    }
    pub fn peer_kem(&self, host: &str) -> RelayResult<String> {
        self.trusted(host)?.map(|x| x.1).ok_or(RelayError {
            status: 403,
            code: "UNTRUSTED_SITE",
        })
    }

    pub fn actors(&self) -> RelayResult<Value> {
        let mut stmt = from_db(
            self.db
                .prepare("SELECT document FROM actors ORDER BY handle LIMIT 100"),
        )?;
        let rows = from_db(stmt.query_map([], |r| r.get::<_, String>(0)))?;
        let mut records = Vec::new();
        for row in rows {
            let text = row.map_err(|_| internal())?;
            records.push(serde_json::from_str::<Value>(&text).map_err(|_| internal())?);
        }
        Ok(json!({"actors":records,"cvp_profile":"experimental"}))
    }
}

impl Relay {
    /// An app publishes public device prekeys only with its site-local actor credential.
    /// Device and account signatures are verified before they become discoverable.
    pub fn publish_prekeys(&mut self, token: &str, body: &Value, now: i64) -> RelayResult<Value> {
        use secure_net_core::session::keys::verify_bundle;
        let actor = self.actor_for_token(token)?;
        if !strict(body, &["device", "published"]) || !valid_device(&body["device"]) {
            return error(400, "BAD_PREKEYS");
        }
        let device = body["device"].as_str().unwrap_or("");
        if !self.listed_device(&actor, device)? {
            return error(403, "FORBIDDEN");
        }
        let p = &body["published"];
        if !strict(p, &["signed", "lastResort", "oneTime", "pqOneTime"]) {
            return error(400, "BAD_PREKEYS");
        }
        let one = p["oneTime"].as_array().ok_or(RelayError {
            status: 400,
            code: "BAD_PREKEYS",
        })?;
        let pq = p["pqOneTime"].as_array().ok_or(RelayError {
            status: 400,
            code: "BAD_PREKEYS",
        })?;
        if one.len() > 50 || pq.len() > 50 {
            return error(413, "TOO_MANY_PREKEYS");
        }
        let doc = self.actor_document(&actor)?.ok_or(RelayError {
            status: 403,
            code: "FORBIDDEN",
        })?;
        let account = doc["body"]["account"].as_str().unwrap_or("");
        let list = &doc["body"]["devices"];
        for (dh, pq_key) in std::iter::once((&Value::Null, &p["lastResort"]))
            .chain(one.iter().map(|dh| (dh, &p["lastResort"])))
            .chain(pq.iter().map(|pq_key| (&Value::Null, pq_key)))
        {
            let bundle = json!({"deviceList":list,"device":device,"signed":p["signed"],
                "pq":pq_key,"oneTime":dh});
            verify_bundle(&bundle, account, 0, now).map_err(|_| RelayError {
                status: 400,
                code: "BAD_PREKEYS",
            })?;
        }
        let existed: Option<i64> = from_db(
            self.db
                .query_row(
                    "SELECT 1 FROM prekeys WHERE actor=?1 AND device=?2",
                    params![actor, device],
                    |r| r.get(0),
                )
                .optional(),
        )?;
        if existed.is_some() {
            return error(409, "PREKEYS_ALREADY_PUBLISHED");
        }
        from_db(self.db.execute(
            "INSERT INTO prekeys(actor,device,published) VALUES(?1,?2,?3)",
            params![actor, device, p.to_string()],
        ))?;
        Ok(json!({"published":true,"private_keys_stored":false,
          "one_time_keys":one.len(),"post_quantum_one_time_keys":pq.len()}))
    }
    /// Atomically consumes X25519 and ML-KEM one-time prekeys; the last-resort
    /// public prekey remains available for future first-contact handshakes.
    pub fn take_prekey_bundle(
        &mut self,
        actor: &str,
        device: &str,
        now: i64,
    ) -> RelayResult<Value> {
        use secure_net_core::session::keys::{take_bundle, verify_bundle, Published};
        if !valid_actor_id(&json!(actor)) || !valid_device(&json!(device)) {
            return error(404, "NOT_FOUND");
        }
        let doc = self.actor_document(actor)?.ok_or(RelayError {
            status: 404,
            code: "NOT_FOUND",
        })?;
        if !self.listed_device(actor, device)? {
            return error(404, "NOT_FOUND");
        }
        let tx = from_db(
            self.db
                .transaction_with_behavior(TransactionBehavior::Immediate),
        )?;
        let stored: Option<String> = from_db(
            tx.query_row(
                "SELECT published FROM prekeys WHERE actor=?1 AND device=?2",
                params![actor, device],
                |r| r.get(0),
            )
            .optional(),
        )?;
        let Some(stored) = stored else {
            return error(404, "NO_PREKEYS");
        };
        let mut prekeys: Published = serde_json::from_str(&stored).map_err(|_| internal())?;
        let bundle = take_bundle(&doc["body"]["devices"], &mut prekeys, device);
        verify_bundle(
            &bundle,
            doc["body"]["account"].as_str().unwrap_or(""),
            0,
            now,
        )
        .map_err(|_| RelayError {
            status: 409,
            code: "PREKEYS_EXPIRED",
        })?;
        from_db(tx.execute(
            "UPDATE prekeys SET published=?3 WHERE actor=?1 AND device=?2",
            params![
                actor,
                device,
                serde_json::to_string(&prekeys).map_err(|_| internal())?
            ],
        ))?;
        from_db(tx.commit())?;
        Ok(bundle)
    }
    pub fn public_actor(&self, id: &str) -> RelayResult<Value> {
        if !valid_actor_id(&json!(id)) {
            return error(404, "NOT_FOUND");
        }
        let doc = self.actor_document(id)?.ok_or(RelayError {
            status: 404,
            code: "NOT_FOUND",
        })?;
        if doc["body"]["discoverable"] != true {
            return error(404, "NOT_FOUND");
        }
        Ok(doc)
    }
}

/// The public relay trial document is *not* /.well-known/secure-net, which
/// remains a community SNIP-0008 proposal. Only manually trusted sites can
/// send transport to this experimental service.
pub fn public_trial_site(app: &crate::App) -> RelayResult<Value> {
    let keys = app
        .federation
        .signer
        .relay_doc(&app.store)
        .map_err(|_| internal())?;
    Ok(json!({
       "protocol":"secure-net",
       "profile":"experimental-direct-only",
       "production_conformance":false,
       "site":app.federation.host,
       "key":{"public":app.federation.signer.key.public},
       "pq":keys,
       "endpoints":{
          "outbox":"/cvp/v2/outbox",
          "deliver":"/cvp/v2/deliver",
          "mailbox":"/cvp/v2/mailbox"
       },
       "features_advertised":[],
       "manually_pin_peer_keys":true,
       "legacy_commonveil_federation_separate":true
    }))
}

/// Apply site-level federation bans to the separate experimental Secure Net
/// transport too; otherwise a CVP-019 feature could bypass operator choices.
fn guard_operator_site_policy(app: &crate::App, host: &str) -> RelayResult<()> {
    if host == app.federation.host {
        return Ok(());
    }
    let verdict = crate::site_policy::decision(&app.store, host).map_err(|_| RelayError {
        status: 503,
        code: "SITE_POLICY_UNAVAILABLE",
    })?;
    if verdict == "suspend" {
        return error(403, "SITE_BLOCKED");
    }
    Ok(())
}

/// A controlled queue drain. A source site signs and PQ-seals each outbound
/// envelope to an independently pinned receiving site. One successful
/// authenticated encrypted acknowledgement removes one queued item.
fn flush_queued(app: &crate::App, relay: &mut Relay, auth: &str) -> RelayResult<Value> {
    let admin = &app.config.secure_net_relay_admin;
    let work = relay.pending(auth, admin, crate::sessions::now_ms())?;
    let mut delivered = 0usize;
    let mut failed = 0usize;
    for (id, host, to, envelope) in work {
        // Do not transmit already queued mail when an admin blocks a remote
        // host. Keep the ciphertext safely queued for a later policy choice.
        if guard_operator_site_policy(app, &host).is_err() {
            relay.delay(auth, admin, &id, crate::sessions::now_ms())?;
            failed += 1;
            continue;
        }
        let kem = relay.peer_kem(&host)?;
        let value: Value = serde_json::from_str(&envelope).map_err(|_| internal())?;
        let body = json!({"v":1,"items":[{"to":to,"envelope":value}]}).to_string();
        let context = sealed::relay_context(&relay.host, &host, "/cvp/v2/deliver");
        let Ok((ciphertext, reply_key)) = sealed::seal(&kem, &body, &context) else {
            relay.delay(auth, admin, &id, crate::sessions::now_ms())?;
            failed += 1;
            continue;
        };
        let raw = json!({"sealed":ciphertext}).to_string();
        let mut headers = app
            .federation
            .signer
            .headers(&app.store, "POST", &host, "/cvp/v2/deliver", &raw, None)
            .map_err(|_| internal())?;
        headers.push(("Content-Type".into(), "application/json".into()));
        headers.push(("CV-Sealed".into(), "1".into()));
        let res = app.federation.signer.transport.request(
            &host,
            "/cvp/v2/deliver",
            "POST",
            &headers,
            Some(&raw),
        );
        let accepted = res
            .ok()
            .filter(|r| r.status == 200)
            .and_then(|r| r.data["sealed"].as_str().map(ToOwned::to_owned))
            .and_then(|sealed_reply| sealed::open_reply(&reply_key, &sealed_reply, &context).ok())
            .and_then(|clear| serde_json::from_str::<Value>(&clear).ok())
            .is_some_and(|v| v["ok"] == true);
        if accepted {
            relay.mark_sent(auth, admin, &id)?;
            delivered += 1;
        } else {
            relay.delay(auth, admin, &id, crate::sessions::now_ms())?;
            failed += 1;
        }
    }
    Ok(json!({"delivered":delivered,"failed_or_pending":failed,
      "cvp_profile":"experimental","complete_interoperability":false}))
}

/// Route only the new exact experimental CVP-019 endpoint family. This code
/// never intercepts Commonveil's existing /cvp/v1/ federation and does not
/// modify application message records or attempt encrypted history migration.
pub async fn handle(
    app: std::sync::Arc<crate::App>,
    req: axum::extract::Request,
) -> axum::http::Response<axum::body::Body> {
    let method = req.method().as_str().to_owned();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();
    let bearer = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_owned();
    let headers: std::collections::HashMap<String, String> = req
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_owned(), v.to_owned()))
        })
        .collect();
    let raw = match axum::body::to_bytes(req.into_body(), MAX_REQUEST + 1).await {
        Ok(raw) => raw,
        Err(_) => return crate::http::json(413, &json!({"code":"TOO_LARGE"})),
    };
    let answer = tokio::task::spawn_blocking(move || {
        let mut service = Relay::open(&app.config.data_dir, &app.federation.host)?;
        let now = crate::sessions::now_ms();
        match (method.as_str(), path.as_str()) {
            ("GET", "/cvp/v2/relay/site") => public_trial_site(&app),
            ("POST", "/cvp/v2/relay/admin/actors") => {
                let body = parse_json(&raw, MAX_REQUEST)?;
                service.register_actor(&bearer, &app.config.secure_net_relay_admin, &body)
            }
            ("POST", "/cvp/v2/relay/admin/trust") => {
                let body = parse_json(&raw, MAX_REQUEST)?;
                service.trust_site(&bearer, &app.config.secure_net_relay_admin, &body)
            }
            ("POST", "/cvp/v2/prekeys") => {
                let body = parse_json(&raw, MAX_REQUEST)?;
                service.publish_prekeys(&bearer, &body, now)
            }
            ("POST", "/cvp/v2/outbox") => {
                let body = parse_json(&raw, MAX_REQUEST)?;
                for item in body["items"].as_array().into_iter().flatten() {
                    let host = item["host"].as_str().unwrap_or("");
                    guard_operator_site_policy(&app, host)?;
                }
                service.outbox(&bearer, &body, now)
            }
            ("GET", "/cvp/v2/mailbox") => {
                let value = query
                    .split('&')
                    .find_map(|part| part.strip_prefix("device="))
                    .unwrap_or("");
                service.mailbox(&bearer, value, now)
            }
            ("POST", "/cvp/v2/mailbox/ack") => {
                let body = parse_json(&raw, 32 * 1024)?;
                service.acknowledge(&bearer, &body)
            }
            ("POST", "/cvp/v2/deliver") => {
                guard_operator_site_policy(
                    &app,
                    headers.get("cv-from").map(String::as_str).unwrap_or(""),
                )?;
                let relay = app
                    .federation
                    .signer
                    .relay_keys(&app.store)
                    .map_err(|_| internal())?;
                service.deliver(
                    &headers,
                    &raw,
                    now,
                    relay["kem"]["secret"].as_str().unwrap_or(""),
                )
            }
            ("POST", "/cvp/v2/outbox/flush") => flush_queued(&app, &mut service, &bearer),
            _ if method == "GET" && path.starts_with("/cvp/v2/prekeys/") => {
                let suffix = path.trim_start_matches("/cvp/v2/prekeys/");
                let Some((actor, device)) = suffix.split_once('/') else {
                    return error(404, "NOT_FOUND");
                };
                service.take_prekey_bundle(actor, device, now)
            }
            _ if method == "GET" && path.starts_with("/cvp/v2/actor/") => {
                service.public_actor(path.trim_start_matches("/cvp/v2/actor/"))
            }
            _ => error(404, "NOT_FOUND"),
        }
    })
    .await;
    match answer {
        Ok(Ok(body)) => crate::http::json(200, &body),
        Ok(Err(e)) => crate::http::json(e.status, &json!({"code":e.code})),
        Err(_) => crate::http::json(500, &json!({"code":"RELAY_UNAVAILABLE"})),
    }
}
