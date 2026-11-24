//! SNIP-0007 experimental **destination ciphertext staging only**.
//!
//! No identity creation, account binding, mailbox redirection, private key escrow,
//! decryption or import is performed here. Commonveil is just one possible client.
//!
//! This implementation is disabled by default, even on self-hosted sites. It is not
//! advertised as CVP transfer support and must not be exposed as production-ready
//! before independent review, encrypted client importer and interop tests.
use std::path::Path;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use secure_net_core::bytes::{from_b64u, random_b64u, sha256, sha256_b64u};
use secure_net_core::signed::{key_id, verify};
use secure_net_core::transfer::{
    ciphertext_root as protocol_ciphertext_root,
    encrypted_report_digest as protocol_encrypted_report_digest,
    verify_intent as protocol_verify_intent,
    verify_recipient_grant as protocol_verify_recipient_grant,
    verify_reconciliation as protocol_verify_reconciliation, Chunk as ProtocolChunk,
    ExpectedRecipient, ExpectedReconciliation, MAX_REPORT_BYTES,
};
use secure_net_core::wire::federation::norm_host;
use serde_json::{json, Value};

pub const MAX_CHUNK: usize = 256 * 1024;
const MAX_CHUNKS: usize = 64;
const MAX_BYTES: usize = MAX_CHUNKS * MAX_CHUNK;
const MAX_BODY: usize = 512 * 1024;
const CHALLENGE_LIFE: i64 = 5 * 60 * 1000;
const TRANSFER_LIFE: i64 = 60 * 60 * 1000;
const MAX_PENDING: i64 = 32;
const MAX_ACTIVE: i64 = 8;
const CAP_PER_ACTOR: i64 = 2;
const PURPOSE: &str = "transfer.intent";
// The client must encrypt the report before uploading it. A server can
// validate framing and signatures, not authenticate the inner AES-GCM tag.
#[cfg(test)]
const RECONCILE_PURPOSE: &str = "transfer.reconcile";
#[cfg(test)]
const RECONCILE_LIFE_MS: i64 = 5 * 60 * 1000;

type StageRow = (
    Vec<u8>,
    i64,
    String,
    i64,
    i64,
    i64,
    String,
    String,
    String,
    Option<String>,
);
type StageResult<T> = Result<T, StageError>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StageError {
    pub status: u16,
    pub code: &'static str,
}
fn err<T>(status: u16, code: &'static str) -> StageResult<T> {
    Err(StageError { status, code })
}

fn valid_actor(public: &str) -> StageResult<String> {
    if public.len() > 4000 || public.is_empty() {
        return err(400, "INVALID_ACTOR");
    }
    let Some((ed, pq)) = public.split_once('.') else {
        return err(400, "HYBRID_KEY_REQUIRED");
    };
    let (Ok(ed), Ok(pq)) = (from_b64u(ed), from_b64u(pq)) else {
        return err(400, "INVALID_ACTOR");
    };
    if ed.len() != 32 || pq.len() != 1952 {
        return err(400, "INVALID_ACTOR");
    }
    key_id(public).map_err(|_| StageError {
        status: 400,
        code: "INVALID_ACTOR",
    })
}

fn require_host(host: &str) -> StageResult<()> {
    if norm_host(host).as_deref() != Some(host) || host.len() > 253 {
        return err(400, "BAD_HOST");
    }
    Ok(())
}

fn envelope_commitment(parts: &[Value]) -> StageResult<(String, usize)> {
    if parts.is_empty() || parts.len() > MAX_CHUNKS {
        return err(400, "BAD_MANIFEST");
    }
    let mut total = 0usize;
    let mut rows = Vec::with_capacity(parts.len());
    for (index, item) in parts.iter().enumerate() {
        // Never persist arbitrary client-supplied fields, which could expose contacts,
        // filenames or message contents in what should be an opaque outer manifest.
        let Some(fields) = item.as_object() else {
            return err(400, "BAD_MANIFEST");
        };
        if fields.len() != 3
            || !["i", "sha256", "bytes"]
                .iter()
                .all(|k| fields.contains_key(*k))
        {
            return err(400, "BAD_MANIFEST");
        }
        let size = item["bytes"]
            .as_u64()
            .and_then(|s| usize::try_from(s).ok())
            .unwrap_or(0);
        let hash = item["sha256"].as_str().unwrap_or("");
        if item["i"].as_u64() != Some(index as u64)
            || size == 0
            || size > MAX_CHUNK
            || !from_b64u(hash).is_ok_and(|b| b.len() == 32)
        {
            return err(400, "BAD_MANIFEST");
        }
        total = total.checked_add(size).ok_or(StageError {
            status: 400,
            code: "BAD_MANIFEST",
        })?;
        if total > MAX_BYTES {
            return err(413, "TOO_LARGE");
        }
        rows.push(json!({ "i": index, "sha256": hash, "bytes": size }));
    }
    // Do not allow the application's outer manifest calculation to diverge
    // from Secure Net's independent SNIP-0007 Rust implementation.
    let protocol_parts: Vec<ProtocolChunk> = rows
        .iter()
        .enumerate()
        .map(|(i, part)| ProtocolChunk {
            index: i as u64,
            digest: part["sha256"].as_str().unwrap_or("").to_string(),
            bytes: part["bytes"].as_u64().unwrap_or(0),
        })
        .collect();
    let root = protocol_ciphertext_root(&protocol_parts).map_err(|_| StageError {
        status: 400,
        code: "BAD_MANIFEST",
    })?;
    Ok((root, total))
}

fn body_intent_valid(
    body: &Value,
    actor: &str,
    destination: &str,
    now: i64,
    root: &str,
    chunk_count: usize,
    bytes: usize,
) -> StageResult<u64> {
    let Some(source) = body["from"].as_str() else {
        return err(400, "BAD_SOURCE");
    };
    require_host(source)?;
    if source == destination
        || body["v"] != 1
        || body["actor"] != actor
        || body["to"] != destination
        || body["ciphertext_root"] != root
        || body["chunks"].as_u64() != Some(chunk_count as u64)
        || body["bytes"].as_u64() != Some(bytes as u64)
    {
        return err(400, "BAD_INTENT");
    }
    let seq = body["seq"].as_u64().filter(|n| *n > 0).ok_or(StageError {
        status: 400,
        code: "BAD_SEQ",
    })?;
    let issued = body["issued_ms"].as_i64().ok_or(StageError {
        status: 400,
        code: "BAD_TIME",
    })?;
    let expires = body["expires_ms"].as_i64().ok_or(StageError {
        status: 400,
        code: "BAD_TIME",
    })?;
    if issued > now.saturating_add(60_000)
        || expires < now
        || expires <= issued
        || expires - issued > 15 * 60_000
    {
        return err(400, "EXPIRED_INTENT");
    }
    Ok(seq)
}

pub struct Stage {
    db: Connection,
    destination: String,
}
impl Stage {
    /// A separate, restrictive database for opaque ciphertext, not the user's account database.
    pub fn open(data_dir: &Path, destination: &str) -> StageResult<Self> {
        require_host(destination)?;
        let db =
            Connection::open(data_dir.join("migration-stage-experimental.db")).map_err(|_| {
                StageError {
                    status: 500,
                    code: "STAGE_UNAVAILABLE",
                }
            })?;
        db.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        // This DB never needs group-readable files; the containing DATA_DIR is 0700.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                data_dir.join("migration-stage-experimental.db"),
                std::fs::Permissions::from_mode(0o600),
            )
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        }
        db.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS challenges (
                challenge TEXT PRIMARY KEY,
                actor TEXT NOT NULL,
                expires INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
             );
             CREATE INDEX IF NOT EXISTS challenges_actor ON challenges(actor);
             CREATE TABLE IF NOT EXISTS actor_seq (
                actor TEXT PRIMARY KEY,
                seq INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS transfers (
                id TEXT PRIMARY KEY, actor TEXT NOT NULL,
                root TEXT NOT NULL, expected_chunks INTEGER NOT NULL,
                expected_bytes INTEGER NOT NULL, token_hash BLOB NOT NULL,
                expires INTEGER NOT NULL, complete INTEGER NOT NULL DEFAULT 0,
                manifest TEXT NOT NULL,
                reconcile_nonce TEXT NOT NULL DEFAULT '',
                reconcile_record TEXT
             );
             CREATE INDEX IF NOT EXISTS transfers_actor ON transfers(actor);
             CREATE TABLE IF NOT EXISTS chunks (
                transfer_id TEXT NOT NULL,
                idx INTEGER NOT NULL,
                digest TEXT NOT NULL,
                ciphertext BLOB NOT NULL,
                PRIMARY KEY(transfer_id, idx),
                FOREIGN KEY(transfer_id) REFERENCES transfers(id) ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS reconciliation_reports (
                transfer_id TEXT PRIMARY KEY,
                digest TEXT NOT NULL,
                ciphertext BLOB NOT NULL,
                FOREIGN KEY(transfer_id) REFERENCES transfers(id) ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS recipient_consent (
                transfer_id TEXT PRIMARY KEY,
                request_record TEXT NOT NULL,
                grant_record TEXT NOT NULL,
                FOREIGN KEY(transfer_id) REFERENCES transfers(id) ON DELETE CASCADE
             );",
        )
        .map_err(|_| StageError {
            status: 500,
            code: "STAGE_UNAVAILABLE",
        })?;
        // Earlier experimental databases had no reconciliation columns. Keep staged
        // ciphertext intact during the schema upgrade. Those older stages must be
        // re-prepared to receive a unique reconciliation challenge.
        let columns: Vec<String> = db
            .prepare("PRAGMA table_info(transfers)")
            .and_then(|mut stmt| {
                stmt.query_map([], |row| row.get::<_, String>(1))?
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        if !columns.iter().any(|c| c == "reconcile_nonce") {
            db.execute_batch(
                "ALTER TABLE transfers ADD COLUMN reconcile_nonce TEXT NOT NULL DEFAULT '';",
            )
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        }
        if !columns.iter().any(|c| c == "reconcile_record") {
            db.execute_batch("ALTER TABLE transfers ADD COLUMN reconcile_record TEXT;")
                .map_err(|_| StageError {
                    status: 500,
                    code: "STAGE_UNAVAILABLE",
                })?;
        }
        Ok(Self {
            db,
            destination: destination.to_string(),
        })
    }

    fn prune(&self, now: i64) -> StageResult<()> {
        self.db
            .execute("DELETE FROM challenges WHERE expires < ?1", params![now])
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        self.db
            .execute("DELETE FROM transfers WHERE expires < ?1", params![now])
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        Ok(())
    }

    /// Bounded, random one-use challenge. This does not bind the actor to a Commonveil account.
    pub fn challenge(&mut self, owner_public: &str, now: i64) -> StageResult<Value> {
        let actor = valid_actor(owner_public)?;
        self.prune(now)?;
        // Lock before counting and inserting, so concurrent challenges cannot defeat
        // the global/per-actor DoS caps.
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        let pending: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM challenges WHERE used = 0 AND expires >= ?1",
                params![now],
                |r| r.get(0),
            )
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        let mine: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM challenges WHERE actor = ?1 AND used = 0 AND expires >= ?2",
                params![actor, now],
                |r| r.get(0),
            )
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        if pending >= MAX_PENDING || mine >= CAP_PER_ACTOR {
            return err(429, "CHALLENGE_LIMIT");
        }
        let challenge = random_b64u(32);
        tx.execute(
            "INSERT INTO challenges(challenge,actor,expires) VALUES(?1,?2,?3)",
            params![challenge, actor, now + CHALLENGE_LIFE],
        )
        .map_err(|_| StageError {
            status: 500,
            code: "STAGE_UNAVAILABLE",
        })?;
        tx.commit().map_err(|_| StageError {
            status: 500,
            code: "STAGE_UNAVAILABLE",
        })?;
        Ok(json!({
            "challenge": challenge, "actor": actor,
            "destination": self.destination, "expires_ms": now + CHALLENGE_LIFE,
            "warning": "Experimental ciphertext staging only; no account claim or inbox cutover"
        }))
    }

    /// Atomically consume a challenge and monotonically reserve a transfer sequence.
    /// It proves possession of the *submitted* independent key. It does not establish
    /// that the same key belongs to an existing Commonveil account or another site.
    pub fn prepare(
        &mut self,
        public: &str,
        signed: &Value,
        manifest: &[Value],
        now: i64,
    ) -> StageResult<Value> {
        let actor = valid_actor(public)?;
        let (root, bytes) = envelope_commitment(manifest)?;
        let body = verify(
            signed,
            |kid| (kid == actor).then(|| public.to_string()),
            Some(&[PURPOSE]),
        )
        .map_err(|_| StageError {
            status: 403,
            code: "BAD_SIGNATURE",
        })?;
        let seq = body_intent_valid(
            body,
            &actor,
            &self.destination,
            now,
            &root,
            manifest.len(),
            bytes,
        )?;
        let signed_nonce = body["challenge"].as_str().unwrap_or("");
        if !from_b64u(signed_nonce).is_ok_and(|b| b.len() == 32) {
            return err(400, "BAD_CHALLENGE");
        }
        self.prune(now)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        let active: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM transfers WHERE expires >= ?1",
                params![now],
                |r| r.get(0),
            )
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        if active >= MAX_ACTIVE {
            return err(429, "STAGE_LIMIT");
        }
        let mine: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM transfers WHERE actor = ?1 AND expires >= ?2",
                params![actor, now],
                |r| r.get(0),
            )
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        if mine >= CAP_PER_ACTOR {
            return err(429, "STAGE_LIMIT");
        }
        let claimed: i64 = tx.execute(
            "UPDATE challenges SET used=1 WHERE challenge=?1 AND actor=?2 AND used=0 AND expires>=?3",
            params![signed_nonce, actor, now],
        ).map_err(|_| StageError { status: 500, code: "STAGE_UNAVAILABLE" })? as i64;
        if claimed != 1 {
            return err(409, "CHALLENGE_USED_OR_EXPIRED");
        }
        let last: Option<i64> = tx
            .query_row(
                "SELECT seq FROM actor_seq WHERE actor=?1",
                params![actor],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        if last.is_some_and(|v| seq <= v as u64) || seq > i64::MAX as u64 {
            return err(409, "STALE_SEQUENCE");
        }
        // The destination verifies the same experimental transfer intent
        // through Secure Net's provider-neutral Rust code. This is an
        // additional check, not permission to link an account or redirect mail.
        protocol_verify_intent(
            signed,
            public,
            &actor,
            &self.destination,
            signed_nonce,
            last.unwrap_or(0) as u64,
            now,
        )
        .map_err(|_| StageError {
            status: 400,
            code: "BAD_INTENT",
        })?;
        tx.execute(
            "INSERT INTO actor_seq(actor,seq) VALUES(?1,?2)
             ON CONFLICT(actor) DO UPDATE SET seq=excluded.seq",
            params![actor, seq as i64],
        )
        .map_err(|_| StageError {
            status: 500,
            code: "STAGE_UNAVAILABLE",
        })?;
        let id = random_b64u(18);
        let token = random_b64u(32);
        let reconcile_nonce = random_b64u(32);
        let hash = sha256(token.as_bytes());
        tx.execute(
            "INSERT INTO transfers(id,actor,root,expected_chunks,expected_bytes,token_hash,expires,manifest,reconcile_nonce)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![id, actor, root, manifest.len() as i64, bytes as i64,
                hash.as_slice(), now + TRANSFER_LIFE, json!({"v":1,"chunks":manifest}).to_string(),
                reconcile_nonce],
        ).map_err(|_| StageError { status: 500, code: "STAGE_UNAVAILABLE" })?;
        tx.commit().map_err(|_| StageError {
            status: 500,
            code: "STAGE_UNAVAILABLE",
        })?;
        Ok(json!({
            "stage_id": id, "stage_token": token,
            "reconcile_challenge": reconcile_nonce,
            "expires_ms": now + TRANSFER_LIFE,
            "ciphertext_complete": false, "client_attested": false,
            "imported": false, "cutover": false
        }))
    }

    fn authorised(&self, id: &str, token: &str, now: i64) -> StageResult<Value> {
        if id.len() != 24
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || token.len() != 43
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return err(404, "NOT_FOUND");
        }
        let stored: Option<StageRow> = self
            .db
            .query_row(
                "SELECT token_hash, expires, manifest, expected_chunks, expected_bytes, complete,
                    actor, root, reconcile_nonce, reconcile_record
             FROM transfers WHERE id = ?1",
                params![id],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                        r.get(9)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        let Some((
            hash,
            expires,
            manifest,
            chunks,
            bytes,
            complete,
            actor,
            root,
            reconcile_nonce,
            reconcile_record,
        )) = stored
        else {
            return err(404, "NOT_FOUND");
        };
        if expires < now {
            return err(410, "EXPIRED");
        }
        // Compare fixed-length digests without leaking the first differing byte.
        let actual = sha256(token.as_bytes());
        if hash.len() != 32 || actual.iter().zip(&hash).fold(0u8, |v, (a, b)| v | (a ^ b)) != 0 {
            return err(404, "NOT_FOUND");
        }
        let manifest: Value = serde_json::from_str(&manifest).map_err(|_| StageError {
            status: 500,
            code: "STAGE_UNAVAILABLE",
        })?;
        Ok(json!({
            "manifest": manifest, "chunks":chunks,"bytes":bytes, "complete": complete != 0,
            "actor": actor, "root": root, "reconcile_nonce": reconcile_nonce,
            "client_attested": reconcile_record.is_some()
        }))
    }

    /// Accept *only ciphertext* with the expected exact size and SHA-256 hash.
    /// Duplicate identical writes are harmless; conflicting writes fail closed.
    pub fn chunk(
        &mut self,
        id: &str,
        token: &str,
        index: usize,
        data: &[u8],
        now: i64,
    ) -> StageResult<Value> {
        let state = self.authorised(id, token, now)?;
        if state["complete"] == true {
            return err(409, "ALREADY_COMPLETE");
        }
        let manifest = state["manifest"]["chunks"].as_array().ok_or(StageError {
            status: 500,
            code: "STAGE_UNAVAILABLE",
        })?;
        let Some(expected) = manifest.get(index) else {
            return err(400, "BAD_INDEX");
        };
        if data.is_empty()
            || data.len() != expected["bytes"].as_u64().unwrap_or(0) as usize
            || sha256_b64u(data) != expected["sha256"].as_str().unwrap_or("")
        {
            return err(400, "CORRUPT_CHUNK");
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT ciphertext FROM chunks WHERE transfer_id=?1 AND idx=?2",
                params![id, index as i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        let repeated = match existing {
            Some(v) if v == data => true,
            Some(_) => return err(409, "CHUNK_CONFLICT"),
            None => {
                tx.execute(
                    "INSERT INTO chunks(transfer_id,idx,digest,ciphertext) VALUES(?1,?2,?3,?4)",
                    params![id, index as i64, sha256_b64u(data), data],
                )
                .map_err(|_| StageError {
                    status: 500,
                    code: "STAGE_UNAVAILABLE",
                })?;
                false
            }
        };
        let count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM chunks WHERE transfer_id=?1",
                params![id],
                |r| r.get(0),
            )
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        let complete = count == manifest.len() as i64;
        if complete {
            tx.execute("UPDATE transfers SET complete=1 WHERE id=?1", params![id])
                .map_err(|_| StageError {
                    status: 500,
                    code: "STAGE_UNAVAILABLE",
                })?;
        }
        tx.commit().map_err(|_| StageError {
            status: 500,
            code: "STAGE_UNAVAILABLE",
        })?;
        Ok(json!({ "received": true, "duplicate": repeated,
            "ciphertext_complete": complete, "imported": false, "cutover": false }))
    }

    pub fn status(
        &self,
        id: &str,
        token: &str,
        cursor: usize,
        limit: usize,
        now: i64,
    ) -> StageResult<Value> {
        let state = self.authorised(id, token, now)?;
        if limit == 0 || limit > 64 || cursor > state["chunks"].as_u64().unwrap_or(0) as usize {
            return err(400, "BAD_CURSOR");
        }
        let count: i64 = self
            .db
            .query_row(
                "SELECT COUNT(*) FROM chunks WHERE transfer_id = ?1",
                params![id],
                |r| r.get(0),
            )
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        let existing = self
            .db
            .prepare("SELECT idx FROM chunks WHERE transfer_id=?1")
            .and_then(|mut st| {
                st.query_map(params![id], |r| r.get::<_, i64>(0))?
                    .collect::<rusqlite::Result<Vec<i64>>>()
            })
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        let received: std::collections::BTreeSet<i64> = existing.into_iter().collect();
        let expected = state["chunks"].as_u64().unwrap_or(0) as usize;
        let mut missing = Vec::new();
        let mut next = None;
        for i in cursor..expected {
            if !received.contains(&(i as i64)) {
                missing.push(i);
                if missing.len() == limit {
                    if i + 1 < expected {
                        next = Some(i + 1);
                    }
                    break;
                }
            }
        }
        let report_staged: bool = self
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM reconciliation_reports WHERE transfer_id=?1)",
                params![id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?
            != 0;
        let recipient_consent_staged: bool = self
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM recipient_consent WHERE transfer_id=?1)",
                params![id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?
            != 0;
        Ok(
            json!({ "received": count, "expected": expected, "missing": missing,
            "next_cursor": next, "ciphertext_complete": state["complete"],
            "reconcile_challenge": state["reconcile_nonce"],
            "encrypted_report_staged": report_staged,
            "recipient_consent_staged": recipient_consent_staged,
            "recipient_key_proven": false, "device_enrolled": false,
            "client_attested": state["client_attested"],
            "imported": false, "cutover": false }),
        )
    }

    /// Persist an already signed independent device request and exact actor
    /// approval. No private KEM key, history key, message or account binding
    /// is accepted here. A signed public KEM key is not proof of possession.
    pub fn recipient_consent(
        &mut self,
        id: &str,
        token: &str,
        owner_public: &str,
        signed_request: &Value,
        signed_grant: &Value,
        now: i64,
    ) -> StageResult<Value> {
        let stage = self.authorised(id, token, now)?;
        if stage["complete"] != true {
            return err(409, "INCOMPLETE_CIPHERTEXT");
        }
        let actor = valid_actor(owner_public)?;
        if stage["actor"] != actor {
            return err(403, "WRONG_ACTOR");
        }
        if stage["reconcile_nonce"].as_str().unwrap_or("").is_empty() {
            return err(409, "RESTAGE_REQUIRED");
        }
        let expected = ExpectedRecipient {
            actor_id: &actor,
            stage_id: id,
            destination: &self.destination,
            ciphertext_root: stage["root"].as_str().unwrap_or(""),
            challenge: stage["reconcile_nonce"].as_str().unwrap_or(""),
            now_ms: now,
        };
        let grant =
            protocol_verify_recipient_grant(signed_request, signed_grant, owner_public, &expected)
                .map_err(|error| {
                    let code = match error.code {
                        "EXPIRED" => "EXPIRED_CONSENT",
                        "WRONG_ACTOR" | "UNKNOWN_SIGNER" => "WRONG_ACTOR",
                        _ => "BAD_RECIPIENT_CONSENT",
                    };
                    StageError {
                        status: if code == "EXPIRED_CONSENT" {
                            409
                        } else if code == "WRONG_ACTOR" {
                            403
                        } else {
                            400
                        },
                        code,
                    }
                })?;
        let recipient = grant["recipient_id"].as_str().unwrap_or("");
        // The shared validator checked exact request/grant field sets. Never
        // blindly persist user-supplied metadata or request plaintext.
        let request_text = signed_request.to_string();
        let grant_text = signed_grant.to_string();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        let complete: Option<i64> = tx
            .query_row(
                "SELECT complete FROM transfers WHERE id=?1",
                params![id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        if complete != Some(1) {
            return err(409, "INCOMPLETE_CIPHERTEXT");
        }
        let previous: Option<(String, String)> = tx
            .query_row(
                "SELECT request_record,grant_record FROM recipient_consent WHERE transfer_id=?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        let duplicate = match previous {
            Some((request, grant)) => {
                if request != request_text || grant != grant_text {
                    return err(409, "RECIPIENT_CONSENT_CONFLICT");
                }
                true
            }
            None => {
                tx.execute(
                    "INSERT INTO recipient_consent(transfer_id,request_record,grant_record) VALUES(?1,?2,?3)",
                    params![id, request_text, grant_text],
                ).map_err(|_| StageError { status: 500, code: "STAGE_UNAVAILABLE" })?;
                false
            }
        };
        tx.commit().map_err(|_| StageError {
            status: 500,
            code: "STAGE_UNAVAILABLE",
        })?;
        Ok(json!({
            "recipient_consent_staged": true, "recipient_id": recipient,
            "duplicate": duplicate, "recipient_key_proven": false,
            "device_enrolled": false, "imported": false, "cutover": false
        }))
    }

    /// Retrieve the two signed *public* authorisation statements. A stage
    /// bearer cannot use these records to recover history or private keys.
    pub fn signed_recipient_consent(&self, id: &str, token: &str, now: i64) -> StageResult<Value> {
        self.authorised(id, token, now)?;
        let records: Option<(String, String)> = self
            .db
            .query_row(
                "SELECT request_record,grant_record FROM recipient_consent WHERE transfer_id=?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        let Some((request, grant)) = records else {
            return err(404, "NOT_FOUND");
        };
        let request: Value = serde_json::from_str(&request).map_err(|_| StageError {
            status: 500,
            code: "STAGE_UNAVAILABLE",
        })?;
        let grant: Value = serde_json::from_str(&grant).map_err(|_| StageError {
            status: 500,
            code: "STAGE_UNAVAILABLE",
        })?;
        Ok(json!({
            "request": request, "grant": grant,
            "recipient_key_proven": false, "device_enrolled": false,
            "imported": false, "cutover": false
        }))
    }

    /// Stage an opaque, separately device-encrypted reconciliation report.
    /// No client keys or plaintext reports belong on this server. The bearer
    /// token authorises storage but does not prove the supplied bytes are AEAD.
    pub fn stage_report(
        &mut self,
        id: &str,
        token: &str,
        ciphertext: &[u8],
        now: i64,
    ) -> StageResult<Value> {
        let state = self.authorised(id, token, now)?;
        if state["complete"] != true {
            return err(409, "INCOMPLETE_CIPHERTEXT");
        }
        if state["client_attested"] == true {
            return err(409, "ALREADY_ATTESTED");
        }
        let digest = protocol_encrypted_report_digest(ciphertext).map_err(|error| StageError {
            status: if error.code == "BAD_REPORT_SIZE" {
                413
            } else {
                400
            },
            code: if error.code == "BAD_REPORT_SIZE" {
                "REPORT_SIZE_LIMIT"
            } else {
                "BAD_REPORT_FORMAT"
            },
        })?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        // Serialise against concurrent report writes, abort and reconciliation.
        let stage_state: Option<(i64, Option<String>)> = tx
            .query_row(
                "SELECT complete, reconcile_record FROM transfers WHERE id=?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        let Some((complete, attested)) = stage_state else {
            return err(404, "NOT_FOUND");
        };
        if complete == 0 {
            return err(409, "INCOMPLETE_CIPHERTEXT");
        }
        if attested.is_some() {
            return err(409, "ALREADY_ATTESTED");
        }
        let previous: Option<(String, Vec<u8>)> = tx
            .query_row(
                "SELECT digest, ciphertext FROM reconciliation_reports WHERE transfer_id=?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        let repeated = match previous {
            Some((old_digest, old_ciphertext)) => {
                if old_digest != digest || old_ciphertext != ciphertext {
                    return err(409, "REPORT_CONFLICT");
                }
                true
            }
            None => {
                tx.execute(
                    "INSERT INTO reconciliation_reports(transfer_id,digest,ciphertext)
                     VALUES(?1,?2,?3)",
                    params![id, digest, ciphertext],
                )
                .map_err(|_| StageError {
                    status: 500,
                    code: "STAGE_UNAVAILABLE",
                })?;
                false
            }
        };
        tx.commit().map_err(|_| StageError {
            status: 500,
            code: "STAGE_UNAVAILABLE",
        })?;
        Ok(json!({
            "report_staged": true, "sha256": digest, "duplicate": repeated,
            "client_attested": false, "imported": false, "cutover": false
        }))
    }

    /// Return the unchanged opaque bytes to an authorised device, which must
    /// independently authenticate/decrypt them and verify the signed statement.
    pub fn download_report(&self, id: &str, token: &str, now: i64) -> StageResult<Value> {
        self.authorised(id, token, now)?;
        let row: Option<(String, Vec<u8>)> = self
            .db
            .query_row(
                "SELECT digest,ciphertext FROM reconciliation_reports WHERE transfer_id=?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        let Some((digest, ciphertext)) = row else {
            return err(404, "NOT_FOUND");
        };
        if protocol_encrypted_report_digest(&ciphertext)
            .ok()
            .as_deref()
            != Some(digest.as_str())
        {
            return err(409, "CORRUPT_REPORT");
        }
        Ok(json!({
            "ciphertext": URL_SAFE_NO_PAD.encode(ciphertext),
            "sha256": digest, "imported": false, "cutover": false
        }))
    }

    /// The owner's client may sign a bounded statement saying it has checked the
    /// staged ciphertext and a *separate encrypted* reconciliation report. A signed
    /// statement is **not** independent proof the inner history was decrypted, and
    /// never constitutes a transfer commit, account import or inbox handover.
    pub fn reconcile(
        &mut self,
        id: &str,
        token: &str,
        owner_public: &str,
        signed: &Value,
        now: i64,
    ) -> StageResult<Value> {
        let state = self.authorised(id, token, now)?;
        if state["complete"] != true {
            return err(409, "INCOMPLETE_CIPHERTEXT");
        }
        let actor = valid_actor(owner_public)?;
        if state["actor"] != actor {
            return err(403, "WRONG_ACTOR");
        }
        // Delegate the hybrid-signed draft record, schema and time checks
        // to the independent Secure Net implementation. No account changes.
        if state["reconcile_nonce"].as_str().unwrap_or("").is_empty() {
            return err(409, "RESTAGE_REQUIRED");
        }
        let claimed_digest = signed["body"]["encrypted_report_sha256"]
            .as_str()
            .unwrap_or("");
        let expected = ExpectedReconciliation {
            owner_public,
            actor_id: &actor,
            stage_id: id,
            destination: &self.destination,
            ciphertext_root: state["root"].as_str().unwrap_or(""),
            challenge: state["reconcile_nonce"].as_str().unwrap_or(""),
            encrypted_report_sha256: claimed_digest,
            now_ms: now,
        };
        let body = protocol_verify_reconciliation(signed, &expected).map_err(|error| {
            let code = match error.code {
                "BAD_SIGNATURE" | "UNKNOWN_SIGNER" | "WRONG_KIND" => "BAD_SIGNATURE",
                "EXPIRED" => "EXPIRED_RECONCILIATION",
                "WRONG_ACTOR" => "WRONG_ACTOR",
                "BAD_REPORT_DIGEST" => "REPORT_HASH_MISMATCH",
                _ => "BAD_RECONCILIATION",
            };
            let status = match code {
                "BAD_SIGNATURE" | "WRONG_ACTOR" => 403,
                "EXPIRED_RECONCILIATION" | "REPORT_HASH_MISMATCH" => 409,
                _ => 400,
            };
            StageError { status, code }
        })?;
        // Verify storage again immediately before recording any owner attestation.
        // The SQLite transaction serialises stage writes and receipt creation.
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        let previous: Option<String> = tx
            .query_row(
                "SELECT reconcile_record FROM transfers WHERE id=?1",
                params![id],
                |row| row.get(0),
            )
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        let stored_manifest = state["manifest"]["chunks"].as_array().ok_or(StageError {
            status: 500,
            code: "STAGE_UNAVAILABLE",
        })?;
        let stored = tx
            .prepare("SELECT idx, digest, ciphertext FROM chunks WHERE transfer_id=?1 ORDER BY idx")
            .and_then(|mut st| {
                st.query_map(params![id], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()
            })
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        if stored.len() != stored_manifest.len() {
            return err(409, "INCOMPLETE_CIPHERTEXT");
        }
        for (position, (index, digest, ciphertext)) in stored.iter().enumerate() {
            let entry = &stored_manifest[position];
            let expected_hash = entry["sha256"].as_str().unwrap_or("");
            if *index != position as i64
                || entry["bytes"].as_u64() != Some(ciphertext.len() as u64)
                || digest != expected_hash
                || sha256_b64u(ciphertext) != expected_hash
            {
                return err(409, "CORRUPT_STAGE");
            }
        }
        // A signed hash of an imagined report is not enough. Require the
        // previously staged opaque report and re-hash it in this same lock.
        let report: Option<(String, Vec<u8>)> = tx
            .query_row(
                "SELECT digest,ciphertext FROM reconciliation_reports WHERE transfer_id=?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        let Some((report_digest, report_ciphertext)) = report else {
            return err(409, "MISSING_ENCRYPTED_REPORT");
        };
        let signed_digest = body["encrypted_report_sha256"].as_str().unwrap_or("");
        if report_digest != signed_digest
            || protocol_encrypted_report_digest(&report_ciphertext)
                .ok()
                .as_deref()
                != Some(signed_digest)
        {
            return err(409, "REPORT_HASH_MISMATCH");
        }
        let record_text = signed.to_string();
        let duplicate =
            if let Some(existing) = previous {
                if existing != record_text {
                    return err(409, "RECONCILIATION_CONFLICT");
                }
                true
            } else {
                tx.execute(
                "UPDATE transfers SET reconcile_record=?2 WHERE id=?1 AND reconcile_record IS NULL",
                params![id, record_text],
            ).map_err(|_| StageError { status: 500, code: "STAGE_UNAVAILABLE" })?;
                false
            };
        tx.commit().map_err(|_| StageError {
            status: 500,
            code: "STAGE_UNAVAILABLE",
        })?;
        Ok(json!({
            "client_attested": true, "duplicate": duplicate,
            "ciphertext_complete": true, "imported": false, "cutover": false,
            "warning": "The owner signed a statement, not proof of readable history or a site move"
        }))
    }

    /// Retrieve the client-authored signed receipt for independent verification.
    /// This is not a relay signature, a zero-knowledge proof or an import receipt.
    pub fn signed_reconciliation(&self, id: &str, token: &str, now: i64) -> StageResult<Value> {
        self.authorised(id, token, now)?;
        let record: Option<String> = self
            .db
            .query_row(
                "SELECT reconcile_record FROM transfers WHERE id=?1",
                params![id],
                |r| r.get(0),
            )
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        let Some(record) = record else {
            return err(404, "NOT_FOUND");
        };
        let statement: Value = serde_json::from_str(&record).map_err(|_| StageError {
            status: 500,
            code: "STAGE_UNAVAILABLE",
        })?;
        Ok(json!({
            "client_signed_statement": statement, "imported": false, "cutover": false
        }))
    }

    pub fn abort(&mut self, id: &str, token: &str, now: i64) -> StageResult<Value> {
        self.authorised(id, token, now)?;
        self.db
            .execute("DELETE FROM transfers WHERE id=?1", params![id])
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        // The consumed one-use challenge and highest sequence remain pinned.
        Ok(json!({ "aborted": true, "source_unchanged": true }))
    }

    pub fn download_chunk(
        &self,
        id: &str,
        token: &str,
        index: usize,
        now: i64,
    ) -> StageResult<Value> {
        let state = self.authorised(id, token, now)?;
        if index >= state["chunks"].as_u64().unwrap_or(0) as usize {
            return err(404, "NOT_FOUND");
        }
        let ciphertext: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT ciphertext FROM chunks WHERE transfer_id=?1 AND idx=?2",
                params![id, index as i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        let Some(ciphertext) = ciphertext else {
            return err(404, "NOT_FOUND");
        };
        Ok(
            json!({ "i":index, "ciphertext":URL_SAFE_NO_PAD.encode(ciphertext),
            "imported": false, "cutover": false }),
        )
    }
}

/// Paths are deliberately not CVP production mailbox paths. No move route is supplied.
pub fn route(
    data_dir: &Path,
    destination: &str,
    method: &str,
    path: &str,
    authorization: &str,
    raw: &[u8],
    now: i64,
) -> (u16, Value) {
    let response = (|| -> StageResult<Value> {
        let mut stage = Stage::open(data_dir, destination)?;
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        if path == "/cvp/v2/experimental-transfer/challenge" && method == "POST" {
            if raw.len() > 8192 {
                return err(413, "TOO_LARGE");
            };
            let data: Value = serde_json::from_slice(raw).map_err(|_| StageError {
                status: 400,
                code: "BAD_JSON",
            })?;
            return stage.challenge(data["owner_public"].as_str().unwrap_or(""), now);
        }
        if path == "/cvp/v2/experimental-transfer/prepare" && method == "POST" {
            if raw.len() > MAX_BODY {
                return err(413, "TOO_LARGE");
            };
            let data: Value = serde_json::from_slice(raw).map_err(|_| StageError {
                status: 400,
                code: "BAD_JSON",
            })?;
            let manifest = data["manifest"].as_array().ok_or(StageError {
                status: 400,
                code: "BAD_MANIFEST",
            })?;
            return stage.prepare(
                data["owner_public"].as_str().unwrap_or(""),
                &data["intent"],
                manifest,
                now,
            );
        }
        // /cvp/v2/experimental-transfer/stages/{stage_id}[/{chunks|status|abort}/{index}]
        if parts.len() >= 4
            && parts[0..3] == ["cvp", "v2", "experimental-transfer"]
            && parts[3] == "stages"
        {
            let id = parts.get(4).copied().unwrap_or("");
            let token = authorization.strip_prefix("Bearer ").unwrap_or("");
            match (
                method,
                parts.get(5).copied(),
                parts.get(6).copied(),
                parts.len(),
            ) {
                ("POST", Some("chunks"), Some(index), 7) => {
                    if raw.len() > MAX_CHUNK {
                        return err(413, "TOO_LARGE");
                    };
                    let i: usize = index.parse().map_err(|_| StageError {
                        status: 400,
                        code: "BAD_INDEX",
                    })?;
                    return stage.chunk(id, token, i, raw, now);
                }
                ("GET", Some("chunks"), Some(index), 7) => {
                    let i: usize = index.parse().map_err(|_| StageError {
                        status: 400,
                        code: "BAD_INDEX",
                    })?;
                    return stage.download_chunk(id, token, i, now);
                }
                ("POST", Some("status"), None, 6) => {
                    let data: Value = if raw.is_empty() {
                        json!({})
                    } else {
                        serde_json::from_slice(raw).map_err(|_| StageError {
                            status: 400,
                            code: "BAD_JSON",
                        })?
                    };
                    let cursor = data["cursor"].as_u64().unwrap_or(0) as usize;
                    let limit = data["limit"].as_u64().unwrap_or(64) as usize;
                    return stage.status(id, token, cursor, limit, now);
                }
                ("POST", Some("report"), None, 6) => {
                    if raw.len() > MAX_REPORT_BYTES {
                        return err(413, "REPORT_SIZE_LIMIT");
                    }
                    return stage.stage_report(id, token, raw, now);
                }
                ("GET", Some("report"), None, 6) => {
                    return stage.download_report(id, token, now);
                }
                ("POST", Some("recipient-consent"), None, 6) => {
                    if raw.len() > 32 * 1024 {
                        return err(413, "TOO_LARGE");
                    }
                    let data: Value = serde_json::from_slice(raw).map_err(|_| StageError {
                        status: 400,
                        code: "BAD_JSON",
                    })?;
                    let fields = data.as_object().ok_or(StageError {
                        status: 400,
                        code: "BAD_RECIPIENT_CONSENT",
                    })?;
                    if fields.len() != 3
                        || ["owner_public", "request", "grant"]
                            .iter()
                            .any(|k| !fields.contains_key(*k))
                    {
                        return err(400, "BAD_RECIPIENT_CONSENT");
                    }
                    return stage.recipient_consent(
                        id,
                        token,
                        data["owner_public"].as_str().unwrap_or(""),
                        &data["request"],
                        &data["grant"],
                        now,
                    );
                }
                ("GET", Some("recipient-consent"), None, 6) => {
                    return stage.signed_recipient_consent(id, token, now);
                }
                ("POST", Some("reconcile"), None, 6) => {
                    if raw.len() > 12 * 1024 {
                        return err(413, "TOO_LARGE");
                    }
                    let data: Value = serde_json::from_slice(raw).map_err(|_| StageError {
                        status: 400,
                        code: "BAD_JSON",
                    })?;
                    return stage.reconcile(
                        id,
                        token,
                        data["owner_public"].as_str().unwrap_or(""),
                        &data["statement"],
                        now,
                    );
                }
                ("GET", Some("reconcile"), None, 6) => {
                    return stage.signed_reconciliation(id, token, now);
                }
                ("POST", Some("abort"), None, 6) => return stage.abort(id, token, now),
                _ => {}
            }
        }
        err(404, "NOT_FOUND")
    })();
    match response {
        Ok(body) => (200, body),
        Err(e) => (e.status, json!({"error":e.code,"code":e.code})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secure_net_core::signed::{sign, SigningKey};

    const NOW: i64 = 1_800_000_000_000;
    const SOURCE: &str = "old.example";
    const DEST: &str = "new.example";
    // Test-only opaque sample. Actual clients must produce authenticated,
    // recipient-bound ciphertext before using the report endpoint.
    const TEST_REPORT: &[u8] =
        b"CVRPT\x01abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz";

    fn fixture(parts: &[&[u8]]) -> (Vec<Value>, String, usize) {
        let m: Vec<Value> = parts
            .iter()
            .enumerate()
            .map(|(i, data)| json!({ "i": i, "bytes": data.len(), "sha256": sha256_b64u(data) }))
            .collect();
        let (root, bytes) = envelope_commitment(&m).unwrap();
        (m, root, bytes)
    }

    fn authorise(
        owner: &SigningKey,
        stage: &mut Stage,
        seq: u64,
        chunks: &[&[u8]],
    ) -> (Value, Vec<Value>) {
        let challenge = stage.challenge(&owner.public_key, NOW).unwrap();
        let nonce = challenge["challenge"].as_str().unwrap();
        let (m, root, bytes) = fixture(chunks);
        let record = sign(
            PURPOSE,
            &json!({
                "v": 1, "actor": owner.kid, "from": SOURCE, "to": DEST,
                "seq": seq, "challenge": nonce, "ciphertext_root": root,
                "chunks": chunks.len(), "bytes": bytes, "issued_ms": NOW,
                "expires_ms": NOW + CHALLENGE_LIFE
            }),
            owner,
        )
        .unwrap();
        (record, m)
    }

    #[test]
    fn independent_actor_stages_only_ciphertext_and_resumes_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let actor = SigningKey::generate(true);
        let a = b"opaque AEAD ciphertext A";
        let b = b"opaque AEAD ciphertext B";
        let (stage_id, stage_token) = {
            let mut s = Stage::open(dir.path(), DEST).unwrap();
            let (intent, m) = authorise(&actor, &mut s, 1, &[a, b]);
            let ticket = s.prepare(&actor.public_key, &intent, &m, NOW).unwrap();
            let id = ticket["stage_id"].as_str().unwrap().to_string();
            let token = ticket["stage_token"].as_str().unwrap().to_string();
            assert_eq!(ticket["cutover"], false);
            assert_eq!(ticket["imported"], false);
            assert_eq!(
                s.chunk(&id, &token, 1, b, NOW).unwrap()["ciphertext_complete"],
                false
            );
            assert_eq!(
                s.status(&id, &token, 0, 64, NOW).unwrap()["missing"],
                json!([0])
            );
            (id, token)
        };
        // The SQLite file is reopened after the "server" is dropped. Nothing depends on
        // keeping a transfer in memory and the client can request missing parts.
        let mut restarted = Stage::open(dir.path(), DEST).unwrap();
        let status = restarted
            .status(&stage_id, &stage_token, 0, 64, NOW + 1000)
            .unwrap();
        assert_eq!(status["received"], 1);
        assert_eq!(status["ciphertext_complete"], false);
        assert_eq!(
            restarted
                .chunk(&stage_id, &stage_token, 1, b, NOW + 1000)
                .unwrap()["duplicate"],
            true
        );
        let first = restarted
            .chunk(&stage_id, &stage_token, 0, a, NOW + 1000)
            .unwrap();
        assert_eq!(first["ciphertext_complete"], true);
        assert_eq!(first["imported"], false);
        assert_eq!(first["cutover"], false);
        assert_eq!(
            restarted
                .download_chunk(&stage_id, &stage_token, 0, NOW + 1000)
                .unwrap()["ciphertext"],
            URL_SAFE_NO_PAD.encode(a)
        );
        assert_eq!(
            restarted
                .chunk(&stage_id, &stage_token, 0, a, NOW + 1000)
                .unwrap_err()
                .code,
            "ALREADY_COMPLETE"
        );
    }

    #[test]
    fn invalid_signature_wrong_destination_and_replay_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let actor = SigningKey::generate(true);
        let attacker = SigningKey::generate(true);
        let mut stage = Stage::open(dir.path(), DEST).unwrap();
        let (good, m) = authorise(&actor, &mut stage, 5, &[b"sealed"]);
        let mut forged = good.clone();
        forged["body"]["to"] = json!("fake.example");
        assert_eq!(
            stage
                .prepare(&actor.public_key, &forged, &m, NOW)
                .unwrap_err()
                .code,
            "BAD_SIGNATURE"
        );
        let mut wrong = good.clone();
        wrong["body"]["ciphertext_root"] = json!(sha256_b64u(b"wrong"));
        assert_eq!(
            stage
                .prepare(&actor.public_key, &wrong, &m, NOW)
                .unwrap_err()
                .code,
            "BAD_SIGNATURE"
        );
        assert_eq!(
            stage
                .prepare(&attacker.public_key, &good, &m, NOW)
                .unwrap_err()
                .code,
            "BAD_SIGNATURE"
        );

        let ok = stage.prepare(&actor.public_key, &good, &m, NOW).unwrap();
        assert_eq!(ok["cutover"], false);
        assert_eq!(
            stage
                .prepare(&actor.public_key, &good, &m, NOW)
                .unwrap_err()
                .code,
            "CHALLENGE_USED_OR_EXPIRED"
        );
        let (old_seq, fresh_m) = authorise(&actor, &mut stage, 5, &[b"sealed"]);
        assert_eq!(
            stage
                .prepare(&actor.public_key, &old_seq, &fresh_m, NOW)
                .unwrap_err()
                .code,
            "STALE_SEQUENCE"
        );
        let (higher, m2) = authorise(&actor, &mut stage, 6, &[b"new encrypted record"]);
        assert!(stage.prepare(&actor.public_key, &higher, &m2, NOW).is_ok());
    }

    #[test]
    fn bad_nonce_or_signature_never_consumes_challenge() {
        let dir = tempfile::tempdir().unwrap();
        let actor = SigningKey::generate(true);
        let mut stage = Stage::open(dir.path(), DEST).unwrap();
        let (good, m) = authorise(&actor, &mut stage, 1, &[b"encrypted blob"]);
        let other_nonce = random_b64u(32);
        let mut bad_body = good["body"].clone();
        bad_body["challenge"] = json!(other_nonce);
        let wrong_nonce = sign(PURPOSE, &bad_body, &actor).unwrap();
        assert_eq!(
            stage
                .prepare(&actor.public_key, &wrong_nonce, &m, NOW)
                .unwrap_err()
                .code,
            "CHALLENGE_USED_OR_EXPIRED"
        );
        assert!(stage.prepare(&actor.public_key, &good, &m, NOW).is_ok());
    }

    #[test]
    fn corrupt_chunks_and_missing_or_stolen_tokens_are_denied() {
        let dir = tempfile::tempdir().unwrap();
        let actor = SigningKey::generate(true);
        let mut stage = Stage::open(dir.path(), DEST).unwrap();
        let (good, m) = authorise(&actor, &mut stage, 1, &[b"sealed blob"]);
        let t = stage.prepare(&actor.public_key, &good, &m, NOW).unwrap();
        let id = t["stage_id"].as_str().unwrap();
        let secret = t["stage_token"].as_str().unwrap();
        assert_eq!(
            stage
                .status(id, &random_b64u(32), 0, 64, NOW)
                .unwrap_err()
                .code,
            "NOT_FOUND"
        );
        assert_eq!(
            stage.status(id, "", 0, 64, NOW).unwrap_err().code,
            "NOT_FOUND"
        );
        assert_eq!(
            stage
                .chunk(id, secret, 0, b"altered blob", NOW)
                .unwrap_err()
                .code,
            "CORRUPT_CHUNK"
        );
        assert_eq!(stage.status(id, secret, 0, 64, NOW).unwrap()["received"], 0);
        assert_eq!(
            stage
                .chunk(id, secret, 999, b"sealed blob", NOW)
                .unwrap_err()
                .code,
            "BAD_INDEX"
        );
        assert_eq!(
            stage.status(id, secret, 0, 0, NOW).unwrap_err().code,
            "BAD_CURSOR"
        );
        assert_eq!(
            stage.download_chunk(id, secret, 0, NOW).unwrap_err().code,
            "NOT_FOUND"
        );
        assert_eq!(
            stage
                .status(id, secret, 0, 64, NOW + TRANSFER_LIFE + 1)
                .unwrap_err()
                .code,
            "EXPIRED"
        );
    }

    #[test]
    fn abort_drops_only_staged_ciphertext_without_releasing_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let actor = SigningKey::generate(true);
        let mut s = Stage::open(dir.path(), DEST).unwrap();
        let (good, m) = authorise(&actor, &mut s, 1, &[b"sealed"]);
        let t = s.prepare(&actor.public_key, &good, &m, NOW).unwrap();
        let id = t["stage_id"].as_str().unwrap();
        let token = t["stage_token"].as_str().unwrap();
        s.chunk(id, token, 0, b"sealed", NOW).unwrap();
        assert_eq!(s.abort(id, token, NOW).unwrap()["source_unchanged"], true);
        assert_eq!(
            s.status(id, token, 0, 64, NOW).unwrap_err().code,
            "NOT_FOUND"
        );
        let (replay, m2) = authorise(&actor, &mut s, 1, &[b"sealed"]);
        assert_eq!(
            s.prepare(&actor.public_key, &replay, &m2, NOW)
                .unwrap_err()
                .code,
            "STALE_SEQUENCE"
        );
    }

    fn signed_reconciliation(owner: &SigningKey, ticket: &Value, root: &str, now: i64) -> Value {
        sign(
            RECONCILE_PURPOSE,
            &json!({
                "v": 1, "actor": owner.kid,
                "stage_id": ticket["stage_id"], "to": DEST,
                "ciphertext_root": root, "challenge": ticket["reconcile_challenge"],
                "encrypted_report_sha256": sha256_b64u(TEST_REPORT),
                "client_checked": true, "issued_ms": now,
                "expires_ms": now + RECONCILE_LIFE_MS,
            }),
            owner,
        )
        .unwrap()
    }

    fn signed_device_consent(
        owner: &SigningKey,
        ticket: &Value,
        root: &str,
        now: i64,
    ) -> (Value, Value) {
        use secure_net_core::transfer::{
            create_recipient_grant, create_recipient_request, ExpectedRecipient,
            RecipientRequestInput,
        };
        let device = SigningKey::generate(true);
        let kem = secure_net_core::cv::kem::kem_keygen(None).unwrap();
        let expected = ExpectedRecipient {
            actor_id: &owner.kid,
            stage_id: ticket["stage_id"].as_str().unwrap(),
            destination: DEST,
            ciphertext_root: root,
            challenge: ticket["reconcile_challenge"].as_str().unwrap(),
            now_ms: now,
        };
        let req = create_recipient_request(
            &device,
            &RecipientRequestInput {
                expected,
                recipient_kem_public: kem["kem_pub"].as_str().unwrap(),
                expires_ms: now + 110_000,
            },
        )
        .unwrap();
        let grant = create_recipient_grant(owner, &req, &expected, now + 90_000).unwrap();
        (req, grant)
    }

    #[test]
    fn signed_recipient_consent_is_durable_immutable_and_not_an_enrolment() {
        let dir = tempfile::tempdir().unwrap();
        let owner = SigningKey::generate(true);
        let attacker = SigningKey::generate(true);
        let chunk = b"opaque recipient-bound ciphertext";
        let (manifest, root, _) = fixture(&[chunk]);
        let (id, token, request, grant) = {
            let mut stage = Stage::open(dir.path(), DEST).unwrap();
            let (intent, _) = authorise(&owner, &mut stage, 1, &[chunk]);
            let ticket = stage
                .prepare(&owner.public_key, &intent, &manifest, NOW)
                .unwrap();
            let id = ticket["stage_id"].as_str().unwrap().to_string();
            let token = ticket["stage_token"].as_str().unwrap().to_string();
            let (request, grant) = signed_device_consent(&owner, &ticket, &root, NOW + 1000);
            assert_eq!(
                stage
                    .recipient_consent(&id, &token, &owner.public_key, &request, &grant, NOW + 1000)
                    .unwrap_err()
                    .code,
                "INCOMPLETE_CIPHERTEXT"
            );
            stage.chunk(&id, &token, 0, chunk, NOW + 1000).unwrap();
            assert_eq!(
                stage
                    .recipient_consent(
                        &id,
                        &random_b64u(32),
                        &owner.public_key,
                        &request,
                        &grant,
                        NOW + 1000
                    )
                    .unwrap_err()
                    .code,
                "NOT_FOUND"
            );
            assert_eq!(
                stage
                    .recipient_consent(
                        &id,
                        &token,
                        &attacker.public_key,
                        &request,
                        &grant,
                        NOW + 1000
                    )
                    .unwrap_err()
                    .code,
                "WRONG_ACTOR"
            );
            let mut altered = grant.clone();
            altered["body"]["owner_approved"] = json!(false);
            assert_eq!(
                stage
                    .recipient_consent(
                        &id,
                        &token,
                        &owner.public_key,
                        &request,
                        &altered,
                        NOW + 1000
                    )
                    .unwrap_err()
                    .code,
                "BAD_RECIPIENT_CONSENT"
            );
            assert_eq!(
                stage
                    .signed_recipient_consent(&id, &token, NOW + 1000)
                    .unwrap_err()
                    .code,
                "NOT_FOUND"
            );
            let first = stage
                .recipient_consent(&id, &token, &owner.public_key, &request, &grant, NOW + 1000)
                .unwrap();
            assert_eq!(first["recipient_consent_staged"], true);
            assert_eq!(first["device_enrolled"], false);
            assert_eq!(first["recipient_key_proven"], false);
            assert_eq!(first["duplicate"], false);
            assert_eq!(
                stage
                    .recipient_consent(&id, &token, &owner.public_key, &request, &grant, NOW + 1001)
                    .unwrap()["duplicate"],
                true
            );
            let (replacement, alternate_grant) =
                signed_device_consent(&owner, &ticket, &root, NOW + 1000);
            assert_eq!(
                stage
                    .recipient_consent(
                        &id,
                        &token,
                        &owner.public_key,
                        &replacement,
                        &alternate_grant,
                        NOW + 1001
                    )
                    .unwrap_err()
                    .code,
                "RECIPIENT_CONSENT_CONFLICT"
            );
            assert_eq!(
                stage.status(&id, &token, 0, 64, NOW + 1000).unwrap()["recipient_consent_staged"],
                true
            );
            (id, token, request, grant)
        };
        let mut restarted = Stage::open(dir.path(), DEST).unwrap();
        let copy = restarted
            .signed_recipient_consent(&id, &token, NOW + 2000)
            .unwrap();
        assert_eq!(copy["request"], request);
        assert_eq!(copy["grant"], grant);
        assert_eq!(copy["device_enrolled"], false);
        assert_eq!(copy["recipient_key_proven"], false);
        assert_eq!(copy["cutover"], false);
        assert_eq!(
            restarted.abort(&id, &token, NOW + 2000).unwrap()["source_unchanged"],
            true
        );
        assert_eq!(
            restarted
                .signed_recipient_consent(&id, &token, NOW + 2000)
                .unwrap_err()
                .code,
            "NOT_FOUND"
        );
    }

    #[test]
    fn recipient_consent_refuses_cross_stage_replay_and_expired_signatures() {
        let dir = tempfile::tempdir().unwrap();
        let owner = SigningKey::generate(true);
        let blob = b"private sealed frame";
        let (manifest, root, _) = fixture(&[blob]);
        let mut stage = Stage::open(dir.path(), DEST).unwrap();
        let (intent, _) = authorise(&owner, &mut stage, 1, &[blob]);
        let ticket = stage
            .prepare(&owner.public_key, &intent, &manifest, NOW)
            .unwrap();
        let id = ticket["stage_id"].as_str().unwrap();
        let token = ticket["stage_token"].as_str().unwrap();
        stage.chunk(id, token, 0, blob, NOW).unwrap();
        let (req, grant) = signed_device_consent(&owner, &ticket, &root, NOW);
        assert_eq!(
            stage
                .recipient_consent(id, token, &owner.public_key, &req, &grant, NOW + 111_000)
                .unwrap_err()
                .code,
            "EXPIRED_CONSENT"
        );
        let (intent2, _) = authorise(&owner, &mut stage, 2, &[blob]);
        let ticket2 = stage
            .prepare(&owner.public_key, &intent2, &manifest, NOW)
            .unwrap();
        let id2 = ticket2["stage_id"].as_str().unwrap();
        let token2 = ticket2["stage_token"].as_str().unwrap();
        stage.chunk(id2, token2, 0, blob, NOW).unwrap();
        assert_eq!(
            stage
                .recipient_consent(id2, token2, &owner.public_key, &req, &grant, NOW + 1000)
                .unwrap_err()
                .code,
            "BAD_RECIPIENT_CONSENT"
        );
        assert_eq!(
            stage.status(id2, token2, 0, 64, NOW + 1000).unwrap()["recipient_consent_staged"],
            false
        );
    }

    #[test]
    fn only_the_original_independent_key_can_attest_after_complete_ciphertext() {
        let dir = tempfile::tempdir().unwrap();
        let owner = SigningKey::generate(true);
        let attacker = SigningKey::generate(true);
        let chunk = b"ciphertext payload only";
        let (manifest, root, _) = fixture(&[chunk]);
        let (id, token, receipt) = {
            let mut s = Stage::open(dir.path(), DEST).unwrap();
            let (intent, _) = authorise(&owner, &mut s, 1, &[chunk]);
            let ticket = s
                .prepare(&owner.public_key, &intent, &manifest, NOW)
                .unwrap();
            let id = ticket["stage_id"].as_str().unwrap().to_string();
            let token = ticket["stage_token"].as_str().unwrap().to_string();
            let receipt = signed_reconciliation(&owner, &ticket, &root, NOW + 1000);
            assert_eq!(
                s.reconcile(&id, &token, &owner.public_key, &receipt, NOW + 1000)
                    .unwrap_err()
                    .code,
                "INCOMPLETE_CIPHERTEXT"
            );
            assert_eq!(
                s.stage_report(&id, &token, TEST_REPORT, NOW + 1000)
                    .unwrap_err()
                    .code,
                "INCOMPLETE_CIPHERTEXT"
            );
            s.chunk(&id, &token, 0, chunk, NOW + 1000).unwrap();
            assert_eq!(
                s.reconcile(&id, &token, &owner.public_key, &receipt, NOW + 1000)
                    .unwrap_err()
                    .code,
                "MISSING_ENCRYPTED_REPORT"
            );
            assert_eq!(
                s.stage_report(&id, &random_b64u(32), TEST_REPORT, NOW + 1000)
                    .unwrap_err()
                    .code,
                "NOT_FOUND"
            );
            assert_eq!(
                s.stage_report(&id, &token, b"too small", NOW + 1000)
                    .unwrap_err()
                    .code,
                "REPORT_SIZE_LIMIT"
            );
            assert_eq!(
                s.stage_report(&id, &token, &[0xA5_u8; 64], NOW + 1000)
                    .unwrap_err()
                    .code,
                "BAD_REPORT_FORMAT"
            );
            assert_eq!(
                s.stage_report(
                    &id,
                    &token,
                    b"CVRPT\x02abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz",
                    NOW + 1000
                )
                .unwrap_err()
                .code,
                "BAD_REPORT_FORMAT"
            );
            let stored = s
                .stage_report(&id, &token, TEST_REPORT, NOW + 1000)
                .unwrap();
            assert_eq!(stored["report_staged"], true);
            assert_eq!(stored["duplicate"], false);
            assert_eq!(
                s.stage_report(&id, &token, TEST_REPORT, NOW + 1000)
                    .unwrap()["duplicate"],
                true
            );
            assert_eq!(
                s.stage_report(
                    &id,
                    &token,
                    b"CVRPT\x01abcdefghijklabcdefghijklmnopqrstuvwxyz123456789012",
                    NOW + 1000
                )
                .unwrap_err()
                .code,
                "REPORT_CONFLICT"
            );
            let downloaded = s.download_report(&id, &token, NOW + 1000).unwrap();
            assert_eq!(
                downloaded["ciphertext"],
                URL_SAFE_NO_PAD.encode(TEST_REPORT)
            );
            assert_eq!(downloaded["sha256"], sha256_b64u(TEST_REPORT));
            assert_eq!(
                s.reconcile(&id, &token, &attacker.public_key, &receipt, NOW + 1000)
                    .unwrap_err()
                    .code,
                "WRONG_ACTOR"
            );
            let forged = sign(RECONCILE_PURPOSE, &receipt["body"], &attacker).unwrap();
            assert_eq!(
                s.reconcile(&id, &token, &owner.public_key, &forged, NOW + 1000)
                    .unwrap_err()
                    .code,
                "BAD_SIGNATURE"
            );
            let mut wrong_stage = receipt["body"].clone();
            wrong_stage["stage_id"] = json!(random_b64u(18));
            let wrong_stage = sign(RECONCILE_PURPOSE, &wrong_stage, &owner).unwrap();
            assert_eq!(
                s.reconcile(&id, &token, &owner.public_key, &wrong_stage, NOW + 1000)
                    .unwrap_err()
                    .code,
                "BAD_RECONCILIATION"
            );
            let mut leaking_metadata = receipt["body"].clone();
            leaking_metadata["contact_name"] = json!("No plaintext metadata allowed");
            let leaking_metadata = sign(RECONCILE_PURPOSE, &leaking_metadata, &owner).unwrap();
            assert_eq!(
                s.reconcile(
                    &id,
                    &token,
                    &owner.public_key,
                    &leaking_metadata,
                    NOW + 1000
                )
                .unwrap_err()
                .code,
                "BAD_RECONCILIATION"
            );
            let mut unsafe_envelope = receipt.clone();
            unsafe_envelope["contact_name"] = json!("Plaintext must not be admitted");
            assert_eq!(
                s.reconcile(&id, &token, &owner.public_key, &unsafe_envelope, NOW + 1000)
                    .unwrap_err()
                    .code,
                "BAD_RECONCILIATION"
            );
            let first = s
                .reconcile(&id, &token, &owner.public_key, &receipt, NOW + 1000)
                .unwrap();
            assert_eq!(
                s.stage_report(&id, &token, TEST_REPORT, NOW + 1000)
                    .unwrap_err()
                    .code,
                "ALREADY_ATTESTED"
            );
            assert_eq!(first["client_attested"], true);
            assert_eq!(first["imported"], false);
            assert_eq!(first["cutover"], false);
            assert_eq!(first["duplicate"], false);
            assert_eq!(
                s.reconcile(&id, &token, &owner.public_key, &receipt, NOW + 1000)
                    .unwrap()["duplicate"],
                true
            );
            let changed = signed_reconciliation(&owner, &ticket, &root, NOW + 1001);
            assert_eq!(
                s.reconcile(&id, &token, &owner.public_key, &changed, NOW + 1001)
                    .unwrap_err()
                    .code,
                "RECONCILIATION_CONFLICT"
            );
            (id, token, receipt)
        };
        let mut restarted = Stage::open(dir.path(), DEST).unwrap();
        let status = restarted.status(&id, &token, 0, 64, NOW + 2000).unwrap();
        assert_eq!(status["client_attested"], true);
        assert_eq!(status["encrypted_report_staged"], true);
        assert_eq!(
            restarted.download_report(&id, &token, NOW + 2000).unwrap()["sha256"],
            sha256_b64u(TEST_REPORT)
        );
        assert_eq!(status["imported"], false);
        assert_eq!(status["cutover"], false);
        assert_eq!(
            restarted
                .signed_reconciliation(&id, &token, NOW + 2000)
                .unwrap()["client_signed_statement"],
            receipt
        );
        assert_eq!(
            restarted.abort(&id, &token, NOW + 2000).unwrap()["source_unchanged"],
            true
        );
        assert_eq!(
            restarted
                .signed_reconciliation(&id, &token, NOW + 2000)
                .unwrap_err()
                .code,
            "NOT_FOUND"
        );
    }

    #[test]
    fn reconciliation_refuses_expiry_and_tampered_durable_storage() {
        let dir = tempfile::tempdir().unwrap();
        let owner = SigningKey::generate(true);
        let ciphertext = b"sealed at client";
        let (manifest, root, _) = fixture(&[ciphertext]);
        let mut stage = Stage::open(dir.path(), DEST).unwrap();
        let (intent, _) = authorise(&owner, &mut stage, 1, &[ciphertext]);
        let ticket = stage
            .prepare(&owner.public_key, &intent, &manifest, NOW)
            .unwrap();
        let id = ticket["stage_id"].as_str().unwrap();
        let token = ticket["stage_token"].as_str().unwrap();
        stage.chunk(id, token, 0, ciphertext, NOW).unwrap();
        stage.stage_report(id, token, TEST_REPORT, NOW).unwrap();
        let old_receipt = signed_reconciliation(&owner, &ticket, &root, NOW);
        assert_eq!(
            stage
                .reconcile(
                    id,
                    token,
                    &owner.public_key,
                    &old_receipt,
                    NOW + RECONCILE_LIFE_MS + 1
                )
                .unwrap_err()
                .code,
            "EXPIRED_RECONCILIATION"
        );
        // Simulate a corrupted stage database, which must fail independently of
        // the previously acknowledged "complete" counter.
        stage
            .db
            .execute(
                "UPDATE chunks SET ciphertext=?1 WHERE transfer_id=?2",
                params![b"changed".to_vec(), id],
            )
            .unwrap();
        let fresh = signed_reconciliation(&owner, &ticket, &root, NOW + 1000);
        assert_eq!(
            stage
                .reconcile(id, token, &owner.public_key, &fresh, NOW + 1000)
                .unwrap_err()
                .code,
            "CORRUPT_STAGE"
        );
        assert_eq!(
            stage.status(id, token, 0, 64, NOW + 1000).unwrap()["client_attested"],
            false
        );
    }

    #[test]
    fn corrupted_stored_report_cannot_be_downloaded_or_attested() {
        let dir = tempfile::tempdir().unwrap();
        let owner = SigningKey::generate(true);
        let ciphertext = b"sealed for device";
        let (manifest, root, _) = fixture(&[ciphertext]);
        let mut stage = Stage::open(dir.path(), DEST).unwrap();
        let (intent, _) = authorise(&owner, &mut stage, 1, &[ciphertext]);
        let ticket = stage
            .prepare(&owner.public_key, &intent, &manifest, NOW)
            .unwrap();
        let id = ticket["stage_id"].as_str().unwrap();
        let token = ticket["stage_token"].as_str().unwrap();
        stage.chunk(id, token, 0, ciphertext, NOW).unwrap();
        stage.stage_report(id, token, TEST_REPORT, NOW).unwrap();
        stage
            .db
            .execute(
                "UPDATE reconciliation_reports SET ciphertext=?1 WHERE transfer_id=?2",
                params![[0x0_u8; 64].as_slice(), id],
            )
            .unwrap();
        let valid = signed_reconciliation(&owner, &ticket, &root, NOW + 1000);
        assert_eq!(
            stage
                .reconcile(id, token, &owner.public_key, &valid, NOW + 1000)
                .unwrap_err()
                .code,
            "REPORT_HASH_MISMATCH"
        );
        assert_eq!(
            stage
                .download_report(id, token, NOW + 1000)
                .unwrap_err()
                .code,
            "CORRUPT_REPORT"
        );
        assert_eq!(
            stage.status(id, token, 0, 64, NOW + 1000).unwrap()["client_attested"],
            false
        );
    }

    #[test]
    fn validly_signed_reconciliation_cannot_attest_to_a_different_report() {
        let dir = tempfile::tempdir().unwrap();
        let owner = SigningKey::generate(true);
        let ciphertext = b"sealed for one device";
        let (manifest, root, _) = fixture(&[ciphertext]);
        let mut stage = Stage::open(dir.path(), DEST).unwrap();
        let (intent, _) = authorise(&owner, &mut stage, 1, &[ciphertext]);
        let ticket = stage
            .prepare(&owner.public_key, &intent, &manifest, NOW)
            .unwrap();
        let id = ticket["stage_id"].as_str().unwrap();
        let token = ticket["stage_token"].as_str().unwrap();
        stage.chunk(id, token, 0, ciphertext, NOW).unwrap();
        stage.stage_report(id, token, TEST_REPORT, NOW).unwrap();
        let mut different_report =
            signed_reconciliation(&owner, &ticket, &root, NOW + 1000)["body"].clone();
        different_report["encrypted_report_sha256"] = json!(sha256_b64u(&[0xC0_u8; 64]));
        let wrong_receipt = sign(RECONCILE_PURPOSE, &different_report, &owner).unwrap();
        assert_eq!(
            stage
                .reconcile(id, token, &owner.public_key, &wrong_receipt, NOW + 1000)
                .unwrap_err()
                .code,
            "REPORT_HASH_MISMATCH"
        );
        assert_eq!(
            stage.status(id, token, 0, 64, NOW + 1000).unwrap()["client_attested"],
            false
        );
        let correct = signed_reconciliation(&owner, &ticket, &root, NOW + 1000);
        assert_eq!(
            stage
                .reconcile(id, token, &owner.public_key, &correct, NOW + 1000)
                .unwrap()["client_attested"],
            true
        );
    }

    #[test]
    fn experimental_schema_upgrade_preserves_existing_stage_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("migration-stage-experimental.db");
        {
            let db = Connection::open(&path).unwrap();
            db.execute_batch(
                "CREATE TABLE transfers(
                    id TEXT PRIMARY KEY, actor TEXT NOT NULL,
                    root TEXT NOT NULL, expected_chunks INTEGER NOT NULL,
                    expected_bytes INTEGER NOT NULL, token_hash BLOB NOT NULL,
                    expires INTEGER NOT NULL, complete INTEGER NOT NULL DEFAULT 0,
                    manifest TEXT NOT NULL
                );
                INSERT INTO transfers(id,actor,root,expected_chunks,expected_bytes,token_hash,expires,manifest)
                VALUES('existing','actor','root',1,10,x'FF',9999999999999,'{}');"
            ).unwrap();
        }
        let s = Stage::open(dir.path(), DEST).unwrap();
        assert_eq!(
            s.db.query_row(
                "SELECT count(*) FROM transfers WHERE id='existing'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        let (nonce, record): (String, Option<String>) =
            s.db.query_row(
                "SELECT reconcile_nonce,reconcile_record FROM transfers WHERE id='existing'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(nonce, "");
        assert!(record.is_none());
    }

    #[test]
    fn disabled_path_is_not_exposed_until_operator_opt_in() {
        let dir = tempfile::tempdir().unwrap();
        let (status, reply) = route(
            dir.path(),
            DEST,
            "GET",
            "/cvp/v2/experimental-transfer/unknown",
            "",
            b"",
            NOW,
        );
        assert_eq!(status, 404);
        assert_eq!(reply["code"], "NOT_FOUND");
        let classical = SigningKey::generate(false);
        let (status, reply) = route(
            dir.path(),
            DEST,
            "POST",
            "/cvp/v2/experimental-transfer/challenge",
            "",
            json!({"owner_public": classical.public_key})
                .to_string()
                .as_bytes(),
            NOW,
        );
        assert_eq!(status, 400);
        assert_eq!(reply["code"], "HYBRID_KEY_REQUIRED");
    }
}
