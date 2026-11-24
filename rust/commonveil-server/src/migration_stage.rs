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
use secure_net_core::canonical::canonical_bytes;
use secure_net_core::signed::{key_id, verify};
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
    let commitment =
        canonical_bytes(&json!({ "v": 1, "chunks": rows })).map_err(|_| StageError {
            status: 400,
            code: "BAD_MANIFEST",
        })?;
    Ok((sha256_b64u(&commitment), total))
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
                manifest TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS transfers_actor ON transfers(actor);
             CREATE TABLE IF NOT EXISTS chunks (
                transfer_id TEXT NOT NULL,
                idx INTEGER NOT NULL,
                digest TEXT NOT NULL,
                ciphertext BLOB NOT NULL,
                PRIMARY KEY(transfer_id, idx),
                FOREIGN KEY(transfer_id) REFERENCES transfers(id) ON DELETE CASCADE
             );",
        )
        .map_err(|_| StageError {
            status: 500,
            code: "STAGE_UNAVAILABLE",
        })?;
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
        let hash = sha256(token.as_bytes());
        tx.execute(
            "INSERT INTO transfers(id,actor,root,expected_chunks,expected_bytes,token_hash,expires,manifest)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![id, actor, root, manifest.len() as i64, bytes as i64,
                hash.as_slice(), now + TRANSFER_LIFE, json!({"v":1,"chunks":manifest}).to_string()],
        ).map_err(|_| StageError { status: 500, code: "STAGE_UNAVAILABLE" })?;
        tx.commit().map_err(|_| StageError {
            status: 500,
            code: "STAGE_UNAVAILABLE",
        })?;
        Ok(json!({
            "stage_id": id, "stage_token": token,
            "expires_ms": now + TRANSFER_LIFE,
            "ciphertext_complete": false, "imported": false, "cutover": false
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
        let stored: Option<(Vec<u8>, i64, String, i64, i64, i64)> = self
            .db
            .query_row(
                "SELECT token_hash, expires, manifest, expected_chunks, expected_bytes, complete
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
                    ))
                },
            )
            .optional()
            .map_err(|_| StageError {
                status: 500,
                code: "STAGE_UNAVAILABLE",
            })?;
        let Some((hash, expires, manifest, chunks, bytes, complete)) = stored else {
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
        Ok(json!({"manifest":manifest, "chunks":chunks,"bytes":bytes,"complete":complete != 0}))
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
        Ok(
            json!({ "received": count, "expected": expected, "missing": missing,
            "next_cursor": next, "ciphertext_complete": state["complete"],
            "imported": false, "cutover": false }),
        )
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
