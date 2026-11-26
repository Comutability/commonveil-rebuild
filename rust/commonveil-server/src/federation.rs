//! The Commonveil Protocol (server/federation/index.mjs): how self-hosted Commonveil sites talk to
//! each other. docs/FEDERATION.md is the specification; this is the implementation.
//!
//! The model, in short:
//! - Identity is an address. Alice on chat.example.com is @alice.chat.example.com; that name
//!   answers who she is (/.well-known/commonveil/identity) and, in a browser, leads to her profile.
//! - Every conversation and every server lives on one site, its host. People always talk to their
//!   own site (their home). When they open something hosted elsewhere, their home relays the call,
//!   signed with the home site's key, and the host runs it as that person.
//! - On the host, a person from another site is a "shadow" account with the same id, whose public
//!   keys and devices are copied from their home with every call. Their keys sign themselves (each
//!   key statement is signed by the one before, and devices are certified by the account), and
//!   everyone's app checks them as it does today, so nothing about end-to-end encryption changes:
//!   the host stores ciphertext it can't read, like any Commonveil site.
use std::collections::HashMap;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use axum::body::Body;
use axum::extract::ws::{CloseFrame, Message as ClientMessage, WebSocket};
use axum::extract::Request;
use axum::http::{HeaderMap, Response};
use futures_util::{SinkExt, StreamExt};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use rusqlite::{params, OptionalExtension};
use secure_net_core::wire::federation::{DEFAULT_ENDPOINTS, PROTOCOL};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio_tungstenite::tungstenite::Message as UpstreamMessage;

use crate::api::ApiError;
use crate::db::{id_of, Db};
use crate::fed_net::{
    b64u, fed_err, js_slice, norm_host, strip_port, unb64u, FedResult, Signer, Transport,
};
use crate::http;
use crate::js::{to_js_string, truthy};
use crate::protocol::js_stringify;
use crate::shared::{blocked_either_way, peer_device_out, statement_out};
use crate::App;

// Where something lives (docs/FEDERATION.md, "Routes"). Ids a site gives its own records: where one
// appears, it says which site holds it.
const ID_KEYS: [&str; 10] = [
    "conversation_id",
    "server_id",
    "channel_id",
    "case_id",
    "message_id",
    "ticket_id",
    "invite_id",
    "role_id",
    "id",
    "parent_id",
];
// Not file ids: a message's list of file parts is chosen by its sender, so a request routed by them
// could be steered to the sender's site. A file is found by where it was posted (docs/FEDERATION.md).
const ID_LIST_KEYS: [&str; 4] = [
    "conversation_ids",
    "server_ids",
    "channel_ids",
    "message_ids",
];
/// Ids a person's app chooses (a thread is named by its first message, an event and a server report
/// by their items): anyone can write any value there, so they only route a request that names
/// nothing else, and never outweigh what a site says about its own records.
const CHOSEN_KEYS: [&str; 3] = ["thread_id", "event_id", "report_id"];
/// What an app names when it picks the site itself (_site): the place the request is about.
const PLACE_KEYS: [&str; 6] = [
    "conversation_id",
    "server_id",
    "channel_id",
    "conversation_ids",
    "server_ids",
    "channel_ids",
];
/// How much a claim about where something lives counts. Claims are kept per person: what one site
/// says to one person never moves anyone else's requests. The highest claim wins; two sites with
/// the same highest claim are a dispute, and the request goes to neither.
/// A chosen id (above) in an answer.
pub const CLAIM_CHOSEN: i64 = 0;
/// A site's answer to this person's request, or its notice that they joined something there.
pub const CLAIM_IMPLICIT: i64 = 1;
/// Learned before 0.24.25, for everyone here (routes then weren't kept per person).
pub const CLAIM_LEGACY: i64 = 2;
/// The person's app named the site (_site), and the site answered.
pub const CLAIM_EXPLICIT: i64 = 3;

/// Where something lives, for one person.
#[derive(Debug, Clone, PartialEq)]
pub enum Route {
    Unknown,
    Host(String),
    /// More than one site makes the highest claim.
    Disputed(Vec<String>),
}

/// How much a claim from a site the person's app named counts: named, unless another site already
/// holds the thing for them by an old route or a named claim. Then only heard: a site can't take over
/// what someone already has by answering a join. (strength, the other site)
pub fn named_claim_strength(claims: &[(String, i64)], host: &str) -> (i64, Option<String>) {
    let mut others: Vec<&(String, i64)> = claims
        .iter()
        .filter(|(h, s)| h != host && *s >= CLAIM_LEGACY)
        .collect();
    others.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    match others.first() {
        Some((h, _)) => (CLAIM_IMPLICIT, Some(h.clone())),
        None => (CLAIM_EXPLICIT, None),
    }
}

/// The claims for one thing, as (site, strength), with blocked sites already left out.
pub fn resolve_route(claims: &[(String, i64)]) -> Route {
    let Some(top) = claims.iter().map(|(_, s)| *s).max() else {
        return Route::Unknown;
    };
    let mut hosts: Vec<String> = claims
        .iter()
        .filter(|(_, s)| *s == top)
        .map(|(h, _)| h.clone())
        .collect();
    hosts.sort();
    hosts.dedup();
    if hosts.len() == 1 {
        Route::Host(hosts.remove(0))
    } else {
        Route::Disputed(hosts)
    }
}
pub const MAX_ACT_BODY: usize = 9 * 1024 * 1024;
// Held messages (docs/OFFLINE.md): tried again after 30 seconds, then less and less often (at
// most every 30 minutes), for up to a week; the same week a message written offline may wait.
const HELD_EVERY_MS: u64 = 30_000;
const HELD_FIRST_RETRY_MS: i64 = 30_000;
const HELD_MAX_WAIT_MS: i64 = 30 * 60_000;
const HELD_MAX_AGE_MS: i64 = 7 * 24 * 3_600_000;
const SHADOW_FIELDS: [&str; 6] = [
    "display_name",
    "bio",
    "pronouns",
    "accent_color",
    "avatar_emoji",
    "avatar_image",
];
const ACTOR_NAMES: [&str; 2] = ["VoiceRoom", "Presence"];
/// Actions that, with no conversation or server named, mean "everything of mine", here and
/// elsewhere (base44/shared/federation/merge.ts).
const FAN_OUT: [(&str, &str); 7] = [
    ("messages.poll", "merge"),
    ("conversations.list", "merge"),
    ("servers.list", "merge"),
    ("messages.scheduled", "merge"),
    ("messages.deliver_mine", "merge"),
    ("keys.peer_keys", "people"),
    ("profile.get_many", "people"),
];
/// Request cursor field, and the reply field it comes back in.
const CURSOR_FIELDS: [(&str, &str); 4] = [
    ("since", "cursor"),
    ("conversations_since", "conversations_cursor"),
    ("servers_since", "servers_cursor"),
    ("server_changes_since", "server_changes_cursor"),
];
/// JavaScript's encodeURIComponent leaves these as they are.
const URI_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');
const IDENTITY_PATH: &str = "/.well-known/commonveil/identity";

fn now_ms() -> i64 {
    crate::sessions::now_ms()
}

fn id24(s: &str) -> bool {
    s.len() == 24
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn enc(s: &str) -> String {
    utf8_percent_encode(s, URI_COMPONENT).to_string()
}

fn dec(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

/// HANDLE_RE: `^[a-z0-9][a-z0-9-]{1,19}(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`.
pub fn handle_ok(v: &str) -> bool {
    let mut parts = v.split('.');
    let first = parts.next().unwrap_or("").as_bytes();
    let first_ok = (2..=20).contains(&first.len())
        && (first[0].is_ascii_lowercase() || first[0].is_ascii_digit())
        && first
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-');
    let rest: Vec<&str> = parts.collect();
    let label = |l: &str| {
        let b = l.as_bytes();
        let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
        !b.is_empty()
            && b.len() <= 63
            && edge(b[0])
            && edge(b[b.len() - 1])
            && b.iter().all(|c| edge(*c) || *c == b'-')
    };
    first_ok && !rest.is_empty() && rest.iter().all(|l| label(l))
}

fn str_of(v: Option<&Value>) -> String {
    if truthy(v) {
        to_js_string(v)
    } else {
        String::new()
    }
}

/// Routes from before 0.24.25 (one table for everyone, first claim kept) become site-wide claims
/// that a person's own explicit choice can still overrule. The old table stays, untouched: if the
/// updater rolls back to 0.24.24, that version still finds its routes. Copying again changes nothing.
pub fn migrate_routes(db: &rusqlite::Connection) -> rusqlite::Result<()> {
    let old: Option<String> = db
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'fed_routes'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if old.is_some() {
        db.execute(&format!("INSERT OR IGNORE INTO fed_claims (user_id, id, host, strength, seen) SELECT '*', id, host, {CLAIM_LEGACY}, seen FROM fed_routes"), [])?;
    }
    Ok(())
}

/// At most this many ids are learned from one answer: what one answer says can't make unbounded
/// work.
const MAX_LEARNED: usize = 2000;
/// At most this many membership notices from one site that add a new claim for one person, in an
/// hour (notice_allowed, keyed "site person"). Refreshes and leaves don't count, so an honest
/// site's bulk join only counts each person's new rooms. This slows how fast notices alone add
/// claims; it doesn't bound the claims an answer to someone's own request adds. Claims are never
/// removed to make room: removing one could leave a rogue site's claim as the only one.
pub const NOTICES_PER_HOUR: u32 = 1000;
static NOTICE_COUNTS: std::sync::OnceLock<Mutex<HashMap<String, (i64, u32)>>> =
    std::sync::OnceLock::new();
/// Whether one more counted membership notice for this key ("site person") is taken this hour.
pub fn notice_allowed(key: &str, now: i64) -> bool {
    let hour = now / 3_600_000;
    let mut counts = NOTICE_COUNTS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if counts.len() > 100_000 {
        counts.clear();
    }
    let c = counts.entry(key.to_string()).or_insert((hour, 0));
    if c.0 != hour {
        *c = (hour, 0);
    }
    c.1 += 1;
    c.1 <= NOTICES_PER_HOUR
}

/// Say something about two sites at most once an hour: a site can't flood the log.
fn warn_once(kind: &str, a: &str, b: &str, line: impl FnOnce() -> String) {
    static LAST: std::sync::OnceLock<Mutex<HashMap<String, i64>>> = std::sync::OnceLock::new();
    let key = if a < b {
        format!("{kind} {a} {b}")
    } else {
        format!("{kind} {b} {a}")
    };
    let now = now_ms();
    let mut last = LAST
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if last.len() > 10_000 {
        last.clear();
    }
    if last.get(&key).is_some_and(|t| now - t < 3_600_000) {
        return;
    }
    last.insert(key, now);
    eprintln!("{}", line());
}

/// The ids a request or an answer names: (id, true if it's under a key an app chooses the value of).
fn ids_named(
    v: &Value,
    key: &str,
    depth: usize,
    max_depth: usize,
    per_list: usize,
    out: &mut Vec<(String, bool)>,
) {
    if depth > max_depth {
        return;
    }
    match v {
        Value::String(s) if (ID_KEYS.contains(&key) || ID_LIST_KEYS.contains(&key)) && id24(s) => {
            out.push((s.clone(), false))
        }
        Value::String(s) if CHOSEN_KEYS.contains(&key) && id24(s) => out.push((s.clone(), true)),
        Value::Array(a) => a
            .iter()
            .take(per_list)
            .for_each(|x| ids_named(x, key, depth + 1, max_depth, per_list, out)),
        Value::Object(o) => o
            .iter()
            .for_each(|(k, x)| ids_named(x, k, depth + 1, max_depth, per_list, out)),
        _ => {}
    }
}

/// The places a request names (PLACE_KEYS) at the top level of its body and of its signed
/// payload. Only the top level: an id nested deeper is data, not the place the request is about,
/// and the hosted site looks no deeper either.
fn places_named(body: &Value) -> Vec<String> {
    fn take(v: &Value, out: &mut Vec<String>) {
        let Some(o) = v.as_object() else { return };
        for (k, x) in o {
            if !PLACE_KEYS.contains(&k.as_str()) {
                continue;
            }
            match x {
                Value::String(s) if id24(s) => out.push(s.clone()),
                Value::Array(a) => a
                    .iter()
                    .take(500)
                    .filter_map(Value::as_str)
                    .filter(|s| id24(s))
                    .for_each(|s| out.push(s.to_string())),
                _ => {}
            }
        }
    }
    let mut out = Vec::new();
    take(body, &mut out);
    if let Some(payload) = body["payload"].as_str() {
        if let Ok(parsed) = serde_json::from_str::<Value>(payload) {
            take(&parsed, &mut out);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// What a store watcher saw, for the federation's own thread (watchers run while the store is
/// locked, so they only hand work on).
pub enum Job {
    Write(String, Value, Option<Value>),
    Remove(String, Value),
}

struct Shadow {
    home: String,
    digest: String,
}

pub struct Federation {
    app: Weak<App>,
    pub enabled: bool,
    pub host: String,
    pub signer: Signer,
    jobs: Mutex<Option<Receiver<Job>>>,
    soon: Mutex<HashMap<String, u64>>,
}

impl Federation {
    /// The site's address, its signer and the federation tables: everything that can fail, done
    /// before the app is made.
    pub fn prepare(
        config: &crate::config::Config,
        store: &crate::store::Store,
        transport: Option<Transport>,
    ) -> Result<(String, Signer), String> {
        let port = url::Url::parse(&config.site_url)
            .ok()
            .and_then(|u| u.port());
        let host = match port {
            Some(p) => format!("{}:{p}", config.host),
            None => config.host.clone(),
        };
        let signer = Signer::new(
            &host,
            store,
            transport.unwrap_or_else(|| Transport::new(config.allow_private_federation)),
        )?;
        store
            .with_db(|db| {
                db.execute_batch(
                    "CREATE TABLE IF NOT EXISTS fed_claims (user_id TEXT NOT NULL, id TEXT NOT NULL, host TEXT NOT NULL, strength INTEGER NOT NULL, seen INTEGER NOT NULL, PRIMARY KEY (user_id, id, host));
                     CREATE INDEX IF NOT EXISTS fed_claims_by_id ON fed_claims (id);
                     CREATE TABLE IF NOT EXISTS fed_user_hosts (user_id TEXT NOT NULL, host TEXT NOT NULL, seen INTEGER NOT NULL, PRIMARY KEY (user_id, host));
                     CREATE TABLE IF NOT EXISTS fed_shadows (user_id TEXT PRIMARY KEY, home TEXT NOT NULL, handle TEXT NOT NULL, digest TEXT NOT NULL DEFAULT '', updated INTEGER NOT NULL);
                     CREATE TABLE IF NOT EXISTS fed_notified (user_id TEXT NOT NULL, room TEXT NOT NULL, PRIMARY KEY (user_id, room));
                     CREATE TABLE IF NOT EXISTS fed_outbox (host TEXT NOT NULL, msg_id TEXT NOT NULL, user_id TEXT NOT NULL, fn TEXT NOT NULL, body TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_at INTEGER NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (host, msg_id));",
                )?;
                migrate_routes(db)
            })
            .map_err(|e| e.to_string())?;
        Ok((host, signer))
    }

    pub fn new(
        app: Weak<App>,
        enabled: bool,
        host: String,
        signer: Signer,
        jobs: Receiver<Job>,
    ) -> Self {
        Self {
            app,
            enabled,
            host,
            signer,
            jobs: Mutex::new(Some(jobs)),
            soon: Mutex::new(HashMap::new()),
        }
    }

    fn app(&self) -> Arc<App> {
        self.app.upgrade().expect("the app outlives its federation")
    }

    // ---------- the federation tables ----------

    fn sql<R>(&self, f: impl FnOnce(&rusqlite::Connection) -> rusqlite::Result<R>) -> Option<R> {
        self.app().store.with_db(f).ok()
    }

    /// Where something on another site lives, for this person: their own claims and the site-wide
    /// ones from before 0.24.25, leaving out blocked sites.
    pub fn route_of(&self, user_id: &str, id: &str) -> Route {
        resolve_route(&self.claims_of(user_id, id))
    }
    /// The route a request takes for one id. A chosen id (CHOSEN_KEYS) routes only by chosen
    /// claims, and anything else only by heard claims or stronger: a notice can't steer a chosen
    /// id, and a chosen id in an answer never steers a request about a place or a room.
    fn route_for(&self, user_id: &str, id: &str, chosen: bool) -> Route {
        let claims: Vec<(String, i64)> = self
            .claims_of(user_id, id)
            .into_iter()
            .filter(|(_, s)| {
                if chosen {
                    *s == CLAIM_CHOSEN
                } else {
                    *s >= CLAIM_IMPLICIT
                }
            })
            .collect();
        resolve_route(&claims)
    }
    fn claims_of(&self, user_id: &str, id: &str) -> Vec<(String, i64)> {
        self.sql(|db| {
            db.prepare("SELECT c.host, MAX(c.strength) FROM fed_claims c LEFT JOIN fed_sites s ON s.host = c.host WHERE c.id = ? AND c.user_id IN (?, '*') AND COALESCE(s.blocked, 0) = 0 GROUP BY c.host")?
                .query_map([id, user_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
                .collect::<rusqlite::Result<Vec<(String, i64)>>>()
        })
        .unwrap_or_default()
    }
    /// A claim from a site the person's app named: see named_claim_strength.
    fn claim_named(&self, user_id: &str, id: &str, host: &str, now: i64) {
        if !id24(id) || host == self.host || self.app().store.has(id) {
            return;
        }
        let (strength, other) = named_claim_strength(&self.claims_of(user_id, id), host);
        if let Some(other) = other {
            warn_once("named", host, &other, || {
                format!("[federation] {host} answered as the home of something {other} already holds for someone here; it stays with {other}. Block whichever is wrong.")
            });
        }
        self.claim(user_id, id, host, strength, now);
    }
    /// Whether this site already has a claim on this id for this person.
    fn has_claim(&self, user_id: &str, id: &str, host: &str) -> bool {
        self.sql(|db| {
            db.query_row(
                "SELECT COUNT(*) FROM fed_claims WHERE user_id = ? AND id = ? AND host = ?",
                [user_id, id, host],
                |r| r.get::<_, i64>(0),
            )
        })
        .unwrap_or(0)
            > 0
    }
    /// Record a site's claim that it holds something, for one person. Never for something that's here.
    fn claim(&self, user_id: &str, id: &str, host: &str, strength: i64, now: i64) {
        if !id24(id) || host == self.host || self.app().store.has(id) {
            return;
        }
        // Heard before, as strongly: nothing changes but when.
        let same = self.sql(|db| db.execute("UPDATE fed_claims SET seen = ? WHERE user_id = ? AND id = ? AND host = ? AND strength >= ?", params![now, user_id, id, host, strength])).unwrap_or(0);
        if same > 0 {
            return;
        }
        let before = self.route_of(user_id, id);
        self.sql(|db| db.execute("INSERT INTO fed_claims (user_id, id, host, strength, seen) VALUES (?, ?, ?, ?, ?) ON CONFLICT(user_id, id, host) DO UPDATE SET strength = MAX(strength, excluded.strength), seen = excluded.seen", params![user_id, id, host, strength, now]));
        // Which sites, never what or whose: the admin can block the one that's wrong.
        let claims = self.claims_of(user_id, id);
        match resolve_route(&claims) {
            Route::Disputed(hosts) if !matches!(before, Route::Disputed(_)) && hosts.len() == 2 => {
                warn_once("dispute", &hosts[0], &hosts[1], || {
                    format!("[federation] {} each claim to hold the same thing; requests about it go to neither. Block whichever is wrong.", hosts.join(" and "))
                });
            }
            Route::Disputed(hosts) if !matches!(before, Route::Disputed(_)) => {
                warn_once("dispute", &hosts[0], host, || {
                    format!("[federation] {} each claim to hold the same thing; requests about it go to neither. Block whichever is wrong.", hosts.join(", "))
                });
            }
            // A route from before 0.24.25 outweighs what this site says: it could be one a site
            // took over then, so say so.
            Route::Host(winner)
                if winner != host
                    && strength < CLAIM_LEGACY
                    && claims
                        .iter()
                        .any(|(h, s)| *h == winner && *s == CLAIM_LEGACY) =>
            {
                warn_once("older", &winner, host, || {
                    format!("[federation] {winner} (a route from before 0.24.25) and {host} each claim to hold the same thing; the older route is used. Block whichever is wrong.")
                });
            }
            _ => {}
        }
    }
    pub fn hosts_of(&self, user_id: &str) -> Vec<String> {
        self.sql(|db| {
            db.prepare("SELECT host FROM fed_user_hosts WHERE user_id = ?")?
                .query_map([user_id], |r| r.get(0))?
                .collect::<rusqlite::Result<Vec<String>>>()
        })
        .unwrap_or_default()
    }
    fn put_host(&self, user_id: &str, host: &str, now: i64) {
        self.sql(|db| db.execute("INSERT INTO fed_user_hosts (user_id, host, seen) VALUES (?, ?, ?) ON CONFLICT(user_id, host) DO UPDATE SET seen = excluded.seen", params![user_id, host, now]));
    }
    fn drop_host(&self, user_id: &str, host: &str) {
        self.sql(|db| {
            db.execute(
                "DELETE FROM fed_user_hosts WHERE user_id = ? AND host = ?",
                params![user_id, host],
            )
        });
    }
    fn shadow(&self, user_id: &str) -> Option<Shadow> {
        self.sql(|db| {
            db.query_row(
                "SELECT home, digest FROM fed_shadows WHERE user_id = ?",
                [user_id],
                |r| {
                    Ok(Shadow {
                        home: r.get(0)?,
                        digest: r.get(1)?,
                    })
                },
            )
            .optional()
        })
        .flatten()
    }
    fn shadow_by_handle(&self, handle: &str) -> Option<(String, String)> {
        self.sql(|db| {
            db.query_row(
                "SELECT user_id, home FROM fed_shadows WHERE handle = ?",
                [handle],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
        })
        .flatten()
    }
    fn put_shadow(&self, user_id: &str, home: &str, handle: &str, digest: &str, now: i64) {
        self.sql(|db| db.execute("INSERT INTO fed_shadows (user_id, home, handle, digest, updated) VALUES (?, ?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET handle = excluded.handle, digest = excluded.digest, updated = excluded.updated", params![user_id, home, handle, digest, now]));
    }
    fn notified(&self, user_id: &str, room: &str) -> bool {
        self.sql(|db| {
            db.query_row(
                "SELECT 1 FROM fed_notified WHERE user_id = ? AND room = ?",
                [user_id, room],
                |_| Ok(()),
            )
            .optional()
        })
        .flatten()
        .is_some()
    }
    fn set_notified(&self, user_id: &str, room: &str, on: bool) {
        let q = if on {
            "INSERT OR IGNORE INTO fed_notified (user_id, room) VALUES (?, ?)"
        } else {
            "DELETE FROM fed_notified WHERE user_id = ? AND room = ?"
        };
        self.sql(|db| db.execute(q, [user_id, room]));
    }

    // ---------- starting ----------

    /// The watchers' thread, and the timer for held messages.
    pub fn start(self: &Arc<Self>) {
        if !self.enabled {
            return;
        }
        if let Some(rx) = self.jobs.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let me = Arc::downgrade(self);
            std::thread::spawn(move || {
                for job in rx {
                    let Some(fed) = me.upgrade() else { break };
                    if fed.app.upgrade().is_none() {
                        break;
                    }
                    fed.handle_job(job);
                }
            });
        }
        let me = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(HELD_EVERY_MS));
            tick.tick().await;
            loop {
                tick.tick().await;
                let Some(fed) = me.upgrade() else { break };
                if fed.app.upgrade().is_none() {
                    break;
                }
                let _ = tokio::task::spawn_blocking(move || fed.deliver_held(now_ms())).await;
            }
        });
    }

    fn handle_job(self: &Arc<Self>, job: Job) {
        match job {
            Job::Write(entity, row, old) => {
                self.watch_membership(&entity, &row, old.as_ref());
                let uid = str_of(row.get("user_id"));
                if (entity == "AccountKey" || entity == "Device") && self.shadow(&uid).is_none() {
                    self.soon(format!("keys:{uid}"), move |fed| fed.keys_changed(&uid));
                } else if entity == "Block" && old.is_none() && self.shadow(&uid).is_none() {
                    self.block_changed(&uid, &str_of(row.get("blocked_user_id")), true);
                }
            }
            Job::Remove(entity, row) => {
                let uid = str_of(row.get("user_id"));
                if entity == "Block" && self.shadow(&uid).is_none() {
                    self.block_changed(&uid, &str_of(row.get("blocked_user_id")), false);
                }
            }
        }
    }

    /// Run `f` a moment from now, unless asked again under the same key before then.
    fn soon(self: &Arc<Self>, key: String, f: impl FnOnce(&Arc<Self>) + Send + 'static) {
        let generation = {
            let mut m = self.soon.lock().unwrap_or_else(|e| e.into_inner());
            let g = m.entry(key.clone()).or_insert(0);
            *g += 1;
            *g
        };
        let me = self.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(1500));
            let mine = {
                let mut m = me.soon.lock().unwrap_or_else(|e| e.into_inner());
                let current = m.get(&key) == Some(&generation);
                if current {
                    m.remove(&key);
                }
                current
            };
            if mine && me.app.upgrade().is_some() {
                f(&me);
            }
        });
    }

    /// Send a notice to another site without waiting for it.
    fn notify(self: &Arc<Self>, host: String, name: &'static str, payload: Value) {
        let me = self.clone();
        std::thread::spawn(move || {
            let Some(app) = me.app.upgrade() else { return };
            if let Err(e) = me.signer.send(&app.store, &host, name, &payload, None) {
                eprintln!("[federation] couldn't tell {host} something: {}", e.message);
            }
        });
    }

    // ---------- handles ----------

    /// A local person's handle: their username (underscores become hyphens), then the handle domain.
    pub fn handle_for(&self, username: &str) -> String {
        format!(
            "{}.{}",
            username.to_lowercase().replace('_', "-"),
            self.app().config.handle_domain
        )
    }

    /// The local username a handle names, if it's one of ours.
    fn local_username(&self, handle: &str) -> Option<String> {
        let suffix = format!(".{}", self.app().config.handle_domain);
        let label = handle.strip_suffix(&suffix)?;
        ((3..=20).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
        .then(|| label.replace('-', "_"))
    }

    fn local_profile(&self, username: &str) -> FedResult<Option<Value>> {
        let app = self.app();
        let rows = Db::service(&app.store).filter(
            "Profile",
            json!({ "username_key": username.to_lowercase() }),
            "created_date",
            1,
        )?;
        Ok(rows.into_iter().next().filter(|p| !truthy(p.get("remote"))))
    }

    /// This site's own people, as other sites see them: handle, id, and where their profile is.
    fn identity(&self, profile: &Value) -> Value {
        let username = to_js_string(profile.get("username"));
        json!({ "handle": self.handle_for(&username), "user_id": profile["user_id"], "home": self.host, "profile_url": format!("{}/u/{username}", self.app().config.site_url) })
    }

    /// What one of our people shares with other sites: public profile fields and public keys.
    pub fn card(&self, user_id: &str) -> FedResult<Option<Value>> {
        let app = self.app();
        let sr = Db::service(&app.store);
        let Some(profile) = sr
            .filter("Profile", json!({ "user_id": user_id }), "created_date", 1)?
            .into_iter()
            .next()
            .filter(|p| !truthy(p.get("remote")))
        else {
            return Ok(None);
        };
        let statements: Vec<Value> = sr
            .filter("AccountKey", json!({ "user_id": user_id }), "version", 500)?
            .iter()
            .map(statement_out)
            .collect();
        let devices: Vec<Value> = sr
            .filter("Device", json!({ "user_id": user_id }), "created_date", 200)?
            .iter()
            .filter(|d| d["status"] == "active" || d["status"] == "revoked")
            .map(peer_device_out)
            .collect();
        let visibility = if truthy(profile.get("profile_visibility")) {
            to_js_string(profile.get("profile_visibility"))
        } else {
            "shared".into()
        };
        let mut shown = Map::new();
        for f in SHADOW_FIELDS {
            shown.insert(
                f.into(),
                if visibility == "nobody" {
                    json!("")
                } else if truthy(profile.get(f)) {
                    profile[f].clone()
                } else {
                    json!("")
                },
            );
        }
        shown.insert("profile_visibility".into(), json!(visibility));
        shown.insert(
            "dm_policy".into(),
            if truthy(profile.get("dm_policy")) {
                profile["dm_policy"].clone()
            } else {
                json!("anyone")
            },
        );
        Ok(Some(
            json!({ "id": user_id, "handle": self.handle_for(&to_js_string(profile.get("username"))), "profile": shown, "directory": { "statements": statements, "devices": devices } }),
        ))
    }

    /// For the handlers: find someone by handle, check they accept a conversation from `me`, keep
    /// a copy of their public keys here, and answer their id. Anything that goes wrong on the way
    /// is the handler's "something went wrong", as on the Node.js server.
    pub fn resolve_for_handler(
        self: &Arc<Self>,
        handle: &str,
        me: &str,
    ) -> crate::api::Result<Option<String>> {
        self.resolve_handle(handle, me)
            .map_err(|e| ApiError::new(500, "INTERNAL", &e.message))
    }

    pub fn resolve_handle(self: &Arc<Self>, handle: &str, me: &str) -> FedResult<Option<String>> {
        if !self.enabled {
            return Ok(None);
        }
        let handle = handle.to_lowercase();
        if !handle_ok(&handle) {
            return Ok(None);
        }
        if let Some(local) = self.local_username(&handle) {
            return Ok(self
                .local_profile(&local)?
                .map(|p| to_js_string(p.get("user_id"))));
        }
        let ident = match self.shadow_by_handle(&handle) {
            Some(known) => Some(known),
            None => self.lookup_handle(&handle),
        };
        let Some((user_id, home)) = ident else {
            return Ok(None);
        };
        let me_card = self.card(me)?;
        let requester = me_card
            .as_ref()
            .map_or(Value::Null, |c| json!({ "id": me, "handle": c["handle"] }));
        let app = self.app();
        let r = self.signer.send(&app.store, &home, "directory", &json!({ "user_id": user_id, "handle": handle, "requester": requester, "purpose": "conversation" }), None)?;
        if r.status != 200 || !truthy(r.data.get("user")) {
            return Ok(None);
        }
        self.mirror(&home, &r.data["user"])?;
        Ok(Some(to_js_string(r.data["user"].get("id"))))
    }

    /// Who a handle on another site is: its own name answers first (like the AT Protocol's
    /// handles), its parent domain second.
    fn lookup_handle(&self, handle: &str) -> Option<(String, String)> {
        let app = self.app();
        let parent = handle.split_once('.').map_or("", |(_, p)| p).to_string();
        let identity_default = DEFAULT_ENDPOINTS
            .iter()
            .find(|(k, _)| *k == "identity")
            .map_or(IDENTITY_PATH, |(_, v)| v)
            .to_string();
        for way in 0..2 {
            let (host, path) = if way == 0 {
                (handle.to_string(), identity_default.clone())
            } else {
                // A site that can't answer at the usual address says where it does in its site document.
                let path = self
                    .signer
                    .endpoint(&app.store, &parent, "identity")
                    .unwrap_or_else(|_| identity_default.clone());
                (parent.clone(), format!("{path}?handle={}", enc(handle)))
            };
            let Ok(r) = self
                .signer
                .transport
                .request(&host, &path, "GET", &[], None)
            else {
                continue;
            };
            let d = &r.data;
            if r.status != 200 || d["handle"] != handle || !d["user_id"].as_str().is_some_and(id24)
            {
                continue;
            }
            let Ok(home) = norm_host(&str_of(d.get("home"))) else {
                continue;
            };
            let Ok(doc) = self.signer.site_doc(&app.store, &home) else {
                continue;
            };
            // A site can only speak for handles under its own handle domain.
            if !handle.ends_with(&format!(".{}", to_js_string(doc.get("handle_domain")))) {
                continue;
            }
            return Some((to_js_string(d.get("user_id")), home));
        }
        None
    }

    // ---------- shadows: people from other sites, as this site knows them ----------

    /// Keep a copy of another site's person here: account, profile, public keys and devices.
    fn mirror(&self, home: &str, card: &Value) -> FedResult<String> {
        let id = card["id"].as_str().filter(|i| id24(i)).map(String::from);
        let handle = card["handle"]
            .as_str()
            .filter(|h| handle_ok(h))
            .map(String::from);
        let (Some(id), Some(handle)) = (id, handle) else {
            return Err(fed_err(
                400,
                "BAD_PERSON",
                "That person's details didn't make sense.",
            ));
        };
        let app = self.app();
        let doc = self.signer.site_doc(&app.store, home)?;
        if !handle.ends_with(&format!(".{}", to_js_string(doc.get("handle_domain")))) {
            return Err(fed_err(
                403,
                "WRONG_SITE",
                "A site can only speak for its own people.",
            ));
        }
        let existing = self
            .sql(|db| {
                db.query_row(
                    "SELECT home FROM fed_shadows WHERE user_id = ?",
                    [&id],
                    |r| r.get::<_, String>(0),
                )
                .optional()
            })
            .flatten();
        if existing.as_ref().is_some_and(|h| h != home) {
            return Err(fed_err(
                403,
                "WRONG_SITE",
                "That person belongs to another site.",
            ));
        }
        if existing.is_none()
            && app
                .store
                .table_of(&id)
                .is_some_and(|t| t == "User" || t == "Person")
        {
            return Err(fed_err(
                409,
                "ID_TAKEN",
                "That id belongs to someone on this site.",
            ));
        }
        let digest = Sha256::digest(
            js_stringify(&json!([
                card["handle"],
                card.get("profile").cloned().unwrap_or(Value::Null),
                card.get("directory").cloned().unwrap_or(Value::Null)
            ]))
            .as_bytes(),
        )
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
        if existing.is_some() && self.shadow(&id).is_some_and(|s| s.digest == digest) {
            return Ok(id);
        }
        let sr = Db::service(&app.store);
        if existing.is_none() {
            app.store.create("User", &json!({ "email": "", "role": "user", "full_name": "", "remote": true, "home": home }), Some(&id))?;
        }
        let p = if truthy(card.get("profile")) {
            card["profile"].clone()
        } else {
            json!({})
        };
        let choose = |v: &Value, allowed: &[&str], default: &str| {
            v.as_str()
                .filter(|s| allowed.contains(s))
                .unwrap_or(default)
                .to_string()
        };
        let mut row = json!({
            "user_id": id, "username": handle, "username_key": handle, "remote": true, "home": home,
            "profile_visibility": choose(&p["profile_visibility"], &["shared", "conversations", "nobody"], "shared"),
            "dm_policy": choose(&p["dm_policy"], &["anyone", "servers", "nobody"], "anyone"),
            "default_listed": false,
        });
        for f in SHADOW_FIELDS {
            row[f] = json!(p[f].as_str().map_or(String::new(), |s| js_slice(
                s,
                if f == "avatar_image" { 48_000 } else { 300 }
            )));
        }
        match sr.first("Profile", json!({ "user_id": id }), "created_date")? {
            Some(prof) => {
                sr.update("Profile", id_of(&prof), row)?;
            }
            None => {
                sr.create("Profile", row)?;
            }
        }
        // Public keys and devices: replaced as a whole with the home site's current list.
        let statements: Vec<Value> = card["directory"]["statements"]
            .as_array()
            .map(|a| a.iter().take(500).cloned().collect())
            .unwrap_or_default();
        let devices: Vec<Value> = card["directory"]["devices"]
            .as_array()
            .map(|a| a.iter().take(200).cloned().collect())
            .unwrap_or_default();
        for k in sr.filter("AccountKey", json!({ "user_id": id }), "version", 500)? {
            sr.delete("AccountKey", id_of(&k))?;
        }
        for s in &statements {
            let mut with_user = s.as_object().cloned().unwrap_or_default();
            with_user.insert("user_id".into(), json!(id));
            let mut out = statement_out(&Value::Object(with_user));
            out["user_id"] = json!(id);
            sr.create("AccountKey", out)?;
        }
        let before = sr.filter("Device", json!({ "user_id": id }), "created_date", 200)?;
        for d in &before {
            if !devices
                .iter()
                .any(|x| x.get("device_id").is_some() && x.get("device_id") == d.get("device_id"))
            {
                sr.delete("Device", id_of(d))?;
            }
        }
        for d in &devices {
            let mut out = peer_device_out(d);
            out["user_id"] = json!(id);
            out["label"] = json!("");
            match before
                .iter()
                .find(|x| x.get("device_id").is_some() && x.get("device_id") == d.get("device_id"))
            {
                Some(old) => {
                    sr.update("Device", id_of(old), out)?;
                }
                None => {
                    sr.create("Device", out)?;
                }
            }
        }
        self.put_shadow(&id, home, &handle, &digest, now_ms());
        Ok(id)
    }

    // ---------- notices about membership, keys and blocks ----------

    fn watch_membership(self: &Arc<Self>, entity: &str, row: &Value, old: Option<&Value>) {
        let ids = |v: Option<&Value>| -> Vec<String> {
            let mut out: Vec<String> = Vec::new();
            for x in v
                .and_then(|m| m.get("member_ids"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let s = to_js_string(Some(x));
                if !out.contains(&s) {
                    out.push(s);
                }
            }
            out
        };
        let (room, added, removed) = match entity {
            "Conversation" => {
                let (now, was) = (ids(Some(row)), ids(old));
                let added: Vec<String> = now.iter().filter(|u| !was.contains(u)).cloned().collect();
                let removed: Vec<String> =
                    was.iter().filter(|u| !now.contains(u)).cloned().collect();
                (format!("c:{}", to_js_string(row.get("id"))), added, removed)
            }
            "ServerMember" => (
                format!("s:{}", to_js_string(row.get("server_id"))),
                if old.is_none() {
                    vec![to_js_string(row.get("user_id"))]
                } else {
                    vec![]
                },
                vec![],
            ),
            _ => return,
        };
        for (list, joined) in [(added, true), (removed, false)] {
            for uid in list {
                let Some(s) = self.shadow(&uid) else { continue };
                if joined && self.notified(&uid, &room) {
                    continue;
                }
                self.set_notified(&uid, &room, joined);
                let kind = if room.starts_with('c') {
                    "conversation"
                } else {
                    "server"
                };
                self.notify(s.home, "inbox", json!({ "type": "membership", "user_id": uid, "room": { "kind": kind, "id": &room[2..] }, "joined": joined }));
            }
        }
    }

    /// After a local person's keys or devices change, the sites hosting their rooms get the new list.
    pub fn keys_changed(self: &Arc<Self>, user_id: &str) {
        let Ok(Some(card)) = self.card(user_id) else {
            return;
        };
        for host in self.hosts_of(user_id) {
            self.notify(host, "inbox", json!({ "type": "keys", "user": card }));
        }
    }

    /// After a local block or unblock: tell the other person's site, and sites hosting our rooms.
    pub fn block_changed(self: &Arc<Self>, user_id: &str, blocked_id: &str, blocked: bool) {
        let mut sites = self.hosts_of(user_id);
        if let Some(s) = self.shadow(blocked_id) {
            if !sites.contains(&s.home) {
                sites.push(s.home);
            }
        }
        for host in sites {
            self.notify(host, "inbox", json!({ "type": "block", "user_id": user_id, "blocked_id": blocked_id, "blocked": blocked }));
        }
    }

    // ---------- home side: relaying my people's calls ----------

    /// What a site's answer to this person says it holds: claims for this person only.
    fn learn_routes(&self, host: &str, data: &Value, user_id: &str) {
        let mut found = Vec::new();
        ids_named(data, "", 0, 8, 5000, &mut found);
        let mut seen = std::collections::HashSet::new();
        found.retain(|f| seen.insert(f.clone()));
        found.truncate(MAX_LEARNED);
        let app = self.app();
        let now = now_ms();
        let mut learned = false;
        for (id, chosen) in found {
            if !app.store.has(&id) {
                self.claim(
                    user_id,
                    &id,
                    host,
                    if chosen { CLAIM_CHOSEN } else { CLAIM_IMPLICIT },
                    now,
                );
                learned = true;
            }
        }
        if learned {
            self.put_host(user_id, host, now);
        }
    }

    /// Which site a request is about, for this person: an explicit _site, or the site holding the
    /// ids it names. Ids an app chooses (CHOSEN_KEYS) count only when nothing else is named.
    fn target_of(&self, body: &Value, user_id: &str) -> FedResult<Option<String>> {
        if let Some(site) = body["_site"].as_str().filter(|s| !s.is_empty()) {
            let site = norm_host(site)?;
            return Ok((site != self.host).then_some(site));
        }
        let app = self.app();
        let mut named = Vec::new();
        ids_named(body, "", 0, 6, 500, &mut named);
        if let Some(payload) = body["payload"].as_str() {
            if let Ok(parsed) = serde_json::from_str::<Value>(payload) {
                ids_named(&parsed, "", 0, 6, 500, &mut named);
            }
        }
        // Calls rooms: "<server>.<channel>" and "dm.<conversation>.<call>" carry their ids too.
        for k in ["room", "room_id"] {
            if let Some(r) = body[k].as_str() {
                for part in r.split('.') {
                    ids_named(&json!(part), "id", 1, 6, 500, &mut named);
                }
            }
        }
        for chosen in [false, true] {
            let (mut hosts, mut here, mut disputed) = (Vec::<String>::new(), false, false);
            for (id, _) in named.iter().filter(|(_, c)| *c == chosen) {
                if app.store.has(id) {
                    here = true;
                    continue;
                }
                match self.route_for(user_id, id, chosen) {
                    Route::Host(h) => {
                        if !hosts.contains(&h) {
                            hosts.push(h);
                        }
                    }
                    Route::Disputed(h) => {
                        disputed = true;
                        let line = || {
                            format!("[federation] {} each claim to hold the same thing; requests about it go to neither. Block whichever is wrong.", h.join(if h.len() == 2 { " and " } else { ", " }))
                        };
                        warn_once("dispute", &h[0], &h[1], line);
                    }
                    Route::Unknown => {}
                }
            }
            hosts.retain(|h| *h != self.host);
            if hosts.len() > 1 {
                return Err(fed_err(
                    400,
                    "MIXED_SITES",
                    "That request names things on more than one site.",
                ));
            }
            if let Some(h) = hosts.pop() {
                return Ok(Some(h));
            }
            if here {
                return Ok(None);
            }
            if disputed {
                return Err(fed_err(409, "DISPUTED_SITE", "More than one site claims to hold this, so it isn't being sent to either. Your site's admin can see which sites in its log, and block the wrong one."));
            }
        }
        Ok(None)
    }

    /// Run one call on another site, as this person: (status, reply).
    pub fn act(
        &self,
        host: &str,
        user_id: &str,
        function: &str,
        body: &Value,
    ) -> FedResult<(u16, Value)> {
        let card = self.card(user_id)?.ok_or_else(|| {
            fed_err(
                409,
                "SETUP_REQUIRED",
                "Finish setting up your account first.",
            )
        })?;
        let app = self.app();
        let r = self.signer.send(
            &app.store,
            host,
            "act",
            &json!({ "user": card, "function": function, "request": js_stringify(body) }),
            Some(user_id),
        )?;
        let mut data = r.data;
        if r.status == 200 {
            self.learn_routes(host, &data, user_id);
        }
        if function == "files" && truthy(Some(&data)) {
            rewrite_file_links(host, &mut data);
        }
        Ok((
            r.status,
            if data.is_null() {
                json!({ "error": format!("{host} didn't answer properly."), "code": "SITE_ERROR" })
            } else {
                data
            },
        ))
    }

    /// For /api/functions: relay a call that's about something on another site, or gather "all of
    /// mine" from every site this person has things on. None means: run it here, as it is.
    pub fn relay_function(
        self: &Arc<Self>,
        function: &str,
        raw: &str,
        user: &Value,
        run_local: &(dyn Fn(&str) -> (u16, Value) + Sync),
    ) -> Option<(u16, Value)> {
        // Signing in is always your own site's business.
        if !self.enabled || function == "identity" {
            return None;
        }
        let Ok(Value::Object(mut body)) =
            serde_json::from_str::<Value>(if raw.is_empty() { "{}" } else { raw })
        else {
            return None;
        };
        let user_id = to_js_string(user.get("id"));
        let target = match self.target_of(&Value::Object(body.clone()), &user_id) {
            Ok(t) => t,
            Err(e) => return Some((e.status, json!({ "error": e.message, "code": e.code }))),
        };
        // Only a site the app actually named counts as its choice: an empty _site routed by claims.
        let named_site = body
            .get("_site")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());
        let had_site = body.contains_key("_site");
        body.shift_remove("_site");
        let body_value = Value::Object(body.clone());
        if let Some(target) = target {
            return Some(match self.act(&target, &user_id, function, &body_value) {
                // The site answered, but isn't well: hold the message rather than lose it.
                Ok((status, _))
                    if matches!(status, 502..=504) && holdable(function, &body_value) =>
                {
                    self.hold(&target, &user_id, function, &body_value)
                }
                // The person's app named the site, and it answered: what the request is about lives
                // there, for this person, whatever another site said before.
                Ok((200, data)) if named_site => {
                    let now = now_ms();
                    let mut places = places_named(&body_value);
                    // Joining by invite names only the code: the server is the one the site joined
                    // them to (as trusted as the ids in its listing, which it chooses too). Never
                    // what someone already has from another site: named_claim_strength.
                    if places.is_empty()
                        && function == "servers"
                        && body_value["action"] == "join_server"
                    {
                        places.extend(
                            data["server_id"]
                                .as_str()
                                .filter(|s| id24(s))
                                .map(str::to_string),
                        );
                    }
                    for id in places {
                        self.claim_named(&user_id, &id, &target, now);
                    }
                    (200, data)
                }
                Ok(r) => r,
                Err(e) if e.code == "SITE_UNREACHABLE" && holdable(function, &body_value) => {
                    self.hold(&target, &user_id, function, &body_value)
                }
                Err(e) if e.status == 500 && e.code == "INTERNAL" => (
                    502,
                    json!({ "error": "Something went wrong.", "code": "SITE_ERROR" }),
                ),
                Err(e) => (e.status, json!({ "error": e.message, "code": e.code })),
            });
        }
        let action = format!("{function}.{}", to_js_string(body.get("action")));
        let kind = FAN_OUT.iter().find(|(k, _)| *k == action).map(|(_, v)| *v);
        let hosts = self.hosts_of(&user_id);
        let Some(kind) = kind.filter(|_| !hosts.is_empty()) else {
            return had_site.then(|| run_local(&js_stringify(&body_value)));
        };
        if kind == "merge" {
            Some(self.fan_out_merge(function, &body, &user_id, &hosts, run_local))
        } else {
            self.fan_out_people(function, &body, &user_id, &hosts, run_local)
        }
    }

    fn fan_out_merge(
        self: &Arc<Self>,
        function: &str,
        body: &Map<String, Value>,
        user_id: &str,
        hosts: &[String],
        run_local: &(dyn Fn(&str) -> (u16, Value) + Sync),
    ) -> (u16, Value) {
        // Cursors become "<this site's>~<base64 JSON of each other site's>", so apps keep one cursor each.
        let mut remote: HashMap<String, Map<String, Value>> = HashMap::new();
        let mut local_body = body.clone();
        for (field, _) in CURSOR_FIELDS {
            let Some(cursor) = body.get(field).and_then(Value::as_str) else {
                continue;
            };
            let mut parts = cursor.split('~');
            local_body.insert(field.into(), json!(parts.next().unwrap_or("")));
            if let Some(rest) = parts.next().filter(|r| !r.is_empty()) {
                // A damaged cursor just starts that site afresh.
                let decoded = unb64u(rest).map(|b| String::from_utf8_lossy(&b).into_owned());
                if let Some(Value::Object(map)) =
                    decoded.and_then(|t| serde_json::from_str::<Value>(&t).ok())
                {
                    for (h, c) in map {
                        remote.entry(h).or_default().insert(field.into(), c);
                    }
                }
            }
        }
        let (status, data) = run_local(&js_stringify(&Value::Object(local_body.clone())));
        if status != 200 {
            return (status, data);
        }
        let mut results: Vec<(String, Value, Value)> = vec![(self.host.clone(), data, Value::Null)];
        let answers: Vec<(String, Option<(u16, Value)>)> = std::thread::scope(|scope| {
            let jobs: Vec<_> = hosts
                .iter()
                .map(|h| {
                    let mut b = local_body.clone();
                    for (field, _) in CURSOR_FIELDS {
                        match remote.get(h).and_then(|r| r.get(field)) {
                            Some(c) => {
                                b.insert(field.into(), c.clone());
                            }
                            None => {
                                b.shift_remove(field);
                            }
                        }
                    }
                    scope.spawn(move || {
                        (
                            h.clone(),
                            self.act(h, user_id, function, &Value::Object(b)).ok(),
                        )
                    })
                })
                .collect();
            jobs.into_iter().filter_map(|j| j.join().ok()).collect()
        });
        for (h, answer) in answers {
            match answer {
                Some((200, data)) => results.push((h, data, Value::Null)),
                Some((401 | 403 | 404, _)) => self.drop_host(user_id, &h),
                _ => {
                    let keep = remote
                        .get(&h)
                        .map_or(Value::Null, |m| Value::Object(m.clone()));
                    results.push((h, Value::Null, keep));
                }
            }
        }
        (200, merge_results(&results))
    }

    fn fan_out_people(
        self: &Arc<Self>,
        function: &str,
        body: &Map<String, Value>,
        user_id: &str,
        hosts: &[String],
        run_local: &(dyn Fn(&str) -> (u16, Value) + Sync),
    ) -> Option<(u16, Value)> {
        let ids: Vec<String> = body
            .get("user_ids")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let app = self.app();
        let remote: Vec<String> = ids
            .into_iter()
            .filter(|id| self.shadow(id).is_some() || !app.store.has(id))
            .collect();
        if remote.is_empty() {
            return None;
        }
        let (status, data) = run_local(&js_stringify(&Value::Object(body.clone())));
        let mut out = if status == 200 {
            data
        } else if function == "keys" {
            json!({ "keys": {} })
        } else {
            json!({ "profiles": [] })
        };
        let mut b = body.clone();
        b.insert("user_ids".into(), json!(remote));
        let b = Value::Object(b);
        let answers: Vec<Option<(u16, Value)>> = std::thread::scope(|scope| {
            let jobs: Vec<_> = hosts
                .iter()
                .map(|h| scope.spawn(|| self.act(h, user_id, function, &b).ok()))
                .collect();
            jobs.into_iter().filter_map(|j| j.join().ok()).collect()
        });
        for answer in answers {
            let Some((200, data)) = answer else { continue };
            if let Some(keys) = data["keys"].as_object() {
                // That site is unreachable or odd: its people stay unknown for now.
                let Some(mine) = out.get_mut("keys").and_then(Value::as_object_mut) else {
                    continue;
                };
                for (k, v) in keys {
                    if !mine.get(k).is_some_and(|x| truthy(Some(x))) {
                        mine.insert(k.clone(), v.clone());
                    }
                }
            }
            if let Some(profiles) = data["profiles"].as_array() {
                let Some(list) = out.get_mut("profiles").and_then(Value::as_array_mut) else {
                    continue;
                };
                for p in profiles {
                    if !list.iter().any(|x| x.get("user_id") == p.get("user_id")) {
                        list.push(p.clone());
                    }
                }
            }
        }
        Some((200, out))
    }

    // ---------- holding messages for sites that can't be reached ----------

    fn hold(&self, host: &str, user_id: &str, function: &str, body: &Value) -> (u16, Value) {
        let now = now_ms();
        let msg_id = to_js_string(body.get("msg_id"));
        let mut held = body.clone();
        held["queued"] = json!(true);
        self.sql(|db| db.execute("INSERT INTO fed_outbox (host, msg_id, user_id, fn, body, attempts, next_at, created) VALUES (?, ?, ?, ?, ?, 0, ?, ?) ON CONFLICT(host, msg_id) DO NOTHING", params![host, msg_id, user_id, function, js_stringify(&held), now + HELD_FIRST_RETRY_MS, now]));
        (
            202,
            json!({ "queued": true, "held_by": self.host, "site": host, "msg_id": msg_id }),
        )
    }

    /// Try held messages that are due. Answers how many went out.
    pub fn deliver_held(&self, now: i64) -> usize {
        type Held = (String, String, String, String, String, i64);
        self.sql(|db| {
            db.execute(
                "DELETE FROM fed_outbox WHERE created < ?",
                [now - HELD_MAX_AGE_MS],
            )
        });
        let due: Vec<Held> = self
            .sql(|db| {
                db.prepare("SELECT host, msg_id, user_id, fn, body, attempts FROM fed_outbox WHERE next_at <= ? ORDER BY created LIMIT 100")?
                    .query_map([now], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?
                    .collect::<rusqlite::Result<Vec<Held>>>()
            })
            .unwrap_or_default();
        let app = self.app();
        let mut sent = 0;
        let mut down: Vec<String> = Vec::new();
        for (host, msg_id, user_id, function, body, attempts) in due {
            let drop = || {
                self.sql(|db| {
                    db.execute(
                        "DELETE FROM fed_outbox WHERE host = ? AND msg_id = ?",
                        [&host, &msg_id],
                    )
                })
            };
            let later = || {
                let wait = HELD_MAX_WAIT_MS
                    .min(HELD_FIRST_RETRY_MS.saturating_mul(1i64 << (attempts + 1).clamp(0, 40)));
                self.sql(|db| db.execute("UPDATE fed_outbox SET attempts = attempts + 1, next_at = ? WHERE host = ? AND msg_id = ?", params![now + wait, host, msg_id]))
            };
            if down.contains(&host) {
                later();
                continue;
            }
            if crate::sessions::user_record(&app.store, &user_id).is_none() {
                drop();
                continue;
            }
            let body: Value = serde_json::from_str(&body).unwrap_or(json!({}));
            match self.act(&host, &user_id, &function, &body) {
                Ok((status, _)) => {
                    if status == 200 {
                        sent += 1;
                    }
                    if status >= 500 || status == 429 {
                        later();
                        continue;
                    }
                    // Delivered, or turned down for good (the sender's device sees why when it next tries).
                    drop();
                }
                Err(_) => {
                    down.push(host.clone());
                    later();
                }
            }
        }
        sent
    }

    // ---------- host side: other sites' people acting here ----------

    fn inbound_act(
        &self,
        from: &str,
        payload: &Value,
        signed_user: &str,
    ) -> FedResult<(u16, Value)> {
        let card = &payload["user"];
        if !truthy(Some(card)) || card["id"].as_str() != Some(signed_user) {
            return Err(fed_err(
                400,
                "BAD_PERSON",
                "The request's person doesn't match its signature.",
            ));
        }
        let function = str_of(payload.get("function"));
        let app = self.app();
        if !app.has_function(&function) || function == "admin" {
            return Err(fed_err(404, "NOT_FOUND", "Unknown function."));
        }
        self.mirror(from, card)?;
        let user = app.store.get("User", signed_user)?;
        let raw = if truthy(payload.get("request")) {
            to_js_string(payload.get("request"))
        } else {
            "{}".into()
        };
        let parsed: Value = serde_json::from_str(&raw).unwrap_or(json!({}));
        // Limited remote sites may continue established encrypted exchanges,
        // but cannot create new remote relationships or joins.
        if crate::site_policy::decision(&app.store, from).map_err(|_| {
            fed_err(
                503,
                "SITE_POLICY_UNAVAILABLE",
                "Unable to check site policy.",
            )
        })? == "limit"
            && ((function == "conversations"
                && ["create_dm", "create_group", "add_members"]
                    .contains(&parsed["action"].as_str().unwrap_or("")))
                || (function == "servers"
                    && ["join_server"].contains(&parsed["action"].as_str().unwrap_or(""))))
        {
            return Err(fed_err(
                403,
                "SITE_LIMITED",
                "This site's moderation policy limits new remote interactions.",
            ));
        }
        // Things that only make sense on a person's own site.
        if ["keys", "profile", "safety"].contains(&function.as_str())
            && !["peer_keys", "get_many", "find"].contains(&parsed["action"].as_str().unwrap_or(""))
        {
            return Err(fed_err(
                403,
                "HOME_ONLY",
                "That's done on the person's own site.",
            ));
        }
        let mut user = user;
        user["role"] = if truthy(user.get("role")) {
            user["role"].clone()
        } else {
            json!("user")
        };
        user["email"] = if truthy(user.get("email")) {
            user["email"].clone()
        } else {
            json!("")
        };
        Ok(app
            .run_function(&function, Some(user), None, &raw)
            .unwrap_or((
                404,
                json!({ "error": "Unknown function.", "code": "NOT_FOUND" }),
            )))
    }

    fn inbound_directory(&self, from: &str, payload: &Value) -> FedResult<Value> {
        let app = self.app();
        let policy = crate::site_policy::current_policy(&app.store).map_err(|_| {
            fed_err(
                503,
                "SITE_POLICY_UNAVAILABLE",
                "Unable to check site policy.",
            )
        })?;
        if policy["allow_remote_discovery"] == false
            || crate::site_policy::decision(&app.store, from).map_err(|_| {
                fed_err(
                    503,
                    "SITE_POLICY_UNAVAILABLE",
                    "Unable to check site policy.",
                )
            })? == "limit"
        {
            return Err(fed_err(
                403,
                "SITE_LIMITED",
                "This site's policy restricts remote discovery.",
            ));
        }
        let handle = str_of(payload.get("handle")).to_lowercase();
        let profile = match self.local_username(&handle) {
            Some(u) => self.local_profile(&u)?,
            None => None,
        };
        let nobody = || fed_err(404, "NOT_FOUND", "Nobody here by that name.");
        let Some(profile) = profile.filter(|p| p["user_id"] == payload["user_id"]) else {
            return Err(nobody());
        };
        let user_id = to_js_string(profile.get("user_id"));
        if payload["purpose"] == "conversation" {
            let policy = if truthy(profile.get("dm_policy")) {
                to_js_string(profile.get("dm_policy"))
            } else {
                "anyone".into()
            };
            // "Only people I share a server with" can't be checked for people on other sites, so it means no.
            if policy != "anyone" {
                return Err(fed_err(
                    403,
                    "NOT_ACCEPTING",
                    format!("{handle} isn't accepting new conversations from other sites."),
                ));
            }
            let requester = &payload["requester"]["id"];
            if truthy(Some(requester)) {
                let app = self.app();
                if blocked_either_way(
                    &Db::service(&app.store),
                    &user_id,
                    &to_js_string(Some(requester)),
                )
                .unwrap_or(false)
                {
                    return Err(nobody());
                }
            }
        }
        let card = self.card(&user_id)?;
        // The person now has someone to talk to on that site.
        self.put_host(&user_id, from, now_ms());
        Ok(json!({ "user": card }))
    }

    fn inbound_inbox(&self, from: &str, payload: &Value) -> FedResult<Value> {
        let app = self.app();
        match payload["type"].as_str() {
            Some("membership") => {
                let uid = str_of(payload.get("user_id"));
                if !id24(&uid)
                    || !app
                        .store
                        .table_of(&uid)
                        .is_some_and(|t| t == "User" || t == "Person")
                    || self.shadow(&uid).is_some()
                {
                    return Ok(json!({ "ok": false }));
                }
                // Only a claim for that person, and a weak one: any site can send this notice.
                let room_id = str_of(payload["room"].get("id"));
                // Only a notice that would add a claim counts towards the cap (see notice_allowed).
                if id24(&room_id)
                    && !self.has_claim(&uid, &room_id, from)
                    && !notice_allowed(&format!("{from} {uid}"), now_ms())
                {
                    warn_once("notices", from, &self.host, || {
                        format!("[federation] {from} sent more than {NOTICES_PER_HOUR} membership notices adding new claims for one person this hour; the rest are refused until the next.")
                    });
                    return Ok(json!({ "ok": false, "code": "TOO_MANY_NOTICES" }));
                }
                if id24(&room_id) {
                    self.claim(&uid, &room_id, from, CLAIM_IMPLICIT, now_ms());
                }
                if truthy(payload.get("joined")) {
                    self.put_host(&uid, from, now_ms());
                }
                Ok(json!({ "ok": true }))
            }
            Some("keys") => {
                let id = to_js_string(payload["user"].get("id"));
                if self.shadow(&id).is_some_and(|s| s.home == from) {
                    self.mirror(from, &payload["user"])?;
                }
                Ok(json!({ "ok": true }))
            }
            Some("block") => {
                let uid = to_js_string(payload.get("user_id"));
                let blocked_id = str_of(payload.get("blocked_id"));
                if !self.shadow(&uid).is_some_and(|s| s.home == from) || !id24(&blocked_id) {
                    return Ok(json!({ "ok": false }));
                }
                let sr = Db::service(&app.store);
                let exists = sr.filter(
                    "Block",
                    json!({ "user_id": uid, "blocked_user_id": blocked_id }),
                    "created_date",
                    1,
                )?;
                if truthy(payload.get("blocked")) && exists.is_empty() {
                    sr.create(
                        "Block",
                        json!({ "user_id": uid, "blocked_user_id": blocked_id }),
                    )?;
                }
                if !truthy(payload.get("blocked")) {
                    for b in &exists {
                        sr.delete("Block", id_of(b))?;
                    }
                }
                Ok(json!({ "ok": true }))
            }
            _ => Err(fed_err(400, "UNKNOWN_TYPE", "Unknown notice.")),
        }
    }

    /// A signed request to /cvp/v1/act, /directory or /inbox: (status, reply).
    fn inbound(
        &self,
        p: &str,
        method: &str,
        headers: &HeaderMap,
        body: &str,
        full_path: &str,
    ) -> (u16, Value) {
        let h = |n: &str| {
            headers
                .get_all(n)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let app = self.app();
        let result = (|| -> FedResult<(u16, Value)> {
            let checked = self
                .signer
                .verify(&app.store, method, &h, body, full_path)?;
            let payload: Value = serde_json::from_str(if checked.body.is_empty() {
                "{}"
            } else {
                &checked.body
            })
            .map_err(|_| fed_err(500, "INTERNAL", "Something went wrong."))?;
            let (status, data) = match p {
                "/cvp/v1/act" => {
                    let (s, d) = self.inbound_act(&checked.from, &payload, &checked.user)?;
                    (s, if d.is_null() { json!({}) } else { d })
                }
                "/cvp/v1/directory" => (200, self.inbound_directory(&checked.from, &payload)?),
                "/cvp/v1/inbox" => (200, self.inbound_inbox(&checked.from, &payload)?),
                _ => return Ok((404, json!({ "error": "Not found" }))),
            };
            // A sealed request gets a sealed answer.
            Ok((status, checked.answer(&data)?))
        })();
        match result {
            Ok(r) => r,
            Err(e) if e.status == 500 && e.code == "INTERNAL" => {
                eprintln!("[federation] something went wrong");
                (
                    500,
                    json!({ "error": "Something went wrong.", "code": "INTERNAL" }),
                )
            }
            Err(e) => (e.status, json!({ "error": e.message, "code": e.code })),
        }
    }

    // ---------- HTTP ----------

    pub fn site_document(&self) -> FedResult<Value> {
        let app = self.app();
        let c = &app.config;
        let mut endpoints = Map::new();
        // The site document itself and file links stay where they are; the rest can move under a prefix.
        for (k, v) in DEFAULT_ENDPOINTS {
            endpoints.insert(
                k.into(),
                json!(if k == "files" {
                    v.to_string()
                } else {
                    format!("{}{v}", c.federation_prefix)
                }),
            );
        }
        Ok(json!({
            "protocol": PROTOCOL, "host": self.host, "name": c.site_name, "software": { "name": "commonveil", "version": c.version },
            "handle_domain": c.handle_domain, "key": { "alg": "Ed25519", "public": self.signer.key.public }, "endpoints": endpoints,
            "pq": self.signer.relay_doc(&app.store)?,
        }))
    }

    fn discover(&self, tag: &str) -> Value {
        let app = self.app();
        let tag = js_slice(tag, 40);
        let q = if tag.is_empty() {
            json!({ "discoverable": true })
        } else {
            json!({ "discoverable": true, "public_tags": tag })
        };
        let rows = Db::service(&app.store)
            .filter("Server", q, "-member_count", 100)
            .unwrap_or_default();
        let servers: Vec<Value> = rows
            .iter()
            .filter(|s| s["status"] != "deleting" && truthy(s.get("public_name")))
            .map(|s| {
                let mut o = json!({ "id": s["id"], "site": self.host, "name": s["public_name"], "description": if truthy(s.get("public_description")) { s["public_description"].clone() } else { json!("") }, "tags": if truthy(s.get("public_tags")) { s["public_tags"].clone() } else { json!([]) }, "icon": if truthy(s.get("public_icon")) { s["public_icon"].clone() } else { json!("") }, "color": if truthy(s.get("public_color")) { s["public_color"].clone() } else { json!("") } });
                if let Some(j) = s.get("join_mode") {
                    o["join_mode"] = j.clone();
                }
                o
            })
            .collect();
        json!({ "site": self.host, "servers": servers })
    }

    fn profile_page(&self, username: &str) -> FedResult<(u16, Value)> {
        let ok = (3..=20).contains(&username.len())
            && username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_');
        let Some(profile) = (if ok {
            self.local_profile(username)?
        } else {
            None
        }) else {
            return Ok((404, json!({ "error": "Nobody here by that name." })));
        };
        let visible = profile["profile_visibility"]
            .as_str()
            .filter(|v| !v.is_empty())
            .unwrap_or("shared")
            == "shared";
        let shown = |f: &str| {
            if visible && truthy(profile.get(f)) {
                profile[f].clone()
            } else {
                json!("")
            }
        };
        Ok((
            200,
            json!({
                "username": profile["username"], "handle": if self.enabled { json!(self.handle_for(&to_js_string(profile.get("username")))) } else { Value::Null },
                "display_name": shown("display_name"), "avatar_image": shown("avatar_image"), "avatar_emoji": shown("avatar_emoji"),
                "accent_color": if truthy(profile.get("accent_color")) { profile["accent_color"].clone() } else { json!("") },
                "accepts_new": profile["dm_policy"].as_str().filter(|v| !v.is_empty()).unwrap_or("anyone") == "anyone",
            }),
        ))
    }

    fn resolve_home(&self, q: &str) -> (u16, Value) {
        let app = self.app();
        let mut q = crate::js::trim(q).to_lowercase();
        q = q.strip_prefix('@').unwrap_or(&q).to_string();
        for scheme in ["http://", "https://"] {
            if let Some(rest) = q.strip_prefix(scheme) {
                q = rest.to_string();
                break;
            }
        }
        if let Some(i) = q.find('/') {
            q.truncate(i);
        }
        let mut home = if handle_ok(&q) {
            self.lookup_handle(&q).map(|(_, h)| h)
        } else {
            None
        };
        if home.is_none() {
            home = self
                .signer
                .site_doc(&app.store, &q)
                .ok()
                .map(|d| to_js_string(d.get("host")));
        }
        match home {
            Some(h) => (
                200,
                json!({ "home": h, "home_url": self.signer.transport.url(&h, "", false) }),
            ),
            None => (404, json!({ "error": "Not found" })),
        }
    }

    fn admin(&self, token: &str, method: &str, body: &str) -> (u16, Value) {
        let app = self.app();
        let user = app.session_for(token).map(|(u, _)| u);
        if !user.is_some_and(|u| u["role"] == "admin") {
            return (403, json!({ "error": "Admins only." }));
        }
        if method == "GET" {
            return (
                200,
                json!({ "enabled": self.enabled, "host": self.host, "handle_domain": app.config.handle_domain, "key": self.signer.key.public, "sites": self.signer.sites(&app.store) }),
            );
        }
        let b: Value = match serde_json::from_str(if body.is_empty() { "{}" } else { body }) {
            Ok(v) => v,
            Err(e) => return (400, json!({ "error": e.to_string() })),
        };
        let host = str_of(b.get("host"));
        let done = match b["action"].as_str() {
            Some(a @ ("block" | "unblock")) => {
                self.signer.set_blocked(&app.store, &host, a == "block")
            }
            Some("accept_new_key") => self.signer.forget(&app.store, &host),
            _ => return (400, json!({ "error": "Unknown action." })),
        };
        match done {
            Ok(()) => (
                200,
                json!({ "ok": true, "sites": self.signer.sites(&app.store) }),
            ),
            Err(e) => (e.status, json!({ "error": e.message })),
        }
    }

    // ---------- realtime rooms across sites ----------

    /// Which site hosts a realtime room, for this person, from the ids in its name. A disputed id
    /// carries the connection nowhere.
    pub fn room_host(&self, room: &str, user_id: &str) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let app = self.app();
        for part in room.split('.').filter(|p| id24(p)) {
            if app.store.has(part) {
                return None;
            }
            match self.route_for(user_id, part, false) {
                Route::Host(h) => return Some(h),
                Route::Disputed(_) => return None,
                Route::Unknown => {}
            }
        }
        None
    }

    /// A person here connects to a room on another site: this site carries their connection there.
    pub async fn proxy_actor(
        self: Arc<Self>,
        client: WebSocket,
        host: String,
        name: String,
        room: String,
        conn_id: String,
        user_id: String,
    ) {
        let me = self.clone();
        let target = host.clone();
        let prepared =
            tokio::task::spawn_blocking(move || -> FedResult<(String, Vec<(String, String)>)> {
                let app = me.app();
                let template = me.signer.endpoint(&app.store, &target, "actors")?;
                let path = format!(
                    "{}?id={}",
                    template
                        .replace("{name}", &enc(&name))
                        .replace("{room}", &enc(&room)),
                    enc(&conn_id)
                );
                let card = me.card(&user_id)?.unwrap_or(Value::Null);
                let mut headers =
                    me.signer
                        .headers(&app.store, "GET", &target, &path, "", Some(&user_id))?;
                headers.push(("CV-Person".into(), b64u(js_stringify(&card).as_bytes())));
                Ok((path, headers))
            })
            .await;
        let (mut client_tx, mut client_rx) = client.split();
        let close = |code: u16, reason: &str| {
            ClientMessage::Close(Some(CloseFrame {
                code,
                reason: reason.to_string().into(),
            }))
        };
        let Ok(Ok((path, headers))) = prepared else {
            let _ = client_tx.send(close(1011, "Can't reach that site")).await;
            return;
        };
        let upstream = match self
            .signer
            .transport
            .websocket(&host, &path, &headers)
            .await
        {
            Ok(u) => u,
            Err(_) => {
                let _ = client_tx.send(close(1011, "Can't reach that site")).await;
                return;
            }
        };
        let (mut up_tx, mut up_rx) = upstream.split();
        let to_site = async {
            while let Some(Ok(m)) = client_rx.next().await {
                let text = match m {
                    ClientMessage::Text(t) => t.to_string(),
                    ClientMessage::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
                    ClientMessage::Close(_) => break,
                    _ => continue,
                };
                if up_tx
                    .send(UpstreamMessage::Text(text.into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            let _ = up_tx.close().await;
        };
        let to_client = async {
            let mut ending = close(1011, "That site went away");
            while let Some(m) = up_rx.next().await {
                match m {
                    Ok(UpstreamMessage::Text(t)) => {
                        if client_tx
                            .send(ClientMessage::Text(t.as_str().into()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Ok(UpstreamMessage::Binary(b)) => {
                        if client_tx
                            .send(ClientMessage::Text(
                                String::from_utf8_lossy(&b).into_owned().into(),
                            ))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Ok(UpstreamMessage::Close(frame)) => {
                        ending = match frame {
                            Some(f) => close(u16::from(f.code), f.reason.as_str()),
                            None => close(1000, ""),
                        };
                        break;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            let _ = client_tx.send(ending).await;
        };
        tokio::select! {
            _ = to_site => {}
            _ = to_client => {}
        }
    }
}

/// Is this an upgrade request for a room here, from another site (`/cvp/v1/actors/...`)?
pub fn is_actor_path(config: &crate::config::Config, path: &str) -> bool {
    path.starts_with("/cvp/v1/actors/")
        || (!config.federation_prefix.is_empty()
            && path.starts_with(&format!("{}/cvp/v1/actors/", config.federation_prefix)))
}

/// Another site carries one of its people into a room here.
pub async fn accept_actor(app: Arc<App>, req: Request) -> Response<Body> {
    use axum::extract::FromRequestParts;
    let status_only = |status: u16| http::response(status, Body::empty(), &[]);
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let after = path
        .find("/cvp/v1/actors/")
        .map_or("", |i| &path[i + "/cvp/v1/actors/".len()..])
        .to_string();
    let mut segs = after.split('/');
    let (name, room_enc) = (
        segs.next().unwrap_or("").to_string(),
        segs.next().unwrap_or("").to_string(),
    );
    let full_path = if query.is_empty() {
        path.clone()
    } else {
        format!("{path}?{query}")
    };
    let conn_id = url::form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == "id")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default();
    let headers = req.headers().clone();
    let (mut parts, _) = req.into_parts();
    let Ok(ws) = axum::extract::ws::WebSocketUpgrade::from_request_parts(&mut parts, &()).await
    else {
        return status_only(400);
    };
    let fed = app.federation.clone();
    let n = name.clone();
    let checked = tokio::task::spawn_blocking(move || -> FedResult<(String, String)> {
        if !fed.enabled || !ACTOR_NAMES.contains(&n.as_str()) {
            return Err(fed_err(404, "NOT_FOUND", "Not found"));
        }
        let h = |k: &str| {
            headers
                .get(k)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        };
        let app = fed.app();
        let c = fed.signer.verify(&app.store, "GET", &h, "", &full_path)?;
        let card: Value = unb64u(&h("cv-person"))
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or_else(|| fed_err(403, "BAD_PERSON", "Person mismatch"))?;
        if card["id"].as_str() != Some(c.user.as_str()) {
            return Err(fed_err(400, "BAD_PERSON", "Person mismatch"));
        }
        fed.mirror(&c.from, &card)?;
        Ok((c.user, dec(&room_enc)))
    })
    .await;
    match checked {
        Ok(Ok((user, room))) => {
            let host = app.actors.clone();
            ws.max_message_size(64 * 1024)
                .on_upgrade(move |socket| host.attach(socket, name, room, conn_id, Some(user)))
        }
        Ok(Err(e)) => status_only(if e.status == 0 { 403 } else { e.status }),
        Err(_) => status_only(500),
    }
}

/// Could a message waiting for another site be held and sent later?
fn holdable(function: &str, body: &Value) -> bool {
    (function == "messages" || function == "channels")
        && body["action"] == "send"
        && body["msg_id"].as_str().is_some_and(|m| {
            (8..=64).contains(&m.len())
                && m.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
}

/// File links in another site's answers become links through this site, so apps only ever talk
/// to their own.
fn rewrite_file_links(host: &str, data: &mut Value) {
    fn link(v: &str) -> Option<usize> {
        let at = v.find("/api/files/")?;
        let tail = &v[at + "/api/files/".len()..];
        let (name, query) = tail.split_once("?exp=")?;
        let (exp, sig) = query.split_once("&sig=")?;
        let ok = name.len() == 48
            && name
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && !exp.is_empty()
            && exp.bytes().all(|b| b.is_ascii_digit())
            && !sig.is_empty()
            && sig
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        ok.then_some(at)
    }
    match data {
        Value::String(s) => {
            if let Some(at) = link(s) {
                *s = format!(
                    "/api/fed/files/{}/{}",
                    enc(host),
                    &s[at + "/api/files/".len()..]
                );
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| rewrite_file_links(host, x)),
        Value::Object(o) => o.values_mut().for_each(|x| rewrite_file_links(host, x)),
        _ => {}
    }
}

/// Put the answers from several sites together (merge.ts): lists joined, cursors kept per site,
/// flags combined. Each result is (site, data or null, the cursors to keep if it didn't answer).
pub fn merge_results(results: &[(String, Value, Value)]) -> Value {
    let reply_fields: Vec<&str> = CURSOR_FIELDS.iter().map(|(_, r)| *r).collect();
    let mut out = Map::new();
    for (_, data, _) in results.iter().filter(|r| truthy(Some(&r.1))) {
        for (k, v) in data.as_object().into_iter().flatten() {
            if reply_fields.contains(&k.as_str()) {
                continue;
            }
            match v {
                Value::Array(items) => {
                    if !out.get(k).is_some_and(|x| truthy(Some(x))) {
                        out.insert(k.clone(), json!([]));
                    }
                    let Some(list) = out.get_mut(k).and_then(Value::as_array_mut) else {
                        continue;
                    };
                    for x in items {
                        let add = if x.is_object() && x["id"].is_string() {
                            !list.iter().any(|y| y.get("id") == Some(&x["id"]))
                        } else if x.is_object() || x.is_array() {
                            true
                        } else {
                            !list.contains(x)
                        };
                        if add {
                            list.push(x.clone());
                        }
                    }
                }
                Value::Bool(b) => {
                    let before = out.get(k).is_some_and(|x| truthy(Some(x)));
                    out.insert(k.clone(), json!(before || *b));
                }
                Value::Object(o) => {
                    let mut merged = match out.get(k) {
                        Some(Value::Object(p)) => p.clone(),
                        _ => Map::new(),
                    };
                    for (kk, vv) in o {
                        merged.insert(kk.clone(), vv.clone());
                    }
                    out.insert(k.clone(), Value::Object(merged));
                }
                _ => {
                    if !out.contains_key(k) {
                        out.insert(k.clone(), v.clone());
                    }
                }
            }
        }
    }
    for (field, cursor_key) in CURSOR_FIELDS {
        let Some(local) = results.first().and_then(|r| r.1.get(cursor_key)) else {
            continue;
        };
        let mut others = Map::new();
        for (host, data, keep) in results.iter().skip(1) {
            let c = if truthy(Some(data)) {
                data.get(cursor_key)
            } else {
                keep.get(field)
            };
            if let Some(Value::String(s)) = c {
                others.insert(host.clone(), json!(s));
            }
        }
        let value = if others.is_empty() {
            local.clone()
        } else {
            json!(format!(
                "{}~{}",
                to_js_string(Some(local)),
                b64u(js_stringify(&Value::Object(others)).as_bytes())
            ))
        };
        out.insert(cursor_key.into(), value);
    }
    Value::Object(out)
}

/// Where a request was sent: the forwarded host behind a trusted proxy, else the Host header.
fn request_host(headers: &HeaderMap, trust_proxy: bool) -> String {
    let get = |k: &str| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    let forwarded = if trust_proxy {
        get("x-forwarded-host")
    } else {
        String::new()
    };
    let raw = if forwarded.is_empty() {
        get("host")
    } else {
        forwarded
    };
    raw.split(',').next().unwrap_or("").trim().to_lowercase()
}

fn reply(status: u16, body: &Value, extra: &[(&str, String)]) -> Response<Body> {
    let mut headers = vec![
        ("Cache-Control", "no-store".to_string()),
        (
            "Content-Type",
            "application/json; charset=utf-8".to_string(),
        ),
    ];
    headers.extend_from_slice(extra);
    http::response(status, body.to_string(), &headers)
}

fn any_origin() -> (&'static str, String) {
    ("Access-Control-Allow-Origin", "*".to_string())
}

/// The outcome of looking at a request: answered here, or not the protocol's.
pub enum Routed {
    Done(Response<Body>),
    Pass(Request),
}

/// Everything the protocol owns (well-known documents, handles, /cvp/v1, ...).
pub async fn route(app: Arc<App>, req: Request) -> Routed {
    let fed = app.federation.clone();
    let c = &app.config;
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let param = |k: &str| {
        url::form_urlencoded::parse(query.as_bytes())
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default()
    };
    let prefix = &c.federation_prefix;
    let moved = if !prefix.is_empty() && path.starts_with(&format!("{prefix}/")) {
        path[prefix.len()..].to_string()
    } else {
        String::new()
    };
    let p = if moved.starts_with("/cvp/v1/") || moved == IDENTITY_PATH {
        moved
    } else {
        path.clone()
    };
    let req_host = request_host(req.headers(), c.trust_proxy);
    let host_only = strip_port(&req_host).to_string();
    let on_handle_host =
        fed.enabled && host_only != c.host && host_only.ends_with(&format!(".{}", c.handle_domain));
    let mine = p == "/api/tls-check"
        || on_handle_host
        || p == "/.well-known/commonveil"
        || p == IDENTITY_PATH
        || p == "/.well-known/webfinger"
        || p == "/.well-known/nodeinfo"
        || p == "/nodeinfo/2.1"
        || (p == "/api/fed/resolve" && fed.enabled)
        || p.starts_with("/api/fed/profile/")
        || p.starts_with("/api/fed/files/")
        || p == "/api/admin/federation"
        || p.starts_with("/cvp/v1/");
    if !mine {
        return Routed::Pass(req);
    }
    let method = req.method().as_str().to_string();
    let full_path = if query.is_empty() {
        path.clone()
    } else {
        format!("{path}?{query}")
    };
    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|t| t.trim().to_string())
        .unwrap_or_default();
    let headers = req.headers().clone();
    // Bodies, for the two things that take one.
    let mut body = String::new();
    if p == "/api/admin/federation" && method != "GET" && !on_handle_host {
        match axum::body::to_bytes(req.into_body(), 4096).await {
            Ok(b) => body = String::from_utf8_lossy(&b).into_owned(),
            Err(_) => return Routed::Done(reply(413, &json!({ "error": "too large" }), &[])),
        }
    } else if p.starts_with("/cvp/v1/")
        && fed.enabled
        && method == "POST"
        && !on_handle_host
        && p != "/api/tls-check"
    {
        match axum::body::to_bytes(req.into_body(), MAX_ACT_BODY).await {
            Ok(b) => body = String::from_utf8_lossy(&b).into_owned(),
            Err(_) => {
                return Routed::Done(reply(
                    413,
                    &json!({ "error": "Something went wrong.", "code": "INTERNAL" }),
                    &[],
                ))
            }
        }
    }
    let tag = param("tag");
    let (q, handle_param, resource, domain) = (
        param("q"),
        param("handle"),
        param("resource"),
        param("domain"),
    );
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    let out = tokio::task::spawn_blocking(move || {
        let app = fed.app();
        let c = &app.config;
        // TLS for handles: Caddy asks before getting a certificate for a name.
        if p == "/api/tls-check" {
            let d = domain.to_lowercase();
            if d == c.host {
                return reply(200, &json!({ "ok": true }), &[]);
            }
            let known = if fed.enabled { fed.local_username(&d) } else { None }.map(|u| fed.local_profile(&u).ok().flatten().is_some()).unwrap_or(false);
            return reply(if known { 200 } else { 404 }, &json!({}), &[]);
        }
        // A handle's own address (alice.example.com): who she is, or her profile in a browser.
        if on_handle_host {
            let profile = fed.local_username(&host_only).and_then(|u| fed.local_profile(&u).ok().flatten());
            if p == IDENTITY_PATH {
                return match &profile {
                    Some(pr) => reply(200, &fed.identity(pr), &[any_origin()]),
                    None => reply(404, &json!({ "error": "Nobody here by that name." }), &[]),
                };
            }
            let to = match &profile {
                Some(pr) => format!("{}/u/{}", c.site_url, to_js_string(pr.get("username"))),
                None => c.site_url.clone(),
            };
            return http::response(302, Body::empty(), &[("Location", to)]);
        }
        if p == "/.well-known/commonveil" {
            if !fed.enabled {
                return reply(404, &json!({ "error": "This site doesn't talk to other sites." }), &[]);
            }
            return match fed.site_document() {
                Ok(doc) => reply(200, &doc, &[any_origin(), ("Cache-Control", "public, max-age=300".into())]),
                Err(_) => reply(500, &json!({ "error": "Something went wrong.", "code": "INTERNAL" }), &[]),
            };
        }
        if p == IDENTITY_PATH {
            let handle = handle_param.to_lowercase();
            let profile = if fed.enabled { fed.local_username(&handle) } else { None }.and_then(|u| fed.local_profile(&u).ok().flatten());
            return match profile {
                Some(pr) => reply(200, &fed.identity(&pr), &[any_origin()]),
                None => reply(404, &json!({ "error": "Nobody here by that name." }), &[]),
            };
        }
        // WebFinger, so fediverse tools can at least find a Commonveil address and its profile page.
        if p == "/.well-known/webfinger" {
            let found = resource.get(..5).filter(|s| s.eq_ignore_ascii_case("acct:")).and_then(|_| resource[5..].split_once('@')).filter(|(name, site)| (3..=20).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') && !site.is_empty());
            let profile = found.filter(|(_, site)| fed.enabled && site.to_lowercase() == c.host).and_then(|(name, _)| fed.local_profile(name).ok().flatten());
            let Some(pr) = profile else { return reply(404, &json!({}), &[]) };
            let username = to_js_string(pr.get("username"));
            return reply(
                200,
                &json!({
                    "subject": format!("acct:{username}@{}", c.host),
                    "aliases": [format!("{}/u/{username}", c.site_url), format!("https://{}", fed.handle_for(&username))],
                    "links": [{ "rel": "http://webfinger.net/rel/profile-page", "type": "text/html", "href": format!("{}/u/{username}", c.site_url) }],
                }),
                &[("Content-Type", "application/jrd+json".into()), any_origin()],
            );
        }
        if p == "/.well-known/nodeinfo" {
            return reply(200, &json!({ "links": [{ "rel": "http://nodeinfo.diaspora.software/ns/schema/2.1", "href": format!("{}/nodeinfo/2.1", c.site_url) }] }), &[]);
        }
        if p == "/nodeinfo/2.1" {
            // Deliberately no user counts: how many people use a site is nobody else's business.
            return reply(
                200,
                &json!({
                    "version": "2.1", "software": { "name": "commonveil", "version": c.version, "repository": "https://github.com/Comutability/commonveil-rebuild" },
                    "protocols": [], "services": { "inbound": [], "outbound": [] }, "openRegistrations": c.open_registration && crate::site_policy::current_policy(&app.store).is_ok_and(|p|p["registration_open"]==true), "usage": { "users": {} },
                    "metadata": { "nodeName": c.site_name, "federation": if fed.enabled { PROTOCOL } else { "off" } },
                }),
                &[],
            );
        }
        // Where someone lives, from their handle or their site's address (for "join from your own site").
        if p == "/api/fed/resolve" {
            let (status, v) = fed.resolve_home(&q);
            return reply(status, &v, &[]);
        }
        // Public profile pages are part of the app (/u/name); this answers what they may show.
        if let Some(name) = p.strip_prefix("/api/fed/profile/") {
            return match fed.profile_page(&dec(name)) {
                Ok((status, v)) => reply(status, &v, &[]),
                Err(_) => reply(500, &json!({ "error": "Something went wrong.", "code": "INTERNAL" }), &[]),
            };
        }
        // Files from other sites, fetched by this site so apps only ever talk to their own. The link
        // itself is the permission (the host signed it, and it expires in minutes), as on the host.
        // This site only fetches from sites its people have things on.
        if p.starts_with("/api/fed/files/") {
            let segs: Vec<&str> = p.split('/').collect();
            let host = wire_host(&dec(segs.get(4).copied().unwrap_or("")));
            let name = segs.get(5).copied().unwrap_or("").to_string();
            let named = name.len() == 48 && name.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            let known = host.as_ref().is_some_and(|h| fed.sql(|db| db.query_row("SELECT 1 FROM fed_user_hosts WHERE host = ? LIMIT 1", [h], |_| Ok(())).optional()).flatten().is_some());
            let (Some(host), true, true) = (host, named, known) else { return reply(404, &json!({ "error": "Not found" }), &[]) };
            match crate::site_policy::decision(&app.store,&host) {
                Ok(mode) if mode=="suspend"||mode=="reject_media"=>return reply(403,&json!({"code":"SITE_MEDIA_BLOCKED","error":"Media from that site is restricted."}),&[]),
                Err(_)=>return reply(503,&json!({"code":"SITE_POLICY_UNAVAILABLE"}),&[]),
                _=>{}
            }
            let search = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs.iter()).finish();
            let bytes = fed.signer.endpoint(&app.store, &host, "files").ok().and_then(|base| fed.signer.transport.bytes(&host, &format!("{base}/{name}?{search}")));
            let Some(bytes) = bytes else { return reply(404, &json!({ "error": "That link has expired." }), &[]) };
            let len = bytes.len().to_string();
            return http::response(200, bytes, &[("Content-Type", "application/octet-stream".into()), ("Cache-Control", "private, no-store".into()), ("X-Content-Type-Options", "nosniff".into()), ("Content-Length", len)]);
        }
        if p == "/api/admin/federation" {
            let (status, v) = fed.admin(&token, &method, &body);
            return reply(status, &v, &[]);
        }
        // /cvp/v1/...
        if !fed.enabled {
            return reply(404, &json!({ "error": "This site doesn't talk to other sites.", "code": "FEDERATION_OFF" }), &[]);
        }
        if method == "GET" && p == "/cvp/v1/discover" {
            match crate::site_policy::current_policy(&app.store) {
                Ok(policy) if policy["allow_remote_discovery"]==false=>return reply(403,&json!({"code":"DISCOVERY_DISABLED","error":"Remote directory listings are disabled."}),&[]),
                Err(_)=>return reply(503,&json!({"code":"SITE_POLICY_UNAVAILABLE"}),&[]),
                _=>{}
            }
            return reply(200, &fed.discover(&tag), &[any_origin(), ("Cache-Control", "public, max-age=120".into())]);
        }
        if method != "POST" {
            return reply(405, &json!({ "error": "Use POST." }), &[]);
        }
        let (status, v) = fed.inbound(&p, &method, &headers, &body, &full_path);
        reply(status, &v, &[])
    })
    .await;
    Routed::Done(out.unwrap_or_else(|_| {
        reply(
            500,
            &json!({ "error": "Something went wrong.", "code": "INTERNAL" }),
            &[],
        )
    }))
}

fn wire_host(h: &str) -> Option<String> {
    norm_host(h).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_are_checked_as_the_typescript_does() {
        for (h, ok) in [
            ("alice.example.com", true),
            ("a.example.com", false),
            ("al-.example.com", true),
            ("-al.example.com", false),
            ("alice.example-.com", false),
            ("alice", false),
            ("alice..com", false),
            ("ALICE.example.com", false),
        ] {
            assert_eq!(handle_ok(h), ok, "{h}");
        }
    }

    #[test]
    fn answers_from_several_sites_merge_as_merge_ts_does() {
        let results = vec![
            (
                "a.test".to_string(),
                json!({ "conversations": [{ "id": "1" }], "cursor": "c-a", "more": false, "keys": { "x": 1 } }),
                Value::Null,
            ),
            (
                "b.test".to_string(),
                json!({ "conversations": [{ "id": "1" }, { "id": "2" }], "cursor": "c-b", "more": true, "keys": { "y": 2 } }),
                Value::Null,
            ),
            ("c.test".to_string(), Value::Null, json!({ "since": "c-c" })),
        ];
        let out = merge_results(&results);
        assert_eq!(out["conversations"], json!([{ "id": "1" }, { "id": "2" }]));
        assert_eq!(out["more"], true);
        assert_eq!(out["keys"], json!({ "x": 1, "y": 2 }));
        let cursor = out["cursor"].as_str().unwrap();
        let (mine, rest) = cursor.split_once('~').unwrap();
        assert_eq!(mine, "c-a");
        let others: Value = serde_json::from_slice(&unb64u(rest).unwrap()).unwrap();
        assert_eq!(others, json!({ "b.test": "c-b", "c.test": "c-c" }));
    }

    #[test]
    fn claims_resolve_as_the_shared_vectors_say() {
        let vectors: Value =
            serde_json::from_str(include_str!("../../../tests/vectors/route-claims.json")).unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let claims: Vec<(String, i64)> = case["claims"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| (c[0].as_str().unwrap().to_string(), c[1].as_i64().unwrap()))
                .collect();
            let want = match (
                case["route"].as_str(),
                case["disputed"].as_array().map_or(0, Vec::len),
            ) {
                (Some(h), _) => Route::Host(h.to_string()),
                (None, 0) => Route::Unknown,
                (None, _) => Route::Disputed(
                    case["disputed"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|h| h.as_str().unwrap().to_string())
                        .collect(),
                ),
            };
            assert_eq!(resolve_route(&claims), want, "{}", case["name"]);
        }
        for case in vectors["named"].as_array().unwrap() {
            let existing: Vec<(String, i64)> = case["existing"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| (c[0].as_str().unwrap().to_string(), c[1].as_i64().unwrap()))
                .collect();
            let want = (
                case["strength"].as_i64().unwrap(),
                case["other"].as_str().map(str::to_string),
            );
            assert_eq!(
                named_claim_strength(&existing, case["host"].as_str().unwrap()),
                want,
                "{}",
                case["name"]
            );
        }
    }

    #[test]
    fn routes_from_before_become_site_wide_claims_and_the_old_table_stays() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE fed_claims (user_id TEXT NOT NULL, id TEXT NOT NULL, host TEXT NOT NULL, strength INTEGER NOT NULL, seen INTEGER NOT NULL, PRIMARY KEY (user_id, id, host));
             CREATE TABLE fed_routes (id TEXT PRIMARY KEY, host TEXT NOT NULL, seen INTEGER NOT NULL);
             INSERT INTO fed_routes VALUES ('aaaaaaaaaaaaaaaaaaaaaaaa', 'b.test', 5), ('bbbbbbbbbbbbbbbbbbbbbbbb', 'c.test', 6);",
        )
        .unwrap();
        migrate_routes(&db).unwrap();
        migrate_routes(&db).unwrap();
        let rows: Vec<(String, String, String, i64, i64)> = db
            .prepare("SELECT user_id, id, host, strength, seen FROM fed_claims ORDER BY id")
            .unwrap()
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![
                ("*".into(), "a".repeat(24), "b.test".into(), CLAIM_LEGACY, 5),
                ("*".into(), "b".repeat(24), "c.test".into(), CLAIM_LEGACY, 6)
            ]
        );
        let kept: i64 = db
            .query_row("SELECT COUNT(*) FROM fed_routes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            kept, 2,
            "0.24.24, if the updater goes back to it, still finds its routes"
        );
    }

    #[test]
    fn chosen_ids_are_told_apart_from_a_sites_own() {
        let id = |c: char| c.to_string().repeat(24);
        let body = json!({ "server_id": id('a'), "thread_id": id('b'), "payload": "x", "list": [{ "event_id": id('c'), "id": id('d') }], "report_id": "not-an-id", "file_ids": [id('e')] });
        let mut out = Vec::new();
        ids_named(&body, "", 0, 6, 500, &mut out);
        out.sort();
        assert_eq!(
            out,
            vec![
                (id('a'), false),
                (id('b'), true),
                (id('c'), true),
                (id('d'), false)
            ],
            "file ids never route"
        );
        let places = places_named(
            &json!({ "server_id": id('a'), "channel_id": id('b'), "thread_id": id('c'), "payload": json!({ "conversation_id": id('d'), "message_id": id('e') }).to_string() }),
        );
        assert_eq!(places, vec![id('a'), id('b'), id('d')]);
    }

    #[test]
    fn file_links_are_carried_through_this_site() {
        let name = "a".repeat(48);
        let mut v = json!({ "links": { "f": format!("http://b.test/api/files/{name}?exp=123&sig=ab_-") }, "other": "x" });
        rewrite_file_links("b.test", &mut v);
        assert_eq!(
            v["links"]["f"],
            format!("/api/fed/files/b.test/{name}?exp=123&sig=ab_-")
        );
        assert_eq!(v["other"], "x");
    }

    #[test]
    fn one_sites_membership_notices_are_capped_per_hour() {
        let hour = 1_000 * 3_600_000;
        for _ in 0..NOTICES_PER_HOUR {
            assert!(notice_allowed("flood-rs.test", hour));
        }
        assert!(!notice_allowed("flood-rs.test", hour));
        assert!(
            notice_allowed("other-rs.test", hour),
            "other sites are counted apart"
        );
        assert!(
            notice_allowed("flood-rs.test", hour + 3_600_000),
            "the next hour starts again"
        );
    }
}
