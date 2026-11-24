//! The proposals forum (base44/shared/handlers/snips.ts, docs/SNIP_FORUM.md): a forum channel in
//! the community server with one post for every Secure Net Improvement Proposal on GitHub.
//!
//! The server can't write posts: channels are end-to-end encrypted with keys it doesn't hold. Its
//! part is to read the proposals from GitHub (public data, cached), to make the empty forum
//! channel when an admin's app asks, and to say which proposals already have a post and whether
//! it's locked. The posts themselves are written, and locked, by a community admin's app.
use std::sync::OnceLock;
use std::time::Duration;

use regex::Regex;
use serde_json::{json, Value};

use crate::api::{Actions, ApiError, Ctx, Result};
use crate::db::{id_of, Db};
use crate::js::{to_js_string, to_number, truthy};
use crate::permissions::{has, p};
use crate::protocol::js_stringify;
use crate::servers_core::{
    audit, channel_out, perms_of, require_member, server_parts, touch_server,
};
use crate::shared::{by_age, iso};
use crate::verify::signed_by_active_device;

pub const SNIP_CHANNEL_KEY: &str = "snips";
const API: &str = "https://api.github.com";
const RAW: &str = "https://raw.githubusercontent.com";
const MAX_SNIPS: usize = 200;
const MAX_PRS: usize = 10;
const DEFAULT_REPO: &str = "Comutability/secure-net";

/// The post for a proposal, and the note left when it closes: fixed ids, so they exist only once.
pub fn snip_thread_id(snip_id: &str) -> String {
    format!("{snip_id}-thread-v1")
}
pub fn snip_closed_note_id(snip_id: &str) -> String {
    format!("{snip_id}-closed-v1")
}

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("valid pattern"))
}

/// `snips/SNIP-0001.md` -> `SNIP-0001`.
fn snip_file(path: &str) -> Option<String> {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"^snips/(SNIP-\d{4})\.md$")
        .captures(path)
        .map(|c| c[1].to_string())
}

fn repo_ok(r: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"^[A-Za-z0-9_.-]{1,60}/[A-Za-z0-9_.-]{1,60}$").is_match(r)
}

/// A proposal is finished when its own Status line says so (GOVERNANCE.md's states).
pub fn is_closed_status(status: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    re(
        &R,
        r"(?i)^(accepted|rejected|implemented|released|withdrawn)\b",
    )
    .is_match(&crate::js::trim(status))
}

/// Control characters become spaces, then trimmed and cut to `max` UTF-16 units.
fn text(v: &str, max: usize) -> String {
    static R: OnceLock<Regex> = OnceLock::new();
    let spaced = re(&R, r"[\x00-\x1f]+").replace_all(v, " ");
    let units: Vec<u16> = crate::js::trim(&spaced).encode_utf16().take(max).collect();
    String::from_utf16_lossy(&units)
}

/// A proposal's title and status, from the top of its file.
pub fn parse_snip(id: &str, md: Option<&str>) -> (String, String) {
    static TITLE: OnceLock<Regex> = OnceLock::new();
    static PREFIX: OnceLock<Regex> = OnceLock::new();
    static STATUS: OnceLock<Regex> = OnceLock::new();
    let md = md.unwrap_or("");
    let raw_title = re(&TITLE, r"(?mR)^#\s+([^\n\r\x{2028}\x{2029}]+)")
        .captures(md)
        .map(|c| {
            re(&PREFIX, r"^SNIP-\d+:\s*")
                .replace(&c[1], "")
                .into_owned()
        });
    let title = text(
        raw_title.as_deref().filter(|t| !t.is_empty()).unwrap_or(id),
        160,
    );
    let status = text(
        re(&STATUS, r"(?mR)^\|\s*Status\s*\|\s*([^|]+)\|")
            .captures(md)
            .map_or("", |c| c.get(1).map_or("", |m| m.as_str())),
        200,
    );
    (title, status)
}

struct GitHub {
    agent: ureq::Agent,
    repo: String,
    token: String,
}

impl GitHub {
    fn gh(&self, path: &str) -> std::result::Result<Value, String> {
        let mut req = self
            .agent
            .get(&format!("{API}/repos/{}{path}", self.repo))
            .set("Accept", "application/vnd.github+json")
            .set("User-Agent", "commonveil")
            .set("X-GitHub-Api-Version", "2022-11-28");
        if !self.token.is_empty() {
            req = req.set("Authorization", &format!("Bearer {}", self.token));
        }
        let res = req.call().map_err(|e| format!("GitHub {path}: {e}"))?;
        let body = res.into_string().map_err(|e| e.to_string())?;
        serde_json::from_str(&body).map_err(|e| e.to_string())
    }
    fn raw(&self, git_ref: &str, path: &str) -> std::result::Result<Option<String>, String> {
        match self
            .agent
            .get(&format!("{RAW}/{}/{git_ref}/{path}", self.repo))
            .set("User-Agent", "commonveil")
            .call()
        {
            Ok(r) => r.into_string().map(Some).map_err(|e| e.to_string()),
            Err(ureq::Error::Status(..)) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
}

fn fetch_snips(repo: &str, token: &str) -> std::result::Result<Vec<Value>, String> {
    let g = GitHub {
        agent: crate::tls::agent().timeout(Duration::from_secs(10)).build(),
        repo: repo.into(),
        token: token.into(),
    };
    let mut out: Vec<(String, Value)> = Vec::new();
    // Source-backed GitHub closure reasons, never AI-written conclusions.
    let declined_reason = |pr: &Value| -> (String, String) {
        let link = to_js_string(pr.get("html_url"));
        let comments = g.gh(&format!(
            "/issues/{}/comments?per_page=50",
            to_js_string(pr.get("number"))
        ));
        if let Ok(comments) = comments {
            if let Some(found) = comments.as_array().and_then(|list| {
                list.iter().rev().find(|comment| {
                    ["OWNER", "MEMBER", "COLLABORATOR"]
                        .contains(&comment["author_association"].as_str().unwrap_or(""))
                        && {
                            let body = comment["body"].as_str().unwrap_or("").to_lowercase();
                            [
                                "declin",
                                "reject",
                                "not merging",
                                "won't merge",
                                "closing because",
                                "closed because",
                                "not suitable",
                            ]
                            .iter()
                            .any(|word| body.contains(word))
                        }
                })
            }) {
                return (
                    text(found["body"].as_str().unwrap_or(""), 650),
                    to_js_string(found.get("html_url")),
                );
            }
        }
        (
            "No maintainer reason recorded on the public GitHub pull request.".into(),
            link,
        )
    };
    // 1. Proposals on the default branch.
    let mut names: Vec<String> = g
        .gh("/contents/snips")?
        .as_array()
        .into_iter()
        .flatten()
        .map(|f| format!("snips/{}", to_js_string(f.get("name"))))
        .filter(|n| snip_file(n).is_some())
        .collect();
    names.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    names.truncate(MAX_SNIPS);
    for path in &names {
        let id = snip_file(path).unwrap_or_default();
        let (title, status) = parse_snip(&id, g.raw("HEAD", path)?.as_deref());
        let closed = true; // Merged onto main closes the forum, not protocol approval.
        out.push((id.clone(), json!({ "id": id, "title": title, "status": status, "url": format!("https://github.com/{repo}/blob/HEAD/{path}"), "where": "main", "closure": "merged_to_main", "closed": closed })));
    }
    // 2. Proposals that so far exist only in a pull request: open ones, then ones closed unmerged.
    let in_pull = |out: &mut Vec<(String, Value)>,
                   pr: &Value,
                   open: bool|
     -> std::result::Result<(), String> {
        let files = g.gh(&format!(
            "/pulls/{}/files?per_page=100",
            to_js_string(pr.get("number"))
        ))?;
        for f in files.as_array().into_iter().flatten() {
            let filename = if truthy(f.get("filename")) {
                to_js_string(f.get("filename"))
            } else {
                String::new()
            };
            let Some(id) = snip_file(&filename) else {
                continue;
            };
            if f["status"] == "removed" || out.iter().any(|(k, _)| *k == id) {
                continue;
            }
            let (title, status) = parse_snip(
                &id,
                g.raw(&to_js_string(pr["head"].get("sha")), &filename)?
                    .as_deref(),
            );
            let closed = !open || is_closed_status(&status);
            let closure = if !open {
                "closed_unmerged"
            } else if closed {
                "status_final"
            } else {
                ""
            };
            let mut value = json!({ "id": id, "title": title, "status": if open { status } else { "Closed without merging".into() }, "url": pr["html_url"], "where": "pull", "pull": pr["number"], "closed": closed, "closure": closure });
            if !open {
                let (reason, reason_source) = declined_reason(pr);
                value["reason"] = json!(reason);
                value["reason_source"] = json!(reason_source);
            }
            out.push((id.clone(), value));
        }
        Ok(())
    };
    for pr in g
        .gh(&format!(
            "/pulls?state=open&per_page={MAX_PRS}&sort=updated&direction=desc"
        ))?
        .as_array()
        .into_iter()
        .flatten()
    {
        in_pull(&mut out, pr, true)?;
    }
    let closed = g.gh("/pulls?state=closed&per_page=30&sort=updated&direction=desc")?;
    for pr in closed
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| !truthy(p.get("merged_at")))
        .take(5)
    {
        in_pull(&mut out, pr, false)?;
    }
    for pr in closed
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| truthy(p.get("merged_at")))
        .take(4)
    {
        let files = g
            .gh(&format!(
                "/pulls/{}/files?per_page=100",
                to_js_string(pr.get("number"))
            ))
            .unwrap_or(json!([]));
        for file in files.as_array().into_iter().flatten() {
            let Some(id) = snip_file(&to_js_string(file.get("filename"))) else {
                continue;
            };
            if file["status"] == "removed" {
                continue;
            }
            if let Some((_, proposal)) = out
                .iter_mut()
                .find(|(k, v)| k == &id && v["where"] == "main" && v.get("merged_pr").is_none())
            {
                let reason = pr["body"]
                    .as_str()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| pr["title"].as_str().unwrap_or(""));
                proposal["reason"] = json!(text(&reason.replace(['\n', '\r'], " "), 400));
                proposal["reason_source"] = pr["html_url"].clone();
                proposal["merged_pr"] = pr["number"].clone();
                proposal["merged_url"] = pr["html_url"].clone();
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out.into_iter().map(|(_, v)| v).collect())
}

fn repo(ctx: &Ctx) -> String {
    let r = &ctx.app.config.snip_forum.repo;
    if !r.is_empty() && repo_ok(r) {
        r.clone()
    } else {
        DEFAULT_REPO.into()
    }
}

/// GitHub allows 60 anonymous requests an hour and a refresh can take 15; with a token, far more.
fn refresh_ms(ctx: &Ctx) -> f64 {
    (if ctx.app.config.snip_forum.token.is_empty() {
        20.0
    } else {
        3.0
    }) * 60_000.0
}

fn proposals(ctx: &Ctx) -> Result<(Value, Value, bool)> {
    let (sr, now, repo) = (ctx.sr(), ctx.now, repo(ctx));
    let row = sr.first("SnipCache", json!({ "key": repo }), "-fetched_at")?;
    let cached = |r: &Value| {
        serde_json::from_str::<Value>(r["data"].as_str().unwrap_or("null")).unwrap_or(Value::Null)
    };
    if let Some(r) = &row {
        if (now as f64
            - crate::dates::parse(&to_js_string(r.get("fetched_at"))).unwrap_or(f64::NAN))
            < refresh_ms(ctx)
        {
            return Ok((cached(r), r["fetched_at"].clone(), false));
        }
    }
    match fetch_snips(&repo, &ctx.app.config.snip_forum.token) {
        Ok(snips) => {
            let record =
                json!({ "key": repo, "fetched_at": iso(now), "data": js_stringify(&json!(snips)) });
            match &row {
                Some(r) => sr.update("SnipCache", id_of(r), record.clone())?,
                None => sr.create("SnipCache", record.clone())?,
            };
            Ok((json!(snips), record["fetched_at"].clone(), false))
        }
        // GitHub can't be reached or is over its limit: carry on with what we had, and never treat
        // a failed read as "these proposals are gone".
        Err(_) => match &row {
            Some(r) => Ok((cached(r), r["fetched_at"].clone(), true)),
            None => Err(ApiError::new(
                503,
                "GITHUB_UNAVAILABLE",
                "GitHub can't be read right now.",
            )),
        },
    }
}

fn default_server(sr: &Db) -> Result<Option<Value>> {
    let mut rows: Vec<Value> = sr
        .filter("Server", json!({ "is_default": true }), "created_date", 5)?
        .into_iter()
        .filter(|s| s["status"] != "deleting")
        .collect();
    rows.sort_by(by_age);
    Ok(rows.into_iter().next())
}

fn forum_of(sr: &Db, server_id: &str) -> Result<Option<Value>> {
    let mut rows = sr.filter(
        "Channel",
        json!({ "server_id": server_id, "template_key": SNIP_CHANNEL_KEY }),
        "created_date",
        5,
    )?;
    rows.sort_by(by_age);
    Ok(rows.into_iter().next())
}

fn status(ctx: &mut Ctx) -> Result<Value> {
    if !ctx.app.config.snip_forum.enabled {
        return Ok(json!({ "enabled": false }));
    }
    let sr = ctx.sr();
    let Some(server) = default_server(&sr)? else {
        return Ok(json!({ "enabled": false }));
    };
    let server_id = id_of(&server).to_string();
    let Ok(member) = require_member(&ctx.own(), &server_id, ctx.user_id()) else {
        return Ok(json!({ "enabled": true, "manager": false }));
    };
    let parts = server_parts(&sr, &server_id)?;
    let perms = perms_of(&parts, &member, None);
    if !(has(perms, p::MANAGE_CHANNELS) && has(perms, p::MANAGE_THREADS)) {
        return Ok(json!({ "enabled": true, "manager": false }));
    }
    let (snips, fetched_at, stale) = proposals(ctx)?;
    let channel = forum_of(&sr, &server_id)?;
    let mut threads = serde_json::Map::new();
    let mut notes = serde_json::Map::new();
    if let Some(c) = &channel {
        for s in snips.as_array().into_iter().flatten() {
            let sid = to_js_string(s.get("id"));
            let post = sr.first(
                "ServerMessage",
                json!({ "channel_id": c["id"], "msg_id": snip_thread_id(&sid) }),
                "created_date",
            )?;
            if let Some(post) = &post {
                if !truthy(post.get("deleted")) {
                    threads.insert(
                        sid.clone(),
                        json!({ "locked": truthy(post.get("thread_locked")) }),
                    );
                }
                if truthy(s.get("closed")) {
                    notes.insert(sid.clone(), json!(sr.first("ServerMessage", json!({ "channel_id": c["id"], "msg_id": snip_closed_note_id(&sid) }), "created_date")?.is_some()));
                }
            }
        }
    }
    Ok(json!({
        "enabled": true, "manager": true, "server_id": server_id, "repo": repo(ctx), "fetched_at": fetched_at, "stale": stale,
        "channel": channel.as_ref().map_or(Value::Null, channel_out), "snips": snips, "threads": threads, "notes": notes,
    }))
}

fn ensure_forum(ctx: &mut Ctx) -> Result<Value> {
    if !ctx.app.config.snip_forum.enabled {
        return Err(ApiError::new(
            404,
            "NOT_ENABLED",
            "The proposals forum isn't turned on for this site.",
        ));
    }
    signed_by_active_device(ctx, "ensure_forum", crate::api::Limits::MAX_BODY_BYTES)?;
    let (sr, uid, now) = (ctx.sr(), ctx.user_id().to_string(), ctx.now);
    let server = default_server(&sr)?
        .ok_or_else(|| ApiError::new(404, "SERVER_NOT_FOUND", "There is no community server."))?;
    let server_id = id_of(&server).to_string();
    let member = require_member(&ctx.own(), &server_id, &uid)?;
    let parts = server_parts(&sr, &server_id)?;
    if !has(perms_of(&parts, &member, None), p::MANAGE_CHANNELS) {
        return Err(ApiError::new(
            403,
            "FORBIDDEN",
            "You need permission to manage channels.",
        ));
    }
    if let Some(existing) = forum_of(&sr, &server_id)? {
        return Ok(json!({ "channel": channel_out(&existing), "created": false }));
    }
    let everyone = parts.roles.iter().find(|r| truthy(r.get("is_everyone")));
    let position = parts
        .channels
        .iter()
        .map(|c| {
            let n = to_number(c.get("position"));
            if n.is_nan() {
                0.0
            } else {
                n
            }
        })
        .fold(0.0_f64, f64::max)
        + 1.0;
    let made = sr.create(
        "Channel",
        json!({
            "server_id": server_id, "audience_id": server_id, "kind": "forum", "parent_id": "", "position": crate::js::number_value(position), "template_key": SNIP_CHANNEL_KEY, "history": "full",
            "private": false, "overwrites": everyone.map_or(json!([]), |e| json!([{ "role_id": e["id"], "allow": 0, "deny": p::CREATE_POSTS }])),
            "slowmode_seconds": 0, "expire_seconds": 0, "sensitive": false, "creator_id": uid,
        }),
    )?;
    // Two admins' apps at the same moment: the older channel stays.
    let mut all = sr.filter(
        "Channel",
        json!({ "server_id": server_id, "template_key": SNIP_CHANNEL_KEY }),
        "created_date",
        5,
    )?;
    all.sort_by(by_age);
    let keep = match all.into_iter().next() {
        Some(first) if first["id"] != made["id"] => first,
        _ => made.clone(),
    };
    let created = keep["id"] == made["id"];
    if !created {
        let _ = sr.delete("Channel", id_of(&made));
    } else {
        touch_server(&sr, &server_id, now, json!({}))?;
        audit(
            &sr,
            &parts.server,
            &uid,
            "channel_create",
            "channel",
            id_of(&made),
            "forum",
            now,
        )?;
    }
    Ok(json!({ "channel": channel_out(&keep), "created": created }))
}

pub fn actions() -> Actions {
    let mut a = Actions::new();
    a.insert("status", status as crate::api::Action);
    a.insert("ensure_forum", ensure_forum);
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_proposal_header_as_the_typescript_does() {
        let md = "# SNIP-0007: Sealed sender\r\n\n| Field | Value |\n|---|---|\n| Status | Accepted (v1) |\n";
        assert_eq!(
            parse_snip("SNIP-0007", Some(md)),
            ("Sealed sender".into(), "Accepted (v1)".into())
        );
        assert_eq!(
            parse_snip("SNIP-0008", None),
            ("SNIP-0008".into(), String::new())
        );
        assert_eq!(
            parse_snip("SNIP-0009", Some("# SNIP-0009: \n")),
            ("SNIP-0009".into(), String::new())
        );
        assert!(is_closed_status(" Withdrawn by author"));
        assert!(!is_closed_status("Draft"));
        assert!(!is_closed_status("Acceptedly"));
        assert_eq!(text("a\u{1}\u{2}b  ", 10), "a b");
        assert_eq!(
            snip_file("snips/SNIP-0001.md").as_deref(),
            Some("SNIP-0001")
        );
        assert!(snip_file("snips/SNIP-001.md").is_none());
        assert!(repo_ok("Comutability/secure-net") && !repo_ok("a/b/c"));
    }
}
