//! Blocking and reporting, the staff side (reports, site content, erasing what removed sign-ins
//! left behind), and security reports from anyone (base44/shared/handlers/safety.ts and
//! disclosure.ts).
use std::collections::HashSet;

use serde_json::{json, Map, Value};

use crate::api::{clean_text, id, Actions, ApiError, Ctx, Result};
use crate::db::{id_of, Db};
use crate::js::{to_js_string, truthy};
use crate::shared::{
    conversation_for_member, count_since, enforce_rate, ids_of, or, profile_for, profile_of,
    rate_limited, within_rate, DAY_MS,
};

const REASONS: [&str; 6] = [
    "spam",
    "harassment",
    "impersonation",
    "illegal",
    "under_16",
    "other",
];
const STATUSES: [&str; 4] = ["open", "reviewing", "resolved", "dismissed"];
const SECURITY_STATUSES: [&str; 4] = ["new", "triaged", "fixed", "closed"];
const REPORTS_PER_DAY: usize = 20;
const ERASE_BUDGET_MS: i64 = 45_000;
const SCAN_PAGE: usize = 200;
const SCAN_LIMIT: usize = 5000;

fn deny(status: u16, code: &str, message: &str) -> ApiError {
    ApiError::new(status, code, message)
}
fn one_of(v: &Value, list: &[&str]) -> Option<String> {
    v.as_str().filter(|s| list.contains(s)).map(String::from)
}

// ---------- members ----------

fn block(ctx: &mut Ctx) -> Result<Value> {
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    let target = id(&ctx.body["user_id"], "member")?;
    if target == uid {
        return Err(deny(400, "BAD_FIELD", "You can't block yourself."));
    }
    if profile_of(&sr, &target)?.is_none() {
        return Err(deny(404, "NOT_FOUND", "Member not found."));
    }
    if sr
        .filter(
            "Block",
            json!({ "user_id": uid, "blocked_user_id": target }),
            "created_date",
            1,
        )?
        .is_empty()
    {
        sr.create(
            "Block",
            json!({ "user_id": uid, "blocked_user_id": target }),
        )?;
    }
    Ok(json!({ "ok": true }))
}

fn unblock(ctx: &mut Ctx) -> Result<Value> {
    let (sr, uid) = (ctx.sr(), ctx.user_id().to_string());
    let target = id(&ctx.body["user_id"], "member")?;
    for r in sr.filter(
        "Block",
        json!({ "user_id": uid, "blocked_user_id": target }),
        "created_date",
        10,
    )? {
        sr.delete("Block", id_of(&r))?;
    }
    Ok(json!({ "ok": true }))
}

fn list_blocks(ctx: &mut Ctx) -> Result<Value> {
    let sr = ctx.sr();
    let rows = sr.filter(
        "Block",
        json!({ "user_id": ctx.user_id() }),
        "-created_date",
        500,
    )?;
    let ids: Vec<Value> = rows.iter().map(|r| r["blocked_user_id"].clone()).collect();
    let profiles = if ids.is_empty() {
        vec![]
    } else {
        sr.filter(
            "Profile",
            json!({ "user_id": { "$in": ids } }),
            "created_date",
            500,
        )?
    };
    Ok(json!({ "blocked": profiles.iter().map(|p| profile_for(p, false)).collect::<Vec<_>>() }))
}

fn my_reports(ctx: &mut Ctx) -> Result<Value> {
    let rows = ctx.sr().filter(
        "Report",
        json!({ "reporter_id": ctx.user_id() }),
        "-created_date",
        500,
    )?;
    let reports: Vec<Value> = rows.iter().map(|r| {
        json!({ "reported_user_id": r["reported_user_id"], "conversation_id": or(&r["conversation_id"], Value::Null), "reason": r["reason"], "details": or(&r["details"], json!("")), "status": r["status"], "created_date": r["created_date"] })
    }).collect();
    Ok(json!({ "reports": reports }))
}

fn report(ctx: &mut Ctx) -> Result<Value> {
    let (sr, uid, now, body) = (ctx.sr(), ctx.user_id().to_string(), ctx.now, &ctx.body);
    let target = id(&body["user_id"], "member")?;
    if target == uid {
        return Err(deny(400, "BAD_FIELD", "You can't report yourself."));
    }
    if profile_of(&sr, &target)?.is_none() {
        return Err(deny(404, "NOT_FOUND", "Member not found."));
    }
    let Some(reason) = one_of(&body["reason"], &REASONS) else {
        return Err(deny(400, "BAD_FIELD", "Choose a reason."));
    };
    let mut conversation_id = String::new();
    if !matches!(body.get("conversation_id"), None | Some(Value::Null))
        && body["conversation_id"] != ""
    {
        let conv =
            conversation_for_member(&sr, &uid, &id(&body["conversation_id"], "conversation")?)?;
        if !ids_of(&conv["member_ids"]).contains(&target) {
            return Err(deny(
                400,
                "BAD_FIELD",
                "That member isn't in this conversation.",
            ));
        }
        conversation_id = id_of(&conv).to_string();
    }
    let details = clean_text(&body["details"], 2000)?;
    enforce_rate(
        &sr,
        "Report",
        json!({ "reporter_id": uid }),
        DAY_MS,
        REPORTS_PER_DAY,
        now,
        "sending reports",
    )?;
    let created = sr.create("Report", json!({ "reporter_id": uid, "reported_user_id": target, "conversation_id": conversation_id, "reason": reason, "details": details, "status": "open" }))?;
    if !within_rate(
        &sr,
        "Report",
        json!({ "reporter_id": uid }),
        DAY_MS,
        REPORTS_PER_DAY,
        now,
        &created,
    )? {
        sr.delete("Report", id_of(&created))?;
        return Err(rate_limited("sending reports"));
    }
    Ok(json!({ "ok": true }))
}

pub fn safety_actions() -> Actions {
    let mut a = Actions::new();
    for (name, f) in [
        ("block", block as crate::api::Action),
        ("unblock", unblock),
        ("list_blocks", list_blocks),
        ("my_reports", my_reports),
        ("report", report),
    ] {
        a.insert(name, f);
    }
    a
}

// ---------- staff ----------

fn require_admin(ctx: &Ctx) -> Result<()> {
    if ctx.user.as_ref().is_none_or(|u| u["role"] != "admin") {
        return Err(deny(403, "FORBIDDEN", "Staff only."));
    }
    Ok(())
}

fn check_failed() -> ApiError {
    deny(503, "CHECK_FAILED", "Couldn't check which sign-ins still exist, so nothing was changed. Please try again later.")
}

/// Which of these user ids still have a sign-in. The staff member's own id is always asked about
/// too: if it can't be found, the answers mean nothing, and nothing may be erased.
fn sign_ins_among(sr: &Db, staff_id: &str, ids: &[String]) -> Result<HashSet<String>> {
    let mut wanted = vec![staff_id.to_string()];
    for i in ids {
        if !wanted.contains(i) {
            wanted.push(i.clone());
        }
    }
    let mut rows = sr
        .filter(
            "User",
            json!({ "id": { "$in": wanted } }),
            "created_date",
            wanted.len(),
        )
        .map_err(|_| check_failed())?;
    rows.extend(
        sr.filter(
            "Person",
            json!({ "id": { "$in": wanted } }),
            "created_date",
            wanted.len(),
        )
        .map_err(|_| check_failed())?,
    );
    let found: HashSet<String> = rows
        .iter()
        .filter_map(|r| r["id"].as_str().map(String::from))
        .collect();
    if !found.contains(staff_id) {
        return Err(check_failed());
    }
    Ok(found)
}

/// A second, separate check for one id. Only a clear "not found" counts as gone.
fn sign_in_gone(store: &crate::store::Store, user_id: &str) -> Result<bool> {
    for table in ["Person", "User"] {
        match store.get(table, user_id) {
            Ok(_) => return Ok(false),
            Err(e) if e.status == 404 => {}
            Err(_) => return Err(check_failed()),
        }
    }
    Ok(true)
}

const RESOURCE_FIELDS: [&str; 11] = [
    "name",
    "website",
    "description",
    "category",
    "open_source",
    "self_hostable",
    "platforms",
    "pricing_summary",
    "privacy_notes",
    "last_reviewed",
    "status",
];

fn content_type(body: &Value) -> Result<&'static str> {
    if crate::js::to_js_string(Some(&or(&body["type"], json!("")))) == "Resource" {
        return Ok("Resource");
    }
    Err(deny(400, "BAD_TYPE", "That isn't site content."))
}

fn content_data(data: &Value) -> Result<Value> {
    let Some(d) = data.as_object().filter(|_| truthy(Some(data))) else {
        return Err(deny(400, "BAD_DATA", "Nothing to save."));
    };
    let mut out = Map::new();
    for k in RESOURCE_FIELDS {
        if let Some(v) = d.get(k) {
            out.insert(k.into(), v.clone());
        }
    }
    let out = Value::Object(out);
    if out.to_string().encode_utf16().count() > 64_000 {
        return Err(deny(413, "TOO_LARGE", "That's too long."));
    }
    Ok(out)
}

fn content_list(ctx: &mut Ctx) -> Result<Value> {
    require_admin(ctx)?;
    let t = content_type(&ctx.body)?;
    Ok(json!({ "items": ctx.own().filter(t, json!({}), "-updated_date", 500)? }))
}

fn content_save(ctx: &mut Ctx) -> Result<Value> {
    require_admin(ctx)?;
    let t = content_type(&ctx.body)?;
    let data = content_data(&ctx.body["data"])?;
    let own = ctx.own();
    let item = match ctx.body["id"].as_str().filter(|s| !s.is_empty()) {
        Some(i) => own.update(t, i, data)?,
        None => own.create(t, data)?,
    };
    Ok(json!({ "item": item }))
}

fn content_delete(ctx: &mut Ctx) -> Result<Value> {
    require_admin(ctx)?;
    let t = content_type(&ctx.body)?;
    let rid = to_js_string(Some(&or(&ctx.body["id"], json!(""))));
    ctx.own().delete(t, &rid)?;
    Ok(json!({ "ok": true }))
}

fn names_of(sr: &Db, ids: Vec<Value>) -> Result<Vec<Value>> {
    let mut unique: Vec<Value> = Vec::new();
    for i in ids {
        if !unique.contains(&i) {
            unique.push(i);
        }
    }
    if unique.is_empty() {
        return Ok(vec![]);
    }
    sr.filter(
        "Profile",
        json!({ "user_id": { "$in": unique } }),
        "created_date",
        500,
    )
}

fn list_reports(ctx: &mut Ctx) -> Result<Value> {
    require_admin(ctx)?;
    let sr = ctx.sr();
    let mut query = json!({});
    if let Some(s) = one_of(&ctx.body["status"], &STATUSES) {
        query["status"] = json!(s);
    }
    let rows = sr.filter("Report", query, "-created_date", 200)?;
    let profiles = names_of(
        &sr,
        rows.iter()
            .flat_map(|r| [r["reporter_id"].clone(), r["reported_user_id"].clone()])
            .collect(),
    )?;
    let name = |uid: &Value| {
        profiles
            .iter()
            .find(|p| p["user_id"] == *uid)
            .map(|p| or(&p["username"], json!("(deleted account)")))
            .unwrap_or(json!("(deleted account)"))
    };
    let reports: Vec<Value> = rows.iter().map(|r| json!({
        "id": r["id"], "reporter": name(&r["reporter_id"]), "reported_user_id": r["reported_user_id"], "reported": name(&r["reported_user_id"]),
        "reason": r["reason"], "details": or(&r["details"], json!("")), "status": r["status"], "resolution_note": or(&r["resolution_note"], json!("")),
        "created_date": r["created_date"], "source": or(&r["source"], json!("member")), "server_id": or(&r["server_id"], json!("")),
        "server_name": or(&r["server_name"], json!("")), "category": or(&r["category"], r["reason"].clone()),
    })).collect();
    Ok(json!({ "reports": reports }))
}

fn update_report(ctx: &mut Ctx) -> Result<Value> {
    require_admin(ctx)?;
    let sr = ctx.sr();
    let report = sr
        .get("Report", &id(&ctx.body["report_id"], "report")?)
        .ok_or_else(|| deny(404, "NOT_FOUND", "Report not found."))?;
    let status = one_of(&ctx.body["status"], &STATUSES)
        .map(Value::from)
        .unwrap_or_else(|| report["status"].clone());
    let updated = sr.update("Report", id_of(&report), json!({ "status": status, "resolution_note": clean_text(&ctx.body["resolution_note"], 1000)?, "handled_by": ctx.user_id() }))?;
    let s = if updated["status"].is_null() {
        status
    } else {
        updated["status"].clone()
    };
    Ok(json!({ "report": { "id": report["id"], "status": s } }))
}

fn list_security_reports(ctx: &mut Ctx) -> Result<Value> {
    require_admin(ctx)?;
    let sr = ctx.sr();
    let mut query = json!({});
    if let Some(s) = one_of(&ctx.body["status"], &SECURITY_STATUSES) {
        query["status"] = json!(s);
    }
    let rows = sr.filter("SecurityReport", query, "-created_date", 200)?;
    let profiles = names_of(
        &sr,
        rows.iter()
            .map(|r| r["reporter_user_id"].clone())
            .filter(|v| truthy(Some(v)))
            .collect(),
    )?;
    let reports: Vec<Value> = rows.iter().map(|r| {
        let reporter = if truthy(r.get("reporter_user_id")) {
            profiles.iter().find(|p| p["user_id"] == r["reporter_user_id"]).map(|p| or(&p["username"], json!("(member)"))).unwrap_or(json!("(member)"))
        } else {
            json!("")
        };
        json!({ "id": r["id"], "summary": r["summary"], "details": r["details"], "contact": or(&r["contact"], json!("")), "reporter": reporter, "status": r["status"], "staff_note": or(&r["staff_note"], json!("")), "created_date": r["created_date"] })
    }).collect();
    Ok(json!({ "reports": reports }))
}

fn update_security_report(ctx: &mut Ctx) -> Result<Value> {
    require_admin(ctx)?;
    let sr = ctx.sr();
    let report = sr
        .get("SecurityReport", &id(&ctx.body["report_id"], "report")?)
        .ok_or_else(|| deny(404, "NOT_FOUND", "Report not found."))?;
    let status = one_of(&ctx.body["status"], &SECURITY_STATUSES)
        .map(Value::from)
        .unwrap_or_else(|| report["status"].clone());
    sr.update(
        "SecurityReport",
        id_of(&report),
        json!({ "status": status, "staff_note": clean_text(&ctx.body["staff_note"], 2000)? }),
    )?;
    Ok(json!({ "report": { "id": report["id"], "status": status } }))
}

fn list_removed_accounts(ctx: &mut Ctx) -> Result<Value> {
    require_admin(ctx)?;
    let (sr, staff) = (ctx.sr(), ctx.user_id().to_string());
    let mut accounts = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let (mut after, mut scanned) = (Value::Null, 0);
    while scanned < SCAN_LIMIT {
        let q = if truthy(Some(&after)) {
            json!({ "created_date": { "$gte": after } })
        } else {
            json!({})
        };
        let page = sr.filter("Profile", q, "created_date", SCAN_PAGE)?;
        let fresh: Vec<&Value> = page.iter().filter(|p| !seen.contains(id_of(p))).collect();
        if fresh.is_empty() {
            break;
        }
        for p in &fresh {
            seen.insert(id_of(p).to_string());
        }
        scanned += fresh.len();
        let ids: Vec<String> = fresh
            .iter()
            .filter(|p| truthy(p.get("user_id")))
            .map(|p| to_js_string(p.get("user_id")))
            .collect();
        let present = sign_ins_among(&sr, &staff, &ids)?;
        for p in &fresh {
            if truthy(p.get("user_id")) && !present.contains(&to_js_string(p.get("user_id"))) {
                accounts.push(json!({ "user_id": p["user_id"], "username": p["username"], "display_name": or(&p["display_name"], json!("")), "created_date": p["created_date"] }));
            }
        }
        after = page
            .last()
            .map(|p| p["created_date"].clone())
            .unwrap_or(Value::Null);
        if page.len() < SCAN_PAGE {
            break;
        }
    }
    Ok(json!({ "accounts": accounts, "complete": scanned < SCAN_LIMIT }))
}

fn erase_removed_account(ctx: &mut Ctx) -> Result<Value> {
    require_admin(ctx)?;
    let (sr, staff) = (ctx.sr(), ctx.user_id().to_string());
    let target = id(&ctx.body["user_id"], "account")?;
    if ctx.body["confirm"] != "ERASE" {
        return Err(deny(400, "CONFIRM_REQUIRED", "Type ERASE to confirm."));
    }
    let present = sign_ins_among(&sr, &staff, std::slice::from_ref(&target))?;
    if present.contains(&target) || !sign_in_gone(ctx.store(), &target)? {
        return Err(deny(409, "SIGN_IN_EXISTS", "That account can still sign in. Members delete their own accounts in Settings; to remove someone, remove their sign-in in Base44 first."));
    }
    let done = crate::deletion::purge_account(
        &sr,
        ctx.store(),
        &target,
        crate::sessions::now_ms() + ERASE_BUDGET_MS,
    )?;
    Ok(json!({ "done": done }))
}

pub fn admin_actions() -> Actions {
    let mut a = Actions::new();
    for (name, f) in [
        ("content_list", content_list as crate::api::Action),
        ("content_save", content_save),
        ("content_delete", content_delete),
        ("list_reports", list_reports),
        ("update_report", update_report),
        ("list_security_reports", list_security_reports),
        ("update_security_report", update_security_report),
        ("list_removed_accounts", list_removed_accounts),
        ("erase_removed_account", erase_removed_account),
    ] {
        a.insert(name, f);
    }
    for (name, action) in crate::site_policy::admin_actions() {
        a.insert(name, action);
    }
    a
}

// ---------- security reports from anyone (disclosure.ts) ----------

const ANONYMOUS_PER_HOUR: usize = 10;
const ANONYMOUS_PER_DAY: usize = 40;
const PER_USER_PER_DAY: usize = 5;
const HOUR_MS: i64 = 3_600_000;

fn submit(ctx: &mut Ctx) -> Result<Value> {
    let (sr, now, body) = (ctx.sr(), ctx.now, &ctx.body);
    let summary = clean_text(&body["summary"], 200)?;
    let details = clean_text(&body["details"], 8000)?;
    let contact = clean_text(&body["contact"], 300)?;
    if summary.encode_utf16().count() < 5 {
        return Err(deny(400, "BAD_FIELD", "Give the problem a short title."));
    }
    if details.encode_utf16().count() < 20 {
        return Err(deny(
            400,
            "BAD_FIELD",
            "Please describe the problem in a little more detail.",
        ));
    }
    let busy = || {
        deny(
            429,
            "RATE_LIMITED",
            "We've had a lot of reports just now. Please try again later.",
        )
    };
    let user = ctx.user.as_ref().map(|u| to_js_string(u.get("id")));
    let anonymous = json!({ "reporter_user_id": "" });
    match &user {
        Some(u) => {
            if count_since(
                &sr,
                "SecurityReport",
                json!({ "reporter_user_id": u }),
                now - DAY_MS,
                PER_USER_PER_DAY,
            )? >= PER_USER_PER_DAY
            {
                return Err(busy());
            }
        }
        None => {
            if count_since(
                &sr,
                "SecurityReport",
                anonymous.clone(),
                now - HOUR_MS,
                ANONYMOUS_PER_HOUR,
            )? >= ANONYMOUS_PER_HOUR
            {
                return Err(busy());
            }
            if count_since(
                &sr,
                "SecurityReport",
                anonymous.clone(),
                now - DAY_MS,
                ANONYMOUS_PER_DAY,
            )? >= ANONYMOUS_PER_DAY
            {
                return Err(busy());
            }
        }
    }
    let created = sr.create("SecurityReport", json!({ "summary": summary, "details": details, "contact": contact, "reporter_user_id": user.clone().unwrap_or_default(), "status": "new", "staff_note": "" }))?;
    let ok = match &user {
        Some(u) => within_rate(
            &sr,
            "SecurityReport",
            json!({ "reporter_user_id": u }),
            DAY_MS,
            PER_USER_PER_DAY,
            now,
            &created,
        )?,
        None => {
            within_rate(
                &sr,
                "SecurityReport",
                anonymous.clone(),
                HOUR_MS,
                ANONYMOUS_PER_HOUR,
                now,
                &created,
            )? && within_rate(
                &sr,
                "SecurityReport",
                anonymous,
                DAY_MS,
                ANONYMOUS_PER_DAY,
                now,
                &created,
            )?
        }
    };
    if !ok {
        sr.delete("SecurityReport", id_of(&created))?;
        return Err(busy());
    }
    Ok(json!({ "ok": true }))
}

pub fn disclosure_actions() -> Actions {
    // Public site rules reveal only operator-authored policy and public reasons.
    let mut a = Actions::new();
    a.insert("submit", submit as crate::api::Action);
    a
}
