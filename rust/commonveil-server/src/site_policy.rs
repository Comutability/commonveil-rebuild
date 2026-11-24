//! Instance-level moderation, separate from per-community roles and from the
//! independently governed Secure Net protocol. Private encrypted message
//! contents never enter this module.
use crate::api::{ApiError, Ctx, Result};
use crate::db::{id_of, Db};
use crate::shared::iso;
use crate::store::Store;
use serde_json::{json, Value};

const MAX_DOMAINS: usize = 300;
const MAX_RULES: usize = 20;
fn deny(status: u16, code: &str, msg: &str) -> ApiError {
    ApiError::new(status, code, msg)
}
pub fn default_policy() -> Value {
    json!({"public_rules":[],"contact":"","federation_mode":"open",
      "registration_open":true,"allow_remote_discovery":true,"show_domain_blocks":false})
}
pub fn policy_of(input: Option<&Value>) -> Value {
    let mut p = default_policy();
    let Some(v) = input else { return p };
    if let Some(rules) = v["public_rules"].as_array() {
        p["public_rules"] = json!(rules
            .iter()
            .filter_map(Value::as_str)
            .take(MAX_RULES)
            .collect::<Vec<_>>());
    }
    if let Some(contact) = v["contact"].as_str() {
        p["contact"] = json!(contact)
    }
    if ["open", "allowlist", "off"].contains(&v["federation_mode"].as_str().unwrap_or("")) {
        p["federation_mode"] = v["federation_mode"].clone()
    }
    for flag in ["registration_open", "allow_remote_discovery"] {
        p[flag] = json!(v[flag] != false)
    }
    p["show_domain_blocks"] = json!(v["show_domain_blocks"] == true);
    p
}
fn manager(ctx: &Ctx) -> Result<bool> {
    let Some(user) = ctx.user.as_ref() else {
        return Err(deny(403, "FORBIDDEN", "Site administrators only."));
    };
    if user["role"] != "admin" {
        return Err(deny(403, "FORBIDDEN", "Site administrators only."));
    }
    Ok(user["site_owner"] == true)
}
fn current(sr: &Db) -> Result<Option<Value>> {
    sr.first("SitePolicy", json!({"scope":"site"}), "created_date")
}
pub fn current_policy(store: &Store) -> Result<Value> {
    let sr = Db::service(store);
    Ok(policy_of(current(&sr)?.as_ref()))
}
pub fn domain_rule(store: &Store, host: &str) -> Result<Option<Value>> {
    let sr = Db::service(store);
    sr.first("SiteDomainRule", json!({"domain":host}), "-created_date")
}
pub fn decision(store: &Store, host: &str) -> Result<String> {
    let policy = current_policy(store)?;
    let rule = domain_rule(store, host)?;
    let severity = rule
        .as_ref()
        .and_then(|r| r["severity"].as_str())
        .unwrap_or("");
    if severity == "suspend"
        || policy["federation_mode"] == "off"
        || (policy["federation_mode"] == "allowlist" && severity != "allow")
    {
        return Ok("suspend".into());
    }
    Ok(if severity.is_empty() {
        "open".into()
    } else {
        severity.into()
    })
}
pub fn clean_host(value: &Value) -> Result<String> {
    let s = value
        .as_str()
        .ok_or_else(|| deny(400, "BAD_DOMAIN", "Enter a DNS hostname."))?
        .trim()
        .to_lowercase();
    if s.len() > 253
        || !s.contains('.')
        || s.contains([':', '/', '\\'])
        || s.ends_with('.')
        || s.bytes().all(|c| c == b'.' || c.is_ascii_digit())
        || !s.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
    {
        return Err(deny(
            400,
            "BAD_DOMAIN",
            "Enter an exact public DNS site hostname.",
        ));
    }
    Ok(s)
}
fn list(sr: &Db, owner: bool) -> Result<Value> {
    let policy = policy_of(current(sr)?.as_ref());
    let domains = sr.list("SiteDomainRule", "created_date", MAX_DOMAINS)?;
    Ok(
        json!({"policy":policy,"domains":domains.iter().map(|r|json!({
        "domain":r["domain"],"severity":r["severity"],"public_reason":r["public_reason"],
        "private_note":r["private_note"],"updated_at":r["updated_at"]})).collect::<Vec<_>>(),
        "admin":true,"owner":owner}),
    )
}
fn check_policy(input: &Value, current: &Value, owner: bool) -> Result<Value> {
    let obj = input
        .as_object()
        .ok_or_else(|| deny(400, "BAD_POLICY", "Invalid policy."))?;
    if obj.keys().any(|k| {
        ![
            "public_rules",
            "contact",
            "registration_open",
            "allow_remote_discovery",
            "show_domain_blocks",
            "federation_mode",
        ]
        .contains(&k.as_str())
    }) {
        return Err(deny(400, "BAD_POLICY", "Unexpected policy field."));
    }
    let mut p = policy_of(Some(current));
    if let Some(rules) = obj.get("public_rules") {
        let list = rules
            .as_array()
            .ok_or_else(|| deny(400, "BAD_RULES", "Use a list of rules."))?;
        if list.len() > MAX_RULES
            || list.iter().any(|r| {
                r.as_str()
                    .is_none_or(|s| !(3..=500).contains(&s.trim().chars().count()))
            })
        {
            return Err(deny(
                400,
                "BAD_RULES",
                "Use at most 20 rules, 3 to 500 characters each.",
            ));
        }
        p["public_rules"] = json!(list
            .iter()
            .map(|r| r.as_str().unwrap_or("").trim())
            .collect::<Vec<_>>());
    }
    if let Some(c) = obj.get("contact") {
        if c.as_str().is_none_or(|s| s.len() > 200) {
            return Err(deny(400, "BAD_CONTACT", "Contact information is too long."));
        }
        p["contact"] = json!(c.as_str().unwrap_or("").trim());
    }
    for flag in [
        "registration_open",
        "allow_remote_discovery",
        "show_domain_blocks",
    ] {
        if let Some(v) = obj.get(flag) {
            if !v.is_boolean() {
                return Err(deny(400, "BAD_POLICY", "Invalid policy flag."));
            }
            if flag == "registration_open" && !owner {
                return Err(deny(
                    403,
                    "OWNER_ONLY",
                    "Only the host owner may change registration.",
                ));
            }
            p[flag] = v.clone();
        }
    }
    if let Some(v) = obj.get("federation_mode") {
        if !owner {
            return Err(deny(
                403,
                "OWNER_ONLY",
                "Only the host owner may change federation mode.",
            ));
        }
        if !["open", "allowlist", "off"].contains(&v.as_str().unwrap_or("")) {
            return Err(deny(400, "BAD_POLICY", "Invalid federation mode."));
        }
        p["federation_mode"] = v.clone();
    }
    Ok(p)
}
fn validate_domain(v: &Value) -> Result<Value> {
    let obj = v
        .as_object()
        .ok_or_else(|| deny(400, "BAD_RULE", "Invalid domain rule."))?;
    if obj
        .keys()
        .any(|k| !["domain", "severity", "public_reason", "private_note"].contains(&k.as_str()))
    {
        return Err(deny(400, "BAD_RULE", "Unexpected field."));
    }
    let host = clean_host(&v["domain"])?;
    let severity = v["severity"].as_str().unwrap_or("");
    if !["suspend", "limit", "reject_media", "allow"].contains(&severity) {
        return Err(deny(
            400,
            "BAD_SEVERITY",
            "Choose suspend, limit, reject media or allow.",
        ));
    }
    let reason = |field: &str, max: usize| -> Result<String> {
        if v.get(field).is_some() && !v[field].is_string() {
            return Err(deny(400, "BAD_REASON", "Invalid reason."));
        }
        let value = v[field].as_str().unwrap_or("").trim();
        if value.chars().count() > max {
            return Err(deny(400, "BAD_REASON", "Reason is too long."));
        }
        Ok(value.into())
    };
    Ok(
        json!({"domain":host,"severity":severity,"public_reason":reason("public_reason",500)?,
      "private_note":reason("private_note",1000)?}),
    )
}
fn get(ctx: &mut Ctx) -> Result<Value> {
    let owner = manager(ctx)?;
    list(&ctx.sr(), owner)
}
fn save(ctx: &mut Ctx) -> Result<Value> {
    let owner = manager(ctx)?;
    let sr = ctx.sr();
    let existing = current(&sr)?;
    let clean = check_policy(&ctx.body["policy"], &policy_of(existing.as_ref()), owner)?;
    let mut data = clean.clone();
    data["scope"] = json!("site");
    data["updated_by"] = json!(ctx.user_id());
    data["updated_at"] = json!(iso(ctx.now));
    if let Some(row) = existing {
        sr.update("SitePolicy", id_of(&row), data)?;
    } else {
        sr.create("SitePolicy", data)?;
    }
    Ok(json!({"policy":clean}))
}
fn upsert(ctx: &mut Ctx) -> Result<Value> {
    let owner = manager(ctx)?;
    let sr = ctx.sr();
    let mut data = validate_domain(&ctx.body["rule"])?;
    let existing = sr.filter(
        "SiteDomainRule",
        json!({"domain":data["domain"]}),
        "created_date",
        5,
    )?;
    if existing.is_empty()
        && sr
            .list("SiteDomainRule", "created_date", MAX_DOMAINS + 1)?
            .len()
            >= MAX_DOMAINS
    {
        return Err(deny(409, "DOMAIN_LIMIT", "Too many domain rules."));
    }
    data["updated_by"] = json!(ctx.user_id());
    data["updated_at"] = json!(iso(ctx.now));
    if let Some(row) = existing.first() {
        sr.update("SiteDomainRule", id_of(row), data)?;
    } else {
        sr.create("SiteDomainRule", data)?;
    }
    list(&sr, owner)
}
fn remove(ctx: &mut Ctx) -> Result<Value> {
    let owner = manager(ctx)?;
    let host = clean_host(&ctx.body["domain"])?;
    let sr = ctx.sr();
    for row in sr.filter("SiteDomainRule", json!({"domain":host}), "created_date", 10)? {
        sr.delete("SiteDomainRule", id_of(&row))?;
    }
    list(&sr, owner)
}
pub fn public_rules(ctx: &mut Ctx) -> Result<Value> {
    let sr = ctx.sr();
    let p = policy_of(current(&sr)?.as_ref());
    let mut blocks = Vec::new();
    if p["show_domain_blocks"] == true {
        for row in sr.list("SiteDomainRule", "created_date", MAX_DOMAINS)? {
            if row["severity"] == "suspend" || row["severity"] == "limit" {
                blocks.push(json!({"domain":row["domain"],"severity":row["severity"],"reason":row["public_reason"]}));
            }
        }
    }
    Ok(json!({"rules":p["public_rules"],"contact":p["contact"],
        "registration_open":p["registration_open"],"federation_mode":p["federation_mode"],
        "domain_blocks":blocks}))
}
pub fn admin_actions() -> crate::api::Actions {
    let mut a = crate::api::Actions::new();
    a.insert("site_policy_get", get);
    a.insert("site_policy_save", save);
    a.insert("site_domain_upsert", upsert);
    a.insert("site_domain_remove", remove);
    a
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_host_and_rules_validation() {
        for host in ["example.com", "chat.example.co.uk"] {
            assert_eq!(clean_host(&json!(host)).unwrap(), host)
        }
        for host in [
            "localhost",
            "http://x.example",
            "a..example.com",
            "127.0.0.1",
            "bad_site.example",
            "-bad.example",
            "bad-.example",
            "something.example:443",
        ] {
            assert!(clean_host(&json!(host)).is_err(), "{host}");
        }
        assert!(validate_domain(
            &json!({"domain":"example.com","severity":"suspend","public_reason":"Spam"})
        )
        .is_ok());
        assert!(validate_domain(
            &json!({"domain":"example.com","severity":"allow","private_note":{"oops":true}})
        )
        .is_err());
        assert!(check_policy(&json!({"federation_mode":"off"}), &default_policy(), false).is_err());
        assert_eq!(
            check_policy(&json!({"registration_open":false}), &default_policy(), true).unwrap()
                ["registration_open"],
            false
        );
    }
}
