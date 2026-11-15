//! The self-hosted data store, matching `server/store.mjs`: every table in base44/entities, kept in
//! SQLite on disk (the same file and layout, so a site's existing data is read as it is) and in
//! memory for queries, with the same query language and row rules.
//!
//! Reads made as a signed-in person follow each table's "rls" rules from its schema file; writes
//! as a person only where a rule allows them. The backend writes as the service role.
use std::collections::{BTreeMap, HashMap};

use indexmap::{IndexMap, IndexSet};
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Map, Value};

use crate::js;

/// A refusal with an HTTP status, as the Node store throws.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError {
    pub status: u16,
    pub message: String,
}
fn denied(status: u16, message: impl Into<String>) -> StoreError {
    StoreError { status, message: message.into() }
}
pub type Result<T> = std::result::Result<T, StoreError>;

/// Strip comments from a .jsonc file.
pub fn parse_jsonc(text: &str) -> std::result::Result<Value, serde_json::Error> {
    let no_block = regex::Regex::new(r"(?s)/\*.*?\*/").unwrap().replace_all(text, "");
    let no_line = regex::Regex::new(r"(?m)^\s*//.*$").unwrap().replace_all(&no_block, "");
    serde_json::from_str(&no_line)
}

/// Every schema in a folder of .jsonc files, by table name.
pub fn load_schemas(dir: &Path) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    let mut files: Vec<_> = std::fs::read_dir(dir).expect("entities folder").filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "jsonc")).collect();
    files.sort();
    for f in files {
        let s = parse_jsonc(&std::fs::read_to_string(&f).unwrap()).unwrap_or_else(|e| panic!("{}: {e}", f.display()));
        out.insert(s["name"].as_str().unwrap().to_string(), s);
    }
    out
}

// ---------- queries ----------

fn refers_to_user(rule: Option<&Value>) -> bool {
    let s = rule.map(Value::to_string).unwrap_or_else(|| "null".into());
    s.contains("{{user") || s.contains("user_condition")
}

/// A signed-in person, as the rules see them.
#[derive(Clone, Debug, Default)]
pub struct Person {
    pub id: String,
    pub email: String,
    /// Every field of their user record (for `user_condition`).
    pub record: Map<String, Value>,
}

/// A row rule as a query for this person: `Some({})` matches everything, `None` nothing.
pub fn rule_to_query(rule: Option<&Value>, user: Option<&Person>, user_data: &dyn Fn(&str) -> Option<Value>) -> Result<Option<Value>> {
    let rule = match rule {
        Some(Value::Bool(true)) => return Ok(Some(json!({}))),
        None | Some(Value::Bool(false)) | Some(Value::Null) => return Ok(None),
        Some(r) => r,
    };
    let resolve = |value: &Value| -> Result<Option<Value>> {
        match value.as_str() {
            Some("{{user.id}}") => Ok(user.map(|u| json!(u.id))),
            Some("{{user.email}}") => Ok(user.map(|u| json!(u.email))),
            Some(s) => {
                if let Some(field) = s.strip_prefix("{{user.data.").and_then(|r| r.strip_suffix("}}")).filter(|f| !f.is_empty() && f.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')) {
                    return Ok(user_data(field));
                }
                if s.contains("{{") {
                    return Err(denied(500, format!("Unsupported rule value {s}")));
                }
                Ok(Some(value.clone()))
            }
            None => Ok(Some(value.clone())),
        }
    };
    let mut parts: Vec<Value> = Vec::new();
    for (key, value) in rule.as_object().into_iter().flatten() {
        if key == "$or" {
            let subs = value.as_array().into_iter().flatten().map(|r| rule_to_query(Some(r), user, user_data)).collect::<Result<Vec<_>>>()?;
            if subs.iter().any(|s| s.as_ref().is_some_and(|q| q.as_object().is_some_and(Map::is_empty))) {
                return Ok(Some(json!({})));
            }
            let live: Vec<Value> = subs.into_iter().flatten().collect();
            if live.is_empty() {
                return Ok(None);
            }
            parts.push(json!({ "$or": live }));
        } else if key == "$and" {
            let subs = value.as_array().into_iter().flatten().map(|r| rule_to_query(Some(r), user, user_data)).collect::<Result<Vec<_>>>()?;
            if subs.iter().any(Option::is_none) {
                return Ok(None);
            }
            parts.extend(subs.into_iter().flatten());
        } else if key == "user_condition" {
            let Some(u) = user else { return Ok(None) };
            for (field, expected) in value.as_object().into_iter().flatten() {
                let actual = match field.as_str() {
                    "id" => Some(json!(u.id)),
                    "email" => Some(json!(u.email)),
                    f => u.record.get(f).cloned(),
                };
                if !js::strict_eq(actual.as_ref(), Some(expected)) {
                    return Ok(None);
                }
            }
        } else if let Some(field) = key.strip_prefix("data.") {
            if user.is_none() && refers_to_user(Some(value)) {
                return Ok(None);
            }
            if let Some(obj) = value.as_object() {
                if obj.len() != 1 || !obj.contains_key("$in") {
                    return Err(denied(500, "Only $in rules are supported"));
                }
                let list = resolve(&obj["$in"])?;
                let list = list.filter(Value::is_array).unwrap_or_else(|| json!([]));
                parts.push(json!({ field: { "$in": list } }));
            } else {
                match resolve(value)? {
                    None => return Ok(None),
                    Some(v) => parts.push(json!({ field: v })),
                }
            }
        } else {
            return Err(denied(500, format!("Unsupported rule key {key}")));
        }
    }
    Ok(Some(if parts.is_empty() { json!({}) } else { json!({ "$and": parts }) }))
}

/// Whether a record matches a query (the subset of MongoDB's language the app uses).
pub fn matches(record: &Value, query: &Value) -> Result<bool> {
    for (key, cond) in query.as_object().into_iter().flatten() {
        if key == "$or" {
            let mut any = false;
            for sub in cond.as_array().into_iter().flatten() {
                if matches(record, sub)? {
                    any = true;
                    break;
                }
            }
            if !any {
                return Ok(false);
            }
            continue;
        }
        if key == "$and" {
            for sub in cond.as_array().into_iter().flatten() {
                if !matches(record, sub)? {
                    return Ok(false);
                }
            }
            continue;
        }
        let value = record.get(key);
        let values: Vec<Option<&Value>> = match value {
            Some(Value::Array(a)) => a.iter().map(Some).collect(),
            v => vec![v],
        };
        let includes = |list: &[Value], v: Option<&Value>| list.iter().any(|x| js::strict_eq(Some(x), v));
        match cond {
            Value::Object(ops) => {
                for (op, arg) in ops {
                    let ok = match op.as_str() {
                        "$in" => arg.as_array().is_some_and(|a| values.iter().any(|v| includes(a, *v))),
                        "$nin" => !arg.as_array().is_some_and(|a| values.iter().any(|v| includes(a, *v))),
                        "$gte" => js::ge(value, Some(arg)),
                        "$gt" => js::gt(value, Some(arg)),
                        "$lte" => js::le(value, Some(arg)),
                        "$lt" => js::lt(value, Some(arg)),
                        "$ne" => !js::strict_eq(value, Some(arg)),
                        "$exists" => matches!(value, Some(v) if !v.is_null()) == js::truthy(Some(arg)),
                        _ => return Err(denied(400, format!("Unsupported query operator {op}"))),
                    };
                    if !ok {
                        return Ok(false);
                    }
                }
            }
            Value::Array(list) => {
                if !values.iter().any(|v| includes(list, *v)) {
                    return Ok(false);
                }
            }
            Value::Null => {
                if !matches!(value, None | Some(Value::Null)) {
                    return Ok(false);
                }
            }
            scalar => {
                let hit = match value {
                    Some(Value::Array(a)) => includes(a, Some(scalar)),
                    v => js::strict_eq(v, Some(scalar)),
                };
                if !hit {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

/// An index key: the scalars a JavaScript `Map` tells apart.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Key {
    Str(String),
    Num(u64),
    Bool(bool),
}
fn key_of(v: &Value) -> Option<Key> {
    match v {
        Value::String(s) => Some(Key::Str(s.clone())),
        Value::Bool(b) => Some(Key::Bool(*b)),
        Value::Number(n) => n.as_f64().map(|f| Key::Num(if f == 0.0 { 0f64.to_bits() } else { f.to_bits() })),
        _ => None,
    }
}

/// Top-level conditions an index can answer: field -> the values that may match.
fn indexable(query: &Value, out: &mut Vec<(String, Vec<Value>)>) {
    for (key, cond) in query.as_object().into_iter().flatten() {
        if key == "$and" {
            for sub in cond.as_array().into_iter().flatten() {
                indexable(sub, out);
            }
            continue;
        }
        if key.starts_with('$') {
            continue;
        }
        let scalar = |v: &Value| matches!(v, Value::String(_) | Value::Number(_) | Value::Bool(_));
        if scalar(cond) {
            out.push((key.clone(), vec![cond.clone()]));
        } else if let Some(o) = cond.as_object() {
            if o.len() == 1 {
                if let Some(list) = o.get("$in").and_then(Value::as_array).filter(|l| l.iter().all(scalar)) {
                    out.push((key.clone(), list.clone()));
                }
            }
        }
    }
}

/// Rows and index sets keep insertion order, as JavaScript's Map and Set do.
#[derive(Default)]
struct Table {
    rows: IndexMap<String, Value>,
    seqs: HashMap<String, i64>,
    indexes: HashMap<String, IndexMap<Key, IndexSet<String>>>,
}

fn index_add(idx: &mut IndexMap<Key, IndexSet<String>>, field: &str, id: &str, row: &Value) {
    let v = row.get(field);
    let items: Vec<&Value> = match v {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(x) => vec![x],
        None => vec![],
    };
    for x in items {
        if let Some(k) = key_of(x) {
            idx.entry(k).or_default().insert(id.to_string());
        }
    }
}
fn index_remove(idx: &mut IndexMap<Key, IndexSet<String>>, field: &str, id: &str, row: &Value) {
    let items: Vec<&Value> = match row.get(field) {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(x) => vec![x],
        None => vec![],
    };
    for x in items {
        if let Some(set) = key_of(x).and_then(|k| idx.get_mut(&k)) {
            set.shift_remove(id);
        }
    }
}

struct Inner {
    db: Connection,
    seq: i64,
    micros: i64,
    tables: HashMap<String, Table>,
}

/// Called after every write: (table, new row, old row). A watcher failing never undoes the write.
pub type WriteHook = Box<dyn Fn(&str, &Value, Option<&Value>) + Send + Sync>;
/// Called after every delete: (table, id, old row).
pub type RemoveHook = Box<dyn Fn(&str, &str, &Value) + Send + Sync>;

pub struct Store {
    pub schemas: BTreeMap<String, Value>,
    inner: Mutex<Inner>,
    pub on_write: Option<WriteHook>,
    pub on_remove: Option<RemoveHook>,
}

fn now_micros() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_micros() as i64).unwrap_or(0)
}

/// `new Date(ms).toISOString()`.
pub fn iso(ms: i64) -> String {
    let (days, rem) = (ms.div_euclid(86_400_000), ms.rem_euclid(86_400_000));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let (h, mi, s, milli) = (rem / 3_600_000, rem / 60_000 % 60, rem / 1000 % 60, rem % 1000);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{milli:03}Z")
}

fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).expect("system randomness");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn valid_fixed_id(s: &str) -> bool {
    (8..=64).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}
fn valid_table(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.as_bytes()[0].is_ascii_alphabetic() && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

fn merge(base: &Value, data: &Value) -> Value {
    let mut out = base.as_object().cloned().unwrap_or_default();
    for (k, v) in data.as_object().into_iter().flatten() {
        out.insert(k.clone(), v.clone());
    }
    Value::Object(out)
}

impl Store {
    /// `file`: the SQLite database path (":memory:" for tests).
    pub fn open(file: &str, schemas: BTreeMap<String, Value>) -> rusqlite::Result<Self> {
        let db = Connection::open(file)?;
        db.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;")?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS records (entity TEXT NOT NULL, id TEXT NOT NULL, seq INTEGER NOT NULL, data TEXT NOT NULL, PRIMARY KEY (entity, id))")?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)")?;
        let seq: i64 = db.query_row("SELECT COALESCE(MAX(seq), 0) FROM records", [], |r| r.get(0))?;
        Ok(Self { schemas, inner: Mutex::new(Inner { db, seq, micros: 0, tables: HashMap::new() }), on_write: None, on_remove: None })
    }

    /// Small settings the server keeps for itself (not entities).
    pub fn get_setting(&self, k: &str) -> Option<Value> {
        let inner = self.inner.lock().unwrap();
        let row: Option<String> = inner.db.query_row("SELECT v FROM kv WHERE k = ?", [k], |r| r.get(0)).optional().ok().flatten();
        row.and_then(|v| serde_json::from_str(&v).ok())
    }
    pub fn set_setting(&self, k: &str, v: Option<&Value>) {
        let inner = self.inner.lock().unwrap();
        match v {
            None | Some(Value::Null) => {
                let _ = inner.db.execute("DELETE FROM kv WHERE k = ?", [k]);
            }
            Some(v) => {
                let _ = inner.db.execute("INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", params![k, v.to_string()]);
            }
        }
    }

    /// Record times, like Base44's: microseconds, never going backwards.
    fn tick(inner: &mut Inner) -> String {
        inner.micros = (inner.micros + 1).max(now_micros());
        let ms = inner.micros.div_euclid(1000);
        iso(ms).replace('Z', &format!("{:03}", inner.micros.rem_euclid(1000)))
    }

    pub fn new_id() -> String {
        let secs = now_micros() / 1_000_000;
        format!("{secs:08x}{}", random_hex(8))
    }

    fn table<'a>(inner: &'a mut Inner, name: &str) -> Result<&'a mut Table> {
        if !inner.tables.contains_key(name) {
            if !valid_table(name) {
                return Err(denied(400, "Bad table name"));
            }
            let mut t = Table::default();
            let mut stmt = inner.db.prepare("SELECT id, seq, data FROM records WHERE entity = ? ORDER BY seq").map_err(|e| denied(500, e.to_string()))?;
            let rows = stmt.query_map([name], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?))).map_err(|e| denied(500, e.to_string()))?;
            for row in rows {
                let (id, seq, data) = row.map_err(|e| denied(500, e.to_string()))?;
                t.rows.insert(id.clone(), serde_json::from_str(&data).unwrap_or(Value::Null));
                t.seqs.insert(id, seq);
            }
            drop(stmt);
            inner.tables.insert(name.to_string(), t);
        }
        Ok(inner.tables.get_mut(name).unwrap())
    }

    fn ensure_index(t: &mut Table, field: &str) {
        if !t.indexes.contains_key(field) {
            let mut idx = IndexMap::new();
            for (id, row) in &t.rows {
                index_add(&mut idx, field, id, row);
            }
            t.indexes.insert(field.to_string(), idx);
        }
    }

    fn write(&self, inner: &mut Inner, name: &str, id: &str, row: Value) -> Result<()> {
        let mut seq = inner.seq;
        let t = Self::table(inner, name)?;
        let old = t.rows.get(id).cloned();
        if let Some(o) = &old {
            for (field, idx) in t.indexes.iter_mut() {
                index_remove(idx, field, id, o);
            }
        }
        if !t.seqs.contains_key(id) {
            seq += 1;
            t.seqs.insert(id.to_string(), seq);
        }
        let s = t.seqs[id];
        for (field, idx) in t.indexes.iter_mut() {
            index_add(idx, field, id, &row);
        }
        t.rows.insert(id.to_string(), row.clone());
        inner.seq = seq;
        inner.db.execute("INSERT INTO records (entity, id, seq, data) VALUES (?, ?, ?, ?) ON CONFLICT(entity, id) DO UPDATE SET data = excluded.data", params![name, id, s, row.to_string()]).map_err(|e| denied(500, e.to_string()))?;
        if let Some(hook) = &self.on_write {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook(name, &row, old.as_ref())));
        }
        Ok(())
    }

    fn remove(&self, inner: &mut Inner, name: &str, id: &str) -> Result<bool> {
        let t = Self::table(inner, name)?;
        let Some(old) = t.rows.shift_remove(id) else { return Ok(false) };
        for (field, idx) in t.indexes.iter_mut() {
            index_remove(idx, field, id, &old);
        }
        t.seqs.remove(id);
        inner.db.execute("DELETE FROM records WHERE entity = ? AND id = ?", params![name, id]).map_err(|e| denied(500, e.to_string()))?;
        if let Some(hook) = &self.on_remove {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook(name, id, &old)));
        }
        Ok(true)
    }

    /// Every matching row (ids), using an index where the query allows.
    fn find(t: &mut Table, query: &Value) -> Result<Vec<String>> {
        let mut conds = Vec::new();
        indexable(query, &mut conds);
        let mut candidates: Option<IndexSet<String>> = None;
        for (field, values) in conds {
            Self::ensure_index(t, &field);
            let idx = &t.indexes[&field];
            let mut ids = IndexSet::new();
            for v in &values {
                if let Some(set) = key_of(v).and_then(|k| idx.get(&k)) {
                    ids.extend(set.iter().cloned());
                }
            }
            if candidates.as_ref().is_none_or(|c| ids.len() < c.len()) {
                candidates = Some(ids);
            }
            if candidates.as_ref().is_some_and(IndexSet::is_empty) {
                break;
            }
        }
        let ids: Vec<String> = match candidates {
            Some(c) => c.into_iter().collect(),
            None => t.rows.keys().cloned().collect(),
        };
        let mut out = Vec::new();
        for id in ids {
            if let Some(row) = t.rows.get(&id) {
                if matches(row, query)? {
                    out.push(id);
                }
            }
        }
        Ok(out)
    }

    // ---------- the entity API (service role) ----------

    /// `sort` is the JavaScript argument: `None` is `undefined` (newest first); like the Node store,
    /// any other falsy value sorts by `created_date`, oldest first.
    pub fn filter(&self, name: &str, query: &Value, sort: Option<&Value>, limit: Option<f64>, skip: Option<f64>) -> Result<Vec<Value>> {
        let mut inner = self.inner.lock().unwrap();
        let t = Self::table(&mut inner, name)?;
        let default = Value::String("-created_date".into());
        let sort = sort.unwrap_or(&default);
        let field_text = if js::truthy(Some(sort)) { js::to_js_string(Some(sort)) } else { "-created_date".into() };
        let field = if field_text.starts_with('-') || field_text.starts_with('+') { &field_text[1..] } else { &field_text[..] };
        let dir = if js::truthy(Some(sort)) && js::to_js_string(Some(sort)).starts_with('-') { -1 } else { 1 };
        let mut found = Self::find(t, query)?;
        // `dir * compare(a[field], b[field]) || seqA - seqB` (see timsort.rs on mixed types).
        crate::timsort::sort(&mut found, |a, b| {
            let c = match js::compare(t.rows[a].get(field), t.rows[b].get(field)) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            } * dir;
            if c != 0 { c } else { t.seqs[a] - t.seqs[b] }
        });
        let start = skip.filter(|s| s.is_finite() && *s > 0.0).map_or(0, |s| s as usize);
        let lim = match limit {
            Some(l) if l.is_finite() && l != 0.0 => l.clamp(0.0, 5000.0) as usize,
            _ => 5000,
        };
        Ok(found.into_iter().skip(start).take(lim).map(|id| t.rows[&id].clone()).collect())
    }

    pub fn get(&self, name: &str, id: &str) -> Result<Value> {
        let mut inner = self.inner.lock().unwrap();
        Self::table(&mut inner, name)?.rows.get(id).cloned().ok_or_else(|| denied(404, "Not found"))
    }

    pub fn create(&self, name: &str, data: &Value, fixed_id: Option<&str>) -> Result<Value> {
        let mut inner = self.inner.lock().unwrap();
        let at = Self::tick(&mut inner);
        let taken = Self::table(&mut inner, name)?.rows.contains_key(fixed_id.unwrap_or(""));
        if let Some(f) = fixed_id {
            if !valid_fixed_id(f) || taken {
                return Err(denied(409, "That id is taken"));
            }
        }
        let id = fixed_id.map(str::to_string).unwrap_or_else(Self::new_id);
        let mut row = data.as_object().cloned().unwrap_or_default();
        row.insert("id".into(), json!(id));
        row.insert("created_date".into(), json!(at));
        row.insert("updated_date".into(), json!(at));
        let row = Value::Object(row);
        self.write(&mut inner, name, &id, row.clone())?;
        Ok(row)
    }

    pub fn update(&self, name: &str, id: &str, data: &Value) -> Result<Value> {
        let mut inner = self.inner.lock().unwrap();
        let row = Self::table(&mut inner, name)?.rows.get(id).cloned().ok_or_else(|| denied(404, "Not found"))?;
        let at = Self::tick(&mut inner);
        let mut next = merge(&row, data);
        next["id"] = row["id"].clone();
        next["created_date"] = row.get("created_date").cloned().unwrap_or(Value::Null);
        next["updated_date"] = json!(at);
        self.write(&mut inner, name, id, next.clone())?;
        Ok(next)
    }

    pub fn update_many(&self, name: &str, query: &Value, ops: &Value) -> Result<Value> {
        let set = ops.get("$set").filter(|_| ops.as_object().is_some_and(|o| o.len() == 1)).ok_or_else(|| denied(400, "updateMany supports $set only"))?;
        let mut inner = self.inner.lock().unwrap();
        let ids = Self::find(Self::table(&mut inner, name)?, query)?;
        let mut n = 0;
        for id in ids {
            let row = Self::table(&mut inner, name)?.rows[&id].clone();
            let mut next = merge(&row, set);
            next["updated_date"] = json!(Self::tick(&mut inner));
            self.write(&mut inner, name, &id, next)?;
            n += 1;
        }
        Ok(json!({ "modifiedCount": n }))
    }

    pub fn delete(&self, name: &str, id: &str) -> Result<Value> {
        let mut inner = self.inner.lock().unwrap();
        self.remove(&mut inner, name, id)?;
        Ok(json!({ "ok": true }))
    }

    pub fn delete_many(&self, name: &str, query: &Value) -> Result<Value> {
        let mut inner = self.inner.lock().unwrap();
        let ids = Self::find(Self::table(&mut inner, name)?, query)?;
        let mut n = 0;
        for id in ids {
            if self.remove(&mut inner, name, &id)? {
                n += 1;
            }
        }
        Ok(json!({ "deletedCount": n }))
    }

    /// The table a row with this id is in, if any.
    pub fn table_of(&self, id: &str) -> Option<String> {
        let mut inner = self.inner.lock().unwrap();
        for name in self.schemas.keys() {
            if Self::table(&mut inner, name).ok()?.rows.contains_key(id) {
                return Some(name.clone());
            }
        }
        None
    }

    pub fn has(&self, id: &str) -> bool {
        self.table_of(id).is_some()
    }

    // ---------- as a person (row rules) ----------

    fn user_data(&self, user: Option<&Person>) -> impl Fn(&str) -> Option<Value> + '_ {
        let row = user.and_then(|u| self.get("Person", &u.id).ok().or_else(|| self.get("User", &u.id).ok()));
        move |field: &str| row.as_ref().and_then(|r| r.get(field).cloned())
    }

    fn rule(&self, name: &str, op: &str, user: Option<&Person>) -> Result<Option<Value>> {
        let Some(schema) = self.schemas.get(name) else { return Ok(None) };
        let ud = self.user_data(user);
        rule_to_query(schema.get("rls").and_then(|r| r.get(op)), user, &ud)
    }

    pub fn person_filter(&self, user: Option<&Person>, name: &str, query: &Value, sort: Option<&Value>, limit: Option<f64>, skip: Option<f64>) -> Result<Vec<Value>> {
        let Some(allowed) = self.rule(name, "read", user)? else { return Ok(vec![]) };
        let q = if allowed.as_object().is_some_and(|o| !o.is_empty()) { json!({ "$and": [query, allowed] }) } else { query.clone() };
        self.filter(name, &q, sort, limit, skip)
    }

    pub fn person_get(&self, user: Option<&Person>, name: &str, id: &str) -> Result<Value> {
        let allowed = self.rule(name, "read", user)?;
        let row = self.get(name, id)?;
        match allowed {
            Some(q) if matches(&row, &q)? => Ok(row),
            _ => Err(denied(404, "Not found")),
        }
    }

    pub fn person_create(&self, user: Option<&Person>, name: &str, data: &Value) -> Result<Value> {
        self.rule(name, "create", user)?.ok_or_else(|| denied(403, "Permission denied"))?;
        self.create(name, data, None)
    }

    pub fn person_update(&self, user: Option<&Person>, name: &str, id: &str, data: &Value) -> Result<Value> {
        let q = self.rule(name, "update", user)?.ok_or_else(|| denied(403, "Permission denied"))?;
        let row = self.get(name, id)?;
        if !matches(&row, &q)? {
            return Err(denied(403, "Permission denied"));
        }
        self.update(name, id, data)
    }

    pub fn person_delete(&self, user: Option<&Person>, name: &str, id: &str) -> Result<Value> {
        let q = self.rule(name, "delete", user)?.ok_or_else(|| denied(403, "Permission denied"))?;
        if let Ok(row) = self.get(name, id) {
            if !matches(&row, &q)? {
                return Err(denied(403, "Permission denied"));
            }
        }
        self.delete(name, id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        let mut schemas = BTreeMap::new();
        schemas.insert("Note".to_string(), json!({ "name": "Note", "rls": { "read": { "$or": [{ "data.owner": "{{user.id}}" }, { "data.public": true }] }, "create": { "user_condition": { "role": "admin" } }, "update": { "data.owner": "{{user.id}}" }, "delete": false } }));
        schemas.insert("Person".to_string(), json!({ "name": "Person", "rls": {} }));
        Store::open(":memory:", schemas).unwrap()
    }
    fn who(id: &str, role: &str) -> Person {
        let mut record = Map::new();
        record.insert("role".into(), json!(role));
        Person { id: id.into(), email: String::new(), record }
    }

    #[test]
    fn create_filter_sort_update_delete() {
        let s = store();
        let a = s.create("Note", &json!({ "n": 2, "owner": "u1", "tags": ["x", "y"] }), None).unwrap();
        let b = s.create("Note", &json!({ "n": 10, "owner": "u2", "public": true }), None).unwrap();
        s.create("Note", &json!({ "owner": "u1" }), None).unwrap();
        assert_eq!(a["id"].as_str().unwrap().len(), 24);
        assert!(a["created_date"].as_str().unwrap() < b["created_date"].as_str().unwrap(), "times never go backwards");
        let by_n = s.filter("Note", &json!({}), Some(&json!("n")), None, None).unwrap();
        assert_eq!(by_n.iter().map(|r| r["n"].clone()).collect::<Vec<_>>(), vec![json!(2), json!(10), Value::Null], "missing values sort last");
        assert_eq!(s.filter("Note", &json!({ "tags": "x" }), None, None, None).unwrap().len(), 1, "a scalar matches inside an array");
        assert_eq!(s.filter("Note", &json!({ "owner": { "$in": ["u1"] }, "n": { "$gte": 1 } }), None, None, None).unwrap().len(), 1);
        assert_eq!(s.filter("Note", &json!({ "n": { "$exists": false } }), None, None, None).unwrap().len(), 1);
        assert_eq!(s.filter("Note", &json!({ "$or": [{ "n": 10 }, { "tags": { "$in": ["y"] } }] }), Some(&json!("-n")), None, None).unwrap()[0]["n"], 10);
        let up = s.update("Note", a["id"].as_str().unwrap(), &json!({ "n": 3, "id": "forged" })).unwrap();
        assert_eq!((up["id"].clone(), up["created_date"].clone(), up["n"].clone()), (a["id"].clone(), a["created_date"].clone(), json!(3)));
        assert_eq!(s.update_many("Note", &json!({ "owner": "u1" }), &json!({ "$set": { "seen": true } })).unwrap()["modifiedCount"], 2);
        assert_eq!(s.delete_many("Note", &json!({ "seen": true })).unwrap()["deletedCount"], 2);
        assert_eq!(s.get("Note", "nope").unwrap_err().status, 404);
        assert_eq!(s.filter("Note", &json!({ "n": { "$regex": "x" } }), None, None, None).unwrap_err().status, 400);
        assert_eq!(s.create("Note", &json!({}), Some(b["id"].as_str().unwrap())).unwrap_err().status, 409);
    }

    #[test]
    fn row_rules_apply_to_people_not_the_service_role() {
        let s = store();
        let mine = s.create("Note", &json!({ "owner": "u1" }), None).unwrap();
        s.create("Note", &json!({ "owner": "u2" }), None).unwrap();
        s.create("Note", &json!({ "owner": "u2", "public": true }), None).unwrap();
        let u1 = who("u1", "user");
        assert_eq!(s.person_filter(Some(&u1), "Note", &json!({}), None, None, None).unwrap().len(), 2, "their own and the public one");
        assert_eq!(s.person_filter(None, "Note", &json!({}), None, None, None).unwrap().len(), 1, "anonymous: public only");
        assert_eq!(s.person_create(Some(&u1), "Note", &json!({})).unwrap_err().status, 403);
        assert!(s.person_create(Some(&who("u9", "admin")), "Note", &json!({})).is_ok());
        assert!(s.person_update(Some(&u1), "Note", mine["id"].as_str().unwrap(), &json!({ "x": 1 })).is_ok());
        assert_eq!(s.person_update(Some(&who("u2", "user")), "Note", mine["id"].as_str().unwrap(), &json!({ "x": 1 })).unwrap_err().status, 403);
        assert_eq!(s.person_delete(Some(&u1), "Note", mine["id"].as_str().unwrap()).unwrap_err().status, 403);
        assert_eq!(s.person_get(Some(&who("u3", "user")), "Note", mine["id"].as_str().unwrap()).unwrap_err().status, 404);
        assert!(s.person_filter(Some(&u1), "Unknown", &json!({}), None, None, None).unwrap().is_empty());
    }

    #[test]
    fn data_survives_reopening_and_settings_persist() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("commonveil.db");
        let schemas = store().schemas;
        {
            let s = Store::open(file.to_str().unwrap(), schemas.clone()).unwrap();
            s.create("Note", &json!({ "owner": "u1", "n": 1 }), None).unwrap();
            s.set_setting("k", Some(&json!({ "a": 1 })));
        }
        let s = Store::open(file.to_str().unwrap(), schemas).unwrap();
        assert_eq!(s.filter("Note", &json!({}), None, None, None).unwrap()[0]["n"], 1);
        assert_eq!(s.get_setting("k"), Some(json!({ "a": 1 })));
        s.set_setting("k", None);
        assert_eq!(s.get_setting("k"), None);
    }

    #[test]
    fn iso_times_match_javascript() {
        assert_eq!(iso(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso(1_800_000_000_123), "2027-01-15T08:00:00.123Z");
        assert_eq!(iso(951_782_400_000), "2000-02-29T00:00:00.000Z");
    }
}
