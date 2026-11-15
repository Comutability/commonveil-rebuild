//! The Rust server against the Node.js one it replaces, while both exist. Needs `node` (22+) and
//! the repository's npm packages; skipped when node isn't found.
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use commonveil_server::store::{load_schemas, Person, Store};
use serde_json::{json, Map, Value};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}
fn node_ok() -> bool {
    Command::new("node").arg("--version").output().is_ok_and(|o| o.status.success())
}

/// A small deterministic generator, so a failure can be replayed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[(self.next() as usize) % xs.len()]
    }
    fn chance(&mut self, n: u64) -> bool {
        self.next().is_multiple_of(n)
    }
}

fn workload(seed: u64) -> Vec<Value> {
    let mut r = Rng(seed);
    let values = [json!(1), json!(2.5), json!("3"), json!("abc"), json!("Zoë"), json!(null), json!(true), json!(false), json!(0), json!(-4), json!([1, "abc"]), json!("10"), json!("2")];
    let users = ["u1", "u2", "u3"];
    let audiences = ["a1", "a2", "a3"];
    let tables = ["Message", "Channel", "Resource", "Profile"];
    let mut ops = Vec::new();
    let mut ids: Vec<(String, String)> = Vec::new();
    // People, whose cv_access the Channel rule reads.
    for (i, u) in users.iter().enumerate() {
        ops.push(json!({ "op": "create", "table": "Person", "id": format!("{u}-person-id"), "data": { "cv_access": audiences[..=i].to_vec() } }));
    }
    let as_person = |r: &mut Rng| {
        let u = *r.pick(&users);
        json!({ "id": format!("{u}-person-id"), "email": format!("{u}@x"), "role": if r.chance(3) { "admin" } else { "user" } })
    };
    for i in 0..1000 {
        let table = *r.pick(&tables);
        let field = *r.pick(&["n", "name", "status", "audience_id", "user_id", "recipient_ids", "missing"]);
        let v = r.pick(&values).clone();
        let op = r.next() % 10;
        let mut row = Map::new();
        let o = match op {
            0..=3 => {
                row.insert("n".into(), r.pick(&values).clone());
                row.insert("name".into(), r.pick(&[json!("b"), json!("A"), json!("a"), json!("é"), json!("10"), json!(9)]).clone());
                row.insert("status".into(), json!(r.pick(&["published", "draft"])));
                row.insert("audience_id".into(), json!(r.pick(&audiences)));
                row.insert("user_id".into(), json!(format!("{}-person-id", r.pick(&users))));
                row.insert("recipient_ids".into(), json!([format!("{}-person-id", r.pick(&users)), format!("{}-person-id", r.pick(&users))]));
                if r.chance(4) {
                    row.remove("n");
                }
                // Sorted fields hold one type each, as real fields do: JavaScript leaves the order
                // of mixed types up to the engine (Node 22 and 26 differ), so it isn't compared.
                match r.next() % 4 {
                    0 => {}
                    1 => {
                        row.insert("rank".into(), json!(null));
                    }
                    _ => {
                        row.insert("rank".into(), json!((r.next() % 7) as i64 - 3));
                    }
                }
                if !r.chance(5) {
                    row.insert("label".into(), json!(r.pick(&["b", "A", "a", "é", "10", "9", "Zoë", ""])));
                }
                let id = format!("id{i:06}x{}", r.next() % 1000);
                ids.push((table.to_string(), id.clone()));
                json!({ "op": "create", "table": table, "id": id, "data": row })
            }
            4..=6 => {
                let query = match r.next() % 9 {
                    0 => json!({ field: v }),
                    1 => json!({ field: { "$in": [v, r.pick(&values).clone()] } }),
                    2 => json!({ field: { r.pick(&["$gte", "$gt", "$lte", "$lt"]).to_string(): v } }),
                    3 => json!({ field: { "$ne": v } }),
                    4 => json!({ field: { "$exists": r.chance(2) } }),
                    5 => json!({ "$or": [{ field: v }, { "status": "draft" }] }),
                    6 => json!({ "$and": [{ "audience_id": { "$in": ["a1", "a2"] } }, { field: { "$nin": [v] } }] }),
                    7 => json!({ field: [v, "a"] }),
                    _ => json!({}),
                };
                let sort = r.pick(&[json!(null), json!("rank"), json!("-rank"), json!("label"), json!("-label"), json!("+status"), json!("-created_date"), json!("missing")]).clone();
                let limit = r.pick(&[json!(null), json!(3), json!(0), json!(-1), json!(10000)]).clone();
                let skip = r.pick(&[json!(null), json!(1), json!(2.7)]).clone();
                let mut o = json!({ "op": "filter", "table": table, "query": query, "sort": sort, "limit": limit, "skip": skip });
                if r.chance(2) {
                    o["as"] = as_person(&mut r);
                }
                o
            }
            7 => match ids.get((r.next() as usize) % ids.len().max(1)) {
                Some((t, id)) => {
                    let mut o = json!({ "op": r.pick(&["get", "update", "delete"]).to_string(), "table": t, "id": id, "data": { field: v } });
                    if r.chance(3) {
                        o["as"] = as_person(&mut r);
                    }
                    o
                }
                None => json!({ "op": "get", "table": table, "id": "nothing-here" }),
            },
            8 => json!({ "op": "updateMany", "table": table, "query": { field: v }, "ops": { "$set": { "touched": i } } }),
            _ => {
                if r.chance(4) {
                    json!({ "op": "deleteMany", "table": table, "query": { "n": v } })
                } else {
                    let mut o = json!({ "op": "create", "table": table, "data": { "n": v } });
                    o["as"] = as_person(&mut r);
                    o
                }
            }
        };
        ops.push(o);
    }
    ops
}

fn person(v: &Value) -> Person {
    Person { id: v["id"].as_str().unwrap().into(), email: v["email"].as_str().unwrap().into(), record: v.as_object().unwrap().clone() }
}
fn num(v: &Value) -> Option<f64> {
    if v.is_null() { None } else { Some(commonveil_server::js::to_number(Some(v))) }
}

fn run_rust(ops: &[Value]) -> Vec<Value> {
    let store = Store::open(":memory:", load_schemas(&repo().join("base44/entities"))).unwrap();
    ops.iter()
        .map(|o| {
            let (t, as_) = (o["table"].as_str().unwrap(), o.get("as").map(person));
            let id = o["id"].as_str().unwrap_or("");
            let r = match (o["op"].as_str().unwrap(), &as_) {
                ("create", Some(p)) => store.person_create(Some(p), t, &o["data"]),
                ("create", None) => store.create(t, &o["data"], o["id"].as_str()),
                ("filter", Some(p)) => store.person_filter(Some(p), t, &o["query"], o.get("sort"), num(&o["limit"]), num(&o["skip"])).map(Value::from),
                ("filter", None) => store.filter(t, &o["query"], o.get("sort"), num(&o["limit"]), num(&o["skip"])).map(Value::from),
                ("get", Some(p)) => store.person_get(Some(p), t, id),
                ("get", None) => store.get(t, id),
                ("update", Some(p)) => store.person_update(Some(p), t, id, &o["data"]),
                ("update", None) => store.update(t, id, &o["data"]),
                ("delete", Some(p)) => store.person_delete(Some(p), t, id),
                ("delete", None) => store.delete(t, id),
                ("updateMany", _) => store.update_many(t, &o["query"], &o["ops"]),
                ("deleteMany", _) => store.delete_many(t, &o["query"]),
                (op, _) => panic!("{op}"),
            };
            match r {
                Ok(v) => json!({ "ok": v }),
                Err(e) => json!({ "error": e.status }),
            }
        })
        .collect()
}

fn run_node(ops: &[Value]) -> Vec<Value> {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/node/store-ops.mjs");
    let mut child = Command::new("node").arg(script).arg(repo().join("base44/entities")).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(Value::from(ops.to_vec()).to_string().as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "the Node store failed");
    serde_json::from_slice(&out.stdout).unwrap()
}

/// Times differ between the two runs; ids and everything else must not.
fn strip(v: &mut Value) {
    match v {
        Value::Object(m) => {
            m.remove("created_date");
            m.remove("updated_date");
            // Ids the store makes itself are random on both sides.
            if m.get("id").and_then(Value::as_str).is_some_and(|i| i.len() == 24 && i.bytes().all(|c| c.is_ascii_hexdigit())) {
                m.insert("id".into(), json!("<made>"));
            }
            m.values_mut().for_each(strip);
        }
        Value::Array(a) => a.iter_mut().for_each(strip),
        _ => {}
    }
}

#[test]
fn the_store_answers_every_operation_as_the_node_store_does() {
    if !node_ok() {
        eprintln!("skipped: node not found");
        return;
    }
    for seed in [1, 2, 3, 42] {
        let ops = workload(seed);
        if let Ok(f) = std::env::var("CV_PARITY_DUMP") {
            std::fs::write(format!("{f}-{seed}.json"), Value::from(ops.clone()).to_string()).unwrap();
        }
        let (mut a, mut b) = (run_rust(&ops), run_node(&ops));
        a.iter_mut().chain(b.iter_mut()).for_each(strip);
        assert_eq!(a.len(), b.len());
        let mut nonempty = 0;
        for (i, (x, y)) in a.iter().zip(&b).enumerate() {
            assert_eq!(x, y, "seed {seed}, operation {i}: {}", ops[i]);
            if x["ok"].as_array().is_some_and(|l| !l.is_empty()) {
                nonempty += 1;
            }
        }
        assert!(nonempty > 60, "the workload should find things ({nonempty})");
    }
}

// ---------- The two servers over HTTP ----------

struct Server(std::process::Child, u16);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn start(node: bool, dist: &Path, data: &Path) -> Server {
    let port = free_port();
    let mut cmd = if node {
        let mut c = Command::new("node");
        c.arg(repo().join("server/index.mjs"));
        c
    } else {
        Command::new(env!("CARGO_BIN_EXE_commonveil-server"))
    };
    cmd.env("PORT", port.to_string()).env("BIND", "127.0.0.1").env("DATA_DIR", data).env("DIST_DIR", dist).env("SITE_URL", "https://cv.example").env("UPDATE_CHECK_HOURS", "1000").env("FEDERATION", "off").env("COMMONVEIL_VERSION", "9.9.9").env("ENTITIES_DIR", repo().join("base44/entities"));
    let server = Server(cmd.stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap(), port);
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return server;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    drop(server);
    panic!("{} server didn't start", if node { "Node" } else { "Rust" });
}

/// (status, headers lower-cased, body)
fn request(port: u16, method: &str, path: &str) -> (u16, Map<String, Value>, Vec<u8>) {
    use std::io::Read;
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(s, "{method} {path} HTTP/1.1\r\nHost: cv.example\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut body = raw[split + 4..].to_vec();
    let mut lines = head.lines();
    let status: u16 = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
    let mut headers = Map::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers.insert(k.trim().to_lowercase(), json!(v.trim()));
        }
    }
    if headers.get("transfer-encoding").is_some_and(|v| v == "chunked") {
        let (mut out, mut i) = (Vec::new(), 0);
        while let Some(end) = body[i..].windows(2).position(|w| w == b"\r\n") {
            let size = usize::from_str_radix(String::from_utf8_lossy(&body[i..i + end]).trim(), 16).unwrap_or(0);
            if size == 0 {
                break;
            }
            let start = i + end + 2;
            out.extend_from_slice(&body[start..start + size]);
            i = start + size + 2;
        }
        body = out;
    }
    (status, headers, body)
}

#[test]
fn the_site_and_its_pages_are_served_as_the_node_server_serves_them() {
    if !node_ok() || !repo().join("node_modules").exists() {
        eprintln!("skipped: node or the npm packages aren't there");
        return;
    }
    let dist = repo().join("dist-selfhost");
    if !dist.join("index.html").exists() {
        eprintln!("skipped: build the self-hosted site first (dist-selfhost)");
        return;
    }
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (node, rust) = (start(true, &dist, d1.path()), start(false, &dist, d2.path()));
    let asset = std::fs::read_dir(dist.join("assets")).unwrap().next().unwrap().unwrap().file_name().into_string().unwrap();
    let paths = [
        "/", "/help", "/help/", "/help/guide", "/help/welcome", "/help/no-such-article", "/security/report", "/privacy?x=1", "/releases",
        "/app", "/app/settings", "/admin", "/invite/abc123", "/u/someone", "/reset-password", "/blog", "/blog/a-post", "/wiki/x/y", "/saved",
        "/no-such-page", "/assets/missing.js", "/missing.png", "/sitemap.xml", "/robots.txt", "/manifest.webmanifest", "/sw.js", "/favicon.svg",
        &format!("/assets/{asset}"), "/%E0%A4%A", "/..%2f..%2fetc%2fpasswd", "/%2e%2e/%2e%2e/etc/passwd", "/api/health", "/api/site", "/api/nope",
    ];
    let compared = ["content-type", "cache-control", "content-security-policy", "x-frame-options", "x-robots-tag", "location", "x-content-type-options", "referrer-policy", "cross-origin-opener-policy", "cross-origin-resource-policy", "permissions-policy"];
    for (method, path) in paths.iter().map(|p| ("GET", *p)).chain([("HEAD", "/"), ("HEAD", "/help/welcome"), ("POST", "/"), ("PUT", "/help")]) {
        let (a, b) = (request(node.1, method, path), request(rust.1, method, path));
        assert_eq!(a.0, b.0, "{method} {path}: status");
        for h in compared {
            assert_eq!(a.1.get(h), b.1.get(h), "{method} {path}: {h}");
        }
        if path == "/help/welcome" && method == "GET" {
            assert!(String::from_utf8_lossy(&a.2).contains("og:title"), "control: the page really has its tags");
        }
        assert!(a.2 == b.2, "{method} {path}: body differs\nnode: {}\nrust: {}", String::from_utf8_lossy(&a.2[..a.2.len().min(400)]), String::from_utf8_lossy(&b.2[..b.2.len().min(400)]));
    }
}
