// The self-hosted data store: every table in base44/entities, kept in SQLite on disk and in
// memory for queries, with the same query language and row rules the backend relies on when
// it runs on Base44. Records are JSON; the store never looks inside except to answer queries.
//
// Reads made as a signed-in person (not the service role) follow each table's "rls" rules from
// its schema file, as Base44 applies them. Writes as a person are allowed only where a rule
// allows them (today: admins editing Resources); the backend writes as the service role.
import fs from "node:fs";
import crypto from "node:crypto";
import { DatabaseSync } from "node:sqlite";

const clone = (v) => (v === undefined ? v : structuredClone(v));
const denied = (status, message) => Object.assign(new Error(message), { status });

/** Strip comments from a .jsonc file. */
export const parseJsonc = (text) => JSON.parse(text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, ""));

export function loadSchemas(dir) {
  const out = {};
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith(".jsonc"))) {
    const s = parseJsonc(fs.readFileSync(new URL(f, dir), "utf8"));
    out[s.name] = s;
  }
  return out;
}

// ---------- queries ----------

const refersToUser = (rule) => JSON.stringify(rule ?? null).includes("{{user") || JSON.stringify(rule ?? null).includes("user_condition");

/**
 * A row rule as a query for this person: {} matches everything, null nothing. Supports the
 * rule shapes Base44 documents and this app uses: data.<field> equality, { $in: "{{user.data.x}}" },
 * user_condition, $or and $and.
 */
export function ruleToQuery(rule, user, userData = () => undefined) {
  if (rule === true) return {};
  if (rule === false || rule === undefined || rule === null) return null;
  const resolve = (value) => {
    if (value === "{{user.id}}") return user?.id;
    if (value === "{{user.email}}") return user?.email;
    const m = typeof value === "string" ? /^\{\{user\.data\.([a-z_]+)\}\}$/.exec(value) : null;
    if (m) return userData(m[1]);
    if (typeof value === "string" && value.includes("{{")) throw new Error(`Unsupported rule value ${value}`);
    return value;
  };
  const parts = [];
  for (const [key, value] of Object.entries(rule)) {
    if (key === "$or") {
      const subs = value.map((r) => ruleToQuery(r, user, userData));
      if (subs.some((s) => s && !Object.keys(s).length)) return {};
      const live = subs.filter(Boolean);
      if (!live.length) return null;
      parts.push({ $or: live });
    } else if (key === "$and") {
      const subs = value.map((r) => ruleToQuery(r, user, userData));
      if (subs.some((s) => s === null)) return null;
      parts.push(...subs);
    } else if (key === "user_condition") {
      if (!user) return null;
      for (const [field, expected] of Object.entries(value)) if (user[field] !== expected) return null;
    } else if (key.startsWith("data.")) {
      if (!user && refersToUser(value)) return null;
      if (value && typeof value === "object" && !Array.isArray(value)) {
        if (Object.keys(value).length !== 1 || !("$in" in value)) throw new Error("Only $in rules are supported");
        const list = resolve(value.$in);
        parts.push({ [key.slice(5)]: { $in: Array.isArray(list) ? list : [] } });
      } else {
        const v = resolve(value);
        if (v === undefined) return null;
        parts.push({ [key.slice(5)]: v });
      }
    } else {
      throw new Error(`Unsupported rule key ${key}`);
    }
  }
  return parts.length ? { $and: parts } : {};
}

function compare(a, b) {
  if (a === b) return 0;
  if (a === undefined || a === null) return 1;
  if (b === undefined || b === null) return -1;
  return a < b ? -1 : 1;
}

export function matches(record, query) {
  for (const [key, cond] of Object.entries(query || {})) {
    if (key === "$or") {
      if (!cond.some((sub) => matches(record, sub))) return false;
      continue;
    }
    if (key === "$and") {
      if (!cond.every((sub) => matches(record, sub))) return false;
      continue;
    }
    const value = record[key];
    const values = Array.isArray(value) ? value : [value];
    if (cond !== null && typeof cond === "object" && !Array.isArray(cond)) {
      for (const [op, arg] of Object.entries(cond)) {
        if (op === "$in") { if (!Array.isArray(arg) || !values.some((v) => arg.includes(v))) return false; }
        else if (op === "$nin") { if (Array.isArray(arg) && values.some((v) => arg.includes(v))) return false; }
        else if (op === "$gte") { if (!(value >= arg)) return false; }
        else if (op === "$gt") { if (!(value > arg)) return false; }
        else if (op === "$lte") { if (!(value <= arg)) return false; }
        else if (op === "$lt") { if (!(value < arg)) return false; }
        else if (op === "$ne") { if (value === arg) return false; }
        else if (op === "$exists") { if ((value !== undefined && value !== null) !== Boolean(arg)) return false; }
        else throw denied(400, `Unsupported query operator ${op}`);
      }
    } else if (Array.isArray(cond)) {
      if (!values.some((v) => cond.includes(v))) return false;
    } else if (cond === null) {
      if (value !== null && value !== undefined) return false;
    } else if (Array.isArray(value) ? !value.includes(cond) : value !== cond) {
      return false;
    }
  }
  return true;
}

const SCALAR = (v) => typeof v === "string" || typeof v === "number" || typeof v === "boolean";

/** Top-level conditions an index can answer: field -> list of values that may match. */
function indexable(query, out = []) {
  for (const [key, cond] of Object.entries(query || {})) {
    if (key === "$and") { for (const sub of cond) indexable(sub, out); continue; }
    if (key.startsWith("$")) continue;
    if (SCALAR(cond)) out.push([key, [cond]]);
    else if (cond && typeof cond === "object" && !Array.isArray(cond) && Array.isArray(cond.$in) && Object.keys(cond).length === 1 && cond.$in.every(SCALAR)) out.push([key, cond.$in]);
  }
  return out;
}

// ---------- the store ----------

export class Store {
  /** file: the SQLite database path (":memory:" for tests). schemas: from loadSchemas(). */
  constructor({ file, schemas }) {
    this.schemas = schemas;
    this.db = new DatabaseSync(file);
    this.db.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;");
    this.db.exec(`CREATE TABLE IF NOT EXISTS records (entity TEXT NOT NULL, id TEXT NOT NULL, seq INTEGER NOT NULL, data TEXT NOT NULL, PRIMARY KEY (entity, id))`);
    this.db.exec(`CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)`);
    this.q = {
      load: this.db.prepare("SELECT id, seq, data FROM records WHERE entity = ? ORDER BY seq"),
      put: this.db.prepare("INSERT INTO records (entity, id, seq, data) VALUES (?, ?, ?, ?) ON CONFLICT(entity, id) DO UPDATE SET data = excluded.data"),
      del: this.db.prepare("DELETE FROM records WHERE entity = ? AND id = ?"),
      maxSeq: this.db.prepare("SELECT COALESCE(MAX(seq), 0) AS s FROM records"),
      kvGet: this.db.prepare("SELECT v FROM kv WHERE k = ?"),
      kvPut: this.db.prepare("INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v"),
      kvDel: this.db.prepare("DELETE FROM kv WHERE k = ?"),
    };
    this.seq = Number(this.q.maxSeq.get().s) || 0;
    this.tables = new Map();
    this.micros = 0;
    this.entities = new Proxy({}, { get: (_t, name) => (typeof name === "string" ? this.#entityApi(name) : undefined) });
  }

  close() {
    this.db.close();
  }

  /** Small settings the server keeps for itself (not entities). */
  getSetting(k, fallback = null) {
    const row = this.q.kvGet.get(k);
    return row ? JSON.parse(row.v) : fallback;
  }

  setSetting(k, v) {
    if (v === undefined || v === null) this.q.kvDel.run(k);
    else this.q.kvPut.run(k, JSON.stringify(v));
  }

  /** Record times, like Base44's: microseconds, never going backwards. */
  tick() {
    this.micros = Math.max(this.micros + 1, Date.now() * 1000);
    return new Date(Math.floor(this.micros / 1000)).toISOString().replace("Z", String(this.micros % 1000).padStart(3, "0"));
  }

  newId() {
    return Math.floor(Date.now() / 1000).toString(16).padStart(8, "0") + crypto.randomBytes(8).toString("hex");
  }

  #table(name) {
    let t = this.tables.get(name);
    if (t) return t;
    if (!/^[A-Za-z][A-Za-z0-9_]{0,62}$/.test(name)) throw denied(400, "Bad table name");
    t = { rows: new Map(), seqs: new Map(), indexes: new Map() };
    for (const r of this.q.load.all(name)) {
      t.rows.set(r.id, JSON.parse(r.data));
      t.seqs.set(r.id, Number(r.seq));
    }
    this.tables.set(name, t);
    return t;
  }

  #index(t, field) {
    let idx = t.indexes.get(field);
    if (idx) return idx;
    idx = new Map();
    for (const [id, row] of t.rows) this.#indexAdd(idx, field, id, row);
    t.indexes.set(field, idx);
    return idx;
  }

  #indexAdd(idx, field, id, row) {
    const v = row[field];
    for (const x of Array.isArray(v) ? v : [v]) {
      if (!SCALAR(x)) continue;
      if (!idx.has(x)) idx.set(x, new Set());
      idx.get(x).add(id);
    }
  }

  #indexRemove(idx, field, id, row) {
    const v = row[field];
    for (const x of Array.isArray(v) ? v : [v]) idx.get(x)?.delete(id);
  }

  #write(name, t, id, row) {
    const old = t.rows.get(id);
    if (old) for (const [field, idx] of t.indexes) this.#indexRemove(idx, field, id, old);
    if (!t.seqs.has(id)) t.seqs.set(id, ++this.seq);
    t.rows.set(id, row);
    for (const [field, idx] of t.indexes) this.#indexAdd(idx, field, id, row);
    this.q.put.run(name, id, t.seqs.get(id), JSON.stringify(row));
  }

  #remove(name, t, id) {
    const old = t.rows.get(id);
    if (!old) return false;
    for (const [field, idx] of t.indexes) this.#indexRemove(idx, field, id, old);
    t.rows.delete(id);
    t.seqs.delete(id);
    this.q.del.run(name, id);
    try {
      this.onRemove?.(name, id, old);
    } catch {
      // A clean-up hook failing never undoes the delete.
    }
    return true;
  }

  /** Every matching row (originals: callers clone). */
  #find(t, query) {
    let candidates = null;
    for (const [field, values] of indexable(query)) {
      const idx = this.#index(t, field);
      const ids = new Set();
      for (const v of values) for (const id of idx.get(v) || []) ids.add(id);
      if (!candidates || ids.size < candidates.size) candidates = ids;
      if (!candidates.size) break;
    }
    const out = [];
    for (const id of candidates || t.rows.keys()) {
      const row = t.rows.get(id);
      if (row && matches(row, query)) out.push(row);
    }
    return out;
  }

  #entityApi(name) {
    const store = this;
    return {
      async filter(query = {}, sort = "-created_date", limit = 5000, skip = 0) {
        const t = store.#table(name);
        const field = String(sort || "-created_date").replace(/^[-+]/, "");
        const dir = String(sort || "").startsWith("-") ? -1 : 1;
        const found = store.#find(t, query).sort((a, b) => dir * compare(a[field], b[field]) || t.seqs.get(a.id) - t.seqs.get(b.id));
        const start = Math.max(0, Number(skip) || 0);
        return clone(found.slice(start, start + Math.max(0, Math.min(Number(limit) || 5000, 5000))));
      },
      async list(sort = "-created_date", limit = 5000, skip = 0) {
        return this.filter({}, sort, limit, skip);
      },
      async get(id) {
        const row = store.#table(name).rows.get(String(id));
        if (!row) throw denied(404, "Not found");
        return clone(row);
      },
      async create(data) {
        const t = store.#table(name);
        const at = store.tick();
        const row = { ...clone(data || {}), id: store.newId(), created_date: at, updated_date: at };
        store.#write(name, t, row.id, row);
        return clone(row);
      },
      async bulkCreate(list) {
        const out = [];
        for (const data of list || []) out.push(await this.create(data));
        return out;
      },
      async update(id, data) {
        const t = store.#table(name);
        const row = t.rows.get(String(id));
        if (!row) throw denied(404, "Not found");
        const next = { ...row, ...clone(data || {}), id: row.id, created_date: row.created_date, updated_date: store.tick() };
        store.#write(name, t, row.id, next);
        return clone(next);
      },
      async updateMany(query, ops) {
        const set = ops?.$set;
        if (!set || Object.keys(ops).length !== 1) throw denied(400, "updateMany supports $set only");
        const t = store.#table(name);
        let n = 0;
        for (const row of store.#find(t, query)) {
          store.#write(name, t, row.id, { ...row, ...clone(set), updated_date: store.tick() });
          n += 1;
        }
        return { modifiedCount: n };
      },
      async delete(id) {
        store.#remove(name, store.#table(name), String(id));
        return { ok: true };
      },
      async deleteMany(query) {
        const t = store.#table(name);
        let n = 0;
        for (const row of store.#find(t, query)) if (store.#remove(name, t, row.id)) n += 1;
        return { deletedCount: n };
      },
    };
  }

  /** Tables as the signed-in person (or an anonymous visitor) sees them. */
  asPerson(user) {
    const store = this;
    const userData = (field) => {
      if (!user) return undefined;
      const row = store.#table("User").rows.get(user.id);
      return row ? clone(row[field]) : undefined;
    };
    return new Proxy({}, {
      get: (_target, name) => {
        if (typeof name !== "string") return undefined;
        const rules = store.schemas[name]?.rls || {};
        const api = store.entities[name];
        const allow = (rule) => {
          const q = store.schemas[name] ? ruleToQuery(rule, user, userData) : null;
          if (!q) throw denied(403, "Permission denied");
          return q;
        };
        return {
          async filter(query = {}, sort, limit, skip) {
            const allowed = store.schemas[name] ? ruleToQuery(rules.read, user, userData) : null;
            if (!allowed) return [];
            return api.filter(Object.keys(allowed).length ? { $and: [query || {}, allowed] } : query, sort, limit, skip);
          },
          async list(sort, limit, skip) {
            return this.filter({}, sort, limit, skip);
          },
          async get(id) {
            const allowed = store.schemas[name] ? ruleToQuery(rules.read, user, userData) : null;
            const row = await api.get(id);
            if (!allowed || !matches(row, allowed)) throw denied(404, "Not found");
            return row;
          },
          async create(data) {
            allow(rules.create);
            return api.create(data);
          },
          async update(id, data) {
            const q = allow(rules.update);
            const row = await api.get(id);
            if (!matches(row, q)) throw denied(403, "Permission denied");
            return api.update(id, data);
          },
          async delete(id) {
            const q = allow(rules.delete);
            const row = await api.get(id).catch(() => null);
            if (row && !matches(row, q)) throw denied(403, "Permission denied");
            return api.delete(id);
          },
        };
      },
    });
  }
}
