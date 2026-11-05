// In-memory stand-in for the Base44 entity store, used to drive the real backend
// handlers in tests. It replaces the database and records emails instead of sending
// them. It does NOT stand in for any session or token API: the handlers never call
// one, and auth.me() here simply returns the test user (or fails, for anonymous callers).
//
// Reads made as the signed-in person (not the service role) follow the row level security
// rules in base44/entities, read from the real schema files, the way Base44 applies them.
import fs from "node:fs";

const clone = (v) => (v === undefined ? v : JSON.parse(JSON.stringify(v)));

const SCHEMA_DIR = new URL("../../base44/entities/", import.meta.url);
const RULES = Object.fromEntries(
  fs
    .readdirSync(SCHEMA_DIR)
    .filter((f) => f.endsWith(".jsonc"))
    .map((f) => JSON.parse(fs.readFileSync(new URL(f, SCHEMA_DIR), "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "")))
    .map((s) => [s.name, s.rls]),
);

/**
 * Turn a row level security rule into a query for this person: {} matches everything, null
 * nothing. Only the rule shapes this app uses are understood; anything else fails the test.
 * userData reads a field of the person's stored User record, at query time, as Base44 does
 * for {{user.data.<field>}} (checked against the live platform).
 */
function ruleToQuery(rule, user, userData = () => undefined) {
  if (rule === true) return {};
  if (rule === false || rule === undefined) return null;
  if (!user) return null; // a rule that refers to the user blocks anonymous callers outright
  const resolve = (value) => {
    if (value === "{{user.id}}") return user.id;
    if (value === "{{user.email}}") return user.email;
    const m = typeof value === "string" ? /^\{\{user\.data\.([a-z_]+)\}\}$/.exec(value) : null;
    if (m) return userData(m[1]);
    if (typeof value === "string" && value.includes("{{")) throw new Error(`Fake RLS doesn't understand ${value}`);
    return value;
  };
  const parts = [];
  for (const [key, value] of Object.entries(rule)) {
    if (key === "$or") {
      const subs = value.map((r) => ruleToQuery(r, user, userData));
      if (subs.some((s) => s && !Object.keys(s).length)) continue;
      const live = subs.filter(Boolean);
      if (!live.length) return null;
      parts.push({ $or: live });
    } else if (key === "$and") {
      const subs = value.map((r) => ruleToQuery(r, user, userData));
      if (subs.some((s) => s === null)) return null;
      parts.push(...subs);
    } else if (key === "user_condition") {
      for (const [field, expected] of Object.entries(value)) if (user[field] !== expected) return null;
    } else if (key.startsWith("data.")) {
      if (value && typeof value === "object" && !Array.isArray(value)) {
        // Only the whole-operand $in form resolves on Base44: { "$in": "{{user.data.list}}" }.
        if (Object.keys(value).length !== 1 || !("$in" in value)) throw new Error("Fake RLS only understands $in rules");
        const list = resolve(value.$in);
        parts.push({ [key.slice(5)]: { $in: Array.isArray(list) ? list : [] } });
      } else {
        parts.push({ [key.slice(5)]: resolve(value) });
      }
    } else {
      throw new Error(`Fake RLS doesn't understand the rule key ${key}`);
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

/**
 * Base44 answers queries on its own record fields (who created a record) with its own values,
 * whatever a schema stores under the same name, so handlers must never filter on them.
 */
const PLATFORM_ONLY = new Set(["created_by", "created_by_id"]);
function assertQueryable(query) {
  for (const [key, cond] of Object.entries(query || {})) {
    if (PLATFORM_ONLY.has(key)) throw new Error(`Queries on ${key} don't match stored values on Base44`);
    if (key === "$or" || key === "$and") cond.forEach(assertQueryable);
  }
}

function matches(record, query) {
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
        if (op === "$in") { if (!values.some((v) => arg.includes(v))) return false; }
        else if (op === "$nin") { if (values.some((v) => arg.includes(v))) return false; }
        else if (op === "$gte") { if (!(value >= arg)) return false; }
        else if (op === "$gt") { if (!(value > arg)) return false; }
        else if (op === "$lte") { if (!(value <= arg)) return false; }
        else if (op === "$lt") { if (!(value < arg)) return false; }
        else if (op === "$ne") { if (value === arg) return false; }
        else throw new Error(`Fake store does not support ${op}`);
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

export class FakeWorld {
  constructor() {
    this.clock = Date.now();
    this.counter = 0;
    this.writes = 0;
    /** Emails the handlers asked to send. Set emailDown to make sending fail. */
    this.emails = [];
    this.emailDown = false;
    /** Reads made as the service role, which on Base44 share one allowance for the whole app. */
    this.serviceReads = 0;
    this.entities = new Proxy({}, {
      get: (target, name) => {
        if (typeof name !== "string") return undefined;
        if (!target[name]) target[name] = this.#entity(name);
        return target[name];
      },
    });
  }

  newId() {
    this.counter += 1;
    return (Math.floor(this.clock / 1000).toString(16) + this.counter.toString(16).padStart(16, "0")).slice(-24).padStart(24, "0");
  }

  /**
   * Record times follow the real clock, as handlers compare them with it. Like the platform's,
   * they have microseconds, so a burst of writes never runs ahead of real time.
   */
  tick() {
    this.micros = Math.max((this.micros || 0) + 1, Date.now() * 1000);
    this.clock = Math.floor(this.micros / 1000);
    return new Date(this.clock).toISOString().replace("Z", String(this.micros % 1000).padStart(3, "0"));
  }

  rows(name) {
    return this.entities[name]._rows;
  }

  #entity(name) {
    const world = this;
    const rows = [];
    return {
      _rows: rows,
      async filter(query = {}, sort = "-created_date", limit = 5000) {
        assertQueryable(query);
        const field = String(sort || "-created_date").replace(/^-/, "");
        const dir = String(sort || "").startsWith("-") ? -1 : 1;
        const found = rows
          .map((r, i) => [r, i])
          .filter(([r]) => matches(r, query))
          .sort((x, y) => dir * compare(x[0][field], y[0][field]) || x[1] - y[1])
          .map(([r]) => r);
        return clone(found.slice(0, limit));
      },
      async get(id) {
        const row = rows.find((r) => r.id === id);
        if (!row) throw Object.assign(new Error("Not found"), { status: 404 });
        return clone(row);
      },
      async create(data) {
        world.writes += 1;
        const at = world.tick();
        const row = { ...clone(data), id: world.newId(), created_date: at, updated_date: at };
        rows.push(row);
        return clone(row);
      },
      async bulkCreate(list) {
        const out = [];
        for (const data of list) out.push(await this.create(data));
        return out;
      },
      async updateMany(query, ops) {
        const set = ops?.$set;
        if (!set || Object.keys(ops).length !== 1) throw new Error("Fake store only supports updateMany with $set");
        let n = 0;
        for (const row of rows) {
          if (!matches(row, query)) continue;
          Object.assign(row, clone(set), { updated_date: world.tick() });
          world.writes += 1;
          n += 1;
        }
        return { modifiedCount: n };
      },
      async deleteMany(query) {
        let n = 0;
        for (let i = rows.length - 1; i >= 0; i -= 1) {
          if (!matches(rows[i], query)) continue;
          rows.splice(i, 1);
          world.writes += 1;
          n += 1;
        }
        return { deletedCount: n };
      },
      async update(id, data) {
        world.writes += 1;
        const row = rows.find((r) => r.id === id);
        if (!row) throw Object.assign(new Error("Not found"), { status: 404 });
        Object.assign(row, clone(data), { updated_date: world.tick() });
        return clone(row);
      },
      async delete(id) {
        world.writes += 1;
        const i = rows.findIndex((r) => r.id === id);
        if (i >= 0) rows.splice(i, 1);
        return { ok: true };
      },
    };
  }

  /**
   * Add a person's User record, as signing in does on Base44. Tests that need one (row rules
   * that read it, or the backend updating it) add it; tests/support/harness.mjs always does.
   */
  addUser(user) {
    const rows = this.entities.User._rows;
    if (!rows.some((r) => r.id === user.id)) {
      const at = this.tick();
      rows.push({ id: user.id, email: user.email, role: user.role, full_name: user.full_name, created_date: at, updated_date: at });
    }
  }

  /** Entities as the signed-in person sees them: the service store, filtered by each entity's rules. */
  #asPerson(user) {
    const world = this;
    const denied = (status, message) => Object.assign(new Error(message), { status });
    // {{user.data.<field>}} reads the stored record at query time; no record, no value.
    const userData = (field) => {
      const row = user ? world.entities.User._rows.find((r) => r.id === user.id) : null;
      return row ? clone(row[field]) : undefined;
    };
    return new Proxy({}, {
      get: (_target, name) => {
        if (typeof name !== "string") return undefined;
        const rules = RULES[name] || {};
        const store = world.entities[name];
        return {
          async filter(query = {}, sort, limit) {
            const allowed = ruleToQuery(rules.read, user, userData);
            if (!allowed) return [];
            return store.filter(Object.keys(allowed).length ? { $and: [query, allowed] } : query, sort, limit);
          },
          async get(id) {
            const allowed = ruleToQuery(rules.read, user, userData);
            const row = await store.get(id);
            if (!allowed || !matches(row, allowed)) throw denied(404, "Not found");
            return row;
          },
          async create() {
            if (!ruleToQuery(rules.create, user)) throw denied(403, "Permission denied");
            throw new Error("Writes as a person aren't emulated: the backend writes as the service role");
          },
          async update() {
            if (!ruleToQuery(rules.update, user)) throw denied(403, "Permission denied");
            throw new Error("Writes as a person aren't emulated: the backend writes as the service role");
          },
          async delete() {
            if (!ruleToQuery(rules.delete, user)) throw denied(403, "Permission denied");
            throw new Error("Writes as a person aren't emulated: the backend writes as the service role");
          },
        };
      },
    });
  }

  /** The store as the service role sees it: everything, with reads counted. */
  #asService() {
    const world = this;
    return new Proxy({}, {
      get: (_target, name) => {
        if (typeof name !== "string") return undefined;
        const store = world.entities[name];
        return {
          filter: (...args) => {
            world.serviceReads += 1;
            return store.filter(...args);
          },
          get: (...args) => {
            world.serviceReads += 1;
            return store.get(...args);
          },
          create: (...args) => store.create(...args),
          bulkCreate: (...args) => store.bulkCreate(...args),
          update: (...args) => store.update(...args),
          updateMany: (...args) => store.updateMany(...args),
          delete: (...args) => store.delete(...args),
          deleteMany: (...args) => store.deleteMany(...args),
        };
      },
    });
  }

  /** What createClientFromRequest returns inside a function, for a given caller. */
  clientFor(user) {
    return {
      entities: this.#asPerson(user),
      auth: {
        me: async () => {
          if (!user) throw Object.assign(new Error("Unauthorized"), { status: 401 });
          return clone(user);
        },
      },
      asServiceRole: {
        entities: this.#asService(),
        integrations: {
          Core: {
            SendEmail: async (args) => {
              if (this.emailDown) throw new Error("Email service unavailable");
              this.emails.push(clone(args));
              return { ok: true };
            },
            UploadPrivateFile: async ({ file }) => {
              this.files = this.files || new Map();
              const uri = `private://file-${this.files.size + 1}`;
              this.files.set(uri, new Uint8Array(await file.arrayBuffer()));
              return { file_uri: uri };
            },
            CreateFileSignedUrl: async ({ file_uri, expires_in }) => ({ signed_url: `https://files.example.test/${encodeURIComponent(file_uri)}?ttl=${expires_in}` }),
          },
        },
      },
    };
  }
}
