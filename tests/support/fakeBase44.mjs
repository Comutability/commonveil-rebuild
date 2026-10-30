// In-memory stand-in for the Base44 entity store, used to drive the real backend
// handlers in tests. It replaces the database only. It does NOT stand in for any
// session or token API: the handlers never call one, and auth.me() here simply
// returns the test user (or fails, for anonymous callers).

const clone = (v) => (v === undefined ? v : JSON.parse(JSON.stringify(v)));

function compare(a, b) {
  if (a === b) return 0;
  if (a === undefined || a === null) return 1;
  if (b === undefined || b === null) return -1;
  return a < b ? -1 : 1;
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

  /** Record times follow the real clock (as handlers compare them with it), never repeating. */
  tick() {
    this.clock = Math.max(this.clock + 1, Date.now());
    return new Date(this.clock).toISOString().replace("Z", "000");
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

  /** What createClientFromRequest returns inside a function, for a given caller. */
  clientFor(user) {
    return {
      auth: {
        me: async () => {
          if (!user) throw Object.assign(new Error("Unauthorized"), { status: 401 });
          return clone(user);
        },
      },
      asServiceRole: { entities: this.entities },
    };
  }
}
