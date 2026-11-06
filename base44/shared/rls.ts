// Row rules, applied in code. Each table's "rls" in base44/entities says what a signed-in person
// may read and write. Base44 applies those itself for its own sign-in; for Commonveil sign-in
// (identity/), the backend reads as the service role and applies the same rules here, so a
// handler reading "as the person" sees exactly what the rules allow, whichever sign-in it was.
//
// Only the rule shapes this app uses are understood: data.<field> equality with {{user.id}} or
// {{user.email}}, { $in: "{{user.data.<field>}}" }, user_condition, $or and $and.
import { RULES } from "./rules.generated.ts";
import { ApiError } from "./http.ts";

type Query = Record<string, any>;
type Person = { id: string; email?: string; role?: string; [k: string]: unknown };

const refersToUser = (rule: unknown) => {
  const s = JSON.stringify(rule ?? null);
  return s.includes("{{user") || s.includes("user_condition");
};

/** A rule as a query for this person: {} matches everything, null nothing. */
export function ruleToQuery(rule: any, user: Person | null, userData: (field: string) => unknown = () => undefined): Query | null {
  if (rule === true) return {};
  if (rule === false || rule === undefined || rule === null) return null;
  const resolve = (value: unknown) => {
    if (value === "{{user.id}}") return user?.id;
    if (value === "{{user.email}}") return user?.email || undefined;
    const m = typeof value === "string" ? /^\{\{user\.data\.([a-z_]+)\}\}$/.exec(value) : null;
    if (m) return userData(m[1]);
    if (typeof value === "string" && value.includes("{{")) throw new Error(`Unsupported rule value ${value}`);
    return value;
  };
  const parts: Query[] = [];
  for (const [key, value] of Object.entries(rule)) {
    if (key === "$or") {
      const subs = (value as any[]).map((r) => ruleToQuery(r, user, userData));
      if (subs.some((s) => s && !Object.keys(s).length)) return {};
      const live = subs.filter(Boolean) as Query[];
      if (!live.length) return null;
      parts.push({ $or: live });
    } else if (key === "$and") {
      const subs = (value as any[]).map((r) => ruleToQuery(r, user, userData));
      if (subs.some((s) => s === null)) return null;
      parts.push(...(subs as Query[]));
    } else if (key === "user_condition") {
      if (!user) return null;
      for (const [field, expected] of Object.entries(value as object)) if ((user as any)[field] !== expected) return null;
    } else if (key.startsWith("data.")) {
      if (!user && refersToUser(value)) return null;
      if (value && typeof value === "object" && !Array.isArray(value)) {
        if (Object.keys(value).length !== 1 || !("$in" in value)) throw new Error("Only $in rules are supported");
        const list = resolve((value as any).$in);
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
  return combine(parts);
}

/** One query that needs all of these: merged into one object where keys don't clash. */
export function combine(parts: Query[]): Query {
  const out: Query = {};
  const rest: Query[] = [];
  for (const p of parts) {
    if (!p || !Object.keys(p).length) continue;
    if (Object.keys(p).some((k) => k in out)) rest.push(p);
    else Object.assign(out, p);
  }
  return rest.length ? { $and: [out, ...rest] } : out;
}

/** Whether a row meets a query (the same operators the app's queries use). */
export function matches(record: any, query: Query | null): boolean {
  if (!query) return false;
  for (const [key, cond] of Object.entries(query)) {
    if (key === "$or") {
      if (!(cond as Query[]).some((sub) => matches(record, sub))) return false;
      continue;
    }
    if (key === "$and") {
      if (!(cond as Query[]).every((sub) => matches(record, sub))) return false;
      continue;
    }
    const value = record?.[key];
    const values = Array.isArray(value) ? value : [value];
    if (cond !== null && typeof cond === "object" && !Array.isArray(cond)) {
      for (const [op, arg] of Object.entries(cond)) {
        if (op === "$in") { if (!Array.isArray(arg) || !values.some((v) => arg.includes(v))) return false; }
        else if (op === "$nin") { if (Array.isArray(arg) && values.some((v) => arg.includes(v))) return false; }
        else if (op === "$gte") { if (!(value >= (arg as any))) return false; }
        else if (op === "$gt") { if (!(value > (arg as any))) return false; }
        else if (op === "$lte") { if (!(value <= (arg as any))) return false; }
        else if (op === "$lt") { if (!(value < (arg as any))) return false; }
        else if (op === "$ne") { if (value === arg) return false; }
        else if (op === "$exists") { if ((value !== undefined && value !== null) !== Boolean(arg)) return false; }
        else return false;
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

const denied = (status: number, message: string) => new ApiError(status, status === 404 ? "NOT_FOUND" : "FORBIDDEN", message);

/**
 * Tables as this person sees them, over the service role: what handlers get as `own` for someone
 * signed in with Commonveil sign-in. userRow is the person's own record (for {{user.data.x}}).
 */
export function personClient(sr: any, user: Person, userRow: Record<string, unknown> = {}) {
  const userData = (field: string) => userRow[field];
  const entities = new Proxy({}, {
    get: (_t, name) => {
      if (typeof name !== "string") return undefined;
      const rules = (RULES as Record<string, any>)[name] || {};
      const api = sr.entities[name];
      const allowed = (op: string) => ruleToQuery(rules[op], user, userData);
      const need = (op: string) => {
        const q = allowed(op);
        if (!q) throw denied(403, "Permission denied");
        return q;
      };
      return {
        async filter(query: Query = {}, sort?: string, limit?: number, skip?: number) {
          const q = allowed("read");
          if (!q) return [];
          return api.filter(Object.keys(q).length ? combine([query || {}, q]) : query, sort, limit, skip);
        },
        async list(sort?: string, limit?: number, skip?: number) {
          return this.filter({}, sort, limit, skip);
        },
        async get(id: string) {
          const q = allowed("read");
          const row = await api.get(id);
          if (!q || !matches(row, q)) throw denied(404, "Not found");
          return row;
        },
        async create(data: Record<string, unknown>) {
          need("create");
          return api.create(data);
        },
        async update(id: string, data: Record<string, unknown>) {
          const q = need("update");
          if (!matches(await api.get(id), q)) throw denied(403, "Permission denied");
          return api.update(id, data);
        },
        async delete(id: string) {
          const q = need("delete");
          const row = await api.get(id).catch(() => null);
          if (row && !matches(row, q)) throw denied(403, "Permission denied");
          return api.delete(id);
        },
      };
    },
  });
  return {
    entities,
    auth: { me: async () => ({ ...user }) },
    asServiceRole: sr,
  };
}
