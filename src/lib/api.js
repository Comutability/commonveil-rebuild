import { base44 } from "@/api/base44Client";

export class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

/** Call one action of a backend function. Throws ApiError with the server's code and message. */
export async function callFn(fn, body) {
  try {
    const res = await base44.functions.invoke(fn, body);
    return res && typeof res === "object" && "data" in res ? res.data : res;
  } catch (err) {
    const status = err?.response?.status ?? err?.status ?? 0;
    const data = err?.response?.data ?? err?.data ?? {};
    if (status === 0) throw new ApiError(0, "NETWORK", "Can't reach Commonveil right now. Check your connection and try again.");
    throw new ApiError(status, data.code || "ERROR", data.error || "Something went wrong. Please try again.");
  }
}

/** Public, published content readable without signing in. */
export async function listContent(entity, sort = "-created_date", limit = 200) {
  return base44.entities[entity].filter({ status: "published" }, sort, limit);
}

export async function contentBySlug(entity, slug) {
  const rows = await base44.entities[entity].filter({ slug, status: "published" }, "-created_date", 1);
  return rows[0] || null;
}
