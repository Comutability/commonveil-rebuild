// Request handling shared by every backend function.
// Each function is a small set of named actions. Every action runs only after the caller is known:
// a Commonveil sign-in session (checked here; see identity/), or, on self-hosted sites, the person
// the server already checked. Base44's own sessions only reach the sign-in function.
import { personClient } from "./rls.ts";
import { userRecord, verifyAccess } from "./identity/sessions.ts";

export const LIMITS = Object.freeze({
  maxBodyBytes: 256 * 1024,
  // A post-quantum wrap is about 1.6 KB, so a 32-person envelope is about 55 KB.
  maxEnvelopeChars: 96 * 1024,
  maxTitleEnvelopeChars: 96 * 1024,
  maxSealedChars: 96 * 1024,
  maxGroupMembers: 32,
  maxDevices: 10,
  maxPendingDevices: 3,
  pendingDeviceMinutes: 15,
  proofSkewMs: 5 * 60 * 1000,
  sentAtSkewMs: 10 * 60 * 1000,
  // A message written offline and sent when the device is back (docs/OFFLINE.md) may be this old.
  queuedMaxAgeMs: 7 * 24 * 3600 * 1000,
  messagesPerMinute: 30,
  conversationsPerHour: 30,
  reportsPerDay: 20,
  resetsPerDay: 3,
  // A reset waits this long, so the account's own devices (or the phrase) can stop it.
  resetDelayHours: 168,
  registrationsPerDay: 10,
  // Keyrings hold at most 256 versions; stop well short.
  maxKeyVersions: 250,
  pageSize: 50,
  pollLimit: 200,
});


export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message?: string) {
    super(message || code);
    this.status = status;
    this.code = code;
  }
}

const HEADERS = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Content-Type": "application/json; charset=utf-8",
};

export function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: HEADERS });
}

/**
 * user is null only in functions that explicitly allow anonymous callers.
 * sr: the service role, which ignores row level security; every call it makes counts against one
 * allowance shared by the whole app. own: the caller's own access, limited by the entities' rules
 * and counted against that person's allowance, so frequent reads (polling) use it where the
 * rules allow.
 */
/**
 * federation: present only on a self-hosted site that talks to other sites (server/federation).
 * resolveHandle(handle, me) finds a person on another site by their handle (alice.example.com),
 * checks they accept a conversation from me, and returns their user id here. On Base44 it's
 * absent, and handles are refused like any other unknown username.
 */
export type Federation = { resolveHandle(handle: string, me: string): Promise<string | null> };
export type Ctx = { sr: any; own: any; user: any; body: any; now: Date; federation?: Federation };
export type Actions = Record<string, (ctx: Ctx) => Promise<unknown>>;
export type RunOptions = {
  allowAnonymous?: boolean;
  maxBodyBytes?: number;
  federation?: Federation;
  /** The sign-in function only: a Base44 session (an account made with an email) may come in. */
  allowPlatformUser?: boolean;
  /** Self-hosted sites: the server checked the caller already, so the client's auth.me() is them. */
  trustPlatformUser?: boolean;
  /** Push notifications: who the site's pushes say they're from (handlers/notifications.ts). */
  push?: { subject: string };
};

/** A handle for someone on another site: their username, then the site's domain. */
export const HANDLE_RE = /^[a-z0-9][a-z0-9-]{1,19}(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

/**
 * Run one named action. By default the caller must be a signed-in user; only the security
 * reporting function sets allowAnonymous. Used by the entry files and by tests.
 */
export async function runAction(base44: any, rawBody: string, actions: Actions, options: RunOptions = {}): Promise<Response> {
  try {
    if (rawBody.length > (options.maxBodyBytes ?? LIMITS.maxBodyBytes)) throw new ApiError(413, "TOO_LARGE", "That request is too large.");
    let body: any = {};
    if (rawBody) {
      try {
        body = JSON.parse(rawBody);
      } catch {
        throw new ApiError(400, "BAD_JSON", "The request wasn't valid JSON.");
      }
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new ApiError(400, "BAD_REQUEST", "Invalid request.");
    // Who's asking (docs/IDENTITY.md): a Commonveil sign-in session, sent as _session, and
    // checked here. A Base44 session alone (an account made with an email) is only good for
    // moving to Commonveil sign-in, except on self-hosted sites, where the server checks callers.
    const sr = base44.asServiceRole;
    let user: any = null;
    let own: any = base44;
    let session: { userId: string; deviceId: string; epoch: number } | null = null;
    let platformUser: any = null;
    const token = body._session;
    delete body._session;
    if (typeof token === "string" && token) {
      session = await verifyAccess(sr, token);
      const record = session ? await userRecord(sr, session.userId) : null;
      if (!session || !record) throw new ApiError(401, "SIGN_IN_REQUIRED", "Please sign in again.");
      user = { ...record, id: record.id, email: record.email || "", role: record.role || "user" };
      own = personClient(sr, user, record);
    } else {
      const me = await base44.auth.me().catch(() => null);
      const found = me && typeof me.id === "string" && me.id ? me : null;
      if (found && options.trustPlatformUser) {
        user = found;
        // Self-hosted sites say which sign-in session it was, too (which device).
        session = (await base44.auth.session?.().catch(() => null)) || null;
      }
      else if (found && options.allowPlatformUser) platformUser = found;
      else if (found) throw new ApiError(401, "NEW_SIGN_IN", "Commonveil has a new way to sign in. Please sign in again.");
    }
    if (!user && !options.allowAnonymous) throw new ApiError(401, "SIGN_IN_REQUIRED", "Please sign in again.");
    const action = typeof body.action === "string" ? body.action : "";
    if (!Object.prototype.hasOwnProperty.call(actions, action)) throw new ApiError(400, "UNKNOWN_ACTION", "Unknown action.");
    const result = await actions[action]({ sr, own, user, body, now: new Date(), federation: options.federation, push: options.push, session, platformUser } as any);
    return json(200, result ?? { ok: true });
  } catch (error) {
    if (error instanceof ApiError) return json(error.status, { error: error.message, code: error.code });
    const message = String((error as any)?.message || "");
    if (/rate limit|too many requests|429/i.test(message)) {
      // Base44 limits how many queries an app makes per minute. Logged so the owner can see it happening.
      console.warn("commonveil upstream busy");
      return json(429, { error: "The service is busy. Please try again in a moment.", code: "UPSTREAM_BUSY" });
    }
    // A field holds a limited amount (a profile picture is the one that can reach it).
    if (/exceeds the maximum allowed size/i.test(message)) {
      return json(400, { error: "That's too much to save at once. Try a smaller picture or shorter text.", code: "TOO_LARGE" });
    }
    // Log a category only: no request bodies, keys or user data.
    console.error("commonveil function failure", { name: (error as any)?.name || "Error" });
    return json(500, { error: "Something went wrong. Nothing was changed.", code: "INTERNAL" });
  }
}

export async function serve(req: Request, makeClient: (req: Request) => any, actions: Actions, options: RunOptions = {}): Promise<Response> {
  if (req.method !== "POST") return json(405, { error: "Use POST.", code: "METHOD_NOT_ALLOWED" });
  const raw = await req.text();
  return runAction(makeClient(req), raw, actions, options);
}

// ---------- small validators ----------

export const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
export const RANDOM_ID_RE = /^[A-Za-z0-9_-]{16,64}$/;

export function str(value: unknown, name: string, max = 200, min = 1): string {
  if (typeof value !== "string" || value.length < min || value.length > max) {
    throw new ApiError(400, "BAD_FIELD", `Invalid ${name}.`);
  }
  return value;
}

export function id(value: unknown, name: string): string {
  if (typeof value !== "string" || !ID_RE.test(value)) throw new ApiError(400, "BAD_FIELD", `Invalid ${name}.`);
  return value;
}

export function randomIdField(value: unknown, name: string): string {
  if (typeof value !== "string" || !RANDOM_ID_RE.test(value)) throw new ApiError(400, "BAD_FIELD", `Invalid ${name}.`);
  return value;
}

export function int(value: unknown, name: string, min = 1, max = 1_000_000): number {
  if (!Number.isInteger(value) || (value as number) < min || (value as number) > max) {
    throw new ApiError(400, "BAD_FIELD", `Invalid ${name}.`);
  }
  return value as number;
}

export function isoTime(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length > 40 || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(value)) {
    throw new ApiError(400, "BAD_FIELD", `Invalid ${name}.`);
  }
  if (Number.isNaN(Date.parse(value))) throw new ApiError(400, "BAD_FIELD", `Invalid ${name}.`);
  return value;
}

export function idList(value: unknown, name: string, max: number): string[] {
  if (!Array.isArray(value) || value.length > max) throw new ApiError(400, "BAD_FIELD", `Invalid ${name}.`);
  const out = new Set<string>();
  for (const v of value) out.add(id(v, name));
  return [...out];
}

/** Strip control characters and trim. */
export function cleanText(value: unknown, max: number): string {
  if (value === undefined || value === null) return "";
  if (typeof value !== "string") throw new ApiError(400, "BAD_FIELD", "Invalid text.");
  // deno-lint-ignore no-control-regex
  const cleaned = value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2066-\u2069]/g, "").trim();
  if (cleaned.length > max) throw new ApiError(400, "TOO_LONG", `Please keep it under ${max} characters.`);
  return cleaned;
}

/** Platform timestamps look like 2026-10-29T11:37:14.587000 (UTC, no zone). */
export function platformTime(date: Date): string {
  return date.toISOString().replace("Z", "");
}

export function parsePlatformTime(value: string): number {
  return Date.parse(/Z$|[+-]\d{2}:\d{2}$/.test(value) ? value : `${value}Z`);
}