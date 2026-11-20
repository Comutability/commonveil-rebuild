// Push notifications that give nothing away (docs/NOTIFICATIONS.md).
//
// A push says only that there's something new: "New message" or "New activity". No name, no
// conversation, no words. Devices keep a record of the notifications they show (one of those
// records is how messages from encrypted apps have turned up in investigations), so nothing worth
// recording goes in one.
//
// What a push carries, encrypted to the browser (handlers/../push/webpush.ts): its kind, and a
// random one-time code. Tapping the notification opens the app, which swaps the code (signed in,
// as the same person) for where to go. Codes last a week and are used once. A mute key lets the
// device stay silent for conversations muted on it, without the push naming the conversation.
import { ApiError, id, type Actions } from "../http.ts";
import { hmac, randomToken, sha256Hex } from "../identity/crypto.ts";
import { makeVapidKeys, pushEndpointOk, sendPush, type VapidKeys } from "../push/webpush.ts";

const MAX_SUBSCRIPTIONS = 10;
const CODE_DAYS = 7;
// A burst of messages makes one notification per device, not one each.
const QUIET_MS = 20_000;
const MAX_PER_SEND = 200;
const B64URL = /^[A-Za-z0-9_-]+$/;

export type PushConfig = { subject: string };

const envOf = (name: string) => {
  try {
    return (globalThis as any).Deno?.env?.get?.(name) || "";
  } catch {
    return "";
  }
};
export const BASE44_PUSH: PushConfig = { subject: envOf("CV_PUSH_SUBJECT") || "https://commonveil.online" };

/** Self-hosted sites: pushes say they're from this site (called once at start-up). */
export function configurePush(subject: string) {
  BASE44_PUSH.subject = subject;
}

let cachedKeys: VapidKeys | null = null;

/** The site's push key: made the first time, then kept. Its public half goes to browsers. */
export async function pushKeys(sr: any): Promise<VapidKeys> {
  if (cachedKeys) return cachedKeys;
  const [row] = await sr.entities.CvSecret.filter({ name: "push-vapid" }, "created_date", 1);
  if (row?.value) return (cachedKeys = JSON.parse(row.value));
  await sr.entities.CvSecret.create({ name: "push-vapid", value: JSON.stringify(await makeVapidKeys()) });
  const [first] = await sr.entities.CvSecret.filter({ name: "push-vapid" }, "created_date", 1);
  return (cachedKeys = JSON.parse(first.value));
}

export function forgetPushKeys() {
  cachedKeys = null;
}

/** What a device needs to stay quiet about a place it's muted, without being told the place. */
export const muteKey = async (secret: string, placeId: string) => (await hmac(secret, `mute:${placeId}`)).slice(0, 16);

/**
 * Tell these people's devices there's something new. kind: "message" (a conversation), "activity"
 * (a server), "conversation" (someone started one with you). Never throws: notifications are a
 * nicety, and a send mustn't fail because of one.
 */
export type PushTally = { attempted: number; sent: number; rejected: number; failed: number; gone: number; skipped: number; status_code?: number };

/** Messages must never fail when a push fails. Diagnostics only contain outcomes, counts and HTTP status codes. */
export async function notifyPeople(sr: any, push: PushConfig | undefined, userIds: string[], { kind, path, placeId, onlyEndpoint, bypassQuiet = false }: { kind: string; path: string; placeId: string; onlyEndpoint?: string; bypassQuiet?: boolean }): Promise<PushTally> {
  const tally: PushTally = { attempted: 0, sent: 0, rejected: 0, failed: 0, gone: 0, skipped: 0 };
  try {
    const people = [...new Set(userIds)].filter((u) => typeof u === "string").slice(0, MAX_PER_SEND);
    if (!people.length) return tally;
    const subs = await sr.entities.PushSubscription.filter({ user_id: { $in: people } }, "created_date", MAX_PER_SEND * 2);
    const scoped = onlyEndpoint ? subs.filter((s: any) => s.endpoint === onlyEndpoint) : subs;
    const now = Date.now();
    const due = scoped.filter((s: any) => bypassQuiet || !s.last_push_at || now - Date.parse(s.last_push_at) > QUIET_MS);
    tally.skipped = scoped.length - due.length;
    if (tally.skipped) console.info("commonveil push: rate_limited", { kind, count: tally.skipped });
    if (!due.length) return tally;
    const keys = await pushKeys(sr);
    const codes = new Map<string, string>();
    for (const userId of new Set(due.map((s: any) => s.user_id))) {
      const code = randomToken(18);
      await sr.entities.PushCode.create({ user_id: userId, code_hash: await sha256Hex(code), path, expires_at: new Date(now + CODE_DAYS * 86_400_000).toISOString() });
      codes.set(userId as string, code);
    }
    await Promise.all(due.map(async (s: any) => {
      tally.attempted += 1;
      try {
        const payload = { v: 1, k: kind, c: codes.get(s.user_id), m: s.mute_secret ? await muteKey(s.mute_secret, placeId) : "" };
        const result = await sendPush({ endpoint: s.endpoint, p256dh: s.p256dh, auth: s.auth }, payload, { keys, subject: (push || BASE44_PUSH).subject, urgency: kind === "message" || kind === "conversation" || kind === "mention" ? "high" : "normal" });
        if (onlyEndpoint && result.status) tally.status_code = result.status;
        console.info("commonveil push: delivery", { kind, outcome: result.state, ...(result.status ? { status: result.status } : {}), ...(result.reason ? { reason: result.reason } : {}) });
        if (result.state === "gone") {
          tally.gone += 1;
          await sr.entities.PushSubscription.delete(s.id).catch(() => null);
        } else if (result.state === "sent") {
          tally.sent += 1;
          await sr.entities.PushSubscription.update(s.id, { last_push_at: new Date().toISOString() }).catch(() => null);
        } else if (result.state === "rejected") tally.rejected += 1;
        else tally.failed += 1;
      } catch {
        tally.failed += 1;
        console.warn("commonveil push: delivery", { kind, outcome: "internal_error" });
      }
    }));
  } catch {
    tally.failed += 1;
    console.warn("commonveil push: preparation_failed", { kind });
  }
  return tally;
}

export const notificationActions: Actions = {
  async key({ sr }) {
    return { public_key: (await pushKeys(sr)).publicKey };
  },

  /** This browser's push subscription. mute_secret: made by the browser, for mute keys. */
  async subscribe({ sr, user, body, session }: any) {
    if (!pushEndpointOk(body.endpoint)) throw new ApiError(400, "BAD_ENDPOINT", "That isn't a browser push address.");
    for (const k of ["p256dh", "auth", "mute_secret"]) {
      if (typeof body[k] !== "string" || !B64URL.test(body[k]) || body[k].length > 200) throw new ApiError(400, "BAD_KEYS", "That subscription is incomplete.");
    }
    // An address belongs to one browser: drop any older claim to it. The app says it again when the
    // settings are opened (a turn-on can be interrupted), so an identical record is left as it is.
    const claimed = await sr.entities.PushSubscription.filter({ endpoint: body.endpoint }, "created_date", 20);
    const same = claimed.find((s: any) => s.user_id === user.id && s.p256dh === body.p256dh && s.auth === body.auth && s.mute_secret === body.mute_secret);
    if (same) return { ok: true };
    for (const old of claimed) await sr.entities.PushSubscription.delete(old.id).catch(() => null);
    const mine = await sr.entities.PushSubscription.filter({ user_id: user.id }, "created_date", MAX_SUBSCRIPTIONS + 5);
    for (const old of mine.slice(0, Math.max(0, mine.length - MAX_SUBSCRIPTIONS + 1))) await sr.entities.PushSubscription.delete(old.id).catch(() => null);
    await sr.entities.PushSubscription.create({ user_id: user.id, device_id: session?.deviceId || "", endpoint: body.endpoint, p256dh: body.p256dh, auth: body.auth, mute_secret: body.mute_secret, last_push_at: "" });
    return { ok: true };
  },

  async unsubscribe({ sr, user, body }) {
    for (const s of await sr.entities.PushSubscription.filter({ user_id: user.id }, "created_date", 50)) {
      if (!body.endpoint || s.endpoint === body.endpoint) await sr.entities.PushSubscription.delete(s.id).catch(() => null);
    }
    return { ok: true };
  },

  /** Where a tapped notification leads. Only for the person it was for, and only once. */
  async open({ sr, user, body }) {
    if (typeof body.code !== "string" || !B64URL.test(body.code) || body.code.length > 60) throw new ApiError(400, "BAD_CODE", "That notification has expired.");
    const [row] = await sr.entities.PushCode.filter({ code_hash: await sha256Hex(body.code) }, "created_date", 1);
    if (!row || row.user_id !== user.id || Date.parse(row.expires_at) < Date.now()) return { path: "/app" };
    await sr.entities.PushCode.delete(row.id).catch(() => null);
    return { path: typeof row.path === "string" && row.path.startsWith("/app") ? row.path : "/app" };
  },

  /** Test only the requesting browser, not every device linked to this account. */
  async test(ctx: any) {
    const endpoint = ctx.body.endpoint;
    if (!pushEndpointOk(endpoint)) throw new ApiError(400, "BAD_ENDPOINT", "This browser has no valid push subscription.");
    const subs = await ctx.sr.entities.PushSubscription.filter({ user_id: ctx.user.id }, "created_date", MAX_SUBSCRIPTIONS + 5);
    if (!subs.some((s: any) => s.endpoint === endpoint)) throw new ApiError(409, "PUSH_NOT_REGISTERED", "This browser's subscription isn't registered. Turn push off and on here.");
    const tally = await notifyPeople(ctx.sr, ctx.push, [ctx.user.id], { kind: "test", path: "/app/settings/notifications", placeId: "test", onlyEndpoint: endpoint, bypassQuiet: true });
    return { ok: true, ...tally };
  },
};

/** Remove an account's subscriptions and codes (account deletion). */
export async function removePush(sr: any, userId: string) {
  for (const name of ["PushSubscription", "PushCode"]) {
    for (const r of await sr.entities[name].filter({ user_id: userId }, "created_date", 200).catch(() => [])) await sr.entities[name].delete(r.id).catch(() => null);
  }
}

export const conversationPath = (conversationId: string) => `/app/c/${id(conversationId, "conversation")}`;