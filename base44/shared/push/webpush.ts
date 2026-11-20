// Web Push, with WebCrypto only (runs on Base44 and self-hosted sites alike):
//   - RFC 8291: the payload is encrypted to the browser's own key, so the push service in between
//     (Google, Mozilla, Apple, Microsoft) can't read it;
//   - RFC 8292 (VAPID): each push is signed with this site's key, so only this site can push to
//     its subscribers.
// What Commonveil puts in a push is deliberately almost nothing: see handlers/notifications.ts.
import { b64url, fromB64url, utf8 } from "../identity/crypto.ts";

const subtle = () => globalThis.crypto.subtle;

/** Browser push services. A subscription must point at one of these. */
const PUSH_HOSTS = [/^fcm\.googleapis\.com$/, /^android\.googleapis\.com$/, /^updates\.push\.services\.mozilla\.com$/, /^([a-z0-9-]+\.)?push\.services\.mozilla\.com$/, /^web\.push\.apple\.com$/, /^([a-z0-9-]+\.)*notify\.windows\.com$/, /^([a-z0-9-]+\.)*push\.apple\.com$/];

export function pushEndpointOk(endpoint: unknown): boolean {
  if (typeof endpoint !== "string" || endpoint.length > 1000) return false;
  try {
    const u = new URL(endpoint);
    return u.protocol === "https:" && !u.port && !u.username && PUSH_HOSTS.some((re) => re.test(u.hostname));
  } catch {
    return false;
  }
}

async function hmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await subtle().importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle().sign("HMAC", k, data));
}

/** HKDF-SHA-256 for outputs of up to 32 bytes. */
async function hkdf(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
  const prk = await hmac(salt, ikm);
  const t = await hmac(prk, concat(info, new Uint8Array([1])));
  return t.slice(0, length);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
}

const pointToJwk = (point: Uint8Array) => ({ kty: "EC", crv: "P-256", x: b64url(point.slice(1, 33)), y: b64url(point.slice(33, 65)), ext: true });

/**
 * Encrypt a payload for one subscription (RFC 8291, aes128gcm). `testing` fixes the sender's key and
 * the salt, for the RFC's test vector only.
 */
export async function encryptPayload(payload: Uint8Array, keys: { p256dh: string; auth: string }, testing?: { senderPrivate: string; senderPublic: string; salt: string }) {
  const uaPublic = fromB64url(keys.p256dh);
  const authSecret = fromB64url(keys.auth);
  if (uaPublic.length !== 65 || uaPublic[0] !== 4 || authSecret.length !== 16) throw new Error("Bad subscription keys");
  let senderPrivate: CryptoKey;
  let senderPublic: Uint8Array;
  if (testing) {
    senderPublic = fromB64url(testing.senderPublic);
    senderPrivate = await subtle().importKey("jwk", { ...pointToJwk(senderPublic), d: testing.senderPrivate }, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  } else {
    const pair = (await subtle().generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair;
    senderPrivate = pair.privateKey;
    senderPublic = new Uint8Array(await subtle().exportKey("raw", pair.publicKey));
  }
  const uaKey = await subtle().importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await subtle().deriveBits({ name: "ECDH", public: uaKey }, senderPrivate, 256));
  const ikm = await hkdf(authSecret, shared, concat(utf8("WebPush: info\0"), uaPublic, senderPublic), 32);
  const salt = testing ? fromB64url(testing.salt) : globalThis.crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, utf8("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, utf8("Content-Encoding: nonce\0"), 12);
  const key = await subtle().importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  // One record: the payload, then 0x02 (the last record's delimiter).
  const sealed = new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv: nonce }, key, concat(payload, new Uint8Array([2]))));
  const header = new Uint8Array(16 + 4 + 1 + 65);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, 4096);
  header[20] = 65;
  header.set(senderPublic, 21);
  return concat(header, sealed);
}

// ---------- VAPID ----------

export type VapidKeys = { publicKey: string; privateJwk: JsonWebKey };

export async function makeVapidKeys(): Promise<VapidKeys> {
  const pair = (await subtle().generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  return { publicKey: b64url(await subtle().exportKey("raw", pair.publicKey)), privateJwk: await subtle().exportKey("jwk", pair.privateKey) };
}

async function vapidHeader(endpoint: string, keys: VapidKeys, subject: string, now = Date.now()) {
  const aud = new URL(endpoint).origin;
  const enc = (o: unknown) => b64url(utf8(JSON.stringify(o)));
  const unsigned = `${enc({ typ: "JWT", alg: "ES256" })}.${enc({ aud, exp: Math.floor(now / 1000) + 12 * 3600, sub: subject })}`;
  const key = await subtle().importKey("jwk", keys.privateJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sig = new Uint8Array(await subtle().sign({ name: "ECDSA", hash: "SHA-256" }, key, utf8(unsigned)));
  return `vapid t=${unsigned}.${b64url(sig)}, k=${keys.publicKey}`;
}

export type Subscription = { endpoint: string; p256dh: string; auth: string };

/**
 * Send one push. Answers "sent", "gone" (the subscription no longer exists: delete it) or "failed".
 * topic: pushes with the same topic replace each other while waiting at the push service, so a
 * device that's been off gets one notification, not a pile.
 */
export type PushErrorCategory = "permission" | "dns" | "tls" | "connection" | "invalid_request" | "unclassified";
export type PushDelivery = { state: "sent" | "gone" | "rejected" | "failed"; status?: number; reason?: "endpoint" | "keys" | "network" | "timeout"; error_category?: PushErrorCategory };

/** Do not include an exception message or cause in a response or log: either can include a push URL. */
export function classifyPushFetchError(err: unknown): { reason: "network" | "timeout"; error_category: PushErrorCategory } {
  const e = err && typeof err === "object" ? err as { name?: string; message?: string; cause?: { name?: string; code?: string; message?: string } } : {};
  const name = typeof e.name === "string" ? e.name : "";
  const code = typeof e.cause?.code === "string" ? e.cause.code : "";
  // Messages are consulted only to choose a fixed safe category, never logged or returned.
  const lower = `${typeof e.message === "string" ? e.message : ""} ${typeof e.cause?.message === "string" ? e.cause.message : ""}`.toLowerCase();
  if (name === "TimeoutError" || name === "AbortError" || code === "ETIMEDOUT" || /timed? out/.test(lower)) return { reason: "timeout", error_category: "connection" };
  if (name === "NotCapable" || name === "PermissionDenied" || code === "EACCES" || /notcapable|permission denied|not permitted|allow-net|network access denied/.test(lower)) return { reason: "network", error_category: "permission" };
  if (code === "ENOTFOUND" || code === "EAI_AGAIN" || /dns|name resolution|lookup failed/.test(lower)) return { reason: "network", error_category: "dns" };
  if (/certificate|tls handshake|ssl handshake|cert verify/.test(lower)) return { reason: "network", error_category: "tls" };
  if (/invalid header|invalid redirect value|invalid request init|unsupported header|abortsignal.timeout is not a function|bad request init/.test(lower)) return { reason: "network", error_category: "invalid_request" };
  if (["ECONNREFUSED", "ECONNRESET", "ENETUNREACH", "EHOSTUNREACH"].includes(code) || /connection refused|connection reset|connect error|network unreachable/.test(lower)) return { reason: "network", error_category: "connection" };
  return { reason: "network", error_category: "unclassified" };
}

/** Safe, fixed-host connectivity probe, used only if a device-specific test fails. */
export async function probeFcmConnection(fetchImpl: typeof fetch = fetch): Promise<{ state: "reachable" | "unreachable" | "timeout"; status?: number; category?: PushErrorCategory }> {
  try {
    const res = await fetchImpl("https://fcm.googleapis.com/", { method: "HEAD", redirect: "manual", signal: AbortSignal.timeout(3500) });
    return { state: "reachable", status: res.status }; // Any HTTP response proves the public host answered; no redirect followed.
  } catch (err) {
    const info = classifyPushFetchError(err);
    return { state: info.reason === "timeout" ? "timeout" : "unreachable", category: info.error_category };
  }
}

/** A push service accepting a request does not prove the device displayed it. Never return or log endpoints or keys. */
export async function sendPush(sub: Subscription, payload: unknown, { keys, subject, topic = "commonveil", ttl = 24 * 3600, urgency = "normal", fetchImpl = fetch }: { keys: VapidKeys; subject: string; topic?: string; ttl?: number; urgency?: "high" | "normal" | "low"; fetchImpl?: typeof fetch }): Promise<PushDelivery> {
  if (!pushEndpointOk(sub.endpoint)) return { state: "gone", reason: "endpoint" };
  let body: Uint8Array;
  let authorization: string;
  try {
    body = await encryptPayload(utf8(JSON.stringify(payload)), sub);
    authorization = await vapidHeader(sub.endpoint, keys, subject);
  } catch {
    return { state: "failed", reason: "keys" };
  }
  try {
    const res = await fetchImpl(sub.endpoint, {
      method: "POST",
      headers: {
        Authorization: authorization,
        "Content-Encoding": "aes128gcm",
        "Content-Type": "application/octet-stream",
        TTL: String(ttl),
        Urgency: urgency,
        Topic: topic,
      },
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(5000),
    });
    // Cloudflare's edge fetch rejects redirect:"error" before network I/O. Manual keeps the
    // request on its allowlisted host; never follow a redirect to an arbitrary URL.
    if (res.type === "opaqueredirect" || res.redirected || (res.status >= 300 && res.status < 400)) return { state: "rejected", status: res.status || undefined };
    if (res.status === 404 || res.status === 410) return { state: "gone", status: res.status };
    return { state: res.ok ? "sent" : "rejected", status: res.status };
  } catch (err) {
    return { state: "failed", ...classifyPushFetchError(err) };
  }
}
