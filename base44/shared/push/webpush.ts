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
export async function sendPush(sub: Subscription, payload: unknown, { keys, subject, topic = "commonveil", ttl = 24 * 3600, urgency = "normal", fetchImpl = fetch }: { keys: VapidKeys; subject: string; topic?: string; ttl?: number; urgency?: "high" | "normal" | "low"; fetchImpl?: typeof fetch }) {
  if (!pushEndpointOk(sub.endpoint)) return "gone";
  const body = await encryptPayload(utf8(JSON.stringify(payload)), sub);
  try {
    const res = await fetchImpl(sub.endpoint, {
      method: "POST",
      headers: {
        Authorization: await vapidHeader(sub.endpoint, keys, subject),
        "Content-Encoding": "aes128gcm",
        "Content-Type": "application/octet-stream",
        TTL: String(ttl),
        Urgency: urgency,
        Topic: topic,
      },
      body,
      redirect: "error",
      signal: AbortSignal.timeout(5000),
    });
    if (res.status === 404 || res.status === 410) return "gone";
    return res.ok ? "sent" : "failed";
  } catch {
    return "failed";
  }
}
