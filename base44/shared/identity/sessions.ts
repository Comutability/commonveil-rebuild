// Sessions for Commonveil sign-in (docs/IDENTITY.md).
//
// Signing in gives the app two tokens:
//   - a refresh token (30 days, stored hashed, tied to one device), and
//   - an access token (15 minutes): "cv1.<claims>.<HMAC>", checked with no database lookup, so it
//     costs nothing per request. Claims: who (u), which device (d), when it expires (x).
// The app swaps the refresh token for a new access token before the old one runs out. A
// disconnected device's refresh token stops working at once; its last access token within 15 minutes.
import { b64url, fromB64url, hmac, randomToken, sameString, sha256Hex, utf8 } from "./crypto.ts";

export const ACCESS_SECONDS = 15 * 60;
export const REFRESH_DAYS = 30;

let cachedSecret: string | null = null;

/** The site's token key: made the first time, then kept (CvSecret). */
export async function tokenSecret(sr: any): Promise<string> {
  if (cachedSecret) return cachedSecret;
  const [row] = await sr.entities.CvSecret.filter({ name: "access-tokens" }, "created_date", 1);
  if (row?.value) return (cachedSecret = row.value);
  await sr.entities.CvSecret.create({ name: "access-tokens", value: randomToken(32) });
  // Two first requests at once: the oldest key wins, for everyone.
  const [first] = await sr.entities.CvSecret.filter({ name: "access-tokens" }, "created_date", 1);
  return (cachedSecret = first.value);
}

/** For tests: forget the cached key (each test world has its own). */
export function forgetSecret() {
  cachedSecret = null;
}

export async function issueAccess(sr: any, userId: string, deviceId: string, now = Date.now()) {
  const claims = b64url(utf8(JSON.stringify({ u: userId, d: deviceId, x: Math.floor(now / 1000) + ACCESS_SECONDS })));
  const sig = await hmac(await tokenSecret(sr), `cv1.${claims}`);
  return { token: `cv1.${claims}.${sig}`, expires_at: new Date(now + ACCESS_SECONDS * 1000).toISOString() };
}

/** { userId, deviceId } for a valid access token, or null. */
export async function verifyAccess(sr: any, token: unknown, now = Date.now()): Promise<{ userId: string; deviceId: string } | null> {
  if (typeof token !== "string" || token.length > 600) return null;
  const [v, claims, sig] = token.split(".");
  if (v !== "cv1" || !claims || !sig) return null;
  const want = await hmac(await tokenSecret(sr), `cv1.${claims}`);
  if (!sameString(want, sig)) return null;
  try {
    const c = JSON.parse(new TextDecoder().decode(fromB64url(claims)));
    if (typeof c.u !== "string" || typeof c.d !== "string" || !(c.x * 1000 > now)) return null;
    return { userId: c.u, deviceId: c.d };
  } catch {
    return null;
  }
}

/** A new refresh token for this device. */
export async function issueRefresh(sr: any, userId: string, deviceId: string, now = Date.now()) {
  const token = `cvr1.${randomToken(32)}`;
  await sr.entities.CvRefresh.create({ user_id: userId, device_id: deviceId, token_hash: await sha256Hex(token), expires_at: new Date(now + REFRESH_DAYS * 86_400_000).toISOString() });
  return token;
}

/** Everything the app keeps after signing in. */
export async function signedIn(sr: any, userId: string, deviceId: string, extra: Record<string, unknown> = {}) {
  const access = await issueAccess(sr, userId, deviceId);
  return { session: { access_token: access.token, access_expires_at: access.expires_at, refresh_token: await issueRefresh(sr, userId, deviceId), user_id: userId, device_id: deviceId }, ...extra };
}

/** The refresh token's row, if it's valid and its device is still connected. */
export async function refreshRow(sr: any, token: unknown, now = Date.now()) {
  if (typeof token !== "string" || !token.startsWith("cvr1.") || token.length > 100) return null;
  const [row] = await sr.entities.CvRefresh.filter({ token_hash: await sha256Hex(token) }, "created_date", 1);
  if (!row || Date.parse(row.expires_at) < now) return null;
  const device = await sr.entities.CvDevice.get(row.device_id).catch(() => null);
  if (!device || device.user_id !== row.user_id) return null;
  return { row, device };
}

// ---------- people ----------

/**
 * A person's own record: a Base44 user (accounts made with an email before Commonveil sign-in, and
 * on self-hosted sites, people from other sites) or a Person (made with a username).
 */
export async function userRecord(sr: any, id: string): Promise<any | null> {
  if (typeof id !== "string" || !id) return null;
  const person = await sr.entities.Person.get(id).catch(() => null);
  if (person) return person;
  return sr.entities.User.get(id).catch(() => null);
}

/** Change a person's own record, whichever table it's in. */
export async function updateUserRecord(sr: any, id: string, changes: Record<string, unknown>) {
  const person = await sr.entities.Person.get(id).catch(() => null);
  if (person) return sr.entities.Person.update(id, changes);
  return sr.entities.User.update(id, changes);
}

/** Whether a record is an account at all (for checks that people still exist). */
export async function userExists(sr: any, id: string): Promise<boolean> {
  return Boolean(await userRecord(sr, id));
}

export const sameToken = sameString;
