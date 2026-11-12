// This browser's Commonveil sign-in session (docs/IDENTITY.md): a short access token, sent with
// every backend call, and a refresh token that renews it. Kept in this browser's storage.
import { SELF_HOSTED, base44 } from "@/api/base44Client";

const KEY = "commonveil_session";
const RENEW_BEFORE_MS = 60_000;
const listeners = new Set();

function read() {
  try {
    const s = JSON.parse(window.localStorage.getItem(KEY) || "null");
    return s && typeof s.refresh_token === "string" && typeof s.access_token === "string" ? s : null;
  } catch {
    return null;
  }
}

let current = typeof window === "undefined" ? null : read();

function write(s) {
  current = s;
  try {
    if (s) window.localStorage.setItem(KEY, JSON.stringify(s));
    else window.localStorage.removeItem(KEY);
  } catch {
    // Storage refused (a private window): the session lasts as long as the page.
  }
  // On a self-hosted site the access token is also the bearer for files, rooms and admin pages.
  if (SELF_HOSTED) base44.auth.setToken(s ? s.access_token : "");
  for (const fn of listeners) fn(s);
}

export const hasSession = () => Boolean(current);
export const sessionUserId = () => current?.user_id || null;
export const sessionDeviceId = () => current?.device_id || null;

export function setSession(session) {
  write(session ? { ...session } : null);
}

/** A fresh access token for the same session (after the account's security epoch moved on). */
export function renewAccess(accessToken, expiresAt) {
  if (current && typeof accessToken === "string") write({ ...current, access_token: accessToken, access_expires_at: expiresAt });
}

export function clearSession() {
  write(null);
}

export function onSessionChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

let renewing = null;

/** POST straight to the sign-in function (without a session of its own, so no loop). */
async function renew(refreshToken) {
  const res = await base44.functions.invoke("identity", { action: "refresh", refresh_token: refreshToken });
  return res && typeof res === "object" && "data" in res ? res.data : res;
}

/**
 * A valid access token, renewed first if it's about to run out. Null when signed out, or when the
 * session has ended (disconnected, or expired); the session is then forgotten.
 */
export async function accessToken() {
  const s = current;
  if (!s) return null;
  if (Date.parse(s.access_expires_at) - Date.now() > RENEW_BEFORE_MS) return s.access_token;
  renewing ||= (async () => {
    try {
      const r = await renew(s.refresh_token);
      if (r?.access_token) {
        write({ ...s, access_token: r.access_token, access_expires_at: r.access_expires_at });
        return r.access_token;
      }
      clearSession();
      return null;
    } catch (err) {
      const status = err?.response?.status ?? err?.status ?? 0;
      // Offline: keep the session and try later. Refused: it's over.
      if (status === 401) clearSession();
      return status === 0 ? s.access_token : null;
    } finally {
      renewing = null;
    }
  })();
  return renewing;
}

if (typeof window !== "undefined") {
  // Another tab signed in or out.
  window.addEventListener("storage", (e) => {
    if (e.key === KEY) {
      current = read();
      for (const fn of listeners) fn(current);
    }
  });
}
