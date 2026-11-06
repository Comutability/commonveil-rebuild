// Commonveil sign-in (docs/IDENTITY.md), on Base44 and self-hosted sites alike: usernames,
// passkeys, this browser's device, the owner key and getting back in. The backend is the
// "identity" function (base44/shared/handlers/identity.ts).
import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { base44, SELF_HOSTED } from "@/api/base44Client";
import { ApiError, callFn } from "@/lib/api";
import { ownerKey, signOwner, wipeOwnerKey } from "@/lib/crypto/owner";
import { clearSession, setSession } from "./session";

const DEVICE_KEY = "commonveil_device";

export class IdentityError extends Error {
  constructor(message, code = "") {
    super(message);
    this.code = code;
  }
}

/** This browser's device credential, if it has one. */
export function storedDevice() {
  try {
    const d = JSON.parse(window.localStorage.getItem(DEVICE_KEY) || "null");
    return d && typeof d.id === "string" && typeof d.secret === "string" ? d : null;
  } catch {
    return null;
  }
}

function keepDevice(device) {
  try {
    if (device) window.localStorage.setItem(DEVICE_KEY, JSON.stringify(device));
    else window.localStorage.removeItem(DEVICE_KEY);
  } catch {
    // Storage refused: this browser is asked to confirm itself each time.
  }
}

export function forgetDevice() {
  keepDevice(null);
}

/** A plain name for this browser, shown in your device list ("Firefox on Linux"). No identifiers. */
export function deviceName() {
  const ua = typeof navigator === "undefined" ? "" : navigator.userAgent || "";
  const browser = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /OPR\//.test(ua) ? "Opera" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "A browser";
  const os = /iPhone|iPad/.test(ua) ? "iOS" : /Android/.test(ua) ? "Android" : /Mac OS X/.test(ua) ? "macOS" : /Windows/.test(ua) ? "Windows" : /CrOS/.test(ua) ? "ChromeOS" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${browser} on ${os}` : browser;
}

const origin = () => window.location.origin;

/** One sign-in action. An answer that signs in is applied: the session and this device are kept. */
async function act(action, body = {}) {
  let data;
  try {
    data = await callFn("identity", { action, ...body });
  } catch (err) {
    throw new IdentityError(err.message, err instanceof ApiError ? err.code : "");
  }
  if (data?.device) keepDevice(data.device);
  if (data?.session) setSession(data.session);
  return data;
}

const withDevice = (body) => ({ ...body, device: storedDevice(), device_name: deviceName() });

export const passkeysSupported = () => typeof window !== "undefined" && Boolean(window.PublicKeyCredential);

async function prompt(fn) {
  try {
    return await fn();
  } catch (err) {
    if (err?.name === "NotAllowedError" || err?.name === "AbortError") throw new IdentityError("The passkey prompt was closed. Try again when you're ready.", "CANCELLED");
    if (err?.name === "InvalidStateError") throw new IdentityError("That passkey is already set up for this account.", "EXISTS");
    throw new IdentityError(err?.message || "Passkeys didn't work in this browser.", "PASSKEY");
  }
}

// ---------- signing in ----------

export const register = ({ username, password, ageConfirmed }) => act("register", withDevice({ username, password, age_confirmed: ageConfirmed === true }));

/** Answers { session } when signed in, or { verify } when this browser must be confirmed first. */
export const login = ({ username, password }) => act("login", withDevice({ username, password }));

export async function loginWithPasskey() {
  const { id, options } = await act("passkey_login_options", { origin: origin() });
  const response = await prompt(() => startAuthentication({ optionsJSON: options }));
  return act("passkey_login", withDevice({ id, response }));
}

/**
 * Base44 only: an account made with an email, just signed in with Base44's email (or Google)
 * sign-in, moves to Commonveil sign-in. Answers { session } or { verify }. Once it has a session,
 * call leavePlatformSession() to sign out of Base44's own.
 */
export const linkPlatform = () => act("link_platform", withDevice({}));

/** Base44 only: end Base44's own sign-in (it redirects through Base44's sign-out, then to `to`). */
export function leavePlatformSession(to) {
  if (SELF_HOSTED) {
    window.location.href = to;
    return;
  }
  base44.auth.logout(new URL(to, window.location.origin).href);
}

// ---------- confirming a new device ----------

export async function confirmWithPasskey(verify) {
  const { options } = await act("check_options", { id: verify.id, origin: origin() });
  const response = await prompt(() => startAuthentication({ optionsJSON: options }));
  return act("check", { id: verify.id, method: "passkey", response });
}

export async function confirmWithKey(verify, phraseOrKey) {
  const key = await ownerKey(phraseOrKey);
  try {
    return await act("check", { id: verify.id, method: "key", signature: signOwner(key, { host: verify.realm, purpose: "verify-device", challenge: verify.challenge }) });
  } finally {
    wipeOwnerKey(key);
  }
}

/** Ask once: answers { waiting } until a signed-in device approves, then signs in. */
export const confirmFromDevice = (verify) => act("check", { id: verify.id, method: "device" });

// ---------- getting back in ----------

export async function recover({ username, method, phraseOrKey, newPassword }) {
  const start = await act("recover_options", { username, origin: origin() });
  if (method === "passkey") {
    if (!start.options) throw new IdentityError("Passkeys can't be used from this address.");
    const response = await prompt(() => startAuthentication({ optionsJSON: start.options }));
    return act("recover", withDevice({ id: start.id, method, response, new_password: newPassword }));
  }
  const key = await ownerKey(phraseOrKey);
  try {
    return await act("recover", withDevice({ id: start.id, method: "key", signature: signOwner(key, { host: start.realm, purpose: "recover", challenge: start.challenge }), new_password: newPassword }));
  } finally {
    wipeOwnerKey(key);
  }
}

// ---------- signed in ----------

export const whoAmI = () => act("me");
export const identityStatus = () => act("status");
/** change: remove_passkey, disconnect_device, set_password, change_password, remove_email. */
export const identityAction = (change, extra = {}) => act("account", { change, ...extra });

/** kind: "device" (only this device) or "synced" (a password manager or phone). */
export async function addPasskey(kind, name = "") {
  const { id, options } = await act("passkey_options", { kind, origin: origin() });
  const response = await prompt(() => startRegistration({ optionsJSON: options }));
  return act("passkey_add", { id, response, name });
}

/** Record the account's owner key from its phrase or private key (proving you hold it). */
export async function setOwnerKey(phraseOrKey) {
  const key = await ownerKey(phraseOrKey);
  try {
    const { id, challenge, realm } = await act("owner_challenge");
    return await act("owner", { id, owner_pub: key.publicKey, signature: signOwner(key, { host: realm, purpose: "set-owner", challenge }) });
  } finally {
    wipeOwnerKey(key);
  }
}

export const pendingApprovals = () => act("approvals");
export const answerApproval = (id, approve) => act("approve", { id, approve });

/** Sign out here: this session ends; the device stays known, so signing back in needs no check. */
export async function signOut() {
  let refresh = null;
  try {
    refresh = JSON.parse(window.localStorage.getItem("commonveil_session") || "null")?.refresh_token || null;
  } catch {
    refresh = null;
  }
  if (refresh) await callFn("identity", { action: "logout", refresh_token: refresh }).catch(() => {});
  clearSession();
}
