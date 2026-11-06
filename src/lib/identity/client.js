// Commonveil Identity on a self-hosted site (server/auth.mjs, docs/IDENTITY.md): usernames,
// passkeys, this browser's device, the owner key and getting back in.
import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { base44 } from "@/api/base44Client";
import { ownerKey, signOwner, wipeOwnerKey } from "@/lib/crypto/owner";

const DEVICE_KEY = "commonveil_device";
const TOKEN_KEY = "base44_access_token";

export class IdentityError extends Error {
  constructor(message, code = "", data = {}) {
    super(message);
    this.code = code;
    this.data = data;
  }
}

/** This browser's device credential for the site, if it has one. */
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
    // Private windows may refuse storage: this browser is then asked to confirm itself each time.
  }
}

/** A plain name for this browser, shown in your device list ("Firefox on Linux"). No identifiers. */
export function deviceName() {
  const ua = typeof navigator === "undefined" ? "" : navigator.userAgent || "";
  const browser = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /OPR\//.test(ua) ? "Opera" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "A browser";
  const os = /iPhone|iPad/.test(ua) ? "iOS" : /Android/.test(ua) ? "Android" : /Mac OS X/.test(ua) ? "macOS" : /Windows/.test(ua) ? "Windows" : /CrOS/.test(ua) ? "ChromeOS" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${browser} on ${os}` : browser;
}

function token() {
  try {
    return window.localStorage.getItem(TOKEN_KEY) || "";
  } catch {
    return "";
  }
}

/** POST to /api/auth/<name>. A response that signs in is applied: the session and this device are kept. */
export async function authCall(name, body = {}) {
  const t = token();
  let res;
  try {
    res = await fetch(`/api/auth/${name}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(t ? { Authorization: `Bearer ${t}` } : {}) },
      body: JSON.stringify(body),
      credentials: "omit",
      cache: "no-store",
    });
  } catch {
    throw new IdentityError("Can't reach the server.", "OFFLINE");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new IdentityError(data.error || "Something went wrong.", data.code || "", data);
  if (data.device) keepDevice(data.device);
  if (data.access_token) base44.auth.setToken(data.access_token);
  return data;
}

const withDevice = (body) => ({ ...body, device: storedDevice(), device_name: deviceName() });

export const passkeysSupported = () => typeof window !== "undefined" && Boolean(window.PublicKeyCredential);

/** Passkey prompts: a cancelled prompt reads as a plain message, not an error dump. */
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

export const register = ({ username, password }) => authCall("register", withDevice({ username, password }));

/** Answers { access_token } when signed in, or { verify } when this device must be confirmed first. */
export const login = ({ username, password }) => authCall("login", withDevice({ username, password }));

export async function loginWithPasskey() {
  const { id, options } = await authCall("passkey-login-options");
  const response = await prompt(() => startAuthentication({ optionsJSON: options }));
  return authCall("passkey-login", withDevice({ id, response }));
}

// ---------- confirming a new device ----------

export async function confirmWithPasskey(verify) {
  const { options } = await authCall("check-options", { id: verify.id });
  const response = await prompt(() => startAuthentication({ optionsJSON: options }));
  return authCall("check", { id: verify.id, method: "passkey", response });
}

export async function confirmWithKey(verify, phraseOrKey) {
  const key = await ownerKey(phraseOrKey);
  try {
    const signature = signOwner(key, { host: verify.host, purpose: "verify-device", challenge: verify.challenge });
    return await authCall("check", { id: verify.id, method: "key", signature });
  } finally {
    wipeOwnerKey(key);
  }
}

/** Ask once: answers { waiting } until a signed-in device approves, then signs in. */
export const confirmFromDevice = (verify) => authCall("check", { id: verify.id, method: "device" });

export const confirmByEmail = (verify, code = "") => authCall("check", { id: verify.id, method: "email", ...(code ? { code } : {}) });

// ---------- getting back in ----------

export async function recover({ username, method, phraseOrKey, newPassword }) {
  const start = await authCall("recover-options", { username });
  if (method === "passkey") {
    const response = await prompt(() => startAuthentication({ optionsJSON: start.options }));
    return authCall("recover", withDevice({ id: start.id, method, response, new_password: newPassword }));
  }
  const key = await ownerKey(phraseOrKey);
  try {
    const signature = signOwner(key, { host: start.host, purpose: "recover", challenge: start.challenge });
    return await authCall("recover", withDevice({ id: start.id, method: "key", signature, new_password: newPassword }));
  } finally {
    wipeOwnerKey(key);
  }
}

// ---------- your sign-in, in settings ----------

export const identityStatus = () => authCall("identity", { device_name: deviceName() });
export const identityAction = (action, extra = {}) => authCall("identity", { action, ...extra });

/** kind: "device" (only this device) or "synced" (a password manager or phone). */
export async function addPasskey(kind, name = "") {
  const { id, options } = await authCall("passkey-options", { kind });
  const response = await prompt(() => startRegistration({ optionsJSON: options }));
  return authCall("passkey-add", { id, response, name });
}

/** Record the account's owner key from its phrase or private key (proving you hold it). */
export async function setOwnerKey(phraseOrKey) {
  const key = await ownerKey(phraseOrKey);
  try {
    const { id, challenge, host } = await authCall("owner-challenge");
    return await authCall("owner", { id, owner_pub: key.publicKey, signature: signOwner(key, { host, purpose: "set-owner", challenge }) });
  } finally {
    wipeOwnerKey(key);
  }
}

export const pendingApprovals = () => authCall("approvals");
export const answerApproval = (id, approve) => authCall("approvals", { id, approve });

export function forgetDevice() {
  keepDevice(null);
}
