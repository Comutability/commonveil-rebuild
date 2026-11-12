// Commonveil sign-in (docs/IDENTITY.md), on Base44 and self-hosted sites alike: usernames,
// passkeys, this browser's device, the owner key and getting back in. The backend is the
// "identity" function (base44/shared/handlers/identity.ts).
import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { base44, SELF_HOSTED } from "@/api/base44Client";
import { ApiError, callFn } from "@/lib/api";
import { ownerKey, signOwner, wipeOwnerKey } from "@/lib/crypto/owner";
import { clearSession, renewAccess, setSession } from "./session";

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

// ---------- proving it's really you ----------
//
// Changes to how the account is protected (passkeys, letting another browser in, the owner key,
// the email) need more than a signed-in session (docs/IDENTITY.md): a proof from this browser's
// encryption device, whose key never leaves it, or the account's password. The encryption layer
// (SecureContext) registers a prover once this browser's device is ready.

let prover = null;

/** fn(action, payloadJson) -> proof, or null when this browser has no ready encryption device. */
export function setIdentityProver(fn) {
  prover = typeof fn === "function" ? fn : null;
}

/** The app asks for the password, then calls again with { password }. */
export const PROOF_REQUIRED = "PROOF_REQUIRED";
const DEVICE_CANT_PROVE = new Set(["DEVICE_UNKNOWN", "DEVICE_NOT_ACTIVE", "PROOF_INVALID", "PROOF_EXPIRED"]);

/** Send a protected change: signed by this browser's device when it can be, else with the password. */
async function proven(action, proofAction, fields, { password } = {}) {
  if (typeof password === "string") return act(action, { ...fields, password });
  const userId = currentUserId();
  if (prover && userId) {
    const payload = JSON.stringify({ ...fields, action: proofAction, user_id: userId });
    let proof = null;
    try {
      proof = await prover(`identity.${proofAction}`, payload);
    } catch {
      proof = null;
    }
    if (proof) {
      try {
        return await act(action, { payload, proof });
      } catch (err) {
        if (!DEVICE_CANT_PROVE.has(err.code)) throw err;
      }
    }
  }
  throw new IdentityError("Enter your password to confirm it's you.", PROOF_REQUIRED);
}

function currentUserId() {
  try {
    return JSON.parse(window.localStorage.getItem("commonveil_session") || "null")?.user_id || "";
  } catch {
    return "";
  }
}

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
  // A change that moved the account's security epoch on gives this browser a token for the new one.
  if (data?.renewed_access) renewAccess(data.renewed_access.access_token, data.renewed_access.access_expires_at);
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

/** setupCode: only for a new self-hosted site's first (admin) account (docs/SELF_HOSTING.md). */
export const register = ({ username, password, ageConfirmed, setupCode }) =>
  act("register", withDevice({ username, password, age_confirmed: ageConfirmed === true, ...(setupCode ? { setup_code: setupCode } : {}) }));

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
const PROTECTED_CHANGES = new Set(["remove_passkey", "remove_email", "set_password"]);

/**
 * change: remove_passkey, disconnect_device, set_password, change_password, remove_email, confirm_age.
 * opts.password: when asked (PROOF_REQUIRED), the account's password.
 */
export const identityAction = (change, extra = {}, opts = {}) =>
  PROTECTED_CHANGES.has(change) && !(change === "set_password" && opts.unproven) ? proven("account", `account.${change}`, { change, ...extra }, opts).catch((err) => {
    // An account with no encryption device yet sets its first password with its session alone.
    if (change === "set_password" && err.code === PROOF_REQUIRED) return act("account", { change, ...extra });
    throw err;
  }) : act("account", { change, ...extra });

/** kind: "device" (only this device) or "synced" (a password manager or phone). */
export async function addPasskey(kind, name = "", opts = {}) {
  const { id, options } = await act("passkey_options", { kind, origin: origin() });
  const response = await prompt(() => startRegistration({ optionsJSON: options }));
  return proven("passkey_add", "passkey_add", { id, response, name }, opts);
}

/**
 * Record the account's owner key from its phrase or private key. Holding the key proves it's
 * yours; replacing an earlier one also needs this browser's encryption device (or the old key).
 */
export async function setOwnerKey(phraseOrKey, opts = {}) {
  const key = await ownerKey(phraseOrKey);
  try {
    const { id, challenge, realm } = await act("owner_challenge");
    const fields = {
      id,
      owner_pub: key.publicKey,
      signature: signOwner(key, { host: realm, purpose: "set-owner", challenge }),
      // If this phrase is already the account's, it vouches for itself.
      old_signature: signOwner(key, { host: realm, purpose: `replace-owner:${key.publicKey}`, challenge }),
    };
    try {
      return await proven("owner", "owner", fields, opts);
    } catch (err) {
      if (err.code !== PROOF_REQUIRED) throw err;
      return act("owner", fields);
    }
  } finally {
    wipeOwnerKey(key);
  }
}

export const pendingApprovals = () => act("approvals");
/** Turning a sign-in down needs nothing more; letting it in is a protected change. */
export const answerApproval = (id, approve, opts = {}) => (approve === true ? proven("approve", "approve", { id, approve: true }, opts) : act("approve", { id, approve: false }));

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

/**
 * This browser's sign-in has ended, or never became a Commonveil one: forget it, end any Base44
 * sign-in left from before (so it can't sign anyone back in), and go to sign in again.
 */
export function needSignIn(returnTo = "/app") {
  clearSession();
  leavePlatformSession(`/login?returnTo=${encodeURIComponent(returnTo)}`);
}