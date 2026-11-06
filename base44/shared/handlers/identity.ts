// Commonveil sign-in (docs/IDENTITY.md), on Base44 and on self-hosted sites alike.
//
//   - New accounts are a username and a password. No email.
//   - Accounts made with an email before this (Base44 accounts) come in once through Base44's own
//     email sign-in, and are then Commonveil accounts too: they can set a password for their
//     username and stop using the email.
//   - Each account has an owner key, derived from its 24-word recovery phrase (the "private key"
//     is the same secret as one string). The site keeps the public half; a signature proves the
//     account is yours.
//   - Passkeys, on one device or synced by a password manager.
//   - A browser that signs in for the first time is confirmed with a passkey, the phrase or
//     private key, or from a device already signed in. Devices can be disconnected.
//   - Getting back in without the password takes a passkey, the phrase or the private key.
import { ApiError, cleanText, type Actions } from "../http.ts";
import { personClient } from "../rls.ts";
import { checkPassword, hashPassword, randomToken, sameString, sha256Hex, verifyEd25519 } from "../identity/crypto.ts";
import { issueAccess, refreshRow, signedIn, userRecord } from "../identity/sessions.ts";
import { authenticationOptions, PasskeyError, registrationOptions, rpIdFor, verifyAssertion, verifyRegistration } from "../identity/webauthn.ts";
import { profileActions } from "./profile.ts";

const USERNAME_RE = /^[A-Za-z0-9_]{3,20}$/;
const MIN_PASSWORD = 10;
const CHECK_MINUTES = 10;
const MAX_PASSKEYS = 20;
const MAX_DEVICES = 50;
const LOCK_AFTER = 10;
const LOCK_MINUTES = 15;
const REGISTRATIONS_PER_HOUR = 60;

/** What a site says about itself to sign-in. Self-hosted sites pass theirs; Base44 uses these. */
export type IdentityConfig = {
  realm: string; // the name owner-key signatures are bound to
  siteName: string;
  passkeyHost: (host: string) => boolean; // which page addresses passkeys may be made on
  adminFor?: (username: string, firstAccount: boolean) => boolean;
  platformCutover?: string; // Base44 accounts made after this can't come in by email
  passwordRounds?: number; // tests only
};

const envOf = (name: string) => {
  try {
    return (globalThis as any).Deno?.env?.get?.(name) || "";
  } catch {
    return "";
  }
};

/** Base44's commonveil.online, its preview address, and local development. */
export const BASE44_IDENTITY: IdentityConfig = {
  realm: envOf("CV_REALM") || "commonveil.online",
  siteName: "Commonveil",
  passkeyHost: (h) => h === "commonveil.online" || h === "www.commonveil.online" || /(^|\.)commonveil-rebuild-71d823fd\.base44\.app$/.test(h) || h === "localhost",
  adminFor: () => false,
  // Email sign-up closed when Commonveil sign-in arrived: only accounts from before can use it.
  platformCutover: "2026-11-06T04:00:00Z",
};

/** What an owner-key signature covers. The app builds the same text (src/lib/crypto/owner.js). */
export const ownerText = (realm: string, purpose: string, challenge: string) => `commonveil-owner/v1\n${realm}\n${purpose}\n${challenge}`;

const nowIso = () => new Date().toISOString();
const deny = (status: number, code: string, message: string) => new ApiError(status, code, message);
const deviceName = (s: unknown) => cleanText(typeof s === "string" ? s.slice(0, 60) : "", 60) || "A browser";

function checkNewPassword(password: unknown) {
  if (typeof password !== "string" || password.length < MIN_PASSWORD || password.length > 512) throw deny(400, "WEAK_PASSWORD", `Use at least ${MIN_PASSWORD} characters.`);
}

// ---------- storage helpers ----------

async function accountOf(sr: any, userId: string) {
  const [a] = await sr.entities.CvAccount.filter({ user_id: userId }, "created_date", 1);
  return a || null;
}

/** A local person by username (not someone from another site). */
async function userIdForName(sr: any, name: unknown): Promise<string | null> {
  const n = String(name || "").trim().replace(/^@/, "");
  if (!USERNAME_RE.test(n)) return null;
  const rows = await sr.entities.Profile.filter({ username_key: n.toLowerCase() }, "created_date", 2);
  const p = rows.find((r: any) => !r.remote);
  return p?.user_id || null;
}

async function putChallenge(sr: any, userId: string | null, purpose: string, data: Record<string, unknown>, minutes = CHECK_MINUTES) {
  const id = randomToken(32);
  await sr.entities.CvChallenge.create({ user_id: userId || "", purpose, token_hash: await sha256Hex(id), data: JSON.stringify(data), expires_at: new Date(Date.now() + minutes * 60_000).toISOString() });
  return id;
}

async function getChallenge(sr: any, id: unknown, purpose: string) {
  if (typeof id !== "string" || id.length > 100) throw deny(400, "EXPIRED", "That took too long. Start again.");
  const [row] = await sr.entities.CvChallenge.filter({ token_hash: await sha256Hex(id) }, "created_date", 1);
  if (!row || row.purpose !== purpose || Date.parse(row.expires_at) < Date.now()) throw deny(400, "EXPIRED", "That took too long. Start again.");
  return { row, data: JSON.parse(row.data || "{}") };
}

const saveChallenge = (sr: any, row: any, data: unknown) => sr.entities.CvChallenge.update(row.id, { data: JSON.stringify(data) });
const dropChallenge = (sr: any, row: any) => sr.entities.CvChallenge.delete(row.id).catch(() => null);

async function newDevice(sr: any, userId: string, name: unknown, how: string) {
  const existing = await sr.entities.CvDevice.filter({ user_id: userId }, "last_seen", MAX_DEVICES + 5);
  for (const old of existing.slice(0, Math.max(0, existing.length - MAX_DEVICES + 1))) await forgetDevice(sr, old.id);
  const secret = randomToken(32);
  const row = await sr.entities.CvDevice.create({ user_id: userId, secret_hash: await sha256Hex(secret), name: deviceName(name), confirmed_by: how, last_seen: nowIso() });
  return { id: row.id, secret };
}

async function knownDevice(sr: any, userId: string, device: any) {
  if (!device || typeof device.id !== "string" || typeof device.secret !== "string" || device.secret.length > 100) return null;
  const row = await sr.entities.CvDevice.get(device.id).catch(() => null);
  if (!row || row.user_id !== userId || !sameString(row.secret_hash, await sha256Hex(device.secret))) return null;
  await sr.entities.CvDevice.update(row.id, { last_seen: nowIso() }).catch(() => null);
  return row;
}

async function forgetDevice(sr: any, deviceId: string) {
  for (const r of await sr.entities.CvRefresh.filter({ device_id: deviceId }, "created_date", 100)) await sr.entities.CvRefresh.delete(r.id).catch(() => null);
  await sr.entities.CvDevice.delete(deviceId).catch(() => null);
}

async function passkeysOf(sr: any, userId: string) {
  return sr.entities.CvPasskey.filter({ user_id: userId }, "created_date", MAX_PASSKEYS + 5);
}

async function methodsFor(sr: any, acct: any) {
  const methods: string[] = [];
  if ((await passkeysOf(sr, acct.user_id)).length) methods.push("passkey");
  if (acct.owner_pub) methods.push("key");
  if ((await sr.entities.CvDevice.filter({ user_id: acct.user_id }, "created_date", 1)).length) methods.push("device");
  return methods;
}

/** Sign in this browser: straight in if it's known, a check if it's new and there's something to check with. */
async function arrive(sr: any, acct: any, device: unknown, name: unknown, how: string, realm: string) {
  const known = await knownDevice(sr, acct.user_id, device);
  if (known) return signedIn(sr, acct.user_id, known.id);
  const methods = await methodsFor(sr, acct);
  if (!methods.length) {
    // Nothing to confirm a new browser with yet (an account's first sign-in with Commonveil sign-in).
    const fresh = await newDevice(sr, acct.user_id, name, how);
    return signedIn(sr, acct.user_id, fresh.id, { device: fresh });
  }
  const n = new Uint32Array(1);
  globalThis.crypto.getRandomValues(n);
  const code = String(n[0] % 1_000_000).padStart(6, "0");
  const challenge = randomToken(32);
  const id = await putChallenge(sr, acct.user_id, "login", { device_name: deviceName(name), code, challenge, attempts: 0, state: "waiting", created_at: nowIso() });
  return { verify: { id, methods, code, challenge, realm } };
}

function originHost(cfg: IdentityConfig, origin: unknown) {
  try {
    return rpIdFor(String(origin || ""), cfg.passkeyHost);
  } catch (e) {
    throw deny(400, "PASSKEY_ORIGIN", (e as Error).message);
  }
}

async function passkeyCheck(sr: any, response: any, challenge: string, rpId: string, userId: string | null) {
  const credentialId = typeof response?.id === "string" ? response.id : "";
  const [row] = credentialId ? await sr.entities.CvPasskey.filter({ credential_id: credentialId }, "created_date", 1) : [];
  if (!row || (userId && row.user_id !== userId) || row.rp_id !== rpId) throw deny(401, "BAD_PASSKEY", "That passkey isn't one this account uses here.");
  try {
    const r = await verifyAssertion(response, { challenge, rpId }, { public_key: row.public_key, counter: Number(row.counter) || 0 });
    await sr.entities.CvPasskey.update(row.id, { counter: r.counter, synced: r.synced || Boolean(row.synced), last_used: nowIso() });
  } catch (e) {
    throw deny(401, "BAD_PASSKEY", e instanceof PasskeyError ? e.message : "That passkey didn't work. Try again.");
  }
  return row;
}

function requireSession(ctx: any) {
  if (!ctx.user || !ctx.session?.deviceId) throw deny(401, "SIGN_IN_REQUIRED", "Please sign in again.");
}

/** The handlers. cfg: the site's identity settings. */
export function identityActions(cfg: IdentityConfig = BASE44_IDENTITY): Actions {
  const rounds = cfg.passwordRounds;
  return {
    // ----- accounts -----

    async register({ sr, body }) {
      const username = String(body.username || "").trim().replace(/^@/, "");
      if (!USERNAME_RE.test(username)) throw deny(400, "BAD_USERNAME", "Usernames are 3 to 20 letters, numbers or underscores.");
      checkNewPassword(body.password);
      if (await userIdForName(sr, username)) throw deny(409, "USERNAME_TAKEN", "That username is taken.");
      const hourAgo = new Date(Date.now() - 3600_000).toISOString().replace("Z", "");
      const recent = await sr.entities.Person.filter({ created_date: { $gte: hourAgo } }, "-created_date", REGISTRATIONS_PER_HOUR);
      if (recent.length >= REGISTRATIONS_PER_HOUR) throw deny(429, "RATE_LIMITED", "A lot of accounts are being made right now. Try again in a while.");
      const first = !(await sr.entities.CvAccount.filter({}, "created_date", 1)).length && !(await sr.entities.User.filter({}, "created_date", 1).catch(() => [])).length;
      const role = cfg.adminFor?.(username, first) ? "admin" : "user";
      const person = await sr.entities.Person.create({ role, email: "", full_name: "" });
      const user = { ...person, email: "" };
      try {
        await profileActions.claim_username({ sr, own: personClient(sr, user, person), user, body: { username }, now: new Date() } as any);
      } catch (err) {
        await sr.entities.Person.delete(person.id).catch(() => null);
        throw err;
      }
      await sr.entities.CvAccount.create({ user_id: person.id, kind: "person", password: await hashPassword(body.password, rounds), owner_pub: "", failed: 0 });
      const device = await newDevice(sr, person.id, body.device_name, "registration");
      return signedIn(sr, person.id, device.id, { device, user: { id: person.id, role } });
    },

    /** An account from before Commonveil sign-in, just signed in with Base44's email sign-in. */
    async link_platform({ sr, body, platformUser }: any) {
      if (!platformUser?.id) throw deny(401, "SIGN_IN_REQUIRED", "Sign in with your email first.");
      let acct = await accountOf(sr, platformUser.id);
      if (!acct) {
        const made = Date.parse(/Z$/.test(String(platformUser.created_date || "")) ? platformUser.created_date : `${platformUser.created_date}Z`);
        if (cfg.platformCutover && !(made < Date.parse(cfg.platformCutover))) {
          throw deny(403, "EMAIL_SIGNUP_CLOSED", "New accounts are made with a username now, not an email. Create one from the sign-up page.");
        }
        acct = await sr.entities.CvAccount.create({ user_id: platformUser.id, kind: "platform", password: "", owner_pub: "", failed: 0, email: String(platformUser.email || "") });
      }
      if (acct.kind === "platform" && !acct.email) throw deny(403, "EMAIL_REMOVED", "This account no longer signs in with an email. Use your username.");
      return arrive(sr, acct, body.device, body.device_name, "email", cfg.realm);
    },

    /** Username and password. On a new browser, answers { verify } instead of a session. */
    async login({ sr, body }) {
      const userId = await userIdForName(sr, body.username);
      const acct = userId ? await accountOf(sr, userId) : null;
      if (acct && acct.failed >= LOCK_AFTER && Date.now() - Date.parse(acct.failed_at || "") < LOCK_MINUTES * 60_000) {
        throw deny(429, "RATE_LIMITED", "Too many wrong passwords. Try again in a few minutes, or get back in with your recovery phrase.");
      }
      const ok = await checkPassword(String(body.password || ""), acct?.password || "");
      if (!ok) {
        if (acct) await sr.entities.CvAccount.update(acct.id, { failed: (Number(acct.failed) || 0) + 1, failed_at: nowIso() });
        throw deny(401, "BAD_LOGIN", acct && !acct.password ? "This account doesn't have a password for its username yet. Sign in with your email, then set one." : "That username and password don't match.");
      }
      if (acct.failed) await sr.entities.CvAccount.update(acct.id, { failed: 0 });
      return arrive(sr, acct, body.device, body.device_name, "password", cfg.realm);
    },

    async check_options({ sr, body }) {
      const { row, data } = await getChallenge(sr, body.id, "login");
      const rpId = originHost(cfg, body.origin);
      const challenge = randomToken(32);
      const allow = (await passkeysOf(sr, row.user_id)).filter((p: any) => p.rp_id === rpId).map((p: any) => ({ id: p.credential_id, transports: p.transports }));
      await saveChallenge(sr, row, { ...data, webauthn: challenge, rp_id: rpId });
      return { options: authenticationOptions({ rpId, challenge, allow }) };
    },

    /** Confirm a new browser: method "passkey", "key" (owner-key signature) or "device" (poll). */
    async check({ sr, body }) {
      const { row, data } = await getChallenge(sr, body.id, "login");
      const acct = await accountOf(sr, row.user_id);
      if (!acct) throw deny(400, "EXPIRED", "That took too long. Start again.");
      const fail = async (message: string) => {
        data.attempts = (data.attempts || 0) + 1;
        if (data.attempts >= 5) await dropChallenge(sr, row);
        else await saveChallenge(sr, row, data);
        throw deny(401, "CHECK_FAILED", message);
      };
      if (body.method === "passkey") {
        if (!data.webauthn) await fail("Start again.");
        try {
          await passkeyCheck(sr, body.response, data.webauthn, data.rp_id, row.user_id);
        } catch (e) {
          await fail((e as Error).message);
        }
      } else if (body.method === "key") {
        const ok = acct.owner_pub && typeof body.signature === "string" && (await verifyEd25519(acct.owner_pub, ownerText(cfg.realm, "verify-device", data.challenge), body.signature));
        if (!ok) await fail("That recovery phrase or private key isn't this account's.");
      } else if (body.method === "device") {
        if (data.state === "denied") {
          await dropChallenge(sr, row);
          throw deny(403, "DENIED", "That sign-in was turned down on your other device.");
        }
        if (data.state !== "approved") return { waiting: true };
      } else {
        throw deny(400, "BAD_METHOD", "Choose how to confirm this device.");
      }
      await dropChallenge(sr, row);
      const device = await newDevice(sr, row.user_id, data.device_name, body.method);
      return signedIn(sr, row.user_id, device.id, { device });
    },

    // ----- passkeys, signed out -----

    async passkey_login_options({ sr, body }) {
      const rpId = originHost(cfg, body.origin);
      const challenge = randomToken(32);
      const id = await putChallenge(sr, null, "passkey-login", { challenge, rp_id: rpId }, 5);
      return { id, options: authenticationOptions({ rpId, challenge, allow: [] }) };
    },

    async passkey_login({ sr, body }) {
      const { row, data } = await getChallenge(sr, body.id, "passkey-login");
      await dropChallenge(sr, row);
      const pk = await passkeyCheck(sr, body.response, data.challenge, data.rp_id, null);
      const acct = await accountOf(sr, pk.user_id);
      if (!acct) throw deny(401, "BAD_PASSKEY", "That passkey isn't one this site knows.");
      const known = await knownDevice(sr, pk.user_id, body.device);
      if (known) return signedIn(sr, pk.user_id, known.id);
      const fresh = await newDevice(sr, pk.user_id, body.device_name, "passkey");
      return signedIn(sr, pk.user_id, fresh.id, { device: fresh });
    },

    // ----- getting back in -----

    /** Says nothing about whether the account exists. */
    async recover_options({ sr, body }) {
      const userId = await userIdForName(sr, body.username);
      let rpId = "";
      try {
        rpId = rpIdFor(String(body.origin || ""), cfg.passkeyHost);
      } catch {
        rpId = "";
      }
      const challenge = randomToken(32);
      const webauthn = randomToken(32);
      const allow = userId && rpId ? (await passkeysOf(sr, userId)).filter((p: any) => p.rp_id === rpId).map((p: any) => ({ id: p.credential_id, transports: p.transports })) : [];
      const id = await putChallenge(sr, userId, "recover", { challenge, webauthn, rp_id: rpId });
      return { id, challenge, realm: cfg.realm, options: rpId ? authenticationOptions({ rpId, challenge: webauthn, allow }) : null };
    },

    /** Prove it with the phrase or private key ("key"), or a passkey, and choose a new password. */
    async recover({ sr, body }) {
      checkNewPassword(body.new_password);
      const { row, data } = await getChallenge(sr, body.id, "recover");
      await dropChallenge(sr, row);
      const acct = row.user_id ? await accountOf(sr, row.user_id) : null;
      const nope = deny(401, "RECOVER_FAILED", "That didn't match this account. Check the username and try again.");
      if (!acct) throw nope;
      if (body.method === "key") {
        if (!acct.owner_pub || typeof body.signature !== "string" || !(await verifyEd25519(acct.owner_pub, ownerText(cfg.realm, "recover", data.challenge), body.signature))) throw nope;
      } else if (body.method === "passkey") {
        try {
          await passkeyCheck(sr, body.response, data.webauthn, data.rp_id, acct.user_id);
        } catch {
          throw nope;
        }
      } else {
        throw nope;
      }
      await sr.entities.CvAccount.update(acct.id, { password: await hashPassword(body.new_password, rounds), failed: 0 });
      // Every session is signed out; devices stay connected.
      for (const r of await sr.entities.CvRefresh.filter({ user_id: acct.user_id }, "created_date", 500)) await sr.entities.CvRefresh.delete(r.id).catch(() => null);
      const known = await knownDevice(sr, acct.user_id, body.device);
      if (known) return signedIn(sr, acct.user_id, known.id);
      const fresh = await newDevice(sr, acct.user_id, body.device_name, body.method);
      return signedIn(sr, acct.user_id, fresh.id, { device: fresh });
    },

    // ----- sessions -----

    async refresh({ sr, body }) {
      const r = await refreshRow(sr, body.refresh_token);
      if (!r) throw deny(401, "SIGN_IN_REQUIRED", "Please sign in again.");
      await sr.entities.CvDevice.update(r.device.id, { last_seen: nowIso() }).catch(() => null);
      const access = await issueAccess(sr, r.row.user_id, r.device.id);
      return { access_token: access.token, access_expires_at: access.expires_at, user_id: r.row.user_id, device_id: r.device.id };
    },

    async logout({ sr, body }) {
      const r = await refreshRow(sr, body.refresh_token);
      if (r) await sr.entities.CvRefresh.delete(r.row.id).catch(() => null);
      return { ok: true };
    },

    async me(ctx: any) {
      requireSession(ctx);
      const rec = await userRecord(ctx.sr, ctx.user.id);
      if (!rec) throw deny(401, "SIGN_IN_REQUIRED", "Please sign in again.");
      return { user: { id: rec.id, role: rec.role || "user", email: rec.email || "", full_name: rec.full_name || "", site_owner: Boolean(rec.site_owner), created_date: rec.created_date } };
    },

    // ----- your sign-in, in settings -----

    async status(ctx: any) {
      requireSession(ctx);
      const { sr, user, session } = ctx;
      const acct = await accountOf(sr, user.id);
      return {
        kind: acct?.kind || "person",
        has_password: Boolean(acct?.password),
        email: acct?.kind === "platform" ? acct.email || "" : "",
        email_retiring: Boolean(acct?.kind === "platform" && acct.email),
        owner: Boolean(acct?.owner_pub),
        owner_set_at: acct?.owner_set_at || null,
        passkeys: (await passkeysOf(sr, user.id)).map((p: any) => ({ id: p.id, name: p.name, synced: Boolean(p.synced), created_at: p.created_date, last_used: p.last_used || null, here: true })),
        devices: (await sr.entities.CvDevice.filter({ user_id: user.id }, "-last_seen", MAX_DEVICES)).map((d: any) => ({ id: d.id, name: d.name, created_at: d.created_date, last_seen: d.last_seen, confirmed_by: d.confirmed_by, current: d.id === session.deviceId })),
      };
    },

    async account(ctx: any) {
      requireSession(ctx);
      const { sr, user, body, session } = ctx;
      const acct = await accountOf(sr, user.id);
      if (!acct) throw deny(404, "NOT_FOUND", "No sign-in for this account.");
      switch (body.change) {
        case "remove_passkey": {
          const pk = await sr.entities.CvPasskey.get(String(body.id || "")).catch(() => null);
          if (pk && pk.user_id === user.id) await sr.entities.CvPasskey.delete(pk.id);
          return { ok: true };
        }
        case "disconnect_device": {
          const d = await sr.entities.CvDevice.get(String(body.id || "")).catch(() => null);
          if (!d || d.user_id !== user.id) throw deny(404, "NOT_FOUND", "That device isn't connected.");
          await forgetDevice(sr, d.id);
          return { ok: true, signed_out: d.id === session.deviceId };
        }
        case "set_password": {
          if (acct.password) throw deny(409, "HAS_PASSWORD", "You already have a password. Change it instead.");
          checkNewPassword(body.new_password);
          await sr.entities.CvAccount.update(acct.id, { password: await hashPassword(body.new_password, rounds) });
          return { ok: true };
        }
        case "change_password": {
          if (!(await checkPassword(String(body.password || ""), acct.password || ""))) throw deny(401, "BAD_LOGIN", "That isn't your current password.");
          checkNewPassword(body.new_password);
          await sr.entities.CvAccount.update(acct.id, { password: await hashPassword(body.new_password, rounds) });
          return { ok: true };
        }
        case "remove_email": {
          if (acct.kind !== "platform") return { ok: true };
          if (!acct.password) throw deny(409, "NEEDS_PASSWORD", "Set a password for your username first.");
          if (!acct.owner_pub) throw deny(409, "NEEDS_OWNER", "Confirm your recovery phrase first, so you can always get back in.");
          await sr.entities.CvAccount.update(acct.id, { email: "" });
          return { ok: true };
        }
        default:
          throw deny(400, "BAD_ACTION", "Unknown change.");
      }
    },

    async approvals(ctx: any) {
      requireSession(ctx);
      const { sr, user } = ctx;
      const rows = await sr.entities.CvChallenge.filter({ user_id: user.id, purpose: "login" }, "-created_date", 10);
      const out = [];
      for (const r of rows) {
        if (Date.parse(r.expires_at) < Date.now()) continue;
        const d = JSON.parse(r.data || "{}");
        if (d.state === "waiting") out.push({ id: r.id, device_name: d.device_name, code: d.code, created_at: d.created_at });
      }
      return { approvals: out };
    },

    async approve(ctx: any) {
      requireSession(ctx);
      const { sr, user, body } = ctx;
      const r = await sr.entities.CvChallenge.get(String(body.id || "")).catch(() => null);
      if (!r || r.user_id !== user.id || r.purpose !== "login" || Date.parse(r.expires_at) < Date.now()) throw deny(404, "NOT_FOUND", "That sign-in has gone.");
      const d = JSON.parse(r.data || "{}");
      await sr.entities.CvChallenge.update(r.id, { data: JSON.stringify({ ...d, state: body.approve === true ? "approved" : "denied", approved_by: ctx.session.deviceId }) });
      return { ok: true };
    },

    // ----- passkeys, signed in -----

    async passkey_options(ctx: any) {
      requireSession(ctx);
      const { sr, user, body } = ctx;
      const rpId = originHost(cfg, body.origin);
      const existing = await passkeysOf(sr, user.id);
      if (existing.length >= MAX_PASSKEYS) throw deny(409, "TOO_MANY", `You can have up to ${MAX_PASSKEYS} passkeys. Remove one first.`);
      const [profile] = await sr.entities.Profile.filter({ user_id: user.id }, "created_date", 1);
      const kind = body.kind === "device" ? "device" : "synced";
      const challenge = randomToken(32);
      const id = await putChallenge(sr, user.id, "passkey-reg", { challenge, kind, rp_id: rpId }, 5);
      const options = registrationOptions({ rpId, rpName: cfg.siteName, userId: user.id, userName: profile?.username || "commonveil", challenge, kind, exclude: existing.filter((p: any) => p.rp_id === rpId).map((p: any) => ({ id: p.credential_id, transports: p.transports })) });
      return { id, options };
    },

    async passkey_add(ctx: any) {
      requireSession(ctx);
      const { sr, user, body } = ctx;
      const { row, data } = await getChallenge(sr, body.id, "passkey-reg");
      if (row.user_id !== user.id) throw deny(400, "EXPIRED", "Start again.");
      let info;
      try {
        info = await verifyRegistration(body.response, { challenge: data.challenge, rpId: data.rp_id });
      } catch (e) {
        throw deny(400, "BAD_PASSKEY", e instanceof PasskeyError ? e.message : "That passkey couldn't be added. Try again.");
      }
      await dropChallenge(sr, row);
      if ((await sr.entities.CvPasskey.filter({ credential_id: info.credentialId }, "created_date", 1)).length) throw deny(409, "EXISTS", "That passkey is already set up.");
      const name = cleanText(typeof body.name === "string" ? body.name.slice(0, 60) : "", 60) || (info.synced ? "Synced passkey" : "Passkey on this device");
      const pk = await sr.entities.CvPasskey.create({ user_id: user.id, credential_id: info.credentialId, public_key: info.publicKey, alg: info.alg, counter: info.counter, transports: info.transports, synced: info.synced, rp_id: data.rp_id, name, last_used: "" });
      return { ok: true, passkey: { id: pk.id, synced: info.synced } };
    },

    // ----- the owner key -----

    async owner_challenge(ctx: any) {
      requireSession(ctx);
      const challenge = randomToken(32);
      const id = await putChallenge(ctx.sr, ctx.user.id, "owner-set", { challenge }, 5);
      return { id, challenge, realm: cfg.realm };
    },

    async owner(ctx: any) {
      requireSession(ctx);
      const { sr, user, body } = ctx;
      const { row, data } = await getChallenge(sr, body.id, "owner-set");
      if (row.user_id !== user.id) throw deny(400, "EXPIRED", "Start again.");
      if (typeof body.owner_pub !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(body.owner_pub)) throw deny(400, "BAD_KEY", "That key isn't valid.");
      if (typeof body.signature !== "string" || !(await verifyEd25519(body.owner_pub, ownerText(cfg.realm, "set-owner", data.challenge), body.signature))) throw deny(400, "BAD_KEY", "That key couldn't be confirmed.");
      await dropChallenge(sr, row);
      const acct = await accountOf(sr, user.id);
      if (!acct) throw deny(404, "NOT_FOUND", "No sign-in for this account.");
      await sr.entities.CvAccount.update(acct.id, { owner_pub: body.owner_pub, owner_set_at: nowIso() });
      return { ok: true };
    },
  };
}

/** Remove everything an account signs in with (account deletion). */
export async function removeSignIn(sr: any, userId: string) {
  for (const name of ["CvRefresh", "CvDevice", "CvPasskey", "CvChallenge", "CvAccount"]) {
    for (;;) {
      const rows = await sr.entities[name].filter({ user_id: userId }, "created_date", 100).catch(() => []);
      if (!rows.length) break;
      for (const r of rows) await sr.entities[name].delete(r.id).catch(() => null);
      if (rows.length < 100) break;
    }
  }
}
