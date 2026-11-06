// Sign-in for a self-hosted site: Commonveil Identity (docs/IDENTITY.md).
//
//   - An account is a username and a password. There's no email for new accounts.
//   - Each account has an owner key: an Ed25519 key derived from its 24-word recovery phrase (the
//     "private key" is the same secret, written as one string). This site keeps only the public
//     half, and anything signed with the private half proves the account is yours.
//   - Passkeys, on one device or synced by a password manager, sign in without a password.
//   - Each browser that signs in is a device. A device this site hasn't seen before must be
//     confirmed with a passkey, the phrase or private key, or from a device already signed in.
//     Devices are listed in settings and can be disconnected.
//   - Getting an account back without its password takes a passkey, the phrase or the private key.
//
// Accounts made with an email before this keep working: they can sign in with it until they've
// set up a passkey or confirmed their phrase, and are asked to. Email resets end once they have.
//
// Stored here: a scrypt hash of each password, the owner public key, passkey public keys, hashes of
// device secrets and session tokens, and devices' names (like "Firefox on Linux"). No IP addresses.
// None of it can read anyone's messages: those keys live on people's devices.
import crypto from "node:crypto";
import { promisify } from "node:util";
import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";
import { verifyEd25519 } from "./federation/net.mjs";

const scrypt = promisify(crypto.scrypt);
const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const SESSION_DAYS = 30;
const CODE_MINUTES = 15;
const RESET_MINUTES = 60;
const CHECK_MINUTES = 10;
const MIN_PASSWORD = 10;
const MAX_PASSKEYS = 20;
const MAX_DEVICES = 50;

export class AuthError extends Error {
  constructor(status, message, code = "AUTH") {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");
const token = () => crypto.randomBytes(32).toString("base64url");
const newId = () => crypto.randomBytes(12).toString("hex");
const normEmail = (e) => String(e || "").trim().toLowerCase();
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/;
const USERNAME_RE = /^[A-Za-z0-9_]{3,20}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const nowIso = () => new Date().toISOString();
const cleanName = (s, fallback) => String(s || "").replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, 60) || fallback;

/** What an owner-key signature covers. The app builds the same text (src/lib/identity/owner.js). */
export const ownerText = (host, purpose, challenge) => `commonveil-owner/v1\n${host}\n${purpose}\n${challenge}`;

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt, 32, SCRYPT);
  return `scrypt$${SCRYPT.N}$${salt.toString("base64")}$${key.toString("base64")}`;
}

async function checkPassword(password, stored) {
  const [kind, n, salt, key] = String(stored || "").split("$");
  if (kind !== "scrypt") return false;
  const want = Buffer.from(key, "base64");
  const got = await scrypt(password, Buffer.from(salt, "base64"), want.length, { ...SCRYPT, N: Number(n) });
  return crypto.timingSafeEqual(want, got);
}

function checkNewPassword(password) {
  if (typeof password !== "string" || password.length < MIN_PASSWORD || password.length > 512) throw new AuthError(400, `Use at least ${MIN_PASSWORD} characters.`, "WEAK_PASSWORD");
}

/** A small fixed-window limiter, per key, in memory. */
class Limiter {
  constructor(max, windowMs) {
    this.max = max;
    this.windowMs = windowMs;
    this.hits = new Map();
  }
  hit(key) {
    const now = Date.now();
    const h = this.hits.get(key);
    if (!h || now - h.at > this.windowMs) {
      this.hits.set(key, { at: now, n: 1 });
      if (this.hits.size > 50_000) this.hits.clear();
      return true;
    }
    h.n += 1;
    return h.n <= this.max;
  }
}

export class Auth {
  /**
   * store: the Store. mail: { enabled, send({to, subject, body}) }. config: { siteUrl, host, siteName,
   * adminEmails, adminUsernames, openRegistration }.
   */
  constructor({ store, mail, config }) {
    this.store = store;
    this.mail = mail;
    this.config = config;
    this.rpID = config.host;
    this.origin = new URL(config.siteUrl).origin;
    /** Set by the app: claims the username for a new account (throws if it can't). */
    this.onRegistered = null;
    const db = store.db;
    this.#migrate(db);
    this.q = {
      byEmail: db.prepare("SELECT * FROM auth_accounts WHERE email = ?"),
      byUser: db.prepare("SELECT * FROM auth_accounts WHERE user_id = ?"),
      insert: db.prepare("INSERT INTO auth_accounts (user_id, email, password, verified, created_at) VALUES (?, ?, ?, ?, ?)"),
      setPassword: db.prepare("UPDATE auth_accounts SET password = ? WHERE user_id = ?"),
      setOwner: db.prepare("UPDATE auth_accounts SET owner_pub = ?, owner_set_at = ? WHERE user_id = ?"),
      dropEmail: db.prepare("UPDATE auth_accounts SET email = NULL WHERE user_id = ?"),
      verify: db.prepare("UPDATE auth_accounts SET verified = 1 WHERE user_id = ?"),
      count: db.prepare("SELECT COUNT(*) AS n FROM auth_accounts"),
      removeAccount: db.prepare("DELETE FROM auth_accounts WHERE user_id = ?"),

      session: db.prepare("SELECT * FROM auth_sessions WHERE token_hash = ?"),
      addSession: db.prepare("INSERT INTO auth_sessions (token_hash, user_id, created_at, expires_at, device_id) VALUES (?, ?, ?, ?, ?)"),
      bindSession: db.prepare("UPDATE auth_sessions SET device_id = ? WHERE token_hash = ?"),
      dropSession: db.prepare("DELETE FROM auth_sessions WHERE token_hash = ?"),
      dropSessions: db.prepare("DELETE FROM auth_sessions WHERE user_id = ?"),
      dropDeviceSessions: db.prepare("DELETE FROM auth_sessions WHERE device_id = ?"),
      dropExpired: db.prepare("DELETE FROM auth_sessions WHERE expires_at < ?"),

      device: db.prepare("SELECT * FROM auth_devices WHERE id = ?"),
      devices: db.prepare("SELECT * FROM auth_devices WHERE user_id = ? ORDER BY last_seen DESC"),
      deviceCount: db.prepare("SELECT COUNT(*) AS n FROM auth_devices WHERE user_id = ?"),
      addDevice: db.prepare("INSERT INTO auth_devices (id, user_id, secret_hash, name, created_at, last_seen, confirmed_by) VALUES (?, ?, ?, ?, ?, ?, ?)"),
      seenDevice: db.prepare("UPDATE auth_devices SET last_seen = ? WHERE id = ?"),
      dropDevice: db.prepare("DELETE FROM auth_devices WHERE id = ?"),
      dropDevices: db.prepare("DELETE FROM auth_devices WHERE user_id = ?"),
      oldestDevice: db.prepare("SELECT id FROM auth_devices WHERE user_id = ? ORDER BY last_seen ASC LIMIT 1"),

      passkey: db.prepare("SELECT * FROM auth_passkeys WHERE id = ?"),
      passkeys: db.prepare("SELECT * FROM auth_passkeys WHERE user_id = ? ORDER BY created_at"),
      addPasskey: db.prepare("INSERT INTO auth_passkeys (id, user_id, public_key, counter, transports, synced, name, created_at, last_used) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"),
      usePasskey: db.prepare("UPDATE auth_passkeys SET counter = ?, last_used = ?, synced = ? WHERE id = ?"),
      dropPasskey: db.prepare("DELETE FROM auth_passkeys WHERE id = ? AND user_id = ?"),
      dropPasskeys: db.prepare("DELETE FROM auth_passkeys WHERE user_id = ?"),

      challenge: db.prepare("SELECT * FROM auth_challenges WHERE id = ?"),
      putChallenge: db.prepare("INSERT INTO auth_challenges (id, user_id, purpose, data, expires_at) VALUES (?, ?, ?, ?, ?)"),
      saveChallenge: db.prepare("UPDATE auth_challenges SET data = ? WHERE id = ?"),
      dropChallenge: db.prepare("DELETE FROM auth_challenges WHERE id = ?"),
      dropChallenges: db.prepare("DELETE FROM auth_challenges WHERE user_id = ?"),
      dropOldChallenges: db.prepare("DELETE FROM auth_challenges WHERE expires_at < ?"),
      pendingFor: db.prepare("SELECT * FROM auth_challenges WHERE user_id = ? AND purpose = 'login' AND expires_at > ? ORDER BY expires_at DESC LIMIT 10"),

      putCode: db.prepare("INSERT INTO auth_codes (email, purpose, code_hash, expires_at, attempts) VALUES (?, ?, ?, ?, 0) ON CONFLICT(email, purpose) DO UPDATE SET code_hash = excluded.code_hash, expires_at = excluded.expires_at, attempts = 0"),
      getCode: db.prepare("SELECT * FROM auth_codes WHERE email = ? AND purpose = ?"),
      bumpCode: db.prepare("UPDATE auth_codes SET attempts = attempts + 1 WHERE email = ? AND purpose = ?"),
      dropCode: db.prepare("DELETE FROM auth_codes WHERE email = ? AND purpose = ?"),
      dropCodesFor: db.prepare("DELETE FROM auth_codes WHERE email = ?"),
    };
    this.loginLimit = new Limiter(10, 15 * 60_000);
    this.mailLimit = new Limiter(5, 60 * 60_000);
    this.checkLimit = new Limiter(20, 15 * 60_000);
  }

  #migrate(db) {
    const cols = db.prepare("PRAGMA table_info(auth_accounts)").all().map((c) => c.name);
    if (cols.length && !cols.includes("owner_pub")) {
      // Before Commonveil Identity, every account had an email. Now it's optional.
      db.exec(`CREATE TABLE auth_accounts_v2 (user_id TEXT PRIMARY KEY, email TEXT UNIQUE, password TEXT NOT NULL, verified INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, owner_pub TEXT, owner_set_at TEXT);
        INSERT INTO auth_accounts_v2 (user_id, email, password, verified, created_at) SELECT user_id, email, password, verified, created_at FROM auth_accounts;
        DROP TABLE auth_accounts;
        ALTER TABLE auth_accounts_v2 RENAME TO auth_accounts;`);
    }
    db.exec(`CREATE TABLE IF NOT EXISTS auth_accounts (user_id TEXT PRIMARY KEY, email TEXT UNIQUE, password TEXT NOT NULL, verified INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, owner_pub TEXT, owner_set_at TEXT)`);
    db.exec(`CREATE TABLE IF NOT EXISTS auth_sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at TEXT NOT NULL, expires_at INTEGER NOT NULL, device_id TEXT)`);
    if (!db.prepare("PRAGMA table_info(auth_sessions)").all().some((c) => c.name === "device_id")) db.exec("ALTER TABLE auth_sessions ADD COLUMN device_id TEXT");
    db.exec(`CREATE INDEX IF NOT EXISTS auth_sessions_user ON auth_sessions(user_id)`);
    db.exec(`CREATE INDEX IF NOT EXISTS auth_sessions_device ON auth_sessions(device_id)`);
    db.exec(`CREATE TABLE IF NOT EXISTS auth_codes (email TEXT NOT NULL, purpose TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (email, purpose))`);
    db.exec(`CREATE TABLE IF NOT EXISTS auth_devices (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, secret_hash TEXT NOT NULL, name TEXT NOT NULL, created_at TEXT NOT NULL, last_seen TEXT NOT NULL, confirmed_by TEXT NOT NULL)`);
    db.exec(`CREATE INDEX IF NOT EXISTS auth_devices_user ON auth_devices(user_id)`);
    db.exec(`CREATE TABLE IF NOT EXISTS auth_passkeys (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, public_key TEXT NOT NULL, counter INTEGER NOT NULL, transports TEXT NOT NULL, synced INTEGER NOT NULL, name TEXT NOT NULL, created_at TEXT NOT NULL, last_used TEXT)`);
    db.exec(`CREATE INDEX IF NOT EXISTS auth_passkeys_user ON auth_passkeys(user_id)`);
    db.exec(`CREATE TABLE IF NOT EXISTS auth_challenges (id TEXT PRIMARY KEY, user_id TEXT, purpose TEXT NOT NULL, data TEXT NOT NULL, expires_at INTEGER NOT NULL)`);
    db.exec(`CREATE INDEX IF NOT EXISTS auth_challenges_user ON auth_challenges(user_id)`);
  }

  /** Email codes are used only when the site can send email (accounts made before usernames). */
  get needsVerification() {
    return Boolean(this.mail?.enabled);
  }

  // ---------- helpers ----------

  #roleFor({ email = "", username = "" }) {
    if (email && this.config.adminEmails.includes(email)) return "admin";
    if (username && (this.config.adminUsernames || []).includes(username.toLowerCase())) return "admin";
    return Number(this.q.count.get().n) === 0 ? "admin" : "user";
  }

  async #userIdFor(name) {
    const s = String(name || "").trim();
    if (s.includes("@")) return this.q.byEmail.get(normEmail(s))?.user_id || null;
    if (!USERNAME_RE.test(s.replace(/^@/, ""))) return null;
    const [p] = await this.store.entities.Profile.filter({ username_key: s.replace(/^@/, "").toLowerCase() }, "created_date", 1);
    return p?.user_id || null;
  }

  async #usernameOf(userId) {
    const [p] = await this.store.entities.Profile.filter({ user_id: userId }, "created_date", 1);
    return p?.username || "";
  }

  #issueSession(userId, deviceId) {
    const t = token();
    this.q.addSession.run(sha256(t), userId, nowIso(), Date.now() + SESSION_DAYS * 86_400_000, deviceId || null);
    if (Math.random() < 0.05) {
      this.q.dropExpired.run(Date.now());
      this.q.dropOldChallenges.run(Date.now());
    }
    return t;
  }

  /** A device for this account, confirmed by `how`. Answers the secret it signs in with next time. */
  #newDevice(userId, name, how) {
    // A long-forgotten device makes way rather than blocking a new one.
    while (Number(this.q.deviceCount.get(userId).n) >= MAX_DEVICES) {
      const old = this.q.oldestDevice.get(userId);
      this.q.dropDeviceSessions.run(old.id);
      this.q.dropDevice.run(old.id);
    }
    const id = newId();
    const secret = token();
    this.q.addDevice.run(id, userId, sha256(secret), cleanName(name, "A browser"), nowIso(), nowIso(), how);
    return { id, secret, user_id: userId };
  }

  #knownDevice(userId, device) {
    if (!device || typeof device.id !== "string" || typeof device.secret !== "string") return null;
    const row = this.q.device.get(device.id);
    if (!row || row.user_id !== userId) return null;
    const a = Buffer.from(row.secret_hash);
    const b = Buffer.from(sha256(device.secret));
    return a.length === b.length && crypto.timingSafeEqual(a, b) ? row : null;
  }

  #signedIn(userId, deviceId, extra = {}) {
    return { access_token: this.#issueSession(userId, deviceId), ...extra };
  }

  #challenge(id, purpose) {
    const row = this.q.challenge.get(String(id || ""));
    if (!row || row.purpose !== purpose || row.expires_at < Date.now()) throw new AuthError(400, "That took too long. Start again.", "EXPIRED");
    return { ...row, data: JSON.parse(row.data) };
  }

  #putChallenge(userId, purpose, data, minutes = CHECK_MINUTES) {
    const id = token();
    this.q.putChallenge.run(id, userId, purpose, JSON.stringify(data), Date.now() + minutes * 60_000);
    return id;
  }

  #ownerOk(acct, purpose, challenge, signature) {
    if (!acct?.owner_pub || typeof signature !== "string" || !B64URL_RE.test(signature)) return false;
    return verifyEd25519(acct.owner_pub, ownerText(this.rpID, purpose, challenge), signature);
  }

  #methodsFor(acct) {
    const methods = [];
    if (this.q.passkeys.all(acct.user_id).length) methods.push("passkey");
    if (acct.owner_pub) methods.push("key");
    if (Number(this.q.deviceCount.get(acct.user_id).n) > 0) methods.push("device");
    if (acct.email && this.mail?.enabled) methods.push("email");
    return methods;
  }

  async #passkeyOptions(userId) {
    const allow = userId ? this.q.passkeys.all(userId).map((p) => ({ id: p.id, transports: JSON.parse(p.transports) })) : [];
    return generateAuthenticationOptions({ rpID: this.rpID, userVerification: "preferred", allowCredentials: allow });
  }

  /** Check a passkey's answer to a challenge. Answers the passkey's row (and records its use). */
  async #passkeyOk(response, expectedChallenge, userId = null) {
    const id = typeof response?.id === "string" ? response.id : "";
    const row = id ? this.q.passkey.get(id) : null;
    if (!row || (userId && row.user_id !== userId)) throw new AuthError(401, "That passkey isn't one this account uses.", "BAD_PASSKEY");
    let result;
    try {
      result = await verifyAuthenticationResponse({
        response,
        expectedChallenge,
        expectedOrigin: this.origin,
        expectedRPID: this.rpID,
        requireUserVerification: false,
        credential: { id: row.id, publicKey: Buffer.from(row.public_key, "base64url"), counter: row.counter, transports: JSON.parse(row.transports) },
      });
    } catch {
      throw new AuthError(401, "That passkey didn't work. Try again.", "BAD_PASSKEY");
    }
    if (!result.verified) throw new AuthError(401, "That passkey didn't work. Try again.", "BAD_PASSKEY");
    this.q.usePasskey.run(result.authenticationInfo.newCounter, nowIso(), result.authenticationInfo.credentialBackedUp ? 1 : row.synced, row.id);
    return row;
  }

  // ---------- accounts ----------

  /** A new account: a username and a password. The first browser it's made on is its first device. */
  async register({ username, password, device_name }, ip = "") {
    username = String(username || "").trim().replace(/^@/, "");
    if (!this.config.openRegistration && Number(this.q.count.get().n) > 0) throw new AuthError(403, "This site isn't taking new accounts.", "CLOSED");
    if (!USERNAME_RE.test(username)) throw new AuthError(400, "Usernames are 3 to 20 letters, numbers or underscores.", "BAD_USERNAME");
    checkNewPassword(password);
    if (!this.loginLimit.hit(`reg:${ip}`)) throw new AuthError(429, "Too many attempts. Try again later.", "RATE_LIMITED");
    if (await this.#userIdFor(username)) throw new AuthError(409, "That username is taken.", "USERNAME_TAKEN");
    const role = this.#roleFor({ username });
    const user = await this.store.entities.User.create({ email: "", role, full_name: "" });
    this.q.insert.run(user.id, null, await hashPassword(password), 1, nowIso());
    try {
      await this.onRegistered?.(user, username);
    } catch (err) {
      this.q.removeAccount.run(user.id);
      await this.store.entities.User.delete(user.id).catch(() => {});
      throw new AuthError(err?.status === 409 ? 409 : 400, err?.message || "That username isn't available.", err?.code || "USERNAME_TAKEN");
    }
    const device = this.#newDevice(user.id, device_name, "registration");
    return this.#signedIn(user.id, device.id, { user, device });
  }

  /** Accounts made before usernames confirm their email with a code (when the site sends email). */
  async verifyOtp({ email, otpCode, device_name }) {
    email = normEmail(email);
    const acct = this.q.byEmail.get(email);
    if (!acct) throw new AuthError(400, "That code has expired. Ask for a new one.", "CODE_EXPIRED");
    this.#checkCode(email, "verify", otpCode);
    this.q.verify.run(acct.user_id);
    const device = this.#newDevice(acct.user_id, device_name, "email");
    return this.#signedIn(acct.user_id, device.id, { device });
  }

  async resendOtp(email) {
    email = normEmail(email);
    const acct = this.q.byEmail.get(email);
    if (acct && !acct.verified && this.needsVerification && this.mailLimit.hit(`otp:${email}`)) await this.#sendCode(email, "verify");
    return { ok: true };
  }

  /**
   * Sign in with a username (or, for older accounts, an email) and password. On a device this site
   * knows, that's it. On a new one, the answer is { verify } and the device must be confirmed.
   */
  async login({ username, email, password, device, device_name }, ip = "") {
    const name = String(username || email || "").trim();
    if (!this.loginLimit.hit(`login:${ip}`) || !this.loginLimit.hit(`login:${name.toLowerCase()}`)) throw new AuthError(429, "Too many attempts. Try again in a few minutes.", "RATE_LIMITED");
    const userId = await this.#userIdFor(name);
    const acct = userId ? this.q.byUser.get(userId) : null;
    // Hash anyway, so a missing account takes as long as a wrong password.
    const ok = acct ? await checkPassword(String(password || ""), acct.password) : (await hashPassword("x"), false);
    if (!ok) throw new AuthError(401, "That username and password don't match.", "BAD_LOGIN");
    if (!acct.verified && acct.email && this.needsVerification) {
      if (this.mailLimit.hit(`otp:${acct.email}`)) await this.#sendCode(acct.email, "verify");
      throw new AuthError(403, "Check your email for a code to finish setting up your account.", "UNVERIFIED");
    }
    const known = this.#knownDevice(acct.user_id, device);
    if (known) {
      this.q.seenDevice.run(nowIso(), known.id);
      return this.#signedIn(acct.user_id, known.id);
    }
    const methods = this.#methodsFor(acct);
    if (!methods.length) {
      // Nothing to confirm a device with yet (an older account's first sign-in since this update).
      const fresh = this.#newDevice(acct.user_id, device_name, "password");
      return this.#signedIn(acct.user_id, fresh.id, { device: fresh });
    }
    const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
    const challenge = token();
    const id = this.#putChallenge(acct.user_id, "login", { device_name: cleanName(device_name, "A browser"), code, challenge, attempts: 0, state: "waiting", created_at: nowIso() });
    return { verify: { id, methods, code, challenge, host: this.rpID } };
  }

  /** Passkey options for confirming a new device. */
  async checkPasskeyOptions({ id }) {
    const c = this.#challenge(id, "login");
    const options = await this.#passkeyOptions(c.user_id);
    c.data.webauthn = options.challenge;
    this.q.saveChallenge.run(JSON.stringify(c.data), c.id);
    return { options };
  }

  /**
   * Confirm a new device: method "passkey" (response), "key" (signature over the challenge with
   * the owner key), "device" (approved from a signed-in device; poll until it is) or "email"
   * (older accounts: first call sends a code, second checks it).
   */
  async checkDevice({ id, method, response, signature, code }, ip = "") {
    if (!this.checkLimit.hit(`check:${ip}`)) throw new AuthError(429, "Too many attempts. Try again in a few minutes.", "RATE_LIMITED");
    const c = this.#challenge(id, "login");
    const acct = this.q.byUser.get(c.user_id);
    if (!acct) throw new AuthError(400, "That took too long. Start again.", "EXPIRED");
    const fail = (message) => {
      c.data.attempts += 1;
      if (c.data.attempts >= 5) this.q.dropChallenge.run(c.id);
      else this.q.saveChallenge.run(JSON.stringify(c.data), c.id);
      throw new AuthError(401, message, "CHECK_FAILED");
    };
    if (method === "passkey") {
      if (!c.data.webauthn) fail("Start again.");
      await this.#passkeyOk(response, c.data.webauthn, c.user_id).catch((e) => fail(e.message));
    } else if (method === "key") {
      if (!this.#ownerOk(acct, "verify-device", c.data.challenge, signature)) fail("That recovery phrase or private key isn't this account's.");
    } else if (method === "device") {
      if (c.data.state === "denied") {
        this.q.dropChallenge.run(c.id);
        throw new AuthError(403, "That sign-in was turned down on your other device.", "DENIED");
      }
      if (c.data.state !== "approved") return { waiting: true };
    } else if (method === "email") {
      if (!acct.email || !this.mail?.enabled) fail("Email isn't available for this account.");
      if (!code) {
        if (this.mailLimit.hit(`check:${acct.email}`)) await this.#sendCode(acct.email, "device");
        return { sent: true };
      }
      try {
        this.#checkCode(acct.email, "device", code);
      } catch (e) {
        fail(e.message);
      }
    } else {
      throw new AuthError(400, "Choose how to confirm this device.", "BAD_METHOD");
    }
    this.q.dropChallenge.run(c.id);
    const device = this.#newDevice(c.user_id, c.data.device_name, method);
    return this.#signedIn(c.user_id, device.id, { device });
  }

  /** Sign-ins waiting for approval, for a signed-in device to approve or turn down. */
  approvals(session) {
    if (!session?.deviceId) return { approvals: [] };
    const rows = this.q.pendingFor.all(session.user.id, Date.now()).map((r) => ({ ...r, data: JSON.parse(r.data) }));
    return { approvals: rows.filter((r) => r.data.state === "waiting").map((r) => ({ id: r.id, device_name: r.data.device_name, code: r.data.code, created_at: r.data.created_at })) };
  }

  approve(session, { id, approve }) {
    if (!session?.deviceId) throw new AuthError(403, "Approve sign-ins from a device that's already signed in.", "NO_DEVICE");
    const c = this.#challenge(id, "login");
    if (c.user_id !== session.user.id) throw new AuthError(404, "That sign-in has gone.", "NOT_FOUND");
    c.data.state = approve ? "approved" : "denied";
    c.data.approved_by = session.deviceId;
    this.q.saveChallenge.run(JSON.stringify(c.data), c.id);
    return { ok: true };
  }

  // ---------- passkeys ----------

  /** kind: "device" (this device only) or "synced" (a password manager, or a phone). */
  async passkeyRegisterOptions(session, { kind }) {
    const userId = session.user.id;
    const existing = this.q.passkeys.all(userId);
    if (existing.length >= MAX_PASSKEYS) throw new AuthError(409, `You can have up to ${MAX_PASSKEYS} passkeys. Remove one first.`, "TOO_MANY");
    const username = (await this.#usernameOf(userId)) || "commonveil";
    const options = await generateRegistrationOptions({
      rpName: this.config.siteName || "Commonveil",
      rpID: this.rpID,
      userName: username,
      userDisplayName: username,
      userID: new TextEncoder().encode(userId),
      attestationType: "none",
      excludeCredentials: existing.map((p) => ({ id: p.id, transports: JSON.parse(p.transports) })),
      authenticatorSelection: { residentKey: "required", userVerification: "preferred", ...(kind === "device" ? { authenticatorAttachment: "platform" } : {}) },
      ...(kind === "device" ? { preferredAuthenticatorType: "localDevice" } : {}),
    });
    const id = this.#putChallenge(userId, "passkey-reg", { challenge: options.challenge, kind: kind === "device" ? "device" : "synced" }, 5);
    return { id, options };
  }

  async passkeyRegister(session, { id, response, name }) {
    const c = this.#challenge(id, "passkey-reg");
    if (c.user_id !== session.user.id) throw new AuthError(400, "Start again.", "EXPIRED");
    let result;
    try {
      result = await verifyRegistrationResponse({ response, expectedChallenge: c.data.challenge, expectedOrigin: this.origin, expectedRPID: this.rpID, requireUserVerification: false });
    } catch {
      throw new AuthError(400, "That passkey couldn't be added. Try again.", "BAD_PASSKEY");
    }
    if (!result.verified) throw new AuthError(400, "That passkey couldn't be added. Try again.", "BAD_PASSKEY");
    this.q.dropChallenge.run(c.id);
    const info = result.registrationInfo;
    const synced = info.credentialBackedUp || info.credentialDeviceType === "multiDevice";
    const fallback = synced ? "Synced passkey" : "Passkey on this device";
    this.q.addPasskey.run(info.credential.id, session.user.id, Buffer.from(info.credential.publicKey).toString("base64url"), info.credential.counter, JSON.stringify(info.credential.transports || []), synced ? 1 : 0, cleanName(name, fallback), nowIso(), null);
    return { ok: true, passkey: { id: info.credential.id, synced } };
  }

  /** Sign in with a passkey alone: no username or password. */
  async passkeyLoginOptions(_body, ip = "") {
    if (!this.loginLimit.hit(`pk:${ip}`)) throw new AuthError(429, "Too many attempts. Try again in a few minutes.", "RATE_LIMITED");
    const options = await this.#passkeyOptions(null);
    const id = this.#putChallenge(null, "passkey-login", { challenge: options.challenge }, 5);
    return { id, options };
  }

  async passkeyLogin({ id, response, device, device_name }) {
    const c = this.#challenge(id, "passkey-login");
    this.q.dropChallenge.run(c.id);
    const row = await this.#passkeyOk(response, c.data.challenge);
    const known = this.#knownDevice(row.user_id, device);
    if (known) {
      this.q.seenDevice.run(nowIso(), known.id);
      return this.#signedIn(row.user_id, known.id);
    }
    const fresh = this.#newDevice(row.user_id, device_name, "passkey");
    return this.#signedIn(row.user_id, fresh.id, { device: fresh });
  }

  // ---------- the owner key ----------

  ownerChallenge(session) {
    const challenge = token();
    const id = this.#putChallenge(session.user.id, "owner-set", { challenge }, 5);
    return { id, challenge, host: this.rpID };
  }

  /** Record the account's owner public key, proven by a signature with its private half. */
  setOwner(session, { id, owner_pub, signature }) {
    if (!session.deviceId) throw new AuthError(403, "Do this from a device that's signed in.", "NO_DEVICE");
    const c = this.#challenge(id, "owner-set");
    if (c.user_id !== session.user.id) throw new AuthError(400, "Start again.", "EXPIRED");
    if (typeof owner_pub !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(owner_pub)) throw new AuthError(400, "That key isn't valid.", "BAD_KEY");
    if (!verifyEd25519(owner_pub, ownerText(this.rpID, "set-owner", c.data.challenge), signature)) throw new AuthError(400, "That key couldn't be confirmed.", "BAD_KEY");
    this.q.dropChallenge.run(c.id);
    this.q.setOwner.run(owner_pub, nowIso(), session.user.id);
    return { ok: true };
  }

  // ---------- getting back in ----------

  /** Start getting an account back. Says nothing about whether the account exists. */
  async recoverOptions({ username }, ip = "") {
    if (!this.loginLimit.hit(`recover:${ip}`)) throw new AuthError(429, "Too many attempts. Try again later.", "RATE_LIMITED");
    const userId = await this.#userIdFor(username);
    const options = await this.#passkeyOptions(userId);
    const challenge = token();
    const id = this.#putChallenge(userId, "recover", { challenge, webauthn: options.challenge });
    return { id, challenge, host: this.rpID, options };
  }

  /**
   * Prove the account is yours with its phrase or private key (method "key") or a passkey, and
   * choose a new password. Every other session is signed out; devices stay as they were.
   */
  async recover({ id, method, signature, response, new_password, device, device_name }, ip = "") {
    if (!this.checkLimit.hit(`recover:${ip}`)) throw new AuthError(429, "Too many attempts. Try again later.", "RATE_LIMITED");
    checkNewPassword(new_password);
    const c = this.#challenge(id, "recover");
    this.q.dropChallenge.run(c.id);
    const acct = c.user_id ? this.q.byUser.get(c.user_id) : null;
    const nope = new AuthError(401, "That didn't match this account. Check the username and try again.", "RECOVER_FAILED");
    if (!acct) throw nope;
    if (method === "key") {
      if (!this.#ownerOk(acct, "recover", c.data.challenge, signature)) throw nope;
    } else if (method === "passkey") {
      await this.#passkeyOk(response, c.data.webauthn, acct.user_id).catch(() => Promise.reject(nope));
    } else {
      throw nope;
    }
    this.q.setPassword.run(await hashPassword(new_password), acct.user_id);
    this.q.dropSessions.run(acct.user_id);
    const known = this.#knownDevice(acct.user_id, device);
    if (known) return this.#signedIn(acct.user_id, known.id);
    const fresh = this.#newDevice(acct.user_id, device_name, method === "key" ? "key" : "passkey");
    return this.#signedIn(acct.user_id, fresh.id, { device: fresh });
  }

  /** Older accounts only: a reset link by email, until they've set up a passkey or confirmed their phrase. */
  async resetPasswordRequest(email) {
    email = normEmail(email);
    const acct = this.q.byEmail.get(email);
    if (acct && this.mail?.enabled && !acct.owner_pub && !this.q.passkeys.all(acct.user_id).length && this.mailLimit.hit(`reset:${email}`)) {
      const t = token();
      this.q.putCode.run(`user:${acct.user_id}`, "reset", sha256(`reset:${t}`), Date.now() + RESET_MINUTES * 60_000);
      await this.mail.send({
        to: email,
        subject: "Commonveil: reset your password",
        body: `Someone asked to reset the password for this account. If it was you, open this link within an hour:\n\n${this.config.siteUrl}/reset-password?token=${encodeURIComponent(`${t}.${Buffer.from(acct.user_id).toString("base64url")}`)}\n\nIf it wasn't you, ignore this email: your password stays the same. Your messages are protected by your devices' keys, not by this password.`,
      });
    }
    return { ok: true };
  }

  /** Make a one-time reset link (for the command line: `cli.mjs reset-password <username>`). */
  resetLink(userId) {
    const t = token();
    this.q.putCode.run(`user:${userId}`, "reset", sha256(`reset:${t}`), Date.now() + RESET_MINUTES * 60_000);
    return `${this.config.siteUrl}/reset-password?token=${encodeURIComponent(`${t}.${Buffer.from(userId).toString("base64url")}`)}`;
  }

  async resetPassword({ resetToken, newPassword }) {
    const [t, u] = String(resetToken || "").split(".");
    const userId = Buffer.from(String(u || ""), "base64url").toString();
    const acct = /^[a-f0-9]{24}$/.test(userId) ? this.q.byUser.get(userId) : null;
    if (!acct || !t) throw new AuthError(400, "That link has expired. Ask for a new one.", "CODE_EXPIRED");
    checkNewPassword(newPassword);
    this.#checkCode(`user:${userId}`, "reset", t);
    this.q.setPassword.run(await hashPassword(newPassword), acct.user_id);
    this.q.dropSessions.run(acct.user_id);
    return { ok: true };
  }

  async #sendCode(email, purpose) {
    const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
    this.q.putCode.run(email, purpose, sha256(`${purpose}:${code}`), Date.now() + CODE_MINUTES * 60_000);
    await this.mail.send({
      to: email,
      subject: "Commonveil: your code",
      body: `Your code is ${code}\n\nIt works for ${CODE_MINUTES} minutes. If you didn't ask for it, you can ignore this email.`,
    });
  }

  #checkCode(key, purpose, code) {
    const row = this.q.getCode.get(key, purpose);
    if (!row || row.expires_at < Date.now() || row.attempts >= 5) throw new AuthError(400, "That code has expired. Ask for a new one.", "CODE_EXPIRED");
    if (sha256(`${purpose}:${String(code || "").trim()}`) !== row.code_hash) {
      this.q.bumpCode.run(key, purpose);
      throw new AuthError(400, "That code didn't work.", "CODE_WRONG");
    }
    this.q.dropCode.run(key, purpose);
  }

  // ---------- your sign-in, in settings ----------

  /**
   * How this account signs in. A session from before devices existed becomes a device here (it was
   * already signed in), and the answer carries that device's secret for the browser to keep.
   */
  identity(session, device_name) {
    const userId = session.user.id;
    const acct = this.q.byUser.get(userId);
    let adopted = null;
    if (!session.deviceId) {
      adopted = this.#newDevice(userId, device_name, "session");
      this.q.bindSession.run(adopted.id, session.tokenHash);
      session.deviceId = adopted.id;
    }
    return {
      email: acct?.email || "",
      email_retiring: Boolean(acct?.email),
      owner: Boolean(acct?.owner_pub),
      owner_set_at: acct?.owner_set_at || null,
      passkeys: this.q.passkeys.all(userId).map((p) => ({ id: p.id, name: p.name, synced: Boolean(p.synced), created_at: p.created_at, last_used: p.last_used })),
      devices: this.q.devices.all(userId).map((d) => ({ id: d.id, name: d.name, created_at: d.created_at, last_seen: d.last_seen, confirmed_by: d.confirmed_by, current: d.id === session.deviceId })),
      ...(adopted ? { device: adopted } : {}),
    };
  }

  async identityAction(session, body) {
    const userId = session.user.id;
    const acct = this.q.byUser.get(userId);
    switch (body.action) {
      case "remove_passkey": {
        this.q.dropPasskey.run(String(body.id || ""), userId);
        return { ok: true };
      }
      case "disconnect_device": {
        const d = this.q.device.get(String(body.id || ""));
        if (!d || d.user_id !== userId) throw new AuthError(404, "That device isn't connected.", "NOT_FOUND");
        this.q.dropDeviceSessions.run(d.id);
        this.q.dropDevice.run(d.id);
        return { ok: true, signed_out: d.id === session.deviceId };
      }
      case "remove_email": {
        if (!acct?.owner_pub) throw new AuthError(409, "Confirm your recovery phrase first, so you can always get back in.", "NEEDS_OWNER");
        if (acct.email) this.q.dropCodesFor.run(acct.email);
        this.q.dropEmail.run(userId);
        await this.store.entities.User.update(userId, { email: "" }).catch(() => {});
        return { ok: true };
      }
      case "change_password": {
        if (!(await checkPassword(String(body.password || ""), acct?.password))) throw new AuthError(401, "That isn't your current password.", "BAD_LOGIN");
        checkNewPassword(body.new_password);
        this.q.setPassword.run(await hashPassword(body.new_password), userId);
        return { ok: true };
      }
      default:
        throw new AuthError(400, "Unknown action.", "BAD_ACTION");
    }
  }

  // ---------- sessions ----------

  /** The session for a bearer token: { user, deviceId, tokenHash }, or null. */
  async sessionFor(bearer) {
    if (!bearer) return null;
    const tokenHash = sha256(bearer);
    const s = this.q.session.get(tokenHash);
    if (!s || s.expires_at < Date.now()) return null;
    if (s.device_id && !this.q.device.get(s.device_id)) {
      this.q.dropSession.run(tokenHash);
      return null;
    }
    const user = await this.store.entities.User.get(s.user_id).catch(() => null);
    return user ? { user, deviceId: s.device_id || null, tokenHash } : null;
  }

  /** The signed-in person for a bearer token, or null. */
  async userFor(bearer) {
    return (await this.sessionFor(bearer))?.user || null;
  }

  logout(bearer) {
    if (bearer) this.q.dropSession.run(sha256(bearer));
  }

  /** Remove a sign-in entirely (an account deleted by its owner, or by staff). */
  removeAccount(userId) {
    const acct = this.q.byUser.get(userId);
    if (acct?.email) this.q.dropCodesFor.run(acct.email);
    this.q.dropCodesFor.run(`user:${userId}`);
    this.q.dropSessions.run(userId);
    this.q.dropDevices.run(userId);
    this.q.dropPasskeys.run(userId);
    this.q.dropChallenges.run(userId);
    this.q.removeAccount.run(userId);
  }

  /** Whether a sign-in still exists for this account (the admin "removed sign-ins" tool asks). */
  hasAccount(userId) {
    return Boolean(this.q.byUser.get(userId));
  }

  /** For the command line: the account for a username or email. */
  async accountFor(name) {
    const userId = await this.#userIdFor(name);
    return userId ? this.q.byUser.get(userId) : null;
  }
}
