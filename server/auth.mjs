// Sign-in for a self-hosted site: email and password, sessions, email codes and password
// resets. This replaces Base44's sign-in. It knows nothing about encryption keys: those live on
// people's devices, and a stolen password still can't read anyone's messages.
//
// Stored here: each account's sign-in address, a scrypt hash of its password, and a hash of each
// session token. The account itself is a row in the User table, like on Base44.
import crypto from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(crypto.scrypt);
const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const SESSION_DAYS = 30;
const CODE_MINUTES = 15;
const RESET_MINUTES = 60;
const MIN_PASSWORD = 10;

export class AuthError extends Error {
  constructor(status, message, code = "AUTH") {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");
const token = () => crypto.randomBytes(32).toString("base64url");
const normEmail = (e) => String(e || "").trim().toLowerCase();
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/;

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
   * store: the Store. mail: { enabled, send({to, subject, body}) }. config: { siteUrl, adminEmails,
   * openRegistration }.
   */
  constructor({ store, mail, config }) {
    this.store = store;
    this.mail = mail;
    this.config = config;
    const db = store.db;
    db.exec(`CREATE TABLE IF NOT EXISTS auth_accounts (user_id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password TEXT NOT NULL, verified INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)`);
    db.exec(`CREATE TABLE IF NOT EXISTS auth_sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at TEXT NOT NULL, expires_at INTEGER NOT NULL)`);
    db.exec(`CREATE INDEX IF NOT EXISTS auth_sessions_user ON auth_sessions(user_id)`);
    db.exec(`CREATE TABLE IF NOT EXISTS auth_codes (email TEXT NOT NULL, purpose TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (email, purpose))`);
    this.q = {
      byEmail: db.prepare("SELECT * FROM auth_accounts WHERE email = ?"),
      byUser: db.prepare("SELECT * FROM auth_accounts WHERE user_id = ?"),
      insert: db.prepare("INSERT INTO auth_accounts (user_id, email, password, verified, created_at) VALUES (?, ?, ?, ?, ?)"),
      setPassword: db.prepare("UPDATE auth_accounts SET password = ? WHERE user_id = ?"),
      verify: db.prepare("UPDATE auth_accounts SET verified = 1 WHERE user_id = ?"),
      count: db.prepare("SELECT COUNT(*) AS n FROM auth_accounts"),
      removeAccount: db.prepare("DELETE FROM auth_accounts WHERE user_id = ?"),
      session: db.prepare("SELECT * FROM auth_sessions WHERE token_hash = ?"),
      addSession: db.prepare("INSERT INTO auth_sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)"),
      dropSession: db.prepare("DELETE FROM auth_sessions WHERE token_hash = ?"),
      dropSessions: db.prepare("DELETE FROM auth_sessions WHERE user_id = ?"),
      dropExpired: db.prepare("DELETE FROM auth_sessions WHERE expires_at < ?"),
      putCode: db.prepare("INSERT INTO auth_codes (email, purpose, code_hash, expires_at, attempts) VALUES (?, ?, ?, ?, 0) ON CONFLICT(email, purpose) DO UPDATE SET code_hash = excluded.code_hash, expires_at = excluded.expires_at, attempts = 0"),
      getCode: db.prepare("SELECT * FROM auth_codes WHERE email = ? AND purpose = ?"),
      bumpCode: db.prepare("UPDATE auth_codes SET attempts = attempts + 1 WHERE email = ? AND purpose = ?"),
      dropCode: db.prepare("DELETE FROM auth_codes WHERE email = ? AND purpose = ?"),
      dropCodesFor: db.prepare("DELETE FROM auth_codes WHERE email = ?"),
    };
    this.loginLimit = new Limiter(10, 15 * 60_000);
    this.mailLimit = new Limiter(5, 60 * 60_000);
  }

  /** Email codes are used only when the site can send email. */
  get needsVerification() {
    return Boolean(this.mail?.enabled);
  }

  #roleFor(email) {
    if (this.config.adminEmails.includes(email)) return "admin";
    return Number(this.q.count.get().n) === 0 ? "admin" : "user";
  }

  async #issueSession(userId) {
    const t = token();
    this.q.addSession.run(sha256(t), userId, new Date().toISOString(), Date.now() + SESSION_DAYS * 86_400_000);
    if (Math.random() < 0.05) this.q.dropExpired.run(Date.now());
    return t;
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

  #checkCode(email, purpose, code) {
    const row = this.q.getCode.get(email, purpose);
    if (!row || row.expires_at < Date.now() || row.attempts >= 5) throw new AuthError(400, "That code has expired. Ask for a new one.", "CODE_EXPIRED");
    if (sha256(`${purpose}:${String(code || "").trim()}`) !== row.code_hash) {
      this.q.bumpCode.run(email, purpose);
      throw new AuthError(400, "That code didn't work.", "CODE_WRONG");
    }
    this.q.dropCode.run(email, purpose);
  }

  async register({ email, password }, ip = "") {
    email = normEmail(email);
    if (!this.config.openRegistration && Number(this.q.count.get().n) > 0) throw new AuthError(403, "This site isn't taking new accounts.", "CLOSED");
    if (!EMAIL_RE.test(email)) throw new AuthError(400, "Enter a valid email address.", "BAD_EMAIL");
    if (typeof password !== "string" || password.length < MIN_PASSWORD || password.length > 512) throw new AuthError(400, `Use at least ${MIN_PASSWORD} characters.`, "WEAK_PASSWORD");
    if (!this.loginLimit.hit(`reg:${ip}`)) throw new AuthError(429, "Too many attempts. Try again later.", "RATE_LIMITED");
    if (this.q.byEmail.get(email)) {
      // Don't reveal whether an address has an account: behave as if a code was sent.
      return this.needsVerification ? { ok: true } : Promise.reject(new AuthError(409, "That email already has an account. Sign in instead.", "EXISTS"));
    }
    const role = this.#roleFor(email);
    const user = await this.store.entities.User.create({ email, role, full_name: "" });
    this.q.insert.run(user.id, email, await hashPassword(password), this.needsVerification ? 0 : 1, new Date().toISOString());
    if (this.needsVerification) {
      await this.#sendCode(email, "verify");
      return { ok: true };
    }
    return { access_token: await this.#issueSession(user.id), user };
  }

  async verifyOtp({ email, otpCode }) {
    email = normEmail(email);
    const acct = this.q.byEmail.get(email);
    if (!acct) throw new AuthError(400, "That code has expired. Ask for a new one.", "CODE_EXPIRED");
    this.#checkCode(email, "verify", otpCode);
    this.q.verify.run(acct.user_id);
    return { access_token: await this.#issueSession(acct.user_id) };
  }

  async resendOtp(email) {
    email = normEmail(email);
    const acct = this.q.byEmail.get(email);
    if (acct && !acct.verified && this.needsVerification && this.mailLimit.hit(`otp:${email}`)) await this.#sendCode(email, "verify");
    return { ok: true };
  }

  async login({ email, password }, ip = "") {
    email = normEmail(email);
    if (!this.loginLimit.hit(`login:${ip}`) || !this.loginLimit.hit(`login:${email}`)) throw new AuthError(429, "Too many attempts. Try again in a few minutes.", "RATE_LIMITED");
    const acct = this.q.byEmail.get(email);
    // Hash anyway, so a missing account takes as long as a wrong password.
    const ok = acct ? await checkPassword(String(password || ""), acct.password) : (await hashPassword("x"), false);
    if (!ok) throw new AuthError(401, "That email and password don't match.", "BAD_LOGIN");
    if (!acct.verified && this.needsVerification) {
      if (this.mailLimit.hit(`otp:${email}`)) await this.#sendCode(email, "verify");
      throw new AuthError(403, "Check your email for a code to finish setting up your account.", "UNVERIFIED");
    }
    return { access_token: await this.#issueSession(acct.user_id) };
  }

  async resetPasswordRequest(email) {
    email = normEmail(email);
    const acct = this.q.byEmail.get(email);
    if (acct && this.mail?.enabled && this.mailLimit.hit(`reset:${email}`)) {
      const t = token();
      this.q.putCode.run(email, "reset", sha256(`reset:${t}`), Date.now() + RESET_MINUTES * 60_000);
      await this.mail.send({
        to: email,
        subject: "Commonveil: reset your password",
        body: `Someone asked to reset the password for this account. If it was you, open this link within an hour:\n\n${this.config.siteUrl}/reset-password?token=${encodeURIComponent(`${t}.${Buffer.from(email).toString("base64url")}`)}\n\nIf it wasn't you, ignore this email: your password stays the same. Your messages are protected by your devices' keys, not by this password.`,
      });
    }
    return { ok: true };
  }

  async resetPassword({ resetToken, newPassword }) {
    const [t, e] = String(resetToken || "").split(".");
    const email = normEmail(Buffer.from(String(e || ""), "base64url").toString());
    const acct = this.q.byEmail.get(email);
    if (!acct || !t) throw new AuthError(400, "That link has expired. Ask for a new one.", "CODE_EXPIRED");
    if (typeof newPassword !== "string" || newPassword.length < MIN_PASSWORD || newPassword.length > 512) throw new AuthError(400, `Use at least ${MIN_PASSWORD} characters.`, "WEAK_PASSWORD");
    this.#checkCode(email, "reset", t);
    this.q.setPassword.run(await hashPassword(newPassword), acct.user_id);
    this.q.dropSessions.run(acct.user_id);
    return { ok: true };
  }

  /** The signed-in person for a bearer token, or null. */
  async userFor(bearer) {
    if (!bearer) return null;
    const s = this.q.session.get(sha256(bearer));
    if (!s || s.expires_at < Date.now()) return null;
    const user = await this.store.entities.User.get(s.user_id).catch(() => null);
    return user;
  }

  logout(bearer) {
    if (bearer) this.q.dropSession.run(sha256(bearer));
  }

  /** Remove a sign-in entirely (an account deleted by its owner, or by staff). */
  removeAccount(userId) {
    const acct = this.q.byUser.get(userId);
    if (acct) this.q.dropCodesFor.run(acct.email);
    this.q.dropSessions.run(userId);
    this.q.removeAccount.run(userId);
  }

  /** Whether a sign-in still exists for this account (the admin "removed sign-ins" tool asks). */
  hasAccount(userId) {
    return Boolean(this.q.byUser.get(userId));
  }
}
