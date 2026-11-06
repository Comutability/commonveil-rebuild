// Commonveil Identity on a self-hosted site (server/auth.mjs): usernames and passwords, devices that
// must be confirmed, passkeys, the owner key from the recovery phrase, getting back in, and
// accounts made with an email before all this.
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { http, startSites } from "./support/selfhost.mjs";
import { SoftPasskey } from "./support/authenticator.mjs";
import { generateRecoveryPhrase } from "../src/lib/crypto/recovery.js";
import { ownerKey, privateKeyFromPhrase, signOwner } from "../src/lib/crypto/owner.js";

let net;
let site;
before(async () => {
  net = await startSites(["id.test"], {}, {
    // A database from before usernames: accounts had to have an email.
    prepare(_name, dir) {
      const db = new DatabaseSync(path.join(dir, "commonveil.db"));
      db.exec("CREATE TABLE auth_accounts (user_id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password TEXT NOT NULL, verified INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)");
      db.exec("CREATE TABLE auth_sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at TEXT NOT NULL, expires_at INTEGER NOT NULL)");
      db.prepare("INSERT INTO auth_accounts VALUES (?, ?, ?, 1, ?)").run("0".repeat(23) + "9", "old@example.com", "scrypt$1$x$y", new Date().toISOString());
      db.close();
    },
  });
  site = net.sites["id.test"];
});
after(async () => {
  await net?.close();
});

const auth = async (name, body = {}, token) => {
  const r = await http(site, `/api/auth/${name}`, { method: "POST", body, token });
  return r;
};
const ok = async (name, body, token) => {
  const r = await auth(name, body, token);
  assert.equal(r.status, 200, `${name}: ${JSON.stringify(r.data)}`);
  return r.data;
};
const me = async (token) => (await http(site, "/api/auth/me", { token })).status;
const PW = "a long enough password";

test("an older database keeps its accounts, with email now optional", () => {
  const db = site.app.store.db;
  const cols = db.prepare("PRAGMA table_info(auth_accounts)").all();
  assert.ok(cols.some((c) => c.name === "owner_pub"));
  assert.equal(cols.find((c) => c.name === "email").notnull, 0);
  assert.equal(db.prepare("SELECT email FROM auth_accounts WHERE user_id = ?").get("0".repeat(23) + "9").email, "old@example.com");
});

test("accounts are a username and a password, and the first browser is the first device", async () => {
  const r = await ok("register", { username: "ivy_k", password: PW, device_name: "Firefox on Linux" });
  assert.ok(r.access_token && r.device?.id && r.device?.secret);
  const [profile] = await site.app.store.entities.Profile.filter({ user_id: r.user.id });
  assert.equal(profile.username, "ivy_k", "the username is the profile's");
  assert.equal((await site.app.store.entities.User.get(r.user.id)).email, "", "no email");
  assert.equal((await auth("register", { username: "IVY_K", password: PW })).status, 409);
  assert.equal((await auth("register", { username: "no", password: PW })).status, 400);
  assert.equal((await auth("register", { username: "short_pw", password: "short" })).status, 400);

  // The same browser signs straight back in; it's known.
  const again = await ok("login", { username: "ivy_k", password: PW, device: r.device });
  assert.ok(again.access_token && !again.verify);
  assert.equal((await auth("login", { username: "ivy_k", password: "wrong password!" })).status, 401);
  assert.equal((await auth("login", { username: "ivy_k", password: PW, device: { id: r.device.id, secret: "forged" } })).data.verify !== undefined, true, "a device is its secret, not its id");
});

test("a new device is confirmed from a device that's signed in", async () => {
  const first = await ok("register", { username: "jun", password: PW, device_name: "Phone" });
  const start = await ok("login", { username: "jun", password: PW, device_name: "Library computer" });
  assert.deepEqual(start.verify.methods, ["device"], "nothing else is set up yet");
  assert.match(start.verify.code, /^\d{6}$/);
  assert.deepEqual(await ok("check", { id: start.verify.id, method: "device" }), { waiting: true });

  const { approvals } = await ok("approvals", {}, first.access_token);
  assert.deepEqual(approvals.map((a) => [a.device_name, a.code]), [["Library computer", start.verify.code]]);
  await ok("approvals", { id: start.verify.id, approve: true }, first.access_token);
  const done = await ok("check", { id: start.verify.id, method: "device" });
  assert.ok(done.access_token && done.device);
  assert.equal(await me(done.access_token), 200);

  // Turned down: that sign-in goes nowhere.
  const other = await ok("login", { username: "jun", password: PW, device_name: "Unknown" });
  await ok("approvals", { id: other.verify.id, approve: false }, first.access_token);
  assert.equal((await auth("check", { id: other.verify.id, method: "device" })).status, 403);

  // Devices are listed, and disconnecting one signs it out.
  const status = await ok("identity", {}, first.access_token);
  assert.deepEqual(status.devices.map((d) => d.name).sort(), ["Library computer", "Phone"]);
  const lib = status.devices.find((d) => d.name === "Library computer");
  await ok("identity", { action: "disconnect_device", id: lib.id }, first.access_token);
  assert.equal(await me(done.access_token), 401);
  assert.ok((await ok("login", { username: "jun", password: PW, device: done.device })).verify, "a disconnected device has to be confirmed again");
});

test("the recovery phrase and private key prove the account is yours, and get you back in", async () => {
  const acct = await ok("register", { username: "kai", password: PW });
  const phrase = generateRecoveryPhrase();
  const key = await ownerKey(phrase);
  const ch = await ok("owner-challenge", {}, acct.access_token);
  assert.equal((await auth("owner", { id: ch.id, owner_pub: key.publicKey, signature: signOwner(key, { host: ch.host, purpose: "set-owner", challenge: "something else" }) }, acct.access_token)).status, 400, "the key has to be proven");
  await ok("owner", { id: ch.id, owner_pub: key.publicKey, signature: signOwner(key, { host: ch.host, purpose: "set-owner", challenge: ch.challenge }) }, acct.access_token);

  // A new device, confirmed with the private key (the phrase's other form).
  const start = await ok("login", { username: "kai", password: PW });
  assert.ok(start.verify.methods.includes("key"));
  const stranger = await ownerKey(generateRecoveryPhrase());
  assert.equal((await auth("check", { id: start.verify.id, method: "key", signature: signOwner(stranger, { host: start.verify.host, purpose: "verify-device", challenge: start.verify.challenge }) })).status, 401);
  const viaKey = await ownerKey(privateKeyFromPhrase(phrase));
  const confirmed = await ok("check", { id: start.verify.id, method: "key", signature: signOwner(viaKey, { host: start.verify.host, purpose: "verify-device", challenge: start.verify.challenge }) });
  assert.ok(confirmed.access_token);
  // A signature for one purpose doesn't work for another.
  const again = await ok("login", { username: "kai", password: PW });
  assert.equal((await auth("check", { id: again.verify.id, method: "key", signature: signOwner(key, { host: again.verify.host, purpose: "recover", challenge: again.verify.challenge }) })).status, 401);

  // Forgot the password: the phrase sets a new one, and every session is signed out.
  const rc = await ok("recover-options", { username: "kai" });
  assert.equal((await auth("recover", { id: rc.id, method: "key", signature: signOwner(stranger, { host: rc.host, purpose: "recover", challenge: rc.challenge }), new_password: "another long password" })).status, 401);
  const rc2 = await ok("recover-options", { username: "kai" });
  const back = await ok("recover", { id: rc2.id, method: "key", signature: signOwner(key, { host: rc2.host, purpose: "recover", challenge: rc2.challenge }), new_password: "another long password", device_name: "New laptop" });
  assert.ok(back.access_token);
  assert.equal(await me(acct.access_token), 401, "old sessions are signed out");
  assert.equal((await auth("login", { username: "kai", password: PW })).status, 401);
  assert.equal((await ok("login", { username: "kai", password: "another long password", device: back.device })).access_token?.length > 0, true);

  // Asking about an account that doesn't exist looks the same.
  const ghost = await auth("recover-options", { username: "nobody_here" });
  assert.equal(ghost.status, 200);
  assert.ok(ghost.data.challenge);
});

test("passkeys: on one device or synced, to sign in, confirm a device or get back in", async () => {
  const acct = await ok("register", { username: "lea", password: PW });
  const deviceKey = new SoftPasskey({ origin: site.config.siteUrl, rpID: site.config.host });
  const syncedKey = new SoftPasskey({ origin: site.config.siteUrl, rpID: site.config.host, synced: true });

  for (const [kind, pk] of [["device", deviceKey], ["synced", syncedKey]]) {
    const { id, options } = await ok("passkey-options", { kind }, acct.access_token);
    if (kind === "device") assert.equal(options.authenticatorSelection.authenticatorAttachment, "platform");
    await ok("passkey-add", { id, response: pk.create(options) }, acct.access_token);
  }
  const status = await ok("identity", {}, acct.access_token);
  assert.deepEqual(status.passkeys.map((p) => p.synced), [false, true], "synced passkeys are told apart");

  // Signing in with a passkey alone, on a new browser.
  const opts = await ok("passkey-login-options", {});
  const signedIn = await ok("passkey-login", { id: opts.id, response: syncedKey.get(opts.options), device_name: "Tablet" });
  assert.ok(signedIn.access_token && signedIn.device);
  // The same answer can't be used twice.
  assert.equal((await auth("passkey-login", { id: opts.id, response: syncedKey.get(opts.options) })).status, 400);

  // Confirming a new device after the password.
  const start = await ok("login", { username: "lea", password: PW });
  assert.ok(start.verify.methods.includes("passkey"));
  const { options } = await ok("check-options", { id: start.verify.id });
  assert.equal(options.allowCredentials.length, 2, "only this account's passkeys are offered");
  assert.ok((await ok("check", { id: start.verify.id, method: "passkey", response: deviceKey.get(options) })).access_token);

  // Someone else's passkey doesn't confirm this account.
  const other = await ok("register", { username: "moe", password: PW });
  const moKey = new SoftPasskey({ origin: site.config.siteUrl, rpID: site.config.host });
  const mo = await ok("passkey-options", { kind: "synced" }, other.access_token);
  await ok("passkey-add", { id: mo.id, response: moKey.create(mo.options) }, other.access_token);
  const s2 = await ok("login", { username: "lea", password: PW });
  const o2 = await ok("check-options", { id: s2.verify.id });
  assert.equal((await auth("check", { id: s2.verify.id, method: "passkey", response: moKey.get({ ...o2.options, allowCredentials: [] }) })).status, 401);

  // Getting back in with a passkey.
  const rc = await ok("recover-options", { username: "lea" });
  const back = await ok("recover", { id: rc.id, method: "passkey", response: deviceKey.get(rc.options), new_password: "brand new password" });
  assert.ok(back.access_token);
  assert.equal(await me(acct.access_token), 401);

  // A passkey from another site's prompt doesn't count here.
  const foreign = new SoftPasskey({ origin: "http://evil.test", rpID: "evil.test" });
  const pkOpts = await ok("passkey-options", { kind: "synced" }, back.access_token);
  assert.equal((await auth("passkey-add", { id: pkOpts.id, response: foreign.create(pkOpts.options) }, back.access_token)).status, 400);
});

test("accounts made with an email still sign in with it, and are moved to the new identity", async () => {
  // An account from before usernames, with a username claimed in the app afterwards.
  const user = await site.app.store.entities.User.create({ email: "nia@example.com", role: "user", full_name: "" });
  const db = site.app.store.db;
  const reg = await ok("register", { username: "temp_x", password: PW }); // to borrow a real password hash
  const hash = db.prepare("SELECT password FROM auth_accounts WHERE user_id = ?").get(reg.user.id).password;
  db.prepare("INSERT INTO auth_accounts (user_id, email, password, verified, created_at) VALUES (?, ?, ?, 1, ?)").run(user.id, "nia@example.com", hash, new Date().toISOString());
  await site.app.store.entities.Profile.create({ user_id: user.id, username: "nia", username_key: "nia", display_name: "Nia", bio: "" });

  const viaEmail = await ok("login", { email: "nia@example.com", password: PW, device_name: "Old laptop" });
  assert.ok(viaEmail.access_token, "the first sign-in since the update trusts this browser: there's nothing to confirm it with yet");
  const status = await ok("identity", {}, viaEmail.access_token);
  assert.equal(status.email_retiring, true);
  assert.equal((await auth("identity", { action: "remove_email" }, viaEmail.access_token)).status, 409, "not before the phrase is confirmed");
  assert.ok((await ok("login", { username: "nia", password: PW, device: viaEmail.device })).access_token, "the username works too");

  const key = await ownerKey(generateRecoveryPhrase());
  const ch = await ok("owner-challenge", {}, viaEmail.access_token);
  await ok("owner", { id: ch.id, owner_pub: key.publicKey, signature: signOwner(key, { host: ch.host, purpose: "set-owner", challenge: ch.challenge }) }, viaEmail.access_token);
  await ok("identity", { action: "remove_email" }, viaEmail.access_token);
  assert.equal((await ok("identity", {}, viaEmail.access_token)).email_retiring, false);
  assert.equal((await site.app.store.entities.User.get(user.id)).email, "");
  assert.equal((await auth("login", { email: "nia@example.com", password: PW })).status, 401, "the email is gone");
});

test("a session from before devices becomes a device when the app next opens", async () => {
  const acct = await ok("register", { username: "ozzy", password: PW });
  const db = site.app.store.db;
  // Make a session the old way: no device.
  const t = "legacy-session-token-for-a-test-0001";
  const hash = (await import("node:crypto")).createHash("sha256").update(t).digest("hex");
  db.prepare("INSERT INTO auth_sessions (token_hash, user_id, created_at, expires_at, device_id) VALUES (?, ?, ?, ?, NULL)").run(hash, acct.user.id, new Date().toISOString(), Date.now() + 86_400_000);
  assert.deepEqual((await ok("approvals", {}, t)).approvals, [], "no device, nothing to approve with");
  const status = await ok("identity", { device_name: "Kept tab" }, t);
  assert.ok(status.device?.secret, "adopted as a device");
  assert.ok(status.devices.some((d) => d.name === "Kept tab" && d.current));
});

test("deleting an account removes everything it signs in with", async () => {
  const acct = await ok("register", { username: "pia", password: PW });
  site.app.auth.removeAccount(acct.user.id);
  const db = site.app.store.db;
  for (const table of ["auth_accounts", "auth_sessions", "auth_devices", "auth_passkeys", "auth_challenges"]) {
    assert.equal(db.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE user_id = ?`).get(acct.user.id).n, 0, table);
  }
});
