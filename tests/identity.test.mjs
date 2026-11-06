// Commonveil sign-in (base44/shared/handlers/identity.ts), the same on Base44 and self-hosted
// sites: usernames and passwords, sessions, devices that must be confirmed, passkeys (with a
// software authenticator), the owner key from the recovery phrase, and getting back in. Run on a
// real self-hosted site; the Base44-only part (accounts made with an email) at the end, on the
// stand-in for Base44.
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { http, startSites } from "./support/selfhost.mjs";
import { SoftPasskey } from "./support/authenticator.mjs";
import { FakeWorld } from "./support/fakeBase44.mjs";
import { runAction } from "../base44/shared/http.ts";
import { identityActions } from "../base44/shared/handlers/identity.ts";
import { profileActions } from "../base44/shared/handlers/profile.ts";
import { forgetSecret } from "../base44/shared/identity/sessions.ts";
import { generateRecoveryPhrase } from "../src/lib/crypto/recovery.js";
import { ownerKey, privateKeyFromPhrase, signOwner } from "../src/lib/crypto/owner.js";

let net;
let site;
before(async () => {
  net = await startSites(["id.test"]);
  site = net.sites["id.test"];
});
after(async () => {
  await net?.close();
});

const ORIGIN = "https://id.test";
const id = async (action, body = {}, token) => http(site, "/api/functions/identity", { method: "POST", body: { action, ...body }, token });
const ok = async (action, body, token) => {
  const r = await id(action, action === "register" ? { age_confirmed: true, ...body } : body, token);
  assert.equal(r.status, 200, `${action}: ${JSON.stringify(r.data)}`);
  return r.data;
};
const call = async (fn, body, token) => http(site, `/api/functions/${fn}`, { method: "POST", body, token });
const me = async (token) => (await id("me", {}, token)).status;
const PW = "a long enough password";
const sign = (key, start, purpose) => signOwner(key, { host: start.realm, purpose, challenge: start.challenge });

test("accounts are a username and a password; the first is the site's admin", async () => {
  const r = await ok("register", { username: "ivy_k", password: PW, device_name: "Firefox on Linux" });
  assert.ok(r.session.access_token && r.session.refresh_token && r.device?.id && r.device?.secret);
  assert.equal(r.user.role, "admin", "the first account on a self-hosted site is its admin");
  const [profile] = await site.app.store.entities.Profile.filter({ user_id: r.user.id });
  assert.equal(profile.username, "ivy_k", "the username is the profile's");
  assert.equal((await site.app.store.entities.Person.get(r.user.id)).email, "", "no email");
  const raw = JSON.stringify(await site.app.store.entities.CvAccount.filter({ user_id: r.user.id }));
  assert.ok(!raw.includes(PW) && raw.includes("pbkdf2-sha256$"), "only a hash of the password is kept");
  assert.equal((await id("register", { username: "IVY_K", password: PW, age_confirmed: true })).status, 409);
  assert.equal((await id("register", { username: "no", password: PW })).status, 400);
  assert.equal((await id("register", { username: "short_pw", password: "short" })).status, 400);
  const young = await id("register", { username: "no_box", password: PW });
  assert.deepEqual([young.status, young.data.code], [400, "AGE_REQUIRED"], "the 16+ box has to be ticked");
  const acctRow = (await site.app.store.entities.CvAccount.filter({ user_id: r.user.id }))[0];
  assert.ok(acctRow.age_confirmed_at && acctRow.terms_version, "only that it was confirmed, and when, is kept");
  assert.equal((await ok("register", { username: "ivy_two", password: PW })).user.role, "user");

  assert.equal((await call("profile", { action: "me" }, r.session.access_token)).status, 200, "the session works with every function");
  const again = await ok("login", { username: "ivy_k", password: PW, device: r.device });
  assert.ok(again.session && !again.verify, "the same browser signs straight back in");
  assert.equal((await id("login", { username: "ivy_k", password: "wrong password!" })).status, 401);
  assert.ok((await ok("login", { username: "ivy_k", password: PW, device: { id: r.device.id, secret: "forged" } })).verify, "a device is its secret, not its id");
});

test("sessions: short access tokens, renewed with the refresh token, ended by signing out", async () => {
  const r = await ok("register", { username: "jo_s", password: PW });
  const s = r.session;
  assert.match(s.access_token, /^cv1\./);
  assert.ok(Date.parse(s.access_expires_at) - Date.now() <= 15 * 60_000 + 1000);
  const renewed = await ok("refresh", { refresh_token: s.refresh_token });
  assert.equal(await me(renewed.access_token), 200);
  const [v, , sig] = s.access_token.split(".");
  const forged = `${v}.${Buffer.from(JSON.stringify({ u: "0".repeat(24), d: r.device.id, x: 9e9 })).toString("base64url")}.${sig}`;
  assert.equal(await me(forged), 401, "a changed token is refused");
  await ok("logout", { refresh_token: s.refresh_token });
  assert.equal((await id("refresh", { refresh_token: s.refresh_token })).status, 401);
});

test("a new device is confirmed from a device that's signed in, and can be disconnected", async () => {
  const first = await ok("register", { username: "jun", password: PW, device_name: "Phone" });
  const t = first.session.access_token;
  const start = await ok("login", { username: "jun", password: PW, device_name: "Library computer" });
  assert.deepEqual(start.verify.methods, ["device"], "nothing else is set up yet");
  assert.match(start.verify.code, /^\d{6}$/);
  assert.deepEqual(await ok("check", { id: start.verify.id, method: "device" }), { waiting: true });

  const { approvals } = await ok("approvals", {}, t);
  assert.deepEqual(approvals.map((a) => [a.device_name, a.code]), [["Library computer", start.verify.code]]);
  await ok("approve", { id: approvals[0].id, approve: true }, t);
  const done = await ok("check", { id: start.verify.id, method: "device" });
  assert.ok(done.session && done.device);

  const other = await ok("login", { username: "jun", password: PW, device_name: "Unknown" });
  const { approvals: waiting } = await ok("approvals", {}, t);
  await ok("approve", { id: waiting[0].id, approve: false }, t);
  assert.equal((await id("check", { id: other.verify.id, method: "device" })).status, 403);

  const status = await ok("status", {}, t);
  assert.deepEqual(status.devices.map((d) => d.name).sort(), ["Library computer", "Phone"]);
  const lib = status.devices.find((d) => d.name === "Library computer");
  await ok("account", { change: "disconnect_device", id: lib.id }, t);
  assert.equal((await id("refresh", { refresh_token: done.session.refresh_token })).status, 401, "its session ends");
  assert.ok((await ok("login", { username: "jun", password: PW, device: done.device })).verify, "it has to be confirmed again");
});

test("the recovery phrase and private key prove the account is yours, and get you back in", async () => {
  const acct = await ok("register", { username: "kai", password: PW });
  const t = acct.session.access_token;
  const phrase = generateRecoveryPhrase();
  const key = await ownerKey(phrase);
  const ch = await ok("owner_challenge", {}, t);
  assert.equal((await id("owner", { id: ch.id, owner_pub: key.publicKey, signature: sign(key, { ...ch, challenge: "x" }, "set-owner") }, t)).status, 400, "the key has to be proven");
  await ok("owner", { id: ch.id, owner_pub: key.publicKey, signature: sign(key, ch, "set-owner") }, t);

  const start = await ok("login", { username: "kai", password: PW });
  assert.ok(start.verify.methods.includes("key"));
  const stranger = await ownerKey(generateRecoveryPhrase());
  assert.equal((await id("check", { id: start.verify.id, method: "key", signature: sign(stranger, start.verify, "verify-device") })).status, 401);
  const viaKey = await ownerKey(privateKeyFromPhrase(phrase));
  assert.ok((await ok("check", { id: start.verify.id, method: "key", signature: sign(viaKey, start.verify, "verify-device") })).session);
  const again = await ok("login", { username: "kai", password: PW });
  assert.equal((await id("check", { id: again.verify.id, method: "key", signature: sign(key, again.verify, "recover") })).status, 401, "a signature for one purpose doesn't work for another");

  const rc = await ok("recover_options", { username: "kai", origin: ORIGIN });
  assert.equal((await id("recover", { id: rc.id, method: "key", signature: sign(stranger, rc, "recover"), new_password: "another long password" })).status, 401);
  const rc2 = await ok("recover_options", { username: "kai", origin: ORIGIN });
  const back = await ok("recover", { id: rc2.id, method: "key", signature: sign(key, rc2, "recover"), new_password: "another long password", device_name: "New laptop" });
  assert.ok(back.session);
  assert.equal((await id("refresh", { refresh_token: acct.session.refresh_token })).status, 401, "old sessions are signed out");
  assert.equal((await id("login", { username: "kai", password: PW })).status, 401);
  assert.ok((await ok("login", { username: "kai", password: "another long password", device: back.device })).session);
  assert.equal((await id("recover_options", { username: "nobody_here", origin: ORIGIN })).status, 200, "an account that doesn't exist looks the same");
});

test("wrong passwords lock the username for a while", async () => {
  await ok("register", { username: "lock_me", password: PW });
  for (let i = 0; i < 10; i += 1) assert.equal((await id("login", { username: "lock_me", password: `wrong ${i} password` })).status, 401);
  assert.equal((await id("login", { username: "lock_me", password: PW })).status, 429);
});

test("passkeys: on one device or synced, to sign in, confirm a device or get back in", async () => {
  const acct = await ok("register", { username: "lea", password: PW });
  const t = acct.session.access_token;
  const deviceKey = new SoftPasskey({ origin: ORIGIN, rpID: "id.test" });
  const syncedKey = new SoftPasskey({ origin: ORIGIN, rpID: "id.test", synced: true });
  for (const [kind, pk] of [["device", deviceKey], ["synced", syncedKey]]) {
    const { id: cid, options } = await ok("passkey_options", { kind, origin: ORIGIN }, t);
    if (kind === "device") assert.equal(options.authenticatorSelection.authenticatorAttachment, "platform");
    assert.equal(options.attestation, "none");
    await ok("passkey_add", { id: cid, response: pk.create(options) }, t);
  }
  assert.deepEqual((await ok("status", {}, t)).passkeys.map((p) => p.synced), [false, true], "synced passkeys are told apart");
  assert.equal((await id("passkey_options", { kind: "synced", origin: "https://evil.test" }, t)).status, 400, "passkeys only on this site's own address");

  const opts = await ok("passkey_login_options", { origin: ORIGIN });
  const signedIn = await ok("passkey_login", { id: opts.id, response: syncedKey.get(opts.options), device_name: "Tablet" });
  assert.ok(signedIn.session && signedIn.device);
  assert.equal((await id("passkey_login", { id: opts.id, response: syncedKey.get(opts.options) })).status, 400, "a challenge is used once");

  const start = await ok("login", { username: "lea", password: PW });
  assert.ok(start.verify.methods.includes("passkey"));
  const { options } = await ok("check_options", { id: start.verify.id, origin: ORIGIN });
  assert.equal(options.allowCredentials.length, 2, "only this account's passkeys are offered");
  assert.ok((await ok("check", { id: start.verify.id, method: "passkey", response: deviceKey.get(options) })).session);

  const other = await ok("register", { username: "moe", password: PW });
  const moKey = new SoftPasskey({ origin: ORIGIN, rpID: "id.test" });
  const mo = await ok("passkey_options", { kind: "synced", origin: ORIGIN }, other.session.access_token);
  await ok("passkey_add", { id: mo.id, response: moKey.create(mo.options) }, other.session.access_token);
  const s2 = await ok("login", { username: "lea", password: PW });
  const o2 = await ok("check_options", { id: s2.verify.id, origin: ORIGIN });
  assert.equal((await id("check", { id: s2.verify.id, method: "passkey", response: moKey.get({ ...o2.options, allowCredentials: [] }) })).status, 401, "someone else's passkey doesn't confirm this account");
  const o3 = await ok("check_options", { id: s2.verify.id, origin: ORIGIN });
  const answer = deviceKey.get(o3.options);
  answer.response.signature = Buffer.from(Buffer.from(answer.response.signature, "base64url").map((b, i) => (i === 10 ? b ^ 1 : b))).toString("base64url");
  assert.equal((await id("check", { id: s2.verify.id, method: "passkey", response: answer })).status, 401, "a tampered answer fails");

  const rc = await ok("recover_options", { username: "lea", origin: ORIGIN });
  const back = await ok("recover", { id: rc.id, method: "passkey", response: deviceKey.get(rc.options), new_password: "brand new password" });
  assert.ok(back.session);

  const foreign = new SoftPasskey({ origin: "https://evil.test", rpID: "evil.test" });
  const pk = await ok("passkey_options", { kind: "synced", origin: ORIGIN }, back.session.access_token);
  assert.equal((await id("passkey_add", { id: pk.id, response: foreign.create(pk.options) }, back.session.access_token)).status, 400, "a passkey made for another site doesn't count");
});

test("nobody can make themselves an admin, or read the sign-in tables", async () => {
  const acct = await ok("register", { username: "quin", password: PW });
  for (const table of ["Person", "User"]) {
    const r = await http(site, `/api/entities/${table}/update`, { method: "POST", body: { id: acct.user.id, data: { role: "admin", site_owner: true } }, token: acct.session.access_token });
    assert.equal(r.status, 403, table);
  }
  const p = await site.app.store.entities.Person.get(acct.user.id);
  assert.deepEqual([p.role, Boolean(p.site_owner)], ["user", false]);
  for (const table of ["CvAccount", "CvDevice", "CvRefresh", "CvPasskey", "CvChallenge", "CvSecret", "Person"]) {
    const r = await http(site, `/api/entities/${table}/list`, { method: "POST", body: {}, token: acct.session.access_token });
    assert.deepEqual(r.data, [], table);
  }
});

test("deleting an account removes everything it signs in with", async () => {
  const acct = await ok("register", { username: "pia_del", password: PW });
  const { removePlatformUser } = await import("../base44/shared/accountDeletion.ts");
  await removePlatformUser({ entities: site.app.store.entities }, acct.user.id);
  for (const table of ["CvAccount", "CvDevice", "CvRefresh"]) assert.equal((await site.app.store.entities[table].filter({ user_id: acct.user.id })).length, 0, table);
  assert.equal(await me(acct.session.access_token), 401);
});

// ---------- on Base44: accounts made with an email ----------

test("on Base44, an account made with an email comes in once by email, then uses its username", async () => {
  forgetSecret();
  try {
    const world = new FakeWorld();
    const actions = identityActions({ realm: "commonveil.online", siteName: "Commonveil", passkeyHost: (h) => h === "commonveil.online", platformCutover: "2026-11-06T04:00:00Z", passwordRounds: 1000 });
    const person = (n, email, made) => {
      const u = { id: `${n}`.repeat(24).slice(0, 24), email, role: "user", full_name: "", created_date: made };
      world.addUser(u);
      return u;
    };
    const run = async (who, body) => {
      const res = await runAction(world.clientFor(who), JSON.stringify(body), actions, { allowAnonymous: true, allowPlatformUser: true });
      return { status: res.status, data: await res.json() };
    };
    const old = person("a", "nia@example.com", "2026-11-01T10:00:00.000");
    await world.clientFor(null).asServiceRole.entities.Profile.create({ user_id: old.id, username: "nia", username_key: "nia", display_name: "Nia", bio: "" });

    const bare = await runAction(world.clientFor(old), JSON.stringify({ action: "me" }), profileActions);
    assert.equal((await bare.json()).code, "NEW_SIGN_IN", "a Base44 session alone isn't accepted any more");

    const linked = await run(old, { action: "link_platform", device_name: "Old laptop" });
    assert.equal(linked.status, 200, JSON.stringify(linked.data));
    const t = linked.data.session.access_token;
    const viaSession = await runAction(world.clientFor(null), JSON.stringify({ action: "me", _session: t }), profileActions);
    assert.equal(viaSession.status, 200, "with a Commonveil session, everything works");

    const status = (await run(null, { action: "status", _session: t })).data;
    assert.deepEqual([status.kind, status.email_retiring, status.has_password, status.age_confirmed], ["platform", true, false, false]);
    assert.equal((await run(null, { action: "account", change: "confirm_age", _session: t })).data.code, "AGE_REQUIRED");
    await run(null, { action: "account", change: "confirm_age", age_confirmed: true, _session: t });
    assert.equal((await run(null, { action: "status", _session: t })).data.age_confirmed, true, "accounts from before the rule confirm it once");
    assert.equal((await run(null, { action: "login", username: "nia", password: PW })).status, 401, "no username password yet");
    assert.equal((await run(null, { action: "account", change: "remove_email", _session: t })).data.code, "NEEDS_PASSWORD");
    assert.equal((await run(null, { action: "account", change: "set_password", new_password: PW, _session: t })).status, 200);
    assert.ok((await run(null, { action: "login", username: "nia", password: PW, device: linked.data.device })).data.session, "now her username and password work");
    assert.equal((await run(null, { action: "account", change: "remove_email", _session: t })).data.code, "NEEDS_OWNER");
    const key = await ownerKey(generateRecoveryPhrase());
    const ch = (await run(null, { action: "owner_challenge", _session: t })).data;
    assert.equal((await run(null, { action: "owner", id: ch.id, owner_pub: key.publicKey, signature: signOwner(key, { host: ch.realm, purpose: "set-owner", challenge: ch.challenge }), _session: t })).status, 200);
    assert.equal((await run(null, { action: "account", change: "remove_email", _session: t })).status, 200);
    assert.equal((await run(old, { action: "link_platform" })).data.code, "EMAIL_REMOVED", "after that, the email doesn't get in");

    const fresh = person("b", "new@example.com", "2026-11-07T10:00:00.000");
    assert.equal((await run(fresh, { action: "link_platform" })).data.code, "EMAIL_SIGNUP_CLOSED", "email sign-up is closed");

    const omar = person("c", "omar@example.com", "2026-10-30T10:00:00.000");
    assert.ok((await run(omar, { action: "link_platform" })).data.session);
    assert.deepEqual((await run(omar, { action: "link_platform", device_name: "Someone else's" })).data.verify.methods, ["device"], "a second browser has to be confirmed");

    const signup = await run(null, { action: "register", username: "new_one", password: PW, age_confirmed: true });
    assert.equal(signup.status, 200, JSON.stringify(signup.data));
    assert.equal(signup.data.user.role, "user", "on Base44 nobody becomes an admin by signing up");
  } finally {
    forgetSecret();
  }
});
