import test from "node:test";
import assert from "node:assert/strict";
import { generateSigningKey } from "../src/core/signed.js";
import { sha256B64u } from "../src/core/bytes.js";
import { createPersona, checkPersonaLink, migrationNotice, acceptMigration, currentSite } from "../src/identity/portable.js";
import { grant, revoke, check, explain, REVOCATION_LIMITS } from "../src/consent/capsule.js";
import { publish, checkManifest, explainPermissions, publishTheme, checkTheme, themeProblems, contrast } from "../src/extensions/manifest.js";

test("personas: a community sees only the persona; the link is provable only when revealed", () => {
  const account = generateSigningKey();
  const p = createPersona(account, { community: "c1", name: "Quiet Heron" });
  assert.ok(!JSON.stringify(p.shown).includes(account.kid), "nothing shown points at the account");
  assert.deepEqual(checkPersonaLink(p.link), { account: account.kid, persona: p.key.kid, community: "c1" });
  const tampered = { ...p.link, body: { ...p.link.body, community: "c2" } };
  assert.throws(() => checkPersonaLink(tampered), /didn't sign/);
  const noPersona = { ...p.link, cosigs: [] };
  assert.throws(() => checkPersonaLink(noPersona), /persona didn't sign/);
});

test("migration: signed by the owner, in order, and replays are ignored", () => {
  const owner = generateSigningKey();
  const n1 = migrationNotice({ subject: "acct", from: "a.example", to: "b.example", seq: 1 }, owner);
  const n2 = migrationNotice({ subject: "acct", from: "b.example", to: "c.example", seq: 2 }, owner);
  const first = acceptMigration(n1, owner.publicKey);
  acceptMigration(n2, owner.publicKey, first);
  assert.throws(() => acceptMigration(n1, owner.publicKey, acceptMigration(n2, owner.publicKey, first)), /older notice/);
  const sneaky = migrationNotice({ subject: "acct", from: "a.example", to: "evil.example", seq: 2 }, generateSigningKey());
  assert.throws(() => acceptMigration(sneaky, owner.publicKey, first), /owner/);
  assert.equal(currentSite([n2, n1, sneaky], owner.publicKey, "a.example"), "c.example");
});

test("consent capsules: specific, time-limited, revocable, and honest about revocation", () => {
  const me = generateSigningKey();
  const friend = generateSigningKey();
  const now = Date.now();
  const c = grant({ audience: [friend.kid], actions: ["read"], resource: "file:abc", notBefore: new Date(now).toISOString(), expires: new Date(now + 3600_000).toISOString(), purpose: "Holiday photos" }, me);
  const ask = (over = {}) => check(c, { grantorPub: me.publicKey, actor: friend.kid, action: "read", resource: "file:abc", now, ...over });
  assert.ok(ask().allowed);
  assert.equal(ask({ action: "forward" }).why, "doesn't allow forward");
  assert.equal(ask({ actor: "someone" }).why, "not for this person or site");
  assert.equal(ask({ resource: "file:other" }).why, "about something else");
  assert.equal(ask({ now: now + 7200_000 }).why, "expired");
  const r = revoke(c, me);
  assert.equal(ask({ revocations: [r], now: now + 1000 }).why, "revoked");
  assert.ok(ask({ revocations: [revoke(c, friend)], now: now + 1000 }).allowed, "only the grantor can revoke");
  assert.ok(explain(c).includes(REVOCATION_LIMITS));
});

test("extension manifests: permissions limited by where it runs, code pinned, publisher signed", () => {
  const pub = generateSigningKey();
  const code = "export default () => {}";
  const m = publish({ id: "org.example.debates", name: "Debate map", version: "1.0.0", execution: "client-local", permissions: ["read.selected", "ui.panel"], code_hash: sha256B64u(code), licence: "MIT" }, pub);
  assert.ok(checkManifest(m, { publisherPub: pub.publicKey, code }).ok);
  assert.ok(!checkManifest(m, { publisherPub: pub.publicKey, code: code + " " }).ok, "changed code is caught");
  assert.throws(() => publish({ id: "org.example.spy", name: "Spy", version: "1.0.0", execution: "server-side", permissions: ["read.channel"], code_hash: sha256B64u(code) }, pub), /isn't available to server-side/);
  const ext = publish({ id: "org.example.translate", name: "Translate", version: "1.0.0", execution: "external", service: "https://translate.example", permissions: ["send.selected"], code_hash: sha256B64u(code) }, pub);
  assert.ok(explainPermissions(ext.body).some((l) => l.includes("outside Commonveil's encryption")));
});

test("themes: tokens only, approved fonts, readable contrast; no CSS or scripts", () => {
  const pub = generateSigningKey();
  const colors = { background: "#ffffff", surface: "#f4f6f8", text: "#1b1f24", muted: "#555d66", accent: "#0b5394", "accent-text": "#ffffff", danger: "#a4161a", "danger-text": "#ffffff", border: "#c9d1d9" };
  const theme = { id: "org.example.harbour", name: "Harbour", version: "1.0.0", colors, fonts: { body: "Atkinson Hyperlegible" }, radius: 6, spacing: "normal" };
  const t = publishTheme(theme, pub);
  assert.ok(checkTheme(t, pub.publicKey).ok);
  assert.ok(contrast("#000000", "#ffffff") === 2100);
  assert.ok(themeProblems({ ...theme, colors: { ...colors, text: "#eeeeee" } }).some((p) => p.includes("too faint")));
  assert.ok(themeProblems({ ...theme, css: "body{display:none}" }).some((p) => p.includes("isn't something a theme can set")));
  assert.ok(themeProblems({ ...theme, fonts: { body: "url(https://evil.example/font)" } }).some((p) => p.includes("approved")));
  assert.ok(themeProblems({ ...theme, colors: { ...colors, accent: "red;}" } }).length);
});
