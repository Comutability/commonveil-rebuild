// The hosted site (the Base44 build, on the test emulator) talking the Commonveil Protocol with a
// real self-hosted site: found by handle in both directions, conversations hosted on either side,
// end-to-end encrypted throughout, and the protocol's refusals.
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import crypto from "node:crypto";
import { startSites } from "./support/selfhost.mjs";
import { Person } from "./support/person.mjs";
import { FakeWorld, Member, FUNCTIONS, addFunctions, signed } from "./support/harness.mjs";
import { HostedFederation, forgetMemo } from "../base44/shared/federation/hosted.ts";
import { serveFederation } from "../base44/shared/federation/inbound.ts";
import { serve } from "../base44/shared/http.ts";
import { SITE, HOSTED_ENDPOINTS, siteDocument } from "../base44/shared/federation/site.ts";
import * as W from "../base44/shared/federation/wire.ts";
import * as SN from "../packages/secure-net/src/wire/federation.js";

const HOSTED = "hosted.test";
let net, world, fed, server, alpha, site;

before(async () => {
  net = await startSites(["alpha.test"]);
  alpha = net.sites["alpha.test"];
  world = new FakeWorld();
  site = { enabled: true, host: HOSTED, name: "Hosted", public_key: "" };
  fed = new HostedFederation({ sr: world.clientFor(null).asServiceRole, site, urlFor: (_host, path) => `${alpha.url}${path}`, log: { warn() {} } });
  site.public_key = (await fed.key()).public;
  // Account lookups for people from other sites follow the site's own setting.
  Object.assign(SITE, { enabled: true, host: HOSTED, public_key: site.public_key });
  // What the platform serves: the static site document, and one function per endpoint.
  server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${HOSTED}`);
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const name = Object.entries(HOSTED_ENDPOINTS).find(([, p]) => p === url.pathname)?.[0];
    let out;
    if (url.pathname === "/.well-known/commonveil") out = new Response(JSON.stringify(siteDocument(site, "test")), { headers: { "Content-Type": "application/octet-stream" } });
    else if (name) out = await serveFederation(new Request(url, { method: req.method, headers: req.headers, body: req.method === "POST" ? Buffer.concat(chunks) : undefined }), () => world.clientFor(null), name, { federation: fed });
    else out = new Response("{}", { status: 404 });
    res.writeHead(out.status, Object.fromEntries(out.headers));
    res.end(await out.text());
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  net.addHost(HOSTED, server.address().port);
  // Every function call on the hosted site goes through the relay, as http.ts's serve() does it.
  for (const [fn, actions] of Object.entries(FUNCTIONS)) addFunctions({ [fn]: actions }, { options: { federation: fed.handlers, functionName: fn, relay: (f, body, user, runLocal) => fed.relay(f, body, user, runLocal) } });
});
after(async () => {
  Object.assign(SITE, { enabled: false, public_key: "" });
  await new Promise((r) => server.close(r));
  await net?.close();
});

test("the hosted site's wire format is Secure Net's, byte for byte", async () => {
  const fields = { method: "post", to: "b.example", path: "/functions/fedact", from: "a.example", date: new Date().toISOString(), nonce: "n".repeat(22), digest: await W.digestOf('{"a":1}'), user: "u1" };
  assert.equal(W.signatureBase(fields), SN.signatureBase(fields));
  assert.equal(await W.digestOf('{"a":1}'), SN.digestOf('{"a":1}'));
  assert.equal(W.PROTOCOL, SN.PROTOCOL);
  assert.deepEqual({ ...W.DEFAULT_ENDPOINTS }, { ...SN.DEFAULT_ENDPOINTS });
  const doc = { endpoints: { act: "/functions/fedact", inbox: "https://evil.example/x", identity: "/a/../b" } };
  assert.deepEqual(W.endpointsOf(doc), SN.endpointsOf(doc));
  for (const h of ["HTTPS://Chat.Example.org/x", "bad host", "a.example:8443"]) assert.equal(W.normHost(h), SN.normHost(h));
  for (const ip of ["10.0.0.1", "8.8.8.8", "::1", "fd00::1", "::ffff:127.0.0.1", "100.64.0.1"]) assert.equal(W.isPrivate(ip), SN.isPrivate(ip), ip);
  // Signatures made on Web Crypto verify with Secure Net's Ed25519, and the other way round.
  const key = await W.generateSiteKey();
  const sig = await W.signText(key.secret, W.signatureBase(fields));
  assert.ok(SN.verifyRequest(fields, sig, key.public));
  const seed = crypto.randomBytes(32);
  const theirs = SN.signRequest(fields, seed.toString("base64url"));
  const pub = crypto.createPublicKey(crypto.createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" })).export({ format: "der", type: "spki" }).subarray(-32).toString("base64url");
  assert.ok(await W.verifyText(pub, W.signatureBase(fields), theirs));
  // Only public names: no bare addresses, no local names.
  for (const h of ["127.0.0.1", "localhost", "intranet", "db.internal", "10.1.2.3:8080", "printer.local"]) assert.equal(W.reachable(h), false, h);
  assert.ok(W.reachable("chat.example.org"));
});

test("a conversation hosted on the hosted site, with someone on a self-hosted site", async () => {
  const hana = await new Member(world, "hana").setup();
  const ben = await new Person(alpha, "ben").setup();
  const dm = (await hana.ok("conversations", await signed(hana, "create_dm", { username: "ben.alpha.test" }))).conversation;
  assert.deepEqual([...dm.member_ids].sort(), [hana.id, ben.id].sort(), "Ben keeps his own id here");
  assert.equal(await world.entities.User.get(ben.id).catch(() => null), null, "with no account on this site");
  assert.equal((await hana.send(dm, "Hello from the hosted site")).status, 200);
  const [row] = await world.entities.Message.filter({ conversation_id: dm.id });
  assert.ok(!JSON.stringify(row).includes("Hello from"), "the hosted site holds ciphertext only");

  // Ben's site was told where the conversation lives, and finds it for him.
  const polled = await ben.ok("conversations", { action: "list" });
  assert.ok(polled.conversations.some((c) => c.id === dm.id), "the conversation reaches Ben through his own site");
  const list = await ben.ok("messages", { action: "list", conversation_id: dm.id });
  const [opened] = await ben.read(list.messages, dm.member_ids);
  assert.deepEqual([opened.text, opened.status], ["Hello from the hosted site", "ok"], "verified against Hana's own key history");
  await ben.send(dm, "Hi Hana!");
  assert.deepEqual((await hana.read(dm)).map((m) => m.text), ["Hello from the hosted site", "Hi Hana!"]);
  assert.equal(alpha.app.store.has(dm.id), false, "nothing is copied to Ben's site");
});

test("a conversation hosted on a self-hosted site, with someone on the hosted site", async () => {
  const ivy = await new Member(world, "ivy_k").setup();
  const ann = await new Person(alpha, "ann").setup();
  const dm = (await ann.ok("conversations", await ann.signed("create_dm", { username: "ivy-k.hosted.test" }))).conversation;
  assert.ok(dm.member_ids.includes(ivy.id), "found by handle through the site document's endpoints");
  await ann.send(dm, "Hello Ivy");
  // Ivy's poll gathers from every site she has conversations on.
  forgetMemo();
  const polled = await ivy.ok("conversations", { action: "list" });
  assert.ok(polled.conversations.some((c) => c.id === dm.id), "the hosted site asks Ann's site on Ivy's behalf");
  assert.equal((await world.entities.Conversation.filter({})).some((c) => c.id === dm.id), false, "and keeps no copy");
  assert.deepEqual((await ivy.read(dm)).map((m) => m.text), ["Hello Ivy"]);
  assert.equal((await ivy.send(dm, "Hello Ann")).status, 200);
  const back = await ann.ok("messages", { action: "list", conversation_id: dm.id });
  assert.deepEqual((await ann.read(back.messages, dm.member_ids)).map((m) => m.text), ["Hello Ivy", "Hello Ann"]);
});

test("the hosted site refuses unsigned, replayed and out-of-place requests", async () => {
  const call = (name, init) => fetch(`http://127.0.0.1:${server.address().port}${HOSTED_ENDPOINTS[name]}`, { ...init, headers: { "X-Forwarded-Host": HOSTED, ...(init?.headers || {}) } });
  assert.equal((await call("act", { method: "POST", body: "{}" })).status, 401, "unsigned");
  assert.equal((await call("identity")).status, 404, "nobody by no name");
  const ivy = await call("identity", { method: "GET" });
  assert.equal(ivy.status, 404);

  // A properly signed request works once.
  const key = await W.generateSiteKey();
  const impostor = new HostedFederation({ sr: new FakeWorld().clientFor(null).asServiceRole, site: { enabled: true, host: "alpha.test", name: "x", public_key: key.public }, urlFor: (_h, p) => `http://127.0.0.1:${server.address().port}${p}` });
  const r = await impostor.send(HOSTED, "inbox", { type: "nonsense" });
  assert.equal(r.status, 401, "signed by a key that isn't alpha.test's pinned key");

  // Things only a person's own site does for them.
  const ben = await new Person(alpha, "ben2").setup();
  const asked = await ben.call("keys", { action: "status", _site: HOSTED });
  assert.deepEqual([asked.status, asked.data?.code ?? asked.body?.code], [403, "HOME_ONLY"]);

  // Off means off.
  site.enabled = false;
  assert.equal((await call("act", { method: "POST", body: "{}" })).status, 404);
  assert.equal(await fed.resolveHandle("ben.alpha.test", "x"), null);
  site.enabled = true;
});

test("every function on the hosted site goes through the relay, and trouble there never blocks local use", async () => {
  const kim = await new Member(world, "kim").setup();
  const lee = await new Member(world, "lee").setup();
  const call = (fn, body, client = world.clientFor(kim.user)) =>
    serve(new Request(`https://${HOSTED}/functions/${fn}`, { method: "POST", headers: { "base44-function-name": fn }, body: JSON.stringify(body) }), () => client, FUNCTIONS[fn], { trustPlatformUser: true });
  // The entry files' own path (serve), with federation on: a local conversation is untouched.
  const made = await call("conversations", await signed(kim, "create_dm", { username: "lee" }));
  assert.equal(made.status, 200);
  const dm = (await made.json()).conversation;
  assert.equal((await world.entities.FedRoute.filter({ ref_id: dm.id })).length, 0, "local things are never routed elsewhere");
  // The routing table can't be read: local calls carry on regardless.
  const real = world.clientFor(kim.user);
  const broken = { ...real, asServiceRole: { ...real.asServiceRole, entities: new Proxy(real.asServiceRole.entities, { get: (t, name) => (name === "FedRoute" ? { filter: async () => { throw new Error("down"); } } : t[name]) }) } };
  forgetMemo();
  const listed = await call("messages", { action: "list", conversation_id: dm.id }, broken);
  assert.equal(listed.status, 200);
  // Another site can't claim something that lives here.
  assert.equal(await fed.learnRoute(dm.id, "Conversation", "alpha.test"), false);
  assert.ok(lee.id);
});
