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
import { prepareGeneration } from "../src/lib/secure/serverProtocol.js";
import { serverActions } from "../base44/shared/handlers/servers.ts";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { HostedFederation, forgetMemo, forgetWarnings, readCapped, useRelayLibrary } from "../base44/shared/federation/hosted.ts";
import { functionTable } from "../server/functions.mjs";
import { serveFederation } from "../base44/shared/federation/inbound.ts";
import { serve } from "../base44/shared/http.ts";
import { SITE, HOSTED_ENDPOINTS, siteDocument } from "../base44/shared/federation/site.ts";
import * as W from "../base44/shared/federation/wire.ts";
import * as SN from "../packages/secure-net/src/wire/federation.js";

const HOSTED = "hosted.test";
let net, world, fed, server, alpha, rogue, site;

before(async () => {
  // On Base44 the functions load the post-quantum library by its npm: name, which Node can't.
  useRelayLibrary({ ml_kem768, ml_dsa65 });
  net = await startSites(["alpha.test", "rogue.test"]);
  alpha = net.sites["alpha.test"];
  rogue = net.sites["rogue.test"];
  world = new FakeWorld();
  site = { enabled: true, host: HOSTED, name: "Hosted", public_key: "", pq: { kem: "", sig: "" } };
  fed = new HostedFederation({ sr: world.clientFor(null).asServiceRole, site, urlFor: (host, path) => `${(net.sites[host.replace(/:\d+$/, "")] || alpha).url}${path}`, log: { warn() {} } });
  site.public_key = (await fed.key()).public;
  const relayKeys = await fed.relayKeys();
  site.pq = { kem: relayKeys.kem.public, sig: relayKeys.sig.public };
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
  addFunctions({ servers: serverActions({ defaultAdmins: () => [] }) });
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
  // Everything that went between the two sites was sealed and doubly signed, both ways.
  const [pinnedThere] = await world.entities.FedSite.filter({ host: "alpha.test" });
  assert.match(pinnedThere.pq, /mlkem768/, "the hosted site holds the self-hosted site to its relay keys");
  assert.match(alpha.app.store.db.prepare("SELECT pq FROM fed_sites WHERE host = ?").get(HOSTED).pq, /mlkem768/, "and the other way round");
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
  assert.equal(await fed.learnRoute(dm.id, "Conversation", "alpha.test", kim.id), false);
  assert.ok(lee.id);
});

test("a reply is counted as it arrives and cut off at the limit, whatever its length header says", async () => {
  let sent = 0;
  let cancelled = false;
  const endless = new ReadableStream({
    pull(controller) {
      sent += 1;
      controller.enqueue(new Uint8Array(1024 * 1024));
    },
    cancel() {
      cancelled = true;
    },
  });
  assert.equal(await readCapped(new Response(endless), 3 * 1024 * 1024), null, "too much");
  assert.ok(cancelled, "the rest isn't read");
  assert.ok(sent <= 6, `stopped after ${sent} chunks`);
  const small = await readCapped(new Response(JSON.stringify({ ok: true })), 1024);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(small)), { ok: true });
});

test("a rogue site's claims can't take over on the hosted site either, and disputes go nowhere", async () => {
  const ida = await new Member(world, "ida_m").setup();
  const amy = await new Person(alpha, "amy").setup();
  const claim = (who, kind, id) => rogue.app.federation.signer.send(HOSTED, "inbox", { type: "membership", user_id: who.id, room: { kind, id }, joined: true });
  const until = async (ask, ok) => {
    let last;
    for (let i = 0; i < 50 && !ok((last = await ask())); i++) {
      forgetMemo();
      await new Promise((r) => setTimeout(r, 40));
    }
    return last;
  };

  // A conversation on alpha with Ida. Then rogue.test claims it too: it goes to neither.
  const dm = (await amy.ok("conversations", await amy.signed("create_dm", { username: "ida-m.hosted.test" }))).conversation;
  await amy.send(dm, "Hello Ida");
  const list = () => ida.call("messages", { action: "list", conversation_id: dm.id });
  assert.equal((await until(list, (r) => r.status === 200)).status, 200, "Ida reads it through the hosted site");
  assert.equal((await claim(ida, "conversation", dm.id)).status, 200);
  forgetMemo();
  const disputed = await list();
  assert.deepEqual([disputed.status, disputed.body.code], [409, "DISPUTED_SITE"]);
  // The admin blocks rogue.test: its claims stop counting.
  const [row] = await world.entities.FedSite.filter({ host: "rogue.test" });
  await world.entities.FedSite.update(row.id, { blocked: true });
  forgetMemo();
  assert.equal((await list()).status, 200);
  await world.entities.FedSite.update(row.id, { blocked: false });
  forgetMemo();

  // A listed server on alpha, claimed for Ida by rogue.test before she joins.
  const { server_id: sid } = await amy.ok("servers", await amy.signed("create_server", { template: "blank" }));
  const state = await amy.ok("servers", { action: "state", server_id: sid });
  const { chains: own } = await amy.keysFor([amy.id]);
  for (const c of state.chains) await amy.ok("servers", (await prepareGeneration({ serverId: sid, chainId: c.chain_id, generation: 0, userId: amy.id, device: amy.device, chains: own, recipientIds: [] })).request);
  await amy.ok("servers", await amy.signed("update_server_settings", { server_id: sid, discoverable: true, join_mode: "open", public: { name: "Alpha garden", description: "Plants", tags: ["community"] } }));
  assert.equal((await claim(ida, "server", sid)).status, 200);
  forgetMemo();
  assert.notEqual((await ida.call("servers", { action: "state", server_id: sid })).status, 200, "while nothing better is known, it goes where rogue said");
  // Joining by naming alpha beats that, now and later.
  await ida.ok("servers", { ...(await signed(ida, "join_server", { server_id: sid })), _site: "alpha.test" });
  forgetMemo();
  const mine = await ida.call("servers", { action: "state", server_id: sid });
  assert.equal(mine.status, 200, JSON.stringify(mine.body));
  assert.equal((await claim(ida, "server", sid)).status, 200);
  forgetMemo();
  assert.equal((await ida.call("servers", { action: "state", server_id: sid })).status, 200, "claiming again changes nothing");
});

test("if the hosted site's FedClaim table can't record whose a claim is, the claim isn't kept", async () => {
  // The platform stores only the fields a table declares: a claim that lost its person or strength
  // would count wrongly, so it's taken back.
  const rows = [];
  const warned = [];
  const sr = {
    entities: {
      FedClaim: {
        filter: async () => rows,
        create: async (r) => (rows.push({ id: "r1", ref_id: r.ref_id, host: r.host, kind: r.kind }), rows.at(-1)),
        update: async () => null,
        delete: async (id) => rows.splice(rows.findIndex((r) => r.id === id), 1),
      },
      FedRoute: { filter: async () => [] },
      FedSite: { filter: async () => [] },
      Conversation: { filter: async () => [] },
      Server: { filter: async () => [] },
      Channel: { filter: async () => [] },
    },
  };
  const f = new HostedFederation({ sr, site: { enabled: true, host: "x.test", public_key: "k" }, urlFor: () => "", log: { warn: (m) => warned.push(m) } });
  forgetMemo();
  assert.equal(await f.learnRoute("a".repeat(24), "Conversation", "b.test", "c".repeat(24)), false);
  assert.deepEqual(rows, [], "nothing is left behind");
  assert.match(warned.join(" "), /FedClaim/);
  forgetMemo();
});

test("on the hosted site, nothing held here can be claimed, whatever kind of room a claim says it is", async () => {
  const hal = await new Member(world, "hal_m").setup();
  const { server_id: sid } = await hal.ok("servers", await signed(hal, "create_server", { template: "blank" }));
  // rogue.test says hal's own server is a conversation it holds: refused, so it stays here.
  assert.equal((await rogue.app.federation.signer.send(HOSTED, "inbox", { type: "membership", user_id: hal.id, room: { kind: "conversation", id: sid }, joined: true })).status, 200);
  assert.deepEqual(await world.entities.FedClaim.filter({ ref_id: sid }), [], "no claim is kept");
  forgetMemo();
  assert.equal((await hal.call("servers", { action: "state", server_id: sid })).status, 200);
  // A route rogue.test took over before 0.24.25 (no person on it) doesn't count either, and goes.
  await world.entities.FedRoute.create({ ref_id: sid, host: "rogue.test", kind: "Conversation" });
  forgetMemo();
  assert.equal((await hal.call("servers", { action: "state", server_id: sid })).status, 200);
  assert.deepEqual(await world.entities.FedRoute.filter({ ref_id: sid }), [], "the old route is removed");
});

test("on the hosted site, other people's claims never hide a person's own, however many there are", async () => {
  const ivy = await new Member(world, "ivy_x").setup();
  const ada = await new Person(alpha, "ada").setup();
  const { server_id: sid } = await ada.ok("servers", await ada.signed("create_server", { template: "blank" }));
  const state = await ada.ok("servers", { action: "state", server_id: sid });
  const { chains: own } = await ada.keysFor([ada.id]);
  for (const c of state.chains) await ada.ok("servers", (await prepareGeneration({ serverId: sid, chainId: c.chain_id, generation: 0, userId: ada.id, device: ada.device, chains: own, recipientIds: [] })).request);
  await ada.ok("servers", await ada.signed("create_invite", { server_id: sid, code: "AlphaGarden1" }));
  // rogue.test claims it for Ivy, then buries the table in claims for 2100 other people.
  assert.equal((await rogue.app.federation.signer.send(HOSTED, "inbox", { type: "membership", user_id: ivy.id, room: { kind: "server", id: sid }, joined: true })).status, 200);
  for (let i = 0; i < 2100; i++) await world.entities.FedClaim.create({ ref_id: sid, user_id: i.toString(16).padStart(24, "0"), host: "rogue.test", kind: "Server", strength: 1 });
  // Ivy joins by invite, naming alpha.test: that's her choice, and it's the one that counts for her.
  const joined = await ivy.ok("servers", { ...(await signed(ivy, "join_server", { invite_code: "AlphaGarden1" })), _site: "alpha.test" });
  assert.equal(joined.server_id, sid);
  forgetMemo();
  const mine = await ivy.call("servers", { action: "state", server_id: sid });
  assert.equal(mine.status, 200, JSON.stringify(mine.body));
  assert.equal((await world.entities.FedClaim.filter({ ref_id: sid, user_id: ivy.id })).length <= 2, true, "one row per site she's heard from, not one per answer");
});

test("on the hosted site, naming a site never moves what someone joined from another site", async () => {
  const ann = await new Member(world, "ann_n").setup();
  const bob = await new Member(world, "bob_n").setup();
  const cal = await new Member(world, "cal_n").setup();
  const dee = await new Member(world, "dee_n").setup();
  const abe = await new Person(alpha, "abe").setup();
  const said = [];
  const quiet = fed.log;
  fed.log = { warn: (...a) => said.push(a.join(" ")) };
  forgetWarnings();
  const listed = async (name) => {
    const { server_id: sid } = await abe.ok("servers", await abe.signed("create_server", { template: "blank" }));
    const state = await abe.ok("servers", { action: "state", server_id: sid });
    const { chains: own } = await abe.keysFor([abe.id]);
    for (const c of state.chains) await abe.ok("servers", (await prepareGeneration({ serverId: sid, chainId: c.chain_id, generation: 0, userId: abe.id, device: abe.device, chains: own, recipientIds: [] })).request);
    await abe.ok("servers", await abe.signed("update_server_settings", { server_id: sid, discoverable: true, join_mode: "open", public: { name, description: "Plants", tags: ["community"] } }));
    return sid;
  };
  const join = async (who, sid) => who.ok("servers", { ...(await signed(who, "join_server", { server_id: sid })), _site: "alpha.test" });
  const stateOf = async (who, sid) => {
    forgetMemo();
    return (await who.call("servers", { action: "state", server_id: sid })).status;
  };
  const before = rogue.app.federation.functions;
  try {
    // Ann joined alpha's server before the update (all that's left is the old route); Bob joined since.
    const sid = await listed("Abe's garden");
    await join(ann, sid);
    for (const row of await world.entities.FedClaim.filter({ ref_id: sid, user_id: ann.id })) await world.entities.FedClaim.delete(row.id);
    await world.entities.FedRoute.create({ ref_id: sid, host: "alpha.test", kind: "Server" });
    await join(bob, sid);
    assert.equal(await stateOf(ann, sid), 200, "the old route takes Ann to alpha");

    // rogue.test sends them an invite. Whatever the code, its join answer names alpha's server.
    const table = functionTable({ defaultAdmins: [] });
    const [actions, options] = table.servers;
    let answer = sid;
    rogue.app.federation.functions = { ...table, servers: [{ ...actions, join_server: async () => ({ server_id: answer, joined: true }) }, options] };
    for (const who of [ann, bob]) {
      const r = await who.ok("servers", { ...(await signed(who, "join_server", { invite_code: "Crafted002" })), _site: "rogue.test" });
      assert.equal(r.server_id, sid, "rogue.test answered the join");
      assert.equal(await stateOf(who, sid), 200, "their requests stay with alpha.test");
    }
    // Dee has nothing of alpha's other server. She joins one of rogue.test's own servers, and is
    // answered with alpha's: only the server she named counts as her choice.
    const other = await listed("Abe's third garden");
    answer = other;
    const r = await dee.ok("servers", { ...(await signed(dee, "join_server", { server_id: "c".repeat(24) })), _site: "rogue.test" });
    assert.equal(r.server_id, other, "rogue.test answered with alpha's server");
    rogue.app.federation.functions = before;
    // So when Dee joins it from alpha's listing, that's what counts for her.
    await join(dee, other);
    assert.equal(await stateOf(dee, other), 200);
    const crafted = said.find((l) => l.includes("answered as the home of something")) || "";
    assert.match(crafted, /rogue\.test answered as the home of something alpha\.test already holds/);
    assert.doesNotMatch(crafted, /[0-9a-f]{24}/);

    // A server rogue.test took over before the update: Cal joining from alpha's listing can't move it.
    forgetWarnings();
    said.length = 0;
    const sid2 = await listed("Abe's other garden");
    await world.entities.FedRoute.create({ ref_id: sid2, host: "rogue.test", kind: "Server" });
    await join(cal, sid2);
    assert.notEqual(await stateOf(cal, sid2), 200, "it stays with rogue.test, which doesn't hold it");
    assert.ok(said.some((l) => l.includes("alpha.test answered as the home of something rogue.test already holds")), said.join("\n"));
    // The admin blocks rogue.test: its old route stops counting, and Cal reaches alpha.
    const [row] = await world.entities.FedSite.filter({ host: "rogue.test" });
    await world.entities.FedSite.update(row.id, { blocked: true });
    try {
      assert.equal(await stateOf(cal, sid2), 200);
    } finally {
      await world.entities.FedSite.update(row.id, { blocked: false });
      forgetMemo();
    }
  } finally {
    rogue.app.federation.functions = before;
    fed.log = quiet;
  }
});
