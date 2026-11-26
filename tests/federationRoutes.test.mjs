// Where things live when a site lies about it (docs/FEDERATION.md, "Routes"): three real
// self-hosted sites, one of them rogue. A site's claims count only for the person they concern, a
// person's own choice of site beats anything a site says, ids an app chooses can't steer a request,
// and two equal claims send a request nowhere until the admin blocks the wrong site.
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { startSites } from "./support/selfhost.mjs";
import { Person } from "./support/person.mjs";
import { prepareGeneration } from "../src/lib/secure/serverProtocol.js";
import { CLAIM, NOTICES_PER_HOUR, forgetNoticeCounts, forgetWarnings, migrateRoutes, namedClaimStrength, noticeAllowed, resolveRoute } from "../server/federation/index.mjs";
import { CLAIM as HOSTED_CLAIM, namedClaimStrength as hostedNamedClaimStrength, noticeAllowed as hostedNoticeAllowed, resolveRoute as hostedResolveRoute } from "../base44/shared/federation/hosted.ts";
import { functionTable } from "../server/functions.mjs";

const vectors = JSON.parse(fs.readFileSync(new URL("./vectors/route-claims.json", import.meta.url), "utf8"));
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
/** Ask until the answer is what's expected (notices between sites arrive on their own time). */
async function until(ask, ok, tries = 50) {
  let last;
  for (let i = 0; i < tries; i++) {
    last = await ask();
    if (ok(last)) return last;
    await wait(40);
  }
  return last;
}

/** Where a site sends its people's requests: [host, fn, action] for each. */
function watchTargets(site) {
  const fed = site.app.federation;
  const act = fed.act.bind(fed);
  const seen = [];
  fed.act = async (host, user, fn, body) => {
    seen.push([host, fn, body.action]);
    return act(host, user, fn, body);
  };
  return seen;
}
/** The lines a site's federation logs as warnings. */
function watchLog(site) {
  const lines = [];
  forgetWarnings();
  site.app.federation.log = { ...site.app.federation.log, warn: (...a) => lines.push(a.join(" ")) };
  return lines;
}
const sentTo = (targets, fn, action) => targets.filter(([, f, a]) => f === fn && a === action).at(-1)?.[0];

let net, home, real, rogue;
before(async () => {
  net = await startSites(["home.test", "real.test", "rogue.test"]);
  home = net.sites["home.test"];
  real = net.sites["real.test"];
  rogue = net.sites["rogue.test"];
});
after(async () => {
  await net?.close();
});

test("claims resolve the same way in the Node.js reference and on the hosted site", () => {
  assert.deepEqual(HOSTED_CLAIM, { implicit: CLAIM.implicit, legacy: CLAIM.legacy, explicit: CLAIM.explicit });
  for (const c of vectors.cases) {
    const claims = c.claims.map(([host, strength]) => ({ host, strength }));
    const want = { route: c.route, disputed: c.disputed };
    assert.deepEqual(resolveRoute(claims), want, c.name);
    assert.deepEqual(hostedResolveRoute(claims), want, `${c.name} (hosted)`);
  }
  for (const c of vectors.named) {
    const existing = c.existing.map(([host, strength]) => ({ host, strength }));
    const want = { strength: c.strength, other: c.other };
    assert.deepEqual(namedClaimStrength(existing, c.host), want, c.name);
    assert.deepEqual(hostedNamedClaimStrength(existing, c.host), want, `${c.name} (hosted)`);
  }
});

test("routes from before 0.24.25 become site-wide claims, and the old table stays for a rollback", () => {
  const db = new DatabaseSync(":memory:");
  db.exec("CREATE TABLE fed_claims (user_id TEXT NOT NULL, id TEXT NOT NULL, host TEXT NOT NULL, strength INTEGER NOT NULL, seen INTEGER NOT NULL, PRIMARY KEY (user_id, id, host))");
  db.exec(`CREATE TABLE fed_routes (id TEXT PRIMARY KEY, host TEXT NOT NULL, seen INTEGER NOT NULL); INSERT INTO fed_routes VALUES ('${"a".repeat(24)}', 'b.test', 5), ('${"b".repeat(24)}', 'c.test', 6)`);
  migrateRoutes(db);
  migrateRoutes(db);
  const rows = db.prepare("SELECT user_id, id, host, strength, seen FROM fed_claims ORDER BY id").all().map((r) => ({ ...r }));
  assert.deepEqual(rows, [
    { user_id: "*", id: "a".repeat(24), host: "b.test", strength: CLAIM.legacy, seen: 5 },
    { user_id: "*", id: "b".repeat(24), host: "c.test", strength: CLAIM.legacy, seen: 6 },
  ]);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM fed_routes").get().n, 2, "0.24.24, if the updater goes back to it, still finds its routes");
});

test("a rogue site can't take over a server it doesn't host", async () => {
  const uma = await new Person(home, "uma").setup();
  const vic = await new Person(home, "vic").setup();
  const rhea = await new Person(real, "rhea").setup();

  // Rhea runs a listed, open server on real.test.
  const { server_id: sid } = await rhea.ok("servers", await rhea.signed("create_server", { template: "blank" }));
  const state = await rhea.ok("servers", { action: "state", server_id: sid });
  const { chains: own } = await rhea.keysFor([rhea.id]);
  for (const c of state.chains) {
    const { request } = await prepareGeneration({ serverId: sid, chainId: c.chain_id, generation: 0, userId: rhea.id, device: rhea.device, chains: own, recipientIds: [] });
    await rhea.ok("servers", request);
  }
  await rhea.ok("servers", await rhea.signed("update_server_settings", { server_id: sid, discoverable: true, join_mode: "open", public: { name: "Real garden", description: "Plants", tags: ["community"] } }));

  // rogue.test has read real's public listing, and tells home.test that Uma joined that server there.
  const targets = watchTargets(home);
  const claim = (who, kind, id) => rogue.app.federation.signer.send("home.test", "inbox", { type: "membership", user_id: who.id, room: { kind, id }, joined: true });
  assert.equal((await claim(uma, "server", sid)).status, 200);
  // While nothing better is known, Uma's requests about it go to rogue.test (which hasn't got it).
  assert.notEqual((await uma.call("servers", { action: "state", server_id: sid })).status, 200);
  assert.equal(sentTo(targets, "servers", "state"), "rogue.test");

  // Vic was never named: rogue's claim doesn't touch him. He joins from real's listing and carries on.
  await vic.ok("servers", { ...(await vic.signed("join_server", { server_id: sid })), _site: "real.test" });
  assert.equal((await vic.call("servers", { action: "state", server_id: sid })).status, 200, "Vic's requests go to the server's own site");
  assert.equal(sentTo(targets, "servers", "state"), "real.test");

  // Uma joins the same way. Naming the site herself beats what rogue.test said, now and later.
  await uma.ok("servers", { ...(await uma.signed("join_server", { server_id: sid })), _site: "real.test" });
  const mine = await uma.call("servers", { action: "state", server_id: sid });
  assert.equal(mine.status, 200, JSON.stringify(mine.data));
  assert.equal(mine.data.server?.id ?? sid, sid);
  assert.equal((await claim(uma, "server", sid)).status, 200);
  assert.equal((await uma.call("servers", { action: "state", server_id: sid })).status, 200, "claiming again changes nothing");
  assert.equal(sentTo(targets, "servers", "state"), "real.test");
  assert.equal(home.app.federation.roomHost(`s.${sid}`, uma.id), "real.test", "realtime rooms follow the same routes");

  // An id an app chooses (here a thread) can't steer a request that names the server.
  const thread = "f".repeat(24);
  await claim(uma, "conversation", thread);
  const channel = state.channels.find((c) => c.kind === "text") || state.channels[0];
  const listed = await uma.call("channels", { action: "list", server_id: sid, channel_id: channel.id, thread_id: thread });
  assert.equal(listed.status, 200, JSON.stringify(listed.data));
  assert.equal(sentTo(targets, "channels", "list"), "real.test", "the thread id didn't steer it");
});

test("two sites claiming the same conversation send requests to neither, until the admin decides", async () => {
  const uma2 = await new Person(home, "uma2").setup();
  const logged = watchLog(home);
  const rex = await new Person(real, "rex").setup();
  // Rex starts a conversation with Uma2. It lives on real.test, which tells home.test.
  const dm = (await rex.ok("conversations", await rex.signed("create_dm", { username: "uma2.home.test" }))).conversation;
  await rex.send(dm, "Hello from real.test");
  const list = () => uma2.call("messages", { action: "list", conversation_id: dm.id });
  assert.equal((await until(list, (r) => r.status === 200)).status, 200, "Uma2 reads it through her site");

  // rogue.test says the same conversation is there: now nobody can tell, so it goes to neither.
  assert.equal((await rogue.app.federation.signer.send("home.test", "inbox", { type: "membership", user_id: uma2.id, room: { kind: "conversation", id: dm.id }, joined: true })).status, 200);
  const disputed = await list();
  assert.deepEqual([disputed.status, disputed.data.code], [409, "DISPUTED_SITE"]);
  const said = logged.find((l) => l.includes("each claim to hold the same thing")) || "";
  assert.match(said, /real\.test/);
  assert.match(said, /rogue\.test/);
  assert.doesNotMatch(said, /[0-9a-f]{24}/, "the log names the sites, not what or whose");

  // The admin blocks rogue.test: its claims stop counting, and the conversation works again.
  home.app.federation.signer.setBlocked("rogue.test", true);
  const back = await list();
  assert.equal(back.status, 200);
  assert.deepEqual((await uma2.read(back.data.messages, dm.member_ids)).map((m) => m.text), ["Hello from real.test"]);
  home.app.federation.signer.setBlocked("rogue.test", false);
  assert.equal((await list()).status, 409, "unblocked, its claim counts again");
});

test("joining by invite counts as naming the site, and an empty _site doesn't", async () => {
  const wes = await new Person(home, "wes").setup();
  const zoe = await new Person(home, "zoe").setup();
  const rae = await new Person(real, "rae").setup();
  const rory = await new Person(rogue, "rory").setup();
  const targets = watchTargets(home);
  const claim = (who, kind, id) => rogue.app.federation.signer.send("home.test", "inbox", { type: "membership", user_id: who.id, room: { kind, id }, joined: true });
  const keyed = async (owner, sid) => {
    const state = await owner.ok("servers", { action: "state", server_id: sid });
    const { chains: own } = await owner.keysFor([owner.id]);
    for (const c of state.chains) await owner.ok("servers", (await prepareGeneration({ serverId: sid, chainId: c.chain_id, generation: 0, userId: owner.id, device: owner.device, chains: own, recipientIds: [] })).request);
    return state;
  };

  // Rae's server on real.test is invite-only. rogue.test claims it for Wes first.
  const { server_id: sid } = await rae.ok("servers", await rae.signed("create_server", { template: "blank" }));
  await keyed(rae, sid);
  await rae.ok("servers", await rae.signed("create_invite", { server_id: sid, code: "RealGarden01" }));
  await claim(wes, "server", sid);
  // Wes joins with the invite, naming real.test. The invite carries only a code; the server it
  // joined him to now lives on real.test, for him.
  const joined = await wes.ok("servers", { ...(await wes.signed("join_server", { invite_code: "RealGarden01" })), _site: "real.test" });
  assert.equal(joined.server_id, sid);
  assert.equal((await wes.call("servers", { action: "state", server_id: sid })).status, 200);
  assert.equal(sentTo(targets, "servers", "state"), "real.test");

  // Rory's server on rogue.test is genuinely there, open to anyone. rogue.test tells home.test
  // that Zoe joined it. Zoe's app sends a join with an empty _site: that isn't naming a site, so it
  // goes where the claims say, and the claim stays a heard one.
  const { server_id: rsid } = await rory.ok("servers", await rory.signed("create_server", { template: "blank" }));
  await keyed(rory, rsid);
  await rory.ok("servers", await rory.signed("update_server_settings", { server_id: rsid, discoverable: true, join_mode: "open", public: { name: "Rogue garden", description: "Weeds", tags: ["community"] } }));
  await claim(zoe, "server", rsid);
  const r = await zoe.call("servers", { ...(await zoe.signed("join_server", { server_id: rsid })), _site: "" });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.equal(sentTo(targets, "servers", "join_server"), "rogue.test");
  const best = home.app.store.db.prepare("SELECT MAX(strength) AS s FROM fed_claims WHERE user_id = ? AND id = ?").get(zoe.id, rsid).s;
  assert.equal(Number(best), CLAIM.implicit, "an empty _site never counts as the person's choice");
});

test("a route a site took over before the update is named in the log, rejoining can't move it, and blocking that site ends it", async () => {
  const yan = await new Person(home, "yan").setup();
  const xia = await new Person(home, "xia").setup();
  const ren = await new Person(real, "ren").setup();
  const targets = watchTargets(home);
  const logged = watchLog(home);
  const { server_id: sid } = await ren.ok("servers", await ren.signed("create_server", { template: "blank" }));
  const state = await ren.ok("servers", { action: "state", server_id: sid });
  const { chains: own } = await ren.keysFor([ren.id]);
  for (const c of state.chains) await ren.ok("servers", (await prepareGeneration({ serverId: sid, chainId: c.chain_id, generation: 0, userId: ren.id, device: ren.device, chains: own, recipientIds: [] })).request);
  await ren.ok("servers", await ren.signed("update_server_settings", { server_id: sid, discoverable: true, join_mode: "open", public: { name: "Ren's garden", description: "Plants", tags: ["community"] } }));

  // Before the update, rogue.test took over the route: 0.24.24 wrote it to fed_routes, and the
  // update made it a site-wide claim.
  home.app.store.db.prepare("INSERT INTO fed_claims (user_id, id, host, strength, seen) VALUES ('*', ?, 'rogue.test', ?, ?)").run(sid, CLAIM.legacy, Date.now());
  // Yan joined back then, so his requests follow the old route, until something stronger.
  await real.app.federation.signer.send("home.test", "inbox", { type: "membership", user_id: yan.id, room: { kind: "server", id: sid }, joined: true });
  assert.notEqual((await yan.call("servers", { action: "state", server_id: sid })).status, 200);
  assert.equal(sentTo(targets, "servers", "state"), "rogue.test");
  const said = logged.find((l) => l.includes("a route from before 0.24.25")) || "";
  assert.match(said, /rogue\.test \(a route from before 0\.24\.25\) and real\.test/);
  assert.doesNotMatch(said, /[0-9a-f]{24}/);

  // Xia joins now, naming real.test. Home can't tell which site is honest, so naming a site never
  // moves something another site already holds by an old route: it stays, and the log says so.
  await xia.ok("servers", { ...(await xia.signed("join_server", { server_id: sid })), _site: "real.test" });
  const before = targets.length;
  await xia.call("servers", { action: "state", server_id: sid });
  assert.equal(sentTo(targets.slice(before), "servers", "state"), "rogue.test");
  assert.ok(logged.some((l) => l.includes("real.test answered as the home of something rogue.test already holds")));

  // The admin reads the log and blocks rogue.test: its old route stops counting for everyone.
  home.app.federation.signer.setBlocked("rogue.test", true);
  const yans = await yan.call("servers", { action: "state", server_id: sid });
  assert.equal(sentTo(targets, "servers", "state"), "real.test");
  assert.notEqual(yans.data.code, "SITE_BLOCKED");
  assert.equal((await xia.call("servers", { action: "state", server_id: sid })).status, 200, "Xia, a member, gets real's server");
  assert.equal(sentTo(targets, "servers", "state"), "real.test");
  home.app.federation.signer.setBlocked("rogue.test", false);
});

test("a site answering a join can't take over a server someone already has", async () => {
  const ann = await new Person(home, "ann_j").setup();
  const bob = await new Person(home, "bob_j").setup();
  const cy = await new Person(home, "cy_j").setup();
  const reg = await new Person(real, "reg").setup();
  const targets = watchTargets(home);
  const logged = watchLog(home);
  const listed = async (name) => {
    const { server_id: id } = await reg.ok("servers", await reg.signed("create_server", { template: "blank" }));
    const state = await reg.ok("servers", { action: "state", server_id: id });
    const { chains: own } = await reg.keysFor([reg.id]);
    for (const c of state.chains) await reg.ok("servers", (await prepareGeneration({ serverId: id, chainId: c.chain_id, generation: 0, userId: reg.id, device: reg.device, chains: own, recipientIds: [] })).request);
    await reg.ok("servers", await reg.signed("update_server_settings", { server_id: id, discoverable: true, join_mode: "open", public: { name, description: "Plants", tags: ["community"] } }));
    return id;
  };
  const sid = await listed("Reg's garden");
  const sid2 = await listed("Reg's other garden");
  // Ann joined before the update (an old route); Bob joined since, from real's listing.
  home.app.store.db.prepare("INSERT INTO fed_claims (user_id, id, host, strength, seen) VALUES ('*', ?, 'real.test', ?, ?)").run(sid, CLAIM.legacy, Date.now());
  await bob.ok("servers", { ...(await bob.signed("join_server", { server_id: sid })), _site: "real.test" });

  // rogue.test sends them an invite. Whatever the code, its join answer names real's server.
  const table = functionTable({ defaultAdmins: [] });
  const [actions, options] = table.servers;
  const before = rogue.app.federation.functions;
  let answer = sid;
  rogue.app.federation.functions = { ...table, servers: [{ ...actions, join_server: async () => ({ server_id: answer, joined: true }) }, options] };
  try {
    for (const who of [ann, bob]) {
      const r = await who.call("servers", { ...(await who.signed("join_server", { invite_code: "Crafted001" })), _site: "rogue.test" });
      assert.equal(r.status, 200, "rogue.test answered the join");
      assert.equal(r.data.server_id, sid);
      const after = await who.call("servers", { action: "state", server_id: sid });
      assert.equal(sentTo(targets, "servers", "state"), "real.test", "their requests stay with real.test");
      if (who === bob) assert.equal(after.status, 200, JSON.stringify(after.data));
    }
    // Cy has nothing of real's other server. She joins one of rogue.test's own servers, and is
    // answered with real's: only the server she named counts as her choice.
    answer = sid2;
    const r = await cy.call("servers", { ...(await cy.signed("join_server", { server_id: "c".repeat(24) })), _site: "rogue.test" });
    assert.equal(r.data.server_id, sid2, "rogue.test answered with real's server");
  } finally {
    rogue.app.federation.functions = before;
  }
  // So when Cy joins it from real's listing, that's what counts for her.
  await cy.ok("servers", { ...(await cy.signed("join_server", { server_id: sid2 })), _site: "real.test" });
  assert.equal((await cy.call("servers", { action: "state", server_id: sid2 })).status, 200);
  assert.equal(sentTo(targets, "servers", "state"), "real.test");
  const said = logged.find((l) => l.includes("answered as the home of something")) || "";
  assert.match(said, /rogue\.test answered as the home of something real\.test already holds/);
  assert.doesNotMatch(said, /[0-9a-f]{24}/);
});

test("a site can't steer a chosen id by notice, push out an honest claim, flood notices, or keep claims after an account is deleted", async () => {
  const una = await new Person(home, "una").setup();
  const db = home.app.store.db;
  const fed = home.app.federation;
  const targets = watchTargets(home);
  const notice = (who, kind, id) => rogue.app.federation.signer.send("home.test", "inbox", { type: "membership", user_id: who.id, room: { kind, id }, joined: true });

  // A notice is a heard claim. A request that names only an id an app chooses (an event here)
  // routes only by chosen claims, so the notice can't send it to rogue.test.
  const event = "e".repeat(24);
  assert.equal((await notice(una, "conversation", event)).status, 200);
  await una.call("events", { action: "shared_event", event_id: event });
  assert.equal(sentTo(targets, "events", "shared_event"), undefined, "the event request stayed here");

  // Lots of claims from an honest site never push out its older ones, so a rogue notice about an
  // old room can't become the only claim (independent review, round 3).
  const room = "c".repeat(24);
  const put = db.prepare("INSERT OR IGNORE INTO fed_claims (user_id, id, host, strength, seen) VALUES (?, ?, 'real.test', ?, ?)");
  put.run(una.id, room, CLAIM.implicit, 1);
  for (let i = 0; i < 2500; i++) put.run(una.id, i.toString(16).padStart(24, "b"), CLAIM.implicit, i + 2);
  assert.equal(fed.routeOf(una.id, room).route, "real.test");
  // One more claim from real.test itself (here a notice), then rogue.test's notice about the old room.
  const fromReal = await real.app.federation.signer.send("home.test", "inbox", { type: "membership", user_id: una.id, room: { kind: "conversation", id: "d".repeat(24) }, joined: true });
  assert.equal(fromReal.status, 200);
  assert.ok(db.prepare("SELECT 1 FROM fed_claims WHERE user_id = ? AND id = ? AND host = 'real.test'").get(una.id, room), "real.test's old claim stays");
  assert.equal((await notice(una, "conversation", room)).status, 200);
  assert.equal(fed.routeOf(una.id, room).route, null, "a dispute at worst, never rogue.test");
  assert.deepEqual(fed.routeOf(una.id, room).disputed, ["real.test", "rogue.test"]);

  // One site's membership notices are capped per hour.
  forgetNoticeCounts();
  const hour = 1_000 * 3_600_000;
  for (let i = 0; i < NOTICES_PER_HOUR; i++) assert.ok(noticeAllowed(`flood.test ${una.id}`, hour));
  assert.equal(noticeAllowed(`flood.test ${una.id}`, hour), false);
  assert.ok(noticeAllowed(`other.test ${una.id}`, hour), "other sites are counted apart");
  assert.ok(noticeAllowed("flood.test " + "f".repeat(24), hour), "and other people");
  assert.ok(noticeAllowed(`flood.test ${una.id}`, hour + 3_600_000), "and the next hour starts again");
  assert.ok(hostedNoticeAllowed(`flood.test ${una.id}`, hour));
  forgetNoticeCounts();

  // At the cap, a notice refreshing a claim rogue.test already has still goes through; one adding
  // a new claim is refused.
  // Not across the turn of the hour, when the count would start again.
  const toNextHour = 3_600_000 - (Date.now() % 3_600_000);
  if (toNextHour < 30_000) await new Promise((r) => setTimeout(r, toNextHour + 100));
  for (let i = 0; i < NOTICES_PER_HOUR; i++) noticeAllowed(`rogue.test ${una.id}`);
  const refresh = await notice(una, "conversation", room);
  assert.equal(refresh.status, 200);
  assert.equal(refresh.body?.ok ?? refresh.data?.ok, true);
  const fresh = await notice(una, "conversation", "a".repeat(24));
  assert.equal(fresh.body?.code ?? fresh.data?.code, "TOO_MANY_NOTICES");
  assert.equal(db.prepare("SELECT 1 FROM fed_claims WHERE user_id = ? AND id = ?").get(una.id, "a".repeat(24)), undefined);
  forgetNoticeCounts();
  const count = () => Number(db.prepare("SELECT COUNT(*) AS n FROM fed_claims WHERE user_id = ?").get(una.id).n);

  // Deleting the account forgets their claims and the sites they use.
  db.prepare("INSERT OR IGNORE INTO fed_user_hosts (user_id, host, seen) VALUES (?, 'rogue.test', 1)").run(una.id);
  const table = (await home.app.store.entities.Person.get(una.id).catch(() => null)) ? "Person" : "User";
  await home.app.store.entities[table].delete(una.id);
  assert.equal(count(), 0);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM fed_user_hosts WHERE user_id = ?").get(una.id).n, 0);
});

test("chosen ids keep their routes, never steer a request naming other ids, and a disputed id stops a relay", async () => {
  const vic = await new Person(home, "quinn").setup();
  const db = home.app.store.db;
  const targets = watchTargets(home);
  const put = db.prepare("INSERT INTO fed_claims (user_id, id, host, strength, seen, chosen) VALUES (?, ?, ?, ?, ?, ?)");
  const ask = (body) => vic.call("events", { action: "shared_event", ...body }).catch((e) => e);
  const last = () => sentTo(targets, "events", "shared_event");

  // real.test gave the event as a chosen id and also as one of its own records (strength 1): the
  // chosen route stays.
  const event = "1".repeat(24);
  put.run(vic.id, event, "real.test", CLAIM.implicit, Date.now(), 1);
  await ask({ event_id: event });
  assert.equal(last(), "real.test");

  // A route from before 0.24.25 still routes an event request.
  const old = "2".repeat(24);
  put.run("*", old, "real.test", CLAIM.legacy, Date.now(), 0);
  targets.length = 0;
  await ask({ event_id: old });
  assert.equal(last(), "real.test");

  // A request that names a server too never goes where only the event's route points.
  targets.length = 0;
  await ask({ event_id: event, server_id: "3".repeat(24) });
  assert.equal(last(), undefined, "stays here");

  // One id routes to real.test and another is disputed between real.test and rogue.test: the
  // request goes to real.test, so rogue.test can't block what the rest of it settles.
  const routed = "4".repeat(24);
  const tied = "5".repeat(24);
  put.run(vic.id, routed, "real.test", CLAIM.implicit, Date.now(), 0);
  put.run(vic.id, tied, "real.test", CLAIM.implicit, Date.now(), 0);
  put.run(vic.id, tied, "rogue.test", CLAIM.implicit, Date.now(), 0);
  targets.length = 0;
  await vic.call("messages", { action: "list", conversation_id: routed, channel_id: tied }).catch((e) => e);
  assert.equal(sentTo(targets, "messages", "list"), "real.test");
  assert.equal(home.app.federation.roomHost(`${routed}.${tied}`, vic.id), "real.test");

  // Disputed between two other sites: nowhere, not even where the other id points.
  const elsewhere = "7".repeat(24);
  put.run(vic.id, elsewhere, "rogue.test", CLAIM.implicit, Date.now(), 0);
  put.run(vic.id, elsewhere, "third.test", CLAIM.implicit, Date.now(), 0);
  targets.length = 0;
  const r = await vic.call("messages", { action: "list", conversation_id: routed, channel_id: elsewhere }).catch((e) => e);
  assert.equal(sentTo(targets, "messages", "list"), undefined);
  assert.equal(r.code ?? r.data?.code ?? r.body?.code, "DISPUTED_SITE");
  assert.equal(home.app.federation.roomHost(`${routed}.${elsewhere}`, vic.id), null);
  assert.equal(home.app.federation.roomHost(`${routed}.${"6".repeat(24)}`, vic.id), "real.test");
});
