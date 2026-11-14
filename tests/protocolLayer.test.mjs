// The experimental protocol layer, end to end: the real client code (pq/layer.js, pq/engine.js,
// protocol.js) against the real backend handlers, with only the database in memory.
import test from "node:test";
import assert from "node:assert/strict";
import { world, addFunctions, signed } from "./support/harness.mjs";
import { protocolActions } from "../base44/shared/handlers/protocol.ts";
import { PqLayer, memoryStore } from "../src/lib/secure/pq/layer.js";
import { buildMessage, openItem } from "../src/lib/secure/protocol.js";

addFunctions({ protocol: protocolActions });
const HOST = "site.example";

function layerFor(member, username = member.name) {
  const store = memoryStore();
  const layer = new PqLayer({
    store,
    host: HOST,
    account: () => ({ userId: member.id, username, device: member.device, keyring: member.keyring }),
    call: async (fn, body) => {
      const r = await member.call(fn, body);
      if (r.status !== 200) throw Object.assign(new Error(r.body.error || r.body.code), { code: r.body.code, status: r.status });
      return r.body;
    },
  });
  return { layer, store };
}

const names = (...members) => Object.fromEntries(members.map((m) => [m.id, m.name]));

async function send(member, layer, conversation, text, usernames) {
  const { chains } = await member.chainsFor(conversation);
  const body = await buildMessage({ userId: member.id, device: member.device, conversation, chains, text, keyring: member.keyring, fs: layer ? layer.wrapperFor(conversation, usernames) : null });
  const r = await member.call("messages", body);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return r.body.message;
}

async function read(member, layer, conversation) {
  const { chains, devices } = await member.chainsFor(conversation);
  const { messages } = await member.ok("messages", { action: "list", conversation_id: conversation.id });
  const out = [];
  for (const m of messages) out.push(await openItem({ kind: "message", item: m, userId: member.id, keyring: member.keyring, senderChain: chains.get(m.sender_id), senderDevices: devices.get(m.sender_id), fsOpen: layer ? layer.opener() : null }));
  return out;
}

test("with the layer on for both, a direct message needs its one-off key as well as the account keys", async () => {
  const { w, members: [alice, bob] } = await world("alice", "bob");
  const conv = await alice.dm(bob);
  const a = layerFor(alice);
  const b = layerFor(bob);
  assert.equal((await a.layer.enable()).handle, "@alice@site.example");
  await b.layer.enable();
  const u = names(alice, bob);

  await send(alice, a.layer, conv, "first, with the layer", u);
  // Bob's account keys alone open the outer envelope and find only a sealed payload.
  let got = await read(bob, null, conv);
  assert.equal(got[0].status, "locked");
  assert.equal(got[0].code, "FS_KEY_MISSING");
  got = await read(bob, b.layer, conv);
  assert.equal(got[0].code, "FS_KEY_MISSING", "not before his device has collected the key");
  assert.equal(await b.layer.sync(u), 1);
  got = await read(bob, b.layer, conv);
  assert.deepEqual([got[0].status, got[0].text, got[0].forwardSecret], ["ok", "first, with the layer", true]);
  // Alice reads her own message from the key she kept.
  assert.equal((await read(alice, a.layer, conv))[0].text, "first, with the layer");

  // Both ways, several times: sessions ratchet, every message has its own key.
  await send(bob, b.layer, conv, "reply", u);
  await send(alice, a.layer, conv, "third", u);
  await send(alice, a.layer, conv, "fourth", u);
  await a.layer.sync(u);
  await b.layer.sync(u);
  assert.deepEqual((await read(alice, a.layer, conv)).map((m) => m.text), ["first, with the layer", "reply", "third", "fourth"]);
  assert.deepEqual((await read(bob, b.layer, conv)).map((m) => m.text), ["first, with the layer", "reply", "third", "fourth"]);

  // What the server holds never contains the text or a usable key, and the mailbox empties.
  const everything = JSON.stringify(Object.keys(w.entities).map((n) => w.rows(n)));
  for (const secret of ["with the layer", "reply", "third", "fourth"]) assert.ok(!everything.includes(secret));
  assert.equal(w.rows("ProtoMail").length, 0);
});

test("without the layer on the other side, messages go exactly as before", async () => {
  const { members: [alice, bob] } = await world("alice", "bob");
  const conv = await alice.dm(bob);
  const a = layerFor(alice);
  await a.layer.enable();
  await send(alice, a.layer, conv, "plain old message", names(alice, bob));
  const got = await read(bob, null, conv);
  assert.deepEqual([got[0].status, got[0].text, got[0].forwardSecret], ["ok", "plain old message", undefined]);
  // And group conversations never use it in this release.
  const { members: [c, d, e] } = await world("carol", "dave", "erin");
  const group = await c.group(["dave", "erin"]);
  const cl = layerFor(c);
  await cl.layer.enable();
  assert.equal(cl.layer.wrapperFor(group, names(c, d, e)), null);
});

test("a second device joins the same identity and gets later keys; earlier messages stay sealed to it", async () => {
  const { members: [alice, bob] } = await world("alice", "bob");
  const conv = await alice.dm(bob);
  const u = names(alice, bob);
  const a = layerFor(alice);
  const b = layerFor(bob);
  await a.layer.enable();
  await b.layer.enable();
  await send(alice, a.layer, conv, "before the phone", u);
  await b.layer.sync(u);

  const linked = await bob.linkDevice("Phone");
  const phone = bob.as(linked.device, linked.keyring);
  const p = layerFor(phone, "bob");
  const status = await p.layer.enable();
  assert.equal(status.actorId, b.layer.status().actorId, "same identity");
  assert.equal(status.devices, 2);

  await send(alice, a.layer, conv, "after the phone", u);
  await p.layer.sync(u);
  await b.layer.sync(u);
  const onPhone = await read(phone, p.layer, conv);
  assert.deepEqual(onPhone.map((m) => m.code || m.text), ["FS_KEY_MISSING", "after the phone"]);
  assert.deepEqual((await read(bob, b.layer, conv)).map((m) => m.text), ["before the phone", "after the phone"]);
  // What Bob sends from his laptop reaches his phone too.
  await send(bob, b.layer, conv, "from the laptop", u);
  await p.layer.sync(u);
  assert.equal((await read(phone, p.layer, conv)).at(-1).text, "from the laptop");
});

test("the server only takes well-formed envelopes, for contacts' listed devices, from the right people", async () => {
  const { w, members: [alice, bob, mallory] } = await world("alice", "bob", "mallory");
  const conv = await alice.dm(bob);
  const u = names(alice, bob);
  const a = layerFor(alice);
  const b = layerFor(bob);
  const m = layerFor(mallory);
  await a.layer.enable();
  await b.layer.enable();
  await m.layer.enable();
  await send(alice, a.layer, conv, "hello", u);
  const mail = w.rows("ProtoMail")[0];
  const env = JSON.parse(mail.envelope);

  // Mallory shares no conversation with Bob: she can't see his identity, take his prekeys or write to his mailbox.
  assert.deepEqual((await mallory.ok("protocol", { action: "actors", user_ids: [bob.id] })).actors, []);
  await mallory.fails("protocol", { action: "bundle", user_id: bob.id, device: env.device }, "NOT_FOUND");
  const before = w.rows("ProtoMail").length;
  assert.equal((await mallory.ok("protocol", { action: "send", items: [{ to: bob.id, envelope: mail.envelope }] })).stored, 0);
  assert.equal(w.rows("ProtoMail").length, before);
  // Nor can she collect his mail, even knowing his device id.
  assert.deepEqual((await mallory.ok("protocol", { action: "collect", device: env.device })).mail, []);
  // Anything but a bare direct envelope is refused.
  await alice.fails("protocol", { action: "send", items: [{ to: bob.id, envelope: JSON.stringify({ ...env, note: "hi" }) }] }, "BAD_ENVELOPE");
  await alice.fails("protocol", { action: "send", items: [{ to: bob.id, envelope: JSON.stringify({ v: 1, mode: "public", activity: {} }) }] }, "BAD_ENVELOPE");
  // Publishing needs a device's signature, your own username, and a newer version.
  const doc = JSON.parse(w.rows("ProtoActor").find((r) => r.user_id === alice.id).document);
  await alice.fails("protocol", { action: "proto_publish", payload: "{}" }, "PROOF_REQUIRED");
  await alice.fails("protocol", await signed(alice, "proto_publish", { document: JSON.stringify(doc), sealed_account: "x".repeat(40), sealed_version: 1 }), "STALE");
  await mallory.fails("protocol", await signed(mallory, "proto_publish", { document: JSON.stringify(doc), sealed_account: "x".repeat(40), sealed_version: 1 }), "BAD_HANDLE");
  // A replayed envelope is dropped by Bob's device, and a copy of Alice's envelope relabelled as Mallory's is refused.
  await b.layer.sync(u);
  w.rows("ProtoMail").push({ ...mail, id: w.newId() });
  assert.equal(await b.layer.sync(u), 0);
  assert.equal(w.rows("ProtoMail").length, 0);
});

test("a changed identity is refused, and turning the layer off removes it from the site", async () => {
  const { w, members: [alice, bob] } = await world("alice", "bob");
  const conv = await alice.dm(bob);
  const u = names(alice, bob);
  const a = layerFor(alice);
  let b = layerFor(bob);
  await a.layer.enable();
  await b.layer.enable();
  await send(alice, a.layer, conv, "one", u);
  // Bob starts again with a new identity (as a site swapping his keys would look to Alice).
  await b.layer.disable({ everywhere: true });
  assert.equal(w.rows("ProtoActor").filter((r) => r.user_id === bob.id).length, 0);
  assert.equal(w.rows("ProtoPrekey").filter((r) => r.user_id === bob.id).length, 0);
  b = layerFor(bob);
  await b.layer.enable();
  const msg = await send(alice, a.layer, conv, "two", u);
  assert.equal(a.layer.status().problems[bob.id], "ACTOR_CHANGED");
  // Alice's message went without the layer, so Bob can read it with his account keys alone.
  assert.equal((await read(bob, null, conv)).find((m) => m.text === "two").forwardSecret, undefined);
  assert.ok(msg);
});
