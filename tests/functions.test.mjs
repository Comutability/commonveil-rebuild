// End-to-end tests of the backend handlers, driven by the real client protocol
// code with real keys. Only the database is in-memory (tests/support/fakeBase44.mjs).
import test from "node:test";
import assert from "node:assert/strict";

import { FakeWorld } from "./support/fakeBase44.mjs";
import { runAction } from "../base44/shared/http.ts";
import { profileActions } from "../base44/shared/handlers/profile.ts";
import { keysActions } from "../base44/shared/handlers/keys.ts";
import { conversationActions } from "../base44/shared/handlers/conversations.ts";
import { messageActions } from "../base44/shared/handlers/messages.ts";
import { safetyActions, adminActions } from "../base44/shared/handlers/safety.ts";

import { createDeviceKeys } from "../src/lib/crypto/device.js";
import { createKeyVersion, latestKey } from "../src/lib/crypto/keyring.js";
import { generateRecoveryPhrase } from "../src/lib/crypto/recovery.js";
import { makeDeviceCert, makeAccountStatement, verifyAccountChain, compareWithPin, pinFromChain } from "../src/lib/crypto/identity.js";
import { fromB64, toB64 } from "../src/lib/crypto/encoding.js";
import {
  prepareNewAccount,
  prepareRegisterDevice,
  prepareApproval,
  acceptKeyringEnvelope,
  prepareAck,
  recoverWithPhrase,
  prepareRevoke,
  prepareRotation,
  prepareReset,
  prepareKeyringResend,
  signedRequest,
  buildMessage,
  buildTitle,
  openItem,
} from "../src/lib/secure/protocol.js";

const FUNCTIONS = { profile: profileActions, keys: keysActions, conversations: conversationActions, messages: messageActions, safety: safetyActions, admin: adminActions };

class Member {
  constructor(world, name, role = "user") {
    this.world = world;
    this.name = name;
    this.user = { id: world.newId(), role, email: `${name}@example.test`, full_name: name };
    this.id = this.user.id;
  }

  async call(fn, body, { anonymous = false } = {}) {
    const res = await runAction(this.world.clientFor(anonymous ? null : this.user), JSON.stringify(body), FUNCTIONS[fn]);
    return { status: res.status, body: await res.json() };
  }

  async ok(fn, body) {
    const res = await this.call(fn, body);
    assert.equal(res.status, 200, `${fn}.${body.action} failed: ${JSON.stringify(res.body)}`);
    return res.body;
  }

  async setup() {
    await this.ok("profile", { action: "claim_username", username: this.name });
    this.device = await createDeviceKeys(`${this.name} laptop`);
    const prepared = await prepareNewAccount({ userId: this.id, device: this.device });
    await this.ok("keys", prepared.request);
    this.keyring = prepared.keyring;
    this.phrase = prepared.phrase;
    return this;
  }

  async status() {
    return this.ok("keys", { action: "status" });
  }

  async myChain() {
    return verifyAccountChain(this.id, (await this.status()).statements);
  }

  async chainsFor(conversation) {
    const chains = new Map([[this.id, await this.myChain()]]);
    const others = conversation.member_ids.filter((m) => m !== this.id);
    const devices = new Map([[this.id, (await this.status()).devices]]);
    if (others.length) {
      const { keys } = await this.ok("keys", { action: "peer_keys", user_ids: others });
      for (const uid of others) {
        chains.set(uid, await verifyAccountChain(uid, keys[uid].statements));
        devices.set(uid, keys[uid].devices);
      }
    }
    return { chains, devices };
  }

  async send(conversation, text, device = this.device) {
    const { chains } = await this.chainsFor(conversation);
    const body = await buildMessage({ userId: this.id, device, conversation, chains, text });
    return this.call("messages", body);
  }

  async read(conversation) {
    const { chains, devices } = await this.chainsFor(conversation);
    const { messages } = await this.ok("messages", { action: "list", conversation_id: conversation.id });
    const out = [];
    for (const m of messages) {
      out.push(await openItem({ kind: "message", item: m, userId: this.id, keyring: this.keyring, senderChain: chains.get(m.sender_id), senderDevices: devices.get(m.sender_id) }));
    }
    return out;
  }

  async dm(other) {
    return (await this.ok("conversations", { action: "create_dm", username: other.name })).conversation;
  }
}

/** A request signed by one of the member's devices (their current one by default). */
const signed = (member, action, payload, device = member.device) => signedRequest({ userId: member.id, device, action, payload });

async function world(...names) {
  const w = new FakeWorld();
  const members = [];
  for (const n of names) members.push(await new Member(w, n).setup());
  return { w, members };
}

// ---------------------------------------------------------------------------

test("every action of every function rejects anonymous callers before any write", async () => {
  const w = new FakeWorld();
  const ghost = new Member(w, "ghost");
  for (const [fn, actions] of Object.entries(FUNCTIONS)) {
    for (const action of Object.keys(actions)) {
      const before = w.writes;
      const res = await ghost.call(fn, { action }, { anonymous: true });
      assert.equal(res.status, 401, `${fn}.${action}`);
      assert.equal(w.writes, before, `${fn}.${action} wrote data`);
    }
  }
  assert.equal((await ghost.call("profile", { action: "nope" })).status, 400);
});

test("usernames are unique without regard to case, reserved names are refused, and a claim is final", async () => {
  const w = new FakeWorld();
  const a = new Member(w, "alice");
  const b = new Member(w, "bob");
  await a.ok("profile", { action: "claim_username", username: "Alice_1" });
  assert.equal((await b.call("profile", { action: "claim_username", username: "alice_1" })).body.code, "USERNAME_TAKEN");
  assert.equal((await b.call("profile", { action: "claim_username", username: "Admin" })).body.code, "USERNAME_TAKEN");
  assert.equal((await b.call("profile", { action: "claim_username", username: "no spaces" })).body.code, "BAD_USERNAME");
  assert.equal((await b.call("profile", { action: "claim_username", username: "ab" })).body.code, "BAD_USERNAME");
  assert.equal((await a.call("profile", { action: "claim_username", username: "another" })).body.code, "ALREADY_CLAIMED");
  const me = await a.ok("profile", { action: "me" });
  assert.equal(me.profile.username, "Alice_1");
  assert.equal(me.encryption_ready, false);
});

test("lookup is exact-match only, and blocked members can't find each other", async () => {
  const { members: [alice, bob] } = await world("alice", "bobby");
  assert.equal((await alice.ok("profile", { action: "find", username: "BOBBY" })).profile.user_id, bob.id);
  assert.equal((await alice.call("profile", { action: "find", username: "bob" })).status, 404);
  await bob.ok("safety", { action: "block", user_id: alice.id });
  assert.equal((await alice.call("profile", { action: "find", username: "bobby" })).status, 404);
  assert.equal((await bob.call("profile", { action: "find", username: "alice" })).status, 404);
  // get_many only returns people you share a conversation with.
  assert.deepEqual((await alice.ok("profile", { action: "get_many", user_ids: [bob.id] })).profiles, []);
});

test("first device publishes version-1 keys, and a second initialisation is refused", async () => {
  const { members: [alice] } = await world("alice");
  const status = await alice.status();
  assert.equal(status.statements.length, 1);
  assert.equal(status.devices.length, 1);
  assert.equal(status.devices[0].status, "active");
  assert.equal(status.devices[0].approved_via, "first_device");
  assert.ok(status.recovery);
  const again = await prepareNewAccount({ userId: alice.id, device: await createDeviceKeys() });
  assert.equal((await alice.call("keys", again.request)).body.code, "ALREADY_INITIALISED");
});

test("initialisation refuses forged statements, foreign certificates and bad proofs", async () => {
  const w = new FakeWorld();
  const alice = new Member(w, "alice");
  await alice.ok("profile", { action: "claim_username", username: "alice" });
  const device = await createDeviceKeys();

  // Requires a username first.
  const nobody = new Member(w, "nobody");
  const p0 = await prepareNewAccount({ userId: nobody.id, device: await createDeviceKeys() });
  assert.equal((await nobody.call("keys", p0.request)).body.code, "PROFILE_REQUIRED");

  // Statement signature broken after signing.
  const p1 = await prepareNewAccount({ userId: alice.id, device });
  const payload1 = JSON.parse(p1.request.payload);
  payload1.statement.recovery_pub = payload1.cert.sign_pub;
  const r1 = await alice.call("keys", await signedRequest({ userId: alice.id, device, action: "init_account", payload: payload1 }));
  assert.equal(r1.body.code, "STATEMENT_INVALID");

  // Certificate for a different device.
  const p2 = await prepareNewAccount({ userId: alice.id, device });
  const payload2 = JSON.parse(p2.request.payload);
  payload2.device = { ...payload2.device, box_pub: (await createDeviceKeys()).box_pub };
  const r2 = await alice.call("keys", await signedRequest({ userId: alice.id, device, action: "init_account", payload: payload2 }));
  assert.equal(r2.body.code, "CERT_MISMATCH");

  // Proof made by a different key than the device being registered.
  const p3 = await prepareNewAccount({ userId: alice.id, device });
  const impostor = await createDeviceKeys();
  const r3 = await alice.call("keys", { ...p3.request, proof: { ...(await signedRequest({ userId: alice.id, device: { ...impostor, device_id: device.device_id }, action: "init_account", payload: JSON.parse(p3.request.payload) })).proof } });
  assert.equal(r3.body.code, "PROOF_INVALID");

  // Proof replayed for a different action.
  const p4 = await prepareNewAccount({ userId: alice.id, device });
  const r4 = await alice.call("keys", { ...p4.request, action: "recover_device" });
  assert.notEqual(r4.status, 200);

  // Statement for someone else's account.
  const p5 = await prepareNewAccount({ userId: nobody.id, device });
  const r5 = await alice.call("keys", await signedRequest({ userId: alice.id, device, action: "init_account", payload: JSON.parse(p5.request.payload) }));
  assert.equal(r5.body.code, "WRONG_ACCOUNT");

  assert.equal((await alice.status()).statements.length, 0, "nothing was published");
});

test("a signed-in session alone can never activate a device", async () => {
  const { members: [alice] } = await world("alice");
  const newDevice = await createDeviceKeys("Phone");
  const reg = await alice.ok("keys", await prepareRegisterDevice({ userId: alice.id, device: newDevice }));
  assert.equal(reg.device.status, "pending");

  // Self-certification with a key that isn't the account key.
  const fakeKey = await createKeyVersion(1);
  const cert = await makeDeviceCert({ userId: alice.id, device: newDevice, keyVersion: fakeKey });
  const r1 = await alice.call("keys", await signedRequest({ userId: alice.id, device: newDevice, action: "recover_device", payload: { device: { device_id: newDevice.device_id, sign_pub: newDevice.sign_pub, box_pub: newDevice.box_pub, label: "x" }, cert } }));
  assert.equal(r1.body.code, "CERT_INVALID");

  // The pending device tries to approve itself.
  const r2 = await alice.call("keys", await prepareApproval({ userId: alice.id, device: newDevice, keyring: alice.keyring, target: reg.device }));
  assert.equal(r2.body.code, "DEVICE_NOT_ACTIVE");

  // No proof at all.
  const r3 = await alice.call("keys", { action: "approve_device", payload: JSON.stringify({ target_device_id: newDevice.device_id }) });
  assert.equal(r3.status, 401);

  const sync = await alice.ok("keys", { action: "device_sync", device_id: newDevice.device_id });
  assert.equal(sync.device.status, "pending");
  assert.equal(sync.envelope, null);
});

test("linking: an approved device receives the keyring, can read history, and acknowledges it", async () => {
  const { members: [alice, bob] } = await world("alice", "bob");
  const dm = await alice.dm(bob);
  assert.equal((await alice.send(dm, "sent before the phone was linked")).status, 200);

  const phone = await createDeviceKeys("Phone");
  await alice.ok("keys", await prepareRegisterDevice({ userId: alice.id, device: phone }));
  const pending = (await alice.status()).devices.find((d) => d.device_id === phone.device_id);
  await alice.ok("keys", await prepareApproval({ userId: alice.id, device: alice.device, keyring: alice.keyring, target: pending }));

  const sync = await alice.ok("keys", { action: "device_sync", device_id: phone.device_id });
  assert.equal(sync.device.status, "active");
  const { keyring } = await acceptKeyringEnvelope({ userId: alice.id, device: phone, envelope: sync.envelope, statements: (await alice.status()).statements });
  const phoneSelf = Object.assign(Object.create(Object.getPrototypeOf(alice)), alice, { device: phone, keyring });
  const read = await phoneSelf.read(dm);
  assert.equal(read[0].status, "ok");
  assert.equal(read[0].text, "sent before the phone was linked");

  await alice.ok("keys", await prepareAck({ userId: alice.id, device: phone, keyringVersion: keyring.versions.at(-1).version }));
  assert.equal((await alice.ok("keys", { action: "device_sync", device_id: phone.device_id })).envelope, null, "copy deleted after ack");
  assert.equal((await phoneSelf.send(dm, "from the phone")).status, 200);
  const bobView = await bob.read(dm);
  assert.deepEqual(bobView.map((m) => [m.status, m.text]), [["ok", "sent before the phone was linked"], ["ok", "from the phone"]]);
});

test("the recovery phrase restores access on a fresh device; the wrong phrase doesn't", async () => {
  const { members: [alice, bob] } = await world("alice", "bob");
  const dm = await alice.dm(bob);
  await alice.send(dm, "remember this");
  const fresh = await createDeviceKeys("New laptop");
  const recoveryResponse = await alice.ok("keys", { action: "get_recovery" });

  await assert.rejects(recoverWithPhrase({ userId: alice.id, device: fresh, phrase: generateRecoveryPhrase(), recoveryResponse }), { code: "WRONG_PHRASE" });

  const { keyring, request } = await recoverWithPhrase({ userId: alice.id, device: fresh, phrase: alice.phrase, recoveryResponse });
  const res = await alice.ok("keys", request);
  assert.equal(res.device.status, "active");
  assert.equal(res.device.approved_via, "recovery_phrase");
  const restored = Object.assign(Object.create(Object.getPrototypeOf(alice)), alice, { device: fresh, keyring });
  assert.equal((await restored.read(dm))[0].text, "remember this");
});

test("removing a device and rotating keys shuts it out of new messages but keeps history readable", async () => {
  const { members: [alice, bob] } = await world("alice", "bob");
  const dm = await alice.dm(bob);
  await bob.send(dm, "before rotation");

  const stolen = await createDeviceKeys("Stolen phone");
  await alice.ok("keys", await prepareRegisterDevice({ userId: alice.id, device: stolen }));
  const pending = (await alice.status()).devices.find((d) => d.device_id === stolen.device_id);
  await alice.ok("keys", await prepareApproval({ userId: alice.id, device: alice.device, keyring: alice.keyring, target: pending }));

  await alice.ok("keys", await prepareRevoke({ userId: alice.id, device: alice.device, targetDeviceId: stolen.device_id }));
  const status = await alice.status();
  const active = status.devices.filter((d) => d.status === "active");
  assert.equal(active.length, 1);
  const rotation = await prepareRotation({ userId: alice.id, device: alice.device, keyring: alice.keyring, chain: await alice.myChain(), activeDevices: active });
  await alice.ok("keys", rotation.request);
  alice.keyring = rotation.keyring;

  const chain = await alice.myChain();
  assert.equal(chain.latest.version, 2);
  assert.equal(chain.rootVersion, 1, "rotation keeps the chain unbroken");

  // The revoked device can't send, even with a valid signature.
  const r = await alice.send(dm, "from the thief", stolen);
  assert.equal(r.body.code, "DEVICE_NOT_ACTIVE");

  // New messages are encrypted to version 2, which the stolen device never got.
  await bob.send(dm, "after rotation");
  const latestMsg = (await bob.ok("messages", { action: "list", conversation_id: dm.id })).messages.at(-1);
  assert.equal(JSON.parse(latestMsg.envelope).wraps.find((w) => w.u === alice.id).kv, 2);
  assert.deepEqual((await alice.read(dm)).map((m) => m.text), ["before rotation", "after rotation"]);

  // Bob's pin from before still leads to Alice's new key through the chain.
  const bobChain = (await bob.chainsFor(dm)).chains.get(alice.id);
  assert.equal(compareWithPin(bobChain, { version: 1, sign_pub: chain.byVersion.get(1).sign_pub }), "rotated");
});

test("a rotation never seals keys to a device without a valid certificate", async () => {
  const { members: [alice] } = await world("alice");
  const status = await alice.status();
  const forged = { ...status.devices[0], device_id: "AAAAAAAAAAAAAAAAAAAAAA", box_pub: (await createDeviceKeys()).box_pub };
  await assert.rejects(
    prepareRotation({ userId: alice.id, device: alice.device, keyring: alice.keyring, chain: await alice.myChain(), activeDevices: [...status.devices, forged] }),
    { code: "UNCERTIFIED_DEVICE" },
  );
  await assert.rejects(
    prepareKeyringResend({ userId: alice.id, device: alice.device, keyring: alice.keyring, target: forged, chain: await alice.myChain() }),
    { code: "UNCERTIFIED_DEVICE" },
  );
});

test("members decrypt and verify messages; outsiders can neither list nor read them", async () => {
  const { members: [alice, bob, eve] } = await world("alice", "bob", "eve");
  const dm = await alice.dm(bob);
  assert.equal((await alice.send(dm, "hello bob")).status, 200);
  assert.equal((await bob.send(dm, "hello alice")).status, 200);
  assert.deepEqual((await bob.read(dm)).map((m) => [m.status, m.text]), [["ok", "hello bob"], ["ok", "hello alice"]]);
  assert.equal((await eve.call("messages", { action: "list", conversation_id: dm.id })).status, 404);
  assert.equal((await eve.call("conversations", { action: "get", conversation_id: dm.id })).status, 404);
  const stored = w0(alice).rows("Message").map((m) => m.envelope).join(" ");
  assert.ok(!stored.includes("hello"), "server only ever stores ciphertext");
});

function w0(member) {
  return member.world;
}

test("the server refuses messages that skip a member, use stale keys, are tampered or badly timed", async () => {
  const { members: [alice, bob, carol] } = await world("alice", "bob", "carol");
  const dm = await alice.dm(bob);
  const { chains } = await alice.chainsFor(dm);

  // Encrypt only to Alice: Bob is skipped.
  const skip = await buildMessage({ userId: alice.id, device: alice.device, conversation: { ...dm, member_ids: [alice.id] }, chains, text: "hi" });
  assert.equal((await alice.call("messages", skip)).body.code, "RECIPIENTS_CHANGED");

  // Encrypt to an outsider as well.
  chains.set(carol.id, (await carol.myChain()));
  const extra = await buildMessage({ userId: alice.id, device: alice.device, conversation: { ...dm, member_ids: [alice.id, bob.id, carol.id] }, chains, text: "hi" });
  assert.equal((await alice.call("messages", extra)).body.code, "RECIPIENTS_CHANGED");

  // Tampered after signing.
  const good = await buildMessage({ userId: alice.id, device: alice.device, conversation: dm, chains, text: "hi" });
  const env = JSON.parse(good.envelope);
  env.ct = toB64(fromB64(env.ct).map((b, i) => (i === 0 ? b ^ 1 : b)));
  assert.equal((await alice.call("messages", { ...good, envelope: JSON.stringify(env) })).body.code, "SIGNATURE_INVALID");

  // Signed by another account's device.
  assert.equal((await alice.call("messages", { ...good, device_id: bob.device.device_id })).body.code, "DEVICE_UNKNOWN");

  // Sent at a time far from now.
  const late = await buildMessage({ userId: alice.id, device: alice.device, conversation: dm, chains, text: "hi" });
  assert.equal((await alice.call("messages", { ...late, sent_at: "2020-01-01T00:00:00.000Z" })).body.code, "CLOCK_SKEW");

  // Bob rotates; Alice's cached keys are now stale.
  const bobStatus = await bob.status();
  const rot = await prepareRotation({ userId: bob.id, device: bob.device, keyring: bob.keyring, chain: await bob.myChain(), activeDevices: bobStatus.devices.filter((d) => d.status === "active") });
  await bob.ok("keys", rot.request);
  bob.keyring = rot.keyring;
  const stale = await buildMessage({ userId: alice.id, device: alice.device, conversation: dm, chains, text: "hi" });
  assert.equal((await alice.call("messages", stale)).body.code, "STALE_KEYS");

  // Resending the exact same message is idempotent.
  const fresh = await buildMessage({ userId: alice.id, device: alice.device, conversation: dm, chains: (await alice.chainsFor(dm)).chains, text: "once" });
  const first = await alice.call("messages", fresh);
  const second = await alice.call("messages", fresh);
  assert.equal(first.status, 200);
  assert.equal(second.body.duplicate, true);
  assert.equal(alice.world.rows("Message").filter((m) => m.msg_id === fresh.msg_id).length, 1);
});

test("a message relayed with a swapped device id or sender fails verification on the reader's side", async () => {
  const { members: [alice, bob] } = await world("alice", "bob");
  const dm = await alice.dm(bob);
  await alice.send(dm, "genuine");
  const row = alice.world.rows("Message")[0];
  // A malicious server rewrites the sender. Decryption is bound to the sender, so it fails closed.
  row.sender_id = bob.id;
  const [view] = await bob.read(dm);
  assert.equal(view.status, "locked");
});

test("blocking stops a DM in both directions", async () => {
  const { members: [alice, bob] } = await world("alice", "bob");
  const dm = await alice.dm(bob);
  await bob.ok("safety", { action: "block", user_id: alice.id });
  assert.equal((await alice.send(dm, "hey")).body.code, "BLOCKED");
  assert.equal((await bob.send(dm, "hey")).body.code, "BLOCKED");
  assert.equal((await alice.call("conversations", { action: "create_dm", username: "bob" })).status, 404);
  await bob.ok("safety", { action: "unblock", user_id: alice.id });
  assert.equal((await alice.send(dm, "hey again")).status, 200);
});

test("groups: names are encrypted, new members need a fresh key copy, and can't read earlier messages", async () => {
  const { members: [alice, bob, carol] } = await world("alice", "bob", "carol");
  const { conversation: group } = await alice.ok("conversations", { action: "create_group", usernames: ["bob"] });
  const { chains } = await alice.chainsFor(group);
  await alice.ok("conversations", await buildTitle({ userId: alice.id, device: alice.device, conversation: group, chains, title: "Book club" }));
  await alice.send(group, "chapter one");

  const { conversation: bigger } = await alice.ok("conversations", await signed(alice, "add_members", { conversation_id: group.id, usernames: ["carol"] }));
  assert.equal(bigger.member_ids.length, 3);
  // Old recipient set is refused now that Carol is in.
  const old = await buildMessage({ userId: alice.id, device: alice.device, conversation: group, chains, text: "x" });
  assert.equal((await alice.call("messages", old)).body.code, "RECIPIENTS_CHANGED");
  // Re-encrypt the name for everyone, then post.
  const all = await alice.chainsFor(bigger);
  await alice.ok("conversations", await buildTitle({ userId: alice.id, device: alice.device, conversation: bigger, chains: all.chains, title: "Book club" }));
  await alice.send(bigger, "welcome carol");

  const carolView = await carol.read(bigger);
  assert.deepEqual(carolView.map((m) => m.status), ["locked", "ok"], "earlier messages stay unreadable to a newcomer");
  assert.equal(carolView[1].text, "welcome carol");
  const conv = (await carol.ok("conversations", { action: "get", conversation_id: group.id })).conversation;
  const title = await openItem({ kind: "title", item: { ...conv.title, conversation_id: conv.id }, userId: carol.id, keyring: carol.keyring, senderChain: all.chains.get(alice.id), senderDevices: (await carol.chainsFor(bigger)).devices.get(alice.id) });
  assert.equal(title.status, "ok");
  assert.equal(title.text, "Book club");

  // Leaving: Bob leaves, and later messages exclude him.
  await bob.ok("conversations", await signed(bob, "leave", { conversation_id: group.id }));
  assert.equal((await bob.call("messages", { action: "list", conversation_id: group.id })).status, 404);
  assert.equal((await alice.call("conversations", await signed(alice, "leave", { conversation_id: (await alice.dm(bob)).id }))).body.code, "DM_LEAVE");
});

test("messages are rate limited per sender", async () => {
  const { members: [alice, bob] } = await world("alice", "bob");
  const dm = await alice.dm(bob);
  const { chains } = await alice.chainsFor(dm);
  let last;
  for (let i = 0; i < 31; i += 1) {
    last = await alice.call("messages", await buildMessage({ userId: alice.id, device: alice.device, conversation: dm, chains, text: `m${i}` }));
  }
  assert.equal(last.body.code, "RATE_LIMITED");
});

test("polling returns what changed after the cursor, including deletions", async () => {
  const { members: [alice, bob] } = await world("alice", "bob");
  const dm = await alice.dm(bob);
  let { cursor } = await bob.ok("messages", { action: "poll" });
  await alice.send(dm, "one");
  await alice.send(dm, "two");
  let page = await bob.ok("messages", { action: "poll", since: cursor });
  assert.equal(page.messages.length, 2);
  cursor = page.cursor;
  const target = page.messages[0];
  assert.equal((await bob.call("messages", await signed(bob, "delete", { message_id: target.id }))).status, 404, "can't delete someone else's message");
  await alice.ok("messages", await signed(alice, "delete", { message_id: target.id }));
  page = await bob.ok("messages", { action: "poll", since: cursor });
  const deleted = page.messages.find((m) => m.id === target.id);
  assert.ok(deleted?.deleted);
  assert.equal(deleted.envelope, null);
});

test("account reset starts a new identity, removes old devices, and contacts see a change", async () => {
  const { members: [alice, bob] } = await world("alice", "bob");
  const dm = await alice.dm(bob);
  await bob.send(dm, "old secret");
  const bobPin = pinFromChain((await bob.chainsFor(dm)).chains.get(alice.id), true);

  const fresh = await createDeviceKeys("After losing everything");
  const reset = await prepareReset({ userId: alice.id, device: fresh, nextVersion: 2 });
  const noConfirm = JSON.parse(reset.request.payload);
  delete noConfirm.confirm;
  assert.equal((await alice.call("keys", await signedRequest({ userId: alice.id, device: fresh, action: "reset_account", payload: noConfirm }))).body.code, "CONFIRM_REQUIRED");
  await alice.ok("keys", reset.request);

  const status = await alice.status();
  assert.equal(status.devices.find((d) => d.device_id === alice.device.device_id).status, "revoked");
  assert.equal(status.devices.find((d) => d.device_id === fresh.device_id).status, "active");
  assert.equal(compareWithPin((await bob.chainsFor(dm)).chains.get(alice.id), bobPin), "changed");

  const newAlice = Object.assign(Object.create(Object.getPrototypeOf(alice)), alice, { device: fresh, keyring: reset.keyring });
  const view = await newAlice.read(dm);
  assert.equal(view[0].status, "locked", "messages to the old identity can't be read after a reset");
  assert.equal((await alice.send(dm, "old device", alice.device)).body.code, "DEVICE_NOT_ACTIVE");
});

test("peer keys are only shared with people you have a conversation with", async () => {
  const { members: [alice, bob, eve] } = await world("alice", "bob", "eve");
  assert.deepEqual((await eve.ok("keys", { action: "peer_keys", user_ids: [alice.id] })).keys, {});
  await alice.dm(bob);
  const { keys } = await bob.ok("keys", { action: "peer_keys", user_ids: [alice.id, eve.id] });
  assert.deepEqual(Object.keys(keys), [alice.id]);
  assert.equal(keys[alice.id].devices[0].label, undefined, "device labels aren't shared with other members");
});

test("reports go to staff; only admins can read and resolve them", async () => {
  const w = new FakeWorld();
  const alice = await new Member(w, "alice").setup();
  const bob = await new Member(w, "bob").setup();
  const staff = new Member(w, "staffer", "admin");
  assert.equal((await alice.call("safety", { action: "report", user_id: bob.id, reason: "nonsense" })).body.code, "BAD_FIELD");
  await alice.ok("safety", { action: "report", user_id: bob.id, reason: "spam", details: "Sent me 40 links" });
  assert.equal((await alice.call("admin", { action: "list_reports" })).status, 403);
  const { reports } = await staff.ok("admin", { action: "list_reports" });
  assert.equal(reports.length, 1);
  assert.equal(reports[0].reported, "bob");
  await staff.ok("admin", { action: "update_report", report_id: reports[0].id, status: "resolved", resolution_note: "Warned" });
  assert.equal((await staff.ok("admin", { action: "list_reports", status: "resolved" })).reports.length, 1);
});

test("a device that missed a rotation can be sent the current keyring by another device", async () => {
  const { members: [alice] } = await world("alice");
  const phone = await createDeviceKeys("Phone");
  await alice.ok("keys", await prepareRegisterDevice({ userId: alice.id, device: phone }));
  const pending = (await alice.status()).devices.find((d) => d.device_id === phone.device_id);
  await alice.ok("keys", await prepareApproval({ userId: alice.id, device: alice.device, keyring: alice.keyring, target: pending }));
  const first = await alice.ok("keys", { action: "device_sync", device_id: phone.device_id });
  const { keyring: phoneKeyring } = await acceptKeyringEnvelope({ userId: alice.id, device: phone, envelope: first.envelope, statements: (await alice.status()).statements });
  await alice.ok("keys", await prepareAck({ userId: alice.id, device: phone, keyringVersion: 1 }));

  // Laptop rotates; then the phone's copy is lost (simulating a failed delivery).
  const status = await alice.status();
  const rot = await prepareRotation({ userId: alice.id, device: alice.device, keyring: alice.keyring, chain: await alice.myChain(), activeDevices: status.devices.filter((d) => d.status === "active") });
  await alice.ok("keys", rot.request);
  alice.keyring = rot.keyring;
  for (const e of alice.world.rows("KeyEnvelope").filter((e) => e.device_id === phone.device_id)) e.device_id = "lost";
  assert.equal((await alice.ok("keys", { action: "device_sync", device_id: phone.device_id })).envelope, null);

  const chain = await alice.myChain();
  const target = (await alice.status()).devices.find((d) => d.device_id === phone.device_id);
  assert.equal(target.synced_key_version, 1);
  await alice.ok("keys", await prepareKeyringResend({ userId: alice.id, device: alice.device, keyring: alice.keyring, target, chain }));
  const again = await alice.ok("keys", { action: "device_sync", device_id: phone.device_id });
  const { keyring } = await acceptKeyringEnvelope({ userId: alice.id, device: phone, envelope: again.envelope, statements: (await alice.status()).statements });
  assert.equal(latestKey(keyring).version, 2);
  assert.ok(phoneKeyring);
});

test("rotation with a statement not signed by the current key is refused", async () => {
  const { members: [alice] } = await world("alice");
  const status = await alice.status();
  const chain = await alice.myChain();
  const rogue = await createKeyVersion(2);
  const rotation = await prepareRotation({ userId: alice.id, device: alice.device, keyring: alice.keyring, chain, activeDevices: status.devices });
  const payload = JSON.parse(rotation.request.payload);
  payload.statement = await makeAccountStatement({ userId: alice.id, keyVersion: rogue, recoveryPub: chain.latest.recovery_pub, signer: rogue });
  payload.statement.signed_by_version = 1;
  const res = await alice.call("keys", await signedRequest({ userId: alice.id, device: alice.device, action: "rotate_keys", payload }));
  assert.equal(res.body.code, "STATEMENT_INVALID");
  assert.equal((await alice.myChain()).latest.version, 1);
});

test("a signed-in session alone can't add people to a group, leave it, or delete messages", async () => {
  const { members: [alice, bob, carol] } = await world("alice", "bob", "carol");
  const { conversation: group } = await alice.ok("conversations", { action: "create_group", usernames: ["bob"] });
  await alice.send(group, "hello group");
  const msg = alice.world.rows("Message")[0];
  const attempts = [
    ["conversations", "add_members", { conversation_id: group.id, usernames: ["carol"] }],
    ["conversations", "leave", { conversation_id: group.id }],
    ["messages", "delete", { message_id: msg.id }],
  ];
  // Session only: no device proof at all.
  for (const [fn, action, payload] of attempts) {
    const res = await alice.call(fn, { action, payload: JSON.stringify(payload) });
    assert.equal(res.status, 401, `${fn}.${action} without a proof`);
    assert.equal(res.body.code, "PROOF_REQUIRED");
  }
  // A proof made for one action or payload can't be reused for another.
  const addProof = await signed(alice, "add_members", { conversation_id: group.id, usernames: ["carol"] });
  assert.equal((await alice.call("conversations", { ...addProof, action: "leave" })).body.code, "PROOF_INVALID");
  const otherPayload = JSON.stringify({ conversation_id: group.id, usernames: ["bob"] });
  assert.equal((await alice.call("conversations", { ...addProof, payload: otherPayload })).body.code, "PROOF_INVALID");
  // Someone else's device can't sign for Alice.
  assert.equal((await alice.call("conversations", await signed(alice, "add_members", { conversation_id: group.id, usernames: ["carol"] }, carol.device))).body.code, "DEVICE_UNKNOWN");
  // A device that has been removed can't either.
  const phone = await createDeviceKeys("Phone");
  await alice.ok("keys", await prepareRegisterDevice({ userId: alice.id, device: phone }));
  const pending = (await alice.status()).devices.find((d) => d.device_id === phone.device_id);
  await alice.ok("keys", await prepareApproval({ userId: alice.id, device: alice.device, keyring: alice.keyring, target: pending }));
  await alice.ok("keys", await prepareRevoke({ userId: alice.id, device: alice.device, targetDeviceId: phone.device_id }));
  assert.equal((await alice.call("conversations", await signed(alice, "add_members", { conversation_id: group.id, usernames: ["carol"] }, phone))).body.code, "DEVICE_NOT_ACTIVE");
  // Nothing changed.
  const stored = alice.world.rows("Conversation").find((c) => c.id === group.id);
  assert.deepEqual(stored.member_ids, [alice.id, bob.id]);
  assert.equal(alice.world.rows("Message")[0].deleted, false);
  // With a proper device signature it works.
  await alice.ok("conversations", await signed(alice, "add_members", { conversation_id: group.id, usernames: ["carol"] }));
  assert.equal(alice.world.rows("Conversation").find((c) => c.id === group.id).member_ids.length, 3);
});
