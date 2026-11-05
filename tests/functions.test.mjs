// End-to-end tests of the backend handlers, driven by the real client protocol
// code with real keys. Only the database is in-memory (tests/support/fakeBase44.mjs).
// Tests named "review:" replay an attack from the security review and check it now fails.
import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";

import { FakeWorld } from "./support/fakeBase44.mjs";
import { runAction } from "../base44/shared/http.ts";
import { profileActions } from "../base44/shared/handlers/profile.ts";
import { keysActions } from "../base44/shared/handlers/keys.ts";
import { conversationActions } from "../base44/shared/handlers/conversations.ts";
import { messageActions } from "../base44/shared/handlers/messages.ts";
import { safetyActions, adminActions } from "../base44/shared/handlers/safety.ts";
import { disclosureActions, DISCLOSURE_LIMITS } from "../base44/shared/handlers/disclosure.ts";
import { inviteActions, serverActions } from "../base44/shared/handlers/servers.ts";
import { serverMessageActions } from "../base44/shared/handlers/serverMessages.ts";
import { voiceActions } from "../base44/shared/handlers/voice.ts";
import { fileActions } from "../base44/shared/handlers/files.ts";
import { eventActions } from "../base44/shared/handlers/events.ts";
import { moderationActions } from "../base44/shared/handlers/moderation.ts";
import { resetMaintenanceThrottle, runMaintenance } from "../base44/shared/maintenance.ts";

import { createDeviceKeys } from "../src/lib/crypto/device.js";
import { createKeyVersion, latestKey, newKeyring, sealKeyringForRecovery, sealKeyringToDevice } from "../src/lib/crypto/keyring.js";
import { deriveRecoveryKey, generateRecoveryPhrase, recoveryAnchorMac } from "../src/lib/crypto/recovery.js";
import {
  compareWithPin,
  headDigest,
  makeAccountStatement,
  makeDeviceCert,
  pinFromChain,
  safetyNumber,
  signItem,
  verifyAccountChain,
} from "../src/lib/crypto/identity.js";
import { fromB64, toB64 } from "../src/lib/crypto/encoding.js";
import {
  REACTIONS,
  acceptKeyringEnvelope,
  buildEdit,
  buildMessage,
  buildReaction,
  buildTitle,
  linkPinFor,
  openItem,
  prepareAck,
  prepareApproval,
  prepareCancelReset,
  prepareFinishReset,
  prepareKeyringResend,
  prepareNewAccount,
  prepareRegisterDevice,
  prepareReset,
  prepareRevoke,
  prepareRotation,
  prepareWithdrawReset,
  recoverWithPhrase,
  signedRequest,
} from "../src/lib/secure/protocol.js";

/** Functions that only signed-in members can call. */
const FUNCTIONS = {
  profile: profileActions, keys: keysActions, conversations: conversationActions, messages: messageActions, safety: safetyActions, admin: adminActions,
  servers: serverActions({ defaultAdmins: () => [] }), channels: serverMessageActions, voice: voiceActions, files: fileActions, events: eventActions, moderation: moderationActions,
};
/** Functions that also accept anonymous callers, exactly as their entry files set it up. */
const PUBLIC_FUNCTIONS = { disclose: disclosureActions, invite: inviteActions };
/** Functions started by the app's own schedule. They act on no member's say-so, only on what's due. */
const SCHEDULED_FUNCTIONS = ["maintenance"];

/** A request signed by one of the member's devices (their current one by default). */
const signed = (member, action, payload, device = member.device) => signedRequest({ userId: member.id, device, action, payload });

class Member {
  constructor(world, name, role = "user") {
    this.world = world;
    this.name = name;
    this.user = { id: world.newId(), role, email: `${name}@example.test`, full_name: name };
    this.id = this.user.id;
  }

  async call(fn, body, { anonymous = false } = {}) {
    const isPublic = Object.hasOwn(PUBLIC_FUNCTIONS, fn);
    const actions = isPublic ? PUBLIC_FUNCTIONS[fn] : FUNCTIONS[fn];
    const res = await runAction(this.world.clientFor(anonymous ? null : this.user), JSON.stringify(body), actions, { allowAnonymous: isPublic });
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
    const body = await buildMessage({ userId: this.id, device, conversation, chains, text, keyring: this.keyring });
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
    return (await this.ok("conversations", await signed(this, "create_dm", { username: other.name }))).conversation;
  }

  async group(usernames) {
    return (await this.ok("conversations", await signed(this, "create_group", { usernames }))).conversation;
  }

  /** Another device for this member, approved from the current one. Returns { device, keyring }. */
  async linkDevice(label = "Phone") {
    const device = await createDeviceKeys(label);
    const pin = linkPinFor(await this.myChain());
    await this.ok("keys", await prepareRegisterDevice({ userId: this.id, device }));
    const pending = (await this.status()).devices.find((d) => d.device_id === device.device_id);
    await this.ok("keys", await prepareApproval({ userId: this.id, device: this.device, keyring: this.keyring, target: pending }));
    const sync = await this.ok("keys", { action: "device_sync", device_id: device.device_id });
    const { keyring } = await acceptKeyringEnvelope({ userId: this.id, device, envelope: sync.envelope, statements: (await this.status()).statements, pin });
    await this.ok("keys", await prepareAck({ userId: this.id, device, keyringVersion: latestKey(keyring).version }));
    return { device, keyring };
  }

  /** Rotate keys from the current device, leaving out any devices being removed. */
  async rotate({ exclude = [], newPhrase = false } = {}) {
    const status = await this.status();
    const rotation = await prepareRotation({
      userId: this.id, device: this.device, keyring: this.keyring, chain: await this.myChain(),
      activeDevices: status.devices.filter((d) => d.status === "active"), excludeDeviceIds: exclude, newPhrase,
    });
    await this.ok("keys", rotation.request);
    this.keyring = rotation.keyring;
    return rotation;
  }

  as(device, keyring) {
    return Object.assign(Object.create(Object.getPrototypeOf(this)), this, { device, keyring });
  }
}

async function world(...names) {
  const w = new FakeWorld();
  const members = [];
  for (const n of names) members.push(await new Member(w, n).setup());
  return { w, members };
}

/** A key statement with a chosen issue time (makeAccountStatement always uses now). */
async function statementAt({ userId, keyVersion, recoveryPub, signer, issuedAt }) {
  const st = await makeAccountStatement({ userId, keyVersion, recoveryPub, signer });
  if (!issuedAt) return st;
  const { canonical, CONTEXTS, accountKeyFields } = await import("../src/lib/crypto/canonical.js");
  const { importSignPrivate, signBytes } = await import("../src/lib/crypto/primitives.js");
  const { utf8 } = await import("../src/lib/crypto/encoding.js");
  st.issued_at = issuedAt;
  st.signature = await signBytes(await importSignPrivate(signer.sign_priv), utf8(canonical(CONTEXTS.accountKey, accountKeyFields(st))));
  return st;
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
  assert.deepEqual((await alice.ok("profile", { action: "get_many", user_ids: [bob.id] })).profiles, []);
});

test("first device publishes version-1 keys with the phrase's anchor, and a second initialisation is refused", async () => {
  const { members: [alice] } = await world("alice");
  const status = await alice.status();
  assert.equal(status.statements.length, 1);
  assert.equal(fromB64(status.statements[0].recovery_mac).length, 32, "the first key carries the recovery anchor");
  assert.equal(status.devices.length, 1);
  assert.equal(status.devices[0].status, "active");
  assert.equal(status.devices[0].approved_via, "first_device");
  assert.ok(status.recovery);
  const again = await prepareNewAccount({ userId: alice.id, device: await createDeviceKeys() });
  assert.equal((await alice.call("keys", again.request)).body.code, "ALREADY_INITIALISED");
});

test("initialisation refuses forged statements, foreign certificates, bad proofs and a missing anchor", async () => {
  const w = new FakeWorld();
  const alice = new Member(w, "alice");
  await alice.ok("profile", { action: "claim_username", username: "alice" });
  const device = await createDeviceKeys();

  const nobody = new Member(w, "nobody");
  const p0 = await prepareNewAccount({ userId: nobody.id, device: await createDeviceKeys() });
  assert.equal((await nobody.call("keys", p0.request)).body.code, "PROFILE_REQUIRED");

  const p1 = await prepareNewAccount({ userId: alice.id, device });
  const payload1 = JSON.parse(p1.request.payload);
  payload1.statement.recovery_pub = payload1.cert.sign_pub;
  assert.equal((await alice.call("keys", await signedRequest({ userId: alice.id, device, action: "init_account", payload: payload1 }))).body.code, "STATEMENT_INVALID");

  const p2 = await prepareNewAccount({ userId: alice.id, device });
  const payload2 = JSON.parse(p2.request.payload);
  payload2.device = { ...payload2.device, box_pub: (await createDeviceKeys()).box_pub };
  assert.equal((await alice.call("keys", await signedRequest({ userId: alice.id, device, action: "init_account", payload: payload2 }))).body.code, "CERT_MISMATCH");

  const p3 = await prepareNewAccount({ userId: alice.id, device });
  const impostor = await createDeviceKeys();
  const r3 = await alice.call("keys", { ...p3.request, proof: { ...(await signedRequest({ userId: alice.id, device: { ...impostor, device_id: device.device_id }, action: "init_account", payload: JSON.parse(p3.request.payload) })).proof } });
  assert.equal(r3.body.code, "PROOF_INVALID");

  const p4 = await prepareNewAccount({ userId: alice.id, device });
  assert.notEqual((await alice.call("keys", { ...p4.request, action: "recover_device" })).status, 200);

  const p5 = await prepareNewAccount({ userId: nobody.id, device });
  assert.equal((await alice.call("keys", await signedRequest({ userId: alice.id, device, action: "init_account", payload: JSON.parse(p5.request.payload) }))).body.code, "WRONG_ACCOUNT");

  const p6 = await prepareNewAccount({ userId: alice.id, device });
  const payload6 = JSON.parse(p6.request.payload);
  delete payload6.statement.recovery_mac;
  assert.equal((await alice.call("keys", await signedRequest({ userId: alice.id, device, action: "init_account", payload: payload6 }))).body.code, "BAD_STATEMENT");

  assert.equal((await alice.status()).statements.length, 0, "nothing was published");
});

test("a signed-in session alone can never activate a device", async () => {
  const { members: [alice] } = await world("alice");
  const newDevice = await createDeviceKeys("Phone");
  const reg = await alice.ok("keys", await prepareRegisterDevice({ userId: alice.id, device: newDevice }));
  assert.equal(reg.device.status, "pending");

  const fakeKey = await createKeyVersion(1);
  const cert = await makeDeviceCert({ userId: alice.id, device: newDevice, keyVersion: fakeKey });
  const r1 = await alice.call("keys", await signedRequest({ userId: alice.id, device: newDevice, action: "recover_device", payload: { device: { device_id: newDevice.device_id, sign_pub: newDevice.sign_pub, box_pub: newDevice.box_pub, label: "x" }, cert } }));
  assert.equal(r1.body.code, "CERT_INVALID");

  const r2 = await alice.call("keys", await prepareApproval({ userId: alice.id, device: newDevice, keyring: alice.keyring, target: reg.device }));
  assert.equal(r2.body.code, "DEVICE_NOT_ACTIVE");

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

  const { device: phone, keyring } = await alice.linkDevice("Phone");
  const phoneSelf = alice.as(phone, keyring);
  const read = await phoneSelf.read(dm);
  assert.equal(read[0].status, "ok");
  assert.equal(read[0].text, "sent before the phone was linked");
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
  assert.equal((await alice.as(fresh, keyring).read(dm))[0].text, "remember this");
});

test("recovery still works after rotations and after the phrase was changed", async () => {
  const { members: [alice] } = await world("alice");
  await alice.rotate();
  const { phrase } = await alice.rotate({ newPhrase: true });
  await alice.rotate();
  const recoveryResponse = await alice.ok("keys", { action: "get_recovery" });
  await assert.rejects(
    recoverWithPhrase({ userId: alice.id, device: await createDeviceKeys(), phrase: alice.phrase, recoveryResponse }),
    { code: "WRONG_PHRASE" },
    "the old phrase stops working",
  );
  const { keyring } = await recoverWithPhrase({ userId: alice.id, device: await createDeviceKeys(), phrase, recoveryResponse });
  assert.equal(latestKey(keyring).version, 4);
});

test("removing a device and rotating keys shuts it out of new messages but keeps history readable", async () => {
  const { members: [alice, bob] } = await world("alice", "bob");
  const dm = await alice.dm(bob);
  await bob.send(dm, "before rotation");

  const { device: stolen } = await alice.linkDevice("Stolen phone");
  await alice.ok("keys", await prepareRevoke({ userId: alice.id, device: alice.device, targetDeviceId: stolen.device_id }));
  await alice.rotate({ exclude: [stolen.device_id] });

  const chain = await alice.myChain();
  assert.equal(chain.latest.version, 2);
  assert.equal(chain.rootVersion, 1, "rotation keeps the chain unbroken");
  assert.equal((await alice.send(dm, "from the thief", stolen)).body.code, "DEVICE_NOT_ACTIVE");

  await bob.send(dm, "after rotation");
  const latestMsg = (await bob.ok("messages", { action: "list", conversation_id: dm.id })).messages.at(-1);
  assert.equal(JSON.parse(latestMsg.envelope).wraps.find((w) => w.u === alice.id).kv, 2);
  assert.deepEqual((await alice.read(dm)).map((m) => m.text), ["before rotation", "after rotation"]);

  const bobChain = (await bob.chainsFor(dm)).chains.get(alice.id);
  const v1Chain = await verifyAccountChain(alice.id, chain.statements.slice(0, 1));
  assert.equal(compareWithPin(bobChain, pinFromChain(v1Chain)), "rotated", "Bob's earlier pin still leads to Alice's new key");
});

test("members decrypt and verify messages; outsiders can neither list nor read them", async () => {
  const { w, members: [alice, bob, eve] } = await world("alice", "bob", "eve");
  const dm = await alice.dm(bob);
  assert.equal((await alice.send(dm, "hello bob")).status, 200);
  assert.equal((await bob.send(dm, "hello alice")).status, 200);
  assert.deepEqual((await bob.read(dm)).map((m) => [m.status, m.text]), [["ok", "hello bob"], ["ok", "hello alice"]]);
  assert.equal((await eve.call("messages", { action: "list", conversation_id: dm.id })).status, 404);
  assert.equal((await eve.call("conversations", { action: "get", conversation_id: dm.id })).status, 404);
  const stored = w.rows("Message").map((m) => m.envelope).join(" ");
  assert.ok(!stored.includes("hello"), "server only ever stores ciphertext");
});

test("the server refuses messages that skip a member, use stale keys, are tampered or badly timed", async () => {
  const { members: [alice, bob, carol] } = await world("alice", "bob", "carol");
  const dm = await alice.dm(bob);
  const { chains } = await alice.chainsFor(dm);

  const skip = await buildMessage({ userId: alice.id, device: alice.device, conversation: { ...dm, member_ids: [alice.id] }, chains, text: "hi" });
  assert.equal((await alice.call("messages", skip)).body.code, "RECIPIENTS_CHANGED");

  chains.set(carol.id, await carol.myChain());
  const extra = await buildMessage({ userId: alice.id, device: alice.device, conversation: { ...dm, member_ids: [alice.id, bob.id, carol.id] }, chains, text: "hi" });
  assert.equal((await alice.call("messages", extra)).body.code, "RECIPIENTS_CHANGED");

  const good = await buildMessage({ userId: alice.id, device: alice.device, conversation: dm, chains, text: "hi" });
  const env = JSON.parse(good.envelope);
  env.ct = toB64(fromB64(env.ct).map((b, i) => (i === 0 ? b ^ 1 : b)));
  assert.equal((await alice.call("messages", { ...good, envelope: JSON.stringify(env) })).body.code, "SIGNATURE_INVALID");
  assert.equal((await alice.call("messages", { ...good, device_id: bob.device.device_id })).body.code, "DEVICE_UNKNOWN");

  const late = await buildMessage({ userId: alice.id, device: alice.device, conversation: dm, chains, text: "hi" });
  assert.equal((await alice.call("messages", { ...late, sent_at: "2020-01-01T00:00:00.000Z" })).body.code, "CLOCK_SKEW");

  await bob.rotate();
  const stale = await buildMessage({ userId: alice.id, device: alice.device, conversation: dm, chains, text: "hi" });
  assert.equal((await alice.call("messages", stale)).body.code, "STALE_KEYS");

  const fresh = await buildMessage({ userId: alice.id, device: alice.device, conversation: dm, chains: (await alice.chainsFor(dm)).chains, text: "once" });
  const first = await alice.call("messages", fresh);
  const second = await alice.call("messages", fresh);
  assert.equal(first.status, 200);
  assert.equal(second.body.duplicate, true);
  assert.equal(alice.world.rows("Message").filter((m) => m.msg_id === fresh.msg_id).length, 1);
});

test("a message relayed with a swapped device id or sender fails verification on the reader's side", async () => {
  const { w, members: [alice, bob] } = await world("alice", "bob");
  const dm = await alice.dm(bob);
  await alice.send(dm, "genuine");
  w.rows("Message")[0].sender_id = bob.id;
  const [view] = await bob.read(dm);
  assert.equal(view.status, "locked");
});

test("blocking stops a DM in both directions", async () => {
  const { members: [alice, bob] } = await world("alice", "bob");
  const dm = await alice.dm(bob);
  await bob.ok("safety", { action: "block", user_id: alice.id });
  assert.equal((await alice.send(dm, "hey")).body.code, "BLOCKED");
  assert.equal((await bob.send(dm, "hey")).body.code, "BLOCKED");
  assert.equal((await alice.call("conversations", await signed(alice, "create_dm", { username: "bob" }))).status, 404);
  await bob.ok("safety", { action: "unblock", user_id: alice.id });
  assert.equal((await alice.send(dm, "hey again")).status, 200);
});

test("groups: names are encrypted, new members need a fresh key copy, and see nothing from before they joined", async () => {
  const { members: [alice, bob, carol] } = await world("alice", "bob", "carol");
  const group = await alice.group(["bob"]);
  const { chains } = await alice.chainsFor(group);
  await alice.ok("conversations", await buildTitle({ userId: alice.id, device: alice.device, conversation: group, chains, title: "Book club" }));
  await alice.send(group, "chapter one");

  const { conversation: bigger } = await alice.ok("conversations", await signed(alice, "add_members", { conversation_id: group.id, usernames: ["carol"] }));
  assert.equal(bigger.member_ids.length, 3);
  const old = await buildMessage({ userId: alice.id, device: alice.device, conversation: group, chains, text: "x" });
  assert.equal((await alice.call("messages", old)).body.code, "RECIPIENTS_CHANGED");
  const all = await alice.chainsFor(bigger);
  await alice.ok("conversations", await buildTitle({ userId: alice.id, device: alice.device, conversation: bigger, chains: all.chains, title: "Book club" }));
  await alice.send(bigger, "welcome carol");

  // Carol isn't even shown that earlier messages exist; Bob still sees everything.
  assert.deepEqual((await carol.read(bigger)).map((m) => [m.status, m.text]), [["ok", "welcome carol"]]);
  assert.deepEqual((await bob.read(bigger)).map((m) => m.text), ["chapter one", "welcome carol"]);
  const conv = (await carol.ok("conversations", { action: "get", conversation_id: group.id })).conversation;
  const title = await openItem({ kind: "title", item: { ...conv.title, conversation_id: conv.id }, userId: carol.id, keyring: carol.keyring, senderChain: all.chains.get(alice.id), senderDevices: (await carol.chainsFor(bigger)).devices.get(alice.id) });
  assert.equal(title.status, "ok");
  assert.equal(title.text, "Book club");

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

test("a poll is one query unless conversations are asked for, and only returns messages sealed to you", async () => {
  const { w, members: [alice, bob, carol] } = await world("alice", "bob", "carol");
  const group = await alice.group(["bob"]);
  const start = await carol.ok("messages", { action: "poll" });
  assert.ok(start.conversations_cursor);
  const before = (await alice.send(group, "before carol")).body.message.id;
  await alice.ok("conversations", await signed(alice, "add_members", { conversation_id: group.id, usernames: ["carol"] }));
  const bigger = (await alice.ok("conversations", { action: "get", conversation_id: group.id })).conversation;
  const after = (await alice.send(bigger, "after carol")).body.message.id;

  const queries = [];
  for (const name of ["Message", "Conversation"]) {
    const entity = w.entities[name];
    const original = entity.filter;
    entity.filter = async (...args) => {
      queries.push(name);
      return original(...args);
    };
  }
  const quick = await carol.ok("messages", { action: "poll", since: start.cursor });
  assert.deepEqual(queries, ["Message"], "one query");
  assert.equal(quick.conversation_ids, undefined);
  assert.deepEqual(quick.messages.map((m) => m.id), [after], "nothing from before she joined");
  assert.ok(!quick.messages.some((m) => m.id === before));

  const full = await carol.ok("messages", { action: "poll", since: start.cursor, conversations_since: start.conversations_cursor });
  assert.deepEqual(full.conversation_ids, [group.id]);
  assert.deepEqual(full.conversations.map((c) => [c.id, c.member_ids.length]), [[group.id, 3]]);
  assert.ok(full.conversations_cursor >= start.conversations_cursor);
  // Bob saw both, and the cursor never runs past "a few seconds ago", so a late row isn't skipped.
  const bobs = await bob.ok("messages", { action: "poll", since: start.cursor });
  assert.deepEqual(bobs.messages.map((m) => m.id).sort(), [before, after].sort());
  assert.ok(Date.parse(`${bobs.cursor}Z`) <= Date.now() - 4_000);
});

test("reading with your own access shows only conversations you're in and messages sealed to you", async () => {
  const { w, members: [alice, bob, eve] } = await world("alice", "bob", "eve");
  const dm = await alice.dm(bob);
  await alice.send(dm, "private");
  const asEve = w.clientFor(eve.user).entities;
  assert.deepEqual(await asEve.Message.filter({}), []);
  assert.deepEqual(await asEve.Conversation.filter({}), []);
  await assert.rejects(asEve.Conversation.get(dm.id), { status: 404 });
  assert.equal((await eve.call("messages", { action: "list", conversation_id: dm.id })).status, 404);
  assert.equal((await eve.call("conversations", { action: "get", conversation_id: dm.id })).status, 404);
  const asBob = w.clientFor(bob.user).entities;
  assert.equal((await asBob.Message.filter({})).length, 1);
  assert.equal((await asBob.Conversation.get(dm.id)).id, dm.id);
  // His own account's rows, and nobody else's.
  for (const name of ["AccountKey", "Device", "KeyEnvelope", "Profile"]) {
    const rows = await asBob[name].filter({});
    assert.ok(rows.length > 0 && rows.every((r) => r.user_id === bob.id), `${name}: only Bob's own rows`);
  }
  await assert.rejects(asBob.AccountKey.get(w.rows("AccountKey").find((k) => k.user_id === alice.id).id), { status: 404 });
  for (const name of ["Report", "SecurityReport", "Block", "RetiredUsername"]) {
    assert.deepEqual(await asBob[name].filter({}), [], `${name} can't be read directly`);
  }
  await assert.rejects(asBob.Message.update("any", {}), { status: 403 });
  await assert.rejects(asBob.Conversation.create({}), { status: 403 });
  await assert.rejects(asBob.AccountKey.create({}), { status: 403 });
  assert.deepEqual(await w.clientFor(null).entities.Message.filter({}), [], "nothing for visitors");
  assert.deepEqual(await w.clientFor(null).entities.Profile.filter({}), [], "nothing for visitors");
});

test("everyday reads come out of the member's own allowance; lookups across members take a few shared queries", async () => {
  const { w, members: [alice, ...others] } = await world("alice", "bob", "carol", "dave", "erin", "frank");
  for (const other of others) await alice.send(await alice.dm(other), `hello ${other.name}`);
  const ids = others.map((o) => o.id);
  w.serviceReads = 0;
  await alice.ok("profile", { action: "me" });
  await alice.ok("keys", { action: "status" });
  await alice.ok("keys", { action: "device_sync", device_id: alice.device.device_id });
  await alice.ok("keys", { action: "get_recovery" });
  const { conversations } = await alice.ok("conversations", { action: "list" });
  await alice.ok("conversations", { action: "get", conversation_id: conversations[0].id });
  await alice.ok("messages", { action: "list", conversation_id: conversations[0].id });
  const start = await alice.ok("messages", { action: "poll" });
  await alice.ok("messages", { action: "poll", since: start.cursor, conversations_since: start.conversations_cursor });
  assert.equal(w.serviceReads, 0, "page loads and polling use none of the shared allowance");
  const { keys } = await alice.ok("keys", { action: "peer_keys", user_ids: ids });
  assert.deepEqual(Object.keys(keys).sort(), [...ids].sort());
  assert.ok(Object.values(keys).every((k) => k.statements.length === 1 && k.devices.length === 1));
  assert.equal(w.serviceReads, 3, "keys for five people in three queries");
  w.serviceReads = 0;
  assert.equal((await alice.ok("profile", { action: "get_many", user_ids: ids })).profiles.length, 5);
  assert.equal(w.serviceReads, 1);
  // Sending: only the block check (direct messages) and everyone's current key versions.
  const { chains } = await alice.chainsFor(conversations[0]);
  const body = await buildMessage({ userId: alice.id, device: alice.device, conversation: conversations[0], chains, text: "one more", keyring: alice.keyring });
  w.serviceReads = 0;
  await alice.ok("messages", body);
  assert.equal(w.serviceReads, 2);
});

test("peer keys are only shared with people you have a conversation with", async () => {
  const { members: [alice, bob, eve] } = await world("alice", "bob", "eve");
  assert.deepEqual((await eve.ok("keys", { action: "peer_keys", user_ids: [alice.id] })).keys, {});
  await alice.dm(bob);
  const { keys } = await bob.ok("keys", { action: "peer_keys", user_ids: [alice.id, eve.id] });
  assert.deepEqual(Object.keys(keys), [alice.id]);
  assert.equal(keys[alice.id].devices[0].label, undefined, "device labels aren't shared with other members");
  assert.equal(keys[alice.id].statements[0].recovery_mac, undefined, "recovery anchors stay with the account");
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
  const { w, members: [alice] } = await world("alice");
  const { device: phone, keyring: phoneKeyring } = await alice.linkDevice("Phone");

  await alice.rotate();
  for (const e of w.rows("KeyEnvelope").filter((e) => e.device_id === phone.device_id)) e.device_id = "lost";
  assert.equal((await alice.ok("keys", { action: "device_sync", device_id: phone.device_id })).envelope, null);

  const target = (await alice.status()).devices.find((d) => d.device_id === phone.device_id);
  assert.equal(target.synced_key_version, 1);
  assert.equal(target.cert_key_version, 2, "the rotation renewed the phone's certificate");
  await alice.ok("keys", await prepareKeyringResend({ userId: alice.id, device: alice.device, keyring: alice.keyring, target, chain: await alice.myChain() }));
  const again = await alice.ok("keys", { action: "device_sync", device_id: phone.device_id });
  const { keyring } = await acceptKeyringEnvelope({ userId: alice.id, device: phone, envelope: again.envelope, statements: (await alice.status()).statements, current: phoneKeyring });
  assert.equal(latestKey(keyring).version, 2);
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

test("a signed-in session alone can't start conversations, change who's in them, or delete messages", async () => {
  const { w, members: [alice, bob, carol] } = await world("alice", "bob", "carol");
  const group = await alice.group(["bob"]);
  await alice.send(group, "hello group");
  const msg = w.rows("Message")[0];
  const attempts = [
    ["conversations", "create_dm", { username: "carol" }],
    ["conversations", "create_group", { usernames: ["carol"] }],
    ["conversations", "add_members", { conversation_id: group.id, usernames: ["carol"] }],
    ["conversations", "leave", { conversation_id: group.id }],
    ["messages", "delete", { message_id: msg.id }],
  ];
  for (const [fn, action, payload] of attempts) {
    const res = await alice.call(fn, { action, payload: JSON.stringify(payload), ...payload });
    assert.equal(res.status, 401, `${fn}.${action} without a proof`);
    assert.equal(res.body.code, "PROOF_REQUIRED");
  }
  const addProof = await signed(alice, "add_members", { conversation_id: group.id, usernames: ["carol"] });
  assert.equal((await alice.call("conversations", { ...addProof, action: "leave" })).body.code, "PROOF_INVALID");
  assert.equal((await alice.call("conversations", { ...addProof, payload: JSON.stringify({ conversation_id: group.id, usernames: ["bob"] }) })).body.code, "PROOF_INVALID");
  assert.equal((await alice.call("conversations", await signed(alice, "add_members", { conversation_id: group.id, usernames: ["carol"] }, carol.device))).body.code, "DEVICE_UNKNOWN");
  const { device: phone } = await alice.linkDevice("Phone");
  await alice.ok("keys", await prepareRevoke({ userId: alice.id, device: alice.device, targetDeviceId: phone.device_id }));
  assert.equal((await alice.call("conversations", await signed(alice, "add_members", { conversation_id: group.id, usernames: ["carol"] }, phone))).body.code, "DEVICE_NOT_ACTIVE");
  assert.equal(w.rows("Conversation").length, 1, "no conversation was started");
  assert.deepEqual(w.rows("Conversation")[0].member_ids, [alice.id, bob.id]);
  assert.equal(w.rows("Message")[0].deleted, false);
  await alice.ok("conversations", await signed(alice, "add_members", { conversation_id: group.id, usernames: ["carol"] }));
  assert.equal(w.rows("Conversation")[0].member_ids.length, 3);
});

// ---------------------------------------------------------------------------
// Security review regressions (A to O)

test("review A: a forged history for your own account is refused before anything is sealed or sent", async () => {
  const { members: [alice, bob] } = await world("alice", "bob");
  // The server shows Alice a made-up v1 with its own keys, plus a made-up active device.
  const fakeV1 = await createKeyVersion(1);
  const fakeRecovery = await deriveRecoveryKey(generateRecoveryPhrase());
  const forged = await verifyAccountChain(alice.id, [await makeAccountStatement({ userId: alice.id, keyVersion: fakeV1, recoveryPub: fakeRecovery.publicKey, signer: fakeV1 })]);
  const evil = await createDeviceKeys("Chrome on macOS");
  const evilCert = await makeDeviceCert({ userId: alice.id, device: evil, keyVersion: fakeV1 });
  const evilRow = { device_id: evil.device_id, sign_pub: evil.sign_pub, box_pub: evil.box_pub, status: "active", synced_key_version: 0, cert_key_version: 1, cert_issued_at: evilCert.issued_at, cert_signature: evilCert.signature };

  await assert.rejects(prepareKeyringResend({ userId: alice.id, device: alice.device, keyring: alice.keyring, target: evilRow, chain: forged }), { code: "KEYRING_MISMATCH" });
  await assert.rejects(prepareRotation({ userId: alice.id, device: alice.device, keyring: alice.keyring, chain: forged, activeDevices: [evilRow] }), { code: "KEYRING_MISMATCH" });
  const dm = await alice.dm(bob);
  const { chains } = await alice.chainsFor(dm);
  chains.set(alice.id, forged);
  await assert.rejects(buildMessage({ userId: alice.id, device: alice.device, conversation: dm, chains, text: "secret plan", keyring: alice.keyring }), { code: "KEYRING_MISMATCH" });
});

test("review B: rewriting a contact's history below the pin is caught, and changes the safety number", async () => {
  const { members: [alice, bob] } = await world("alice", "bob");
  const dm = await alice.dm(bob);
  await alice.rotate();
  const real = (await bob.chainsFor(dm)).chains.get(alice.id);
  const pin = pinFromChain(real, true);
  const bobChain = await bob.myChain();
  const before = safetyNumber({ user_id: bob.id, digest: headDigest(bobChain) }, { user_id: alice.id, digest: headDigest(real) });

  // The server invents a v1 and re-signs v2 with Alice's real signing key but its own encryption key.
  const f1 = await createKeyVersion(1);
  const serverKey = await createKeyVersion(2);
  const [st1, st2] = real.statements;
  const forged = await verifyAccountChain(alice.id, [
    await makeAccountStatement({ userId: alice.id, keyVersion: f1, recoveryPub: st1.recovery_pub, signer: f1 }),
    await makeAccountStatement({ userId: alice.id, keyVersion: { version: 2, ecdh_pub: serverKey.ecdh_pub, sign_pub: st2.sign_pub }, recoveryPub: st2.recovery_pub, signer: f1 }),
  ]);
  assert.equal(forged.latest.sign_pub, real.latest.sign_pub, "the same signing key, as in the attack");
  assert.equal(compareWithPin(forged, pin), "changed");
  const after = safetyNumber({ user_id: bob.id, digest: headDigest(bobChain) }, { user_id: alice.id, digest: headDigest(forged) });
  assert.notEqual(after, before, "comparing safety numbers would catch it too");
});

test("review C: messages sent from a removed device after its removal don't show as verified", async () => {
  const { members: [alice, bob] } = await world("alice", "bob");
  const dm = await alice.dm(bob);
  const { device: stolen } = await alice.linkDevice("Stolen phone");
  const { chains: before } = await alice.chainsFor(dm);
  const stolenRow = (await alice.status()).devices.find((d) => d.device_id === stolen.device_id);
  await alice.ok("keys", await prepareRevoke({ userId: alice.id, device: alice.device, targetDeviceId: stolen.device_id }));
  await alice.rotate({ exclude: [stolen.device_id] });

  // The thief signs a message dated after the rotation; a malicious server stores it anyway.
  const forged = await buildMessage({ userId: alice.id, device: stolen, conversation: dm, chains: before, text: "send the money" });
  const sentAt = new Date(Date.now() + 30 * 60_000).toISOString();
  const signature = await signItem({ device: stolen, kind: "message", conversationId: dm.id, itemId: forged.msg_id, senderId: alice.id, deviceId: stolen.device_id, envelopeJson: forged.envelope, sentAt });
  const item = { conversation_id: dm.id, msg_id: forged.msg_id, sender_id: alice.id, device_id: stolen.device_id, envelope: forged.envelope, signature, sent_at: sentAt };
  const { chains, devices } = await bob.chainsFor(dm);
  const relisted = devices.get(alice.id).map((d) => (d.device_id === stolen.device_id ? { ...d, status: "active" } : d));
  assert.equal(relisted.find((d) => d.device_id === stolen.device_id).cert_key_version, stolenRow.cert_key_version);
  const view = await openItem({ kind: "message", item, userId: bob.id, keyring: bob.keyring, senderChain: chains.get(alice.id), senderDevices: relisted });
  assert.equal(view.status, "unverified");
  assert.equal(view.reason, "removed-device");

  // Its messages from before the removal still check out.
  const earlier = await buildMessage({ userId: alice.id, device: stolen, conversation: dm, chains: before, text: "from before" });
  const earlierItem = { conversation_id: dm.id, msg_id: earlier.msg_id, sender_id: alice.id, device_id: stolen.device_id, envelope: earlier.envelope, signature: earlier.signature, sent_at: earlier.sent_at };
  const statements = chains.get(alice.id).statements.map((s) => ({ ...s }));
  const rotatedLater = await statementAt({
    userId: alice.id, keyVersion: { version: 2, ecdh_pub: statements[1].ecdh_pub, sign_pub: statements[1].sign_pub },
    recoveryPub: statements[1].recovery_pub, signer: alice.keyring.versions[0], issuedAt: new Date(Date.now() + 60 * 60_000).toISOString(),
  });
  const laterChain = await verifyAccountChain(alice.id, [statements[0], rotatedLater]);
  const ok = await openItem({ kind: "message", item: earlierItem, userId: bob.id, keyring: bob.keyring, senderChain: laterChain, senderDevices: devices.get(alice.id) });
  assert.equal(ok.status, "ok");
  assert.equal(ok.removedDevice, true, "and are marked as coming from a device that's since been removed");
});

test("review D: rotation and resend leave out removed devices, even when the server lists them again", async () => {
  const { members: [alice] } = await world("alice");
  const { device: stolen } = await alice.linkDevice("Stolen phone");
  const listedBefore = (await alice.status()).devices.filter((d) => d.status === "active");
  await alice.ok("keys", await prepareRevoke({ userId: alice.id, device: alice.device, targetDeviceId: stolen.device_id }));

  // A server that still lists the removed device as active can't get it the new keys...
  const rotation = await prepareRotation({
    userId: alice.id, device: alice.device, keyring: alice.keyring, chain: await alice.myChain(), activeDevices: listedBefore, excludeDeviceIds: [stolen.device_id],
  });
  const payload = JSON.parse(rotation.request.payload);
  assert.equal(payload.envelopes.length, 0);
  assert.ok(!payload.certs.some((c) => c.device_id === stolen.device_id));
  await alice.ok("keys", rotation.request);
  alice.keyring = rotation.keyring;

  // ...and after the rotation its old certificate no longer counts for anything new.
  const relisted = { ...listedBefore.find((d) => d.device_id === stolen.device_id), status: "active" };
  await assert.rejects(prepareKeyringResend({ userId: alice.id, device: alice.device, keyring: alice.keyring, target: relisted, chain: await alice.myChain() }), { code: "UNCERTIFIED_DEVICE" });
  const mine = (await alice.status()).devices.filter((d) => d.status === "active");
  await assert.rejects(
    prepareRotation({ userId: alice.id, device: alice.device, keyring: alice.keyring, chain: await alice.myChain(), activeDevices: [...mine, relisted] }),
    { code: "UNCERTIFIED_DEVICE" },
  );
});

test("review E: a password alone can't take an account over; a reset waits and the account's devices or phrase can stop it", async () => {
  const { w, members: [alice, bob] } = await world("alice", "bob");
  const dm = await alice.dm(bob);
  await alice.send(dm, "the real alice");

  // Someone with only Alice's password asks for a reset from their own browser.
  const attacker = await createDeviceKeys("Attacker's browser");
  const reset = await prepareReset({ userId: alice.id, device: attacker, nextVersion: 2 });
  const requested = await alice.ok("keys", reset.request);
  assert.equal(requested.request.status, "waiting");
  assert.ok(Date.parse(requested.request.effective_at) - Date.now() > 6.9 * 24 * 3600_000, "a week's wait");
  assert.equal(requested.emailed, true);
  assert.equal(w.emails.length, 1, "the account's own address is told");
  assert.equal(w.emails[0].to, alice.user.email);
  assert.match(w.emails[0].subject, /reset your encryption keys/);

  // Nothing has changed: Alice's device is active, her keys stand, and her devices see the request.
  const status = await alice.status();
  assert.equal(status.statements.length, 1);
  assert.equal(status.devices.find((d) => d.device_id === alice.device.device_id).status, "active");
  assert.equal(status.resets[0].status, "waiting");
  assert.equal(status.resets[0].device_label, "Attacker's browser");

  // The attacker can't act as Alice in the meantime.
  assert.equal((await alice.call("profile", { action: "delete_account", confirm: "DELETE" })).body.code, "PROOF_REQUIRED");
  assert.equal((await alice.call("profile", await signed(alice, "delete_account", { confirm: "DELETE" }, attacker))).body.code, "DEVICE_UNKNOWN");
  assert.equal((await alice.call("conversations", await signed(alice, "add_members", { conversation_id: dm.id, usernames: ["bob"] }, attacker))).body.code, "DEVICE_UNKNOWN");
  assert.equal((await alice.call("keys", await prepareFinishReset({ userId: alice.id, device: attacker, requestId: requested.request.id }))).body.code, "RESET_WAITING");

  // A second browser can't stack another request on top.
  const other = await prepareReset({ userId: alice.id, device: await createDeviceKeys(), nextVersion: 2 });
  assert.equal((await alice.call("keys", other.request)).body.code, "RESET_PENDING");

  // Alice's device cancels it; even after the wait, it can't complete.
  assert.equal((await alice.call("keys", { action: "cancel_reset" })).body.code, "PROOF_REQUIRED", "cancelling needs a device too");
  await alice.ok("keys", await prepareCancelReset({ userId: alice.id, device: alice.device }));
  w.rows("ResetRequest")[0].effective_at = new Date(Date.now() - 1000).toISOString();
  assert.equal((await alice.call("keys", await prepareFinishReset({ userId: alice.id, device: attacker, requestId: requested.request.id }))).body.code, "RESET_ENDED");
  assert.equal((await alice.myChain()).latest.version, 1);
  assert.equal((await bob.read(dm))[0].status, "ok");
});

test("review E: unlocking with the phrase also cancels a waiting reset", async () => {
  const { w, members: [alice] } = await world("alice");
  const intruder = await createDeviceKeys("Intruder");
  const reset = await prepareReset({ userId: alice.id, device: intruder, nextVersion: 2 });
  w.emailDown = true;
  const { request, emailed } = await alice.ok("keys", reset.request);
  assert.equal(emailed, false, "if the email can't be sent, the request still stands and the devices still show it");
  assert.equal((await alice.status()).resets[0].status, "waiting");
  const fresh = await createDeviceKeys("Alice's new laptop");
  const recovered = await recoverWithPhrase({ userId: alice.id, device: fresh, phrase: alice.phrase, recoveryResponse: await alice.ok("keys", { action: "get_recovery" }) });
  await alice.ok("keys", recovered.request);
  assert.equal(w.rows("ResetRequest")[0].status, "cancelled");
  assert.equal(w.rows("ResetRequest")[0].ended_by, "recovery");
  w.rows("ResetRequest")[0].effective_at = new Date(Date.now() - 1000).toISOString();
  assert.equal((await alice.call("keys", await prepareFinishReset({ userId: alice.id, device: intruder, requestId: request.id }))).body.code, "RESET_ENDED");
});

test("a reset nobody stops completes after the wait: new identity, old devices removed, contacts see a change", async () => {
  const { w, members: [alice, bob] } = await world("alice", "bob");
  const dm = await alice.dm(bob);
  await bob.send(dm, "old secret");
  const bobPin = pinFromChain((await bob.chainsFor(dm)).chains.get(alice.id), true);

  const fresh = await createDeviceKeys("After losing everything");
  const reset = await prepareReset({ userId: alice.id, device: fresh, nextVersion: 2 });
  const noConfirm = JSON.parse(reset.request.payload);
  delete noConfirm.confirm;
  assert.equal((await alice.call("keys", await signedRequest({ userId: alice.id, device: fresh, action: "request_reset", payload: noConfirm }))).body.code, "CONFIRM_REQUIRED");
  const { request } = await alice.ok("keys", reset.request);
  // Someone else's device can't finish it, and nor can a stray session.
  assert.equal((await alice.call("keys", await prepareFinishReset({ userId: alice.id, device: bob.device, requestId: request.id }))).body.code, "PROOF_INVALID");
  w.rows("ResetRequest")[0].effective_at = new Date(Date.now() - 1000).toISOString();
  const finished = await alice.ok("keys", await prepareFinishReset({ userId: alice.id, device: fresh, requestId: request.id }));
  assert.equal(finished.emailed, true);
  assert.deepEqual(w.emails.map((e) => e.subject), [
    "Commonveil: someone asked to reset your encryption keys",
    "Commonveil: your encryption keys were reset",
  ], "the account's address hears when it's asked for and when it's done");

  const status = await alice.status();
  assert.equal(status.devices.find((d) => d.device_id === alice.device.device_id).status, "revoked");
  assert.equal(status.devices.find((d) => d.device_id === fresh.device_id).status, "active");
  assert.equal(compareWithPin((await bob.chainsFor(dm)).chains.get(alice.id), bobPin), "changed");
  const newAlice = alice.as(fresh, reset.keyring);
  assert.equal((await newAlice.read(dm))[0].status, "locked", "messages to the old identity can't be read after a reset");
  const fromOld = await buildMessage({ userId: alice.id, device: alice.device, conversation: dm, chains: (await alice.chainsFor(dm)).chains, text: "old device" });
  assert.equal((await alice.call("messages", fromOld)).body.code, "DEVICE_NOT_ACTIVE");
  await assert.rejects(alice.send(dm, "old device"), { code: "KEYRING_MISMATCH" }, "and the old keys know they no longer apply");
  // The new identity's phrase works for recovery.
  const recovered = await recoverWithPhrase({ userId: alice.id, device: await createDeviceKeys(), phrase: reset.phrase, recoveryResponse: await alice.ok("keys", { action: "get_recovery" }) });
  assert.equal(latestKey(recovered.keyring).version, 2);
  // Only the browser that asked can take a request back.
  const again = await prepareReset({ userId: alice.id, device: await createDeviceKeys(), nextVersion: 3 });
  const second = (await alice.ok("keys", again.request)).request;
  const requester = await createDeviceKeys();
  assert.equal((await alice.call("keys", await prepareWithdrawReset({ userId: alice.id, device: requester, requestId: second.id }))).body.code, "PROOF_INVALID");
});

test("review F: a new device only accepts the keyring that matches its link code, and recovery only the phrase's keys", async () => {
  const { members: [alice] } = await world("alice");
  const phone = await createDeviceKeys("Phone");
  const pin = linkPinFor(await alice.myChain());
  await alice.ok("keys", await prepareRegisterDevice({ userId: alice.id, device: phone }));

  // The server seals a keyring of its own, with a matching made-up history, to the phone.
  const fakeV1 = await createKeyVersion(1);
  const fakeKeyring = newKeyring(alice.id, fakeV1);
  const fakeStatement = await makeAccountStatement({ userId: alice.id, keyVersion: fakeV1, recoveryPub: (await deriveRecoveryKey(generateRecoveryPhrase())).publicKey, signer: fakeV1 });
  const fakeEnvelope = await sealKeyringToDevice(fakeKeyring, phone);
  await assert.rejects(acceptKeyringEnvelope({ userId: alice.id, device: phone, envelope: fakeEnvelope, statements: [fakeStatement], pin }), { code: "ANCHOR_MISMATCH" });
  await assert.rejects(acceptKeyringEnvelope({ userId: alice.id, device: phone, envelope: fakeEnvelope, statements: [fakeStatement] }), { code: "NO_ANCHOR" });
  // Or the real history with its own keyring: the keys don't match the history.
  await assert.rejects(acceptKeyringEnvelope({ userId: alice.id, device: phone, envelope: fakeEnvelope, statements: (await alice.status()).statements, pin }), { code: "KEYRING_MISMATCH" });

  // Recovery: a server-made backup sealed to Alice's real (public) recovery key, under a made-up history that copies her recovery key.
  const real = await alice.myChain();
  const forgedStatement = await makeAccountStatement({ userId: alice.id, keyVersion: fakeV1, recoveryPub: real.latest.recovery_pub, signer: fakeV1 });
  const forgedBackup = await sealKeyringForRecovery(fakeKeyring, real.latest.recovery_pub);
  const forgedResponse = { statements: [forgedStatement], recovery: { ...forgedBackup, recovery_pub: real.latest.recovery_pub } };
  await assert.rejects(recoverWithPhrase({ userId: alice.id, device: await createDeviceKeys(), phrase: alice.phrase, recoveryResponse: forgedResponse }), { code: "ANCHOR_MISSING" });
  // Copying Alice's real anchor onto the made-up statement doesn't help: it covers the keys.
  const copied = { ...forgedStatement, recovery_mac: real.latest.recovery_mac };
  await assert.rejects(recoverWithPhrase({ userId: alice.id, device: await createDeviceKeys(), phrase: alice.phrase, recoveryResponse: { ...forgedResponse, statements: [copied] } }), { code: "ANCHOR_MISSING" });
});

test("review I: device requests are rate limited, and a pile of old rows never hides a live device", async () => {
  const { w, members: [alice] } = await world("alice");
  const longAgo = new Date(Date.now() - 3 * 24 * 3600_000).toISOString().replace("Z", "000");
  for (let i = 0; i < 150; i += 1) {
    const row = await w.entities.Device.create({ user_id: alice.id, device_id: `old${String(i).padStart(14, "0")}`, sign_pub: "x", box_pub: "y", status: "revoked", revoked_reason: "expired" });
    w.rows("Device").find((r) => r.id === row.id).created_date = longAgo;
  }
  const { device: laptop } = await alice.linkDevice("Laptop");
  const listed = (await alice.status()).devices;
  assert.ok(listed.some((d) => d.device_id === alice.device.device_id && d.status === "active"));
  assert.ok(listed.some((d) => d.device_id === laptop.device_id && d.status === "active"));

  // Registrations: at most a handful a day, however they're spaced.
  let refused = null;
  for (let i = 0; i < 12 && !refused; i += 1) {
    const d = await createDeviceKeys(`Request ${i}`);
    const res = await alice.call("keys", await prepareRegisterDevice({ userId: alice.id, device: d }));
    if (res.status !== 200) refused = res.body.code;
    for (const row of w.rows("Device").filter((r) => r.status === "pending")) row.status = "revoked"; // make room under the pending limit
  }
  assert.equal(refused, "RATE_LIMITED");
});

test("review O: rate limits hold when requests arrive at the same moment", async () => {
  const { w, members: [alice, bob] } = await world("alice", "bob");
  const results = await Promise.all(
    Array.from({ length: 45 }, async () => alice.call("conversations", await signed(alice, "create_group", { usernames: ["bob"] }))),
  );
  const ok = results.filter((r) => r.status === 200).length;
  assert.ok(ok <= 30, `${ok} groups were created against a limit of 30`);
  assert.equal(w.rows("Conversation").filter((c) => c.creator_id === alice.id).length, ok);
  assert.ok(results.filter((r) => r.status === 429).length >= 15);
  assert.ok(bob);
});

// ---------------------------------------------------------------------------
// Reporting security problems

test("only the security-report and invite-preview functions let in callers who aren't signed in", () => {
  const dir = new URL("../base44/functions/", import.meta.url);
  const names = readdirSync(dir).sort();
  assert.deepEqual(names, [...Object.keys(FUNCTIONS), ...Object.keys(PUBLIC_FUNCTIONS), ...SCHEDULED_FUNCTIONS].sort(), "every deployed function is covered here");
  for (const name of names) {
    const source = readFileSync(new URL(`${name}/entry.ts`, dir), "utf8");
    if (SCHEDULED_FUNCTIONS.includes(name)) {
      // No member actions at all: only the named task, run as the app itself (see the maintenance tests).
      assert.doesNotMatch(source, /serve\(|Actions|allowAnonymous/, name);
      assert.match(source, /runMaintenance\(createClientFromRequest\(req\)\.asServiceRole, task, new Date\(\)\)/, name);
      continue;
    }
    const isPublic = Object.hasOwn(PUBLIC_FUNCTIONS, name);
    assert.equal(/allowAnonymous/.test(source), isPublic, name);
    if (!isPublic) assert.match(source, /return serve\(req, createClientFromRequest, \w+(, \{ maxBodyBytes: \w+ \})?\);/, `${name} keeps the default sign-in check`);
    else assert.match(source, /return serve\(req, createClientFromRequest, \w+, \{ allowAnonymous: true \}\);/, name);
  }
});

test("anyone can report a security problem, within limits, and only staff can read the reports", async () => {
  const w = new FakeWorld();
  const visitor = new Member(w, "visitor");
  const alice = await new Member(w, "alice").setup();
  const staff = new Member(w, "staffer", "admin");
  const report = (n) => ({ action: "submit", summary: `Problem ${n}`, details: "Open the page, then look closely at the response.", contact: "researcher@example.test" });
  const anon = (body) => visitor.call("disclose", body, { anonymous: true });

  assert.equal((await anon({ action: "submit", summary: "x", details: "long enough to count as details" })).body.code, "BAD_FIELD");
  assert.equal((await anon({ action: "submit", summary: "A title", details: "too short" })).body.code, "BAD_FIELD");
  assert.equal((await anon({ action: "submit", summary: "A title", details: "d".repeat(8001) })).body.code, "TOO_LONG");
  assert.equal((await anon({ action: "submit", summary: "A title", details: { nested: true } })).body.code, "BAD_FIELD");
  assert.equal((await anon({ action: "list_security_reports" })).body.code, "UNKNOWN_ACTION", "nothing but submit is reachable");
  assert.equal(w.rows("SecurityReport").length, 0);

  for (let i = 0; i < DISCLOSURE_LIMITS.anonymousPerHour; i += 1) assert.equal((await anon(report(i))).status, 200);
  assert.equal((await anon(report("extra"))).status, 429);
  for (let i = 0; i < DISCLOSURE_LIMITS.perUserPerDay; i += 1) assert.equal((await alice.call("disclose", report(`a${i}`))).status, 200);
  assert.equal((await alice.call("disclose", report("a-extra"))).status, 429);

  const hoursAgo = (h) => new Date(Date.now() - h * 3600_000).toISOString().replace("Z", "000");
  let anonymous = DISCLOSURE_LIMITS.anonymousPerHour;
  while (anonymous < DISCLOSURE_LIMITS.anonymousPerDay) {
    for (const r of w.rows("SecurityReport")) if (!r.reporter_user_id) r.created_date = hoursAgo(2);
    assert.equal((await anon(report(`later ${anonymous}`))).status, 200, `report ${anonymous + 1}`);
    anonymous += 1;
  }
  for (const r of w.rows("SecurityReport")) if (!r.reporter_user_id) r.created_date = hoursAgo(2);
  assert.equal((await anon(report("over the day"))).status, 429);
  for (const r of w.rows("SecurityReport")) r.created_date = hoursAgo(25);
  assert.equal((await anon(report("next day"))).status, 200);

  const stored = w.rows("SecurityReport");
  assert.ok(stored.every((r) => r.status === "new" && r.contact === "researcher@example.test"));
  assert.equal(stored.filter((r) => r.reporter_user_id === alice.id).length, DISCLOSURE_LIMITS.perUserPerDay);

  assert.equal((await alice.call("admin", { action: "list_security_reports" })).status, 403);
  assert.equal((await alice.call("admin", { action: "update_security_report", report_id: stored[0].id, status: "closed" })).status, 403);
  const { reports } = await staff.ok("admin", { action: "list_security_reports", status: "new" });
  assert.equal(reports.length, stored.length);
  assert.equal(reports.find((r) => r.summary === "Problem 0").reporter, "");
  const fromAlice = reports.find((r) => r.reporter === "alice");
  assert.ok(fromAlice);
  await staff.ok("admin", { action: "update_security_report", report_id: fromAlice.id, status: "triaged", staff_note: "Reproduced" });
  const triaged = (await staff.ok("admin", { action: "list_security_reports", status: "triaged" })).reports;
  assert.deepEqual(triaged.map((r) => [r.id, r.staff_note]), [[fromAlice.id, "Reproduced"]]);
});

// ---------------------------------------------------------------------------
// Deleting an account

const PERSONAL = ["Message", "Conversation", "Block", "Report", "KeyEnvelope", "AccountKey", "Device", "Profile", "ResetRequest"];

/** Record each row as it was at the moment it was deleted. */
function watchDeletes(w, names) {
  const seen = [];
  for (const name of names) {
    const entity = w.entities[name];
    const original = entity.delete;
    entity.delete = async (rowId) => {
      const row = entity._rows.find((r) => r.id === rowId);
      if (row) seen.push({ name, row: JSON.parse(JSON.stringify(row)) });
      return original(rowId);
    };
  }
  return seen;
}

/**
 * Rows that still mention a user, apart from what's meant to stay: the recipient lists sealed
 * inside other people's messages, and reports other people made about them.
 */
function mentions(w, userId) {
  const found = [];
  for (const name of PERSONAL) {
    for (const r of w.rows(name)) {
      if (name === "Report" && r.reported_user_id === userId && r.reporter_id !== userId) continue;
      // Other people's messages to her still list her as a recipient, inside the signed envelope and beside it.
      const visible = name === "Message" && r.sender_id !== userId ? { ...r, envelope: "", recipient_ids: [] } : r;
      if (JSON.stringify(visible).includes(userId)) found.push(`${name} ${r.id}`);
    }
  }
  return found;
}

test("deleting an account takes a device signature and the word DELETE, then removes everything of theirs", async () => {
  const { w, members: [alice, bob, carol] } = await world("alice", "bob", "carol");
  for (const m of [alice, bob, carol]) w.rows("User").push({ ...m.user });

  const dm = await alice.dm(bob);
  await alice.send(dm, "hello bob");
  await bob.send(dm, "hello alice");
  const group = await alice.group(["bob", "carol"]);
  const { chains } = await alice.chainsFor(group);
  await alice.ok("conversations", await buildTitle({ userId: alice.id, device: alice.device, conversation: group, chains, title: "Neighbours" }));
  await alice.send(group, "hello group");
  await bob.send(group, "bob was here");
  await alice.ok("safety", { action: "report", user_id: carol.id, reason: "spam" });
  await carol.ok("safety", { action: "report", user_id: alice.id, reason: "harassment", details: "Kept messaging me" });
  await carol.ok("safety", { action: "block", user_id: alice.id });
  await alice.ok("disclose", { action: "submit", summary: "Found a bug", details: "The steps to reproduce it go in here." });

  const sessionOnly = await alice.call("profile", { action: "delete_account", confirm: "DELETE" });
  assert.equal(sessionOnly.status, 401);
  assert.equal(sessionOnly.body.code, "PROOF_REQUIRED");
  assert.equal((await alice.call("profile", await signed(alice, "delete_account", { confirm: "delete" }))).body.code, "CONFIRM_REQUIRED");
  const leaveProof = await signed(alice, "leave", { confirm: "DELETE" });
  assert.equal((await alice.call("profile", { ...leaveProof, action: "delete_account" })).body.code, "PROOF_INVALID");
  assert.equal((await alice.call("profile", await signed(alice, "delete_account", { confirm: "DELETE" }, bob.device))).body.code, "DEVICE_UNKNOWN");
  assert.equal(w.rows("Profile").filter((p) => p.user_id === alice.id).length, 1, "nothing removed yet");

  const deleted = watchDeletes(w, PERSONAL);
  assert.deepEqual(await alice.ok("profile", await signed(alice, "delete_account", { confirm: "DELETE" })), { done: true, sign_in_removed: true });

  const count = (name) => deleted.filter((d) => d.name === name).length;
  assert.deepEqual(
    ["Message", "Conversation", "Report", "Block", "AccountKey", "Device", "Profile"].map((n) => [n, count(n)]),
    [["Message", 3], ["Conversation", 1], ["Report", 1], ["Block", 1], ["AccountKey", 1], ["Device", 1], ["Profile", 1]],
  );
  assert.ok(count("KeyEnvelope") >= 1);
  for (const { name, row } of deleted) {
    assert.ok(!JSON.stringify(row).includes(alice.id), `${name} row still named Alice when it was deleted`);
    if (name === "Message") assert.equal(row.envelope, "");
    if (name === "KeyEnvelope") assert.equal(row.sealed, "");
    if (name === "Profile") assert.equal(row.username, "");
  }
  assert.deepEqual(mentions(w, alice.id), []);
  assert.equal(w.rows("User").some((u) => u.id === alice.id), false, "sign-in removed");
  assert.equal(w.rows("User").length, 2);
  assert.deepEqual(w.rows("SecurityReport").map((r) => [r.summary, r.reporter_user_id]), [["Found a bug", ""]]);
  assert.deepEqual(w.rows("Report").map((r) => [r.reporter_id, r.reported_user_id, r.details]), [[carol.id, alice.id, "Kept messaging me"]], "Carol's report about Alice stays");

  const { conversations } = await bob.ok("conversations", { action: "list" });
  assert.deepEqual(conversations.map((c) => c.id), [group.id]);
  const after = conversations[0];
  assert.deepEqual(after.member_ids, [bob.id, carol.id]);
  assert.equal(after.title, null, "a name only Alice could vouch for is cleared");
  assert.equal((await bob.send(after, "carry on")).status, 200);
  assert.deepEqual((await carol.read(after)).map((m) => [m.status, m.text]), [["ok", "bob was here"], ["ok", "carry on"]]);

  assert.equal((await bob.call("profile", { action: "find", username: "alice" })).status, 404);
  const mallory = new Member(w, "mallory");
  assert.equal((await mallory.call("profile", { action: "claim_username", username: "Alice" })).body.code, "USERNAME_TAKEN");
  assert.deepEqual(w.rows("RetiredUsername").map((r) => Object.keys(r).filter((k) => !["id", "created_date", "updated_date"].includes(k))), [["username_key"]]);

  assert.equal((await alice.ok("profile", await signed(alice, "delete_account", { confirm: "DELETE" }))).done, true);
});

test("a deletion that runs out of time picks up where it stopped", async () => {
  const { w, members: [alice, bob, carol] } = await world("alice", "bob", "carol");
  const dm = await alice.dm(bob);
  for (let i = 0; i < 4; i += 1) await bob.send(dm, `to alice ${i}`);
  const group = await bob.group(["alice", "carol"]);
  for (let i = 0; i < 3; i += 1) await alice.send(group, `from alice ${i}`);

  const realNow = Date.now;
  Date.now = () => realNow() + w.writes * 10_000;
  let calls = 0;
  try {
    for (;;) {
      calls += 1;
      assert.ok(calls < 40, "deletion never finished");
      const res = await alice.ok("profile", await signed(alice, "delete_account", { confirm: "DELETE" }));
      if (res.done) break;
      assert.deepEqual(res, { done: false });
    }
  } finally {
    Date.now = realNow;
  }
  assert.ok(calls >= 3, `expected several calls, took ${calls}`);
  assert.deepEqual(mentions(w, alice.id), []);
  assert.deepEqual((await bob.ok("conversations", { action: "list" })).conversations.map((c) => c.member_ids), [[bob.id, carol.id]]);
});

test("an account that never set up keys is deleted with just the confirmation; staff accounts can't be deleted here", async () => {
  const w = new FakeWorld();
  const dan = new Member(w, "dan");
  await dan.ok("profile", { action: "claim_username", username: "dan" });
  assert.equal((await dan.call("profile", { action: "delete_account" })).body.code, "CONFIRM_REQUIRED");
  assert.equal((await dan.call("profile", { action: "delete_account", confirm: "yes" })).body.code, "CONFIRM_REQUIRED");
  assert.deepEqual(await dan.ok("profile", { action: "delete_account", confirm: "DELETE" }), { done: true, sign_in_removed: true });
  assert.equal(w.rows("Profile").length, 0);
  const eve = new Member(w, "eve");
  assert.equal((await eve.ok("profile", { action: "delete_account", confirm: "DELETE" })).done, true);
  const staff = new Member(w, "staffer", "admin");
  const refused = await staff.call("profile", { action: "delete_account", confirm: "DELETE" });
  assert.equal(refused.status, 403);
  assert.equal(refused.body.code, "STAFF_ACCOUNT");
});

test("staff can erase what a removed sign-in left behind, and never an account that can still sign in", async () => {
  const { w, members: [alice, bob] } = await world("alice", "bob");
  const staff = new Member(w, "staffer", "admin");
  for (const m of [alice, bob, staff]) w.rows("User").push({ ...m.user });
  const dm = await alice.dm(bob);
  await alice.send(dm, "hello bob");
  await bob.send(dm, "hello alice");
  const group = await alice.group(["bob"]);
  await bob.send(group, "bob in the group");
  await alice.send(group, "alice in the group");

  // Bob's sign-in is removed in the Base44 dashboard. Everything of his is still here.
  w.rows("User").splice(w.rows("User").findIndex((u) => u.id === bob.id), 1);
  assert.equal((await alice.call("admin", { action: "list_removed_accounts" })).status, 403);
  assert.equal((await alice.call("admin", { action: "erase_removed_account", user_id: bob.id, confirm: "ERASE" })).status, 403);
  const listed = await staff.ok("admin", { action: "list_removed_accounts" });
  assert.deepEqual(listed.accounts.map((a) => a.username), ["bob"]);
  assert.equal(listed.complete, true);

  assert.equal((await staff.call("admin", { action: "erase_removed_account", user_id: bob.id })).body.code, "CONFIRM_REQUIRED");
  assert.equal((await staff.call("admin", { action: "erase_removed_account", user_id: alice.id, confirm: "ERASE" })).body.code, "SIGN_IN_EXISTS");

  // If the platform can't see sign-ins properly, nobody is called removed and nothing is erased.
  const users = w.entities.User;
  const { filter, get } = users;
  users.filter = async () => [];
  users.get = async () => {
    throw Object.assign(new Error("Not found"), { status: 404 });
  };
  assert.equal((await staff.call("admin", { action: "list_removed_accounts" })).body.code, "CHECK_FAILED");
  assert.equal((await staff.call("admin", { action: "erase_removed_account", user_id: alice.id, confirm: "ERASE" })).body.code, "CHECK_FAILED");
  // Two separate checks: one missing Alice isn't enough.
  users.filter = async (...args) => (await filter(...args)).filter((u) => u.id !== alice.id);
  users.get = get;
  assert.equal((await staff.call("admin", { action: "erase_removed_account", user_id: alice.id, confirm: "ERASE" })).body.code, "SIGN_IN_EXISTS");
  users.filter = filter;
  users.get = async () => {
    throw Object.assign(new Error("Service unavailable"), { status: 503 });
  };
  assert.equal((await staff.call("admin", { action: "erase_removed_account", user_id: bob.id, confirm: "ERASE" })).body.code, "CHECK_FAILED");
  users.get = get;
  assert.equal(w.rows("Profile").length, 2, "nothing was erased by any of that");

  assert.deepEqual(await staff.ok("admin", { action: "erase_removed_account", user_id: bob.id, confirm: "ERASE" }), { done: true });
  assert.deepEqual(mentions(w, bob.id), []);
  assert.deepEqual((await staff.ok("admin", { action: "list_removed_accounts" })).accounts, []);
  const { conversations } = await alice.ok("conversations", { action: "list" });
  assert.deepEqual(conversations.map((c) => [c.id, c.member_ids]), [[group.id, [alice.id]]], "the direct conversation went; Bob left the group");
  assert.deepEqual((await alice.read(conversations[0])).map((m) => m.text), ["alice in the group"]);
  const newcomer = new Member(w, "newcomer");
  assert.equal((await newcomer.call("profile", { action: "claim_username", username: "bob" })).body.code, "USERNAME_TAKEN");
  assert.equal(w.rows("Profile").filter((p) => p.user_id === alice.id).length, 1, "Alice is untouched");
});

test("the last member to leave a group takes its messages with it, blanked first", async () => {
  const { w, members: [alice, bob] } = await world("alice", "bob");
  const group = await alice.group(["bob"]);
  await alice.send(group, "one");
  await bob.send(group, "two");
  await bob.ok("conversations", await signed(bob, "leave", { conversation_id: group.id }));
  const deleted = watchDeletes(w, ["Message", "Conversation"]);
  await alice.ok("conversations", await signed(alice, "leave", { conversation_id: group.id }));
  assert.equal(w.rows("Conversation").length, 0);
  assert.equal(w.rows("Message").length, 0);
  assert.deepEqual(deleted.map((d) => d.name).sort(), ["Conversation", "Message", "Message"]);
  assert.ok(deleted.every(({ row }) => !row.envelope && !row.sender_id && !(row.member_ids || []).length));
});

test("statements without the phrase's anchor are refused where the phrase is to hand", async () => {
  const { members: [alice] } = await world("alice");
  const rotation = await prepareRotation({
    userId: alice.id, device: alice.device, keyring: alice.keyring, chain: await alice.myChain(),
    activeDevices: (await alice.status()).devices.filter((d) => d.status === "active"), newPhrase: true,
  });
  const payload = JSON.parse(rotation.request.payload);
  delete payload.statement.recovery_mac;
  assert.equal((await alice.call("keys", await signed(alice, "rotate_keys", payload))).body.code, "BAD_STATEMENT");
  // An ordinary rotation carries no anchor; one sent anyway isn't stored.
  const plain = await prepareRotation({
    userId: alice.id, device: alice.device, keyring: alice.keyring, chain: await alice.myChain(),
    activeDevices: (await alice.status()).devices.filter((d) => d.status === "active"),
  });
  const plainPayload = JSON.parse(plain.request.payload);
  plainPayload.statement.recovery_mac = await recoveryAnchorMac(new Uint8Array(32), plainPayload.statement);
  await alice.ok("keys", await signed(alice, "rotate_keys", plainPayload));
  assert.equal((await alice.status()).statements[1].recovery_mac, "");
});

// ---------------------------------------------------------------------------
// Disappearing messages, group admins, security emails and auto-delete

const DAY_MS = 24 * 3600_000;
const dayString = (ms) => new Date(ms).toISOString().slice(0, 10);
const conversationCall = async (member, action, payload) => member.call("conversations", await signed(member, action, payload));

/** Run a scheduled task as the automation does: no user, the app's own access. */
async function maintenance(w, task, at = new Date()) {
  resetMaintenanceThrottle();
  const res = await runMaintenance(w.clientFor(null).asServiceRole, task, at);
  assert.equal(res.status, 200, `${task} failed`);
  return res.json();
}

test("disappearing messages: either person in a DM sets the timer; messages vanish when it's up and are then deleted, blanked first", async () => {
  const { w, members: [alice, bob] } = await world("alice", "bob");
  const dm = await alice.dm(bob);
  await alice.send(dm, "sent before the timer");
  assert.equal((await bob.call("conversations", { action: "set_expiry", conversation_id: dm.id, seconds: 86_400 })).body.code, "PROOF_REQUIRED");
  assert.equal((await conversationCall(bob, "set_expiry", { conversation_id: dm.id, seconds: 3600 })).body.code, "BAD_FIELD", "only the offered choices");
  const set = (await conversationCall(bob, "set_expiry", { conversation_id: dm.id, seconds: 86_400 })).body;
  assert.equal(set.conversation.expire_seconds, 86_400);
  assert.equal(set.conversation.expiry_set_by, bob.id, "everyone sees who set it");
  const conv = set.conversation;

  assert.equal((await alice.send(conv, "gone tomorrow")).status, 200);
  assert.equal((await alice.send(conv, "also timed")).status, 200);
  const timed = w.rows("Message").filter((r) => r.expires_at);
  assert.equal(timed.length, 2, "messages from before the timer keep no expiry");
  assert.ok(Math.abs(Date.parse(timed[0].expires_at) - Date.now() - 86_400_000) < 60_000, "a day from when it arrived");
  assert.deepEqual((await bob.read(conv)).map((m) => m.text), ["sent before the timer", "gone tomorrow", "also timed"]);

  // Time's up for one: it's hidden straight away, from listing and polling alike...
  timed[0].expires_at = new Date(Date.now() - 1000).toISOString();
  const goneId = timed[0].id;
  assert.deepEqual((await bob.read(conv)).map((m) => m.text), ["sent before the timer", "also timed"]);
  const polled = await bob.ok("messages", { action: "poll", since: "2000-01-01T00:00:00" });
  assert.ok(polled.messages.length && polled.messages.every((m) => m.id !== goneId));
  // ...paging still finds what's behind it...
  const page = await bob.ok("messages", { action: "list", conversation_id: conv.id, limit: 2 });
  assert.deepEqual(page.messages.length, 1);
  assert.equal(page.has_more, true);
  const older = await bob.ok("messages", { action: "list", conversation_id: conv.id, limit: 2, before: page.before });
  assert.equal(older.messages.length, 1);
  // ...and the scheduled clean-up deletes it, blanked first. Nothing else is touched.
  const deleted = watchDeletes(w, ["Message"]);
  assert.deepEqual(await maintenance(w, "expire"), { task: "expire", removed: 1, server_removed: 0, audit_removed: 0, passes_removed: 0, files_removed: 0, bans_lifted: 0, done: true });
  assert.equal(deleted.length, 1);
  assert.equal(deleted[0].row.id, goneId);
  assert.ok(!deleted[0].row.envelope && !deleted[0].row.sender_id && !deleted[0].row.expires_at && !deleted[0].row.recipient_ids.length);
  assert.equal(w.rows("Message").length, 2);
  assert.deepEqual(await maintenance(w, "expire"), { task: "expire", removed: 0, server_removed: 0, audit_removed: 0, passes_removed: 0, files_removed: 0, bans_lifted: 0, done: true }, "nothing else was due");

  // Either of them can turn it off; later messages are kept again.
  const off = (await conversationCall(alice, "set_expiry", { conversation_id: dm.id, seconds: 0 })).body.conversation;
  assert.equal(off.expire_seconds, 0);
  assert.equal(off.expiry_set_by, alice.id);
  await alice.send(off, "kept again");
  assert.equal(w.rows("Message").filter((r) => r.expires_at).length, 1);
});

test("the scheduled clean-up takes no instructions: unknown tasks are refused, and back-to-back calls do nothing", async () => {
  const w = new FakeWorld();
  const sr = w.clientFor(null).asServiceRole;
  resetMaintenanceThrottle();
  assert.equal((await runMaintenance(sr, "erase_everything", new Date())).status, 400);
  assert.equal((await runMaintenance(sr, undefined, new Date())).status, 400);
  assert.equal((await runMaintenance(sr, "__proto__", new Date())).status, 400);
  assert.equal((await (await runMaintenance(sr, "expire", new Date())).json()).removed, 0);
  const reads = w.serviceReads;
  assert.deepEqual(await (await runMaintenance(sr, "expire", new Date())).json(), { task: "expire", skipped: "ran recently" });
  assert.equal(w.serviceReads, reads, "a repeat call costs nothing");
});

test("group admins: only admins add, remove, rename, set the timer or choose admins, and a group always keeps one", async () => {
  const { members: [alice, bob, carol, dave] } = await world("alice", "bob", "carol", "dave");
  const group = await alice.group(["bob", "carol"]);
  assert.deepEqual(group.admin_ids, [alice.id], "whoever starts a group runs it");

  for (const [action, payload] of [
    ["add_members", { conversation_id: group.id, usernames: ["dave"] }],
    ["remove_member", { conversation_id: group.id, user_id: carol.id }],
    ["set_admin", { conversation_id: group.id, user_id: bob.id, admin: true }],
    ["set_expiry", { conversation_id: group.id, seconds: 86_400 }],
  ]) {
    assert.equal((await conversationCall(bob, action, payload)).body.code, "NOT_ADMIN", action);
  }
  const { chains } = await bob.chainsFor(group);
  const rename = await buildTitle({ userId: bob.id, device: bob.device, conversation: group, chains, title: "Bob's club" });
  assert.equal((await bob.call("conversations", rename)).body.code, "NOT_ADMIN");

  // Alice makes Bob an admin. He adds Dave and removes Carol.
  const promoted = (await conversationCall(alice, "set_admin", { conversation_id: group.id, user_id: bob.id, admin: true })).body.conversation;
  assert.deepEqual(promoted.admin_ids, [alice.id, bob.id]);
  assert.equal((await conversationCall(bob, "add_members", { conversation_id: group.id, usernames: ["dave"] })).status, 200);
  const removed = (await conversationCall(bob, "remove_member", { conversation_id: group.id, user_id: carol.id })).body.conversation;
  assert.deepEqual(removed.member_ids, [alice.id, bob.id, dave.id]);
  assert.equal((await carol.call("conversations", { action: "get", conversation_id: group.id })).status, 404, "Carol no longer sees it");
  assert.equal((await carol.call("messages", { action: "list", conversation_id: group.id })).status, 404);
  assert.equal((await conversationCall(bob, "remove_member", { conversation_id: group.id, user_id: carol.id })).body.code, "NOT_MEMBER");
  assert.equal((await conversationCall(bob, "remove_member", { conversation_id: group.id, user_id: bob.id })).body.code, "BAD_FIELD", "leaving is separate");
  assert.equal((await conversationCall(bob, "set_admin", { conversation_id: group.id, user_id: carol.id, admin: true })).body.code, "NOT_MEMBER");
  assert.equal((await conversationCall(bob, "set_admin", { conversation_id: group.id, user_id: dave.id, admin: "yes" })).body.code, "BAD_FIELD");
  assert.equal((await conversationCall(bob, "set_expiry", { conversation_id: group.id, seconds: 604_800 })).status, 200);

  // Admins can step down while another remains; the last one can't.
  assert.equal((await conversationCall(alice, "set_admin", { conversation_id: group.id, user_id: alice.id, admin: false })).status, 200);
  assert.equal((await conversationCall(bob, "set_admin", { conversation_id: group.id, user_id: bob.id, admin: false })).body.code, "LAST_ADMIN");
  // If the last admin leaves, the longest-standing member takes over.
  assert.equal((await conversationCall(bob, "leave", { conversation_id: group.id })).status, 200);
  const after = (await alice.ok("conversations", { action: "get", conversation_id: group.id })).conversation;
  assert.deepEqual(after.member_ids, [alice.id, dave.id]);
  assert.deepEqual(after.admin_ids, [alice.id]);
  assert.equal(after.expire_seconds, 604_800, "the timer stays as it was set");

  const dm = await alice.dm(bob);
  assert.deepEqual(dm.admin_ids, [], "direct messages have no admins");
  assert.equal((await conversationCall(alice, "set_admin", { conversation_id: dm.id, user_id: bob.id, admin: true })).body.code, "NOT_GROUP");
  assert.equal((await conversationCall(alice, "remove_member", { conversation_id: dm.id, user_id: bob.id })).body.code, "NOT_GROUP");
});

test("a group whose admins are all gone is run by its creator, or else its longest-standing member", async () => {
  const { w, members: [alice, bob, carol] } = await world("alice", "bob", "carol");
  const group = await alice.group(["bob", "carol"]);
  const row = w.rows("Conversation").find((c) => c.id === group.id);
  delete row.admin_ids; // as a group from before admins existed would be
  assert.deepEqual((await bob.ok("conversations", { action: "get", conversation_id: group.id })).conversation.admin_ids, [alice.id]);
  assert.equal((await conversationCall(bob, "set_expiry", { conversation_id: group.id, seconds: 86_400 })).body.code, "NOT_ADMIN");
  row.creator_id = "";
  row.member_ids = [bob.id, carol.id];
  assert.deepEqual((await bob.ok("conversations", { action: "get", conversation_id: group.id })).conversation.admin_ids, [bob.id]);
  assert.equal((await conversationCall(bob, "set_expiry", { conversation_id: group.id, seconds: 86_400 })).status, 200);
});

test("security emails: a new device, a used recovery phrase and a finished reset are emailed, saying nothing about the device", async () => {
  const { w, members: [alice] } = await world("alice");
  await alice.linkDevice("Kitchen tablet 7731");
  assert.equal(w.emails.length, 1);
  assert.equal(w.emails[0].to, alice.user.email, "only ever the account's own sign-in address");
  assert.equal(w.emails[0].subject, "Commonveil: a new device was added to your account");

  const fresh = await createDeviceKeys("Borrowed laptop 4410");
  const recovered = await recoverWithPhrase({ userId: alice.id, device: fresh, phrase: alice.phrase, recoveryResponse: await alice.ok("keys", { action: "get_recovery" }) });
  assert.equal((await alice.ok("keys", recovered.request)).emailed, true);
  assert.equal(w.emails[1].subject, "Commonveil: your recovery phrase was used");
  for (const e of w.emails) {
    for (const secret of ["Kitchen tablet", "7731", "Borrowed laptop", "4410", alice.name, alice.id]) {
      assert.ok(!e.body.includes(secret) && !e.subject.includes(secret), `an email mentions ${secret}`);
    }
  }

  // If email is down, the change still happens.
  w.emailDown = true;
  await alice.linkDevice("Phone");
  assert.equal(w.emails.length, 2);
  assert.equal((await alice.status()).devices.filter((d) => d.status === "active").length, 4);
});

test("auto-delete is off unless chosen, needs a device, and keeps only the day the account was last used", async () => {
  const { w, members: [alice] } = await world("alice");
  const profile = () => w.rows("Profile").find((p) => p.user_id === alice.id);
  const writes = w.writes;
  assert.deepEqual((await alice.ok("profile", { action: "me" })).auto_delete, { days: 0, last_active_on: null, warned: false });
  assert.equal(w.writes, writes, "nothing about use is noted by default");
  assert.equal(profile().last_active_at, undefined);

  assert.equal((await alice.call("profile", { action: "set_auto_delete", days: 183 })).body.code, "PROOF_REQUIRED");
  for (const days of [30, "183", -1, 183.5, null]) {
    assert.equal((await alice.call("profile", await signed(alice, "set_auto_delete", { days }))).body.code, "BAD_FIELD", String(days));
  }
  const today = dayString(Date.now());
  const on = await alice.ok("profile", await signed(alice, "set_auto_delete", { days: 183 }));
  assert.deepEqual(on.auto_delete, { days: 183, last_active_on: today, warned: false });

  // Using the app notes the day, at most once a day.
  profile().last_active_at = "2026-01-01";
  await alice.ok("profile", { action: "me" });
  assert.equal(profile().last_active_at, today);
  const after = w.writes;
  await alice.ok("profile", { action: "me" });
  assert.equal(w.writes, after, "once a day");

  // Off again: the day is cleared.
  const off = await alice.ok("profile", await signed(alice, "set_auto_delete", { days: 0 }));
  assert.deepEqual(off.auto_delete, { days: 0, last_active_on: null, warned: false });
  assert.equal(profile().last_active_at, "");
  // Another member can't see any of it.
  const bob = await new Member(w, "bob").setup();
  await alice.dm(bob);
  const seen = await bob.ok("profile", { action: "get_many", user_ids: [alice.id] });
  assert.deepEqual(Object.keys(seen.profiles[0]).sort(), ["accent_color", "avatar_emoji", "bio", "display_name", "pronouns", "user_id", "username"]);

  const staff = new Member(w, "staffer", "admin");
  assert.equal((await staff.call("profile", { action: "set_auto_delete", days: 183 })).body.code, "STAFF_ACCOUNT");
});

test("auto-delete: a week's warning by email, signing in keeps the account, otherwise it's deleted with everything in it", async () => {
  const { w, members: [alice, bob] } = await world("alice", "bob");
  for (const m of [alice, bob]) w.rows("User").push({ ...m.user });
  const dm = await alice.dm(bob);
  await alice.send(dm, "hi bob");
  await alice.ok("profile", await signed(alice, "set_auto_delete", { days: 183 }));
  const profile = () => w.rows("Profile").find((p) => p.user_id === alice.id);
  const quiet = { task: "inactive", warned: 0, deleted: 0, skipped: 0, done: true };
  const now = Date.now();

  assert.deepEqual(await maintenance(w, "inactive"), quiet, "used today: nothing to do");
  // Unused for 177 days: a week's notice by email, nothing deleted.
  profile().last_active_at = dayString(now - 177 * DAY_MS);
  assert.deepEqual(await maintenance(w, "inactive", new Date(now)), { ...quiet, warned: 1 });
  assert.equal(w.emails.length, 1);
  assert.equal(w.emails[0].to, alice.user.email);
  assert.equal(w.emails[0].subject, "Commonveil: your account will be deleted soon");
  assert.ok(!w.emails[0].body.includes(alice.name) && !w.emails[0].body.includes("bob"));
  assert.deepEqual(await maintenance(w, "inactive", new Date(now + 3 * DAY_MS)), quiet, "warned once");
  assert.equal((await alice.ok("profile", { action: "me" })).auto_delete.warned, false, "signing in withdraws the warning");
  assert.equal(profile().inactive_warned_at, "");
  assert.deepEqual(await maintenance(w, "inactive", new Date(now + 8 * DAY_MS)), quiet, "and keeps the account");

  // Long unused this time: still a full week between the warning and the deletion.
  profile().last_active_at = dayString(now - 400 * DAY_MS);
  assert.deepEqual(await maintenance(w, "inactive", new Date(now)), { ...quiet, warned: 1 });
  assert.deepEqual(await maintenance(w, "inactive", new Date(now + 6 * DAY_MS)), quiet);
  assert.deepEqual(await maintenance(w, "inactive", new Date(now + 7 * DAY_MS + 60_000)), { ...quiet, deleted: 1 });
  assert.deepEqual(mentions(w, alice.id), []);
  assert.equal(w.rows("User").some((u) => u.id === alice.id), false, "the sign-in goes too");
  assert.deepEqual((await bob.ok("conversations", { action: "list" })).conversations, []);
  assert.equal(w.rows("Profile").length, 1);
});

test("auto-delete leaves staff alone, and if the warning can't be sent the setting still stands a week after the date", async () => {
  const { w, members: [alice] } = await world("alice");
  const staff = await new Member(w, "staffer", "admin").setup();
  for (const m of [alice, staff]) w.rows("User").push({ ...m.user });
  await alice.ok("profile", await signed(alice, "set_auto_delete", { days: 365 }));
  const now = Date.now();
  const staffProfile = w.rows("Profile").find((p) => p.user_id === staff.id);
  Object.assign(staffProfile, { delete_after_days: 183, last_active_at: dayString(now - 900 * DAY_MS) });
  const quiet = { task: "inactive", warned: 0, deleted: 0, skipped: 1, done: true };

  w.emailDown = true;
  w.rows("Profile").find((p) => p.user_id === alice.id).last_active_at = dayString(now - 360 * DAY_MS);
  assert.deepEqual(await maintenance(w, "inactive", new Date(now)), quiet, "no warning went out, so nothing happens yet");
  assert.deepEqual(await maintenance(w, "inactive", new Date(now + 11 * DAY_MS)), quiet, "tried again each run");
  assert.deepEqual(await maintenance(w, "inactive", new Date(now + 13 * DAY_MS)), { ...quiet, deleted: 1 });
  assert.equal(w.rows("Profile").filter((p) => p.user_id === alice.id).length, 0);
  assert.equal(w.rows("Profile").filter((p) => p.user_id === staff.id).length, 1, "staff accounts are never deleted this way");
});

test("members can get a copy of the reports they made, and only those", async () => {
  const { members: [alice, bob, carol] } = await world("alice", "bob", "carol");
  const dm = await alice.dm(bob);
  await alice.ok("safety", { action: "report", user_id: bob.id, reason: "spam", details: "Kept sending links", conversation_id: dm.id });
  await carol.ok("safety", { action: "report", user_id: alice.id, reason: "other", details: "Carol's words about Alice" });
  const mine = await alice.ok("safety", { action: "my_reports" });
  assert.deepEqual(mine.reports.map((r) => [r.reported_user_id, r.conversation_id, r.reason, r.details, r.status]), [[bob.id, dm.id, "spam", "Kept sending links", "open"]]);
  assert.deepEqual((await bob.ok("safety", { action: "my_reports" })).reports, [], "nobody sees reports about them");
});

test("replies, reactions and edits travel as ordinary encrypted messages: the server can't tell them apart", async () => {
  const { w, members: [alice, bob] } = await world("alice", "bob");
  const dm = await alice.dm(bob);
  const first = (await alice.send(dm, "Lunch on Friday?")).body.message;
  const timed = (await conversationCall(bob, "set_expiry", { conversation_id: dm.id, seconds: 604_800 })).body.conversation;
  const { chains } = await bob.chainsFor(timed);
  const reply = await buildMessage({ userId: bob.id, device: bob.device, conversation: timed, chains, text: "Yes please", replyTo: first.msg_id, keyring: bob.keyring });
  const reaction = await buildReaction({ userId: bob.id, device: bob.device, conversation: timed, chains, target: first.msg_id, emoji: REACTIONS[1], keyring: bob.keyring });
  for (const body of [reply, reaction]) assert.equal((await bob.call("messages", body)).status, 200);
  const edit = await buildEdit({ userId: alice.id, device: alice.device, conversation: timed, chains: (await alice.chainsFor(timed)).chains, target: first.msg_id, text: "Lunch on Saturday?", keyring: alice.keyring });
  assert.equal((await alice.call("messages", edit)).status, 200);
  await assert.rejects(buildReaction({ userId: bob.id, device: bob.device, conversation: timed, chains, target: first.msg_id, emoji: "free text" }), /offered reactions/);

  const stored = w.rows("Message");
  assert.equal(stored.length, 4);
  for (const r of stored) {
    const row = JSON.stringify(r);
    for (const secret of ["Lunch", "Yes please", "Saturday", "reaction", "edit", "reply", REACTIONS[1]]) assert.ok(!row.includes(secret), `${secret} is visible to the server`);
    if (r.id !== first.id) assert.ok(!row.includes(first.msg_id), "what a message points at is encrypted too");
  }

  const read = await alice.read(timed);
  assert.deepEqual(read.map((r) => [r.status, r.content.type]), [["ok", "text"], ["ok", "text"], ["ok", "reaction"], ["ok", "edit"]]);
  assert.equal(read[0].content.expire_seconds, undefined, "sent before the timer");
  assert.deepEqual(read[1].content, { type: "text", text: "Yes please", reply_to: first.msg_id, expire_seconds: 604_800 }, "the sender's timer is signed inside");
  assert.deepEqual(read[2].content, { type: "reaction", target: first.msg_id, emoji: REACTIONS[1], remove: false, expire_seconds: 604_800 });
  assert.deepEqual(read[3].content, { type: "edit", target: first.msg_id, text: "Lunch on Saturday?", expire_seconds: 604_800 });
});
