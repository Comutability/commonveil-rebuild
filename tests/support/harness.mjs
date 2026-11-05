// Shared test harness: members who call the real backend handlers with requests built by the
// real client code. Only the database is in memory (fakeBase44.mjs). tests/functions.test.mjs
// has its own copy of this from before it was shared.
import assert from "node:assert/strict";

import { FakeWorld } from "./fakeBase44.mjs";
import { runAction } from "../../base44/shared/http.ts";
import { profileActions } from "../../base44/shared/handlers/profile.ts";
import { keysActions } from "../../base44/shared/handlers/keys.ts";
import { conversationActions } from "../../base44/shared/handlers/conversations.ts";
import { messageActions } from "../../base44/shared/handlers/messages.ts";
import { safetyActions, adminActions } from "../../base44/shared/handlers/safety.ts";
import { disclosureActions } from "../../base44/shared/handlers/disclosure.ts";

import { createDeviceKeys } from "../../src/lib/crypto/device.js";
import { latestKey } from "../../src/lib/crypto/keyring.js";
import { verifyAccountChain } from "../../src/lib/crypto/identity.js";
import {
  acceptKeyringEnvelope,
  buildMessage,
  linkPinFor,
  openItem,
  prepareAck,
  prepareApproval,
  prepareNewAccount,
  prepareRegisterDevice,
  prepareRotation,
  signedRequest,
} from "../../src/lib/secure/protocol.js";

/** Functions only signed-in members can call. Test files add theirs with addFunctions. */
export const FUNCTIONS = { profile: profileActions, keys: keysActions, conversations: conversationActions, messages: messageActions, safety: safetyActions, admin: adminActions };
export const PUBLIC_FUNCTIONS = { disclose: disclosureActions };

export function addFunctions(more, { anonymous = false } = {}) {
  Object.assign(anonymous ? PUBLIC_FUNCTIONS : FUNCTIONS, more);
}

/** A request signed by one of the member's devices (their current one by default). */
export const signed = (member, action, payload, device = member.device) => signedRequest({ userId: member.id, device, action, payload });

export class Member {
  constructor(world, name, { role = "user", email } = {}) {
    this.world = world;
    this.name = name;
    this.user = { id: world.newId(), role, email: email || `${name}@example.test`, full_name: name };
    this.id = this.user.id;
    world.addUser(this.user);
  }

  async call(fn, body, { anonymous = false } = {}) {
    const isPublic = Object.hasOwn(PUBLIC_FUNCTIONS, fn);
    const actions = isPublic ? PUBLIC_FUNCTIONS[fn] : FUNCTIONS[fn];
    if (!actions) throw new Error(`No test function ${fn}`);
    const res = await runAction(this.world.clientFor(anonymous ? null : this.user), JSON.stringify(body), actions, { allowAnonymous: isPublic });
    return { status: res.status, body: await res.json() };
  }

  async ok(fn, body) {
    const res = await this.call(fn, body);
    assert.equal(res.status, 200, `${fn}.${body.action} failed: ${JSON.stringify(res.body)}`);
    return res.body;
  }

  async fails(fn, body, code) {
    const res = await this.call(fn, body);
    assert.notEqual(res.status, 200, `${fn}.${body.action} should have failed`);
    if (code) assert.equal(res.body.code, code, `${fn}.${body.action}: ${JSON.stringify(res.body)}`);
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

  /** Verified chains and device lists for everyone in memberIds (the people need to be known to this member). */
  async keysFor(memberIds) {
    const chains = new Map([[this.id, await this.myChain()]]);
    const devices = new Map([[this.id, (await this.status()).devices]]);
    const others = [...new Set(memberIds)].filter((m) => m !== this.id);
    if (others.length) {
      const { keys } = await this.ok("keys", { action: "peer_keys", user_ids: others });
      for (const uid of others) {
        if (!keys[uid]) continue;
        chains.set(uid, await verifyAccountChain(uid, keys[uid].statements));
        devices.set(uid, keys[uid].devices);
      }
    }
    return { chains, devices };
  }

  async chainsFor(conversation) {
    return this.keysFor(conversation.member_ids);
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
  async linkDevice(label = "Phone", device = null) {
    const d = device || (await createDeviceKeys(label));
    const pin = linkPinFor(await this.myChain());
    await this.ok("keys", await prepareRegisterDevice({ userId: this.id, device: d }));
    const pending = (await this.status()).devices.find((x) => x.device_id === d.device_id);
    await this.ok("keys", await prepareApproval({ userId: this.id, device: this.device, keyring: this.keyring, target: pending }));
    const sync = await this.ok("keys", { action: "device_sync", device_id: d.device_id });
    const { keyring } = await acceptKeyringEnvelope({ userId: this.id, device: d, envelope: sync.envelope, statements: (await this.status()).statements, pin });
    await this.ok("keys", await prepareAck({ userId: this.id, device: d, keyringVersion: latestKey(keyring).version }));
    return { device: d, keyring, sealed: sync.envelope.sealed };
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
    if (rotation.phrase) this.phrase = rotation.phrase;
    return rotation;
  }

  as(device, keyring) {
    return Object.assign(Object.create(Object.getPrototypeOf(this)), this, { device, keyring });
  }
}

export async function world(...names) {
  const w = new FakeWorld();
  const members = [];
  for (const n of names) members.push(await new Member(w, n).setup());
  return { w, members };
}

export { FakeWorld };
