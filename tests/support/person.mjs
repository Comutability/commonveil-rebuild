// A person on a real self-hosted site (tests/support/selfhost.mjs), using the app's own
// encryption code: register, set up keys, send and read.
import assert from "node:assert/strict";
import { http } from "./selfhost.mjs";
import { createDeviceKeys } from "../../src/lib/crypto/device.js";
import { verifyAccountChain } from "../../src/lib/crypto/identity.js";
import { buildMessage, openItem, prepareNewAccount, signedRequest } from "../../src/lib/secure/protocol.js";

export class Person {
  constructor(site, name) {
    this.site = site;
    this.name = name;
  }
  async call(fn, body) {
    return http(this.site, `/api/functions/${fn}`, { method: "POST", body, token: this.token });
  }
  async ok(fn, body) {
    const r = await this.call(fn, body);
    assert.equal(r.status, 200, `${fn}.${body.action} on ${this.site.config.host}: ${JSON.stringify(r.data)}`);
    return r.data;
  }
  signed(action, payload) {
    return signedRequest({ userId: this.id, device: this.device, action, payload });
  }
  async setup() {
    const r = await http(this.site, "/api/auth/register", { method: "POST", body: { username: this.name, password: "correct horse battery staple" } });
    assert.equal(r.status, 200, JSON.stringify(r.data));
    this.token = r.data.access_token;
    this.id = r.data.user.id;
    this.device = await createDeviceKeys(`${this.name} laptop`);
    const prepared = await prepareNewAccount({ userId: this.id, device: this.device });
    await this.ok("keys", prepared.request);
    this.keyring = prepared.keyring;
    return this;
  }
  /** Verified keys for these people. Like the app, it keeps what it has already checked. */
  async chains(ids) {
    this.known ||= new Map();
    const others = ids.filter((i) => i !== this.id);
    const r = await this.call("keys", { action: "peer_keys", user_ids: others });
    for (const [uid, k] of Object.entries(r.status === 200 ? r.data.keys : {})) this.known.set(uid, { chain: await verifyAccountChain(uid, k.statements), devices: k.devices });
    const mine = await this.call("keys", { action: "status" });
    if (mine.status === 200) this.known.set(this.id, { chain: await verifyAccountChain(this.id, mine.data.statements), devices: mine.data.devices });
    return new Map(ids.filter((i) => this.known.has(i)).map((i) => [i, this.known.get(i)]));
  }
  async keysFor(ids) {
    const c = await this.chains(ids.length ? ids : [this.id]);
    return { chains: new Map([...c].map(([k, v]) => [k, v.chain])), devices: new Map([...c].map(([k, v]) => [k, v.devices])) };
  }
  /** The sealed, signed request for a message, without sending it (as the app's outbox keeps it). */
  async build(conversation, text) {
    const c = await this.chains(conversation.member_ids);
    const chains = new Map([...c].map(([k, v]) => [k, v.chain]));
    return buildMessage({ userId: this.id, device: this.device, conversation, chains, text, keyring: this.keyring });
  }
  async send(conversation, text) {
    return this.ok("messages", await this.build(conversation, text));
  }
  async read(messages, memberIds) {
    const c = await this.chains(memberIds);
    const out = [];
    for (const m of messages) {
      const s = c.get(m.sender_id);
      out.push(await openItem({ kind: "message", item: m, userId: this.id, keyring: this.keyring, senderChain: s?.chain, senderDevices: s?.devices }));
    }
    return out;
  }
}
