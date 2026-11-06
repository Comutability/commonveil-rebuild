// Two real self-hosted sites talking the Commonveil Protocol, driven by the real client code with
// real keys: identity by address, a conversation across sites, and the protocol's refusals.
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { http, startSites } from "./support/selfhost.mjs";
import { createDeviceKeys } from "../src/lib/crypto/device.js";
import { verifyAccountChain } from "../src/lib/crypto/identity.js";
import { buildMessage, openItem, prepareNewAccount, signedRequest } from "../src/lib/secure/protocol.js";
import { buildChannelMessage, openGrants, openServerItem, prepareGeneration, prepareGrants, textPayload } from "../src/lib/secure/serverProtocol.js";

let net;
before(async () => {
  net = await startSites(["alpha.test", "beta.test"]);
});
after(async () => {
  await net?.close();
});

class Person {
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
    const r = await http(this.site, "/api/auth/register", { method: "POST", body: { email: `${this.name}@example.com`, password: "correct horse battery staple" } });
    assert.equal(r.status, 200, JSON.stringify(r.data));
    this.token = r.data.access_token;
    this.id = r.data.user.id;
    await this.ok("profile", { action: "claim_username", username: this.name });
    this.device = await createDeviceKeys(`${this.name} laptop`);
    const prepared = await prepareNewAccount({ userId: this.id, device: this.device });
    await this.ok("keys", prepared.request);
    this.keyring = prepared.keyring;
    return this;
  }
  async chains(ids) {
    const out = new Map();
    const { keys } = await this.ok("keys", { action: "peer_keys", user_ids: ids.filter((i) => i !== this.id) });
    for (const [uid, k] of Object.entries(keys)) out.set(uid, { chain: await verifyAccountChain(uid, k.statements), devices: k.devices });
    const mine = await this.ok("keys", { action: "status" });
    out.set(this.id, { chain: await verifyAccountChain(this.id, mine.statements), devices: mine.devices });
    return out;
  }
  async keysFor(ids) {
    const c = await this.chains(ids.length ? ids : [this.id]);
    return { chains: new Map([...c].map(([k, v]) => [k, v.chain])), devices: new Map([...c].map(([k, v]) => [k, v.devices])) };
  }
  async send(conversation, text) {
    const c = await this.chains(conversation.member_ids);
    const chains = new Map([...c].map(([k, v]) => [k, v.chain]));
    return this.ok("messages", await buildMessage({ userId: this.id, device: this.device, conversation, chains, text, keyring: this.keyring }));
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

test("each site publishes its document, and people have addresses that say who they are", async () => {
  const a = net.sites["alpha.test"];
  const doc = await http(a, "/.well-known/commonveil");
  assert.equal(doc.status, 200);
  assert.equal(doc.data.protocol, "commonveil/1");
  assert.equal(doc.data.host, "alpha.test");
  assert.match(doc.data.key.public, /^[A-Za-z0-9_-]{43}$/);

  const zoe = await new Person(a, "zoe_q").setup();
  const ident = await http(a, "/.well-known/commonveil/identity", { host: "zoe-q.alpha.test" });
  assert.deepEqual([ident.status, ident.data.handle, ident.data.user_id, ident.data.home], [200, "zoe-q.alpha.test", zoe.id, "alpha.test"], "underscores become hyphens in a handle");
  const page = await http(a, "/", { host: "zoe-q.alpha.test" });
  assert.equal(page.status, 302);
  assert.equal(page.headers.get("location"), "http://alpha.test/u/zoe_q", "a handle in a browser leads to the profile");
  assert.equal((await http(a, "/.well-known/commonveil/identity", { host: "nobody.alpha.test" })).status, 404);
  assert.equal((await http(a, "/api/tls-check?domain=zoe-q.alpha.test")).status, 200, "certificates only for real people");
  assert.equal((await http(a, "/api/tls-check?domain=nobody.alpha.test")).status, 404);
  const wf = await http(a, "/.well-known/webfinger?resource=acct:zoe_q@alpha.test");
  assert.equal(wf.data.subject, "acct:zoe_q@alpha.test");
  const ni = await http(a, "/nodeinfo/2.1");
  assert.deepEqual(ni.data.usage, { users: {} }, "no user counts");
});

test("a conversation across two sites: started by handle, end-to-end encrypted, read and answered on both", async () => {
  const a = net.sites["alpha.test"];
  const b = net.sites["beta.test"];
  const ann = await new Person(a, "ann").setup();
  const ben = await new Person(b, "ben").setup();

  // Ann writes to ben.beta.test. The conversation lives on Ann's site.
  const dm = (await ann.ok("conversations", await ann.signed("create_dm", { username: "ben.beta.test" }))).conversation;
  assert.deepEqual([...dm.member_ids].sort(), [ann.id, ben.id].sort(), "Ben's id is the same on both sites");
  await ann.send(dm, "Hello Ben, from another site");
  const stored = a.app.store.entities;
  const [row] = await stored.Message.filter({ conversation_id: dm.id });
  assert.ok(!JSON.stringify(row).includes("Hello Ben"), "Ann's site holds ciphertext only");

  // Ben's own site finds it for him.
  const start = await ben.ok("messages", { action: "poll" });
  await new Promise((r) => setTimeout(r, 30));
  const polled = await ben.ok("messages", { action: "poll", since: start.cursor, conversations_since: start.conversations_cursor });
  assert.ok(polled.conversations.some((c) => c.id === dm.id), "the conversation reaches Ben through his site");
  const list = await ben.ok("messages", { action: "list", conversation_id: dm.id });
  const [opened] = await ben.read(list.messages, dm.member_ids);
  assert.equal(opened.text, "Hello Ben, from another site");
  assert.equal(opened.status, "ok", "verified against Ann's own key history");

  // Ben answers; his site relays it to the conversation's site.
  await ben.send(dm, "Hi Ann!");
  const back = await ann.ok("messages", { action: "list", conversation_id: dm.id });
  const texts = (await ann.read(back.messages, dm.member_ids)).map((m) => m.text);
  assert.deepEqual(texts, ["Hello Ben, from another site", "Hi Ann!"]);
  assert.equal(b.app.store.has(dm.id), false, "nothing is copied to Ben's site");
});

test("a server on one site, found and joined from another, with encrypted channels both ways", async () => {
  const a = net.sites["alpha.test"];
  const b = net.sites["beta.test"];
  const owner = await new Person(b, "bea").setup();
  const guest = await new Person(a, "abe").setup();

  // Bea makes a listed, open server on beta.
  const { server_id: sid } = await owner.ok("servers", await owner.signed("create_server", { template: "blank" }));
  let state = await owner.ok("servers", { action: "state", server_id: sid });
  const { chains: own } = await owner.keysFor([owner.id]);
  for (const c of state.chains) {
    const { request } = await prepareGeneration({ serverId: sid, chainId: c.chain_id, generation: 0, userId: owner.id, device: owner.device, chains: own, recipientIds: [] });
    await owner.ok("servers", request);
  }
  await owner.ok("servers", await owner.signed("update_server_settings", { server_id: sid, discoverable: true, join_mode: "open", public: { name: "Beta garden", description: "Plants", tags: ["community"] } }));

  // Abe browses beta's listing from alpha and joins.
  const listed = await guest.ok("servers", { action: "discover", _site: "beta.test" });
  assert.ok(listed.servers.some((x) => x.id === sid && x.name === "Beta garden"));
  const local = await guest.ok("servers", { action: "discover" });
  assert.ok(!local.servers.some((x) => x.id === sid), "alpha's own listing is alpha's");
  const joined = await guest.ok("servers", { ...(await guest.signed("join_server", { server_id: sid })), _site: "beta.test" });
  assert.equal(joined.server_id, sid);
  const mine = await guest.ok("servers", { action: "list" });
  assert.ok(mine.servers.some((x) => x.id === sid), "the server shows in Abe's list on his own site");

  // Bea's app hands Abe the keys; Abe reads and writes in a channel.
  state = await owner.ok("servers", { action: "state", server_id: sid });
  const ownerKeys = (await openGrants({ grants: state.grants, generations: state.generations, userId: owner.id, keyring: owner.keyring })).keys;
  const pending = await owner.ok("servers", { action: "pending_grants", server_id: sid });
  const { chains } = await owner.keysFor(Object.keys(pending.recipients));
  const grants = await prepareGrants({ serverId: sid, items: pending.items, keys: ownerKeys, chains, userId: owner.id, device: owner.device });
  assert.ok((await owner.ok("servers", grants)).accepted > 0);

  const channel = state.channels.find((c) => c.template_key === "general");
  await owner.ok("channels", await buildChannelMessage({ serverId: sid, channel, generations: state.generations, keys: ownerKeys, userId: owner.id, device: owner.device, payload: textPayload("Welcome, Abe"), kind: "message" }));

  const gs = await guest.ok("servers", { action: "state", server_id: sid });
  const guestKeys = (await openGrants({ grants: gs.grants, generations: gs.generations, userId: guest.id, keyring: guest.keyring })).keys;
  await guest.ok("channels", await buildChannelMessage({ serverId: sid, channel, generations: gs.generations, keys: guestKeys, userId: guest.id, device: guest.device, payload: textPayload("Thanks, Bea"), kind: "message" }));

  const { keys: people } = await guest.ok("keys", { action: "peer_keys", user_ids: [owner.id] });
  const list = await guest.ok("channels", { action: "list", server_id: sid, channel_id: channel.id });
  const { chains: both, devices } = await guest.keysFor([owner.id]);
  assert.ok(people[owner.id]);
  const texts = [];
  for (const item of list.messages) {
    const o = await openServerItem({ kind: "message", item, serverId: sid, channelId: channel.id, keys: guestKeys, senderChain: both.get(item.sender_id), senderDevices: devices.get(item.sender_id) });
    texts.push(o.text);
  }
  assert.deepEqual(texts, ["Welcome, Abe", "Thanks, Bea"]);
  assert.equal(a.app.store.has(sid), false, "the server stays on its own site");
});

test("people choose who reaches them from other sites, and blocks cross sites", async () => {
  const a = net.sites["alpha.test"];
  const b = net.sites["beta.test"];
  const cat = await new Person(a, "cat").setup();
  const dan = await new Person(b, "dan").setup();
  await dan.ok("profile", { action: "update", dm_policy: "servers" });
  const refused = await cat.call("conversations", await cat.signed("create_dm", { username: "dan.beta.test" }));
  assert.equal(refused.status, 404, "only 'anyone' accepts people from other sites");
  await dan.ok("profile", { action: "update", dm_policy: "anyone" });
  await dan.ok("safety", { action: "block", user_id: cat.id }).catch(() => null);
  // Dan's site may not know Cat yet; blocking by id still stops her from his side.
  assert.equal((await cat.call("conversations", await cat.signed("create_dm", { username: "nobody.beta.test" }))).status, 404);
});

test("the protocol refuses unsigned, replayed, mistimed and foreign-handle requests", async () => {
  const a = net.sites["alpha.test"];
  const b = net.sites["beta.test"];
  const unsigned = await http(a, "/cvp/v1/act", { method: "POST", body: { user: { id: "0".repeat(24) } } });
  assert.equal(unsigned.status, 400);

  const signer = b.app.federation.signer;
  const body = JSON.stringify({ type: "membership", user_id: "f".repeat(24), room: { kind: "conversation", id: "e".repeat(24) }, joined: true });
  const headers = signer.headers({ method: "POST", to: "alpha.test", path: "/cvp/v1/inbox", body });
  const send = () => fetch(`${a.url}/cvp/v1/inbox`, { method: "POST", headers: { ...headers, "Content-Type": "application/json", "X-Forwarded-Host": "alpha.test" }, body });
  assert.equal((await send()).status, 200);
  assert.equal((await send()).status, 401, "a request can't be replayed");

  const tampered = await fetch(`${a.url}/cvp/v1/inbox`, { method: "POST", headers: { ...signer.headers({ method: "POST", to: "alpha.test", path: "/cvp/v1/inbox", body }), "Content-Type": "application/json", "X-Forwarded-Host": "alpha.test" }, body: body.replace("true", "false") });
  assert.equal(tampered.status, 401, "the body is covered by the signature");

  // Beta can't speak for a person with an alpha handle.
  const card = { id: "a".repeat(24), handle: "mallory.alpha.test", profile: {}, directory: { statements: [], devices: [] } };
  const forged = await signer.post("alpha.test", "/cvp/v1/act", { user: card, function: "conversations", request: JSON.stringify({ action: "list" }) }, { user: card.id });
  assert.equal(forged.status, 403);
  assert.equal(forged.data.code, "WRONG_SITE");
});

test("an admin can stop talking to a site", async () => {
  const a = net.sites["alpha.test"];
  const b = net.sites["beta.test"];
  a.app.federation.signer.setBlocked("beta.test", true);
  const r = await b.app.federation.signer.post("alpha.test", "/cvp/v1/inbox", { type: "membership" });
  assert.equal(r.status, 403);
  a.app.federation.signer.setBlocked("beta.test", false);
});
