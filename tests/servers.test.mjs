// Servers: encryption (key chains, grants, items), and the backend's membership, permissions,
// moderation, invites, discovery, tickets and the community server, driven by the real client
// code with real keys. Only the database is in memory.
import test from "node:test";
import assert from "node:assert/strict";

import { FakeWorld, Member, addFunctions, signed, world } from "./support/harness.mjs";
import { inviteActions, serverActions } from "../base44/shared/handlers/servers.ts";
import { serverMessageActions } from "../base44/shared/handlers/serverMessages.ts";
import { voiceActions } from "../base44/shared/handlers/voice.ts";
import * as serverPerms from "../base44/shared/permissions.ts";
import * as clientPerms from "../src/lib/secure/permissions.js";
import { fromB64, randomId, toB64 } from "../src/lib/crypto/encoding.js";
import { kemKeygen } from "../src/lib/crypto/kem.js";
import {
  ChainKeys,
  STEP_MS,
  decryptServerItem,
  encryptServerItem,
  generationCommit,
  makeGrant,
  newInviteSecret,
  openGrant,
  openInvitePreview,
  ratchetTo,
  sealInvitePreview,
  stepAt,
} from "../src/lib/crypto/serverKeys.js";
import {
  buildChannelMessage,
  buildServerItem,
  chainForChannel,
  channelChain,
  historyChain,
  liveChain,
  openGrants,
  openServerItem,
  postPayload,
  prepareGeneration,
  prepareGrants,
  reactionPayload,
  textPayload,
} from "../src/lib/secure/serverProtocol.js";
import { REACTIONS } from "../src/lib/secure/protocol.js";

let ADMINS = [];
addFunctions({ servers: serverActions({ defaultAdmins: () => ADMINS }), channels: serverMessageActions });
addFunctions({ invite: inviteActions }, { anonymous: true });
addFunctions({ voice: voiceActions });

const P = clientPerms.P;

// ---------- server helpers on a member ----------

Object.assign(Member.prototype, {
  async server(serverId) {
    return this.ok("servers", { action: "state", server_id: serverId });
  },
  async keysOf(state) {
    const { keys, unreadable, bad } = await openGrants({ grants: state.grants, generations: state.generations, userId: this.id, keyring: this.keyring });
    this.serverKeys = keys;
    return { keys, unreadable, bad };
  },
  /** The first generation of every chain the member can read that has none yet. */
  async initKeys(serverId) {
    const state = await this.server(serverId);
    const { chains } = await this.keysFor([this.id]);
    for (const c of state.chains) {
      if (state.generations.some((g) => g.chain_id === c.chain_id)) continue;
      const { request } = await prepareGeneration({ serverId, chainId: c.chain_id, generation: 0, userId: this.id, device: this.device, chains, recipientIds: [] });
      await this.ok("servers", request);
    }
    return this.server(serverId);
  },
  /** Hand keys to whoever's waiting, as members' apps do in the background. Returns how many were sent. */
  async fulfil(serverId) {
    const state = await this.server(serverId);
    const { keys } = await this.keysOf(state);
    const pending = await this.ok("servers", { action: "pending_grants", server_id: serverId });
    if (!pending.items.length) return 0;
    const { chains } = await this.keysFor(Object.keys(pending.recipients));
    const request = await prepareGrants({ serverId, items: pending.items, keys, chains, userId: this.id, device: this.device });
    if (!request) return 0;
    return (await this.ok("servers", request)).accepted;
  },
  async create(template = "blank") {
    const { server_id } = await this.ok("servers", await signed(this, "create_server", { template }));
    await this.initKeys(server_id);
    return server_id;
  },
  async channelNamed(serverId, key) {
    const state = await this.server(serverId);
    return state.channels.find((c) => c.template_key === key);
  },
  async post(serverId, channel, payload, kind = "message", threadId = "") {
    const state = await this.server(serverId);
    const { keys } = await this.keysOf(state);
    const body = await buildChannelMessage({ serverId, channel, generations: state.generations, keys, userId: this.id, device: this.device, payload, kind, threadId });
    return this.call("channels", body);
  },
  async say(serverId, channel, text) {
    return this.post(serverId, channel, textPayload(text));
  },
  /** Read a channel: [{ status, text, sender }] for every message listed. */
  async readChannel(serverId, channel, extra = {}) {
    const state = await this.server(serverId);
    const { keys } = await this.keysOf(state);
    const { messages } = await this.ok("channels", { action: "list", server_id: serverId, channel_id: channel.id, ...extra });
    const { chains, devices } = await this.keysFor(messages.map((m) => m.sender_id));
    const out = [];
    for (const m of messages) {
      const r = await openServerItem({ kind: "message", item: m, serverId, channelId: channel.id, keys, senderChain: chains.get(m.sender_id), senderDevices: devices.get(m.sender_id) });
      out.push({ status: r.status, text: r.text, sender: m.sender_id, content: r.content, msg_id: m.msg_id });
    }
    return out;
  },
  async invite(serverId, opts = {}) {
    const code = randomId(9).replace(/[^A-Za-z0-9]/g, "x").slice(0, 10);
    const secret = newInviteSecret();
    const preview = await sealInvitePreview({ code, secret, preview: { name: opts.name || "A server", description: "hi" } });
    await this.ok("servers", await signed(this, "create_invite", { server_id: serverId, code, preview, max_uses: opts.max_uses ?? 0, max_age_seconds: opts.max_age_seconds ?? 604_800 }));
    return { code, secret };
  },
  async join(code) {
    return this.ok("servers", await signed(this, "join_server", { invite_code: code }));
  },
});

async function serverWith(owner, ...others) {
  const sid = await owner.create("blank");
  for (const m of others) {
    const { code } = await owner.invite(sid);
    await m.join(code);
  }
  await owner.fulfil(sid);
  return sid;
}

// ---------- crypto ----------

test("permissions: the app's copy agrees with the server's", () => {
  assert.deepEqual(clientPerms.P, serverPerms.P);
  assert.equal(clientPerms.ALL_PERMISSIONS, serverPerms.ALL_PERMISSIONS);
  assert.equal(clientPerms.DEFAULT_EVERYONE, serverPerms.DEFAULT_EVERYONE);
  const everyone = { id: "e", is_everyone: true, permissions: clientPerms.DEFAULT_EVERYONE, position: 0 };
  const mod = { id: "m", permissions: P.MANAGE_MESSAGES | P.KICK_MEMBERS, position: 5 };
  const admin = { id: "a", permissions: P.ADMINISTRATOR, position: 9 };
  const roles = [everyone, mod, admin];
  const server = { owner_id: "owner" };
  const channels = [
    { kind: "text", overwrites: [] },
    { kind: "announcement", overwrites: [{ role_id: "e", deny: P.SEND_MESSAGES }] },
    { kind: "text", overwrites: [{ role_id: "e", deny: P.VIEW_CHANNEL }, { role_id: "m", allow: P.VIEW_CHANNEL }] },
  ];
  const members = [{ user_id: "u", role_ids: [] }, { user_id: "v", role_ids: ["m"] }, { user_id: "w", role_ids: ["a"] }, { user_id: "owner", role_ids: [] }];
  for (const m of members) {
    assert.equal(clientPerms.basePermissions(server, roles, m), serverPerms.basePermissions(server, roles, m));
    for (const c of channels) assert.equal(clientPerms.channelPermissions(server, roles, m, c), serverPerms.channelPermissions(server, roles, m, c));
  }
  assert.equal(clientPerms.channelPermissions(server, roles, members[0], channels[1]) & P.SEND_MESSAGES, 0, "announcements: members can't post");
  assert.ok(clientPerms.channelPermissions(server, roles, members[0], channels[1]) & P.ADD_REACTIONS, "...but can react");
  assert.equal(clientPerms.channelPermissions(server, roles, members[0], channels[2]), 0, "a private channel is invisible without the role");
  assert.ok(clientPerms.channelPermissions(server, roles, members[1], channels[2]) & P.VIEW_CHANNEL);
  assert.ok(clientPerms.channelIsPrivate(roles, channels[2]) && !clientPerms.channelIsPrivate(roles, channels[1]));
});

test("key chains: the live chain moves on hourly, forward only, and a generation's key is committed to", () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const k5 = ratchetTo(key, "s1.l", 0, 0, 5);
  assert.deepEqual(ratchetTo(ratchetTo(key, "s1.l", 0, 0, 2), "s1.l", 0, 2, 5), k5, "stepping in parts gives the same key");
  assert.notDeepEqual(ratchetTo(key, "s1.l", 1, 0, 5), k5, "bound to the generation");
  assert.throws(() => ratchetTo(k5, "s1.l", 0, 5, 4), /before/);
  const start = "2026-11-01T00:00:00.000Z";
  assert.equal(stepAt("s1.l", start, Date.parse(start) + 3 * STEP_MS + 5), 3);
  assert.equal(stepAt("s1.h", start, Date.parse(start) + 3 * STEP_MS), 0, "history chains don't move");
  const keys = new ChainKeys();
  keys.add("s1.l", 0, 2, ratchetTo(key, "s1.l", 0, 0, 2));
  assert.deepEqual(keys.get("s1.l", 0, 5), k5);
  assert.throws(() => keys.get("s1.l", 0, 1), (e) => e.code === "BEFORE_KEY");
  assert.throws(() => keys.get("s1.l", 1, 0), (e) => e.code === "NO_KEY");
  assert.equal(generationCommit("s1.h", 0, key), generationCommit("s1.h", 0, key));
  assert.notEqual(generationCommit("s1.h", 0, key), generationCommit("s1.h", 1, key));
});

test("server items are bound to their kind, server, channel, id, sender, device and key", async () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const keys = new ChainKeys();
  keys.add("srv.h", 0, 0, key);
  const scope = { kind: "message", server_id: "srv", channel_id: "chan", item_id: randomId(16), sender_id: "alice", device_id: randomId(16), chain_id: "srv.h", generation: 0, step: 0 };
  const env = await encryptServerItem({ scope, chainKey: key, payload: { type: "text", text: "hello" } });
  const base = { kind: scope.kind, server_id: "srv", channel_id: "chan", item_id: scope.item_id, sender_id: "alice", device_id: scope.device_id };
  assert.equal((await decryptServerItem({ base, envelope: env, keys })).payload.text, "hello");
  for (const change of [{ channel_id: "other" }, { item_id: randomId(16) }, { sender_id: "mallory" }, { kind: "channel" }, { server_id: "srv2" }]) {
    await assert.rejects(decryptServerItem({ base: { ...base, ...change }, envelope: env, keys }));
  }
  const wrong = new ChainKeys();
  wrong.add("srv.h", 0, 0, crypto.getRandomValues(new Uint8Array(32)));
  await assert.rejects(decryptServerItem({ base, envelope: env, keys: wrong }), (e) => e.code === "DECRYPT_FAILED");
  await assert.rejects(decryptServerItem({ base, envelope: { ...env, gen: 1 }, keys }), (e) => e.code === "NO_KEY");
});

test("grants open only for their recipient, post-quantum when the recipient has a post-quantum key", async () => {
  const { members: [alice, bob] } = await world("alice", "bobby");
  const { chains } = await alice.keysFor([alice.id]);
  const bobChain = (await bob.keysFor([bob.id])).chains.get(bob.id);
  const key = crypto.getRandomValues(new Uint8Array(32));
  const recipient = { user_id: bob.id, key_version: bobChain.latest.version, ecdh_pub: bobChain.latest.ecdh_pub, kem_pub: bobChain.latest.kem_pub };
  const grant = await makeGrant({ serverId: "srv", chainId: "srv.h", generation: 0, step: 0, keyBytes: key, recipient, userId: alice.id, device: alice.device });
  assert.ok(JSON.parse(grant.sealed).kct, "sealed post-quantum");
  assert.deepEqual(await openGrant({ grant, userId: bob.id, keyring: bob.keyring }), key);
  await assert.rejects(openGrant({ grant, userId: alice.id, keyring: alice.keyring }), (e) => e.code === "NOT_YOURS");
  await assert.rejects(openGrant({ grant: { ...grant, generation: 1 }, userId: bob.id, keyring: bob.keyring }), (e) => e.code === "GRANT_UNREADABLE");
  void chains;
});

test("invite previews open with the link's secret and nothing else", async () => {
  const secret = newInviteSecret();
  const sealed = await sealInvitePreview({ code: "abcdEFGH12", secret, preview: { name: "Book club" } });
  assert.equal((await openInvitePreview({ code: "abcdEFGH12", secret, sealed })).name, "Book club");
  assert.equal(await openInvitePreview({ code: "abcdEFGH12", secret: newInviteSecret(), sealed }), null);
  assert.equal(await openInvitePreview({ code: "otherCODE1", secret, sealed }), null);
});

// ---------- servers end to end ----------

test("a new server: its keys come from its creator's device, and its name is encrypted", async () => {
  const { w, members: [alice] } = await world("alice");
  const sid = await alice.create("friends");
  const state = await alice.server(sid);
  assert.equal(state.server.owner_id, alice.id);
  assert.deepEqual(state.chains.map((c) => c.chain_id).sort(), [historyChain(sid), liveChain(sid)].sort());
  assert.equal(state.generations.length, 2);
  assert.equal(state.grants.length, 2, "one copy of each chain's key, for alice");
  const { keys, bad } = await alice.keysOf(state);
  assert.equal(bad.length, 0);

  const item = await buildServerItem({ kind: "server", serverId: sid, generations: state.generations, keys, userId: alice.id, device: alice.device, payload: { name: "Alice's friends", description: "Plans" } });
  await alice.ok("servers", await signed(alice, "set_server_profile", { server_id: sid, item }));
  const after = await alice.server(sid);
  const row = w.rows("Server").find((s) => s.id === sid);
  assert.ok(!JSON.stringify(row).includes("Alice's friends"), "the database never sees the name");
  const { chains, devices } = await alice.keysFor([alice.id]);
  const opened = await openServerItem({ kind: "server", item: after.server.profile, serverId: sid, keys, senderChain: chains.get(alice.id), senderDevices: devices.get(alice.id) });
  assert.equal(opened.status, "ok");
  assert.equal(opened.content.name, "Alice's friends");
  assert.ok(state.channels.some((c) => c.template_key === "plans"));
});

test("joining by invite: newcomers wait for keys, members' apps hand them over, and everyone reads the same messages", async () => {
  const { w, members: [alice, bob] } = await world("alice", "bobby");
  const sid = await alice.create("blank");
  const { code, secret } = await alice.invite(sid, { name: "Alice's place" });
  const info = (await bob.call("invite", { action: "invite_info", code }, { anonymous: true })).body;
  assert.equal(info.server_id, sid);
  assert.equal((await openInvitePreview({ code, secret, sealed: info.preview })).name, "Alice's place");
  assert.equal(info.public, null, "an unlisted server shows nothing in the clear");

  await bob.join(code);
  const waiting = await bob.server(sid);
  assert.equal(waiting.member.key_status, "pending");
  assert.equal(waiting.grants.length, 0);
  const general = waiting.channels.find((c) => c.template_key === "general");
  await assert.rejects(bob.say(sid, general, "too early"), (e) => e.code === "NO_KEY", "no keys yet: the app can't encrypt anything");

  assert.ok((await alice.fulfil(sid)) >= 2, "alice's app seals both chains' keys to bob");
  const ready = await bob.server(sid);
  assert.equal(ready.member.key_status, "ok");
  const { bad } = await bob.keysOf(ready);
  assert.equal(bad.length, 0);

  assert.equal((await alice.say(sid, general, "welcome bob")).status, 200);
  assert.equal((await bob.say(sid, general, "thanks!")).status, 200);
  const seenByAlice = await alice.readChannel(sid, general);
  const seenByBob = await bob.readChannel(sid, general);
  assert.deepEqual(seenByAlice.map((r) => [r.status, r.text]), [["ok", "welcome bob"], ["ok", "thanks!"]]);
  assert.deepEqual(seenByBob.map((r) => [r.status, r.text]), [["ok", "welcome bob"], ["ok", "thanks!"]]);
  assert.ok(w.rows("ServerMessage").every((m) => !m.envelope.includes("welcome")), "ciphertext only");
});

test("channels set to 'from when they joined' don't show newcomers what came before; 'full history' ones do", async () => {
  const { members: [alice, bob, carol] } = await world("alice", "bobby", "carol");
  const sid = await serverWith(alice, bob);
  const general = await alice.channelNamed(sid, "general");
  assert.equal(general.history, "joined");
  // A channel with full history.
  const state = await alice.server(sid);
  const { keys } = await alice.keysOf(state);
  const name = await buildServerItem({ kind: "channel", serverId: sid, generations: state.generations, keys, userId: alice.id, device: alice.device, payload: { name: "notes" } });
  const { channel: notes } = await alice.ok("servers", await signed(alice, "create_channel", { server_id: sid, kind: "text", history: "full", item: name }));
  assert.equal(chainForChannel(sid, notes), historyChain(sid));
  assert.equal(chainForChannel(sid, general), liveChain(sid));

  await alice.say(sid, general, "before carol");
  await alice.say(sid, notes, "notes before carol");
  const { code } = await alice.invite(sid);
  await carol.join(code);
  await bob.fulfil(sid); // any member with the keys can hand them on
  const carolState = await carol.server(sid);
  assert.equal(carolState.member.key_status, "ok");
  await alice.say(sid, general, "after carol");

  const inGeneral = await carol.readChannel(sid, general);
  assert.deepEqual(inGeneral.map((r) => r.text), ["after carol"], "earlier messages aren't listed to her");
  const inNotes = await carol.readChannel(sid, notes);
  assert.deepEqual(inNotes.map((r) => [r.status, r.text]), [["ok", "notes before carol"]]);

  // Even if the service did hand her the earlier row, her key starts at the hour she joined.
  const liveGrant = carolState.grants.find((g) => g.chain_id === liveChain(sid));
  const aliceGrant = state.grants.find((g) => g.chain_id === liveChain(sid));
  assert.ok(liveGrant.step >= aliceGrant.step);
});

test("permissions are enforced by the server: announcements, forums, slow mode, timeouts, rules", async () => {
  const { w, members: [alice, bob] } = await world("alice", "bobby");
  const sid = await alice.create("community");
  const { code } = await alice.invite(sid);
  await bob.join(code);
  await alice.fulfil(sid);
  const ann = await alice.channelNamed(sid, "announcements");
  const general = await alice.channelNamed(sid, "general");
  const help = await alice.channelNamed(sid, "help");

  assert.equal((await bob.say(sid, ann, "hi all")).body.code, "MISSING_PERMISSION", "members can't post announcements");
  assert.equal((await alice.say(sid, ann, "Welcome!")).status, 200);
  const [annMsg] = await bob.readChannel(sid, ann);
  assert.equal((await bob.post(sid, ann, reactionPayload(annMsg.msg_id, REACTIONS[0]), "reaction")).status, 200, "but they can react");
  // A reaction sent as a message doesn't get past readers either: the payload has to match the kind.
  const sneaky = await bob.post(sid, ann, textPayload("smuggled"), "reaction");
  assert.equal(sneaky.status, 200, "the server can't read the payload...");
  const read = await alice.readChannel(sid, ann);
  assert.equal(read.find((r) => r.msg_id === sneaky.body.message.msg_id).status, "locked", "...but readers drop it");

  // Forums: posts, then replies in the post.
  const post = await bob.post(sid, help, postPayload("How do I link a phone?", "Asking for a friend"), "post");
  assert.equal(post.status, 200);
  assert.equal((await bob.say(sid, help, "a stray message")).body.code, "BAD_FIELD", "in a forum, reply to a post or start one");
  assert.equal((await alice.post(sid, help, textPayload("Settings → Devices"), "message", post.body.message.msg_id)).status, 200);
  const posts = await bob.readChannel(sid, help, { posts: true });
  assert.equal(posts[0].content.title, "How do I link a phone?");
  const thread = await bob.readChannel(sid, help, { thread_id: post.body.message.msg_id });
  assert.deepEqual(thread.map((r) => r.text), ["Asking for a friend", "Settings → Devices"]);
  assert.equal(w.rows("ServerMessage").find((m) => m.msg_id === post.body.message.msg_id).reply_count, 1);

  // Slow mode and timeouts apply to members, not to staff.
  await alice.ok("servers", await signed(alice, "update_channel", { server_id: sid, channel_id: general.id, slowmode_seconds: 60 }));
  assert.equal((await bob.say(sid, general, "one")).status, 200);
  assert.equal((await bob.say(sid, general, "two")).body.code, "SLOWMODE");
  assert.equal((await alice.say(sid, general, "staff aren't slowed")).status, 200);
  assert.equal((await alice.say(sid, general, "at all")).status, 200);
  await alice.ok("servers", await signed(alice, "timeout_member", { server_id: sid, user_id: bob.id, minutes: 10 }));
  await alice.ok("servers", await signed(alice, "update_channel", { server_id: sid, channel_id: general.id, slowmode_seconds: 0 }));
  assert.equal((await bob.say(sid, general, "three")).body.code, "TIMED_OUT");
  await alice.ok("servers", await signed(alice, "timeout_member", { server_id: sid, user_id: bob.id, minutes: 0 }));

  // Rules screening.
  await alice.ok("servers", await signed(alice, "update_server_settings", { server_id: sid, rules_required: true }));
  assert.equal((await bob.say(sid, general, "four")).body.code, "RULES_REQUIRED");
  await bob.ok("servers", await signed(bob, "accept_rules", { server_id: sid }));
  assert.equal((await bob.say(sid, general, "four")).status, 200);

  // Members can't manage the server.
  assert.equal((await bob.call("servers", await signed(bob, "create_channel", { server_id: sid, kind: "text" }))).body.code, "MISSING_PERMISSION");
  assert.equal((await bob.call("servers", await signed(bob, "kick_member", { server_id: sid, user_id: alice.id }))).body.code, "MISSING_PERMISSION");
  // The audit log notes who changed what, never what anyone said.
  const log = await alice.ok("servers", { action: "audit_log", server_id: sid });
  assert.ok(log.entries.some((e) => e.action === "member_timeout"));
  assert.ok(log.entries.some((e) => e.action === "server_settings"));
  assert.equal((await bob.call("servers", { action: "audit_log", server_id: sid })).body.code, "MISSING_PERMISSION");
});

test("private channels: only people who can see them can read their rows, and they have their own keys", async () => {
  const { w, members: [alice, bob, carol] } = await world("alice", "bobby", "carol");
  const sid = await alice.create("community");
  for (const m of [bob, carol]) {
    const { code } = await alice.invite(sid);
    await m.join(code);
  }
  await alice.fulfil(sid);
  const staffChat = (await alice.server(sid)).channels.find((c) => c.template_key === "staff-chat");
  assert.ok(staffChat.private);
  const staffChain = channelChain(sid, staffChat.id);
  assert.ok((await alice.server(sid)).generations.some((g) => g.chain_id === staffChain), "alice made the staff channel's keys");
  assert.equal((await alice.say(sid, staffChat, "staff only")).status, 200);

  // Bob isn't staff: the channel, its keys and its messages are invisible to him.
  const bobState = await bob.server(sid);
  assert.ok(!bobState.channels.some((c) => c.id === staffChat.id));
  assert.ok(!bobState.chains.some((c) => c.chain_id === staffChain));
  assert.equal((await bob.call("channels", { action: "list", server_id: sid, channel_id: staffChat.id })).body.code, "CHANNEL_NOT_FOUND");
  const bobClient = w.clientFor(bob.user);
  assert.equal((await bobClient.entities.ServerMessage.filter({ channel_id: staffChat.id })).length, 0, "row rules hide them too");

  // Make bob a moderator: he can see it, waits for its key, and gets it from alice's app.
  const mod = bobState.roles.find((r) => r.template_key === "moderator");
  await alice.ok("servers", await signed(alice, "set_member_roles", { server_id: sid, user_id: bob.id, role_ids: [mod.id] }));
  const promoted = await bob.server(sid);
  assert.ok(promoted.channels.some((c) => c.id === staffChat.id));
  assert.equal(promoted.member.key_status, "pending");
  await alice.fulfil(sid);
  assert.deepEqual((await bob.readChannel(sid, staffChat)).map((r) => [r.status, r.text]), [["ok", "staff only"]]);

  // Take the role away: the rows disappear for him, and the channel's keys are due to be renewed.
  await alice.ok("servers", await signed(alice, "set_member_roles", { server_id: sid, user_id: bob.id, role_ids: [] }));
  assert.equal((await bobClient.entities.ServerMessage.filter({ channel_id: staffChat.id })).length, 0);
  const chain = (await alice.server(sid)).chains.find((c) => c.chain_id === staffChain);
  assert.equal(chain.rotation_needed, true);
  void carol;
});

test("a ban removes someone for good and renews the keys they held; they can't come back", async () => {
  const { w, members: [alice, bob, carol] } = await world("alice", "bobby", "carol");
  const sid = await serverWith(alice, bob, carol);
  const general = await alice.channelNamed(sid, "general");
  await carol.say(sid, general, "hello");
  await alice.ok("servers", await signed(alice, "ban_member", { server_id: sid, user_id: carol.id, delete_seconds: 3600 }));
  assert.equal((await carol.call("servers", { action: "state", server_id: sid })).body.code, "SERVER_NOT_FOUND");
  assert.ok(w.rows("ServerMessage").filter((m) => m.sender_id === carol.id).every((m) => m.deleted), "her last hour of messages went");
  const { code } = await alice.invite(sid);
  assert.equal((await carol.call("servers", await signed(carol, "join_server", { invite_code: code }))).body.code, "BANNED");

  let state = await alice.server(sid);
  assert.ok(state.chains.filter((c) => c.chain_id === historyChain(sid) || c.chain_id === liveChain(sid)).every((c) => c.rotation_needed));
  // Alice's app renews both chains, with copies for everyone still in.
  const { chains } = await alice.keysFor([alice.id, bob.id]);
  for (const chainId of [historyChain(sid), liveChain(sid)]) {
    const next = Math.max(...state.generations.filter((g) => g.chain_id === chainId).map((g) => g.generation)) + 1;
    const { request } = await prepareGeneration({ serverId: sid, chainId, generation: next, userId: alice.id, device: alice.device, chains, recipientIds: [bob.id] });
    await alice.ok("servers", request);
  }
  state = await alice.server(sid);
  assert.ok(state.chains.every((c) => !c.rotation_needed));
  assert.equal((await alice.say(sid, general, "new keys")).status, 200);
  assert.equal(JSON.parse(w.rows("ServerMessage").at(-1).envelope).gen, 1, "sent with the new generation");
  assert.deepEqual((await bob.readChannel(sid, general)).map((r) => r.text).slice(-1), ["new keys"]);
  // Only people allowed to renew keys can.
  const bobChains = (await bob.keysFor([bob.id])).chains;
  const { request } = await prepareGeneration({ serverId: sid, chainId: historyChain(sid), generation: 2, userId: bob.id, device: bob.device, chains: bobChains, recipientIds: [] });
  assert.equal((await bob.call("servers", request)).body.code, "MISSING_PERMISSION");
  assert.equal((await alice.ok("servers", { action: "bans", server_id: sid })).bans.length, 1);
});

test("keys can't be forged or misdirected: grants must match what the recipient should have", async () => {
  const { members: [alice, bob, carol] } = await world("alice", "bobby", "carol");
  const sid = await alice.create("blank");
  const { code } = await alice.invite(sid);
  await bob.join(code);
  // Carol isn't in the server: a grant for her is skipped. Bob can't hand on keys he doesn't hold.
  const { chains } = await alice.keysFor([bob.id, carol.id]);
  const state = await alice.server(sid);
  const { keys } = await alice.keysOf(state);
  const items = [{ user_id: carol.id, chain_id: historyChain(sid), generation: 0, step: 0 }];
  const toCarol = await prepareGrants({ serverId: sid, items, keys, chains: new Map([[carol.id, (await carol.keysFor([carol.id])).chains.get(carol.id)]]), userId: alice.id, device: alice.device });
  assert.equal((await alice.ok("servers", toCarol)).accepted, 0);
  const bobItems = [{ user_id: alice.id, chain_id: historyChain(sid), generation: 0, step: 0 }];
  const fake = new ChainKeys();
  fake.add(historyChain(sid), 0, 0, crypto.getRandomValues(new Uint8Array(32)));
  const fromBob = await prepareGrants({ serverId: sid, items: bobItems, keys: fake, chains: (await bob.keysFor([alice.id])).chains, userId: bob.id, device: bob.device });
  assert.equal((await bob.call("servers", fromBob)).body.code, "NOT_HELD");
  // A key that doesn't match its generation's commitment is set aside, not used.
  const forged = await prepareGrants({ serverId: sid, items: [{ user_id: bob.id, chain_id: historyChain(sid), generation: 0, step: 0 }], keys: fake, chains, userId: alice.id, device: alice.device });
  await alice.ok("servers", forged);
  const { bad, keys: bobKeys } = await bob.keysOf(await bob.server(sid));
  assert.equal(bad.length, 1);
  assert.equal(bobKeys.has(historyChain(sid), 0), false);
});

test("discovery is opt-in, and only listed servers' public cards are shown", async () => {
  const { members: [alice, bob] } = await world("alice", "bobby");
  const sid = await alice.create("community");
  assert.equal((await bob.ok("servers", { action: "discover" })).servers.filter((s) => s.id === sid).length, 0);
  assert.equal((await alice.call("servers", await signed(alice, "update_server_settings", { server_id: sid, discoverable: true }))).body.code, "BAD_FIELD", "a listing needs a public name");
  await alice.ok("servers", await signed(alice, "update_server_settings", { server_id: sid, discoverable: true, join_mode: "open", public: { name: "Privacy pals", description: "Talk", tags: ["privacy"] } }));
  const found = (await bob.ok("servers", { action: "discover", tag: "privacy" })).servers.find((s) => s.id === sid);
  assert.equal(found.name, "Privacy pals");
  await bob.ok("servers", await signed(bob, "join_server", { server_id: sid }));
  await alice.ok("servers", await signed(alice, "update_server_settings", { server_id: sid, discoverable: false }));
  assert.equal((await bob.ok("servers", { action: "discover" })).servers.filter((s) => s.id === sid).length, 0);
  assert.equal((await bob.call("servers", await signed(bob, "join_server", { server_id: (await world("zed")).members[0].id }))).status, 404);
});

test("member lists show staff and people who chose to be listed, nobody else", async () => {
  const { members: [alice, bob, carol] } = await world("alice", "bobby", "carol");
  const sid = await serverWith(alice, bob, carol);
  let list = await bob.ok("servers", { action: "members", server_id: sid });
  assert.deepEqual(list.members.map((m) => m.user_id), [alice.id], "the owner is staff; the others haven't opted in");
  assert.equal(list.count, 3);
  await carol.ok("servers", await signed(carol, "set_listed", { server_id: sid, listed: true }));
  list = await bob.ok("servers", { action: "members", server_id: sid });
  assert.deepEqual(list.members.map((m) => m.user_id).sort(), [alice.id, carol.id].sort());
  assert.ok(list.members.every((m) => /^\d{4}-\d{2}$/.test(m.joined_at)), "join dates only to the month");
  await alice.ok("servers", await signed(alice, "update_server_settings", { server_id: sid, member_list: "count_only" }));
  list = await bob.ok("servers", { action: "members", server_id: sid });
  assert.deepEqual(list.members, []);
  assert.equal(list.count, 3);
});

test("the community server: everyone joins once, the listed addresses become its admins, and leaving sticks", async () => {
  const w = new FakeWorld();
  ADMINS = ["owner@example.test", "second@example.test"];
  try {
    const first = await new Member(w, "first").setup();
    const owner = await new Member(w, "owner", { email: "owner@example.test" }).setup();
    const second = await new Member(w, "second", { email: "second@example.test" }).setup();
    const list1 = await first.ok("servers", { action: "list" });
    assert.equal(list1.servers.length, 1);
    const community = list1.servers[0];
    assert.ok(community.is_default);
    assert.equal(community.public.name, "Commonveil Community");
    assert.equal(community.owner_id, "", "no owner until the first listed address joins");
    await second.ok("servers", { action: "list" });
    await owner.ok("servers", { action: "list" });
    const state = await owner.server(community.id);
    assert.equal(state.server.owner_id, owner.id);
    const admin = state.roles.find((r) => r.template_key === "admin");
    assert.deepEqual(state.member.role_ids, [admin.id]);
    assert.deepEqual((await second.server(community.id)).member.role_ids, [admin.id], "both listed addresses are admins");
    assert.deepEqual((await first.server(community.id)).member.role_ids, []);
    assert.equal(w.rows("Server").filter((s) => s.is_default).length, 1, "only ever one community server");

    // Only staff set up and hand out the community server's keys, so ordinary members' apps
    // never learn who's joining. Until an admin's app has been by, newcomers wait.
    assert.equal(state.server.settings.key_handout, "staff");
    const firstChains = (await first.keysFor([first.id])).chains;
    const early = await prepareGeneration({ serverId: community.id, chainId: historyChain(community.id), generation: 0, userId: first.id, device: first.device, chains: firstChains, recipientIds: [] });
    assert.equal((await first.call("servers", early.request)).body.code, "MISSING_PERMISSION");
    const firstPending = await first.ok("servers", { action: "pending_grants", server_id: community.id });
    assert.deepEqual([firstPending.items, firstPending.staff_only], [[], true]);
    await owner.initKeys(community.id);
    await owner.fulfil(community.id);
    const firstState = await first.server(community.id);
    assert.equal(firstState.member.key_status, "ok");
    assert.ok(firstState.generations.some((g) => g.chain_id === historyChain(community.id)));
    assert.ok(!firstState.chains.some((c) => c.kind === "c"), "staff channels aren't hers to see");
    assert.equal((await second.server(community.id)).member.key_status, "ok", "admins get the staff channels' keys too");
    const general = state.channels.find((c) => c.template_key === "general");
    await owner.ok("servers", await signed(owner, "accept_rules", { server_id: community.id }));
    assert.equal((await owner.say(community.id, general, "Welcome, everyone")).status, 200);
    assert.equal((await first.say(community.id, general, "hi")).body.code, "RULES_REQUIRED", "the community server asks people to accept its rules");

    // Leaving: not added back.
    await first.ok("servers", await signed(first, "leave_server", { server_id: community.id }));
    assert.equal((await first.ok("servers", { action: "list" })).servers.length, 0);
    assert.equal((await first.call("servers", await signed(first, "delete_server", { server_id: community.id, confirm: "DELETE" }))).status, 404);
    assert.equal((await owner.call("servers", await signed(owner, "delete_server", { server_id: community.id, confirm: "DELETE" }))).body.code, "DEFAULT_SERVER");
    // ...but they can rejoin from Discover whenever they like.
    await first.ok("servers", await signed(first, "join_server", { server_id: community.id }));
    assert.equal((await first.ok("servers", { action: "list" })).servers.length, 1);
  } finally {
    ADMINS = [];
  }
});

test("support tickets are private encrypted groups with the server's support team", async () => {
  const { members: [alice, bob, carol] } = await world("alice", "bobby", "carol");
  const sid = await alice.create("community");
  for (const m of [bob, carol]) {
    const { code } = await alice.invite(sid);
    await m.join(code);
  }
  const state = await alice.server(sid);
  const tickets = state.channels.find((c) => c.kind === "tickets");
  const support = state.roles.find((r) => r.template_key === "support");
  await alice.ok("servers", await signed(alice, "set_member_roles", { server_id: sid, user_id: carol.id, role_ids: [support.id] }));
  const opened = await bob.ok("servers", await signed(bob, "open_ticket", { server_id: sid, channel_id: tickets.id }));
  assert.deepEqual(opened.staff.sort(), [alice.id, carol.id].sort());
  const conv = (await bob.ok("conversations", { action: "get", conversation_id: opened.conversation_id })).conversation;
  assert.equal(conv.kind, "group");
  assert.equal(conv.server_id, sid);
  assert.equal(conv.ticket.status, "open");
  assert.equal((await bob.send(conv, "My phone won't link")).status, 200);
  assert.equal((await carol.read(conv))[0].text, "My phone won't link");
  assert.equal((await carol.ok("servers", { action: "tickets", server_id: sid })).tickets.length, 1);
  await carol.ok("servers", await signed(carol, "set_ticket_status", { server_id: sid, conversation_id: conv.id, status: "closed" }));
  assert.equal((await bob.ok("servers", { action: "tickets", server_id: sid })).tickets[0].status, "closed");
});

test("who can message you: anyone, only people you share a server with, or nobody new", async () => {
  const { members: [alice, bob, carol] } = await world("alice", "bobby", "carol");
  const sid = await serverWith(alice, bob);
  await bob.ok("profile", { action: "update", dm_policy: "servers" });
  assert.equal((await alice.call("conversations", await signed(alice, "create_dm", { username: bob.name }))).status, 200, "they share a server");
  assert.equal((await carol.call("conversations", await signed(carol, "create_dm", { username: bob.name }))).body.code, "NOT_ACCEPTING");
  await bob.ok("profile", { action: "update", dm_policy: "nobody" });
  assert.equal((await carol.call("conversations", await signed(carol, "create_group", { usernames: [bob.name] }))).body.code, "NOT_ACCEPTING");
  assert.equal((await alice.call("conversations", await signed(alice, "create_dm", { username: bob.name }))).status, 200, "an existing conversation carries on");
  // Profiles: server members see as much as each person chooses.
  await bob.ok("profile", { action: "update", pronouns: "he/him", profile_visibility: "conversations" });
  const asCarol = (await carol.ok("profile", { action: "get_many", user_ids: [bob.id] })).profiles;
  assert.deepEqual(asCarol, [], "carol shares nothing with bob");
  const { code } = await alice.invite(sid);
  await carol.join(code);
  const now = (await carol.ok("profile", { action: "get_many", user_ids: [bob.id] })).profiles[0];
  assert.equal(now.username, bob.name);
  assert.equal(now.pronouns, "", "bob shows his profile only to people he has a conversation with");
  assert.equal((await alice.ok("profile", { action: "get_many", user_ids: [bob.id] })).profiles[0].pronouns, "he/him");
  assert.equal((await bob.call("profile", { action: "update", accent_color: "neon" })).body.code, "BAD_FIELD");
});

test("deleting an account takes it out of its servers, hands on what it owned, and blanks its messages", async () => {
  const { w, members: [alice, bob] } = await world("alice", "bobby");
  const sid = await serverWith(alice, bob);
  const general = await alice.channelNamed(sid, "general");
  await alice.say(sid, general, "from alice");
  const lonely = await alice.create("blank");
  await alice.ok("profile", await signed(alice, "delete_account", { confirm: "DELETE" }));
  assert.equal(w.rows("Server").find((s) => s.id === sid).owner_id, bob.id, "bob owns it now");
  assert.ok(!w.rows("Server").some((s) => s.id === lonely), "a server she was alone in is gone");
  assert.ok(!w.rows("ServerMessage").some((m) => m.sender_id === alice.id));
  assert.ok(!w.rows("ServerMember").some((m) => m.user_id === alice.id));
  assert.ok(!w.rows("KeyGrant").some((g) => g.user_id === alice.id));
});

test("polling brings server messages and server changes with the member's own access", async () => {
  const { w, members: [alice, bob] } = await world("alice", "bobby");
  const sid = await serverWith(alice, bob);
  const general = await alice.channelNamed(sid, "general");
  const start = await bob.ok("messages", { action: "poll" });
  await new Promise((r) => setTimeout(r, 20));
  await alice.say(sid, general, "ping");
  const before = w.serviceReads;
  const quick = await bob.ok("messages", { action: "poll", since: start.cursor, servers_since: "2000-01-01T00:00:00" });
  assert.ok(quick.server_messages.some((m) => m.channel_id === general.id));
  assert.equal(quick.servers, undefined, "server changes only when asked for");
  const page = await bob.ok("messages", { action: "poll", since: start.cursor, servers_since: "2000-01-01T00:00:00", server_changes_since: "2000-01-01T00:00:00" });
  assert.equal(w.serviceReads, before, "no shared-allowance reads");
  assert.ok(page.server_messages.some((m) => m.channel_id === general.id));
  assert.ok(page.servers.some((s) => s.id === sid));
  assert.deepEqual(page.server_ids, [sid]);
  assert.ok(page.server_changes_cursor > "2000-01-01T00:00:00");
});

test("voice: a pass to join a call needs membership, a voice channel and no timeout", async () => {
  const { w, members: [alice, bob, carol] } = await world("alice", "bobby", "carol");
  const sid = await serverWith(alice, bob);
  const voice = await alice.channelNamed(sid, "general-voice");
  const text = await alice.channelNamed(sid, "general");
  const pass = await bob.ok("voice", await signed(bob, "voice_ticket", { server_id: sid, channel_id: voice.id }));
  assert.equal(pass.room, `${sid}.${voice.id}`);
  assert.equal(pass.can_speak, true);
  const row = w.rows("VoiceTicket").find((t) => t.id === pass.ticket);
  assert.equal(row.user_id, bob.id);
  assert.equal(row.device_id, bob.device.device_id);
  assert.ok(Date.parse(row.expires_at) - Date.now() <= 60_000 && Date.parse(row.expires_at) > Date.now());
  await bob.fails("voice", await signed(bob, "voice_ticket", { server_id: sid, channel_id: text.id }), "BAD_FIELD");
  await carol.fails("voice", await signed(carol, "voice_ticket", { server_id: sid, channel_id: voice.id }));
  await bob.fails("voice", { action: "voice_ticket", payload: JSON.stringify({ server_id: sid, channel_id: voice.id }) }, "PROOF_REQUIRED");
  const member = w.rows("ServerMember").find((m) => m.server_id === sid && m.user_id === bob.id);
  member.timeout_until = new Date(Date.now() + 600_000).toISOString();
  await bob.fails("voice", await signed(bob, "voice_ticket", { server_id: sid, channel_id: voice.id }), "TIMED_OUT");
  member.timeout_until = "";
  for (let i = 0; i < 6; i += 1) await alice.ok("voice", await signed(alice, "voice_ticket", { server_id: sid, channel_id: voice.id }));
  await alice.fails("voice", await signed(alice, "voice_ticket", { server_id: sid, channel_id: voice.id }), "RATE_LIMITED");
});

test("files: parts are stored as ciphertext for members who can post, and links go only to people who can see them, while the message exists", async () => {
  const { fileActions, FILES_MAX_BODY } = await import("../base44/shared/handlers/files.ts");
  addFunctions({ files: fileActions }, { options: { maxBodyBytes: FILES_MAX_BODY } });
  const { w, members: [alice, bob, carol] } = await world("alice", "bobby", "carol");
  const sid = await serverWith(alice, bob);
  const general = await alice.channelNamed(sid, "general");
  const msgId = randomId(16);
  const data = toB64(crypto.getRandomValues(new Uint8Array(1000)));
  const part = (who, extra = {}) => signed(who, "upload_part", { scope: "server", server_id: sid, channel_id: general.id, msg_id: msgId, part: 0, parts: 1, data, ...extra });
  const { file_id } = await bob.ok("files", await part(bob));
  await carol.fails("files", await part(carol));
  // A full-size part (bigger than other functions accept) goes through.
  await bob.ok("files", await part(bob, { data: toB64(new Uint8Array(768 * 1024).fill(7)), parts: 2 }));
  await bob.fails("files", await part(bob, { parts: 99 }), "BAD_FIELD");
  await bob.fails("files", await part(bob, { data: "not base64!" }), "BAD_FIELD");
  // No message with that id yet: no link, even for a member.
  assert.deepEqual((await alice.ok("files", { action: "download_links", file_ids: [file_id] })).links, {});
  // Once the message exists, members get a link and outsiders don't.
  const sent = await bob.post(sid, general, { type: "text", text: "a file" });
  assert.equal(sent.status, 200);
  const row = w.rows("Attachment").find((r) => r.id === file_id);
  row.msg_id = sent.body.message.msg_id;
  const links = (await alice.ok("files", { action: "download_links", file_ids: [file_id] })).links;
  assert.match(links[file_id], /^https:\/\/files\.example\.test\//);
  assert.deepEqual((await carol.ok("files", { action: "download_links", file_ids: [file_id] })).links, {});
  assert.equal(JSON.stringify(row).includes("a file"), false);
});
