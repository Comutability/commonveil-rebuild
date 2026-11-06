// The VoiceRoom actor, run against a stand-in for the platform's actor runtime: admission by
// single-use pass, who hears what, relaying set-up messages, and waking from hibernation.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

// Stand-in for "base44:runtime/actors": just what VoiceRoom uses.
const RUNTIME = `
export class Actor {
  constructor(env) { this.env = env; }
  get instanceId() { return this.env.room; }
  get storage() { return this.env.storage; }
  get client() { return this.env.client; }
  getConnections() { return [...this.env.conns.values()]; }
  async schedule(key, at) { this.env.wakes.set(key, at); }
  async cancelSchedule(key) { this.env.wakes.delete(key); }
}`;

const dir = mkdtempSync(join(tmpdir(), "voiceroom-"));
writeFileSync(join(dir, "runtime.mjs"), RUNTIME);
const source = readFileSync(new URL("../base44/actors/VoiceRoom/entry.ts", import.meta.url), "utf8").replace('from "base44:runtime/actors"', 'from "./runtime.mjs"').replace('from "../../shared/identity/sessions.ts"', `from "${new URL("../base44/shared/identity/sessions.ts", import.meta.url).href}"`);
writeFileSync(join(dir, "VoiceRoom.mjs"), source);
const { default: VoiceRoom } = await import(pathToFileURL(join(dir, "VoiceRoom.mjs")).href);

const ROOM = "server1abcd.channel1abcd";
const FP = Array.from({ length: 32 }, () => "AB").join(":");
const hello = (n) => ({ call_id: `call${n}abcdefgh`, fingerprint: FP, issued_at: new Date().toISOString(), signature: "c2lnbmF0dXJl" });

function env() {
  const tickets = new Map();
  const saved = new Map();
  const removed = new Set();
  return {
    removed,
    room: ROOM,
    conns: new Map(),
    wakes: new Map(),
    tickets,
    storage: { get: async (k) => saved.get(k), put: async (k, v) => void saved.set(k, structuredClone(v)), delete: async (k) => saved.delete(k) },
    client: {
      asServiceRole: {
        entities: {
          ServerMember: { filter: async (q) => (removed.has(q.user_id) ? [] : [{ user_id: q.user_id, timeout_until: "" }]) },
          VoiceTicket: {
            get: async (id) => {
              if (!tickets.has(id)) throw new Error("not found");
              return tickets.get(id);
            },
            delete: async (id) => {
              if (!tickets.delete(id)) throw new Error("not found");
            },
          },
        },
      },
    },
  };
}

function connect(e, id, userId) {
  const c = {
    id,
    identity: userId ? { type: "authenticated", userId } : { type: "anonymous", anonymousId: "anon" },
    got: [],
    rejected: null,
    send(m) {
      this.got.push(structuredClone(m));
    },
    reject(code, reason) {
      this.rejected = { code, reason };
      e.conns.delete(id);
    },
  };
  e.conns.set(id, c);
  return c;
}

let n = 0;
function pass(e, userId, { room = ROOM, expiresIn = 60_000, device = `dev${userId}xyz`, stage = false, mod = false } = {}) {
  const id = `ticket${++n}abcd`;
  e.tickets.set(id, { id, room, user_id: userId, device_id: device, can_speak: stage ? mod : true, can_moderate: mod, stage, expires_at: new Date(Date.now() + expiresIn).toISOString() });
  return id;
}

async function joined(room, e, connId, userId) {
  const c = connect(e, connId, userId);
  await room.handleConnect(c);
  await room.handleMessage(c, { type: "join", ticket: pass(e, userId), hello: hello(userId) });
  return c;
}

test("voice room: only signed-in people with a valid, unused pass get in", async () => {
  const e = env();
  const room = new VoiceRoom(e);
  await room.handleStart();
  const anon = connect(e, "conn-anon-1", null);
  await room.handleConnect(anon);
  assert.deepEqual(anon.got.map((m) => m.type), ["sign-in-needed"], "asked for a Commonveil sign-in, nothing else");
  await room.handleMessage(anon, { type: "join", ticket: "made-up" });
  assert.equal(anon.rejected?.code, 4003, "nothing gets in before signing in");
  const forged = connect(e, "conn-anon-2", null);
  await room.handleConnect(forged);
  await room.handleMessage(forged, { type: "__auth", token: "cv1.not.real" });
  assert.equal(forged.rejected?.code, 4003, "a bad sign-in token is refused");

  const a = connect(e, "conn-alice-1", "alice");
  await room.handleConnect(a);
  assert.deepEqual(a.got.map((m) => m.type), ["pass-needed"]);
  // Someone else's pass, another room's pass, an expired pass, a made-up pass.
  for (const ticket of [pass(e, "bob"), pass(e, "alice", { room: "other.room1234" }), pass(e, "alice", { expiresIn: -1 }), "ticketmadeup1"]) {
    await room.handleMessage(a, { type: "join", ticket, hello: hello(1) });
  }
  assert.deepEqual(a.got.slice(1).map((m) => m.code), ["PASS_INVALID", "PASS_INVALID", "PASS_INVALID", "PASS_INVALID"]);
  assert.equal(room.people.size, 0);
  const good = pass(e, "alice");
  await room.handleMessage(a, { type: "join", ticket: good, hello: { ...hello(1), fingerprint: "nope" } });
  assert.equal(a.got.at(-1).code, "BAD_JOIN", "a malformed offer is refused");
  await room.handleMessage(a, { type: "join", ticket: good, hello: hello(1) });
  assert.equal(a.got.at(-1).type, "welcome");
  assert.equal(e.tickets.has(good), false, "the pass is used up");
  const b = connect(e, "conn-bob-1", "bob");
  await room.handleConnect(b);
  await room.handleMessage(b, { type: "join", ticket: good, hello: hello(2) });
  assert.equal(b.got.at(-1).code, "PASS_INVALID", "a used pass doesn't work twice");
});

test("voice room: members hear about each other and relay set-up; outsiders hear nothing", async () => {
  const e = env();
  const room = new VoiceRoom(e);
  await room.handleStart();
  const a = await joined(room, e, "conn-alice-1", "alice");
  const b = await joined(room, e, "conn-bob-1", "bob");
  const lurker = connect(e, "conn-lurk-1", "mallory");
  await room.handleConnect(lurker);
  const welcomeB = b.got.find((m) => m.type === "welcome");
  assert.deepEqual(welcomeB.peers.map((p) => p.user_id), ["alice"]);
  assert.equal(JSON.stringify(welcomeB).includes("conn-alice-1"), false, "connection ids are never shared");
  const joinedMsg = a.got.find((m) => m.type === "peer-joined");
  assert.equal(joinedMsg.peer.user_id, "bob");
  await room.handleMessage(b, { type: "signal", to: welcomeB.peers[0].seat, data: { sdp: { type: "offer", sdp: "v=0" } } });
  assert.deepEqual(a.got.at(-1), { type: "signal", from: welcomeB.seat, data: { sdp: { type: "offer", sdp: "v=0" } } });
  await room.handleMessage(lurker, { type: "signal", to: welcomeB.seat, data: { sdp: "x" } });
  await room.handleMessage(b, { type: "signal", to: welcomeB.peers[0].seat, data: { blob: "x".repeat(30000) } });
  assert.equal(a.got.at(-1).type, "signal", "outsiders and oversized messages aren't relayed");
  assert.equal(a.got.filter((m) => m.type === "signal").length, 1);
  await room.handleMessage(b, { type: "state", muted: true, deafened: false });
  assert.deepEqual(a.got.at(-1), { type: "peer-state", seat: welcomeB.seat, muted: true, deafened: false, can_speak: true, hand: false, mod_muted: false });
  await room.handleMessage(b, { type: "leave" });
  assert.deepEqual(a.got.at(-1), { type: "peer-left", seat: welcomeB.seat });
  assert.deepEqual(lurker.got.map((m) => m.type), ["pass-needed"], "a connection without a pass learns nothing");
});

test("voice room: a call holds eight, the same device rejoining replaces itself, and it survives hibernation", async () => {
  const e = env();
  const room = new VoiceRoom(e);
  await room.handleStart();
  for (let i = 0; i < 8; i += 1) await joined(room, e, `conn-user${i}-1`, `user${i}`);
  const late = await joined(room, e, "conn-late-1", "late");
  assert.equal(late.got.at(-1).code, "CALL_FULL");
  const again = await joined(room, e, "conn-user0-2", "user0");
  assert.equal(again.got.at(-1).type, "welcome");
  assert.equal(e.conns.has("conn-user0-1"), false, "the old connection was closed");
  assert.equal(room.people.size, 8);
  // Hibernation: a fresh instance with the same storage and sockets carries on.
  const woken = new VoiceRoom(e);
  await woken.handleStart();
  assert.equal(woken.people.size, 8);
  e.conns.delete("conn-user1-1");
  const woken2 = new VoiceRoom(e);
  await woken2.handleStart();
  assert.equal(woken2.people.size, 8, "someone whose socket went while it slept keeps their place for a while");
  assert.ok(e.wakes.has("drop:conn-user1-1"));
  await woken2.handleWake("drop:conn-user1-1");
  assert.equal(woken2.people.size, 7, "then it's given up");
  const seat = woken2.people.get("conn-user2-1").seat;
  assert.ok(woken2.nextSeat > seat);
});

test("voice room: a dropped socket keeps its place for a while, and coming back changes nothing for the others", async () => {
  const e = env();
  const room = new VoiceRoom(e);
  await room.handleStart();
  const a = await joined(room, e, "conn-alice-1", "alice");
  const b = await joined(room, e, "conn-bob-1", "bob");
  const seatB = b.got.find((m) => m.type === "welcome").seat;
  e.conns.delete("conn-bob-1");
  await room.handleClose(b);
  assert.equal(a.got.some((m) => m.type === "peer-left"), false, "not yet");
  assert.ok(e.wakes.has("drop:conn-bob-1"));
  // The SDK reconnects with the same id: same place, no pass needed, nobody told.
  const back = connect(e, "conn-bob-1", "bob");
  await room.handleConnect(back);
  assert.equal(back.got.at(-1).type, "welcome");
  assert.equal(back.got.at(-1).seat, seatB);
  assert.equal(e.wakes.has("drop:conn-bob-1"), false);
  await room.handleWake("drop:conn-bob-1");
  assert.equal(a.got.some((m) => m.type === "peer-left"), false);
  // Gone for good: the wake tells the others.
  e.conns.delete("conn-bob-1");
  await room.handleClose(back);
  await room.handleWake("drop:conn-bob-1");
  assert.deepEqual(a.got.at(-1), { type: "peer-left", seat: seatB });
  // Someone else can't take over a place by reusing its connection id.
  const c = await joined(room, e, "conn-carol-1", "carol");
  e.conns.delete("conn-carol-1");
  await room.handleClose(c);
  const thief = connect(e, "conn-carol-1", "mallory");
  await room.handleConnect(thief);
  assert.deepEqual(thief.got.map((m) => m.type), ["pass-needed"]);
});

test("stage: listeners can't speak until a moderator brings them up; only moderators can", async () => {
  const e = env();
  const room = new VoiceRoom(e);
  await room.handleStart();
  const join = async (connId, userId, opts) => {
    const c = connect(e, connId, userId);
    await room.handleConnect(c);
    await room.handleMessage(c, { type: "join", ticket: pass(e, userId, { stage: true, ...opts }), hello: hello(userId) });
    return c;
  };
  const mod = await join("conn-mod-1", "alice", { mod: true });
  const fan = await join("conn-fan-1", "bob", {});
  const other = await join("conn-oth-1", "carol", {});
  const fanSeat = fan.got.find((m) => m.type === "welcome").seat;
  const otherSeat = other.got.find((m) => m.type === "welcome").seat;
  assert.equal(fan.got.find((m) => m.type === "welcome").can_speak, false);
  // Unmuting yourself as a listener does nothing.
  await room.handleMessage(fan, { type: "state", muted: false, deafened: false });
  assert.equal(mod.got.at(-1).muted, true);
  await room.handleMessage(fan, { type: "hand", raised: true });
  assert.equal(mod.got.at(-1).hand, true);
  // A listener can't bring anyone up.
  await room.handleMessage(other, { type: "set-speaker", seat: fanSeat, speak: true });
  assert.equal(mod.got.at(-1).can_speak, false);
  await room.handleMessage(mod, { type: "set-speaker", seat: fanSeat, speak: true });
  assert.deepEqual([fan.got.at(-1).seat, fan.got.at(-1).can_speak, fan.got.at(-1).hand], [fanSeat, true, false]);
  await room.handleMessage(fan, { type: "state", muted: false, deafened: false });
  assert.equal(other.got.at(-1).muted, false);
  await room.handleMessage(mod, { type: "mute-peer", seat: fanSeat });
  assert.equal(other.got.at(-1).muted, true);
  assert.ok(otherSeat);
});

test("voice room: people removed from the server are taken out within a minute, and mod mutes stick", async () => {
  const e = env();
  const room = new VoiceRoom(e);
  await room.handleStart();
  const a = await joined(room, e, "conn-alice-1", "alice");
  const b = await joined(room, e, "conn-bob-1", "bob");
  assert.equal(e.wakes.has("recheck"), true);
  e.removed.add("bob");
  await room.handleWake("recheck");
  assert.equal(b.rejected?.code, 4006);
  assert.equal(a.got.at(-1).type, "peer-left");
  assert.deepEqual([...room.people.values()].map((p) => p.userId), ["alice"]);
  // Someone else's connection id doesn't let you act as them.
  const imposter = connect(e, "conn-alice-1", "mallory");
  await room.handleMessage(imposter, { type: "state", muted: true, deafened: true });
  assert.equal([...room.people.values()][0].deafened, false);
});

test("voice room: a moderator's mute can't be undone by the person muted", async () => {
  const e = env();
  const room = new VoiceRoom(e);
  await room.handleStart();
  const c = connect(e, "conn-mod-9", "alice");
  await room.handleConnect(c);
  const id = `ticketmod${++n}x`;
  e.tickets.set(id, { id, room: ROOM, user_id: "alice", device_id: "devalicexyz", can_speak: true, can_moderate: true, stage: false, expires_at: new Date(Date.now() + 60000).toISOString() });
  await room.handleMessage(c, { type: "join", ticket: id, hello: hello("alice") });
  const b = await joined(room, e, "conn-bob-9", "bob");
  const bSeat = b.got.find((m) => m.type === "welcome").seat;
  await room.handleMessage(c, { type: "mute-peer", seat: bSeat });
  await room.handleMessage(b, { type: "state", muted: false, deafened: false });
  assert.deepEqual([c.got.at(-1).muted, c.got.at(-1).mod_muted], [true, true]);
  await room.handleMessage(c, { type: "unmute-peer", seat: bSeat });
  await room.handleMessage(b, { type: "state", muted: false, deafened: false });
  assert.equal(c.got.at(-1).muted, false);
});
