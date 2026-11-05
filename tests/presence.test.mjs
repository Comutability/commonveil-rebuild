// The Presence actor, against a stand-in runtime: only members get in, people are listed once,
// typing reaches the others (throttled), and nothing is written to storage.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const RUNTIME = `
export class Actor {
  constructor(env) { this.env = env; }
  get instanceId() { return this.env.room; }
  get storage() { return this.env.storage; }
  get client() { return this.env.client; }
  getConnections() { return [...this.env.conns.values()]; }
}`;
const dir = mkdtempSync(join(tmpdir(), "presence-"));
writeFileSync(join(dir, "runtime.mjs"), RUNTIME);
writeFileSync(join(dir, "Presence.mjs"), readFileSync(new URL("../base44/actors/Presence/entry.ts", import.meta.url), "utf8").replace('from "base44:runtime/actors"', 'from "./runtime.mjs"'));
const { default: Presence } = await import(pathToFileURL(join(dir, "Presence.mjs")).href);

function env(members) {
  const writes = [];
  return {
    room: "s.server1abcd",
    conns: new Map(),
    writes,
    storage: { get: async () => undefined, put: async (k) => void writes.push(k), delete: async () => {} },
    client: { asServiceRole: { entities: { ServerMember: { filter: async (q) => (members.includes(q.user_id) && q.server_id === "server1abcd" ? [{ user_id: q.user_id }] : []) } } } },
  };
}

function connect(e, id, userId) {
  const c = {
    id, identity: { type: "authenticated", userId }, got: [], rejected: null,
    send(m) { this.got.push(structuredClone(m)); },
    reject(code) { this.rejected = code; e.conns.delete(id); },
  };
  e.conns.set(id, c);
  return c;
}

test("presence: members only, one entry per person, typing passed on, nothing stored", async () => {
  const e = env(["alice00001", "bobby00001"]);
  const room = new Presence(e);
  await room.handleStart();
  const a1 = connect(e, "conn-a1", "alice00001");
  await room.handleConnect(a1);
  const a2 = connect(e, "conn-a2", "alice00001");
  await room.handleConnect(a2);
  const b = connect(e, "conn-b", "bobby00001");
  await room.handleConnect(b);
  const mallory = connect(e, "conn-m", "mallory001");
  await room.handleConnect(mallory);
  assert.equal(mallory.rejected, 4003);
  const last = b.got.filter((m) => m.type === "here").pop();
  assert.deepEqual(last.people.map((p) => p.user_id).sort(), ["alice00001", "bobby00001"]);
  await room.handleMessage(b, { type: "typing", channel_id: "channel1abcd" });
  assert.ok(a1.got.some((m) => m.type === "typing" && m.user_id === "bobby00001" && m.channel_id === "channel1abcd"));
  assert.ok(!b.got.some((m) => m.type === "typing"), "not echoed back");
  const before = a1.got.length;
  await room.handleMessage(b, { type: "typing", channel_id: "channel1abcd" });
  assert.equal(a1.got.length, before, "throttled");
  await room.handleMessage(a1, { type: "hello", status: "idle" });
  // alice is still online on her other device.
  assert.equal(b.got.filter((m) => m.type === "here").pop().people.find((p) => p.user_id === "alice00001").status, "online");
  await room.handleClose(b);
  e.conns.delete("conn-b");
  assert.deepEqual(a1.got.filter((m) => m.type === "here").pop().people.map((p) => p.user_id), ["alice00001"]);
  // After hibernation, a hello re-admits.
  await room.handleStart();
  await room.handleMessage(a1, { type: "hello", status: "online" });
  assert.ok(a1.got.at(-1).type === "here");
  assert.deepEqual(e.writes, []);
});
