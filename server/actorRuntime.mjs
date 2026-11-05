// The realtime rooms (base44/actors: VoiceRoom and Presence) on a self-hosted site. This is the
// small part of Base44's actor runtime they use: one instance per room, WebSocket connections
// with the signed-in person's identity, a little storage, and wake-up timers.
//
// base44/actors/*/entry.ts import { Actor } from "base44:runtime/actors"; server/loader.mjs
// points that at this file.

export class Actor {
  constructor(env) {
    this.env = env;
  }
  get instanceId() {
    return this.env.instanceId;
  }
  get storage() {
    return this.env.storage;
  }
  get client() {
    return this.env.client;
  }
  getConnections() {
    return [...this.env.conns.values()];
  }
  async schedule(key, at) {
    this.env.schedule(key, at);
  }
  async cancelSchedule(key) {
    this.env.cancel(key);
  }
}
