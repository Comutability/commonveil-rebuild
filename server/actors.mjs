// Hosts the realtime rooms over WebSockets: /api/actors/<Name>/<instance>?id=<connection>&token=<session>.
// Each room is one instance of its actor class, made on first connection and dropped once empty.
import { WebSocketServer } from "ws";

const MAX_MESSAGE_BYTES = 64 * 1024;
const NAME_RE = /^[A-Za-z]{1,40}$/;
const INSTANCE_RE = /^[A-Za-z0-9._-]{1,160}$/;
const CONN_RE = /^[A-Za-z0-9_-]{8,64}$/;

export class ActorHost {
  /** classes: { Name: ActorClass }. client: the service client the rooms read with. */
  constructor({ classes, client, store, auth, log = console }) {
    this.classes = classes;
    this.client = client;
    this.store = store;
    this.auth = auth;
    this.log = log;
    this.instances = new Map();
    this.wss = new WebSocketServer({ noServer: true, maxPayload: MAX_MESSAGE_BYTES });
  }

  #storage(key) {
    const k = (name) => `actor:${key}:${name}`;
    return {
      get: async (name) => this.store.getSetting(k(name), undefined) ?? undefined,
      put: async (name, value) => this.store.setSetting(k(name), value),
      delete: async (name) => this.store.setSetting(k(name), null),
    };
  }

  async #instance(name, instanceId) {
    const key = `${name}:${instanceId}`;
    let inst = this.instances.get(key);
    if (inst) {
      await inst.ready;
      return inst;
    }
    const timers = new Map();
    const env = {
      instanceId,
      storage: this.#storage(key),
      client: this.client,
      conns: new Map(),
      schedule: (k, at) => {
        clearTimeout(timers.get(k));
        timers.set(k, setTimeout(() => {
          timers.delete(k);
          Promise.resolve(inst.actor.handleWake?.(k)).catch((e) => this.log.warn?.("[actor] wake failed", e?.message)).finally(() => this.#maybeDrop(key));
        }, Math.max(0, Number(at) - Date.now())));
      },
      cancel: (k) => {
        clearTimeout(timers.get(k));
        timers.delete(k);
      },
    };
    const actor = new this.classes[name](env);
    inst = { actor, env, timers, ready: Promise.resolve(actor.handleStart?.()) };
    this.instances.set(key, inst);
    await inst.ready;
    return inst;
  }

  #maybeDrop(key) {
    const inst = this.instances.get(key);
    if (inst && inst.env.conns.size === 0 && inst.timers.size === 0) this.instances.delete(key);
  }

  /** Called by the HTTP server for upgrade requests under /api/actors/. */
  handleUpgrade(req, socket, head) {
    const url = new URL(req.url, "http://local");
    const [, , , name, instanceId] = url.pathname.split("/");
    const connId = url.searchParams.get("id") || "";
    if (!NAME_RE.test(name || "") || !this.classes[name] || !INSTANCE_RE.test(decodeURIComponent(instanceId || "")) || !CONN_RE.test(connId)) {
      socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
      socket.destroy();
      return;
    }
    this.wss.handleUpgrade(req, socket, head, (ws) => this.#connected(ws, name, decodeURIComponent(instanceId), connId, url.searchParams.get("token") || ""));
  }

  async #connected(ws, name, instanceId, connId, token) {
    let user = null;
    try {
      user = await this.auth.userFor(token);
    } catch {
      user = null;
    }
    const inst = await this.#instance(name, instanceId);
    const key = `${name}:${instanceId}`;
    const conn = {
      id: connId,
      identity: user ? { type: "authenticated", userId: user.id } : { type: "anonymous", anonymousId: connId },
      send(msg) {
        if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(msg));
      },
      reject(code, reason) {
        try {
          ws.close(code, String(reason || "").slice(0, 120));
        } catch {
          ws.terminate();
        }
      },
    };
    const previous = inst.env.conns.get(connId);
    if (previous && previous.ws !== ws) previous.ws.terminate();
    conn.ws = ws;
    inst.env.conns.set(connId, conn);
    let queue = Promise.resolve();
    const run = (fn) => {
      queue = queue.then(fn).catch((e) => this.log.warn?.(`[actor ${name}]`, e?.message));
      return queue;
    };
    run(() => inst.actor.handleConnect?.(conn));
    ws.on("message", (data) => {
      let msg;
      try {
        msg = JSON.parse(String(data));
      } catch {
        return;
      }
      if (msg && msg.type === "__ping") {
        conn.send({ type: "__pong" });
        return;
      }
      run(() => inst.actor.handleMessage?.(conn, msg));
    });
    ws.on("close", () => {
      if (inst.env.conns.get(connId)?.ws !== ws) return;
      inst.env.conns.delete(connId);
      run(() => inst.actor.handleClose?.(conn)).finally(() => this.#maybeDrop(key));
    });
    ws.on("error", () => ws.terminate());
  }
}
