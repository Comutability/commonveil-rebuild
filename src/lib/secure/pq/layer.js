// The experimental protocol layer, wired to a backend and a store (both passed in, so the tests
// run it against the real handlers with memory in place of the browser's database).
//
//   call(fn, body)        calls a backend function, as the signed-in person
//   store.load()/save(s)  this device's layer state (engine.js); store.getKey/putKey: one-off keys
//   account()             { userId, username, device, keyring } as they are now
//   host                  this site's address, for handles
import { fromB64u, b64u, utf8 } from "../../../../packages/secure-net/src/core/bytes.js";
import { keyForVersion, latestKey, sealToRecipient, openFromSender } from "../../crypto/keyring.js";
import { importEcdhPrivate } from "../../crypto/primitives.js";
import { signedRequest } from "../protocol.js";
import * as E from "./engine.js";

const context = (userId, version) => `commonveil/proto-account/v1|${userId}|${version}`;
const fromUtf8 = (b) => new TextDecoder().decode(b);
const LOW_PREKEYS = 4;

export class PqLayer {
  constructor({ call, store, account, host }) {
    this.call = call;
    this.store = store;
    this.account = account;
    this.host = host;
    this.state = null;
    this.problems = {}; // user id -> why the layer isn't used with them
    this.queue = Promise.resolve();
    this.listeners = new Set();
  }

  /** One thing at a time: session state must never be used from two places at once. */
  #serial(fn) {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => null);
    return run;
  }

  async #commit(state) {
    this.state = state;
    await this.store.save(state);
  }

  #signed(action, payload) {
    const { userId, device } = this.account();
    return signedRequest({ userId, device, action, payload });
  }

  onKeys(fn) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  /** Load this device's state, if the layer is on here. */
  async start() {
    this.state = (await this.store.load()) || null;
    return this.enabled;
  }

  get enabled() {
    return Boolean(this.state?.actor);
  }

  get handle() {
    return this.state ? `@${this.state.handle}` : null;
  }

  /** Turn the layer on for this device (creating the account's identity, or joining it). */
  enable() {
    return this.#serial(async () => {
      if (this.enabled) return this.status();
      const { userId, username, keyring } = this.account();
      if (!username) throw new E.PqError("NO_PROFILE", "Choose a username first.");
      const { actor } = await this.call("protocol", { action: "mine" });
      let state;
      let sealed;
      let version;
      if (actor) {
        const k = keyForVersion(keyring, actor.sealed_version);
        if (!k) throw new E.PqError("NO_KEY", "This device doesn't have the keys that protect your protocol identity. Link it again from another device.");
        const secret = fromUtf8(await openFromSender({ ecdhPriv: await importEcdhPrivate(k.ecdh_priv), ecdhPub: k.ecdh_pub, kemPriv: k.kem_priv || null }, JSON.parse(actor.sealed_account), context(userId, k.version)));
        state = E.joinIdentity({ accountSecret: secret, document: JSON.parse(actor.document), username, host: this.host });
        sealed = actor.sealed_account;
        version = actor.sealed_version;
      } else {
        state = E.createIdentity({ username, host: this.host });
        const k = latestKey(keyring);
        sealed = JSON.stringify(await sealToRecipient({ ecdhPub: k.ecdh_pub, kemPub: k.kem_pub || null }, utf8(state.account.secretKey), context(userId, k.version)));
        version = k.version;
      }
      await this.call("protocol", await this.#signed("proto_publish", { document: JSON.stringify(state.actor), sealed_account: sealed, sealed_version: version }));
      const pre = E.makePrekeys(state);
      // Keep the prekey secrets before the site hears of the public halves.
      await this.#commit(pre.state);
      await this.call("protocol", await this.#signed("proto_prekeys", pre.publish));
      return this.status();
    });
  }

  /** Turn the layer off on this device. everywhere: also delete the account's identity from the site. */
  disable({ everywhere = false } = {}) {
    return this.#serial(async () => {
      if (everywhere) await this.call("protocol", await this.#signed("proto_disable", {}));
      this.state = null;
      await this.store.clear();
    });
  }

  status() {
    if (!this.enabled) return { enabled: false };
    return { enabled: true, handle: this.handle, actorId: E.myActorId(this.state), devices: this.state.deviceList.body.devices.length, problems: { ...this.problems } };
  }

  /** Learn the actors of these people (and refresh our own). Returns the user ids the layer can be used with. */
  async #learn(userIds, usernames) {
    const { userId } = this.account();
    const { actors } = await this.call("protocol", { action: "actors", user_ids: [...new Set([...userIds, userId])] });
    const byUser = new Map(actors.map((a) => [a.user_id, a.document]));
    let state = this.state;
    if (byUser.has(userId)) state = E.refreshSelf(state, byUser.get(userId));
    const ready = [];
    for (const uid of userIds) {
      if (uid === userId) continue;
      if (!byUser.has(uid) || !usernames[uid]) {
        continue;
      }
      const r = E.learnPeer(state, { userId: uid, username: usernames[uid], host: this.host, documentJson: byUser.get(uid) });
      state = r.state;
      if (r.peer) {
        ready.push(uid);
        delete this.problems[uid];
      } else this.problems[uid] = r.problem;
    }
    if (state !== this.state) await this.#commit(state);
    return ready;
  }

  /**
   * The second seal for a direct conversation, as protocol.js buildMessage's `fs`: seals the
   * payload under a one-off key and sends that key to the other person's devices and our own
   * others. Returns null (send as usual) when the other person doesn't have the layer on.
   * usernames: user id -> username, for the members.
   */
  wrapperFor(conversation, usernames) {
    if (!this.enabled || conversation.kind !== "dm") return null;
    return (payload, scope) => this.#serial(async () => {
      const { userId } = this.account();
      const others = conversation.member_ids.filter((m) => m !== userId);
      const ready = await this.#learn(others, usernames);
      if (ready.length !== others.length || !others.length) return null;
      const targets = E.targetsFor(this.state, others, userId);
      const bundles = {};
      for (const t of targets.filter((x) => x.needsBundle)) {
        try {
          bundles[t.device] = (await this.call("protocol", { action: "bundle", user_id: t.userId, device: t.device })).bundle;
        } catch (e) {
          // One of our own other devices without prekeys only misses out itself; theirs stops the layer.
          if (t.userId !== userId) return null;
        }
      }
      const reachable = targets.filter((t) => !t.needsBundle || bundles[t.device]);
      const { key, wrapped } = await E.wrapPayload(payload, scope);
      const { state, items } = await E.sealMessageKey(this.state, { targets: reachable, bundles, conversationId: scope.conversationId, itemId: scope.itemId, key });
      // Our own copy of the key first, then the session state, then the network: a message is
      // never sent sealed under a key nobody kept.
      await this.store.putKey(userId, scope.itemId, b64u(key));
      await this.#commit(state);
      await this.call("protocol", { action: "send", items });
      return wrapped;
    });
  }

  /** As protocol.js openItem's `fsOpen`. */
  opener() {
    return async (wrapped, scope) => {
      const stored = await this.store.getKey(scope.senderId, scope.itemId);
      if (!stored) return null;
      return E.unwrapPayload(wrapped, fromB64u(stored), scope);
    };
  }

  /** Collect this device's mailbox: new one-off keys are stored, and prekeys topped up. Returns how many keys arrived. */
  sync(usernames = {}) {
    return this.#serial(async () => {
      if (!this.enabled) return 0;
      const { userId } = this.account();
      const device = this.state.device.kid;
      let got = 0;
      let ack = [];
      for (let round = 0; round < 5; round += 1) {
        const res = await this.call("protocol", { action: "collect", device, ack });
        ack = [];
        const unknown = [...new Set(res.mail.map((m) => m.from).filter((u) => u !== userId && !this.state.peers[u]))];
        if (unknown.length) await this.#learn(unknown, usernames);
        for (const m of res.mail) {
          try {
            const r = await E.openMail(this.state, { fromUserId: m.from, myUserId: userId, envelopeJson: m.envelope });
            if (r.key) {
              await this.store.putKey(r.key.userId, r.key.itemId, b64u(r.key.key));
              got += 1;
            }
            await this.#commit(r.state);
            ack.push(m.id);
          } catch (e) {
            // From someone we can't check yet: leave it for a later round. Anything else can never open: drop it.
            if (e.code !== "UNKNOWN_SENDER") ack.push(m.id);
          }
        }
        if (res.prekeys.otk < LOW_PREKEYS || res.prekeys.pq < LOW_PREKEYS) {
          const pre = E.makePrekeys(this.state, { full: false });
          await this.#commit(pre.state);
          await this.call("protocol", await this.#signed("proto_prekeys", pre.publish));
        }
        if (!ack.length) break;
        if (res.mail.length < 100) {
          await this.call("protocol", { action: "collect", device, ack });
          break;
        }
      }
      if (got) for (const fn of this.listeners) fn(got);
      return got;
    });
  }

  /** The safety number to compare with someone, once their identity has been seen. */
  safetyNumber(userId) {
    const p = this.state?.peers[userId];
    return p ? E.safetyNumberWith(this.state, p.record.body) : null;
  }
}

/** A store in memory (tests, and browsers without IndexedDB). */
export function memoryStore() {
  let state = null;
  const keys = new Map();
  return {
    load: async () => (state ? JSON.parse(state) : null),
    save: async (s) => {
      state = JSON.stringify(s);
    },
    clear: async () => {
      state = null;
      keys.clear();
    },
    getKey: async (userId, itemId) => keys.get(`${userId}:${itemId}`) || null,
    putKey: async (userId, itemId, key) => {
      keys.set(`${userId}:${itemId}`, key);
    },
  };
}
