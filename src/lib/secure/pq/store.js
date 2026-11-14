// The experimental protocol layer's state on this device, in the browser's IndexedDB, per account.
// Like the device's other keys without a passcode lock, it is stored as data: anyone with full
// access to this browser profile can read it. The passcode lock doesn't cover it yet, so the
// layer can't be turned on while a lock is set (docs/SECURE_NET_LAYER.md).
import { createStore, del, get, set, keys as allKeys } from "idb-keyval";

const db = typeof indexedDB !== "undefined" ? createStore("commonveil-pq", "layer") : undefined;

export function browserStore(userId) {
  const k = (name) => `${userId}:${name}`;
  return {
    load: async () => (await get(k("state"), db)) || null,
    save: (state) => set(k("state"), state, db),
    getKey: async (senderId, itemId) => (await get(k(`key:${senderId}:${itemId}`), db)) || null,
    putKey: (senderId, itemId, key) => set(k(`key:${senderId}:${itemId}`), key, db),
    clear: async () => {
      for (const name of await allKeys(db)) if (String(name).startsWith(`${userId}:`)) await del(name, db);
    },
  };
}

export const pqStorageAvailable = () => Boolean(db);
