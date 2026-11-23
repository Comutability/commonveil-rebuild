// Only encrypted passport files may persist in IndexedDB.
// Decrypted contacts and message content are deliberately memory-only.
import { createStore, del, get, set } from "idb-keyval";

const store = typeof indexedDB !== "undefined" ? createStore("commonveil-passport", "items") : undefined;
const key = (userId, name) => `${userId}:${name}`;

export async function loadArchive(userId) {
  if (!store || !userId) return null;
  // A short-lived early preview stored unencrypted archives. Never load it again.
  await del(key(userId, "archive"), store).catch(() => {});
  return (await get(key(userId, "encrypted-passport"), store).catch(() => null)) || null;
}

export async function saveArchive(userId, doc) {
  if (!store || !userId) throw new Error("Browser storage is unavailable.");
  if (doc?.format !== "commonveil-passport-2" || !doc?.sealed?.archive || !doc?.sealed?.contacts) {
    throw new Error("Only an encrypted identity archive can be saved.");
  }
  await set(key(userId, "encrypted-passport"), doc, store);
  return doc;
}

export async function clearArchive(userId) {
  if (!store || !userId) return;
  await Promise.all([
    del(key(userId, "encrypted-passport"), store),
    del(key(userId, "archive"), store),
  ]);
}
