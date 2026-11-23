// What a passport leaves on the site you land on (lib/identity/passport.js): the move history,
// so your next export carries it, and the archive you brought, kept here in this browser because
// it's yours, not the site's. IndexedDB, per account, readable only while signed in.
import { createStore, del, get, set } from "idb-keyval";

const store = typeof indexedDB !== "undefined" ? createStore("commonveil-passport", "items") : undefined;
const key = (userId, name) => `${userId}:${name}`;

/** The moves this account has recorded, oldest first. */
export async function loadChain(userId) {
  if (!store || !userId) return [];
  const chain = await get(key(userId, "chain"), store).catch(() => null);
  return Array.isArray(chain) ? chain : [];
}

export async function saveChain(userId, chain) {
  if (!store || !userId) return;
  await set(key(userId, "chain"), (chain || []).slice(-50), store);
}

/** The archive brought from another site: { from, imported_at, body, contacts, data }. */
export async function loadArchive(userId) {
  if (!store || !userId) return null;
  return (await get(key(userId, "archive"), store).catch(() => null)) || null;
}

export async function saveArchive(userId, archive) {
  if (!store || !userId) return null;
  await set(key(userId, "archive"), archive, store);
  return archive;
}

export async function clearArchive(userId) {
  if (!store || !userId) return;
  await del(key(userId, "archive"), store);
}