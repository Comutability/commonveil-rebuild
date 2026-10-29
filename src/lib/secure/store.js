// Local, per-account storage in this browser's IndexedDB.
// Device private keys are stored as non-extractable CryptoKey objects.
// The keyring is stored as data: anyone who can run code in this site, or who
// has full access to this browser profile, can read it. That's stated in the docs.
import { createStore, del, get, set } from "idb-keyval";
import { parseKeyring, serializeKeyring } from "../crypto/keyring.js";

const store = typeof indexedDB !== "undefined" ? createStore("commonveil", "e2ee") : undefined;
const key = (userId, name) => `${name}:${userId}`;

export async function loadDevice(userId) {
  return (await get(key(userId, "device"), store)) || null;
}

export async function saveDevice(userId, device) {
  await set(key(userId, "device"), device, store);
}

export async function loadKeyring(userId) {
  const text = await get(key(userId, "keyring"), store);
  return text ? parseKeyring(text, userId) : null;
}

export async function saveKeyring(userId, keyring) {
  await set(key(userId, "keyring"), serializeKeyring(keyring), store);
}

/** Trust-on-first-use pins: { [userId]: { version, sign_pub, verified, pinned_at } } */
export async function loadPins(userId) {
  return (await get(key(userId, "pins"), store)) || {};
}

export async function savePins(userId, pins) {
  await set(key(userId, "pins"), pins, store);
}

/** Read markers live only on this device, so the server never learns what you've read. */
export async function loadReadState(userId) {
  return (await get(key(userId, "read"), store)) || {};
}

export async function saveReadState(userId, state) {
  await set(key(userId, "read"), state, store);
}

/** Remove every key and record for this account from this browser. */
export async function wipeLocal(userId) {
  for (const name of ["device", "keyring", "pins", "read"]) await del(key(userId, name), store);
}

export function storageAvailable() {
  return Boolean(store);
}
