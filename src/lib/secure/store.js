// Local, per-account storage in this browser's IndexedDB.
// Device private keys are stored as non-extractable CryptoKey objects.
// The keyring is stored as data: anyone who can run code in this site, or who
// has full access to this browser profile, can read it. That's stated in the docs.
// With a passcode lock set, it's stored encrypted instead (see crypto/lock.js).
import { createStore, del, get, promisifyRequest, set } from "idb-keyval";
import { parseKeyring, serializeKeyring } from "../crypto/keyring.js";
import { isSealedKeyring } from "../crypto/lock.js";

const store = typeof indexedDB !== "undefined" ? createStore("commonveil", "e2ee") : undefined;
const key = (userId, name) => `${name}:${userId}`;

export async function loadDevice(userId) {
  return (await get(key(userId, "device"), store)) || null;
}

export async function saveDevice(userId, device) {
  await set(key(userId, "device"), device, store);
}

/** Only for a keyring stored without a lock. */
export async function loadKeyring(userId) {
  const stored = await get(key(userId, "keyring"), store);
  if (isSealedKeyring(stored)) throw new Error("This browser's keys are locked.");
  return stored ? parseKeyring(stored, userId) : null;
}

export async function saveKeyring(userId, keyring) {
  await set(key(userId, "keyring"), serializeKeyring(keyring), store);
}

/** The keyring as stored: its text, a sealed record (lock set), or null. */
export async function loadKeyringRecord(userId) {
  return (await get(key(userId, "keyring"), store)) || null;
}

export async function saveKeyringRecord(userId, record) {
  await set(key(userId, "keyring"), record, store);
}

/** The passcode lock's settings, if one is set (see crypto/lock.js). */
export async function loadLock(userId) {
  return (await get(key(userId, "lock"), store)) || null;
}

export async function saveLock(userId, record) {
  await set(key(userId, "lock"), record, store);
}

/**
 * Set, change or remove the lock together with the keyring it covers, in one transaction: the
 * stored keyring must always be readable with whatever lock is stored next to it.
 * lockRecord null removes the lock (keyringValue is then the keyring's plain text).
 */
export async function saveLockAndKeyring(userId, lockRecord, keyringValue) {
  await store("readwrite", (s) => {
    if (lockRecord) s.put(lockRecord, key(userId, "lock"));
    else s.delete(key(userId, "lock"));
    s.put(keyringValue, key(userId, "keyring"));
    return promisifyRequest(s.transaction);
  });
}

/** Trust-on-first-use pins: { [userId]: { version, digest, sign_pub, statements, verified, pinned_at } } */
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

/**
 * Who was in each conversation when you last confirmed it: { [conversationId]: userId[] }.
 * The server controls membership, so the app pauses sending when someone new appears
 * until you've seen who it is.
 */
export async function loadMemberPins(userId) {
  return (await get(key(userId, "members"), store)) || {};
}

export async function saveMemberPins(userId, pins) {
  await set(key(userId, "members"), pins, store);
}

/**
 * While a new browser waits for approval: the account history it showed in its link code
 * ({ version, digest }). The keys it's sent must belong to that history.
 */
export async function loadLinkPin(userId) {
  return (await get(key(userId, "linkpin"), store)) || null;
}

export async function saveLinkPin(userId, pin) {
  await set(key(userId, "linkpin"), pin, store);
}

export async function clearLinkPin(userId) {
  await del(key(userId, "linkpin"), store);
}

/**
 * A reset this browser asked for: { request_id, effective_at, device, keyring }. The new keys
 * wait here until the reset completes. device keeps its non-extractable keys.
 */
export async function loadPendingReset(userId) {
  return (await get(key(userId, "reset"), store)) || null;
}

export async function savePendingReset(userId, pending) {
  await set(key(userId, "reset"), pending, store);
}

export async function clearPendingReset(userId) {
  await del(key(userId, "reset"), store);
}

/** Alert settings for this browser: { notify, showSender, titleCount }. They never leave it. */
export async function loadAlerts(userId) {
  return (await get(key(userId, "alerts"), store)) || null;
}

export async function saveAlerts(userId, settings) {
  await set(key(userId, "alerts"), settings, store);
}

/** Where you've read up to in each server channel: { [channelId]: time }. Only on this device. */
export async function loadServerRead(userId) {
  return (await get(key(userId, "sread"), store)) || {};
}

export async function saveServerRead(userId, state) {
  await set(key(userId, "sread"), state, store);
}

/**
 * Server preferences on this device: { muted: { [serverOrChannelId]: true }, collapsed: { [categoryId]: true },
 * last: { [serverId]: channelId }, order: [serverId] }. They never leave it.
 */
export async function loadServerPrefs(userId) {
  return (await get(key(userId, "sprefs"), store)) || {};
}

export async function saveServerPrefs(userId, prefs) {
  await set(key(userId, "sprefs"), prefs, store);
}

/** Remove every key and record for this account from this browser. */
export async function wipeLocal(userId) {
  for (const name of ["device", "keyring", "lock", "pins", "read", "members", "linkpin", "reset", "alerts", "sread", "sprefs"]) await del(key(userId, name), store);
}

export function storageAvailable() {
  return Boolean(store);
}
