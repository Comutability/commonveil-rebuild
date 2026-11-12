// The passcode lock: this browser's copy of the account keys, encrypted at rest with a key
// made from a passcode only the person knows. PBKDF2-SHA-256 (600,000 rounds) turns the
// passcode into an AES-256-GCM key, which stays in memory (non-extractable) while unlocked
// and is dropped on lock.
//
// What it protects: someone who opens this browser while it's locked, or who copies its files,
// doesn't get the keys that read your messages without the passcode. What it doesn't: someone
// who copies the files can try passcodes offline as fast as their hardware allows, so a longer
// passcode matters; and this device's signing key is a browser-held key that can't be exported
// or wrapped, so code running in this browser profile can still use it.
import { fromB64, fromUtf8, randomBytes, toB64, utf8 } from "./encoding.js";
import { aesDecrypt, aesEncrypt } from "./primitives.js";

export const LOCK_ITERATIONS = 600_000;
export const MIN_PASSCODE_CHARS = 8;
export const IDLE_CHOICES = Object.freeze([5, 15, 60]);
const CHECK = "commonveil passcode check v1";

export class LockError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = "LockError";
    this.code = code;
  }
}

const subtle = () => globalThis.crypto.subtle;
const aad = (purpose) => utf8(`commonveil-lock:${purpose}`);

/** Passcodes are compared as typed, after Unicode normalisation, so the same characters always match. */
export function checkPasscode(passcode) {
  const p = String(passcode || "").normalize("NFKC");
  if (p.length < MIN_PASSCODE_CHARS) throw new LockError("TOO_SHORT", `Use at least ${MIN_PASSCODE_CHARS} characters.`);
  if (p.length > 256) throw new LockError("TOO_LONG", "That passcode is too long.");
  return p;
}

function checkRecord(record) {
  const ok = record && record.v === 1 && record.kdf === "PBKDF2-SHA256" && Number.isInteger(record.iterations)
    && record.iterations >= 100_000 && record.iterations <= 10_000_000 && typeof record.salt === "string" && record.check;
  if (!ok) throw new LockError("BAD_LOCK", "This browser's lock settings are damaged.");
  return record;
}

export async function deriveLockKey(passcode, record, { checked = false } = {}) {
  const p = checked ? passcode : String(passcode || "").normalize("NFKC");
  const base = await subtle().importKey("raw", utf8(p), "PBKDF2", false, ["deriveKey"]);
  return subtle().deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: fromB64(record.salt), iterations: record.iterations },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function sealWithLock(key, text, purpose) {
  const { iv, ct } = await aesEncrypt(key, utf8(text), aad(purpose));
  return { iv: toB64(iv), ct: toB64(ct) };
}

export async function openWithLock(key, sealed, purpose) {
  try {
    return fromUtf8(await aesDecrypt(key, fromB64(sealed.iv), fromB64(sealed.ct), aad(purpose)));
  } catch {
    throw new LockError("WRONG_PASSCODE", "That passcode isn't right.");
  }
}

/** A new lock: the record to store, and the key to keep in memory while unlocked. */
export async function createLock(passcode, idleMinutes, { iterations = LOCK_ITERATIONS } = {}) {
  const p = checkPasscode(passcode);
  if (!IDLE_CHOICES.includes(idleMinutes)) throw new LockError("BAD_IDLE", "Choose when to lock.");
  const record = { v: 1, kdf: "PBKDF2-SHA256", iterations, salt: toB64(randomBytes(16)), idle_minutes: idleMinutes };
  const key = await deriveLockKey(p, record, { checked: true });
  record.check = await sealWithLock(key, CHECK, "check");
  return { record, key };
}

/** The key for a stored lock, if the passcode is right. */
export async function unlock(passcode, record) {
  checkRecord(record);
  const key = await deriveLockKey(passcode, record);
  if ((await openWithLock(key, record.check, "check")) !== CHECK) throw new LockError("WRONG_PASSCODE", "That passcode isn't right.");
  return key;
}

const keyringPurpose = (userId) => `keyring:${userId}`;

/** How a keyring is stored while a lock is set. */
export async function sealKeyringText(key, userId, keyringText) {
  return { v: 1, locked: true, ...(await sealWithLock(key, keyringText, keyringPurpose(userId))) };
}

export const isSealedKeyring = (stored) => Boolean(stored && typeof stored === "object" && stored.locked === true);

export function openKeyringText(key, userId, stored) {
  return openWithLock(key, stored, keyringPurpose(userId));
}
