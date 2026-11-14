// Accounts, devices and prekeys for the session protocol (CVP-016).
//
// An account is one quantum-resistant signing key (Ed25519 + ML-DSA-65). It signs the account's
// device list. Each device has its own signing key and its own X25519 identity key, and publishes
// prekeys signed by its signing key. Nothing a site serves is trusted unless it chains back to
// the account key, which people check with a safety number.
import { randomB64u, sha256B64u, utf8 } from "../core/bytes.js";
import { canonicalBytes } from "../core/canonical.js";
import { generateSigningKey, sign, verify, SignatureError } from "../core/signed.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { dhKeyPair, kemKeyPair, SessionError } from "./primitives.js";

export const DEVICE_LIST = "session.device-list";
export const PREKEY = "session.prekey";
const DAY = 86_400_000;
export const SIGNED_PREKEY_LIFETIME = 30 * DAY;

/** A new account key. Keep its secret on trusted devices, or derive it from a recovery phrase. */
export const createAccount = () => generateSigningKey({ pq: true });

/** A new device: a signing key and an X25519 identity key. */
export function createDevice() {
  const sign = generateSigningKey({ pq: true });
  return { kid: sign.kid, sign, dh: dhKeyPair() };
}

/** What others may know about a device. */
export const devicePublic = (device) => ({ kid: device.kid, sign: device.sign.publicKey, dh: device.dh.pk });

/**
 * The account's list of devices, signed by the account key. seq only goes up: a recipient
 * remembers the highest it has seen and refuses older lists, so a site can't bring back a
 * device that was removed.
 */
export function signDeviceList(account, devices, { seq, now = Date.now() }) {
  if (!Number.isSafeInteger(seq) || seq < 1) throw new SessionError("BAD_INPUT", "seq must be a positive integer");
  const list = devices.map((d) => (d.sign && typeof d.sign === "object" ? devicePublic(d) : d));
  return sign(DEVICE_LIST, { account: account.publicKey, devices: list, seq, issued: now }, account);
}

/** Check a device list against the account key you trust for that person. */
export function verifyDeviceList(record, { accountKey, minSeq = 0 }) {
  let body;
  try {
    body = verify(record, (kid) => (kid === record?.sig?.kid ? accountKey : null), { kinds: [DEVICE_LIST] });
  } catch (e) {
    if (e instanceof SignatureError) throw new SessionError("UNTRUSTED", `Device list: ${e.message}`);
    throw e;
  }
  if (body.account !== accountKey) throw new SessionError("UNTRUSTED", "Device list is for a different account");
  if (!Number.isSafeInteger(body.seq) || body.seq < minSeq) throw new SessionError("ROLLBACK", "Device list is older than one already seen");
  if (!Array.isArray(body.devices) || body.devices.length === 0) throw new SessionError("BAD_INPUT", "Device list is empty");
  return body;
}

/** Add a device to the list (on an existing device, after comparing link codes). */
export function approveLink(account, currentList, newDevice, { now = Date.now() } = {}) {
  const pub = newDevice.sign && typeof newDevice.sign === "object" ? devicePublic(newDevice) : newDevice;
  const others = currentList.devices.filter((d) => d.kid !== pub.kid);
  return signDeviceList(account, [...others, pub], { seq: currentList.seq + 1, now });
}

/** Remove a device (lost, sold, compromised). Peers stop encrypting to it once they see the list. */
export function removeDevice(account, currentList, kid, { now = Date.now() } = {}) {
  return signDeviceList(account, currentList.devices.filter((d) => d.kid !== kid), { seq: currentList.seq + 1, now });
}

const digits = (bytes, groups) => {
  const out = [];
  for (let i = 0; i < groups; i += 1) {
    const n = ((bytes[i * 4] << 24) | (bytes[i * 4 + 1] << 16) | (bytes[i * 4 + 2] << 8) | bytes[i * 4 + 3]) >>> 0;
    out.push(String(n % 100000).padStart(5, "0"));
  }
  return out.join(" ");
};

/**
 * The code both devices show while linking a new one: the new device shows it (or a QR code of
 * it), the existing device computes it from what it received, and the person checks they match.
 */
export const linkCode = (devicePub) => digits(sha256(utf8(`secure-net/session/v1/link\n${devicePub.sign}\n${devicePub.dh}`)), 6);

/** The safety number two people compare to know they have each other's real account keys. */
export function safetyNumber(accountKeyA, accountKeyB) {
  const [a, b] = [accountKeyA, accountKeyB].sort();
  return digits(sha256(utf8(`secure-net/session/v1/safety\n${a}\n${b}`)), 8);
}

function prekeyMaker(device, secrets) {
  return (type, extra = {}) => {
    const pair = type === "x25519" ? dhKeyPair() : kemKeyPair();
    const id = randomB64u(9);
    secrets[id] = { type, sk: pair.sk, pk: pair.pk, ...extra };
    return sign(PREKEY, { device: device.kid, type, id, pub: pair.pk, ...extra }, device.sign);
  };
}

/**
 * Prekeys for a device: a signed X25519 prekey, a last-resort ML-KEM-768 prekey, and batches of
 * one-time X25519 and ML-KEM-768 prekeys. Every public prekey is signed by the device. Keep
 * `secrets` on the device; publish `published` to the site that holds your mailbox.
 */
export function createPrekeys(device, { oneTime = 20, pqOneTime = 20, now = Date.now(), lifetime = SIGNED_PREKEY_LIFETIME } = {}) {
  const secrets = {};
  const make = prekeyMaker(device, secrets);
  const expires = now + lifetime;
  return {
    secrets,
    published: {
      signed: make("x25519", { expires }),
      lastResort: make("ml-kem-768", { expires, lastResort: true }),
      oneTime: Array.from({ length: oneTime }, () => make("x25519", { oneTime: true })),
      pqOneTime: Array.from({ length: pqOneTime }, () => make("ml-kem-768", { oneTime: true })),
    },
  };
}

/** More one-time prekeys, when the site says the stock is low. Merge `secrets` into the device's. */
export function moreOneTimePrekeys(device, { oneTime = 20, pqOneTime = 20 } = {}) {
  const secrets = {};
  const make = prekeyMaker(device, secrets);
  return {
    secrets,
    oneTime: Array.from({ length: oneTime }, () => make("x25519", { oneTime: true })),
    pqOneTime: Array.from({ length: pqOneTime }, () => make("ml-kem-768", { oneTime: true })),
  };
}

/**
 * Rotate the signed prekey and the last-resort ML-KEM prekey (do this well before they expire).
 * Keep the old secrets for a while so messages already on their way can still be opened.
 */
export function rotateSignedPrekeys(device, { now = Date.now(), lifetime = SIGNED_PREKEY_LIFETIME } = {}) {
  const secrets = {};
  const make = prekeyMaker(device, secrets);
  const expires = now + lifetime;
  return { secrets, signed: make("x25519", { expires }), lastResort: make("ml-kem-768", { expires, lastResort: true }) };
}

/**
 * What a site hands out for one device (CVP-016, "Bundles"): the device list, the signed prekey,
 * one ML-KEM-768 prekey (one-time if any are left, else the last-resort one) and one X25519
 * one-time prekey if any are left. The site MUST give each one-time prekey out at most once.
 * This helper takes them from `published`, as a site would.
 */
export function takeBundle(deviceList, published, kid) {
  return {
    deviceList,
    device: kid,
    signed: published.signed,
    pq: published.pqOneTime.shift() || published.lastResort,
    oneTime: published.oneTime.shift() || null,
  };
}

/** Check a bundle: everything must chain back to the account key you trust. */
export function verifyBundle(bundle, { accountKey, minSeq = 0, now = Date.now() }) {
  const list = verifyDeviceList(bundle.deviceList, { accountKey, minSeq });
  const dev = list.devices.find((d) => d.kid === bundle.device);
  if (!dev) throw new SessionError("UNTRUSTED", "That device isn't on the account's device list");
  const check = (rec, type, { optional = false } = {}) => {
    if (!rec) {
      if (optional) return null;
      throw new SessionError("BAD_INPUT", `Bundle is missing a ${type} prekey`);
    }
    let body;
    try {
      body = verify(rec, (kid) => (kid === dev.kid ? dev.sign : null), { kinds: [PREKEY] });
    } catch (e) {
      throw new SessionError("UNTRUSTED", `Prekey: ${e.message}`);
    }
    if (body.device !== dev.kid || body.type !== type) throw new SessionError("UNTRUSTED", "Prekey is for a different device or of the wrong type");
    if (body.expires != null && body.expires < now) throw new SessionError("EXPIRED", "Prekey has expired");
    return body;
  };
  const signed = check(bundle.signed, "x25519");
  if (signed.oneTime) throw new SessionError("BAD_INPUT", "Signed prekey must not be one-time");
  const pq = check(bundle.pq, "ml-kem-768");
  if (!pq.oneTime && !pq.lastResort) throw new SessionError("BAD_INPUT", "ML-KEM prekey must be one-time or last-resort");
  const oneTime = check(bundle.oneTime, "x25519", { optional: true });
  if (oneTime && !oneTime.oneTime) throw new SessionError("BAD_INPUT", "One-time prekey isn't marked one-time");
  return { list, device: dev, signed, pq, oneTime };
}

/** A stable fingerprint of a device list (for logs and UIs, never for trust). */
export const deviceListId = (record) => sha256B64u(canonicalBytes(record.body)).slice(0, 22);

