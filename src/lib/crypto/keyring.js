// The account keyring: every version of an account's encryption (ECDH) and
// signing (ECDSA) key pair. All of an account's approved devices hold the same
// keyring. It leaves a device only sealed to another device's box key, or sealed
// to the account's recovery key (which only the 24-word phrase can open).
import { CryptoFormatError, fromB64, fromUtf8, utf8 } from "./encoding.js";
import {
  exportPkcs8,
  exportRaw,
  generateEcdh,
  generateEcdsa,
  openSealed,
  sealTo,
} from "./primitives.js";

export const KEYRING_FORMAT = "commonveil.keyring.v1";
const MAX_VERSIONS = 256;

export async function createKeyVersion(version) {
  if (!Number.isInteger(version) || version < 1) throw new Error("Invalid key version");
  const enc = await generateEcdh(true);
  const sig = await generateEcdsa(true);
  return {
    version,
    ecdh_priv: await exportPkcs8(enc.privateKey),
    ecdh_pub: await exportRaw(enc.publicKey),
    sign_priv: await exportPkcs8(sig.privateKey),
    sign_pub: await exportRaw(sig.publicKey),
    created_at: new Date().toISOString(),
  };
}

export function newKeyring(userId, firstVersion) {
  const keyring = { format: KEYRING_FORMAT, user_id: userId, versions: [firstVersion] };
  validateKeyring(keyring, userId);
  return keyring;
}

export function latestKey(keyring) {
  return keyring.versions[keyring.versions.length - 1];
}

export function keyForVersion(keyring, version) {
  return keyring.versions.find((v) => v.version === version) || null;
}

/** Returns a new keyring with one more key version appended. */
export function withVersion(keyring, keyVersion) {
  if (keyVersion.version !== latestKey(keyring).version + 1) {
    throw new Error("Key versions must increase by exactly one");
  }
  const next = { ...keyring, versions: [...keyring.versions, keyVersion] };
  validateKeyring(next, keyring.user_id);
  return next;
}

function isB64(value) {
  if (typeof value !== "string" || value.length === 0) return false;
  try {
    fromB64(value);
    return true;
  } catch {
    return false;
  }
}

export function validateKeyring(keyring, expectedUserId) {
  if (!keyring || typeof keyring !== "object" || keyring.format !== KEYRING_FORMAT) {
    throw new CryptoFormatError("Unknown keyring format");
  }
  if (typeof keyring.user_id !== "string" || keyring.user_id.length === 0) {
    throw new CryptoFormatError("Keyring has no owner");
  }
  if (expectedUserId && keyring.user_id !== expectedUserId) {
    throw new CryptoFormatError("Keyring belongs to a different account");
  }
  const versions = keyring.versions;
  if (!Array.isArray(versions) || versions.length === 0 || versions.length > MAX_VERSIONS) {
    throw new CryptoFormatError("Keyring has no keys");
  }
  // Versions are contiguous. After an account reset a keyring can start above 1.
  const first = versions[0].version;
  versions.forEach((v, i) => {
    if (!Number.isInteger(v.version) || v.version !== first + i) {
      throw new CryptoFormatError("Keyring versions are not contiguous");
    }
    for (const field of ["ecdh_priv", "ecdh_pub", "sign_priv", "sign_pub"]) {
      if (!isB64(v[field])) throw new CryptoFormatError(`Keyring version ${v.version} is missing ${field}`);
    }
  });
  return keyring;
}

export function serializeKeyring(keyring) {
  validateKeyring(keyring);
  return JSON.stringify(keyring);
}

export function parseKeyring(text, expectedUserId) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new CryptoFormatError("Keyring is not valid JSON");
  }
  return validateKeyring(parsed, expectedUserId);
}

/** Check each private key really belongs to its listed public key. */
export async function assertKeyringConsistent(keyring) {
  const subtle = globalThis.crypto.subtle;
  for (const v of keyring.versions) {
    const pairs = [
      [v.ecdh_priv, v.ecdh_pub, { name: "ECDH", namedCurve: "P-256" }, ["deriveBits"]],
      [v.sign_priv, v.sign_pub, { name: "ECDSA", namedCurve: "P-256" }, ["sign"]],
    ];
    for (const [priv, pub, alg, usages] of pairs) {
      const key = await subtle.importKey("pkcs8", fromB64(priv), alg, true, usages);
      const jwk = await subtle.exportKey("jwk", key);
      const raw = fromB64(pub);
      const x = fromB64(jwk.x.replace(/-/g, "+").replace(/_/g, "/").padEnd(44, "="));
      const y = fromB64(jwk.y.replace(/-/g, "+").replace(/_/g, "/").padEnd(44, "="));
      const matches =
        raw.length === 65 &&
        raw[0] === 4 &&
        x.every((b, i) => b === raw[1 + i]) &&
        y.every((b, i) => b === raw[33 + i]);
      if (!matches) throw new CryptoFormatError(`Keyring version ${v.version} has mismatched keys`);
    }
  }
}

export const deviceTransferContext = (userId, deviceId, version) =>
  `commonveil/keyring-to-device/v1|${userId}|${deviceId}|${version}`;

export const recoveryContext = (userId, version) => `commonveil/keyring-recovery/v1|${userId}|${version}`;

/** Seal the whole keyring to another device's box key (device linking and key rotation). */
export async function sealKeyringToDevice(keyring, device) {
  const version = latestKey(keyring).version;
  const sealed = await sealTo(
    device.box_pub,
    utf8(serializeKeyring(keyring)),
    deviceTransferContext(keyring.user_id, device.device_id, version),
  );
  return { keyring_version: version, sealed };
}

export async function openKeyringFromDevice({ boxPriv, boxPub, userId, deviceId, keyringVersion, sealed }) {
  const bytes = await openSealed(boxPriv, boxPub, sealed, deviceTransferContext(userId, deviceId, keyringVersion));
  const keyring = parseKeyring(fromUtf8(bytes), userId);
  if (latestKey(keyring).version !== keyringVersion) throw new CryptoFormatError("Keyring version mismatch");
  await assertKeyringConsistent(keyring);
  return keyring;
}

/** Seal the whole keyring to the account's recovery public key. */
export async function sealKeyringForRecovery(keyring, recoveryPub) {
  const version = latestKey(keyring).version;
  const sealed = await sealTo(recoveryPub, utf8(serializeKeyring(keyring)), recoveryContext(keyring.user_id, version));
  return { keyring_version: version, sealed };
}
