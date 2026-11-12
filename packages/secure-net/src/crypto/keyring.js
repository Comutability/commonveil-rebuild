// The account keyring: every version of an account's encryption (ECDH) and
// signing (ECDSA) key pair, and from November 2026 a post-quantum hybrid key pair
// (ML-KEM-768 + P-256, see kem.js) for each new version. All of an account's approved
// devices hold the same keyring. It leaves a device only sealed to another device's keys,
// or sealed to the account's recovery key (which only the 24-word phrase can open).
import { CryptoFormatError, fromB64, fromUtf8, utf8 } from "./encoding.js";
import {
  exportPkcs8,
  exportRaw,
  generateEcdh,
  generateEcdsa,
  openSealed,
  sealTo,
} from "./primitives.js";
import { KEM_PUBLIC_BYTES, KEM_SEED_BYTES, isKemSealed, kemKeygen, kemOpen, kemPublicFromSecret, kemSeal } from "./kem.js";

export const KEYRING_FORMAT = "commonveil.keyring.v1";
const MAX_VERSIONS = 256;

/** A new key version. Every new version has a post-quantum key as well as the classical pair. */
export async function createKeyVersion(version) {
  if (!Number.isInteger(version) || version < 1) throw new Error("Invalid key version");
  const enc = await generateEcdh(true);
  const sig = await generateEcdsa(true);
  const kem = kemKeygen();
  return {
    version,
    ecdh_priv: await exportPkcs8(enc.privateKey),
    ecdh_pub: await exportRaw(enc.publicKey),
    sign_priv: await exportPkcs8(sig.privateKey),
    sign_pub: await exportRaw(sig.publicKey),
    kem_priv: kem.kem_priv,
    kem_pub: kem.kem_pub,
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

function isB64(value, length) {
  if (typeof value !== "string" || value.length === 0) return false;
  try {
    const bytes = fromB64(value);
    return length === undefined || bytes.length === length;
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
    // Versions made before post-quantum keys have neither half; a version can't have just one.
    if (v.kem_priv !== undefined || v.kem_pub !== undefined) {
      if (!isB64(v.kem_priv, KEM_SEED_BYTES) || !isB64(v.kem_pub, KEM_PUBLIC_BYTES)) {
        throw new CryptoFormatError(`Keyring version ${v.version} has a malformed post-quantum key`);
      }
    }
  });
  return keyring;
}

/** True if this key version has a post-quantum key. */
export const hasKemKey = (keyVersion) => typeof keyVersion?.kem_pub === "string" && keyVersion.kem_pub.length > 0;

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
    if (hasKemKey(v) && kemPublicFromSecret(v.kem_priv) !== v.kem_pub) {
      throw new CryptoFormatError(`Keyring version ${v.version} has a mismatched post-quantum key`);
    }
  }
}

/**
 * Seal to a recipient: post-quantum when they have a post-quantum key (kemPub), classical
 * (ecdhPub) otherwise. Every caller passes only keys it has verified.
 */
export async function sealToRecipient({ ecdhPub, kemPub }, plaintext, context) {
  return kemPub ? kemSeal(kemPub, plaintext, context) : sealTo(ecdhPub, plaintext, context);
}

/** Open a value sealed with sealToRecipient, given the private halves (WebCrypto ECDH key, KEM seed). */
export async function openFromSender({ ecdhPriv, ecdhPub, kemPriv }, sealed, context) {
  if (isKemSealed(sealed)) {
    if (!kemPriv) throw new CryptoFormatError("Sealed to a post-quantum key this device doesn't have");
    return kemOpen(kemPriv, sealed, context);
  }
  return openSealed(ecdhPriv, ecdhPub, sealed, context);
}

export const deviceTransferContext = (userId, deviceId, version) =>
  `commonveil/keyring-to-device/v1|${userId}|${deviceId}|${version}`;

export const recoveryContext = (userId, version) => `commonveil/keyring-recovery/v1|${userId}|${version}`;

/**
 * Seal the whole keyring to another device (device linking and key rotation): to its
 * post-quantum key when kemPub is given (only ever a key the caller verified), else to its box key.
 */
export async function sealKeyringToDevice(keyring, device, kemPub = null) {
  const version = latestKey(keyring).version;
  const sealed = await sealToRecipient(
    { ecdhPub: device.box_pub, kemPub },
    utf8(serializeKeyring(keyring)),
    deviceTransferContext(keyring.user_id, device.device_id, version),
  );
  return { keyring_version: version, sealed };
}

export async function openKeyringFromDevice({ boxPriv, boxPub, kemPriv = null, userId, deviceId, keyringVersion, sealed }) {
  const bytes = await openFromSender({ ecdhPriv: boxPriv, ecdhPub: boxPub, kemPriv }, sealed, deviceTransferContext(userId, deviceId, keyringVersion));
  const keyring = parseKeyring(fromUtf8(bytes), userId);
  if (latestKey(keyring).version !== keyringVersion) throw new CryptoFormatError("Keyring version mismatch");
  await assertKeyringConsistent(keyring);
  return keyring;
}

/**
 * Seal the whole keyring to the account's recovery key: the phrase's post-quantum key when the
 * account has one (recoveryKemPub), otherwise its classical one.
 */
export async function sealKeyringForRecovery(keyring, recoveryPub, recoveryKemPub = "") {
  const version = latestKey(keyring).version;
  const sealed = await sealToRecipient(
    { ecdhPub: recoveryPub, kemPub: recoveryKemPub || null },
    utf8(serializeKeyring(keyring)),
    recoveryContext(keyring.user_id, version),
  );
  return { keyring_version: version, sealed };
}
