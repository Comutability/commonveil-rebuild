// Thin wrappers over WebCrypto. P-256 for ECDH and ECDSA, HKDF-SHA-256, AES-256-GCM.
import {
  CryptoFormatError,
  concatBytes,
  fromB64,
  randomBytes,
  toB64,
  utf8,
} from "./encoding.js";

const ECDH = { name: "ECDH", namedCurve: "P-256" };
const ECDSA = { name: "ECDSA", namedCurve: "P-256" };
const SIGN_ALG = { name: "ECDSA", hash: "SHA-256" };

const subtle = () => globalThis.crypto.subtle;

export class DecryptError extends Error {
  constructor(message = "Decryption failed") {
    super(message);
    this.name = "DecryptError";
  }
}

export function assertRawP256(raw) {
  if (!(raw instanceof Uint8Array) || raw.length !== 65 || raw[0] !== 4) {
    throw new CryptoFormatError("Invalid P-256 public key");
  }
}

export async function generateEcdh(extractable) {
  return subtle().generateKey(ECDH, extractable, ["deriveBits"]);
}

export async function generateEcdsa(extractable) {
  return subtle().generateKey(ECDSA, extractable, ["sign", "verify"]);
}

export async function exportRaw(publicKey) {
  return toB64(new Uint8Array(await subtle().exportKey("raw", publicKey)));
}

export async function exportPkcs8(privateKey) {
  return toB64(new Uint8Array(await subtle().exportKey("pkcs8", privateKey)));
}

export async function importEcdhPublic(b64) {
  const raw = fromB64(b64);
  assertRawP256(raw);
  return subtle().importKey("raw", raw, ECDH, true, []);
}

export async function importVerifyKey(b64) {
  const raw = fromB64(b64);
  assertRawP256(raw);
  return subtle().importKey("raw", raw, ECDSA, true, ["verify"]);
}

export async function importEcdhPrivate(pkcs8B64) {
  return subtle().importKey("pkcs8", fromB64(pkcs8B64), ECDH, false, ["deriveBits"]);
}

export async function importSignPrivate(pkcs8B64) {
  return subtle().importKey("pkcs8", fromB64(pkcs8B64), ECDSA, false, ["sign"]);
}

export async function ecdh(privateKey, publicKey) {
  return new Uint8Array(await subtle().deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256));
}

export async function hkdfBytes(ikm, salt, info, length = 32) {
  const base = await subtle().importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await subtle().deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info: utf8(info) },
    base,
    length * 8,
  );
  return new Uint8Array(bits);
}

export async function aesKeyFromBytes(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new CryptoFormatError("AES key must be 32 bytes");
  return subtle().importKey("raw", /** @type {BufferSource} */ (bytes), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function hkdfAesKey(ikm, salt, info) {
  return aesKeyFromBytes(await hkdfBytes(ikm, salt, info, 32));
}

export async function aesEncrypt(key, plaintext, aad) {
  const iv = randomBytes(12);
  const ct = await subtle().encrypt({ name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, key, plaintext);
  return { iv, ct: new Uint8Array(ct) };
}

export async function aesDecrypt(key, iv, ct, aad) {
  if (iv.length !== 12 || ct.length < 16) throw new DecryptError("Malformed ciphertext");
  try {
    const pt = await subtle().decrypt({ name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, key, ct);
    return new Uint8Array(pt);
  } catch {
    throw new DecryptError();
  }
}

export async function signBytes(privateKey, bytes) {
  return toB64(new Uint8Array(await subtle().sign(SIGN_ALG, privateKey, bytes)));
}

export async function verifyBytes(publicKey, signatureB64, bytes) {
  let sig;
  try {
    sig = fromB64(signatureB64);
  } catch {
    return false;
  }
  if (sig.length !== 64) return false;
  try {
    return await subtle().verify(SIGN_ALG, publicKey, sig, bytes);
  } catch {
    return false;
  }
}

export async function verifyWithRaw(publicKeyB64, signatureB64, text) {
  let key;
  try {
    key = await importVerifyKey(publicKeyB64);
  } catch {
    return false;
  }
  return verifyBytes(key, signatureB64, utf8(text));
}

/**
 * Seal bytes to a P-256 public key (ECIES: ephemeral ECDH, HKDF-SHA-256, AES-256-GCM).
 * `context` is used as both the HKDF info and the AEAD associated data, so a sealed
 * value only opens in the exact context it was made for.
 */
export async function sealTo(recipientPubB64, plaintext, context) {
  const recipientRaw = fromB64(recipientPubB64);
  assertRawP256(recipientRaw);
  const recipient = await subtle().importKey("raw", recipientRaw, ECDH, false, []);
  const eph = await generateEcdh(true);
  const epk = new Uint8Array(await subtle().exportKey("raw", eph.publicKey));
  const shared = await ecdh(eph.privateKey, recipient);
  const key = await hkdfAesKey(shared, concatBytes(epk, recipientRaw), context);
  const { iv, ct } = await aesEncrypt(key, plaintext, utf8(context));
  shared.fill(0);
  return { epk: toB64(epk), iv: toB64(iv), ct: toB64(ct) };
}

/** Derive the AES key for a sealed value from an already-computed ECDH secret. */
export async function sealedKeyFromSecret(sharedSecret, epkRaw, recipientRaw, context) {
  return hkdfAesKey(sharedSecret, concatBytes(epkRaw, recipientRaw), context);
}

export function parseSealed(sealed) {
  if (!sealed || typeof sealed !== "object") throw new CryptoFormatError("Missing sealed value");
  const epk = fromB64(sealed.epk);
  assertRawP256(epk);
  const iv = fromB64(sealed.iv);
  const ct = fromB64(sealed.ct);
  if (iv.length !== 12 || ct.length < 17) throw new CryptoFormatError("Malformed sealed value");
  return { epk, iv, ct };
}

/** Open a value sealed with sealTo, using a WebCrypto ECDH private key. */
export async function openSealed(privateKey, recipientPubB64, sealed, context) {
  const { epk, iv, ct } = parseSealed(sealed);
  const epkKey = await subtle().importKey("raw", epk, ECDH, false, []);
  const shared = await ecdh(privateKey, epkKey);
  const key = await sealedKeyFromSecret(shared, epk, fromB64(recipientPubB64), context);
  shared.fill(0);
  return aesDecrypt(key, iv, ct, utf8(context));
}
