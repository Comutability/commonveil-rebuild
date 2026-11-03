// Post-quantum hybrid sealing.
//
// MLKEM768-P256 (the CFRG "concrete hybrid KEM" pairing ML-KEM-768 with P-256, as implemented
// by @noble/post-quantum) gives a 32-byte shared secret that stays safe if either half does:
// ML-KEM-768 against a future quantum computer, P-256 against a flaw in the newer maths. It's
// used wherever something is sealed to someone's public key and then stored, so recorded
// traffic can't be opened later ("harvest now, decrypt later"): message keys, server key
// grants, keyrings sent to devices and the recovery backup.
//
// A key pair is a 32-byte seed (kept in the keyring, like the other private keys) and a
// 1249-byte public key. A sealed value is { kct, iv, ct }: the KEM ciphertext, then AES-256-GCM
// under HKDF(shared secret). The context string is the HKDF info and the AEAD associated data,
// so a sealed value only opens in the exact context it was made for, as with the classical
// seal in primitives.js (whose values carry `epk` instead of `kct`).
import { ml_kem768_p256 } from "@noble/post-quantum/hybrid.js";
import { CryptoFormatError, fromB64, toB64, utf8 } from "./encoding.js";
import { aesDecrypt, aesEncrypt, hkdfAesKey } from "./primitives.js";

export const KEM_NAME = "MLKEM768-P256";
export const KEM_PUBLIC_BYTES = 1249;
export const KEM_SEED_BYTES = 32;
export const KEM_CIPHERTEXT_BYTES = 1153;

const SALT = utf8("commonveil/kem-seal/v1");

export class KemError extends Error {
  constructor(message = "Couldn't open this sealed value") {
    super(message);
    this.name = "KemError";
  }
}

function bytesOf(b64, length, what) {
  let bytes;
  try {
    bytes = fromB64(b64);
  } catch {
    throw new CryptoFormatError(`Invalid ${what}`);
  }
  if (bytes.length !== length) throw new CryptoFormatError(`Invalid ${what}`);
  return bytes;
}

/** True for a string that decodes to a hybrid public key of the right size. */
export function isKemPublic(b64) {
  try {
    bytesOf(b64, KEM_PUBLIC_BYTES, "post-quantum key");
    return true;
  } catch {
    return false;
  }
}

/** A new key pair. A 32-byte seed always gives the same pair (used for the recovery phrase's). */
export function kemKeygen(seed) {
  const { publicKey, secretKey } = ml_kem768_p256.keygen(seed);
  try {
    return { kem_pub: toB64(publicKey), kem_priv: toB64(secretKey) };
  } finally {
    secretKey.fill(0);
  }
}

/** The public key for a seed: lets a keyring check its private and public halves belong together. */
export function kemPublicFromSecret(kemPrivB64) {
  const seed = bytesOf(kemPrivB64, KEM_SEED_BYTES, "post-quantum secret");
  try {
    return toB64(ml_kem768_p256.getPublicKey(seed));
  } finally {
    seed.fill(0);
  }
}

/** Seal bytes to a hybrid public key. */
export async function kemSeal(kemPubB64, plaintext, context) {
  const publicKey = bytesOf(kemPubB64, KEM_PUBLIC_BYTES, "post-quantum key");
  const { cipherText, sharedSecret } = ml_kem768_p256.encapsulate(publicKey);
  try {
    const key = await hkdfAesKey(sharedSecret, SALT, context);
    const { iv, ct } = await aesEncrypt(key, plaintext, utf8(context));
    return { kct: toB64(cipherText), iv: toB64(iv), ct: toB64(ct) };
  } finally {
    sharedSecret.fill(0);
  }
}

export function isKemSealed(sealed) {
  return Boolean(sealed && typeof sealed === "object" && typeof sealed.kct === "string");
}

/** Open a value sealed with kemSeal, using the 32-byte seed. Throws KemError if it doesn't open. */
export async function kemOpen(kemPrivB64, sealed, context) {
  if (!isKemSealed(sealed)) throw new KemError("Not a post-quantum sealed value");
  let seed;
  let sharedSecret;
  try {
    const kct = bytesOf(sealed.kct, KEM_CIPHERTEXT_BYTES, "post-quantum ciphertext");
    const iv = fromB64(sealed.iv);
    const ct = fromB64(sealed.ct);
    seed = bytesOf(kemPrivB64, KEM_SEED_BYTES, "post-quantum secret");
    sharedSecret = ml_kem768_p256.decapsulate(kct, seed);
    const key = await hkdfAesKey(sharedSecret, SALT, context);
    return await aesDecrypt(key, iv, ct, utf8(context));
  } catch {
    throw new KemError();
  } finally {
    seed?.fill(0);
    sharedSecret?.fill(0);
  }
}
