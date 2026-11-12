// 24-word recovery phrase (standard BIP-39 English wordlist, 256 bits of entropy).
// The phrase deterministically derives a P-256 recovery key pair. Devices seal the
// keyring to the public half; only someone holding the phrase can open it.
//
// Anyone can seal something to a public key, the server included, so the phrase also
// derives a second, secret "anchor" key. Key statements made while the phrase is to hand
// (first setup, a new phrase, a reset) carry an HMAC under it. On recovery, that HMAC is
// how the device knows the published keys, and so the backup, are really the account's.
// The phrase itself is never stored or sent anywhere.
//
// The phrase also derives a post-quantum key pair (ML-KEM-768 + P-256, see kem.js). Accounts
// set up, or given a new phrase, from November 2026 publish it, and their backup is sealed to it.
import { p256 } from "@noble/curves/nist.js";
import { generateMnemonic, mnemonicToEntropy, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { anchorText } from "./canonical.js";
import { CryptoFormatError, equalBytes, fromB64, fromUtf8, toB64, utf8 } from "./encoding.js";
import { aesDecrypt, hkdfBytes, parseSealed, sealedKeyFromSecret } from "./primitives.js";
import { assertKeyringConsistent, latestKey, parseKeyring, recoveryContext } from "./keyring.js";
import { isKemSealed, kemKeygen, kemOpen } from "./kem.js";

export const RECOVERY_WORD_COUNT = 24;

export class RecoveryError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = "RecoveryError";
    this.code = code;
  }
}

export function generateRecoveryPhrase() {
  return generateMnemonic(wordlist, 256);
}

export function normalizePhrase(input) {
  return String(input ?? "")
    .toLowerCase()
    .replace(/[^a-z]+/g, " ")
    .trim();
}

export function phraseWords(input) {
  const normalized = normalizePhrase(input);
  return normalized ? normalized.split(" ") : [];
}

export function isKnownWord(word) {
  return wordlist.includes(String(word || "").toLowerCase());
}

export function isValidPhrase(input) {
  const words = phraseWords(input);
  return words.length === RECOVERY_WORD_COUNT && validateMnemonic(words.join(" "), wordlist);
}

/**
 * Derive the recovery keys. Same phrase, same keys, on any device.
 * Returns { secret, publicKey, anchorKey, kemSecret, kemPublicKey }. Wipe them with wipeRecoveryKey after use.
 */
export async function deriveRecoveryKey(phrase) {
  const words = phraseWords(phrase);
  if (words.length !== RECOVERY_WORD_COUNT || !validateMnemonic(words.join(" "), wordlist)) {
    throw new RecoveryError("INVALID_PHRASE", "That recovery phrase isn't valid. Check each word and the order.");
  }
  const entropy = mnemonicToEntropy(words.join(" "), wordlist);
  const salt = utf8("commonveil/recovery/v1");
  try {
    const anchorKey = await hkdfBytes(entropy, salt, "anchor-hmac", 32);
    const kemSeed = await hkdfBytes(entropy, salt, "mlkem768-p256-seed", 32);
    const kem = kemKeygen(kemSeed);
    kemSeed.fill(0);
    for (let counter = 0; counter < 8; counter += 1) {
      const secret = await hkdfBytes(entropy, salt, `p256-secret|${counter}`, 32);
      if (p256.utils.isValidSecretKey(secret)) {
        return { secret, publicKey: toB64(p256.getPublicKey(secret, false)), anchorKey, kemSecret: kem.kem_priv, kemPublicKey: kem.kem_pub };
      }
    }
    anchorKey.fill(0);
  } finally {
    entropy.fill(0);
  }
  throw new RecoveryError("DERIVATION_FAILED", "Could not derive a recovery key.");
}

export function wipeRecoveryKey(keys) {
  keys?.secret?.fill(0);
  keys?.anchorKey?.fill(0);
  if (keys) keys.kemSecret = null;
}

async function anchorHmac(anchorKey, statement) {
  const key = await globalThis.crypto.subtle.importKey("raw", anchorKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await globalThis.crypto.subtle.sign("HMAC", key, utf8(anchorText(statement))));
}

/** The anchor for a key statement made while the phrase is to hand. */
export async function recoveryAnchorMac(anchorKey, statement) {
  return toB64(await anchorHmac(anchorKey, statement));
}

/** True if this statement was made by someone holding the phrase these keys came from. */
export async function verifyRecoveryAnchor(anchorKey, statement) {
  if (typeof statement?.recovery_mac !== "string" || !statement.recovery_mac) return false;
  let given;
  try {
    given = fromB64(statement.recovery_mac);
  } catch {
    return false;
  }
  return equalBytes(await anchorHmac(anchorKey, statement), given);
}

/** Open a value sealed (with primitives.sealTo) to the recovery public key. */
export async function openWithRecoverySecret(secret, recoveryPubB64, sealed, context) {
  const { epk, iv, ct } = parseSealed(sealed);
  const point = p256.getSharedSecret(secret, epk, true); // compressed point: 0x02|0x03 then x
  const shared = point.slice(1);
  const key = await sealedKeyFromSecret(shared, epk, fromB64(recoveryPubB64), context);
  shared.fill(0);
  return aesDecrypt(key, iv, ct, utf8(context));
}

/**
 * Open the recovery backup with already-derived keys. On its own this proves nothing
 * about where the backup came from: check the published keys with verifyRecoveryAnchor
 * and the keyring against them (protocol.recoverWithPhrase does both). A backup sealed to
 * the phrase's post-quantum key opens with that; an older one with the classical key.
 */
export async function openKeyringWithRecoveryKey({ keys, userId, keyringVersion, recoveryPub, recoveryKemPub = "", sealed }) {
  if (keys.publicKey !== recoveryPub || (recoveryKemPub && keys.kemPublicKey !== recoveryKemPub)) {
    throw new RecoveryError("WRONG_PHRASE", "That phrase is valid, but it isn't the recovery phrase for this account.");
  }
  let bytes;
  try {
    const context = recoveryContext(userId, keyringVersion);
    bytes = isKemSealed(sealed) ? await kemOpen(keys.kemSecret, sealed, context) : await openWithRecoverySecret(keys.secret, recoveryPub, sealed, context);
  } catch {
    throw new RecoveryError("BACKUP_UNREADABLE", "The encrypted backup could not be opened with this phrase.");
  }
  const keyring = parseKeyring(fromUtf8(bytes), userId);
  if (latestKey(keyring).version !== keyringVersion) throw new CryptoFormatError("Keyring version mismatch");
  await assertKeyringConsistent(keyring);
  return keyring;
}

export async function openKeyringWithPhrase({ phrase, userId, keyringVersion, recoveryPub, sealed }) {
  const keys = await deriveRecoveryKey(phrase);
  try {
    return await openKeyringWithRecoveryKey({ keys, userId, keyringVersion, recoveryPub, sealed });
  } finally {
    wipeRecoveryKey(keys);
  }
}
