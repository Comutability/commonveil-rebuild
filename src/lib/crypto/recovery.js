// 24-word recovery phrase (standard BIP-39 English wordlist, 256 bits of entropy).
// The phrase deterministically derives a P-256 recovery key pair. Devices seal the
// keyring to the public half; only someone holding the phrase can open it.
// The phrase itself is never stored or sent anywhere.
import { p256 } from "@noble/curves/nist.js";
import { generateMnemonic, mnemonicToEntropy, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { CryptoFormatError, fromB64, fromUtf8, toB64, utf8 } from "./encoding.js";
import { aesDecrypt, hkdfBytes, parseSealed, sealedKeyFromSecret } from "./primitives.js";
import { assertKeyringConsistent, latestKey, parseKeyring, recoveryContext } from "./keyring.js";

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

/** Derive the recovery key pair. Same phrase, same key, on any device. */
export async function deriveRecoveryKey(phrase) {
  const words = phraseWords(phrase);
  if (words.length !== RECOVERY_WORD_COUNT || !validateMnemonic(words.join(" "), wordlist)) {
    throw new RecoveryError("INVALID_PHRASE", "That recovery phrase isn't valid. Check each word and the order.");
  }
  const entropy = mnemonicToEntropy(words.join(" "), wordlist);
  const salt = utf8("commonveil/recovery/v1");
  try {
    for (let counter = 0; counter < 8; counter += 1) {
      const secret = await hkdfBytes(entropy, salt, `p256-secret|${counter}`, 32);
      if (p256.utils.isValidSecretKey(secret)) {
        return { secret, publicKey: toB64(p256.getPublicKey(secret, false)) };
      }
    }
  } finally {
    entropy.fill(0);
  }
  throw new RecoveryError("DERIVATION_FAILED", "Could not derive a recovery key.");
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

export async function openKeyringWithPhrase({ phrase, userId, keyringVersion, recoveryPub, sealed }) {
  const { secret, publicKey } = await deriveRecoveryKey(phrase);
  try {
    if (publicKey !== recoveryPub) {
      throw new RecoveryError("WRONG_PHRASE", "That phrase is valid, but it isn't the recovery phrase for this account.");
    }
    let bytes;
    try {
      bytes = await openWithRecoverySecret(secret, recoveryPub, sealed, recoveryContext(userId, keyringVersion));
    } catch {
      throw new RecoveryError("BACKUP_UNREADABLE", "The encrypted backup could not be opened with this phrase.");
    }
    const keyring = parseKeyring(fromUtf8(bytes), userId);
    if (latestKey(keyring).version !== keyringVersion) throw new CryptoFormatError("Keyring version mismatch");
    await assertKeyringConsistent(keyring);
    return keyring;
  } finally {
    secret.fill(0);
  }
}
