// The owner key: proof that an account is yours (docs/IDENTITY.md).
//
// The 24-word recovery phrase is 256 bits of entropy. The private key is the same 256 bits in one
// string ("cvkey1…", with a checksum), so either can stand in for the other: keep whichever is
// easier to store. Both derive an Ed25519 owner key. The site keeps its public half; signing a
// challenge with the private half proves the account is yours, for confirming a new device or
// getting back in without a password. Neither the phrase nor the key is ever sent anywhere.
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { fromB64, toB64Url, utf8 } from "./encoding.js";
import { hkdfBytes } from "./primitives.js";
import { RECOVERY_WORD_COUNT, phraseWords } from "./recovery.js";

const PREFIX = "cvkey1";

export class OwnerKeyError extends Error {
  constructor(message) {
    super(message);
    this.name = "OwnerKeyError";
  }
}

const fromB64Url = (s) => fromB64(String(s).replace(/-/g, "+").replace(/_/g, "/") + "===".slice((String(s).length + 3) % 4));

/** The private key for a recovery phrase. */
export function privateKeyFromPhrase(phrase) {
  const entropy = entropyOf(phrase);
  try {
    return PREFIX + toB64Url(new Uint8Array([...entropy, ...sha256(entropy).slice(0, 4)]));
  } finally {
    entropy.fill(0);
  }
}

/** The recovery phrase for a private key. */
export function phraseFromPrivateKey(key) {
  const entropy = entropyOf(key);
  try {
    return entropyToMnemonic(entropy, wordlist);
  } finally {
    entropy.fill(0);
  }
}

export function looksLikePrivateKey(input) {
  return String(input || "").trim().startsWith(PREFIX);
}

/** The 32 bytes behind a phrase or a private key. Throws OwnerKeyError with a readable message. */
function entropyOf(input) {
  const text = String(input || "").trim();
  if (looksLikePrivateKey(text)) {
    let raw;
    try {
      raw = fromB64Url(text.slice(PREFIX.length));
    } catch {
      raw = new Uint8Array(0);
    }
    const entropy = raw.slice(0, 32);
    const check = sha256(entropy).slice(0, 4);
    if (raw.length !== 36 || check.some((b, i) => b !== raw[32 + i])) throw new OwnerKeyError("That private key isn't valid. Check it was copied whole.");
    return entropy;
  }
  const words = phraseWords(text);
  if (words.length !== RECOVERY_WORD_COUNT || !validateMnemonic(words.join(" "), wordlist)) throw new OwnerKeyError("That recovery phrase isn't valid. Check each word and the order.");
  return mnemonicToEntropy(words.join(" "), wordlist);
}

/** The owner key for a phrase or private key: { secret, publicKey } (publicKey base64url). */
export async function ownerKey(input) {
  const entropy = entropyOf(input);
  try {
    const secret = await hkdfBytes(entropy, utf8("commonveil/owner/v1"), "ed25519", 32);
    return { secret, publicKey: toB64Url(ed25519.getPublicKey(secret)) };
  } finally {
    entropy.fill(0);
  }
}

/** What a signature covers; the server checks the same text (server/auth.mjs). */
export const ownerText = (host, purpose, challenge) => `commonveil-owner/v1\n${host}\n${purpose}\n${challenge}`;

/** Sign a site's challenge. purpose: "set-owner", "verify-device" or "recover". */
export function signOwner(key, { host, purpose, challenge }) {
  return toB64Url(ed25519.sign(utf8(ownerText(host, purpose, challenge)), key.secret));
}

export function wipeOwnerKey(key) {
  key?.secret?.fill(0);
}
