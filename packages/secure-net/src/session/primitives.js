// The primitives of the session protocol (CVP-016), in one place so the spec, the test vectors
// and the code can't drift apart.
//
//   X25519 (RFC 7748) and ML-KEM-768 (FIPS 203) for key agreement, always together;
//   HKDF-SHA-256 (RFC 5869) and HMAC-SHA-256 for derivation;
//   AES-256-GCM for encryption; Ed25519 + ML-DSA-65 (FIPS 204) for signatures (core/signed).
import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { b64u, fromB64u, utf8, concat } from "../core/bytes.js";
import { canonicalBytes } from "../core/canonical.js";

export const LABEL = "secure-net/session/v1";
/** Every purpose derived through info(). Registered in spec/registry.json; anything else is refused. */
export const PURPOSES = Object.freeze(["handshake", "transcript", "root", "message", "group", "history"]);
const info = (what) => {
  if (!PURPOSES.includes(what)) throw new Error(`"${LABEL}/${what}" isn't a registered label`);
  return utf8(`${LABEL}/${what}`);
};
const ZERO32 = new Uint8Array(32);

export const random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

export class SessionError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "SessionError";
    this.code = code;
  }
}

// ---- Key pairs, held as base64url so state can be stored as JSON ----

export function dhKeyPair(secret = x25519.utils.randomSecretKey()) {
  return { sk: b64u(secret), pk: b64u(x25519.getPublicKey(secret)) };
}

export function dh(sk, pk) {
  let out;
  try {
    out = x25519.getSharedSecret(fromB64u(sk), fromB64u(pk));
  } catch {
    throw new SessionError("BAD_KEY", "Not a usable X25519 key");
  }
  // An all-zero result means the peer sent a low-order point: refuse it (RFC 7748, section 6.1).
  if (out.every((b) => b === 0)) throw new SessionError("BAD_KEY", "Key agreement produced a weak result");
  return out;
}

export function kemKeyPair(seed = random(64)) {
  const { publicKey, secretKey } = ml_kem768.keygen(seed);
  return { sk: b64u(secretKey), pk: b64u(publicKey) };
}

/** Encapsulate to an ML-KEM-768 public key. Returns the ciphertext (base64url) and shared secret. */
const decode = (s, code, what) => {
  try {
    return fromB64u(s);
  } catch {
    throw new SessionError(code, `Not ${what}`);
  }
};

export function encapsulate(pk, coins) {
  const key = decode(pk, "BAD_KEY", "an ML-KEM-768 public key");
  if (key.length !== 1184) throw new SessionError("BAD_KEY", "Not an ML-KEM-768 public key");
  const { cipherText, sharedSecret } = coins ? ml_kem768.encapsulate(key, coins) : ml_kem768.encapsulate(key);
  return { ct: b64u(cipherText), ss: sharedSecret };
}

export function decapsulate(ct, sk) {
  const c = decode(ct, "BAD_MESSAGE", "an ML-KEM-768 ciphertext");
  if (c.length !== 1088) throw new SessionError("BAD_MESSAGE", "Not an ML-KEM-768 ciphertext");
  return ml_kem768.decapsulate(c, fromB64u(sk));
}

// ---- Derivations (spec/CVP-016, "Key schedule") ----

/** The handshake secret: 32 bytes of 0xFF, every X25519 output, then the ML-KEM secret. */
export function handshakeSecret(dhs, ss, transcriptHash) {
  return hkdf(sha256, concat(new Uint8Array(32).fill(0xff), ...dhs, ss), ZERO32, concat(info("handshake"), transcriptHash), 32);
}

/** One step of the root chain: mixes in an X25519 output and an ML-KEM secret (empty if none). */
export function kdfRoot(rk, dhOut, ss = new Uint8Array(0)) {
  const out = hkdf(sha256, concat(dhOut, ss), rk, info("root"), 64);
  return { rk: out.slice(0, 32), ck: out.slice(32) };
}

/** One step of a sending or receiving chain. */
export function kdfChain(ck) {
  return { mk: hmac(sha256, ck, Uint8Array.of(1)), ck: hmac(sha256, ck, Uint8Array.of(2)) };
}

/** A message key's AES-256-GCM key and nonce. Each message key is used once, so the nonce is fixed by it. */
export function messageKeys(mk, label = "message") {
  const out = hkdf(sha256, mk, ZERO32, info(label), 44);
  return { key: out.slice(0, 32), iv: out.slice(32) };
}

export const transcriptHash = (obj) => sha256(concat(info("transcript"), canonicalBytes(obj)));

// ---- AES-256-GCM ----

export async function seal(mk, plaintext, ad, label) {
  const { key, iv } = messageKeys(mk, label);
  const k = await globalThis.crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
  return new Uint8Array(await globalThis.crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: ad }, k, plaintext));
}

export async function open(mk, ciphertext, ad, label) {
  const { key, iv } = messageKeys(mk, label);
  const k = await globalThis.crypto.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
  try {
    return new Uint8Array(await globalThis.crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: ad }, k, ciphertext));
  } catch {
    throw new SessionError("DECRYPT_FAILED", "The message couldn't be decrypted");
  }
}

export const toBytes = (p) => (typeof p === "string" ? utf8(p) : p);
