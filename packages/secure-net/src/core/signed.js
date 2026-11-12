// Signed objects: the one envelope every Secure Net record uses (CVP-001, CVP-002).
//
//   { kind, body, sig: { kid, alg: "Ed25519", value } }
//
// The signature covers "secure-net/<kind>/v1\n" followed by the canonical JSON of the body, so a
// signature made for one kind of record can never be replayed as another. A key's id (kid) is
// the hash of its public key, so a record names its signer without trusting anyone's directory.
import { ed25519 } from "@noble/curves/ed25519.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { b64u, fromB64u, sha256B64u, utf8, concat } from "./bytes.js";
import { canonicalBytes, canonicalJson } from "./canonical.js";

export const ALG = "Ed25519";
/**
 * Quantum-resistant keys sign twice: Ed25519 and ML-DSA-65 (FIPS 204). Both must verify, so a
 * record stays trustworthy unless both are broken. Such a key's public form is
 * "<Ed25519>.<ML-DSA-65>", and its id covers both halves.
 */
export const HYBRID_ALG = "Ed25519+ML-DSA-65";
const isHybrid = (key) => typeof key === "string" && key.includes(".");
const KIND = /^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$/;

export class SignatureError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "SignatureError";
    this.code = code;
  }
}

/** A key's id: the first 128 bits of the hash of its public key. */
export const keyId = (publicKey) => sha256B64u(isHybrid(publicKey) ? utf8(publicKey) : fromB64u(publicKey)).slice(0, 22);

/** A new signing key. secretKey and publicKey are base64url. */
export function generateSigningKey({ pq = false } = {}) {
  const { secretKey, publicKey } = ed25519.keygen();
  let pub = b64u(publicKey);
  let secret = b64u(secretKey);
  if (pq) {
    const seed = globalThis.crypto.getRandomValues(new Uint8Array(32));
    pub = `${pub}.${b64u(ml_dsa65.keygen(seed).publicKey)}`;
    secret = `${secret}.${b64u(seed)}`;
  }
  return { kid: keyId(pub), publicKey: pub, secretKey: secret };
}

function signBytes(bytes, key) {
  const [edSecret, pqSeed] = key.secretKey.split(".");
  const value = b64u(ed25519.sign(bytes, fromB64u(edSecret)));
  if (!pqSeed) return { kid: key.kid, alg: ALG, value };
  return { kid: key.kid, alg: HYBRID_ALG, value, pq: b64u(ml_dsa65.sign(bytes, ml_dsa65.keygen(fromB64u(pqSeed)).secretKey)) };
}

/** The signing key for a 32-byte seed (for keys derived from something else, like a phrase). */
export function signingKeyFromSeed(seed) {
  const pub = b64u(ed25519.getPublicKey(seed));
  return { kid: keyId(pub), publicKey: pub, secretKey: b64u(seed) };
}

/** The exact bytes signed for a record of this kind. */
export function signingBytes(kind, body) {
  if (!KIND.test(kind)) throw new SignatureError("BAD_KIND", `"${kind}" isn't a record kind`);
  return concat(utf8(`secure-net/${kind}/v1\n`), canonicalBytes(body));
}

/** Sign a record. */
export function sign(kind, body, key) {
  return { kind, body, sig: signBytes(signingBytes(kind, body), key) };
}

/** A second signature over the same record (for records that need several signers). */
export function cosign(record, key) {
  return signBytes(signingBytes(record.kind, record.body), key);
}

/** Whether one signature over a record is good, given the signer's public key. */
export function checkSignature(record, sig, publicKey) {
  if (!sig || typeof sig.value !== "string" || typeof publicKey !== "string") return false;
  if (keyId(publicKey) !== sig.kid) return false;
  const [edPub, pqPub] = publicKey.split(".");
  // The key decides what's required, never the signature: a quantum-resistant key's records
  // need both signatures, so stripping one doesn't make a classical-only record.
  if (sig.alg !== (pqPub ? HYBRID_ALG : ALG)) return false;
  try {
    const bytes = signingBytes(record.kind, record.body);
    if (!ed25519.verify(fromB64u(sig.value), bytes, fromB64u(edPub))) return false;
    return pqPub ? typeof sig.pq === "string" && ml_dsa65.verify(fromB64u(sig.pq), bytes, fromB64u(pqPub)) : true;
  } catch {
    return false;
  }
}

/**
 * Verify a record. keyFor(kid) returns the public key for an id, or nothing if it isn't trusted
 * for this purpose. kinds, when given, is the list of kinds the caller is prepared to accept.
 */
export function verify(record, keyFor, { kinds } = {}) {
  if (!record || typeof record !== "object" || !record.sig) throw new SignatureError("MALFORMED", "Not a signed record");
  if (kinds && !kinds.includes(record.kind)) throw new SignatureError("WRONG_KIND", `Expected ${kinds.join(" or ")}, got ${record.kind}`);
  const pub = keyFor(record.sig.kid);
  if (!pub) throw new SignatureError("UNKNOWN_SIGNER", "Signed by a key that isn't trusted here");
  if (!checkSignature(record, record.sig, pub)) throw new SignatureError("BAD_SIGNATURE", "The signature doesn't match");
  return record.body;
}

/** A record's id: the hash of its canonical form, signature included. */
export const recordId = (record) => sha256B64u(canonicalJson({ kind: record.kind, body: record.body, sig: record.sig, cosigs: record.cosigs }));
