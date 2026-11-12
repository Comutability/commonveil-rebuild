// Signed objects: the one envelope every Secure Net record uses (CVP-001, CVP-002).
//
//   { kind, body, sig: { kid, alg: "Ed25519", value } }
//
// The signature covers "secure-net/<kind>/v1\n" followed by the canonical JSON of the body, so a
// signature made for one kind of record can never be replayed as another. A key's id (kid) is
// the hash of its public key, so a record names its signer without trusting anyone's directory.
import { ed25519 } from "@noble/curves/ed25519.js";
import { b64u, fromB64u, sha256B64u, utf8, concat } from "./bytes.js";
import { canonicalBytes, canonicalJson } from "./canonical.js";

export const ALG = "Ed25519";
const KIND = /^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$/;

export class SignatureError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "SignatureError";
    this.code = code;
  }
}

/** A key's id: the first 128 bits of the hash of its public key. */
export const keyId = (publicKey) => sha256B64u(fromB64u(publicKey)).slice(0, 22);

/** A new signing key. secretKey and publicKey are base64url. */
export function generateSigningKey() {
  const { secretKey, publicKey } = ed25519.keygen();
  const pub = b64u(publicKey);
  return { kid: keyId(pub), publicKey: pub, secretKey: b64u(secretKey) };
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
  const value = b64u(ed25519.sign(signingBytes(kind, body), fromB64u(key.secretKey)));
  return { kind, body, sig: { kid: key.kid, alg: ALG, value } };
}

/** A second signature over the same record (for records that need several signers). */
export function cosign(record, key) {
  const value = b64u(ed25519.sign(signingBytes(record.kind, record.body), fromB64u(key.secretKey)));
  return { kid: key.kid, alg: ALG, value };
}

/** Whether one signature over a record is good, given the signer's public key. */
export function checkSignature(record, sig, publicKey) {
  if (!sig || sig.alg !== ALG || typeof sig.value !== "string") return false;
  if (keyId(publicKey) !== sig.kid) return false;
  try {
    return ed25519.verify(fromB64u(sig.value), signingBytes(record.kind, record.body), fromB64u(publicKey));
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
