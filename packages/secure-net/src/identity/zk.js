// Zero-knowledge ownership proofs (CVP-001).
//
// A signature proves you hold a key, but the same signature is the same bytes everywhere: two
// sites can put their copies side by side and see one person. A proof here says only "the holder
// of this public key is behind this" and nothing else. It is a Schnorr proof of knowledge over
// Ed25519's group (Fiat–Shamir, so it needs no round trip): the verifier learns that whoever made
// it knows the private half, and learns nothing about the key's owner, where else it was used, or
// what was proved before. Each proof is bound to a context (a site, a purpose, a record digest),
// so a proof made for one place cannot be shown at another.
//
// The proof itself is classical. It is only ever used together with a quantum-resistant
// signature (Ed25519 + ML-DSA-65, see ../core/signed.js): both must verify, so a quantum computer
// that could forge the proof alone still cannot mint a passport.
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { b64u, fromB64u, utf8, concat } from "../core/bytes.js";
import { canonicalBytes } from "../core/canonical.js";

export const ZK_ALG = "Ed25519-Schnorr";
export const OWNER_PROOF = "identity.owner-proof";

// The group's order: 2^252 + 27742317777372353535851937790883648493.
const ORDER = 2n ** 252n + 27742317777372353535851937790883648493n;
const Point = ed25519.Point;

export class ZkError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ZkError";
    this.code = code;
  }
}

/** The scalar an Ed25519 secret seed signs with (SHA-512, clamped), as published. */
function scalarOf(seed) {
  const h = sha512(seed);
  const a = h.slice(0, 32);
  a[0] &= 248;
  a[31] &= 127;
  a[31] |= 64;
  let x = 0n;
  for (let i = 31; i >= 0; i -= 1) x = (x << 8n) | BigInt(a[i]);
  return x % ORDER;
}

const scalarBytes = (n) => {
  const out = new Uint8Array(32);
  let v = n % ORDER;
  for (let i = 0; i < 32; i += 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
};

const scalarFromB64 = (s) => {
  const raw = fromB64u(s);
  if (raw.length !== 32) throw new ZkError("MALFORMED", "A proof scalar must be 32 bytes");
  let v = 0n;
  for (let i = 31; i >= 0; i -= 1) v = (v << 8n) | BigInt(raw[i]);
  return v;
};

function randomScalar() {
  for (;;) {
    const x = scalarFromB64(b64u(globalThis.crypto.getRandomValues(new Uint8Array(32))));
    if (x > 0n && x < ORDER) return x;
  }
}

/** The challenge: the hash of the statement and the context, reduced to the group's order. */
function challengeOf(R, Y, context) {
  const bytes = sha512(concat(utf8(`secure-net/${OWNER_PROOF}/v1\n`), canonicalBytes({ R, Y, context: context || {} })));
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) v = (v << 8n) | BigInt(bytes[i]);
  return v % ORDER;
}

/**
 * Prove the holder of `secret` (an Ed25519 seed, as seed bytes) is behind `publicKey`.
 * context names what's being proved and where, e.g. { purpose, handle, digest, site }.
 * Answers a proof that travels in the record it's about.
 */
export function proveOwner(secret, publicKey, context = {}) {
  if (!(secret instanceof Uint8Array) || secret.length !== 32) throw new ZkError("BAD_KEY", "A proof needs the owner's 32-byte secret");
  const x = scalarOf(secret);
  const Y = b64u(Point.BASE.multiply(x).toBytes());
  if (publicKey && publicKey !== Y) throw new ZkError("WRONG_KEY", "That secret doesn't belong to that public key");
  const r = randomScalar();
  const R = b64u(Point.BASE.multiply(r).toBytes());
  const c = challengeOf(R, Y, context);
  const s = (r + c * x) % ORDER;
  return { alg: ZK_ALG, Y, R, s: b64u(scalarBytes(s)), context: context || {} };
}

/**
 * Whether a proof shows the holder of `publicKey` is behind it, for this context. Reveals nothing:
 * the answer is a boolean, and the proof can't be reused anywhere else.
 */
export function checkOwnerProof(proof, publicKey, context = {}) {
  if (!proof || proof.alg !== ZK_ALG || typeof proof.R !== "string" || typeof proof.s !== "string") return false;
  const Y = proof.Y;
  if (typeof publicKey === "string" && publicKey !== Y) return false;
  try {
    // The context is part of what was proved: a proof for one place isn't a proof for another.
    const c = challengeOf(proof.R, Y, context || {});
    const s = scalarFromB64(proof.s);
    if (s <= 0n || s >= ORDER) return false;
    const left = Point.BASE.multiply(s);
    const right = Point.fromBytes(fromB64u(proof.R)).add(Point.fromBytes(fromB64u(Y)).multiply(c));
    return left.equals(right);
  } catch {
    return false;
  }
}