// Byte helpers shared by the protocol modules. base64url without padding is the wire form.
import { sha256 } from "@noble/hashes/sha2.js";

export const utf8 = (s) => new TextEncoder().encode(s);

export function b64u(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 1) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64u(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) throw new TypeError("not base64url");
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

export const sha256B64u = (bytes) => b64u(sha256(typeof bytes === "string" ? utf8(bytes) : bytes));

export function randomB64u(n = 16) {
  return b64u(globalThis.crypto.getRandomValues(new Uint8Array(n)));
}

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** Constant-time comparison of two byte strings. */
export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i += 1) d |= a[i] ^ b[i];
  return d === 0;
}
