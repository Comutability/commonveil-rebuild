// Byte and text helpers shared by every crypto module.
// Plain ES module with relative imports only, so Node tests can load it directly.

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export class CryptoFormatError extends Error {
  constructor(message) {
    super(message);
    this.name = "CryptoFormatError";
  }
}

export function utf8(text) {
  if (typeof text !== "string") throw new TypeError("Expected a string");
  return textEncoder.encode(text);
}

export function fromUtf8(bytes) {
  return textDecoder.decode(bytes);
}

const B64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function toB64(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (let i = 0; i < view.length; i += 0x8000) {
    binary += String.fromCharCode(...view.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

export function fromB64(text) {
  if (typeof text !== "string" || !B64_RE.test(text)) {
    throw new CryptoFormatError("Invalid base64 value");
  }
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

export function toB64Url(bytes) {
  return toB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function randomBytes(length) {
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/** Random URL-safe identifier. 16 bytes (128 bits) by default. */
export function randomId(byteLength = 16) {
  return toB64Url(randomBytes(byteLength));
}

export function concatBytes(...parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

export async function sha256(bytes) {
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes));
}

export async function sha256B64(text) {
  return toB64(await sha256(utf8(text)));
}
