// Small cryptographic helpers for Commonveil sign-in, on WebCrypto only, so the same code runs on
// Base44 (Deno) and on self-hosted sites (Node).
const subtle = () => globalThis.crypto.subtle;
const enc = new TextEncoder();

export const utf8 = (s: string) => enc.encode(s);

export function b64url(bytes: Uint8Array | ArrayBuffer): string {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (let i = 0; i < b.length; i += 1) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64url(s: string): Uint8Array {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("bad base64url");
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

export function randomToken(bytes = 32): string {
  const b = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(b);
  return b64url(b);
}

export async function sha256(data: Uint8Array | string): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest("SHA-256", typeof data === "string" ? utf8(data) : data));
}

export async function sha256Hex(data: string): Promise<string> {
  return [...(await sha256(data))].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/** Constant-time comparison of two strings. */
export function sameString(a: string, b: string): boolean {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export async function hmac(secret: string, text: string): Promise<string> {
  const key = await subtle().importKey("raw", utf8(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(await subtle().sign("HMAC", key, utf8(text)));
}

// ---------- passwords ----------

/** PBKDF2-SHA256, 600,000 rounds (OWASP's 2023 figure), 16-byte salt, 32-byte key. */
export const PASSWORD_ROUNDS = 600_000;

async function pbkdf2(password: string, salt: Uint8Array, rounds: number): Promise<Uint8Array> {
  const key = await subtle().importKey("raw", utf8(password.normalize("NFKC")), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await subtle().deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: rounds }, key, 256));
}

export async function hashPassword(password: string, rounds = PASSWORD_ROUNDS): Promise<string> {
  const salt = new Uint8Array(16);
  globalThis.crypto.getRandomValues(salt);
  return `pbkdf2-sha256$${rounds}$${b64url(salt)}$${b64url(await pbkdf2(password, salt, rounds))}`;
}

export async function checkPassword(password: string, stored: string): Promise<boolean> {
  const [kind, rounds, salt, want] = String(stored || "").split("$");
  if (kind !== "pbkdf2-sha256" || !Number(rounds)) {
    // Spend the same time on a missing or unusable hash.
    await pbkdf2(String(password || ""), new Uint8Array(16), PASSWORD_ROUNDS);
    return false;
  }
  const got = b64url(await pbkdf2(String(password || ""), fromB64url(salt), Number(rounds)));
  return sameString(got, want);
}

// ---------- signatures ----------

/** Ed25519: a 32-byte public key (base64url), a 64-byte signature (base64url). */
export async function verifyEd25519(publicKey: string, text: string, signature: string): Promise<boolean> {
  try {
    const key = await subtle().importKey("raw", fromB64url(publicKey), { name: "Ed25519" }, false, ["verify"]);
    return await subtle().verify({ name: "Ed25519" }, key, fromB64url(signature), utf8(text));
  } catch {
    return false;
  }
}
