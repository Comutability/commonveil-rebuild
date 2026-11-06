// Passkeys (WebAuthn), checked with WebCrypto. Commonveil asks for no attestation (nothing that
// identifies the make of a device), so registering is reading the new key out of the
// authenticator's data, and signing in is checking a signature with it. Keys: ES256 (P-256),
// EdDSA (Ed25519) and RS256. The options made here are the JSON forms @simplewebauthn/browser
// (and navigator.credentials, via its helpers) expects.
import { b64url, fromB64url, sha256, utf8 } from "./crypto.ts";

const subtle = () => globalThis.crypto.subtle;
export const ALGS = [-8, -7, -257];

export class PasskeyError extends Error {}

// ---------- just enough CBOR ----------

function cbor(bytes: Uint8Array, start = 0): { value: any; end: number } {
  let i = start;
  const head = () => {
    const b = bytes[i++];
    const major = b >> 5;
    const info = b & 31;
    let n: number;
    if (info < 24) n = info;
    else if (info === 24) n = bytes[i++];
    else if (info === 25) { n = (bytes[i] << 8) | bytes[i + 1]; i += 2; }
    else if (info === 26) { n = ((bytes[i] << 24) >>> 0) + ((bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3]); i += 4; }
    else if (info === 27) { n = 0; for (let k = 0; k < 8; k += 1) n = n * 256 + bytes[i++]; }
    else throw new PasskeyError("Unsupported CBOR");
    return { major, info, n };
  };
  const read = (depth: number): any => {
    if (depth > 16 || i >= bytes.length) throw new PasskeyError("Bad CBOR");
    const { major, info, n } = head();
    switch (major) {
      case 0: return n;
      case 1: return -1 - n;
      case 2: { const v = bytes.slice(i, i + n); i += n; if (v.length !== n) throw new PasskeyError("Bad CBOR"); return v; }
      case 3: { const v = new TextDecoder().decode(bytes.slice(i, i + n)); i += n; return v; }
      case 4: { const a = []; for (let k = 0; k < n; k += 1) a.push(read(depth + 1)); return a; }
      case 5: { const m = new Map(); for (let k = 0; k < n; k += 1) { const key = read(depth + 1); m.set(key, read(depth + 1)); } return m; }
      case 7: return info === 20 ? false : info === 21 ? true : null;
      default: throw new PasskeyError("Unsupported CBOR");
    }
  };
  const value = read(0);
  return { value, end: i };
}

// ---------- authenticator data ----------

type AuthData = { rpIdHash: Uint8Array; flags: number; counter: number; credentialId?: Uint8Array; publicKey?: Uint8Array };

function parseAuthData(data: Uint8Array): AuthData {
  if (data.length < 37) throw new PasskeyError("Short authenticator data");
  const out: AuthData = { rpIdHash: data.slice(0, 32), flags: data[32], counter: ((data[33] << 24) >>> 0) + ((data[34] << 16) | (data[35] << 8) | data[36]) };
  if (out.flags & 0x40) {
    let i = 37 + 16;
    const len = (data[i] << 8) | data[i + 1];
    i += 2;
    out.credentialId = data.slice(i, i + len);
    i += len;
    const { end } = cbor(data, i);
    out.publicKey = data.slice(i, end);
  }
  return out;
}

const UP = 0x01;
const BE = 0x08;
const BS = 0x10;

// ---------- keys ----------

async function importCose(coseBytes: Uint8Array): Promise<{ key: CryptoKey; alg: number }> {
  const m: Map<number, any> = cbor(coseBytes).value;
  const kty = m.get(1);
  const alg = m.get(3);
  if (kty === 2 && alg === -7 && m.get(-1) === 1) {
    const key = await subtle().importKey("jwk", { kty: "EC", crv: "P-256", x: b64url(m.get(-2)), y: b64url(m.get(-3)), ext: true }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return { key, alg };
  }
  if (kty === 1 && alg === -8 && m.get(-1) === 6) {
    return { key: await subtle().importKey("raw", m.get(-2), { name: "Ed25519" }, false, ["verify"]), alg };
  }
  if (kty === 3 && alg === -257) {
    const key = await subtle().importKey("jwk", { kty: "RSA", n: b64url(m.get(-1)), e: b64url(m.get(-2)), alg: "RS256", ext: true }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    return { key, alg };
  }
  throw new PasskeyError("That kind of passkey isn't supported.");
}

/** ECDSA signatures come DER-encoded; WebCrypto wants r and s, 32 bytes each. */
function derToRaw(der: Uint8Array): Uint8Array {
  if (der[0] !== 0x30) throw new PasskeyError("Bad signature");
  let i = 2;
  const part = () => {
    if (der[i++] !== 0x02) throw new PasskeyError("Bad signature");
    const len = der[i++];
    let v = der.slice(i, i + len);
    i += len;
    while (v.length > 32 && v[0] === 0) v = v.slice(1);
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out;
  };
  const r = part();
  const s = part();
  const raw = new Uint8Array(64);
  raw.set(r);
  raw.set(s, 32);
  return raw;
}

async function verifySignature(coseKey: Uint8Array, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
  const { key, alg } = await importCose(coseKey);
  if (alg === -7) return subtle().verify({ name: "ECDSA", hash: "SHA-256" }, key, derToRaw(signature), data);
  if (alg === -8) return subtle().verify({ name: "Ed25519" }, key, signature, data);
  return subtle().verify({ name: "RSASSA-PKCS1-v1_5" }, key, signature, data);
}

// ---------- the browser's side ----------

/** Is this an origin a passkey for rpId may come from? Its own name or a subdomain, over HTTPS (or localhost). */
export function originFits(origin: string, rpId: string): boolean {
  try {
    const u = new URL(origin);
    const host = u.hostname.toLowerCase();
    const secure = u.protocol === "https:" || host === "localhost" || host.endsWith(".localhost");
    return secure && (host === rpId || host.endsWith(`.${rpId}`));
  } catch {
    return false;
  }
}

/** A safe passkey site name: what the app's page is on (checked against what's allowed). */
export function rpIdFor(origin: string, allowed: (host: string) => boolean): string {
  let host = "";
  try {
    host = new URL(origin).hostname.toLowerCase();
  } catch {
    host = "";
  }
  if (!host || !allowed(host)) throw new PasskeyError("Passkeys can't be used from this address.");
  return host;
}

function clientData(response: any, type: string, challenge: string, rpId: string) {
  let parsed: any;
  const raw = fromB64url(String(response?.response?.clientDataJSON || ""));
  try {
    parsed = JSON.parse(new TextDecoder().decode(raw));
  } catch {
    throw new PasskeyError("That passkey's answer couldn't be read.");
  }
  if (parsed.type !== type || parsed.challenge !== challenge || !originFits(String(parsed.origin || ""), rpId) || parsed.crossOrigin === true) {
    throw new PasskeyError("That passkey's answer wasn't for this sign-in.");
  }
  return raw;
}

export function registrationOptions({ rpId, rpName, userId, userName, challenge, exclude, kind }: { rpId: string; rpName: string; userId: string; userName: string; challenge: string; exclude: { id: string; transports?: string[] }[]; kind: "device" | "synced" }) {
  return {
    challenge,
    rp: { id: rpId, name: rpName },
    user: { id: b64url(utf8(userId)), name: userName, displayName: userName },
    pubKeyCredParams: ALGS.map((alg) => ({ type: "public-key", alg })),
    timeout: 300_000,
    attestation: "none",
    excludeCredentials: exclude.map((c) => ({ type: "public-key", id: c.id, transports: c.transports || [] })),
    authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "preferred", ...(kind === "device" ? { authenticatorAttachment: "platform" } : {}) },
    ...(kind === "device" ? { hints: ["client-device"] } : {}),
    extensions: { credProps: true },
  };
}

export function authenticationOptions({ rpId, challenge, allow }: { rpId: string; challenge: string; allow: { id: string; transports?: string[] }[] }) {
  return { challenge, rpId, timeout: 300_000, userVerification: "preferred", allowCredentials: allow.map((c) => ({ type: "public-key", id: c.id, transports: c.transports || [] })) };
}

/** A new passkey's answer. Answers what to store about it. */
export async function verifyRegistration(response: any, { challenge, rpId }: { challenge: string; rpId: string }) {
  clientData(response, "webauthn.create", challenge, rpId);
  let att: Map<string, any>;
  try {
    att = cbor(fromB64url(String(response?.response?.attestationObject || ""))).value;
  } catch {
    throw new PasskeyError("That passkey couldn't be read.");
  }
  const auth = parseAuthData(att.get("authData"));
  if (b64url(auth.rpIdHash) !== b64url(await sha256(rpId))) throw new PasskeyError("That passkey is for another site.");
  if (!(auth.flags & UP) || !auth.credentialId || !auth.publicKey) throw new PasskeyError("That passkey couldn't be added.");
  const id = b64url(auth.credentialId);
  if (response.id !== id) throw new PasskeyError("That passkey's answer didn't match.");
  const { alg } = await importCose(auth.publicKey);
  const transports = Array.isArray(response?.response?.transports) ? response.response.transports.filter((t: unknown) => typeof t === "string").slice(0, 6) : [];
  return { credentialId: id, publicKey: b64url(auth.publicKey), alg, counter: auth.counter, synced: Boolean(auth.flags & BE), transports };
}

/** A passkey's answer when signing in. Answers its new counter and whether it's synced. */
export async function verifyAssertion(response: any, { challenge, rpId }: { challenge: string; rpId: string }, stored: { public_key: string; counter: number }) {
  const raw = clientData(response, "webauthn.get", challenge, rpId);
  const data = fromB64url(String(response?.response?.authenticatorData || ""));
  const auth = parseAuthData(data);
  if (b64url(auth.rpIdHash) !== b64url(await sha256(rpId))) throw new PasskeyError("That passkey is for another site.");
  if (!(auth.flags & UP)) throw new PasskeyError("The passkey prompt wasn't answered.");
  const signed = new Uint8Array(data.length + 32);
  signed.set(data);
  signed.set(await sha256(raw), data.length);
  const ok = await verifySignature(fromB64url(stored.public_key), fromB64url(String(response?.response?.signature || "")), signed).catch(() => false);
  if (!ok) throw new PasskeyError("That passkey didn't work. Try again.");
  // A counter that goes backwards means the passkey may have been copied.
  if (auth.counter > 0 && stored.counter > 0 && auth.counter <= stored.counter) throw new PasskeyError("That passkey looks like a copy. Remove it and add it again.");
  return { counter: auth.counter, synced: Boolean(auth.flags & BS) || Boolean(auth.flags & BE) };
}
