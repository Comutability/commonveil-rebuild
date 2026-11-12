// The site-to-site wire format, for the hosted site's functions. The definition is Secure Net's
// (packages/secure-net/src/wire/federation.js); functions can't import it there (it uses npm
// packages by bare name), so this is the same thing on Web Crypto alone, and
// tests/hostedFederation.test.mjs checks the two agree byte for byte.

export const PROTOCOL = "commonveil/1";
export const SITE_DOCUMENT = "/.well-known/commonveil";
export const SKEW_MS = 5 * 60_000;
export const HOST_RE = /^(?=.{1,253}(:\d{1,5})?$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:\d{1,5})?$/;

export const DEFAULT_ENDPOINTS: Record<string, string> = Object.freeze({
  act: "/cvp/v1/act",
  directory: "/cvp/v1/directory",
  inbox: "/cvp/v1/inbox",
  discover: "/cvp/v1/discover",
  actors: "/cvp/v1/actors/{name}/{room}",
  identity: "/.well-known/commonveil/identity",
  files: "/api/files",
});

const ENDPOINT_RE = /^\/[A-Za-z0-9._~{}\/-]{0,199}$/;

export function endpointsOf(doc: any): Record<string, string> {
  const out = { ...DEFAULT_ENDPOINTS };
  const given = doc && typeof doc.endpoints === "object" && doc.endpoints ? doc.endpoints : {};
  for (const name of Object.keys(DEFAULT_ENDPOINTS)) {
    const v = given[name];
    if (typeof v === "string" && ENDPOINT_RE.test(v) && !v.includes("//") && !v.split("/").includes("..")) out[name] = v;
  }
  return out;
}

export function normHost(h: unknown): string | null {
  const v = String(h || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  return HOST_RE.test(v) ? v : null;
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

export function isPrivate(ip: string): boolean {
  const v = String(ip).toLowerCase().replace(/^\[|\]$/g, "");
  if (IPV4.test(v)) {
    const [a, b] = v.split(".").map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  if (v.startsWith("::ffff:")) return isPrivate(v.slice(7));
  return v === "::1" || v === "::" || v.startsWith("fc") || v.startsWith("fd") || v.startsWith("fe80") || v.startsWith("ff");
}

/**
 * Whether the hosted site may connect to this address at all: a public DNS name. Bare IP
 * addresses, single-label names and local names are refused. (A function can't check the
 * address a name resolves to at connect time, as a self-hosted site does; the platform's own
 * network rules are the second line.)
 */
export function reachable(host: string): boolean {
  const name = host.replace(/:\d+$/, "");
  if (!HOST_RE.test(host) || !name.includes(".")) return false;
  if (IPV4.test(name) || /^\d+$/.test(name.split(".").pop() || "")) return false;
  return !/(^|\.)(localhost|local|internal|lan|home|corp|intranet)$/.test(name);
}

export const b64u = (bytes: Uint8Array) => {
  let s = "";
  for (let i = 0; i < bytes.length; i += 1) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
export const fromB64u = (s: string) => Uint8Array.from(atob(String(s).replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const utf8 = (s: string) => new TextEncoder().encode(s);

export async function digestOf(body: string): Promise<string> {
  return `sha-256=${b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(body || ""))))}`;
}

export const signatureBase = ({ method, to, path, from, date, nonce, digest, user }: Record<string, string>) =>
  ["commonveil-request/v1", method.toUpperCase(), to, path, from, date, nonce, digest, user || "-"].join("\n");

/** A new site key: { public (raw, base64url), secret (PKCS#8, base64url) }. */
export async function generateSiteKey(): Promise<{ public: string; secret: string }> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" } as any, true, ["sign", "verify"])) as CryptoKeyPair;
  return {
    public: b64u(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))),
    secret: b64u(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))),
  };
}

export async function signText(secretPkcs8: string, text: string): Promise<string> {
  const key = await crypto.subtle.importKey("pkcs8", fromB64u(secretPkcs8), { name: "Ed25519" } as any, false, ["sign"]);
  return b64u(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" } as any, key, utf8(text))));
}

export async function verifyText(publicRaw: string, text: string, signature: string): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey("raw", fromB64u(publicRaw), { name: "Ed25519" } as any, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" } as any, key, fromB64u(signature), utf8(text));
  } catch {
    return false;
  }
}
