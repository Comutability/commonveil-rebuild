// Signature and format checks done on the server. The server never holds a
// private key; it only verifies signatures and the shape of ciphertext.
import { ApiError, LIMITS, randomIdField, isoTime } from "./http.ts";
import {
  CONTEXTS,
  canonical,
  certText,
  chainGenerationFields,
  deviceKemFields,
  deviceProofFields,
  itemFields,
  keyGrantFields,
  serverItemFields,
  statementText,
} from "./canonical.ts";

/** Post-quantum hybrid keys (ML-KEM-768 + P-256, MLKEM768-P256): public key and ciphertext sizes. */
export const KEM_PUBLIC_BYTES = 1249;
export const KEM_CIPHERTEXT_BYTES = 1153;

const B64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function b64Bytes(value: unknown): Uint8Array | null {
  if (typeof value !== "string" || value.length === 0 || value.length > 200_000 || !B64_RE.test(value)) return null;
  const bin = atob(value);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

export async function sha256B64(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return bytesToB64(new Uint8Array(digest));
}

/** A real, on-curve, uncompressed P-256 public key. */
export async function isP256Key(value: unknown): Promise<boolean> {
  const raw = b64Bytes(value);
  if (!raw || raw.length !== 65 || raw[0] !== 4) return false;
  try {
    await crypto.subtle.importKey("raw", raw, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return true;
  } catch {
    return false;
  }
}

export async function requireP256Key(value: unknown, name: string): Promise<string> {
  if (!(await isP256Key(value))) throw new ApiError(400, "BAD_KEY", `Invalid ${name}.`);
  return value as string;
}

/**
 * A hybrid public key: ML-KEM-768's 1184 bytes, then an uncompressed P-256 point. The server can
 * check the point and the length; the ML-KEM half is checked by whoever encapsulates to it.
 */
export async function isKemKey(value: unknown): Promise<boolean> {
  const raw = b64Bytes(value);
  if (!raw || raw.length !== KEM_PUBLIC_BYTES) return false;
  return isP256Key(bytesToB64(raw.subarray(KEM_PUBLIC_BYTES - 65)));
}

export async function requireKemKey(value: unknown, name: string): Promise<string> {
  if (!(await isKemKey(value))) throw new ApiError(400, "BAD_KEY", `Invalid ${name}.`);
  return value as string;
}

/** "" when absent, else a valid hybrid key. */
async function optionalKemKey(value: unknown, name: string): Promise<string> {
  if (value === undefined || value === null || value === "") return "";
  return requireKemKey(value, name);
}

export async function verifySig(publicKeyB64: string, signatureB64: unknown, text: string): Promise<boolean> {
  const raw = b64Bytes(publicKeyB64);
  const sig = b64Bytes(signatureB64);
  if (!raw || raw.length !== 65 || !sig || sig.length !== 64) return false;
  try {
    const key = await crypto.subtle.importKey("raw", raw, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, new TextEncoder().encode(text));
  } catch {
    return false;
  }
}

// ---------- statements ----------

export async function parseStatement(raw: any, userId: string) {
  if (!raw || typeof raw !== "object") throw new ApiError(400, "BAD_STATEMENT", "Missing key statement.");
  if (raw.user_id !== userId) throw new ApiError(403, "WRONG_ACCOUNT", "That key statement is for a different account.");
  if (!Number.isInteger(raw.version) || raw.version < 1) throw new ApiError(400, "BAD_STATEMENT", "Invalid key version.");
  if (!Number.isInteger(raw.signed_by_version) || raw.signed_by_version < 1) throw new ApiError(400, "BAD_STATEMENT", "Invalid signer.");
  const statement = {
    user_id: userId,
    version: raw.version as number,
    ecdh_pub: await requireP256Key(raw.ecdh_pub, "encryption key"),
    sign_pub: await requireP256Key(raw.sign_pub, "signing key"),
    recovery_pub: await requireP256Key(raw.recovery_pub, "recovery key"),
    signed_by_version: raw.signed_by_version as number,
    issued_at: isoTime(raw.issued_at, "issued_at"),
    signature: typeof raw.signature === "string" ? raw.signature : "",
    recovery_mac: "",
    // Post-quantum keys (account-key/v2). A statement without one is the v1 form.
    kem_pub: await optionalKemKey(raw.kem_pub, "post-quantum key"),
    recovery_kem_pub: "",
  };
  if (statement.kem_pub) statement.recovery_kem_pub = await optionalKemKey(raw.recovery_kem_pub, "post-quantum recovery key");
  else if (raw.recovery_kem_pub) throw new ApiError(400, "BAD_STATEMENT", "A post-quantum recovery key needs a post-quantum account key.");
  // HMAC under a key only the recovery phrase produces. The server can't check it, only its shape.
  if (raw.recovery_mac !== undefined && raw.recovery_mac !== null && raw.recovery_mac !== "") {
    const mac = b64Bytes(raw.recovery_mac);
    if (!mac || mac.length !== 32) throw new ApiError(400, "BAD_STATEMENT", "Invalid recovery anchor.");
    statement.recovery_mac = raw.recovery_mac;
  }
  return statement;
}

/** Statements made with the phrase to hand (setup, reset, a new phrase) must carry its anchor. */
export function requireRecoveryAnchor(statement: any) {
  if (!statement.recovery_mac) throw new ApiError(400, "BAD_STATEMENT", "This key statement is missing its recovery anchor.");
}

export async function verifyStatement(statement: any, signerPub: string): Promise<boolean> {
  return verifySig(signerPub, statement.signature, statementText(statement));
}

// ---------- devices ----------

export async function parseDevice(raw: any) {
  if (!raw || typeof raw !== "object") throw new ApiError(400, "BAD_DEVICE", "Missing device.");
  const device: any = {
    device_id: randomIdField(raw.device_id, "device id"),
    label: typeof raw.label === "string" ? raw.label.replace(/[\u0000-\u001F\u007F]/g, "").trim().slice(0, 60) || "Device" : "Device",
    sign_pub: await requireP256Key(raw.sign_pub, "device signing key"),
    box_pub: await requireP256Key(raw.box_pub, "device box key"),
  };
  const kem = await optionalKemKey(raw.kem_pub, "device post-quantum key");
  if (kem) device.kem_pub = kem;
  return device;
}

/**
 * Certificate must name exactly these device keys and be signed by the given account key.
 * It may also cover the device's post-quantum key (device-cert/v2), which must then be the one
 * stored for the device. Returns the certificate with has_kem saying which form it is.
 */
export async function verifyCert(rawCert: any, userId: string, device: any, keyVersion: number, accountSignPub: string) {
  if (!rawCert || typeof rawCert !== "object") throw new ApiError(400, "BAD_CERT", "Missing device certificate.");
  const cert: any = {
    user_id: rawCert.user_id,
    device_id: rawCert.device_id,
    sign_pub: rawCert.sign_pub,
    box_pub: rawCert.box_pub,
    key_version: rawCert.key_version,
    issued_at: isoTime(rawCert.issued_at, "certificate time"),
    signature: rawCert.signature,
  };
  if (rawCert.kem_pub !== undefined && rawCert.kem_pub !== "") cert.kem_pub = rawCert.kem_pub;
  const matches =
    cert.user_id === userId &&
    cert.device_id === device.device_id &&
    cert.sign_pub === device.sign_pub &&
    cert.box_pub === device.box_pub &&
    cert.key_version === keyVersion &&
    (cert.kem_pub === undefined || cert.kem_pub === device.kem_pub);
  if (!matches) throw new ApiError(400, "CERT_MISMATCH", "The device certificate doesn't match the device.");
  const ok = await verifySig(accountSignPub, cert.signature, certText(cert));
  if (!ok) throw new ApiError(403, "CERT_INVALID", "The device certificate failed its signature check.");
  return { ...cert, has_kem: cert.kem_pub !== undefined };
}

/** A device's own signature over its post-quantum key (device-kem/v1). */
export async function verifyDeviceKemSig(userId: string, device: any, kemPub: string, signature: unknown) {
  return verifySig(device.sign_pub, signature, canonical(CONTEXTS.deviceKem, deviceKemFields({ user_id: userId, device_id: device.device_id, kem_pub: kemPub })));
}

/** Proof that this request was signed by the device holding signPub. */
export async function verifyProof(opts: {
  userId: string;
  action: string;
  payloadJson: string;
  proof: any;
  signPub: string;
  now: Date;
}) {
  const p = opts.proof;
  if (!p || typeof p !== "object") throw new ApiError(401, "PROOF_REQUIRED", "This action must come from one of your devices.");
  const deviceId = randomIdField(p.device_id, "device id");
  const issuedAt = isoTime(p.issued_at, "proof time");
  const nonce = randomIdField(p.nonce, "nonce");
  if (Math.abs(opts.now.getTime() - Date.parse(issuedAt)) > LIMITS.proofSkewMs) {
    throw new ApiError(401, "PROOF_EXPIRED", "That request is too old. Check your device clock and try again.");
  }
  const text = canonical(
    CONTEXTS.deviceProof,
    deviceProofFields({
      user_id: opts.userId,
      device_id: deviceId,
      action: opts.action,
      payload_hash: await sha256B64(opts.payloadJson),
      issued_at: issuedAt,
      nonce,
    }),
  );
  if (!(await verifySig(opts.signPub, p.signature, text))) {
    throw new ApiError(403, "PROOF_INVALID", "This device couldn't prove it's yours.");
  }
  return deviceId;
}

export async function verifyItemSignature(item: {
  kind: string;
  conversation_id: string;
  item_id: string;
  sender_id: string;
  device_id: string;
  envelope: string;
  sent_at: string;
  signature: unknown;
  signPub: string;
}) {
  const text = canonical(
    CONTEXTS.item,
    itemFields({
      kind: item.kind,
      conversation_id: item.conversation_id,
      item_id: item.item_id,
      sender_id: item.sender_id,
      device_id: item.device_id,
      envelope_hash: await sha256B64(item.envelope),
      sent_at: item.sent_at,
    }),
  );
  return verifySig(item.signPub, item.signature, text);
}

/** Signature over an encrypted server item (server-item/v1). */
export async function verifyServerItemSignature(item: {
  kind: string;
  server_id: string;
  channel_id: string;
  item_id: string;
  sender_id: string;
  device_id: string;
  envelope: string;
  sent_at: string;
  signature: unknown;
  signPub: string;
}) {
  const text = canonical(
    CONTEXTS.serverItem,
    serverItemFields({ ...item, envelope_hash: await sha256B64(item.envelope) }),
  );
  return verifySig(item.signPub, item.signature, text);
}

/** Signature over a new key generation (chain-gen/v1), by the device that made it. */
export async function verifyGenerationSignature(g: any, signPub: string) {
  return verifySig(signPub, g.signature, canonical(CONTEXTS.chainGeneration, chainGenerationFields(g)));
}

/** Signature over a key grant (key-grant/v1), by the device that sealed it. */
export async function verifyGrantSignature(g: any, signPub: string) {
  return verifySig(signPub, g.signature, canonical(CONTEXTS.keyGrant, keyGrantFields({ ...g, sealed_hash: await sha256B64(g.sealed) })));
}

// ---------- ciphertext shapes ----------

/** A sealed value: classical {epk, iv, ct} or post-quantum {kct, iv, ct}. */
export function validSealed(value: unknown): boolean {
  if (!value || typeof value !== "object") return false;
  const s = value as any;
  const iv = b64Bytes(s.iv);
  const ct = b64Bytes(s.ct);
  if (!iv || iv.length !== 12 || !ct || ct.length < 17) return false;
  if (s.kct !== undefined) {
    const kct = b64Bytes(s.kct);
    return s.epk === undefined && Boolean(kct && kct.length === KEM_CIPHERTEXT_BYTES);
  }
  const epk = b64Bytes(s.epk);
  return Boolean(epk && epk.length === 65 && epk[0] === 4);
}

export const isKemSealed = (value: any) => Boolean(value && typeof value === "object" && typeof value.kct === "string");

export function requireSealed(value: unknown, name: string): string {
  if (!validSealed(value)) throw new ApiError(400, "BAD_CIPHERTEXT", `Invalid ${name}.`);
  const v = value as any;
  const out = JSON.stringify(isKemSealed(v) ? { kct: v.kct, iv: v.iv, ct: v.ct } : { epk: v.epk, iv: v.iv, ct: v.ct });
  if (out.length > LIMITS.maxSealedChars) throw new ApiError(413, "TOO_LARGE", `${name} is too large.`);
  return out;
}

/**
 * Validate a message/title envelope and return its wraps.
 * The server can't read it, but it can insist it is well-formed.
 */
export function parseEnvelopeShape(envelopeJson: string, maxChars: number) {
  if (typeof envelopeJson !== "string" || envelopeJson.length === 0 || envelopeJson.length > maxChars) {
    throw new ApiError(413, "TOO_LARGE", "That message is too large.");
  }
  let env: any;
  try {
    env = JSON.parse(envelopeJson);
  } catch {
    throw new ApiError(400, "BAD_ENVELOPE", "The encrypted message is malformed.");
  }
  const bad = () => new ApiError(400, "BAD_ENVELOPE", "The encrypted message is malformed.");
  // Version 2: every wrap classical. Version 3: post-quantum wraps ({kct}) for those who have the keys.
  if (!env || (env.v !== 2 && env.v !== 3)) throw bad();
  const iv = b64Bytes(env.iv);
  const ct = b64Bytes(env.ct);
  const kc = b64Bytes(env.kc);
  if (!iv || iv.length !== 12 || !ct || ct.length < 17 || !kc || kc.length !== 32) throw bad();
  if (!Array.isArray(env.wraps) || env.wraps.length === 0 || env.wraps.length > LIMITS.maxGroupMembers) throw bad();
  const wraps: { u: string; kv: number; kem: boolean }[] = [];
  const seen = new Set<string>();
  for (const w of env.wraps) {
    if (!w || typeof w.u !== "string" || seen.has(w.u) || !Number.isInteger(w.kv) || w.kv < 1) throw bad();
    const wiv = b64Bytes(w.iv);
    const wk = b64Bytes(w.wk);
    if (!wiv || wiv.length !== 12 || !wk || wk.length !== 48) throw bad();
    const kem = w.kct !== undefined;
    if (kem) {
      const kct = b64Bytes(w.kct);
      if (env.v !== 3 || w.epk !== undefined || !kct || kct.length !== KEM_CIPHERTEXT_BYTES) throw bad();
    } else {
      const epk = b64Bytes(w.epk);
      if (!epk || epk.length !== 65) throw bad();
    }
    seen.add(w.u);
    wraps.push({ u: w.u, kv: w.kv, kem });
  }
  return wraps;
}
