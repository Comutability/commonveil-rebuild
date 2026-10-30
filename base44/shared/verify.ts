// Signature and format checks done on the server. The server never holds a
// private key; it only verifies signatures and the shape of ciphertext.
import { ApiError, LIMITS, randomIdField, isoTime } from "./http.ts";
import { CONTEXTS, accountKeyFields, canonical, deviceCertFields, deviceProofFields, itemFields } from "./canonical.ts";

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
  };
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
  return verifySig(signerPub, statement.signature, canonical(CONTEXTS.accountKey, accountKeyFields(statement)));
}

// ---------- devices ----------

export async function parseDevice(raw: any) {
  if (!raw || typeof raw !== "object") throw new ApiError(400, "BAD_DEVICE", "Missing device.");
  return {
    device_id: randomIdField(raw.device_id, "device id"),
    label: typeof raw.label === "string" ? raw.label.replace(/[\u0000-\u001F\u007F]/g, "").trim().slice(0, 60) || "Device" : "Device",
    sign_pub: await requireP256Key(raw.sign_pub, "device signing key"),
    box_pub: await requireP256Key(raw.box_pub, "device box key"),
  };
}

/** Certificate must name exactly these device keys and be signed by the given account key. */
export async function verifyCert(rawCert: any, userId: string, device: any, keyVersion: number, accountSignPub: string) {
  if (!rawCert || typeof rawCert !== "object") throw new ApiError(400, "BAD_CERT", "Missing device certificate.");
  const cert = {
    user_id: rawCert.user_id,
    device_id: rawCert.device_id,
    sign_pub: rawCert.sign_pub,
    box_pub: rawCert.box_pub,
    key_version: rawCert.key_version,
    issued_at: isoTime(rawCert.issued_at, "certificate time"),
    signature: rawCert.signature,
  };
  const matches =
    cert.user_id === userId &&
    cert.device_id === device.device_id &&
    cert.sign_pub === device.sign_pub &&
    cert.box_pub === device.box_pub &&
    cert.key_version === keyVersion;
  if (!matches) throw new ApiError(400, "CERT_MISMATCH", "The device certificate doesn't match the device.");
  const ok = await verifySig(accountSignPub, cert.signature, canonical(CONTEXTS.deviceCert, deviceCertFields(cert)));
  if (!ok) throw new ApiError(403, "CERT_INVALID", "The device certificate failed its signature check.");
  return cert;
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

// ---------- ciphertext shapes ----------

export function validSealed(value: unknown): boolean {
  if (!value || typeof value !== "object") return false;
  const s = value as any;
  const epk = b64Bytes(s.epk);
  const iv = b64Bytes(s.iv);
  const ct = b64Bytes(s.ct);
  return Boolean(epk && epk.length === 65 && epk[0] === 4 && iv && iv.length === 12 && ct && ct.length >= 17);
}

export function requireSealed(value: unknown, name: string): string {
  if (!validSealed(value)) throw new ApiError(400, "BAD_CIPHERTEXT", `Invalid ${name}.`);
  const out = JSON.stringify({ epk: (value as any).epk, iv: (value as any).iv, ct: (value as any).ct });
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
  if (!env || env.v !== 2) throw bad();
  const iv = b64Bytes(env.iv);
  const ct = b64Bytes(env.ct);
  const kc = b64Bytes(env.kc);
  if (!iv || iv.length !== 12 || !ct || ct.length < 17 || !kc || kc.length !== 32) throw bad();
  if (!Array.isArray(env.wraps) || env.wraps.length === 0 || env.wraps.length > LIMITS.maxGroupMembers) throw bad();
  const wraps: { u: string; kv: number }[] = [];
  const seen = new Set<string>();
  for (const w of env.wraps) {
    if (!w || typeof w.u !== "string" || seen.has(w.u) || !Number.isInteger(w.kv) || w.kv < 1) throw bad();
    const epk = b64Bytes(w.epk);
    const wiv = b64Bytes(w.iv);
    const wk = b64Bytes(w.wk);
    if (!epk || epk.length !== 65 || !wiv || wiv.length !== 12 || !wk || wk.length !== 48) throw bad();
    seen.add(w.u);
    wraps.push({ u: w.u, kv: w.kv });
  }
  return wraps;
}
