// Account identity: signed key statements, device certificates, device proofs,
// item signatures, safety numbers and device-link codes.
import { sha256 as syncSha256 } from "@noble/hashes/sha2.js";
import {
  CONTEXTS,
  accountKeyFields,
  canonical,
  deviceCertFields,
  deviceProofFields,
  itemFields,
} from "./canonical.js";
import { concatBytes, randomId, sha256B64, utf8 } from "./encoding.js";
import { importSignPrivate, signBytes, verifyWithRaw } from "./primitives.js";
import { latestKey } from "./keyring.js";

export class IdentityError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = "IdentityError";
    this.code = code;
  }
}

const nowIso = () => new Date().toISOString();

async function signWithPkcs8(pkcs8, text) {
  return signBytes(await importSignPrivate(pkcs8), utf8(text));
}

/**
 * Publishable statement for one account key version.
 * signer = the same key version for a first key or a reset (self-signed),
 *          or the previous version for a rotation (chained).
 */
export async function makeAccountStatement({ userId, keyVersion, recoveryPub, signer }) {
  const statement = {
    user_id: userId,
    version: keyVersion.version,
    ecdh_pub: keyVersion.ecdh_pub,
    sign_pub: keyVersion.sign_pub,
    recovery_pub: recoveryPub,
    signed_by_version: signer.version,
    issued_at: nowIso(),
  };
  statement.signature = await signWithPkcs8(signer.sign_priv, canonical(CONTEXTS.accountKey, accountKeyFields(statement)));
  return statement;
}

/**
 * Verify an account's full published key history.
 * Returns the latest statement and the "root" version: the most recent
 * self-signed statement the latest key descends from. A root above 1 means the
 * account was reset at some point and earlier keys are not vouched for.
 */
export async function verifyAccountChain(userId, statements) {
  if (!Array.isArray(statements) || statements.length === 0) {
    throw new IdentityError("NO_KEYS", "This member hasn't set up encryption yet.");
  }
  const sorted = [...statements].sort((a, b) => a.version - b.version);
  const byVersion = new Map();
  for (let i = 0; i < sorted.length; i += 1) {
    const st = sorted[i];
    if (st.user_id !== userId) throw new IdentityError("WRONG_USER", "A key statement belongs to someone else.");
    if (!Number.isInteger(st.version) || st.version !== i + 1) {
      throw new IdentityError("VERSION_GAP", "This member's key history has a gap.");
    }
    const selfSigned = st.signed_by_version === st.version;
    if (!selfSigned && st.signed_by_version !== st.version - 1) {
      throw new IdentityError("BAD_CHAIN", "This member's key history is out of order.");
    }
    const signer = selfSigned ? st : byVersion.get(st.signed_by_version);
    const ok = await verifyWithRaw(signer.sign_pub, st.signature, canonical(CONTEXTS.accountKey, accountKeyFields(st)));
    if (!ok) throw new IdentityError("BAD_SIGNATURE", "A published key statement failed its signature check.");
    byVersion.set(st.version, st);
  }
  const latest = sorted[sorted.length - 1];
  let rootVersion = latest.version;
  while (byVersion.get(rootVersion).signed_by_version !== rootVersion) {
    rootVersion = byVersion.get(rootVersion).signed_by_version;
  }
  return { userId, latest, rootVersion, byVersion };
}

/**
 * Compare a verified chain with what this device pinned earlier.
 * "rotated" is safe: every step since the pin is signed by the previous key.
 * "changed" means the pinned key no longer leads to the current one (an account
 * reset, or the server substituting keys) and needs the person's attention.
 */
export function compareWithPin(chain, pin) {
  if (!pin) return "new";
  const pinned = chain.byVersion.get(pin.version);
  const continuous = Boolean(pinned) && pinned.sign_pub === pin.sign_pub && pin.version >= chain.rootVersion;
  if (!continuous) return "changed";
  return pin.version === chain.latest.version ? "same" : "rotated";
}

export function pinFromChain(chain, verified = false) {
  return {
    version: chain.latest.version,
    sign_pub: chain.latest.sign_pub,
    verified,
    pinned_at: nowIso(),
  };
}

/** Check a keyring against the account's verified published keys. */
export function assertKeyringMatchesChain(keyring, chain) {
  for (const v of keyring.versions) {
    const st = chain.byVersion.get(v.version);
    if (!st || st.ecdh_pub !== v.ecdh_pub || st.sign_pub !== v.sign_pub) {
      throw new IdentityError("KEYRING_MISMATCH", "These keys don't match the keys published for this account.");
    }
  }
  if (latestKey(keyring).version !== chain.latest.version) {
    throw new IdentityError("KEYRING_STALE", "This copy of the account keys is out of date.");
  }
}

export async function makeDeviceCert({ userId, device, keyVersion }) {
  const cert = {
    user_id: userId,
    device_id: device.device_id,
    sign_pub: device.sign_pub,
    box_pub: device.box_pub,
    key_version: keyVersion.version,
    issued_at: nowIso(),
  };
  cert.signature = await signWithPkcs8(keyVersion.sign_priv, canonical(CONTEXTS.deviceCert, deviceCertFields(cert)));
  return cert;
}

export async function verifyDeviceCert(cert, chain) {
  const signer = chain.byVersion.get(cert.key_version);
  if (!signer || cert.user_id !== chain.userId) return false;
  return verifyWithRaw(signer.sign_pub, cert.signature, canonical(CONTEXTS.deviceCert, deviceCertFields(cert)));
}

/** Proof that a request comes from this device. payloadJson is sent verbatim. */
export async function makeDeviceProof({ userId, device, action, payloadJson }) {
  const proof = { device_id: device.device_id, issued_at: nowIso(), nonce: randomId(12) };
  const payload_hash = await sha256B64(payloadJson);
  const text = canonical(
    CONTEXTS.deviceProof,
    deviceProofFields({ user_id: userId, device_id: device.device_id, action, payload_hash, issued_at: proof.issued_at, nonce: proof.nonce }),
  );
  proof.signature = await signBytes(device.sign_priv, utf8(text));
  return proof;
}

async function itemText({ kind, conversationId, itemId, senderId, deviceId, envelopeJson, sentAt }) {
  const envelope_hash = await sha256B64(envelopeJson);
  return canonical(
    CONTEXTS.item,
    itemFields({ kind, conversation_id: conversationId, item_id: itemId, sender_id: senderId, device_id: deviceId, envelope_hash, sent_at: sentAt }),
  );
}

export async function signItem({ device, ...item }) {
  return signBytes(device.sign_priv, utf8(await itemText(item)));
}

export async function verifyItem({ signPub, signature, ...item }) {
  return verifyWithRaw(signPub, signature, await itemText(item));
}

function digitGroups(bytes, groups, bytesPerGroup, modulo, width) {
  let out = "";
  for (let i = 0; i < groups; i += 1) {
    let n = 0;
    for (const b of bytes.subarray(i * bytesPerGroup, (i + 1) * bytesPerGroup)) n = n * 256 + b;
    out += String(n % modulo).padStart(width, "0");
  }
  return out;
}

/** 30 digits for one account key. Iterated hash to make grinding a lookalike expensive. */
export function safetyFingerprint(userId, signPub) {
  const keyBytes = utf8(signPub);
  let h = syncSha256(utf8(`commonveil/safety/v1|${userId}|${signPub}`));
  for (let i = 0; i < 4096; i += 1) h = syncSha256(concatBytes(h, keyBytes));
  return digitGroups(h, 6, 5, 100000, 5);
}

/** 60-digit safety number for a pair of accounts. The same on both sides. */
export function safetyNumber(a, b) {
  const [first, second] = [a, b].sort((p, q) => (p.user_id < q.user_id ? -1 : p.user_id > q.user_id ? 1 : 0));
  return safetyFingerprint(first.user_id, first.sign_pub) + safetyFingerprint(second.user_id, second.sign_pub);
}

/** 20-digit code shown on both devices during linking, so a substituted key is caught. */
export function linkCode({ userId, deviceId, signPub, boxPub }) {
  const h = syncSha256(utf8(`commonveil/link-code/v1|${userId}|${deviceId}|${signPub}|${boxPub}`));
  return digitGroups(h, 5, 2, 10000, 4);
}

export function groupDigits(digits, size) {
  return (digits.match(new RegExp(`.{1,${size}}`, "g")) || []).join(" ");
}
