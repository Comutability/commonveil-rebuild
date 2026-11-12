// Account identity: signed key statements, device certificates, device proofs,
// item signatures, safety numbers and device-link codes.
import { sha256 as syncSha256 } from "@noble/hashes/sha2.js";
import {
  CONTEXTS,
  canonical,
  certText,
  deviceKemFields,
  deviceProofFields,
  itemFields,
  statementText,
} from "./canonical.js";
import { concatBytes, randomId, sha256B64, toB64, utf8 } from "./encoding.js";
import { importSignPrivate, signBytes, verifyWithRaw } from "./primitives.js";
import { latestKey } from "./keyring.js";
import { isKemPublic } from "./kem.js";

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
 * A key version with a post-quantum key publishes it too, with the recovery phrase's
 * post-quantum key if the account has one (recoveryKemPub), in the account-key/v2 form.
 */
export async function makeAccountStatement({ userId, keyVersion, recoveryPub, recoveryKemPub = "", signer }) {
  const statement = {
    user_id: userId,
    version: keyVersion.version,
    ecdh_pub: keyVersion.ecdh_pub,
    sign_pub: keyVersion.sign_pub,
    recovery_pub: recoveryPub,
    signed_by_version: signer.version,
    issued_at: nowIso(),
  };
  if (keyVersion.kem_pub) {
    statement.kem_pub = keyVersion.kem_pub;
    statement.recovery_kem_pub = recoveryKemPub || "";
  }
  statement.signature = await signWithPkcs8(signer.sign_priv, statementText(statement));
  return statement;
}

/** One link of the hash chain over an account's published key history. */
function nextDigest(previous, statement) {
  return toB64(syncSha256(utf8(`commonveil/chain-digest/v1\n${previous}\n${statementText(statement)}\n${statement.signature}`)));
}

/** True if this statement publishes a post-quantum key. */
export const statementHasKem = (st) => typeof st?.kem_pub === "string" && st.kem_pub.length > 0;

/**
 * Verify an account's full published key history.
 * Returns the latest statement and the "root" version: the most recent
 * self-signed statement the latest key descends from. A root above 1 means the
 * account was reset at some point and earlier keys are not vouched for.
 * digests holds, for each version, a hash of every statement up to and including
 * it: pins, safety numbers and link codes commit to the whole history, not one key.
 */
export async function verifyAccountChain(userId, statements) {
  if (!Array.isArray(statements) || statements.length === 0) {
    throw new IdentityError("NO_KEYS", "This member hasn't set up encryption yet.");
  }
  const sorted = [...statements].sort((a, b) => a.version - b.version);
  const byVersion = new Map();
  const digests = new Map();
  let digest = "";
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
    if (statementHasKem(st) && (!isKemPublic(st.kem_pub) || (st.recovery_kem_pub && !isKemPublic(st.recovery_kem_pub)))) {
      throw new IdentityError("BAD_KEY", "A published post-quantum key is malformed.");
    }
    const signer = selfSigned ? st : byVersion.get(st.signed_by_version);
    const ok = await verifyWithRaw(signer.sign_pub, st.signature, statementText(st));
    if (!ok) throw new IdentityError("BAD_SIGNATURE", "A published key statement failed its signature check.");
    byVersion.set(st.version, st);
    digest = nextDigest(digest, st);
    digests.set(st.version, digest);
  }
  const latest = sorted[sorted.length - 1];
  let rootVersion = latest.version;
  while (byVersion.get(rootVersion).signed_by_version !== rootVersion) {
    rootVersion = byVersion.get(rootVersion).signed_by_version;
  }
  return { userId, latest, rootVersion, byVersion, digests, statements: sorted };
}

/** Hash of an account's whole published history, up to its latest key. */
export const headDigest = (chain) => chain.digests.get(chain.latest.version);

/**
 * Compare a verified chain with what this device pinned earlier.
 * "same": nothing changed. "rotated": the pinned history is intact, and every key
 * since is signed by the one before it. "changed": something at or before the pinned
 * key differs, or the account was reset since. That needs the person's attention:
 * it's what a server substituting keys looks like.
 */
export function compareWithPin(chain, pin) {
  if (!pin) return "new";
  const pinned = chain.byVersion.get(pin.version);
  if (!pinned || pin.version < chain.rootVersion) return "changed";
  if (pin.digest) {
    if (chain.digests.get(pin.version) !== pin.digest) return "changed";
    return pin.version === chain.latest.version ? "same" : "rotated";
  }
  // A pin from before histories were pinned: the key must still match, and it's re-pinned.
  return pinned.sign_pub === pin.sign_pub ? "rotated" : "changed";
}

/** Pins keep the history itself, so signatures can still be checked against it while a change is reviewed. */
export function pinFromChain(chain, verified = false) {
  return {
    version: chain.latest.version,
    digest: headDigest(chain),
    sign_pub: chain.latest.sign_pub,
    statements: chain.statements.map((s) => ({ ...s })),
    verified,
    pinned_at: nowIso(),
  };
}

/**
 * Check a chain against keys only this account's own devices can vouch for: the keyring
 * this device holds, or the history it showed in its link code (pin: { version, digest }).
 * Every key after the anchor must follow on by rotation. A reset since means this
 * device's keys are no longer the account's.
 */
export function anchorChain(chain, { keyring = null, pin = null } = {}) {
  let anchorVersion;
  if (keyring) {
    for (const v of keyring.versions) {
      const st = chain.byVersion.get(v.version);
      if (!st) {
        throw new IdentityError("KEYS_ROLLED_BACK", "Your account's published keys are older than the keys on this device. Don't send anything until this is sorted out.");
      }
      if (!sameKeys(st, v)) {
        throw new IdentityError("KEYRING_MISMATCH", "Your account's published keys don't match the keys on this device. Don't send anything until this is sorted out.");
      }
    }
    anchorVersion = latestKey(keyring).version;
  } else if (pin && Number.isInteger(pin.version) && pin.digest) {
    if (chain.digests.get(pin.version) !== pin.digest) {
      throw new IdentityError("ANCHOR_MISMATCH", "Your account's keys aren't the ones this device showed in its link code, so they weren't accepted.");
    }
    anchorVersion = pin.version;
  } else {
    throw new IdentityError("NO_ANCHOR", "This device can't confirm where these keys came from. Set it up again.");
  }
  if (chain.rootVersion > anchorVersion) {
    throw new IdentityError("ACCOUNT_RESET", "Your account's encryption was reset from another device, so the keys in this browser no longer apply.");
  }
  return anchorVersion;
}

/** A published statement and a keyring version carry the same public keys, post-quantum key included. */
export function sameKeys(st, v) {
  return Boolean(st && v) && st.ecdh_pub === v.ecdh_pub && st.sign_pub === v.sign_pub && (st.kem_pub || "") === (v.kem_pub || "");
}

/** Check a keyring against the account's verified published keys. */
export function assertKeyringMatchesChain(keyring, chain) {
  for (const v of keyring.versions) {
    const st = chain.byVersion.get(v.version);
    if (!sameKeys(st, v)) {
      throw new IdentityError("KEYRING_MISMATCH", "These keys don't match the keys published for this account.");
    }
  }
  if (latestKey(keyring).version !== chain.latest.version) {
    throw new IdentityError("KEYRING_STALE", "This copy of the account keys is out of date.");
  }
}

/**
 * Certificate for a device's keys under one account key version. kemPub: the device's
 * post-quantum key, only when the caller has verified it belongs to the device (it came from
 * the device itself, was in the link code, or carries the device's own signature).
 */
export async function makeDeviceCert({ userId, device, keyVersion, kemPub = "" }) {
  const cert = {
    user_id: userId,
    device_id: device.device_id,
    sign_pub: device.sign_pub,
    box_pub: device.box_pub,
    key_version: keyVersion.version,
    issued_at: nowIso(),
  };
  if (kemPub) cert.kem_pub = kemPub;
  cert.signature = await signWithPkcs8(keyVersion.sign_priv, certText(cert));
  return cert;
}

export async function verifyDeviceCert(cert, chain) {
  const signer = chain.byVersion.get(cert.key_version);
  if (!signer || cert.user_id !== chain.userId) return false;
  return verifyWithRaw(signer.sign_pub, cert.signature, certText(cert));
}

/**
 * A device's own signature over its post-quantum key. Devices set up before post-quantum keys
 * add one this way; it's certified at the account's next key rotation.
 */
export async function signDeviceKem({ userId, device }) {
  const text = canonical(CONTEXTS.deviceKem, deviceKemFields({ user_id: userId, device_id: device.device_id, kem_pub: device.kem_pub }));
  return signBytes(device.sign_priv, utf8(text));
}

export async function verifyDeviceKem({ userId, deviceId, signPub, kemPub, signature }) {
  if (!isKemPublic(kemPub)) return false;
  const text = canonical(CONTEXTS.deviceKem, deviceKemFields({ user_id: userId, device_id: deviceId, kem_pub: kemPub }));
  return verifyWithRaw(signPub, signature, text);
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

/** @param {any} item */
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

/**
 * 30 digits for one account. They cover the account's whole published key history
 * (headDigest), so two people comparing numbers also confirm that nobody substituted
 * any key, including an earlier one. Iterated hash to make grinding a lookalike expensive.
 */
export function safetyFingerprint(userId, digest) {
  if (typeof digest !== "string" || !digest) throw new IdentityError("NO_KEYS", "No key history to fingerprint.");
  const bytes = utf8(digest);
  let h = syncSha256(utf8(`commonveil/safety/v2|${userId}|${digest}`));
  for (let i = 0; i < 4096; i += 1) h = syncSha256(concatBytes(h, bytes));
  return digitGroups(h, 6, 5, 100000, 5);
}

/** 60-digit safety number for a pair of accounts, each given as { user_id, digest }. The same on both sides. */
export function safetyNumber(a, b) {
  const [first, second] = [a, b].sort((p, q) => (p.user_id < q.user_id ? -1 : p.user_id > q.user_id ? 1 : 0));
  return safetyFingerprint(first.user_id, first.digest) + safetyFingerprint(second.user_id, second.digest);
}

/**
 * 20-digit code shown on both devices during linking. It covers the new device's keys,
 * its post-quantum key included, so none can be swapped, and the account's key history as
 * each side sees it, so the new device can't be handed a forged account.
 */
export function linkCode({ userId, deviceId, signPub, boxPub, kemPub = "", accountDigest }) {
  if (typeof accountDigest !== "string" || !accountDigest) throw new IdentityError("NO_ANCHOR", "No account history for the link code.");
  const text = kemPub
    ? `commonveil/link-code/v3|${userId}|${deviceId}|${signPub}|${boxPub}|${kemPub}|${accountDigest}`
    : `commonveil/link-code/v2|${userId}|${deviceId}|${signPub}|${boxPub}|${accountDigest}`;
  return digitGroups(syncSha256(utf8(text)), 5, 2, 10000, 4);
}

export function groupDigits(digits, size) {
  return (digits.match(new RegExp(`.{1,${size}}`, "g")) || []).join(" ");
}
