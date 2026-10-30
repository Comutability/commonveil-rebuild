// Client side of the Commonveil protocol, as pure functions: they build request
// bodies and open responses, with no network or storage. The UI calls these,
// and tests/functions.test.mjs drives the real backend handlers with them.
//
// The server is not trusted with keys. Everything it hands back about this account's
// own keys is checked against something only the account's devices or phrase can
// produce: the keyring this device holds, the history this device showed in its link
// code, or the recovery anchor only the phrase can make.
import { randomId } from "../crypto/encoding.js";
import {
  createKeyVersion,
  keyForVersion,
  latestKey,
  newKeyring,
  openKeyringFromDevice,
  sealKeyringForRecovery,
  sealKeyringToDevice,
  withVersion,
} from "../crypto/keyring.js";
import {
  RecoveryError,
  deriveRecoveryKey,
  generateRecoveryPhrase,
  openKeyringWithRecoveryKey,
  recoveryAnchorMac,
  verifyRecoveryAnchor,
  wipeRecoveryKey,
} from "../crypto/recovery.js";
import {
  IdentityError,
  anchorChain,
  assertKeyringMatchesChain,
  headDigest,
  makeAccountStatement,
  makeDeviceCert,
  makeDeviceProof,
  signItem,
  verifyAccountChain,
  verifyDeviceCert,
  verifyItem,
} from "../crypto/identity.js";
import { decryptEnvelope, encryptEnvelope } from "../crypto/envelope.js";
import { publicDevice } from "../crypto/device.js";

export const MAX_MESSAGE_CHARS = 4000;

/** Allowance for device clocks when deciding whether an item was sent after its device was removed. */
export const REMOVAL_GRACE_MS = 10 * 60 * 1000;

/** Body for an action that must be signed by a device. */
export async function signedRequest({ userId, device, action, payload }) {
  const payloadJson = JSON.stringify(payload);
  const proof = await makeDeviceProof({ userId, device, action, payloadJson });
  return { action, payload: payloadJson, proof };
}

const certOf = (userId, d) => ({
  user_id: userId,
  device_id: d.device_id,
  sign_pub: d.sign_pub,
  box_pub: d.box_pub,
  key_version: d.cert_key_version,
  issued_at: d.cert_issued_at,
  signature: d.cert_signature,
});

/**
 * True if a device row from the server carries a certificate the verified chain vouches for.
 * currentOnly: the certificate must be for the latest key. Certificates are renewed for every
 * remaining device at each rotation, so a device left on an older one was removed then.
 */
export async function deviceIsCertified(userId, deviceRow, chain, { currentOnly = false, minVersion = 1 } = {}) {
  if (!deviceRow?.cert_signature || !Number.isInteger(deviceRow.cert_key_version)) return false;
  if (currentOnly && deviceRow.cert_key_version !== chain.latest.version) return false;
  if (deviceRow.cert_key_version < minVersion) return false;
  return verifyDeviceCert(certOf(userId, deviceRow), chain);
}

/** What a new device shows in its link code, and later holds the keys it's sent to. */
export function linkPinFor(chain) {
  return { version: chain.latest.version, digest: headDigest(chain) };
}

// ---------- first device ----------

/**
 * Generate a brand-new account identity locally. Nothing is sent until the
 * person has written down and confirmed the phrase; then send `request`.
 */
export async function prepareNewAccount({ userId, device }) {
  const phrase = generateRecoveryPhrase();
  const recovery = await deriveRecoveryKey(phrase);
  try {
    const v1 = await createKeyVersion(1);
    const keyring = newKeyring(userId, v1);
    const statement = await makeAccountStatement({ userId, keyVersion: v1, recoveryPub: recovery.publicKey, signer: v1 });
    statement.recovery_mac = await recoveryAnchorMac(recovery.anchorKey, statement);
    const cert = await makeDeviceCert({ userId, device, keyVersion: v1 });
    const sealedRecovery = await sealKeyringForRecovery(keyring, recovery.publicKey);
    const request = await signedRequest({
      userId,
      device,
      action: "init_account",
      payload: { device: publicDevice(device), statement, cert, recovery: { ...sealedRecovery, key_sign_pub: v1.sign_pub } },
    });
    return { phrase, keyring, request };
  } finally {
    wipeRecoveryKey(recovery);
  }
}

// ---------- adding a device ----------

export function prepareRegisterDevice({ userId, device }) {
  return signedRequest({ userId, device, action: "register_device", payload: { device: publicDevice(device) } });
}

/**
 * On an existing device: approve a pending one after the person compared link codes.
 * target must be the snapshot of the keys the person compared, not a fresh copy from the server.
 */
export async function prepareApproval({ userId, device, keyring, target }) {
  const latest = latestKey(keyring);
  const cert = await makeDeviceCert({ userId, device: target, keyVersion: latest });
  const envelope = await sealKeyringToDevice(keyring, target);
  return signedRequest({
    userId,
    device,
    action: "approve_device",
    payload: { target_device_id: target.device_id, cert, envelope: { ...envelope, key_sign_pub: latest.sign_pub } },
  });
}

/** Re-send the current keyring to an active device that missed it. */
export async function prepareKeyringResend({ userId, device, keyring, target, chain }) {
  assertKeyringMatchesChain(keyring, chain);
  if (!(await deviceIsCertified(userId, target, chain, { currentOnly: true }))) {
    throw new IdentityError("UNCERTIFIED_DEVICE", "That device isn't certified for your current keys, so they weren't sent to it.");
  }
  const latest = latestKey(keyring);
  const envelope = await sealKeyringToDevice(keyring, target);
  return signedRequest({
    userId,
    device,
    action: "send_keyring",
    payload: { target_device_id: target.device_id, envelope: { ...envelope, key_sign_pub: latest.sign_pub } },
  });
}

/**
 * On the receiving device: open the keyring sent to it and make sure it's the account's
 * real one. Anyone can seal a keyring to this device's public key, so either:
 * - current: the keyring this device already holds. The new one must carry those same
 *   keys, which only this account's devices have; or
 * - pin: the history this new device showed in its link code, which the person matched
 *   against an existing device. The keys must belong to that history.
 */
export async function acceptKeyringEnvelope({ userId, device, envelope, statements, current = null, pin = null }) {
  const keyring = await openKeyringFromDevice({
    boxPriv: device.box_priv,
    boxPub: device.box_pub,
    userId,
    deviceId: device.device_id,
    keyringVersion: envelope.keyring_version,
    sealed: envelope.sealed,
  });
  const chain = await verifyAccountChain(userId, statements);
  if (current) {
    for (const v of current.versions) {
      const got = keyForVersion(keyring, v.version);
      if (!got || got.ecdh_pub !== v.ecdh_pub || got.sign_pub !== v.sign_pub) {
        throw new IdentityError("KEYRING_MISMATCH", "The keys sent to this device don't follow on from the ones it already has, so they weren't used.");
      }
    }
    anchorChain(chain, { keyring: current });
  } else {
    anchorChain(chain, { pin });
  }
  assertKeyringMatchesChain(keyring, chain);
  return { keyring, chain };
}

export function prepareAck({ userId, device, keyringVersion }) {
  return signedRequest({ userId, device, action: "ack_envelopes", payload: { keyring_version: keyringVersion } });
}

/**
 * Recover with the 24-word phrase on a new device. The backup is sealed to a public
 * key, which the server could also do with keys of its own. So the published keys are
 * first traced back to a statement carrying the phrase's anchor: only the phrase can
 * make one. Everything after it must follow on by rotation.
 */
export async function recoverWithPhrase({ userId, device, phrase, recoveryResponse }) {
  const { statements, recovery } = recoveryResponse;
  const chain = await verifyAccountChain(userId, statements);
  const keys = await deriveRecoveryKey(phrase);
  try {
    if (keys.publicKey !== chain.latest.recovery_pub) {
      throw new RecoveryError("WRONG_PHRASE", "That phrase is valid, but it isn't the current recovery phrase for this account.");
    }
    let anchored = false;
    for (let v = chain.latest.version; v >= chain.rootVersion && !anchored; v -= 1) {
      const st = chain.byVersion.get(v);
      if (st.recovery_pub !== keys.publicKey) break;
      anchored = await verifyRecoveryAnchor(keys.anchorKey, st);
    }
    if (!anchored) {
      throw new IdentityError("ANCHOR_MISSING", "Your account's published keys couldn't be confirmed with this phrase, so they weren't trusted.");
    }
    if (recovery.recovery_pub !== chain.latest.recovery_pub) {
      throw new IdentityError("BACKUP_MISMATCH", "The recovery backup doesn't match your published keys.");
    }
    const keyring = await openKeyringWithRecoveryKey({
      keys,
      userId,
      keyringVersion: recovery.keyring_version,
      recoveryPub: chain.latest.recovery_pub,
      sealed: recovery.sealed,
    });
    assertKeyringMatchesChain(keyring, chain);
    const cert = await makeDeviceCert({ userId, device, keyVersion: latestKey(keyring) });
    const request = await signedRequest({ userId, device, action: "recover_device", payload: { device: publicDevice(device), cert } });
    return { keyring, chain, request };
  } finally {
    wipeRecoveryKey(keys);
  }
}

// ---------- removing devices, rotating, resetting ----------

export function prepareRevoke({ userId, device, targetDeviceId }) {
  return signedRequest({ userId, device, action: "revoke_device", payload: { target_device_id: targetDeviceId } });
}

export function prepareDeny({ userId, device, targetDeviceId }) {
  return signedRequest({ userId, device, action: "deny_device", payload: { target_device_id: targetDeviceId } });
}

/**
 * New key version signed by the current one. The chain must match this device's own
 * keyring, so the server can't steer the new keys or the backup. The keyring is sealed
 * only to devices certified for the current key, minus any being removed (the server's
 * device list can't be relied on to leave them out). newPhrase=true changes the phrase.
 */
export async function prepareRotation({ userId, device, keyring, chain, activeDevices, excludeDeviceIds = [], newPhrase = false }) {
  assertKeyringMatchesChain(keyring, chain);
  const keep = activeDevices.filter((d) => !excludeDeviceIds.includes(d.device_id));
  for (const d of keep) {
    if (!(await deviceIsCertified(userId, d, chain, { currentOnly: true }))) {
      throw new IdentityError(
        "UNCERTIFIED_DEVICE",
        "A device on your account isn't certified for your current keys, so keys weren't rotated. Remove it in Settings, then try again.",
      );
    }
  }
  let phrase = null;
  let recovery = null;
  try {
    let recoveryPub = chain.latest.recovery_pub;
    if (newPhrase) {
      phrase = generateRecoveryPhrase();
      recovery = await deriveRecoveryKey(phrase);
      recoveryPub = recovery.publicKey;
    }
    const prev = latestKey(keyring);
    const next = await createKeyVersion(prev.version + 1);
    const statement = await makeAccountStatement({ userId, keyVersion: next, recoveryPub, signer: prev });
    if (recovery) statement.recovery_mac = await recoveryAnchorMac(recovery.anchorKey, statement);
    const nextKeyring = withVersion(keyring, next);
    const certs = [];
    const envelopes = [];
    for (const d of keep) {
      certs.push(await makeDeviceCert({ userId, device: d, keyVersion: next }));
      if (d.device_id !== device.device_id) {
        envelopes.push({ device_id: d.device_id, ...(await sealKeyringToDevice(nextKeyring, d)), key_sign_pub: next.sign_pub });
      }
    }
    const backup = { ...(await sealKeyringForRecovery(nextKeyring, recoveryPub)), key_sign_pub: next.sign_pub };
    const request = await signedRequest({ userId, device, action: "rotate_keys", payload: { statement, certs, envelopes, recovery: backup } });
    return { keyring: nextKeyring, phrase, request };
  } finally {
    if (recovery) wipeRecoveryKey(recovery);
  }
}

/**
 * Last resort when every device and the phrase are lost. The server holds the request
 * for a waiting period, during which any of the account's devices (or the phrase) can
 * cancel it. Contacts see a key change once it completes.
 */
export async function prepareReset({ userId, device, nextVersion }) {
  const phrase = generateRecoveryPhrase();
  const recovery = await deriveRecoveryKey(phrase);
  try {
    const key = await createKeyVersion(nextVersion);
    const keyring = newKeyring(userId, key);
    const statement = await makeAccountStatement({ userId, keyVersion: key, recoveryPub: recovery.publicKey, signer: key });
    statement.recovery_mac = await recoveryAnchorMac(recovery.anchorKey, statement);
    const cert = await makeDeviceCert({ userId, device, keyVersion: key });
    const backup = { ...(await sealKeyringForRecovery(keyring, recovery.publicKey)), key_sign_pub: key.sign_pub };
    const request = await signedRequest({
      userId,
      device,
      action: "request_reset",
      payload: { confirm: "RESET", device: publicDevice(device), statement, cert, recovery: backup },
    });
    return { phrase, keyring, request };
  } finally {
    wipeRecoveryKey(recovery);
  }
}

/** From the device that asked for the reset, once the waiting period is over. */
export function prepareFinishReset({ userId, device, requestId }) {
  return signedRequest({ userId, device, action: "finish_reset", payload: { request_id: requestId } });
}

/** From the device that asked for the reset: take the request back. */
export function prepareWithdrawReset({ userId, device, requestId }) {
  return signedRequest({ userId, device, action: "withdraw_reset", payload: { request_id: requestId } });
}

/** From any of the account's active devices: stop a reset someone asked for. */
export function prepareCancelReset({ userId, device }) {
  return signedRequest({ userId, device, action: "cancel_reset", payload: {} });
}

// ---------- conversations ----------

export function prepareCreateDm({ userId, device, username }) {
  return signedRequest({ userId, device, action: "create_dm", payload: { username } });
}

export function prepareCreateGroup({ userId, device, usernames }) {
  return signedRequest({ userId, device, action: "create_group", payload: { usernames } });
}

// ---------- messages and group names ----------

function recipientsFor(memberIds, chains) {
  return memberIds.map((uid) => {
    const chain = chains.get(uid);
    if (!chain) throw new IdentityError("MISSING_KEYS", "Someone in this conversation has no verified keys yet.");
    return { user_id: uid, key_version: chain.latest.version, ecdh_pub: chain.latest.ecdh_pub };
  });
}

async function buildItem({ kind, userId, device, conversation, chains, payload, keyring }) {
  // Your own copy goes to your own current key, as this device's keyring proves it to be.
  if (keyring) {
    const own = chains.get(userId);
    const k = latestKey(keyring);
    if (!own || own.latest.version !== k.version || own.latest.ecdh_pub !== k.ecdh_pub) {
      throw new IdentityError("KEYRING_MISMATCH", "Your keys changed. Refresh and try again.");
    }
  }
  const itemId = randomId(16);
  const sentAt = new Date().toISOString();
  const scope = { kind, conversation_id: conversation.id, item_id: itemId, sender_id: userId, device_id: device.device_id };
  const envelope = JSON.stringify(await encryptEnvelope({ scope, recipients: recipientsFor(conversation.member_ids, chains), payload }));
  const signature = await signItem({
    device, kind, conversationId: conversation.id, itemId, senderId: userId, deviceId: device.device_id, envelopeJson: envelope, sentAt,
  });
  return { itemId, sentAt, envelope, signature };
}

/** chains: Map(user_id -> verified chain) covering every member, including you. */
export async function buildMessage({ userId, device, conversation, chains, text, keyring = null }) {
  const clean = String(text || "").replace(/\r\n/g, "\n");
  if (!clean.trim()) throw new Error("Message is empty");
  if (clean.length > MAX_MESSAGE_CHARS) throw new Error(`Messages can be up to ${MAX_MESSAGE_CHARS} characters`);
  const item = await buildItem({ kind: "message", userId, device, conversation, chains, payload: { type: "text", text: clean }, keyring });
  return {
    action: "send",
    conversation_id: conversation.id,
    msg_id: item.itemId,
    envelope: item.envelope,
    signature: item.signature,
    device_id: device.device_id,
    sent_at: item.sentAt,
  };
}

export async function buildTitle({ userId, device, conversation, chains, title, keyring = null }) {
  const clean = String(title || "").trim().slice(0, 80);
  const item = await buildItem({ kind: "title", userId, device, conversation, chains, payload: { type: "title", title: clean }, keyring });
  return {
    action: "set_title",
    conversation_id: conversation.id,
    item_id: item.itemId,
    envelope: item.envelope,
    signature: item.signature,
    device_id: device.device_id,
    sent_at: item.sentAt,
  };
}

/**
 * Certificates are renewed for every remaining device at each key rotation. If a
 * device's newest certificate is older than a rotation that came before this item was
 * sent, the device was removed at that rotation and whatever it sent since isn't vouched for.
 */
export function sentAfterRemoval(chain, certVersion, sentAt) {
  const next = chain.byVersion.get(certVersion + 1);
  if (!next) return false;
  const sent = Date.parse(sentAt);
  const rotated = Date.parse(next.issued_at);
  if (!Number.isFinite(sent) || !Number.isFinite(rotated)) return true;
  return sent > rotated + REMOVAL_GRACE_MS;
}

/**
 * Decrypt and verify one message or title.
 * status: "ok" (decrypted, and the signature checks out back to the sender's account key),
 *         "unverified" (decrypted, but it can't be vouched for: show a warning; reason says why),
 *         "locked" (can't decrypt on this device), "deleted".
 * minCertVersion: the oldest key version whose device certificates count (for your own
 * account, the first version in your keyring).
 */
export async function openItem({ kind, item, userId, keyring, senderChain, senderDevices, minCertVersion = 1 }) {
  if (item.deleted || !item.envelope) return { status: "deleted" };
  const itemId = kind === "title" ? item.item_id : item.msg_id;
  const conversationId = item.conversation_id;
  const scope = { kind, conversation_id: conversationId, item_id: itemId, sender_id: item.sender_id, device_id: item.device_id };
  let payload;
  try {
    payload = await decryptEnvelope({ scope, envelope: item.envelope, userId, keyring });
  } catch (error) {
    return { status: "locked", code: error.code || "DECRYPT_FAILED", message: error.message };
  }
  let verified = false;
  let reason = "unverified";
  const dev = (senderDevices || []).find((d) => d.device_id === item.device_id);
  if (dev && senderChain && (await deviceIsCertified(item.sender_id, dev, senderChain, { minVersion: minCertVersion }))) {
    verified = await verifyItem({
      signPub: dev.sign_pub,
      signature: item.signature,
      kind,
      conversationId,
      itemId,
      senderId: item.sender_id,
      deviceId: item.device_id,
      envelopeJson: item.envelope,
      sentAt: item.sent_at,
    });
    if (verified && sentAfterRemoval(senderChain, dev.cert_key_version, item.sent_at)) {
      verified = false;
      reason = "removed-device";
    }
  }
  const text = kind === "title" ? payload?.title : payload?.text;
  if (typeof text !== "string") return { status: "locked", code: "BAD_PAYLOAD", message: "Unrecognised content." };
  return {
    status: verified ? "ok" : "unverified",
    reason: verified ? null : reason,
    text: text.slice(0, kind === "title" ? 80 : MAX_MESSAGE_CHARS),
    removedDevice: dev?.status === "revoked",
  };
}
