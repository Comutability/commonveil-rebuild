// Client side of the Commonveil protocol, as pure functions: they build request
// bodies and open responses, with no network or storage. The UI calls these,
// and tests/functions.test.mjs drives the real backend handlers with them.
import { randomId } from "../crypto/encoding.js";
import {
  createKeyVersion,
  latestKey,
  newKeyring,
  openKeyringFromDevice,
  sealKeyringForRecovery,
  sealKeyringToDevice,
  withVersion,
} from "../crypto/keyring.js";
import { deriveRecoveryKey, generateRecoveryPhrase, openKeyringWithPhrase } from "../crypto/recovery.js";
import {
  IdentityError,
  assertKeyringMatchesChain,
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

/** True if a device row from the server carries a certificate our verified chain vouches for. */
export async function deviceIsCertified(userId, deviceRow, chain) {
  if (!deviceRow?.cert_signature || !Number.isInteger(deviceRow.cert_key_version)) return false;
  return verifyDeviceCert(certOf(userId, deviceRow), chain);
}

// ---------- first device ----------

/**
 * Generate a brand-new account identity locally. Nothing is sent until the
 * person has written down and confirmed the phrase; then send `request`.
 */
export async function prepareNewAccount({ userId, device }) {
  const phrase = generateRecoveryPhrase();
  const recovery = await deriveRecoveryKey(phrase);
  recovery.secret.fill(0);
  const v1 = await createKeyVersion(1);
  const keyring = newKeyring(userId, v1);
  const statement = await makeAccountStatement({ userId, keyVersion: v1, recoveryPub: recovery.publicKey, signer: v1 });
  const cert = await makeDeviceCert({ userId, device, keyVersion: v1 });
  const sealedRecovery = await sealKeyringForRecovery(keyring, recovery.publicKey);
  const request = await signedRequest({
    userId,
    device,
    action: "init_account",
    payload: { device: publicDevice(device), statement, cert, recovery: { ...sealedRecovery, key_sign_pub: v1.sign_pub } },
  });
  return { phrase, keyring, request };
}

// ---------- adding a device ----------

export function prepareRegisterDevice({ userId, device }) {
  return signedRequest({ userId, device, action: "register_device", payload: { device: publicDevice(device) } });
}

/** On an existing device: approve a pending one after the person compared link codes. */
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

/** Re-send the current keyring to an active device that missed a rotation. */
export async function prepareKeyringResend({ userId, device, keyring, target, chain }) {
  if (!(await deviceIsCertified(userId, target, chain))) {
    throw new IdentityError("UNCERTIFIED_DEVICE", "That device isn't certified by your account key, so your keys weren't sent to it.");
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

/** On the new device: open the keyring sent to it and check it against the published keys. */
export async function acceptKeyringEnvelope({ userId, device, envelope, statements }) {
  const keyring = await openKeyringFromDevice({
    boxPriv: device.box_priv,
    boxPub: device.box_pub,
    userId,
    deviceId: device.device_id,
    keyringVersion: envelope.keyring_version,
    sealed: envelope.sealed,
  });
  const chain = await verifyAccountChain(userId, statements);
  assertKeyringMatchesChain(keyring, chain);
  return { keyring, chain };
}

export function prepareAck({ userId, device, keyringVersion }) {
  return signedRequest({ userId, device, action: "ack_envelopes", payload: { keyring_version: keyringVersion } });
}

/** Recover with the 24-word phrase on a new device. */
export async function recoverWithPhrase({ userId, device, phrase, recoveryResponse }) {
  const { statements, recovery } = recoveryResponse;
  const chain = await verifyAccountChain(userId, statements);
  if (recovery.recovery_pub !== chain.latest.recovery_pub) {
    throw new IdentityError("BACKUP_MISMATCH", "The recovery backup doesn't match your published keys.");
  }
  const keyring = await openKeyringWithPhrase({
    phrase,
    userId,
    keyringVersion: recovery.keyring_version,
    recoveryPub: chain.latest.recovery_pub,
    sealed: recovery.sealed,
  });
  assertKeyringMatchesChain(keyring, chain);
  const cert = await makeDeviceCert({ userId, device, keyVersion: latestKey(keyring) });
  const request = await signedRequest({ userId, device, action: "recover_device", payload: { device: publicDevice(device), cert } });
  return { keyring, chain, request };
}

// ---------- removing devices, rotating, resetting ----------

export function prepareRevoke({ userId, device, targetDeviceId }) {
  return signedRequest({ userId, device, action: "revoke_device", payload: { target_device_id: targetDeviceId } });
}

export function prepareDeny({ userId, device, targetDeviceId }) {
  return signedRequest({ userId, device, action: "deny_device", payload: { target_device_id: targetDeviceId } });
}

/**
 * New key version signed by the current one. The keyring is sealed only to
 * devices whose certificates our own chain vouches for, so a device slipped in
 * by the server never receives keys. Pass newPhrase=true to change the phrase.
 */
export async function prepareRotation({ userId, device, keyring, chain, activeDevices, newPhrase = false }) {
  for (const d of activeDevices) {
    if (!(await deviceIsCertified(userId, d, chain))) {
      throw new IdentityError("UNCERTIFIED_DEVICE", "One of the active devices isn't certified by your account key. Keys were not rotated.");
    }
  }
  let phrase = null;
  let recoveryPub = chain.latest.recovery_pub;
  if (newPhrase) {
    phrase = generateRecoveryPhrase();
    const rk = await deriveRecoveryKey(phrase);
    rk.secret.fill(0);
    recoveryPub = rk.publicKey;
  }
  const prev = latestKey(keyring);
  const next = await createKeyVersion(prev.version + 1);
  const statement = await makeAccountStatement({ userId, keyVersion: next, recoveryPub, signer: prev });
  const nextKeyring = withVersion(keyring, next);
  const certs = [];
  const envelopes = [];
  for (const d of activeDevices) {
    certs.push(await makeDeviceCert({ userId, device: d, keyVersion: next }));
    if (d.device_id !== device.device_id) {
      envelopes.push({ device_id: d.device_id, ...(await sealKeyringToDevice(nextKeyring, d)), key_sign_pub: next.sign_pub });
    }
  }
  const recovery = { ...(await sealKeyringForRecovery(nextKeyring, recoveryPub)), key_sign_pub: next.sign_pub };
  const request = await signedRequest({ userId, device, action: "rotate_keys", payload: { statement, certs, envelopes, recovery } });
  return { keyring: nextKeyring, phrase, request };
}

/** Last resort when every device and the phrase are lost. Contacts will see a key change. */
export async function prepareReset({ userId, device, nextVersion }) {
  const phrase = generateRecoveryPhrase();
  const rk = await deriveRecoveryKey(phrase);
  rk.secret.fill(0);
  const key = await createKeyVersion(nextVersion);
  const keyring = newKeyring(userId, key);
  const statement = await makeAccountStatement({ userId, keyVersion: key, recoveryPub: rk.publicKey, signer: key });
  const cert = await makeDeviceCert({ userId, device, keyVersion: key });
  const recovery = { ...(await sealKeyringForRecovery(keyring, rk.publicKey)), key_sign_pub: key.sign_pub };
  const request = await signedRequest({
    userId,
    device,
    action: "reset_account",
    payload: { confirm: "RESET", device: publicDevice(device), statement, cert, recovery },
  });
  return { phrase, keyring, request };
}

// ---------- messages and group names ----------

function recipientsFor(memberIds, chains) {
  return memberIds.map((uid) => {
    const chain = chains.get(uid);
    if (!chain) throw new IdentityError("MISSING_KEYS", "Someone in this conversation has no verified keys yet.");
    return { user_id: uid, key_version: chain.latest.version, ecdh_pub: chain.latest.ecdh_pub };
  });
}

async function buildItem({ kind, userId, device, conversation, chains, payload }) {
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
export async function buildMessage({ userId, device, conversation, chains, text }) {
  const clean = String(text || "").replace(/\r\n/g, "\n");
  if (!clean.trim()) throw new Error("Message is empty");
  if (clean.length > MAX_MESSAGE_CHARS) throw new Error(`Messages can be up to ${MAX_MESSAGE_CHARS} characters`);
  const item = await buildItem({ kind: "message", userId, device, conversation, chains, payload: { type: "text", text: clean } });
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

export async function buildTitle({ userId, device, conversation, chains, title }) {
  const clean = String(title || "").trim().slice(0, 80);
  const item = await buildItem({ kind: "title", userId, device, conversation, chains, payload: { type: "title", title: clean } });
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
 * Decrypt and verify one message or title.
 * status: "ok" (decrypted, signature checks out back to the sender's account key),
 *         "unverified" (decrypted, but the signature couldn't be checked: show a warning),
 *         "locked" (can't decrypt on this device), "deleted".
 */
export async function openItem({ kind, item, userId, keyring, senderChain, senderDevices }) {
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
  const dev = (senderDevices || []).find((d) => d.device_id === item.device_id);
  if (dev && senderChain && (await deviceIsCertified(item.sender_id, dev, senderChain))) {
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
  }
  const text = kind === "title" ? payload?.title : payload?.text;
  if (typeof text !== "string") return { status: "locked", code: "BAD_PAYLOAD", message: "Unrecognised content." };
  return {
    status: verified ? "ok" : "unverified",
    text: text.slice(0, kind === "title" ? 80 : MAX_MESSAGE_CHARS),
    removedDevice: dev?.status === "revoked",
  };
}
