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
  signDeviceKem,
  signItem,
  verifyAccountChain,
  verifyDeviceCert,
  verifyDeviceKem,
  verifyItem,
} from "../crypto/identity.js";
import { decryptEnvelope, encryptEnvelope } from "../crypto/envelope.js";
import { publicDevice } from "../crypto/device.js";
import { isReactionEmoji } from "../emoji.js";
import { cleanPoll, cleanVote } from "./polls.js";
import { cleanAttachments } from "./attachments.js";

export const MAX_MESSAGE_CHARS = 4000;

/** What a message shows as text in lists, previews and search. */
export const textOf = (content) => (content.type === "reaction" || content.type === "vote" ? "" : content.type === "poll" ? content.question : content.type === "call" ? "Started a call" : content.text);

/** The reactions on offer. Anything else in a reaction is ignored, so a reaction can't carry a message. */
export const REACTIONS = Object.freeze(["\u{1F44D}", "\u2764\uFE0F", "\u{1F602}", "\u{1F62E}", "\u{1F622}", "\u{1F64F}"]);

/** Message ids are random, chosen by the sender, and bound into each message's encryption. */
const ITEM_ID_RE = /^[A-Za-z0-9_-]{16,64}$/;
const isItemId = (v) => typeof v === "string" && ITEM_ID_RE.test(v);

/** Disappearing-message timers a conversation can have, in seconds: off, a day, a week, four weeks. */
export const EXPIRY_CHOICES = Object.freeze([0, 86_400, 604_800, 2_419_200]);

/** Allowance for device clocks when deciding whether an item was sent after its device was removed. */
export const REMOVAL_GRACE_MS = 10 * 60 * 1000;

/** A device proof for a request whose body is built elsewhere (the identity client). */
export const deviceProofFor = ({ userId, device, action, payloadJson }) => makeDeviceProof({ userId, device, action, payloadJson });

/** Body for an action that must be signed by a device. */
export async function signedRequest({ userId, device, action, payload }) {
  const payloadJson = JSON.stringify(payload);
  const proof = await makeDeviceProof({ userId, device, action, payloadJson });
  return { action, payload: payloadJson, proof };
}

/** A device row's certificate. cert_has_kem says whether it covers the device's post-quantum key too. */
const certOf = (userId, d) => ({
  user_id: userId,
  device_id: d.device_id,
  sign_pub: d.sign_pub,
  box_pub: d.box_pub,
  ...(d.cert_has_kem && d.kem_pub ? { kem_pub: d.kem_pub } : {}),
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

/**
 * A device's post-quantum key, if it can be vouched for: covered by its certificate, or signed
 * by the device itself (devices set up before they had one). Otherwise null, and keyrings are
 * sealed to it the classical way. The server's word alone is never enough.
 */
export async function verifiedDeviceKem(userId, deviceRow, chain) {
  if (!deviceRow?.kem_pub) return null;
  if (!(await deviceIsCertified(userId, deviceRow, chain))) return null;
  if (deviceRow.cert_has_kem) return deviceRow.kem_pub;
  if (!deviceRow.kem_sig) return null;
  const ok = await verifyDeviceKem({ userId, deviceId: deviceRow.device_id, signPub: deviceRow.sign_pub, kemPub: deviceRow.kem_pub, signature: deviceRow.kem_sig });
  return ok ? deviceRow.kem_pub : null;
}

/** What a new device shows in its link code, and later holds the keys it's sent to. */
export function linkPinFor(chain) {
  return { version: chain.latest.version, digest: headDigest(chain) };
}

/** True once this account's current key has a post-quantum key. */
export const chainIsPostQuantum = (chain) => Boolean(chain?.latest?.kem_pub);

/** True once the account's recovery backup is sealed to a post-quantum key from the phrase. */
export const recoveryIsPostQuantum = (chain) => Boolean(chain?.latest?.recovery_kem_pub);

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
    const statement = await makeAccountStatement({
      userId, keyVersion: v1, recoveryPub: recovery.publicKey, recoveryKemPub: recovery.kemPublicKey, signer: v1,
    });
    statement.recovery_mac = await recoveryAnchorMac(recovery.anchorKey, statement);
    const cert = await makeDeviceCert({ userId, device, keyVersion: v1, kemPub: device.kem_pub || "" });
    const sealedRecovery = await sealKeyringForRecovery(keyring, recovery.publicKey, recovery.kemPublicKey);
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
  // The link code the person compared covers the new device's post-quantum key too.
  const kemPub = target.kem_pub || "";
  const cert = await makeDeviceCert({ userId, device: target, keyVersion: latest, kemPub });
  const envelope = await sealKeyringToDevice(keyring, target, kemPub || null);
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
  const envelope = await sealKeyringToDevice(keyring, target, await verifiedDeviceKem(userId, target, chain));
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
    kemPriv: device.kem_priv || null,
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
      recoveryKemPub: chain.latest.recovery_kem_pub || "",
      sealed: recovery.sealed,
    });
    assertKeyringMatchesChain(keyring, chain);
    const cert = await makeDeviceCert({ userId, device, keyVersion: latestKey(keyring), kemPub: device.kem_pub || "" });
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
    // An ordinary rotation keeps the phrase, so it keeps the phrase's post-quantum key, if the
    // account has one; only a new phrase can add one (it's derived from the phrase).
    let recoveryKemPub = chain.latest.recovery_kem_pub || "";
    if (newPhrase) {
      phrase = generateRecoveryPhrase();
      recovery = await deriveRecoveryKey(phrase);
      recoveryPub = recovery.publicKey;
      recoveryKemPub = recovery.kemPublicKey;
    }
    const prev = latestKey(keyring);
    const next = await createKeyVersion(prev.version + 1);
    const statement = await makeAccountStatement({ userId, keyVersion: next, recoveryPub, recoveryKemPub, signer: prev });
    if (recovery) statement.recovery_mac = await recoveryAnchorMac(recovery.anchorKey, statement);
    const nextKeyring = withVersion(keyring, next);
    const certs = [];
    const envelopes = [];
    for (const d of keep) {
      // This device's own post-quantum key is known; others' only count if they can be vouched for.
      const kemPub = d.device_id === device.device_id ? device.kem_pub || "" : (await verifiedDeviceKem(userId, d, chain)) || "";
      certs.push(await makeDeviceCert({ userId, device: d, keyVersion: next, kemPub }));
      if (d.device_id !== device.device_id) {
        envelopes.push({ device_id: d.device_id, ...(await sealKeyringToDevice(nextKeyring, d, kemPub || null)), key_sign_pub: next.sign_pub });
      }
    }
    const backup = { ...(await sealKeyringForRecovery(nextKeyring, recoveryPub, recoveryKemPub)), key_sign_pub: next.sign_pub };
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
    const statement = await makeAccountStatement({
      userId, keyVersion: key, recoveryPub: recovery.publicKey, recoveryKemPub: recovery.kemPublicKey, signer: key,
    });
    statement.recovery_mac = await recoveryAnchorMac(recovery.anchorKey, statement);
    const cert = await makeDeviceCert({ userId, device, keyVersion: key, kemPub: device.kem_pub || "" });
    const backup = { ...(await sealKeyringForRecovery(keyring, recovery.publicKey, recovery.kemPublicKey)), key_sign_pub: key.sign_pub };
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

/**
 * A device set up before post-quantum keys publishes the one it just made, with its own
 * signature, so the next key rotation can certify it and seal keys to it.
 */
export async function prepareSetDeviceKem({ userId, device }) {
  const kem_sig = await signDeviceKem({ userId, device });
  return signedRequest({ userId, device, action: "set_device_kem", payload: { kem_pub: device.kem_pub, kem_sig } });
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
    return { user_id: uid, key_version: chain.latest.version, ecdh_pub: chain.latest.ecdh_pub, kem_pub: chain.latest.kem_pub || null };
  });
}

async function buildItem({ kind, userId, device, conversation, chains, payload, keyring, itemId: presetId = null }) {
  // Your own copy goes to your own current key, as this device's keyring proves it to be.
  if (keyring) {
    const own = chains.get(userId);
    const k = latestKey(keyring);
    if (!own || own.latest.version !== k.version || own.latest.ecdh_pub !== k.ecdh_pub) {
      throw new IdentityError("KEYRING_MISMATCH", "Your keys changed. Refresh and try again.");
    }
  }
  const itemId = presetId && isItemId(presetId) ? presetId : randomId(16);
  const sentAt = new Date().toISOString();
  const scope = { kind, conversation_id: conversation.id, item_id: itemId, sender_id: userId, device_id: device.device_id };
  const envelope = JSON.stringify(await encryptEnvelope({ scope, recipients: recipientsFor(conversation.member_ids, chains), payload }));
  const signature = await signItem({
    device, kind, conversationId: conversation.id, itemId, senderId: userId, deviceId: device.device_id, envelopeJson: envelope, sentAt,
  });
  return { itemId, sentAt, envelope, signature };
}

function cleanMessageText(text) {
  const clean = String(text || "").replace(/\r\n/g, "\n");
  if (!clean.trim()) throw new Error("Message is empty");
  if (clean.length > MAX_MESSAGE_CHARS) throw new Error(`Messages can be up to ${MAX_MESSAGE_CHARS} characters`);
  return clean;
}

/**
 * The conversation's timer goes inside the encrypted, signed message too, so the sender's
 * choice holds in every member's app whatever the server says.
 */
const timerOf = (conversation) => {
  const seconds = Number(conversation.expire_seconds) || 0;
  return EXPIRY_CHOICES.includes(seconds) && seconds > 0 ? { expire_seconds: seconds } : {};
};

async function buildMessageBody({ userId, device, conversation, chains, payload, keyring, itemId = null }) {
  const item = await buildItem({ kind: "message", userId, device, conversation, chains, payload: { ...payload, ...timerOf(conversation) }, keyring, itemId });
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

/**
 * chains: Map(user_id -> verified chain) covering every member, including you.
 * replyTo: the msg_id of the message this answers, if any. Only the id is sent, never a copy of it.
 */
export async function buildMessage({ userId, device, conversation, chains, text, keyring = null, replyTo = null }) {
  const payload = { type: "text", text: cleanMessageText(text) };
  if (replyTo !== null && replyTo !== undefined) {
    if (!isItemId(replyTo)) throw new Error("That message can't be replied to.");
    payload.reply_to = replyTo;
  }
  return buildMessageBody({ userId, device, conversation, chains, payload, keyring });
}

/** Add (or, with remove, take back) one of the offered reactions to a message. */
export async function buildReaction({ userId, device, conversation, chains, keyring = null, target, emoji, remove = false }) {
  if (!isItemId(target)) throw new Error("That message can't be reacted to.");
  if (!isReactionEmoji(emoji)) throw new Error("Choose one of the offered reactions.");
  const payload = { type: "reaction", target, emoji, ...(remove ? { remove: true } : {}) };
  return buildMessageBody({ userId, device, conversation, chains, payload, keyring });
}

/** Any other checked payload (a poll, a vote), built like a message. */
export async function buildPayloadMessage({ userId, device, conversation, chains, keyring = null, payload, itemId = null }) {
  if (!messageContent(payload)) throw new Error("That can't be sent.");
  return buildMessageBody({ userId, device, conversation, chains, payload, keyring, itemId });
}

// ---------- reports to a server's moderators ----------

export const REPORT_REASONS = Object.freeze(["spam", "harassment", "hate", "sexual", "violence", "self_harm", "scam", "illegal", "other"]);

/** A report's content, checked field by field. */
export function cleanReport(p, serverId) {
  if (!p || typeof p !== "object" || p.type !== "report" || p.server_id !== serverId) return null;
  if (!REPORT_REASONS.includes(p.reason) || !isUserish(p.target_id)) return null;
  const s = (v, max) => (typeof v === "string" ? v.slice(0, max) : "");
  const quote = p.quote && typeof p.quote === "object" && typeof p.quote.text === "string"
    ? { text: p.quote.text.slice(0, MAX_MESSAGE_CHARS), author_id: isUserish(p.quote.author_id) ? p.quote.author_id : "", sent_at: s(p.quote.sent_at, 40) }
    : null;
  return {
    type: "report", server_id: serverId, target_id: p.target_id, reason: p.reason, note: s(p.note, 1000),
    channel_id: isUserish(p.channel_id) ? p.channel_id : "", msg_id: isItemId(p.msg_id) ? p.msg_id : "", quote,
  };
}
const isUserish = (v) => typeof v === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(v);

/**
 * A report sealed to exactly these people (the reporter and the moderators), with each one's
 * current account key, like a group message: the service can't read it.
 */
export async function buildReport({ userId, device, serverId, recipients, chains, keyring = null, payload }) {
  const content = cleanReport(payload, serverId);
  if (!content) throw new Error("That report isn't complete.");
  const item = await buildItem({ kind: "report", userId, device, conversation: { id: serverId, member_ids: recipients }, chains, payload: content, keyring });
  return { item_id: item.itemId, envelope: item.envelope, signature: item.signature, device_id: device.device_id, sent_at: item.sentAt };
}

/** Open a report row from the moderation function. */
export async function openReport({ row, userId, keyring, senderChain, senderDevices }) {
  const item = { msg_id: row.report_id, conversation_id: row.server_id, sender_id: row.reporter_id, device_id: row.device_id, envelope: row.envelope, signature: row.signature, sent_at: row.sent_at };
  const r = await openItem({ kind: "report", item, userId, keyring, senderChain, senderDevices, reportServerId: row.server_id });
  if (r.content && r.content.target_id !== row.target_id) return { status: "locked", code: "MISMATCH", message: "This report doesn't match who it's filed against." };
  return r;
}

/** New text for one of your own messages. Everyone sees that it was edited. */
export async function buildEdit({ userId, device, conversation, chains, keyring = null, target, text }) {
  if (!isItemId(target)) throw new Error("That message can't be edited.");
  const payload = { type: "edit", target, text: cleanMessageText(text) };
  return buildMessageBody({ userId, device, conversation, chains, payload, keyring });
}

/** What a decrypted message says, checked field by field. Unknown kinds and stray fields are dropped. */
function messageContent(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  const seconds = Number(payload.expire_seconds);
  const timer = EXPIRY_CHOICES.includes(seconds) && seconds > 0 ? { expire_seconds: seconds } : {};
  if (payload.type === "text" || payload.type === undefined) {
    if (typeof payload.text !== "string") return null;
    const files = cleanAttachments(payload.attachments);
    if (!payload.text.trim() && !files.length) return null;
    return { type: "text", text: payload.text.slice(0, MAX_MESSAGE_CHARS), ...(isItemId(payload.reply_to) ? { reply_to: payload.reply_to } : {}), ...(payload.forwarded === true ? { forwarded: true } : {}), ...(files.length ? { attachments: files } : {}), ...timer };
  }
  if (payload.type === "reaction") {
    if (!isItemId(payload.target) || !isReactionEmoji(payload.emoji)) return null;
    return { type: "reaction", target: payload.target, emoji: payload.emoji, remove: payload.remove === true, ...timer };
  }
  if (payload.type === "poll") {
    const poll = cleanPoll(payload);
    return poll ? { ...poll, ...timer } : null;
  }
  if (payload.type === "vote") {
    const vote = cleanVote(payload);
    return vote ? { ...vote, ...timer } : null;
  }
  if (payload.type === "call") {
    // A call starting: its id, and the key its audio and video frames are sealed with.
    if (typeof payload.call_id !== "string" || !/^[A-Za-z0-9_-]{8,32}$/.test(payload.call_id)) return null;
    if (typeof payload.key !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(payload.key)) return null;
    return { type: "call", call_id: payload.call_id, key: payload.key, video: payload.video === true, ...timer };
  }
  if (payload.type === "edit") {
    if (!isItemId(payload.target) || typeof payload.text !== "string" || !payload.text.trim()) return null;
    return { type: "edit", target: payload.target, text: payload.text.slice(0, MAX_MESSAGE_CHARS), ...timer };
  }
  return null;
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
export async function openItem({ kind, item, userId, keyring, senderChain, senderDevices, minCertVersion = 1, reportServerId = null }) {
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
  const base = { status: verified ? "ok" : "unverified", reason: verified ? null : reason, removedDevice: dev?.status === "revoked" };
  if (kind === "title") {
    if (typeof payload?.title !== "string") return { status: "locked", code: "BAD_PAYLOAD", message: "Unrecognised content." };
    return { ...base, text: payload.title.slice(0, 80) };
  }
  if (kind === "report") {
    const report = cleanReport(payload, reportServerId);
    // A report is about the person it says it's about: the service can't relabel it.
    return report ? { ...base, content: report, text: report.note } : { status: "locked", code: "BAD_PAYLOAD", message: "Unrecognised report." };
  }
  const content = messageContent(payload);
  if (!content) return { status: "locked", code: "BAD_PAYLOAD", message: "This message needs a newer version of Commonveil." };
  return { ...base, text: textOf(content), content };
}
