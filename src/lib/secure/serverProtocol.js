// Client side of server (community) encryption, as pure functions like protocol.js: build
// request bodies, open what comes back. No network, no storage. See crypto/serverKeys.js for
// the design. tests/servers.test.mjs drives the real backend handlers with these.
import { randomId } from "../crypto/encoding.js";
import {
  ChainKeys,
  ServerKeyError,
  channelChain,
  decryptServerItem,
  encryptServerItem,
  generationCommit,
  historyChain,
  liveChain,
  makeGeneration,
  makeGrant,
  openGrant,
  parseChainId,
  signServerItem,
  stepAt,
  verifyGeneration,
  verifyGrantSignature,
  verifyServerItem,
} from "../crypto/serverKeys.js";
import { MAX_MESSAGE_CHARS, REACTIONS, deviceIsCertified, sentAfterRemoval, signedRequest } from "./protocol.js";

export { ChainKeys, historyChain, liveChain, channelChain, parseChainId };

export const MAX_POST_TITLE = 100;
export const MAX_NAME = 100;
export const MAX_TOPIC = 300;
const ITEM_ID_RE = /^[A-Za-z0-9_-]{16,64}$/;
const isItemId = (v) => typeof v === "string" && ITEM_ID_RE.test(v);
const isId = (v) => typeof v === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(v);

/** The key chain a channel's messages use. The server checks the same rule. */
export function chainForChannel(serverId, channel) {
  if (channel.private) return channelChain(serverId, channel.id);
  return channel.history === "full" ? historyChain(serverId) : liveChain(serverId);
}

export function latestGeneration(generations, chainId) {
  let best = null;
  for (const g of generations || []) if (g.chain_id === chainId && (!best || g.generation > best.generation)) best = g;
  return best;
}

/** Encrypt and sign one item with a chain's current key. Returns the item fields the server stores. */
export async function buildServerItem({ kind, serverId, channelId = "", chainId = historyChain(serverId), generations, keys, userId, device, payload, at = Date.now() }) {
  const gen = latestGeneration(generations, chainId);
  if (!gen) throw new ServerKeyError("NO_KEYS_YET", "This server's encryption is still being set up. Try again in a moment.");
  const step = stepAt(chainId, gen.started_at, at);
  const chainKey = keys.get(chainId, gen.generation, step);
  const itemId = randomId(16);
  const sentAt = new Date(at).toISOString();
  const scope = { kind, server_id: serverId, channel_id: channelId, item_id: itemId, sender_id: userId, device_id: device.device_id, chain_id: chainId, generation: gen.generation, step };
  const envelope = JSON.stringify(await encryptServerItem({ scope, chainKey, payload }));
  const signature = await signServerItem({ device, kind, serverId, channelId, itemId, senderId: userId, deviceId: device.device_id, envelopeJson: envelope, sentAt });
  return { envelope, item_id: itemId, sender_id: userId, device_id: device.device_id, sent_at: sentAt, signature };
}

// ---------- payloads ----------

function cleanText(text, max, what = "Messages") {
  const clean = String(text || "").replace(/\r\n/g, "\n");
  if (!clean.trim()) throw new Error(`${what} can't be empty`);
  if (clean.length > max) throw new Error(`${what} can be up to ${max} characters`);
  return clean;
}

function mentionsOf(m) {
  if (!m) return undefined;
  const users = [...new Set((m.users || []).filter(isId))].slice(0, 50);
  const roles = [...new Set((m.roles || []).filter(isId))].slice(0, 20);
  const everyone = m.everyone === true;
  if (!users.length && !roles.length && !everyone) return undefined;
  return { users, roles, ...(everyone ? { everyone: true } : {}) };
}

export function textPayload(text, { replyTo = null, mentions = null } = {}) {
  const payload = { type: "text", text: cleanText(text, MAX_MESSAGE_CHARS) };
  if (replyTo) {
    if (!isItemId(replyTo)) throw new Error("That message can't be replied to.");
    payload.reply_to = replyTo;
  }
  const m = mentionsOf(mentions);
  if (m) payload.mentions = m;
  return payload;
}

export function postPayload(title, text, { mentions = null } = {}) {
  const payload = { type: "post", title: cleanText(title, MAX_POST_TITLE, "Titles").trim(), text: cleanText(text, MAX_MESSAGE_CHARS) };
  const m = mentionsOf(mentions);
  if (m) payload.mentions = m;
  return payload;
}

export function reactionPayload(target, emoji, remove = false) {
  if (!isItemId(target)) throw new Error("That message can't be reacted to.");
  if (!REACTIONS.includes(emoji)) throw new Error("Choose one of the offered reactions.");
  return { type: "reaction", target, emoji, ...(remove ? { remove: true } : {}) };
}

export function editPayload(target, text) {
  if (!isItemId(target)) throw new Error("That message can't be edited.");
  return { type: "edit", target, text: cleanText(text, MAX_MESSAGE_CHARS) };
}

const KIND_OF_TYPE = { text: "message", post: "post", reaction: "reaction", edit: "edit" };

/**
 * What a decrypted channel message says, checked field by field. The server sees each row's
 * kind (message, reaction, edit, post); the payload must agree, or it's dropped.
 */
export function serverMessageContent(payload, declaredKind) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  if (KIND_OF_TYPE[payload.type] !== declaredKind) return null;
  const mentions = mentionsOf(payload.mentions);
  if (payload.type === "text") {
    if (typeof payload.text !== "string") return null;
    return { type: "text", text: payload.text.slice(0, MAX_MESSAGE_CHARS), ...(isItemId(payload.reply_to) ? { reply_to: payload.reply_to } : {}), ...(mentions ? { mentions } : {}) };
  }
  if (payload.type === "post") {
    if (typeof payload.title !== "string" || typeof payload.text !== "string" || !payload.title.trim()) return null;
    return { type: "post", title: payload.title.slice(0, MAX_POST_TITLE), text: payload.text.slice(0, MAX_MESSAGE_CHARS), ...(mentions ? { mentions } : {}) };
  }
  if (payload.type === "reaction") {
    if (!isItemId(payload.target) || !REACTIONS.includes(payload.emoji)) return null;
    return { type: "reaction", target: payload.target, emoji: payload.emoji, remove: payload.remove === true };
  }
  if (payload.type === "edit") {
    if (!isItemId(payload.target) || typeof payload.text !== "string" || !payload.text.trim()) return null;
    return { type: "edit", target: payload.target, text: payload.text.slice(0, MAX_MESSAGE_CHARS) };
  }
  return null;
}

/** What a decrypted server-wide item says (a name, a profile...). Unknown fields are dropped. */
export function itemContent(kind, payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  const s = (v, max) => (typeof v === "string" ? v.slice(0, max) : "");
  if (kind === "server") return { name: s(payload.name, MAX_NAME), description: s(payload.description, 500), icon: s(payload.icon, 8), color: s(payload.color, 9), banner: s(payload.banner, 9) };
  if (kind === "channel") return { name: s(payload.name, MAX_NAME), topic: s(payload.topic, MAX_TOPIC) };
  if (kind === "role") return { name: s(payload.name, 60), color: s(payload.color, 9) };
  if (kind === "nick") return { nick: s(payload.nick, 32) };
  if (kind === "rules") return { rules: Array.isArray(payload.rules) ? payload.rules.filter((r) => typeof r === "string" && r.trim()).slice(0, 25).map((r) => r.slice(0, 500)) : [], intro: s(payload.intro, 1000) };
  if (kind === "ban") return { reason: s(payload.reason, 500) };
  return null;
}

/** A channel message, ready to send. kind: "message", "post", "reaction" or "edit". */
export async function buildChannelMessage({ serverId, channel, generations, keys, userId, device, payload, kind, threadId = "" }) {
  const item = await buildServerItem({ kind: "message", serverId, channelId: channel.id, chainId: chainForChannel(serverId, channel), generations, keys, userId, device, payload });
  return {
    action: "send",
    server_id: serverId,
    channel_id: channel.id,
    msg_id: item.item_id,
    kind,
    thread_id: threadId,
    envelope: item.envelope,
    signature: item.signature,
    device_id: device.device_id,
    sent_at: item.sent_at,
  };
}

// ---------- opening ----------

/**
 * Decrypt and verify one server item.
 * status: "ok", "unverified" (reason says why), "waiting" (this device hasn't been given that key
 * yet), "before" (from before you could read here), "locked" (can't be read), "deleted".
 * item: a message row ({ msg_id, sender_id, device_id, envelope, signature, sent_at, kind }), or an
 * item ({ item_id, ... }) with kind given.
 */
export async function openServerItem({ kind, item, serverId, channelId = "", keys, senderChain, senderDevices, minCertVersion = 1 }) {
  if (!item || item.deleted || !item.envelope) return { status: "deleted" };
  const itemId = kind === "message" ? item.msg_id : item.item_id;
  const base = { kind, server_id: serverId, channel_id: channelId, item_id: itemId, sender_id: item.sender_id, device_id: item.device_id };
  let decrypted;
  try {
    decrypted = await decryptServerItem({ base, envelope: item.envelope, keys });
  } catch (error) {
    if (error?.code === "NO_KEY") return { status: "waiting" };
    if (error?.code === "BEFORE_KEY") return { status: "before" };
    return { status: "locked", code: error?.code || "DECRYPT_FAILED" };
  }
  let verified = false;
  let reason = "unverified";
  const dev = (senderDevices || []).find((d) => d.device_id === item.device_id);
  if (dev && senderChain && (await deviceIsCertified(item.sender_id, dev, senderChain, { minVersion: minCertVersion }))) {
    verified = await verifyServerItem({
      signPub: dev.sign_pub, signature: item.signature, kind, serverId, channelId, itemId, senderId: item.sender_id, deviceId: item.device_id,
      envelopeJson: item.envelope, sentAt: item.sent_at,
    });
    if (verified && sentAfterRemoval(senderChain, dev.cert_key_version, item.sent_at)) {
      verified = false;
      reason = "removed-device";
    }
  }
  const out = { status: verified ? "ok" : "unverified", reason: verified ? null : reason, removedDevice: dev?.status === "revoked", chain: decrypted.chain };
  if (kind === "message") {
    const content = serverMessageContent(decrypted.payload, item.kind);
    if (!content) return { status: "locked", code: "BAD_PAYLOAD" };
    return { ...out, content, text: content.type === "reaction" ? "" : content.text };
  }
  const content = itemContent(kind, decrypted.payload);
  if (!content) return { status: "locked", code: "BAD_PAYLOAD" };
  return { ...out, content };
}

// ---------- keys ----------

/**
 * Open this member's grants into a ChainKeys. Keys for the start of a generation are checked
 * against its signed commitment. Returns { keys, unreadable } (grants that couldn't be opened,
 * for request_keys), and bad (grants that opened to the wrong key).
 */
export async function openGrants({ grants, generations, userId, keyring, keys = new ChainKeys() }) {
  const unreadable = [];
  const bad = [];
  for (const g of grants || []) {
    if (keys.has(g.chain_id, g.generation) && keys.firstStep(g.chain_id, g.generation) <= g.step) continue;
    let bytes;
    try {
      bytes = await openGrant({ grant: g, userId, keyring });
    } catch {
      unreadable.push(g.id);
      continue;
    }
    if (g.step === 0) {
      const gen = (generations || []).find((x) => x.chain_id === g.chain_id && x.generation === g.generation);
      if (!gen || generationCommit(g.chain_id, g.generation, bytes) !== gen.commit) {
        bad.push(g.id);
        continue;
      }
    }
    keys.add(g.chain_id, g.generation, g.step, bytes);
    bytes.fill(0);
  }
  return { keys, unreadable, bad };
}

const recipientOf = (userId, chain) => ({ user_id: userId, key_version: chain.latest.version, ecdh_pub: chain.latest.ecdh_pub, kem_pub: chain.latest.kem_pub || null });

/**
 * A new generation for a chain, with copies for the given people (chains: Map user_id -> verified
 * key chain, which must include the caller). Returns { request, keyBytes, generation }.
 */
export async function prepareGeneration({ serverId, chainId, generation, userId, device, chains, recipientIds }) {
  const { generation: statement, keyBytes } = await makeGeneration({ serverId, chainId, generation, userId, device });
  const grants = [];
  for (const uid of [...new Set([userId, ...recipientIds])]) {
    const chain = chains.get(uid);
    if (!chain) continue;
    grants.push(await makeGrant({ serverId, chainId, generation, step: 0, keyBytes, recipient: recipientOf(uid, chain), userId, device }));
  }
  const request = await signedRequest({ userId, device, action: "create_generation", payload: { server_id: serverId, generation: statement, grants } });
  return { request, keyBytes, generation: statement };
}

/**
 * Copies of keys for people waiting (items from pending_grants). Only keys this device holds,
 * only to verified key chains. Returns the request, or null if there's nothing to send.
 */
export async function prepareGrants({ serverId, items, keys, chains, userId, device }) {
  const grants = [];
  for (const it of items) {
    const chain = chains.get(it.user_id);
    if (!chain) continue;
    let keyBytes;
    try {
      keyBytes = keys.get(it.chain_id, it.generation, it.step);
    } catch {
      continue;
    }
    grants.push(await makeGrant({ serverId, chainId: it.chain_id, generation: it.generation, step: it.step, keyBytes, recipient: recipientOf(it.user_id, chain), userId, device }));
  }
  if (!grants.length) return null;
  return signedRequest({ userId, device, action: "grant_keys", payload: { server_id: serverId, grants } });
}

/** True if a generation statement is signed by a device the creator's verified chain certifies. */
export async function generationIsVouched({ generation, creatorChain, creatorDevices }) {
  const dev = (creatorDevices || []).find((d) => d.device_id === generation.device_id);
  if (!dev || !creatorChain || !(await deviceIsCertified(generation.creator_id, dev, creatorChain))) return false;
  return verifyGeneration(generation, dev.sign_pub);
}

/** True if a grant was sealed by a device the grantor's verified chain certifies. */
export async function grantIsVouched({ grant, grantorChain, grantorDevices }) {
  const dev = (grantorDevices || []).find((d) => d.device_id === grant.grantor_device_id);
  if (!dev || !grantorChain || !(await deviceIsCertified(grant.grantor_id, dev, grantorChain))) return false;
  return verifyGrantSignature(grant, dev.sign_pub);
}

/** A device-signed request about a server. */
export function serverRequest({ userId, device, action, payload }) {
  return signedRequest({ userId, device, action, payload });
}
