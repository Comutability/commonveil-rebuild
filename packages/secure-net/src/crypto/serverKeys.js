// Server (community) encryption. Groups seal every message's key to every member, which doesn't
// scale past a few dozen people. Servers instead share symmetric keys, handed to each member
// once, sealed to their account key (post-quantum where they have one):
//
// - Each server has two key chains. The history chain ("<server>.h") is for what everyone
//   who joins may read, from the start: the server's name and description, channel names,
//   roles, nicknames, and channels set to show their history to newcomers. The live chain
//   ("<server>.l") is for channels set to show newcomers only what's sent after they join.
// - A private channel (one only some roles can see) has its own chain ("<server>.c.<channel>").
// - A chain has generations. Each starts with a fresh random 32-byte key, published with a
//   signed commitment to it. A new generation starts when someone is banned, or removed from a
//   private server, so nothing sent afterwards can be read with keys they had.
// - The live chain moves on every hour inside a generation: K(n+1) = HKDF(K(n), ...). Someone
//   who joins is given the key for the hour they joined, and can work out later hours but never
//   earlier ones. (The server also doesn't list earlier messages to them.)
// - Members' apps hand keys to people who join (a "grant": the key sealed to the newcomer, signed
//   by the device that sealed it). The server can't read a grant, only store and deliver it.
//
// Every item (message, name, profile...) gets its own key, derived from the chain key and bound
// to exactly what it is: its kind, server, channel, id, sender, sending device, chain, generation
// and hour. Each envelope commits to its item key, so everyone holding the chain key reads the
// same thing. The sending device signs the envelope.
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 as syncSha256 } from "@noble/hashes/sha2.js";
import { CONTEXTS, canonical, chainGenerationFields, keyGrantFields, serverItemFields } from "./canonical.js";
import { CryptoFormatError, concatBytes, equalBytes, fromB64, fromUtf8, randomBytes, sha256B64, toB64, utf8 } from "./encoding.js";
import { aesDecrypt, aesEncrypt, aesKeyFromBytes, importEcdhPrivate, signBytes, verifyWithRaw } from "./primitives.js";
import { keyForVersion, openFromSender, sealToRecipient } from "./keyring.js";
import { isKemSealed } from "./kem.js";

/** Live chains move on once an hour. */
export const STEP_MS = 3600_000;
/** About eleven years of hours: a generation older than this must be replaced. */
export const MAX_STEPS = 100_000;
export const SERVER_ENVELOPE_VERSION = 1;

const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const CHAIN_RE = /^([A-Za-z0-9_-]{1,64})\.(h|l|c\.[A-Za-z0-9_-]{1,64})$/;
const KINDS = new Set(["message", "server", "channel", "role", "nick", "rules", "ban", "automod", "emoji", "stickers", "onboarding", "icon", "banner", "event", "rsvp", "case"]);

export class ServerKeyError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = "ServerKeyError";
    this.code = code;
  }
}

// ---------- chains ----------

export const historyChain = (serverId) => `${serverId}.h`;
export const liveChain = (serverId) => `${serverId}.l`;
export const channelChain = (serverId, channelId) => `${serverId}.c.${channelId}`;

/** { serverId, kind: "h" | "l" | "c", channelId } or null for something that isn't a chain id. */
export function parseChainId(chainId) {
  const m = typeof chainId === "string" ? CHAIN_RE.exec(chainId) : null;
  if (!m) return null;
  if (m[2] === "h" || m[2] === "l") return { serverId: m[1], kind: m[2], channelId: "" };
  return { serverId: m[1], kind: "c", channelId: m[2].slice(2) };
}

export const isLiveChain = (chainId) => parseChainId(chainId)?.kind === "l";

/** The hour of a live chain generation that a moment falls in. History and channel chains have only step 0. */
export function stepAt(chainId, startedAt, atMs) {
  if (!isLiveChain(chainId)) return 0;
  const start = Date.parse(startedAt);
  if (!Number.isFinite(start) || !Number.isFinite(atMs)) throw new ServerKeyError("BAD_TIME", "Invalid time");
  const step = Math.max(0, Math.floor((atMs - start) / STEP_MS));
  if (step > MAX_STEPS) throw new ServerKeyError("CHAIN_TOO_OLD", "This key generation has run out of hours.");
  return step;
}

const ratchetInfo = (chainId, generation, step) => utf8(`commonveil/ratchet/v1|${chainId}|${generation}|${step}`);

/** The key for a later hour of a live chain generation, from an earlier one. Never backwards. */
export function ratchetTo(keyBytes, chainId, generation, fromStep, toStep) {
  if (!(keyBytes instanceof Uint8Array) || keyBytes.length !== 32) throw new CryptoFormatError("Chain keys are 32 bytes");
  if (!Number.isInteger(fromStep) || !Number.isInteger(toStep) || toStep < fromStep) {
    throw new ServerKeyError("BEFORE_KEY", "That's from before this key.");
  }
  if (toStep - fromStep > MAX_STEPS) throw new ServerKeyError("CHAIN_TOO_OLD", "This key generation has run out of hours.");
  let k = keyBytes.slice();
  for (let n = fromStep + 1; n <= toStep; n += 1) {
    const next = hkdf(syncSha256, k, new Uint8Array(0), ratchetInfo(chainId, generation, n), 32);
    k.fill(0);
    k = next;
  }
  return k;
}

/** A hash of a generation's first key, published with it, so whoever is given that key can check it. */
export function generationCommit(chainId, generation, keyBytes) {
  return toB64(syncSha256(concatBytes(utf8(`commonveil/chain-commit/v1|${chainId}|${generation}|`), keyBytes)));
}

/**
 * Keys this device holds, by chain and generation. Each entry keeps the earliest step it has
 * (what it was given) and the latest one worked out, so moving on an hour is one step of work.
 */
export class ChainKeys {
  constructor() {
    this.map = new Map();
  }

  #key(chainId, generation) {
    return `${chainId}|${generation}`;
  }

  /** Add a key for a generation at a step. A key for an earlier step of the same generation wins. */
  add(chainId, generation, step, keyBytes) {
    const k = this.#key(chainId, generation);
    const have = this.map.get(k);
    if (have && have.step <= step) return;
    this.map.set(k, { step, key: keyBytes.slice(), latestStep: step, latestKey: keyBytes.slice() });
  }

  has(chainId, generation) {
    return this.map.has(this.#key(chainId, generation));
  }

  /** The earliest step held for a generation, or null. */
  firstStep(chainId, generation) {
    return this.map.get(this.#key(chainId, generation))?.step ?? null;
  }

  /** The key for a generation at a step, or throws ServerKeyError (NO_KEY, BEFORE_KEY). */
  get(chainId, generation, step) {
    const entry = this.map.get(this.#key(chainId, generation));
    if (!entry) throw new ServerKeyError("NO_KEY", "This device hasn't been given that key yet.");
    if (step < entry.step) throw new ServerKeyError("BEFORE_KEY", "That's from before you could read here.");
    if (step === entry.step) return entry.key;
    if (step >= entry.latestStep) {
      const k = ratchetTo(entry.latestKey, chainId, generation, entry.latestStep, step);
      entry.latestKey.fill(0);
      entry.latestKey = k;
      entry.latestStep = step;
      return k;
    }
    return ratchetTo(entry.key, chainId, generation, entry.step, step);
  }

  /** Forget everything (locking, signing out). */
  clear() {
    for (const entry of this.map.values()) {
      entry.key.fill(0);
      entry.latestKey.fill(0);
    }
    this.map.clear();
  }

  get size() {
    return this.map.size;
  }
}

// ---------- generations ----------

/**
 * A new generation for a chain, made on this device: a fresh key, and a signed statement of
 * the generation (number, start, commitment). Returns { generation: statement, keyBytes }.
 */
export async function makeGeneration({ serverId, chainId, generation, userId, device, startedAt = new Date().toISOString() }) {
  if (parseChainId(chainId)?.serverId !== serverId) throw new ServerKeyError("BAD_CHAIN", "That key chain isn't this server's.");
  if (!Number.isInteger(generation) || generation < 0) throw new ServerKeyError("BAD_GENERATION", "Invalid key generation.");
  const keyBytes = randomBytes(32);
  const statement = {
    server_id: serverId,
    chain_id: chainId,
    generation,
    started_at: startedAt,
    commit: generationCommit(chainId, generation, keyBytes),
    creator_id: userId,
    device_id: device.device_id,
  };
  statement.signature = await signBytes(device.sign_priv, utf8(canonical(CONTEXTS.chainGeneration, chainGenerationFields(statement))));
  return { generation: statement, keyBytes };
}

/** True if a generation statement is signed by the given device key. */
export function verifyGeneration(statement, signPub) {
  return verifyWithRaw(signPub, statement.signature, canonical(CONTEXTS.chainGeneration, chainGenerationFields(statement)));
}

// ---------- grants ----------

export const grantContext = (g) =>
  `commonveil/key-grant/v1|${g.server_id}|${g.chain_id}|${g.generation}|${g.step}|${g.recipient_id}|${g.recipient_key_version}`;

/**
 * Seal a chain key to one member. recipient: { user_id, key_version, ecdh_pub, kem_pub } from
 * their verified key history. The device that seals it signs the grant.
 */
export async function makeGrant({ serverId, chainId, generation, step, keyBytes, recipient, userId, device }) {
  const base = {
    server_id: serverId,
    chain_id: chainId,
    generation,
    step,
    recipient_id: recipient.user_id,
    recipient_key_version: recipient.key_version,
  };
  const sealed = JSON.stringify(await sealToRecipient({ ecdhPub: recipient.ecdh_pub, kemPub: recipient.kem_pub || null }, keyBytes, grantContext(base)));
  /** @type {Record<string, any>} */
  const grant = { ...base, sealed, grantor_id: userId, grantor_device_id: device.device_id, granted_at: new Date().toISOString() };
  grant.signature = await signBytes(device.sign_priv, utf8(await grantText(grant)));
  return grant;
}

async function grantText(g) {
  return canonical(CONTEXTS.keyGrant, keyGrantFields({ ...g, sealed_hash: await sha256B64(g.sealed) }));
}

export async function verifyGrantSignature(grant, signPub) {
  return verifyWithRaw(signPub, grant.signature, await grantText(grant));
}

/** Open a grant made to this account. Returns the 32-byte key. */
export async function openGrant({ grant, userId, keyring }) {
  if (grant.recipient_id !== userId) throw new ServerKeyError("NOT_YOURS", "That key was given to someone else.");
  const kv = keyForVersion(keyring, grant.recipient_key_version);
  if (!kv) throw new ServerKeyError("KEY_VERSION_MISSING", "That key was sealed to an account key this device doesn't hold.");
  let sealed;
  try {
    sealed = JSON.parse(grant.sealed);
  } catch {
    throw new ServerKeyError("BAD_GRANT", "That key is malformed.");
  }
  let bytes;
  try {
    const ecdhPriv = isKemSealed(sealed) ? null : await importEcdhPrivate(kv.ecdh_priv);
    bytes = await openFromSender({ ecdhPriv, ecdhPub: kv.ecdh_pub, kemPriv: kv.kem_priv || null }, sealed, grantContext(grant));
  } catch {
    throw new ServerKeyError("GRANT_UNREADABLE", "That key couldn't be opened.");
  }
  if (bytes.length !== 32) throw new ServerKeyError("BAD_GRANT", "That key is malformed.");
  return bytes;
}

// ---------- encrypted items ----------

function checkScope(s) {
  if (!s || !KINDS.has(s.kind)) throw new ServerKeyError("BAD_SCOPE", "Unknown item kind");
  for (const name of ["server_id", "item_id", "sender_id", "device_id"]) {
    if (typeof s[name] !== "string" || !ID_RE.test(s[name])) throw new ServerKeyError("BAD_SCOPE", `Invalid ${name}`);
  }
  if (typeof s.channel_id !== "string" || (s.channel_id && !ID_RE.test(s.channel_id))) throw new ServerKeyError("BAD_SCOPE", "Invalid channel_id");
  if (parseChainId(s.chain_id)?.serverId !== s.server_id) throw new ServerKeyError("BAD_SCOPE", "Invalid chain");
  if (!Number.isInteger(s.generation) || s.generation < 0 || !Number.isInteger(s.step) || s.step < 0) throw new ServerKeyError("BAD_SCOPE", "Invalid generation");
}

export const itemContext = (s) =>
  `commonveil/server-content/v1|${s.kind}|${s.server_id}|${s.channel_id}|${s.item_id}|${s.sender_id}|${s.device_id}|${s.chain_id}|${s.generation}|${s.step}`;

function itemKey(chainKey, context) {
  return hkdf(syncSha256, chainKey, utf8("commonveil/server-item-key/v1"), utf8(context), 32);
}

const keyCommitment = (context, key) => syncSha256(concatBytes(utf8(`commonveil/key-commitment/v1|${context}|`), key));

/**
 * Encrypt one item. scope: { kind, server_id, channel_id ("" for server-wide items), item_id,
 * sender_id, device_id, chain_id, generation, step }; chainKey: that chain's key at that step.
 * Returns the envelope, as an object: { v, chain, gen, step, iv, ct, kc }.
 */
export async function encryptServerItem({ scope, chainKey, payload }) {
  checkScope(scope);
  const context = itemContext(scope);
  const key = itemKey(chainKey, context);
  try {
    const { iv, ct } = await aesEncrypt(await aesKeyFromBytes(key), utf8(JSON.stringify(payload)), utf8(context));
    return { v: SERVER_ENVELOPE_VERSION, chain: scope.chain_id, gen: scope.generation, step: scope.step, iv: toB64(iv), ct: toB64(ct), kc: toB64(keyCommitment(context, key)) };
  } finally {
    key.fill(0);
  }
}

/** Parse and check an envelope's shape. Throws ServerKeyError BAD_ENVELOPE. */
export function parseServerEnvelope(text) {
  let env;
  try {
    env = typeof text === "string" ? JSON.parse(text) : text;
    if (!env || env.v !== SERVER_ENVELOPE_VERSION || !parseChainId(env.chain)) throw new Error("shape");
    if (!Number.isInteger(env.gen) || env.gen < 0 || !Number.isInteger(env.step) || env.step < 0) throw new Error("gen");
    if (fromB64(env.iv).length !== 12 || fromB64(env.ct).length < 17 || fromB64(env.kc).length !== 32) throw new Error("bytes");
  } catch {
    throw new ServerKeyError("BAD_ENVELOPE", "This item is malformed.");
  }
  return env;
}

/**
 * Decrypt an item with the chain keys this device holds. base: the scope without the chain
 * fields (they come from the envelope, which the sender signed). Throws ServerKeyError: NO_KEY
 * (not given that key yet), BEFORE_KEY (from before you could read it), DECRYPT_FAILED.
 */
export async function decryptServerItem({ base, envelope, keys }) {
  const env = parseServerEnvelope(envelope);
  const scope = { ...base, chain_id: env.chain, generation: env.gen, step: env.step };
  checkScope(scope);
  const chainKey = keys.get(env.chain, env.gen, env.step);
  const context = itemContext(scope);
  const key = itemKey(chainKey, context);
  try {
    if (!equalBytes(keyCommitment(context, key), fromB64(env.kc))) throw new ServerKeyError("DECRYPT_FAILED", "This item's key doesn't match its commitment.");
    const plain = await aesDecrypt(await aesKeyFromBytes(key), fromB64(env.iv), fromB64(env.ct), utf8(context));
    return { payload: JSON.parse(fromUtf8(plain)), chain: env.chain, generation: env.gen, step: env.step };
  } catch (error) {
    if (error instanceof ServerKeyError) throw error;
    throw new ServerKeyError("DECRYPT_FAILED", "This item failed its integrity check.");
  } finally {
    key.fill(0);
  }
}

/** @param {any} item */
async function itemText({ kind, serverId, channelId, itemId, senderId, deviceId, envelopeJson, sentAt }) {
  return canonical(
    CONTEXTS.serverItem,
    serverItemFields({ kind, server_id: serverId, channel_id: channelId, item_id: itemId, sender_id: senderId, device_id: deviceId, envelope_hash: await sha256B64(envelopeJson), sent_at: sentAt }),
  );
}

export async function signServerItem({ device, ...item }) {
  return signBytes(device.sign_priv, utf8(await itemText(item)));
}

export async function verifyServerItem({ signPub, signature, ...item }) {
  return verifyWithRaw(signPub, signature, await itemText(item));
}

// ---------- invite previews ----------

/**
 * An invite link is /invite/<code>#<secret>. Browsers never send the part after # to a server,
 * so the server stores the preview (server name, description, icon) encrypted under a key only
 * the link gives, and shows it to whoever opens the link without being able to read it itself.
 */
export function newInviteSecret() {
  return toB64(randomBytes(18)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function inviteKey(secret, code) {
  const raw = utf8(String(secret));
  return hkdf(syncSha256, raw, utf8("commonveil/invite-preview/v1"), utf8(String(code)), 32);
}

export async function sealInvitePreview({ code, secret, preview }) {
  const key = inviteKey(secret, code);
  try {
    const { iv, ct } = await aesEncrypt(await aesKeyFromBytes(key), utf8(JSON.stringify(preview)), utf8(`commonveil/invite-preview/v1|${code}`));
    return JSON.stringify({ v: 1, iv: toB64(iv), ct: toB64(ct) });
  } finally {
    key.fill(0);
  }
}

export async function openInvitePreview({ code, secret, sealed }) {
  const key = inviteKey(secret, code);
  try {
    const env = JSON.parse(sealed);
    const plain = await aesDecrypt(await aesKeyFromBytes(key), fromB64(env.iv), fromB64(env.ct), utf8(`commonveil/invite-preview/v1|${code}`));
    return JSON.parse(fromUtf8(plain));
  } catch {
    return null;
  } finally {
    key.fill(0);
  }
}