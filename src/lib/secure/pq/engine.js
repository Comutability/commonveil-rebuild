// The experimental protocol layer on a device, as pure functions over a plain JSON state: no
// network and no storage, so the tests can drive the real backend handlers with it.
//
// What it does (docs/SECURE_NET_LAYER.md): each account gets a Secure Net actor (CVP-017) whose devices
// hold post-quantum sessions with other people's devices (CVP-016). A direct message is sealed a
// second time under a one-off key, and that key travels to each device over those sessions as a
// signed activity (CVP-018) in a direct envelope (CVP-019). Opening the message then needs both
// the account keys it has always needed and the one-off key, which only the devices that were
// there at the time hold: forward secrecy, quantum-resistant, on top of what was already there.
import { b64u, fromB64u, utf8 } from "../../../../packages/secure-net/src/core/bytes.js";
import { createAccount, createDevice, signDeviceList, createPrekeys, moreOneTimePrekeys, safetyNumber } from "../../../../packages/secure-net/src/session/keys.js";
import { initiate, respond, decrypt, isInitial, initialSender, handshakeId } from "../../../../packages/secure-net/src/session/session.js";
import { createActorDocument, verifyActorDocument, actorIdOf, parseHandle } from "../../../../packages/secure-net/src/social/actor.js";
import { signActivity, verifyActivity } from "../../../../packages/secure-net/src/social/activity.js";
import { sealDirect, openDirectPayload, sessionTag, envelopeProblems } from "../../../../packages/secure-net/src/social/delivery.js";

/** The object type that carries a message's one-off key (an extension type, CVP-021). */
export const KEY_TYPE = "io.github.comutability.messagekey";
export const ONE_TIME = 10;
const MAX_HANDSHAKES = 500;
const ITEM = /^[A-Za-z0-9_-]{16,64}$/;

export class PqError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PqError";
    this.code = code;
  }
}

const clone = (v) => JSON.parse(JSON.stringify(v));
const handleFor = (username, host) => `${String(username).toLowerCase()}@${host}`;

function fresh(account, handle, name) {
  const device = createDevice();
  return { v: 1, handle, name: name || undefined, account, device, seq: 0, deviceList: null, actor: null, prekeys: {}, sessions: {}, tags: {}, handshakes: [], peers: {}, sent: {} };
}

function republish(state, devices, former = []) {
  const s = state;
  s.seq += 1;
  s.deviceList = signDeviceList(s.account, devices, { seq: s.seq });
  s.actor = createActorDocument(s.account, { handle: s.handle, name: s.name, devices: s.deviceList, former, seq: s.seq });
  return s;
}

/** The first device of an account turns the layer on. */
export function createIdentity({ username, host, name }) {
  const handle = handleFor(username, host);
  if (!parseHandle(handle)) throw new PqError("BAD_HANDLE", "This site's address or your username can't be used as a handle.");
  const s = fresh(createAccount(), handle, name);
  return republish(s, [{ kid: s.device.kid, sign: s.device.sign.publicKey, dh: s.device.dh.pk }]);
}

/**
 * Another device of the same account joins: given the account key (opened from the copy sealed to
 * the account's keyring) and the actor document the site holds, it adds itself to the device list.
 */
export function joinIdentity({ accountSecret, document, username, host, name }) {
  const body = verifyActorDocument(document, { handle: handleFor(username, host) });
  const account = { kid: body.id, publicKey: body.account, secretKey: accountSecret };
  const s = fresh(account, body.handle, name ?? body.name);
  s.seq = body.seq;
  const others = body.devices.body.devices.filter((d) => d.kid !== s.device.kid);
  if (others.length >= 10) throw new PqError("TOO_MANY", "This account already has ten devices using the experimental protocol.");
  return republish(s, [...others, { kid: s.device.kid, sign: s.device.sign.publicKey, dh: s.device.dh.pk }], body.former);
}

/** Fresh prekeys for this device, to publish. Returns { state, publish }. */
export function makePrekeys(state, { full = true, oneTime = ONE_TIME, pqOneTime = ONE_TIME } = {}) {
  const s = clone(state);
  if (full) {
    const { secrets, published } = createPrekeys(s.device, { oneTime, pqOneTime });
    Object.assign(s.prekeys, secrets);
    return { state: s, publish: { device: s.device.kid, signed: JSON.stringify(published.signed), lastResort: JSON.stringify(published.lastResort), oneTime: published.oneTime.map((r) => JSON.stringify(r)), pqOneTime: published.pqOneTime.map((r) => JSON.stringify(r)) } };
  }
  const more = moreOneTimePrekeys(s.device, { oneTime, pqOneTime });
  Object.assign(s.prekeys, more.secrets);
  return { state: s, publish: { device: s.device.kid, oneTime: more.oneTime.map((r) => JSON.stringify(r)), pqOneTime: more.pqOneTime.map((r) => JSON.stringify(r)) } };
}

/**
 * Take in this account's own actor document as the site holds it (another of its devices may
 * have joined or left). It must be the same actor, signed by the same account key, and not older.
 */
export function refreshSelf(state, documentJson) {
  const s = clone(state);
  const record = JSON.parse(documentJson);
  const body = verifyActorDocument(record, { id: actorIdOf(s.account.publicKey), minSeq: s.seq });
  if (body.account !== s.account.publicKey) throw new PqError("UNTRUSTED", "That isn't this account's identity");
  if (!body.devices.body.devices.some((d) => d.kid === s.device.kid)) throw new PqError("REMOVED", "This device was removed from the account's protocol devices.");
  s.seq = body.seq;
  s.actor = record;
  s.deviceList = body.devices;
  return s;
}

export const myActorId = (state) => actorIdOf(state.account.publicKey);
export const safetyNumberWith = (state, peer) => safetyNumber(state.account.publicKey, peer.account);

/**
 * Take in someone's actor document, as the site gave it for their user id. It must verify, be for
 * their username on this site, and be the same actor as before (pinned on first sight): a
 * different one is refused, and the layer isn't used with them until a person has looked.
 * Returns { state, peer } with peer null when they can't be used.
 */
export function learnPeer(state, { userId, username, host, documentJson }) {
  const s = clone(state);
  let record;
  let body;
  try {
    record = JSON.parse(documentJson);
    body = verifyActorDocument(record, { handle: handleFor(username, host) });
  } catch (e) {
    return { state: s, peer: null, problem: e.code || "BAD_DOCUMENT" };
  }
  const known = s.peers[userId];
  if (known && known.id !== body.id) return { state: s, peer: null, problem: "ACTOR_CHANGED" };
  if (known && body.seq < known.seq) return { state: s, peer: null, problem: "ROLLBACK" };
  s.peers[userId] = { id: body.id, seq: body.seq, record };
  return { state: s, peer: body };
}

const peerBody = (state, userId) => (state.peers[userId] ? verifyActorDocument(state.peers[userId].record, { id: state.peers[userId].id }) : null);
const userOfActor = (state, actorId) => Object.keys(state.peers).find((u) => state.peers[u].id === actorId) || null;

/** The devices a key must reach: every device of each recipient, and this account's other devices. */
export function targetsFor(state, userIds, myUserId) {
  const out = [];
  for (const uid of new Set([...userIds, myUserId])) {
    const body = uid === myUserId ? verifyActorDocument(state.actor) : peerBody(state, uid);
    if (!body) throw new PqError("NO_PEER", "Someone here isn't using the experimental protocol.");
    for (const d of body.devices.body.devices) if (d.kid !== state.device.kid) out.push({ userId: uid, actor: body, device: d.kid, needsBundle: !state.sessions[d.kid] });
  }
  return out;
}

/**
 * Seal a message's one-off key for the given targets. bundles: device kid -> prekey bundle, for
 * targets that need one. Returns { state, items: [{ to: userId, envelope }] }.
 */
export async function sealMessageKey(state, { targets, bundles = {}, conversationId, itemId, key, now = Date.now() }) {
  if (!ITEM.test(itemId) || key.length !== 32) throw new PqError("BAD_INPUT", "Bad message key");
  const s = clone(state);
  const me = myActorId(s);
  const items = [];
  const byActor = new Map();
  for (const t of targets) {
    if (!s.sessions[t.device]) {
      if (!bundles[t.device]) throw new PqError("NO_BUNDLE", "A device's prekeys couldn't be fetched.");
      s.sessions[t.device] = initiate({ me: { device: s.device, deviceList: s.deviceList }, bundle: bundles[t.device], accountKey: t.actor.account, minSeq: t.actor.devices.body.seq, now });
      s.tags[sessionTag(s.sessions[t.device])] = t.device;
    }
    if (!byActor.has(t.actor.id)) byActor.set(t.actor.id, { userId: t.userId, devices: [] });
    byActor.get(t.actor.id).devices.push(t.device);
  }
  for (const [actorId, { userId, devices }] of byActor) {
    const activity = signActivity(s.device, me, { type: "Create", to: [actorId], object: { type: KEY_TYPE, conversation: conversationId, message: itemId, key: b64u(key) } }, { encrypted: true, now });
    const sessions = Object.fromEntries(devices.map((d) => [d, s.sessions[d]]));
    const sendActor = s.sent[actorId] !== s.seq;
    const out = await sealDirect(sessions, { activity, ...(sendActor ? { actor: s.actor } : {}) });
    Object.assign(s.sessions, out.sessions);
    s.sent[actorId] = s.seq;
    for (const it of out.items) items.push({ to: userId, envelope: JSON.stringify(it.envelope) });
  }
  return { state: s, items };
}

/**
 * Open one envelope from the mailbox. fromUserId is who the site says sent it; the sender must be
 * that person's pinned actor (or this account's own). Returns { state, key } where key is
 * { userId, conversationId, itemId, key } when the envelope carried a message key, else null.
 * Throws PqError or a session error; the state passed in is never changed.
 */
export async function openMail(state, { fromUserId, myUserId, envelopeJson, now = Date.now() }) {
  const s = clone(state);
  let env;
  try {
    env = JSON.parse(envelopeJson);
  } catch {
    throw new PqError("BAD_MESSAGE", "Not an envelope");
  }
  if (envelopeProblems(env).length || env.mode !== "direct" || env.device !== s.device.kid) throw new PqError("BAD_MESSAGE", "Not a direct envelope for this device");
  const expected = fromUserId === myUserId ? { id: myActorId(s), account: s.account.publicKey } : s.peers[fromUserId] && { id: s.peers[fromUserId].id, account: s.peers[fromUserId].record.body.account };
  if (!expected) throw new PqError("UNKNOWN_SENDER", "From someone whose identity this device hasn't seen yet");
  let peer = s.tags[env.session];
  let plaintext;
  if (!peer && isInitial(env.message)) {
    const who = initialSender(env.message);
    if (who.account !== expected.account) throw new PqError("UNTRUSTED", "The sender isn't who the site says");
    if (s.handshakes.includes(who.handshake)) throw new PqError("REPLAY", "First message already received");
    const r = await respond({ me: { device: s.device, deviceList: s.deviceList, prekeys: s.prekeys }, message: env.message, accountKey: expected.account });
    s.handshakes = [...s.handshakes, handshakeId(env.message)].slice(-MAX_HANDSHAKES);
    s.prekeys = r.prekeys;
    peer = r.state.peer.device;
    s.sessions[peer] = r.state;
    s.tags[sessionTag(r.state)] = peer;
    plaintext = r.plaintext;
  } else {
    if (!peer || !s.sessions[peer]) throw new PqError("UNKNOWN_SESSION", "No session for that envelope");
    if (s.sessions[peer].peer.account !== expected.account) throw new PqError("UNTRUSTED", "The sender isn't who the site says");
    const r = await decrypt(s.sessions[peer], env.message);
    s.sessions[peer] = r.state;
    plaintext = r.plaintext;
  }
  const p = openDirectPayload(plaintext, { fromDevice: peer, fromActor: expected.id });
  let actorBody = fromUserId === myUserId ? verifyActorDocument(s.actor) : peerBody(s, fromUserId);
  if (p.actor && fromUserId !== myUserId) {
    const b = verifyActorDocument(p.actor, { id: expected.id, minSeq: s.peers[fromUserId].seq });
    s.peers[fromUserId] = { id: b.id, seq: b.seq, record: p.actor };
    actorBody = b;
  } else if (p.actor && fromUserId === myUserId) {
    // Another of our own devices changed the device list: use the newer one to check it.
    actorBody = verifyActorDocument(p.actor, { id: expected.id });
  }
  if (!p.activity) return { state: s, key: null };
  const a = verifyActivity(p.activity, actorBody, { encrypted: true, now });
  const o = a.object;
  if (a.type !== "Create" || o?.type !== KEY_TYPE) return { state: s, key: null };
  let key;
  try {
    key = fromB64u(o.key);
  } catch {
    key = null;
  }
  if (typeof o.conversation !== "string" || !ITEM.test(o.message || "") || !key || key.length !== 32) throw new PqError("BAD_MESSAGE", "Bad message key");
  return { state: s, key: { userId: fromUserId, conversationId: o.conversation, itemId: o.message, key } };
}

// ---- The second seal on a message's content ----

const ad = ({ conversationId, itemId, senderId }) => utf8(`commonveil/fs/v1\n${conversationId}\n${itemId}\n${senderId}`);
const aes = (key, usage) => globalThis.crypto.subtle.importKey("raw", key, "AES-GCM", false, [usage]);

/** Seal a message payload under a fresh one-off key. Returns { key, wrapped } (wrapped replaces the payload). */
export async function wrapPayload(payload, scope) {
  const key = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await globalThis.crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: ad(scope) }, await aes(key, "encrypt"), utf8(JSON.stringify(payload))));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv);
  out.set(ct, 12);
  return { key, wrapped: { type: "fs", v: 1, c: b64u(out) } };
}

/** Open a wrapped payload with its key. Throws if the key is wrong or it was sealed for another message. */
export async function unwrapPayload(wrapped, key, scope) {
  if (wrapped?.type !== "fs" || wrapped.v !== 1 || typeof wrapped.c !== "string") throw new PqError("BAD_MESSAGE", "Not a sealed payload");
  const raw = fromB64u(wrapped.c);
  const pt = await globalThis.crypto.subtle.decrypt({ name: "AES-GCM", iv: raw.slice(0, 12), additionalData: ad(scope) }, await aes(key, "decrypt"), raw.slice(12));
  return JSON.parse(new TextDecoder().decode(pt));
}

export { userOfActor };
