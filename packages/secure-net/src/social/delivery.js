// End-to-end delivery (CVP-019): how activities travel, and what sites can see.
//
// Three envelope modes. A site carries every one of them, and can read only the first:
//
//   public    the signed activity in the clear, for posts addressed to "public"
//   direct    a CVP-016 session message to one device: direct messages, follows, and the sender
//             keys that let followers read followers-only posts
//   audience  one sender-key message (CVP-016 groups) for everyone in an audience: followers-only
//             posts and group posts, encrypted once however many people receive them
//
// Inside the encryption is the activity, still signed by the device that made it, so whoever
// opens it can check who wrote it with quantum-resistant signatures.
import { canonicalBytes, canonicalJson } from "../core/canonical.js";
import { b64u, fromB64u, utf8, concat } from "../core/bytes.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { SessionError } from "../session/primitives.js";
import { encryptToDevices } from "../session/session.js";
import { createSenderKey, distribution, acceptDistribution, groupEncrypt, groupDecrypt } from "../session/group.js";
import { actorIdOf } from "./actor.js";
import { ACTIVITY } from "./activity.js";
import { ACTOR } from "./actor.js";
import { isActorId, isObjectId, newId, ownerOf, PUBLIC } from "./vocabulary.js";

export const MODES = Object.freeze(["public", "direct", "audience"]);
export const DELIVERY_LIMITS = Object.freeze({ items: 100, envelopeBytes: 512 * 1024, requestBytes: 4 * 1024 * 1024 });
const KID = /^[A-Za-z0-9_-]{22}$/;

/** Problems with an envelope's outer form (what a site checks before storing it). */
export function envelopeProblems(env) {
  if (!env || typeof env !== "object" || env.v !== 1) return ["Not a version 1 envelope"];
  if (!MODES.includes(env.mode)) return [`Unknown mode "${env.mode}"`];
  const out = [];
  if (env.mode === "public") {
    if (env.activity?.kind !== ACTIVITY || !env.activity.sig) out.push("A public envelope carries one signed activity");
    else if (![...(env.activity.body?.to || []), ...(env.activity.body?.cc || [])].includes(PUBLIC)) out.push("Only activities addressed to public may travel in the clear");
  } else if (env.mode === "direct") {
    if (!KID.test(env.device || "")) out.push("A direct envelope names the recipient device");
    if (!KID.test(env.session || "")) out.push("A direct envelope carries its session tag");
    if (env.message?.v !== 1 || typeof env.message?.c !== "string") out.push("A direct envelope carries one CVP-016 message");
  } else {
    if (!isObjectId(env.audience)) out.push("An audience envelope names its audience");
    if (env.message?.v !== 1 || env.message?.group !== env.audience || typeof env.message?.sig !== "string") out.push("An audience envelope carries one sender-key message for that audience");
  }
  for (const k of Object.keys(env)) if (!["v", "mode", "activity", "device", "session", "message", "audience"].includes(k)) out.push(`Unexpected field ${k}: envelopes carry nothing else, so they leak nothing else`);
  if (out.length === 0 && canonicalBytes(env).length > DELIVERY_LIMITS.envelopeBytes) out.push("Envelope is too large");
  return out;
}

/**
 * The tag a direct envelope carries so the recipient device knows which session opens it: derived
 * from the session's handshake hash, the same at both ends. A site sees which envelopes belong to
 * the same conversation, but not who is in it.
 */
export const sessionTag = (state) => b64u(sha256(concat(utf8("secure-net/social/v1/session\n"), fromB64u(state.ad)))).slice(0, 22);

const encode = (payload) => canonicalJson(payload);
function decode(bytes) {
  let p;
  try {
    p = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new SessionError("BAD_MESSAGE", "Payload isn't JSON");
  }
  if (!p || p.v !== 1 || (p.activity === undefined && p.senderKeys === undefined && p.actor === undefined)) throw new SessionError("BAD_MESSAGE", "Not a version 1 payload");
  if (p.actor !== undefined && p.actor?.kind !== ACTOR) throw new SessionError("BAD_MESSAGE", "Payload actor isn't an actor document");
  if (p.activity !== undefined && p.activity?.kind !== ACTIVITY) throw new SessionError("BAD_MESSAGE", "Payload activity isn't a signed activity");
  if (p.senderKeys !== undefined && !Array.isArray(p.senderKeys)) throw new SessionError("BAD_MESSAGE", "Bad sender keys");
  return p;
}

// ---- Public ----

/** The envelope for a public activity. */
export function publicEnvelope(record) {
  const env = { v: 1, mode: "public", activity: record };
  const p = envelopeProblems(env);
  if (p.length) throw new SessionError("BAD_INPUT", p.join("; "));
  return env;
}

// ---- Direct ----

/**
 * Seal a payload { activity?, senderKeys?, actor? } for several devices over their sessions
 * (sessions: device kid -> CVP-016 state). Returns { sessions, items: [{ to, envelope }] }, where
 * `to` is the recipient actor (the mailbox the envelope goes to).
 */
export async function sealDirect(sessions, { activity, senderKeys, actor }) {
  const payload = { v: 1 };
  if (activity) payload.activity = activity;
  if (senderKeys?.length) payload.senderKeys = senderKeys;
  if (actor) payload.actor = actor;
  const out = await encryptToDevices(sessions, encode(payload));
  const items = Object.entries(out.messages).map(([device, message]) => ({
    to: actorIdOf(sessions[device].peer.account),
    envelope: { v: 1, mode: "direct", device, session: sessionTag(out.sessions[device]), message },
  }));
  return { sessions: out.sessions, items };
}

/**
 * Read a direct payload once the session layer has decrypted it, and check it came from the
 * device the session is with: the activity must be signed by that device, and sender keys are
 * recorded as that device's. Returns { activity?, senderKeys: [view...], actor? }. An actor
 * document in the payload must be the sender's own.
 */
export function openDirectPayload(plaintext, { fromDevice, fromActor }) {
  const p = decode(plaintext);
  if (p.activity && (p.activity.body?.device !== fromDevice || p.activity.body?.actor !== fromActor)) {
    throw new SessionError("UNTRUSTED", "The activity wasn't made by the device that sent it");
  }
  const senderKeys = (p.senderKeys || []).map((d) => {
    if (ownerOf(d?.group) !== fromActor) throw new SessionError("UNTRUSTED", "A sender key for someone else's audience");
    return acceptDistribution(d, { from: fromDevice });
  });
  if (p.actor && p.actor.body?.id !== fromActor) throw new SessionError("UNTRUSTED", "An actor document for someone else");
  return { activity: p.activity, senderKeys, actor: p.actor };
}

// ---- Audiences (followers-only and group posts) ----

/**
 * A new audience this device posts to: its followers, or a group's members. The audience id is
 * an object id of the actor's, so anyone can tell whose audience it is.
 */
export function createAudience(actorId, { kind = "followers" } = {}) {
  const id = newId(actorId);
  return { id, kind, key: createSenderKey(id), members: [] };
}

const memberKey = (m) => `${m.actor}/${m.device}`;

/**
 * Add member devices ({ actor, device }). Returns { audience, send }: send the current sender key
 * (`send.senderKey`) to `send.to` over direct sessions. New members can't read anything sealed
 * before they joined, because the key only moves forward.
 */
export function addMembers(audience, members) {
  const have = new Set(audience.members.map(memberKey));
  const fresh = members.filter((m) => isActorId(m.actor) && KID.test(m.device) && !have.has(memberKey(m)));
  return { audience: { ...audience, members: [...audience.members, ...fresh] }, send: { to: fresh, senderKey: distribution(audience.key) } };
}

/**
 * Remove members (unfollowed, blocked, left the group, or a device removed). The audience gets a
 * new sender key, which goes to every remaining member: whoever was removed can't read what's
 * sealed next. Returns { audience, send }.
 */
export function removeMembers(audience, predicate) {
  const members = audience.members.filter((m) => !predicate(m));
  const key = createSenderKey(audience.id);
  return { audience: { ...audience, members, key }, send: { to: members, senderKey: distribution(key) } };
}

/** Seal a signed activity once for the whole audience. Returns { audience, envelope }. */
export async function sealToAudience(audience, record) {
  const { key, message } = await groupEncrypt(audience.key, encode({ v: 1, activity: record }));
  return { audience: { ...audience, key }, envelope: { v: 1, mode: "audience", audience: audience.id, message } };
}

/**
 * Open an audience envelope with the sender key accepted from that device. The activity inside
 * must be signed by the same device. Returns { view, activity }.
 */
export async function openAudience(view, envelope) {
  if (envelope?.mode !== "audience" || envelope.audience !== view.group || envelope.message?.group !== view.group) throw new SessionError("BAD_MESSAGE", "Not for this audience");
  const { state, plaintext } = await groupDecrypt(view, envelope.message);
  const p = decode(plaintext);
  if (!p.activity || p.activity.body?.device !== view.from || p.activity.body?.actor !== ownerOf(view.group)) {
    throw new SessionError("UNTRUSTED", "The activity wasn't made by the device whose key sealed it");
  }
  return { view: state, activity: p.activity };
}

/** The id under which a receiver keeps a sender key: audience and key id together. */
export const viewKey = (audienceId, senderKeyId) => `${audienceId}#${senderKeyId}`;

// ---- Site to site ----

/** The body of a delivery request between sites (CVP-019, "Site to site"). */
export function deliveryBody(items) {
  if (!Array.isArray(items) || items.length === 0 || items.length > DELIVERY_LIMITS.items) throw new SessionError("BAD_INPUT", `1 to ${DELIVERY_LIMITS.items} items per request`);
  for (const it of items) {
    if (!isActorId(it.to)) throw new SessionError("BAD_INPUT", "Each item names the recipient actor");
    const p = envelopeProblems(it.envelope);
    if (p.length) throw new SessionError("BAD_INPUT", p.join("; "));
  }
  return { v: 1, items };
}

/** Check a delivery request body; returns the items. */
export function readDeliveryBody(body) {
  if (!body || body.v !== 1 || !Array.isArray(body.items) || body.items.length === 0 || body.items.length > DELIVERY_LIMITS.items) {
    throw new SessionError("BAD_MESSAGE", "Not a version 1 delivery");
  }
  for (const it of body.items) {
    if (!isActorId(it?.to)) throw new SessionError("BAD_MESSAGE", "Item without a recipient");
    const p = envelopeProblems(it.envelope);
    if (p.length) throw new SessionError("BAD_MESSAGE", p.join("; "));
  }
  return body.items;
}

