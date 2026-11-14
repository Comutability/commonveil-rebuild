// Actors and discovery (CVP-017).
//
// An actor is an account: a person, group, organisation, service or app. Its id is its account
// key's id (CVP-002), so an id names one key and can't be taken over by any site. Its actor
// document, signed by that quantum-resistant account key, says what it's called, where its
// mailbox is, and which devices speak for it (the CVP-016 device list, plus devices it used to
// have and until when, so older posts still verify).
//
// A handle, @name@host, is only a pointer: the site at host serves the actor document for name.
// A site can lie about which actor a handle points to (people compare safety numbers for that),
// but it can't forge or alter an actor document.
import { keyId, sign, verify, SignatureError } from "../core/signed.js";
import { normHost } from "../wire/federation.js";
import { verifyDeviceList } from "../session/keys.js";
import { SessionError } from "../session/primitives.js";
import { ACTOR_TYPES } from "./vocabulary.js";

export const ACTOR = "actor.document";
const NAME = /^[a-z0-9_]([a-z0-9_.-]{0,62}[a-z0-9_])?$/;
const MAX_FORMER = 200;

/** Split "@name@host" (or "name@host") into its parts, or null if it isn't a handle. */
export function parseHandle(handle) {
  const m = /^@?([^@\s]+)@([^@\s]+)$/.exec(String(handle || "").trim());
  if (!m) return null;
  const name = m[1].toLowerCase();
  const host = normHost(m[2]);
  return NAME.test(name) && host ? { name, host, handle: `${name}@${host}` } : null;
}

/** An actor's id: the id of its account key. */
export const actorIdOf = (accountPublicKey) => keyId(accountPublicKey);

/**
 * Make (or update) an actor document. `devices` is the account's signed device list (CVP-016).
 * `former` lists devices that used to be on it: { kid, sign, until } (until: ms). seq must go up
 * with every change; receivers refuse a lower one.
 */
export function createActorDocument(account, { handle, type = "Person", name, summary, icon, devices, former = [], seq, now = Date.now(), discoverable = true }) {
  const h = parseHandle(handle);
  if (!h) throw new SessionError("BAD_INPUT", "A handle looks like name@host");
  if (!account.publicKey.includes(".")) throw new SessionError("BAD_INPUT", "An actor's account key must be quantum-resistant (Ed25519 + ML-DSA-65)");
  const body = { v: 1, type, id: actorIdOf(account.publicKey), handle: h.handle, account: account.publicKey, seq, devices, former, discoverable, updated: now };
  if (name !== undefined) body.name = name;
  if (summary !== undefined) body.summary = summary;
  if (icon !== undefined) body.icon = icon;
  const record = sign(ACTOR, body, account);
  verifyActorDocument(record); // never hand out something we'd refuse
  return record;
}

/**
 * Check an actor document. It is self-certifying: the account key inside must have signed it,
 * and its id must be that key's id. Pass `id` when you asked for a particular actor, `handle`
 * when you looked one up by handle, and `minSeq` from what you've seen before.
 * Returns the body.
 */
export function verifyActorDocument(record, { id, handle, minSeq = 0 } = {}) {
  const b = record?.body;
  if (record?.kind !== ACTOR || !b || typeof b !== "object") throw new SessionError("BAD_MESSAGE", "Not an actor document");
  if (b.v !== 1) throw new SessionError("BAD_MESSAGE", "Unsupported actor document version");
  if (typeof b.account !== "string" || !b.account.includes(".")) throw new SessionError("UNTRUSTED", "Actor's account key isn't quantum-resistant");
  if (b.id !== actorIdOf(b.account)) throw new SessionError("UNTRUSTED", "Actor id isn't its account key's id");
  try {
    verify(record, (kid) => (kid === b.id ? b.account : null), { kinds: [ACTOR] });
  } catch (e) {
    if (e instanceof SignatureError) throw new SessionError("UNTRUSTED", `Actor document: ${e.message}`);
    throw e;
  }
  if (id !== undefined && b.id !== id) throw new SessionError("UNTRUSTED", "That's a different actor");
  const h = parseHandle(b.handle);
  if (!h || h.handle !== b.handle) throw new SessionError("BAD_MESSAGE", "Bad handle");
  if (handle !== undefined && parseHandle(handle)?.handle !== b.handle) throw new SessionError("UNTRUSTED", "The document is for a different handle");
  if (!ACTOR_TYPES.includes(b.type)) throw new SessionError("BAD_MESSAGE", `Unknown actor type ${b.type}`);
  if (!Number.isSafeInteger(b.seq) || b.seq < 1) throw new SessionError("BAD_MESSAGE", "Bad seq");
  if (b.seq < minSeq) throw new SessionError("ROLLBACK", "Actor document is older than one already seen");
  if (!Number.isSafeInteger(b.updated)) throw new SessionError("BAD_MESSAGE", "Bad updated time");
  for (const [f, max] of [["name", 200], ["summary", 2000]]) if (b[f] !== undefined && !(typeof b[f] === "string" && b[f].length <= max)) throw new SessionError("BAD_MESSAGE", `Bad ${f}`);
  verifyDeviceList(b.devices, { accountKey: b.account });
  if (!Array.isArray(b.former) || b.former.length > MAX_FORMER) throw new SessionError("BAD_MESSAGE", "Bad former devices");
  for (const f of b.former) {
    if (!f || typeof f.kid !== "string" || typeof f.sign !== "string" || !Number.isSafeInteger(f.until) || keyId(f.sign) !== f.kid) {
      throw new SessionError("BAD_MESSAGE", "Bad former device");
    }
  }
  return b;
}

/**
 * The signing key a device had for this actor at a time (ms): a current device's key, or a former
 * device's key if the time is before it was removed. Null if the device didn't speak for the actor.
 */
export function deviceKeyAt(actor, deviceKid, at) {
  const cur = actor.devices.body.devices.find((d) => d.kid === deviceKid);
  if (cur) return cur.sign;
  const old = actor.former.find((d) => d.kid === deviceKid);
  return old && Number.isSafeInteger(at) && at < old.until ? old.sign : null;
}

/** Where a handle's actor document is (CVP-017, "Discovery"). */
export function discoveryUrl(handle, endpoint = "/.well-known/commonveil/actor") {
  const h = parseHandle(handle);
  if (!h) throw new SessionError("BAD_INPUT", "A handle looks like name@host");
  return `https://${h.host}${endpoint}?handle=${encodeURIComponent(h.name)}`;
}

