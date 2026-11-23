// CVP-017 actor documents, checked on this device and never on a site's word.
//
// Secure Net (packages/secure-net, frozen at 0.5.0) owns the rules: an actor's id is its account
// key's id, the document is signed by that hybrid key, and its device list is signed too. This
// file only wraps those rules for the screens and collects what went wrong instead of throwing.
//
// It creates nothing and binds nothing. An actor document says what a key is called and which
// devices speak for it; it never says that the account signed in here owns it. Binding is a
// separate, deliberately unbuilt step (docs/IDENTITY.md, "Protocol actors").
import { verifyActorDocument } from "../../../packages/secure-net/src/social/actor.js";
import { keyId } from "../../../packages/secure-net/src/core/signed.js";

export const ACTOR_KIND = "actor.document";
const MAX_DOCUMENT_CHARS = 256 * 1024;

export class ActorCheckError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ActorCheckError";
    this.code = code;
  }
}

/** A pasted or uploaded document, as an object. Nothing is fetched or stored to do this. */
export function parseActorJson(input) {
  if (input && typeof input === "object") return input;
  const text = String(input ?? "").trim();
  if (!text) throw new ActorCheckError("EMPTY", "Paste or choose an actor document first.");
  if (text.length > MAX_DOCUMENT_CHARS) throw new ActorCheckError("TOO_LARGE", "That is larger than an actor document can be.");
  try {
    return JSON.parse(text);
  } catch {
    throw new ActorCheckError("MALFORMED", "That isn't JSON. Paste the whole document, starting with {.");
  }
}

/** The short form people read out to compare keys: the first 8 characters of the key's id. */
export function fingerprintOf(publicKey) {
  if (!publicKey) return "";
  const id = keyId(String(publicKey));
  return `${id.slice(0, 4)} ${id.slice(4, 8)}`;
}

const isoOrEmpty = (ms) => {
  if (!Number.isSafeInteger(ms)) return "";
  try {
    return new Date(ms).toISOString();
  } catch {
    return "";
  }
};

const deviceKids = (body) => {
  const list = body?.devices?.body?.devices;
  return Array.isArray(list) ? list.map((d) => (typeof d?.kid === "string" ? d.kid : "")).filter(Boolean) : [];
};

/**
 * Everything the screens show about one document, and whether it actually checks out.
 * `handle` (when given) is the handle you expected: the site's own address, never taken from the
 * document itself. `minSeq` is the highest seq this browser has already accepted for that actor,
 * so a replayed older document is refused (verifyActorDocument answers ROLLBACK).
 */
export function describeActor(record, { handle, minSeq = 0 } = {}) {
  const body = record && typeof record === "object" ? record.body : null;
  const account = typeof body?.account === "string" ? body.account : "";
  const out = {
    ok: false,
    code: null,
    problems: [],
    body,
    id: typeof body?.id === "string" ? body.id : "",
    handle: typeof body?.handle === "string" ? body.handle : "",
    account,
    fingerprint: fingerprintOf(account),
    type: typeof body?.type === "string" ? body.type : "",
    name: typeof body?.name === "string" ? body.name : "",
    seq: Number.isSafeInteger(body?.seq) ? body.seq : null,
    devices: deviceKids(body),
    former: Array.isArray(body?.former) ? body.former.length : 0,
    discoverable: body?.discoverable !== false,
    updated: isoOrEmpty(body?.updated),
  };
  try {
    verifyActorDocument(record, { minSeq, ...(handle ? { handle } : {}) });
    out.ok = true;
  } catch (error) {
    out.code = error?.code || "INVALID";
    out.problems.push(error?.message || "That actor document couldn't be checked.");
  }
  return out;
}

/** Why a check failed, in words someone can act on. */
export function problemText(code, message) {
  if (code === "ROLLBACK") return `${message}. This browser has already seen a newer version of that actor, so this one is being ignored.`;
  if (code === "UNTRUSTED") return `${message}. The document was changed after it was signed, or it isn't from the key it names.`;
  if (code === "BAD_MESSAGE") return `${message}. It isn't a well-formed actor document.`;
  return message;
}