// Consent capsules (CVP-014): a signed, specific, time-limited permission. "These people may read
// this file until Friday." "This site may keep a copy of my messages." "This app may see the
// message I select, and nothing else."
//
// A capsule says who granted what, to whom, about what, and for how long. It can be revoked by a
// signed revocation. Revocation is honest about its limits: it stops future access (no new keys,
// no further hosted copies), but it can't make anyone forget what they already saw or saved.
// Clients must say that when someone revokes (REVOCATION_LIMITS below).
import { sign, checkSignature, signingBytes } from "../core/signed.js";
import { sha256B64u, randomB64u } from "../core/bytes.js";

export const CAPSULE = "consent.capsule";
export const REVOCATION = "consent.revocation";
export const ACTIONS = ["read", "store", "replicate", "forward", "process", "publish"];
export const REVOCATION_LIMITS =
  "Revoking stops new access from now on. It can't remove copies, screenshots or downloads someone already made, or what they remember.";

export class ConsentError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ConsentError";
    this.code = code;
  }
}

export const capsuleId = (capsule) => sha256B64u(signingBytes(capsule.kind, capsule.body));

/**
 * Grant consent. audience: key ids (or site addresses for "store"/"replicate"). resource: what
 * it's about (a hash, a channel id, "*" for everything of yours). keys: optional wrapped keys
 * for the audience (opaque to this module).
 */
export function grant({ audience, actions, resource, notBefore = new Date().toISOString(), expires, purpose = "", keys = null }, grantorKey) {
  if (!Array.isArray(audience) || !audience.length || audience.length > 256) throw new ConsentError("BAD_AUDIENCE", "Say who this is for");
  if (!Array.isArray(actions) || !actions.length || actions.some((a) => !ACTIONS.includes(a))) throw new ConsentError("BAD_ACTIONS", `Actions must be from ${ACTIONS.join(", ")}`);
  if (typeof resource !== "string" || !resource) throw new ConsentError("BAD_RESOURCE", "Say what this is about");
  if (!(Date.parse(expires) > Date.parse(notBefore))) throw new ConsentError("BAD_TIME", "Consent must end after it starts");
  return sign(CAPSULE, { id: randomB64u(12), grantor: grantorKey.kid, audience, actions, resource, not_before: notBefore, expires, purpose, keys }, grantorKey);
}

/** Withdraw a capsule. Only its grantor can. */
export const revoke = (capsule, grantorKey, reason = "") => sign(REVOCATION, { capsule: capsuleId(capsule), at: new Date().toISOString(), reason }, grantorKey);

/**
 * Whether a capsule allows this, now. revocations: revocation records seen so far.
 * Returns { allowed, why }.
 */
export function check(capsule, { grantorPub, actor, action, resource, now = Date.now(), revocations = [] }) {
  const b = capsule?.body;
  if (capsule?.kind !== CAPSULE || !b) return { allowed: false, why: "not a consent capsule" };
  if (capsule.sig?.kid !== b.grantor || !checkSignature(capsule, capsule.sig, grantorPub)) return { allowed: false, why: "not signed by its grantor" };
  const id = capsuleId(capsule);
  if (revocations.some((r) => r?.kind === REVOCATION && r.body?.capsule === id && r.sig?.kid === b.grantor && checkSignature(r, r.sig, grantorPub) && Date.parse(r.body.at) <= now)) {
    return { allowed: false, why: "revoked" };
  }
  if (now < Date.parse(b.not_before)) return { allowed: false, why: "not yet" };
  if (now > Date.parse(b.expires)) return { allowed: false, why: "expired" };
  if (!b.audience.includes(actor)) return { allowed: false, why: "not for this person or site" };
  if (!b.actions.includes(action)) return { allowed: false, why: `doesn't allow ${action}` };
  if (b.resource !== "*" && b.resource !== resource) return { allowed: false, why: "about something else" };
  return { allowed: true, why: "" };
}

/** A plain-language description of a capsule, for showing people before they agree. */
export function explain(capsule) {
  const b = capsule.body;
  const who = b.audience.length === 1 ? "1 recipient" : `${b.audience.length} recipients`;
  const what = b.resource === "*" ? "everything of yours" : "one item";
  return `${who} may ${b.actions.join(", ")} ${what} until ${new Date(b.expires).toUTCString()}.${b.purpose ? ` Purpose: ${b.purpose}.` : ""} ${REVOCATION_LIMITS}`;
}
