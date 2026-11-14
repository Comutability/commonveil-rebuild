// Signed activities (CVP-018).
//
// Every activity is signed on the device that made it, with that device's quantum-resistant key
// (Ed25519 + ML-DSA-65), and names the device. A receiver checks the device spoke for the actor
// (its actor document, CVP-017) when the activity says it was published. The signature travels
// with the activity everywhere, including inside end-to-end encryption, so a recipient can show
// it to others (a reply quoting it, a report to moderators) and they can check it too.
import { sign, checkSignature, recordId } from "../core/signed.js";
import { canonicalBytes } from "../core/canonical.js";
import { SessionError } from "../session/primitives.js";
import { activityProblems, LIMITS, newId } from "./vocabulary.js";
import { deviceKeyAt } from "./actor.js";

export const ACTIVITY = "social.activity";
/** How far in the future a published time may be, for clocks that disagree. */
export const FUTURE_SKEW_MS = 5 * 60_000;

/**
 * Make and sign an activity on a device. Fills in id and published if missing.
 * `encrypted` is whether it will travel end to end encrypted (CVP-019).
 */
export function signActivity(device, actorId, activity, { encrypted = false, now = Date.now() } = {}) {
  const body = { ...activity, actor: actorId, device: device.kid };
  if (body.id === undefined) body.id = newId(actorId);
  if (body.published === undefined) body.published = now;
  if (body.object && typeof body.object === "object" && body.type === "Create") {
    body.object = { attributedTo: actorId, published: body.published, ...body.object };
    if (body.object.id === undefined) body.object.id = newId(actorId);
  }
  const problems = activityProblems(body, { encrypted });
  if (problems.length) throw new SessionError("BAD_ACTIVITY", problems.join("; "));
  if (canonicalBytes(body).length > LIMITS.bytes) throw new SessionError("TOO_LARGE", "Activity is too large");
  return sign(ACTIVITY, body, device.sign);
}

/**
 * Check a signed activity against its actor's document body (from verifyActorDocument).
 * Refuses one signed by a device that didn't speak for the actor at the time it claims, one from
 * the future, or one that isn't valid vocabulary. Returns the body.
 */
export function verifyActivity(record, actor, { encrypted = false, now = Date.now() } = {}) {
  const b = record?.body;
  if (record?.kind !== ACTIVITY || !b || typeof b !== "object") throw new SessionError("BAD_MESSAGE", "Not an activity");
  if (b.actor !== actor.id) throw new SessionError("UNTRUSTED", "Activity is from a different actor");
  if (typeof b.device !== "string" || record.sig?.kid !== b.device) throw new SessionError("UNTRUSTED", "Activity isn't signed by the device it names");
  const key = deviceKeyAt(actor, b.device, b.published);
  if (!key) throw new SessionError("UNTRUSTED", "That device didn't speak for this actor then");
  if (!key.includes(".")) throw new SessionError("UNTRUSTED", "Device key isn't quantum-resistant");
  if (!checkSignature(record, record.sig, key)) throw new SessionError("UNTRUSTED", "Activity signature doesn't match");
  if (Number.isSafeInteger(b.published) && b.published > now + FUTURE_SKEW_MS) throw new SessionError("BAD_TIME", "Activity is dated in the future");
  if (canonicalBytes(b).length > LIMITS.bytes) throw new SessionError("TOO_LARGE", "Activity is too large");
  const problems = activityProblems(b, { encrypted });
  if (problems.length) throw new SessionError("BAD_ACTIVITY", problems.join("; "));
  return b;
}

/** A stable fingerprint of a signed activity (for de-duplication and logs). */
export const activityDigest = (record) => recordId(record);
