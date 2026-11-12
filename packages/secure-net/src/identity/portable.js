// Portable identity (CVP-001): personas, and moving an account or a community between sites.
//
// Personas: a person can show each community a different key and name, with no visible link to
// their main account. They hold a link proof privately and reveal it only if they choose (to a
// moderator, say). Linking can still happen through other means: same writing, same times,
// same network address. Clients should say so (the "Privacy Lens").
//
// Migration: an account or community moves by a signed notice naming the old and new site. Each
// notice has a sequence number, so an old notice replayed later is ignored, and it's signed by
// the key that owns the thing being moved, not by either site.
import { generateSigningKey, sign, checkSignature, keyId } from "../core/signed.js";

export const PERSONA_LINK = "identity.persona-link";
export const MIGRATION = "identity.migration";

export class IdentityError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "IdentityError";
    this.code = code;
  }
}

/**
 * A new persona for one community. Returns the persona's own key (keep it secret), what the
 * community sees, and a link proof (keep it private until you choose to reveal it).
 */
export function createPersona(accountKey, { community, name }) {
  if (typeof name !== "string" || !name.trim() || name.length > 64) throw new IdentityError("BAD_NAME", "A persona needs a name");
  const key = generateSigningKey();
  const shown = { kid: key.kid, pub: key.publicKey, name: name.trim(), community };
  // Signed by both keys: the account vouches for the persona, and the persona agrees.
  const link = sign(PERSONA_LINK, { account: accountKey.kid, account_pub: accountKey.publicKey, persona: key.kid, persona_pub: key.publicKey, community, at: new Date().toISOString() }, accountKey);
  const personaSig = sign(PERSONA_LINK, link.body, key).sig;
  return { key, shown, link: { ...link, cosigs: [personaSig] } };
}

/** Check a revealed link proof: both keys signed it. Returns { account, persona, community }. */
export function checkPersonaLink(link) {
  const b = link?.body;
  if (link?.kind !== PERSONA_LINK || !b) throw new IdentityError("MALFORMED", "Not a persona link");
  if (keyId(b.account_pub) !== b.account || keyId(b.persona_pub) !== b.persona) throw new IdentityError("BAD_KEYS", "Key ids don't match the keys");
  if (link.sig?.kid !== b.account || !checkSignature(link, link.sig, b.account_pub)) throw new IdentityError("BAD_SIGNATURE", "The account didn't sign this");
  const ps = (link.cosigs || []).find((s) => s.kid === b.persona);
  if (!ps || !checkSignature(link, ps, b.persona_pub)) throw new IdentityError("BAD_SIGNATURE", "The persona didn't sign this");
  return { account: b.account, persona: b.persona, community: b.community };
}

/**
 * A move from one site to another, signed by the owner's key. subject: what moves (an account id
 * or a community id). seq: one more than the last notice for this subject.
 */
export function migrationNotice({ subject, from, to, seq, keepOldUntil = null }, ownerKey) {
  if (!Number.isSafeInteger(seq) || seq < 1) throw new IdentityError("BAD_SEQ", "A notice needs a sequence number from 1");
  if (!from || !to || from === to) throw new IdentityError("BAD_SITES", "A move needs two different sites");
  return sign(MIGRATION, { subject, from, to, seq, at: new Date().toISOString(), keep_old_until: keepOldUntil }, ownerKey);
}

/**
 * Check a notice against the owner's key and what's known so far. last: the last accepted notice
 * for this subject (or null). Returns the notice body; throws for anything stale or forged.
 */
export function acceptMigration(notice, ownerPub, last = null) {
  if (notice?.kind !== MIGRATION) throw new IdentityError("MALFORMED", "Not a migration notice");
  if (!checkSignature(notice, notice.sig, ownerPub)) throw new IdentityError("BAD_SIGNATURE", "Not signed by the owner");
  const b = notice.body;
  if (last) {
    if (b.subject !== last.subject) throw new IdentityError("WRONG_SUBJECT", "This notice is about something else");
    if (b.seq <= last.seq) throw new IdentityError("REPLAYED", "An older notice than one already accepted");
    if (b.from !== last.to) throw new IdentityError("DISCONTINUOUS", "This move doesn't start where the last one ended");
  }
  return b;
}

/** Where something lives now, after a list of notices (checked in order). */
export function currentSite(notices, ownerPub, start) {
  let last = null;
  let site = start;
  for (const n of [...notices].sort((a, b) => a.body.seq - b.body.seq)) {
    try {
      const b = acceptMigration(n, ownerPub, last ?? { subject: n.body.subject, seq: 0, to: start });
      last = b;
      site = b.to;
    } catch {
      // A bad or stale notice is skipped; the rest still apply.
    }
  }
  return site;
}
