// Lexicons (CVP-021): how anyone adds new kinds of object without asking anyone.
//
// As in the AT Protocol, a new type is named by a reverse domain name (an NSID, like
// org.example.recipe), and the people who control that domain publish its schema. Here the
// schema is a signed record from the actor lexicons@<that domain>. Clients that know the
// schema check objects against it; clients that don't still show the object's ordinary members
// (name, content, attachments), so an unknown type degrades to a readable post, never an error.
import { sign, checkSignature } from "../core/signed.js";
import { SessionError } from "../session/primitives.js";
import { parseHandle } from "./actor.js";
import { isActorId, isObjectId } from "./vocabulary.js";

export const LEXICON = "lexicon.schema";
/** The handle name a domain's lexicons are published under: lexicons@<domain>. Sites reserve it for their operator. */
export const PUBLISHER = "lexicons";
const NSID = /^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*){2,}$/;
const FIELD = /^[a-z][A-Za-z0-9]{0,39}$/;
export const FIELD_TYPES = Object.freeze(["string", "integer", "boolean", "id", "actor", "array"]);
/** Members every object may have (CVP-018); a lexicon can't redefine them. */
export const COMMON = Object.freeze(["type", "id", "attributedTo", "published", "updated", "content", "mediaType", "name", "summary", "sensitive", "language", "inReplyTo", "context", "attachment", "tag"]);

export const isNsid = (v) => typeof v === "string" && v.length <= 200 && NSID.test(v);
/** The domain that controls an NSID: all but its last segment, reversed. */
export const authorityOf = (nsid) => (isNsid(nsid) ? nsid.split(".").slice(0, -1).reverse().join(".") : null);

function fieldProblems(name, f, out, nested = false) {
  if (!f || !FIELD_TYPES.includes(f.type) || (nested && f.type === "array")) return out.push(`${name}: type must be one of ${FIELD_TYPES.join(", ")}`);
  if (f.max !== undefined && !(Number.isSafeInteger(f.max) && f.max >= 0)) out.push(`${name}: max must be a whole number`);
  if (f.min !== undefined && !Number.isSafeInteger(f.min)) out.push(`${name}: min must be an integer`);
  if (f.required !== undefined && typeof f.required !== "boolean") out.push(`${name}: required must be true or false`);
  if (f.type === "array") fieldProblems(`${name}[]`, f.items, out, true);
  return out;
}

/** Problems with a lexicon body (empty if fine). */
export function lexiconProblems(l) {
  const out = [];
  if (!l || l.v !== 1 || !isNsid(l.id)) return ["A lexicon needs v: 1 and an id like org.example.recipe"];
  if (!Number.isSafeInteger(l.revision) || l.revision < 1) out.push("revision must be a positive integer");
  if (l.description !== undefined && !(typeof l.description === "string" && l.description.length <= 1000)) out.push("description is too long");
  const names = Object.keys(l.fields || {});
  if (!l.fields || typeof l.fields !== "object" || names.length > 50) return [...out, "fields must be an object of at most 50 fields"];
  for (const n of names) {
    if (!FIELD.test(n) || COMMON.includes(n)) out.push(`"${n}" can't be a field name`);
    else fieldProblems(n, l.fields[n], out);
  }
  return out;
}

/** Publish a lexicon: signed by the account key of lexicons@<the NSID's domain>. */
export function createLexicon(account, body) {
  const full = { v: 1, ...body };
  const p = lexiconProblems(full);
  if (p.length) throw new SessionError("BAD_INPUT", p.join("; "));
  return sign(LEXICON, full, account);
}

/** Check a lexicon against its publisher's actor document body. Returns the lexicon body. */
export function verifyLexicon(record, actor, { minRevision = 0 } = {}) {
  const l = record?.body;
  if (record?.kind !== LEXICON) throw new SessionError("BAD_MESSAGE", "Not a lexicon");
  const p = lexiconProblems(l);
  if (p.length) throw new SessionError("BAD_MESSAGE", p.join("; "));
  if (record.sig?.kid !== actor.id || !checkSignature(record, record.sig, actor.account)) throw new SessionError("UNTRUSTED", "Lexicon isn't signed by that actor");
  const h = parseHandle(actor.handle);
  if (h?.host !== authorityOf(l.id) || h.name !== PUBLISHER) throw new SessionError("UNTRUSTED", `Only ${PUBLISHER}@${authorityOf(l.id)} may define ${l.id}`);
  if (l.revision < minRevision) throw new SessionError("ROLLBACK", "Lexicon is older than one already seen");
  return l;
}

function valueOk(v, f) {
  switch (f.type) {
    case "string": return typeof v === "string" && v.length <= (f.max ?? 10_000);
    case "integer": return Number.isSafeInteger(v) && (f.min === undefined || v >= f.min) && (f.max === undefined || v <= f.max);
    case "boolean": return typeof v === "boolean";
    case "id": return isObjectId(v);
    case "actor": return isActorId(v);
    case "array": return Array.isArray(v) && v.length <= (f.max ?? 100) && v.every((x) => valueOk(x, f.items));
    default: return false;
  }
}

/** Problems with an object's own fields under its lexicon (CVP-018 checks the common members). */
export function extensionProblems(object, lexicon) {
  const out = [];
  if (object?.type !== lexicon.id) return [`Object isn't a ${lexicon.id}`];
  for (const [n, f] of Object.entries(lexicon.fields)) {
    if (object[n] === undefined) {
      if (f.required) out.push(`${n} is required`);
    } else if (!valueOk(object[n], f)) out.push(`${n} isn't a valid ${f.type}`);
  }
  for (const n of Object.keys(object)) if (!COMMON.includes(n) && !lexicon.fields[n]) out.push(`${n} isn't in ${lexicon.id} revision ${lexicon.revision}`);
  return out;
}
