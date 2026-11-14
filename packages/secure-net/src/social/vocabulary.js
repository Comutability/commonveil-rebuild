// The social vocabulary (CVP-018): ActivityStreams 2.0 names, as plain canonical JSON.
//
// The type names are ActivityStreams' own (Create, Note, Follow, Like...), so anyone who knows
// ActivityPub recognises them and a bridge can map them one to one. The wire is not JSON-LD:
// there is no @context, every value has one fixed shape, numbers are integers (CVP-002), and
// identifiers are derived from keys rather than URLs, because most objects are end-to-end
// encrypted and no server can fetch them.
import { SessionError } from "../session/primitives.js";

export const ACTOR_TYPES = Object.freeze(["Person", "Group", "Organization", "Service", "Application"]);
export const ACTIVITY_TYPES = Object.freeze(["Create", "Update", "Delete", "Follow", "Accept", "Reject", "Undo", "Like", "Announce", "Add", "Remove", "Block", "Flag", "Join", "Leave", "Invite", "Move"]);
export const OBJECT_TYPES = Object.freeze(["Note", "Article", "Image", "Video", "Audio", "Document", "Page", "Event", "Place", "Question", "Tombstone"]);
/** Addresses that aren't actors: everyone, and the author's followers. */
export const PUBLIC = "public";
export const FOLLOWERS = "followers";
export const MEDIA_TYPES = Object.freeze(["text/plain", "text/markdown"]);

export const LIMITS = Object.freeze({
  content: 50_000, // characters in content
  summary: 500,
  name: 200,
  attachments: 20,
  tags: 100,
  recipients: 1000, // to + cc
  options: 50, // Question options
  bytes: 256 * 1024, // canonical size of one activity
});

const KID = /^[A-Za-z0-9_-]{22}$/;
const ID = /^([A-Za-z0-9_-]{22}):[A-Za-z0-9_-]{16,64}$/;
const GROUP = /^group:[A-Za-z0-9_-]{16,64}$/;
const B64U = /^[A-Za-z0-9_-]+$/;
const EXTENSION_TYPE = /^(?=.{1,200}$)[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*){2,}$/;
const LANG = /^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$/;

export const isActorId = (v) => typeof v === "string" && KID.test(v);
export const isObjectId = (v) => typeof v === "string" && ID.test(v);
/** The actor an object or activity id belongs to. Ids start with their author's actor id. */
export const ownerOf = (id) => (typeof id === "string" ? ID.exec(id)?.[1] ?? null : null);
export const isAddress = (v) => v === PUBLIC || v === FOLLOWERS || isActorId(v) || (typeof v === "string" && GROUP.test(v));

/** A new id for something this actor makes. */
export function newId(actor) {
  if (!isActorId(actor)) throw new SessionError("BAD_INPUT", "Not an actor id");
  const r = globalThis.crypto.getRandomValues(new Uint8Array(16));
  let s = "";
  for (const b of r) s += String.fromCharCode(b);
  return `${actor}:${btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}`;
}

const isInt = (v) => Number.isSafeInteger(v) && v >= 0;
const str = (v, max) => typeof v === "string" && v.length <= max;

/** Problems with an attachment reference (empty list if fine). */
function attachmentProblems(a, encrypted, at, out) {
  if (!a || typeof a !== "object") return out.push(`${at} isn't an object`);
  if (!["Image", "Video", "Audio", "Document"].includes(a.type)) out.push(`${at}.type must be Image, Video, Audio or Document`);
  if (!str(a.url, 2048) || !/^https:\/\//.test(a.url)) out.push(`${at}.url must be an https URL`);
  if (!str(a.mediaType, 100) || !/^[a-z]+\/[a-z0-9.+-]+$/.test(a.mediaType)) out.push(`${at}.mediaType must be a media type`);
  if (!isInt(a.size)) out.push(`${at}.size must be a whole number of bytes`);
  if (!(typeof a.sha256 === "string" && /^[A-Za-z0-9_-]{43}$/.test(a.sha256))) out.push(`${at}.sha256 must be the base64url SHA-256 of the stored bytes`);
  if (a.key !== undefined) {
    if (!encrypted) out.push(`${at}.key may only appear in end-to-end encrypted activities`);
    if (!(typeof a.key === "string" && B64U.test(a.key) && a.key.length === 43)) out.push(`${at}.key must be a base64url 32-byte AES-256-GCM key`);
  } else if (encrypted) out.push(`${at} in an encrypted activity must carry its key (the file is stored encrypted)`);
  if (a.name !== undefined && !str(a.name, 1500)) out.push(`${at}.name (the description) is too long`);
  if (a.width !== undefined && !isInt(a.width)) out.push(`${at}.width must be a whole number`);
  if (a.height !== undefined && !isInt(a.height)) out.push(`${at}.height must be a whole number`);
  return out;
}

/** Problems with an object (Note, Article...). actor is who the activity says made it. */
export function objectProblems(o, { actor, encrypted, at = "object" } = {}) {
  const out = [];
  if (!o || typeof o !== "object" || Array.isArray(o)) return [`${at} must be an object`];
  // A type is either registered, or an extension named by a reverse domain name (CVP-021), whose
  // common members are checked here and whose own fields are checked against its lexicon.
  if (!OBJECT_TYPES.includes(o.type) && !EXTENSION_TYPE.test(o.type || "")) return [`${at}.type "${o.type}" isn't a registered object type or an extension type like org.example.recipe`];
  if (!isObjectId(o.id)) out.push(`${at}.id must be "<actor id>:<random>"`);
  if (o.attributedTo !== actor) out.push(`${at}.attributedTo must be the actor (${actor})`);
  if (o.id && ownerOf(o.id) !== actor) out.push(`${at}.id must start with the actor's id`);
  if (o.type === "Tombstone") return out;
  if (!isInt(o.published)) out.push(`${at}.published must be milliseconds since 1970 (an integer)`);
  if (o.updated !== undefined && !isInt(o.updated)) out.push(`${at}.updated must be an integer`);
  if (o.content !== undefined && !str(o.content, LIMITS.content)) out.push(`${at}.content must be text of at most ${LIMITS.content} characters`);
  if (o.mediaType !== undefined && !MEDIA_TYPES.includes(o.mediaType)) out.push(`${at}.mediaType must be ${MEDIA_TYPES.join(" or ")}`);
  if (o.name !== undefined && !str(o.name, LIMITS.name)) out.push(`${at}.name is too long`);
  if (o.summary !== undefined && !str(o.summary, LIMITS.summary)) out.push(`${at}.summary (content warning) is too long`);
  if (o.sensitive !== undefined && typeof o.sensitive !== "boolean") out.push(`${at}.sensitive must be true or false`);
  if (o.language !== undefined && !(typeof o.language === "string" && LANG.test(o.language))) out.push(`${at}.language must be a BCP 47 tag`);
  if (o.inReplyTo !== undefined && !isObjectId(o.inReplyTo)) out.push(`${at}.inReplyTo must be an object id`);
  if (o.context !== undefined && !(isObjectId(o.context) || GROUP.test(o.context))) out.push(`${at}.context must be an object or group id`);
  if (o.attachment !== undefined) {
    if (!Array.isArray(o.attachment) || o.attachment.length > LIMITS.attachments) out.push(`${at}.attachment must be a list of at most ${LIMITS.attachments}`);
    else o.attachment.forEach((a, i) => attachmentProblems(a, encrypted, `${at}.attachment[${i}]`, out));
  }
  if (o.tag !== undefined) {
    if (!Array.isArray(o.tag) || o.tag.length > LIMITS.tags) out.push(`${at}.tag must be a list of at most ${LIMITS.tags}`);
    else o.tag.forEach((t, i) => {
      if (t?.type === "Mention" ? !isActorId(t.href) : t?.type === "Hashtag" ? !str(t.name, 100) || !/^#\S+$/.test(t.name) : true) out.push(`${at}.tag[${i}] must be a Mention (href: actor id) or a Hashtag (name: #word)`);
    });
  }
  if (o.type === "Question") {
    const opts = o.oneOf ?? o.anyOf;
    if (!Array.isArray(opts) || opts.length < 2 || opts.length > LIMITS.options || (o.oneOf && o.anyOf)) out.push(`${at} must have 2 to ${LIMITS.options} options in oneOf or anyOf`);
    else if (!opts.every((x) => x?.type === "Note" && str(x.name, LIMITS.name))) out.push(`${at} options must be { type: "Note", name }`);
    if (o.endTime !== undefined && !isInt(o.endTime)) out.push(`${at}.endTime must be an integer`);
  }
  if (o.type === "Event") {
    if (!isInt(o.startTime)) out.push(`${at}.startTime must be an integer`);
    if (o.endTime !== undefined && !isInt(o.endTime)) out.push(`${at}.endTime must be an integer`);
  }
  return out;
}

const needsId = (v) => isObjectId(v);
/** What each activity's object must be. */
const OBJECT_RULES = {
  Create: "object",
  Update: "object-or-actor",
  Delete: "id",
  Follow: "actor",
  Accept: "id",
  Reject: "id",
  Undo: "id",
  Like: "id",
  Announce: "id",
  Add: "id",
  Remove: "id",
  Block: "actor",
  Flag: "id-or-actor",
  Join: "group",
  Leave: "group",
  Invite: "actor",
  Move: "actor",
};

/**
 * Problems with an activity body, as plain sentences (empty if fine). `encrypted` says whether it
 * travels end to end encrypted (CVP-019), which decides whether attachment keys may appear.
 */
export function activityProblems(a, { encrypted = false } = {}) {
  const out = [];
  if (!a || typeof a !== "object" || Array.isArray(a)) return ["An activity must be an object"];
  if (!ACTIVITY_TYPES.includes(a.type)) return [`Activity type "${a.type}" isn't registered`];
  if (!isActorId(a.actor)) out.push("actor must be an actor id");
  if (!isObjectId(a.id) || ownerOf(a.id) !== a.actor) out.push("id must be \"<actor id>:<random>\" for this actor");
  if (!isInt(a.published)) out.push("published must be milliseconds since 1970 (an integer)");
  for (const f of ["to", "cc"]) if (a[f] !== undefined && (!Array.isArray(a[f]) || !a[f].every(isAddress))) out.push(`${f} must be a list of addresses ("public", "followers", actor ids or group ids)`);
  const recipients = [...(a.to || []), ...(a.cc || [])];
  if (recipients.length === 0) out.push("An activity must be addressed (to or cc)");
  if (recipients.length > LIMITS.recipients) out.push(`At most ${LIMITS.recipients} recipients`);
  if (recipients.includes(PUBLIC) && encrypted) out.push("A public activity isn't encrypted (CVP-019): send it as a public envelope");
  const rule = OBJECT_RULES[a.type];
  const o = a.object;
  if (rule === "object") out.push(...objectProblems(o, { actor: a.actor, encrypted }));
  else if (rule === "object-or-actor") {
    if (typeof o === "object" && o?.type && ACTOR_TYPES.includes(o.type)) {
      if (o.id !== a.actor) out.push("Update of an actor must be of the actor itself");
    } else out.push(...objectProblems(o, { actor: a.actor, encrypted }));
  } else if (rule === "id" && !needsId(o)) out.push(`${a.type}'s object must be an object or activity id`);
  else if (rule === "actor" && !isActorId(o)) out.push(`${a.type}'s object must be an actor id`);
  else if (rule === "id-or-actor" && !needsId(o) && !isActorId(o)) out.push(`${a.type}'s object must be an object id or an actor id`);
  else if (rule === "group" && !(typeof o === "string" && GROUP.test(o))) out.push(`${a.type}'s object must be a group id`);
  if (["Delete", "Update", "Undo"].includes(a.type)) {
    const target = typeof o === "string" ? o : o?.id;
    if (target && ownerOf(target) && ownerOf(target) !== a.actor) out.push(`${a.type} may only act on the actor's own objects and activities`);
  }
  if (a.type === "Move" && !isActorId(a.target)) out.push("Move needs target: the actor id moved to");
  if ((a.type === "Add" || a.type === "Remove") && !(typeof a.target === "string" && (GROUP.test(a.target) || isObjectId(a.target)))) out.push(`${a.type} needs target: a group or collection id`);
  if (a.type === "Flag" && a.content !== undefined && !str(a.content, LIMITS.summary * 4)) out.push("Flag content (the reason) is too long");
  if (a.result !== undefined) out.push("result is not part of version 1 activities");
  return out;
}

/** The ActivityStreams 2.0 term for each of our fields where the names differ (for bridges; informative). */
export const AS2_DIFFERENCES = Object.freeze({
  public: "https://www.w3.org/ns/activitystreams#Public",
  followers: "the actor's followers collection URL",
  published: "xsd:dateTime string (here: integer milliseconds)",
  id: "dereferenceable URL (here: <actor id>:<random>, not fetchable for encrypted objects)",
});
