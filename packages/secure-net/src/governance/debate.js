// Structured debates (CVP-012): a motion's discussion as signed, typed records rather than one
// long thread, so a client can show it as a map of claims, rebuttals and evidence, and an
// accessible threaded list from the same data.
//
// Record kinds (each signed by its author):
//   debate.position   { motion, side, statement }          the side someone takes
//   debate.argument   { motion, side, claim, detail, parent? }   a claim, optionally under another
//   debate.rebuttal   { motion, target, claim, detail }    an answer to an argument or rebuttal
//   debate.evidence   { motion, target, source, citation } a source for a claim (a URL or a hash)
//   debate.round      { motion, name, phase, opens, closes, who }  a time-boxed phase (moderators)
//   debate.moderation { motion, target, action, reason }   hide or restore an item (moderators)
//
// Roles (debater, voter, moderator, observer) belong to the community, not to the protocol: the
// caller says who may post and who moderates.
import { sha256B64u } from "../core/bytes.js";
import { sign, checkSignature, signingBytes } from "../core/signed.js";

export const KINDS = ["debate.position", "debate.argument", "debate.rebuttal", "debate.evidence", "debate.round", "debate.moderation"];
const PHASES = ["opening", "argument", "rebuttal", "closing", "open"];
const MAX_TEXT = 10_000;

export const itemId = (record) => sha256B64u(signingBytes(record.kind, record.body));

const text = (s, max = MAX_TEXT) => typeof s === "string" && s.length > 0 && s.length <= max;

/** Make a debate record. */
export function post(kind, body, key) {
  if (!KINDS.includes(kind)) throw new TypeError(`Unknown debate record ${kind}`);
  return sign(kind, { ...body, at: body.at || new Date().toISOString() }, key);
}

function shapeOk(r, sides) {
  const b = r.body;
  switch (r.kind) {
    case "debate.position":
      return sides.has(b.side) && text(b.statement);
    case "debate.argument":
      return sides.has(b.side) && text(b.claim, 500) && (b.detail === undefined || text(b.detail));
    case "debate.rebuttal":
      return typeof b.target === "string" && text(b.claim, 500) && (b.detail === undefined || text(b.detail));
    case "debate.evidence":
      return typeof b.target === "string" && text(b.source, 2000) && (b.citation === undefined || text(b.citation, 2000));
    case "debate.round":
      return text(b.name, 100) && PHASES.includes(b.phase) && Date.parse(b.opens) < Date.parse(b.closes) && ["all", "debaters"].includes(b.who || "all");
    case "debate.moderation":
      return typeof b.target === "string" && ["hide", "restore"].includes(b.action) && (b.reason === undefined || text(b.reason, 500));
    default:
      return false;
  }
}

/** Which phase a contribution kind belongs in, when a debate has rounds. */
const PHASE_FOR = { "debate.position": ["opening", "open"], "debate.argument": ["opening", "argument", "open"], "debate.rebuttal": ["rebuttal", "argument", "open"], "debate.evidence": ["opening", "argument", "rebuttal", "closing", "open"] };

/**
 * Check and arrange a debate's records. options:
 *   keyFor(kid)       a participant's public key (or nothing)
 *   canPost(kid)      whether someone may contribute (default: anyone keyFor knows)
 *   isModerator(kid)  who may set rounds and hide items
 *   debaters          Set of kids allowed in rounds marked who: "debaters"
 * Returns { items, rejected, tree, threaded }: tree has positions and top-level arguments with
 * their replies nested; threaded is the same, flattened depth-first with a depth on each item.
 */
export function arrange(motion, records, { keyFor, canPost = (kid) => Boolean(keyFor(kid)), isModerator = () => false, debaters = new Set() } = {}) {
  const motionKey = sha256B64u(signingBytes(motion.kind, motion.body));
  const sides = new Set([...motion.body.options.map((o) => o.id), "neutral"]);
  const rejected = [];
  const accepted = new Map();
  const reject = (r, why) => rejected.push({ id: r?.kind && r?.body ? itemId(r) : null, why });

  // Rounds and moderation first: they decide what else is allowed or shown.
  const ordered = [...records].sort((a, b) => (["debate.round", "debate.moderation"].includes(a.kind) ? 0 : 1) - (["debate.round", "debate.moderation"].includes(b.kind) ? 0 : 1));
  const rounds = [];
  const hidden = new Map();
  for (const r of ordered) {
    if (!r || !KINDS.includes(r.kind) || r.body?.motion !== motionKey) {
      reject(r, "not part of this debate");
      continue;
    }
    const pub = keyFor(r.sig?.kid);
    if (!pub || !checkSignature(r, r.sig, pub)) {
      reject(r, "signature doesn't match");
      continue;
    }
    if (!shapeOk(r, sides)) {
      reject(r, "malformed");
      continue;
    }
    const id = itemId(r);
    if (accepted.has(id)) continue;
    if (r.kind === "debate.round" || r.kind === "debate.moderation") {
      if (!isModerator(r.sig.kid)) {
        reject(r, "only moderators can do that");
        continue;
      }
      if (r.kind === "debate.round") rounds.push(r.body);
      else {
        const prev = hidden.get(r.body.target);
        if (!prev || Date.parse(r.body.at) >= Date.parse(prev.at)) hidden.set(r.body.target, r.body);
      }
      accepted.set(id, r);
      continue;
    }
    if (!canPost(r.sig.kid)) {
      reject(r, "not allowed to take part");
      continue;
    }
    if (rounds.length) {
      const t = Date.parse(r.body.at);
      const open = rounds.find((rd) => t >= Date.parse(rd.opens) && t <= Date.parse(rd.closes) && PHASE_FOR[r.kind].includes(rd.phase) && (rd.who !== "debaters" || debaters.has(r.sig.kid)));
      if (!open) {
        reject(r, "outside any round that allows it");
        continue;
      }
    }
    accepted.set(id, r);
  }

  // Replies must point at something that exists in this debate.
  const nodes = new Map();
  for (const [id, r] of accepted) {
    if (r.kind === "debate.round" || r.kind === "debate.moderation") continue;
    nodes.set(id, { id, kind: r.kind, author: r.sig.kid, ...r.body, hidden: hidden.get(id)?.action === "hide", replies: [] });
  }
  const roots = [];
  for (const node of nodes.values()) {
    const parentId = node.kind === "debate.argument" ? node.parent : node.target;
    if (node.kind === "debate.position" || (node.kind === "debate.argument" && !node.parent)) {
      roots.push(node);
      continue;
    }
    const parent = nodes.get(parentId);
    if (!parent || parent.kind === "debate.position") {
      rejected.push({ id: node.id, why: "replies to something that isn't in this debate" });
      nodes.delete(node.id);
      continue;
    }
    parent.replies.push(node);
  }
  const byTime = (a, b) => Date.parse(a.at) - Date.parse(b.at) || (a.id < b.id ? -1 : 1);
  const threaded = [];
  const walk = (list, depth) => {
    for (const n of list.sort(byTime)) {
      threaded.push({ ...n, depth, replies: undefined });
      walk(n.replies, depth + 1);
    }
  };
  walk(roots, 0);
  return { items: [...nodes.values()].length, rejected, rounds, tree: roots, threaded };
}
