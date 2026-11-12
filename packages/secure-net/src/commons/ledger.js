// The Commons ledger (CVP-011): a community's signed, hash-chained history, which any approved
// site can keep a full copy of and serve from if the community's home site goes down.
//
// It works like a blockchain in the ways that matter here, and unlike one in the ways that don't:
//   - Each block names the one before it by hash, so history can't be rewritten quietly.
//   - Every copy checks every block itself, from the first, so a copy is as trustworthy as the
//     original and no site has to be believed.
//   - There's no mining, no coin and no global chain. Who may write is decided by the community's
//     own keys (its "authority"), with a threshold of co-signatures for anything that changes who
//     is in charge. Timestamps are information only: they never decide anything.
//
// Blocks carry structure (members, roles, channels, which site hosts what) in the clear, so any
// copy can enforce access rules, and content only as ciphertext ("sealed"), so a copy can't read
// it. That's a real metadata trade-off: a replica learns the community's membership. Choose
// replicas accordingly (docs: spec/CVP-011-commons-ledger.md).
import { canonicalJson } from "../core/canonical.js";
import { sha256B64u } from "../core/bytes.js";
import { checkSignature, keyId, sign, cosign, signingBytes } from "../core/signed.js";

export const BLOCK_KIND = "commons.block";
export const HOST_KIND = "commons.host";
const MAX_EVENTS = 256;
const MAX_BLOCK_BYTES = 512 * 1024;

/** What each event type needs from whoever signs the block. "authority" also needs the threshold. */
export const EVENT_CAPS = {
  "commons.genesis": "authority",
  "keys.set": "authority",
  "replicas.set": "authority",
  "policy.set": "authority",
  "host.move": "authority",
  "governance.result": "govern",
  "member.add": "members",
  "member.remove": "members",
  "role.set": "roles",
  "ban.set": "moderate",
  "channel.set": "channels",
  "channel.remove": "channels",
  "content.ref": "content",
  note: "content",
};
const AUTHORITY_EVENTS = new Set(["keys.set", "replicas.set", "policy.set", "host.move"]);
/** Capabilities a key can hold. "authority" implies all of them. */
export const CAPS = ["authority", "govern", "members", "roles", "moderate", "channels", "content"];
const DEFAULT_POLICY = { auto_failover: true, failover_after_s: 300, authority_change: "threshold", open_join: false };

export class LedgerError extends Error {
  constructor(code, message, height) {
    super(message);
    this.name = "LedgerError";
    this.code = code;
    this.height = height;
  }
}
const fail = (code, message, height) => {
  throw new LedgerError(code, message, height);
};

/** A block's id: the hash of exactly what its author signed. */
export const blockId = (block) => sha256B64u(signingBytes(BLOCK_KIND, block.body));

/** The hash an authority event is voted on as (its "action"), without its mandate. */
export function actionHash(event) {
  const { mandate: _mandate, ...rest } = event;
  return sha256B64u(canonicalJson(rest));
}

function checkKeys(keys, height) {
  if (!Array.isArray(keys) || !keys.length || keys.length > 64) fail("BAD_KEYS", "A community needs between 1 and 64 keys", height);
  const seen = new Set();
  for (const k of keys) {
    if (!k || typeof k.pub !== "string" || keyId(k.pub) !== k.kid) fail("BAD_KEYS", "A key's id doesn't match its public key", height);
    if (seen.has(k.kid)) fail("BAD_KEYS", "A key is listed twice", height);
    seen.add(k.kid);
    if (!Array.isArray(k.caps) || !k.caps.length || k.caps.some((c) => !CAPS.includes(c))) fail("BAD_KEYS", "A key has an unknown capability", height);
  }
}

function checkReplicas(replicas, succession, height) {
  if (!Array.isArray(replicas) || replicas.length > 32) fail("BAD_REPLICAS", "Up to 32 replicas", height);
  for (const r of replicas) {
    if (!r || typeof r.site !== "string" || !r.site || typeof r.pub !== "string" || keyId(r.pub) !== r.kid) fail("BAD_REPLICAS", "A replica needs a site and its key", height);
    if (r.caps && r.caps.some((c) => !CAPS.includes(c) || c === "authority" || c === "govern")) fail("BAD_REPLICAS", "A replica can't hold authority", height);
  }
  if (!Array.isArray(succession) || succession.some((s) => !replicas.some((r) => r.site === s))) fail("BAD_REPLICAS", "Succession may only name replicas", height);
}

function checkHome(home, height) {
  if (!home || typeof home.site !== "string" || !home.site || typeof home.pub !== "string" || keyId(home.pub) !== home.kid) fail("BAD_HOME", "The home site needs an address and a key", height);
}

/** The state before a community exists. */
const emptyState = () => ({
  community: "",
  name: "",
  height: -1,
  head: "",
  epoch: 0,
  keys: [],
  threshold: 1,
  home: null,
  replicas: [],
  succession: [],
  policy: { ...DEFAULT_POLICY },
  members: {},
  bans: {},
  channels: {},
  results: {},
  content: 0,
});

/** Everyone who may sign blocks, with what they may do. */
export function signersOf(state) {
  const out = new Map();
  for (const k of state.keys) out.set(k.kid, { pub: k.pub, caps: new Set(k.caps.includes("authority") ? CAPS : k.caps), authority: k.caps.includes("authority") });
  for (const r of state.replicas) if (!out.has(r.kid)) out.set(r.kid, { pub: r.pub, caps: new Set(r.caps || ["members", "content"]), authority: false });
  if (state.home && !out.has(state.home.kid)) out.set(state.home.kid, { pub: state.home.pub, caps: new Set(["members", "content"]), authority: false });
  for (const [kid, m] of Object.entries(state.members)) {
    if (!out.has(kid) && !state.bans[kid]) out.set(kid, { pub: m.pub, caps: new Set(["content"]), authority: false, member: true });
  }
  return out;
}

/** Distinct authority keys that signed this block (author and co-signers). */
function authoritySigners(block, state) {
  const keys = new Map(state.keys.filter((k) => k.caps.includes("authority")).map((k) => [k.kid, k.pub]));
  const got = new Set();
  for (const s of [block.sig, ...(block.cosigs || [])]) {
    const pub = keys.get(s?.kid);
    if (pub && !got.has(s.kid) && checkSignature(block, s, pub)) got.add(s.kid);
  }
  return got;
}

function applyEvent(state, e, block, ctx) {
  const h = block.body.height;
  switch (e.type) {
    case "commons.genesis": {
      if (h !== 0) fail("BAD_EVENT", "Only the first block can start a community", h);
      if (typeof e.name !== "string" || !e.name || e.name.length > 100) fail("BAD_EVENT", "A community needs a name", h);
      checkKeys(e.keys, h);
      checkHome(e.home, h);
      checkReplicas(e.replicas || [], e.succession || [], h);
      if (!Number.isSafeInteger(e.threshold) || e.threshold < 1 || e.threshold > e.keys.filter((k) => k.caps.includes("authority")).length) fail("BAD_EVENT", "The threshold must be between 1 and the number of authority keys", h);
      Object.assign(state, { name: e.name, keys: e.keys, threshold: e.threshold, home: e.home, replicas: e.replicas || [], succession: e.succession || [], policy: { ...DEFAULT_POLICY, ...(e.policy || {}) } });
      return;
    }
    case "keys.set":
      checkKeys(e.keys, h);
      if (!Number.isSafeInteger(e.threshold) || e.threshold < 1 || e.threshold > e.keys.filter((k) => k.caps.includes("authority")).length) fail("BAD_EVENT", "The threshold must be between 1 and the number of authority keys", h);
      state.keys = e.keys;
      state.threshold = e.threshold;
      ctx.newEpoch = true;
      return;
    case "replicas.set":
      checkReplicas(e.replicas, e.succession || [], h);
      state.replicas = e.replicas;
      state.succession = e.succession || [];
      return;
    case "policy.set":
      if (e.policy?.authority_change && !["threshold", "vote"].includes(e.policy.authority_change)) fail("BAD_EVENT", "Unknown authority rule", h);
      state.policy = { ...state.policy, ...e.policy };
      return;
    case "host.move":
      // A planned migration: the community keeps its id, history and members; only the site changes.
      checkHome(e.home, h);
      state.home = e.home;
      ctx.newEpoch = true;
      return;
    case "governance.result": {
      const r = e.result;
      if (!r?.body?.motion || !r.sig) fail("BAD_EVENT", "Not a vote result", h);
      const tallier = state.keys.find((k) => k.kid === r.sig.kid && (k.caps.includes("authority") || k.caps.includes("govern")));
      if (!tallier || !checkSignature(r, r.sig, tallier.pub)) fail("BAD_EVENT", "A vote result must be signed by one of the community's keys", h);
      state.results[sha256B64u(signingBytes(r.kind, r.body))] = { motion: r.body.motion, passed: Boolean(r.body.passed), action: r.body.action || "" };
      return;
    }
    case "member.add":
      if (typeof e.pub !== "string" || keyId(e.pub) !== e.member) fail("BAD_EVENT", "A member's id must match their key", h);
      if (state.bans[e.member]) fail("BANNED", "That member is banned", h);
      state.members[e.member] = { pub: e.pub, roles: state.members[e.member]?.roles || [], since: h };
      return;
    case "member.remove":
      // Members may always leave; removing someone else needs the members capability.
      if (e.member !== block.sig.kid && !ctx.caps.has("members")) fail("NOT_ALLOWED", "Only the member or a moderator can remove a member", h);
      delete state.members[e.member];
      return;
    case "role.set":
      if (!state.members[e.member]) fail("BAD_EVENT", "Not a member", h);
      if (!Array.isArray(e.roles) || e.roles.some((r) => typeof r !== "string")) fail("BAD_EVENT", "Roles are a list of names", h);
      state.members[e.member].roles = e.roles;
      return;
    case "ban.set":
      if (e.banned) {
        state.bans[e.member] = { since: h };
        delete state.members[e.member];
      } else delete state.bans[e.member];
      return;
    case "channel.set":
      if (typeof e.channel !== "string" || !e.channel) fail("BAD_EVENT", "A channel needs an id", h);
      state.channels[e.channel] = { name: String(e.name || ""), sealed: e.sealed || null, since: state.channels[e.channel]?.since ?? h };
      return;
    case "channel.remove":
      delete state.channels[e.channel];
      return;
    case "content.ref":
      if (e.channel && !state.channels[e.channel]) fail("BAD_EVENT", "No such channel", h);
      state.content += 1;
      return;
    case "note":
      state.content += 1;
      return;
    default:
      fail("UNKNOWN_EVENT", `Unknown event type ${e.type}`, h);
  }
}

/**
 * Apply one block to a state, checking everything. Returns the new state; the old one is left as
 * it was. Throws LedgerError if the block isn't valid here.
 */
export function applyBlock(prior, block) {
  const b = block?.body;
  const h = b?.height;
  if (!block || block.kind !== BLOCK_KIND || !b || !block.sig) fail("MALFORMED", "Not a ledger block", h);
  if (canonicalJson(block).length > MAX_BLOCK_BYTES) fail("TOO_LARGE", "Block too large", h);
  if (!Array.isArray(b.events) || !b.events.length || b.events.length > MAX_EVENTS) fail("MALFORMED", "A block holds 1 to 256 events", h);
  if (h !== prior.height + 1) fail("WRONG_HEIGHT", `Expected block ${prior.height + 1}`, h);
  if (b.prev !== prior.head) fail("WRONG_PREV", "This block doesn't follow the one before it", h);
  if (h > 0 && b.community !== prior.community) fail("WRONG_COMMUNITY", "This block belongs to another community", h);
  if (b.epoch !== prior.epoch) fail("WRONG_EPOCH", "This block was made under a different authority", h);

  const state = structuredClone(prior);
  let signer;
  if (h === 0) {
    const g = b.events[0];
    if (b.events.length !== 1 || g?.type !== "commons.genesis") fail("MALFORMED", "The first block holds only the genesis event", h);
    applyEvent(state, g, block, { caps: new Set(CAPS) });
    signer = signersOf(state).get(block.sig.kid);
    if (!signer?.authority || !checkSignature(block, block.sig, signer.pub)) fail("BAD_SIGNATURE", "The first block must be signed by one of its own authority keys", h);
    if (authoritySigners(block, state).size < state.threshold) fail("THRESHOLD", "Not enough authority signatures", h);
    state.community = blockId(block);
  } else {
    signer = signersOf(prior).get(block.sig.kid);
    if (!signer) fail("UNKNOWN_SIGNER", "Signed by a key this community doesn't know", h);
    if (!checkSignature(block, block.sig, signer.pub)) fail("BAD_SIGNATURE", "The block's signature doesn't match", h);
    const ctx = { caps: signer.caps, newEpoch: false };
    const needsAuthority = b.events.some((e) => AUTHORITY_EVENTS.has(e?.type));
    if (needsAuthority) {
      const count = authoritySigners(block, prior).size;
      if (count < prior.threshold) fail("THRESHOLD", `Needs ${prior.threshold} authority signatures, has ${count}`, h);
    }
    for (const e of b.events) {
      if (!e || typeof e.type !== "string") fail("MALFORMED", "An event needs a type", h);
      const cap = EVENT_CAPS[e.type];
      if (!cap) fail("UNKNOWN_EVENT", `Unknown event type ${e.type}`, h);
      if (e.type === "commons.genesis") fail("BAD_EVENT", "A community only starts once", h);
      const allowed = cap === "authority" ? needsAuthority : signer.caps.has(cap) || (e.type === "member.remove" && e.member === block.sig.kid);
      if (!allowed) fail("NOT_ALLOWED", `This signer can't make ${e.type}`, h);
      if (AUTHORITY_EVENTS.has(e.type) && prior.policy.authority_change === "vote") {
        const result = state.results[e.mandate];
        if (!result?.passed || result.action !== actionHash(e)) fail("NO_MANDATE", "This change needs a passed vote for exactly this change", h);
      }
      applyEvent(state, e, block, ctx);
    }
    if (ctx.newEpoch) state.epoch += 1;
  }
  state.height = h;
  state.head = blockId(block);
  return state;
}

/** Check a whole chain from its first block. Returns the final state. */
export function replay(blocks) {
  let state = emptyState();
  for (const block of blocks) state = applyBlock(state, block);
  return state;
}

/** Make a block that follows a state. key signs it; cosigners add their signatures (for authority changes). */
export function makeBlock(state, events, key, { cosigners = [], at = new Date().toISOString() } = {}) {
  const body = { community: state.height < 0 ? "" : state.community, height: state.height + 1, prev: state.head, epoch: state.epoch, at, events };
  const block = sign(BLOCK_KIND, body, key);
  const cosigs = cosigners.filter((k) => k.kid !== key.kid).map((k) => cosign(block, k));
  return cosigs.length ? { ...block, cosigs } : block;
}

/** Add someone's co-signature to a block that's waiting for enough of them. */
export const addCosignature = (block, key) => ({ ...block, cosigs: [...(block.cosigs || []).filter((s) => s.kid !== key.kid), cosign(block, key)] });

/** Start a community. keys: [{ kid, pub, caps }]; home: { site, kid, pub } (the home site's key). */
export function genesis({ name, keys, threshold = 1, home, replicas = [], succession = [], policy = {} }, key, { cosigners = [], at } = {}) {
  const event = { type: "commons.genesis", name, keys, threshold, home, replicas, succession, policy: { ...DEFAULT_POLICY, ...policy } };
  return makeBlock(emptyState(), [event], key, { cosigners, at });
}

/** How much authority stands behind a block: the number of distinct authority keys that signed it. */
const weightOf = (block, state) => authoritySigners(block, state).size;

/**
 * Bring a local copy up to date from another copy. Both are checked from the start. Where they
 * agree, nothing happens; where one simply has more blocks, those are added. Where they split
 * (two different blocks at the same height), one branch is chosen the same way on every site:
 *   1. the block with more authority signatures wins, then
 *   2. the longer valid branch, then
 *   3. the block whose id sorts first.
 * Never by timestamp. A key that signed both sides of a split is reported as equivocating, with
 * both blocks as proof.
 */
export function reconcile(local, remote) {
  const states = [emptyState()];
  let i = 0;
  while (i < local.length && i < remote.length && blockId(local[i]) === blockId(remote[i])) {
    states.push(applyBlock(states[i], local[i]));
    i += 1;
  }
  const base = states[i];
  const extend = (blocks) => {
    const out = [];
    let s = base;
    for (const b of blocks.slice(i)) {
      try {
        s = applyBlock(s, b);
      } catch {
        break; // a copy is only good up to its first bad block
      }
      out.push(b);
    }
    return { blocks: out, state: s };
  };
  const mine = extend(local);
  const theirs = extend(remote);
  const evidence = [];
  if (mine.blocks.length && theirs.blocks.length) {
    const [a, b] = [mine.blocks[0], theirs.blocks[0]];
    const signersA = new Set([a.sig.kid, ...(a.cosigs || []).map((s) => s.kid)]);
    for (const kid of [b.sig.kid, ...(b.cosigs || []).map((s) => s.kid)]) {
      if (signersA.has(kid)) evidence.push({ kid, height: a.body.height, blocks: [a, b] });
    }
  }
  const score = (side) => [side.blocks.length ? weightOf(side.blocks[0], base) : -1, side.blocks.length, side.blocks.length ? blockId(side.blocks[0]) : ""];
  const [sa, sb] = [score(mine), score(theirs)];
  let pick = mine;
  if (sb[0] !== sa[0]) pick = sb[0] > sa[0] ? theirs : mine;
  else if (sb[1] !== sa[1]) pick = sb[1] > sa[1] ? theirs : mine;
  else if (theirs.blocks.length && sb[2] < sa[2]) pick = theirs;
  return { blocks: [...local.slice(0, i), ...pick.blocks], state: pick.state, changed: pick === theirs && theirs.blocks.length > 0, forked: Boolean(mine.blocks.length && theirs.blocks.length), evidence };
}

/**
 * A site saying it's serving a community, and how far its copy goes. Signed with the site's key.
 * role "home" is the community's own site; "acting" is a replica covering while home is down.
 */
export function announceHost(state, { site, role, validForS = 600, at = new Date() }, siteKey) {
  const t = at instanceof Date ? at : new Date(at);
  return sign(HOST_KIND, { community: state.community, site, role, height: state.height, head: state.head, at: t.toISOString(), until: new Date(t.getTime() + validForS * 1000).toISOString() }, siteKey);
}

/**
 * Which site to use for a community right now. The home site while it answers; when it doesn't,
 * and the community's policy allows it, the first replica in its succession order that has a
 * current copy (announcements older than their "until" don't count). Returns { site, role } or null.
 */
export function chooseHost(state, announcements, { now = Date.now(), unreachable = new Set() } = {}) {
  const valid = new Map();
  for (const a of announcements) {
    const b = a?.body;
    if (a?.kind !== HOST_KIND || b?.community !== state.community || Date.parse(b.until) < now) continue;
    const who = b.site === state.home?.site ? state.home : state.replicas.find((r) => r.site === b.site);
    if (!who || !checkSignature(a, a.sig, who.pub)) continue;
    if ((valid.get(b.site)?.body.height ?? -1) < b.height) valid.set(b.site, a);
  }
  if (state.home && !unreachable.has(state.home.site)) return { site: state.home.site, role: "home" };
  if (!state.policy.auto_failover) return null;
  const best = Math.max(-1, ...[...valid.values()].map((a) => a.body.height));
  for (const site of state.succession) {
    if (unreachable.has(site)) continue;
    const a = valid.get(site);
    if (a && a.body.height >= best) return { site, role: "acting" };
  }
  return null;
}

/** A plain summary of a state, for showing people (who's in charge, where it lives, who has a copy). */
export function describe(state) {
  return {
    community: state.community,
    name: state.name,
    height: state.height,
    epoch: state.epoch,
    authority: state.keys.filter((k) => k.caps.includes("authority")).map((k) => k.kid),
    threshold: state.threshold,
    home: state.home?.site || "",
    replicas: state.replicas.map((r) => r.site),
    succession: state.succession,
    members: Object.keys(state.members).length,
    channels: Object.keys(state.channels).length,
  };
}

export { emptyState };
