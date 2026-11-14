// Repositories (CVP-020): an actor's public activities as a signed, verifiable set.
//
// Like an AT Protocol repository, it lets anyone check they have all of an actor's public
// records, exactly as the actor published them, whichever site (or mirror, or indexer) they came
// from; and it lets an actor carry their public history to another site. Unlike one, each commit
// is signed with Ed25519 and ML-DSA-65, and only public activities are in it: encrypted ones
// live on devices (CVP-019), never in a repository.
//
// A commit signs the Merkle root of the record ids, in order. Deleting removes a record, so the
// next root no longer covers it.
import { sha256 } from "@noble/hashes/sha2.js";
import { b64u, fromB64u, utf8, concat, equalBytes } from "../core/bytes.js";
import { sign, checkSignature, recordId } from "../core/signed.js";
import { SessionError } from "../session/primitives.js";
import { verifyActorDocument, deviceKeyAt } from "./actor.js";
import { verifyActivity } from "./activity.js";
import { PUBLIC } from "./vocabulary.js";

export const COMMIT = "repo.commit";
export const MAX_RECORDS = 100_000;

const leaf = (id) => sha256(concat(utf8("secure-net/repo/v1/leaf\n"), utf8(id)));
const node = (l, r) => sha256(concat(utf8("secure-net/repo/v1/node\n"), l, r));
const empty = () => sha256(utf8("secure-net/repo/v1/empty\n"));
const split = (n) => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};
function rootOf(h) {
  if (h.length === 0) return empty();
  if (h.length === 1) return h[0];
  const k = split(h.length);
  return node(rootOf(h.slice(0, k)), rootOf(h.slice(k)));
}
function pathOf(h, i) {
  if (h.length === 1) return [];
  const k = split(h.length);
  return i < k ? [...pathOf(h.slice(0, k), i), rootOf(h.slice(k))] : [...pathOf(h.slice(k), i - k), rootOf(h.slice(0, k))];
}

/** The Merkle root (base64url) of a list of record ids, in order. */
export const merkleRoot = (ids) => b64u(rootOf(ids.map(leaf)));

/** Proof that ids[index] is in the set: sibling hashes from the leaf up (base64url). */
export function inclusionProof(ids, index) {
  if (!Number.isSafeInteger(index) || index < 0 || index >= ids.length) throw new SessionError("BAD_INPUT", "No such record");
  return pathOf(ids.map(leaf), index).map(b64u);
}

/** Check a proof that a record id is at `index` of `count` records under `root`. */
export function verifyInclusion(id, index, count, proof, root) {
  const up = (i, n, p) => {
    if (n === 1) {
      if (p.length) throw new SessionError("BAD_PROOF", "Proof is too long");
      return leaf(id);
    }
    if (!p.length) throw new SessionError("BAD_PROOF", "Proof is too short");
    const k = split(n);
    const sib = fromB64u(p[p.length - 1]);
    return i < k ? node(up(i, k, p.slice(0, -1)), sib) : node(sib, up(i - k, n - k, p.slice(0, -1)));
  };
  try {
    return Number.isSafeInteger(index) && index >= 0 && index < count && equalBytes(up(index, count, proof), fromB64u(root));
  } catch {
    return false;
  }
}

/** An empty repository for an actor. */
export const createRepo = (actorId) => ({ actor: actorId, records: [], head: null });

function commit(repo, device, records, now) {
  const body = { v: 1, actor: repo.actor, device: device.kid, seq: (repo.head?.body.seq ?? 0) + 1, prev: repo.head ? recordId(repo.head) : null, root: merkleRoot(records.map(recordId)), count: records.length, at: now };
  return { actor: repo.actor, records, head: sign(COMMIT, body, device.sign) };
}

/** Add a signed public activity and commit. */
export function appendToRepo(repo, device, record, { now = Date.now() } = {}) {
  if (record?.body?.actor !== repo.actor) throw new SessionError("BAD_INPUT", "That activity is another actor's");
  if (![...(record.body.to || []), ...(record.body.cc || [])].includes(PUBLIC)) throw new SessionError("BAD_INPUT", "Only public activities go in a repository");
  if (repo.records.length >= MAX_RECORDS) throw new SessionError("TOO_LARGE", "Repository is full");
  return commit(repo, device, [...repo.records, record], now);
}

/** Remove the activities whose id, or whose object's id, is `id` (after a Delete), and commit. */
export function removeFromRepo(repo, device, id, { now = Date.now() } = {}) {
  return commit(repo, device, repo.records.filter((r) => r.body.id !== id && r.body.object?.id !== id), now);
}

/** What a site serves for a repository: the actor document, the head commit and the records. */
export const exportRepo = (repo, actorRecord) => ({ v: 1, actor: actorRecord, head: repo.head, records: repo.records });

/** Check a head commit against its actor (document body). Returns the commit body. */
export function verifyCommit(head, actor, { minSeq = 0 } = {}) {
  const c = head?.body;
  if (head?.kind !== COMMIT || !c || c.v !== 1) throw new SessionError("BAD_MESSAGE", "Not a repository commit");
  if (c.actor !== actor.id || head.sig?.kid !== c.device) throw new SessionError("UNTRUSTED", "Commit is for another actor or device");
  const key = deviceKeyAt(actor, c.device, c.at);
  if (!key || !key.includes(".") || !checkSignature(head, head.sig, key)) throw new SessionError("UNTRUSTED", "Commit isn't signed by a device of the actor");
  if (!Number.isSafeInteger(c.seq) || c.seq < 1 || !Number.isSafeInteger(c.count) || c.count < 0) throw new SessionError("BAD_MESSAGE", "Bad commit");
  if (c.seq < minSeq) throw new SessionError("ROLLBACK", "Repository is older than one already seen");
  return c;
}

/**
 * Check a whole exported repository, from any source: the actor document, the head commit, every
 * record (a valid public activity of the actor's), and that the records are exactly the set the
 * commit signed. Returns { actor, commit, records }.
 */
export function verifyRepo(exported, { id, minSeq = 0, now = Date.now() } = {}) {
  if (exported?.v !== 1 || !Array.isArray(exported.records)) throw new SessionError("BAD_MESSAGE", "Not a repository");
  const actor = verifyActorDocument(exported.actor, { id });
  const c = verifyCommit(exported.head, actor, { minSeq });
  if (exported.records.length !== c.count) throw new SessionError("TAMPERED", "Records are missing or added");
  for (const r of exported.records) {
    const b = verifyActivity(r, actor, { now });
    if (![...(b.to || []), ...(b.cc || [])].includes(PUBLIC)) throw new SessionError("TAMPERED", "A record that isn't public");
  }
  if (merkleRoot(exported.records.map(recordId)) !== c.root) throw new SessionError("TAMPERED", "Records don't match the signed root");
  return { actor, commit: c, records: exported.records };
}
