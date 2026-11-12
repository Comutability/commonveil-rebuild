// Community votes without a blockchain (CVP-012): signed motions, ballots and results that any
// site or member can check, counted the same way everywhere.
//
// Two kinds of ballot:
//   - public: each ballot is signed by the member's key. Anyone can recount and see who voted
//     for what. A member can change their vote until it closes (the highest "seq" counts).
//   - secret: each eligible member gets one private token for this vote (tokens/voprf.js) and
//     casts a ballot carrying only the token. The issuer can't tell whose ballot is whose, but
//     only the issuer can check the tokens, so the count is only as honest as the issuer.
//     The community chooses which kind fits each decision.
//
// A vote counts ballots received between its opening and closing times, by the collecting site's
// clock. The result commits to the exact set of ballots it counted (a hash of each), so anyone
// holding the ballots can tell whether a ballot they cast was left out.
import { sha256B64u, randomB64u } from "../core/bytes.js";
import { canonicalJson } from "../core/canonical.js";
import { sign, checkSignature, signingBytes } from "../core/signed.js";
import { spendToken } from "../tokens/voprf.js";

export const MOTION = "governance.motion";
export const BALLOT = "vote.ballot";
export const SECRET_BALLOT = "vote.secret-ballot";
export const RESULT = "vote.result";
export const METHODS = ["majority", "supermajority", "approval", "ranked"];

export class VoteError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "VoteError";
    this.code = code;
  }
}
const fail = (code, message) => {
  throw new VoteError(code, message);
};

/** A motion's id is the hash of what its proposer signed. */
export const motionId = (motion) => sha256B64u(signingBytes(motion.kind, motion.body));

/**
 * Propose a motion. eligible: the member key ids who may vote (taken from the community's ledger
 * at a given height, so everyone counts the same people). action: for a vote that authorises a
 * ledger change, its actionHash (commons/ledger.js).
 */
export function propose({ community, title, question = "", options, method = "majority", passOption = options?.[0]?.id, threshold = { num: 2, den: 3 }, quorum = 0, opens, closes, ballot = "public", eligible, eligibleAt = -1, issuer = null, action = "" }, key) {
  const body = { id: randomB64u(12), community, title, question, options, method, pass_option: passOption, threshold, quorum, opens, closes, ballot, eligible, eligible_at: eligibleAt, issuer, action };
  checkMotionBody(body);
  return sign(MOTION, body, key);
}

function checkMotionBody(m) {
  if (typeof m.title !== "string" || !m.title || m.title.length > 200) fail("BAD_MOTION", "A motion needs a title");
  if (!Array.isArray(m.options) || m.options.length < 2 || m.options.length > 50) fail("BAD_MOTION", "A motion needs 2 to 50 options");
  const ids = new Set(m.options.map((o) => o?.id));
  if (ids.size !== m.options.length || [...ids].some((id) => typeof id !== "string" || !id)) fail("BAD_MOTION", "Each option needs its own id");
  if (!METHODS.includes(m.method)) fail("BAD_MOTION", `Method must be one of ${METHODS.join(", ")}`);
  if (!ids.has(m.pass_option)) fail("BAD_MOTION", "The passing option must be one of the options");
  if (m.method === "supermajority" && !(Number.isSafeInteger(m.threshold?.num) && Number.isSafeInteger(m.threshold?.den) && m.threshold.num > 0 && m.threshold.num <= m.threshold.den)) fail("BAD_MOTION", "A supermajority needs a fraction, such as 2/3");
  if (!Number.isSafeInteger(m.quorum) || m.quorum < 0) fail("BAD_MOTION", "Quorum is a number of ballots");
  if (!(Date.parse(m.opens) < Date.parse(m.closes))) fail("BAD_MOTION", "A vote must open before it closes");
  if (!["public", "secret"].includes(m.ballot)) fail("BAD_MOTION", "Ballots are public or secret");
  if (!Array.isArray(m.eligible) || !m.eligible.length) fail("BAD_MOTION", "Someone must be able to vote");
  if (m.ballot === "secret" && typeof m.issuer?.publicKey !== "string") fail("BAD_MOTION", "A secret ballot needs a token issuer");
}

/** Check a motion's signature (keyFor gives a proposer's public key) and contents. Returns its body. */
export function checkMotion(motion, keyFor) {
  if (motion?.kind !== MOTION) fail("BAD_MOTION", "Not a motion");
  const pub = keyFor(motion.sig?.kid);
  if (!pub || !checkSignature(motion, motion.sig, pub)) fail("BAD_SIGNATURE", "The motion's signature doesn't match its proposer");
  checkMotionBody(motion.body);
  return motion.body;
}

/** A public ballot. seq: raise it to change your vote; the highest counts. */
export const castBallot = (motion, choice, key, seq = 1) => sign(BALLOT, { motion: motionId(motion), choice, seq }, key);

/** A secret ballot: the choice and a token, unsigned. Send it without signing in. */
export const castSecretBallot = (motion, choice, token) => ({ kind: SECRET_BALLOT, body: { motion: motionId(motion), choice, token } });

/** A ballot's id, as a result commits to it. */
export const ballotId = (ballot) => sha256B64u(canonicalJson({ kind: ballot.kind, body: ballot.body, sig: ballot.sig || null }));

function validChoice(m, choice) {
  const ids = new Set(m.options.map((o) => o.id));
  if (m.method === "majority" || m.method === "supermajority") return typeof choice === "string" && ids.has(choice);
  if (!Array.isArray(choice) || !choice.length || choice.length > ids.size) return false;
  if (new Set(choice).size !== choice.length) return false;
  return choice.every((c) => ids.has(c));
}

/** Instant-runoff: drop the option with fewest first preferences until one has a majority. */
function instantRunoff(options, choices) {
  let remaining = options.map((o) => o.id);
  const rounds = [];
  for (;;) {
    const counts = Object.fromEntries(remaining.map((id) => [id, 0]));
    let active = 0;
    for (const ranking of choices) {
      const top = ranking.find((c) => remaining.includes(c));
      if (top) {
        counts[top] += 1;
        active += 1;
      }
    }
    rounds.push(counts);
    const sorted = [...remaining].sort((a, b) => counts[b] - counts[a] || (a < b ? -1 : 1));
    if (counts[sorted[0]] * 2 > active || remaining.length <= 2 || active === 0) return { winner: active ? sorted[0] : null, rounds };
    // Fewest first preferences goes; ties go by option order, the same on every site.
    const least = Math.min(...remaining.map((id) => counts[id]));
    const out = [...remaining].reverse().find((id) => counts[id] === least);
    remaining = remaining.filter((id) => id !== out);
  }
}

/**
 * Count a vote. received: [{ ballot, at }] where at is when the collecting site got it.
 * For public ballots, keyFor gives a voter's public key. For secret ballots, issuerKey is the
 * issuer's key for this vote (tokens/voprf.js issuerKey) and spent the set of spent tokens.
 * Returns the result body (not yet signed: see signResult).
 */
export function tally(motion, received, { keyFor = () => null, issuerKey = null, spent = new Set() } = {}) {
  const m = motion.body;
  const id = motionId(motion);
  const opens = Date.parse(m.opens);
  const closes = Date.parse(m.closes);
  const eligible = new Set(m.eligible);
  const inTime = received.filter((r) => r?.ballot?.body?.motion === id && Date.parse(r.at) >= opens && Date.parse(r.at) <= closes);
  let spoiled = 0;
  const counted = [];

  if (m.ballot === "public") {
    const latest = new Map();
    const clash = new Set();
    for (const { ballot } of inTime) {
      const kid = ballot.sig?.kid;
      if (ballot.kind !== BALLOT || !eligible.has(kid) || !Number.isSafeInteger(ballot.body.seq)) {
        spoiled += 1;
        continue;
      }
      const pub = keyFor(kid);
      if (!pub || !checkSignature(ballot, ballot.sig, pub)) {
        spoiled += 1;
        continue;
      }
      const prev = latest.get(kid);
      if (!prev || ballot.body.seq > prev.body.seq) latest.set(kid, ballot);
      else if (ballot.body.seq === prev.body.seq && canonicalJson(ballot.body) !== canonicalJson(prev.body)) clash.add(`${kid}:${ballot.body.seq}`);
    }
    for (const [kid, ballot] of latest) {
      // Two different ballots with the same number from one voter: neither counts.
      if (clash.has(`${kid}:${ballot.body.seq}`) || !validChoice(m, ballot.body.choice)) spoiled += 1;
      else counted.push(ballot);
    }
  } else {
    if (!issuerKey) fail("NO_ISSUER", "Counting secret ballots needs the issuer's key");
    for (const { ballot } of inTime) {
      if (ballot.kind !== SECRET_BALLOT || !validChoice(m, ballot.body.choice)) {
        spoiled += 1;
        continue;
      }
      try {
        spendToken(issuerKey, ballot.body.token, spent);
        counted.push(ballot);
      } catch {
        spoiled += 1;
      }
    }
  }

  const counts = Object.fromEntries(m.options.map((o) => [o.id, 0]));
  let rounds = null;
  let winner = null;
  const total = counted.length;
  if (m.method === "ranked") {
    ({ winner, rounds } = instantRunoff(m.options, counted.map((b) => b.body.choice)));
    for (const b of counted) counts[b.body.choice[0]] += 1;
  } else {
    for (const b of counted) for (const c of [b.body.choice].flat()) counts[c] += 1;
    const best = Math.max(...Object.values(counts));
    const top = m.options.map((o) => o.id).filter((oid) => counts[oid] === best);
    winner = total && top.length === 1 ? top[0] : null;
  }
  const quorumMet = total >= m.quorum;
  const yes = counts[m.pass_option];
  let passes = false;
  if (m.method === "majority") passes = yes * 2 > total;
  else if (m.method === "supermajority") passes = yes * m.threshold.den >= m.threshold.num * total && total > 0;
  else passes = winner === m.pass_option;

  const ballots = counted.map(ballotId).sort();
  return {
    motion: id,
    community: m.community,
    method: m.method,
    counts,
    rounds,
    winner,
    total,
    spoiled,
    quorum_met: quorumMet,
    passed: quorumMet && passes,
    ballots,
    ballots_hash: sha256B64u(ballots.join("\n")),
    action: m.action || "",
  };
}

/** Sign a result (the tallier's key). A passed result with an action can then go in the ledger. */
export const signResult = (body, key) => sign(RESULT, body, key);

/**
 * Check a published result for a public vote by counting the ballots again. Throws if the
 * signature is wrong or the count differs. Secret votes can only be checked by the issuer.
 */
export function verifyResult(motion, result, received, { keyFor, tallierKey }) {
  if (result?.kind !== RESULT || !checkSignature(result, result.sig, tallierKey)) fail("BAD_SIGNATURE", "The result isn't signed by the tallier");
  if (motion.body.ballot !== "public") fail("NOT_PUBLIC", "Only public ballots can be recounted by anyone");
  const again = tally(motion, received, { keyFor });
  if (canonicalJson(again) !== canonicalJson(result.body)) fail("MISCOUNT", "Counting the ballots again gives a different result");
  return again;
}
