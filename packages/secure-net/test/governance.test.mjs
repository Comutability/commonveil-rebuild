import test from "node:test";
import assert from "node:assert/strict";
import { generateSigningKey } from "../src/core/signed.js";
import { propose, castBallot, castSecretBallot, tally, signResult, verifyResult, checkMotion } from "../src/governance/vote.js";
import { post, arrange, itemId } from "../src/governance/debate.js";
import { issuerKey, requestTokens, issueTokens, finishTokens, spendToken, checkToken, nullifier } from "../src/tokens/voprf.js";

const people = (n) => Array.from({ length: n }, () => generateSigningKey());
const lookup = (list) => (kid) => list.find((p) => p.kid === kid)?.publicKey;
const now = Date.now();
const window = { opens: new Date(now - 60_000).toISOString(), closes: new Date(now + 60_000).toISOString() };
const at = (ms = 0) => new Date(now + ms).toISOString();
const yesNo = [{ id: "yes", label: "Yes" }, { id: "no", label: "No" }];

test("public vote: one counted ballot per member, the latest wins, late and ineligible ballots don't count", () => {
  const v = people(5);
  const outsider = generateSigningKey();
  const motion = propose({ community: "c1", title: "Open a books channel", options: yesNo, eligible: v.map((p) => p.kid), quorum: 3, ...window }, v[0]);
  assert.equal(checkMotion(motion, lookup(v)).title, "Open a books channel");
  const received = [
    { ballot: castBallot(motion, "no", v[0], 1), at: at() },
    { ballot: castBallot(motion, "yes", v[0], 2), at: at(1) }, // changed their mind
    { ballot: castBallot(motion, "yes", v[1]), at: at() },
    { ballot: castBallot(motion, "no", v[2]), at: at() },
    { ballot: castBallot(motion, "yes", v[3]), at: at(120_000) }, // after closing
    { ballot: castBallot(motion, "yes", outsider), at: at() },
    { ballot: castBallot(motion, "maybe", v[4]), at: at() }, // not an option
  ];
  const keyFor = lookup([...v, outsider]);
  const r = tally(motion, received, { keyFor });
  assert.deepEqual(r.counts, { yes: 2, no: 1 });
  assert.equal(r.total, 3);
  assert.equal(r.spoiled, 2);
  assert.ok(r.quorum_met && r.passed);
  const signed = signResult(r, v[0]);
  assert.deepEqual(verifyResult(motion, signed, received, { keyFor, tallierKey: v[0].publicKey }), r, "anyone can recount");
  const fiddled = signResult({ ...r, counts: { yes: 3, no: 0 } }, v[0]);
  assert.throws(() => verifyResult(motion, fiddled, received, { keyFor, tallierKey: v[0].publicKey }), /different result/);
});

test("two different ballots with the same number from one voter: neither counts", () => {
  const v = people(2);
  const motion = propose({ community: "c1", title: "T", options: yesNo, eligible: v.map((p) => p.kid), ...window }, v[0]);
  const r = tally(motion, [{ ballot: castBallot(motion, "yes", v[0], 1), at: at() }, { ballot: castBallot(motion, "no", v[0], 1), at: at() }, { ballot: castBallot(motion, "yes", v[1]), at: at() }], { keyFor: lookup(v) });
  assert.equal(r.total, 1);
  assert.equal(r.spoiled, 1);
});

test("supermajority, quorum and ranked choice count the same way everywhere", () => {
  const v = people(9);
  const sm = propose({ community: "c", title: "Change the rules", options: yesNo, method: "supermajority", threshold: { num: 2, den: 3 }, eligible: v.map((p) => p.kid), ...window }, v[0]);
  const ballots = (choices) => choices.map((c, i) => ({ ballot: castBallot(sm, c, v[i]), at: at() }));
  assert.equal(tally(sm, ballots(["yes", "yes", "yes", "yes", "yes", "no", "no", "no"]), { keyFor: lookup(v) }).passed, false, "5 of 8 isn't two thirds");
  assert.equal(tally(sm, ballots(["yes", "yes", "yes", "yes", "yes", "yes", "no", "no", "no"]), { keyFor: lookup(v) }).passed, true, "6 of 9 is");
  const q = propose({ community: "c", title: "Q", options: yesNo, quorum: 5, eligible: v.map((p) => p.kid), ...window }, v[0]);
  const r = tally(q, [{ ballot: castBallot(q, "yes", v[0]), at: at() }], { keyFor: lookup(v) });
  assert.ok(!r.quorum_met && !r.passed);

  const opts = ["a", "b", "c"].map((id) => ({ id, label: id }));
  const rc = propose({ community: "c", title: "Pick a name", options: opts, method: "ranked", passOption: "b", eligible: v.map((p) => p.kid), ...window }, v[0]);
  // First preferences a:4 b:3 c:2. c goes; its voters prefer b, so b wins 5-4.
  const rankings = [["a"], ["a"], ["a"], ["a"], ["b"], ["b"], ["b"], ["c", "b"], ["c", "b"]];
  const res = tally(rc, rankings.map((c, i) => ({ ballot: castBallot(rc, c, v[i]), at: at() })), { keyFor: lookup(v) });
  assert.equal(res.winner, "b");
  assert.equal(res.rounds.length, 2);
  assert.ok(res.passed);
});

test("secret ballots: tokens are unlinkable, one per member, and can't be spent twice or forged", () => {
  const v = people(3);
  const seed = new Uint8Array(32).fill(7);
  const motion0 = { community: "c", title: "Elect a moderator", options: yesNo, ballot: "secret", eligible: v.map((p) => p.kid), ...window };
  const key = issuerKey(seed, "vote:elect");
  const motion = propose({ ...motion0, issuer: { publicKey: key.publicKey } }, v[0]);

  // Each member asks for one token (the issuer checks they're eligible and haven't had one).
  const tokens = v.map(() => {
    const { pending, request } = requestTokens(1);
    return finishTokens(pending, issueTokens(key, request), key.publicKey)[0];
  });
  // A token from a different issuer key doesn't verify against this one (the proof check).
  const other = issuerKey(seed, "vote:other");
  const { pending, request } = requestTokens(1);
  assert.throws(() => finishTokens(pending, issueTokens(other, request), key.publicKey), /proof/);

  const received = [
    { ballot: castSecretBallot(motion, "yes", tokens[0]), at: at() },
    { ballot: castSecretBallot(motion, "no", tokens[1]), at: at() },
    { ballot: castSecretBallot(motion, "yes", tokens[2]), at: at() },
    { ballot: castSecretBallot(motion, "no", tokens[2]), at: at() }, // same token again
    { ballot: castSecretBallot(motion, "no", { input: tokens[0].input, output: tokens[1].output }), at: at() }, // forged
  ];
  const r = tally(motion, received, { issuerKey: key });
  assert.deepEqual(r.counts, { yes: 2, no: 1 });
  assert.equal(r.spoiled, 2);
  assert.ok(!JSON.stringify(received.map((x) => x.ballot)).includes(v[0].kid), "no ballot names its voter");
});

test("tokens: issued blind, checked by the issuer, spent once", () => {
  const key = issuerKey(new Uint8Array(32).fill(1), "reports");
  const { pending, request } = requestTokens(3);
  const ts = finishTokens(pending, issueTokens(key, request), key.publicKey);
  assert.equal(ts.length, 3);
  assert.ok(!request.some((b) => ts.some((t) => t.input === b)), "the issuer never sees a token's input");
  const spent = new Set();
  assert.equal(spendToken(key, ts[0], spent), nullifier(ts[0]));
  assert.throws(() => spendToken(key, ts[0], spent), /already been used/);
  assert.ok(checkToken(key, ts[1]));
  assert.ok(!checkToken(issuerKey(new Uint8Array(32).fill(1), "other"), ts[1]), "tokens are only good for their scope");
});

test("debates: typed, signed items arranged as a map and as an accessible thread; rounds and moderation apply", () => {
  const [mod, ann, ben] = people(3);
  const keyFor = lookup([mod, ann, ben]);
  const motion = propose({ community: "c", title: "Should the library open on Sundays?", options: yesNo, eligible: [ann.kid, ben.kid], ...window }, mod);
  const m = itemId(motion);
  const round = post("debate.round", { motion: m, name: "Open floor", phase: "open", opens: at(-60_000), closes: at(60_000), who: "all" }, mod);
  const pos = post("debate.position", { motion: m, side: "yes", statement: "More access for working families.", at: at() }, ann);
  const arg = post("debate.argument", { motion: m, side: "yes", claim: "Weekend demand is high", detail: "Saturday visits are double weekday visits.", at: at(1) }, ann);
  const reb = post("debate.rebuttal", { motion: m, target: itemId(arg), claim: "Staff costs rise on Sundays", at: at(2) }, ben);
  const ev = post("debate.evidence", { motion: m, target: itemId(arg), source: "https://example.org/visits.csv", citation: "Library visit counts, 2025", at: at(3) }, ann);
  const late = post("debate.argument", { motion: m, side: "no", claim: "Too late", at: at(120_000) }, ben);
  const orphan = post("debate.rebuttal", { motion: m, target: "nothing", claim: "Reply to nothing", at: at(4) }, ben);
  const hide = post("debate.moderation", { motion: m, target: itemId(reb), action: "hide", reason: "Off topic", at: at(5) }, mod);
  const fake = post("debate.moderation", { motion: m, target: itemId(arg), action: "hide", at: at(5) }, ben);

  const d = arrange(motion, [pos, arg, reb, ev, late, orphan, hide, fake, round], { keyFor, isModerator: (kid) => kid === mod.kid });
  assert.equal(d.tree.length, 2, "a position and a top-level argument");
  const top = d.tree.find((n) => n.kind === "debate.argument");
  assert.deepEqual(top.replies.map((r) => r.kind).sort(), ["debate.evidence", "debate.rebuttal"]);
  assert.ok(top.replies.find((r) => r.kind === "debate.rebuttal").hidden, "moderators can hide");
  assert.ok(!top.hidden, "others can't");
  assert.deepEqual(d.threaded.map((n) => n.depth), [0, 0, 1, 1]);
  assert.deepEqual(d.rejected.map((r) => r.why).sort(), ["only moderators can do that", "outside any round that allows it", "replies to something that isn't in this debate"]);
});
