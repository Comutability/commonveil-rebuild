import test from "node:test";
import assert from "node:assert/strict";
import { generateSigningKey } from "../src/core/signed.js";
import { genesis, replay, makeBlock, addCosignature, reconcile, announceHost, chooseHost, actionHash, describe, blockId } from "../src/commons/ledger.js";
import { propose, castBallot, tally, signResult } from "../src/governance/vote.js";

const key = () => generateSigningKey();
const entry = (k, caps = ["authority"]) => ({ kid: k.kid, pub: k.publicKey, caps });
const site = (name, k) => ({ site: name, kid: k.kid, pub: k.publicKey });

function community({ threshold = 1, policy = {} } = {}) {
  const [alice, bob, carol] = [key(), key(), key()];
  const [homeKey, r1Key, r2Key] = [key(), key(), key()];
  const g = genesis(
    {
      name: "Allotment Society",
      keys: [entry(alice), entry(bob), entry(carol)],
      threshold,
      home: site("home.example", homeKey),
      replicas: [site("one.example", r1Key), site("two.example", r2Key)],
      succession: ["one.example", "two.example"],
      policy,
    },
    alice,
    { cosigners: threshold > 1 ? [bob, carol].slice(0, threshold - 1) : [] },
  );
  return { alice, bob, carol, homeKey, r1Key, r2Key, chain: [g], state: replay([g]) };
}

const push = (c, events, signer, opts) => {
  const b = makeBlock(c.state, events, signer, opts);
  c.chain.push(b);
  c.state = replay(c.chain);
  return b;
};

test("a community starts, admits members and posts sealed content; any copy checks out", () => {
  const c = community();
  assert.equal(c.state.community, blockId(c.chain[0]), "its id is its first block");
  const dan = key();
  // The home site may admit members (it holds the members capability by default).
  push(c, [{ type: "channel.set", channel: "general", name: "General" }], c.alice);
  push(c, [{ type: "member.add", member: dan.kid, pub: dan.publicKey }], c.homeKey);
  // ...but not set up channels: that's for the community's own keys.
  assert.throws(() => replay([...c.chain, makeBlock(c.state, [{ type: "channel.set", channel: "x" }], c.homeKey)]), /can't make channel.set/);
  // A member may post content: ciphertext only.
  push(c, [{ type: "content.ref", channel: "general", ref: "blob:abc", sealed: "ciphertext..." }], dan);
  assert.equal(c.state.content, 1);
  // A mirror rebuilds the same state from the blocks alone.
  const mirror = replay(structuredClone(c.chain));
  assert.equal(mirror.head, c.state.head);
  assert.deepEqual(describe(mirror), describe(c.state));
});

test("members can't do what they aren't allowed to, and tampering is caught", () => {
  const c = community();
  const dan = key();
  push(c, [{ type: "member.add", member: dan.kid, pub: dan.publicKey }], c.alice);
  assert.throws(() => replay([...c.chain, makeBlock(c.state, [{ type: "channel.set", channel: "x" }], dan)]), /can't make channel.set/);
  assert.throws(() => replay([...c.chain, makeBlock(c.state, [{ type: "note" }], key())]), /doesn't know/);
  const forged = structuredClone(c.chain);
  forged[1].body.events[0].member = key().kid;
  assert.throws(() => replay(forged), /signature|match/);
  const reordered = [c.chain[0], { ...c.chain[1], body: { ...c.chain[1].body, prev: "x" } }];
  assert.throws(() => replay(reordered), /doesn't follow|signature/);
  // Members can always leave.
  push(c, [{ type: "member.remove", member: dan.kid }], dan);
  assert.equal(c.state.members[dan.kid], undefined);
});

test("changing who's in charge needs the threshold, and starts a new epoch", () => {
  const c = community({ threshold: 2 });
  const erin = key();
  const change = { type: "keys.set", keys: [entry(c.alice), entry(c.bob), entry(erin)], threshold: 2 };
  assert.throws(() => replay([...c.chain, makeBlock(c.state, [change], c.alice)]), /Needs 2 authority signatures/);
  const pending = makeBlock(c.state, [change], c.alice);
  const block = addCosignature(pending, c.carol);
  c.chain.push(block);
  c.state = replay(c.chain);
  assert.equal(c.state.epoch, 1);
  // A block made under the old authority is no longer accepted.
  const stale = makeBlock({ ...c.state, epoch: 0 }, [{ type: "note" }], c.alice);
  assert.throws(() => replay([...c.chain, stale]), /different authority/);
  // Carol is no longer an authority key.
  assert.throws(() => replay([...c.chain, makeBlock(c.state, [{ type: "note" }], c.carol)]), /doesn't know/);
});

test("a community can require a passed vote for exactly the change being made", () => {
  const c = community({ policy: { authority_change: "vote" } });
  const change = { type: "replicas.set", replicas: [], succession: [] };
  assert.throws(() => replay([...c.chain, makeBlock(c.state, [change], c.alice)]), /needs a passed vote/);
  const now = Date.now();
  const voters = [c.alice, c.bob, c.carol];
  const motion = propose({ community: c.state.community, title: "Stop using replicas", options: [{ id: "yes", label: "Yes" }, { id: "no", label: "No" }], opens: new Date(now - 60_000).toISOString(), closes: new Date(now + 60_000).toISOString(), eligible: voters.map((v) => v.kid), action: actionHash(change) }, c.alice);
  const received = [castBallot(motion, "yes", c.alice), castBallot(motion, "yes", c.bob), castBallot(motion, "no", c.carol)].map((ballot) => ({ ballot, at: new Date(now).toISOString() }));
  const keyFor = (kid) => voters.find((v) => v.kid === kid)?.publicKey;
  const result = signResult(tally(motion, received, { keyFor }), c.alice);
  assert.equal(result.body.passed, true);
  push(c, [{ type: "governance.result", result }], c.alice);
  const resultId = Object.keys(c.state.results)[0];
  // A different change can't borrow the mandate.
  const other = { type: "replicas.set", replicas: c.state.replicas, succession: ["two.example"], mandate: resultId };
  assert.throws(() => replay([...c.chain, makeBlock(c.state, [other], c.alice)]), /exactly this change/);
  push(c, [{ ...change, mandate: resultId }], c.alice);
  assert.deepEqual(c.state.replicas, []);
});

test("split brain: two admins remove each other while cut off; every copy settles on the same history", () => {
  const c = community();
  const base = [...c.chain];
  const s = c.state;
  const aliceSide = makeBlock(s, [{ type: "keys.set", keys: [entry(c.alice), entry(c.carol)], threshold: 1 }], c.alice);
  const bobSide = makeBlock(s, [{ type: "keys.set", keys: [entry(c.bob), entry(c.carol)], threshold: 1 }], c.bob, { cosigners: [c.carol] });
  const a = [...base, aliceSide];
  const b = [...base, bobSide];
  const fromA = reconcile(a, b);
  const fromB = reconcile(b, a);
  assert.equal(fromA.state.head, fromB.state.head, "both sides agree");
  assert.equal(fromA.state.head, blockId(bobSide), "more authority signatures win, not the clock");
  assert.ok(fromA.forked);
  // Carol signed both? No: only Bob's. But if one key signs both sides, that's reported.
  const carolBoth = makeBlock(s, [{ type: "note" }], c.carol);
  const r = reconcile([...base, makeBlock(s, [{ type: "note", n: 1 }], c.carol)], [...base, carolBoth]);
  assert.equal(r.evidence[0]?.kid, c.carol.kid, "equivocation is reported with proof");
});

test("a mirror catches up from another copy, and stops at the first bad block", () => {
  const c = community();
  push(c, [{ type: "note" }], c.alice);
  push(c, [{ type: "note" }], c.alice);
  const behind = c.chain.slice(0, 1);
  const up = reconcile(behind, c.chain);
  assert.equal(up.state.height, 2);
  assert.ok(up.changed);
  const poisoned = [...c.chain, { ...makeBlock(c.state, [{ type: "note" }], c.alice), sig: { ...c.chain[1].sig } }];
  const safe = reconcile(c.chain, poisoned);
  assert.equal(safe.state.height, 2, "the bad block isn't taken");
});

test("failover: when home stops answering, the first current replica in succession takes over; home comes back first", () => {
  const c = community();
  push(c, [{ type: "note" }], c.alice);
  const now = Date.now();
  const anns = [
    announceHost(c.state, { site: "home.example", role: "home", at: new Date(now) }, c.homeKey),
    announceHost({ ...c.state, height: c.state.height - 1 }, { site: "one.example", role: "acting", at: new Date(now) }, c.r1Key),
    announceHost(c.state, { site: "two.example", role: "acting", at: new Date(now) }, c.r2Key),
    announceHost(c.state, { site: "one.example", role: "acting", at: new Date(now) }, c.r2Key), // wrong key: ignored
  ];
  assert.deepEqual(chooseHost(c.state, anns, { now }), { site: "home.example", role: "home" });
  const down = new Set(["home.example"]);
  assert.deepEqual(chooseHost(c.state, anns, { now, unreachable: down }), { site: "two.example", role: "acting" }, "one.example is behind, so two.example covers");
  const fresh = [...anns, announceHost(c.state, { site: "one.example", role: "acting", at: new Date(now) }, c.r1Key)];
  assert.deepEqual(chooseHost(c.state, fresh, { now, unreachable: down }), { site: "one.example", role: "acting" });
  assert.equal(chooseHost(c.state, fresh, { now: now + 3600_000, unreachable: down }), null, "stale announcements don't count");
  // The acting replica keeps the community running: it can admit members and carry content.
  const dan = key();
  push(c, [{ type: "member.add", member: dan.kid, pub: dan.publicKey }], c.r1Key);
  // But it can't change who's in charge.
  assert.throws(() => replay([...c.chain, makeBlock(c.state, [{ type: "host.move", home: site("one.example", c.r1Key) }], c.r1Key)]), /Needs 1 authority|can't make/);
  const manual = community({ policy: { auto_failover: false } });
  assert.equal(chooseHost(manual.state, [], { now, unreachable: new Set(["home.example"]) }), null, "communities can require a person to decide");
});

test("a planned move keeps the community's id, history and members", () => {
  const c = community();
  const id = c.state.community;
  const newHome = key();
  push(c, [{ type: "host.move", home: site("new.example", newHome) }], c.alice);
  assert.equal(c.state.community, id);
  assert.equal(c.state.home.site, "new.example");
  assert.equal(c.state.epoch, 1);
});
