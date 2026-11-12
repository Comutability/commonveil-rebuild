import test from "node:test";
import assert from "node:assert/strict";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { generateSigningKey, sign, verify, checkSignature, HYBRID_ALG } from "../src/core/signed.js";
import { genesis, replay, makeBlock } from "../src/commons/ledger.js";
import { relaySuite, relayContext, relayKeysOf, relayKeysAcceptable, SUITE } from "../src/wire/sealed.js";
import { signatureBase } from "../src/wire/federation.js";

test("quantum-resistant signing keys sign twice, and both signatures are required", () => {
  const k = generateSigningKey({ pq: true });
  const r = sign("test.thing", { n: 1 }, k);
  assert.equal(r.sig.alg, HYBRID_ALG);
  const keyFor = () => k.publicKey;
  assert.deepEqual(verify(r, keyFor), { n: 1 });
  // Strip or break either half: refused.
  const { pq: _pq, ...classicalOnly } = r.sig;
  assert.ok(!checkSignature(r, { ...classicalOnly, alg: "Ed25519" }, k.publicKey), "no downgrade to the classical half");
  assert.ok(!checkSignature(r, { ...r.sig, pq: sign("test.thing", { n: 2 }, k).sig.pq }, k.publicKey));
  assert.ok(!checkSignature(r, { ...r.sig, value: sign("test.thing", { n: 2 }, k).sig.value }, k.publicKey));
  assert.throws(() => verify({ ...r, body: { n: 2 } }, keyFor), /doesn't match/);
  // Classical keys still work, and can't pass for quantum-resistant ones.
  const c = generateSigningKey();
  assert.ok(checkSignature(sign("test.thing", {}, c), sign("test.thing", {}, c).sig, c.publicKey));
});

test("a community's ledger can run entirely on quantum-resistant keys", () => {
  const alice = generateSigningKey({ pq: true });
  const home = generateSigningKey({ pq: true });
  const g = genesis({ name: "PQ", keys: [{ kid: alice.kid, pub: alice.publicKey, caps: ["authority"] }], home: { site: "home.example", kid: home.kid, pub: home.publicKey } }, alice);
  let state = replay([g]);
  const b = makeBlock(state, [{ type: "note" }], alice);
  state = replay([g, b]);
  assert.equal(state.height, 1);
  const stripped = { ...b, sig: { kid: b.sig.kid, alg: "Ed25519", value: b.sig.value } };
  assert.throws(() => replay([g, stripped]), /signature/);
});

test("the sealed relay: only the receiving site can read a request, only as that request, and replies come back sealed", async () => {
  const suite = relaySuite({ ml_kem768, ml_dsa65 });
  const beta = await suite.generateKeys();
  const other = await suite.generateKeys();
  const ctx = relayContext({ from: "alpha.example", to: "beta.example", path: "/cvp/v1/act" });
  const body = JSON.stringify({ function: "messages", request: "{}" });
  const { sealed, replyKey } = await suite.seal(beta.kem.public, body, ctx);
  assert.ok(!sealed.includes("messages"), "nothing readable in transit");
  const opened = await suite.open(beta.kem.secret, sealed, ctx);
  assert.equal(opened.text, body);
  await assert.rejects(suite.open(other.kem.secret, sealed, ctx), /couldn't be opened/, "another site can't open it");
  await assert.rejects(suite.open(beta.kem.secret, sealed, relayContext({ from: "alpha.example", to: "beta.example", path: "/cvp/v1/inbox" })), /couldn't be opened/, "nor as a different request");
  const tampered = JSON.parse(sealed);
  tampered.k = JSON.parse((await suite.seal(beta.kem.public, body, ctx)).sealed).k;
  await assert.rejects(suite.open(beta.kem.secret, JSON.stringify(tampered), ctx), /couldn't be opened/, "the post-quantum half matters");
  const reply = await suite.sealReply(opened.replyKey, '{"ok":true}', ctx);
  assert.equal(await suite.openReply(replyKey, reply, ctx), '{"ok":true}');
  await assert.rejects(suite.openReply(replyKey, reply, "elsewhere"), /couldn't be opened/);
});

test("relay signatures and published keys", async () => {
  const suite = relaySuite({ ml_kem768, ml_dsa65 });
  const keys = await suite.generateKeys();
  const base = signatureBase({ method: "POST", to: "b.example", path: "/cvp/v1/act", from: "a.example", date: "d", nonce: "n", digest: "x", user: "" });
  const sig = suite.sign(keys.sig.secret, base);
  assert.ok(suite.verify(keys.sig.public, base, sig));
  assert.ok(!suite.verify(keys.sig.public, base + "x", sig));
  const doc = { pq: { suite: SUITE, kem: keys.kem.public, sig: keys.sig.public } };
  assert.deepEqual(relayKeysOf(doc), doc.pq);
  assert.equal(relayKeysOf({ pq: { suite: "other", kem: "x", sig: "y" } }), null);
  assert.equal(relayKeysOf({}), null);
  // A site may start sealing; it may never stop, or swap keys quietly.
  assert.ok(relayKeysAcceptable(null, doc.pq));
  assert.ok(relayKeysAcceptable(null, null));
  assert.ok(relayKeysAcceptable(doc.pq, { ...doc.pq }));
  assert.ok(!relayKeysAcceptable(doc.pq, null), "no going back to unsealed");
  assert.ok(!relayKeysAcceptable(doc.pq, { ...doc.pq, sig: (await suite.generateKeys()).sig.public }));
});
