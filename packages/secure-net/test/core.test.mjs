import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { canonicalJson } from "../src/core/canonical.js";
import { generateSigningKey, sign, verify, cosign, checkSignature, keyId } from "../src/core/signed.js";
import { signatureBase, signRequest, verifyRequest, digestOf, isPrivate, normHost, freshEnough } from "../src/wire/federation.js";
import { negotiate, FEATURES } from "../src/wire/features.js";

test("canonical JSON: one encoding per value, and anything ambiguous is refused", () => {
  assert.equal(canonicalJson({ b: 1, a: [true, null, "x"], c: { z: 0, y: -0 } }), '{"a":[true,null,"x"],"b":1,"c":{"y":0,"z":0}}');
  assert.equal(canonicalJson({ a: undefined, b: 2 }), '{"b":2}');
  for (const bad of [1.5, NaN, Infinity, 2 ** 60, new Date(), () => 1, "\uD800"]) assert.throws(() => canonicalJson({ v: bad }), /NOT_CANONICAL|can't|broken|whole|plain/);
  const loop = {};
  loop.self = loop;
  assert.throws(() => canonicalJson(loop), /itself/);
});

test("signed records: bound to their kind, signer and exact contents", () => {
  const k = generateSigningKey();
  const r = sign("test.thing", { n: 1 }, k);
  const keyFor = (kid) => (kid === k.kid ? k.publicKey : null);
  assert.deepEqual(verify(r, keyFor), { n: 1 });
  assert.throws(() => verify({ ...r, body: { n: 2 } }, keyFor), /doesn't match/);
  assert.throws(() => verify({ ...r, kind: "test.other" }, keyFor), /doesn't match/);
  assert.throws(() => verify(r, () => null), /isn't trusted/);
  assert.throws(() => verify(r, keyFor, { kinds: ["test.else"] }), /Expected/);
  const k2 = generateSigningKey();
  assert.ok(checkSignature(r, cosign(r, k2), k2.publicKey));
  assert.ok(!checkSignature(r, cosign(r, k2), k.publicKey), "a signature names its key");
  assert.equal(keyId(k.publicKey), k.kid);
});

test("federation wire: signatures match Node's own Ed25519, so existing sites interoperate", () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64url");
  const fields = { method: "post", to: "b.example", path: "/cvp/v1/inbox", from: "a.example", date: new Date().toUTCString(), nonce: "n1", digest: digestOf("{}"), user: "u1" };
  const nodeSig = crypto.sign(null, Buffer.from(signatureBase(fields)), privateKey).toString("base64url");
  assert.ok(verifyRequest(fields, nodeSig, pub), "Secure Net accepts a Node-signed request");
  const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32).toString("base64url");
  const ours = signRequest(fields, seed);
  assert.ok(crypto.verify(null, Buffer.from(signatureBase(fields)), publicKey, Buffer.from(ours, "base64url")), "Node accepts a Secure Net-signed request");
  assert.ok(!verifyRequest({ ...fields, path: "/other" }, ours, pub));
  assert.equal(digestOf("{}"), `sha-256=${crypto.createHash("sha256").update("{}").digest("base64url")}`);
  assert.ok(freshEnough(fields.date) && !freshEnough("Mon, 01 Jan 2001 00:00:00 GMT"));
});

test("address rules: private networks are off limits, site names have one form", () => {
  for (const ip of ["10.0.0.1", "127.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.1.1", "100.64.0.1", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "[::1]", "0.0.0.0", "224.0.0.1"]) assert.ok(isPrivate(ip), ip);
  for (const ip of ["8.8.8.8", "1.1.1.1", "2606:4700::1111", "172.32.0.1"]) assert.ok(!isPrivate(ip), ip);
  assert.equal(normHost("HTTPS://Chat.Example.org/path"), "chat.example.org");
  assert.equal(normHost("bad host"), null);
});

test("feature negotiation: only what both speak, at the lower version", () => {
  assert.deepEqual(negotiate({ a: 2, b: 1 }, { a: 1, c: 3 }), { a: 1 });
  assert.ok(FEATURES["cvp.commons-ledger"] >= 1);
});
