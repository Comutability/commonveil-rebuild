// The client core (rust/commonveil-client) as WebAssembly gives the same answers as the
// JavaScript copy of Secure Net the app uses today (packages/secure-net), and each reads what
// the other writes. Stage 0 of the implementation plan moves the app onto the WebAssembly, so
// this is the check that the move changes no format.
//
// The WebAssembly is built in CI (the `wasm` job); without a build in wasm-pkg/nodejs these tests
// are skipped, unless WASM_REQUIRED is set, as CI sets it. To run them locally, build it as that job does.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { canonical } from "../packages/secure-net/src/crypto/canonical.js";
import { fromB64, toB64, utf8 } from "../packages/secure-net/src/crypto/encoding.js";
import { kemKeygen, kemOpen, kemPublicFromSecret, kemSeal } from "../packages/secure-net/src/crypto/kem.js";
import { linkCode, safetyFingerprint, safetyNumber } from "../packages/secure-net/src/crypto/identity.js";
import { exportPkcs8, exportRaw, generateEcdh, generateEcdsa, importEcdhPrivate, openSealed, sealTo, signBytes, verifyWithRaw } from "../packages/secure-net/src/crypto/primitives.js";
import { generateRecoveryPhrase, isValidPhrase } from "../packages/secure-net/src/crypto/recovery.js";
import { phraseFromPrivateKey, privateKeyFromPhrase } from "../packages/secure-net/src/crypto/owner.js";
import { generationCommit, ratchetTo, stepAt } from "../packages/secure-net/src/crypto/serverKeys.js";

const PKG = path.resolve(import.meta.dirname, "../wasm-pkg/nodejs/commonveil_client.js");
const built = fs.existsSync(PKG);
// CI sets WASM_REQUIRED, so a missing build fails there instead of skipping.
if (!built && process.env.WASM_REQUIRED) throw new Error(`The WebAssembly build is missing: ${PKG}`);
const wasm = built ? createRequire(import.meta.url)(PKG) : null;
const skip = built ? false : "the WebAssembly isn't built here (CI's wasm job builds it)";

/** One call into the WebAssembly: its answer, or it throws with Secure Net's error code. */
function call(op, request = {}) {
  const reply = JSON.parse(wasm.call(JSON.stringify({ op, ...request })));
  if (reply.error) throw Object.assign(new Error(reply.error.message), { code: reply.error.code });
  return reply.ok;
}

const bytes = (n, start = 1) => Uint8Array.from({ length: n }, (_, i) => (start + i * 7) % 256);

test("it says which Secure Net it carries", { skip }, () => {
  assert.equal(wasm.secureNetVersion(), "0.7.0");
  assert.equal(wasm.version(), JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, "../package.json"), "utf8")).version);
});

test("canonical text, the bytes every signature covers", { skip }, () => {
  for (const [context, fields] of [
    ["account-key/v1", ["u1", "1", "abc", "2026-11-19T12:00:00.000Z"]],
    ["device-cert/v2", ["ünïcödé", "", "a|b", "😀"]],
    ["test/v12", []],
  ]) {
    assert.equal(call("cv.canonical", { context, fields }), canonical(context, fields), `${context}`);
  }
  assert.throws(() => canonical("test/v1", ["two\nlines"]));
  assert.throws(() => call("cv.canonical", { context: "test/v1", fields: ["two\nlines"] }), { code: "BAD_FORMAT" });
});

test("safety numbers and link codes", { skip }, () => {
  const a = { user_id: "a".repeat(24), digest: "digest-of-a" };
  const b = { user_id: "b".repeat(24), digest: "digest-of-b" };
  assert.equal(call("cv.safetyFingerprint", { userId: a.user_id, digest: a.digest }), safetyFingerprint(a.user_id, a.digest));
  assert.equal(call("cv.safetyNumber", { a: b, b: a }), safetyNumber(b, a));
  const link = { userId: a.user_id, deviceId: "d".repeat(32), signPub: "c2lnbg==", boxPub: "Ym94", accountDigest: "digest-of-a" };
  assert.equal(call("cv.linkCode", link), linkCode(link));
  assert.equal(call("cv.linkCode", { ...link, kemPub: "a2Vt" }), linkCode({ ...link, kemPub: "a2Vt" }));
});

test("post-quantum keys: the same pair from a seed, and each opens what the other seals", { skip }, async () => {
  const seed = bytes(32);
  const js = kemKeygen(seed);
  assert.deepEqual(call("cv.kemKeygen", { seed: toB64(seed) }), js);
  assert.equal(call("cv.kemPublic", { priv: js.kem_priv }), kemPublicFromSecret(js.kem_priv));
  const plaintext = bytes(100, 3);
  const fromJs = await kemSeal(js.kem_pub, plaintext, "test/v1");
  assert.equal(call("cv.kemOpen", { priv: js.kem_priv, sealed: fromJs, context: "test/v1" }), toB64(plaintext));
  const fromRust = call("cv.kemSeal", { pub: js.kem_pub, plaintext: toB64(plaintext), context: "test/v1" });
  assert.deepEqual(await kemOpen(js.kem_priv, fromRust, "test/v1"), plaintext);
  await assert.rejects(kemOpen(js.kem_priv, fromRust, "other/v1"), "bound to its context");
});

test("P-256 signatures verify across the two", { skip }, async () => {
  const pair = await generateEcdsa(true);
  const pub = await exportRaw(pair.publicKey);
  const text = "commonveil/test/v1\n1\nhello";
  const jsSig = await signBytes(pair.privateKey, utf8(text)); // already base64
  assert.equal(call("cv.verifyText", { pub, signature: jsSig, text }), true);
  assert.equal(call("cv.verifyText", { pub, signature: jsSig, text: `${text}!` }), false);
  const rustSig = call("cv.signText", { priv: await exportPkcs8(pair.privateKey), text });
  assert.equal(await verifyWithRaw(pub, rustSig, text), true);
});

test("sealing to a P-256 key opens across the two", { skip }, async () => {
  const pair = await generateEcdh(true);
  const pub = await exportRaw(pair.publicKey);
  const pkcs8 = await exportPkcs8(pair.privateKey);
  const plaintext = bytes(64, 9);
  const fromJs = await sealTo(pub, plaintext, "test/v1");
  assert.equal(call("cv.openSealed", { priv: pkcs8, pub, sealed: fromJs, context: "test/v1" }), toB64(plaintext));
  const fromRust = call("cv.sealTo", { pub, plaintext: toB64(plaintext), context: "test/v1" });
  assert.deepEqual(await openSealed(await importEcdhPrivate(pkcs8), pub, fromRust, "test/v1"), plaintext);
});

test("recovery phrases and owner keys", { skip }, () => {
  const phrase = generateRecoveryPhrase();
  assert.equal(call("cv.isValidPhrase", { phrase }), isValidPhrase(phrase));
  assert.equal(call("cv.isValidPhrase", { phrase: `${phrase} extra` }), isValidPhrase(`${phrase} extra`));
  const key = privateKeyFromPhrase(phrase);
  assert.equal(call("cv.privateKeyFromPhrase", { phrase }), key);
  assert.equal(call("cv.phraseFromPrivateKey", { key }), phraseFromPrivateKey(key));
});

test("server chain keys step and ratchet alike", { skip }, () => {
  const chainId = `${"s".repeat(24)}.l`;
  const startedAt = "2026-11-19T12:00:00.000Z";
  const at = Date.parse(startedAt) + 5 * 3600_000 + 17;
  assert.equal(stepAt(chainId, startedAt, at), 5);
  assert.equal(call("cv.stepAt", { chainId, startedAt, atMs: at }), stepAt(chainId, startedAt, at));
  assert.equal(call("cv.stepAt", { chainId: `${"s".repeat(24)}.h`, startedAt, atMs: at }), 0, "history chains have only step 0");
  const key = bytes(32, 5);
  assert.equal(call("cv.ratchetTo", { key: toB64(key), chainId, generation: 2, fromStep: 0, toStep: 3 }), toB64(ratchetTo(key, chainId, 2, 0, 3)));
  assert.equal(call("cv.generationCommit", { chainId, generation: 2, key: toB64(key) }), generationCommit(chainId, 2, key));
  assert.deepEqual(fromB64(toB64(key)), key);
});
