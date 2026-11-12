// The end-to-end crypto Commonveil uses (src/crypto). Commonveil's own suite tests these in depth
// against its backend; these check they work on their own.
import test from "node:test";
import assert from "node:assert/strict";
import { kemKeygen, kemSeal, kemOpen, KemError } from "../src/crypto/kem.js";
import { utf8, fromUtf8 } from "../src/crypto/encoding.js";
import { generateRecoveryPhrase, deriveRecoveryKey } from "../src/crypto/recovery.js";
import { createKeyVersion } from "../src/crypto/keyring.js";
import { makeAccountStatement, verifyAccountChain } from "../src/crypto/identity.js";

test("post-quantum hybrid sealing: only the right key, only the right context", async () => {
  const a = kemKeygen();
  const b = kemKeygen();
  const sealed = await kemSeal(a.kem_pub, utf8("hello"), "ctx/one");
  assert.equal(fromUtf8(await kemOpen(a.kem_priv, sealed, "ctx/one")), "hello");
  await assert.rejects(kemOpen(b.kem_priv, sealed, "ctx/one"), KemError);
  await assert.rejects(kemOpen(a.kem_priv, sealed, "ctx/two"), KemError);
});

test("account key chains: a rotation chains to the key before it; edits are caught", async () => {
  const recovery = await deriveRecoveryKey(generateRecoveryPhrase());
  const v1 = await createKeyVersion(1);
  const v2 = await createKeyVersion(2);
  const s1 = await makeAccountStatement({ userId: "u1", keyVersion: v1, recoveryPub: recovery.publicKey, signer: v1 });
  const s2 = await makeAccountStatement({ userId: "u1", keyVersion: v2, recoveryPub: recovery.publicKey, signer: v1 });
  const chain = await verifyAccountChain("u1", [s2, s1]);
  assert.equal(chain.latest.version, 2);
  assert.equal(chain.rootVersion, 1);
  await assert.rejects(verifyAccountChain("u1", [s1, { ...s2, ecdh_pub: s1.ecdh_pub }]), /signature/);
  await assert.rejects(verifyAccountChain("u2", [s1]), /someone else/);
});
