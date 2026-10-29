// Crypto protocol tests. Real WebCrypto and real keys throughout; nothing is mocked.
// Run: node --test tests/
import test from "node:test";
import assert from "node:assert/strict";

import * as clientCanon from "../src/lib/crypto/canonical.js";
import * as serverCanon from "../base44/shared/canonical.ts";
import { fromB64, randomId, toB64 } from "../src/lib/crypto/encoding.js";
import { generateEcdh, exportRaw, sealTo, openSealed } from "../src/lib/crypto/primitives.js";
import {
  createKeyVersion,
  newKeyring,
  withVersion,
  latestKey,
  sealKeyringToDevice,
  openKeyringFromDevice,
  sealKeyringForRecovery,
  parseKeyring,
  serializeKeyring,
  assertKeyringConsistent,
} from "../src/lib/crypto/keyring.js";
import {
  generateRecoveryPhrase,
  isValidPhrase,
  deriveRecoveryKey,
  openKeyringWithPhrase,
  normalizePhrase,
} from "../src/lib/crypto/recovery.js";
import { encryptEnvelope, decryptEnvelope } from "../src/lib/crypto/envelope.js";
import {
  makeAccountStatement,
  verifyAccountChain,
  compareWithPin,
  pinFromChain,
  assertKeyringMatchesChain,
  makeDeviceCert,
  verifyDeviceCert,
  makeDeviceProof,
  signItem,
  verifyItem,
  safetyNumber,
  linkCode,
} from "../src/lib/crypto/identity.js";
import { createDeviceKeys } from "../src/lib/crypto/device.js";

const uid = () => Array.from(crypto.getRandomValues(new Uint8Array(12)), (b) => b.toString(16).padStart(2, "0")).join("");

async function makeAccount() {
  const userId = uid();
  const v1 = await createKeyVersion(1);
  const phrase = generateRecoveryPhrase();
  const recovery = await deriveRecoveryKey(phrase);
  const statement = await makeAccountStatement({ userId, keyVersion: v1, recoveryPub: recovery.publicKey, signer: v1 });
  return { userId, keyring: newKeyring(userId, v1), phrase, recoveryPub: recovery.publicKey, statements: [statement] };
}

async function rotate(account) {
  const prev = latestKey(account.keyring);
  const next = await createKeyVersion(prev.version + 1);
  const statement = await makeAccountStatement({ userId: account.userId, keyVersion: next, recoveryPub: account.recoveryPub, signer: prev });
  account.keyring = withVersion(account.keyring, next);
  account.statements.push(statement);
  return account;
}

const recipientOf = (account) => {
  const k = latestKey(account.keyring);
  return { user_id: account.userId, key_version: k.version, ecdh_pub: k.ecdh_pub };
};

test("client and server canonical text are byte-identical", () => {
  const samples = {
    accountKeyFields: { user_id: "u1", version: 3, ecdh_pub: "AAA=", sign_pub: "BBB=", recovery_pub: "CCC=", signed_by_version: 2, issued_at: "2026-10-29T10:00:00.000Z" },
    deviceCertFields: { user_id: "u1", device_id: "d1", sign_pub: "S=", box_pub: "B=", key_version: 1, issued_at: "t" },
    deviceProofFields: { user_id: "u1", device_id: "d1", action: "approve_device", payload_hash: "h=", issued_at: "t", nonce: "n" },
    itemFields: { kind: "message", conversation_id: "c", item_id: "i", sender_id: "s", device_id: "d", envelope_hash: "e", sent_at: "t" },
  };
  for (const [fn, input] of Object.entries(samples)) {
    for (const ctx of Object.values(clientCanon.CONTEXTS)) {
      assert.equal(
        clientCanon.canonical(ctx, clientCanon[fn](input)),
        serverCanon.canonical(ctx, serverCanon[fn](input)),
        `${fn} in ${ctx}`,
      );
    }
  }
  assert.deepEqual(clientCanon.CONTEXTS, serverCanon.CONTEXTS);
});

test("canonical text refuses line breaks and non-strings", () => {
  assert.throws(() => clientCanon.canonical("item/v1", ["a\nb"]));
  assert.throws(() => clientCanon.canonical("item/v1", ["a\rb"]));
  assert.throws(() => clientCanon.canonical("item/v1", [1]));
  assert.throws(() => clientCanon.canonical("Bad Context", ["a"]));
  assert.throws(() => serverCanon.canonical("item/v1", ["a\nb"]));
});

test("recovery phrase is 24 standard words and derives the same key every time", async () => {
  const phrase = generateRecoveryPhrase();
  assert.equal(phrase.split(" ").length, 24);
  assert.ok(isValidPhrase(phrase));
  const a = await deriveRecoveryKey(phrase);
  const b = await deriveRecoveryKey(`  ${phrase.toUpperCase().replace(/ /g, "   ")}\n`);
  assert.equal(a.publicKey, b.publicKey, "normalisation must not change the key");
  assert.equal(fromB64(a.publicKey).length, 65);
  // BIP-39 vector: 256 bits of zero entropy is 23 x "abandon" + "art". 24 x "abandon" fails the checksum.
  assert.ok(isValidPhrase(`${"abandon ".repeat(23)}art`));
  assert.equal(isValidPhrase("abandon ".repeat(24)), false);
  assert.equal(isValidPhrase("abandon ".repeat(11) + "about"), false, "12-word phrases are not accepted");
  await assert.rejects(deriveRecoveryKey("not a real phrase"), { code: "INVALID_PHRASE" });
  assert.equal(normalizePhrase("Abandon, ABOUT!"), "abandon about");
});

test("keyring sealed for recovery opens only with the right phrase, account and version", async () => {
  const acct = await makeAccount();
  const { keyring_version, sealed } = await sealKeyringForRecovery(acct.keyring, acct.recoveryPub);
  const opened = await openKeyringWithPhrase({ phrase: acct.phrase, userId: acct.userId, keyringVersion: keyring_version, recoveryPub: acct.recoveryPub, sealed });
  assert.equal(serializeKeyring(opened), serializeKeyring(acct.keyring));

  const other = generateRecoveryPhrase();
  await assert.rejects(
    openKeyringWithPhrase({ phrase: other, userId: acct.userId, keyringVersion: keyring_version, recoveryPub: acct.recoveryPub, sealed }),
    { code: "WRONG_PHRASE" },
  );
  await assert.rejects(
    openKeyringWithPhrase({ phrase: acct.phrase, userId: uid(), keyringVersion: keyring_version, recoveryPub: acct.recoveryPub, sealed }),
    { code: "BACKUP_UNREADABLE" },
    "an envelope replayed into another account must not open",
  );
  await assert.rejects(
    openKeyringWithPhrase({ phrase: acct.phrase, userId: acct.userId, keyringVersion: keyring_version + 1, recoveryPub: acct.recoveryPub, sealed }),
    { code: "BACKUP_UNREADABLE" },
  );
  const tampered = { ...sealed, ct: toB64(fromB64(sealed.ct).map((b, i) => (i === 3 ? b ^ 1 : b))) };
  await assert.rejects(
    openKeyringWithPhrase({ phrase: acct.phrase, userId: acct.userId, keyringVersion: keyring_version, recoveryPub: acct.recoveryPub, sealed: tampered }),
    { code: "BACKUP_UNREADABLE" },
  );
});

test("WebCrypto sealing and noble opening agree (cross-library ECDH check)", async () => {
  const phrase = generateRecoveryPhrase();
  const { publicKey } = await deriveRecoveryKey(phrase);
  const acct = await makeAccount();
  const sealed = await sealKeyringForRecovery(acct.keyring, publicKey);
  const opened = await openKeyringWithPhrase({ phrase, userId: acct.userId, keyringVersion: sealed.keyring_version, recoveryPub: publicKey, sealed: sealed.sealed });
  assert.equal(opened.user_id, acct.userId);
});

test("account key chain: genesis, rotation and reset are told apart", async () => {
  const acct = await makeAccount();
  let chain = await verifyAccountChain(acct.userId, acct.statements);
  assert.equal(chain.latest.version, 1);
  assert.equal(chain.rootVersion, 1);
  const pin = pinFromChain(chain, true);

  await rotate(acct);
  await rotate(acct);
  chain = await verifyAccountChain(acct.userId, acct.statements);
  assert.equal(chain.latest.version, 3);
  assert.equal(chain.rootVersion, 1);
  assert.equal(compareWithPin(chain, pin), "rotated", "chained rotation keeps continuity");
  assertKeyringMatchesChain(acct.keyring, chain);

  // Reset: version 4 is self-signed, so continuity from the old pin breaks.
  const v4 = await createKeyVersion(4);
  acct.statements.push(await makeAccountStatement({ userId: acct.userId, keyVersion: v4, recoveryPub: acct.recoveryPub, signer: v4 }));
  chain = await verifyAccountChain(acct.userId, acct.statements);
  assert.equal(chain.rootVersion, 4);
  assert.equal(compareWithPin(chain, pin), "changed");
  assert.equal(compareWithPin(chain, pinFromChain(chain)), "same");
});

test("a substituted or forged key statement is rejected", async () => {
  const acct = await makeAccount();
  await rotate(acct);
  const attacker = await createKeyVersion(2);
  // Forged rotation: claims to be signed by v1 but is signed by the attacker.
  const forged = await makeAccountStatement({ userId: acct.userId, keyVersion: attacker, recoveryPub: acct.recoveryPub, signer: attacker });
  forged.signed_by_version = 1;
  await assert.rejects(verifyAccountChain(acct.userId, [acct.statements[0], forged]), { code: "BAD_SIGNATURE" });
  // Edited field after signing.
  const edited = { ...acct.statements[1], ecdh_pub: attacker.ecdh_pub };
  await assert.rejects(verifyAccountChain(acct.userId, [acct.statements[0], edited]), { code: "BAD_SIGNATURE" });
  // Gap in versions.
  await assert.rejects(verifyAccountChain(acct.userId, [acct.statements[1]]), { code: "VERSION_GAP" });
  // Someone else's statement.
  await assert.rejects(verifyAccountChain(uid(), acct.statements), { code: "WRONG_USER" });

  // Server swaps in a whole fake history that copies the pinned key at v1 but extends it.
  const pin = pinFromChain(await verifyAccountChain(acct.userId, acct.statements.slice(0, 1)));
  const fakeV1 = await createKeyVersion(1);
  const fakeV2 = await createKeyVersion(2);
  const fakeChain = await verifyAccountChain(acct.userId, [
    await makeAccountStatement({ userId: acct.userId, keyVersion: fakeV1, recoveryPub: acct.recoveryPub, signer: fakeV1 }),
    await makeAccountStatement({ userId: acct.userId, keyVersion: fakeV2, recoveryPub: acct.recoveryPub, signer: fakeV1 }),
  ]);
  assert.equal(compareWithPin(fakeChain, pin), "changed");
});

test("envelopes decrypt for every recipient and nobody else", async () => {
  const [alice, bob, carol, mallory] = await Promise.all([makeAccount(), makeAccount(), makeAccount(), makeAccount()]);
  const scope = { kind: "message", conversation_id: uid(), item_id: randomId(), sender_id: alice.userId, device_id: randomId() };
  const payload = { type: "text", text: "Meet at the library, 4pm. 🦉" };
  const envelope = await encryptEnvelope({ scope, recipients: [alice, bob, carol].map(recipientOf), payload });
  const json = JSON.stringify(envelope);
  for (const acct of [alice, bob, carol]) {
    assert.deepEqual(await decryptEnvelope({ scope, envelope: json, userId: acct.userId, keyring: acct.keyring }), payload);
  }
  await assert.rejects(decryptEnvelope({ scope, envelope: json, userId: mallory.userId, keyring: mallory.keyring }), { code: "NOT_ADDRESSED" });
  // Mallory relabels Bob's wrap as hers: still can't open it with her keys.
  const relabelled = { ...envelope, wraps: envelope.wraps.map((w) => (w.u === bob.userId ? { ...w, u: mallory.userId } : w)) };
  await assert.rejects(decryptEnvelope({ scope, envelope: relabelled, userId: mallory.userId, keyring: mallory.keyring }), { code: "UNWRAP_FAILED" });
});

test("envelopes are bound to their conversation, item, sender and device", async () => {
  const [alice, bob] = await Promise.all([makeAccount(), makeAccount()]);
  const scope = { kind: "message", conversation_id: uid(), item_id: randomId(), sender_id: alice.userId, device_id: randomId() };
  const envelope = await encryptEnvelope({ scope, recipients: [recipientOf(alice), recipientOf(bob)], payload: { type: "text", text: "hi" } });
  const variants = [
    { ...scope, conversation_id: uid() },
    { ...scope, item_id: randomId() },
    { ...scope, sender_id: bob.userId },
    { ...scope, device_id: randomId() },
    { ...scope, kind: "title" },
  ];
  for (const wrong of variants) {
    await assert.rejects(decryptEnvelope({ scope: wrong, envelope, userId: bob.userId, keyring: bob.keyring }));
  }
  const flipped = { ...envelope, ct: toB64(fromB64(envelope.ct).map((b, i) => (i === 0 ? b ^ 0x80 : b))) };
  await assert.rejects(decryptEnvelope({ scope, envelope: flipped, userId: bob.userId, keyring: bob.keyring }), { code: "DECRYPT_FAILED" });
});

test("messages sent to an older key version still decrypt after rotation", async () => {
  const [alice, bob] = await Promise.all([makeAccount(), makeAccount()]);
  const scope = { kind: "message", conversation_id: uid(), item_id: randomId(), sender_id: alice.userId, device_id: randomId() };
  const envelope = await encryptEnvelope({ scope, recipients: [recipientOf(alice), recipientOf(bob)], payload: { type: "text", text: "before" } });
  await rotate(bob);
  assert.equal((await decryptEnvelope({ scope, envelope, userId: bob.userId, keyring: bob.keyring })).text, "before");
  // A keyring started fresh after a reset cannot read pre-reset messages.
  const reset = newKeyring(bob.userId, await createKeyVersion(5));
  await assert.rejects(decryptEnvelope({ scope, envelope, userId: bob.userId, keyring: reset }), { code: "KEY_VERSION_MISSING" });
});

test("device certificates, request proofs and item signatures verify and resist tampering", async () => {
  const acct = await makeAccount();
  const device = await createDeviceKeys("Test laptop");
  const cert = await makeDeviceCert({ userId: acct.userId, device, keyVersion: latestKey(acct.keyring) });
  let chain = await verifyAccountChain(acct.userId, acct.statements);
  assert.ok(await verifyDeviceCert(cert, chain));
  assert.equal(await verifyDeviceCert({ ...cert, box_pub: (await createDeviceKeys()).box_pub }, chain), false, "box key is covered");

  await rotate(acct);
  chain = await verifyAccountChain(acct.userId, acct.statements);
  assert.ok(await verifyDeviceCert(cert, chain), "old certs stay verifiable through the chain");

  const proof = await makeDeviceProof({ userId: acct.userId, device, action: "revoke_device", payloadJson: '{"target":"x"}' });
  assert.equal(proof.device_id, device.device_id);
  assert.equal(fromB64(proof.signature).length, 64);

  const item = { kind: "message", conversationId: uid(), itemId: randomId(), senderId: acct.userId, deviceId: device.device_id, envelopeJson: '{"v":1}', sentAt: new Date().toISOString() };
  const signature = await signItem({ device, ...item });
  assert.ok(await verifyItem({ signPub: device.sign_pub, signature, ...item }));
  assert.equal(await verifyItem({ signPub: device.sign_pub, signature, ...item, envelopeJson: '{"v":2}' }), false);
  assert.equal(await verifyItem({ signPub: device.sign_pub, signature, ...item, conversationId: uid() }), false);
  assert.equal(await verifyItem({ signPub: (await createDeviceKeys()).sign_pub, signature, ...item }), false);
});

test("device keys are not exportable", async () => {
  const device = await createDeviceKeys();
  assert.equal(device.sign_priv.extractable, false);
  assert.equal(device.box_priv.extractable, false);
  await assert.rejects(crypto.subtle.exportKey("pkcs8", device.sign_priv));
});

test("keyring transfer to a new device opens only on that device", async () => {
  const acct = await makeAccount();
  const newDevice = await createDeviceKeys();
  const otherDevice = await createDeviceKeys();
  const { keyring_version, sealed } = await sealKeyringToDevice(acct.keyring, newDevice);
  const opened = await openKeyringFromDevice({
    boxPriv: newDevice.box_priv, boxPub: newDevice.box_pub, userId: acct.userId, deviceId: newDevice.device_id, keyringVersion: keyring_version, sealed,
  });
  assert.equal(serializeKeyring(opened), serializeKeyring(acct.keyring));
  await assert.rejects(openKeyringFromDevice({
    boxPriv: otherDevice.box_priv, boxPub: otherDevice.box_pub, userId: acct.userId, deviceId: otherDevice.device_id, keyringVersion: keyring_version, sealed,
  }));
  await assert.rejects(openKeyringFromDevice({
    boxPriv: newDevice.box_priv, boxPub: newDevice.box_pub, userId: acct.userId, deviceId: otherDevice.device_id, keyringVersion: keyring_version, sealed,
  }), "sealed value is bound to the device id");
});

test("keyring consistency check catches a private key paired with the wrong public key", async () => {
  const acct = await makeAccount();
  await assertKeyringConsistent(acct.keyring);
  const other = await createKeyVersion(1);
  const broken = parseKeyring(JSON.stringify({ ...acct.keyring, versions: [{ ...acct.keyring.versions[0], ecdh_pub: other.ecdh_pub }] }), acct.userId);
  await assert.rejects(assertKeyringConsistent(broken));
  assert.throws(() => parseKeyring(JSON.stringify({ ...acct.keyring, user_id: uid() }), acct.userId));
});

test("safety numbers match on both sides and change with the key", async () => {
  const [a, b] = await Promise.all([makeAccount(), makeAccount()]);
  const ka = { user_id: a.userId, sign_pub: latestKey(a.keyring).sign_pub };
  const kb = { user_id: b.userId, sign_pub: latestKey(b.keyring).sign_pub };
  const n1 = safetyNumber(ka, kb);
  assert.equal(n1, safetyNumber(kb, ka));
  assert.match(n1, /^\d{60}$/);
  await rotate(b);
  assert.notEqual(n1, safetyNumber(ka, { user_id: b.userId, sign_pub: latestKey(b.keyring).sign_pub }));
});

test("link codes are 20 digits and depend on every device key", async () => {
  const d = await createDeviceKeys();
  const base = { userId: uid(), deviceId: d.device_id, signPub: d.sign_pub, boxPub: d.box_pub };
  const code = linkCode(base);
  assert.match(code, /^\d{20}$/);
  assert.equal(code, linkCode(base));
  const other = await createDeviceKeys();
  assert.notEqual(code, linkCode({ ...base, boxPub: other.box_pub }));
  assert.notEqual(code, linkCode({ ...base, signPub: other.sign_pub }));
});

test("generic sealing round trip and context binding", async () => {
  const kp = await generateEcdh(false);
  const pub = await exportRaw(kp.publicKey);
  const sealed = await sealTo(pub, new TextEncoder().encode("secret"), "ctx/a");
  assert.equal(new TextDecoder().decode(await openSealed(kp.privateKey, pub, sealed, "ctx/a")), "secret");
  await assert.rejects(openSealed(kp.privateKey, pub, sealed, "ctx/b"));
});
