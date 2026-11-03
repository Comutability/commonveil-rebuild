// Post-quantum protection: the hybrid KEM, version 2 key statements, post-quantum wraps,
// device keys, recovery backups, and accounts from before November 2026 upgrading.
import test from "node:test";
import assert from "node:assert/strict";

import { Member, signed, world, FakeWorld } from "./support/harness.mjs";
import { KemError, KEM_PUBLIC_BYTES, isKemSealed, kemKeygen, kemOpen, kemPublicFromSecret, kemSeal } from "../src/lib/crypto/kem.js";
import { fromB64, utf8, fromUtf8 } from "../src/lib/crypto/encoding.js";
import { createDeviceKeys, publicDevice, withDeviceKem } from "../src/lib/crypto/device.js";
import { createKeyVersion, newKeyring, sealKeyringForRecovery } from "../src/lib/crypto/keyring.js";
import { deriveRecoveryKey, generateRecoveryPhrase, recoveryAnchorMac } from "../src/lib/crypto/recovery.js";
import { compareWithPin, linkCode, makeAccountStatement, makeDeviceCert, pinFromChain, verifyAccountChain } from "../src/lib/crypto/identity.js";
import { encryptEnvelope } from "../src/lib/crypto/envelope.js";
import { statementText } from "../src/lib/crypto/canonical.js";
import { statementText as serverStatementText } from "../base44/shared/canonical.ts";
import {
  acceptKeyringEnvelope,
  chainIsPostQuantum,
  deviceIsCertified,
  prepareSetDeviceKem,
  recoverWithPhrase,
  recoveryIsPostQuantum,
  signedRequest,
  verifiedDeviceKem,
} from "../src/lib/secure/protocol.js";

const strip = (obj, ...fields) => {
  const out = { ...obj };
  for (const f of fields) delete out[f];
  return out;
};

/** An account set up the way it was before post-quantum keys: no KEM anywhere. */
async function legacyMember(w, name) {
  const m = new Member(w, name);
  await m.ok("profile", { action: "claim_username", username: name });
  m.device = strip(await createDeviceKeys(`${name} laptop`), "kem_pub", "kem_priv");
  const phrase = generateRecoveryPhrase();
  const recovery = await deriveRecoveryKey(phrase);
  const v1 = strip(await createKeyVersion(1), "kem_pub", "kem_priv");
  const keyring = newKeyring(m.id, v1);
  const statement = await makeAccountStatement({ userId: m.id, keyVersion: v1, recoveryPub: recovery.publicKey, signer: v1 });
  statement.recovery_mac = await recoveryAnchorMac(recovery.anchorKey, statement);
  const cert = await makeDeviceCert({ userId: m.id, device: m.device, keyVersion: v1 });
  const backup = await sealKeyringForRecovery(keyring, recovery.publicKey);
  const request = await signedRequest({
    userId: m.id, device: m.device, action: "init_account",
    payload: { device: publicDevice(m.device), statement, cert, recovery: { ...backup, key_sign_pub: v1.sign_pub } },
  });
  await m.ok("keys", request);
  m.keyring = keyring;
  m.phrase = phrase;
  return m;
}

test("hybrid sealing opens only with the right key, in the right context, untampered", async () => {
  const a = kemKeygen();
  const b = kemKeygen();
  assert.equal(fromB64(a.kem_pub).length, KEM_PUBLIC_BYTES);
  assert.equal(kemPublicFromSecret(a.kem_priv), a.kem_pub);
  const sealed = await kemSeal(a.kem_pub, utf8("hello"), "ctx/one");
  assert.ok(isKemSealed(sealed));
  assert.equal(fromUtf8(await kemOpen(a.kem_priv, sealed, "ctx/one")), "hello");
  await assert.rejects(kemOpen(b.kem_priv, sealed, "ctx/one"), KemError);
  await assert.rejects(kemOpen(a.kem_priv, sealed, "ctx/two"), KemError);
  const flipped = fromB64(sealed.kct);
  flipped[10] ^= 1;
  await assert.rejects(kemOpen(a.kem_priv, { ...sealed, kct: Buffer.from(flipped).toString("base64") }, "ctx/one"), KemError);
  // Same seed, same keys: how the recovery phrase's post-quantum key is made.
  const seed = new Uint8Array(32).fill(9);
  assert.equal(kemKeygen(seed).kem_pub, kemKeygen(seed).kem_pub);
});

test("new accounts publish post-quantum keys, and taking one out or swapping it breaks the signature", async () => {
  const { members: [alice] } = await world("alice");
  const { statements } = await alice.status();
  assert.ok(statements[0].kem_pub && statements[0].recovery_kem_pub, "version 1 carries both post-quantum keys");
  const chain = await verifyAccountChain(alice.id, statements);
  assert.ok(chainIsPostQuantum(chain) && recoveryIsPostQuantum(chain));
  assert.equal(statementText(statements[0]), serverStatementText(statements[0]), "client and server sign the same text");
  assert.ok(statementText(statements[0]).startsWith("commonveil/account-key/v2\n"));

  const stripped = strip(statements[0], "kem_pub", "recovery_kem_pub");
  await assert.rejects(verifyAccountChain(alice.id, [stripped]), /signature/);
  await assert.rejects(verifyAccountChain(alice.id, [{ ...statements[0], kem_pub: kemKeygen().kem_pub }]), /signature/);
  await assert.rejects(verifyAccountChain(alice.id, [{ ...statements[0], recovery_kem_pub: kemKeygen().kem_pub }]), /signature/);
  await assert.rejects(verifyAccountChain(alice.id, [{ ...statements[0], kem_pub: "AAAA" }]), /malformed/);

  // Every device this account has is certified with its post-quantum key.
  const [device] = (await alice.status()).devices;
  assert.equal(device.cert_has_kem, true);
  assert.ok(await deviceIsCertified(alice.id, device, chain));
  assert.equal(await verifiedDeviceKem(alice.id, device, chain), alice.device.kem_pub);
  // A certificate's post-quantum key must be the one the device registered.
  assert.equal(await deviceIsCertified(alice.id, { ...device, kem_pub: kemKeygen().kem_pub }, chain), false);
});

test("messages to members with post-quantum keys are wrapped post-quantum, and the server insists on it", async () => {
  const { w, members: [alice, bob] } = await world("alice", "bobby");
  const dm = await alice.dm(bob);
  assert.equal((await alice.send(dm, "hi bob")).status, 200);
  const [row] = w.rows("Message");
  const env = JSON.parse(row.envelope);
  assert.equal(env.v, 3);
  assert.ok(env.wraps.every((x) => typeof x.kct === "string" && x.epk === undefined), "every wrap is post-quantum");
  const [read] = await bob.read(dm);
  assert.equal(read.status, "ok");
  assert.equal(read.text, "hi bob");

  // A classical wrap for someone whose key is post-quantum is refused.
  const { chains } = await alice.chainsFor(dm);
  const recipients = dm.member_ids.map((u) => ({ user_id: u, key_version: chains.get(u).latest.version, ecdh_pub: chains.get(u).latest.ecdh_pub }));
  const { buildMessage } = await import("../src/lib/secure/protocol.js");
  const body = await buildMessage({ userId: alice.id, device: alice.device, conversation: dm, chains, text: "x", keyring: alice.keyring });
  const classical = JSON.stringify(await encryptEnvelope({
    scope: { kind: "message", conversation_id: dm.id, item_id: body.msg_id, sender_id: alice.id, device_id: alice.device.device_id },
    recipients,
    payload: { type: "text", text: "downgraded" },
  }));
  const { signItem } = await import("../src/lib/crypto/identity.js");
  const signature = await signItem({ device: alice.device, kind: "message", conversationId: dm.id, itemId: body.msg_id, senderId: alice.id, deviceId: alice.device.device_id, envelopeJson: classical, sentAt: body.sent_at });
  const res = await alice.call("messages", { ...body, envelope: classical, signature });
  assert.equal(res.body.code, "STALE_KEYS");
});

test("an account from before post-quantum keys upgrades with one rotation and keeps reading what came before", async () => {
  const w = new FakeWorld();
  const alice = await legacyMember(w, "alice");
  const bob = await new Member(w, "bobby").setup();
  assert.equal(chainIsPostQuantum(await alice.myChain()), false);

  const dm = await alice.dm(bob);
  assert.equal((await bob.send(dm, "before the upgrade")).status, 200);
  const env = JSON.parse(w.rows("Message")[0].envelope);
  assert.ok(env.wraps.find((x) => x.u === alice.id).epk, "alice's copy is classical: her key has no post-quantum half yet");
  assert.ok(env.wraps.find((x) => x.u === bob.id).kct, "bob's copy is post-quantum");
  const bobPin = pinFromChain((await bob.keysFor([alice.id])).chains.get(alice.id));

  // The browser gives itself a post-quantum key, signs it, then rotates the account's keys.
  alice.device = withDeviceKem(alice.device);
  await alice.ok("keys", await prepareSetDeviceKem({ userId: alice.id, device: alice.device }));
  await alice.rotate();
  const chain = await alice.myChain();
  assert.ok(chainIsPostQuantum(chain), "the new key version has a post-quantum key");
  assert.equal(recoveryIsPostQuantum(chain), false, "the recovery key stays classical until the phrase is changed");
  assert.equal((await alice.status()).devices[0].cert_has_kem, true, "the rotation certified the device's post-quantum key");

  // Bob's pin moves on quietly: it's an ordinary rotation, signed by the key before it.
  const { chains } = await bob.keysFor([alice.id]);
  assert.equal(compareWithPin(chains.get(alice.id), bobPin), "rotated");

  assert.equal((await bob.send(dm, "after the upgrade")).status, 200);
  const latest = JSON.parse(w.rows("Message")[1].envelope);
  assert.ok(latest.wraps.every((x) => x.kct), "now both copies are post-quantum");
  const texts = (await alice.read(dm)).map((r) => [r.status, r.text]);
  assert.deepEqual(texts, [["ok", "before the upgrade"], ["ok", "after the upgrade"]]);

  // A new phrase brings a post-quantum recovery key, and the backup is sealed to it.
  await alice.rotate({ newPhrase: true });
  assert.ok(recoveryIsPostQuantum(await alice.myChain()));
  const backup = w.rows("KeyEnvelope").find((e) => e.kind === "recovery");
  assert.ok(isKemSealed(JSON.parse(backup.sealed)));
});

test("rotations can't drop the post-quantum key, or change the recovery key without a new phrase", async () => {
  const { members: [alice] } = await world("alice");
  const { prepareRotation } = await import("../src/lib/secure/protocol.js");
  const status = await alice.status();
  const chain = await alice.myChain();
  // A rotation without a post-quantum key.
  const keyring = { ...alice.keyring, versions: alice.keyring.versions.map((v) => ({ ...v })) };
  const rotation = await prepareRotation({ userId: alice.id, device: alice.device, keyring, chain, activeDevices: status.devices.filter((d) => d.status === "active") });
  const payload = JSON.parse(rotation.request.payload);
  const prev = alice.keyring.versions[0];
  const plain = strip(await createKeyVersion(2), "kem_pub", "kem_priv");
  payload.statement = await makeAccountStatement({ userId: alice.id, keyVersion: plain, recoveryPub: chain.latest.recovery_pub, signer: prev });
  const noKem = await signedRequest({ userId: alice.id, device: alice.device, action: "rotate_keys", payload });
  assert.equal((await alice.call("keys", noKem)).body.code, "BAD_STATEMENT");
  // A rotation that swaps the recovery key's post-quantum half without a new phrase.
  const next = await createKeyVersion(2);
  payload.statement = await makeAccountStatement({ userId: alice.id, keyVersion: next, recoveryPub: chain.latest.recovery_pub, recoveryKemPub: kemKeygen().kem_pub, signer: prev });
  const swapped = await signedRequest({ userId: alice.id, device: alice.device, action: "rotate_keys", payload });
  assert.equal((await alice.call("keys", swapped)).body.code, "BAD_STATEMENT");
});

test("a device's own post-quantum key: signed by it, certified at the next rotation, and never taken on the server's word", async () => {
  const w = new FakeWorld();
  const alice = await legacyMember(w, "alice");
  // A second legacy browser, linked the old way.
  const phone = strip(await createDeviceKeys("phone"), "kem_pub", "kem_priv");
  const linked = await alice.linkDevice("phone", phone);
  assert.ok(!isKemSealed(linked.sealed), "no post-quantum key yet, so the keyring went the classical way");

  // The phone adds a post-quantum key. A forged signature is refused.
  const phoneKem = withDeviceKem(phone);
  const forged = await signedRequest({ userId: alice.id, device: phoneKem, action: "set_device_kem", payload: { kem_pub: phoneKem.kem_pub, kem_sig: "A".repeat(86) + "==" } });
  assert.equal((await alice.call("keys", forged)).body.code, "SIGNATURE_INVALID");
  await alice.ok("keys", await prepareSetDeviceKem({ userId: alice.id, device: phoneKem }));

  // If the server lists a different post-quantum key for the phone, the laptop won't use it.
  const chain = await alice.myChain();
  const row = (await alice.status()).devices.find((d) => d.device_id === phone.device_id);
  assert.equal(await verifiedDeviceKem(alice.id, row, chain), phoneKem.kem_pub);
  assert.equal(await verifiedDeviceKem(alice.id, { ...row, kem_pub: kemKeygen().kem_pub }, chain), null);

  // The laptop rotates (upgrading itself too); the phone's key is certified and its keyring sealed post-quantum.
  alice.device = withDeviceKem(alice.device);
  await alice.ok("keys", await prepareSetDeviceKem({ userId: alice.id, device: alice.device }));
  await alice.rotate();
  const after = (await alice.status()).devices.find((d) => d.device_id === phone.device_id);
  assert.equal(after.cert_has_kem, true);
  const sync = await alice.ok("keys", { action: "device_sync", device_id: phone.device_id });
  assert.ok(isKemSealed(sync.envelope.sealed));
  const { keyring } = await acceptKeyringEnvelope({ userId: alice.id, device: phoneKem, envelope: sync.envelope, statements: (await alice.status()).statements, current: linked.keyring });
  assert.equal(keyring.versions.length, 2);
  assert.ok(keyring.versions[1].kem_pub);
});

test("new devices link post-quantum, and the link code covers their post-quantum key", async () => {
  const { members: [alice] } = await world("alice");
  const linked = await alice.linkDevice("tablet");
  assert.ok(isKemSealed(linked.sealed), "the keyring went to the tablet post-quantum");
  const base = { userId: alice.id, deviceId: "d", signPub: "s", boxPub: "b", accountDigest: "h" };
  assert.notEqual(linkCode({ ...base, kemPub: kemKeygen().kem_pub }), linkCode({ ...base, kemPub: kemKeygen().kem_pub }));
  assert.notEqual(linkCode({ ...base, kemPub: kemKeygen().kem_pub }), linkCode(base));
});

test("recovery: a post-quantum backup opens with the phrase, and an older classical one still does", async () => {
  const w = new FakeWorld();
  const modern = await new Member(w, "alice").setup();
  const legacy = await legacyMember(w, "bobby");
  for (const m of [modern, legacy]) {
    const recoveryResponse = await m.ok("keys", { action: "get_recovery" });
    assert.equal(isKemSealed(recoveryResponse.recovery.sealed), m === modern);
    const device = await createDeviceKeys("new browser");
    const { keyring, request } = await recoverWithPhrase({ userId: m.id, device, phrase: m.phrase, recoveryResponse });
    await m.ok("keys", request);
    assert.equal(keyring.versions.length, 1);
    const status = await m.status();
    assert.equal(status.devices.find((d) => d.device_id === device.device_id).cert_has_kem, true, "the recovered browser is certified with its post-quantum key");
  }
  // The wrong phrase doesn't open a post-quantum backup either.
  const recoveryResponse = await modern.ok("keys", { action: "get_recovery" });
  await assert.rejects(recoverWithPhrase({ userId: modern.id, device: await createDeviceKeys("x"), phrase: generateRecoveryPhrase(), recoveryResponse }), /isn't the current recovery phrase/);
});

test("the server refuses malformed post-quantum keys", async () => {
  const { members: [alice] } = await world("alice");
  const bad = await signedRequest({ userId: alice.id, device: alice.device, action: "set_device_kem", payload: { kem_pub: "AAAA", kem_sig: "x" } });
  assert.equal((await alice.call("keys", bad)).body.code, "BAD_KEY");
  const already = await prepareSetDeviceKem({ userId: alice.id, device: { ...alice.device, kem_pub: kemKeygen().kem_pub } });
  assert.equal((await alice.call("keys", already)).body.code, "ALREADY_SET");
  const fresh = new Member(alice.world, "carol");
  await fresh.ok("profile", { action: "claim_username", username: "carol" });
  const device = await createDeviceKeys("c");
  const { prepareNewAccount } = await import("../src/lib/secure/protocol.js");
  const prepared = await prepareNewAccount({ userId: fresh.id, device });
  const payload = JSON.parse(prepared.request.payload);
  payload.statement.kem_pub = Buffer.from(new Uint8Array(KEM_PUBLIC_BYTES)).toString("base64");
  const req = await signedRequest({ userId: fresh.id, device, action: "init_account", payload });
  assert.equal((await fresh.call("keys", req)).body.code, "BAD_KEY");
  void signed;
});
