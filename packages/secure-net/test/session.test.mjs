import test from "node:test";
import assert from "node:assert/strict";
import {
  createAccount, createDevice, devicePublic, signDeviceList, verifyDeviceList, approveLink, removeDevice,
  linkCode, safetyNumber, createPrekeys, takeBundle, initiate, respond, encrypt, decrypt, isInitial,
  initialSender, planFanOut, encryptToDevices, createSenderKey, distribution, acceptDistribution,
  groupEncrypt, groupDecrypt, sealHistory, openHistory, SessionError,
} from "../src/session/index.js";

const text = (b) => new TextDecoder().decode(b);
const code = (fn) => fn.then(() => null, (e) => e.code);

/** A person with one or more devices, each with prekeys published to their "site". */
function person(nDevices = 1) {
  const account = createAccount();
  const devices = Array.from({ length: nDevices }, () => createDevice());
  const list = signDeviceList(account, devices, { seq: 1 });
  const prekeys = devices.map((d) => createPrekeys(d, { oneTime: 3, pqOneTime: 3 }));
  return { account, devices, list, prekeys, me: (i = 0) => ({ device: devices[i], deviceList: list, prekeys: prekeys[i].secrets }) };
}

/** Alice starts a session with Bob's first device and they exchange messages both ways. */
async function pair() {
  const alice = person();
  const bob = person();
  const bundle = takeBundle(bob.list, bob.prekeys[0].published, bob.devices[0].kid);
  let a = initiate({ me: alice.me(), bundle, accountKey: bob.account.publicKey });
  const first = await encrypt(a, "hello Bob");
  a = first.state;
  const r = await respond({ me: bob.me(), message: first.message, accountKey: alice.account.publicKey });
  bob.prekeys[0].secrets = r.prekeys;
  return { alice, bob, a, b: r.state, first, firstPlain: text(r.plaintext) };
}

test("two devices agree a session, and messages flow both ways through many ratchet steps", async () => {
  let { a, b, first, firstPlain } = await pair();
  assert.equal(firstPlain, "hello Bob");
  assert.ok(isInitial(first.message));
  assert.ok(!JSON.stringify(first.message).includes("hello"), "the relay only sees ciphertext");
  for (let round = 0; round < 6; round += 1) {
    let m = await encrypt(b, `b${round}`);
    b = m.state;
    assert.ok(m.message.h.ct, "every new chain carries an ML-KEM ciphertext");
    let d = await decrypt(a, m.message);
    a = d.state;
    assert.equal(text(d.plaintext), `b${round}`);
    m = await encrypt(a, `a${round}`);
    a = m.state;
    assert.ok(!m.message.x, "the handshake stops once Bob has answered");
    assert.ok(m.message.h.ct);
    d = await decrypt(b, m.message);
    b = d.state;
    assert.equal(text(d.plaintext), `a${round}`);
  }
});

test("messages can arrive out of order and late, but only once", async () => {
  let { a, b } = await pair();
  const sent = [];
  for (let i = 0; i < 5; i += 1) {
    const m = await encrypt(b, `m${i}`);
    b = m.state;
    sent.push(m.message);
  }
  for (const i of [3, 0, 4, 1, 2]) {
    const d = await decrypt(a, sent[i]);
    a = d.state;
    assert.equal(text(d.plaintext), `m${i}`);
  }
  assert.equal(await code(decrypt(a, sent[2])), "REPLAY");
  // A late message from an older chain still opens after the chain has moved on.
  const late = await encrypt(b, "late");
  b = late.state;
  const next = await encrypt(a, "reply");
  a = next.state;
  b = (await decrypt(b, next.message)).state;
  const newer = await encrypt(b, "newer");
  b = newer.state;
  a = (await decrypt(a, newer.message)).state;
  assert.equal(text((await decrypt(a, late.message)).plaintext), "late");
});

test("tampering, downgrades and replays are refused, and leave the session as it was", async () => {
  let { a, b } = await pair();
  const m = await encrypt(b, "secret");
  b = m.state;
  // Change one character in the middle: the last characters of base64url carry spare bits, so
  // changing those can leave the bytes as they were.
  const mid = Math.floor(m.message.c.length / 2);
  const flip = { ...m.message, c: m.message.c.slice(0, mid) + (m.message.c[mid] === "A" ? "B" : "A") + m.message.c.slice(mid + 1) };
  assert.equal(await code(decrypt(a, flip)), "DECRYPT_FAILED");
  assert.equal(await code(decrypt(a, { ...m.message, h: { ...m.message.h, n: 1 } })), "DECRYPT_FAILED");
  const { ct: _ct, ...noKem } = m.message.h;
  assert.equal(await code(decrypt(a, { ...m.message, h: noKem })), "DOWNGRADE");
  // None of that changed Alice's state: the real message still opens.
  const d = await decrypt(a, m.message);
  assert.equal(text(d.plaintext), "secret");
  assert.equal(await code(decrypt(d.state, m.message)), "REPLAY");
});

test("a session only starts with keys that chain back to the account key you trust", async () => {
  const alice = person();
  const bob = person();
  const mallory = person();
  const bundle = takeBundle(bob.list, bob.prekeys[0].published, bob.devices[0].kid);
  assert.throws(() => initiate({ me: alice.me(), bundle, accountKey: mallory.account.publicKey }), (e) => e.code === "UNTRUSTED");
  // A site swapping in its own prekey for Bob's.
  const fake = takeBundle(mallory.list, mallory.prekeys[0].published, mallory.devices[0].kid);
  assert.throws(() => initiate({ me: alice.me(), bundle: { ...bundle, signed: fake.signed }, accountKey: bob.account.publicKey }), (e) => e.code === "UNTRUSTED");
  // Bob refuses a first message from someone claiming to be Alice.
  const a = initiate({ me: alice.me(), bundle, accountKey: bob.account.publicKey });
  const m = await encrypt(a, "hi");
  assert.equal(initialSender(m.message).account, alice.account.publicKey);
  assert.equal(await code(respond({ me: bob.me(), message: m.message, accountKey: mallory.account.publicKey })), "UNTRUSTED");
  // Safety numbers are the same from both sides and differ for anyone else.
  assert.equal(safetyNumber(alice.account.publicKey, bob.account.publicKey), safetyNumber(bob.account.publicKey, alice.account.publicKey));
  assert.notEqual(safetyNumber(alice.account.publicKey, bob.account.publicKey), safetyNumber(alice.account.publicKey, mallory.account.publicKey));
  assert.match(safetyNumber(alice.account.publicKey, bob.account.publicKey), /^(\d{5} ){7}\d{5}$/);
});

test("one-time prekeys work once; with none left the last-resort ML-KEM prekey still gives a post-quantum session", async () => {
  const alice = person();
  const bob = person();
  const bundle = takeBundle(bob.list, bob.prekeys[0].published, bob.devices[0].kid);
  const m = await encrypt(initiate({ me: alice.me(), bundle, accountKey: bob.account.publicKey }), "one");
  const r = await respond({ me: bob.me(), message: m.message, accountKey: alice.account.publicKey });
  assert.equal(await code(respond({ me: { ...bob.me(), prekeys: r.prekeys }, message: m.message, accountKey: alice.account.publicKey })), "UNKNOWN_PREKEY");
  // Use up the rest.
  bob.prekeys[0].published.oneTime.length = 0;
  bob.prekeys[0].published.pqOneTime.length = 0;
  const last = takeBundle(bob.list, bob.prekeys[0].published, bob.devices[0].kid);
  assert.equal(last.oneTime, null);
  assert.ok(last.pq.body.lastResort);
  const m2 = await encrypt(initiate({ me: alice.me(), bundle: last, accountKey: bob.account.publicKey }), "two");
  const r2 = await respond({ me: { ...bob.me(), prekeys: r.prekeys }, message: m2.message, accountKey: alice.account.publicKey });
  assert.equal(text(r2.plaintext), "two");
  assert.ok(r2.prekeys[last.pq.body.id], "the last-resort prekey is kept");
});

test("device lists only move forward, and removed devices drop out of fan-out", () => {
  const p = person(3);
  const two = removeDevice(p.account, verifyDeviceList(p.list, { accountKey: p.account.publicKey }), p.devices[2].kid);
  const body = verifyDeviceList(two, { accountKey: p.account.publicKey, minSeq: 1 });
  assert.equal(body.devices.length, 2);
  assert.throws(() => verifyDeviceList(p.list, { accountKey: p.account.publicKey, minSeq: 2 }), (e) => e.code === "ROLLBACK");
  const plan = planFanOut(body, { [p.devices[0].kid]: {}, [p.devices[2].kid]: {} }, { skip: "me" });
  assert.deepEqual(plan, { encryptTo: [p.devices[0].kid], needBundles: [p.devices[1].kid], drop: [p.devices[2].kid] });
});

test("a message reaches every device of the recipient and the sender's other devices", async () => {
  const alice = person(2);
  const bob = person(2);
  const sessions = {};
  const targets = [
    ...bob.devices.map((d, i) => ({ p: bob, i, kid: d.kid })),
    { p: alice, i: 1, kid: alice.devices[1].kid },
  ];
  for (const t of targets) sessions[t.kid] = initiate({ me: alice.me(0), bundle: takeBundle(t.p.list, t.p.prekeys[t.i].published, t.kid), accountKey: t.p.account.publicKey });
  const plan = planFanOut(verifyDeviceList(bob.list, { accountKey: bob.account.publicKey }), sessions, { skip: alice.devices[0].kid });
  assert.equal(plan.encryptTo.length, 2);
  const out = await encryptToDevices(sessions, "to all of you");
  for (const t of targets) {
    const r = await respond({ me: t.p.me(t.i), message: out.messages[t.kid], accountKey: alice.account.publicKey });
    assert.equal(text(r.plaintext), "to all of you");
  }
});

test("groups: sender keys go out over sessions, and someone who leaves can't read what follows", async () => {
  // Three members; each pair already has a session, so we skip straight to the group layer and
  // carry distributions over a real session for one of them.
  let { a, b } = await pair();
  let aliceKey = createSenderKey("g1");
  const sent = await encrypt(a, JSON.stringify(distribution(aliceKey)));
  a = sent.state;
  const got = await decrypt(b, sent.message);
  b = got.state;
  let bobView = acceptDistribution(JSON.parse(text(got.plaintext)), { from: "alice-device" });
  let carolView = acceptDistribution(distribution(aliceKey), { from: "alice-device" });

  const msgs = [];
  for (let i = 0; i < 3; i += 1) {
    const g = await groupEncrypt(aliceKey, `g${i}`);
    aliceKey = g.key;
    msgs.push(g.message);
  }
  for (const i of [2, 0, 1]) {
    const d = await groupDecrypt(bobView, msgs[i]);
    bobView = d.state;
    assert.equal(text(d.plaintext), `g${i}`);
  }
  carolView = (await groupDecrypt(carolView, msgs[0])).state;
  assert.equal(await code(groupDecrypt(bobView, msgs[1])), "REPLAY");
  // A member can't forge a message as Alice: the signature is Alice's alone.
  const forged = { ...msgs[2], c: msgs[1].c };
  assert.equal(await code(groupDecrypt(carolView, forged)), "UNTRUSTED");

  // Carol leaves: Alice makes a new sender key and sends it only to Bob.
  aliceKey = createSenderKey("g1");
  bobView = acceptDistribution(distribution(aliceKey), { from: "alice-device" });
  const after = await groupEncrypt(aliceKey, "after Carol left");
  assert.equal(text((await groupDecrypt(bobView, after.message)).plaintext), "after Carol left");
  assert.equal(await code(groupDecrypt(carolView, after.message)), "BAD_MESSAGE");
});

test("a new device is linked by comparing codes, then gets history end to end from an old device", async () => {
  const p = person(1);
  const fresh = createDevice();
  // The new device shows its code; the old device computes it from what it received.
  const shown = linkCode(devicePublic(fresh));
  assert.equal(linkCode(devicePublic(fresh)), shown);
  assert.notEqual(linkCode(devicePublic(createDevice())), shown);
  const list = approveLink(p.account, verifyDeviceList(p.list, { accountKey: p.account.publicKey }), fresh);
  assert.equal(verifyDeviceList(list, { accountKey: p.account.publicKey, minSeq: 2 }).devices.length, 2);
  p.list = list;
  const freshKeys = createPrekeys(fresh, { oneTime: 1, pqOneTime: 1 });

  // The old device opens a session to the new one and sends the history key over it.
  const history = Array.from({ length: 50 }, (_, i) => ({ id: i, from: i % 2 ? "Bob" : "Alice", text: `message ${i}`, at: 1_700_000_000_000 + i }));
  const { offer, chunks } = await sealHistory(history, { chunkSize: 512 });
  assert.ok(chunks.length > 1);
  assert.ok(!chunks.join("").includes("message"));
  const s = initiate({ me: { device: p.devices[0], deviceList: list }, bundle: takeBundle(list, freshKeys.published, fresh.kid), accountKey: p.account.publicKey });
  const m = await encrypt(s, JSON.stringify(offer));
  const r = await respond({ me: { device: fresh, deviceList: list, prekeys: freshKeys.secrets }, message: m.message, accountKey: p.account.publicKey });
  const got = await openHistory(JSON.parse(text(r.plaintext)), chunks);
  assert.deepEqual(got, history);
  // A store that drops, reorders or alters chunks is caught.
  assert.equal(await code(openHistory(offer, chunks.slice(1))), "INCOMPLETE");
  assert.equal(await code(openHistory(offer, [chunks[1], chunks[0], ...chunks.slice(2)])), "TAMPERED");
  assert.ok((await code(openHistory({ ...offer, key: offer.key.replace(/^./, (c) => (c === "A" ? "B" : "A")) }, chunks))) === "DECRYPT_FAILED");
});

test("errors are SessionErrors with stable codes", () => {
  assert.throws(() => signDeviceList(createAccount(), [], { seq: 0 }), (e) => e instanceof SessionError && e.code === "BAD_INPUT");
});

test("the code matches the published test vectors (spec/vectors/cvp-016-v1.json)", async () => {
  const fs = await import("node:fs");
  const { vectors } = await import("../scripts/vectors.mjs");
  const published = JSON.parse(fs.readFileSync(new URL("../spec/vectors/cvp-016-v1.json", import.meta.url), "utf8"));
  assert.deepEqual(await vectors(), published);
});

test("hostile headers are refused with stable codes and leave the session usable", async () => {
  const { a, b } = await pair();
  const y = await encrypt(b, "yo");
  const h = y.message.h;
  const cases = {
    BAD_KEY: [{ ...h, dh: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }, { ...h, kem: "AAAA" }],
    BAD_MESSAGE: [{ ...h, dh: "__proto__" }, { ...h, n: -1 }, { ...h, ct: "x" }],
    DECRYPT_FAILED: [{ ...h, extra: 1 }, { ...h, pn: 1e9 }],
  };
  for (const [want, headers] of Object.entries(cases)) for (const bad of headers) assert.equal(await code(decrypt(a, { ...y.message, h: bad })), want, JSON.stringify(Object.keys(bad)));
  assert.equal(await code(decrypt(a, { ...y.message, c: "@@" })), "BAD_MESSAGE");
  assert.equal(text((await decrypt(a, y.message)).plaintext), "yo");
});
