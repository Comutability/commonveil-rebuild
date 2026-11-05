// Voice: signed call offers and the extra layer of frame encryption. Real keys, nothing mocked.
import test from "node:test";
import assert from "node:assert/strict";

import { createKeyVersion } from "../src/lib/crypto/keyring.js";
import { makeAccountStatement, makeDeviceCert, verifyAccountChain } from "../src/lib/crypto/identity.js";
import { createDeviceKeys } from "../src/lib/crypto/device.js";
import { fingerprintOf, signHello, verifyHello } from "../src/lib/voice/hello.js";
import { FRAME_VERSION, frameTransform, openFrame, sealFrame } from "../src/lib/voice/frames.js";

const uid = () => Array.from(crypto.getRandomValues(new Uint8Array(12)), (b) => b.toString(16).padStart(2, "0")).join("");
const FP = Array.from({ length: 32 }, (_, i) => (i * 7 + 3).toString(16).padStart(2, "0").toUpperCase()).join(":");

async function member() {
  const userId = uid();
  const v1 = await createKeyVersion(1);
  const statement = await makeAccountStatement({ userId, keyVersion: v1, recoveryPub: v1.ecdh_pub, signer: v1 });
  const chain = await verifyAccountChain(userId, [statement]);
  const device = await createDeviceKeys("Test browser");
  const cert = await makeDeviceCert({ userId, device, keyVersion: v1 });
  const row = { device_id: device.device_id, sign_pub: device.sign_pub, box_pub: device.box_pub, status: "active", cert_signature: cert.signature, cert_key_version: cert.key_version, cert_issued_at: cert.issued_at };
  return { userId, chain, device, row };
}

const aesKey = () => crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

test("fingerprintOf reads one SHA-256 fingerprint from an SDP", () => {
  const sdp = `v=0\r\na=fingerprint:sha-256 ${FP.toLowerCase()}\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=fingerprint:sha-256 ${FP}\r\n`;
  assert.equal(fingerprintOf(sdp), FP);
  assert.equal(fingerprintOf("v=0\r\n"), null);
  const other = FP.replace(/^../, "00");
  assert.equal(fingerprintOf(`a=fingerprint:sha-256 ${FP}\r\na=fingerprint:sha-256 ${other}\r\n`), null, "two different certificates");
});

test("a signed call offer verifies against the device's certificate, and nothing else does", async () => {
  const a = await member();
  const b = await member();
  const room = `${uid()}.${uid()}`;
  const hello = await signHello({ device: a.device, room, userId: a.userId, callId: "call1234abcd", fingerprint: FP });
  const peer = { user_id: a.userId, device_id: a.device.device_id, hello };
  assert.equal(await verifyHello({ room, peer, chain: a.chain, devices: [a.row] }), true);
  // Another room, another fingerprint, another account's chain, an unknown device, a revoked device.
  assert.equal(await verifyHello({ room: `${room}x`, peer, chain: a.chain, devices: [a.row] }), false);
  assert.equal(await verifyHello({ room, peer: { ...peer, hello: { ...hello, fingerprint: FP.replace(/^../, "00") } }, chain: a.chain, devices: [a.row] }), false);
  assert.equal(await verifyHello({ room, peer, chain: b.chain, devices: [a.row] }), false);
  assert.equal(await verifyHello({ room, peer, chain: a.chain, devices: [b.row] }), false);
  assert.equal(await verifyHello({ room, peer, chain: a.chain, devices: [{ ...a.row, status: "revoked" }] }), false);
  // Claiming someone else's device.
  assert.equal(await verifyHello({ room, peer: { ...peer, user_id: b.userId }, chain: b.chain, devices: [a.row] }), false);
});

test("audio frames open only with the right key and untouched", async () => {
  const key = await aesKey();
  const other = await aesKey();
  const data = crypto.getRandomValues(new Uint8Array(120));
  const sealed = await sealFrame(key, 3, 4211, data);
  assert.equal(sealed[0], FRAME_VERSION);
  assert.equal(sealed.length, data.length + 7 + 12 + 16);
  assert.deepEqual(await openFrame(async (g, s) => (g === 3 && s === 4211 ? key : null), sealed), data);
  assert.equal(await openFrame(async () => other, sealed), null, "wrong key");
  assert.equal(await openFrame(async () => null, sealed), null, "no key for that epoch");
  const flipped = sealed.slice();
  flipped[30] ^= 1;
  assert.equal(await openFrame(async () => key, flipped), null, "tampered ciphertext");
  const relabelled = sealed.slice();
  relabelled[6] ^= 1;
  assert.equal(await openFrame(async () => key, relabelled), null, "tampered header");
});

test("the frame transform never passes audio on in the clear", async () => {
  const key = await aesKey();
  const run = async (side, keys, frames) => {
    const stats = { sealed: 0, opened: 0, dropped: 0 };
    const out = [];
    const t = frameTransform(side, keys, stats);
    const writer = t.writable.getWriter();
    const reader = t.readable.getReader();
    const reading = (async () => {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        out.push(new Uint8Array(value.data));
      }
    })();
    for (const f of frames) await writer.write({ data: f.buffer.slice(0) });
    await writer.close();
    await reading;
    return { out, stats };
  };
  const plain = [new Uint8Array([1, 2, 3, 4]), new Uint8Array(60).fill(9)];
  const noKey = await run("send", { current: () => null }, plain);
  assert.equal(noKey.out.length, 0);
  assert.equal(noKey.stats.dropped, 2);
  const sent = await run("send", { current: () => ({ generation: 1, step: 2, key }) }, plain);
  assert.equal(sent.stats.sealed, 2);
  assert.notDeepEqual(sent.out[1].subarray(19, 79), plain[1]);
  const got = await run("recv", { keyFor: async () => key }, sent.out);
  assert.deepEqual(got.out, plain);
  const unsealed = await run("recv", { keyFor: async () => key }, plain);
  assert.equal(unsealed.out.length, 0, "unencrypted frames are dropped");
});
