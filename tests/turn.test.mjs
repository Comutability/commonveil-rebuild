import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { turnIceServers } from "../base44/shared/handlers/turn.ts";

test("TURN is disabled when no operator secret and URLs are configured", async () => {
  const oldSecret = process.env.VOICE_TURN_SECRET;
  const oldUrls = process.env.VOICE_TURN_URLS;
  try {
    delete process.env.VOICE_TURN_SECRET;
    process.env.VOICE_TURN_URLS = "turn:relay.example.test:3478?transport=udp";
    assert.deepEqual(await turnIceServers("user-id"), []);
    process.env.VOICE_TURN_SECRET = "a-valid-length-secret-for-turn-tests";
    delete process.env.VOICE_TURN_URLS;
    assert.deepEqual(await turnIceServers("user-id"), []);
  } finally {
    if (oldSecret === undefined) delete process.env.VOICE_TURN_SECRET;
    else process.env.VOICE_TURN_SECRET = oldSecret;
    if (oldUrls === undefined) delete process.env.VOICE_TURN_URLS;
    else process.env.VOICE_TURN_URLS = oldUrls;
  }
});

test("TURN credentials use coturn REST HMAC-SHA1 and expire after six hours", async () => {
  const oldSecret = process.env.VOICE_TURN_SECRET;
  const oldUrls = process.env.VOICE_TURN_URLS;
  try {
    process.env.VOICE_TURN_SECRET = "a-long-random-operator-secret-0123456789";
    process.env.VOICE_TURN_URLS = "turn:relay.example.test:3478?transport=udp, turns:relay.example.test:5349?transport=tcp";
    const now = Math.floor(Date.now() / 1000);
    const [server] = await turnIceServers("user-id");
    assert.deepEqual(server.urls, ["turn:relay.example.test:3478?transport=udp", "turns:relay.example.test:5349?transport=tcp"]);
    const [expires, userId] = server.username.split(":");
    assert.equal(userId, "user-id");
    assert.ok(Number(expires) >= now + 6 * 3600 - 2 && Number(expires) <= now + 6 * 3600 + 2);
    assert.equal(server.credential, createHmac("sha1", process.env.VOICE_TURN_SECRET).update(server.username).digest("base64"));
    assert.equal(JSON.stringify(server).includes(process.env.VOICE_TURN_SECRET), false, "shared secret must never leave server");
  } finally {
    if (oldSecret === undefined) delete process.env.VOICE_TURN_SECRET;
    else process.env.VOICE_TURN_SECRET = oldSecret;
    if (oldUrls === undefined) delete process.env.VOICE_TURN_URLS;
    else process.env.VOICE_TURN_URLS = oldUrls;
  }
});

test("TURN rejects malformed URLs rather than accepting insecure configuration", async () => {
  const oldSecret = process.env.VOICE_TURN_SECRET;
  const oldUrls = process.env.VOICE_TURN_URLS;
  try {
    process.env.VOICE_TURN_SECRET = "a-valid-length-secret-for-turn-tests";
    for (const url of ["https://example.test", "turn:relay.test:3478?token=secret", "turn:user:password@relay.test:3478", "turn:bad /path"]) {
      process.env.VOICE_TURN_URLS = url;
      assert.deepEqual(await turnIceServers("user-id"), []);
    }
  } finally {
    if (oldSecret === undefined) delete process.env.VOICE_TURN_SECRET;
    else process.env.VOICE_TURN_SECRET = oldSecret;
    if (oldUrls === undefined) delete process.env.VOICE_TURN_URLS;
    else process.env.VOICE_TURN_URLS = oldUrls;
  }
});
