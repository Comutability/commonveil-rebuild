// Push notifications that give nothing away (base44/shared/handlers/notifications.ts): Web Push
// encryption against the RFC's own test vector, what a push carries (decrypted here as the browser
// would), one-time codes, bursts made into one, and push addresses that are gone.
import test, { afterEach } from "node:test";
import assert from "node:assert/strict";
import { FakeWorld } from "./support/fakeBase44.mjs";
import { Member } from "./support/harness.mjs";
import { encryptPayload, pushEndpointOk } from "../base44/shared/push/webpush.ts";
import { forgetPushKeys, muteKey } from "../base44/shared/handlers/notifications.ts";
import { b64url, fromB64url } from "../base44/shared/identity/crypto.ts";

const subtle = globalThis.crypto.subtle;
const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
  forgetPushKeys();
});

test("Web Push encryption matches RFC 8291's test vector", async () => {
  const out = await encryptPayload(new TextEncoder().encode("When I grow up, I want to be a watermelon"),
    { p256dh: "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4", auth: "BTBZMqHH6r4Tts7J_aSIgg" },
    { senderPrivate: "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw", senderPublic: "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8", salt: "DGv6ra1nlYgDCS1FRnbzlw" });
  assert.equal(b64url(out), "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN");
});

test("pushes only go to browser push services", () => {
  for (const ok of ["https://fcm.googleapis.com/fcm/send/abc", "https://updates.push.services.mozilla.com/wpush/v2/x", "https://web.push.apple.com/QK", "https://wns2-par02p.notify.windows.com/w/?token=x"]) assert.ok(pushEndpointOk(ok), ok);
  for (const bad of ["http://fcm.googleapis.com/x", "https://evil.test/x", "https://fcm.googleapis.com.evil.test/x", "https://127.0.0.1/x", "https://fcm.googleapis.com:8443/x", "https://user@fcm.googleapis.com/x"]) assert.ok(!pushEndpointOk(bad), bad);
});

/** A browser: its push keys, and a way to open what's pushed to it (RFC 8291, receiving side). */
async function browser() {
  const pair = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const pub = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
  const auth = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const hmac = async (k, d) => new Uint8Array(await subtle.sign("HMAC", await subtle.importKey("raw", k, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]), d));
  const hkdf = async (salt, ikm, info, n) => (await hmac(await hmac(salt, ikm), new Uint8Array([...info, 1]))).slice(0, n);
  const te = (s) => new TextEncoder().encode(s);
  return {
    keys: { p256dh: b64url(pub), auth: b64url(auth) },
    async open(body) {
      const salt = body.slice(0, 16);
      const senderPub = body.slice(21, 86);
      const sender = await subtle.importKey("raw", senderPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
      const shared = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: sender }, pair.privateKey, 256));
      const ikm = await hkdf(auth, shared, new Uint8Array([...te("WebPush: info\0"), ...pub, ...senderPub]), 32);
      const cek = await hkdf(salt, ikm, te("Content-Encoding: aes128gcm\0"), 16);
      const nonce = await hkdf(salt, ikm, te("Content-Encoding: nonce\0"), 12);
      const plain = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: nonce }, await subtle.importKey("raw", cek, "AES-GCM", false, ["decrypt"]), body.slice(86)));
      return JSON.parse(new TextDecoder().decode(plain.slice(0, plain.lastIndexOf(2))));
    },
  };
}

/** Catch outgoing pushes instead of sending them. status: what the push service answers. */
function pushService(status = 201) {
  const sent = [];
  globalThis.fetch = async (url, init) => {
    sent.push({ url: String(url), headers: init.headers, body: new Uint8Array(init.body) });
    return new Response(null, { status });
  };
  return sent;
}

async function pair() {
  const w = new FakeWorld();
  const ann = await new Member(w, "ann").setup();
  const bea = await new Member(w, "bea").setup();
  const b = await browser();
  const muteSecret = b64url(globalThis.crypto.getRandomValues(new Uint8Array(32)));
  await bea.ok("notifications", { action: "subscribe", endpoint: "https://fcm.googleapis.com/fcm/send/bea-phone", ...b.keys, mute_secret: muteSecret });
  return { w, ann, bea, b, muteSecret };
}

test("a message sends a push that says only that there's something new", async () => {
  const { ann, bea, b, muteSecret } = await pair();
  const sent = pushService();
  const dm = await ann.dm(bea);
  const r = await ann.send(dm, "Meet at the north gate at six");
  assert.equal(r.status, 200);
  assert.equal(sent.length, 1, "Bea's browser was told");
  const push = sent[0];
  assert.equal(push.url, "https://fcm.googleapis.com/fcm/send/bea-phone");
  assert.match(push.headers.Authorization, /^vapid t=[\w-]+\.[\w-]+\.[\w-]+, k=[\w-]{87}$/, "signed by this site (VAPID)");
  assert.equal(push.headers["Content-Encoding"], "aes128gcm");
  assert.equal(push.headers.Topic, "commonveil", "waiting pushes replace each other");

  const raw = new TextDecoder("latin1").decode(push.body);
  for (const secret of ["north gate", dm.id, ann.id, bea.id, "ann"]) assert.ok(!raw.includes(secret), `the push service can't see ${secret}`);
  const payload = await b.open(push.body);
  assert.deepEqual(Object.keys(payload).sort(), ["c", "k", "m", "v"]);
  assert.equal(payload.k, "message");
  for (const secret of [dm.id, ann.id, bea.id, "ann", "north gate"]) assert.ok(!JSON.stringify(payload).includes(secret), `even the browser's copy doesn't name ${secret}`);
  assert.equal(payload.m, await muteKey(muteSecret, dm.id), "the browser can tell it's a muted place, if it is, without being told the place");

  // Tapping it: Bea's app swaps the code for where to go, once.
  assert.equal((await ann.ok("notifications", { action: "open", code: payload.c })).path, "/app", "someone else's code goes nowhere");
  assert.equal((await bea.ok("notifications", { action: "open", code: payload.c })).path, `/app/c/${dm.id}`);
  assert.equal((await bea.ok("notifications", { action: "open", code: payload.c })).path, "/app", "and only once");

  // The sender's own devices aren't told.
  assert.ok(sent.every((s) => s.url.includes("bea-phone")));
});

test("a burst of messages is one notification, and dead push addresses are forgotten", async () => {
  const { w, ann, bea } = await pair();
  let sent = pushService();
  const dm = await ann.dm(bea);
  for (const t of ["one", "two", "three"]) await ann.send(dm, t);
  assert.equal(sent.length, 1, "one notification for the burst");

  // The browser unsubscribed or was reset: the push service says it's gone.
  const subs = await w.clientFor(null).asServiceRole.entities.PushSubscription.filter({ user_id: bea.id });
  await w.clientFor(null).asServiceRole.entities.PushSubscription.update(subs[0].id, { last_push_at: "" });
  sent = pushService(410);
  await ann.send(dm, "four");
  assert.equal(sent.length, 1);
  assert.equal((await w.clientFor(null).asServiceRole.entities.PushSubscription.filter({ user_id: bea.id })).length, 0, "forgotten");

  // A push service that's down never stops the message itself.
  globalThis.fetch = async () => {
    throw new Error("unreachable");
  };
  assert.equal((await ann.send(dm, "five")).status, 200);
});

test("subscriptions: only real push addresses, one owner each, gone with the account", async () => {
  const { w, ann, bea, b } = await pair();
  const bad = await ann.call("notifications", { action: "subscribe", endpoint: "https://evil.test/collect", ...b.keys, mute_secret: "x" });
  assert.equal(bad.body.code, "BAD_ENDPOINT", "the server can't be made to post anywhere else");
  // The same browser address signed in as someone else moves to them.
  await ann.ok("notifications", { action: "subscribe", endpoint: "https://fcm.googleapis.com/fcm/send/bea-phone", ...b.keys, mute_secret: "abc" });
  assert.equal((await w.clientFor(null).asServiceRole.entities.PushSubscription.filter({ endpoint: "https://fcm.googleapis.com/fcm/send/bea-phone" })).map((s) => s.user_id).join(), ann.id);
  await ann.ok("notifications", { action: "unsubscribe", endpoint: "https://fcm.googleapis.com/fcm/send/bea-phone" });
  assert.equal((await w.clientFor(null).asServiceRole.entities.PushSubscription.filter({ user_id: ann.id })).length, 0);
  // The site's push key is public; its private half never leaves the server.
  const { public_key } = await bea.ok("notifications", { action: "key" });
  assert.equal(fromB64url(public_key).length, 65);
});
