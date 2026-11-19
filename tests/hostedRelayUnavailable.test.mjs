// When the post-quantum library can't be loaded, the hosted site fails closed: it publishes no
// relay keys, sends nothing to a site that requires sealing, and refuses that site's requests.
// Node can't load the npm: specifiers the functions use, and this file never hands the library in
// (useRelayLibrary), so here hosted.ts is in the state it would be in if Base44 couldn't load it.
// The other site in these tests does have the library: it's only the hosted site's that's missing.
import test from "node:test";
import assert from "node:assert/strict";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { FakeWorld } from "./support/fakeBase44.mjs";
import { FederationError, HostedFederation, relayAlgorithms } from "../base44/shared/federation/hosted.ts";
import { serveFederation } from "../base44/shared/federation/inbound.ts";
import * as W from "../base44/shared/federation/wire.ts";
import { relaySuite, SUITE } from "../base44/shared/federation/sealed.generated.js";

const HOSTED = "hosted.example.org";
const peerKey = await W.generateSiteKey();
const peerRelay = await relaySuite({ ml_kem768, ml_dsa65 }).generateKeys();
// Sites whose names start with "sealing" publish relay keys, so they require sealing.
const siteDocument = (host) => ({
  protocol: W.PROTOCOL,
  host,
  name: host,
  handle_domain: host,
  key: { alg: "Ed25519", public: peerKey.public },
  endpoints: { inbox: "/inbox", act: "/act", directory: "/directory", identity: "/identity", discover: "/discover" },
  ...(host.startsWith("sealing") ? { pq: { suite: SUITE, kem: peerRelay.kem.public, sig: peerRelay.sig.public } } : {}),
});
const sent = [];
async function fetchImpl(url, init = {}) {
  const u = new URL(url);
  sent.push({ host: u.host, path: u.pathname, method: init.method || "GET", headers: init.headers || {}, body: String(init.body ?? "") });
  if (u.pathname === W.SITE_DOCUMENT) return new Response(JSON.stringify(siteDocument(u.host)), { status: 200 });
  return new Response(JSON.stringify({ ok: true }), { status: 200 });
}
const world = new FakeWorld();
const site = { enabled: true, host: HOSTED, name: "Hosted", public_key: "", pq: { kem: "", sig: "" } };
const fed = new HostedFederation({ sr: world.clientFor(null).asServiceRole, site, fetchImpl, log: { warn() {} } });
site.public_key = (await fed.key()).public;

/** A request signed by another site, as it would arrive at the hosted site's inbox. */
async function signedRequest(from, { sealed = false, body = "{}" } = {}) {
  const date = new Date().toISOString();
  const nonce = W.b64u(crypto.getRandomValues(new Uint8Array(16)));
  const digest = await W.digestOf(body);
  const pathname = "/functions/fedinbox";
  const base = W.signatureBase({ method: "POST", to: HOSTED, path: pathname, from, date, nonce, digest, user: "" });
  const headers = { "CV-From": from, "CV-Date": date, "CV-Nonce": nonce, "CV-Digest": digest, "CV-Signature": await W.signText(peerKey.secret, base), ...(sealed ? { "CV-Sealed": "1" } : {}) };
  return [new Request(`https://${HOSTED}${pathname}`, { method: "POST", headers, body }), body];
}

test("the relay's algorithms are unavailable, and stay so", async () => {
  const first = relayAlgorithms();
  assert.equal(await first, null);
  assert.equal(relayAlgorithms(), first, "the answer is kept, not retried on every call");
});

test("no relay keys are made or published", async () => {
  assert.equal(await fed.relayKeys(), null);
  assert.equal(world.rows("FedKey").filter((r) => r.purpose === "relay").length, 0);
  const res = await serveFederation(new Request(`https://${HOSTED}/functions/fedidentity?site=1`), () => world.clientFor(null), "identity", { federation: fed });
  assert.equal(res.status, 200);
  assert.equal((await res.json()).pq, null);
});

test("nothing is sent to a site that requires sealing", async () => {
  sent.length = 0;
  await assert.rejects(fed.send("sealing.example.org", "inbox", { secret: "must not leave" }), (e) => e instanceof FederationError && e.status === 502 && e.code === "SITE_UNREACHABLE");
  assert.equal(sent.filter((r) => r.method === "POST").length, 0);
  assert.ok(!sent.some((r) => r.body.includes("must not leave")));
});

test("a site that requires sealing is refused, not answered in the clear", async () => {
  const [req, body] = await signedRequest("sealing2.example.org");
  await assert.rejects(fed.verify(req, body), (e) => e instanceof FederationError && e.status === 503 && e.code === "RELAY_UNAVAILABLE");
});

test("a request marked sealed can't be opened, so it's refused", async () => {
  const [req, body] = await signedRequest("plain2.example.org", { sealed: true, body: JSON.stringify({ sealed: "abc" }) });
  await assert.rejects(fed.verify(req, body), (e) => e instanceof FederationError && e.status === 400 && e.code === "CANNOT_OPEN");
});

test("a site without relay keys is still reached as before, unsealed", async () => {
  sent.length = 0;
  const reply = await fed.send("plain.example.org", "inbox", { hello: 1 });
  assert.equal(reply.status, 200);
  const post = sent.find((r) => r.method === "POST");
  assert.ok(post, "the request was sent");
  assert.ok(!("CV-Sealed" in post.headers) && !("CV-PQ-Signature" in post.headers));
});
