// CVP-017 actor documents: what the app checks on this device, and how it remembers what it saw.
//
// These are the rules a move would rest on, so each one is tested against a real signed document
// and against the ways it can be wrong: forged, for another handle, replayed older than one already
// accepted, or shaped so its id isn't its key's id. Nothing here binds an actor to an account:
// that step is deliberately not built (docs/IDENTITY.md, "Protocol actors").
import test from "node:test";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { createAccount, createDevice, devicePublic, signDeviceList } from "../packages/secure-net/src/session/keys.js";
import { createActorDocument, actorIdOf } from "../packages/secure-net/src/social/actor.js";
import { describeActor, parseActorJson, fingerprintOf, problemText } from "../src/lib/identity/protocolIdentity.js";
import { seenActor, rememberActor } from "../src/lib/identity/seenActors.js";
import { destinationHost, evaluateDestination, checkDestination, DiscoveryError } from "../src/lib/identity/siteDiscovery.js";

const NOW = 1_700_000_000_000;

function actor({ handle = "ann@alpha.test", seq = 3, user = "ann", extra = {}, account = null } = {}) {
  const key = account || createAccount();
  const device = createDevice();
  const devices = signDeviceList(key, [devicePublic(device)], { seq: 1, now: NOW });
  const document = createActorDocument(key, { handle, type: "Person", name: user, devices, seq, now: NOW, ...extra });
  return { account: key, device, devices, document };
}

const memoryStorage = () => {
  const rows = new Map();
  return { getItem: (k) => (rows.has(k) ? rows.get(k) : null), setItem: (k, v) => rows.set(k, String(v)), rows };
};

test("a real actor document checks out, and names the same actor as its key", () => {
  const { account, device, document } = actor();
  const info = describeActor(document);
  assert.equal(info.ok, true, info.problems.join("; "));
  assert.equal(info.id, account.kid);
  assert.equal(info.id, actorIdOf(account.publicKey));
  assert.equal(info.handle, "ann@alpha.test");
  assert.equal(info.fingerprint, fingerprintOf(account.publicKey));
  assert.match(info.fingerprint, /^[A-Za-z0-9_-]{4} [A-Za-z0-9_-]{4}$/);
  assert.deepEqual(info.devices, [device.kid]);
  assert.equal(info.seq, 3);
  assert.equal(info.type, "Person");
});

test("a document changed after it was signed is refused, never repaired", () => {
  const { document } = actor();
  const forged = { ...document, body: { ...document.body, name: "Someone else" } };
  const info = describeActor(forged);
  assert.equal(info.ok, false);
  assert.equal(info.code, "UNTRUSTED");
  assert.match(problemText(info.code, info.problems[0]), /changed after it was signed/);
});

test("an id that isn't the key's id is refused before any signature is believed", () => {
  const { document } = actor();
  const other = createAccount();
  const wrongId = { ...document, body: { ...document.body, account: other.publicKey } };
  const info = describeActor(wrongId);
  assert.equal(info.ok, false);
  assert.match(info.problems.join(" "), /Actor id isn't its account key's id/);
});

test("a document is only accepted for the handle that was asked for", () => {
  const { document } = actor();
  assert.equal(describeActor(document, { handle: "ann@alpha.test" }).ok, true);
  const wrong = describeActor(document, { handle: "bob@alpha.test" });
  assert.equal(wrong.ok, false);
  assert.match(wrong.problems.join(" "), /different handle/);
});

test("an older document is refused once a newer one has been seen", () => {
  const { document } = actor({ seq: 3 });
  const older = describeActor(document, { minSeq: 4 });
  assert.equal(older.ok, false);
  assert.equal(older.code, "ROLLBACK");
  assert.match(problemText(older.code, older.problems[0]), /already seen a newer version/);
  assert.equal(describeActor(document, { minSeq: 3 }).ok, true, "the same seq is not a rollback");
});

test("the device list inside a document is signed by the account, and a bad one is refused", () => {
  const { document, account } = actor();
  const other = createAccount();
  const stranger = signDeviceList(other, [devicePublic(createDevice())], { seq: 1, now: NOW });
  const swapped = { ...document, body: { ...document.body, devices: stranger } };
  const info = describeActor(swapped);
  assert.equal(info.ok, false, "a device list signed by another account can't ride along");
  assert.equal(info.devices.length, 1, "but the document still shows what it claims, so a person can see it changed");
  assert.ok(info.problems.length > 0);
});

test("what the browser has seen only ever goes up, and survives a broken store", () => {
  const storage = memoryStorage();
  assert.equal(seenActor("a", storage), null);
  assert.equal(rememberActor("a", { seq: 2, handle: "ann@alpha.test" }, storage).raised, true);
  assert.equal(rememberActor("a", { seq: 5 }, storage).raised, true);
  assert.equal(seenActor("a", storage).seq, 5);
  const lower = rememberActor("a", { seq: 4 }, storage);
  assert.equal(lower.raised, false, "an older seq never wins");
  assert.equal(seenActor("a", storage).seq, 5);
  storage.setItem("cv.seen-actors.v1", "not json");
  assert.equal(seenActor("a", storage), null, "a corrupt store is empty, not a crash");
  assert.equal(rememberActor("a", { seq: 1 }, storage).raised, true);
});

test("a pasted document is read as JSON and nothing else", () => {
  const { document } = actor();
  assert.deepEqual(parseActorJson(JSON.stringify(document)), document);
  assert.deepEqual(parseActorJson(document), document);
  assert.throws(() => parseActorJson("  "), /Paste or choose/);
  assert.throws(() => parseActorJson("{nope"), /isn't JSON/);
  assert.throws(() => parseActorJson("x".repeat(300 * 1024)), /larger than an actor document/);
});

// ---- discovery: an address typed by hand must never reach anything private ----

test("only public HTTPS names are accepted as another site", () => {
  assert.equal(destinationHost("friend.example.org"), "friend.example.org");
  assert.equal(destinationHost("https://friend.example.org/some/path"), "friend.example.org");
  assert.equal(destinationHost("  FRIEND.Example.ORG.  "), "friend.example.org");
  assert.equal(destinationHost("https://friend.example.org:8443"), "friend.example.org:8443");
  for (const bad of ["", "   ", "localhost", "http://friend.example.org", "https://127.0.0.1", "127.0.0.1", "10.0.0.5", "192.168.1.2",
    "169.254.169.254", "https://[::1]", "::1", "intranet", "server.local", "box.internal", "user:pass@friend.example.org",
    "https://user:pass@friend.example.org", "friend.example.org?x=1", "nosite"]) {
    assert.throws(() => destinationHost(bad), DiscoveryError, `refused: ${bad}`);
  }
});

test("the browser never reads another site itself: its own server does, for a checked address", async () => {
  // The app's Content Security Policy only lets the browser talk to its own site.
  const source = readFileSync(new URL("../src/lib/identity/siteDiscovery.js", import.meta.url), "utf8");
  assert.doesNotMatch(source, /\bfetch\s*\(/, "no direct fetch to another site");
  const asked = [];
  const read = async (host) => {
    asked.push(host);
    return { protocol: "commonveil/1", host, key: { public: "k" } };
  };
  await checkDestination("https://Friend.Example.org/some/path", { read });
  assert.deepEqual(asked, ["friend.example.org"], "the server is asked about the cleaned address only");
  // A bad address is explained here and never reaches the server.
  await assert.rejects(() => checkDestination("http://localhost", { read }), DiscoveryError);
  await assert.rejects(() => checkDestination("10.0.0.1", { read }), DiscoveryError);
  assert.equal(asked.length, 1);
  await assert.rejects(() => checkDestination("friend.example.org"), /can't read other sites/);
  await assert.rejects(() => checkDestination("friend.example.org", { read: async () => "<html>" }), /didn't answer with a site document/);
});

const siteDoc = (over = {}) => ({
  protocol: "commonveil/1",
  host: "friend.example.org",
  name: "Friend",
  software: { name: "commonveil", version: "9.9.9" },
  handle_domain: "friend.example.org",
  key: { alg: "Ed25519", public: "site-key" },
  endpoints: {
    directory: "/cvp/v1/directory", inbox: "/cvp/v1/inbox", identity: "/.well-known/commonveil/identity",
    actor: "/.well-known/commonveil/actor", prekeys: "/cvp/v2/prekeys",
    outbox: "/cvp/v2/outbox", mailbox: "/cvp/v2/mailbox",
    deliver: "/cvp/v2/deliver", repo: "/cvp/v2/repo",
  },
  features: {
    "cvp.actors": 1, "cvp.sessions": 2, "cvp.delivery": 2,
    "cvp.sealed-relay": 1, "cvp.pq-signatures": 1, "cvp.transfer": 1,
  },
  pq: { suite: "p256-mlkem768+mldsa65", kem: "kem", sig: "sig" },
  ...over,
});

test("a checklist reports what a site can do, and gaps it would hit today", () => {
  const full = evaluateDestination(siteDoc(), { host: "friend.example.org" });
  assert.equal(full.ok, true, full.items.filter((i) => i.state === "gap").map((i) => i.label).join(", "));
  assert.equal(full.gaps, 0);

  const noActors = evaluateDestination(siteDoc({ limits: { actors: false } }), { host: "friend.example.org" });
  assert.equal(noActors.ok, false);
  assert.ok(noActors.items.some((i) => i.id === "actors" && i.state === "gap"), "a site that doesn't serve actors is a gap, not a footnote");

  const otherHost = evaluateDestination(siteDoc({ host: "somewhere.else" }), { host: "friend.example.org" });
  assert.equal(otherHost.ok, false);
  assert.ok(otherHost.items.some((i) => i.id === "host" && i.state === "gap"));

  const oldProtocol = evaluateDestination(siteDoc({ protocol: "commonveil/0" }), { host: "friend.example.org" });
  assert.equal(oldProtocol.ok, false);
  assert.ok(oldProtocol.items.some((i) => i.id === "protocol" && i.state === "gap"));

  const cheap = evaluateDestination(siteDoc({ pq: undefined }), { host: "friend.example.org" });
  assert.equal(cheap.ok, false, "migration must not downgrade post-quantum transport");
  assert.ok(cheap.items.some((i) => i.id === "sealed" && i.state === "gap"));

  const missingTransfer = evaluateDestination(siteDoc({ features: {
    "cvp.actors": 1, "cvp.sessions": 2, "cvp.delivery": 2,
    "cvp.sealed-relay": 1, "cvp.pq-signatures": 1,
  } }), { host: "friend.example.org" });
  assert.equal(missingTransfer.ok, false, "legacy federation is not full account portability");
  assert.ok(missingTransfer.items.some((i) => i.id === "transfer" && i.state === "gap"));

  const missingMailbox = evaluateDestination(siteDoc({
    endpoints: { directory: "/cvp/v1/directory", inbox: "/cvp/v1/inbox",
      identity: "/.well-known/commonveil/identity", actor: "/.well-known/commonveil/actor" },
  }), { host: "friend.example.org" });
  assert.equal(missingMailbox.ok, false, "old inbox is not independent v2 delivery");
  assert.ok(missingMailbox.items.some((i) => i.id === "v2-transport" && i.state === "gap"));
});

test("the screen's flow refuses a replay, and only a newer document moves the mark", () => {
  const storage = memoryStorage();
  const { account } = actor();
  const base = { handle: "ann@alpha.test", user: "ann" };
  const v4 = actor({ ...base, seq: 4, account });
  const v5 = actor({ ...base, seq: 5, account });
  const v6 = actor({ ...base, seq: 6, account });

  // What ExternalActorVerify does: look up what was seen, check against it, remember only if it verifies.
  const check = (document) => {
    const seen = seenActor(document.body.id, storage);
    const info = describeActor(document, { minSeq: seen?.seq || 0 });
    if (info.ok) rememberActor(info.id, { seq: info.seq, handle: info.handle }, storage);
    return info;
  };

  assert.equal(check(v5.document).ok, true, "the first sighting is accepted");
  assert.equal(seenActor(v5.document.body.id, storage).seq, 5);

  assert.equal(check(v5.document).ok, true, "the same document again is the same state, so it still verifies");
  assert.equal(seenActor(v5.document.body.id, storage).seq, 5, "and the mark stays where it was");

  const stale = check(v4.document);
  assert.equal(stale.ok, false, "an older document is refused");
  assert.equal(stale.code, "ROLLBACK");
  assert.equal(seenActor(v5.document.body.id, storage).seq, 5, "a refused document never moves the mark");

  assert.equal(check(v6.document).ok, true, "a newer version is accepted");
  assert.equal(seenActor(v5.document.body.id, storage).seq, 6);

  assert.equal(check(v5.document).ok, false, "once a newer version is known, the older one can't come back");
  assert.equal(seenActor(v5.document.body.id, storage).seq, 6);
});

test("checking an address end to end never claims a move happened", async () => {
  const result = await checkDestination("https://friend.example.org/", { read: async () => siteDoc() });
  assert.equal(result.host, "friend.example.org");
  assert.equal(result.ok, true);
  assert.equal(result.doc.name, "Friend");
  assert.ok(!("move" in result) && !("migrated" in result), "preparation returns a report, nothing more");
});