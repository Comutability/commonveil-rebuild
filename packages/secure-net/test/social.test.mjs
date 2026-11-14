import test from "node:test";
import assert from "node:assert/strict";
import { createAccount, createDevice, signDeviceList, devicePublic } from "../src/session/keys.js";
import { generateSigningKey, sign } from "../src/core/signed.js";
import { canonicalJson } from "../src/core/canonical.js";
import {
  parseHandle, createActorDocument, verifyActorDocument, actorIdOf, deviceKeyAt, discoveryUrl,
  signActivity, verifyActivity, activityProblems, newId, publicEnvelope, envelopeProblems,
  openDirectPayload, createAudience, addMembers, removeMembers, sealToAudience, openAudience,
  readDeliveryBody, MemoryNetwork, ReferenceSite, SocialClient, PUBLIC, FOLLOWERS,
} from "../src/social/index.js";
import { acceptDistribution } from "../src/session/group.js";
import { signRequest, digestOf } from "../src/wire/federation.js";

const code = (fn) => {
  try {
    fn();
    return null;
  } catch (e) {
    return e.code;
  }
};
const acode = (p) => p.then(() => null, (e) => e.code);
const utf8 = (s) => new TextEncoder().encode(s);

function actor(handle = "alice@a.example", nDevices = 1) {
  const account = createAccount();
  const devices = Array.from({ length: nDevices }, () => createDevice());
  const list = signDeviceList(account, devices, { seq: 1 });
  const record = createActorDocument(account, { handle, name: "Alice", devices: list, seq: 1 });
  return { account, devices, list, record, body: verifyActorDocument(record), id: actorIdOf(account.publicKey) };
}

test("handles parse to a name and host, and nothing else does", () => {
  assert.deepEqual(parseHandle("@Alice@A.Example"), { name: "alice", host: "a.example", handle: "alice@a.example" });
  assert.equal(parseHandle("alice"), null);
  assert.equal(parseHandle("a@b@c"), null);
  assert.equal(parseHandle("alice@-bad-.example"), null);
  assert.equal(parseHandle("Al ice@a.example"), null);
  assert.equal(discoveryUrl("@alice@a.example"), "https://a.example/.well-known/commonveil/actor?handle=alice");
});

test("actor documents are self-certifying, quantum-resistant and only move forward", () => {
  const a = actor();
  assert.equal(a.body.id, a.id);
  // Anyone altering it, or claiming someone else's id, is caught.
  assert.equal(code(() => verifyActorDocument({ ...a.record, body: { ...a.body, name: "Mallory" } })), "UNTRUSTED");
  const m = actor("mallory@a.example");
  assert.equal(code(() => verifyActorDocument({ ...m.record, body: { ...m.body, id: a.id } })), "UNTRUSTED");
  assert.equal(code(() => verifyActorDocument(a.record, { id: m.id })), "UNTRUSTED");
  assert.equal(code(() => verifyActorDocument(a.record, { handle: "alice@b.example" })), "UNTRUSTED");
  // Classical account keys can't make actors.
  const classical = generateSigningKey();
  assert.equal(code(() => createActorDocument(classical, { handle: "c@a.example", devices: a.list, seq: 1 })), "BAD_INPUT");
  const forged = sign("actor.document", { ...a.body, account: classical.publicKey, id: actorIdOf(classical.publicKey) }, classical);
  assert.equal(code(() => verifyActorDocument(forged)), "UNTRUSTED");
  // Someone else's device list can't be passed off as yours.
  assert.equal(code(() => createActorDocument(a.account, { handle: "alice@a.example", devices: m.list, seq: 2 })), "UNTRUSTED");
  // Rollback.
  const v2 = createActorDocument(a.account, { handle: "alice@a.example", devices: a.list, seq: 2 });
  assert.equal(verifyActorDocument(v2, { minSeq: 2 }).seq, 2);
  assert.equal(code(() => verifyActorDocument(a.record, { minSeq: 2 })), "ROLLBACK");
});

test("activities are signed by a device that speaks for the actor at the time", () => {
  const a = actor("alice@a.example", 2);
  const note = signActivity(a.devices[0], a.id, { type: "Create", to: [PUBLIC], object: { type: "Note", content: "hi", mediaType: "text/plain" } }, { now: 1000 });
  assert.equal(verifyActivity(note, a.body, { now: 2000 }).object.content, "hi");
  assert.equal(note.body.object.attributedTo, a.id);
  // Changed after signing, or claiming another actor or device: refused.
  assert.equal(code(() => verifyActivity({ ...note, body: { ...note.body, object: { ...note.body.object, content: "bye" } } }, a.body)), "UNTRUSTED");
  const m = actor("m@a.example");
  assert.equal(code(() => verifyActivity(note, m.body)), "UNTRUSTED");
  assert.equal(code(() => verifyActivity({ ...note, body: { ...note.body, device: a.devices[1].kid } }, a.body)), "UNTRUSTED");
  // Dated in the future.
  const future = signActivity(a.devices[0], a.id, { type: "Like", to: [m.id], object: `${m.id}:abcdefghijklmnop`, published: Date.now() + 3_600_000 });
  assert.equal(code(() => verifyActivity(future, a.body)), "BAD_TIME");
  // Device 0 is removed at t=5000: what it signed before still verifies; after, it doesn't.
  const list2 = signDeviceList(a.account, [a.devices[1]], { seq: 2 });
  const doc2 = verifyActorDocument(createActorDocument(a.account, { handle: "alice@a.example", devices: list2, former: [{ kid: a.devices[0].kid, sign: devicePublic(a.devices[0]).sign, until: 5000 }], seq: 2 }));
  assert.equal(deviceKeyAt(doc2, a.devices[0].kid, 4999), devicePublic(a.devices[0]).sign);
  assert.equal(deviceKeyAt(doc2, a.devices[0].kid, 5000), null);
  assert.ok(verifyActivity(note, doc2, { now: 9000 }));
  const late = signActivity(a.devices[0], a.id, { type: "Create", to: [PUBLIC], object: { type: "Note", content: "after removal" } }, { now: 6000 });
  assert.equal(code(() => verifyActivity(late, doc2, { now: 9000 })), "UNTRUSTED");
});

test("the vocabulary refuses activities that don't make sense", () => {
  const a = actor();
  const b = actor("bob@b.example");
  const base = { actor: a.id, id: newId(a.id), published: 1 };
  const ok = (x, o) => assert.deepEqual(activityProblems({ ...base, ...x }, o), []);
  const bad = (x, re, o) => assert.match(activityProblems({ ...base, ...x }, o).join(" | "), re);
  ok({ type: "Follow", to: [b.id], object: b.id });
  ok({ type: "Like", to: [b.id], object: `${b.id}:abcdefghijklmnop` });
  bad({ type: "Follow", object: b.id }, /must be addressed/);
  bad({ type: "Shout", to: [PUBLIC] }, /isn't registered/);
  bad({ type: "Delete", to: [FOLLOWERS], object: `${b.id}:abcdefghijklmnop` }, /own objects/);
  bad({ type: "Create", to: [PUBLIC], object: { type: "Note", id: `${b.id}:abcdefghijklmnop`, attributedTo: b.id, published: 1 } }, /attributedTo must be the actor/);
  bad({ type: "Create", to: [PUBLIC], object: { type: "Note", id: newId(a.id), attributedTo: a.id, published: 1.5 } }, /integer/);
  bad({ type: "Create", to: [PUBLIC], object: { type: "Note", id: newId(a.id), attributedTo: a.id, published: 1 } }, /public activity isn't encrypted/, { encrypted: true });
  const img = { type: "Image", url: "https://files.a.example/x", mediaType: "image/png", size: 10, sha256: "A".repeat(43) };
  bad({ type: "Create", to: [FOLLOWERS], object: { type: "Note", id: newId(a.id), attributedTo: a.id, published: 1, attachment: [img] } }, /must carry its key/, { encrypted: true });
  bad({ type: "Create", to: [PUBLIC], object: { type: "Note", id: newId(a.id), attributedTo: a.id, published: 1, attachment: [{ ...img, key: "B".repeat(43) }] } }, /key may only appear/);
  bad({ type: "Follow", to: ["https://example.org/users/bob"], object: b.id }, /list of addresses/);
});

test("envelopes carry nothing a site doesn't need, and public ones only public activities", () => {
  const a = actor();
  const pub = signActivity(a.devices[0], a.id, { type: "Create", to: [PUBLIC], object: { type: "Note", content: "hi" } });
  assert.deepEqual(envelopeProblems(publicEnvelope(pub)), []);
  assert.match(envelopeProblems({ ...publicEnvelope(pub), from: a.id }).join(), /Unexpected field from/);
  const priv = signActivity(a.devices[0], a.id, { type: "Create", to: [FOLLOWERS], object: { type: "Note", content: "secret" } }, { encrypted: true });
  assert.equal(code(() => publicEnvelope(priv)), "BAD_INPUT");
  assert.match(envelopeProblems({ v: 1, mode: "direct", device: a.devices[0].kid, message: { v: 1, c: "x" } }).join(), /session tag/);
  assert.equal(code(() => readDeliveryBody({ v: 1, items: [] })), "BAD_MESSAGE");
});

test("audiences: members read, removed members can't read what follows, and keys are bound to their sender", async () => {
  const a = actor();
  const b = actor("bob@b.example");
  let aud = createAudience(a.id);
  let r = addMembers(aud, [{ actor: b.id, device: b.devices[0].kid }]);
  aud = r.audience;
  let view = acceptDistribution(r.send.senderKey, { from: a.devices[0].kid });
  const post = signActivity(a.devices[0], a.id, { type: "Create", to: [FOLLOWERS], object: { type: "Note", content: "one" } }, { encrypted: true });
  let s = await sealToAudience(aud, post);
  aud = s.audience;
  const opened = await openAudience(view, s.envelope);
  view = opened.view;
  assert.equal(verifyActivity(opened.activity, a.body, { encrypted: true }).object.content, "one");
  assert.ok(!JSON.stringify(s.envelope).includes("one\""));
  // Removed: the next envelope uses a new key Bob never received.
  aud = removeMembers(aud, (m) => m.actor === b.id).audience;
  s = await sealToAudience(aud, signActivity(a.devices[0], a.id, { type: "Create", to: [FOLLOWERS], object: { type: "Note", content: "two" } }, { encrypted: true }));
  assert.equal(await acode(openAudience(view, s.envelope)), "BAD_MESSAGE");
  // A key handed over by one device can't be used to pass off another device's activity.
  const other = actor("m@a.example");
  const keyFromMallory = acceptDistribution({ ...r.send.senderKey }, { from: other.devices[0].kid });
  const s2 = await sealToAudience({ ...aud, key: { ...r.audience.key } }, post);
  assert.equal(await acode(openAudience(keyFromMallory, s2.envelope)), "UNTRUSTED");
  // A direct payload claiming to carry a sender key for someone else's audience is refused.
  const foreign = createAudience(other.id);
  const payload = utf8(canonicalJson({ v: 1, senderKeys: [{ type: "sender-key", group: foreign.id, id: foreign.key.id, ck: foreign.key.ck, n: 0, sign: foreign.key.signPk }] }));
  assert.equal(code(() => openDirectPayload(payload, { fromDevice: a.devices[0].kid, fromActor: a.id })), "UNTRUSTED");
  const wrongDevice = utf8(canonicalJson({ v: 1, activity: post }));
  assert.equal(code(() => openDirectPayload(wrongDevice, { fromDevice: b.devices[0].kid, fromActor: a.id })), "UNTRUSTED");
});

test("sites refuse unsigned, altered, replayed and misattributed deliveries", async () => {
  const net = new MemoryNetwork();
  const siteA = new ReferenceSite("a.example");
  const siteB = new ReferenceSite("b.example");
  net.add(siteA);
  net.add(siteB);
  const alice = new SocialClient({ handle: "alice@a.example", network: net }).register();
  const bob = new SocialClient({ handle: "bob@b.example", network: net }).register();
  await bob.follow("@alice@a.example");
  await alice.sync();
  await bob.sync();
  await alice.post("public hello", { to: PUBLIC });
  const req = net.log.map((l) => JSON.parse(l)).filter((r) => r.signature).at(-1);
  assert.equal(await acode(siteB.receive(req)), "REPLAY");
  const fresh = { ...req, nonce: "fresh-nonce-1234" };
  assert.equal(await acode(siteB.receive(fresh)), "UNTRUSTED");
  assert.equal(await acode(siteB.receive({ ...req, nonce: "n2", body: req.body.replace("hello", "HELLO") })), "BAD_REQUEST");
  // Handles are first come: Mallory can't take Alice's.
  const mallory = new SocialClient({ handle: "alice@a.example", network: net });
  assert.throws(() => mallory.register(), (e) => e.code === "TAKEN");
  // Another site can't host Alice, so it can't deliver her public posts as if from her site.
  const evil = new ReferenceSite("evil.example");
  net.add(evil);
  assert.throws(() => evil.publishActor(alice.actorRecord), (e) => e.code === "BAD_INPUT");
  const pub = siteA.publicActivities(alice.id).at(-1);
  assert.equal(pub.body.object.content, "public hello");
  const body = canonicalJson({ v: 1, items: [{ to: bob.id, envelope: publicEnvelope(pub) }] });
  const fields = { method: "POST", to: "b.example", path: "/cvp/v2/deliver", from: "evil.example", date: new Date().toUTCString(), nonce: "evil-nonce-00001", digest: digestOf(body) };
  const forged = { ...fields, signature: signRequest(fields, evil.key.secretKey), body };
  const before = siteB.mailboxes.get(bob.id).length;
  assert.equal(await acode(siteB.receive(forged)), "NOT_FOUND");
  assert.equal(siteB.mailboxes.get(bob.id).length, before, "nothing was stored");
});

test("end to end through two sites: follows, followers-only posts, direct messages, unfollowing", async () => {
  const net = new MemoryNetwork();
  net.add(new ReferenceSite("a.example"));
  net.add(new ReferenceSite("b.example"));
  const alice = new SocialClient({ handle: "alice@a.example", network: net }).register();
  const bob = new SocialClient({ handle: "bob@b.example", network: net }).register();
  const carol = new SocialClient({ handle: "carol@b.example", network: net }).register();
  await bob.follow("alice@a.example");
  assert.deepEqual((await alice.sync()).map((x) => x.kind), ["followed-by"]);
  assert.deepEqual((await bob.sync()).map((x) => x.kind), ["accepted"]);
  assert.ok(bob.following.has(alice.id));
  await alice.post("for followers");
  await alice.post("for Bob", { to: [bob.id] });
  const got = await bob.sync();
  assert.deepEqual(got.map((x) => [x.how, x.content]), [["followers", "for followers"], ["direct", "for Bob"]]);
  assert.deepEqual(await carol.sync(), []);
  await bob.like(got[0].id, alice.id);
  await alice.sync();
  assert.equal(alice.likes.get(got[0].id).size, 1);
  await bob.unfollow(alice.id);
  await alice.sync();
  assert.equal(alice.followers.members.length, 0);
  await alice.post("after");
  assert.deepEqual(await bob.sync(), []);
  const everything = net.log.join("\n");
  // Activity types are searched for as JSON, plain and as escaped inside a request body: a bare
  // word like "Undo" can occur by chance in base64 ciphertext, but a quoted member can't.
  const types = ["Follow", "Like", "Undo", "Accept", "Create"].flatMap((t) => [`"type":"${t}"`, `\\"type\\":\\"${t}\\"`]);
  for (const secret of ["for followers", "for Bob", ...types]) assert.ok(!everything.includes(secret), `${secret} crossed the network in the clear`);
  // The same search does find a public post, so it would catch a leak.
  await carol.follow("alice@a.example");
  await alice.sync();
  await alice.post("out loud", { to: PUBLIC });
  assert.ok(net.log.join("\n").includes(`\\"type\\":\\"Create\\"`));
});

// ---- Repositories, moving and lexicons (the AT Protocol-style parts) ----
import {
  createRepo, appendToRepo, removeFromRepo, exportRepo, verifyRepo, merkleRoot, inclusionProof, verifyInclusion,
  createLexicon, verifyLexicon, extensionProblems, authorityOf, isNsid,
} from "../src/social/index.js";
import { recordId } from "../src/core/signed.js";

test("repositories: anyone can check they hold exactly what the actor published", () => {
  const a = actor();
  const pub = (content, now) => signActivity(a.devices[0], a.id, { type: "Create", to: [PUBLIC], object: { type: "Note", content } }, { now });
  let repo = createRepo(a.id);
  const posts = ["one", "two", "three", "four", "five"].map((c, i) => pub(c, 1000 + i));
  for (const p of posts) repo = appendToRepo(repo, a.devices[0], p, { now: 2000 });
  const out = exportRepo(repo, a.record);
  const checked = verifyRepo(out, { id: a.id });
  assert.equal(checked.commit.seq, 5);
  assert.equal(checked.records.length, 5);
  // A mirror that drops, reorders, alters or adds a record is caught.
  assert.equal(code(() => verifyRepo({ ...out, records: out.records.slice(1) })), "TAMPERED");
  assert.equal(code(() => verifyRepo({ ...out, records: [out.records[1], out.records[0], ...out.records.slice(2)] })), "TAMPERED");
  assert.equal(code(() => verifyRepo({ ...out, records: [...out.records.slice(0, 4), pub("forged", 3000)] })), "TAMPERED");
  // An old head can't be served once a newer one has been seen.
  assert.equal(code(() => verifyRepo(out, { minSeq: 6 })), "ROLLBACK");
  // Someone else can't commit to it, and private activities can't go in.
  const m = actor("m@a.example");
  assert.equal(code(() => verifyRepo({ ...out, head: appendToRepo(createRepo(a.id), m.devices[0], posts[0]).head })), "UNTRUSTED");
  const priv = signActivity(a.devices[0], a.id, { type: "Create", to: [FOLLOWERS], object: { type: "Note", content: "x" } }, { encrypted: true });
  assert.equal(code(() => appendToRepo(repo, a.devices[0], priv)), "BAD_INPUT");
  // Deleting removes the record from what the next commit signs.
  const less = removeFromRepo(repo, a.devices[0], posts[2].body.object.id);
  assert.equal(verifyRepo(exportRepo(less, a.record)).records.length, 4);
  assert.equal(less.head.body.prev, recordId(repo.head));
  // One record can be proved to be in the set without the rest.
  const ids = repo.records.map(recordId);
  for (let i = 0; i < ids.length; i += 1) assert.ok(verifyInclusion(ids[i], i, ids.length, inclusionProof(ids, i), repo.head.body.root));
  assert.ok(!verifyInclusion(ids[0], 1, ids.length, inclusionProof(ids, 1), repo.head.body.root));
  assert.ok(!verifyInclusion(recordId(pub("other", 9)), 0, ids.length, inclusionProof(ids, 0), repo.head.body.root));
  assert.notEqual(merkleRoot([]), merkleRoot([ids[0]]));
});

test("lexicons: new object types by domain, checked when known and readable when not", () => {
  const chef = actor("lexicons@example.org");
  assert.ok(isNsid("org.example.recipe") && !isNsid("recipe") && !isNsid("Org.Example.Recipe"));
  assert.equal(authorityOf("org.example.recipe"), "example.org");
  const lex = createLexicon(chef.account, { id: "org.example.recipe", revision: 1, description: "A recipe", fields: { serves: { type: "integer", min: 1, max: 100, required: true }, ingredients: { type: "array", items: { type: "string", max: 200 }, max: 100, required: true }, vegan: { type: "boolean" } } });
  const l = verifyLexicon(lex, chef.body);
  // Only an actor on the type's own domain can define it.
  const other = actor("eve@evil.example");
  assert.equal(code(() => verifyLexicon(createLexicon(other.account, lex.body), other.body)), "UNTRUSTED");
  assert.equal(code(() => verifyLexicon(lex, other.body)), "UNTRUSTED");
  // Nor can another user of the same site, or anyone altering a published lexicon.
  const user = actor("someone@example.org");
  assert.equal(code(() => verifyLexicon(createLexicon(user.account, lex.body), user.body)), "UNTRUSTED");
  assert.equal(code(() => verifyLexicon({ ...lex, body: { ...lex.body, description: "Changed" } }, chef.body)), "UNTRUSTED");
  assert.equal(code(() => verifyLexicon({ ...lex, sig: createLexicon(user.account, lex.body).sig }, chef.body)), "UNTRUSTED");
  assert.equal(code(() => verifyLexicon(lex, chef.body, { minRevision: 2 })), "ROLLBACK");
  assert.equal(code(() => createLexicon(chef.account, { id: "org.example.bad", revision: 1, fields: { content: { type: "string" } } })), "BAD_INPUT");
  // An extension object is a valid activity for everyone, and its own fields are checked by those who know the lexicon.
  const a = actor();
  const recipe = { type: "org.example.recipe", name: "Dal", content: "Simmer the lentils.", serves: 4, ingredients: ["lentils", "onion"] };
  const act = signActivity(a.devices[0], a.id, { type: "Create", to: [PUBLIC], object: recipe });
  assert.ok(verifyActivity(act, a.body));
  assert.deepEqual(extensionProblems(act.body.object, l), []);
  assert.match(extensionProblems({ ...act.body.object, serves: 0 }, l).join(), /serves isn't a valid integer/);
  assert.match(extensionProblems({ ...act.body.object, ingredients: undefined }, l).join(), /ingredients is required/);
  assert.match(extensionProblems({ ...act.body.object, calories: 5 }, l).join(), /calories isn't in/);
  assert.match(activityProblems({ ...act.body, object: { ...act.body.object, type: "Recipe" } }).join(), /isn't a registered object type/);
});

test("an actor moves to another site and keeps their id, followers, sessions and history", async () => {
  const net = new MemoryNetwork();
  for (const h of ["a.example", "b.example", "c.example"]) net.add(new ReferenceSite(h));
  const alice = new SocialClient({ handle: "alice@a.example", network: net }).register();
  const bob = new SocialClient({ handle: "bob@b.example", network: net }).register();
  await bob.follow("alice@a.example");
  await alice.sync();
  await bob.sync();
  await alice.post("public before the move", { to: PUBLIC });
  await bob.sync();
  const idBefore = alice.id;
  await alice.migrate("alice@c.example");
  assert.equal(alice.id, idBefore);
  assert.deepEqual((await bob.sync()).map((x) => x.kind), ["profile-updated"]);
  assert.equal(bob.known.get(alice.id).handle, "alice@c.example");
  // Followers-only posts still reach Bob, now from the new site, with the same keys.
  await alice.post("after the move");
  assert.deepEqual((await bob.sync()).map((x) => [x.how, x.content]), [["followers", "after the move"]]);
  // The public history came too, and verifies from the new site.
  const repo = verifyRepo(net.site("c.example").repo(alice.id), { id: alice.id });
  assert.equal(repo.records[0].body.object.content, "public before the move");
  assert.throws(() => net.site("a.example").repo(alice.id), (e) => e.code === "NOT_FOUND");
  // A newcomer using the old handle is sent to the new site, and gets the same actor.
  const carol = new SocialClient({ handle: "carol@b.example", network: net }).register();
  assert.equal(carol.lookup("alice@a.example").id, alice.id);
  assert.equal(carol.known.get(alice.id).handle, "alice@c.example");
  // The old site can't hand the old name to someone else, or redirect it to a different actor's forgery.
  assert.throws(() => new SocialClient({ handle: "alice@a.example", network: net }).register(), (e) => e.code === "TAKEN");
  assert.throws(() => net.site("c.example").release(alice.actorRecord), (e) => e.code === "ROLLBACK" || e.code === "BAD_INPUT");
  // Indexers see every commit in the sites' change feeds.
  assert.equal(net.site("a.example").changes().commits.length, 1);
  assert.equal(net.site("c.example").changes(0).commits[0].actor, alice.id);
});
