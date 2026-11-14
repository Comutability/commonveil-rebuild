// Test vectors (CVP-000, section 8): fixed inputs and what each must produce. Another
// implementation that matches these agrees with this one byte for byte.
//
//   cvp-002-v1.json  canonical JSON and signed records (Ed25519 and Ed25519 + ML-DSA-65)
//   cvp-016-v1.json  every derivation in the session protocol
//   cvp-017-v1.json  actor documents
//   cvp-018-v1.json  activities: valid and invalid vocabulary, a signed activity
//   cvp-019-v1.json  envelopes, delivery bodies and session tags
//   cvp-020-v1.json  repository Merkle roots, proofs and a commit
//   cvp-021-v1.json  a lexicon and objects judged against it
//
//   node scripts/vectors.mjs           write them
//   node scripts/vectors.mjs --check   fail if the files and the code disagree
import fs from "node:fs";
import path from "node:path";
import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { handshakeSecret, kdfRoot, kdfChain, messageKeys, transcriptHash, seal } from "../src/session/primitives.js";
import { linkCode, safetyNumber } from "../src/session/keys.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { canonicalJson } from "../src/core/canonical.js";
import { signingBytes, keyId, checkSignature, recordId, ALG, HYBRID_ALG } from "../src/core/signed.js";
import { b64u, fromB64u } from "../src/core/bytes.js";
import { verifyActorDocument } from "../src/social/actor.js";
import { verifyActivity } from "../src/social/activity.js";
import { activityProblems } from "../src/social/vocabulary.js";
import { envelopeProblems, sessionTag, readDeliveryBody } from "../src/social/delivery.js";
import { merkleRoot, inclusionProof, verifyInclusion, verifyRepo } from "../src/social/repo.js";
import { verifyLexicon, extensionProblems, authorityOf } from "../src/social/lexicon.js";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const files = {
  "cvp-002-v1.json": () => signedRecordVectors(),
  "cvp-016-v1.json": () => vectors(),
  "cvp-017-v1.json": () => socialVectors().then((v) => v.actors),
  "cvp-018-v1.json": () => socialVectors().then((v) => v.activities),
  "cvp-019-v1.json": () => socialVectors().then((v) => v.delivery),
  "cvp-020-v1.json": () => socialVectors().then((v) => v.repos),
  "cvp-021-v1.json": () => socialVectors().then((v) => v.lexicons),
};
const hex = (b) => Buffer.from(b).toString("hex");
const seq = (start, n = 32) => Uint8Array.from({ length: n }, (_, i) => (start + i) & 0xff);
const utf8 = (s) => new TextEncoder().encode(s);

export async function vectors() {
  const aSk = seq(0x01);
  const bSk = seq(0x41);
  const kemSeed = seq(0x81, 64);
  const coins = seq(0xc1);
  const { publicKey: kemPk } = ml_kem768.keygen(kemSeed);
  const enc = ml_kem768.encapsulate(kemPk, coins);
  const transcript = { v: 1, initiator: { account: "A", device: "a1", sign: "As", dh: "Ad" }, responder: { account: "B", device: "b1", sign: "Bs", dh: "Bd" }, ek: "E", ct: "C", signed: "s", pq: "p", oneTime: null };
  const th = transcriptHash(transcript);
  const dhs = [seq(0x10), seq(0x30), seq(0x50), seq(0x70)];
  const ss = seq(0x90);
  const root1 = kdfRoot(seq(0x00), seq(0x20), seq(0x40));
  const root0 = kdfRoot(seq(0x00), seq(0x20));
  const chain = kdfChain(seq(0x60));
  const mkeys = messageKeys(chain.mk);
  return {
    description: "CVP-016 session protocol, version 1. All byte strings are hex. seq(s, n) means the n bytes s, s+1, s+2, ... (mod 256).",
    x25519: { aSecret: hex(aSk), bSecret: hex(bSk), aPublic: hex(x25519.getPublicKey(aSk)), bPublic: hex(x25519.getPublicKey(bSk)), shared: hex(x25519.getSharedSecret(aSk, x25519.getPublicKey(bSk))) },
    mlkem768: { seed: hex(kemSeed), coins: hex(coins), publicKeySha256: hex(sha256(kemPk)), cipherTextSha256: hex(sha256(enc.cipherText)), sharedSecret: hex(enc.sharedSecret) },
    transcript: { input: transcript, hash: hex(th) },
    handshake: { dh: dhs.map(hex), mlkem: hex(ss), transcriptHash: hex(th), secret: hex(handshakeSecret(dhs, ss, th)), threeDh: hex(handshakeSecret(dhs.slice(0, 3), ss, th)) },
    root: { rk: hex(seq(0x00)), dh: hex(seq(0x20)), mlkem: hex(seq(0x40)), out: { rk: hex(root1.rk), ck: hex(root1.ck) }, withoutMlkem: { rk: hex(root0.rk), ck: hex(root0.ck) } },
    chain: { ck: hex(seq(0x60)), mk: hex(chain.mk), next: hex(chain.ck) },
    message: { mk: hex(chain.mk), key: hex(mkeys.key), iv: hex(mkeys.iv), plaintext: "secure-net", ad: hex(utf8("ad")), ciphertext: hex(await seal(chain.mk, utf8("secure-net"), utf8("ad"))) },
    codes: { linkCode: linkCode({ sign: "S", dh: "D" }), safetyNumber: safetyNumber("A", "B") },
  };
}


/** CVP-002: canonical JSON, and signed records with a classical and a quantum-resistant key. */
export async function signedRecordVectors() {
  const canonical = [
    { name: "keys sorted by UTF-16 code unit, no whitespace", json: '{"z":1,"a":[3,2,1],"B":{"y":null,"x":true}}' },
    { name: "non-ASCII keys sort after ASCII; astral characters by their surrogates", json: '{"\\uffff":1,"\\ud83d\\ude00":2,"\\u00e9":3,"a":4,"B":5}' },
    { name: "strings: only quote, backslash and control characters are escaped; other text is raw UTF-8", json: '{"s":"line\\nbreak\\ttab \\u0007 \\"q\\" \\\\ / \\u00e9 \\u2028 \\ud83d\\ude00"}' },
    { name: "integers in the safe range; negative zero becomes 0", json: '[0,-0,9007199254740991,-9007199254740991,true,false,null,""]' },
    { name: "empty containers", json: '{"a":{},"b":[]}' },
  ].map((c) => {
    const text = canonicalJson(JSON.parse(c.json));
    return { ...c, canonical: text, canonicalUtf8: hex(utf8(text)) };
  });
  const refused = [
    { name: "a fraction", json: "1.5" },
    { name: "a number past 2^53 - 1", json: "9007199254740992" },
    { name: "an exponent that isn't a safe integer", json: "1e300" },
    { name: "a lone surrogate", json: '"\\ud800"' },
  ].map((c) => {
    try {
      canonicalJson(JSON.parse(c.json));
      throw new Error(`${c.name} was accepted`);
    } catch (e) {
      if (e.code !== "NOT_CANONICAL") throw e;
      return { ...c, result: "refused" };
    }
  });

  const kind = "example.note";
  const body = { text: "Built together. Open to everyone.", n: 7, tags: ["a", "b"] };
  const bytes = signingBytes(kind, body);

  const edSecret = seq(0x21);
  const edPub = b64u(ed25519.getPublicKey(edSecret));
  const classical = { kind, body, sig: { kid: keyId(edPub), alg: ALG, value: b64u(ed25519.sign(bytes, edSecret)) } };

  const pqSeed = seq(0x61);
  const pq = ml_dsa65.keygen(pqSeed);
  const hybridPub = `${edPub}.${b64u(pq.publicKey)}`;
  const hybrid = { kind, body, sig: { kid: keyId(hybridPub), alg: HYBRID_ALG, value: classical.sig.value, pq: b64u(ml_dsa65.sign(bytes, pq.secretKey, { extraEntropy: false })) } };
  for (const [r, k] of [[classical, edPub], [hybrid, hybridPub]]) if (!checkSignature(r, r.sig, k)) throw new Error("vector doesn't verify");

  const { pq: _drop, ...stripped } = hybrid.sig;
  const mustRefuse = [
    { name: "body changed after signing", record: { ...classical, body: { ...body, n: 8 } }, publicKey: edPub },
    { name: "same signature presented as another kind", record: { ...classical, kind: "example.other" }, publicKey: edPub },
    { name: "quantum-resistant key, ML-DSA-65 signature removed", record: { ...hybrid, sig: { ...stripped, alg: ALG } }, publicKey: hybridPub },
    { name: "quantum-resistant key, ML-DSA-65 signature from a different body", record: { ...hybrid, sig: { ...hybrid.sig, pq: b64u(ml_dsa65.sign(signingBytes(kind, { ...body, n: 8 }), pq.secretKey, { extraEntropy: false })) } }, publicKey: hybridPub },
    { name: "key id that isn't the hash of the key", record: { ...classical, sig: { ...classical.sig, kid: keyId(hybridPub) } }, publicKey: edPub },
  ];
  for (const m of mustRefuse) if (checkSignature(m.record, m.record.sig, m.publicKey)) throw new Error(`${m.name} was accepted`);

  return {
    description: "CVP-002 canonical JSON and signed records, version 1. Byte strings are hex unless a field says base64url. json fields are JSON texts to parse first. seq(s, n) means the n bytes s, s+1, ... (mod 256). ML-DSA-65 is FIPS 204 ML-DSA.Sign with an empty context; these signatures were made deterministically so they can be reproduced, but implementations may sign with randomness (hedged), so check by verifying, not by comparing.",
    canonical,
    refused,
    signingBytes: { kind, body, layout: "the label secure-net/<kind>/v1 in UTF-8, the byte 0x0a, then the canonical JSON of the body", label: `secure-net/${kind}/v1`, hex: hex(bytes) },
    classical: { secretKey: hex(edSecret), publicKey: edPub, record: classical, recordId: recordId(classical) },
    hybrid: { ed25519Secret: hex(edSecret), mldsa65Seed: hex(pqSeed), publicKey: hybridPub, record: hybrid, recordId: recordId(hybrid) },
    mustRefuse,
  };
}


/** A quantum-resistant key from fixed seeds, and a signer that doesn't use randomness (vectors only). */
function fixedKey(edSeed, pqSeed) {
  const pq = ml_dsa65.keygen(pqSeed);
  const publicKey = `${b64u(ed25519.getPublicKey(edSeed))}.${b64u(pq.publicKey)}`;
  return { kid: keyId(publicKey), publicKey, edSecret: edSeed, pqSecret: pq.secretKey };
}
function fixedSign(kind, body, k) {
  const bytes = signingBytes(kind, body);
  return { kind, body, sig: { kid: k.kid, alg: HYBRID_ALG, value: b64u(ed25519.sign(bytes, k.edSecret)), pq: b64u(ml_dsa65.sign(bytes, k.pqSecret, { extraEntropy: false })) } };
}
const refused = (fn) => {
  try {
    fn();
    return null;
  } catch (e) {
    return e.code || "refused";
  }
};

/** CVP-017, 018 and 019. */
export async function socialVectors() {
  const T = 1_800_000_000_000;
  const account = fixedKey(seq(0x01), seq(0x11));
  const device = fixedKey(seq(0x21), seq(0x31));
  const dhPub = b64u(x25519.getPublicKey(seq(0x41)));
  const list = fixedSign("session.device-list", { account: account.publicKey, devices: [{ kid: device.kid, sign: device.publicKey, dh: dhPub }], seq: 1, issued: T }, account);
  const id = keyId(account.publicKey);
  const actorBody = { v: 1, type: "Person", id, handle: "alice@a.example", account: account.publicKey, seq: 1, devices: list, former: [], discoverable: true, updated: T, name: "Alice" };
  const actor = fixedSign("actor.document", actorBody, account);
  const actorChecked = verifyActorDocument(actor, { handle: "alice@a.example" });
  const other = fixedKey(seq(0x51), seq(0x61));
  const actorRefuse = [
    { name: "name changed after signing", record: { ...actor, body: { ...actorBody, name: "Mallory" } } },
    { name: "id isn't the account key's id", record: fixedSign("actor.document", { ...actorBody, id: keyId(other.publicKey) }, account) },
    { name: "signed by another key", record: fixedSign("actor.document", actorBody, other) },
    { name: "a device list signed by another account", record: fixedSign("actor.document", { ...actorBody, devices: fixedSign("session.device-list", list.body, other) }, account) },
    { name: "looked up as a different handle", record: actor, lookup: "bob@a.example" },
    { name: "older than one already seen (seen seq 2)", record: actor, minSeq: 2 },
  ].map((c) => {
    const r = refused(() => verifyActorDocument(c.record, { handle: c.lookup, minSeq: c.minSeq }));
    if (!r) throw new Error(`${c.name} was accepted`);
    return { ...c, result: "refused" };
  });

  const note = { type: "Create", id: `${id}:AAAAAAAAAAAAAAAAAAAAAA`, actor: id, device: device.kid, published: T + 1000, to: ["public"], cc: ["followers"],
    object: { type: "Note", id: `${id}:BBBBBBBBBBBBBBBBBBBBBB`, attributedTo: id, published: T + 1000, content: "Built together. Open to everyone.", mediaType: "text/plain" } };
  const signedNote = fixedSign("social.activity", note, device);
  verifyActivity(signedNote, actorChecked, { now: T + 2000 });
  const bob = keyId(other.publicKey);
  const examples = [
    { name: "public Note", activity: note, encrypted: false, valid: true },
    { name: "followers-only Note with an encrypted image", encrypted: true, valid: true, activity: { ...note, to: ["followers"], cc: undefined, object: { ...note.object, attachment: [{ type: "Image", url: "https://files.a.example/1", mediaType: "image/jpeg", size: 1024, sha256: "C".repeat(43), key: "D".repeat(43), name: "A heron" }] } } },
    { name: "Follow", encrypted: true, valid: true, activity: { type: "Follow", id: `${id}:EEEEEEEEEEEEEEEEEEEEEE`, actor: id, published: T, to: [bob], object: bob } },
    { name: "Like", encrypted: true, valid: true, activity: { type: "Like", id: `${id}:FFFFFFFFFFFFFFFFFFFFFF`, actor: id, published: T, to: [bob], object: `${bob}:GGGGGGGGGGGGGGGGGGGGGG` } },
    { name: "Question (poll)", encrypted: false, valid: true, activity: { ...note, object: { type: "Question", id: `${id}:HHHHHHHHHHHHHHHHHHHHHH`, attributedTo: id, published: T, name: "Which day?", oneOf: [{ type: "Note", name: "Thursday" }, { type: "Note", name: "Friday" }], endTime: T + 86_400_000 } } },
    { name: "unregistered type", encrypted: false, valid: false, activity: { ...note, type: "Shout" } },
    { name: "not addressed", encrypted: false, valid: false, activity: { ...note, to: [], cc: [] } },
    { name: "public but sent encrypted", encrypted: true, valid: false, activity: note },
    { name: "fractional time", encrypted: false, valid: false, activity: { ...note, published: 1.5 } },
    { name: "object attributed to someone else", encrypted: false, valid: false, activity: { ...note, object: { ...note.object, attributedTo: bob } } },
    { name: "deleting someone else's object", encrypted: true, valid: false, activity: { type: "Delete", id: `${id}:IIIIIIIIIIIIIIIIIIIIII`, actor: id, published: T, to: ["followers"], object: `${bob}:GGGGGGGGGGGGGGGGGGGGGG` } },
    { name: "id not owned by the actor", encrypted: false, valid: false, activity: { ...note, id: `${bob}:AAAAAAAAAAAAAAAAAAAAAA` } },
    { name: "URL addresses (ActivityPub style) aren't addresses here", encrypted: true, valid: false, activity: { type: "Follow", id: `${id}:JJJJJJJJJJJJJJJJJJJJJJ`, actor: id, published: T, to: ["https://b.example/users/bob"], object: bob } },
    { name: "image key in a public post", encrypted: false, valid: false, activity: { ...note, object: { ...note.object, attachment: [{ type: "Image", url: "https://files.a.example/1", mediaType: "image/jpeg", size: 1, sha256: "C".repeat(43), key: "D".repeat(43) }] } } },
  ].map((e) => {
    const a = JSON.parse(JSON.stringify(e.activity));
    const ok = activityProblems(a, { encrypted: e.encrypted }).length === 0;
    if (ok !== e.valid) throw new Error(`vector "${e.name}" should be ${e.valid ? "valid" : "invalid"}`);
    return { name: e.name, encrypted: e.encrypted, valid: e.valid, activity: a };
  });

  const ad = b64u(seq(0x70));
  const tag = sessionTag({ ad });
  const publicEnv = { v: 1, mode: "public", activity: signedNote };
  const envs = [
    { name: "public", envelope: publicEnv, valid: true },
    { name: "direct", valid: true, envelope: { v: 1, mode: "direct", device: device.kid, session: tag, message: { v: 1, h: { dh: b64u(seq(0x80)), kem: "A", pn: 0, n: 0 }, c: "AA" } } },
    { name: "audience", valid: true, envelope: { v: 1, mode: "audience", audience: `${id}:KKKKKKKKKKKKKKKKKKKKKK`, message: { v: 1, group: `${id}:KKKKKKKKKKKKKKKKKKKKKK`, id: "LLLLLLLLLLLL", n: 0, c: "AA", sig: "AA" } } },
    { name: "public envelope with a followers-only activity", valid: false, envelope: { ...publicEnv, activity: { ...signedNote, body: { ...note, to: ["followers"], cc: [] } } } },
    { name: "extra field (sender) on an envelope", valid: false, envelope: { ...publicEnv, from: id } },
    { name: "direct without a session tag", valid: false, envelope: { v: 1, mode: "direct", device: device.kid, message: { v: 1, c: "AA" } } },
    { name: "unknown mode", valid: false, envelope: { v: 1, mode: "broadcast" } },
  ].map((e) => {
    const ok = envelopeProblems(e.envelope).length === 0;
    if (ok !== e.valid) throw new Error(`envelope vector "${e.name}" wrong`);
    return e;
  });
  const delivery = { v: 1, items: [{ to: bob, envelope: publicEnv }] };
  readDeliveryBody(delivery);

  // CVP-020
  const ids = ["a", "b", "c", "d", "e"].map((x) => `record-${x}`);
  const roots = [0, 1, 2, 3, 4, 5].map((n) => ({ ids: ids.slice(0, n), root: merkleRoot(ids.slice(0, n)) }));
  const proofs = [0, 2, 4].map((i) => ({ index: i, id: ids[i], count: 5, proof: inclusionProof(ids, i), root: merkleRoot(ids) }));
  for (const p of proofs) if (!verifyInclusion(p.id, p.index, p.count, p.proof, p.root)) throw new Error("proof vector doesn't verify");
  const commitBody = { v: 1, actor: id, device: device.kid, seq: 1, prev: null, root: merkleRoot([recordId(signedNote)]), count: 1, at: T + 1500 };
  const head = fixedSign("repo.commit", commitBody, device);
  const repo = { v: 1, actor, head, records: [signedNote] };
  verifyRepo(repo, { id, now: T + 2000 });
  const repoRefuse = [
    { name: "a record removed", repo: { ...repo, records: [] } },
    { name: "commit signed by a key that isn't the actor's device", repo: { ...repo, head: fixedSign("repo.commit", commitBody, other) } },
    { name: "root for a different set", repo: { ...repo, head: fixedSign("repo.commit", { ...commitBody, root: merkleRoot(["x"]) }, device) } },
  ].map((c) => {
    if (!refused(() => verifyRepo(c.repo, { id, now: T + 2000 }))) throw new Error(`${c.name} was accepted`);
    return { ...c, result: "refused" };
  });

  // CVP-021
  const chefBody = { ...actorBody, handle: "lexicons@example.org" };
  const chef = verifyActorDocument(fixedSign("actor.document", chefBody, account));
  const lexBody = { v: 1, id: "org.example.recipe", revision: 1, description: "A recipe", fields: { serves: { type: "integer", min: 1, max: 100, required: true }, ingredients: { type: "array", items: { type: "string", max: 200 }, max: 100, required: true }, vegan: { type: "boolean" } } };
  const lexicon = fixedSign("lexicon.schema", lexBody, account);
  verifyLexicon(lexicon, chef);
  if (!refused(() => verifyLexicon(lexicon, actorChecked))) throw new Error("lexicon accepted from the wrong domain");
  const notPublisher = fixedSign("actor.document", { ...actorBody, handle: "someone@example.org" }, account);
  if (!refused(() => verifyLexicon(lexicon, verifyActorDocument(notPublisher)))) throw new Error("lexicon accepted from an ordinary user of the domain");
  const recipe = { type: "org.example.recipe", id: `${id}:MMMMMMMMMMMMMMMMMMMMMM`, attributedTo: id, published: T, name: "Dal", content: "Simmer the lentils.", serves: 4, ingredients: ["lentils", "onion"] };
  const lexObjects = [
    { name: "a valid recipe", object: recipe, valid: true },
    { name: "optional field present", object: { ...recipe, vegan: true }, valid: true },
    { name: "required field missing", object: { ...recipe, ingredients: undefined }, valid: false },
    { name: "integer below min", object: { ...recipe, serves: 0 }, valid: false },
    { name: "wrong item type in array", object: { ...recipe, ingredients: ["lentils", 3] }, valid: false },
    { name: "field the lexicon doesn't define", object: { ...recipe, calories: 300 }, valid: false },
  ].map((e) => {
    const o = JSON.parse(JSON.stringify(e.object));
    if ((extensionProblems(o, lexBody).length === 0) !== e.valid) throw new Error(`lexicon vector "${e.name}" wrong`);
    return { name: e.name, valid: e.valid, object: o };
  });

  return {
    repos: {
      description: "CVP-020 repositories, version 1. Merkle hashes: leaf = SHA-256(\"secure-net/repo/v1/leaf\" 0x0a id), node = SHA-256(\"secure-net/repo/v1/node\" 0x0a left right), empty = SHA-256(\"secure-net/repo/v1/empty\" 0x0a); the tree splits at the largest power of two below the count (as RFC 6962). Roots and proofs are base64url. The repository uses the actor and signed activity from cvp-017 and cvp-018.",
      roots,
      proofs,
      repository: { export: repo, now: T + 2000 },
      mustRefuse: repoRefuse,
    },
    lexicons: {
      description: "CVP-021 lexicons, version 1. The lexicon is signed by the account key from cvp-017-v1.json, as the actor lexicons@example.org (publisher). It must be refused when checked against the same key's actor at a.example (cvp-017-v1.json), and against notPublisher (the same key as an ordinary user of example.org).",
      authority: { nsid: "org.example.recipe", domain: authorityOf("org.example.recipe") },
      publisher: fixedSign("actor.document", chefBody, account),
      notPublisher,
      lexicon,
      objects: lexObjects,
    },
    actors: {
      description: "CVP-017 actor documents, version 1. Keys are made from fixed seeds (seq(s, n): bytes s, s+1, ... mod 256); ML-DSA-65 signatures were made without randomness so they can be reproduced, but check them by verifying. Times are milliseconds.",
      keys: { account: { ed25519Seed: hex(seq(0x01)), mldsa65Seed: hex(seq(0x11)), publicKey: account.publicKey, kid: account.kid }, device: { ed25519Seed: hex(seq(0x21)), mldsa65Seed: hex(seq(0x31)), publicKey: device.publicKey, kid: device.kid, x25519Secret: hex(seq(0x41)), x25519Public: dhPub } },
      actor: { record: actor, lookedUpAs: "alice@a.example", actorId: id, recordId: recordId(actor) },
      mustRefuse: actorRefuse,
    },
    activities: {
      description: "CVP-018 activities, version 1. examples: activity bodies with whether they are valid when sent encrypted or not (unsigned; check the vocabulary rules only). signed: a signed activity that verifies against the actor document in cvp-017-v1.json at now.",
      examples,
      signed: { record: signedNote, now: T + 2000, recordId: recordId(signedNote) },
    },
    delivery: {
      description: "CVP-019 envelopes and delivery bodies, version 1. Envelope messages here are placeholders for their shape only: their cryptography is CVP-016's, whose vectors apply.",
      sessionTag: { handshakeHash: hex(seq(0x70)), label: "secure-net/social/v1/session", layout: "SHA-256 of the label, the byte 0x0a and the 32-byte handshake hash; base64url; first 22 characters", tag },
      envelopes: envs,
      deliveryBody: delivery,
    },
  };
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  let failed = false;
  for (const [name, make] of Object.entries(files)) {
    const file = path.join(root, "spec/vectors", name);
    const json = `${JSON.stringify(await make(), null, 2)}\n`;
    if (process.argv.includes("--check")) {
      const same = fs.existsSync(file) && fs.readFileSync(file, "utf8") === json;
      console.log(same ? `${name} matches` : `${name} doesn't match the code`);
      failed ||= !same;
    } else {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, json);
      console.log(`wrote spec/vectors/${name}`);
    }
  }
  process.exit(failed ? 1 : 0);
}
