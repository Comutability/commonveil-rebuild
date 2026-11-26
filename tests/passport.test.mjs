// The experimental archive is deliberately a read-only feature.
// These tests cover signing, ciphertext integrity, recovery-secret matching and malformed input.
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { createServer } from "vite";
import { entropyToMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";

let vite;
let passport;

before(async () => {
  vite = await createServer({
    configFile: false,
    resolve: { alias: [{ find: "@/", replacement: resolve("src") + "/" }] },
    server: { middlewareMode: true },
    appType: "custom",
    logLevel: "silent",
  });
  passport = await vite.ssrLoadModule("/src/lib/identity/passport.js");
});

after(async () => {
  await vite?.close();
});

const first = entropyToMnemonic(new Uint8Array(32).fill(5), wordlist);
const wrong = entropyToMnemonic(new Uint8Array(32).fill(8), wordlist);
const data = {
  format: "commonveil-export-1",
  conversations: [
    {
      kind: "direct message",
      members: [
        { user_id: "self", username: "alice", you: true },
        { user_id: "other", username: "bob", display_name: "Bob" },
      ],
      messages: [
        { from: "Bob", text: "Only the owner should read this", sent: "2026-11-23T12:00:00Z" },
      ],
    },
  ],
};

const make = async () => passport.buildPassport({
  phrase: first, handle: "@alice@site-a.example", home: "site-a.example",
  userId: "self", profile: { username: "alice" }, data,
});

test("the archive signs the ciphertext and opens with the matching secret", async () => {
  const doc = await make();
  assert.equal(doc.format, "commonveil-passport-2");
  assert.equal(doc.record.sig.alg, "Ed25519+ML-DSA-65");
  assert.equal(passport.verifyPassport(doc).ok, true);
  const opened = await passport.openPassport(doc, first);
  assert.equal(opened.contacts.length, 1);
  assert.equal(opened.contacts[0].username, "bob");
  assert.deepEqual(opened.data, data);
  assert.equal(JSON.stringify(doc).includes("Only the owner should read this"), false);
  // Look for the plaintext as it would appear, not three bare letters: random base64 ciphertext
  // contains "Bob" by chance about once in every 25 archives of this size.
  assert.equal(JSON.stringify(doc).includes('"display_name":"Bob"'), false);
  assert.equal(JSON.stringify(doc).includes('\\"display_name\\":\\"Bob\\"'), false);
});

test("modifying signed contents, removing PQ signature or altering ciphertext is refused", async () => {
  const doc = await make();
  const flip = (x) => structuredClone(x);
  const bodyChange = flip(doc);
  bodyChange.record.body.profile.username = "mallory";
  assert.equal(passport.verifyPassport(bodyChange).ok, false);
  const noPq = flip(doc);
  delete noPq.record.sig.pq;
  assert.equal(passport.verifyPassport(noPq).ok, false);
  const ctChanged = flip(doc);
  ctChanged.sealed.archive.ct = ctChanged.sealed.archive.ct.slice(0, -1) + (ctChanged.sealed.archive.ct.endsWith("A") ? "B" : "A");
  assert.equal(passport.verifyPassport(ctChanged).ok, false);
  const invalidKey = flip(doc);
  invalidKey.record.body.owner.hybrid = null;
  assert.equal(passport.verifyPassport(invalidKey).ok, false);
});

test("an unrelated recovery phrase cannot unlock a valid archive", async () => {
  const doc = await make();
  await assert.rejects(() => passport.openPassport(doc, wrong), { code: "WRONG_PHRASE" });
});

test("unsupported or malformed identity files are refused", () => {
  assert.throws(() => passport.readPassport('{"format":"commonveil-passport-1"}'), { code: "MALFORMED" });
  assert.throws(() => passport.readPassport("not JSON"), { code: "MALFORMED" });
  assert.throws(() => passport.readPassport("x".repeat(128 * 1024 * 1024 + 1)), { code: "TOO_LARGE" });
});
