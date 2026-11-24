import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import {
  encryptMigrationReport, decryptMigrationReport, MigrationReportError,
} from "../src/lib/identity/migrationReport.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const context = {
  actorId: "x".repeat(22),
  stageId: "a".repeat(24),
  destination: "destination.example",
  ciphertextRoot: "A".repeat(43),
  recipientDeviceId: "d".repeat(22),
};
const report = {
  version: 1,
  summary: { readableMessages: 17, missingMessages: 3, stagedAttachments: 2 },
  privateMissingRecordIds: ["private-message-123", "missing-file-123"],
};
const key = () => crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
);
const enc = (recipientKey, ctx = context, r = report) =>
  encryptMigrationReport({ report: r, recipientKey, context: ctx });
const dec = (ciphertext, recipientKey, ctx = context) =>
  decryptMigrationReport({ ciphertext, recipientKey, context: ctx });

test("private reconciliation is authenticated to an independent actor and device", async () => {
  const recipientKey = await key();
  assert.equal(recipientKey.extractable, false);
  const ciphertext = await enc(recipientKey);
  assert.ok(ciphertext instanceof Uint8Array);
  assert.ok(ciphertext.length > 48);
  assert.ok(ciphertext.length <= 64 * 1024);
  assert.equal(new TextDecoder().decode(ciphertext).includes("private-message-123"), false);
  assert.deepEqual(await dec(ciphertext, recipientKey), report);
  const next = await enc(recipientKey);
  assert.notDeepEqual(next, ciphertext, "fresh GCM nonces must produce distinct ciphertext");
});

test("an unauthorised device or another actor, destination or stage cannot open the report", async () => {
  const recipientKey = await key();
  const ciphertext = await enc(recipientKey);
  await assert.rejects(dec(ciphertext, await key()), { code: "AUTH_FAILED" });
  for (const [field, value] of [
    ["actorId", "b".repeat(22)],
    ["stageId", "b".repeat(24)],
    ["destination", "elsewhere.example"],
    ["recipientDeviceId", "z".repeat(22)],
    ["ciphertextRoot", "C".repeat(43)],
  ]) {
    await assert.rejects(dec(ciphertext, recipientKey, { ...context, [field]: value }), { code: "AUTH_FAILED" });
  }
});

test("ciphertext tampering, invalid format and oversized private reports fail closed", async () => {
  const recipientKey = await key();
  const ciphertext = await enc(recipientKey);
  const changed = ciphertext.slice();
  changed[changed.length - 1] ^= 1;
  await assert.rejects(dec(changed, recipientKey), { code: "AUTH_FAILED" });
  const badVersion = ciphertext.slice();
  badVersion[0] ^= 1;
  await assert.rejects(dec(badVersion, recipientKey), { code: "BAD_REPORT" });
  await assert.rejects(dec(new Uint8Array(6), recipientKey), { code: "BAD_REPORT" });
  await assert.rejects(dec(new Uint8Array(65537), recipientKey), { code: "BAD_REPORT" });
  await assert.rejects(enc(recipientKey, context, { version: 1, data: "a".repeat(65536) }),
    { code: "REPORT_SIZE_LIMIT" });
  await assert.rejects(enc(recipientKey, context, { version: 2 }),
    { code: "BAD_REPORT" });
});

test("key export and malformed destination bindings are rejected", async () => {
  const extractable = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
  );
  await assert.rejects(enc(extractable), { code: "KEY_REQUIRED" });
  const wrongKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 128 }, false, ["encrypt", "decrypt"]
  );
  await assert.rejects(enc(wrongKey), { code: "KEY_REQUIRED" });
  const recipientKey = await key();
  for (const [field, value] of [
    ["destination", "localhost"],
    ["destination", "127.0.0.1"],
    ["destination", "site..example"],
    ["actorId", ""],
    ["stageId", ""],
    ["ciphertextRoot", "bad"],
  ]) {
    await assert.rejects(enc(recipientKey, { ...context, [field]: value }), {
      code: "BAD_CONTEXT",
    });
  }
});
