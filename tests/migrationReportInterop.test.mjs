import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  migrationReportAssociatedData,
  migrationReportCommitment,
  encryptMigrationReport,
  decryptMigrationReport,
} from "../src/lib/identity/migrationReport.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
const vector = JSON.parse(readFileSync(
  new URL("./fixtures/secure-net-transfer-report-v1.json", import.meta.url), "utf8"
));

function contextFromVector() {
  const c = vector.context;
  return {
    actorId: c.actor_id,
    stageId: c.stage_id,
    destination: c.destination,
    ciphertextRoot: c.ciphertext_root,
    recipientDeviceId: c.recipient_device_id,
  };
}

test("Secure Net Rust and browser agree byte-for-byte on transfer AAD", () => {
  const ctx = contextFromVector();
  const aad = migrationReportAssociatedData(ctx);
  assert.equal(new TextDecoder().decode(aad), vector.aad_utf8);
  for (const key of ["actorId", "stageId", "destination", "ciphertextRoot", "recipientDeviceId"]) {
    const changed = { ...ctx, [key]: key === "destination" ? "another.example.org" : "z".repeat(ctx[key].length) };
    assert.notEqual(new TextDecoder().decode(migrationReportAssociatedData(changed)), vector.aad_utf8);
  }
});

test("Secure Net synthetic frame and its digest match browser framing", async () => {
  const synthetic = Buffer.from(vector.synthetic_report_b64url, "base64url");
  const commitment = await migrationReportCommitment(synthetic);
  assert.equal(commitment.sha256, vector.synthetic_report_sha256_b64url);
  assert.equal(commitment.bytes, synthetic.byteLength);
  const badVersion = new Uint8Array(synthetic);
  badVersion[5] = 2;
  await assert.rejects(migrationReportCommitment(badVersion), { code: "BAD_REPORT" });
  await assert.rejects(migrationReportCommitment(new Uint8Array(65537)), { code: "BAD_REPORT" });
});

test("real device-side authenticated encryption matches the shared envelope digest format", async () => {
  const recipientKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
  const ctx = contextFromVector();
  const report = { version: 1, privateMissingRecordIds: ["hidden-message-42"], readable: 9 };
  const bytes = await encryptMigrationReport({ report, recipientKey, context: ctx });
  const commitment = await migrationReportCommitment(bytes);
  assert.equal(commitment.sha256.length, 43);
  assert.equal(commitment.bytes, bytes.length);
  assert.deepEqual(await decryptMigrationReport({ ciphertext: bytes, recipientKey, context: ctx }), report);
  const tampered = bytes.slice();
  tampered[tampered.length - 1] ^= 1;
  assert.notEqual((await migrationReportCommitment(tampered)).sha256, commitment.sha256);
  await assert.rejects(
    decryptMigrationReport({ ciphertext: tampered, recipientKey, context: ctx }),
    { code: "AUTH_FAILED" }
  );
});
