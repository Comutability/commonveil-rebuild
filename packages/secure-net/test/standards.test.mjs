import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { checkStandards } from "../scripts/standards.mjs";
import { signedRecordVectors, vectors } from "../scripts/vectors.mjs";

test("the code, the registries and the part documents agree (CVP-000)", async () => {
  const { problems } = await checkStandards();
  assert.deepEqual(problems, []);
});

test("the code matches the published CVP-002 vectors", async () => {
  const published = JSON.parse(fs.readFileSync(new URL("../spec/vectors/cvp-002-v1.json", import.meta.url), "utf8"));
  assert.deepEqual(await signedRecordVectors(), published);
  assert.ok(published.canonical.length >= 5 && published.mustRefuse.length >= 5);
});

test("vector scripts are deterministic", async () => {
  assert.deepEqual(await vectors(), await vectors());
  assert.deepEqual(await signedRecordVectors(), await signedRecordVectors());
});

test("session label purposes outside the registry are refused at run time", async () => {
  const { PURPOSES, messageKeys } = await import("../src/session/primitives.js");
  assert.ok(PURPOSES.includes("message"));
  assert.throws(() => messageKeys(new Uint8Array(32), "made-up"), /isn't a registered label/);
});
