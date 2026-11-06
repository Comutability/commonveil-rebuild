// The backend applies each table's row rules in code for Commonveil sign-in (base44/shared/rls.ts),
// from a generated copy. It must match the schema files.
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

test("the generated row rules match base44/entities", () => {
  assert.doesNotThrow(() => execFileSync(process.execPath, ["scripts/build-rules.mjs", "--check"], { stdio: "pipe" }), "run: node scripts/build-rules.mjs");
});
