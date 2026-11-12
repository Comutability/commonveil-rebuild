// Regression tests for the security review's findings that don't need a whole site
// (docs/SECURITY_REVIEW.md): the verification cache (CV-01), capped reads from other sites
// (CV-17), updates that fail or never finish (CV-19), backup pruning (CV-21), and the updater
// refusing to go backwards. The rest are next to the code they test (identity, servers, functions).
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { createVouchCache } from "../src/lib/secure/vouch.js";
import { readCapped } from "../server/federation/net.mjs";
import { Updates } from "../server/updates.mjs";

test("CV-01: a remembered check is for exactly that record, signer and devices, never for its signature alone", async () => {
  const check = createVouchCache();
  const honest = { chain_id: "c1", generation: 3, commit: "abc", signature: "SIG" };
  const signer = { chain: { head: "h1" }, devices: [{ device_id: "d1", sign_pub: "P1" }] };
  let verified = 0;
  const verify = (ok) => async () => {
    verified += 1;
    return ok;
  };
  assert.equal(await check("g", honest, signer, verify(true)), true);
  assert.equal(await check("g", honest, signer, verify(false)), true, "the same record isn't checked twice");
  assert.equal(verified, 1);
  // A backend swaps in a different commitment under the same signature: checked again, and fails.
  assert.equal(await check("g", { ...honest, commit: "attacker's" }, signer, verify(false)), false);
  // The signer's devices changed (one removed): checked again too.
  assert.equal(await check("g", honest, { ...signer, devices: [] }, verify(false)), false);
  assert.equal(verified, 3);
});

/** A response whose body arrives in chunks, with whatever length header it likes. */
function streamed(sizes, { length = null } = {}) {
  let sent = 0;
  let pulled = 0;
  const body = new ReadableStream({
    pull(c) {
      if (pulled >= sizes.length) return c.close();
      const n = sizes[pulled++];
      sent += n;
      c.enqueue(new Uint8Array(n));
    },
  });
  return { res: new Response(body, { headers: length === null ? {} : { "content-length": String(length) } }), sent: () => sent };
}

test("CV-17: a reply from another site is cut off as soon as it's too big, whatever it claims", async () => {
  const MB = 1024 * 1024;
  const big = streamed(Array(12).fill(MB / 2));
  assert.equal(await readCapped(big.res, 4 * MB), null);
  assert.ok(big.sent() <= 5 * MB, `stopped reading at the limit (read ${big.sent()} bytes, not 6 MB)`);
  const fine = streamed([1000, 2000]);
  assert.equal((await readCapped(fine.res, 4 * MB)).length, 3000);
});

function updatesFor({ fetchImpl, version = "0.20.0" } = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "cv-updates-"));
  const db = new DatabaseSync(path.join(dataDir, "test.db"));
  db.exec("CREATE TABLE t (x)");
  const settings = new Map();
  const store = { db, getSetting: (k, d) => settings.get(k) ?? d, setSetting: (k, v) => settings.set(k, v) };
  const config = { version, dataDir, updaterUrl: "http://updater:8090", updaterToken: "t".repeat(32), updateFeed: "https://example.invalid", updateCheckHours: 6 };
  return { updates: new Updates({ config, store, log: { info() {}, warn() {} }, fetchImpl }), dataDir };
}

test("CV-19: an update that can't be asked for, or fails, doesn't stay 'Updating…'", async () => {
  const down = updatesFor({ fetchImpl: async () => { throw new Error("connect ECONNREFUSED"); } });
  await assert.rejects(() => down.updates.apply("0.21.0"), /Couldn't reach the updater/);
  assert.equal(down.updates.view().applying, null);
  assert.match(down.updates.view().error, /Couldn't reach/);

  // Accepted, then rolled back: the app learns it from the updater and offers another try.
  let job = { busy: true, last: null };
  const calls = [];
  const flaky = updatesFor({
    fetchImpl: async (url) => {
      calls.push(url);
      if (String(url).endsWith("/update")) return new Response(JSON.stringify({ ok: true }), { status: 202 });
      return new Response(JSON.stringify(job), { status: 200 });
    },
  });
  await flaky.updates.apply("0.21.0");
  assert.ok(flaky.updates.view().applying, "updating");
  job = { busy: false, last: { ok: false, version: "0.21.0", error: "didn't start", rolled_back: true, at: new Date(Date.now() + 1000).toISOString() } };
  await flaky.updates.reconcile();
  assert.equal(flaky.updates.view().applying, null);
  assert.match(flaky.updates.view().error, /went back/);
});

test("CV-21: pruning keeps the newest backups by when they were made, including the one just made", () => {
  const { updates, dataDir } = updatesFor({ version: "0.19.0" });
  const dir = path.join(dataDir, "backups");
  fs.mkdirSync(dir, { recursive: true });
  // Older backups whose names sort after the new one as text (0.9 > 0.19).
  for (let i = 0; i < 6; i += 1) {
    const f = path.join(dir, `commonveil-0.9.${i}-to-0.9.${i + 1}.db`);
    fs.writeFileSync(f, "old");
    fs.utimesSync(f, new Date(Date.now() - (10 - i) * 86_400_000), new Date(Date.now() - (10 - i) * 86_400_000));
  }
  const made = updates.backup("0.20.0");
  assert.ok(fs.existsSync(made), "the new backup is kept");
  assert.equal(fs.readdirSync(dir).filter((f) => f.endsWith(".db")).length, 5, "five in all");
  assert.ok(!fs.existsSync(path.join(dir, "commonveil-0.9.0-to-0.9.1.db")), "the oldest went");
});
