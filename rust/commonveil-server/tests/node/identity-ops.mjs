// Parity helper (temporary): runs sign-in operations through base44/shared/identity/*.ts, for
// tests/parity.rs to compare with Rust.   node identity-ops.mjs <entities dir> < ops.json
import { Store, loadSchemas } from "../../../../server/store.mjs";
import { checkPassword, hashPassword, hmac, verifyEd25519 } from "../../../../base44/shared/identity/crypto.ts";
import { issueAccess, verifyAccess } from "../../../../base44/shared/identity/sessions.ts";
import { pathToFileURL } from "node:url";

const store = new Store({ file: ":memory:", schemas: loadSchemas(pathToFileURL(process.argv[2].replace(/\/?$/, "/"))) });
const sr = { entities: store.entities };
const ops = JSON.parse(await new Promise((r) => { let s = ""; process.stdin.on("data", (c) => (s += c)); process.stdin.on("end", () => r(s)); }));
const out = [];
for (const o of ops) {
  if (o.op === "seed") { for (const [t, rows] of Object.entries(o.tables)) for (const row of rows) await store.entities[t].create(row); out.push(null); }
  else if (o.op === "checkPassword") out.push(await checkPassword(o.password, o.hash));
  else if (o.op === "hashPassword") out.push(await hashPassword(o.password, o.rounds));
  else if (o.op === "hmac") out.push(await hmac(o.secret, o.text));
  else if (o.op === "verifyAccess") out.push(await verifyAccess(sr, o.token, o.now));
  else if (o.op === "issueAccess") out.push(await issueAccess(sr, o.user, o.device, o.now));
  else if (o.op === "verifyEd25519") out.push(await verifyEd25519(o.key, o.text, o.sig));
}
console.log(JSON.stringify(out));
