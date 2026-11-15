// Parity helper (temporary, until the Node.js server is gone): runs a list of store operations
// through server/store.mjs and prints every answer, for tests/parity.rs to compare with Rust.
//   node store-ops.mjs <entities dir> < ops.json
import { Store, loadSchemas } from "../../../../server/store.mjs";
import { pathToFileURL } from "node:url";

const dir = pathToFileURL(process.argv[2].replace(/\/?$/, "/"));
const store = new Store({ file: ":memory:", schemas: loadSchemas(dir) });
const ops = JSON.parse(await new Promise((r) => { let s = ""; process.stdin.on("data", (c) => (s += c)); process.stdin.on("end", () => r(s)); }));
const out = [];
for (const o of ops) {
  try {
    const t = o.as ? store.asPerson(o.as)[o.table] : store.entities[o.table];
    let r;
    if (o.op === "create") r = o.as ? await t.create(o.data) : await t.create(o.data, o.id);
    else if (o.op === "filter") r = await t.filter(o.query, o.sort, o.limit, o.skip);
    else if (o.op === "get") r = await t.get(o.id);
    else if (o.op === "update") r = await t.update(o.id, o.data);
    else if (o.op === "updateMany") r = await t.updateMany(o.query, o.ops);
    else if (o.op === "delete") r = await t.delete(o.id);
    else if (o.op === "deleteMany") r = await t.deleteMany(o.query);
    out.push({ ok: r });
  } catch (e) {
    out.push({ error: e.status || 500 });
  }
}
console.log(JSON.stringify(out));
store.close();
