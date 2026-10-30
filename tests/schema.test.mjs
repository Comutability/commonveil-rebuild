// Checks on the entity schemas themselves.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const DIR = path.resolve("base44/entities");
// Fields Base44 adds to every record. A schema property with one of these names is stored, but
// queries and field lists use the platform's own value instead, so a filter on it never matches.
const BUILT_IN = new Set(["id", "created_date", "updated_date", "created_by", "created_by_id", "is_sample"]);

/** JSONC: drop comments (none of these files has "//" or "/*" inside a string). */
const parse = (text) => JSON.parse(text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, ""));

const schemas = fs
  .readdirSync(DIR)
  .filter((f) => f.endsWith(".jsonc") && f !== "User.jsonc")
  .map((f) => [f, parse(fs.readFileSync(path.join(DIR, f), "utf8"))]);

test("no entity defines a field Base44 already adds to every record", () => {
  assert.ok(schemas.length >= 10);
  for (const [file, schema] of schemas) {
    const clashes = Object.keys(schema.properties || {}).filter((k) => BUILT_IN.has(k));
    assert.deepEqual(clashes, [], `${file} defines ${clashes.join(", ")}`);
  }
});

test("member data is reachable only through the backend functions", () => {
  const PUBLIC_CONTENT = new Set(["BlogPost", "Guide", "LearningPath", "Resource", "WikiPage"]);
  for (const [file, schema] of schemas) {
    if (PUBLIC_CONTENT.has(schema.name)) continue;
    assert.deepEqual(schema.rls, { read: false, create: false, update: false, delete: false }, `${file} must be closed to direct access`);
  }
});

test("every required field is a defined field", () => {
  for (const [file, schema] of schemas) {
    for (const field of schema.required || []) assert.ok(field in (schema.properties || {}), `${file} requires undefined field ${field}`);
  }
});
