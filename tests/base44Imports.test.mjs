// Base44 refuses to deploy a backend function whose code imports anything but a literal specifier
// ("`import(...)` with a non-literal specifier is not supported in backend functions"), and one
// such import in base44/shared stops every function from deploying. This keeps them out.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "../base44");

function sourceFiles(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(file);
    return /\.(ts|js|mjs)$/.test(entry.name) ? [file] : [];
  });
}

/** Every import(...) in some code whose specifier isn't one plain string, comments aside. */
function nonLiteralImports(text) {
  const code = text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`\\])\/\/.*$/gm, "$1");
  return [...code.matchAll(/\bimport\s*\(\s*([^)]*?)\s*\)/g)].map((m) => m[1]).filter((arg) => !/^(["'])[^"'`$\n]+\1$/.test(arg));
}

test("the check finds a specifier worked out at run time", () => {
  assert.deepEqual(nonLiteralImports('await import("npm:@noble/post-quantum@0.7.1/ml-kem.js");'), []);
  assert.deepEqual(nonLiteralImports("await import('./federation/hosted.ts');"), []);
  assert.deepEqual(nonLiteralImports("// import(`${old}`) in a comment\n/* import(name) */"), []);
  assert.deepEqual(nonLiteralImports("const plain = 'x/'; await import(`${plain}ml-kem.js`);"), ["`${plain}ml-kem.js`"]);
  assert.deepEqual(nonLiteralImports("await import(name);"), ["name"]);
  assert.deepEqual(nonLiteralImports('await import("./a" + ".ts");'), ['"./a" + ".ts"']);
});

test("backend functions import only literal specifiers, which Base44 can deploy", () => {
  const found = sourceFiles(ROOT).flatMap((file) => nonLiteralImports(fs.readFileSync(file, "utf8")).map((arg) => `${path.relative(ROOT, file)}: import(${arg})`));
  assert.deepEqual(found, []);
});
