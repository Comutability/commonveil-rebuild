// Base44 refuses to deploy a backend function whose code imports anything but a literal specifier
// ("`import(...)` with a non-literal specifier is not supported in backend functions"), and one
// such import in base44/shared stops every function from deploying. This keeps them out, reading
// the code with the TypeScript parser so strings and comments can't hide one.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import ts from "typescript";

const ROOT = path.resolve(import.meta.dirname, "../base44");

function sourceFiles(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(file);
    return /\.(ts|js|mjs)$/.test(entry.name) ? [file] : [];
  });
}

/** Every import(...) in some code whose specifier isn't one plain string literal: its text. */
function nonLiteralImports(text, name = "code.ts") {
  const source = ts.createSourceFile(name, text, ts.ScriptTarget.Latest, true, name.endsWith(".ts") ? ts.ScriptKind.TS : ts.ScriptKind.JS);
  const found = [];
  // import(...), and the newer import.defer(...) and import.source(...), which parse as calls on
  // import's meta-property.
  const isImportCall = (callee) => callee.kind === ts.SyntaxKind.ImportKeyword || (ts.isMetaProperty(callee) && callee.keywordToken === ts.SyntaxKind.ImportKeyword && callee.name.text !== "meta");
  const visit = (node) => {
    if (ts.isCallExpression(node) && isImportCall(node.expression)) {
      const specifier = node.arguments[0];
      if (!specifier || !ts.isStringLiteral(specifier)) found.push(specifier ? specifier.getText(source) : "");
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return found;
}

test("the check finds a specifier worked out at run time, wherever it hides", () => {
  assert.deepEqual(nonLiteralImports('await import("npm:@noble/post-quantum@0.7.1/ml-kem.js");'), []);
  assert.deepEqual(nonLiteralImports("await import('./federation/hosted.ts');"), []);
  assert.deepEqual(nonLiteralImports("// import(`${old}`) in a comment\n/* import(name) */"), []);
  assert.deepEqual(nonLiteralImports("const plain = 'x/'; await import(`${plain}ml-kem.js`);"), ["`${plain}ml-kem.js`"]);
  assert.deepEqual(nonLiteralImports("await import(name);"), ["name"]);
  assert.deepEqual(nonLiteralImports('await import("./a" + ".ts");'), ['"./a" + ".ts"']);
  // Strings that look like comments don't hide what follows them.
  assert.deepEqual(nonLiteralImports('const sep = "a//b"; await import(name);'), ["name"]);
  assert.deepEqual(nonLiteralImports('const a = "/*"; await import(name); const b = "*/";'), ["name"]);
  // The newer forms of import(...) are held to the same rule.
  assert.deepEqual(nonLiteralImports("await import.defer(name); await import.source(name);"), ["name", "name"]);
  assert.deepEqual(nonLiteralImports('await import.defer("./a.ts"); const u = import.meta.url;'), []);
});

test("backend functions import only literal specifiers, which Base44 can deploy", () => {
  const found = sourceFiles(ROOT).flatMap((file) => nonLiteralImports(fs.readFileSync(file, "utf8"), file).map((arg) => `${path.relative(ROOT, file)}: import(${arg})`));
  assert.deepEqual(found, []);
});

test("every function and actor names the same shared code revision", () => {
  // Base44 redeploys a function or actor only when its own entry changes, so a change to
  // base44/shared bumps this line in all of them at once (AGENTS.md); one left behind keeps old code.
  const entries = ["functions", "actors"].flatMap((kind) => fs.readdirSync(path.join(ROOT, kind)).map((name) => path.join(ROOT, kind, name, "entry.ts")));
  const revisions = new Map(entries.map((file) => [path.relative(ROOT, file), /^\/\/ Shared code revision: (\S+?)\./.exec(fs.readFileSync(file, "utf8"))?.[1] || "none"]));
  assert.ok(revisions.size >= 26, "functions and actors found");
  assert.equal(new Set(revisions.values()).size, 1, JSON.stringify(Object.fromEntries(revisions)));
});

test("the post-quantum library the functions load is the version the tests hand in", () => {
  const pinned = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, "../package.json"), "utf8")).dependencies["@noble/post-quantum"];
  const hosted = fs.readFileSync(path.join(ROOT, "shared/federation/hosted.ts"), "utf8");
  const loaded = [...hosted.matchAll(/npm:@noble\/post-quantum@([^/"']+)\//g)].map((m) => m[1]);
  assert.ok(loaded.length >= 2, "hosted.ts names the library");
  assert.deepEqual([...new Set(loaded)], [pinned]);
});
