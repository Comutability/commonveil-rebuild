// Commonveil's copy of Secure Net (packages/secure-net), the protocol library it's built on
// (https://github.com/Comutability/secure-net).
//
//   npm run secure-net:sync [-- path/to/secure-net]   copy a Secure Net checkout in (default ../secure-net)
//   npm run secure-net:check                         fail if the copy differs from its manifest
//
// The copy is checked on every verify, so a change made here by mistake (instead of in Secure
// Net) is caught: change Secure Net, then sync.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const dest = path.join(root, "packages/secure-net");
const MANIFEST = "secure-net.manifest.json";

const hash = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("base64url");

function check() {
  const file = path.join(dest, MANIFEST);
  if (!fs.existsSync(file)) return [`${path.relative(root, file)} is missing`];
  const { files } = JSON.parse(fs.readFileSync(file, "utf8"));
  const problems = [];
  for (const [rel, want] of Object.entries(files)) {
    const abs = path.join(dest, rel);
    if (!fs.existsSync(abs)) problems.push(`${rel} is missing`);
    else if (hash(abs) !== want) problems.push(`${rel} differs from Secure Net`);
  }
  const walk = (rel) => {
    const abs = path.join(dest, rel);
    if (fs.statSync(abs).isDirectory()) for (const e of fs.readdirSync(abs)) walk(path.posix.join(rel, e));
    else if (rel !== MANIFEST && !files[rel]) problems.push(`${rel} isn't part of Secure Net`);
  };
  for (const e of fs.readdirSync(dest)) walk(e);
  return problems;
}

if (process.argv.includes("--check")) {
  const problems = check();
  if (problems.length) {
    console.error(`packages/secure-net doesn't match Secure Net:\n  ${problems.join("\n  ")}\nChange Secure Net itself, then run npm run secure-net:sync.`);
    process.exit(1);
  }
  const { version } = JSON.parse(fs.readFileSync(path.join(dest, MANIFEST), "utf8"));
  console.log(`packages/secure-net is Secure Net ${version}, unchanged.`);
} else {
  const src = path.resolve(process.argv[2] || path.join(root, "../secure-net"));
  const manifest = JSON.parse(fs.readFileSync(path.join(src, MANIFEST), "utf8"));
  for (const rel of Object.keys(manifest.files)) if (hash(path.join(src, rel)) !== manifest.files[rel]) throw new Error(`${rel} in ${src} doesn't match its manifest: run node scripts/manifest.mjs there first`);
  fs.rmSync(dest, { recursive: true, force: true });
  for (const rel of [...Object.keys(manifest.files), MANIFEST]) {
    fs.mkdirSync(path.dirname(path.join(dest, rel)), { recursive: true });
    fs.copyFileSync(path.join(src, rel), path.join(dest, rel));
  }
  console.log(`Copied Secure Net ${manifest.version} (${Object.keys(manifest.files).length} files) into packages/secure-net.`);
}
