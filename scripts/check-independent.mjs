// Checks that a self-hosted build owes nothing to Base44: no Base44 package was installed, and
// nothing in the built site or the server mentions a Base44 host or package.
//
//   node scripts/check-independent.mjs dist-selfhost
import fs from "node:fs";
import path from "node:path";

const dist = path.resolve(process.argv[2] || "dist-selfhost");
const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const FORBIDDEN = /base44\.(app|com|dev)|base44-realtime|@base44\/(sdk|vite-plugin)/;
const problems = [];

function scan(dir, filter) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) scan(p, filter);
    else if (filter(p)) {
      const m = FORBIDDEN.exec(fs.readFileSync(p, "utf8"));
      if (m) problems.push(`${path.relative(root, p)}: mentions ${m[0]}`);
    }
  }
}

scan(dist, (p) => /\.(js|html|css|json|webmanifest|txt|xml)$/.test(p));
for (const dir of ["server", "updater"]) scan(path.join(root, dir), (p) => /\.m?js$/.test(p));
if (process.env.CHECK_INSTALLED !== "false" && fs.existsSync(path.join(root, "node_modules/@base44"))) {
  problems.push("node_modules/@base44 is installed: remove it before building (see Dockerfile)");
}

if (problems.length) {
  console.error(`Not independent of Base44:\n  ${problems.join("\n  ")}`);
  process.exit(1);
}
console.log("No Base44 code, hosts or packages in the self-hosted build.");
