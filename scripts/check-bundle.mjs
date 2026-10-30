// Checks the production build for anything the site's Content Security Policy would block.
// The editor preview runs without the policy, so these breaks would otherwise only show up on
// the published site (a Radix Select did exactly that: it renders a <style> through innerHTML,
// which Trusted Types refuses, and the page crashed).
//
//   npm run build && node scripts/check-bundle.mjs
import fs from "node:fs";
import path from "node:path";

const dist = path.resolve(process.argv[2] || "dist");
const problems = [];

const html = fs.readFileSync(path.join(dist, "index.html"), "utf8");
if (!/<meta charset="UTF-8" \/>\s*<meta http-equiv="Content-Security-Policy"[^>]*require-trusted-types-for 'script'/i.test(html)) {
  problems.push("index.html: the Content Security Policy (with Trusted Types) isn't the first thing after the charset");
}
for (const tag of html.match(/<script\b[^>]*>/gi) || []) {
  if (!/\bsrc=/.test(tag)) problems.push(`index.html: an inline script, which the policy blocks: ${tag}`);
}

const assets = path.join(dist, "assets");
for (const file of fs.readdirSync(assets).filter((f) => f.endsWith(".js"))) {
  const code = fs.readFileSync(path.join(assets, file), "utf8");
  const checks = [
    [/dangerouslySetInnerHTML:\{/g, "a component renders HTML from a string (dangerouslySetInnerHTML)"],
    [/\beval\(/g, "eval()"],
    [/new Function\(/g, "new Function()"],
    [/document\.write\(/g, "document.write()"],
    [/insertAdjacentHTML\(/g, "insertAdjacentHTML()"],
    [/\.outerHTML\s*=/g, "an outerHTML assignment"],
  ];
  for (const [re, what] of checks) {
    for (const m of code.matchAll(re)) {
      problems.push(`${file}: ${what}, which Trusted Types blocks: ...${code.slice(Math.max(0, m.index - 100), m.index + 100)}...`);
    }
  }
}

if (problems.length) {
  console.error(`Bundle check failed (${problems.length}):\n- ${problems.join("\n- ")}`);
  process.exit(1);
}
console.log("Bundle check: the policy is in place, and nothing in the bundle needs what it blocks.");
