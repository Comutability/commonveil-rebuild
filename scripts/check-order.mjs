// Fails if any app code uses a const or let before the line that declares it.
//
// In a React component that is a crash the moment the component renders ("Cannot access 'x'
// before initialization"), and nothing else here would notice: the unit tests run the logic, not
// the screens, and ESLint has no rule for it. 0.23.0 shipped with exactly this and showed every
// signed-in person a blank page (docs/SECURITY_REVIEW.md, 14 November 2026).
//
// The TypeScript compiler can see it, so this runs it over src/ and keeps only those findings
// (TS2448, TS2449, TS2450, TS2454); the app isn't otherwise type-checked.
import { spawnSync } from "node:child_process";
import path from "node:path";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const tsc = path.join(root, "node_modules", ".bin", "tsc");
const run = spawnSync(tsc, ["-p", path.join(root, "tsconfig.order.json"), "--pretty", "false"], { cwd: root, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
if (run.error) {
  console.error(`Couldn't run the TypeScript compiler: ${run.error.message}`);
  process.exit(1);
}
const found = `${run.stdout}\n${run.stderr}`.split("\n").filter((l) => /error TS(2448|2449|2450|2454):/.test(l));
if (found.length) {
  console.error("Used before it is declared (this crashes when the code runs):\n");
  for (const l of found) console.error(`  ${l}`);
  process.exit(1);
}
console.log("No variable is used before it is declared.");
