// WCAG 2 A/AA checks with axe-core, light and dark, on public pages and signed-in screens.
import { chromium } from "playwright";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { BASE, PEOPLE, check } from "./lib.mjs";

const require = createRequire(import.meta.url);
const axeSource = fs.readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");
const ROOT = process.env.CV_E2E_DIR || "/tmp/cv-e2e";

/** within: a selector to audit just that part (a dialog, not the page dimmed behind it). */
async function audit(page, label, within = null) {
  await page.addScriptTag({ content: axeSource });
  const result = await page.evaluate(async (sel) => window.axe.run(sel ? document.querySelector(sel) : document, { runOnly: ["wcag2a", "wcag2aa"] }), within);
  const problems = result.violations.map((v) => `${v.id} (${v.impact}) x${v.nodes.length}: ${v.nodes[0]?.target.join(" ")}`);
  if (problems.length) console.log(`  ${label}:\n    ${problems.join("\n    ")}`);
  return problems.length;
}

const browser = await chromium.launch();
let total = 0;
for (const colorScheme of ["light", "dark"]) {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, colorScheme });
  const page = await ctx.newPage();
  for (const p of ["/", "/help", "/help/moderation", "/releases", "/resources", "/security", "/privacy", "/search", "/login", "/register"]) {
    await page.goto(BASE + p, { waitUntil: "networkidle", timeout: 90000 });
    total += await audit(page, `${colorScheme} ${p}`);
  }
  await ctx.close();
  const app = await chromium.launchPersistentContext(path.join(ROOT, "profiles", "ann1"), { viewport: { width: 1280, height: 900 }, colorScheme });
  const ap = app.pages()[0] || (await app.newPage());
  await ap.goto(`${BASE}/app`, { waitUntil: "networkidle", timeout: 90000 });
  await ap.waitForSelector('h1:has-text("Messages")', { timeout: 60000 });
  await ap.locator(`a:has-text("${PEOPLE.ben.display}")`).first().click();
  await ap.waitForTimeout(4000);
  total += await audit(ap, `${colorScheme} /app conversation`);
  await ap.getByRole("button", { name: /Conversation details/ }).click();
  await ap.getByRole("dialog").waitFor({ timeout: 30000 });
  await ap.waitForTimeout(1000);
  total += await audit(ap, `${colorScheme} /app conversation details`, '[role="dialog"]');
  await ap.keyboard.press("Escape");
  await ap.goto(`${BASE}/app/settings`, { waitUntil: "networkidle", timeout: 90000 });
  await ap.waitForTimeout(3000);
  total += await audit(ap, `${colorScheme} /app/settings`);
  await app.close();
}
await browser.close();
check(total === 0, "no WCAG 2 A/AA violations found by axe-core");
