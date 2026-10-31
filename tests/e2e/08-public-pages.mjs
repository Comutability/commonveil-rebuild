// Public pages render on desktop (light) and phone (dark) without errors or sideways scrolling.
import { chromium } from "playwright";
import { BASE, SHOTS, check } from "./lib.mjs";

const PAGES = ["/", "/blog", "/blog/nostr-in-plain-english", "/guides", "/guides/docker-for-beginners", "/paths", "/paths/self-host-your-data", "/resources", "/wiki", "/wiki/what-is-end-to-end-encryption", "/privacy", "/security", "/search", "/saved", "/login", "/register", "/no-such-page"];
const RUNS = [
  { name: "desktop-light", viewport: { width: 1280, height: 900 }, colorScheme: "light" },
  { name: "phone-dark", viewport: { width: 390, height: 844 }, colorScheme: "dark", isMobile: true },
];

const browser = await chromium.launch();
for (const run of RUNS) {
  const ctx = await browser.newContext({ viewport: run.viewport, colorScheme: run.colorScheme, isMobile: run.isMobile });
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  for (const p of PAGES) {
    await page.goto(BASE + p, { waitUntil: "networkidle", timeout: 90000 });
    await page.waitForTimeout(500);
    const h1 = await page.locator("h1").first().innerText().catch(() => "");
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
    check(h1.length > 0 && !overflow, `${run.name} ${p} renders ("${h1.slice(0, 40)}")`);
    await page.screenshot({ path: `${SHOTS}/08-${run.name}${p.replace(/\//g, "_") || "_home"}.png` });
  }
  check(errors.length === 0, `${run.name}: no page errors`);
  await ctx.close();
}
await browser.close();
