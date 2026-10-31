// The newer in-app features on a production build, under its Content Security Policy: reactions,
// edits, the timer, the passcode lock (WebCrypto PBKDF2 and AES-GCM), the data download and
// auto-delete. Run it like 10: against dist/ served by serve-dist.mjs, or the published site.
// Args: <embed url for a freshly provisioned member>. It starts a conversation with Ann (from 01).
import { chromium } from "playwright";
import fs from "node:fs";
import { BASE, PEOPLE, check, expectText, setUp, sendText } from "./lib.mjs";

const [memberUrl] = process.argv.slice(2);
const browser = await chromium.launch();
const violations = [];
const errors = [];

const sctx = await browser.newContext();
const sp = await sctx.newPage();
await sp.goto(memberUrl, { waitUntil: "networkidle", timeout: 120000 });
let token = null;
for (let i = 0; i < 90 && !token; i += 1) {
  token = await sp.evaluate(() => localStorage.getItem("base44_access_token")).catch(() => null);
  if (!token) await sp.waitForTimeout(1000);
}
await sctx.close();
if (!token) throw new Error("no session");

const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, acceptDownloads: true });
await ctx.exposeBinding("__cvViolation", (_s, v) => violations.push(v));
await ctx.addInitScript(() => {
  document.addEventListener("securitypolicyviolation", (e) => window.__cvViolation({ directive: e.violatedDirective, blocked: e.blockedURI || "inline", sample: e.sample || "" }));
});
const page = await ctx.newPage();
page.on("pageerror", (e) => errors.push(e.message));
page.on("console", (m) => { if (m.type() === "error" && /content security|trusted|refused to/i.test(m.text())) errors.push(m.text()); });
await page.goto(`${BASE}/app?access_token=${encodeURIComponent(token)}`, { waitUntil: "networkidle", timeout: 120000 });
await setUp(page, { username: `e2e_csp_${Date.now().toString(36).slice(-5)}`, display: "Csp Test" });
check(true, "set up under the policy");

await page.getByRole("button", { name: "New" }).click();
await page.fill("#dm-username", PEOPLE.ann.username);
await page.getByRole("button", { name: "Start conversation" }).click();
await page.waitForURL(/\/app\/c\//, { timeout: 60000 });
const text = `Policy check ${Date.now() % 100000}`;
await sendText(page, text);
const bubble = page.locator("div.group", { hasText: text }).last();
await bubble.hover();
await bubble.getByRole("button", { name: "Message options" }).click();
await page.getByRole("menuitem", { name: "React with Heart" }).click();
await bubble.getByRole("button", { name: /^Heart, 1/ }).waitFor({ timeout: 30000 });
check(true, "reacting works under the policy");
await bubble.hover();
await bubble.getByRole("button", { name: "Message options" }).click();
await page.getByRole("menuitem", { name: "Edit" }).click();
await sendText(page, `${text} (edited)`);
await page.locator("div.group", { hasText: `${text} (edited)` }).locator("text=· edited").waitFor({ timeout: 30000 });
check(true, "editing works under the policy");
await page.getByRole("button", { name: /Conversation details/ }).click();
await page.selectOption("#disappearing", "604800");
await expectText(page, "New messages will disappear after a week.");
await page.selectOption("#disappearing", "0");
await expectText(page, "Disappearing messages are off.");
await page.keyboard.press("Escape");
check(true, "the timer works under the policy");

await page.goto(`${BASE}/app/settings`, { waitUntil: "networkidle" });
await page.fill("#passcode-new", "policy check passcode");
await page.fill("#passcode-again", "policy check passcode");
await page.getByRole("button", { name: "Turn on" }).click();
await expectText(page, "This browser is now locked with your passcode.");
await page.reload({ waitUntil: "networkidle" });
await page.waitForSelector('h1:has-text("Commonveil is locked")', { timeout: 60000 });
await page.fill("#passcode", "policy check passcode");
await page.getByRole("button", { name: "Unlock" }).click();
await page.waitForSelector('h1:has-text("Settings")', { timeout: 90000 });
check(true, "the passcode lock (PBKDF2 and AES-GCM in the browser) works under the policy");
const [download] = await Promise.all([page.waitForEvent("download", { timeout: 120000 }), page.getByRole("button", { name: "Download my data" }).click()]);
const data = JSON.parse(fs.readFileSync(await download.path(), "utf8"));
check(data.conversations.some((c) => c.messages.some((m) => m.text === `${text} (edited)`)), "the data download works under the policy");
await page.getByRole("button", { name: "Turn off" }).click();
await expectText(page, "The lock is off.");
await page.selectOption("#auto-delete", "365");
await expectText(page, "Saved.");
await page.selectOption("#auto-delete", "0");
await expectText(page, "The day you last used Commonveil is no longer kept.");
check(true, "auto-delete works under the policy");

console.log(violations.length ? `VIOLATIONS: ${JSON.stringify(violations)}` : "ok - nothing was blocked by the policy");
console.log(errors.length ? `ERRORS: ${errors.join(" | ")}` : "ok - no page errors");
await browser.close();
